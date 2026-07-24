// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorGetAssertion`: resolve the credential from the allowList
//! (resident-id lookup or a non-resident box) or, if the allowList is empty, by
//! scanning resident credentials for the rp; sign authData ‖ clientDataHash
//! with the credential key. A verified `pinUvAuthParam` sets the `uv` flag
//! ([`enforce_pin`]); credProtect visibility is enforced in [`Best::consider`].
//! When resident discovery finds more than one credential, the sorted EF_CRED
//! slots are saved so [`get_next_assertion`] can return the rest one at a time.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::sha256;
use rsk_fs::Storage;

use crate::cbordec::{cbor, def_arr, def_map};
use crate::consts::{
    CRED_PROT_UV_OPTIONAL_WITH_LIST, CRED_PROT_UV_REQUIRED, CURVE_P256, EF_CRED, EF_PIN, FLAG_ED,
    FLAG_UP, FLAG_UV, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_RESIDENT_CREDENTIALS,
};
use crate::credential::{
    CRED_BOX_MAX, CRED_REC_MAX, CRED_RESIDENT_LEN, Credential, RECORD_PREFIX, USER_ID_MAX,
    USER_NAME_MAX, cred_record_box, credential_load, derive_large_blob_key, resident_key_input,
    slot_map,
};
use crate::ec::{CredKey, MAX_SIG_LEN};
use crate::error::{CtapError, CtapResult};
use crate::hmacsecret::{self, HmacSecretReq, SALT_AUTH_MAX, SALT_ENC_MAX};
use crate::journal;
use crate::keyderiv::{KEY_HANDLE_LEN, fido_load_key, verify_key};
use crate::seed::{cred_sign_counter, get_sign_counter, set_cred_sign_counter};
use crate::state::{AssertionState, MAX_ASSERTION_CREDS, PERM_GA};
use crate::{Ctx, Rng};
use rsk_crypto::pinproto::PinProto;

const MAX_ALLOW: usize = MAX_CREDENTIAL_COUNT_IN_LIST as usize;
/// Sized by the create-side ceiling so no creatable box is ever skipped
/// (`Best::consider` drops longer candidates). It sits on the getAssertion
/// frame — the ML-DSA keypair already lives off-stack.
const MAX_CRED_ID: usize = CRED_BOX_MAX;
/// The stored user.id is capped at create, so echoing this many is lossless.
const MAX_USER_ID: usize = USER_ID_MAX;

struct Request<'a> {
    rp_id: &'a str,
    client_data_hash: &'a [u8],
    allow: [&'a [u8]; MAX_ALLOW],
    allow_len: usize,
    rk_option: bool,
    uv: bool,
    /// The `up` option (default true). `up:false` is the platform's silent
    /// pre-flight probe; honoring it (no touch, UP flag 0) is what keeps a
    /// WebAuthn login to a single touch. See the presence check in
    /// `get_assertion_inner` and the `strict-up` feature.
    up: bool,
    pin_uv_auth_param: Option<&'a [u8]>,
    pin_uv_auth_protocol: u64,
    ext_cred_blob: bool,
    ext_third_party_payment: bool,
    ext_large_blob_key: Option<bool>,
    hmac_secret: HmacSecretReq<'a>,
}

fn parse(data: &[u8]) -> Result<Request<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Request {
        rp_id: "",
        client_data_hash: &[],
        allow: [&[]; MAX_ALLOW],
        allow_len: 0,
        rk_option: false,
        uv: false,
        up: true,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: 0,
        ext_cred_blob: false,
        ext_third_party_payment: false,
        ext_large_blob_key: None,
        hmac_secret: HmacSecretReq::default(),
    };
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Keys 1..=2 (rpId, clientDataHash) are mandatory and ordered first.
        if expected <= 2 && key != expected {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.rp_id = cbor(d.str())?,
            2 => req.client_data_hash = cbor(d.bytes())?,
            3 => parse_allow_list(&mut d, &mut req)?,
            5 => parse_options(&mut d, &mut req)?,
            4 => parse_extensions(&mut d, &mut req)?,
            6 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            7 => req.pin_uv_auth_protocol = cbor(d.u32())? as u64,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Parse the `allowList` (request key 3) into `req.allow` (capped at MAX_ALLOW).
fn parse_allow_list<'a>(d: &mut Decoder<'a>, req: &mut Request<'a>) -> Result<(), CtapError> {
    let a = def_arr(d)?;
    for _ in 0..a {
        let m = def_map(d)?;
        let mut id: &[u8] = &[];
        let (mut id_present, mut type_present) = (false, false);
        for _ in 0..m {
            match cbor(d.str())? {
                "id" => {
                    id = cbor(d.bytes())?;
                    id_present = true;
                }
                // Read "type" as text so a byte-string yields CborUnexpectedType.
                "type" => {
                    let _: &str = cbor(d.str())?;
                    type_present = true;
                }
                _ => cbor(d.skip())?,
            }
        }
        // A credential descriptor needs both "type" and "id".
        if !type_present || !id_present {
            return Err(CtapError::MissingParameter);
        }
        if req.allow_len < MAX_ALLOW {
            req.allow[req.allow_len] = id;
            req.allow_len += 1;
        }
    }
    Ok(())
}

/// Parse the getAssertion `extensions` map (request key 4) into `req`.
fn parse_extensions<'a>(d: &mut Decoder<'a>, req: &mut Request<'a>) -> Result<(), CtapError> {
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.str())? {
            "credBlob" => req.ext_cred_blob = cbor(d.bool())?,
            "thirdPartyPayment" => req.ext_third_party_payment = cbor(d.bool())?,
            "largeBlobKey" => req.ext_large_blob_key = Some(cbor(d.bool())?),
            "hmac-secret" => req.hmac_secret = hmacsecret::parse(d)?,
            _ => cbor(d.skip())?,
        }
    }
    Ok(())
}

/// Parse the `options` map (request key 5: rk / uv / up) into `req`.
fn parse_options(d: &mut Decoder<'_>, req: &mut Request<'_>) -> Result<(), CtapError> {
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.str())? {
            "rk" => req.rk_option = cbor(d.bool())?,
            "uv" => req.uv = cbor(d.bool())?,
            "up" => req.up = cbor(d.bool())?,
            _ => cbor(d.skip())?,
        }
    }
    Ok(())
}

/// Max user name / displayName length echoed in an assertion — the create-side
/// truncation cap, so a stored name always fits verbatim.
const MAX_USER_NAME: usize = USER_NAME_MAX;

/// The newest matching credential found so far.
struct Best {
    id: [u8; MAX_CRED_ID],
    len: usize,
    created: u64,
    resident: bool,
    /// For a resident credential, its STORED 42-byte resident id — the stable
    /// credentialId returned to the platform. Kept verbatim rather than
    /// re-derived from the box so it survives an updateUserInformation reseal.
    resident_id: [u8; CRED_RESIDENT_LEN],
    /// The winning credential's EF_CRED slot, keying its per-credential signature
    /// counter. `None` for a non-resident (allowList box) credential, which keeps
    /// no on-device state and reports signCount 0.
    slot: Option<u16>,
    user: [u8; MAX_USER_ID],
    user_len: usize,
    // name / displayName, returned only on a multi-credential resident discovery.
    name: [u8; MAX_USER_NAME],
    name_len: usize,
    display: [u8; MAX_USER_NAME],
    display_len: usize,
    found: u32,
    any: bool,
}

impl Best {
    fn new() -> Self {
        Self {
            id: [0; MAX_CRED_ID],
            len: 0,
            created: 0,
            resident: false,
            resident_id: [0; CRED_RESIDENT_LEN],
            slot: None,
            user: [0; MAX_USER_ID],
            user_len: 0,
            name: [0; MAX_USER_NAME],
            name_len: 0,
            display: [0; MAX_USER_NAME],
            display_len: 0,
            found: 0,
            any: false,
        }
    }

    /// Load `cand` and, if it decrypts for this rp and is visible, fold it in
    /// (keeping the newest). Returns the credential's creation time when it
    /// counted. A credProtect-hidden credential is skipped (returns `None`) so it
    /// neither signs nor counts toward `numberOfCredentials`.
    #[allow(clippy::too_many_arguments)]
    fn consider(
        &mut self,
        seed: &[u8; 32],
        rp_id_hash: &[u8; 32],
        cand: &[u8],
        resident_id: Option<&[u8]>,
        slot: Option<u16>,
        uv: bool,
        has_allow: bool,
        scratch: &mut [u8],
    ) -> Option<u64> {
        if cand.len() > self.id.len() {
            return None;
        }
        let c = credential_load(seed, cand, rp_id_hash, scratch)?;
        // credProtect visibility (§7): a UV-required
        // credential is invisible without UV; a UV-optional-with-list credential
        // is invisible during resident discovery (no allowList) without UV.
        let hidden = (c.ext.cred_protect == CRED_PROT_UV_REQUIRED && !uv)
            || (c.ext.cred_protect == CRED_PROT_UV_OPTIONAL_WITH_LIST && !has_allow && !uv);
        if hidden {
            return None;
        }
        self.found += 1;
        if !self.any || c.created >= self.created {
            self.any = true;
            self.created = c.created;
            // A resident candidate carries its stored 42-byte id + EF_CRED slot; a
            // non-resident (allowList box) carries neither.
            self.resident = resident_id.is_some();
            self.slot = slot;
            if let Some(rid) = resident_id {
                let m = rid.len().min(CRED_RESIDENT_LEN);
                self.resident_id[..m].copy_from_slice(&rid[..m]);
            }
            self.len = cand.len();
            self.id[..cand.len()].copy_from_slice(cand);
            self.user_len = c.user_id.len().min(MAX_USER_ID);
            self.user[..self.user_len].copy_from_slice(&c.user_id[..self.user_len]);
            self.name_len = c.user_name.len().min(MAX_USER_NAME);
            self.name[..self.name_len].copy_from_slice(&c.user_name.as_bytes()[..self.name_len]);
            self.display_len = c.user_display_name.len().min(MAX_USER_NAME);
            self.display[..self.display_len]
                .copy_from_slice(&c.user_display_name.as_bytes()[..self.display_len]);
        }
        Some(c.created)
    }
}

/// `authenticatorGetAssertion`: write the response CBOR into `out`, returning its
/// length.
pub fn get_assertion<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;
    if req.rp_id.is_empty() || req.client_data_hash.len() != 32 {
        return Err(CtapError::MissingParameter);
    }
    if req.uv {
        return Err(CtapError::InvalidOption);
    }
    if req.rk_option {
        return Err(CtapError::UnsupportedOption);
    }
    // largeBlobKey may only be requested as `true`.
    if req.ext_large_blob_key == Some(false) {
        return Err(CtapError::InvalidOption);
    }
    if req.hmac_secret.present
        && (req.hmac_secret.salt_enc.is_empty() || req.hmac_secret.salt_auth.is_empty())
    {
        return Err(CtapError::MissingParameter);
    }

    let rp_id_hash = sha256(req.rp_id.as_bytes());
    let uv = enforce_pin(ctx, &req, &rp_id_hash)?;

    let mut seed = ctx.load_keydev().ok_or(CtapError::Other)?;
    let result = get_assertion_inner(ctx, &req, &rp_id_hash, &seed, uv, out);
    seed.zeroize();
    if result.is_ok() {
        journal::append(ctx, journal::EV_GET_ASSERT, 0, &rp_id_hash[..8]);
    } else {
        // getNextAssertion performs no presence check of its own — it may only
        // continue a getAssertion whose presence gate SUCCEEDED (CTAP 2.1 §6.3).
        // The multi-credential queue is armed during resident discovery, before
        // that gate; if the ceremony then fails (declined / timed-out / cancelled
        // touch, or any later error) the queue must be torn down, or the next
        // getNextAssertion would emit a UP=1 assertion the user never approved.
        ctx.state.gna.reset();
    }
    result
}

/// Whether this getAssertion asserts user presence: honor `up:false` (the
/// platform's silent pre-flight) unless the `strict-up` build forces a touch on
/// every assertion. Shared by the alwaysUv gate and `get_assertion_inner`.
fn want_up(req: &Request) -> bool {
    cfg!(feature = "strict-up") || req.up
}

/// CTAP2.1 PIN/UV enforcement (§6.1): verifies a `pinUvAuthParam` against the
/// token and reports whether to set the `uv` flag.
/// Unlike makeCredential, an absent param is allowed (the assertion just lacks UV).
fn enforce_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
) -> Result<bool, CtapError> {
    match req.pin_uv_auth_param {
        // Zero-length probe (selection gesture): touch, then report PIN state.
        // With no button configured this confirms instantly. CTAP 2.1 §6.2.2 step 1
        // (mirrors makeCredential): PIN set → PIN_INVALID, unset → PIN_NOT_SET — the
        // code a selection-managing platform reads to move on to PIN entry.
        Some(&[]) => {
            ctx.require_presence(crate::Confirm::titled("Use this key?"))?;
            Err(if ctx.fs.has_data(EF_PIN) {
                CtapError::PinInvalid
            } else {
                CtapError::PinNotSet
            })
        }
        Some(param) => {
            let proto = match req.pin_uv_auth_protocol {
                0 => return Err(CtapError::MissingParameter),
                p => PinProto::from_u64(p).ok_or(CtapError::InvalidParameter)?,
            };
            if !ctx.state.verify_token(proto, req.client_data_hash, param)
                || !ctx.state.user_verified()
                || ctx.state.paut.permissions & PERM_GA == 0
                || (ctx.state.paut.has_rp_id && ctx.state.paut.rp_id_hash != *rp_id_hash)
            {
                return Err(CtapError::PinAuthInvalid);
            }
            ctx.state.mark_token_used(ctx.now_ms);
            // Bind an unscoped token to this rpId on first use (CTAP 2.1 §6.2.2),
            // as makeCredential does — else it stays reusable across RPs.
            if !ctx.state.paut.has_rp_id {
                ctx.state.paut.rp_id_hash = *rp_id_hash;
                ctx.state.paut.has_rp_id = true;
            }
            Ok(true)
        }
        // alwaysUv forces UV only for an assertion that asserts presence; the
        // platform's silent up:false pre-flight (credential discovery, e.g.
        // ssh-sk) is exempt — CTAP 2.1 §6.2.2 step 5 guards the PUAT_REQUIRED
        // path on the `up` option being present and true. Without the exemption
        // the probe fails and OpenSSH reports "device not found". Key this on the
        // raw `up`, NOT want_up: strict-up adds a button poll on the probe (below)
        // but must not turn the probe into a PUAT_REQUIRED refusal — that re-broke
        // ssh-sk whenever always-uv and strict-up combined (issue #34 follow-up).
        None if req.up && crate::config::always_uv_enabled(ctx.fs) => Err(CtapError::PuatRequired),
        None => Ok(false),
    }
}

/// Populate `best` with the newest visible credential for this rp — from the
/// allowList (resident-id lookup or a non-resident box) or, if it is empty, by
/// scanning resident credentials. On a multi-credential resident discovery, arm
/// getNextAssertion (newest first) so it can return the rest one at a time.
#[allow(clippy::too_many_arguments)]
fn resolve_credential<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    uv: bool,
    best: &mut Best,
) {
    if req.allow_len > 0 {
        resolve_from_allowlist(ctx, req, rp_id_hash, seed, uv, best);
    } else {
        resolve_by_discovery(ctx, req, rp_id_hash, seed, uv, best);
    }
}

/// allowList resolution: for each descriptor, look up a resident-id box (by its
/// 42-byte id across the live EF_CRED slots) or decrypt a non-resident box, and
/// fold the newest visible match into `best`.
fn resolve_from_allowlist<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    uv: bool,
    best: &mut Best,
) {
    let mut scratch = [0u8; CRED_REC_MAX];
    let mut rec = [0u8; CRED_REC_MAX];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    for &id in &req.allow[..req.allow_len] {
        // A resident id is exactly 42 bytes, matched against the stored records;
        // fall back to the non-resident box path for anything else — and for a
        // 42-byte id not stored as a resident — so no cleartext marker is needed.
        let mut resident_hit = false;
        if id.len() == CRED_RESIDENT_LEN {
            for i in 0..MAX_RESIDENT_CREDENTIALS {
                if !occupied[i as usize] {
                    continue;
                }
                let Some(n) = ctx.fs.read(EF_CRED + i, &mut rec) else {
                    continue;
                };
                let n = n.min(rec.len());
                if n >= RECORD_PREFIX && rec[..32] == *rp_id_hash && rec[32..RECORD_PREFIX] == *id {
                    best.consider(
                        seed,
                        rp_id_hash,
                        cred_record_box(&rec[..n]),
                        Some(&rec[32..RECORD_PREFIX]),
                        Some(i),
                        uv,
                        true,
                        &mut scratch,
                    );
                    resident_hit = true;
                    break;
                }
            }
        }
        if !resident_hit {
            best.consider(seed, rp_id_hash, id, None, None, uv, true, &mut scratch);
        }
    }
}

/// Resident discovery (empty allowList): fold every stored credential for this rp
/// into `best`, and — when more than one matches — arm getNextAssertion with the
/// sorted EF_CRED slots so the rest can be walked one at a time.
fn resolve_by_discovery<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    uv: bool,
    best: &mut Best,
) {
    let mut scratch = [0u8; CRED_REC_MAX];
    let mut rec = [0u8; CRED_REC_MAX];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    // Collect the matching EF_CRED slots so getNextAssertion can walk them.
    let mut cands: [(u16, u64); MAX_ASSERTION_CREDS] = [(0, 0); MAX_ASSERTION_CREDS];
    let mut ncand = 0usize;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = ctx.fs.read(EF_CRED + i, &mut rec) else {
            continue;
        };
        let n = n.min(rec.len());
        if n >= RECORD_PREFIX
            && rec[..32] == *rp_id_hash
            && let Some(created) = best.consider(
                seed,
                rp_id_hash,
                cred_record_box(&rec[..n]),
                Some(&rec[32..RECORD_PREFIX]),
                Some(i),
                uv,
                false,
                &mut scratch,
            )
            && ncand < MAX_ASSERTION_CREDS
        {
            cands[ncand] = (i, created);
            ncand += 1;
        }
    }
    // Arm getNextAssertion when more than one credential matched (newest first).
    if ncand > 1 {
        arm_get_next_assertion(
            &mut ctx.state.gna,
            &mut cands[..ncand],
            req,
            rp_id_hash,
            uv,
            ctx.now_ms,
        );
    }
}

/// Arm getNextAssertion for a multi-credential resident discovery: sort the
/// matching EF_CRED slots newest-first and stash them (with the request's uv/up
/// and extension inputs) so [`get_next_assertion`] can return the rest one at a
/// time. `cands` is the `(slot, created)` list; only its length matters after.
fn arm_get_next_assertion(
    gna: &mut AssertionState,
    cands: &mut [(u16, u64)],
    req: &Request,
    rp_id_hash: &[u8; 32],
    uv: bool,
    now_ms: u64,
) {
    cands.sort_unstable_by_key(|c| core::cmp::Reverse(c.1));
    gna.active = true;
    gna.rp_id_hash = *rp_id_hash;
    gna.client_data_hash.copy_from_slice(req.client_data_hash);
    gna.uv = uv;
    // Carry the request's RAW `up` (not want_up) so every getNextAssertion leg emits
    // the same inert UP=0 as the Begin leg for an up:false pre-flight under strict-up.
    gna.up = req.up;
    gna.total = cands.len() as u8;
    gna.counter = 1;
    gna.started_ms = now_ms;
    for (k, &(slot, _)) in cands.iter().enumerate() {
        gna.slots[k] = slot;
    }
    // Carry the request's extension inputs so getNextAssertion re-evaluates them
    // (hmac-secret included) per credential.
    gna.hmac_present = req.hmac_secret.present;
    if req.hmac_secret.present {
        gna.hmac_proto = req.hmac_secret.proto;
        gna.hmac_peer_x = req.hmac_secret.peer_x;
        gna.hmac_peer_y = req.hmac_secret.peer_y;
        let se = req.hmac_secret.salt_enc.len().min(gna.hmac_salt_enc.len());
        gna.hmac_salt_enc[..se].copy_from_slice(&req.hmac_secret.salt_enc[..se]);
        gna.hmac_salt_enc_len = se as u8;
        let sa = req
            .hmac_secret
            .salt_auth
            .len()
            .min(gna.hmac_salt_auth.len());
        gna.hmac_salt_auth[..sa].copy_from_slice(&req.hmac_secret.salt_auth[..sa]);
        gna.hmac_salt_auth_len = sa as u8;
    }
    gna.ext_cred_blob = req.ext_cred_blob;
    gna.ext_third_party_payment = req.ext_third_party_payment;
}

fn get_assertion_inner<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    uv: bool,
    out: &mut [u8],
) -> CtapResult {
    // Presence POLL decision: honor `up:false` (the silent pre-flight) unless
    // `strict-up` forces a touch. The emitted UP flag follows raw `up` (below), NOT
    // this — so a polled up:false probe stays inert (UP=0), preserving alwaysUv.
    let want_up = want_up(req);
    let mut best = Best::new();
    resolve_credential(ctx, req, rp_id_hash, seed, uv, &mut best);

    if !best.any {
        // Poll presence BEFORE disclosing no-match so the device isn't a silent
        // credential-existence oracle (matches YubiKey; §6.2.2 discloses first, but
        // requiring the gesture is spec-permitted). up:false pre-flight stays silent.
        if want_up {
            ctx.require_presence(crate::Confirm::new("Sign in?", req.rp_id.as_bytes(), &[]))?;
        }
        // That poll is a real presence gesture, so spend the token like the success
        // path — a no-match ceremony must not leave an acfg token usable without a
        // fresh touch (GHSA-wqjm-653g-hgw3). Keyed on the raw `up`.
        ctx.state.consume_after_user_presence_if(req.up);
        return Err(CtapError::NoCredentials);
    }

    // Re-load the selected credential for its stored extension data + curve.
    let mut sel_scratch = [0u8; CRED_REC_MAX];
    let sel = credential_load(seed, &best.id[..best.len], rp_id_hash, &mut sel_scratch);
    let sel_large_blob = sel.as_ref().map(|c| c.ext.large_blob_key).unwrap_or(false);
    let curve = sel.as_ref().map_or(CURVE_P256 as i64, |c| c.curve);

    // The signing / hmac-secret / largeBlobKey key-derivation input: a v2 resident
    // credential keys off its STABLE resident id (so an updateUserInformation
    // reseal doesn't rotate the keys), everything else off the box — the same
    // choice makeCredential made when it issued the RP's pubkey.
    let key_input = resident_key_input(
        &best.id[..best.len],
        best.resident.then_some(&best.resident_id[..]),
    );

    // hmac-secret output (needs the clientPIN ephemeral key + the RNG for the IV).
    let mut hs = [0u8; SALT_ENC_MAX];
    let hs_len = if req.hmac_secret.present {
        let ephemeral = *ctx.state.ephemeral_scalar();
        hmacsecret::eval(
            &req.hmac_secret,
            &ephemeral,
            seed,
            key_input,
            uv,
            ctx.rng,
            &mut hs,
        )?
    } else {
        0
    };

    // authData extension output (credBlob / hmac-secret / thirdPartyPayment).
    let mut ext = [0u8; 320];
    let ext_len = encode_ga_extensions(
        req.ext_cred_blob,
        req.ext_third_party_payment,
        sel.as_ref(),
        &hs[..hs_len],
        &mut ext,
    )?;
    let ed = if ext_len > 0 { FLAG_ED } else { 0 };

    // largeBlobKey response field (0x07) — only when the request and the stored
    // credential both opted in.
    let large_blob_key = if req.ext_large_blob_key == Some(true) && sel_large_blob {
        Some(derive_large_blob_key(seed, key_input))
    } else {
        None
    };

    // A U2F/CTAP1 key handle (loaded via the credential_load fallback) signs with
    // its path-as-is scalar (keyderiv::verify_key); fido_load_key rewrites the
    // first path entry for CTAP2 creds.
    let key = if sel.as_ref().is_some_and(|c| c.u2f) {
        let kh = <&[u8; KEY_HANDLE_LEN]>::try_from(&best.id[..best.len])
            .map_err(|_| CtapError::Other)?;
        let mut scalar = verify_key(seed, rp_id_hash, kh).ok_or(CtapError::Other)?;
        let key = CredKey::from_raw(CURVE_P256 as i64, &scalar).ok_or(CtapError::Other)?;
        scalar.zeroize();
        key
    } else {
        let mut raw = fido_load_key(seed, key_input).ok_or(CtapError::Other)?;
        let key = CredKey::from_raw(curve, &raw).ok_or(CtapError::Other)?;
        raw.zeroize();
        key
    };

    // §6.2 user presence. `up` defaults to true; the platform sets up:false for
    // its silent pre-flight (credential discovery), which a spec-compliant key
    // answers with NO touch and the UP flag clear — that is what keeps a WebAuthn
    // login to one touch. The `strict-up` build opts out: it polls the button on
    // every assertion, so an allowList login asks for two touches (one for the
    // pre-flight probe, one for the real assertion). No button configured → the
    // poll confirms instantly. A CTAPHID_CANCEL during the wait surfaces as
    // KEEPALIVE_CANCEL.
    if want_up {
        // The trusted screen (display build) names the relying party AND the
        // account of the credential being used — the anti-phishing payload: a tap
        // can't approve a hidden rp, and the user sees which stored credential
        // signs in. Empty for a credential with no stored user name (older / U2F).
        let account = sel.as_ref().map(|c| c.user_name.as_bytes()).unwrap_or(&[]);
        ctx.require_presence(crate::Confirm::new(
            "Sign in?",
            req.rp_id.as_bytes(),
            account,
        ))?;
    }

    // Spend the pinUvAuthToken now presence was asserted (CTAP 2.1 §6.2.2 / §6.5.5.7
    // triad; GHSA-wqjm-653g-hgw3). Keyed on the raw `up`, NOT want_up: a strict-up
    // pre-flight (up:false) stays inert and must not consume the token, else the real
    // assertion loses its permission.
    ctx.state.consume_after_user_presence_if(req.up);

    // authData = rpIdHash | flags([UP][,UV][,ED]) | counter [| ext] — no attestedCredentialData.
    // Per-credential signature counter: a resident credential reports (and then
    // advances) its own EF_CRED_CTR entry, so an RP can't correlate this key's
    // usage with any OTHER credential. A credential from before EF_CRED_CTR existed
    // has no entry yet and seeds from the frozen global counter (never decreasing).
    // A non-resident credential keeps no on-device state and reports 0.
    let ctr = match best.slot {
        Some(slot) => cred_sign_counter(ctx.fs, slot).unwrap_or_else(|| get_sign_counter(ctx.fs)),
        None => 0,
    };
    let mut ad = [0u8; 37 + 320 + 32];
    ad[..32].copy_from_slice(rp_id_hash);
    // Emit UP from the request's raw `up`, NOT want_up: strict-up still polls the
    // button (above) but an up:false pre-flight must stay inert (UP=0), else the
    // alwaysUv exemption yields a signable assertion (CTAP 2.1 §6.2.2; ssh-sk unaffected).
    let up_flag = if req.up { FLAG_UP } else { 0 };
    ad[32] = up_flag | ed | if uv { FLAG_UV } else { 0 };
    ad[33..37].copy_from_slice(&ctr.to_be_bytes());
    ad[37..37 + ext_len].copy_from_slice(&ext[..ext_len]);
    let ad_len = 37 + ext_len;
    ad[ad_len..ad_len + 32].copy_from_slice(req.client_data_hash);
    let mut sig = [0u8; MAX_SIG_LEN];
    let sig_len = key.sign(&ad[..ad_len + 32], ctx.rng, &mut sig);

    // Response: { 1: {id,type}, 2: authData, 3: sig [, 4: user] [, 5: count] [, 7: largeBlobKey] }.
    // A resident credential's id is its STORED 42-byte resident id (stable across
    // updateUserInformation); a non-resident's is the box itself.
    let cred_id: &[u8] = if best.resident {
        &best.resident_id
    } else {
        &best.id[..best.len]
    };
    // numberOfCredentials and the full user identity are a resident-discovery
    // feature: with an allowList present, CTAP2.1 returns exactly one assertion
    // and no count. `multi` also gates name/displayName.
    let multi = best.found > 1 && req.allow_len == 0;
    let mut fields = 3u64;
    if best.resident {
        fields += 1; // user
    }
    if multi {
        fields += 1; // numberOfCredentials
    }
    if large_blob_key.is_some() {
        fields += 1; // largeBlobKey
    }

    let mut enc = Encoder::new(Cursor::new(&mut *out));
    enc.map(fields)
        .and_then(|e| e.u8(1)?.map(2))
        .and_then(|e| e.str("id")?.bytes(cred_id))
        .and_then(|e| e.str("type")?.str("public-key"))
        .and_then(|e| e.u8(2)?.bytes(&ad[..ad_len]))
        .and_then(|e| e.u8(3)?.bytes(&sig[..sig_len]))
        .map_err(|_| CtapError::Other)?;
    if best.resident {
        // name / displayName are user-identifiable info: returned only on a
        // multi-credential discovery AND only when the user is verified (§6.2.2
        // privacy rule / conformance Discoverable P-2). Without uv → id only.
        let with_name = multi && uv && best.name_len > 0;
        let with_display = multi && uv && best.display_len > 0;
        let entries = 1 + u64::from(with_name) + u64::from(with_display);
        enc.u8(4)
            .and_then(|e| e.map(entries))
            .and_then(|e| e.str("id")?.bytes(&best.user[..best.user_len]))
            .map_err(|_| CtapError::Other)?;
        if with_name {
            let s = core::str::from_utf8(&best.name[..best.name_len]).unwrap_or("");
            enc.str("name")
                .and_then(|e| e.str(s))
                .map_err(|_| CtapError::Other)?;
        }
        if with_display {
            let s = core::str::from_utf8(&best.display[..best.display_len]).unwrap_or("");
            enc.str("displayName")
                .and_then(|e| e.str(s))
                .map_err(|_| CtapError::Other)?;
        }
    }
    if multi {
        // Clamp to what the getNextAssertion queue can actually serve
        // (MAX_ASSERTION_CREDS): over-reporting strands the excess credentials
        // behind a premature NOT_ALLOWED.
        enc.u8(5)
            .and_then(|e| e.u32(best.found.min(MAX_ASSERTION_CREDS as u32)))
            .map_err(|_| CtapError::Other)?;
    }
    if let Some(lbk) = large_blob_key {
        enc.u8(7)
            .and_then(|e| e.bytes(&lbk))
            .map_err(|_| CtapError::Other)?;
    }
    let resp_len = enc.writer().position();

    // Advance the per-credential counter AFTER building the response (so a torn
    // write leaves the old value and never double-reports) — resident only.
    if let Some(slot) = best.slot {
        set_cred_sign_counter(ctx.fs, slot, ctr.wrapping_add(1)).map_err(|_| CtapError::Other)?;
    }
    Ok(resp_len)
}

/// Build the getAssertion authData extension map (credBlob bytes / hmac-secret /
/// thirdPartyPayment) into `out`; returns its length (0 if none apply). `hmac` is
/// the already-evaluated hmac-secret output (empty when not requested). Echoes the
/// selected credential's stored extension data.
fn encode_ga_extensions(
    get_cred_blob: bool,
    third_party_payment: bool,
    sel: Option<&Credential>,
    hmac: &[u8],
    out: &mut [u8],
) -> Result<usize, CtapError> {
    let l = u64::from(get_cred_blob) + u64::from(!hmac.is_empty()) + u64::from(third_party_payment);
    if l == 0 {
        return Ok(0);
    }
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(l).map_err(|_| CtapError::Other)?;
    if get_cred_blob {
        // Echo the stored credBlob (empty byte string if the credential has none).
        let blob = sel.map(|c| c.ext.cred_blob).unwrap_or(&[]);
        enc.str("credBlob")
            .and_then(|e| e.bytes(blob))
            .map_err(|_| CtapError::Other)?;
    }
    if !hmac.is_empty() {
        enc.str("hmac-secret")
            .and_then(|e| e.bytes(hmac))
            .map_err(|_| CtapError::Other)?;
    }
    if third_party_payment {
        let tpp = sel.map(|c| c.ext.third_party_payment).unwrap_or(false);
        enc.str("thirdPartyPayment")
            .and_then(|e| e.bool(tpp))
            .map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// `authenticatorGetNextAssertion`: return the next credential from a
/// multi-credential `getAssertion`, walking the saved EF_CRED slots.
/// `NotAllowed` if there is no carry-over, it is exhausted, or the 30 s window
/// elapsed.
pub fn get_next_assertion<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    if !ctx.state.gna.active || ctx.state.gna.counter >= ctx.state.gna.total {
        return Err(CtapError::NotAllowed);
    }
    if ctx.now_ms.saturating_sub(ctx.state.gna.started_ms) > 30_000 {
        ctx.state.gna.reset();
        return Err(CtapError::NotAllowed);
    }
    let idx = ctx.state.gna.counter as usize;
    let slot = ctx.state.gna.slots[idx];
    let rp_id_hash = ctx.state.gna.rp_id_hash;
    let client_data_hash = ctx.state.gna.client_data_hash;
    let uv = ctx.state.gna.uv;
    let up = ctx.state.gna.up;

    // Re-read the credential record; the resident id is its stored 42-byte prefix.
    let mut rec = [0u8; CRED_REC_MAX];
    let n = match ctx.fs.read(EF_CRED + slot, &mut rec) {
        Some(n) if n.min(rec.len()) >= RECORD_PREFIX => n.min(rec.len()),
        _ => {
            ctx.state.gna.reset();
            return Err(CtapError::NoCredentials);
        }
    };
    if rec[..32] != rp_id_hash {
        ctx.state.gna.reset();
        return Err(CtapError::NoCredentials);
    }
    let mut resident_id = [0u8; CRED_RESIDENT_LEN];
    resident_id.copy_from_slice(&rec[32..RECORD_PREFIX]);

    let mut seed = ctx.load_keydev().ok_or(CtapError::Other)?;
    let result = next_assertion_response(
        ctx,
        cred_record_box(&rec[..n]),
        &resident_id,
        slot,
        &rp_id_hash,
        &client_data_hash,
        uv,
        up,
        &seed,
        out,
    );
    seed.zeroize();
    let resp_len = result?;

    ctx.state.gna.counter += 1;
    if ctx.state.gna.counter >= ctx.state.gna.total {
        ctx.state.gna.reset();
    }
    Ok(resp_len)
}

#[allow(clippy::too_many_arguments)]
fn next_assertion_response<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    cred_box: &[u8],
    resident_id: &[u8],
    slot: u16,
    rp_id_hash: &[u8; 32],
    client_data_hash: &[u8; 32],
    uv: bool,
    up: bool,
    seed: &[u8; 32],
    out: &mut [u8],
) -> CtapResult {
    let mut scratch = [0u8; CRED_REC_MAX];
    let cred = credential_load(seed, cred_box, rp_id_hash, &mut scratch)
        .ok_or(CtapError::NoCredentials)?;
    let curve = cred.curve;
    // getNextAssertion only walks resident discovery, so a v2 credential keys off
    // its stable resident id here too (matching the first assertion's key).
    let key_input = resident_key_input(cred_box, Some(resident_id));

    // getNextAssertion only ever walks a multi-credential resident discovery;
    // name / displayName are user-identifiable and returned only when the user
    // is verified (§6.3 privacy rule), otherwise id only.
    let mut user = [0u8; MAX_USER_ID];
    let user_len = cred.user_id.len().min(MAX_USER_ID);
    user[..user_len].copy_from_slice(&cred.user_id[..user_len]);
    let mut name = [0u8; MAX_USER_NAME];
    let name_len = cred.user_name.len().min(MAX_USER_NAME);
    name[..name_len].copy_from_slice(&cred.user_name.as_bytes()[..name_len]);
    let mut display = [0u8; MAX_USER_NAME];
    let display_len = cred.user_display_name.len().min(MAX_USER_NAME);
    display[..display_len].copy_from_slice(&cred.user_display_name.as_bytes()[..display_len]);

    // Re-evaluate hmac-secret for this credential from the carried request.
    let mut hs = [0u8; SALT_ENC_MAX];
    let hs_len = if ctx.state.gna.hmac_present {
        let g = &ctx.state.gna;
        let (se, sa) = (g.hmac_salt_enc_len as usize, g.hmac_salt_auth_len as usize);
        let (mut salt_enc, mut salt_auth) = ([0u8; SALT_ENC_MAX], [0u8; SALT_AUTH_MAX]);
        salt_enc[..se].copy_from_slice(&g.hmac_salt_enc[..se]);
        salt_auth[..sa].copy_from_slice(&g.hmac_salt_auth[..sa]);
        let req = HmacSecretReq {
            present: true,
            proto: g.hmac_proto,
            peer_x: g.hmac_peer_x,
            peer_y: g.hmac_peer_y,
            salt_enc: &salt_enc[..se],
            salt_auth: &salt_auth[..sa],
        };
        let ephemeral = *ctx.state.ephemeral_scalar();
        hmacsecret::eval(&req, &ephemeral, seed, key_input, uv, ctx.rng, &mut hs)?
    } else {
        0
    };

    // authData extension output (credBlob / hmac-secret / thirdPartyPayment).
    let mut ext = [0u8; 320];
    let ext_len = encode_ga_extensions(
        ctx.state.gna.ext_cred_blob,
        ctx.state.gna.ext_third_party_payment,
        Some(&cred),
        &hs[..hs_len],
        &mut ext,
    )?;
    let ed = if ext_len > 0 { FLAG_ED } else { 0 };

    let mut raw = fido_load_key(seed, key_input).ok_or(CtapError::Other)?;
    let key = CredKey::from_raw(curve, &raw).ok_or(CtapError::Other)?;
    raw.zeroize();

    // getNextAssertion only ever walks resident discovery, so every credential
    // here has an EF_CRED slot and its own signature counter (a legacy credential
    // seeds from the frozen global). See [`get_assertion_inner`].
    let ctr = cred_sign_counter(ctx.fs, slot).unwrap_or_else(|| get_sign_counter(ctx.fs));
    let mut ad = [0u8; 37 + 320];
    ad[..32].copy_from_slice(rp_id_hash);
    let up_flag = if up { FLAG_UP } else { 0 };
    ad[32] = up_flag | ed | if uv { FLAG_UV } else { 0 };
    ad[33..37].copy_from_slice(&ctr.to_be_bytes());
    ad[37..37 + ext_len].copy_from_slice(&ext[..ext_len]);
    let ad_len = 37 + ext_len;
    let mut signed = [0u8; 37 + 320 + 32];
    signed[..ad_len].copy_from_slice(&ad[..ad_len]);
    signed[ad_len..ad_len + 32].copy_from_slice(client_data_hash);
    let mut sig = [0u8; MAX_SIG_LEN];
    let sig_len = key.sign(&signed[..ad_len + 32], ctx.rng, &mut sig);

    // Response: { 1: {id,type}, 2: authData, 3: sig, 4: {id[,name,displayName]} } (no count).
    let with_name = uv && name_len > 0;
    let with_display = uv && display_len > 0;
    let entries = 1 + u64::from(with_name) + u64::from(with_display);
    let mut enc = Encoder::new(Cursor::new(&mut *out));
    enc.map(4)
        .and_then(|e| e.u8(1)?.map(2))
        .and_then(|e| e.str("id")?.bytes(resident_id))
        .and_then(|e| e.str("type")?.str("public-key"))
        .and_then(|e| e.u8(2)?.bytes(&ad[..ad_len]))
        .and_then(|e| e.u8(3)?.bytes(&sig[..sig_len]))
        .and_then(|e| e.u8(4)?.map(entries))
        .and_then(|e| e.str("id")?.bytes(&user[..user_len]))
        .map_err(|_| CtapError::Other)?;
    if with_name {
        let s = core::str::from_utf8(&name[..name_len]).unwrap_or("");
        enc.str("name")
            .and_then(|e| e.str(s))
            .map_err(|_| CtapError::Other)?;
    }
    if with_display {
        let s = core::str::from_utf8(&display[..display_len]).unwrap_or("");
        enc.str("displayName")
            .and_then(|e| e.str(s))
            .map_err(|_| CtapError::Other)?;
    }
    let resp_len = enc.writer().position();
    set_cred_sign_counter(ctx.fs, slot, ctr.wrapping_add(1)).map_err(|_| CtapError::Other)?;
    Ok(resp_len)
}

#[cfg(test)]
#[path = "getassertion_tests.rs"]
mod tests;
