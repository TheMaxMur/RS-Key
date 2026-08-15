// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorClientPIN`: getPINRetries (1), getKeyAgreement (2), setPIN
//! (3), changePIN (4), getPinToken (5) and
//! getPinUvAuthTokenUsingPinWithPermissions (9). The trusted-display build adds
//! built-in user verification — getPinUvAuthTokenUsingUvWithPermissions (6) and
//! getUVRetries (7), where the user types the PIN on the device's own pad so it
//! never reaches the host. The PIN/UV-auth state lives in
//! [`crate::state::FidoState`]. PIN commands never touch the seed's at-rest
//! format (UP-only operations must keep working across power cycles); a
//! successful verify only migrates legacy PIN-wrapped blobs back to plain
//! ([`migrate_keydev_pin`]).

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::pinproto::{self, PinProto};
use rsk_crypto::{Device, sha256};
use rsk_fs::{Fs, Storage};

use crate::cbordec::{cbor, def_map, skip_value};
use crate::consts::{
    CP_GET_PIN_TOKEN, CP_GET_PIN_UV_TOKEN_USING_PIN, EF_DEVICE_PIN, EF_MINPINLEN, EF_PIN,
    MAX_MIN_PIN_RPIDS, MAX_PIN_RETRIES, MIN_PIN_LENGTH, PIN_MISMATCH_LIMIT,
};
use crate::cose::cose_key_ecdh;
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::{clear_ppuat, ensure_ppuat, migrate_keydev_pin};
use crate::state::{PERM_ACFG, PERM_BE, PERM_GA, PERM_MC, PERM_PCMR};
use crate::{Ctx, PinEntry, Rng};

pub(crate) const PIN_FILE_LEN: usize = 35; // retries(1) + len(1) + format(1) + verifier(32)
pub(crate) const PADDED_PIN_LEN: usize = 64;
/// The longest PIN the host clientPIN path can represent: CTAP pads the PIN into a
/// 64-byte buffer that must keep a trailing zero, so 63 bytes is the ceiling (the host
/// rejects a 64th non-zero byte). The device-local set enforces the same cap so a PIN
/// chosen on the panel always stays verifiable over USB too.
pub const MAX_PIN_LENGTH: usize = PADDED_PIN_LEN - 1;

#[derive(Default)]
struct Req<'a> {
    proto: u64,
    subcommand: u64,
    key_agreement: bool,
    kax: &'a [u8],
    kay: &'a [u8],
    pin_uv_auth_param: Option<&'a [u8]>,
    new_pin_enc: Option<&'a [u8]>,
    pin_hash_enc: Option<&'a [u8]>,
    permissions: u64,
    rp_id: Option<&'a str>,
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req::default();
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Keys 1 (pinUvAuthProtocol) and 2 (subCommand) are mandatory and first.
        if expected <= 2 && key != expected {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.proto = cbor(d.u32())? as u64,
            2 => req.subcommand = cbor(d.u32())? as u64,
            3 => {
                req.key_agreement = true;
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.i32())? {
                        -2 => req.kax = cbor(d.bytes())?,
                        -3 => req.kay = cbor(d.bytes())?,
                        // kty (1), crv (-1) and alg (3) are the platform's to get
                        // right: a YubiKey 5.7.4 reads none of the three, and
                        // answers SUCCESS to kty=6, crv=6 and alg=-7 alike.
                        _ => skip_value(&mut d)?,
                    }
                }
            }
            4 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            5 => req.new_pin_enc = Some(cbor(d.bytes())?),
            6 => req.pin_hash_enc = Some(cbor(d.bytes())?),
            9 => req.permissions = cbor(d.u32())? as u64,
            10 => req.rp_id = Some(cbor(d.str())?),
            _ => skip_value(&mut d)?,
        }
    }
    Ok(req)
}

/// A COSE P-256 coordinate: exactly 32 bytes, never left-padded. A short one used
/// to be right-aligned, which rescued a platform whose bignum strips a leading
/// zero — but a YubiKey 5.7.4 refuses 31 *and* 33 bytes with INVALID_PARAMETER at
/// both COSE-parse sites, so the lenience only bought a divergence.
fn coord(src: &[u8]) -> Result<[u8; 32], CtapError> {
    src.try_into().map_err(|_| CtapError::InvalidParameter)
}

/// CTAP 2.1 §6.1.2 / §6.2.2 step 2's protocol gate, shared by makeCredential and
/// getAssertion. A *present* `pinUvAuthProtocol` must name a protocol this build
/// supports — `0` is such a value, not an absence — and a YubiKey 5.7.4 judges it
/// ahead of step 1's selection gesture, with or without a `pinUvAuthParam`.
pub(crate) fn checked_proto(proto: Option<u64>) -> Result<Option<PinProto>, CtapError> {
    proto
        .map(|p| PinProto::from_u64(p).ok_or(CtapError::InvalidParameter))
        .transpose()
}

/// `authenticatorClientPIN`: dispatch the subcommand, writing the response CBOR
/// into `out` and returning its length (0 for set/changePIN, which reply with
/// only the status byte).
pub fn client_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;
    ctx.state.ensure_initialized(ctx.rng);

    // One owner, ahead of the subcommand: a YubiKey 5.7.4 answers INVALID_PARAMETER
    // to an unsupported protocol — `0` included — on getPINRetries, on subcommand
    // `0` and on an undefined subcommand alike, i.e. before it has looked at which
    // one was asked for. The parser has already made key 1 mandatory, so an absent
    // protocol never reaches here.
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;

    match req.subcommand {
        0x0 => Err(CtapError::MissingParameter),
        0x1 => get_pin_retries(ctx, out),
        0x2 => get_key_agreement(ctx, out),
        0x3 => set_pin(ctx, &req, proto, out),
        0x4 => change_pin(ctx, &req, proto, out),
        CP_GET_PIN_TOKEN | CP_GET_PIN_UV_TOKEN_USING_PIN => get_pin_token(ctx, &req, proto, out),
        // Built-in UV (0x06 token / 0x07 retries) exists only where the firmware can
        // collect a PIN on its own UI; elsewhere it is a subcommand this build does
        // not implement, which §8.1 covers along with every undefined value.
        0x6 if ctx.presence.uv_available() => get_uv_token(ctx, &req, proto, out),
        0x7 if ctx.presence.uv_available() => get_uv_retries(ctx, out),
        _ => Err(CtapError::InvalidSubcommand),
    }
}

fn get_pin_retries<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let retries = pin_retries(ctx);
    let pc = ctx.state.needs_power_cycle;
    let len = encode(out, |e| {
        e.map(if pc { 2 } else { 1 })?.u8(3)?.u8(retries)?;
        if pc {
            e.u8(4)?.bool(true)?;
        }
        Ok(())
    })?;
    Ok(len)
}

fn get_key_agreement<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let (x, y) = ctx.state.ephemeral_public().ok_or(CtapError::Other)?;
    let len = encode(out, |e| {
        e.map(1)?.u8(1)?;
        cose_key_ecdh(e, &x, &y)
    })?;
    Ok(len)
}

/// Refines `RSKeySecurityState!NoTokenAfterInvalidation` — SEC-FIDO-003.
fn set_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    proto: PinProto,
    out: &mut [u8],
) -> CtapResult {
    let _ = out;
    require_pin_inputs(req, true, false)?;
    // §6.5.5.5: "If a PIN has already been set, authenticator returns
    // CTAP2_ERR_PIN_AUTH_INVALID error" — changePIN is the only way to replace one.
    if ctx.fs.has_data(EF_PIN) {
        return Err(CtapError::PinAuthInvalid);
    }
    let new_pin_enc = req.new_pin_enc.unwrap();
    let want = PADDED_PIN_LEN + proto.iv_overhead();
    // A padded new PIN longer than 64 bytes means the PIN exceeds the 63-byte
    // maximum → a policy violation, not a malformed request (conformance
    // ClientPin*-Policy F-2; protocol 2's 16-byte IV made this hit the strict
    // length guard and wrongly return INVALID_PARAMETER).
    if new_pin_enc.len() > want {
        return Err(CtapError::PinPolicyViolation);
    }
    if new_pin_enc.len() != want {
        return Err(CtapError::InvalidParameter);
    }
    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    let secret = &shared[..slen];

    if !pinproto::verify(proto, secret, new_pin_enc, req.pin_uv_auth_param.unwrap()) {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }
    let mut padded = [0u8; PADDED_PIN_LEN];
    let dec = pinproto::decrypt(proto, secret, new_pin_enc, &mut padded);
    shared.zeroize();
    if dec.is_err() {
        return Err(CtapError::PinAuthInvalid);
    }
    // No PIN was set, so no `pcmr` grant can be outstanding — except one a build
    // whose wipe still deferred EF_PAUTHTOKEN left behind. Establishing a PIN over
    // that leftover would hand the old holder the credentials created next.
    clear_ppuat(ctx.fs).map_err(|_| CtapError::Other)?;
    let res = store_new_pin(ctx, &padded);
    padded.zeroize();
    res?;
    journal::append(ctx, journal::EV_PIN_SET, 0, &[]);
    Ok(0)
}

/// Refines `RSKeySecurityState!NoTokenAfterInvalidation` — SEC-FIDO-003.
fn change_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    proto: PinProto,
    out: &mut [u8],
) -> CtapResult {
    let _ = out;
    require_pin_inputs(req, true, true)?;
    let pin_hash_enc = req.pin_hash_enc.unwrap();
    let new_pin_enc = req.new_pin_enc.unwrap();
    pin_set_and_unblocked(ctx)?;
    // An over-long padded new PIN is a policy violation (see `set_pin`).
    if new_pin_enc.len() > PADDED_PIN_LEN + proto.iv_overhead() {
        return Err(CtapError::PinPolicyViolation);
    }
    if new_pin_enc.len() != PADDED_PIN_LEN + proto.iv_overhead()
        || pin_hash_enc.len() != 16 + proto.iv_overhead()
    {
        return Err(CtapError::InvalidParameter);
    }
    if ctx.state.needs_power_cycle {
        return Err(CtapError::PinAuthBlocked);
    }
    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    let secret = &shared[..slen];

    // The MAC covers newPinEnc ‖ pinHashEnc (≤ 80 + 32 for protocol 2).
    let mut macd = [0u8; 112];
    macd[..new_pin_enc.len()].copy_from_slice(new_pin_enc);
    macd[new_pin_enc.len()..new_pin_enc.len() + pin_hash_enc.len()].copy_from_slice(pin_hash_enc);
    if !pinproto::verify(
        proto,
        secret,
        &macd[..new_pin_enc.len() + pin_hash_enc.len()],
        req.pin_uv_auth_param.unwrap(),
    ) {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }

    // Verify the old PIN (decrements the counter; mismatch path regenerates).
    let mut old_hash = [0u8; PADDED_PIN_LEN];
    if pinproto::decrypt(proto, secret, pin_hash_enc, &mut old_hash).is_err() {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }
    if let Err(e) = spend_and_verify_pin_hash(ctx, &old_hash[..16]) {
        shared.zeroize();
        old_hash.zeroize();
        return Err(e);
    }
    // The verify migrated any legacy PIN-wrapped seed; the seed itself is
    // PIN-independent, so changing the PIN only swaps the verifier.
    old_hash.zeroize();

    // Decrypt + install the new PIN.
    let mut padded = [0u8; PADDED_PIN_LEN];
    let dec = pinproto::decrypt(proto, secret, new_pin_enc, &mut padded);
    shared.zeroize();
    if dec.is_err() {
        return Err(CtapError::PinAuthInvalid);
    }
    // §6.5.5.6: under a pending forced change the new PIN must actually differ —
    // otherwise re-entering the old one would clear the flag and satisfy nothing.
    if force_change_pending(ctx) {
        let pin_len = padded
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PADDED_PIN_LEN);
        if pin_verifier_matches(ctx, &padded[..pin_len]) {
            padded.zeroize();
            return Err(CtapError::PinPolicyViolation);
        }
    }
    // §6.5.5.6 step 15 calls resetPersistentPinUvAuthToken. Revoke *before* the new
    // verifier lands: a power cut the other way round would leave the old holder's
    // `pcmr` grant live against a PIN they no longer know. A rejected change then
    // costs a re-fetch, which is the cheap direction.
    clear_ppuat(ctx.fs).map_err(|_| CtapError::Other)?;
    let res = store_new_pin(ctx, &padded);
    padded.zeroize();
    res?;
    // The new PIN met minPINLength (store_new_pin), so the change satisfies a
    // pending forced-PIN-change policy.
    clear_force_change(ctx.fs)?;
    ctx.state.reset_pin_uv_auth_token(ctx.rng);
    ctx.state.needs_power_cycle = false;
    journal::append(ctx, journal::EV_PIN_CHANGE, 0, &[]);
    Ok(0)
}

fn get_pin_token<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    proto: PinProto,
    out: &mut [u8],
) -> CtapResult {
    require_pin_inputs(req, false, true)?;
    let permissions = req.permissions as u8;
    if req.subcommand == CP_GET_PIN_TOKEN {
        if req.permissions != 0 || req.rp_id.is_some() {
            return Err(CtapError::InvalidParameter);
        }
    } else {
        // 0x9: getPinUvAuthTokenUsingPinWithPermissions.
        if req.permissions == 0 {
            return Err(CtapError::InvalidParameter);
        }
        if permissions & PERM_BE != 0 {
            return Err(CtapError::UnauthorizedPermission);
        }
        if permissions & PERM_PCMR != 0 && permissions != PERM_PCMR {
            return Err(CtapError::UnauthorizedPermission);
        }
    }
    pin_set_and_unblocked(ctx)?;
    if ctx.state.needs_power_cycle {
        return Err(CtapError::PinAuthBlocked);
    }
    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    // §6.5.5.7.1/.2 place the display's consent between the key agreement and the
    // PIN check, so a decline costs no retry.
    if let Err(e) = consent_for_permissions(ctx, permissions) {
        shared.zeroize();
        return Err(e);
    }
    let secret = &shared[..slen];

    let mut pin_hash = [0u8; PADDED_PIN_LEN];
    if pinproto::decrypt(proto, secret, req.pin_hash_enc.unwrap(), &mut pin_hash).is_err() {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }
    if let Err(e) = spend_and_verify_pin_hash(ctx, &pin_hash[..16]) {
        shared.zeroize();
        pin_hash.zeroize();
        return Err(e);
    }

    pin_hash.zeroize();

    // CTAP 2.1 forced PIN change: while EF_MINPINLEN[1] is set, a successful PIN
    // check still refuses the token until changePIN lifts the flag. The FIDO
    // conformance ClientPin forcePINChange tests assert a DIFFERENT code per
    // subcommand: legacy getPinToken (0x05) → CTAP2_ERR_PIN_INVALID (0x31)
    // (ClientPin1-NewPin F-1 / ClientPin2-GetPinToken F-5); the permissions-based
    // getPinUvAuthTokenUsingPinWithPermissions (0x09) → CTAP2_ERR_PIN_POLICY_VIOLATION
    // (0x37) (ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions F-1). The PIN
    // verify above already succeeded, so the retry counter is untouched either way.
    if force_change_pending(ctx) {
        return Err(if req.subcommand == CP_GET_PIN_TOKEN {
            CtapError::PinInvalid
        } else {
            CtapError::PinPolicyViolation
        });
    }

    // The legacy getPinToken (0x05) grants the fixed mc|ga permission set; the
    // permissions-based variant (0x09) uses exactly what was requested.
    let permissions = if req.subcommand == CP_GET_PIN_TOKEN {
        PERM_MC | PERM_GA
    } else {
        permissions
    };
    let res = issue_token(ctx, proto, secret, permissions, req.rp_id, out);
    shared.zeroize();
    res
}

/// Build the requested pinUvAuthToken, encrypt it under the ECDH `secret`, and
/// write the clientPIN response. Shared by the PIN (0x05/0x09) and the built-in-UV
/// (0x06) token paths once verification has already succeeded — the token itself
/// is identical; only *how* the user verified differs.
/// Refines `RSKeySecurityState!NoLiveTokenWithoutPinRecord` — SEC-FIDO-008.
fn issue_token<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    proto: PinProto,
    secret: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
    out: &mut [u8],
) -> CtapResult {
    // §6.5.5.7.2 step 12 / .3 step 11: a `pcmr` request is answered with the
    // persistent token and stops there — it neither mints nor begins using a
    // session token. Minting it here *is* the permission assignment: the record
    // exists only while some platform holds the grant (`EF_PAUTHTOKEN`).
    let mut pdata = if permissions & PERM_PCMR != 0 {
        ensure_ppuat(&ctx.dev, ctx.fs, ctx.rng).map_err(|_| CtapError::Other)?
    } else {
        ctx.state.reset_pin_uv_auth_token(ctx.rng);
        // §6.5.5.7.3 steps 13/14 are an either/or, and their Note says which one
        // applies "can vary between authenticators": always 14 here, because a
        // `true` would make §6.1.2 step 14 skip the presence request — which on a
        // display build is the screen that names the rp. Step 14's Note allows it.
        ctx.state.begin_using_token(false, ctx.now_ms);
        ctx.state.paut.permissions = permissions;
        match rp_id {
            Some(rp) => {
                ctx.state.paut.rp_id_hash = sha256(rp.as_bytes());
                ctx.state.paut.has_rp_id = true;
            }
            None => ctx.state.paut.has_rp_id = false,
        }
        ctx.state.paut.token
    };

    let mut token_enc = [0u8; 32 + 16];
    // A random IV, as CTAP 2.1 §6.5.7 requires and the `hmac-secret` sibling
    // already did. The hard-coded zero was mostly masked because the token is
    // freshly random per issuance — but not on the `PERM_PCMR` branch, whose token
    // outlives the power cycle, so repeated issuances under one shared secret
    // encrypted identically and were linkable on the wire (audit run-34 #37).
    let mut iv = [0u8; 16];
    ctx.rng.fill(&mut iv);
    let enc = pinproto::encrypt(proto, secret, &iv, &pdata, &mut token_enc);
    pdata.zeroize();
    let enc_len = enc.map_err(|_| CtapError::Other)?;
    ctx.state.needs_power_cycle = false;
    let len = encode(out, |e| {
        e.map(1)?.u8(2)?.bytes(&token_enc[..enc_len])?;
        Ok(())
    })?;
    Ok(len)
}

/// `getPinUvAuthTokenUsingUvWithPermissions` (0x06): the built-in-UV counterpart of
/// the permissions-based PIN token (0x09). Instead of the host sending the PIN, the
/// user verifies on the device's own UI (the trusted-display PIN pad) — the PIN
/// never crosses the host — and the same EF_PIN verifier is checked locally. Only
/// reached on a build that advertises `options.uv` (gated in the dispatch).
fn get_uv_token<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    proto: PinProto,
    out: &mut [u8],
) -> CtapResult {
    require_pin_inputs(req, false, false)?;
    let permissions = req.permissions as u8;
    // WithPermissions: a non-zero permission set is mandatory; bio-enrollment (be)
    // is unsupported, and pcm-readonly (pcmr) may not be combined with anything else.
    if req.permissions == 0 {
        return Err(CtapError::InvalidParameter);
    }
    // §6.5.5.7.3 maps each permission to its own option ID on this path: `be` needs
    // uvBioEnroll and `acfg` needs **uvAcfg** — neither of which this device
    // advertises, so both are unauthorized here even though `authnrCfg` (which gates
    // acfg on the host-PIN path, 0x09) is true.
    if permissions & (PERM_BE | PERM_ACFG) != 0 {
        return Err(CtapError::UnauthorizedPermission);
    }
    if permissions & PERM_PCMR != 0 && permissions != PERM_PCMR {
        return Err(CtapError::UnauthorizedPermission);
    }
    // Readiness first, then consent, then the pad — the order §6.5.5.7.3 lists them
    // in, so a device with no PIN answers NOT_ALLOWED without painting a screen.
    // `builtin_uv` re-checks readiness for its other caller (makeCredential /
    // getAssertion), which reaches it without passing through here.
    builtin_uv_ready(ctx)?;
    consent_for_permissions(ctx, permissions)?;
    builtin_uv(ctx)?;

    // A pending forced PIN change still blocks token issuance (changePIN first).
    if force_change_pending(ctx) {
        return Err(CtapError::PinPolicyViolation);
    }

    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    let res = issue_token(ctx, proto, &shared[..slen], permissions, req.rp_id, out);
    shared.zeroize();
    res
}

/// The outcome of the CTAP 2.1 §6.1.2 / §6.2.2 user-verification step: whether the
/// response carries the `uv` flag, and whether the built-in UV ceremony already
/// supplied evidence of user interaction — §6.1.2 step 13 / §6.2.2 step 8 then set
/// `up` without asking for a second gesture.
#[derive(Clone, Copy)]
pub(crate) struct UvOutcome {
    pub uv: bool,
    pub up_collected: bool,
}

impl UvOutcome {
    /// No user verification was performed.
    pub const NONE: Self = Self {
        uv: false,
        up_collected: false,
    };
    /// A `pinUvAuthParam` verified against the pinUvAuthToken.
    pub const TOKEN: Self = Self {
        uv: true,
        up_collected: false,
    };
    /// Built-in UV ran on the device's own pad.
    pub const BUILTIN: Self = Self {
        uv: true,
        up_collected: true,
    };

    /// Whether the ceremony still owes its `Confirm` screen. Built-in UV supplies the
    /// *gesture* (§6.1.2 step 13 / §6.2.2 step 8), but on a backend that paints what it
    /// is asking about it cannot supply the *disclosure*: `collect_pin` takes no
    /// `Confirm`, and `PinPad.title` is trusted `&'static str` by construction, so the
    /// pad can never name a relying party. Skipping the card there would let a host
    /// trade one context-free PIN entry for an assertion over an rp the user never saw
    /// (audit run-28). The spec permits the second screen — it only excuses the second
    /// *gesture* — so paint it whenever the backend has one.
    pub fn needs_confirm(self, shows_confirm: bool) -> bool {
        !self.up_collected || shows_confirm
    }
}

/// Run [`builtin_uv`] as the ceremonies' UV step (§6.1.2 step 11.2, §6.2.2 step
/// 6.2) and map its outcome. The spec's error ladder collapses here: `clientPin`
/// is true whenever the pad is configured (built-in UV verifies the same EF_PIN),
/// so every remaining failure — a wrong PIN, an exhausted budget — is
/// PUAT_REQUIRED. A CTAPHID_CANCEL keeps its transport-level code.
///
/// ONE deliberate divergence: an explicit Deny on the pad ([`PinEntry::Declined`],
/// the only source of `OperationDenied` here) keeps that code instead of becoming
/// PUAT_REQUIRED. The ladder would tell the platform to collect the PIN over USB
/// instead, turning the trusted display's refusal into a prompt the user just
/// declined — the panel's veto has to be final, or it is not a veto.
pub(crate) fn builtin_uv_step<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
) -> Result<UvOutcome, CtapError> {
    match builtin_uv(ctx) {
        Ok(()) => Ok(UvOutcome::BUILTIN),
        Err(
            e @ (CtapError::UserActionTimeout
            | CtapError::KeepAliveCancel
            | CtapError::OperationDenied),
        ) => Err(e),
        Err(_) => Err(CtapError::PuatRequired),
    }
}

/// Whether built-in UV can run at all, in the dialect §6.5.5.7.3 uses: a method that
/// is supported but not configured is `NOT_ALLOWED`, and an exhausted budget is
/// `UV_BLOCKED` — where the host-PIN path reports PIN_NOT_SET / PIN_BLOCKED for the
/// very same states. Built-in UV shares EF_PIN and its counter with clientPIN.
fn builtin_uv_ready<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> Result<(), CtapError> {
    if !ctx.fs.has_data(EF_PIN) {
        return Err(CtapError::NotAllowed);
    }
    if pin_retries(ctx) == 0 || ctx.state.needs_power_cycle {
        return Err(CtapError::UvBlocked);
    }
    Ok(())
}

/// §6.5.5.7: "If the authenticator has a display, request user consent for the
/// requested permissions. If this is not approved, return CTAP2_ERR_OPERATION_DENIED."
/// Gated on `shows_confirm` — the same "has a display" test `authenticatorReset` uses
/// for its §6.6 exemption — so a screenless build never polls its button here.
///
/// `pcmr` is named on the card because it is not a session grant: it mints a flash record
/// that outlives every power cycle until a PIN change or a reset, and on the built-in-UV
/// path (0x06) the host sends no PIN, so this screen is the whole disclosure. One title
/// for both would have the user approve it exactly as they approve a ten-minute `mc|ga`
/// token (audit run-37).
fn consent_for_permissions<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    permissions: u8,
) -> Result<(), CtapError> {
    let title = if permissions & PERM_PCMR != 0 {
        "Always list passkeys?"
    } else {
        "Allow host access?"
    };
    if ctx.presence.shows_confirm() && !ctx.check_user_presence(crate::Confirm::titled(title)) {
        return Err(CtapError::OperationDenied);
    }
    Ok(())
}

/// The `uv` option ID (CTAP 2.1 §6.4): the backend has a PIN pad of its own AND a
/// PIN is configured, i.e. built-in user verification is both capable and
/// "presently configured". `false` on every screenless build.
pub(crate) fn builtin_uv_enabled<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> bool {
    ctx.presence.uv_available() && ctx.fs.has_data(EF_PIN)
}

/// `performBuiltInUv(internalRetry = true)` — the spec's built-in user
/// verification ceremony, shared by clientPIN 0x06 and the makeCredential /
/// getAssertion `uv` option (§6.1.2 step 11.2, §6.2.2 step 6.2). Built-in UV
/// verifies the same EF_PIN as clientPIN and shares its retry budget. A short
/// entry (below minPINLength) is refused by the pad without a verify, so it can't
/// burn a retry; an actual mismatch does, exactly like a host PIN.
fn builtin_uv<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> Result<(), CtapError> {
    builtin_uv_ready(ctx)?;
    let min = min_pin_length(ctx.fs) as usize;
    let mut pin = [0u8; PADDED_PIN_LEN];
    let entry = ctx.presence.collect_pin(min, &mut pin);
    let verified = perform_builtin_uv(ctx, entry, &pin);
    pin.zeroize();
    verified
}

/// Verify a PIN entered via built-in UV against EF_PIN, mapping the entry outcome
/// and translating the host-PIN error dialect of [`spend_and_verify_pin_hash`] into the
/// built-in-UV codes a platform expects (UV_INVALID / UV_BLOCKED). A non-entry
/// (decline / timeout / cancel) returns before the verify, so it never spends a
/// retry; only a real mismatch does.
fn perform_builtin_uv<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    entry: PinEntry,
    pin: &[u8],
) -> Result<(), CtapError> {
    let len = match entry {
        PinEntry::Entered(len) => len.min(pin.len()),
        PinEntry::Declined => return Err(CtapError::OperationDenied),
        PinEntry::Timeout => return Err(CtapError::UserActionTimeout),
        PinEntry::Cancelled => return Err(CtapError::KeepAliveCancel),
        PinEntry::Unsupported => return Err(CtapError::UnsupportedOption),
    };
    let mut dhash = sha256(&pin[..len]);
    let res = spend_and_verify_pin_hash(ctx, &dhash[..16]);
    dhash.zeroize();
    res.map_err(|e| match e {
        CtapError::PinInvalid => CtapError::UvInvalid,
        CtapError::PinBlocked | CtapError::PinAuthBlocked => CtapError::UvBlocked,
        other => other,
    })
}

/// `getUVRetries` (0x07): the built-in-UV retry budget. Built-in UV verifies the
/// same EF_PIN as clientPIN and shares its counter, so this mirrors getPINRetries
/// (response key 0x05 `uvRetries`, plus 0x04 `powerCycleState` while soft-locked).
fn get_uv_retries<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let retries = pin_retries(ctx);
    let pc = ctx.state.needs_power_cycle;
    let len = encode(out, |e| {
        e.map(if pc { 2 } else { 1 })?.u8(5)?.u8(retries)?;
        if pc {
            e.u8(4)?.bool(true)?;
        }
        Ok(())
    })?;
    Ok(len)
}

// --- helpers --------------------------------------------------------------

/// The retry counter from EF_PIN, or the full budget if no PIN is set.
fn pin_retries<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> u8 {
    let mut buf = [0u8; PIN_FILE_LEN];
    match ctx.fs.read(EF_PIN, &mut buf) {
        Some(n) if n >= 1 => buf[0],
        _ => MAX_PIN_RETRIES,
    }
}

fn pin_set_and_unblocked<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> Result<(), CtapError> {
    if !ctx.fs.has_data(EF_PIN) {
        return Err(CtapError::PinNotSet);
    }
    if pin_retries(ctx) == 0 {
        return Err(CtapError::PinBlocked);
    }
    Ok(())
}

/// Common presence checks for set/change/getToken; returns the protocol.
/// `need_new_pin` (set/change) also requires `pinUvAuthParam`; getPinToken carries
/// neither.
fn require_pin_inputs(req: &Req, need_new_pin: bool, need_pin_hash: bool) -> Result<(), CtapError> {
    let missing = !req.key_agreement
        || req.kax.is_empty()
        || req.kay.is_empty()
        || (need_new_pin && (req.new_pin_enc.is_none() || req.pin_uv_auth_param.is_none()))
        || (need_pin_hash && req.pin_hash_enc.is_none());
    if missing {
        return Err(CtapError::MissingParameter);
    }
    Ok(())
}

fn derive_shared<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    proto: PinProto,
    out: &mut [u8; 64],
) -> Result<usize, CtapError> {
    let kax = coord(req.kax)?;
    let kay = coord(req.kay)?;
    pinproto::ecdh(proto, ctx.state.ephemeral_scalar(), &kax, &kay, out)
        .map_err(|_| CtapError::InvalidParameter)
}

/// Compare a candidate 16-byte PIN hash against the stored verifier. Decrements
/// the retry counter first; on mismatch applies the lockout ladder.
/// Refines `RSKeySecurityState!NoAuthorizationBypass` — SEC-FIDO-001.
fn spend_and_verify_pin_hash<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    pin_hash: &[u8],
) -> Result<(), CtapError> {
    let mut pin_data = [0u8; PIN_FILE_LEN];
    let n = ctx
        .fs
        .read(EF_PIN, &mut pin_data)
        .ok_or(CtapError::PinNotSet)?;
    if n != PIN_FILE_LEN {
        return Err(CtapError::Other);
    }
    // Self-defend the decrement rather than trusting the external
    // pin_set_and_unblocked() gate: release builds have no overflow-checks, so a
    // future caller reaching here at 0 would wrap the retry budget to 255. The
    // sibling spend_and_verify_pin_at has the same in-function guard.
    if pin_data[0] == 0 {
        return Err(CtapError::PinBlocked);
    }
    pin_data[0] -= 1;
    ctx.fs
        .put(EF_PIN, &pin_data)
        .map_err(|_| CtapError::Other)?;
    // Read the decremented counter back before trusting it. This single flash
    // write is the anti-bruteforce gate; a glitch or partial program during put()
    // could persist the old (higher) count while RAM marches on, silently widening
    // the retry budget. If the stored value doesn't match, fail closed (treat as
    // blocked) rather than continue on an unverified count — the same read-back the
    // OTP fuse writes already do (firmware/src/otp_keys.rs).
    let mut readback = [0u8; PIN_FILE_LEN];
    match ctx.fs.read(EF_PIN, &mut readback) {
        Some(PIN_FILE_LEN) if readback[0] == pin_data[0] => {}
        _ => return Err(CtapError::PinBlocked),
    }
    let retries = pin_data[0];

    let cand = ctx.dev.pin_derive_verifier(pin_hash);
    let mut matched = pinproto_ct_eq(&cand, &pin_data[3..PIN_FILE_LEN]);
    let mut migrated = false;
    if !matched && ctx.dev.otp_key.is_some() {
        // Kbase-migration fallback: a verifier stored before the OTP key was
        // provisioned. A match under the pre-OTP arm is the correct PIN — the
        // seed migrates below before the verifier is rewritten, so a crash
        // between the two re-runs this path on the next verify.
        let cand_old = ctx.dev.without_otp().pin_derive_verifier(pin_hash);
        if pinproto_ct_eq(&cand_old, &pin_data[3..PIN_FILE_LEN]) {
            pin_data[3..PIN_FILE_LEN].copy_from_slice(&cand);
            matched = true;
            migrated = true;
        }
    }
    if !matched {
        ctx.state.regenerate(ctx.rng);
        // A YubiKey 5.7.4 drops any outstanding pinUvAuthToken here too, through
        // all three doors (0x05, 0x09, changePIN's old-PIN check) — measured ×4
        // each, with getKeyAgreement / getPINRetries / idle as the controls that
        // leave it alive. CTAP 2.0 §5.6.6 and 2.1 name only the key
        // regeneration, so this is the card's rule, and the safe direction: a
        // token minted before someone started guessing stops working, and a
        // platform can always mint another.
        ctx.state.reset_pin_uv_auth_token(ctx.rng);
        if retries == 0 {
            // The transition into the hard lockout (later attempts are turned
            // away before the verify, so this records exactly once).
            journal::append(ctx, journal::EV_PIN_LOCKOUT, 0, &[]);
            return Err(CtapError::PinBlocked);
        }
        ctx.state.new_pin_mismatches += 1;
        if ctx.state.new_pin_mismatches >= PIN_MISMATCH_LIMIT {
            ctx.state.needs_power_cycle = true;
            journal::append(ctx, journal::EV_PIN_LOCKOUT, 1, &[]);
            return Err(CtapError::PinAuthBlocked);
        }
        return Err(CtapError::PinInvalid);
    }

    // Correct PIN: migrate a legacy PIN-wrapped seed to the plain format (the
    // only moment its outer layer is open), then reset the counter.
    migrate_keydev_pin(&ctx.dev, ctx.fs, pin_hash).map_err(|_| CtapError::Other)?;
    pin_data[0] = MAX_PIN_RETRIES;
    ctx.state.new_pin_mismatches = 0;
    ctx.fs
        .put(EF_PIN, &pin_data)
        .map_err(|_| CtapError::Other)?;
    // The record we just superseded was keyed under the pre-OTP arm, i.e. under
    // HKDF("NO-OTP", serial_hash) — derivable from the public chip serial. The
    // one-shot at-rest lap has already run by now, so re-arm it or that copy stays
    // in the flash ring as an offline dictionary target (rsk-fs `EF_HARDENED`
    // invariant; audit run-35 found four of five lazy re-keys skipping this).
    if migrated {
        rsk_fs::request_rescrub(ctx.fs);
    }
    Ok(())
}

/// Hash the PIN, derive its device-sealed verifier, and persist it to `EF_PIN` with a
/// fresh retry budget — the storage core shared by the host set/change path
/// ([`store_new_pin`]) and the device-local set ([`store_local_pin`]). It enforces no
/// policy and touches no CTAP session state; the callers do. The seed is not touched —
/// it stays kbase-only so UP-only operations keep working.
///
/// Establishing a clientPIN also runs §6.5.5.6 step 15's `resetPersistentPinUvAuthToken`,
/// here rather than in each caller: the `pcmr` grant is a flash record that no PIN
/// derives, so a writer that forgot left it authorizing credential-directory reads for
/// ever — which is what the on-pad change did (audit run-37). `EF_DEVICE_PIN` is a
/// different credential and grants nothing, so it revokes nothing.
fn write_pin_verifier<S: Storage>(
    fid: u16,
    dev: &Device,
    fs: &mut Fs<S>,
    pin: &[u8],
    code_points: usize,
) -> Result<(), CtapError> {
    // Before the new verifier lands, never after: a power cut the other way round
    // leaves the old holder's grant live against a PIN they no longer know.
    if fid == EF_PIN {
        clear_ppuat(fs).map_err(|_| CtapError::Other)?;
    }
    let mut dhash = sha256(pin);
    let mut pin_data = [0u8; PIN_FILE_LEN];
    pin_data[0] = MAX_PIN_RETRIES;
    // PINCodePointLength (§6.5.5.5) — what `setMinPINLength` compares its new floor
    // against, so it must be code points like the floor itself.
    pin_data[1] = code_points as u8;
    pin_data[2] = 1; // verifier format 1
    pin_data[3..].copy_from_slice(&dev.pin_derive_verifier(&dhash[..16]));
    dhash.zeroize();
    fs.put(fid, &pin_data).map_err(|_| CtapError::Other)
}

/// Whether `pin` is the PIN currently stored in EF_PIN. Unlike
/// [`spend_and_verify_pin_hash`] this costs no retry and has no session side effects —
/// it exists only for §6.5.5.6's "the new PIN must differ" check, where a match is a
/// policy violation rather than an authentication attempt.
fn pin_verifier_matches<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, pin: &[u8]) -> bool {
    let mut pin_data = [0u8; PIN_FILE_LEN];
    if ctx.fs.read(EF_PIN, &mut pin_data) != Some(PIN_FILE_LEN) {
        return false;
    }
    let mut dhash = sha256(pin);
    let cand = ctx.dev.pin_derive_verifier(&dhash[..16]);
    dhash.zeroize();
    pinproto_ct_eq(&cand, &pin_data[3..PIN_FILE_LEN])
}

/// The PIN's length in Unicode code points — the unit `minPINLength` (getInfo 0x0D)
/// and `PINCodePointLength` are defined in. `None` when the bytes are not UTF-8, so
/// the caller can refuse rather than fall back to a byte count that over-measures
/// every non-ASCII PIN.
fn pin_code_points(pin: &[u8]) -> Option<usize> {
    Some(core::str::from_utf8(pin).ok()?.chars().count())
}

/// A trivially guessable PIN — a single repeated code point (`000000`) or a ±1 run
/// (`123456` / `654321`) — refused by the `strong-pin` / `fips-profile` builds atop the
/// length floor. `pub` so the trusted-display PIN pad rejects them at entry too.
#[cfg(any(feature = "strong-pin", feature = "fips-profile"))]
pub fn pin_is_trivial(pin: &[u8]) -> bool {
    pin.len() >= 2
        && (pin.iter().all(|&b| b == pin[0])
            || pin.windows(2).all(|w| w[0].checked_add(1) == Some(w[1]))
            || pin.windows(2).all(|w| w[1].checked_add(1) == Some(w[0])))
}

/// Validate the padded new PIN and store the EF_PIN verifier (the host setPIN/changePIN
/// path).
fn store_new_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    padded: &[u8; PADDED_PIN_LEN],
) -> Result<(), CtapError> {
    if padded[PADDED_PIN_LEN - 1] != 0 {
        return Err(CtapError::PinPolicyViolation);
    }
    let pin_len = padded
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(PADDED_PIN_LEN);
    // minPINLength is counted in Unicode code points (getInfo 0x0D), not UTF-8 bytes:
    // measuring bytes lets a 2-character CJK PIN clear a floor of 4. A PIN that is not
    // UTF-8 cannot be counted at all — refused under §6.5.5.5's "arbitrary, additional
    // constraints" allowance.
    let cps = pin_code_points(&padded[..pin_len]).ok_or(CtapError::PinPolicyViolation)?;
    if cps < min_pin_length(ctx.fs) as usize {
        return Err(CtapError::PinPolicyViolation);
    }
    #[cfg(any(feature = "strong-pin", feature = "fips-profile"))]
    if pin_is_trivial(&padded[..pin_len]) {
        return Err(CtapError::PinPolicyViolation);
    }
    write_pin_verifier(EF_PIN, &ctx.dev, ctx.fs, &padded[..pin_len], cps)?;
    ctx.state.needs_power_cycle = false;
    Ok(())
}

/// The configured minimum PIN length (`EF_MINPINLEN[0]`), or the CTAP default when no
/// policy is set. Takes `Fs` directly (not a `Ctx`) so the trusted-display set-PIN flow
/// can read the floor it must enforce without a `Ctx` it does not hold.
pub fn min_pin_length<S: Storage>(fs: &mut Fs<S>) -> u8 {
    let mut buf = [0u8; 2];
    match fs.read(EF_MINPINLEN, &mut buf) {
        Some(n) if n >= 1 => buf[0],
        _ => MIN_PIN_LENGTH,
    }
}

/// The pending forced-PIN-change flag (`EF_MINPINLEN[1]`).
fn force_change_pending<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> bool {
    let mut buf = [0u8; 2];
    matches!(ctx.fs.read(EF_MINPINLEN, &mut buf), Some(n) if n >= 2 && buf[1] != 0)
}

/// A successful changePIN satisfies the policy: drop the flag, keep the
/// minimum and the RP-id hash list (EF_MINPINLEN = [min, force, hashes…]).
fn clear_force_change<S: Storage>(fs: &mut Fs<S>) -> Result<(), CtapError> {
    let mut buf = [0u8; 2 + 32 * MAX_MIN_PIN_RPIDS];
    if let Some(n) = fs.read(EF_MINPINLEN, &mut buf)
        && n >= 2
        && buf[1] != 0
    {
        buf[1] = 0;
        fs.put(EF_MINPINLEN, &buf[..n])
            .map_err(|_| CtapError::Other)?;
    }
    Ok(())
}

fn pinproto_ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

/// Outcome of a device-local PIN verify ([`spend_and_verify_local_pin`]).
pub enum LocalPin {
    /// Correct PIN; the retry counter was reset to the full budget.
    Ok,
    /// Wrong PIN; `retries_left` attempts remain before the hard lock.
    Wrong { retries_left: u8 },
    /// No PIN set, the retry budget is spent, or a flash glitch was caught on
    /// read-back — the gated action must not proceed.
    Blocked,
}

/// Why a device-local PIN set/change ([`store_local_pin`]) was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SetPinError {
    /// The new PIN is shorter than the configured `minPINLength`; `min` is that floor.
    TooShort { min: u8 },
    /// The new PIN is longer than [`MAX_PIN_LENGTH`] — the host clientPIN path could not
    /// represent it, so it is refused here too; `max` is that ceiling.
    TooLong { max: u8 },
    /// The `EF_PIN` write failed (flash error) — no PIN was stored.
    Storage,
}

/// Whether a clientPIN is set. The trusted display gates a destructive local
/// action behind the PIN only when one exists (otherwise the hold gesture alone
/// stands in for user verification).
pub fn pin_is_set<S: Storage>(fs: &mut Fs<S>) -> bool {
    fs.has_data(EF_PIN)
}

/// The PIN's remaining retry budget (the `EF_PIN` counter), or `None` when no PIN is
/// set. Read-only — unlike [`spend_and_verify_local_pin`] it never decrements — so the trusted
/// display can show "N tries remaining" up front on the unlock pad without spending a
/// try. It is the same persistent counter the host clientPIN path enforces.
pub fn pin_retries_left<S: Storage>(fs: &mut Fs<S>) -> Option<u8> {
    retries_left_at(EF_PIN, fs)
}

/// Whether the trusted-display **device PIN** ([`EF_DEVICE_PIN`]) is set. The display
/// boot-locks and gates its destructive on-device actions on this, not the FIDO clientPIN.
pub fn device_pin_is_set<S: Storage>(fs: &mut Fs<S>) -> bool {
    fs.has_data(EF_DEVICE_PIN)
}

/// The device PIN's remaining retry budget (read-only, like [`pin_retries_left`]).
pub fn device_pin_retries_left<S: Storage>(fs: &mut Fs<S>) -> Option<u8> {
    retries_left_at(EF_DEVICE_PIN, fs)
}

/// Read the retry counter from a PIN record (`fid`'s byte 0) without decrementing it.
fn retries_left_at<S: Storage>(fid: u16, fs: &mut Fs<S>) -> Option<u8> {
    let mut pin_data = [0u8; PIN_FILE_LEN];
    let out = match fs.read(fid, &mut pin_data) {
        Some(PIN_FILE_LEN) => Some(pin_data[0]),
        _ => None,
    };
    pin_data.zeroize();
    out
}

/// Verify a PIN typed on the device's own pad for a display-initiated action (a
/// local Passkeys delete — there is no host and no CTAP session). It reuses
/// `spend_and_verify_pin_hash`'s persistent anti-bruteforce gate verbatim — the EF_PIN
/// retry counter is decremented before the compare and read back fail-closed, a
/// correct PIN resets it and migrates a legacy PIN-wrapped seed, a wrong attempt
/// at zero is a hard block — but deliberately omits the CTAP-session side effects
/// (`state.regenerate`, the RAM 3-strikes power-cycle lock, the journal) that are
/// meaningless off the host path and need a `Ctx` the display task does not hold.
/// The persistent 8-try counter is the real gate and is identical here, so this
/// opens no faster path to grind the PIN than USB already does. The caller
/// zeroizes `pin`.
pub fn spend_and_verify_local_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    pin: &[u8],
) -> LocalPin {
    spend_and_verify_pin_at(EF_PIN, dev, fs, pin, true)
}

/// Verify the trusted-display **device PIN** ([`EF_DEVICE_PIN`]) — the same fail-closed
/// retry-counter gate as [`spend_and_verify_local_pin`], but against the device PIN's own record and
/// **without** the seed migration (the device PIN never wraps the seed; that is the FIDO
/// clientPIN's job). Used by the display lock / on-device delete / factory-reset gates.
pub fn spend_and_verify_device_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    pin: &[u8],
) -> LocalPin {
    spend_and_verify_pin_at(EF_DEVICE_PIN, dev, fs, pin, false)
}

/// Shared core for the device-local PIN verifies. Reads `fid`'s `[retries, len, format,
/// verifier]` record, decrements the counter **before** the compare and reads it back
/// fail-closed, resets it on a match, and (only when `migrate_seed`) migrates a legacy
/// PIN-wrapped seed — the EF_PIN path keeps that; the device PIN does not. The caller
/// zeroizes `pin`.
fn spend_and_verify_pin_at<S: Storage>(
    fid: u16,
    dev: &Device,
    fs: &mut Fs<S>,
    pin: &[u8],
    migrate_seed: bool,
) -> LocalPin {
    let mut pin_data = [0u8; PIN_FILE_LEN];
    let Some(n) = fs.read(fid, &mut pin_data) else {
        return LocalPin::Blocked;
    };
    if n != PIN_FILE_LEN || pin_data[0] == 0 {
        return LocalPin::Blocked;
    }
    pin_data[0] -= 1;
    if fs.put(fid, &pin_data).is_err() {
        return LocalPin::Blocked;
    }
    // Trust the decremented counter only after reading it back — the same
    // fail-closed anti-glitch gate `spend_and_verify_pin_hash` applies (a torn program could
    // otherwise persist the old, higher count while RAM marched on).
    let mut readback = [0u8; PIN_FILE_LEN];
    match fs.read(fid, &mut readback) {
        Some(PIN_FILE_LEN) if readback[0] == pin_data[0] => {}
        _ => return LocalPin::Blocked,
    }
    let retries = pin_data[0];

    let mut pin_hash = sha256(pin);
    let cand = dev.pin_derive_verifier(&pin_hash[..16]);
    let mut matched = pinproto_ct_eq(&cand, &pin_data[3..PIN_FILE_LEN]);
    let mut migrated = false;
    if !matched && dev.otp_key.is_some() {
        // Pre-OTP verifier fallback, identical to `spend_and_verify_pin_hash`.
        let cand_old = dev.without_otp().pin_derive_verifier(&pin_hash[..16]);
        if pinproto_ct_eq(&cand_old, &pin_data[3..PIN_FILE_LEN]) {
            pin_data[3..PIN_FILE_LEN].copy_from_slice(&cand);
            matched = true;
            migrated = true;
        }
    }
    if !matched {
        pin_hash.zeroize();
        if retries == 0 {
            return LocalPin::Blocked;
        }
        return LocalPin::Wrong {
            retries_left: retries,
        };
    }

    // Correct PIN: for the FIDO clientPIN, migrate a legacy PIN-wrapped seed (only
    // openable now) before resetting the counter; the device PIN has no seed to migrate.
    // Fail closed if a required flash write fails.
    if migrate_seed {
        let seed_ok = migrate_keydev_pin(dev, fs, &pin_hash[..16]).is_ok();
        pin_hash.zeroize();
        if !seed_ok {
            return LocalPin::Blocked;
        }
    } else {
        pin_hash.zeroize();
    }
    pin_data[0] = MAX_PIN_RETRIES;
    if fs.put(fid, &pin_data).is_err() {
        return LocalPin::Blocked;
    }
    // See `spend_and_verify_pin_hash`: the superseded pre-OTP verifier is derivable
    // from the public chip serial, and the one-shot at-rest lap has already run.
    if migrated {
        rsk_fs::request_rescrub(fs);
    }
    LocalPin::Ok
}

/// Set or replace the device PIN from the trusted display (the on-device Set / Change
/// PIN flow). Writes the same `EF_PIN` verifier the host setPIN/changePIN path stores —
/// device-sealed, format 1, with a fresh retry budget — so the host afterwards sees a
/// clientPIN exactly as if it had been set over USB. It enforces both `minPINLength` and
/// the host-representable [`MAX_PIN_LENGTH`] ceiling (so a panel-set PIN stays usable over
/// USB). The flash-backed `pcmr` grant dies with the old PIN inside
/// `write_pin_verifier`. What is left to the caller is the RAM session token: `FidoState`
/// lives in the worker and outlives every dispatch, so a token minted under the old PIN
/// would keep `PERM_CM` authority (and `deleteCredential` takes no touch) for up to
/// `PUAT_MAX_USAGE_PERIOD_MS` after the owner believes they locked the host out. The
/// firmware caller MUST signal that — see `firmware::display::note_local_pin_changed`. It
/// does not journal the change either (no [`Ctx`]). The CALLER verifies the
/// *current* PIN first when one is set (so a change still proves knowledge of the old
/// PIN) and zeroizes `pin`. A pending forced-PIN-change flag is cleared best-effort
/// since a satisfied new PIN meets the policy.
pub fn store_local_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    pin: &[u8],
) -> Result<(), SetPinError> {
    let min = min_pin_length(fs);
    // Counted in code points, like the host path — the pad types ASCII digits today,
    // but the floor is defined that way and the two must not drift apart.
    let cps = pin_code_points(pin).ok_or(SetPinError::TooShort { min })?;
    if (cps as u8) < min {
        return Err(SetPinError::TooShort { min });
    }
    if pin.len() > MAX_PIN_LENGTH {
        return Err(SetPinError::TooLong {
            max: MAX_PIN_LENGTH as u8,
        });
    }
    write_pin_verifier(EF_PIN, dev, fs, pin, cps).map_err(|_| SetPinError::Storage)?;
    // The new PIN meets the policy, so drop any pending forced-change marker. The PIN is
    // already stored, so a flash hiccup here is benign (a stale flag only re-prompts a
    // change on the host) — don't fail the set over it.
    let _ = clear_force_change(fs);
    Ok(())
}

/// Set or replace the trusted-display **device PIN** ([`EF_DEVICE_PIN`]) — the same
/// device-sealed, format-1 verifier with a fresh retry budget as the FIDO clientPIN, but
/// in its own record and **independent** of it (no `minPINLength` policy, no forced-change
/// flag — those are FIDO-side; the device PIN's floor is the fixed [`MIN_PIN_LENGTH`]).
/// The caller verifies the *current* device PIN first when one is set, and zeroizes `pin`.
pub fn store_device_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    pin: &[u8],
) -> Result<(), SetPinError> {
    let cps = pin_code_points(pin).ok_or(SetPinError::TooShort {
        min: MIN_PIN_LENGTH,
    })?;
    if (cps as u8) < MIN_PIN_LENGTH {
        return Err(SetPinError::TooShort {
            min: MIN_PIN_LENGTH,
        });
    }
    if pin.len() > MAX_PIN_LENGTH {
        return Err(SetPinError::TooLong {
            max: MAX_PIN_LENGTH as u8,
        });
    }
    write_pin_verifier(EF_DEVICE_PIN, dev, fs, pin, cps).map_err(|_| SetPinError::Storage)
}

fn encode<F>(out: &mut [u8], f: F) -> Result<usize, CtapError>
where
    F: FnOnce(
        &mut Encoder<Cursor<&mut [u8]>>,
    ) -> Result<(), minicbor::encode::Error<minicbor::encode::write::EndOfSlice>>,
{
    let mut enc = Encoder::new(Cursor::new(out));
    f(&mut enc).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

#[cfg(test)]
#[path = "clientpin_tests.rs"]
mod tests;
