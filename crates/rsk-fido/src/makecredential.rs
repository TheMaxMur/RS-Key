// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorMakeCredential`: every credential ships packed **basic**
//! attestation — ES256 over authData ‖ clientDataHash by the device key, with the
//! per-device cert as the x5c leaf. Self-attestation and `fmt:"none"` were both
//! tried and both break clients: an empty statement is rejected by OpenSSH < 10.0
//! and a packed EdDSA self-attestation fails on Windows/WinHello (issue #26).
//! Resident keys (rk) are stored; non-resident credentials carry the full box in
//! authData. A configured PIN requires a verified `pinUvAuthParam`
//! (`enforce_pin`), which sets the `uv` flag — except for a non-discoverable
//! credential, which `makeCredUvNotRqd` lets through on presence alone. Request
//! extensions are sealed into the box and echoed in the authData extension
//! output (ED flag); excludeList is credProtect-aware. Enterprise attestation
//! (request field 0x0A): level 2 emits a full attestation signed by the device
//! key with its x5c cert and the `ep` response flag; level 1 is accepted but
//! stays self-attestation.

use minicbor::encode::Write;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::MLDSA65_PK_LEN;
use rsk_crypto::sha256;
use rsk_fs::{Fs, Storage};

use crate::cbordec::{cbor, def_arr, def_map, parse_credential_descriptors, skip_value};
use crate::cert;
use crate::clientpin::{UvOutcome, builtin_uv_enabled, builtin_uv_step};
use crate::consts::{
    AAGUID, ALG_ED25519, ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_ESP256,
    ALG_ESP384, ALG_ESP512, ALG_MLDSA44, ALG_MLDSA65, CRED_PROT_UV_OPTIONAL, CRED_PROT_UV_REQUIRED,
    CURVE_ED25519, CURVE_MLDSA44, CURVE_MLDSA65, CURVE_P256, CURVE_P256K1, CURVE_P384, CURVE_P521,
    EF_ATT_CHAIN, EF_EA_ENABLED, EF_EE_DEV, EF_MINPINLEN, EF_PIN, FLAG_AT, FLAG_ED, FLAG_UP,
    FLAG_UV, LARGE_BLOB_EXT, MAX_CREDBLOB_LENGTH, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_MIN_PIN_RPIDS,
    MAX_RESIDENT_CREDENTIALS,
};
use crate::credential::{
    CRED_BOX_MAX, CRED_PUBKEY_MAX, CRED_REC_MAX, CRED_RESIDENT_LEN, CredExt, CredInput, Credential,
    RECORD_PREFIX, RP_ID_MAX, USER_ID_MAX, USER_NAME_MAX, cred_record_box, credential_create,
    credential_load, credential_store, derive_large_blob_key, derive_resident, resident_key_input,
    slot_map, truncate_utf8,
};
use crate::ec::{CredKey, MAX_SIG_LEN, P256Key};
use crate::error::{CtapError, CtapResult};
use crate::hmacsecret::{self, HmacSecretReq, SALT_ENC_MAX};
use crate::journal;
use crate::keyderiv::fido_load_key;
use crate::largeblobext::{self, McInput};
use crate::seed::load_att_key;
use crate::state::PERM_MC;
use crate::{Ctx, Rng};

const MAX_EXCLUDE: usize = MAX_CREDENTIAL_COUNT_IN_LIST as usize;

/// authData fixed prefix: rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ aaguid(16) ‖
/// credIdLen(2).
const AUTH_DATA_HEADER: usize = 32 + 1 + 4 + 16 + 2;
/// Ceiling of `encode_mc_extensions`' output (its scratch buffer, below).
const MC_EXT_MAX: usize = 192;
/// Largest AKP COSE public key `cose_public` emits — the ML-DSA-65 case: a
/// 3-entry map (1) with kty (1+1), alg −49 (1+2) and the 1952-byte pk wrapped as
/// key −1 (1) + a >255-byte CBOR byte-string header (3) → 10 + pk = 1962.
const COSE_AKP_MLDSA65_MAX: usize = 1 + (1 + 1) + (1 + 2) + (1 + 3) + MLDSA65_PK_LEN;
/// authData scratch, sized for the ML-DSA-65 worst case (a non-resident box at
/// `CRED_BOX_MAX` + the AKP COSE key + full extensions) plus the 32-byte
/// clientDataHash appended in place for the attestation signature.
const AD_BUF: usize = 3072;
const _: () = assert!(
    AUTH_DATA_HEADER + CRED_BOX_MAX + COSE_AKP_MLDSA65_MAX + MC_EXT_MAX + 32 <= AD_BUF,
    "authData buffer too small for the ML-DSA-65 worst case",
);

/// Map a requested COSE alg to the `(alg, curve)` the credential is created with,
/// or `None` if unsupported. The alg returned is the one the platform **asked
/// for**: the curve-explicit ids (`-9`/`-19`/`-51`/`-52`) share their key material
/// with the classic spelling, and WebAuthn §7.1 has the RP match the attested
/// key's alg against the list it sent, so folding one fails its own registration.
fn alg_to_curve(alg: i64) -> Option<(i64, u8)> {
    match alg {
        ALG_ES256 => Some((ALG_ES256, CURVE_P256)),
        ALG_ESP256 => Some((ALG_ESP256, CURVE_P256)),
        ALG_ES384 => Some((ALG_ES384, CURVE_P384)),
        ALG_ESP384 => Some((ALG_ESP384, CURVE_P384)),
        ALG_ES512 => Some((ALG_ES512, CURVE_P521)),
        ALG_ESP512 => Some((ALG_ESP512, CURVE_P521)),
        // The FIPS-style profile keeps secp256k1 out of new credentials
        // (existing K1 credentials still assert — creation is the policy gate).
        ALG_ES256K if cfg!(not(feature = "fips-profile")) => Some((ALG_ES256K, CURVE_P256K1)),
        ALG_EDDSA => Some((ALG_EDDSA, CURVE_ED25519)),
        ALG_ED25519 => Some((ALG_ED25519, CURVE_ED25519)),
        // ML-DSA-44 and -65 are backed; -50 (ML-DSA-87) falls through — its
        // response overruns the CTAPHID message ceiling.
        ALG_MLDSA44 => Some((ALG_MLDSA44, CURVE_MLDSA44)),
        ALG_MLDSA65 => Some((ALG_MLDSA65, CURVE_MLDSA65)),
        _ => None,
    }
}

struct Request<'a> {
    client_data_hash: &'a [u8],
    rp_id: &'a str,
    user_id: &'a [u8],
    user_name: &'a str,
    user_display_name: &'a str,
    has_pubkey_param: bool,
    /// First supported algorithm + its curve (`0` / unset = none supported).
    sel_alg: i64,
    sel_curve: i64,
    exclude: [&'a [u8]; MAX_EXCLUDE],
    exclude_len: usize,
    rk: bool,
    /// The `up` option as supplied (absent = implicit true). `up=false` is
    /// rejected (§6.1.2); `up=true` is accepted as the default.
    up: Option<bool>,
    uv: bool,
    pin_uv_auth_param: Option<&'a [u8]>,
    /// `None` = the platform sent no pinUvAuthProtocol. A numeric `0` is a value
    /// it did send, and an unsupported one (§6.1.2 step 2).
    pin_uv_auth_protocol: Option<u64>,
    /// `None` = no credProtect extension. `Some(0)` is an out-of-range level.
    ext_cred_protect: Option<u64>,
    ext_cred_blob: &'a [u8],
    ext_min_pin_length: bool,
    ext_third_party_payment: bool,
    ext_hmac_secret: bool,
    ext_large_blob_key: Option<bool>,
    /// The CTAP 2.3 `largeBlob` extension input, on a `largeblob-ext` build.
    ext_large_blob: McInput,
    hmac_secret_mc: HmacSecretReq<'a>,
    /// enterpriseAttestation (request field 0x0A): 1 vendor-facilitated, 2
    /// platform-managed (full attestation by the device key). §6.1.2 step 9 keys
    /// on the field being **present**, so `None` and `Some(0)` differ.
    enterprise_attestation: Option<u64>,
}

fn parse(data: &[u8]) -> Result<Request<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Request {
        client_data_hash: &[],
        rp_id: "",
        user_id: &[],
        user_name: "",
        user_display_name: "",
        has_pubkey_param: false,
        sel_alg: 0,
        sel_curve: 0,
        exclude: [&[]; MAX_EXCLUDE],
        exclude_len: 0,
        rk: false,
        up: None,
        uv: false,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
        ext_cred_protect: None,
        ext_cred_blob: &[],
        ext_min_pin_length: false,
        ext_third_party_payment: false,
        ext_hmac_secret: false,
        ext_large_blob_key: None,
        ext_large_blob: McInput::Absent,
        hmac_secret_mc: HmacSecretReq::default(),
        enterprise_attestation: None,
    };

    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Keys 1..=4 are mandatory and must appear first, in order.
        if expected <= 4 && key != expected {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.client_data_hash = cbor(d.bytes())?,
            2 => parse_rp_entity(&mut d, &mut req)?,
            3 => parse_user_entity(&mut d, &mut req)?,
            4 => parse_pubkey_params(&mut d, &mut req)?,
            5 => req.exclude_len = parse_credential_descriptors(&mut d, &mut req.exclude)?,
            6 => parse_extensions(&mut d, &mut req)?,
            7 => parse_options(&mut d, &mut req)?,
            8 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            9 => req.pin_uv_auth_protocol = Some(cbor(d.u32())? as u64),
            10 => req.enterprise_attestation = Some(cbor(d.u32())? as u64),
            _ => skip_value(&mut d)?,
        }
    }
    Ok(req)
}

/// Parse the `rp` PublicKeyCredentialRpEntity (request key 2) into `req`.
fn parse_rp_entity<'a>(d: &mut Decoder<'a>, req: &mut Request<'a>) -> Result<(), CtapError> {
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.str())? {
            "id" => req.rp_id = cbor(d.str())?,
            // rp.name must be a text string when present (conformance
            // MakeCredential Req-2 F-2); read-as-text so a non-text value
            // surfaces as CBOR_UNEXPECTED_TYPE.
            "name" => {
                let _: &str = cbor(d.str())?;
            }
            _ => skip_value(d)?,
        }
    }
    Ok(())
}

/// Parse the `user` PublicKeyCredentialUserEntity (request key 3) into `req`.
fn parse_user_entity<'a>(d: &mut Decoder<'a>, req: &mut Request<'a>) -> Result<(), CtapError> {
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.str())? {
            "id" => req.user_id = cbor(d.bytes())?,
            "name" => req.user_name = cbor(d.str())?,
            "displayName" => req.user_display_name = cbor(d.str())?,
            _ => skip_value(d)?,
        }
    }
    Ok(())
}

/// Parse `pubKeyCredParams` (request key 4), selecting the first supported
/// algorithm — §6.1.2 step 4: the platform's list order IS its preference order,
/// and every element is still validated after one is chosen.
fn parse_pubkey_params(d: &mut Decoder<'_>, req: &mut Request<'_>) -> Result<(), CtapError> {
    let a = def_arr(d)?;
    for _ in 0..a {
        req.has_pubkey_param = true;
        let m = def_map(d)?;
        let (mut ty, mut alg, mut ty_present, mut alg_present) = ("", 0i64, false, false);
        for _ in 0..m {
            match cbor(d.str())? {
                "type" => {
                    ty = cbor(d.str())?;
                    ty_present = true;
                }
                "alg" => {
                    alg = cbor(d.i64())?;
                    alg_present = true;
                }
                _ => skip_value(d)?,
            }
        }
        // Every entry is a PublicKeyCredentialParameters and must carry both
        // "type" and "alg" (conformance MakeCredential Req-4 F-4).
        if !ty_present || !alg_present {
            return Err(CtapError::InvalidCbor);
        }
        if ty == "public-key"
            && req.sel_alg == 0
            && let Some((ca, cv)) = alg_to_curve(alg)
        {
            req.sel_alg = ca;
            req.sel_curve = cv as i64;
        }
    }
    Ok(())
}

/// Parse the makeCredential `extensions` map (request key 6) into `req`.
fn parse_extensions<'a>(d: &mut Decoder<'a>, req: &mut Request<'a>) -> Result<(), CtapError> {
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.str())? {
            "credProtect" => req.ext_cred_protect = Some(cbor(d.u32())? as u64),
            "credBlob" => req.ext_cred_blob = cbor(d.bytes())?,
            "minPinLength" => req.ext_min_pin_length = cbor(d.bool())?,
            "thirdPartyPayment" => req.ext_third_party_payment = cbor(d.bool())?,
            "hmac-secret" => req.ext_hmac_secret = cbor(d.bool())?,
            "hmac-secret-mc" => req.hmac_secret_mc = hmacsecret::parse(d)?,
            // Only one of the two large-blob designs is a recognized extension in
            // a given build (§12.4); the other falls through to the skip arm like
            // any unknown one, so its downstream checks stay inert.
            "largeBlobKey" if !LARGE_BLOB_EXT => req.ext_large_blob_key = Some(cbor(d.bool())?),
            "largeBlob" if LARGE_BLOB_EXT => req.ext_large_blob = largeblobext::parse_mc(d)?,
            _ => skip_value(d)?,
        }
    }
    Ok(())
}

/// Parse the `options` map (request key 7: rk / up / uv) into `req`.
fn parse_options(d: &mut Decoder<'_>, req: &mut Request<'_>) -> Result<(), CtapError> {
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.str())? {
            "rk" => req.rk = cbor(d.bool())?,
            "up" => req.up = Some(cbor(d.bool())?),
            "uv" => req.uv = cbor(d.bool())?,
            _ => skip_value(d)?,
        }
    }
    Ok(())
}

/// `authenticatorMakeCredential`: write the response CBOR into `out`, returning
/// its length.
pub fn make_credential<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let mut req = parse(data)?;

    if req.client_data_hash.len() != 32 || req.rp_id.is_empty() || req.user_id.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    // rpId (a domain) and user.id have hard maxima; reject an over-long one
    // explicitly rather than let the sealed box overflow into a vague
    // `CtapError::Other`. Together with the name truncation below this makes
    // `CRED_BOX_MAX` a true ceiling for every accepted request.
    if req.rp_id.len() > RP_ID_MAX || req.user_id.len() > USER_ID_MAX {
        return Err(CtapError::InvalidLength);
    }
    // No valid WebAuthn rpId contains whitespace — the spec requires a valid domain
    // string, and U+0020 is a forbidden host code point, so no browser can send one.
    // The trusted display is why it matters: `font::width` measures ink, so trailing
    // spaces paint NOTHING, and "bank.com " renders pixel-identically to "bank.com"
    // on the sign-in, passkey-list and delete screens while hashing to a different
    // relying party entirely. An all-whitespace id also passes the length-based
    // emptiness checks here and in `Label::is_empty`, so the ceremony paints a blank
    // relying-party line with the attacker's `user.name` beneath it (audit run-36).
    if req.rp_id.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(CtapError::InvalidParameter);
    }
    // CTAP 2.1 §6.1.2: overlong user.name / user.displayName are truncated,
    // not an error.
    req.user_name = truncate_utf8(req.user_name, USER_NAME_MAX);
    req.user_display_name = truncate_utf8(req.user_display_name, USER_NAME_MAX);
    if !req.has_pubkey_param {
        return Err(CtapError::MissingParameter);
    }
    if req.sel_alg == 0 {
        return Err(CtapError::UnsupportedAlgorithm);
    }
    // §6.1.2 step 5: "pinUvAuthParam and the 'uv' option are processed as mutually
    // exclusive with pinUvAuthParam taking precedence" — a token request that also
    // carries uv:true is NOT an error, the option is simply treated as false.
    if req.pin_uv_auth_param.is_some() {
        req.uv = false;
    }
    // up is implicitly true, and an explicit up=true is accepted (conformance
    // MakeCredential Req-6: P-3 up=true succeeds, F-1 up=false fails). `uv` is an
    // error only when there is no built-in user verification method, or it is not
    // presently configured — on a screenless build, always.
    if req.up == Some(false) {
        return Err(CtapError::InvalidOption);
    }
    if req.uv && !builtin_uv_enabled(ctx) {
        return Err(CtapError::InvalidOption);
    }
    // largeBlobKey may not be requested as false and requires a resident key.
    if req.ext_large_blob_key == Some(false) || (req.ext_large_blob_key == Some(true) && !req.rk) {
        return Err(CtapError::InvalidOption);
    }
    // hmac-secret-mc requires the hmac-secret flag to also be set.
    if req.hmac_secret_mc.present && !req.ext_hmac_secret {
        return Err(CtapError::MissingParameter);
    }
    // hmac-secret-mc carries the same salt fields as getAssertion's hmac-secret, so
    // an absent one is refused in the same place and with the same code. A
    // zero-length one was sent, and is the length gate's business.
    if req.hmac_secret_mc.present
        && (req.hmac_secret_mc.salt_enc.is_none() || req.hmac_secret_mc.salt_auth.is_none())
    {
        return Err(CtapError::MissingParameter);
    }
    // credProtect (§12.1) defines only levels 1/2/3 and names no error for anything
    // else, so the oracle decides: a YubiKey 5.7.4 refuses 0, 4 and 255 alike with
    // CTAP1_ERR_INVALID_PARAMETER. A level of `0` is a value the platform sent.
    if let Some(level) = req.ext_cred_protect
        && !(CRED_PROT_UV_OPTIONAL..=CRED_PROT_UV_REQUIRED).contains(&level)
    {
        return Err(CtapError::InvalidParameter);
    }
    // Enterprise attestation (§6.1.2 step 9) keys on the field being PRESENT: with
    // EA disabled every present value is INVALID_PARAMETER — `0` included, measured
    // — and with it enabled only 1/2 pass. Whether attestation is actually performed
    // (and the `ep` flag set) is decided later: type 2 for any RP, type 1 only for a
    // vendor-listed RP — see `rp_eligible_for_vendor_ea` in `make_credential_inner`.
    if let Some(level) = req.enterprise_attestation {
        if !ctx.fs.has_data(EF_EA_ENABLED) {
            return Err(CtapError::InvalidParameter);
        }
        if level != 1 && level != 2 {
            return Err(CtapError::InvalidOption);
        }
    }

    let rp_id_hash = sha256(req.rp_id.as_bytes());
    let verified = enforce_pin(ctx, &req, &rp_id_hash)?;

    let mut seed = ctx.load_keydev().ok_or(CtapError::Other)?;
    let result = make_credential_inner(ctx, &req, &rp_id_hash, &seed, verified, out);
    seed.zeroize();
    result
}

/// Whether `rp_id` is on the built-in vendor-facilitated (type 1) enterprise
/// attestation list. Shipping firmware carries an EMPTY list — no RP qualifies,
/// so type-1 EA never fires by default. The `ea-conformance-rpid` feature adds the
/// FIDO Conformance Tool's fixed test RPID so its Enterprise-Attestation type-1
/// case can be exercised; it is never enabled in a shipped image.
fn rp_eligible_for_vendor_ea(rp_id: &str) -> bool {
    let _ = rp_id;
    #[cfg(feature = "ea-conformance-rpid")]
    if rp_id == "enterprisetest.certinfra.fidoalliance.org" {
        return true;
    }
    false
}

/// CTAP2.1 PIN/UV enforcement (§6.1.2 steps 6–11): verifies a `pinUvAuthParam`
/// against the token, or runs built-in UV, and reports what the response carries.
fn enforce_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
) -> Result<UvOutcome, CtapError> {
    // §6.1.2 step 2 ahead of step 1's selection gesture — where the oracle puts it.
    let proto = crate::clientpin::checked_proto(req.pin_uv_auth_protocol)?;
    let pin_set = ctx.fs.has_data(EF_PIN);
    match req.pin_uv_auth_param {
        // Zero-length probe: a selection gesture — wait for a touch, then report
        // the PIN state. With no button configured this confirms instantly. CTAP 2.1
        // §6.1.2 step 1 fixes the codes: PIN set → PIN_INVALID, unset → PIN_NOT_SET.
        // A platform managing device selection (e.g. Chrome) advances from this
        // touch to PIN entry off PIN_INVALID; PIN_AUTH_INVALID strands the ceremony.
        Some(&[]) => {
            ctx.require_presence(crate::Confirm::titled("Use this key?"))?;
            Err(if pin_set {
                CtapError::PinInvalid
            } else {
                CtapError::PinNotSet
            })
        }
        Some(param) => {
            let proto = proto.ok_or(CtapError::MissingParameter)?;
            if !ctx.state.verify_token(proto, req.client_data_hash, param)
                || ctx.state.paut.permissions & PERM_MC == 0
                || (ctx.state.paut.has_rp_id && ctx.state.paut.rp_id_hash != *rp_id_hash)
                || !ctx.state.user_verified()
            {
                return Err(CtapError::PinAuthInvalid);
            }
            ctx.state.mark_token_used(ctx.now_ms);
            if !ctx.state.paut.has_rp_id {
                ctx.state.paut.rp_id_hash = *rp_id_hash;
                ctx.state.paut.has_rp_id = true;
            }
            Ok(UvOutcome::TOKEN)
        }
        None => {
            let always_uv = crate::config::always_uv_enabled(ctx.fs);
            // §6.1.2 step 6.3: with alwaysUv on and a configured pad, a token-less
            // request is UPGRADED to built-in UV rather than refused. Step 11.2 then
            // runs the ceremony for either route.
            if req.uv || (always_uv && builtin_uv_enabled(ctx)) {
                return builtin_uv_step(ctx);
            }
            // alwaysUv without a way to verify (§6.1.2 steps 6.2/6.4): clientPin is
            // always an advertised option ID here, so the code is PUAT_REQUIRED.
            if always_uv {
                return Err(CtapError::PuatRequired);
            }
            // makeCredUvNotRqd (§6.1.2 steps 7/10): with a PIN configured a
            // DISCOVERABLE credential still needs a token; a non-discoverable one is
            // created on user presence alone, `uv` clear (issue #51).
            if pin_set && req.rk {
                return Err(CtapError::PuatRequired);
            }
            Ok(UvOutcome::NONE)
        }
    }
}

fn make_credential_inner<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    verified: UvOutcome,
    out: &mut [u8],
) -> CtapResult {
    let uv = verified.uv;
    // excludeList: refuse if any listed credential is already ours and visible
    // (a UV-required credProtect credential is invisible without UV — §12.1).
    for &id in &req.exclude[..req.exclude_len] {
        if exclude_hit(ctx.fs, seed, rp_id_hash, id, uv) {
            // §6.1.2 step 12 requires a user-presence gesture BEFORE disclosing the
            // match, so the device isn't a silent credential-existence oracle
            // (matches the getAssertion no-match poll and a real YubiKey) — unless
            // built-in UV already provided it, and step 12 then terminates without
            // waiting. No `needs_confirm` here: this card is title-only, so unlike
            // the registration card below it names nothing a display would owe the
            // user. `up` is implicit; spend the token on that touch too, so acfg
            // can't ride it (GHSA-wqjm class).
            if !verified.up_collected {
                ctx.require_presence(crate::Confirm::titled("Use this key?"))?;
            }
            ctx.state.consume_after_user_presence();
            return Err(CtapError::CredentialExcluded);
        }
    }

    // Seal the credential.
    let mut iv = [0u8; 12];
    ctx.rng.fill(&mut iv);
    let input = CredInput {
        rp_id: req.rp_id,
        user_id: req.user_id,
        user_name: req.user_name,
        user_display_name: req.user_display_name,
        use_sign_count: true,
        rk: req.rk,
        created_ms: ctx.now_ms,
        alg: req.sel_alg,
        curve: req.sel_curve,
        ext: CredExt {
            cred_protect: req.ext_cred_protect.unwrap_or(0),
            cred_blob: req.ext_cred_blob,
            hmac_secret: req.ext_hmac_secret,
            large_blob_key: req.ext_large_blob_key == Some(true),
            third_party_payment: req.ext_third_party_payment,
        },
    };
    let mut cred_box = [0u8; CRED_BOX_MAX];
    let box_len = credential_create(seed, &ctx.dev, &input, rp_id_hash, &iv, &mut cred_box)
        .map_err(|_| CtapError::Other)?;

    // Compute the resident id up front (resident keys only): the signing key,
    // hmac-secret and largeBlobKey all derive from `key_input` — the STABLE
    // resident id for a resident credential, the box for a non-resident one — so
    // they survive an updateUserInformation reseal (see `resident_key_input`). It
    // must be the same input the assertion / enumeration paths use, and the same
    // id echoed into authData below.
    let resident = req
        .rk
        .then(|| derive_resident(&cred_box[..box_len], &ctx.dev));
    let key_input = resident_key_input(&cred_box[..box_len], resident.as_ref().map(|r| &r[..]));

    // Derive the credential keypair for the selected curve.
    let mut raw = fido_load_key(seed, key_input).ok_or(CtapError::Other)?;
    let key = CredKey::from_raw(req.sel_curve, &raw).ok_or(CtapError::Other)?;
    raw.zeroize();

    // Cache the public point in the resident record so enumeration emits it
    // instead of recomputing d·G per call. `key` already holds it (it is the
    // point encoded into authData below); empty for an uncacheable curve.
    let mut cached_pubkey = [0u8; CRED_PUBKEY_MAX];
    let cached_pubkey_len = key.public_point(&mut cached_pubkey).unwrap_or(0);

    // hmac-secret-mc output (an hmac-secret evaluation at registration time).
    let mut hs = [0u8; SALT_ENC_MAX];
    let hs_len = if req.hmac_secret_mc.present {
        let ephemeral = *ctx.state.ephemeral_scalar();
        hmacsecret::eval(
            &req.hmac_secret_mc,
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

    // authData extension output (credBlob / credProtect / hmac-secret / minPinLength / hmac-secret-mc).
    let mut ext = [0u8; MC_EXT_MAX];
    let ext_len = encode_mc_extensions(ctx.fs, req, rp_id_hash, &hs[..hs_len], &mut ext)?;
    let ed = if ext_len > 0 { FLAG_ED } else { 0 };

    // §6.1.2 user presence: makeCredential's `up` is implicitly true and cannot
    // be disabled, so a configured button is ALWAYS polled before creating the
    // credential — matching getAssertion — even on the no-PIN path (e.g. an SSH
    // `ed25519-sk` enrollment with no FIDO PIN set). The zero-length
    // pinUvAuthParam probe already took its own touch in `enforce_pin` and
    // returned early, so it never reaches here. No button → instant. A
    // CTAPHID_CANCEL during the wait surfaces as KEEPALIVE_CANCEL.
    // The trusted screen (display build) names the relying party being registered;
    // the `Register` kind picks the "Save new passkey?" layout. §6.1.2 step 13: a
    // built-in UV ceremony IS the evidence of user interaction, so it sets `up`
    // without asking a second time — except where that card is the only screen
    // naming the rp being registered ([`needs_confirm`]).
    if verified.needs_confirm(ctx.presence.shows_confirm()) {
        ctx.require_presence(crate::Confirm::register(
            req.rp_id.as_bytes(),
            req.user_name.as_bytes(),
        ))?;
    }

    // Spend the pinUvAuthToken now the presence test passed (CTAP 2.1 §6.5.5.7
    // triad; GHSA-wqjm-653g-hgw3). makeCredential's `up` is implicitly true; on the
    // no-PIN path no token is in use so this is a no-op.
    ctx.state.consume_after_user_presence();

    // authData = rpIdHash | flags | counter | aaguid | credIdLen | credId | COSEpubkey | ext.
    // Worst case (ML-DSA-65): AUTH_DATA_HEADER(55) + CRED_BOX_MAX(748) +
    // COSE_AKP_MLDSA65_MAX(1962) + MC_EXT_MAX(192) + clientDataHash(32) = 2989,
    // statically bounded by AD_BUF above.
    // A new credential's signature counter starts at 0 (CTAP2 counters are
    // per-credential now; `credential_store` seeds this credential's counter so its
    // first assertion reports 1). Non-resident credentials keep no on-device state
    // and stay at 0 forever.
    let ctr = 0u32;
    let mut ad = [0u8; AD_BUF];
    let mut p = 0;
    ad[p..p + 32].copy_from_slice(rp_id_hash);
    p += 32;
    ad[p] = FLAG_AT | FLAG_UP | ed | if uv { FLAG_UV } else { 0 };
    p += 1;
    ad[p..p + 4].copy_from_slice(&ctr.to_be_bytes());
    p += 4;
    ad[p..p + 16].copy_from_slice(&AAGUID);
    p += 16;
    if let Some(rid) = &resident {
        ad[p..p + 2].copy_from_slice(&(rid.len() as u16).to_be_bytes());
        p += 2;
        ad[p..p + rid.len()].copy_from_slice(rid);
        p += rid.len();
    } else {
        ad[p..p + 2].copy_from_slice(&(box_len as u16).to_be_bytes());
        p += 2;
        ad[p..p + box_len].copy_from_slice(&cred_box[..box_len]);
        p += box_len;
    }
    let cose_len = {
        let mut enc = Encoder::new(Cursor::new(&mut ad[p..]));
        key.cose_public(req.sel_alg, &mut enc)
            .map_err(|_| CtapError::Other)?;
        enc.writer().position()
    };
    p += cose_len;
    ad[p..p + ext_len].copy_from_slice(&ext[..ext_len]);
    p += ext_len;
    let ad_len = p;

    // Attestation over authData ‖ clientDataHash.
    ad[ad_len..ad_len + 32].copy_from_slice(req.client_data_hash);
    // `ea_performed` — platform-managed (type 2), or vendor-facilitated (type 1)
    // for an RP on the built-in enterprise list (empty in shipping firmware) —
    // presents the org/EP cert and sets the `ep` flag. A type-1 request for a
    // non-listed RP is NOT enterprise: full attestation with the device's own
    // cert and no `ep` (CTAP2.1 §6.1.3, conformance Enterprise-Attestation F-6).
    let ea_performed = req.enterprise_attestation == Some(2)
        || (req.enterprise_attestation == Some(1) && rp_eligible_for_vendor_ea(req.rp_id));
    // Every credential ships packed **basic** attestation: the device key signs and
    // the x5c leaf is its cert. Both alternatives break clients — an empty
    // `fmt:"none"` statement is rejected by OpenSSH < 10.0, which verifies any
    // x5c-less credential unconditionally, and a packed EdDSA self-attestation fails
    // on Windows/WinHello (issue #26). Basic attestation signs with ES256 whatever
    // the credential algorithm is, so neither path is reached.
    let mut att = AttBufs::new();
    let (sig_len, chain_len, certs) =
        make_attestation(ctx, seed, &ad[..ad_len + 32], ea_performed, &mut att)?;

    // largeBlobKey response field (0x05) — resident credentials only.
    let large_blob_key = if req.ext_large_blob_key == Some(true) && req.rk {
        Some(derive_large_blob_key(seed, key_input))
    } else {
        None
    };

    // §12.4 makeCredential: this device gives every DISCOVERABLE credential
    // large-blob capability (the spec's "MAY choose to always create new
    // credentials with large blob capability"), because the blob hangs off the
    // resident record. A non-discoverable credential keeps no on-device state at
    // all, so `support: "required"` is refused rather than silently unmet — and
    // an absent input returns nothing, the "MUST NOT return unsolicited output".
    let large_blob_supported = match req.ext_large_blob {
        McInput::Absent => false,
        _ if req.rk => true,
        McInput::Required => return Err(CtapError::LargeBlobStorageFull),
        McInput::Preferred => false,
    };

    let resp_len = encode_mc_response(
        out,
        &ad[..ad_len],
        &att,
        AttShape {
            sig_len,
            chain_len,
            certs,
            ea_performed,
        },
        large_blob_key,
        large_blob_supported,
    )?;

    if req.rk
        && credential_store(
            seed,
            &ctx.dev,
            ctx.fs,
            &cred_box[..box_len],
            rp_id_hash,
            req.rp_id,
            req.user_id,
            &cached_pubkey[..cached_pubkey_len],
        )
        .is_err()
    {
        return Err(CtapError::KeyStoreFull);
    }
    journal::append(ctx, journal::EV_MAKE_CRED, 0, &rp_id_hash[..8]);
    Ok(resp_len)
}

/// What shape the attestation statement takes, so the response encoder does not
/// have to re-derive it: the lengths [`make_attestation`] returned plus whether
/// enterprise attestation was performed.
struct AttShape {
    sig_len: usize,
    chain_len: usize,
    certs: u8,
    /// Enterprise attestation was actually performed, so `ep` (field 4) is set.
    ea_performed: bool,
}

/// Encode the makeCredential response: `{1: fmt, 2: authData, 3: attStmt
/// [, 4: ep] [, 5: largeBlobKey] [, 6: unsignedExtensionOutputs]}`.
///
/// `fmt` is always `"packed"` and attStmt is always `{alg, sig, x5c}` — basic
/// attestation with the device cert, or the org chain when EA was performed. The
/// three keys are already in CTAP2 canonical order. `ep` appears only when EA was
/// actually performed. Fields 5 and 6 are the two mutually exclusive large-blob
/// designs, so at most one of them is ever present.
fn encode_mc_response(
    out: &mut [u8],
    ad: &[u8],
    att: &AttBufs,
    shape: AttShape,
    large_blob_key: Option<[u8; 32]>,
    large_blob_supported: bool,
) -> CtapResult {
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(
        3 + u64::from(shape.ea_performed)
            + u64::from(large_blob_key.is_some())
            + u64::from(large_blob_supported),
    )
    .and_then(|e| e.u8(1)?.str("packed"))
    .and_then(|e| e.u8(2)?.bytes(ad))
    .and_then(|e| e.u8(3))
    .map_err(|_| CtapError::Other)?;
    enc.map(3)
        .and_then(|e| e.str("alg")?.i64(ALG_ES256))
        .and_then(|e| e.str("sig")?.bytes(&att.sig[..shape.sig_len]))
        .map_err(|_| CtapError::Other)?;
    encode_x5c(&mut enc, &att.chain[..shape.chain_len], shape.certs)?;
    if shape.ea_performed {
        enc.u8(4)
            .and_then(|e| e.bool(true)) // ep: enterprise attestation used
            .map_err(|_| CtapError::Other)?;
    }
    if let Some(lbk) = large_blob_key {
        enc.u8(5)
            .and_then(|e| e.bytes(&lbk))
            .map_err(|_| CtapError::Other)?;
    }
    if large_blob_supported {
        enc.u8(6).map_err(|_| CtapError::Other)?;
        largeblobext::write_mc_output(&mut enc).map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// The `x5c` array of the packed attestation statement, sliced out of the stored
/// chain record one DER cert at a time.
fn encode_x5c<W: Write>(enc: &mut Encoder<W>, chain: &[u8], certs: u8) -> Result<(), CtapError> {
    enc.str("x5c")
        .and_then(|e| e.array(u64::from(certs)))
        .map_err(|_| CtapError::Other)?;
    for i in 0..certs {
        let c = cert::att_chain_cert(chain, i).ok_or(CtapError::Other)?;
        enc.bytes(c).map_err(|_| CtapError::Other)?;
    }
    Ok(())
}

/// Output buffers for [`make_attestation`]: the raw signature and the packed x5c
/// chain, filled in place and then sliced by the returned lengths.
struct AttBufs {
    sig: [u8; MAX_SIG_LEN],
    chain: [u8; cert::ATT_CHAIN_REC_MAX],
}

impl AttBufs {
    fn new() -> Self {
        Self {
            sig: [0u8; MAX_SIG_LEN],
            chain: [0u8; cert::ATT_CHAIN_REC_MAX],
        }
    }
}

/// Sign `signed` (authData ‖ clientDataHash) into `att` and shape the attestation
/// statement — always basic or enterprise, so always ES256 with an x5c chain. When
/// enterprise attestation was performed and an org key is installed it signs with
/// that key + the EF_ATT_CHAIN chain; otherwise with the device key (the seed
/// scalar) + its self-signed EF_EE_DEV cert (the pair U2F register uses). Returns
/// `(sig_len, chain_len, cert_count)`.
fn make_attestation<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    seed: &[u8; 32],
    signed: &[u8],
    ea_performed: bool,
    att: &mut AttBufs,
) -> Result<(usize, usize, u8), CtapError> {
    let org_key = if ea_performed {
        load_att_key(&ctx.dev, ctx.fs)
    } else {
        None
    };
    if let Some(mut scalar) = org_key {
        let k = P256Key::from_scalar(&scalar);
        scalar.zeroize();
        let k = k.ok_or(CtapError::Other)?;
        let sl = k.sign_der(signed, &mut att.sig);
        let cl = ctx
            .fs
            .read(EF_ATT_CHAIN, &mut att.chain[..])
            .map(|n| n.min(att.chain.len()))
            .filter(|&n| cert::att_chain_count(&att.chain[..n]) > 0)
            .ok_or(CtapError::Other)?;
        let count = cert::att_chain_count(&att.chain[..cl]);
        Ok((sl, cl, count))
    } else {
        let device_key = P256Key::from_scalar(seed).ok_or(CtapError::Other)?;
        let sl = device_key.sign_der(signed, &mut att.sig);
        // Read straight into the chain buffer past its 3-byte header — this runs on
        // every makeCredential now, so a 512-byte scratch cert would be stack the
        // ML-DSA paths cannot spare.
        let room = att.chain.len() - 3;
        let cl = match ctx.fs.read(EF_EE_DEV, &mut att.chain[3..]) {
            Some(n) if n > 0 => n.min(room),
            _ => return Err(CtapError::Other),
        };
        // Wrap the single self-signed cert in the packed-chain layout so the
        // x5c encode has one shape.
        att.chain[0] = 1;
        att.chain[1..3].copy_from_slice(&(cl as u16).to_le_bytes());
        Ok((sl, 3 + cl, 1))
    }
}

/// Is `id` an existing credential for this rp that is *visible* now? A
/// UV-required credProtect credential is hidden without UV, so it does not
/// count as an excludeList hit (§12.1).
fn exclude_hit<S: Storage>(
    fs: &mut Fs<S>,
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    id: &[u8],
    uv: bool,
) -> bool {
    let visible = |c: &Credential| c.ext.cred_protect != CRED_PROT_UV_REQUIRED || uv;
    let mut scratch = [0u8; CRED_REC_MAX];
    // A resident id is exactly 42 bytes, matched against the stored records; fall
    // back to the non-resident box path for anything else — and for a 42-byte id
    // not stored as a resident — so no cleartext marker is needed.
    if id.len() == CRED_RESIDENT_LEN {
        let mut rec = [0u8; CRED_REC_MAX];
        let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
        slot_map(fs, crate::consts::EF_CRED, &mut occupied);
        for i in 0..MAX_RESIDENT_CREDENTIALS {
            if !occupied[i as usize] {
                continue;
            }
            let Some(n) = fs.read(crate::consts::EF_CRED + i, &mut rec) else {
                continue;
            };
            let n = n.min(rec.len());
            if n >= RECORD_PREFIX && rec[..32] == *rp_id_hash && rec[32..RECORD_PREFIX] == *id {
                return credential_load(seed, cred_record_box(&rec[..n]), rp_id_hash, &mut scratch)
                    .map(|c| visible(&c))
                    .unwrap_or(false);
            }
        }
    }
    credential_load(seed, id, rp_id_hash, &mut scratch)
        .map(|c| visible(&c))
        .unwrap_or(false)
}

/// Build the makeCredential authData extension map (credBlob bool / credProtect /
/// hmac-secret / minPinLength / hmac-secret-mc) into `out`; returns its length
/// (0 if none apply). `hmac_mc` is the already-evaluated hmac-secret-mc output.
fn encode_mc_extensions<S: Storage>(
    fs: &mut Fs<S>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    hmac_mc: &[u8],
    out: &mut [u8],
) -> Result<usize, CtapError> {
    let blob_present = !req.ext_cred_blob.is_empty();
    let min_pin = if req.ext_min_pin_length {
        rp_min_pin_len(fs, rp_id_hash)
    } else {
        0
    };
    let l = u64::from(blob_present)
        + u64::from(req.ext_cred_protect.is_some())
        + u64::from(req.ext_hmac_secret)
        + u64::from(min_pin > 0)
        + u64::from(!hmac_mc.is_empty());
    if l == 0 {
        return Ok(0);
    }
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(l).map_err(|_| CtapError::Other)?;
    if blob_present {
        // The flag reports whether the blob was short enough to seal — inclusive of
        // the advertised maxCredBlobLength, matching `CredExt::cred_blob_ok`.
        enc.str("credBlob")
            .and_then(|e| e.bool(req.ext_cred_blob.len() <= MAX_CREDBLOB_LENGTH))
            .map_err(|_| CtapError::Other)?;
    }
    if let Some(level) = req.ext_cred_protect {
        enc.str("credProtect")
            .and_then(|e| e.u64(level))
            .map_err(|_| CtapError::Other)?;
    }
    if req.ext_hmac_secret {
        enc.str("hmac-secret")
            .and_then(|e| e.bool(true))
            .map_err(|_| CtapError::Other)?;
    }
    if min_pin > 0 {
        enc.str("minPinLength")
            .and_then(|e| e.u8(min_pin))
            .map_err(|_| CtapError::Other)?;
    }
    if !hmac_mc.is_empty() {
        enc.str("hmac-secret-mc")
            .and_then(|e| e.bytes(hmac_mc))
            .map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// The per-RP minimum PIN length from EF_MINPINLEN (`[len, force, rpIdHash…]`), or
/// 0 if this rp is not in the authorised list (set via authenticatorConfig).
fn rp_min_pin_len<S: Storage>(fs: &mut Fs<S>, rp_id_hash: &[u8; 32]) -> u8 {
    let mut buf = [0u8; 2 + 32 * MAX_MIN_PIN_RPIDS];
    let Some(n) = fs.read(EF_MINPINLEN, &mut buf) else {
        return 0;
    };
    let n = n.min(buf.len());
    let mut o = 2;
    while o + 32 <= n {
        if buf[o..o + 32] == *rp_id_hash {
            return buf[0];
        }
        o += 32;
    }
    0
}

#[cfg(test)]
#[path = "makecredential_tests.rs"]
mod tests;
