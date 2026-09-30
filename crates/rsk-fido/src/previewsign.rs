// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico's `previewSign` WebAuthn extension, draft v4 as snapshotted 2025-08-21 —
//! the shape python-fido2 2.2.1 speaks — behind the `preview-sign` feature. A
//! registration mints a signing key alongside the credential; an assertion signs
//! the relying party's `tbs` with it, outside authData and clientData.
//!
//! One algorithm: ESP256-split-ARKG. The key is an ARKG-P256 seed (the `arkg` module):
//! the relying party derives public keys from its public half, and names the one a
//! signature is for in `args`, a COSE_Sign_Args. Split signing: `tbs` is the SHA-256
//! digest the relying party took, and the device signs that digest.
//!
//! Stateless, as the draft allows. The signing key handle is the draft's example
//! encoding, `HMAC-SHA-256(k, params ‖ "previewSign" ‖ rpIdHash) ‖ params` with
//! `params = [alg, flags, auxIkm]` and `k` drawn from a per-credential secret; the
//! seed is re-derived from the same secret and `params`. Nothing is stored, so no
//! record changes shape and an older build's records load as they always did.
//!
//! A key asked for `unattended` (flags `0b000`) signs without a touch, as a YubiKey
//! 5.8.0's does. Two deliberate deviations from the draft. The signing key's
//! attestation object is `none`, as that YubiKey answers it, where the draft gives it
//! the credential's format: only an enterprise attestation signs it. And an ML-DSA
//! credential refuses the extension with `CTAP2_ERR_UNSUPPORTED_ALGORITHM`, since
//! its registration response leaves no room for a second attestation object.

// Host bytes: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use minicbor::encode::write::Cursor;
use minicbor::encode::{Error, Write};
use minicbor::{Decoder, Encoder};
use rsk_crypto::{ct_eq, hmac_sha256};
use rsk_secret::Secret;

use crate::Rng;
use crate::arkg::{self, POINT_LEN, cat};
use crate::cbordec::{cbor, def_arr, def_map, skip_value};
use crate::consts::{
    AAGUID, ALG_ARKG_P256, ALG_ECDH_ES_HKDF_256, ALG_ES256, ALG_ESP256, ALG_ESP256_SPLIT_ARKG,
    CURVE_MLDSA44, CURVE_MLDSA65, CURVE_MLDSA87, CURVE_P256, FLAG_UP, FLAG_UV, KTY_ARKG_PUB,
};
use crate::cose::cose_key_ec2_var;
use crate::ec::{MAX_DER_SIG, P256Key};
use crate::error::CtapError;

/// The extension identifier: the request key, and the output keys it answers under.
pub(crate) const NAME: &str = "previewSign";

// The draft's CBOR map keys (its CDDL aliases), for both directions.
const KEY_KH: i64 = 2;
const KEY_ALG: i64 = 3;
const KEY_FLAGS: i64 = 4;
const KEY_TBS: i64 = 6;
const KEY_SIG: i64 = 6;
const KEY_ARGS: i64 = 7;
const KEY_ATT_OBJ: i64 = 7;

// `flags` names the authData flags a signature must carry: none (`unattended`),
// UP (`require-up`, the default), or UP and UV (`require-uv`).
const FLAGS_UNATTENDED: u8 = 0b000;
const FLAGS_REQUIRE_UP: u8 = FLAG_UP;
const FLAGS_REQUIRE_UV: u8 = FLAG_UP | FLAG_UV;

// COSE_Sign_Args (draft-lundberg-cose-two-party-signing-algs): `alg`, then the ARKG
// arguments (ARKG draft §5.3): the ARKG key handle and its ctx.
const ARGS_ALG: i64 = 3;
const ARGS_ARKG_KH: i64 = -1;
const ARGS_ARKG_CTX: i64 = -2;

// The ARKG-pub key's labels (ARKG draft §5.1): the BL key, the KEM key, and the
// algorithm keys derived from the seed are for.
const PUB_BL: i8 = -1;
const PUB_KEM: i8 = -2;
const PUB_DKALG: i8 = -3;

/// ESP256-split signs a SHA-256 digest: the relying party hashed, the device signs.
const PREHASH_LEN: usize = 32;
/// `auxIkm`: fresh entropy per signing key, carried inside the handle.
const AUX_IKM_LEN: usize = 32;
/// `[alg, flags, auxIkm]`, canonical: array head, -65539's five bytes, a one-byte
/// flags value, the 32-byte string's two-byte head.
const PARAMS_LEN: usize = 1 + 5 + 1 + 2 + AUX_IKM_LEN;
/// HMAC-SHA-256 over the params, the handle's first half.
const MAC_LEN: usize = 32;
/// The signing key handle this device mints: the MAC, then the params.
const HANDLE_LEN: usize = MAC_LEN + PARAMS_LEN;

/// The per-credential secret's own label in the device seed's HMAC ratchet.
const SECRET_LABEL: &[u8] = b"RS-Key/previewSign";
// What the per-credential secret is split into: the handle's MAC key, and the
// keying material of each half of the ARKG seed.
const MAC_KEY_LABEL: &[u8] = b"kh-mac";
const SEED_BL_LABEL: &[u8] = b"arkg-bl";
const SEED_KEM_LABEL: &[u8] = b"arkg-kem";
const SEED_LABEL_MAX: usize = SEED_KEM_LABEL.len();

/// Ceiling of the attested key's authData — 316 bytes for ESP256-split-ARKG.
const AUTH_DATA_MAX: usize = 384;
/// The assertion's authData entry at its largest: `"previewSign": {sig: DER}`.
pub(crate) const GA_EXT_MAX: usize = 1 + NAME.len() + 1 + 1 + 2 + MAX_DER_SIG;
/// The largest classic credential key in COSE, a P-521 EC2 key: the makeCredential
/// response bound this extension's output is checked against.
pub(crate) const COSE_EC2_MAX: usize = 1 + 2 + 3 + 2 + 2 * (3 + 66);
/// Field 6's previewSign entry less the certificates: its heads, the attestation
/// object's (`fmt`, authData, a packed ES256 statement), a head per certificate.
pub(crate) const UNSIGNED_SANS_CHAIN_MAX: usize = 1
    + 1
    + (1 + NAME.len())
    + 1
    + 1
    + 3
    + 1
    + (1 + 7)
    + (1 + 3 + AUTH_DATA_MAX)
    + 1
    + 1
    + (4 + 1)
    + (4 + 2 + MAX_DER_SIG)
    + (4 + 1)
    + 3 * crate::cert::ATT_CHAIN_MAX_CERTS;

/// The makeCredential input as sent: `alg` kept raw, so its elements are judged
/// after `flags` — the reference's order.
#[derive(Clone, Copy, Default)]
pub(crate) struct McInput<'a> {
    present: bool,
    algs: Option<&'a [u8]>,
    flags: Option<u64>,
}

/// The getAssertion input as sent.
#[derive(Clone, Copy, Default)]
pub(crate) struct GaInput<'a> {
    present: bool,
    kh: Option<&'a [u8]>,
    tbs: Option<&'a [u8]>,
    args: Option<&'a [u8]>,
}

/// What a registration settled on: the algorithm and the flags the key is bound to.
#[derive(Clone, Copy)]
pub(crate) struct KeyRequest {
    alg: i64,
    flags: u8,
}

/// A registration's signing key — all of it public: the handle, and the seed's
/// public half.
pub(crate) struct GeneratedKey {
    alg: i64,
    flags: u8,
    handle: [u8; HANDLE_LEN],
    bl: [u8; POINT_LEN],
    kem: [u8; POINT_LEN],
}

/// A DER ECDSA signature: the attested key's attestation, or a `tbs` signature.
pub(crate) struct DerSig {
    der: [u8; MAX_DER_SIG],
    len: usize,
}

impl DerSig {
    fn bytes(&self) -> Result<&[u8], CtapError> {
        self.der.get(..self.len).ok_or(CtapError::Other)
    }
}

/// A generated key made ready for the unsigned output: its attested authData's
/// inputs, and the attestation signature over it (`None` for the `none` format).
pub(crate) struct Attested<'a> {
    key: &'a GeneratedKey,
    rp_id_hash: &'a [u8; 32],
    ad_flags: u8,
    sig: Option<DerSig>,
}

/// Parse the makeCredential `previewSign` value. Types are checked here, with the
/// rest of the request; what the values mean waits for [`negotiate`].
pub(crate) fn parse_mc<'a>(d: &mut Decoder<'a>) -> Result<McInput<'a>, CtapError> {
    let mut input = McInput {
        present: true,
        ..McInput::default()
    };
    for _ in 0..def_map(d)? {
        match cbor(d.i64())? {
            KEY_ALG => input.algs = Some(raw_array(d)?),
            KEY_FLAGS => input.flags = Some(cbor(d.u64())?),
            _ => skip_value(d)?,
        }
    }
    Ok(input)
}

/// Parse the getAssertion `previewSign` value.
pub(crate) fn parse_ga<'a>(d: &mut Decoder<'a>) -> Result<GaInput<'a>, CtapError> {
    let mut input = GaInput {
        present: true,
        ..GaInput::default()
    };
    for _ in 0..def_map(d)? {
        match cbor(d.i64())? {
            KEY_KH => input.kh = Some(cbor(d.bytes())?),
            KEY_TBS => input.tbs = Some(cbor(d.bytes())?),
            KEY_ARGS => input.args = Some(cbor(d.bytes())?),
            _ => skip_value(d)?,
        }
    }
    Ok(input)
}

/// A definite array's encoding, walked but not read.
fn raw_array<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8], CtapError> {
    let start = d.position();
    for _ in 0..def_arr(d)? {
        skip_value(d)?;
    }
    d.input()
        .get(start..d.position())
        .ok_or(CtapError::InvalidCbor)
}

/// Settle a registration's input in a YubiKey 5.8.0's order: bad `flags` (0x2C), an
/// `alg` that is not a negative integer (0x11), none supported (0x26) — then an
/// ML-DSA `cred_curve` refuses the extension like an unsupported algorithm.
pub(crate) fn negotiate(
    input: &McInput<'_>,
    cred_curve: i64,
) -> Result<Option<KeyRequest>, CtapError> {
    if !input.present {
        return Ok(None);
    }
    let flags = match input.flags.map(u8::try_from) {
        None | Some(Ok(FLAGS_REQUIRE_UP)) => FLAGS_REQUIRE_UP,
        Some(Ok(FLAGS_UNATTENDED)) => FLAGS_UNATTENDED,
        Some(Ok(FLAGS_REQUIRE_UV)) => FLAGS_REQUIRE_UV,
        Some(_) => return Err(CtapError::InvalidOption),
    };
    let algs = input.algs.ok_or(CtapError::MissingParameter)?;
    let mut d = Decoder::new(algs);
    let mut chosen = None;
    for _ in 0..def_arr(&mut d)? {
        let alg = cbor(d.i64())?;
        if alg >= 0 {
            return Err(CtapError::CborUnexpectedType);
        }
        if chosen.is_none() && alg == ALG_ESP256_SPLIT_ARKG {
            chosen = Some(alg);
        }
    }
    let alg = chosen.ok_or(CtapError::UnsupportedAlgorithm)?;
    if [CURVE_MLDSA44, CURVE_MLDSA65, CURVE_MLDSA87]
        .iter()
        .any(|&c| i64::from(c) == cred_curve)
    {
        return Err(CtapError::UnsupportedAlgorithm);
    }
    Ok(Some(KeyRequest { alg, flags }))
}

/// Refuse what a signing request needs no credential to be refused for (v4
/// authentication steps 1–2): no allowList, or a missing `kh` or `tbs`, is
/// `INVALID_OPTION`.
pub(crate) fn check_ga(input: &GaInput<'_>, allow_len: usize) -> Result<(), CtapError> {
    if input.present && (allow_len == 0 || input.kh.is_none() || input.tbs.is_none()) {
        return Err(CtapError::InvalidOption);
    }
    Ok(())
}

/// The credential's previewSign secret: the device seed's HMAC ratchet, as
/// `credential::derive_large_blob_key` walks it, under this extension's label.
/// `key_input` is `credential::resident_key_input`'s, like every per-credential key.
fn credential_secret(seed: &[u8; 32], key_input: &[u8]) -> Secret<[u8; 32]> {
    let mut k = Secret::new(hmac_sha256(seed, b"SLIP-0022"));
    *k.expose_mut() = hmac_sha256(k.expose(), SECRET_LABEL);
    *k.expose_mut() = hmac_sha256(k.expose(), key_input);
    k
}

/// The handle's MAC over `params ‖ "previewSign" ‖ rpIdHash` (the draft's example
/// key handle encoding), under a key of its own from the credential secret.
fn handle_mac(
    secret: &Secret<[u8; 32]>,
    params: &[u8],
    rp_id_hash: &[u8; 32],
) -> Result<[u8; MAC_LEN], CtapError> {
    let key = Secret::new(hmac_sha256(secret.expose(), MAC_KEY_LABEL));
    let mut buf = [0u8; PARAMS_LEN + NAME.len() + 32];
    let msg = cat(&mut buf, &[params, NAME.as_bytes(), rp_id_hash]).ok_or(CtapError::Other)?;
    Ok(hmac_sha256(key.expose(), msg))
}

/// The ARKG seed a handle's `params` name, under the credential secret.
fn seed_for(secret: &Secret<[u8; 32]>, params: &[u8]) -> Result<arkg::PrivateSeed, CtapError> {
    let mut buf = [0u8; SEED_LABEL_MAX + PARAMS_LEN];
    let bl_msg = cat(&mut buf, &[SEED_BL_LABEL, params]).ok_or(CtapError::Other)?;
    let ikm_bl = Secret::new(hmac_sha256(secret.expose(), bl_msg));
    let kem_msg = cat(&mut buf, &[SEED_KEM_LABEL, params]).ok_or(CtapError::Other)?;
    let ikm_kem = Secret::new(hmac_sha256(secret.expose(), kem_msg));
    arkg::derive_seed(ikm_bl.expose(), ikm_kem.expose()).ok_or(CtapError::Other)
}

/// Mint the signing key a registration asked for (v4 registration steps 6–7): a
/// fresh `auxIkm`, the handle over it, and the seed's public half. `key_input` is
/// the credential's, so the key is bound to it.
pub(crate) fn generate<R: Rng>(
    seed: &[u8; 32],
    key_input: &[u8],
    rp_id_hash: &[u8; 32],
    request: KeyRequest,
    rng: &mut R,
) -> Result<GeneratedKey, CtapError> {
    let mut aux = [0u8; AUX_IKM_LEN];
    rng.fill(&mut aux);
    let mut handle = [0u8; HANDLE_LEN];
    let (mac, params) = handle
        .split_first_chunk_mut::<MAC_LEN>()
        .ok_or(CtapError::Other)?;
    let written = {
        let mut enc = Encoder::new(Cursor::new(&mut *params));
        enc.array(3)
            .and_then(|e| e.i64(request.alg)?.u8(request.flags)?.bytes(&aux))
            .map_err(|_| CtapError::Other)?;
        enc.writer().position()
    };
    if written != PARAMS_LEN {
        return Err(CtapError::Other);
    }
    let secret = credential_secret(seed, key_input);
    *mac = handle_mac(&secret, params, rp_id_hash)?;
    let (bl, kem) = seed_for(&secret, params)?
        .public()
        .ok_or(CtapError::Other)?;
    Ok(GeneratedKey {
        alg: request.alg,
        flags: request.flags,
        handle,
        bl,
        kem,
    })
}

/// The registration's authData output: `"previewSign": {alg: chosen}`.
pub(crate) fn write_mc_ext<W: Write>(
    enc: &mut Encoder<W>,
    key: &GeneratedKey,
) -> Result<(), Error<W::Error>> {
    enc.str(NAME)?.map(1)?.i64(KEY_ALG)?.i64(key.alg)?;
    Ok(())
}

/// The attested key's authData (v4 registration step 9): the credential's rpIdHash
/// and flags, signCount 0, the AAGUID, the handle as the credential id, the ARKG
/// public seed as its key, and `{"previewSign": {flags}}`.
fn write_auth_data<W: Write>(
    enc: &mut Encoder<W>,
    key: &GeneratedKey,
    rp_id_hash: &[u8; 32],
    ad_flags: u8,
) -> Result<(), Error<W::Error>> {
    let id_len = u16::try_from(HANDLE_LEN).map_err(|_| Error::message("handle length"))?;
    let sign_count = 0u32;
    let head: [&[u8]; 6] = [
        rp_id_hash,
        &[ad_flags],
        &sign_count.to_be_bytes(),
        &AAGUID,
        &id_len.to_be_bytes(),
        &key.handle,
    ];
    for part in head {
        enc.writer_mut().write_all(part).map_err(Error::write)?;
    }
    write_public_seed(enc, key)?;
    enc.map(1)?
        .str(NAME)?
        .map(1)?
        .i64(KEY_FLAGS)?
        .u8(key.flags)?;
    Ok(())
}

/// The ARKG-pub COSE key (ARKG draft §5.1), CTAP canonical: `{1: ARKG-pub, 3:
/// ARKG-P256, -1: pk_bl, -2: pk_kem, -3: ESP256}`. The inner keys carry an `alg`
/// (ES256; ECDH-ES+HKDF-256) — python-fido2 refuses a COSE key without one.
fn write_public_seed<W: Write>(
    enc: &mut Encoder<W>,
    key: &GeneratedKey,
) -> Result<(), Error<W::Error>> {
    let (bl_x, bl_y) = xy(&key.bl).ok_or(Error::message("bl point"))?;
    let (kem_x, kem_y) = xy(&key.kem).ok_or(Error::message("kem point"))?;
    enc.map(5)?
        .u8(1)?
        .i64(KTY_ARKG_PUB)?
        .u8(3)?
        .i64(ALG_ARKG_P256)?;
    enc.i8(PUB_BL)?;
    cose_key_ec2_var(enc, ALG_ES256, CURVE_P256, bl_x, bl_y)?;
    enc.i8(PUB_KEM)?;
    cose_key_ec2_var(enc, ALG_ECDH_ES_HKDF_256, CURVE_P256, kem_x, kem_y)?;
    enc.i8(PUB_DKALG)?.i64(ALG_ESP256)?;
    Ok(())
}

/// An uncompressed point's `(x, y)`.
fn xy(point: &[u8; POINT_LEN]) -> Option<(&[u8], &[u8])> {
    point.get(1..)?.split_at_checked(32)
}

/// Sign the attested key's authData ‖ clientDataHash with `signer`, the credential's
/// own attestation key — or, for the `none` format, sign nothing.
pub(crate) fn attest<'a>(
    key: &'a GeneratedKey,
    rp_id_hash: &'a [u8; 32],
    ad_flags: u8,
    client_data_hash: &[u8],
    signer: Option<&P256Key>,
) -> Result<Attested<'a>, CtapError> {
    let sig = match signer {
        Some(signer) => {
            let mut buf = [0u8; AUTH_DATA_MAX + 32];
            let ad_len = {
                let mut enc = Encoder::new(Cursor::new(buf.as_mut_slice()));
                write_auth_data(&mut enc, key, rp_id_hash, ad_flags)
                    .map_err(|_| CtapError::Other)?;
                enc.writer().position()
            };
            let signed = cat_at(&mut buf, ad_len, client_data_hash).ok_or(CtapError::Other)?;
            let mut der = [0u8; MAX_DER_SIG];
            let len = signer.sign_der(signed, &mut der);
            Some(DerSig { der, len })
        }
        None => None,
    };
    Ok(Attested {
        key,
        rp_id_hash,
        ad_flags,
        sig,
    })
}

/// Append `tail` to the `len` bytes at the head of `buf`: the whole, or `None`.
fn cat_at<'b>(buf: &'b mut [u8], len: usize, tail: &[u8]) -> Option<&'b [u8]> {
    let end = len + tail.len();
    buf.get_mut(len..end)?.copy_from_slice(tail);
    buf.get(..end)
}

/// The attested key's authData, as the attestation object's byte string: its
/// length first, measured by encoding it once into nothing.
pub(crate) fn write_attested_auth_data<W: Write>(
    enc: &mut Encoder<W>,
    att: &Attested<'_>,
) -> Result<(), CtapError> {
    let len = encoded_len(|e| {
        write_auth_data(e, att.key, att.rp_id_hash, att.ad_flags).map_err(|_| CtapError::Other)
    })?;
    enc.bytes_len(len).map_err(|_| CtapError::Other)?;
    write_auth_data(enc, att.key, att.rp_id_hash, att.ad_flags).map_err(|_| CtapError::Other)
}

/// The attestation signature, when the format has one.
pub(crate) fn attestation_sig<'a>(att: &'a Attested<'_>) -> Result<Option<&'a [u8]>, CtapError> {
    att.sig.as_ref().map(DerSig::bytes).transpose()
}

/// Open the unsigned output's entry: `"previewSign": {att-obj: bstr}` up to the
/// byte string's head, `att_obj_len` long; the attestation object follows.
pub(crate) fn write_unsigned_head<W: Write>(
    enc: &mut Encoder<W>,
    att_obj_len: u64,
) -> Result<(), CtapError> {
    enc.str(NAME)
        .and_then(|e| e.map(1)?.i64(KEY_ATT_OBJ)?.bytes_len(att_obj_len))
        .map_err(|_| CtapError::Other)?;
    Ok(())
}

/// A writer that keeps nothing and counts what passes through.
pub(crate) struct Tally(u64);

impl Write for Tally {
    type Error = core::convert::Infallible;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.0 += buf.len() as u64;
        Ok(())
    }
}

/// How many bytes `write` encodes — a CBOR byte string needs its length first.
pub(crate) fn encoded_len(
    write: impl FnOnce(&mut Encoder<Tally>) -> Result<(), CtapError>,
) -> Result<u64, CtapError> {
    let mut enc = Encoder::new(Tally(0));
    write(&mut enc)?;
    Ok(enc.writer().0)
}

/// The params a handle carries, once its MAC checked out.
struct HandleParams<'a> {
    alg: i64,
    flags: u8,
    bytes: &'a [u8],
}

/// Open a signing key handle this device minted for this credential (the draft's
/// example decoding): a MAC under another credential's secret, another RP's
/// rpIdHash, or any other shape is `INVALID_CREDENTIAL`.
fn open_handle<'a>(
    secret: &Secret<[u8; 32]>,
    handle: &'a [u8],
    rp_id_hash: &[u8; 32],
) -> Result<HandleParams<'a>, CtapError> {
    let (mac, params) = handle
        .split_first_chunk::<MAC_LEN>()
        .ok_or(CtapError::InvalidCredential)?;
    if params.len() != PARAMS_LEN {
        return Err(CtapError::InvalidCredential);
    }
    if !ct_eq(mac, &handle_mac(secret, params, rp_id_hash)?) {
        return Err(CtapError::InvalidCredential);
    }
    // Only this device writes what passes the MAC; the walk just reads it back.
    let mut d = Decoder::new(params);
    let items = def_arr(&mut d).map_err(|_| CtapError::InvalidCredential)?;
    let alg = d.i64().map_err(|_| CtapError::InvalidCredential)?;
    let flags = d.u8().map_err(|_| CtapError::InvalidCredential)?;
    let aux = d.bytes().map_err(|_| CtapError::InvalidCredential)?;
    if items != 3 {
        return Err(CtapError::InvalidCredential);
    }
    if alg != ALG_ESP256_SPLIT_ARKG || aux.len() != AUX_IKM_LEN || d.position() != params.len() {
        return Err(CtapError::InvalidCredential);
    }
    Ok(HandleParams {
        alg,
        flags,
        bytes: params,
    })
}

/// COSE_Sign_Args as `args` carries it: `alg` and the ARKG arguments; any other
/// label is ignored.
struct SignArgs<'a> {
    alg: Option<i64>,
    kh: Option<&'a [u8]>,
    ctx: Option<&'a [u8]>,
}

/// Parse `args`: exactly one CBOR map.
fn parse_args(raw: &[u8]) -> Result<SignArgs<'_>, CtapError> {
    let mut args = SignArgs {
        alg: None,
        kh: None,
        ctx: None,
    };
    let mut d = Decoder::new(raw);
    for _ in 0..def_map(&mut d)? {
        match cbor(d.i64())? {
            ARGS_ALG => args.alg = Some(cbor(d.i64())?),
            ARGS_ARKG_KH => args.kh = Some(cbor(d.bytes())?),
            ARGS_ARKG_CTX => args.ctx = Some(cbor(d.bytes())?),
            _ => skip_value(&mut d)?,
        }
    }
    if d.position() != raw.len() {
        return Err(CtapError::InvalidCbor);
    }
    Ok(args)
}

/// An assertion's signature, in the draft's order (v4 authentication steps 3–10):
/// the handle, `args`, the key's UP/UV policy against what this authData will say
/// (`up`, `uv`), then the ARKG key and `tbs`. `None` when nothing was asked.
pub(crate) fn sign(
    input: &GaInput<'_>,
    seed: &[u8; 32],
    key_input: &[u8],
    rp_id_hash: &[u8; 32],
    up: bool,
    uv: bool,
) -> Result<Option<DerSig>, CtapError> {
    if !input.present {
        return Ok(None);
    }
    let (Some(handle), Some(tbs)) = (input.kh, input.tbs) else {
        return Err(CtapError::InvalidOption);
    };
    let secret = credential_secret(seed, key_input);
    let params = open_handle(&secret, handle, rp_id_hash)?;
    // ESP256-split-ARKG cannot sign without its ARKG arguments.
    let args = parse_args(input.args.ok_or(CtapError::MissingParameter)?)?;
    if args.alg != Some(params.alg) {
        return Err(CtapError::InvalidCredential);
    }
    let (Some(arkg_kh), Some(ctx)) = (args.kh, args.ctx) else {
        return Err(CtapError::MissingParameter);
    };
    if tbs.len() != PREHASH_LEN {
        return Err(CtapError::InvalidLength);
    }
    if params.flags & FLAG_UP != 0 && !up {
        return Err(CtapError::UpRequired);
    }
    if params.flags & FLAG_UV != 0 && !uv {
        return Err(CtapError::PuatRequired);
    }
    let sk = arkg::derive_private_key(&seed_for(&secret, params.bytes)?, arkg_kh, ctx)
        .ok_or(CtapError::InvalidCredential)?;
    let sig = rsk_ec::sign_p256(sk.expose(), tbs).ok_or(CtapError::Other)?;
    let der = sig.to_der();
    let mut out = DerSig {
        der: [0; MAX_DER_SIG],
        len: der.as_bytes().len(),
    };
    out.der
        .get_mut(..out.len)
        .ok_or(CtapError::Other)?
        .copy_from_slice(der.as_bytes());
    Ok(Some(out))
}

/// The assertion's authData output: `"previewSign": {sig: signature}`.
pub(crate) fn write_ga_ext<W: Write>(enc: &mut Encoder<W>, sig: &DerSig) -> Result<(), CtapError> {
    let bytes = sig.bytes()?;
    enc.str(NAME)
        .and_then(|e| e.map(1)?.i64(KEY_SIG)?.bytes(bytes))
        .map_err(|_| CtapError::Other)?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "previewsign_tests.rs"]
mod tests;
