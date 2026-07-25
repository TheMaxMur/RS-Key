// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERATE ASYMMETRIC KEY PAIR (0x47), IMPORT ASYMMETRIC KEY (0xFE) and
//! ATTESTATION (0xF9). Generation writes a self-signed certificate into the
//! slot's certificate object (`70/71/FE`-wrapped, as `ykman` expects) so GET
//! DATA serves one immediately; IMPORT requires management-key auth.

use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{
    Curve, MAX_RSA_PUBDO, PrivKey, generate_rsa, make_ec_pubkey_do, make_rsa_response, rsa_from_pqe,
};
use rsk_sdk::tlv::find_tag;
use rsk_sdk::{ResBuf, Sw};
use zeroize::Zeroize;

use crate::files::*;
use crate::seal;
use crate::x509;
use crate::{Session, WRONG_DATA, wrap_cert_object};

// Yubico generation/import template policy tags.
const TAG_PIN_POLICY: u16 = 0xAA;
const TAG_TOUCH_POLICY: u16 = 0xAB;

/// Parsed `AC` generation template: algorithm + optional policy tags.
pub(crate) struct GenReq {
    pub algo: u8,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
}

pub(crate) fn parse_gen_template(data: &[u8]) -> Result<GenReq, Sw> {
    if data.is_empty() {
        return Err(Sw::WRONG_LENGTH);
    }
    if data[0] != TAG_GEN_TEMPLATE {
        return Err(WRONG_DATA);
    }
    let ac = find_tag(data, TAG_GEN_TEMPLATE as u16)
        .filter(|v| !v.is_empty())
        .ok_or(WRONG_DATA)?;
    let algo = find_tag(ac, 0x80)
        .filter(|v| !v.is_empty())
        .ok_or(WRONG_DATA)?[0];
    // SP 800-131A: no RSA-1024 generation under the FIPS-style profile. This is
    // the one template parser, so it also covers the firmware prime-search path.
    if cfg!(feature = "fips-profile") && algo == ALGO_RSA1024 {
        return Err(WRONG_DATA);
    }
    let pin_policy = find_tag(ac, TAG_PIN_POLICY).and_then(|v| v.first().copied());
    let touch_policy = find_tag(ac, TAG_TOUCH_POLICY).and_then(|v| v.first().copied());
    Ok(GenReq {
        algo,
        pin_policy,
        touch_policy,
    })
}

/// The PIV algorithm id for an RSA key, keyed off its modulus length in bytes
/// (`RsaPrivateKey::size()`): 128→1024, 256→2048, 384→3072, 512→4096. The single
/// source of truth for size→algo, shared by the firmware fast-path and the
/// display retired-slot store so they cannot drift.
pub(crate) fn rsa_algo_from_size(modulus_bytes: usize) -> Option<u8> {
    Some(match modulus_bytes {
        128 => ALGO_RSA1024,
        256 => ALGO_RSA2048,
        384 => ALGO_RSA3072,
        512 => ALGO_RSA4096,
        _ => return None,
    })
}

/// Inverse of [`rsa_algo_from_size`]: modulus length in bytes for a PIV RSA
/// algorithm id.
pub(crate) fn rsa_size_from_algo(algo: u8) -> Option<usize> {
    Some(match algo {
        ALGO_RSA1024 => 128,
        ALGO_RSA2048 => 256,
        ALGO_RSA3072 => 384,
        ALGO_RSA4096 => 512,
        _ => return None,
    })
}

/// Resolve the metadata policy bytes at store time (the stored value is never
/// `DEFAULT`): signature slot defaults to PIN-always.
pub(crate) fn resolved_policies(slot: u8, req_pin: Option<u8>, req_touch: Option<u8>) -> [u8; 2] {
    let def_pin = if slot == SLOT_SIGNATURE {
        PINPOLICY_ALWAYS
    } else {
        PINPOLICY_ONCE
    };
    [
        req_pin.unwrap_or(def_pin),
        req_touch.unwrap_or(TOUCHPOLICY_ALWAYS),
    ]
}

/// Build the slot's self-signed certificate and store it (70/71/FE-wrapped)
/// in the paired certificate object.
fn store_slot_cert<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
    spki: x509::Spki,
    signer: x509::Signer,
) -> Result<(), Sw> {
    let mut cert = [0u8; x509::MAX_CERT];
    let n = x509::build_cert(
        &x509::CertParams {
            subject_slot: slot,
            algo,
            spki,
            attestation: None,
            ca_pathlen: None,
        },
        &signer,
        rng,
        &mut cert,
    )?;
    let mut obj = [0u8; x509::MAX_CERT + 16];
    let on = wrap_cert_object(&cert[..n], &mut obj);
    let fid = cert_fid_for_slot(slot).ok_or(WRONG_DATA)?;
    fs.put(fid, &obj[..on]).map_err(|_| Sw::MEMORY_FAILURE)
}

/// The EC/EdDSA curve a non-RSA GENERATE algorithm produces.
pub(crate) fn curve_for_algo(algo: u8) -> Option<Curve> {
    Some(match algo {
        ALGO_ECCP256 => Curve::P256,
        ALGO_ECCP384 => Curve::P384,
        ALGO_ED25519 => Curve::Ed25519,
        ALGO_X25519 => Curve::X25519,
        _ => return None,
    })
}

/// Build + store the slot's self-signed certificate for a freshly minted EC or
/// Ed25519 key. X25519 is key-agreement-only and cannot self-sign, so — by
/// design — no certificate is written; a host/CA provisions one later via PUT
/// DATA (GET DATA then returns 6A82 until it does).
fn store_generated_cert<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
    curve: Curve,
    point: &[u8],
    key: &PrivKey,
) -> Result<(), Sw> {
    let (spki, signer) = match algo {
        ALGO_X25519 => return Ok(()),
        ALGO_ED25519 => (
            x509::Spki::Rfc8410 { curve, point },
            x509::Signer::Ed25519(key),
        ),
        _ => (x509::Spki::Ec { curve, point }, x509::Signer::Ec(key)),
    };
    store_slot_cert(fs, rng, slot, algo, spki, signer)
}

/// Build the metadata record for an EC key slot into `out`: the 4-byte
/// `[algo, pin_policy, touch_policy, origin]` head with the uncompressed public
/// `point` appended, so GET METADATA emits it (tag 0x04) instead of recomputing
/// `d·G` per probe. An empty `point` writes just the head (uncacheable path).
/// Returns the record length; `out` must be `>= 4 + point.len()`.
fn ec_slot_meta(algo: u8, pol: [u8; 2], origin: u8, point: &[u8], out: &mut [u8]) -> usize {
    out[0] = algo;
    out[1] = pol[0];
    out[2] = pol[1];
    out[3] = origin;
    out[4..4 + point.len()].copy_from_slice(point);
    4 + point.len()
}

/// EF_META bytes kept free for every slot's essential 4-byte head, so an optional
/// cached public point can never crowd a head out. Well above the max PIV meta
/// record count (4 active + 20 retired + card-mgmt + attestation slots) times the
/// 8-byte head record, so every slot's head — and thus provisioning — always fits.
pub(crate) const META_POINT_RESERVE: usize = 256;

/// Store a slot's meta record best-effort. `rec` is the 4-byte
/// `[algo, pin_pol, touch_pol, origin]` head, optionally followed by the cached
/// public point ([`ec_slot_meta`]). The head is essential (GET METADATA and the
/// PIN/touch gate read it); the point is only a GET METADATA speed-up. If the full
/// record would leave too little room for other slots' heads, store just the head
/// — GET METADATA then derives the point on the fly, exactly as for a key made by
/// pre-cache firmware. So the optional cache can never fail provisioning or leave a
/// key without its metadata, and EF_META stays bounded regardless of slot count.
pub(crate) fn meta_add_slot<S: Storage>(fs: &mut Fs<S>, fid: u16, rec: &[u8]) -> Result<(), Sw> {
    if fs.meta_add_reserve(fid, rec, META_POINT_RESERVE).is_ok() {
        return Ok(());
    }
    fs.meta_add(fid, &rec[..rec.len().min(4)])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Drop a slot's meta record just before an IMPORT commits its key.
///
/// Power-cut ordering: a tear then leaves the previous key with no origin record,
/// which [`attest`] refuses at its `meta_find`, rather than the imported key
/// paired with the previous key's `ORIGIN_GENERATED` — which it would certify.
pub(crate) fn drop_slot_meta<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Result<(), Sw> {
    fs.meta_delete(fid).map_err(|_| Sw::MEMORY_FAILURE)
}

/// The EC / Ed25519 / X25519 arm of GENERATE; RSA goes through
/// [`crate::PivApplet::rsa_generate_finish`] (the firmware runs the dual-core
/// prime search, CCID keepalives flowing meanwhile) or the blocking fallback
/// below.
pub(crate) fn generate_ec<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    req: &GenReq,
    res: &mut ResBuf,
) -> Sw {
    let Some(curve) = curve_for_algo(req.algo) else {
        return WRONG_DATA;
    };
    let Some(key) = PrivKey::generate(curve, rng) else {
        return Sw::EXEC_ERROR;
    };
    let mut point = [0u8; MAX_EC_POINT];
    let plen = match key.public_point(&mut point) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Err(e) = store_generated_cert(fs, rng, slot, req.algo, curve, &point[..plen], &key) {
        return e;
    }
    if let Err(e) = seal::store_ec_key(dev, fs, rng, key_fid(slot), &key) {
        return e;
    }
    // Cache the public point in its own per-slot file so GET METADATA stays O(1) at
    // any slot count — the shared EF_META cache fills after ~10 EC slots and the
    // rest would recompute d·G. Best-effort: on failure GET METADATA derives it.
    let _ = fs.put(pubkey_fid(slot), &point[..plen]);
    let pol = resolved_policies(slot, req.pin_policy, req.touch_policy);
    let mut mbuf = [0u8; 4 + MAX_EC_POINT];
    let mlen = ec_slot_meta(req.algo, pol, ORIGIN_GENERATED, &point[..plen], &mut mbuf);
    if let Err(e) = meta_add_slot(fs, key_fid(slot).get(), &mbuf[..mlen]) {
        return e;
    }
    let mut out = [0u8; 110];
    let n = make_ec_pubkey_do(&point[..plen], &mut out);
    if !res.extend(&out[..n]) {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}

/// Store a freshly generated RSA key + certificate and emit the
/// `7F49 { 81 N, 82 E }` response. Shared by the firmware keygen fast-path and
/// the blocking in-process fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_rsa<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
    pol: [u8; 2],
    key: &RsaPrivateKey,
    res: &mut ResBuf,
) -> Sw {
    let n = key.n().to_bytes_be();
    let e = key.e().to_bytes_be();
    if let Err(sw) = store_slot_cert(
        fs,
        rng,
        slot,
        algo,
        x509::Spki::Rsa { n: &n, e: &e },
        x509::Signer::Rsa(key),
    ) {
        return sw;
    }
    if let Err(sw) = seal::store_rsa_key(dev, fs, rng, key_fid(slot), key) {
        return sw;
    }
    if fs
        .meta_add(
            key_fid(slot).get(),
            &[algo, pol[0], pol[1], ORIGIN_GENERATED],
        )
        .is_err()
    {
        return Sw::MEMORY_FAILURE;
    }
    let mut out = [0u8; MAX_RSA_PUBDO];
    let dn = make_rsa_response(key, &mut out);
    if !res.extend(&out[..dn]) {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}

/// Blocking RSA generation — the in-process fallback (host tests; on-device the
/// firmware fast-path steps the prime search itself).
pub(crate) fn generate_rsa_blocking<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    req: &GenReq,
    res: &mut ResBuf,
) -> Sw {
    let Some(nbytes) = rsa_size_from_algo(req.algo) else {
        return WRONG_DATA;
    };
    let key = match generate_rsa(rng, nbytes * 8) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let pol = resolved_policies(slot, req.pin_policy, req.touch_policy);
    finish_rsa(dev, fs, rng, slot, req.algo, pol, &key, res)
}

/// On-device EC / EdDSA key generation into an empty retired slot (82–95), driven by
/// the trusted display. There is no management-key auth — physical presence at the panel
/// is the authorisation — so it is deliberately fenced to retired slots that hold no
/// key: it can only *add* a key, never overwrite one (the four primary slots and F9
/// stay USB-managed). EC P-256/P-384, Ed25519 and X25519 only — these are instant; RSA
/// runs its slow dual-core prime search in the firmware and persists via
/// [`store_retired_rsa`]. Stores the sealed key, the self-signed cert (none for X25519,
/// which can't self-sign) and the metadata, the same writes the host GENERATE makes, so
/// `ykman` / GET DATA see a normal slot after.
pub(crate) fn generate_retired_ec<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
) -> Result<(), Sw> {
    if !is_retired(slot) {
        return Err(Sw::INCORRECT_P1P2);
    }
    // Never clobber a key on-device: overwriting a retired slot needs USB + mgmt-key.
    if fs.has_key(key_fid(slot)) {
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let curve = curve_for_algo(algo).ok_or(WRONG_DATA)?;
    let Some(key) = PrivKey::generate(curve, rng) else {
        return Err(Sw::EXEC_ERROR);
    };
    let mut point = [0u8; MAX_EC_POINT];
    let plen = key.public_point(&mut point)?;
    store_generated_cert(fs, rng, slot, algo, curve, &point[..plen], &key)?;
    seal::store_ec_key(dev, fs, rng, key_fid(slot), &key)?;
    let pol = resolved_policies(slot, None, None);
    let mut mbuf = [0u8; 4 + MAX_EC_POINT];
    let mlen = ec_slot_meta(algo, pol, ORIGIN_GENERATED, &point[..plen], &mut mbuf);
    meta_add_slot(fs, key_fid(slot).get(), &mbuf[..mlen])
}

/// Persist a display-generated RSA key into an empty retired slot — the RSA companion
/// to [`generate_retired_ec`]. The slow prime search runs in the firmware (dual-core,
/// off this function), so this only writes the result: the self-signed cert, the sealed
/// key and the metadata, with the same empty-retired-slot fence (it can only *add* a
/// key, never overwrite one; the four primary slots and F9 stay USB-managed).
pub(crate) fn store_retired_rsa<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    key: &RsaPrivateKey,
) -> Result<(), Sw> {
    if !is_retired(slot) {
        return Err(Sw::INCORRECT_P1P2);
    }
    if fs.has_key(key_fid(slot)) {
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let algo = rsa_algo_from_size(key.size()).ok_or(Sw::EXEC_ERROR)?;
    let n = key.n().to_bytes_be();
    let e = key.e().to_bytes_be();
    store_slot_cert(
        fs,
        rng,
        slot,
        algo,
        x509::Spki::Rsa { n: &n, e: &e },
        x509::Signer::Rsa(key),
    )?;
    seal::store_rsa_key(dev, fs, rng, key_fid(slot), key)?;
    let pol = resolved_policies(slot, None, None);
    fs.meta_add(
        key_fid(slot).get(),
        &[algo, pol[0], pol[1], ORIGIN_GENERATED],
    )
    .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Import an RSA key from its CRT primes (tags 0x01 `p`, 0x02 `q`), fixing the
/// public exponent at 65537; the modulus size must match the requested algo.
fn import_rsa<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    algo: u8,
    slot: u8,
    data: &[u8],
) -> Result<(), Sw> {
    let p = find_tag(data, 0x01).filter(|v| !v.is_empty());
    let q = find_tag(data, 0x02).filter(|v| !v.is_empty());
    let (Some(p), Some(q)) = (p, q) else {
        return Err(WRONG_DATA);
    };
    let Some(key) = rsa_from_pqe(&[0x01, 0x00, 0x01], p, q) else {
        return Err(Sw::EXEC_ERROR);
    };
    let Some(want) = rsa_size_from_algo(algo) else {
        return Err(WRONG_DATA);
    };
    if key.size() != want {
        return Err(WRONG_DATA);
    }
    drop_slot_meta(fs, key_fid(slot).get())?;
    seal::store_rsa_key(dev, fs, rng, key_fid(slot), &key)
}

/// Import a NIST-curve key from its scalar (tag 0x06); rejects a zero/invalid
/// scalar early by deriving the public point.
fn import_ec<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    algo: u8,
    slot: u8,
    data: &[u8],
) -> Result<(), Sw> {
    let Some(scalar) = find_tag(data, 0x06).filter(|v| !v.is_empty()) else {
        return Err(WRONG_DATA);
    };
    let Some(curve) = curve_for_algo(algo) else {
        return Err(WRONG_DATA);
    };
    let field = if algo == ALGO_ECCP256 { 32 } else { 48 };
    if scalar.len() > field {
        return Err(WRONG_DATA);
    }
    let Some(key) = PrivKey::from_scalar(curve, scalar) else {
        return Err(WRONG_DATA);
    };
    // Reject the zero/invalid scalar early: deriving the public point fails for
    // out-of-range keys.
    let mut pt = [0u8; MAX_EC_POINT];
    if key.public_point(&mut pt).is_err() {
        return Err(WRONG_DATA);
    }
    drop_slot_meta(fs, key_fid(slot).get())?;
    seal::store_ec_key(dev, fs, rng, key_fid(slot), &key)
}

/// Import an Edwards-curve key from its raw 32-byte seed/scalar (tag 0x07
/// Ed25519, 0x08 X25519).
fn import_edwards<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    algo: u8,
    slot: u8,
    data: &[u8],
) -> Result<(), Sw> {
    // yubikit tags the raw 32-byte seed/scalar 0x07 (Ed25519) / 0x08 (X25519).
    let (tag, curve) = if algo == ALGO_ED25519 {
        (0x07u16, Curve::Ed25519)
    } else {
        (0x08u16, Curve::X25519)
    };
    let Some(scalar) = find_tag(data, tag).filter(|v| !v.is_empty()) else {
        return Err(WRONG_DATA);
    };
    if scalar.len() > 32 {
        return Err(WRONG_DATA);
    }
    // ykman / yubico-piv-tool import the X25519 private key little-endian
    // (RFC 8410 / RFC 7748); `PrivKey` keeps the scalar as a big-endian MPI
    // (keys.rs reverses it for the curve op), so flip the imported bytes — else
    // the slot's public key disagrees with the key's real identity and ciphertext
    // bound to it can't be decrypted. Ed25519's tag 0x07 is a hash seed, not an
    // integer, so it is imported verbatim.
    let mut flipped = [0u8; 32];
    let scalar = if algo == ALGO_X25519 {
        let n = scalar.len();
        for (i, &b) in scalar.iter().enumerate() {
            flipped[n - 1 - i] = b;
        }
        &flipped[..n]
    } else {
        scalar
    };
    let key = PrivKey::from_scalar(curve, scalar);
    flipped.zeroize();
    let Some(key) = key else {
        return Err(WRONG_DATA);
    };
    drop_slot_meta(fs, key_fid(slot).get())?;
    seal::store_ec_key(dev, fs, rng, key_fid(slot), &key)
}

/// IMPORT ASYMMETRIC KEY; gated on management-key auth.
pub(crate) fn import<S: Storage>(
    sess: &Session,
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    algo: u8,
    slot: u8,
    data: &[u8],
) -> Sw {
    if !is_key(slot) {
        return Sw::INCORRECT_P1P2;
    }
    if !sess.has_mgm {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    // SP 800-131A: no RSA-1024 import under the FIPS-style profile either.
    if cfg!(feature = "fips-profile") && algo == ALGO_RSA1024 {
        return WRONG_DATA;
    }
    let pin_policy = find_tag(data, TAG_PIN_POLICY).and_then(|v| v.first().copied());
    let touch_policy = find_tag(data, TAG_TOUCH_POLICY).and_then(|v| v.first().copied());
    let stored = match algo {
        ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096 => {
            import_rsa(dev, fs, rng, algo, slot, data)
        }
        ALGO_ECCP256 | ALGO_ECCP384 => import_ec(dev, fs, rng, algo, slot, data),
        ALGO_ED25519 | ALGO_X25519 => import_edwards(dev, fs, rng, algo, slot, data),
        _ => Err(WRONG_DATA),
    };
    if let Err(sw) = stored {
        return sw;
    }
    let pol = resolved_policies(slot, pin_policy, touch_policy);
    // Cache the public point for EC slots (import is not a hot path, so derive it
    // once from the freshly sealed key); RSA keeps the bare 4-byte record.
    let mut mbuf = [0u8; 4 + MAX_EC_POINT];
    let mlen = if matches!(
        algo,
        ALGO_ECCP256 | ALGO_ECCP384 | ALGO_ED25519 | ALGO_X25519
    ) {
        let mut point = [0u8; MAX_EC_POINT];
        match seal::load_ec_key(dev, fs, key_fid(slot)).and_then(|k| k.public_point(&mut point)) {
            Ok(plen) => {
                let _ = fs.put(pubkey_fid(slot), &point[..plen]);
                ec_slot_meta(algo, pol, ORIGIN_IMPORTED, &point[..plen], &mut mbuf)
            }
            Err(_) => ec_slot_meta(algo, pol, ORIGIN_IMPORTED, &[], &mut mbuf),
        }
    } else {
        ec_slot_meta(algo, pol, ORIGIN_IMPORTED, &[], &mut mbuf)
    };
    if let Err(e) = meta_add_slot(fs, key_fid(slot).get(), &mbuf[..mlen]) {
        return e;
    }
    Sw::OK
}

/// Build an attestation certificate for a *generated* slot key, signed by the
/// F9 key, returned as bare DER (as real YubiKeys do).
pub(crate) fn attest<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    serial4: [u8; 4],
    res: &mut ResBuf,
) -> Sw {
    if !is_key(slot) {
        return Sw::REFERENCE_NOT_FOUND;
    }
    if !fs.has_key(key_fid(slot)) {
        return Sw::REFERENCE_NOT_FOUND;
    }
    let mut meta = [0u8; 8];
    let Some(meta_len) = fs.meta_find(key_fid(slot).get(), &mut meta) else {
        return Sw::REFERENCE_NOT_FOUND;
    };
    if meta_len < 4 || meta[3] != ORIGIN_GENERATED {
        return Sw::INCORRECT_PARAMS;
    }
    let f9 = match seal::load_ec_key(dev, fs, key_fid(SLOT_ATTESTATION)) {
        Ok(k) => k,
        Err(e) => return e,
    };
    // The attestation serial is the device serial as a raw little-endian u32.
    let serial_le = [serial4[3], serial4[2], serial4[1], serial4[0]];
    let att = x509::AttestExt {
        firmware: [crate::VERSION.0, crate::VERSION.1, crate::VERSION.2],
        serial_le,
        policy: [meta[1], meta[2]],
    };
    let mut cert = [0u8; x509::MAX_CERT];
    let built = match meta[0] {
        ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096 => {
            let key = match seal::load_rsa_key(dev, fs, key_fid(slot)) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let n = key.n().to_bytes_be();
            let e = key.e().to_bytes_be();
            x509::build_cert(
                &x509::CertParams {
                    subject_slot: slot,
                    algo: meta[0],
                    spki: x509::Spki::Rsa { n: &n, e: &e },
                    attestation: Some(att),
                    ca_pathlen: None,
                },
                &x509::Signer::Ec(&f9),
                rng,
                &mut cert,
            )
        }
        ALGO_ECCP256 | ALGO_ECCP384 => {
            let key = match seal::load_ec_key(dev, fs, key_fid(slot)) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let mut point = [0u8; MAX_EC_POINT];
            let plen = match key.public_point(&mut point) {
                Ok(n) => n,
                Err(e) => return e,
            };
            x509::build_cert(
                &x509::CertParams {
                    subject_slot: slot,
                    algo: meta[0],
                    spki: x509::Spki::Ec {
                        curve: key.curve(),
                        point: &point[..plen],
                    },
                    attestation: Some(att),
                    ca_pathlen: None,
                },
                &x509::Signer::Ec(&f9),
                rng,
                &mut cert,
            )
        }
        ALGO_ED25519 | ALGO_X25519 => {
            let key = match seal::load_ec_key(dev, fs, key_fid(slot)) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let mut point = [0u8; MAX_EC_POINT];
            let plen = match key.public_point(&mut point) {
                Ok(n) => n,
                Err(e) => return e,
            };
            x509::build_cert(
                &x509::CertParams {
                    subject_slot: slot,
                    algo: meta[0],
                    spki: x509::Spki::Rfc8410 {
                        curve: key.curve(),
                        point: &point[..plen],
                    },
                    attestation: Some(att),
                    ca_pathlen: None,
                },
                &x509::Signer::Ec(&f9),
                rng,
                &mut cert,
            )
        }
        _ => return WRONG_DATA,
    };
    let n = match built {
        Ok(n) => n,
        Err(e) => return e,
    };
    let ok = res.extend(&cert[..n]);
    cert.zeroize();
    if !ok {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}
