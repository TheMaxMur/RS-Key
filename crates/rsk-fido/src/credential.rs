// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Credential IDs. A CTAP2 credential ID is a self-contained ChaCha20-Poly1305
//! box: a CBOR map of the credential's metadata, encrypted under a key derived
//! from the device seed, with the rpId hash as AEAD associated data. Layout:
//!
//! ```text
//! iv(12) ‖ ciphertext ‖ poly1305_tag(16) ‖ silent_tag(16)
//! ```
//!
//! There is no cleartext prefix: the box is indistinguishable from random, so a
//! credential id carries no device- or model-fingerprint an RP could link on
//! (WebAuthn unlinkability — a YubiKey's ids look random for the same reason).
//! The encryption key comes from a fixed internal `CRED_PROTO` label, never from
//! an on-wire byte. [`verify_decrypt`] still opens the legacy `f1d00202`-prefixed
//! boxes relying parties registered before this format — the poly1305 tag tells
//! the framings apart, so old credentials keep working across the upgrade.
//!
//! The silent tag binds the box to this device + rp without decrypting it.
//! Resident credentials additionally derive a 42-byte "resident id" that is what
//! the authenticator returns to the RP; the full box is kept in flash.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::{
    Device, chacha20poly1305_decrypt, chacha20poly1305_encrypt, hmac_sha256, hmac_sha512, sha256,
};
use rsk_fs::{Fs, Storage};
use rsk_sdk::error::{Error, Result};

use crate::consts::{
    ALG_ES256, CURVE_P256, EF_CRED, EF_RP, MAX_CREDBLOB_LENGTH, MAX_RESIDENT_CREDENTIALS,
    RP_NICK_MAX_LEN,
};

// `MAX_CREDBLOB_LENGTH` (128) over-bounds the sealable credBlob (`< 128`), a
// harmless 1-byte slack in `CRED_BOX_MAX`.
use crate::keyderiv::{KEY_HANDLE_LEN, verify_key};

const CRED_PROTO: &[u8; 4] = b"\xf1\xd0\x02\x02";
const CRED_PROTO_RESIDENT: &[u8; 4] = b"\xf1\xd0\x02\x03";
/// Derive label for the EF_RP rpId box — domain-separated from the credential-id
/// protos so the rpId box key can never coincide with a cred-box key.
const RP_PROTO: &[u8] = b"RS-Key/EF_RP/rpId";
/// Derive label for the device-local EF_RPNICK box — its own domain so the nickname
/// box key is distinct from the rpId box and every cred-box key.
const NICK_PROTO: &[u8] = b"RS-Key/EF_RPNICK/nick";
const PROTO_LEN: usize = 4;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SILENT_TAG_LEN: usize = 16;
/// Legacy header before the ciphertext on a prefixed box: proto + iv.
const HEAD_LEN: usize = PROTO_LEN + IV_LEN; // 16
/// Bytes wrapping the ciphertext on a legacy proto-0x02 box: head + poly + silent.
const WRAP_LEN_22: usize = HEAD_LEN + TAG_LEN + SILENT_TAG_LEN; // 48
/// Bytes wrapping the ciphertext on a current (prefix-free) box: iv + poly + silent.
const WRAP_LEN: usize = IV_LEN + TAG_LEN + SILENT_TAG_LEN; // 44

// --- Sealed-field maxima. makeCredential enforces the first three (over-max
// input → InvalidLength) and truncates the names, so the box ceiling below is a
// TRUE bound for every accepted request. ---

/// rpId ceiling — the DNS name maximum, shared by the non-resident box and the
/// resident EF_RP record ([`RP_REC_MAX`]).
pub(crate) const RP_ID_MAX: usize = 253;
/// user.id ceiling (WebAuthn: 1..=64 bytes). getAssertion already echoes at most
/// this many, so the box never stores more.
pub(crate) const USER_ID_MAX: usize = 64;
/// user.name / user.displayName ceiling — CTAP 2.1 §6.1.2 sanctions truncating
/// to it rather than erroring.
pub(crate) const USER_NAME_MAX: usize = 64;

/// The one credential-box ceiling: create (makeCredential), assert
/// (getAssertion's `Best::id`) and reseal (credMgmt update) all size from it —
/// a divergent assert cap strands fresh credentials (create OK, assert skips).
///
/// DERIVED from the field maxima so it can never again drift below what the
/// device accepts (the 640 literal it replaced omitted credBlob + extensions
/// and under-sized the box once `RP_ID_MAX` rose to 253). Every optional field
/// present, every string at its cap; `9` is the u64/i64 CBOR worst case, string
/// headers are 2 bytes at 24..=255.
const CBOR_KEY: usize = 1;
const CBOR_STR_HDR: usize = 2;
const CBOR_U64: usize = 9;
const MAX_EXT_BODY: usize = CBOR_KEY
    + 1 // sub-map header
    + (1 + 8) + CBOR_STR_HDR + MAX_CREDBLOB_LENGTH // "credBlob" + bytes
    + (1 + 11) + CBOR_U64 // "credProtect" + u64
    + (1 + 11) + 1 // "hmac-secret" + bool
    + (1 + 12) + 1 // "largeBlobKey" + bool
    + (1 + 17) + 1; // "thirdPartyPayment" + bool
const MAX_BODY: usize = 1 // outer map header (<24 fields)
    + CBOR_KEY + CBOR_STR_HDR + RP_ID_MAX // 1: rpId
    + CBOR_KEY + CBOR_STR_HDR + USER_ID_MAX // 3: userId
    + CBOR_KEY + CBOR_STR_HDR + USER_NAME_MAX // 4: name
    + CBOR_KEY + CBOR_STR_HDR + USER_NAME_MAX // 5: displayName
    + CBOR_KEY + CBOR_U64 // 6: createdMs
    + MAX_EXT_BODY // 7: extensions
    + CBOR_KEY + 1 // 8: useSignCount
    + CBOR_KEY + CBOR_U64 // 9: alg
    + CBOR_KEY + CBOR_U64 // 10: curve
    + CBOR_KEY + 1; // 11: rk
pub(crate) const CRED_BOX_MAX: usize = WRAP_LEN_22 + MAX_BODY;

/// Truncate `s` to at most `max` bytes on a UTF-8 character boundary.
pub(crate) fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Largest EF_RPNICK record: `iv(12) ‖ ciphertext ‖ tag(16)` for a max-length nickname.
pub(crate) const NICK_BOX_MAX: usize = IV_LEN + RP_NICK_MAX_LEN + TAG_LEN;

/// Resident-id length.
pub const CRED_RESIDENT_LEN: usize = 42;

/// Offset of the LEGACY resident-id version marker (v1–v3) — a header byte at
/// `[8]`, behind the `f1d00203` marker at `[4..8]`. Current v4 ids are prefix-free
/// and carry no marker; this offset is still read to key legacy ids off the box
/// (v1) vs. the stable id (v2/v3) and to size their record trailer (v3). See
/// [`resident_keys_off_id`] / [`resident_has_trailer`].
const RESIDENT_VERSION_IDX: usize = 8;
/// Legacy v2 marker: the signing / hmac-secret / largeBlobKey keys derive from
/// the STABLE resident id, so they survive an updateUserInformation reseal
/// (CTAP2.1 §6.8). Legacy v1 credentials (implicit marker 0) key off the box; v4
/// ids (no marker) also key off the stable id. Already-provisioned devices stay
/// byte-for-byte compatible across the upgrade.
const RESIDENT_VERSION_V2: u8 = 1;
/// Legacy v3 marker: v2 key-derivation semantics PLUS a length-prefixed cached
/// public key in the EF_CRED record (see [`compose_cred_record`]), so enumeration
/// emits the stored point instead of recomputing `d·G` per call — the dominant
/// per-credential cost on this MCU's software EC. v4 records carry the same
/// trailer; legacy v1/v2 records without it keep deriving the point on the fly.
const RESIDENT_VERSION_V3: u8 = 2;

/// Credential extensions sealed into the box. `minPinLength` is not stored —
/// it is a request-only flag that gates the authData `minPINLength` output.
#[derive(Clone, Copy, Default)]
pub struct CredExt<'a> {
    pub cred_protect: u64,
    pub cred_blob: &'a [u8],
    pub hmac_secret: bool,
    pub large_blob_key: bool,
    pub third_party_payment: bool,
}

impl CredExt<'_> {
    /// Whether this credBlob is short enough to seal (`< MAX_CREDBLOB_LENGTH`).
    fn cred_blob_ok(&self) -> bool {
        !self.cred_blob.is_empty() && self.cred_blob.len() < MAX_CREDBLOB_LENGTH
    }

    /// Number of entries the box's field-0x07 sub-map would carry.
    fn box_entries(&self) -> u64 {
        u64::from(self.cred_blob_ok())
            + u64::from(self.cred_protect != 0)
            + u64::from(self.hmac_secret)
            + u64::from(self.large_blob_key)
            + u64::from(self.third_party_payment)
    }
}

/// Inputs to [`credential_create`] — the request fields to seal into the box.
pub struct CredInput<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub use_sign_count: bool,
    pub rk: bool,
    pub created_ms: u64,
    /// COSE algorithm + FIDO curve (`CURVE_*`). Stored only when non-default
    /// (ES256/P-256), so existing P-256 boxes stay byte-identical.
    pub alg: i64,
    pub curve: i64,
    pub ext: CredExt<'a>,
}

/// A decrypted credential, borrowing the caller's scratch buffer.
pub struct Credential<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub use_sign_count: bool,
    pub rk: bool,
    pub alg: i64,
    pub curve: i64,
    /// Creation timestamp (device uptime) — getAssertion picks the newest match.
    pub created: u64,
    pub ext: CredExt<'a>,
    /// A U2F/CTAP1 key handle loaded via the [`credential_load`] fallback (no
    /// sealed body): getAssertion signs it with the path-as-is scalar
    /// ([`crate::keyderiv::verify_key`]), not the CTAP2 `fido_load_key` derivation.
    pub u2f: bool,
}

/// The box encryption key: a SLIP-0022 HMAC chain over the device seed.
fn derive_chacha_key(seed: &[u8; 32], proto: &[u8]) -> [u8; 32] {
    let mut k = hmac_sha256(seed, b"SLIP-0022");
    k = hmac_sha256(&k, proto);
    hmac_sha256(&k, b"Encryption key")
}

/// The silent tag: HMAC(SHA256(serial‖rpIdHash), prefix)[..16] where `prefix`
/// is the whole box except the silent tag.
///
/// Write-only: boxes are verified by decrypting (the chacha key comes from the
/// seed), never by this tag, so OTP-MKEK provisioning switching the tag source
/// from `serial_id` to `otp_key` cannot orphan old boxes. Any future change
/// that starts CHECKING the tag must accept both sources — pre-OTP credentials
/// carry serial-keyed tags.
fn silent_tag(dev: &Device, prefix: &[u8], rp_id_hash: &[u8; 32]) -> [u8; SILENT_TAG_LEN] {
    let src = dev.otp_key.map(|o| &o[..]).unwrap_or(dev.serial_id);
    let mut buf = [0u8; 64];
    buf[..src.len()].copy_from_slice(src);
    buf[src.len()..src.len() + 32].copy_from_slice(rp_id_hash);
    let k = sha256(&buf[..src.len() + 32]);
    let full = hmac_sha256(&k, prefix);
    let mut tag = [0u8; SILENT_TAG_LEN];
    tag.copy_from_slice(&full[..SILENT_TAG_LEN]);
    tag
}

/// Does this id carry the legacy `f1d00203` resident marker at `[4..8]`? Only
/// v1–v3 ids do; a current v4 resident id is prefix-free (see [`derive_resident`]),
/// so this drives the v1/v2/v3-vs-v4 format dispatch, not the allowList routing —
/// which is length-based ([`CRED_RESIDENT_LEN`]) so it catches both.
pub fn is_resident(data: &[u8]) -> bool {
    data.len() >= PROTO_LEN + 4 && &data[4..8] == CRED_PROTO_RESIDENT
}

/// Seal `input` into a credential box written to `out`. `iv` is
/// caller-supplied randomness. Returns the box length.
pub fn credential_create(
    seed: &[u8; 32],
    dev: &Device,
    input: &CredInput,
    rp_id_hash: &[u8; 32],
    iv: &[u8; IV_LEN],
    out: &mut [u8],
) -> Result<usize> {
    if out.len() < WRAP_LEN {
        return Err(Error::NoMemory);
    }
    // Encode the inner CBOR straight into the ciphertext slot (out[12..], right
    // after the iv — no cleartext prefix).
    let body_end = out.len() - TAG_LEN - SILENT_TAG_LEN;
    let rs = {
        let mut enc = Encoder::new(Cursor::new(&mut out[IV_LEN..body_end]));
        encode_body(&mut enc, input).map_err(|_| Error::NoMemory)?;
        enc.writer().position()
    };

    // The key label is a fixed internal constant, decoupled from the wire bytes,
    // so the box need not carry it. `verify_decrypt` re-derives from the same
    // label for the prefix-free trial.
    let mut key = derive_chacha_key(seed, CRED_PROTO);
    let tag = chacha20poly1305_encrypt(&key, iv, rp_id_hash, &mut out[IV_LEN..IV_LEN + rs]);
    key.zeroize();

    out[..IV_LEN].copy_from_slice(iv);
    out[IV_LEN + rs..IV_LEN + rs + TAG_LEN].copy_from_slice(&tag);

    let prefix_len = IV_LEN + rs + TAG_LEN;
    let st = silent_tag(dev, &out[..prefix_len], rp_id_hash);
    out[prefix_len..prefix_len + SILENT_TAG_LEN].copy_from_slice(&st);
    Ok(prefix_len + SILENT_TAG_LEN)
}

fn encode_body<W: minicbor::encode::Write>(
    enc: &mut Encoder<W>,
    c: &CredInput,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    let ext_n = c.ext.box_entries();
    // alg/curve are stored only for non-default curves (P-256 boxes stay identical).
    let store_alg = c.curve != CURVE_P256 as i64;
    let mut n = 4u64; // rpId, userId, created, use_sign_count
    if !c.user_name.is_empty() {
        n += 1;
    }
    if !c.user_display_name.is_empty() {
        n += 1;
    }
    if ext_n > 0 {
        n += 1;
    }
    if store_alg {
        n += 2;
    }
    if c.rk {
        n += 1;
    }
    enc.map(n)?;
    enc.u8(1)?.str(c.rp_id)?;
    enc.u8(3)?.bytes(c.user_id)?;
    if !c.user_name.is_empty() {
        enc.u8(4)?.str(c.user_name)?;
    }
    if !c.user_display_name.is_empty() {
        enc.u8(5)?.str(c.user_display_name)?;
    }
    enc.u8(6)?.u64(c.created_ms)?;
    if ext_n > 0 {
        enc.u8(7)?.map(ext_n)?;
        if c.ext.cred_blob_ok() {
            enc.str("credBlob")?.bytes(c.ext.cred_blob)?;
        }
        if c.ext.cred_protect != 0 {
            enc.str("credProtect")?.u64(c.ext.cred_protect)?;
        }
        if c.ext.hmac_secret {
            enc.str("hmac-secret")?.bool(true)?;
        }
        if c.ext.large_blob_key {
            enc.str("largeBlobKey")?.bool(true)?;
        }
        if c.ext.third_party_payment {
            enc.str("thirdPartyPayment")?.bool(true)?;
        }
    }
    enc.u8(8)?.bool(c.use_sign_count)?;
    if store_alg {
        enc.u8(9)?.i64(c.alg)?;
        enc.u8(10)?.i64(c.curve)?;
    }
    if c.rk {
        enc.u8(11)?.bool(true)?;
    }
    Ok(())
}

/// Try one candidate framing. The iv sits at `orig[iv_off..iv_off+IV_LEN]`, the
/// ciphertext right after it, and `trailing` bytes follow the ciphertext (the
/// poly1305 tag, plus a silent tag for the 32-byte case). Copies `orig` into
/// `scratch`, decrypts in place under `key_label`, and on an authentic tag leaves
/// the plaintext at `scratch[iv_off+IV_LEN..][..pt_len]`, returning `pt_len`.
fn try_format(
    seed: &[u8; 32],
    orig: &[u8],
    rp_id_hash: &[u8; 32],
    scratch: &mut [u8],
    iv_off: usize,
    key_label: &[u8],
    trailing: usize,
) -> Option<usize> {
    let len = orig.len();
    let ct_off = iv_off + IV_LEN;
    if len < ct_off + trailing || len > scratch.len() {
        return None;
    }
    let ct_len = len - ct_off - trailing;
    scratch[..len].copy_from_slice(orig);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&scratch[iv_off..ct_off]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&scratch[ct_off + ct_len..ct_off + ct_len + TAG_LEN]);
    let mut key = derive_chacha_key(seed, key_label);
    let res = chacha20poly1305_decrypt(
        &key,
        &iv,
        rp_id_hash,
        &mut scratch[ct_off..ct_off + ct_len],
        &tag,
    );
    key.zeroize();
    res.ok()?;
    Some(ct_len)
}

/// Decrypt `cred_id` into `scratch`, trying the current prefix-free framing first
/// and the legacy prefixed framings as a fallback. On success returns
/// `(ciphertext_offset, plaintext_len)` — the plaintext sits at
/// `scratch[offset..offset+len]`. The poly1305 tag decides which framing is
/// authentic, so an IV that happens to begin with `f1d00202` is still resolved
/// correctly; a wrongly-framed trial garbles `scratch`, which the next trial's
/// copy overwrites.
fn verify_decrypt(
    seed: &[u8; 32],
    cred_id: &[u8],
    rp_id_hash: &[u8; 32],
    scratch: &mut [u8],
) -> Option<(usize, usize)> {
    // Current format: iv ‖ ct ‖ poly ‖ silent, key from the fixed CRED_PROTO
    // label, no on-wire prefix.
    if let Some(pt) = try_format(
        seed,
        cred_id,
        rp_id_hash,
        scratch,
        0,
        CRED_PROTO,
        TAG_LEN + SILENT_TAG_LEN,
    ) {
        return Some((IV_LEN, pt));
    }
    if cred_id.len() < PROTO_LEN {
        return None;
    }
    if &cred_id[..PROTO_LEN] == CRED_PROTO {
        // Legacy proto-0x02: f1d00202 ‖ iv ‖ ct ‖ poly ‖ silent.
        if let Some(pt) = try_format(
            seed,
            cred_id,
            rp_id_hash,
            scratch,
            PROTO_LEN,
            CRED_PROTO,
            TAG_LEN + SILENT_TAG_LEN,
        ) {
            return Some((HEAD_LEN, pt));
        }
    } else if let Some(pt) = try_format(
        seed,
        cred_id,
        rp_id_hash,
        scratch,
        PROTO_LEN,
        &cred_id[..PROTO_LEN],
        TAG_LEN,
    ) {
        // Even older: proto ‖ iv ‖ ct ‖ poly (no silent tag), key from the proto.
        return Some((HEAD_LEN, pt));
    }
    None
}

/// Verify and parse a box into a [`Credential`] borrowing `scratch` (which
/// must be ≥ `cred_id.len()`).
pub fn credential_load<'a>(
    seed: &[u8; 32],
    cred_id: &[u8],
    rp_id_hash: &[u8; 32],
    scratch: &'a mut [u8],
) -> Option<Credential<'a>> {
    if cred_id.len() > scratch.len() {
        return None;
    }
    if let Some((off, pt_len)) = verify_decrypt(seed, cred_id, rp_id_hash, scratch) {
        return parse_body(&scratch[off..off + pt_len]);
    }
    // U2F fallback: a 64-byte path‖tag handle that verifies against this rp
    // loads as a minimal P-256 credential with no sealed body.
    if let Ok(kh) = <&[u8; KEY_HANDLE_LEN]>::try_from(cred_id)
        && verify_key(seed, rp_id_hash, kh).is_some()
    {
        return Some(Credential {
            rp_id: "",
            user_id: &[],
            user_name: "",
            user_display_name: "",
            use_sign_count: false,
            rk: false,
            alg: ALG_ES256,
            curve: CURVE_P256 as i64,
            created: 0,
            ext: CredExt::default(),
            u2f: true,
        });
    }
    None
}

fn parse_body(cbor: &[u8]) -> Option<Credential<'_>> {
    let mut d = Decoder::new(cbor);
    let mut cred = Credential {
        rp_id: "",
        user_id: &[],
        user_name: "",
        user_display_name: "",
        use_sign_count: false,
        rk: false,
        alg: ALG_ES256,
        curve: CURVE_P256 as i64,
        created: 0,
        ext: CredExt::default(),
        u2f: false,
    };
    let entries = d.map().ok()??;
    for _ in 0..entries {
        match d.u32().ok()? {
            1 => cred.rp_id = d.str().ok()?,
            3 => cred.user_id = d.bytes().ok()?,
            4 => cred.user_name = d.str().ok()?,
            5 => cred.user_display_name = d.str().ok()?,
            6 => cred.created = d.u64().ok()?,
            7 => {
                let m = d.map().ok()??;
                for _ in 0..m {
                    match d.str().ok()? {
                        "credProtect" => cred.ext.cred_protect = d.u64().ok()?,
                        "credBlob" => cred.ext.cred_blob = d.bytes().ok()?,
                        "hmac-secret" => cred.ext.hmac_secret = d.bool().ok()?,
                        "largeBlobKey" => cred.ext.large_blob_key = d.bool().ok()?,
                        "thirdPartyPayment" => cred.ext.third_party_payment = d.bool().ok()?,
                        _ => d.skip().ok()?,
                    }
                }
            }
            8 => cred.use_sign_count = d.bool().ok()?,
            9 => cred.alg = d.i64().ok()?,
            10 => cred.curve = d.i64().ok()?,
            11 => cred.rk = d.bool().ok()?,
            _ => d.skip().ok()?,
        }
    }
    Some(cred)
}

/// The 42-byte resident id returned to the RP for a resident credential — the
/// authenticator's lookup key for the box it keeps in flash.
///
/// v4 (current): 42 pseudo-random bytes, an HMAC of the box keyed by the device
/// serial. It carries no device- or model-fingerprint — every byte depends on
/// the box, whose random IV makes each id unique — so two ids from one device
/// share nothing an RP could link on, exactly as a YubiKey's random ids don't
/// (WebAuthn unlinkability). Legacy v1–v3 ids instead led with a
/// `serial-derived(4) ‖ f1d00203(4) ‖ version ‖ 00` header; those stay stored
/// byte-for-byte and keep deriving via the old scheme, and the two formats are
/// told apart by that `f1d00203` marker — which v4 guarantees it never carries,
/// so a v4 id is never mis-read as legacy and mis-keyed off the box.
///
/// Called ONLY at create time; the result is stored and read back verbatim on
/// every lookup, so changing this scheme cannot strand already-issued ids.
pub fn derive_resident(cred_id: &[u8], dev: &Device) -> [u8; CRED_RESIDENT_LEN] {
    let mut outk = [0u8; CRED_RESIDENT_LEN];
    let a = hmac_sha256(dev.serial_id, cred_id);
    let b = hmac_sha256(&a, b"resident-id");
    outk[..32].copy_from_slice(&a);
    outk[32..].copy_from_slice(&b[..CRED_RESIDENT_LEN - 32]);
    if &outk[4..8] == CRED_PROTO_RESIDENT {
        outk[4] ^= 0x01; // never collide with the legacy marker (2⁻³²)
    }
    outk
}

/// Whether the credential keys off its stable resident id — legacy v2/v3 (marker
/// [`RESIDENT_VERSION_V2`]+), or any v4 (no legacy marker) — rather than the box
/// (legacy v1 only). A v4 id never carries the [`is_resident`] marker, so it is
/// never mistaken for v1 and keyed off the box.
fn resident_keys_off_id(rid: &[u8]) -> bool {
    rid.len() == CRED_RESIDENT_LEN
        && (!is_resident(rid) || rid[RESIDENT_VERSION_IDX] >= RESIDENT_VERSION_V2)
}

/// Whether the stored record carries the length-prefixed cached-pubkey trailer —
/// legacy v3, or any v4. `rid` is the record's 42-byte resident-id field.
fn resident_has_trailer(rid: &[u8]) -> bool {
    rid.len() == CRED_RESIDENT_LEN
        && (!is_resident(rid) || rid[RESIDENT_VERSION_IDX] == RESIDENT_VERSION_V3)
}

/// The 64-byte cred_random (`CredRandomWithUV ‖ CredRandomWithoutUV`) for the
/// hmac-secret extension — an HMAC-SHA512 ratchet over the device seed, keyed
/// each round by the previous output's first 32 bytes. The caller picks the UV
/// half: `[32..64]` with UV, `[0..32]` without.
pub fn derive_hmac_key(seed: &[u8; 32], cred_id: &[u8]) -> [u8; 64] {
    let proto = &cred_id[..PROTO_LEN.min(cred_id.len())];
    let mut k = hmac_sha512(seed, b"SLIP-0022");
    k = hmac_sha512(&k[..32], proto);
    k = hmac_sha512(&k[..32], b"hmac-secret");
    k = hmac_sha512(&k[..32], cred_id);
    k
}

/// The 32-byte largeBlobKey for a credential — an HMAC-SHA256 ratchet over the
/// device seed (same shape as the chacha key).
pub fn derive_large_blob_key(seed: &[u8; 32], cred_id: &[u8]) -> [u8; 32] {
    let proto = &cred_id[..PROTO_LEN.min(cred_id.len())];
    let mut k = hmac_sha256(seed, b"SLIP-0022");
    k = hmac_sha256(&k, proto);
    k = hmac_sha256(&k, b"largeBlobKey");
    k = hmac_sha256(&k, cred_id);
    k
}

/// The key-derivation input for a credential's signing key ([`fido_load_key`]),
/// hmac-secret ([`derive_hmac_key`]) and largeBlobKey ([`derive_large_blob_key`]).
///
/// A **v2/v3/v4 resident** credential ([`resident_keys_off_id`]) keys off its
/// STABLE resident id, so the keys survive an updateUserInformation reseal —
/// which draws a fresh IV and thus a new box ([`crate::credmgmt`], CTAP2.1 §6.8).
/// Every other case keys off the box exactly as before: a **v1** resident
/// credential (older, marker 0) so the RP's stored pubkey still verifies, and a
/// **non-resident** credential (`resident_id` is `None`) which has no stable id
/// and cannot be resealed anyway.
///
/// Callers MUST route ALL THREE derivations through this so the pubkey issued at
/// makeCredential and the key used at every assertion / enumeration path agree —
/// a single site left on the box would make v2 passkeys fail to verify.
pub(crate) fn resident_key_input<'a>(
    cred_box: &'a [u8],
    resident_id: Option<&'a [u8]>,
) -> &'a [u8] {
    match resident_id {
        Some(rid) if resident_keys_off_id(rid) => rid,
        _ => cred_box,
    }
}

/// A resident record is `rp_id_hash(32) ‖ resident_id(42) ‖ [pubkey trailer] ‖
/// full_cred_id`. The trailer (`pubkey_len(1) ‖ pubkey`) is present for a v3 or v4
/// resident id and is read/written through [`cred_record_box`] /
/// [`cred_record_pubkey`] / [`compose_cred_record`]; legacy v1/v2 records have the
/// box directly at `RECORD_PREFIX`.
pub const RECORD_PREFIX: usize = 32 + CRED_RESIDENT_LEN;

/// Largest cached public point a v3 record can carry: an uncompressed P-521
/// point (`04 ‖ x(66) ‖ y(66)`). The lattice schemes cache no point (their
/// public keys dwarf the record), so this bounds the trailer.
pub const CRED_PUBKEY_MAX: usize = 133;

/// Largest EF_CRED record — up to ~1 KiB with a large credBlob.
pub(crate) const CRED_REC_MAX: usize = 1024;

// A ceiling-sized resident box, plus the v3 public-key trailer, must still fit
// its EF_CRED record. Conservative: no single credential hits both maxima at
// once (the max box is a lattice cred, which caches no point).
const _: () = assert!(RECORD_PREFIX + 1 + CRED_PUBKEY_MAX + CRED_BOX_MAX <= CRED_REC_MAX);

/// Offset at which the credential box begins in a stored record, skipping the v3
/// length-prefixed public-key trailer. Total (never panics): a corrupt v3 length
/// is clamped to the record end, so the box then fails to decrypt and the
/// credential is skipped rather than mis-sliced.
fn cred_box_offset(rec: &[u8]) -> usize {
    if rec.len() > RECORD_PREFIX && resident_has_trailer(&rec[32..RECORD_PREFIX]) {
        (RECORD_PREFIX + 1 + rec[RECORD_PREFIX] as usize).min(rec.len())
    } else {
        RECORD_PREFIX
    }
}

/// The credential box within a stored record — the bytes [`credential_load`]
/// decrypts. For a v3 record this is AFTER the cached-pubkey trailer; for v1/v2
/// it starts at [`RECORD_PREFIX`]. Every reader of a stored EF_CRED record MUST
/// go through this, or a v3 trailer would be fed into the box and break decrypt.
pub(crate) fn cred_record_box(rec: &[u8]) -> &[u8] {
    &rec[cred_box_offset(rec)..]
}

/// The cached public point stored in a v3 record, or `None` for a v1/v2 record
/// or a v3 record with an empty (uncacheable-curve) trailer.
pub(crate) fn cred_record_pubkey(rec: &[u8]) -> Option<&[u8]> {
    if rec.len() > RECORD_PREFIX && resident_has_trailer(&rec[32..RECORD_PREFIX]) {
        let len = rec[RECORD_PREFIX] as usize;
        if len == 0 {
            return None;
        }
        rec.get(RECORD_PREFIX + 1..RECORD_PREFIX + 1 + len)
    } else {
        None
    }
}

/// Assemble an EF_CRED record into `out`, returning its length. A v3 `resident_id`
/// (marker [`RESIDENT_VERSION_V3`]) gets the length-prefixed `pubkey` trailer
/// between the resident id and the box; a v1/v2 id writes the box directly, byte
/// for byte as before. Returns `None` if it would not fit or the inputs are
/// malformed.
pub(crate) fn compose_cred_record(
    rp_id_hash: &[u8; 32],
    resident_id: &[u8],
    pubkey: &[u8],
    cred_box: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if resident_id.len() != CRED_RESIDENT_LEN || pubkey.len() > CRED_PUBKEY_MAX {
        return None;
    }
    let has_trailer = resident_has_trailer(resident_id);
    let trailer = if has_trailer { 1 + pubkey.len() } else { 0 };
    let total = RECORD_PREFIX + trailer + cred_box.len();
    if total > out.len() {
        return None;
    }
    out[..32].copy_from_slice(rp_id_hash);
    out[32..RECORD_PREFIX].copy_from_slice(resident_id);
    let mut p = RECORD_PREFIX;
    if has_trailer {
        out[p] = pubkey.len() as u8;
        p += 1;
        out[p..p + pubkey.len()].copy_from_slice(pubkey);
        p += pubkey.len();
    }
    out[p..p + cred_box.len()].copy_from_slice(cred_box);
    Some(p + cred_box.len())
}

/// EF_RP head before the (boxed) rpId tail: `count(1) ‖ rpIdHash(32)`.
pub(crate) const RP_PREFIX: usize = 1 + 32;

/// Largest EF_RP record: `count ‖ rpIdHash ‖ box(iv ‖ rpId ‖ tag)` at
/// [`RP_ID_MAX`]. Older (smaller) records load unchanged — reads are
/// length-driven with no fixed-size assumptions.
pub(crate) const RP_REC_MAX: usize = RP_PREFIX + IV_LEN + RP_ID_MAX + TAG_LEN;

/// Mark which slots `base+0..base+out.len()` hold a live record (`out[i]` is
/// occupied iff a key `base+i` exists), read from the fs in-RAM present index —
/// no flash scan. This runs on every credMgmt enumerate/getNext and every
/// makeCredential (dedup + free-slot), so scanning the whole partition each call
/// (~84 ms on a full store) dominated those paths; the present index answers it
/// in sub-ms and is occupancy-equivalent (see [`Fs::present_slots`]). Callers
/// still `fs.read` the occupied slots — those hit the key cache.
pub(crate) fn slot_map<S: Storage>(fs: &mut Fs<S>, base: u16, out: &mut [bool]) {
    fs.present_slots(base, out);
}

/// Estimated free discoverable-credential slots (getInfo
/// `remainingDiscoverableCredentials`, 0x14): the EF_CRED headroom, clamped so it
/// never over-promises against the SHARED dynamic-file store (see [`remaining_rk`]).
/// Walks only the present-key index (cheap, in-RAM — safe on the getInfo hot path).
pub(crate) fn remaining_discoverable<S: Storage>(fs: &mut Fs<S>) -> u16 {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    let used = occupied.iter().filter(|&&b| b).count() as u16;
    remaining_rk(fs, used)
}

/// The honest free-discoverable-credential estimate reported by BOTH getInfo 0x14
/// and credMgmt getCredsMetadata (0x02): the EF_CRED headroom, clamped so it never
/// promises slots the SHARED dynamic-file store can't back. A new discoverable
/// credential costs up to two dynamic files — its EF_CRED record, plus an EF_RP
/// record for a new rp — so halve the free file budget. Without this the reports
/// over-promise once PIV keys / OATH creds have drained the shared store; both
/// fields are CTAP 2.1 *estimates*, so clamping down is spec-compliant.
pub(crate) fn remaining_rk<S: Storage>(fs: &mut Fs<S>, used_ef_cred: u16) -> u16 {
    let by_slots = MAX_RESIDENT_CREDENTIALS.saturating_sub(used_ef_cred);
    let by_files = (fs.free_dynamic() / 2) as u16;
    by_slots.min(by_files)
}

/// Persist a resident credential into a free or matching EF_CRED slot and bump
/// the EF_RP count. `pubkey` is the credential's uncompressed public point
/// (from [`crate::ec::CredKey::public_point`], already computed for authData at
/// makeCredential), cached in the v3 record so enumeration need not recompute
/// `d·G`; pass an empty slice for an uncacheable-curve credential.
// Each argument is a distinct field of the resident record (seed, device, store,
// box, rpIdHash, rpId, userId, cached pubkey); a struct would add indirection for
// the single makeCredential call site.
#[allow(clippy::too_many_arguments)]
pub fn credential_store<S: Storage>(
    seed: &[u8; 32],
    dev: &Device,
    fs: &mut Fs<S>,
    cred_id: &[u8],
    rp_id_hash: &[u8; 32],
    rp_id: &str,
    user_id: &[u8],
    pubkey: &[u8],
) -> Result<()> {
    let mut slot: Option<u16> = None;
    let mut new_record = true;
    let mut rec = [0u8; CRED_REC_MAX];
    let mut scratch = [0u8; CRED_REC_MAX];

    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            if slot.is_none() {
                slot = Some(i);
            }
            continue;
        }
        let n = match fs.read(EF_CRED + i, &mut rec) {
            Some(n) if n > 0 => n.min(rec.len()),
            _ => continue,
        };
        if n < RECORD_PREFIX || rec[..32] != *rp_id_hash {
            continue;
        }
        if let Some(c) = credential_load(seed, cred_record_box(&rec[..n]), rp_id_hash, &mut scratch)
            && c.user_id == user_id
        {
            slot = Some(i);
            new_record = false;
            break;
        }
    }

    let slot = slot.ok_or(Error::NoMemory)?; // KEY_STORE_FULL
    let resident = derive_resident(cred_id, dev);
    let total = compose_cred_record(rp_id_hash, &resident, pubkey, cred_id, &mut rec)
        .ok_or(Error::NoMemory)?;
    fs.put(EF_CRED + slot, &rec[..total])?;

    // A freshly created (or re-registered) credential restarts its per-credential
    // signature counter: makeCredential reported signCount 0, so the next
    // operation reports 1. This also clears any stale entry a prior occupant of a
    // reused slot may have left in the packed EF_CRED_CTR file.
    crate::seed::set_cred_sign_counter(fs, slot, 1)?;

    if new_record {
        bump_rp(fs, seed, rp_id_hash, rp_id)?;
    }
    Ok(())
}

/// Increment the credential count for an rp, creating its EF_RP record if new.
/// A new record's rpId domain is boxed under the device seed (see [`seal_rp_id`])
/// so a flash dump never reveals the cleartext list of relying parties; the
/// rpIdHash stays cleartext as the O(1) lookup key.
fn bump_rp<S: Storage>(
    fs: &mut Fs<S>,
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    rp_id: &str,
) -> Result<()> {
    let mut rec = [0u8; RP_REC_MAX];
    let mut free: Option<u16> = None;
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            if free.is_none() {
                free = Some(i);
            }
            continue;
        }
        let fid = EF_RP + i;
        if let Some(n) = fs.read(fid, &mut rec)
            && n >= RP_PREFIX
            && rec[1..RP_PREFIX] == *rp_id_hash
        {
            // Existing rp: bump the count, re-storing the boxed tail verbatim.
            let n = n.min(rec.len());
            rec[0] = rec[0].saturating_add(1);
            return fs.put(fid, &rec[..n]);
        }
    }
    let slot = free.ok_or(Error::NoMemory)?;
    rec[0] = 1;
    rec[1..RP_PREFIX].copy_from_slice(rp_id_hash);
    let blen = seal_rp_id(seed, rp_id, rp_id_hash, &mut rec[RP_PREFIX..])?;
    fs.put(EF_RP + slot, &rec[..RP_PREFIX + blen])
}

/// Box the rpId domain under the device seed. Layout written to `out`:
/// `iv(12) ‖ ciphertext ‖ poly1305_tag(16)`, ChaCha20-Poly1305 with the rpIdHash
/// as AAD. The IV is *deterministic* — there is exactly one EF_RP record per
/// rpIdHash and its plaintext (the domain) is immutable, so a fixed (key, iv)
/// never encrypts two different messages, which is the only thing nonce reuse
/// must avoid. Returns the box length.
pub(crate) fn seal_rp_id(
    seed: &[u8; 32],
    rp_id: &str,
    rp_id_hash: &[u8; 32],
    out: &mut [u8],
) -> Result<usize> {
    let id = rp_id.as_bytes();
    let total = IV_LEN + id.len() + TAG_LEN;
    if total > out.len() {
        return Err(Error::NoMemory);
    }
    let mut key = derive_chacha_key(seed, RP_PROTO);
    let iv_full = hmac_sha256(&key, rp_id_hash);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&iv_full[..IV_LEN]);
    out[..IV_LEN].copy_from_slice(&iv);
    out[IV_LEN..IV_LEN + id.len()].copy_from_slice(id);
    let tag = chacha20poly1305_encrypt(&key, &iv, rp_id_hash, &mut out[IV_LEN..IV_LEN + id.len()]);
    out[IV_LEN + id.len()..total].copy_from_slice(&tag);
    key.zeroize();
    Ok(total)
}

/// Recover the rpId domain from an EF_RP `tail`, whether it is a box (written by
/// [`seal_rp_id`]) or a legacy cleartext domain. The recovered string is written
/// into `out` and returned alongside a `was_boxed` flag (used by the boot
/// migration to decide whether to re-box). Trial-decryption distinguishes the
/// two formats: a cleartext domain fails the poly1305 check (probability of a
/// false positive ≈ 2⁻¹²⁸).
pub(crate) fn unseal_rp_id<'a>(
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    tail: &[u8],
    out: &'a mut [u8],
) -> Option<(&'a str, bool)> {
    let n = tail.len();
    // A box is iv(12) ‖ ct ‖ tag(16): at least 28 bytes, and it authenticates.
    if n >= IV_LEN + TAG_LEN && n <= out.len() {
        let ct_len = n - IV_LEN - TAG_LEN;
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&tail[..IV_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&tail[n - TAG_LEN..]);
        out[..ct_len].copy_from_slice(&tail[IV_LEN..IV_LEN + ct_len]);
        let mut key = derive_chacha_key(seed, RP_PROTO);
        let ok = chacha20poly1305_decrypt(&key, &iv, rp_id_hash, &mut out[..ct_len], &tag).is_ok();
        key.zeroize();
        if ok {
            return core::str::from_utf8(&out[..ct_len]).ok().map(|s| (s, true));
        }
    }
    // Legacy cleartext domain (the failed decrypt above left `out` garbled, so
    // re-copy the raw tail here).
    if n <= out.len() {
        out[..n].copy_from_slice(tail);
        return core::str::from_utf8(&out[..n]).ok().map(|s| (s, false));
    }
    None
}

/// Box a device-local RP nickname under the device seed. Layout written to `out`:
/// `iv(12) ‖ ciphertext ‖ poly1305_tag(16)`, ChaCha20-Poly1305 with the rpIdHash as
/// AAD — same shape as [`seal_rp_id`]. Two differences matter:
///
/// * The nickname is **mutable** (unlike the immutable rpId domain), so the IV is
///   synthetic over the *plaintext*: `iv = HMAC(key, rpIdHash ‖ nick)[..12]`. A fixed
///   (key, iv) thus only ever encrypts the one nickname it was derived from, so a
///   re-rename to a different string draws a different IV — no nonce reuse. Equal
///   nicknames under different rpIdHashes also differ (the hash is folded in). The
///   residual (a rename back to a prior value reproduces a prior box) is
///   deterministic-encryption-level leakage, matching [`seal_rp_id`]'s own model.
/// * The rpIdHash AAD binds the box to its RP, so a stale nickname left in a reused
///   slot fails to open under a different RP — the AEAD itself is the slot-reuse guard,
///   no cleartext key prefix is stored.
pub(crate) fn seal_nick(
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    nick: &str,
    out: &mut [u8],
) -> Result<usize> {
    let id = nick.as_bytes();
    if id.len() > RP_NICK_MAX_LEN {
        return Err(Error::NoMemory);
    }
    let total = IV_LEN + id.len() + TAG_LEN;
    if total > out.len() {
        return Err(Error::NoMemory);
    }
    let mut key = derive_chacha_key(seed, NICK_PROTO);
    let mut iv_src = [0u8; 32 + RP_NICK_MAX_LEN];
    iv_src[..32].copy_from_slice(rp_id_hash);
    iv_src[32..32 + id.len()].copy_from_slice(id);
    let iv_full = hmac_sha256(&key, &iv_src[..32 + id.len()]);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&iv_full[..IV_LEN]);
    out[..IV_LEN].copy_from_slice(&iv);
    out[IV_LEN..IV_LEN + id.len()].copy_from_slice(id);
    let tag = chacha20poly1305_encrypt(&key, &iv, rp_id_hash, &mut out[IV_LEN..IV_LEN + id.len()]);
    out[IV_LEN + id.len()..total].copy_from_slice(&tag);
    key.zeroize();
    Ok(total)
}

/// Recover a device-local RP nickname from an EF_RPNICK record. Returns the nickname
/// only if the box opens under this rpIdHash — an absent, short, or stale (slot-reused)
/// record yields `None`, so the caller falls back to the rpId.
pub(crate) fn unseal_nick<'a>(
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    tail: &[u8],
    out: &'a mut [u8],
) -> Option<&'a str> {
    let n = tail.len();
    if n < IV_LEN + TAG_LEN {
        return None;
    }
    let ct_len = n - IV_LEN - TAG_LEN;
    if ct_len > out.len() {
        return None; // `out` holds only the plaintext nickname, not the whole box
    }
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&tail[..IV_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&tail[n - TAG_LEN..]);
    out[..ct_len].copy_from_slice(&tail[IV_LEN..IV_LEN + ct_len]);
    let mut key = derive_chacha_key(seed, NICK_PROTO);
    let ok = chacha20poly1305_decrypt(&key, &iv, rp_id_hash, &mut out[..ct_len], &tag).is_ok();
    key.zeroize();
    if ok {
        core::str::from_utf8(&out[..ct_len]).ok()
    } else {
        None
    }
}

/// Boot pass: re-box any legacy cleartext EF_RP record so a flash dump no longer
/// reveals the cleartext list of relying parties. Idempotent and crash-safe —
/// already-boxed records authenticate and are skipped, and a partially-migrated
/// set converges over boots. Must run after the keydev seed is readable under
/// the current root (i.e. after [`crate::seed::migrate_keydev_boot`]).
pub fn migrate_rp_seal<S: Storage>(dev: &Device, fs: &mut Fs<S>) {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    if !occupied.iter().any(|&b| b) {
        return; // no resident-cred RPs → nothing to seal, don't materialize the seed
    }
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return;
    };
    let mut buf = [0u8; RP_REC_MAX];
    let mut plain = [0u8; RP_REC_MAX];
    let mut out = [0u8; RP_REC_MAX];
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let fid = EF_RP + i;
        let Some(n) = fs.read(fid, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n < RP_PREFIX {
            continue;
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&buf[1..RP_PREFIX]);
        let Some((domain, was_boxed)) =
            unseal_rp_id(&seed, &rp_id_hash, &buf[RP_PREFIX..n], &mut plain)
        else {
            continue;
        };
        if was_boxed {
            continue; // already sealed
        }
        out[0] = buf[0];
        out[1..RP_PREFIX].copy_from_slice(&rp_id_hash);
        if let Ok(blen) = seal_rp_id(&seed, domain, &rp_id_hash, &mut out[RP_PREFIX..]) {
            let _ = fs.put(fid, &out[..RP_PREFIX + blen]);
        }
    }
    seed.zeroize();
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod tests;
