// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Device master-seed lifecycle: at-rest sealing, format migrations, the
//! soft-lock wrap and first-boot init (seed / counter / large-blob / cert).
//!
//! The seed (and the org attestation scalar `EF_ATT_KEY`) is stored
//! ChaCha20-Poly1305-sealed under a key HKDF-derived from the device root key
//! (`derive_kbase`), behind a 1-byte format tag: 0x02 is the device-key-only
//! (pre-OTP) arm, 0x12 the OTP-MKEK arm; `migrate_keydev_boot` re-seals across
//! the arm boundary at boot. The record is `[tag] ‖ nonce(12) ‖ ct(32) ‖
//! tag(16)`, AAD = the serial hash. The 12-byte nonce is SYNTHETIC —
//! `HMAC(HMAC(nonce_key, fid), value)` truncated — so the seed and the
//! attestation key (one shared arm key) never share a nonce, and re-sealing the
//! same value is byte-identical: the property that makes the boot migration
//! deterministic and crash-safe without an RNG (the seal it replaces reused a
//! fixed serial-hash IV across both slots and carried no MAC).
//!
//! Older records still load and are re-sealed forward: the pre-AEAD AES-256-CBC
//! wrap (tags 0x01 pre-OTP / 0x11 OTP, fixed IV, no MAC) is read by `cbc_open`
//! and upgraded at boot. The legacy 0x03/0x13 variants add an outer PIN-keyed
//! AEAD over that CBC inner; they are migrated at the first successful PIN
//! verify (`migrate_keydev_pin`), the only moment their outer layer is open — a
//! PIN-wrapped seed makes every UP-only operation (an SSH `ed25519-sk` login,
//! any no-PIN assertion) fail after a power cycle until some clientPIN command
//! runs, and the at-rest protection is the kbase itself (silicon-rooted once the
//! OTP key is burnt).

use zeroize::Zeroize;

use rsk_crypto::aes_encrypt;
use rsk_crypto::chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_crypto::{Device, Mode, PinKdf, aes_decrypt, hkdf_sha256, hmac_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::error::{Error, Result};

use crate::Rng;
use crate::cert::{build_attestation_cert, matches_template as cert_matches_template};
use crate::consts::{
    EF_ATT_KEY, EF_COUNTER, EF_CRED_CTR, EF_EE_DEV, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_LARGEBLOB,
    EF_PAUTHTOKEN, ENC_GETINFO_MEMBER_LEN, LARGEBLOB_INITIAL, MAX_RESIDENT_CREDENTIALS,
};
use crate::ec::P256Key;

/// Legacy fixed-IV AES-CBC tags (load + migrate only; never written).
const FORMAT_F1: u8 = 0x01; // pre-OTP CBC
const FORMAT_F3: u8 = 0x03; // pre-OTP CBC under an outer PIN AEAD
const FORMAT_F1_OTP: u8 = 0x11; // OTP-arm CBC
const FORMAT_F3_OTP: u8 = 0x13; // OTP-arm CBC under an outer PIN AEAD
/// Current ChaCha20-Poly1305 tags (`[tag] ‖ nonce ‖ ct ‖ tag`).
const FORMAT_G1: u8 = 0x02; // pre-OTP AEAD
const FORMAT_G1_OTP: u8 = 0x12; // OTP-arm AEAD

const KEYDEV_F1_LEN: usize = 33; // legacy: format(1) + CBC ct(32)
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `[tag] ‖ nonce(12) ‖ ct(32) ‖ tag(16)`. Numerically equal to the legacy
/// PIN-wrapped length below; the tag byte (0x02/0x12 vs 0x03/0x13) disambiguates.
const KEYDEV_G1_LEN: usize = 1 + NONCE_LEN + 32 + TAG_LEN;
const KEYDEV_F3_LEN: usize = 61; // legacy PIN-wrapped: format(1) + AEAD(nonce 12 + ct 32 + tag 16)

/// HKDF `info` labels (off the arm's kbase, salt = serial_hash).
const INFO_SEED_ENC: &[u8] = b"KEYDEV/CHACHA";
const INFO_SEED_NONCE: &[u8] = b"KEYDEV/NONCE";
/// Our label for the 128-bit device identifier behind getInfo's `encIdentifier`.
/// Its own domain, so the identifier is independent of every other value derived
/// from the seed and reveals nothing about it.
const INFO_ENCID_DEVICE: &[u8] = b"KEYDEV/ENCID";
/// Fixed by CTAP 2.2, not by us: the `encIdentifier` key is
/// HKDF-SHA256(salt = 32 zero bytes, IKM = persistent pinUvAuthToken, L = 16).
const INFO_ENCID: &[u8] = b"encIdentifier";
const INFO_ENCCSS: &[u8] = b"encCredStoreState";
const ENCID_SALT: [u8; 32] = [0u8; 32];

/// `EF_KEY_DEV_ENC` layout: nonce(12) ‖ ChaCha20-Poly1305(seed value, 32) ‖ tag(16).
///
/// The lock wraps the decrypted seed *value*, not the stored file content, so
/// lock/unlock is independent of the at-rest format tag and of the kbase the
/// plain file is sealed under.
pub const LOCK_BLOB_LEN: usize = 12 + 32 + 16;

/// Whether the soft lock is engaged (the wrapped blob is what's on flash).
pub fn lock_engaged<S: Storage>(fs: &mut Fs<S>) -> bool {
    // Both halves, not just the sealed copy. `aut_enable` writes `EF_KEY_DEV_ENC`
    // and *then* deletes the plaintext `EF_KEY_DEV`; a power cut between the two
    // left both records, and testing only the sealed one reported `locked: true`
    // while `load_keydev` still read the surviving plaintext — so every FIDO
    // operation worked and BACKUP_EXPORT still handed out the seed without the lock
    // key. Reading the torn state as *unlocked* is the truth, and it lets
    // `rsk lock enable` simply be retried (audit run-33).
    fs.has_key(EF_KEY_DEV_ENC) && !fs.has_key(EF_KEY_DEV)
}

/// Wrap the seed value under a host-supplied 32-byte lock key (AUT_ENABLE).
pub fn seal_seed_locked(
    rng: &mut impl Rng,
    lock_key: &[u8; 32],
    seed: &[u8; 32],
) -> [u8; LOCK_BLOB_LEN] {
    let mut blob = [0u8; LOCK_BLOB_LEN];
    let (nonce, rest) = blob.split_at_mut(12);
    rng.fill(nonce);
    let (ct, tag) = rest.split_at_mut(32);
    ct.copy_from_slice(seed);
    let nonce12: [u8; 12] = nonce.try_into().unwrap();
    tag.copy_from_slice(&chacha20poly1305_encrypt(lock_key, &nonce12, &[], ct));
    blob
}

/// Unwrap `EF_KEY_DEV_ENC` content with the lock key (vendor UNLOCK). `None` on
/// a wrong key, a tampered blob, or a malformed length.
pub fn open_seed_locked(lock_key: &[u8; 32], blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() != LOCK_BLOB_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&blob[12..44]);
    match chacha20poly1305_decrypt(lock_key, &nonce, &[], &mut seed, &tag) {
        Ok(()) => Some(seed),
        Err(_) => {
            seed.zeroize();
            None
        }
    }
}

/// The ChaCha tag this device generation writes: 0x12 once the OTP key is
/// provisioned, 0x02 before (the only formats ever written).
fn plain_tag(dev: &Device) -> u8 {
    if dev.otp_key.is_some() {
        FORMAT_G1_OTP
    } else {
        FORMAT_G1
    }
}

/// The arm a ChaCha tag was sealed under: 0x02 uses the pre-OTP arm; 0x12 needs
/// the OTP key (None when absent — an OTP-era blob read without the OTP key is
/// orphaned and must fail cleanly, never yield a wrong-key result).
fn gcm_arm<'a>(dev: &Device<'a>, tag: u8) -> Option<Device<'a>> {
    match tag {
        FORMAT_G1 => Some(dev.without_otp()),
        FORMAT_G1_OTP => dev.otp_key.map(|_| *dev),
        _ => None,
    }
}

/// The ChaCha20-Poly1305 sealing key for `arm`: HKDF-SHA256(serial_hash, kbase).
fn seed_enc_key(arm: &Device) -> [u8; 32] {
    let mut kbase = arm.derive_kbase();
    let mut enc = [0u8; 32];
    hkdf_sha256(arm.serial_hash, &kbase, INFO_SEED_ENC, &mut enc).expect("32-byte HKDF output");
    kbase.zeroize();
    enc
}

/// The synthetic-nonce PRF key for `arm`: a second HKDF label off the same kbase.
fn seed_nonce_key(arm: &Device) -> [u8; 32] {
    let mut kbase = arm.derive_kbase();
    let mut nk = [0u8; 32];
    hkdf_sha256(arm.serial_hash, &kbase, INFO_SEED_NONCE, &mut nk).expect("32-byte HKDF output");
    kbase.zeroize();
    nk
}

/// Synthetic 12-byte nonce for `fid`'s `value`: `HMAC(nonce_key, fid)` re-keys a
/// second HMAC over the value. Distinct fids (the seed vs the attestation key)
/// and distinct values both yield distinct nonces, so two records under the one
/// shared arm key never share a (key, nonce) pair; identical material re-seals
/// identically (deterministic → idempotent migration, no RNG).
fn synth_nonce(nonce_key: &[u8; 32], fid: KeyFid, value: &[u8; 32]) -> [u8; NONCE_LEN] {
    let sub = hmac_sha256(nonce_key, &fid.get().to_be_bytes());
    let full = hmac_sha256(&sub, value);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&full[..NONCE_LEN]);
    nonce
}

/// Seal `value` as `[tag] ‖ nonce ‖ ct ‖ tag16` under the current arm's ChaCha
/// key, AAD = serial_hash; `fid` domain-separates the synthetic nonce.
fn seal_gcm(dev: &Device, fid: KeyFid, value: &[u8; 32]) -> [u8; KEYDEV_G1_LEN] {
    let mut nk = seed_nonce_key(dev);
    let nonce = synth_nonce(&nk, fid, value);
    nk.zeroize();
    let mut rec = [0u8; KEYDEV_G1_LEN];
    rec[0] = plain_tag(dev);
    rec[1..1 + NONCE_LEN].copy_from_slice(&nonce);
    let ctpos = 1 + NONCE_LEN;
    rec[ctpos..ctpos + 32].copy_from_slice(value);
    let mut enc = seed_enc_key(dev);
    let tag = chacha20poly1305_encrypt(&enc, &nonce, dev.serial_hash, &mut rec[ctpos..ctpos + 32]);
    enc.zeroize();
    rec[ctpos + 32..].copy_from_slice(&tag);
    rec
}

/// Open a ChaCha record (`0x02`/`0x12`), deriving the key from the tag's arm and
/// authenticating with the serial hash. `None` on a malformed blob, an orphaned
/// OTP-era tag (no OTP key), or an auth failure — a flipped tag byte picks the
/// wrong arm and the MAC rejects it.
fn open_gcm(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != KEYDEV_G1_LEN {
        return None;
    }
    let arm = gcm_arm(dev, buf[0])?;
    let ctpos = 1 + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[1..ctpos]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[ctpos + 32..]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&buf[ctpos..ctpos + 32]);
    let mut enc = seed_enc_key(&arm);
    let r = chacha20poly1305_decrypt(&enc, &nonce, dev.serial_hash, &mut value, &tag);
    enc.zeroize();
    match r {
        Ok(()) => Some(value),
        Err(_) => {
            value.zeroize();
            None
        }
    }
}

/// Decrypt a legacy fixed-IV AES-CBC record (`0x01` pre-OTP / `0x11` OTP, no
/// MAC), kept for load + migration of devices provisioned before the AEAD
/// format. An orphaned `0x11` read without the OTP key returns `None`.
fn cbc_open(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != KEYDEV_F1_LEN {
        return None;
    }
    let arm = match buf[0] {
        FORMAT_F1 => dev.without_otp(),
        FORMAT_F1_OTP => {
            dev.otp_key?;
            *dev
        }
        _ => return None,
    };
    let mut value = [0u8; 32];
    value.copy_from_slice(&buf[1..KEYDEV_F1_LEN]);
    let mut kbase = arm.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let r = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut value);
    kbase.zeroize();
    match r {
        Ok(()) => Some(value),
        Err(_) => {
            value.zeroize();
            None
        }
    }
}

/// Recover a 32-byte value from any supported on-flash form: the current ChaCha
/// AEAD (either arm) or a legacy CBC record. A PIN-wrapped (0x03/0x13) blob
/// returns `None` — it is not loadable until `migrate_keydev_pin` opens its
/// outer layer.
fn open_any(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    open_gcm(dev, buf).or_else(|| cbc_open(dev, buf))
}

/// Read and decrypt the 32-byte device seed. Returns `None` if absent,
/// undecryptable, or still in a legacy PIN-wrapped format (0x03/0x13) — those
/// become loadable again once a successful PIN verify migrates them
/// ([`migrate_keydev_pin`]).
pub fn load_keydev<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_KEY_DEV)
}

/// The org-provisioned FIDO attestation scalar (`EF_ATT_KEY`), sealed exactly
/// like the seed — the tag records which kbase arm wrapped it, so import before
/// or after OTP provisioning both stay loadable.
pub fn load_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_ATT_KEY)
}

pub fn store_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, key: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_ATT_KEY, key)
}

/// The persistent pinUvAuthToken (CTAP 2.2 §6.5.2.2), sealed exactly like the
/// seed. `None` means no platform holds a `pcmr` grant. Presence is necessary but
/// NOT sufficient — a build whose wipe deferred this record could leave it behind
/// its PIN, so [`crate::credmgmt`] owns the grant test, not this reader.
pub fn load_ppuat<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_PAUTHTOKEN)
}

/// [`load_ppuat`], minting and persisting a fresh token when none exists — the
/// `pcmr` half of §6.5.5.7.2/.3. Unlike the session token it outlives the power
/// cycle, so it must reach flash before it reaches the platform.
pub fn ensure_ppuat<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
) -> Result<[u8; 32]> {
    if let Some(tok) = load_ppuat(dev, fs) {
        return Ok(tok);
    }
    let mut tok = [0u8; 32];
    rng.fill(&mut tok);
    let r = put_sealed32(dev, fs, EF_PAUTHTOKEN, &tok);
    if r.is_err() {
        tok.zeroize();
    }
    r.map(|()| tok)
}

/// `resetPersistentPinUvAuthToken` (§6.5.4): drop the token, which clears its
/// permissions with it. `force_delete`, not `delete` — this revokes a capability,
/// so a false-absent present bit must not leave the record live in the backend.
/// Refines `RSKeySecurityState!NoTokenAfterInvalidation` — SEC-FIDO-003.
pub fn clear_ppuat<S: Storage>(fs: &mut Fs<S>) -> Result<()> {
    fs.force_delete(EF_PAUTHTOKEN.get())
}

/// getInfo's `encIdentifier` (0x19): `iv ‖ AES-128-CBC(k, id)`, where `id` is this
/// device's 128-bit identifier and `k` is HKDF-SHA256 over the persistent
/// pinUvAuthToken, under the salt and label CTAP 2.2 fixes for it. Only a holder of
/// that token can decrypt it, which is the whole point: the device stays recognizable
/// to a platform it has been paired with and opaque to everyone else.
///
/// **The IV is fresh per call.** A fixed or repeating one would turn this member
/// into a stable cross-origin fingerprint served to anyone who asks — the exact
/// tracking vector the member is designed to avoid.
///
/// `id` is derived from the master seed under its own label, so it follows the
/// seed across `authenticatorReset`: a reset mints a new seed, and the device
/// stops being linkable to its pre-reset self. Deriving it from the silicon root
/// instead would have survived the reset and defeated that.
///
/// `None` when no persistent token has been issued yet, or the seed is unreadable
/// behind a soft lock. The member is optional, and a placeholder built from some
/// other value would be a claim no platform could detect as false.
pub fn enc_identifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
) -> Option<[u8; ENC_GETINFO_MEMBER_LEN]> {
    // The token is the gate, so it is read FIRST: a device that has never issued one
    // is the common case, and opening the seal on the seed only to discard it would
    // be a ChaCha20-Poly1305 open on every getInfo for nothing.
    let mut token = load_ppuat(dev, fs)?;
    let mut key = [0u8; 16];
    let derived = hkdf_sha256(&ENCID_SALT, &token, INFO_ENCID, &mut key);
    token.zeroize();
    if derived.is_err() {
        key.zeroize();
        return None;
    }

    let Some(mut seed) = load_keydev(dev, fs) else {
        key.zeroize();
        return None;
    };
    let mut id = [0u8; 16];
    let derived = hkdf_sha256(dev.serial_hash, &seed, INFO_ENCID_DEVICE, &mut id);
    seed.zeroize();
    if derived.is_err() {
        id.zeroize();
        key.zeroize();
        return None;
    }

    let out = seal_getinfo_member(&key, &mut id, rng);
    key.zeroize();
    out
}

/// getInfo's `encCredStoreState` (0x1E): the same `iv ‖ AES-128-CBC(k, block)` as
/// [`enc_identifier`] under its own label, over a 128-bit tag that changes whenever
/// the discoverable-credential set does. A platform holding the persistent token
/// compares it with what it cached and re-enumerates only when it differs.
///
/// The master seed is not touched: the tag is bookkeeping, not derived material, and
/// the token is sealed under the device root rather than the seed. So unlike
/// [`enc_identifier`] this member survives a soft lock.
///
/// `None` when no persistent token has been issued yet: the member is optional, and
/// a value under a key nobody holds says nothing to anyone.
pub fn enc_cred_store_state<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
) -> Option<[u8; ENC_GETINFO_MEMBER_LEN]> {
    let mut token = load_ppuat(dev, fs)?;
    let mut key = [0u8; 16];
    let derived = hkdf_sha256(&ENCID_SALT, &token, INFO_ENCCSS, &mut key);
    token.zeroize();
    if derived.is_err() {
        key.zeroize();
        return None;
    }
    let mut block = crate::credential::cred_store_state(fs);
    let out = seal_getinfo_member(&key, &mut block, rng);
    key.zeroize();
    out
}

/// `iv ‖ AES-128-CBC(k, block)` with a **fresh IV per call** — the shape CTAP 2.3
/// fixes for both encrypted getInfo members. A fixed or repeating IV would turn
/// either one into a stable fingerprint served to anyone who asks, which is the
/// tracking vector they exist to avoid. `block` is spent: it is zeroized here.
fn seal_getinfo_member(
    key: &[u8; 16],
    block: &mut [u8; 16],
    rng: &mut impl Rng,
) -> Option<[u8; ENC_GETINFO_MEMBER_LEN]> {
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    let sealed = aes_encrypt(key, &iv, Mode::Cbc, block);
    if sealed.is_err() {
        block.zeroize();
        return None;
    }

    let mut out = [0u8; ENC_GETINFO_MEMBER_LEN];
    out[..16].copy_from_slice(&iv);
    out[16..].copy_from_slice(block);
    block.zeroize();
    Some(out)
}

/// Read and unseal a 32-byte value from any supported at-rest form (read-both).
fn get_sealed32<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Option<[u8; 32]> {
    let mut buf = [0u8; 64];
    let n = fs.read_key(fid, &mut buf)?;
    let out = open_any(dev, &buf[..n.min(buf.len())]);
    buf.zeroize();
    out
}

/// Store `seed` ChaCha20-Poly1305-sealed under the device root key (tag 0x02, or
/// 0x12 once the OTP key is provisioned).
pub fn encrypt_keydev_f1<S: Storage>(dev: &Device, fs: &mut Fs<S>, seed: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_KEY_DEV, seed)
}

/// Seal a 32-byte value under the current arm's ChaCha key and write it to `fid`.
fn put_sealed32<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    value: &[u8; 32],
) -> Result<()> {
    let mut rec = seal_gcm(dev, fid, value);
    let r = fs.put_key(fid, Sealed::wrap(&rec));
    rec.zeroize();
    r
}

/// Boot-pass migration for the seed and the attestation key: bring each to the
/// current ChaCha form under the current kbase arm — upgrading a legacy CBC
/// record (removing the fixed-IV / no-MAC weakness) and re-sealing a pre-OTP
/// blob under the OTP arm once the fuse key is present. A PIN-wrapped (0x03/0x13)
/// seed is left untouched — that migrates at the first PIN verify
/// ([`migrate_keydev_pin`]). Idempotent and crash-safe: each re-seal is one
/// atomic record write, and a torn write leaves the prior record intact.
pub fn migrate_keydev_boot<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Result<()> {
    migrate_slot(dev, fs, EF_KEY_DEV)?;
    migrate_slot(dev, fs, EF_ATT_KEY)
}

/// Re-seal one slot forward if it is not already current-arm ChaCha. Absent
/// slots and unrecoverable (PIN-wrapped) records are no-ops.
fn migrate_slot<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<()> {
    let mut buf = [0u8; 64];
    let Some(n) = fs.read_key(fid, &mut buf) else {
        return Ok(());
    };
    let n = n.min(buf.len());
    // Already current-arm ChaCha? Skip the redundant flash erase (the
    // deterministic re-seal would be byte-identical anyway).
    if buf[0] == plain_tag(dev)
        && let Some(mut v) = open_gcm(dev, &buf[..n])
    {
        v.zeroize();
        buf.zeroize();
        return Ok(());
    }
    let recovered = open_any(dev, &buf[..n]);
    buf.zeroize();
    match recovered {
        Some(mut v) => {
            let r = put_sealed32(dev, fs, fid, &v);
            v.zeroize();
            r
        }
        None => Ok(()),
    }
}

/// Lazy migration of a legacy PIN-wrapped seed (0x03/0x13) forward to the
/// current ChaCha form, callable only when a PIN just verified (the outer AEAD
/// key derives from the PIN hash — the only moment that layer is open). Strips
/// the PIN AEAD, recovers the seed through the inner CBC layer, and re-seals it
/// under the current arm in one atomic write (a pre-OTP blob on an OTP device
/// lands straight at 0x12). No-op for current or unmatchable tags. `pin_hash` is
/// the verified 16-byte PIN hash.
pub fn migrate_keydev_pin<S: Storage>(dev: &Device, fs: &mut Fs<S>, pin_hash: &[u8]) -> Result<()> {
    let mut buf = [0u8; 64];
    let Some(KEYDEV_F3_LEN) = fs.read_key(EF_KEY_DEV, &mut buf) else {
        return Ok(());
    };
    let (seal_dev, cbc_tag) = match buf[0] {
        FORMAT_F3 => (dev.without_otp(), FORMAT_F1),
        FORMAT_F3_OTP if dev.otp_key.is_some() => (*dev, FORMAT_F1_OTP),
        _ => return Ok(()),
    };
    // Strip the outer PIN AEAD, leaving the inner CBC record the seed was sealed
    // in before the PIN was set.
    let mut session = seal_dev.pin_derive_session(pin_hash);
    let mut cbc = [0u8; KEYDEV_F1_LEN];
    cbc[0] = cbc_tag;
    let r = seal_dev.decrypt_with_aad(&session, &buf[1..KEYDEV_F3_LEN], PinKdf::V2, &mut cbc[1..]);
    session.zeroize();
    buf.zeroize();
    if r.is_err() {
        cbc.zeroize();
        return Err(Error::ExecError);
    }
    // Recover the seed through the shared CBC reader and re-seal it forward under
    // the current arm as authenticated ChaCha.
    let recovered = cbc_open(dev, &cbc);
    cbc.zeroize();
    match recovered {
        Some(mut seed) => {
            let r = put_sealed32(dev, fs, EF_KEY_DEV, &seed);
            seed.zeroize();
            r
        }
        None => Err(Error::ExecError),
    }
}

/// First-boot init: generate the seed if absent, initialise the signature
/// counter and the default large-blob array, and create the U2F attestation
/// certificate.
///
/// On a soft-locked device (`EF_KEY_DEV` gone, `EF_KEY_DEV_ENC` present) the
/// seed is NOT regenerated — the wrapped blob *is* the seed — and the
/// attestation step is skipped (the cert already exists from before the lock;
/// the seed is unreadable here anyway).
/// Refines `RSKeySecurityState!RamNeverOutlivesFlashSeed` — SEC-FIDO-007.
pub fn ensure_seed<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut impl Rng) -> Result<()> {
    let locked = lock_engaged(fs);
    if !fs.has_key(EF_KEY_DEV) && !locked {
        let mut seed = [0u8; 32];
        loop {
            rng.fill(&mut seed);
            if P256Key::from_scalar(&seed).is_some() {
                break;
            }
        }
        let r = encrypt_keydev_f1(dev, fs, &seed);
        seed.zeroize();
        r?;
    }
    if !fs.has_data(EF_COUNTER) {
        fs.put(EF_COUNTER, &[0u8; 4])?;
    }
    if !fs.has_data(EF_LARGEBLOB) {
        fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL)?;
    }
    if !locked {
        let mut seed = load_keydev(dev, fs).ok_or(Error::ExecError)?;
        let r = rebuild_att_cert(fs, rng, &seed);
        seed.zeroize();
        r?;
    }
    Ok(())
}

/// Rebuild `EF_EE_DEV` if it does not both match the current template and certify
/// `seed`'s public key. Split out of [`ensure_seed`] so the one moment a
/// soft-locked device has its seed in hand — a successful vendor UNLOCK — can run
/// it too; that device is otherwise stuck serving a pre-§8.2.1 leaf forever
/// (audit run-32).
pub fn rebuild_att_cert<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
    seed: &[u8; 32],
) -> Result<()> {
    let key = P256Key::from_scalar(seed).ok_or(Error::ExecError)?;
    let mut buf = [0u8; 512];
    let fresh = match fs.read(EF_EE_DEV, &mut buf) {
        Some(n) => cert_matches_template(&buf[..n.min(buf.len())], &key),
        None => false,
    };
    if fresh {
        return Ok(());
    }
    let mut serial = [0u8; 16];
    // 0x01..=0x7F: positive AND minimally encoded. The template's INTEGER is
    // fixed-width, so a leading 0x00 cannot be dropped and X.690 §8.3.2 makes the
    // whole certificate unparseable to strict RPs.
    loop {
        rng.fill(&mut serial);
        serial[0] &= 0x7F;
        if serial[0] != 0x00 {
            break;
        }
    }
    let n = build_attestation_cert(&key, &serial, &mut buf).ok_or(Error::ExecError)?;
    fs.put(EF_EE_DEV, &buf[..n])
}

/// The global signature counter, stored little-endian.
pub fn get_sign_counter<S: Storage>(fs: &mut Fs<S>) -> u32 {
    let mut buf = [0u8; 4];
    match fs.read(EF_COUNTER, &mut buf) {
        Some(4) => u32::from_le_bytes(buf),
        _ => 0,
    }
}

/// Persist `counter+1`; returns the value *before* the bump — the value to
/// report in the current operation. Now used only by U2F authenticate (CTAP2
/// signature counters are per-credential, see [`cred_sign_counter`]).
pub fn bump_sign_counter<S: Storage>(fs: &mut Fs<S>) -> Result<u32> {
    let ctr = get_sign_counter(fs);
    fs.put(EF_COUNTER, &ctr.wrapping_add(1).to_le_bytes())?;
    Ok(ctr)
}

/// Packed EF_CRED_CTR length: one `u32` per resident slot.
const CRED_CTR_LEN: usize = MAX_RESIDENT_CREDENTIALS as usize * 4;

/// The per-credential signature counter stored for EF_CRED `slot`, or `None` when
/// the slot has no LIVE entry — meaning "unmaterialized". `None` covers three
/// cases that are all handled identically (seed from the frozen global): the
/// packed file is absent, it is shorter than `slot`, OR the slot reads as **0**.
///
/// The zero case matters: a write to a HIGHER slot zero-extends the packed file
/// across every lower slot, so a legacy slot below a freshly written one reads
/// back a real `0` rather than staying short. A LIVE counter is always `>= 1`
/// (`credential_store` seeds a new credential at 1; each assertion stores `ctr+1`;
/// a migrated credential seeds from the global, which is `>= 1` whenever any
/// resident credential exists), so `0` unambiguously marks an unmaterialized slot.
/// The caller seeds a `None` from the frozen global counter so a migrated
/// credential's signCount never DEcreases (see [`crate::getassertion`]).
pub fn cred_sign_counter<S: Storage>(fs: &mut Fs<S>, slot: u16) -> Option<u32> {
    let off = slot as usize * 4;
    let mut buf = [0u8; CRED_CTR_LEN];
    let n = fs.read(EF_CRED_CTR, &mut buf)?;
    let end = off + 4;
    if end > n.min(CRED_CTR_LEN) {
        return None;
    }
    match u32::from_le_bytes(buf[off..end].try_into().unwrap()) {
        0 => None, // a zero-filled gap slot is unmaterialized, not a live signCount 0
        v => Some(v),
    }
}

/// Persist EF_CRED `slot`'s per-credential signature counter, growing the packed
/// EF_CRED_CTR file as needed. Entries below the current length are preserved;
/// entries in the newly grown gap are left 0, which [`cred_sign_counter`] reads
/// back as unmaterialized (so a legacy slot below this one still seeds from the
/// global counter). `slot` is an EF_CRED index (`< MAX_RESIDENT_CREDENTIALS`).
pub fn set_cred_sign_counter<S: Storage>(fs: &mut Fs<S>, slot: u16, value: u32) -> Result<()> {
    let off = slot as usize * 4;
    let end = off + 4;
    if end > CRED_CTR_LEN {
        return Err(Error::ExecError);
    }
    let mut buf = [0u8; CRED_CTR_LEN];
    let n = fs
        .read(EF_CRED_CTR, &mut buf)
        .unwrap_or(0)
        .min(CRED_CTR_LEN);
    buf[off..end].copy_from_slice(&value.to_le_bytes());
    fs.put(EF_CRED_CTR, &buf[..end.max(n)])
}

/// Test-only: build a legacy PIN-wrapped seed record (tag 0x03 pre-OTP / 0x13
/// OTP) — the outer PIN-keyed AEAD over the seed's inner CBC ciphertext — to
/// exercise [`migrate_keydev_pin`]. The tag arm must match the device generation.
#[cfg(test)]
pub(crate) fn wrap_keydev_legacy<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    seed: &[u8; 32],
    pin_hash: &[u8],
) {
    let mut inner = *seed;
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    aes_encrypt(&kbase, &iv, Mode::Cbc, &mut inner).unwrap();
    kbase.zeroize();
    let mut out = [0u8; KEYDEV_F3_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F3_OTP
    } else {
        FORMAT_F3
    };
    let session = dev.pin_derive_session(pin_hash);
    dev.encrypt_with_aad(&session, &inner, PinKdf::V2, &[0x24; 12], &mut out[1..])
        .unwrap();
    inner.zeroize();
    fs.put(EF_KEY_DEV.get(), &out).unwrap();
}

#[cfg(test)]
#[path = "seed_tests.rs"]
mod tests;
