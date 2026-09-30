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

use rsk_secret::Secret;

use rsk_crypto::aes_encrypt;
use rsk_crypto::chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_crypto::{Device, Mode, PinKdf, aes_decrypt, hkdf_sha256, hmac_sha256};
use rsk_fs::{Fs, KeyFid, Rearmed, Sealed, Storage};
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
/// A probe the medium could not answer reads as ENGAGED — every caller treats
/// `true` as "refuse until unlocked", and [`ensure_seed`] treats it as "do not
/// mint a seed over this one" (see [`lock_state`]).
pub fn lock_engaged<S: Storage>(fs: &mut Fs<S>) -> bool {
    lock_state(fs).unwrap_or(true)
}

/// [`lock_engaged`] with a failed probe kept apart from an absence.
/// `Fs::has_key` answers the same `false` for both, and this pair is what
/// `ensure_seed` decides seed regeneration on — the one write on the device that
/// destroys every credential derived from the old seed.
pub fn lock_state<S: Storage>(fs: &mut Fs<S>) -> Result<bool> {
    // Both halves, not just the sealed copy. `aut_enable` writes `EF_KEY_DEV_ENC`
    // and *then* deletes the plaintext `EF_KEY_DEV`; a power cut between the two
    // left both records, and testing only the sealed one reported `locked: true`
    // while `load_keydev` still read the surviving plaintext — so every FIDO
    // operation worked and BACKUP_EXPORT still handed out the seed without the lock
    // key. Reading the torn state as *unlocked* is the truth, and it lets
    // `rsk lock enable` simply be retried (audit run-33).
    Ok(fs.try_has_key(EF_KEY_DEV_ENC)? && !fs.try_has_key(EF_KEY_DEV)?)
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
pub fn open_seed_locked(lock_key: &[u8; 32], blob: &[u8]) -> Option<Secret<[u8; 32]>> {
    if blob.len() != LOCK_BLOB_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    let mut seed = Secret::<[u8; 32]>::zeroed();
    seed.expose_mut().copy_from_slice(&blob[12..44]);
    match chacha20poly1305_decrypt(lock_key, &nonce, &[], seed.expose_mut(), &tag) {
        Ok(()) => Some(seed),
        Err(_) => {
            seed.wipe();
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
        FORMAT_G1 => dev.pre_otp_arm(),
        FORMAT_G1_OTP => dev.otp_key.map(|_| *dev),
        _ => None,
    }
}

/// The ChaCha20-Poly1305 sealing key for `arm`: HKDF-SHA256(serial_hash, kbase).
fn seed_enc_key(arm: &Device) -> Secret<[u8; 32]> {
    let mut kbase = arm.derive_kbase();
    let mut enc = Secret::<[u8; 32]>::zeroed();
    hkdf_sha256(
        arm.serial_hash,
        kbase.expose(),
        INFO_SEED_ENC,
        enc.expose_mut(),
    )
    .expect("32-byte HKDF output");
    kbase.wipe();
    enc
}

/// The synthetic-nonce PRF key for `arm`: a second HKDF label off the same kbase.
fn seed_nonce_key(arm: &Device) -> Secret<[u8; 32]> {
    let mut kbase = arm.derive_kbase();
    let mut nk = Secret::<[u8; 32]>::zeroed();
    hkdf_sha256(
        arm.serial_hash,
        kbase.expose(),
        INFO_SEED_NONCE,
        nk.expose_mut(),
    )
    .expect("32-byte HKDF output");
    kbase.wipe();
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
    let nonce = synth_nonce(nk.expose(), fid, value);
    nk.wipe();
    let mut rec = [0u8; KEYDEV_G1_LEN];
    rec[0] = plain_tag(dev);
    rec[1..1 + NONCE_LEN].copy_from_slice(&nonce);
    let ctpos = 1 + NONCE_LEN;
    rec[ctpos..ctpos + 32].copy_from_slice(value);
    let mut enc = seed_enc_key(dev);
    let tag = chacha20poly1305_encrypt(
        enc.expose(),
        &nonce,
        dev.serial_hash,
        &mut rec[ctpos..ctpos + 32],
    );
    enc.wipe();
    rec[ctpos + 32..].copy_from_slice(&tag);
    rec
}

/// Open a ChaCha record (`0x02`/`0x12`), deriving the key from the tag's arm and
/// authenticating with the serial hash. `None` on a malformed blob, an orphaned
/// OTP-era tag (no OTP key), or an auth failure — a flipped tag byte picks the
/// wrong arm and the MAC rejects it.
fn open_gcm(dev: &Device, buf: &[u8]) -> Option<Secret<[u8; 32]>> {
    if buf.len() != KEYDEV_G1_LEN {
        return None;
    }
    let arm = gcm_arm(dev, buf[0])?;
    let ctpos = 1 + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[1..ctpos]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[ctpos + 32..]);
    let mut value = Secret::<[u8; 32]>::zeroed();
    value.expose_mut().copy_from_slice(&buf[ctpos..ctpos + 32]);
    let mut enc = seed_enc_key(&arm);
    let r = chacha20poly1305_decrypt(
        enc.expose(),
        &nonce,
        dev.serial_hash,
        value.expose_mut(),
        &tag,
    );
    enc.wipe();
    match r {
        Ok(()) => Some(value),
        Err(_) => {
            value.wipe();
            None
        }
    }
}

/// Decrypt a legacy fixed-IV AES-CBC record (`0x01` pre-OTP / `0x11` OTP, no
/// MAC), kept for load + migration of devices provisioned before the AEAD
/// format. An orphaned `0x11` read without the OTP key returns `None`.
fn cbc_open(dev: &Device, buf: &[u8]) -> Option<Secret<[u8; 32]>> {
    if buf.len() != KEYDEV_F1_LEN {
        return None;
    }
    let arm = match buf[0] {
        FORMAT_F1 => dev.pre_otp_arm()?,
        FORMAT_F1_OTP => {
            dev.otp_key?;
            *dev
        }
        _ => return None,
    };
    let mut value = Secret::<[u8; 32]>::zeroed();
    value.expose_mut().copy_from_slice(&buf[1..KEYDEV_F1_LEN]);
    let mut kbase = arm.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let r = aes_decrypt(kbase.expose(), &iv, Mode::Cbc, value.expose_mut());
    kbase.wipe();
    match r {
        Ok(()) => Some(value),
        Err(_) => {
            value.wipe();
            None
        }
    }
}

/// Recover a 32-byte value from any supported on-flash form: the current ChaCha
/// AEAD (either arm) or a legacy CBC record. A PIN-wrapped (0x03/0x13) blob
/// returns `None` — it is not loadable until `migrate_keydev_pin` opens its
/// outer layer.
fn open_any(dev: &Device, buf: &[u8]) -> Option<Secret<[u8; 32]>> {
    open_gcm(dev, buf).or_else(|| cbc_open(dev, buf))
}

/// Read and decrypt the 32-byte device seed. Returns `None` if absent,
/// undecryptable, or still in a legacy PIN-wrapped format (0x03/0x13) — those
/// become loadable again once a successful PIN verify migrates them
/// ([`migrate_keydev_pin`]).
pub fn load_keydev<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<Secret<[u8; 32]>> {
    get_sealed32(dev, fs, EF_KEY_DEV)
}

/// The org-provisioned FIDO attestation scalar (`EF_ATT_KEY`), sealed exactly
/// like the seed — the tag records which kbase arm wrapped it, so import before
/// or after OTP provisioning both stay loadable.
pub fn load_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<Secret<[u8; 32]>> {
    get_sealed32(dev, fs, EF_ATT_KEY)
}

pub fn store_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, key: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_ATT_KEY, key, None)
}

/// The persistent pinUvAuthToken (CTAP 2.2 §6.5.2.2), sealed exactly like the
/// seed; `None` if never minted, dropped by a PIN change, or unreadable here.
/// Presence is necessary but NOT sufficient — provisioning mints it before any PIN
/// exists, so [`crate::credmgmt`] owns the grant test, not this reader.
pub fn load_ppuat<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<Secret<[u8; 32]>> {
    get_sealed32(dev, fs, EF_PAUTHTOKEN)
}

/// [`load_ppuat`], minting a fresh token only when the record is confirmed absent —
/// the `pcmr` half of §6.5.5.7.2/.3. Unlike the session token it outlives the power
/// cycle, so it must reach flash before it reaches the platform.
pub fn ensure_ppuat<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
) -> Result<Secret<[u8; 32]>> {
    if let Some(tok) = try_get_sealed32(dev, fs, EF_PAUTHTOKEN)? {
        return Ok(tok);
    }
    let mut tok = Secret::<[u8; 32]>::zeroed();
    rng.fill(tok.expose_mut());
    let r = put_sealed32(dev, fs, EF_PAUTHTOKEN, tok.expose(), None);
    if r.is_err() {
        tok.wipe();
    }
    r.map(|()| tok)
}

/// `resetPersistentPinUvAuthToken` (§6.5.4): drop the token, which clears its
/// permissions with it. `force_delete`, not `delete` — this revokes a capability,
/// so a false-absent present bit must not leave the record live in the backend.
///
/// The FOLDED answer, deliberately, though EF_PAUTHTOKEN carries no EF_META head of
/// its own: `att_clear` and OpenPGP's attribute-change erase are in exactly that
/// position too, and splitting the halves for this one caller would re-open, at this
/// caller alone, the swallowed metadata drop 0x0987 closed. All four call sites are
/// one-shot commands, so refusing costs the command and no sweep's progress — the
/// reason the four reset sweeps, which lose a whole range, decided the other way.
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
/// `None` while the grant record is absent (a PIN change dropped it and nothing has
/// minted it again) or the seed is unreadable behind a soft lock: a placeholder built
/// from some other value would be a claim no platform could detect as false.
pub fn enc_identifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
) -> Option<[u8; ENC_GETINFO_MEMBER_LEN]> {
    // The token is the gate, so it is read FIRST: while a PIN change has the grant
    // dropped, opening the seal on the seed only to discard it would be a
    // ChaCha20-Poly1305 open on every getInfo for nothing.
    let mut token = load_ppuat(dev, fs)?;
    let mut key = Secret::<[u8; 16]>::zeroed();
    let derived = hkdf_sha256(&ENCID_SALT, token.expose(), INFO_ENCID, key.expose_mut());
    token.wipe();
    if derived.is_err() {
        key.wipe();
        return None;
    }

    let Some(mut seed) = load_keydev(dev, fs) else {
        key.wipe();
        return None;
    };
    let mut id = Secret::<[u8; 16]>::zeroed();
    let derived = hkdf_sha256(
        dev.serial_hash,
        seed.expose(),
        INFO_ENCID_DEVICE,
        id.expose_mut(),
    );
    seed.wipe();
    if derived.is_err() {
        id.wipe();
        key.wipe();
        return None;
    }

    let out = seal_getinfo_member(key.expose(), &mut id, rng);
    key.wipe();
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
/// `None` while the grant record is absent (a PIN change dropped it and nothing has
/// minted it again): there is no key to seal under. `None` too when the tag
/// itself cannot be read — an absent member equals no tag a platform is holding, so
/// it re-enumerates, where the collapsed zero is the tag an older build's untouched
/// store publishes and would tell one its cache is still good.
pub fn enc_cred_store_state<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut impl Rng,
) -> Option<[u8; ENC_GETINFO_MEMBER_LEN]> {
    let mut token = load_ppuat(dev, fs)?;
    let mut key = Secret::<[u8; 16]>::zeroed();
    let derived = hkdf_sha256(&ENCID_SALT, token.expose(), INFO_ENCCSS, key.expose_mut());
    token.wipe();
    if derived.is_err() {
        key.wipe();
        return None;
    }
    let mut block = Secret::new(crate::credential::cred_store_state(fs).ok()?);
    let out = seal_getinfo_member(key.expose(), &mut block, rng);
    key.wipe();
    out
}

/// `iv ‖ AES-128-CBC(k, block)` with a **fresh IV per call** — the shape CTAP 2.3
/// fixes for both encrypted getInfo members. A fixed or repeating IV would turn
/// either one into a stable fingerprint served to anyone who asks, which is the
/// tracking vector they exist to avoid. `block` is spent: it is zeroized here.
fn seal_getinfo_member(
    key: &[u8; 16],
    block: &mut Secret<[u8; 16]>,
    rng: &mut impl Rng,
) -> Option<[u8; ENC_GETINFO_MEMBER_LEN]> {
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    let sealed = aes_encrypt(key, &iv, Mode::Cbc, block.expose_mut());
    if sealed.is_err() {
        block.wipe();
        return None;
    }

    let mut out = [0u8; ENC_GETINFO_MEMBER_LEN];
    out[..16].copy_from_slice(&iv);
    out[16..].copy_from_slice(block.expose());
    block.wipe();
    Some(out)
}

/// Read and unseal a 32-byte value from any supported at-rest form (read-both).
fn get_sealed32<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Option<Secret<[u8; 32]>> {
    try_get_sealed32(dev, fs, fid).ok().flatten()
}

/// [`get_sealed32`] keeping a confirmed absence (`Ok(None)`) apart from a read that
/// failed or a record that will not open under `dev` (`Err`): the OTP root is read per
/// operation, so either can be one bad read. Mint over `Ok(None)` only.
fn try_get_sealed32<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
) -> Result<Option<Secret<[u8; 32]>>> {
    let mut buf = Secret::<[u8; 64]>::zeroed();
    let out = match fs.try_read_key(fid, buf.expose_mut()) {
        Ok(Some(n)) => open_any(dev, &buf.expose()[..n.min(buf.expose().len())])
            .map(Some)
            .ok_or(Error::ExecError),
        other => other.map(|_| None),
    };
    buf.wipe();
    out
}

/// Store `seed` ChaCha20-Poly1305-sealed under the device root key (tag 0x02, or
/// 0x12 once the OTP key is provisioned).
pub fn encrypt_keydev_f1<S: Storage>(dev: &Device, fs: &mut Fs<S>, seed: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_KEY_DEV, seed, None)
}

/// Seal a 32-byte value under the current arm's ChaCha key and write it to `fid`,
/// over a pre-OTP copy when `rearmed` says so.
fn put_sealed32<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    value: &[u8; 32],
    rearmed: Option<&Rearmed>,
) -> Result<()> {
    let mut rec = Secret::new(seal_gcm(dev, fid, value));
    let r = fs.put_key_over(fid, Sealed::wrap(rec.expose()), rearmed);
    rec.wipe();
    r
}

/// Boot-pass migration for the seed, the attestation key and the persistent
/// grant: bring each to the current ChaCha form under the current kbase arm —
/// upgrading a legacy CBC record (removing the fixed-IV / no-MAC weakness) and
/// re-sealing a pre-OTP blob under the OTP arm once the fuse key is present. A
/// PIN-wrapped (0x03/0x13) seed is left untouched — that migrates at the first
/// PIN verify ([`migrate_keydev_pin`]). Idempotent and crash-safe: each re-seal
/// is one atomic record write, and a torn write leaves the prior record intact.
///
/// The grant is here because provisioning mints it ([`ensure_seed`]) and a device
/// is burned after its first boot, so the record a `pcmr` holder and getInfo's
/// encIdentifier hang off would otherwise stay under the chip-serial arm for life.
///
/// `Ok(true)` when a slot stays under the chip-serial arm (a PIN-wrapped seed, until
/// its PIN verifies), and a refused re-seal or a read the flash failed is the `Err`:
/// either keeps the page-58 lock waiting (`rsk_rescue::Platform::pre_otp_left`).
pub fn migrate_keydev_boot<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Result<bool> {
    let seed = migrate_slot(dev, fs, EF_KEY_DEV)?;
    let att = migrate_slot(dev, fs, EF_ATT_KEY)?;
    let grant = migrate_slot(dev, fs, EF_PAUTHTOKEN)?;
    Ok(seed || att || grant)
}

/// Re-seal one slot forward if it is not already current-arm ChaCha. Absent
/// slots and unrecoverable (PIN-wrapped) records are no-ops; the answer is whether
/// the slot is left under the chip-serial arm.
fn migrate_slot<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<bool> {
    let mut buf = Secret::<[u8; 64]>::zeroed();
    let Some(n) = fs.try_read_key(fid, buf.expose_mut())? else {
        return Ok(false);
    };
    let n = n.min(buf.expose().len());
    // Already current-arm ChaCha? Skip the redundant flash erase (the
    // deterministic re-seal would be byte-identical anyway).
    if buf.expose()[0] == plain_tag(dev)
        && let Some(mut v) = open_gcm(dev, &buf.expose()[..n])
    {
        v.wipe();
        buf.wipe();
        return Ok(false);
    }
    // `weak`: 0x01/0x02 are sealed under the chip-serial arm, so the re-seal below
    // supersedes a copy the public serial alone derives. This pass runs BEFORE the
    // boot's lap, but a boot that skipped the slot already latched the marker.
    //
    // 0x11 is deliberately OUT: the copy it displaces is fixed-IV/no-MAC CBC, but
    // under the OTP arm, so a flash dump alone cannot open it. That is a second
    // at-rest weakness this re-seal repairs and the lap owes nothing for.
    let weak = matches!(buf.expose()[0], FORMAT_F1 | FORMAT_G1) && dev.otp_key.is_some();
    // Past the latch a PIN-wrapped pre-OTP seed was planted and no PIN use moves it.
    let pin_wrapped =
        buf.expose()[0] == FORMAT_F3 && dev.otp_key.is_some() && dev.pre_otp_arm().is_some();
    let recovered = open_any(dev, &buf.expose()[..n]);
    buf.wipe();
    match recovered {
        Some(mut v) => {
            // Ahead of the write and gating it, per `rsk_fs::request_rescrub`: a
            // reset in the window then costs one idempotent lap, and a medium that
            // refuses the re-arm leaves the pre-OTP record in force instead.
            let r = match rsk_fs::request_rescrub_if(fs, weak) {
                Ok(rearmed) => put_sealed32(dev, fs, fid, v.expose(), rearmed.as_ref()),
                Err(_) => Err(Error::MemoryFatal),
            };
            v.wipe();
            r.map(|()| false)
        }
        // A pre-OTP PIN-wrapped seed moves at its first PIN verify (`migrate_keydev_pin`).
        None => Ok(pin_wrapped),
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
    let mut buf = Secret::<[u8; 64]>::zeroed();
    let Some(KEYDEV_F3_LEN) = fs.read_key(EF_KEY_DEV, buf.expose_mut()) else {
        return Ok(());
    };
    // `weak`: a 0x03 record on an OTP card is sealed under the chip-serial arm, so
    // the re-seal below supersedes a copy the public serial alone derives. 0x13 is
    // already OTP-rooted, and a card with no OTP key has no lap to re-arm.
    let (seal_dev, cbc_tag, weak) = match (buf.expose()[0], dev.pre_otp_arm()) {
        (FORMAT_F3, Some(old)) => (old, FORMAT_F1, dev.otp_key.is_some()),
        (FORMAT_F3_OTP, _) if dev.otp_key.is_some() => (*dev, FORMAT_F1_OTP, false),
        _ => return Ok(()),
    };
    // Strip the outer PIN AEAD, leaving the inner CBC record the seed was sealed
    // in before the PIN was set.
    let mut session = seal_dev.pin_derive_session(pin_hash);
    let mut cbc = Secret::<[u8; KEYDEV_F1_LEN]>::zeroed();
    cbc.expose_mut()[0] = cbc_tag;
    let r = seal_dev.decrypt_with_aad(
        session.expose(),
        &buf.expose()[1..KEYDEV_F3_LEN],
        PinKdf::V2,
        &mut cbc.expose_mut()[1..],
    );
    session.wipe();
    buf.wipe();
    if r.is_err() {
        cbc.wipe();
        return Err(Error::ExecError);
    }
    // Recover the seed through the shared CBC reader and re-seal it forward under
    // the current arm as authenticated ChaCha.
    let recovered = cbc_open(dev, cbc.expose());
    cbc.wipe();
    match recovered {
        Some(mut seed) => {
            // The re-arm belongs here, not at the two callers: theirs is gated on
            // EF_PIN's verifier having been pre-OTP, and one faulted `read_key` here
            // is enough to leave that verifier migrated and this record at 0x03.
            let r = match rsk_fs::request_rescrub_if(fs, weak) {
                Ok(rearmed) => put_sealed32(dev, fs, EF_KEY_DEV, seed.expose(), rearmed.as_ref()),
                Err(_) => Err(Error::MemoryFatal),
            };
            seed.wipe();
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
    let locked = lock_state(fs)?;
    if !fs.try_has_key(EF_KEY_DEV)? && !locked {
        let mut seed = Secret::<[u8; 32]>::zeroed();
        loop {
            rng.fill(seed.expose_mut());
            if P256Key::from_scalar(seed.expose()).is_some() {
                break;
            }
        }
        // A new seed starts a new credential store — a fresh device, or one just
        // reset — and §6.6 wants a new state for it. Ahead of the seed: a cut between
        // the two leaves no seed, so the next call runs this whole arm again.
        let r = put_new_store_state(dev, fs, seed.expose())
            .and_then(|()| encrypt_keydev_f1(dev, fs, seed.expose()));
        seed.wipe();
        r?;
    }
    // Not `has_data`: a faulted probe here would roll the signature counter back
    // to zero and overwrite the large-blob array — the same absent-means-first-boot
    // reading the seed guard above makes, at two records the owner cannot rebuild.
    if !fs.try_has_counter(EF_COUNTER)? {
        fs.put_counter(EF_COUNTER, &[0u8; 4])?;
    }
    if !fs.try_has_data(EF_LARGEBLOB)? {
        fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL)?;
    }
    if !locked {
        let mut seed = load_keydev(dev, fs).ok_or(Error::ExecError)?;
        let r = rebuild_att_cert(fs, rng, seed.expose());
        seed.wipe();
        r?;
        // getInfo 0x19/0x1E are sealed under this grant, so a device never asked for
        // one published neither — and a conformance runner reads getInfo before it
        // can ask. The reference device publishes both from the factory.
        let mut tok = ensure_ppuat(dev, fs, rng)?;
        tok.wipe();
    }
    Ok(())
}

/// Our label for a new store's `encCredStoreState` tag, in its own domain off the seed.
const INFO_STORE_STATE: &[u8] = b"KEYDEV/CREDSTATE";

/// Writes a new store's `encCredStoreState` tag, derived from the fresh seed that starts
/// it: as unpredictable as the seed, without a draw that would move every later value
/// provisioning takes. A loaded seed can repeat, so `BACKUP_LOAD` draws one instead.
fn put_new_store_state<S: Storage>(dev: &Device, fs: &mut Fs<S>, seed: &[u8; 32]) -> Result<()> {
    let mut tag = [0u8; crate::consts::CRED_STATE_LEN];
    hkdf_sha256(dev.serial_hash, seed, INFO_STORE_STATE, &mut tag).map_err(|_| Error::ExecError)?;
    fs.put(crate::consts::EF_CRED_STATE, &tag)
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
    // The collapsing probe stands. The arm it collapses into REWRITES the leaf,
    // which reads like the class this file is full of — but the rewrite is built
    // from the seed the caller already holds, so it is always correct: everything
    // but the serial and the signature is a fixed template, and the attesting key,
    // the AAGUID and the subject come out byte-identical. The cost is a new serial
    // and one flash write, i.e. a repeated repair.
    //
    // Skipping on the failure instead was tried and REFUTED by measurement: a
    // truncated `scan` leaves `EF_EE_DEV` undecided, so the probe reaches the
    // medium on a first boot too — and the skip then leaves the device with NO
    // certificate, or lets `backup_load` install a new seed and report success
    // over the leaf that certifies the old one.
    //
    // That rewrite IS a superseding write — measured, `[Write(0xce00, 490B)]` on a
    // fully provisioned card with a stale template — so `ensure_seed` owes the
    // at-rest lap no re-arm for the REASON stated here and not for "it writes only
    // what it found absent": `EF_EE_DEV` is a public X.509 leaf, not a
    // chip-serial-sealed secret, so the copy it displaces discloses nothing.
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

/// The global signature counter, stored little-endian; 0 when the record is
/// absent or short (`authenticatorReset` deletes it, `ensure_seed` recreates it
/// at the next boot).
///
/// Not `Fs::read`, and no collapsing sibling: signCount is the ONLY clone
/// evidence a relying party gets (WebAuthn L3 §6.1.1), and the value a failed
/// probe would collapse to is 0 — the one that erases it. The safe default the
/// [`crate::vendor::backup_sealed`] pair leans on does not exist for a `u32`.
pub fn global_sign_counter<S: Storage>(fs: &mut Fs<S>) -> Result<u32> {
    let mut buf = [0u8; 4];
    Ok(match fs.try_read_counter(EF_COUNTER, &mut buf)? {
        Some(4) => u32::from_le_bytes(buf),
        _ => 0,
    })
}

/// Persist `counter+1`; returns the value *before* the bump — the value to
/// report in the current operation. Now used only by U2F authenticate (CTAP2
/// signature counters are per-credential, see [`cred_sign_counter`]).
pub fn bump_sign_counter<S: Storage>(fs: &mut Fs<S>) -> Result<u32> {
    let ctr = global_sign_counter(fs)?;
    fs.put_counter(EF_COUNTER, &ctr.wrapping_add(1).to_le_bytes())?;
    Ok(ctr)
}

/// Packed EF_CRED_CTR length: one `u32` per resident slot.
const CRED_CTR_LEN: usize = MAX_RESIDENT_CREDENTIALS as usize * 4;

/// The per-credential signature counter stored for EF_CRED `slot`. Three answers,
/// deliberately kept apart: `Err` is a probe the medium could not serve,
/// `Ok(None)` is an UNMATERIALIZED slot, `Ok(Some(v))` a live counter.
///
/// `Ok(None)` covers three cases that are all handled identically (seed from the
/// frozen global): the packed file is absent, it is shorter than `slot`, OR the
/// slot reads as **0**. The zero case matters: a write to a HIGHER slot
/// zero-extends the packed file across every lower slot, so a legacy slot below a
/// freshly written one reads back a real `0` rather than staying short. A LIVE
/// counter is always `>= 1` (`credential_store` seeds a new credential at 1; each
/// assertion stores `ctr+1`; a migrated credential seeds from the global, which is
/// `>= 1` whenever any resident credential exists), so `0` unambiguously marks an
/// unmaterialized slot.
///
/// The fault is the fourth state and cannot join them: the caller seeds an
/// unmaterialized slot from the global counter, so collapsing the two hands a LIVE
/// credential a signCount off a different sequence (see [`report_sign_counter`]).
pub fn cred_sign_counter<S: Storage>(fs: &mut Fs<S>, slot: u16) -> Result<Option<u32>> {
    let off = slot as usize * 4;
    let mut buf = [0u8; CRED_CTR_LEN];
    let Some(n) = fs.try_read_counter(EF_CRED_CTR, &mut buf)? else {
        return Ok(None);
    };
    let end = off + 4;
    if end > n.min(CRED_CTR_LEN) {
        return Ok(None);
    }
    Ok(
        match u32::from_le_bytes(buf[off..end].try_into().unwrap()) {
            0 => None, // a zero-filled gap slot is unmaterialized, not a live signCount 0
            v => Some(v),
        },
    )
}

/// The signCount to report for EF_CRED `slot`: its own counter, or the frozen
/// global one for a slot that has none yet — a credential from before EF_CRED_CTR
/// existed, whose count must not DEcrease across the upgrade.
///
/// Fallible on both reads. A counter that could not be read has no substitute:
/// the global is not this credential's sequence, and 0 is the value an RP reads
/// as "no clone detection here".
pub fn report_sign_counter<S: Storage>(fs: &mut Fs<S>, slot: u16) -> Result<u32> {
    match cred_sign_counter(fs, slot)? {
        Some(v) => Ok(v),
        None => global_sign_counter(fs),
    }
}

/// Persist EF_CRED `slot`'s per-credential signature counter, growing the packed
/// EF_CRED_CTR file as needed. Entries below the current length are preserved;
/// entries in the newly grown gap are left 0, which [`cred_sign_counter`] reads
/// back as unmaterialized (so a legacy slot below this one still seeds from the
/// global counter). `slot` is an EF_CRED index (`< MAX_RESIDENT_CREDENTIALS`).
///
/// Not `Fs::read`: this read is the merge, so a fault collapsing to "absent"
/// writes a ZERO-filled buffer truncated to `end` — one bad probe zeroes every
/// lower slot and drops every higher one, for credentials this call never named.
pub fn set_cred_sign_counter<S: Storage>(fs: &mut Fs<S>, slot: u16, value: u32) -> Result<()> {
    let off = slot as usize * 4;
    let end = off + 4;
    if end > CRED_CTR_LEN {
        return Err(Error::ExecError);
    }
    let mut buf = [0u8; CRED_CTR_LEN];
    let n = fs
        .try_read_counter(EF_CRED_CTR, &mut buf)?
        .unwrap_or(0)
        .min(CRED_CTR_LEN);
    buf[off..end].copy_from_slice(&value.to_le_bytes());
    fs.put_counter(EF_CRED_CTR, &buf[..end.max(n)])
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
    let mut inner = Secret::new(*seed);
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    aes_encrypt(kbase.expose(), &iv, Mode::Cbc, inner.expose_mut()).unwrap();
    kbase.wipe();
    let mut out = [0u8; KEYDEV_F3_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F3_OTP
    } else {
        FORMAT_F3
    };
    let session = dev.pin_derive_session(pin_hash);
    dev.encrypt_with_aad(
        session.expose(),
        inner.expose(),
        PinKdf::V2,
        &[0x24; 12],
        &mut out[1..],
    )
    .unwrap();
    inner.wipe();
    fs.put(EF_KEY_DEV.get(), &out).unwrap();
}

/// `EF_ATT_KEY` as an enterprise attestation has to tell it apart: no org key, one
/// that will not open under this device, or the key itself.
pub(crate) enum AttKey {
    Absent,
    Unopenable,
    Loaded(Secret<[u8; 32]>),
}

/// [`load_att_key`] with its outcomes kept apart, and `Err` for a read the flash
/// failed: a retry may serve that one, and never a record that will not open.
pub(crate) fn read_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Result<AttKey> {
    let mut buf = Secret::<[u8; 64]>::zeroed();
    let out = fs
        .try_read_key(EF_ATT_KEY, buf.expose_mut())
        .map(|read| match read {
            None => AttKey::Absent,
            Some(n) => open_any(dev, &buf.expose()[..n.min(buf.expose().len())])
                .map_or(AttKey::Unopenable, AttKey::Loaded),
        });
    buf.wipe();
    out
}

#[cfg(test)]
#[path = "seed_tests.rs"]
mod tests;
