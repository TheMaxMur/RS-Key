// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

/// Test-only: `seed` AES-CBC-encrypted under `dev`'s arm (fixed serial-hash IV)
/// as the pre-AEAD legacy record (tag 0x01 pre-OTP / 0x11 OTP), to exercise the
/// boot upgrade path without the old write code.
pub(crate) fn write_legacy_cbc<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    seed: &[u8; 32],
) {
    let mut ct = *seed;
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    aes_encrypt(&kbase, &iv, Mode::Cbc, &mut ct).unwrap();
    kbase.zeroize();
    let mut out = [0u8; KEYDEV_F1_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F1_OTP
    } else {
        FORMAT_F1
    };
    out[1..].copy_from_slice(&ct);
    ct.zeroize();
    fs.put_key(fid, Sealed::wrap(&out)).unwrap();
}

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

const OTP_KEY: [u8; 32] = [0x77; 32];

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn otp_dev() -> Device<'static> {
    Device {
        otp_key: Some(&OTP_KEY),
        ..dev()
    }
}

fn fs() -> Fs<RamStorage> {
    Fs::new(RamStorage::new())
}

#[test]
fn seed_roundtrips_through_flash() {
    let d = dev();
    let mut fs = fs();
    let seed = [0x5A; 32];
    encrypt_keydev_f1(&d, &mut fs, &seed).unwrap();
    // Stored as [tag] ‖ nonce ‖ ct ‖ tag, ChaCha-sealed — not the plaintext.
    assert_eq!(fs.size(EF_KEY_DEV.get()), Some(KEYDEV_G1_LEN));
    let mut raw = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1);
    assert_ne!(&raw[13..45], &seed); // the ciphertext, not the seed
    assert_eq!(load_keydev(&d, &mut fs), Some(seed));
}

#[test]
fn wrong_device_cannot_decrypt_seed() {
    let mut fs = fs();
    encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
    let other = Device {
        serial_hash: &[0xCD; 32],
        ..dev()
    };
    // A different root key derives a different AEAD key → the tag rejects it.
    assert_eq!(load_keydev(&other, &mut fs), None);
}

#[test]
fn seal_is_authenticated_against_tamper() {
    // The property the fixed-IV CBC seal lacked: a single flipped ciphertext
    // byte no longer decrypts to a silently-corrupted seed — the MAC refuses.
    let d = dev();
    let mut fs = fs();
    encrypt_keydev_f1(&d, &mut fs, &[0x5A; 32]).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    raw[13] ^= 0x01; // flip a ciphertext byte
    fs.put_key(EF_KEY_DEV, Sealed::wrap(&raw)).unwrap();
    assert_eq!(load_keydev(&d, &mut fs), None);
}

#[test]
fn seed_and_att_key_never_share_a_nonce() {
    // The finding: two same-format scalars under one fixed-IV CBC key leaked
    // via block-0 keystream reuse. The fid-separated synthetic nonce means
    // even an identical value stores differently across the two slots.
    let d = dev();
    let mut fs = fs();
    let value = [0x5A; 32];
    encrypt_keydev_f1(&d, &mut fs, &value).unwrap();
    store_att_key(&d, &mut fs, &value).unwrap();
    let mut a = [0u8; KEYDEV_G1_LEN];
    let mut b = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut a).unwrap();
    fs.read(EF_ATT_KEY.get(), &mut b).unwrap();
    assert_ne!(&a[1..13], &b[1..13]); // distinct nonces
    assert_ne!(&a[13..45], &b[13..45]); // distinct ciphertext
    assert_eq!(load_keydev(&d, &mut fs), Some(value));
    assert_eq!(load_att_key(&d, &mut fs), Some(value));
}

#[test]
fn legacy_cbc_record_loads_and_upgrades_at_boot() {
    // A device provisioned before the AEAD format holds a fixed-IV CBC
    // record; it must still load, and the boot pass upgrades it to ChaCha.
    let d = dev();
    let mut fs = fs();
    let seed = [0x5A; 32];
    write_legacy_cbc(&d, &mut fs, EF_KEY_DEV, &seed);
    assert_eq!(fs.size(EF_KEY_DEV.get()), Some(KEYDEV_F1_LEN));
    assert_eq!(load_keydev(&d, &mut fs), Some(seed));

    migrate_keydev_boot(&d, &mut fs).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_G1_LEN));
    assert_eq!(raw[0], FORMAT_G1);
    assert_eq!(load_keydev(&d, &mut fs), Some(seed));

    // Idempotent AND byte-deterministic (synthetic nonce): a second pass
    // leaves the record identical.
    migrate_keydev_boot(&d, &mut fs).unwrap();
    let mut again = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut again).unwrap();
    assert_eq!(raw, again);
}

#[test]
fn att_key_legacy_cbc_migrates_at_boot() {
    // The attestation scalar shares the seal path and the boot migration.
    let d = dev();
    let mut fs = fs();
    let att = [0x21; 32];
    write_legacy_cbc(&d, &mut fs, EF_ATT_KEY, &att);
    assert_eq!(load_att_key(&d, &mut fs), Some(att));
    migrate_keydev_boot(&d, &mut fs).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_ATT_KEY.get(), &mut raw), Some(KEYDEV_G1_LEN));
    assert_eq!(raw[0], FORMAT_G1);
    assert_eq!(load_att_key(&d, &mut fs), Some(att));
}

#[test]
fn legacy_pin_wrapped_seed_unreadable_until_pin_migrates_it() {
    let d = dev();
    let mut fs = fs();
    let seed = [0x5A; 32];
    let pin_hash = [0x99u8; 16];
    wrap_keydev_legacy(&d, &mut fs, &seed, &pin_hash);
    assert_eq!(fs.size(EF_KEY_DEV.get()), Some(KEYDEV_F3_LEN));
    // The wrapped blob is unreadable (the UP-only failure window)…
    assert_eq!(load_keydev(&d, &mut fs), None);
    // …until a PIN verify unwraps it forward to plain ChaCha, permanently.
    migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_G1_LEN));
    assert_eq!(raw[0], FORMAT_G1);
    assert_eq!(load_keydev(&d, &mut fs), Some(seed));
    // Idempotent.
    migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
    assert_eq!(load_keydev(&d, &mut fs), Some(seed));
}

#[test]
fn migration_with_wrong_pin_fails_and_leaves_blob_intact() {
    let d = dev();
    let mut fs = fs();
    wrap_keydev_legacy(&d, &mut fs, &[0x5A; 32], &[0x99u8; 16]);
    assert!(migrate_keydev_pin(&d, &mut fs, &[0x11u8; 16]).is_err());
    let mut raw = [0u8; KEYDEV_F3_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_F3_LEN));
    assert_eq!(raw[0], FORMAT_F3);
}

#[test]
fn ensure_seed_is_idempotent() {
    let d = dev();
    let mut fs = fs();
    let mut rng = SeqRng(7);
    ensure_seed(&d, &mut fs, &mut rng).unwrap();
    let seed1 = load_keydev(&d, &mut fs).unwrap();
    assert!(fs.has_data(EF_COUNTER));
    assert_eq!(get_sign_counter(&mut fs), 0);
    // A second scan must not regenerate the seed.
    ensure_seed(&d, &mut fs, &mut rng).unwrap();
    assert_eq!(load_keydev(&d, &mut fs).unwrap(), seed1);
    assert!(P256Key::from_scalar(&seed1).is_some());
}

#[test]
fn counter_bumps_and_persists() {
    let mut fs = fs();
    fs.put(EF_COUNTER, &[0u8; 4]).unwrap();
    assert_eq!(bump_sign_counter(&mut fs).unwrap(), 0);
    assert_eq!(bump_sign_counter(&mut fs).unwrap(), 1);
    assert_eq!(get_sign_counter(&mut fs), 2);
}

#[test]
fn lock_blob_roundtrips_and_authenticates() {
    let mut rng = SeqRng(3);
    let key = [0x4D; 32];
    let seed = [0x5A; 32];
    let blob = seal_seed_locked(&mut rng, &key, &seed);
    assert_eq!(open_seed_locked(&key, &blob), Some(seed));
    // Wrong key, tampered ciphertext, truncated blob: all refused.
    assert_eq!(open_seed_locked(&[0x4E; 32], &blob), None);
    let mut bad = blob;
    bad[20] ^= 1;
    assert_eq!(open_seed_locked(&key, &bad), None);
    assert_eq!(open_seed_locked(&key, &blob[..LOCK_BLOB_LEN - 1]), None);
}

#[test]
fn ensure_seed_skips_generation_when_locked() {
    // A locked device has only the wrapped blob on flash; a boot pass must
    // not invent a fresh seed next to it (that would fork the identity).
    let d = dev();
    let mut fs = fs();
    let mut rng = SeqRng(9);
    let blob = seal_seed_locked(&mut rng, &[0x4D; 32], &[0x5A; 32]);
    fs.put(EF_KEY_DEV_ENC.get(), &blob).unwrap();
    ensure_seed(&d, &mut fs, &mut rng).unwrap();
    assert!(!fs.has_data(EF_KEY_DEV.get()));
    assert!(fs.has_data(EF_COUNTER)); // the rest of the scan still runs
    assert!(!fs.has_data(EF_EE_DEV)); // cert step skipped (seed unreadable)
}

#[test]
fn boot_migration_reseals_plain_seed_to_otp_kbase() {
    let mut fs = fs();
    let seed = [0x5A; 32];
    encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap(); // 0x02 pre-OTP arm

    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1_OTP);
    assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));

    // Idempotent: a second pass is a no-op (tag already 0x12).
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
}

#[test]
fn boot_migration_without_otp_is_noop() {
    let mut fs = fs();
    encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
    migrate_keydev_boot(&dev(), &mut fs).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1);
}

#[test]
fn otp_era_seed_fails_cleanly_without_otp_key() {
    // Downgrade scenario: a 0x12 blob read by a no-OTP device must yield a
    // clean None, never a wrong-key result masquerading as a seed.
    let mut fs = fs();
    let seed = [0x5A; 32];
    encrypt_keydev_f1(&otp_dev(), &mut fs, &seed).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1_OTP);
    assert_eq!(load_keydev(&dev(), &mut fs), None);
}

#[test]
fn pre_otp_wrapped_seed_migrates_to_otp_plain_at_verify() {
    let mut fs = fs();
    let seed = [0x5A; 32];
    let pin_hash = [0x99u8; 16];

    // Legacy pre-OTP layout: plain seed, then a PIN set wrapped it (0x03).
    wrap_keydev_legacy(&dev(), &mut fs, &seed, &pin_hash);
    let mut raw = [0u8; KEYDEV_F3_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_F3);

    // The boot pass cannot touch a PIN-wrapped blob.
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_F3);

    // First PIN verify on the OTP build unwraps the outer layer AND re-seals
    // forward — straight to a plain 0x12, loadable with no session.
    migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
    let mut g = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut g), Some(KEYDEV_G1_LEN));
    assert_eq!(g[0], FORMAT_G1_OTP);
    assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));

    // Idempotent.
    migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
    assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
}

#[test]
fn otp_wrapped_seed_migrates_to_plain_at_verify() {
    // A legacy 0x13 blob unwraps to 0x12 at verify; without the OTP key it
    // is left untouched.
    let mut fs = fs();
    let seed = [0x5A; 32];
    let pin_hash = [0x99u8; 16];
    wrap_keydev_legacy(&otp_dev(), &mut fs, &seed, &pin_hash);
    let mut raw = [0u8; KEYDEV_F3_LEN];
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_F3_OTP);

    // Orphan on a no-OTP build: no-op, no error, still closed.
    migrate_keydev_pin(&dev(), &mut fs, &pin_hash).unwrap();
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_F3_OTP);
    assert_eq!(load_keydev(&dev(), &mut fs), None);

    migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
    let mut g = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut g), Some(KEYDEV_G1_LEN));
    assert_eq!(g[0], FORMAT_G1_OTP);
    assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
}

/// Recover the identifier the way a platform holding the persistent token would:
/// re-derive the AES key from the token, split `iv ‖ ct`, decrypt one block.
fn open_enc_identifier(token: &[u8; 32], blob: &[u8; ENC_IDENTIFIER_LEN]) -> [u8; 16] {
    let mut key = [0u8; 16];
    hkdf_sha256(&ENCID_SALT, token, INFO_ENCID, &mut key).unwrap();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&blob[..16]);
    let mut pt = [0u8; 16];
    pt.copy_from_slice(&blob[16..]);
    aes_decrypt(&key, &iv, Mode::Cbc, &mut pt).unwrap();
    pt
}

/// The member is keyed by the persistent token and names the seed, so it cannot be
/// built without both. Neither absence is an error — 0x19 is optional, and emitting
/// something derived from a stand-in would be a claim nothing could falsify.
#[test]
fn enc_identifier_needs_both_a_token_and_a_readable_seed() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(7));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    assert!(
        enc_identifier(&d, &mut f, &mut rng).is_none(),
        "no persistent token yet — nothing to key it with"
    );

    ensure_ppuat(&d, &mut f, &mut rng).unwrap();
    assert!(enc_identifier(&d, &mut f, &mut rng).is_some());

    // A soft lock moves the seed into EF_KEY_DEV_ENC and deletes the plain record.
    f.delete_key(EF_KEY_DEV).unwrap();
    assert!(
        enc_identifier(&d, &mut f, &mut rng).is_none(),
        "seed unreadable behind a soft lock — no identifier to encrypt"
    );
}

/// The security property the member lives or dies by: **the bytes must differ on
/// every call** — a repeating IV would serve a stable cross-origin fingerprint to
/// anyone who asks — **while the identifier underneath stays the same**, or a
/// platform holding the token could never recognize the device twice. Asserting
/// only the first half would pass for a random blob that identifies nothing;
/// asserting only the second would pass for the fingerprint.
#[test]
fn enc_identifier_is_fresh_per_call_but_stable_underneath() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(11));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let token = ensure_ppuat(&d, &mut f, &mut rng).unwrap();

    let first = enc_identifier(&d, &mut f, &mut rng).unwrap();
    let second = enc_identifier(&d, &mut f, &mut rng).unwrap();
    assert_ne!(first, second, "a repeated blob is a device fingerprint");
    assert_ne!(first[..16], second[..16], "the IV itself must be fresh");

    let id = open_enc_identifier(&token, &first);
    assert_eq!(
        id,
        open_enc_identifier(&token, &second),
        "the same device must decrypt to the same identifier"
    );
    assert_ne!(id, [0u8; 16], "an all-zero identifier identifies nothing");
}

/// `authenticatorReset` mints a fresh seed, and the identifier is derived from it,
/// so a reset device stops being linkable to its pre-reset self. That is the reason
/// the seed is the root rather than the silicon key, which a reset cannot touch.
#[test]
fn enc_identifier_follows_the_seed_across_a_reseed() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(13));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let token = ensure_ppuat(&d, &mut f, &mut rng).unwrap();
    let before = open_enc_identifier(&token, &enc_identifier(&d, &mut f, &mut rng).unwrap());

    f.delete_key(EF_KEY_DEV).unwrap();
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let after = open_enc_identifier(&token, &enc_identifier(&d, &mut f, &mut rng).unwrap());

    assert_ne!(before, after, "a new seed must mean a new identity");
}

/// The identifier is HKDF'd from the seed under its own label, so it must not equal
/// the seed, nor any other value derived from it — the label is what stops a leaked
/// identifier from saying anything about the key material behind it.
#[test]
fn enc_identifier_is_not_the_seed_nor_the_at_rest_key() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(17));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let token = ensure_ppuat(&d, &mut f, &mut rng).unwrap();
    let id = open_enc_identifier(&token, &enc_identifier(&d, &mut f, &mut rng).unwrap());

    let seed = load_keydev(&d, &mut f).unwrap();
    assert_ne!(id, seed[..16], "the identifier must not expose the seed");

    let mut sibling = [0u8; 16];
    hkdf_sha256(d.serial_hash, &seed, INFO_SEED_ENC, &mut sibling).unwrap();
    assert_ne!(id, sibling, "labels must separate the domains");
}
