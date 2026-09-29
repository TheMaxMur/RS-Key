// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::EF_COUNTER;
use rsk_fs::storage::faults::{Cut, RemoveStuck};
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
    let mut ct = rsk_secret::Secret::new(*seed);
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    aes_encrypt(kbase.expose(), &iv, Mode::Cbc, ct.expose_mut()).unwrap();
    kbase.wipe();
    let mut out = [0u8; KEYDEV_F1_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F1_OTP
    } else {
        FORMAT_F1
    };
    out[1..].copy_from_slice(ct.expose());
    ct.wipe();
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
        latched: false,
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
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&seed))
    );
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
    assert!((load_keydev(&other, &mut fs)).is_none());
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
    assert!((load_keydev(&d, &mut fs)).is_none());
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
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&value))
    );
    assert_eq!(
        crate::bare(load_att_key(&d, &mut fs)),
        Some(crate::bare(&value))
    );
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
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&seed))
    );

    migrate_keydev_boot(&d, &mut fs).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_G1_LEN));
    assert_eq!(raw[0], FORMAT_G1);
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&seed))
    );

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
    assert_eq!(
        crate::bare(load_att_key(&d, &mut fs)),
        Some(crate::bare(&att))
    );
    migrate_keydev_boot(&d, &mut fs).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_ATT_KEY.get(), &mut raw), Some(KEYDEV_G1_LEN));
    assert_eq!(raw[0], FORMAT_G1);
    assert_eq!(
        crate::bare(load_att_key(&d, &mut fs)),
        Some(crate::bare(&att))
    );
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
    assert!((load_keydev(&d, &mut fs)).is_none());
    // …until a PIN verify unwraps it forward to plain ChaCha, permanently.
    migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_G1_LEN));
    assert_eq!(raw[0], FORMAT_G1);
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&seed))
    );
    // Idempotent.
    migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&seed))
    );
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
    assert!(fs.has_counter(EF_COUNTER));
    assert_eq!(global_sign_counter(&mut fs).unwrap(), 0);
    // A second scan must not regenerate the seed.
    ensure_seed(&d, &mut fs, &mut rng).unwrap();
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs).unwrap()),
        crate::bare(&seed1)
    );
    assert!(P256Key::from_scalar(seed1.expose()).is_some());
}

#[test]
fn counter_bumps_and_persists() {
    let mut fs = fs();
    fs.put_counter(EF_COUNTER, &[0u8; 4]).unwrap();
    assert_eq!(bump_sign_counter(&mut fs).unwrap(), 0);
    assert_eq!(bump_sign_counter(&mut fs).unwrap(), 1);
    assert_eq!(global_sign_counter(&mut fs).unwrap(), 2);
}

#[test]
fn lock_blob_roundtrips_and_authenticates() {
    let mut rng = SeqRng(3);
    let key = [0x4D; 32];
    let seed = [0x5A; 32];
    let blob = seal_seed_locked(&mut rng, &key, &seed);
    assert_eq!(
        crate::bare(open_seed_locked(&key, &blob)),
        Some(crate::bare(&seed))
    );
    // Wrong key, tampered ciphertext, truncated blob: all refused.
    assert!((open_seed_locked(&[0x4E; 32], &blob)).is_none());
    let mut bad = blob;
    bad[20] ^= 1;
    assert!((open_seed_locked(&key, &bad)).is_none());
    assert!((open_seed_locked(&key, &blob[..LOCK_BLOB_LEN - 1])).is_none());
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
    assert!(fs.has_counter(EF_COUNTER)); // the rest of the scan still runs
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
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );

    // Idempotent: a second pass is a no-op (tag already 0x12).
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );
}

/// Past the fuse latch a record only the pre-OTP arm opens was planted: a seed a
/// flash writer sealed under the public chip serial is neither loaded nor moved
/// onto the fused root, in any of its three pre-OTP shapes. The same records open
/// and move on an unlatched device; the tests above hold that half.
#[test]
fn past_the_latch_no_pre_otp_seed_opens_or_moves() {
    let latched = Device {
        latched: true,
        ..otp_dev()
    };
    let seed = [0x5A; 32];
    let pin_hash = [0x99u8; 16];
    type Plant = fn(&mut Fs<RamStorage>);
    let plants: [(&str, Plant); 3] = [
        ("ChaCha 0x02", |fs| {
            encrypt_keydev_f1(&dev(), fs, &[0x5A; 32]).unwrap()
        }),
        ("CBC 0x01", |fs| {
            write_legacy_cbc(&dev(), fs, EF_KEY_DEV, &[0x5A; 32])
        }),
        ("PIN-wrapped 0x03", |fs| {
            wrap_keydev_legacy(&dev(), fs, &[0x5A; 32], &[0x99; 16])
        }),
    ];
    for (shape, plant) in plants {
        let mut fs = fs();
        plant(&mut fs);
        let mut before = [0u8; 64];
        let n = fs.read(EF_KEY_DEV.get(), &mut before).unwrap();
        assert!(
            load_keydev(&latched, &mut fs).is_none(),
            "{shape}: a planted seed loaded past the latch"
        );
        assert_eq!(migrate_keydev_boot(&latched, &mut fs), Ok(false), "{shape}");
        migrate_keydev_pin(&latched, &mut fs, &pin_hash).unwrap();
        let mut after = [0u8; 64];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut after), Some(n));
        assert_eq!(
            after, before,
            "{shape}: a planted seed moved past the latch"
        );
        assert!(load_keydev(&latched, &mut fs).is_none(), "{shape}");
    }
    // The control: unlatched, the same plant opens.
    let mut fs = fs();
    encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap();
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );
}

/// The grant rides the same pass, and it has to: provisioning mints it and the burn
/// comes after the first boot, so a record left at 0x02 is one a flash dump plus the
/// public serial opens — the `pcmr` reads and getInfo's encIdentifier with it.
#[test]
fn boot_migration_reseals_the_grant_record_to_otp_kbase() {
    let mut fs = fs();
    let token = ensure_ppuat(&dev(), &mut fs, &mut SeqRng(3)).unwrap();
    let mut raw = [0u8; KEYDEV_G1_LEN];
    fs.read(EF_PAUTHTOKEN.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1, "fixture: minted before the burn");

    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    fs.read(EF_PAUTHTOKEN.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1_OTP, "the burn must move the grant too");
    assert_eq!(
        crate::bare(load_ppuat(&otp_dev(), &mut fs)),
        Some(crate::bare(&token)),
        "and the platform holding it keeps the token it was handed"
    );
    assert!(
        (load_ppuat(&dev(), &mut fs)).is_none(),
        "the chip-serial arm no longer opens the record"
    );

    // Idempotent: a second pass is a no-op (tag already 0x12).
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    assert_eq!(
        crate::bare(load_ppuat(&otp_dev(), &mut fs)),
        Some(crate::bare(&token))
    );
}

#[test]
fn the_boot_pass_re_arms_the_lap_before_it_supersedes_a_pre_otp_seed() {
    // Standing before `run_at_rest_lap` in `firmware/src/main.rs` is not the same as
    // standing before every lap. A boot whose `read_key` here faulted skipped the
    // slot and latched the marker all the same, so the boot that finally re-seals it
    // supersedes a chip-serial-rooted copy under a marker the lap gates on.
    let seed = [0x5A; 32];
    let mut raw = [0u8; KEYDEV_G1_LEN];

    // The ORDER, on the one medium that can tell the two orderings apart.
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap(); // 0x02 pre-OTP arm
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: an earlier boot latched the marker"
    );
    medium.clear_ops();
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    medium.assert_re_armed_before(EF_KEY_DEV.get(), |_| false, "migrate_keydev_boot");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "the re-seal superseded a chip-serial-sealed copy, so the lap must run again"
    );
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1_OTP);

    // The GATE. A medium refusing only `remove(EF_HARDENED)` reaches that same end
    // state with no reset in it, so the re-seal must not go ahead at all.
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    assert!(
        migrate_keydev_boot(&otp_dev(), &mut fs).is_err(),
        "a re-arm the medium refused is not a migration that may proceed"
    );
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(
        raw[0], FORMAT_G1,
        "the re-arm never landed, so the pre-OTP record must stay in force instead \
         of being superseded under a marker nothing will clear"
    );
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: the refusal really left the marker on the medium"
    );

    // The control, same medium, fault cleared: the migration DOES happen, so the
    // assertion above is about the gate and not about a pass that never fires.
    medium.refuse(None);
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
    assert_eq!(raw[0], FORMAT_G1_OTP);
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );
    assert!(!medium.live(rsk_fs::EF_HARDENED));

    // The other pre-OTP tag the same arm accepts: a legacy fixed-IV CBC record
    // (0x01) is chip-serial-rooted too, so it owes the same re-arm — and the
    // attestation slot rides the same helper as the seed.
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    write_legacy_cbc(&dev(), &mut fs, EF_ATT_KEY, &seed);
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    medium.assert_re_armed_before(
        EF_ATT_KEY.get(),
        |_| false,
        "migrate_keydev_boot's 0x01 arm",
    );
    assert_eq!(
        crate::bare(load_att_key(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );

    // And the grant slot, which the same helper carries: its pre-OTP copy is
    // chip-serial-rooted like the seed's, so it owes the re-arm on the same terms.
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let token = ensure_ppuat(&dev(), &mut fs, &mut SeqRng(5)).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
    medium.assert_re_armed_before(
        EF_PAUTHTOKEN.get(),
        |_| false,
        "migrate_keydev_boot's grant arm",
    );
    assert_eq!(
        crate::bare(load_ppuat(&otp_dev(), &mut fs)),
        Some(crate::bare(&token))
    );
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
    assert!((load_keydev(&dev(), &mut fs)).is_none());
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
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );

    // Idempotent.
    migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );
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
    assert!((load_keydev(&dev(), &mut fs)).is_none());

    migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
    let mut g = [0u8; KEYDEV_G1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut g), Some(KEYDEV_G1_LEN));
    assert_eq!(g[0], FORMAT_G1_OTP);
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), &mut fs)),
        Some(crate::bare(&seed))
    );
}

/// Recover the identifier the way a platform holding the persistent token would:
/// re-derive the AES key from the token, split `iv ‖ ct`, decrypt one block.
fn open_enc_identifier(token: &[u8; 32], blob: &[u8; ENC_GETINFO_MEMBER_LEN]) -> [u8; 16] {
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
        enc_identifier(&d, &mut f, &mut rng).is_some(),
        "provisioning mints the grant, so the member is published from the start"
    );

    // The no-token state is still reachable — a PIN change revokes the grant — and
    // it is still an absence rather than an error.
    clear_ppuat(&mut f).unwrap();
    assert!(
        enc_identifier(&d, &mut f, &mut rng).is_none(),
        "no persistent token — nothing to key it with"
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

    let id = open_enc_identifier(token.expose(), &first);
    assert_eq!(
        id,
        open_enc_identifier(token.expose(), &second),
        "the same device must decrypt to the same identifier"
    );
    assert_ne!(id, [0u8; 16], "an all-zero identifier identifies nothing");
}

/// The 0x1E twin of [`open_enc_identifier`], differing only in the HKDF label —
/// which is the whole reason the two members do not decrypt to each other.
fn open_enc_cred_store_state(token: &[u8; 32], blob: &[u8; ENC_GETINFO_MEMBER_LEN]) -> [u8; 16] {
    let mut key = [0u8; 16];
    hkdf_sha256(&ENCID_SALT, token, INFO_ENCCSS, &mut key).unwrap();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&blob[..16]);
    let mut pt = [0u8; 16];
    pt.copy_from_slice(&blob[16..]);
    aes_decrypt(&key, &iv, Mode::Cbc, &mut pt).unwrap();
    pt
}

/// The token is the whole gate, exactly as for 0x19. Unlike 0x19 the seed is NOT:
/// the tag is bookkeeping, and a soft-locked device must still be able to tell a
/// platform its credential set is unchanged.
#[test]
fn enc_cred_store_state_needs_a_token_but_not_the_seed() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(17));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    assert!(
        enc_cred_store_state(&d, &mut f, &mut rng).is_some(),
        "provisioning mints the grant, so the member is published from the start"
    );

    clear_ppuat(&mut f).unwrap();
    assert!(
        enc_cred_store_state(&d, &mut f, &mut rng).is_none(),
        "no persistent token — nothing to key it with"
    );

    ensure_ppuat(&d, &mut f, &mut rng).unwrap();
    assert!(enc_cred_store_state(&d, &mut f, &mut rng).is_some());

    f.delete_key(EF_KEY_DEV).unwrap();
    assert!(
        enc_cred_store_state(&d, &mut f, &mut rng).is_some(),
        "a soft lock hides the seed, which this member never reads"
    );
}

/// Same two-sided property 0x19 lives by: fresh bytes every call, stable plaintext
/// underneath — and the plaintext must be the tag the store actually holds, or the
/// member reports a change the credential set never had (and misses ones it did).
#[test]
fn enc_cred_store_state_is_fresh_per_call_and_carries_the_stored_tag() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(19));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let token = ensure_ppuat(&d, &mut f, &mut rng).unwrap();

    let first = enc_cred_store_state(&d, &mut f, &mut rng).unwrap();
    let second = enc_cred_store_state(&d, &mut f, &mut rng).unwrap();
    assert_ne!(first[..16], second[..16], "the IV itself must be fresh");
    assert_ne!(first, second, "a repeated blob is a fingerprint");
    assert_eq!(
        open_enc_cred_store_state(token.expose(), &first),
        open_enc_cred_store_state(token.expose(), &second),
        "an unchanged store must decrypt to an unchanged tag"
    );
    assert_ne!(
        open_enc_cred_store_state(token.expose(), &first),
        [0u8; 16],
        "a new store starts from its seed's tag, not the zero tag older devices share"
    );

    crate::credential::renew_store_state(&mut f, &mut SeqRng(21)).unwrap();
    let after = enc_cred_store_state(&d, &mut f, &mut rng).unwrap();
    assert_ne!(
        open_enc_cred_store_state(token.expose(), &after),
        open_enc_cred_store_state(token.expose(), &first),
        "a renewed tag must reach the platform"
    );
    assert_eq!(
        open_enc_cred_store_state(token.expose(), &after),
        crate::credential::cred_store_state(&mut f).unwrap(),
        "and it must be the tag the record holds, not some other value"
    );
}

/// The two members share every byte of their construction except the HKDF label, so
/// this is the one thing that keeps them apart. Decrypting one under the other's
/// label must not yield the other's plaintext — a copy-paste that reused
/// `INFO_ENCID` would otherwise pass every test above.
#[test]
fn the_two_encrypted_members_do_not_decrypt_to_each_other() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(23));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let token = ensure_ppuat(&d, &mut f, &mut rng).unwrap();

    let id_blob = enc_identifier(&d, &mut f, &mut rng).unwrap();
    let state_blob = enc_cred_store_state(&d, &mut f, &mut rng).unwrap();
    let id = open_enc_identifier(token.expose(), &id_blob);
    let state = open_enc_cred_store_state(token.expose(), &state_blob);

    assert_ne!(id, state, "the identifier is not the store tag");
    assert_ne!(
        open_enc_cred_store_state(token.expose(), &id_blob),
        id,
        "the identifier must not open under the encCredStoreState label"
    );
    assert_ne!(
        open_enc_identifier(token.expose(), &state_blob),
        state,
        "the store tag must not open under the encIdentifier label"
    );
}

/// `authenticatorReset` mints a fresh seed, and the identifier is derived from it,
/// so a reset device stops being linkable to its pre-reset self. That is the reason
/// the seed is the root rather than the silicon key, which a reset cannot touch.
#[test]
fn enc_identifier_follows_the_seed_across_a_reseed() {
    let (d, mut f, mut rng) = (dev(), fs(), SeqRng(13));
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let token = ensure_ppuat(&d, &mut f, &mut rng).unwrap();
    let before = open_enc_identifier(
        token.expose(),
        &enc_identifier(&d, &mut f, &mut rng).unwrap(),
    );

    f.delete_key(EF_KEY_DEV).unwrap();
    ensure_seed(&d, &mut f, &mut rng).unwrap();
    let after = open_enc_identifier(
        token.expose(),
        &enc_identifier(&d, &mut f, &mut rng).unwrap(),
    );

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
    let id = open_enc_identifier(
        token.expose(),
        &enc_identifier(&d, &mut f, &mut rng).unwrap(),
    );

    let seed = load_keydev(&d, &mut f).unwrap();
    assert_ne!(
        id,
        seed.expose()[..16],
        "the identifier must not expose the seed"
    );

    let mut sibling = [0u8; 16];
    hkdf_sha256(d.serial_hash, seed.expose(), INFO_SEED_ENC, &mut sibling).unwrap();
    assert_ne!(id, sibling, "labels must separate the domains");
}

/// A faulted `EF_KEY_DEV` probe must not mint a new device seed over the one on
/// flash — every credential the key holds is derived from it, so that write is
/// the most destructive one this firmware makes.
///
/// `Fs::has_key` answers the same `false` for "never provisioned" and for a probe
/// the medium could not serve, and `ensure_seed`'s first-boot guard is exactly
/// that test — `lock_engaged` included, which is why both halves are fallible now.
#[test]
fn a_faulted_probe_does_not_mint_a_second_device_seed() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    let seed = load_keydev(&d, &mut fs).expect("the device seed is provisioned");
    let stored = medium
        .value(EF_KEY_DEV.get())
        .expect("and is on the medium");
    let counter = medium
        .value(EF_COUNTER.get())
        .expect("so is the signature counter");

    // The next boot re-runs `ensure_seed`, with EF_KEY_DEV's reads faulting.
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    medium.stick(Some(EF_KEY_DEV.get()));
    assert!(
        ensure_seed(&d, &mut fs, &mut SeqRng(2)).is_err(),
        "a boot that could not read the seed record must fail, not re-provision"
    );
    assert_eq!(
        medium.value(EF_KEY_DEV.get()).as_deref(),
        Some(&stored[..]),
        "a faulted probe minted a new device seed over the live one"
    );
    assert_eq!(
        medium.value(EF_COUNTER.get()).as_deref(),
        Some(&counter[..]),
        "and rolled the signature counter back to zero"
    );
    medium.stick(None);
    assert_eq!(
        crate::bare(load_keydev(&d, &mut fs)),
        Some(crate::bare(&seed)),
        "the credentials derived from this seed must still resolve"
    );
}

/// `ensure_seed`'s other two guards, each aimed at its own record. A persistent
/// fault on `EF_KEY_DEV` is caught by the seed guard three lines above and these
/// never run — which is how both came to be held by nothing while the suite stayed
/// green. Their absent arm rolls the signature counter back to zero and overwrites
/// the large-blob array, at boot, with no host command involved.
#[test]
fn a_faulted_probe_does_not_reinitialise_the_counter_or_the_large_blob() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    // Move both off the values a first boot writes, so a re-initialisation shows.
    fs.put_counter(EF_COUNTER, &[9, 8, 7, 6]).unwrap();
    fs.put(EF_LARGEBLOB, &[0xAB; 8]).unwrap();

    for (fid, what) in [
        (EF_COUNTER.get(), "the signature counter"),
        (EF_LARGEBLOB, "the large-blob array"),
    ] {
        let before = medium.value(fid).expect("on the medium");
        medium.stick(Some(fid));
        let r = ensure_seed(&d, &mut fs, &mut SeqRng(2));
        medium.stick(None);
        assert_eq!(
            medium.value(fid).as_deref(),
            Some(&before[..]),
            "a faulted probe re-initialised {what}"
        );
        assert!(
            r.is_err(),
            "a boot that could not read {what} must fail, not re-initialise it"
        );
    }
}

/// Every boot ends `ensure_seed` in `ensure_ppuat`, whose read took "could not read"
/// for "never minted": one faulted read minted a token over the live one, revoking
/// every platform's `pcmr` grant and changing getInfo's encIdentifier under them.
#[test]
fn a_faulted_grant_read_does_not_rotate_the_persistent_token() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    let token = load_ppuat(&d, &mut fs).expect("provisioning mints the grant");
    let stored = medium
        .value(EF_PAUTHTOKEN.get())
        .expect("and it is on the medium");

    // The next boot, with ONE read of the grant record failing and then recovering.
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    medium.stick_once(EF_PAUTHTOKEN.get());
    let r = ensure_seed(&d, &mut fs, &mut SeqRng(2));
    assert_eq!(
        medium.value(EF_PAUTHTOKEN.get()).as_deref(),
        Some(&stored[..]),
        "a faulted read minted a new persistent token over the live one"
    );
    assert!(
        r.is_err(),
        "a boot that could not read the grant must say so, not re-mint it"
    );
    assert_eq!(
        crate::bare(load_ppuat(&d, &mut fs)),
        Some(crate::bare(&token)),
        "every platform holding the grant must still hold it"
    );
}

/// The OTP root is read per operation and a failed read looks unprovisioned, so an
/// OTP-arm record can refuse to open for one operation. Minting there rotated a live
/// grant and sealed the replacement under the serial-only arm the fuses retire.
#[test]
fn a_grant_that_will_not_open_is_not_reminted() {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let token = ensure_ppuat(&otp_dev(), &mut fs, &mut SeqRng(1)).unwrap();
    let mut before = [0u8; 64];
    let n = fs.read_key(EF_PAUTHTOKEN, &mut before).unwrap();

    assert!(
        ensure_ppuat(&dev(), &mut fs, &mut SeqRng(2)).is_err(),
        "a grant this operation's key cannot open must not be replaced"
    );
    let mut after = [0u8; 64];
    assert_eq!(fs.read_key(EF_PAUTHTOKEN, &mut after), Some(n));
    assert_eq!(after[..n], before[..n], "the sealed record was rewritten");
    assert_eq!(
        crate::bare(ensure_ppuat(&otp_dev(), &mut fs, &mut SeqRng(3)).unwrap()),
        crate::bare(&token),
        "the next operation that can open it hands out the same grant"
    );
}

/// The global signature counter is FIDO's clone-detection signal, and a collapsing
/// `Fs::read` of it answers the same 0 for "never written" and "I could not look".
/// `bump_sign_counter` then persists 1 over whatever was there, and U2F
/// AUTHENTICATE signs that fabricated 0 — one faulted probe erases the monotonic
/// evidence an RP uses to notice a cloned key.
#[test]
fn a_faulted_counter_probe_does_not_roll_the_global_counter_back() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    // Off the value a first boot writes, so a roll-back shows.
    fs.put_counter(EF_COUNTER, &77u32.to_le_bytes()).unwrap();
    let before = medium.value(EF_COUNTER.get()).expect("on the medium");

    medium.stick(Some(EF_COUNTER.get()));
    let bumped = bump_sign_counter(&mut fs);
    medium.stick(None);
    assert_eq!(
        medium.value(EF_COUNTER.get()).as_deref(),
        Some(&before[..]),
        "a faulted probe rolled the global signature counter back"
    );
    assert!(
        bumped.is_err(),
        "and reported a counter it never read as the one to sign"
    );
}

/// `set_cred_sign_counter` reads the packed file to preserve the other slots, so
/// that read IS the merge. Defaulting it to 0 makes a fault look like an absent
/// file, and the write that follows is a ZERO-filled buffer truncated to the target
/// slot: every other credential's counter zeroed or dropped by one flash fault.
#[test]
fn a_faulted_cred_counter_probe_does_not_zero_the_other_slots() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    for (slot, v) in [(0u16, 11u32), (1, 22), (2, 33)] {
        set_cred_sign_counter(&mut fs, slot, v).unwrap();
    }
    let before = medium.value(EF_CRED_CTR.get()).expect("on the medium");
    assert_eq!(before.len(), 12, "three packed slots");

    medium.stick(Some(EF_CRED_CTR.get()));
    let wrote = set_cred_sign_counter(&mut fs, 1, 23);
    medium.stick(None);
    let after = medium
        .value(EF_CRED_CTR.get())
        .expect("still on the medium");
    assert_eq!(
        after.len(),
        before.len(),
        "a faulted probe truncated the packed counter file"
    );
    assert_eq!(
        cred_sign_counter(&mut fs, 0),
        Ok(Some(11)),
        "and zeroed a lower slot's counter"
    );
    assert_eq!(
        cred_sign_counter(&mut fs, 2),
        Ok(Some(33)),
        "and dropped a higher slot's counter"
    );
    assert!(
        wrote.is_err(),
        "a write that could not read the file it merges into must fail"
    );
}

/// The slot has FOUR states and only three answers may share one. A faulted read
/// must not read as *unmaterialized*: the caller seeds that from the global
/// counter, so the collapse hands a live credential a signCount off a different
/// sequence. Absent, short and a zero-filled gap stay together — they are the
/// legacy slot the seeding rule was written for.
#[test]
fn a_faulted_cred_counter_probe_is_not_an_unmaterialized_slot() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    fs.put_counter(EF_COUNTER, &60u32.to_le_bytes()).unwrap();

    // Absent: no packed file at all.
    assert_eq!(cred_sign_counter(&mut fs, 0), Ok(None));
    assert_eq!(report_sign_counter(&mut fs, 0).unwrap(), 60);

    // Short: writing slot 0 leaves the file 4 bytes, so slot 1 is past its end.
    set_cred_sign_counter(&mut fs, 0, 44).unwrap();
    assert_eq!(cred_sign_counter(&mut fs, 1), Ok(None));
    assert_eq!(report_sign_counter(&mut fs, 1).unwrap(), 60);

    // Live-zero gap: writing slot 2 zero-extends the file across slot 1, which is
    // a real 0 on the medium and still unmaterialized.
    set_cred_sign_counter(&mut fs, 2, 55).unwrap();
    assert_eq!(medium.value(EF_CRED_CTR.get()).map(|v| v.len()), Some(12));
    assert_eq!(cred_sign_counter(&mut fs, 1), Ok(None));
    assert_eq!(report_sign_counter(&mut fs, 1).unwrap(), 60);
    // Live: its own value, never the global.
    assert_eq!(cred_sign_counter(&mut fs, 0), Ok(Some(44)));
    assert_eq!(report_sign_counter(&mut fs, 0).unwrap(), 44);

    // Faulted: the fourth state, and the only one that is not an answer.
    medium.stick(Some(EF_CRED_CTR.get()));
    let read = cred_sign_counter(&mut fs, 0);
    let reported = report_sign_counter(&mut fs, 0);
    medium.stick(None);
    assert!(
        read.is_err(),
        "a counter the medium could not serve read as an unmaterialized slot"
    );
    assert!(
        reported.is_err(),
        "and was reported as the global counter, off another sequence"
    );
}

/// The platform-facing half of the same probe. `encCredStoreState` is the only place
/// the tag is published, and the collapsed answer is the ZERO tag — which is not a
/// neutral value here but the one a device an older build provisioned serves, so a
/// platform that cached it is told its cache is still good while the store has
/// gained credentials since.
///
/// Omitted instead: the member is optional, and an ABSENT one equals no tag the
/// platform holds, so it re-enumerates. That is the direction this record can afford
/// — over-reporting a change costs one walk, under-reporting costs correctness.
#[test]
fn a_faulted_cred_state_probe_does_not_publish_the_zero_tag() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(29)).unwrap();
    let token = ensure_ppuat(&d, &mut fs, &mut SeqRng(31)).unwrap();
    // An older build provisioned without a tag, and absent reads as zero.
    fs.delete(crate::consts::EF_CRED_STATE).unwrap();
    let fresh = enc_cred_store_state(&d, &mut fs, &mut SeqRng(33)).unwrap();
    assert_eq!(
        open_enc_cred_store_state(token.expose(), &fresh),
        [0u8; 16],
        "control: a store an older build provisioned, untouched since, publishes zero"
    );

    crate::credential::renew_store_state(&mut fs, &mut SeqRng(21)).unwrap();
    medium.stick_once(crate::consts::EF_CRED_STATE);
    let faulted = enc_cred_store_state(&d, &mut fs, &mut SeqRng(35));
    medium.stick(None);
    assert!(
        faulted.is_none_or(|b| open_enc_cred_store_state(token.expose(), &b) != [0u8; 16]),
        "a faulted probe published the zero tag — the platform that cached it \
         is told the credential set is unchanged"
    );
    assert!(
        faulted.is_none(),
        "an unreadable tag has no honest value; the optional member is omitted"
    );
}

/// The collapse `rebuild_att_cert` keeps, and the arm that refutes fixing it.
///
/// A faulted freshness probe rewrites `EF_EE_DEV` with a fresh serial. That is the
/// whole cost: everything but the serial and the signature is a fixed template, so
/// the attesting key, the AAGUID and the subject come out byte-identical and the
/// device's attestation identity is unchanged — a repeated repair, which is where
/// `Fs::try_read`'s own policy leaves a collapsing probe.
#[test]
fn a_faulted_cert_probe_reissues_the_leaf_and_keeps_the_identity() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    ensure_seed(&d, &mut fs, &mut SeqRng(1)).unwrap();
    let before = medium
        .value(EF_EE_DEV)
        .expect("the attestation cert is on the medium");

    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    medium.stick(Some(EF_EE_DEV));
    let r = ensure_seed(&d, &mut fs, &mut SeqRng(2));
    medium.stick(None);
    let after = medium.value(EF_EE_DEV).expect("still on the medium");
    use crate::cert::{SERIAL_OFF, TBS_LEN};
    assert!(
        r.is_ok(),
        "a freshness probe that failed must not fail the boot"
    );
    assert_ne!(
        &after[SERIAL_OFF..SERIAL_OFF + 16],
        &before[SERIAL_OFF..SERIAL_OFF + 16],
        "control: the collapse is what reissues the leaf — without it this test \
         proves nothing about the identity below"
    );
    let seed = load_keydev(&d, &mut fs).expect("the seed it certifies");
    let key = P256Key::from_scalar(seed.expose()).unwrap();
    assert!(
        cert_matches_template(&after, &key),
        "the reissued leaf must still certify this device's own attestation key"
    );
    // The TBS is fixed-length and the serial is the only field in it that moves,
    // so this is the identity claim in bytes. NOT the first four: the outer
    // SEQUENCE length follows the ECDSA signature, which is 70 or 71 bytes.
    assert_eq!(after[4..SERIAL_OFF], before[4..SERIAL_OFF]);
    assert_eq!(
        after[SERIAL_OFF + 16..4 + TBS_LEN],
        before[SERIAL_OFF + 16..4 + TBS_LEN],
        "the reissue moved a field of the TBS other than the serial"
    );
}

/// Why skipping the rewrite on a failed probe is NOT the fail-closed direction.
///
/// The premise it would rest on — "a genuinely absent record is answered from the
/// scan cache, so the fault never reaches the medium" — is false under a TRUNCATED
/// walk: `Fs::scan` fills `decided` only when the walk completed, so an un-yielded
/// FID stays undecided and the probe goes to the medium. On a first boot that is a
/// device left with no attestation certificate at all.
#[test]
fn a_truncated_scan_still_issues_the_attestation_certificate() {
    let d = dev();
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    medium.truncate_walk(true);
    fs.scan(); // the walk that never decides EF_EE_DEV absent
    medium.truncate_walk(false);
    medium.stick(Some(EF_EE_DEV));
    let r = ensure_seed(&d, &mut fs, &mut SeqRng(3));
    medium.stick(None);
    assert!(r.is_ok(), "a first boot must provision");
    let cert = medium.value(EF_EE_DEV).expect(
        "a first boot issues the attestation certificate even when the \
                 freshness probe could not be answered",
    );
    let seed = load_keydev(&d, &mut fs).expect("and the seed it certifies");
    assert!(
        cert_matches_template(&cert, &P256Key::from_scalar(seed.expose()).unwrap()),
        "and it certifies that seed's public key"
    );
}

/// What the boot pass reports keeps the page-58 lock waiting (audit run-27 #8): a
/// pre-OTP seed it moved is not left, a PIN-wrapped one it cannot touch is, until
/// the first PIN verify moves it, and one whose re-seal the medium refused is the
/// error. Without the fused key nothing is judged left.
#[test]
fn the_boot_pass_reports_what_it_left_under_the_chip_serial_arm() {
    let seed = [0x5A; 32];
    let pin_hash = [0x99u8; 16];

    let mut store = fs();
    encrypt_keydev_f1(&dev(), &mut store, &seed).unwrap();
    assert_eq!(
        migrate_keydev_boot(&otp_dev(), &mut store),
        Ok(false),
        "moved"
    );
    assert_eq!(
        migrate_keydev_boot(&otp_dev(), &mut store),
        Ok(false),
        "already current"
    );

    let mut store = fs();
    wrap_keydev_legacy(&dev(), &mut store, &seed, &pin_hash);
    assert_eq!(
        migrate_keydev_boot(&otp_dev(), &mut store),
        Ok(true),
        "PIN-wrapped"
    );
    assert_eq!(
        migrate_keydev_boot(&dev(), &mut store),
        Ok(false),
        "no fused key"
    );
    migrate_keydev_pin(&otp_dev(), &mut store, &pin_hash).unwrap();
    assert_eq!(
        migrate_keydev_boot(&otp_dev(), &mut store),
        Ok(false),
        "after the PIN"
    );

    let (cut, medium) = rsk_fs::storage::faults::Cut::new();
    let mut store = Fs::new(cut);
    store.scan();
    encrypt_keydev_f1(&dev(), &mut store, &seed).unwrap();
    medium.arm(0);
    assert!(
        migrate_keydev_boot(&otp_dev(), &mut store).is_err(),
        "refused re-seal"
    );
}

/// A read of a slot the flash failed is not a slot with nothing left in it (review
/// of the page-58 verdict). Whichever read the fault lands on, or every read, the
/// pass either moved the pre-OTP record or keeps the lock waiting.
#[test]
fn a_faulted_read_of_a_pre_otp_slot_is_never_reported_clear() {
    for fault in [None, Some(0), Some(1), Some(2)] {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut store = Fs::new(backend);
        store.scan();
        encrypt_keydev_f1(&dev(), &mut store, &[0x5A; 32]).unwrap();
        let before = medium.value(EF_KEY_DEV.get());
        match fault {
            None => medium.stick(Some(EF_KEY_DEV.get())),
            Some(skip) => medium.stick_after(EF_KEY_DEV.get(), skip),
        }
        let verdict = migrate_keydev_boot(&otp_dev(), &mut store);
        medium.stick(None);
        assert!(
            verdict != Ok(false) || medium.value(EF_KEY_DEV.get()) != before,
            "fault {fault:?}: reported clear over the pre-OTP seed it never moved"
        );
    }
}

/// CTAP 2.3 §6.6 gives a new store a new state. The tag is written ahead of the seed,
/// so provisioning cut anywhere — and the boot that retries it, cut again — never
/// leaves a live seed over no tag, which would read as the zero every older store has.
#[test]
fn a_torn_provisioning_never_leaves_a_seed_without_its_store_state() {
    use rsk_fs::cut::{Snap, sweep_recovery};
    sweep_recovery(
        |_fs| (),
        |fs, _| {
            let _ = ensure_seed(&dev(), fs, &mut SeqRng(41));
        },
        |fs| {
            let _ = ensure_seed(&dev(), fs, &mut SeqRng(43));
        },
        |fs: &mut Fs<Snap>, first, second| {
            assert!(
                load_keydev(&dev(), fs).is_some(),
                "cuts {first}/{second}: the boot after a cut provisions a seed"
            );
            assert!(
                fs.has_data(crate::consts::EF_CRED_STATE),
                "cuts {first}/{second}: a live seed over no store state"
            );
        },
    );
}

/// An upgrade mints no tag: a seed already there is an existing store, so a platform
/// holding an older build's zero tag keeps a valid cache until the store changes.
#[test]
fn an_existing_seed_keeps_its_store_state() {
    let (d, mut f) = (dev(), fs());
    ensure_seed(&d, &mut f, &mut SeqRng(45)).unwrap();
    f.delete(crate::consts::EF_CRED_STATE).unwrap();
    ensure_seed(&d, &mut f, &mut SeqRng(47)).unwrap();
    assert!(
        !f.has_data(crate::consts::EF_CRED_STATE),
        "a boot over an existing seed must not mint a store state"
    );
}
