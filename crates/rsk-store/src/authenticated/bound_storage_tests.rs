// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Admitted flash fixtures precede byte-exact migration and fault assertions."
)]

use super::*;
use crate::authenticated::{KeySource, Layout, RootArm, RootRead};
use crate::tests::{Effect, FaultFlash, Io, Rule};
use rsk_fs::Storage;
use rsk_fs::counter::{DEVICE_PIN, FIDO_PIN, OATH_PIN, OPENPGP_RETRIES, PIV_RETRIES};
use sequential_storage::cache::{Cache, Uncached};

#[path = "public_pin_tests.rs"]
mod public_pin_tests;

type Store = Authenticated<FaultFlash, Cache<Uncached, Uncached, Uncached, u16>>;
const MAIN_END: u32 = 32768;
const END: u32 = MAIN_END + super::super::storage::AUTHORITY_BYTES;

fn source() -> KeySource {
    KeySource::new([0x43; 32], |_| RootRead::Blank, false)
}

fn store(flash: &FaultFlash) -> Store {
    Authenticated::new(
        flash.clone(),
        0..MAIN_END,
        MAIN_END..END,
        Cache::new_uncached(),
        source(),
        [0x4B; 16],
        RootArm::PreOtp,
    )
    .unwrap()
}

fn seeded(fid: u16, value: &[u8]) -> (FaultFlash, Store) {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut store = store(&flash);
    store.initialize_blank().unwrap();
    let key = source().key(RootArm::PreOtp).unwrap();
    store.main.write(key.expose(), fid, Some(value)).unwrap();
    (flash, store)
}

#[test]
fn pin_migration_leaves_main_bytes_and_all_non_retry_bytes_unchanged() {
    for (fid, initial, at) in [
        (PIV_RETRIES, vec![3; 4], 1),
        (OPENPGP_RETRIES, vec![3; 7], 4),
        (FIDO_PIN, vec![8; 35], 0),
        (FIDO_PIN, vec![8; 36], 0),
        (DEVICE_PIN, vec![8; 35], 0),
        (OATH_PIN, vec![3; 34], 0),
    ] {
        let (flash, mut mounted) = seeded(fid, &initial);
        let before = flash.image();
        let mut spent = initial.clone();
        spent[at] -= 1;
        flash.arm(&[]);
        mounted.write(fid, &spent).unwrap();
        let layout = Layout::new(MAIN_END..END).unwrap();
        let after = flash.image();
        let counter_start = usize::try_from(layout.counter[0].start).unwrap();
        assert_eq!(&before[..counter_start], &after[..counter_start]);
        assert!(flash.events().iter().any(|e| e.0 == Io::Program));
        assert!(
            flash
                .events()
                .iter()
                .filter(|e| e.0 != Io::Read)
                .all(|e| e.1 >= layout.counter[0].start)
        );
        let mut reopened = store(&flash);
        let mut value = [0; VALUE_BYTES];
        assert_eq!(reopened.read(fid, &mut value), Some(spent.len()));
        assert_eq!(&value[..spent.len()], spent);
        reopened.write(fid, &initial).unwrap();
        assert_eq!(reopened.read(fid, &mut value), Some(initial.len()));
        assert_eq!(&value[..initial.len()], initial);
    }
}

#[test]
fn unsupported_pin_width_stays_in_main_without_truncating_the_value() {
    let (flash, mut mounted) = seeded(FIDO_PIN, &[8; 37]);
    let before = flash.image();
    let mut changed = [8; 37];
    changed[0] = 7;
    mounted.write(FIDO_PIN, &changed).unwrap();
    let after = flash.image();
    let start = usize::try_from(Layout::new(MAIN_END..END).unwrap().counter[0].start).unwrap();
    assert_eq!(&before[start..], &after[start..]);
    let mut out = [0; 37];
    assert_eq!(store(&flash).read(FIDO_PIN, &mut out), Some(37));
    assert_eq!(out, changed);
}

#[test]
fn replacement_and_delete_recreate_cannot_inherit_old_counter_state() {
    let (flash, mut mounted) = seeded(FIDO_PIN, &[8; 35]);
    let mut spent = [8; 35];
    spent[0] = 1;
    mounted.write(FIDO_PIN, &spent).unwrap();
    let mut new = [9; 35];
    new[0] = 8;
    mounted.write(FIDO_PIN, &new).unwrap();
    let mut out = [0; 35];
    assert_eq!(mounted.read(FIDO_PIN, &mut out), Some(35));
    assert_eq!(out, new);
    mounted.remove(FIDO_PIN).unwrap();
    mounted.write(FIDO_PIN, &[8; 35]).unwrap();
    assert_eq!(store(&flash).read(FIDO_PIN, &mut out), Some(35));
    assert_eq!(out, [8; 35]);

    mounted.write(0xBA00, b"sealed owner").unwrap();
    mounted.write_bound_counter(0xBA00, &[0x42; 36]).unwrap();
    mounted.remove(0xBA00).unwrap();
    mounted.write(0xBA00, b"sealed owner").unwrap();
    assert_eq!(store(&flash).read_bound_counter(0xBA00, &mut []), Ok(None));
}

#[test]
fn counter_buckets_are_hidden_and_direct_mutations_are_blocked() {
    let (_, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    mounted.write(PIV_RETRIES, &[3, 2, 3, 3]).unwrap();
    let bucket = public_pin(PIV_RETRIES).unwrap();
    assert_eq!(mounted.read(bucket, &mut []), None);
    assert!(!mounted.last_error());
    assert_eq!(mounted.write(bucket, b"forged"), Err(Error::Blocked));
    assert_eq!(mounted.remove(bucket), Err(Error::Blocked));
    let mut fids = Vec::new();
    assert!(mounted.for_each_key(&mut |fid| fids.push(fid)));
    assert_eq!(fids, vec![PIV_RETRIES]);
}

#[test]
fn private_counter_namespace_keeps_adjacent_main_files_available() {
    let (_, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    let first = super::super::bound_counter::FIRST_BUCKET;
    let last = public_pin(OPENPGP_RETRIES).unwrap();
    for fid in first..=last {
        assert_eq!(mounted.write(fid, b"forged"), Err(Error::Blocked));
        assert_eq!(mounted.remove(fid), Err(Error::Blocked));
    }
    for fid in [first - 1, last + 1] {
        mounted.write(fid, b"main file").unwrap();
        let mut out = [0; 9];
        assert_eq!(mounted.read(fid, &mut out), Some(out.len()));
        assert_eq!(&out, b"main file");
        mounted.remove(fid).unwrap();
        assert_eq!(mounted.read(fid, &mut out), None);
        assert!(!mounted.last_error());
    }
}

#[test]
fn public_pin_records_read_only_the_counter_partition_after_migration() {
    for (fid, before, after) in [
        (PIV_RETRIES, vec![3; 4], vec![5, 4, 5, 4]),
        (OPENPGP_RETRIES, vec![3; 7], vec![1, 127, 127, 127, 2, 2, 2]),
    ] {
        let (flash, mut mounted) = seeded(fid, &before);
        mounted.write(fid, &after).unwrap();
        flash.arm(&[]);
        let mut out = [0; 8];
        assert_eq!(mounted.read(fid, &mut out), Some(after.len()));
        assert_eq!(&out[..after.len()], after);
        let start = Layout::new(MAIN_END..END).unwrap().counter[0].start;
        assert!(
            flash
                .events()
                .iter()
                .all(|event| event.0 == Io::Read && event.1 >= start)
        );
        mounted.remove(fid).unwrap();
        let mut reopened = store(&flash);
        assert_eq!(reopened.read(fid, &mut out), None);
        let mut listed = Vec::new();
        assert!(reopened.for_each_key(&mut |fid| listed.push(fid)));
        assert!(!listed.contains(&fid));
        reopened.write(fid, &before).unwrap();
        assert_eq!(reopened.read(fid, &mut out), Some(before.len()));
        assert_eq!(&out[..before.len()], before);
        listed.clear();
        assert!(reopened.for_each_key(&mut |fid| listed.push(fid)));
        assert_eq!(listed.iter().filter(|&&item| item == fid).count(), 1);
    }
}

#[test]
fn pin_presence_is_main_authority_but_retry_bytes_require_the_counter_authority() {
    let (flash, mut mounted) = seeded(FIDO_PIN, &[8; 35]);
    let mut charged = [8; 35];
    charged[0] = 7;
    mounted.write(FIDO_PIN, &charged).unwrap();
    flash.arm(&[]);
    assert_eq!(mounted.read(FIDO_PIN, &mut []), Some(35));
    let layout = Layout::new(MAIN_END..END).unwrap();
    assert!(
        flash
            .events()
            .iter()
            .all(|event| event.0 == Io::Read && event.1 < layout.counter[0].start)
    );
    let mut image = flash.image();
    for range in layout.counter {
        image[usize::try_from(range.start).unwrap() + super::super::CHECKPOINT_BYTES] ^= 1;
    }
    flash.replace_image_before_read(0, image);
    let mut out = [0xA5; 35];
    assert_eq!(mounted.read(FIDO_PIN, &mut out), None);
    assert!(mounted.last_error());
    assert_eq!(out, [0xA5; 35]);
}

#[test]
fn root_rekey_preserves_pin_and_hotp_owner_generations() {
    let (_, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    mounted.write(PIV_RETRIES, &[3, 1, 3, 2]).unwrap();
    mounted.write(0xBA00, b"sealed owner").unwrap();
    mounted.write_bound_counter(0xBA00, &[0x42; 36]).unwrap();
    let old = source().key(RootArm::PreOtp).unwrap();
    let new_source = KeySource::new(
        [0x43; 32],
        |out| {
            out.fill(0x56);
            RootRead::Fused
        },
        false,
    );
    let new = new_source.key(RootArm::Otp).unwrap();
    mounted
        .main
        .rekey(old.expose(), new.expose(), RootArm::Otp)
        .unwrap();
    mounted
        .counters
        .rekey(old.expose(), new.expose(), RootArm::Otp)
        .unwrap();
    mounted.source = new_source;
    mounted.main_arm = RootArm::Otp;
    mounted.counter_arm = RootArm::Otp;
    let mut pin = [0; 4];
    assert_eq!(mounted.read(PIV_RETRIES, &mut pin), Some(4));
    assert_eq!(pin, [3, 1, 3, 2]);
    let mut hotp = [0; 36];
    assert_eq!(mounted.read_bound_counter(0xBA00, &mut hotp), Ok(Some(36)));
    assert_eq!(hotp, [0x42; 36]);
}

#[test]
fn interrupted_first_and_later_pin_publications_never_roll_back_acknowledged_retries() {
    for existing in [false, true] {
        let (seed, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
        if existing {
            mounted.write(PIV_RETRIES, &[3, 2, 3, 3]).unwrap();
        }
        let before = seed.image();
        seed.arm(&[]);
        mounted.write(PIV_RETRIES, &[3, 1, 3, 3]).unwrap();
        let program_bytes: usize = seed
            .events()
            .iter()
            .filter(|e| e.0 == Io::Program)
            .map(|e| e.2)
            .sum();
        for cut in 0..=program_bytes {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            flash.replace_image_before_read(0, before.clone());
            let mut mounted = store(&flash);
            assert_eq!(mounted.read(PIV_RETRIES, &mut []), Some(4));
            flash.arm(&[Rule {
                io: Io::Program,
                skip: 0,
                effect: Effect::Shutoff(cut),
                latched: true,
            }]);
            let acknowledged = mounted.write(PIV_RETRIES, &[3, 1, 3, 3]).is_ok();
            assert!(flash.hits()[0] > 0);
            flash.clear();
            let mut reopened = store(&flash);
            let mut pin = [0; 4];
            assert_eq!(reopened.read(PIV_RETRIES, &mut pin), Some(4), "cut={cut}");
            assert!(
                pin[1] == 1 || !acknowledged && pin[1] == if existing { 2 } else { 3 },
                "cut={cut}, {pin:?}"
            );
            assert_eq!([pin[0], pin[2], pin[3]], [3; 3]);
        }
    }
}

#[test]
fn tampered_or_unreadable_counter_authority_never_falls_back_to_main_retries() {
    for offset in [0, 128, 160, 20479] {
        let (flash, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
        mounted.write(PIV_RETRIES, &[3, 1, 3, 3]).unwrap();
        let layout = Layout::new(MAIN_END..END).unwrap();
        let mut image = flash.image();
        for range in layout.counter {
            image[usize::try_from(range.start + offset).unwrap()] ^= 1;
        }
        flash.replace_image_before_read(0, image);
        if offset == 0 || offset == 20479 {
            // Unrelated bytes are checked at mutation, as in the main payload backend.
            assert_eq!(
                mounted.write(PIV_RETRIES, &[3, 0, 3, 3]),
                Err(Error::MemoryFatal)
            );
        }
        let mut out = [0xA5; 4];
        assert_eq!(mounted.read(PIV_RETRIES, &mut out), None);
        assert!(mounted.last_error());
        assert_eq!(out, [0xA5; 4]);
    }
}

#[test]
fn all_hotp_slots_fit_beside_full_fido_counters_and_survive_counter_rollovers() {
    let (_, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    mounted.write(PIV_RETRIES, &[3, 2, 3, 3]).unwrap();
    mounted
        .write(OPENPGP_RETRIES, &[1, 127, 127, 127, 2, 1, 3])
        .unwrap();
    mounted
        .write(rsk_fs::counter::EF_CRED_CTR.get(), &[0xA5; 256 * 4])
        .unwrap();
    mounted
        .write(rsk_fs::counter::EF_COUNTER.get(), &[3; 4])
        .unwrap();
    mounted
        .write(rsk_fs::counter::EF_SIG_COUNT.get(), &[3; 3])
        .unwrap();
    mounted
        .write(rsk_fs::counter::COUNTER_FID.get(), &[3; 4])
        .unwrap();
    for fid in 0xBA00u16..=0xBAFE {
        mounted.write(fid, &fid.to_le_bytes()).unwrap();
        mounted
            .write_bound_counter(fid, &[fid.to_le_bytes()[0]; 36])
            .unwrap();
    }
    for _ in 0..3 {
        for fid in 0xBA00u16..=0xBAFE {
            let value = [fid.to_le_bytes()[0]; 36];
            let mut out = [0; 36];
            assert_eq!(mounted.read_bound_counter(fid, &mut out), Ok(Some(36)));
            assert_eq!(out, value);
            mounted.write_bound_counter(fid, &value).unwrap();
        }
    }
    let mut fido = [0; 1024];
    assert_eq!(
        mounted.read(rsk_fs::counter::EF_CRED_CTR.get(), &mut fido),
        Some(1024)
    );
    assert_eq!(fido, [0xA5; 1024]);
    let mut retries = [0; 4];
    assert_eq!(mounted.read(PIV_RETRIES, &mut retries), Some(4));
    assert_eq!(retries, [3, 2, 3, 3]);
    let mut pgp = [0; 7];
    assert_eq!(mounted.read(OPENPGP_RETRIES, &mut pgp), Some(7));
    assert_eq!(pgp, [1, 127, 127, 127, 2, 1, 3]);
}

#[test]
fn every_byte_cut_of_hotp_migration_preserves_the_last_acknowledged_counter() {
    for existing in [false, true] {
        let (seed, mut mounted) = seeded(0xBA00, b"sealed owner");
        if existing {
            mounted.write_bound_counter(0xBA00, &[1; 36]).unwrap();
        }
        let before = seed.image();
        seed.arm(&[]);
        mounted.write_bound_counter(0xBA00, &[2; 36]).unwrap();
        let program_bytes: usize = seed
            .events()
            .iter()
            .filter(|e| e.0 == Io::Program)
            .map(|e| e.2)
            .sum();
        for cut in 0..=program_bytes {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            flash.replace_image_before_read(0, before.clone());
            let mut mounted = store(&flash);
            assert_eq!(mounted.read(0xBA00, &mut []), Some(12));
            flash.arm(&[Rule {
                io: Io::Program,
                skip: 0,
                effect: Effect::Shutoff(cut),
                latched: true,
            }]);
            let acknowledged = mounted.write_bound_counter(0xBA00, &[2; 36]) == Ok(true);
            assert!(flash.hits()[0] > 0);
            flash.clear();
            let mut reopened = store(&flash);
            let mut value = [0; 36];
            let n = reopened.read_bound_counter(0xBA00, &mut value).unwrap();
            if n == Some(36) && value == [2; 36] {
                continue;
            }
            assert!(!acknowledged, "acknowledged value lost at cut={cut}");
            if existing {
                assert_eq!(n, Some(36));
                assert_eq!(value, [1; 36]);
            } else {
                assert_eq!(n, None);
            }
        }
    }
}

#[test]
fn replaying_both_counter_banks_during_a_live_mount_cannot_restore_pin_retries() {
    let (flash, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    mounted.write(PIV_RETRIES, &[3, 2, 3, 3]).unwrap();
    let old = flash.image();
    mounted.write(PIV_RETRIES, &[3, 1, 3, 3]).unwrap();
    flash.replace_image_before_read(0, old);
    let mut out = [0xA5; 4];
    assert_eq!(mounted.read(PIV_RETRIES, &mut out), None);
    assert!(mounted.last_error());
    assert_eq!(out, [0xA5; 4]);
}
