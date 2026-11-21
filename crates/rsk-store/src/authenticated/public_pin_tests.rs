// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn public_pin_records_preserve_the_full_supported_value_and_reject_overflow() {
    for fid in [PIV_RETRIES, OPENPGP_RETRIES] {
        let (flash, mut mounted) = seeded(fid, &[3; 4]);
        let value = [0x42; 36];
        mounted.write(fid, &value).unwrap();
        assert_eq!(mounted.write(fid, &[0x43; 37]), Err(Error::MemoryFatal));
        let mut reopened = store(&flash);
        let mut short = [0; 1];
        assert_eq!(reopened.read(fid, &mut short), Some(36));
        assert_eq!(short, [0x42]);
        let mut full = [0; 36];
        assert_eq!(reopened.read(fid, &mut full), Some(36));
        assert_eq!(full, value);
    }
}

#[test]
fn earlier_bound_retry_records_migrate_without_restoring_legacy_attempts() {
    for (fid, before, charged) in [
        (PIV_RETRIES, vec![3; 4], vec![3, 1, 3, 2]),
        (OPENPGP_RETRIES, vec![3; 7], vec![3, 3, 3, 3, 1, 2, 1]),
    ] {
        let (flash, mut mounted) = seeded(fid, &before);
        assert!(mounted.write_pin(fid, &charged).unwrap());
        let mut mounted = store(&flash);
        let mut out = [0; 8];
        assert_eq!(mounted.read(fid, &mut out), Some(charged.len()));
        assert_eq!(&out[..charged.len()], charged);
        let mut listed = Vec::new();
        assert!(mounted.for_each_key(&mut |found| listed.push(found)));
        assert_eq!(listed, vec![fid]);
        mounted.write(fid, &charged).unwrap();
        let mut mounted = store(&flash);
        assert_eq!(mounted.read(fid, &mut out), Some(charged.len()));
        assert_eq!(&out[..charged.len()], charged);
    }
}

#[test]
fn public_pin_tombstone_blocks_legacy_fallback_and_differs_from_an_empty_value() {
    let (flash, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    mounted.write_public_pin(PIV_RETRIES, None).unwrap();
    let mut reopened = store(&flash);
    assert_eq!(reopened.read(PIV_RETRIES, &mut []), None);
    assert!(!reopened.last_error());
    let mut listed = Vec::new();
    assert!(reopened.for_each_key(&mut |fid| listed.push(fid)));
    assert!(!listed.contains(&PIV_RETRIES));
    reopened.write(PIV_RETRIES, &[]).unwrap();
    assert_eq!(reopened.read(PIV_RETRIES, &mut []), Some(0));
    let key = source().key(RootArm::PreOtp).unwrap();
    for malformed in [&[][..], &[0, 1], &[2]] {
        reopened
            .counters
            .write(
                key.expose(),
                public_pin(PIV_RETRIES).unwrap(),
                Some(malformed),
            )
            .unwrap();
        let mut out = [0xA5; 4];
        assert_eq!(reopened.read(PIV_RETRIES, &mut out), None);
        assert!(reopened.last_error());
        assert_eq!(out, [0xA5; 4]);
    }
}

#[test]
fn interrupted_public_pin_removal_never_restores_the_old_main_retry_count() {
    let (seed, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
    mounted.write(PIV_RETRIES, &[3, 1, 3, 2]).unwrap();
    let before = seed.image();
    seed.arm(&[]);
    mounted.remove(PIV_RETRIES).unwrap();
    let events = seed.events();
    for io in [Io::Program, Io::Erase] {
        let mut total = 0;
        let mut points = std::collections::BTreeSet::from([0]);
        for (_, _, count) in events.iter().filter(|event| event.0 == io) {
            total += count;
            points.extend([total - 1, total]);
        }
        if total == 0 {
            continue;
        }
        for cut in points {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            flash.replace_image_before_read(0, before.clone());
            let mut mounted = store(&flash);
            assert_eq!(mounted.read(PIV_RETRIES, &mut []), Some(4));
            flash.arm(&[Rule {
                io,
                skip: 0,
                effect: Effect::Shutoff(cut),
                latched: true,
            }]);
            let acknowledged = mounted.remove(PIV_RETRIES).is_ok();
            assert!(flash.hits()[0] > 0);
            flash.clear();
            let mut reopened = store(&flash);
            let mut out = [0; 4];
            let length = reopened.read(PIV_RETRIES, &mut out);
            assert!(!reopened.last_error());
            if length.is_some() {
                assert_eq!(length, Some(4), "{io:?} cut={cut}");
                assert!(!acknowledged);
                assert_eq!(out, [3, 1, 3, 2]);
            }
        }
    }
}
