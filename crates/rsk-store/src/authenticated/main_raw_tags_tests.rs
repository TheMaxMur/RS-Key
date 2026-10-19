// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{KeySource, RootRead, authority::READ_MAC_PROOFS, keys::DERIVATIONS};

#[path = "main_first_read_tests.rs"]
mod first_read;

std::thread_local! {
    static ROOT: core::cell::Cell<[u8; 32]> = const { core::cell::Cell::new([0x56; 32]) };
    static MODE: core::cell::Cell<RootRead> = const { core::cell::Cell::new(RootRead::Fused) };
    static READS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static CHANGE_AFTER_READ: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static RESTORE_AFTER_READ: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

fn root_read(out: &mut [u8; 32]) -> RootRead {
    READS.with(|count| count.set(count.get() + 1));
    ROOT.with(|root| {
        *out = root.get();
        if CHANGE_AFTER_READ.with(core::cell::Cell::get) {
            root.set([0x79; 32]);
        } else if RESTORE_AFTER_READ.with(core::cell::Cell::get) {
            root.set([0x56; 32]);
        }
    });
    MODE.with(core::cell::Cell::get)
}

fn source() -> KeySource {
    KeySource::new([0x43; 32], root_read, false)
}

fn prepared() -> (
    Main<impl MultiwriteNorFlash + Clone, UncachedMap>,
    Secret<[u8; 32]>,
) {
    prepared_value(b"owner")
}

fn prepared_value(
    data: &[u8],
) -> (
    Main<impl MultiwriteNorFlash + Clone + use<>, UncachedMap>,
    Secret<[u8; 32]>,
) {
    ROOT.with(|root| root.set([0x56; 32]));
    MODE.with(|mode| mode.set(RootRead::Fused));
    CHANGE_AFTER_READ.with(|change| change.set(false));
    RESTORE_AFTER_READ.with(|change| change.set(false));
    let mut main = main();
    main.arm = RootArm::Otp;
    let key = source().key(RootArm::Otp).unwrap();
    main.initialize(key.expose(), 0, &Directory::new()).unwrap();
    main.write(key.expose(), 0xB000, Some(data)).unwrap();
    assert_eq!(
        main.read(key.expose(), 0xB000, &mut []),
        Ok(Some(data.len()))
    );
    (main, key)
}

fn warmed() -> Main<impl MultiwriteNorFlash + Clone, UncachedMap> {
    let (mut main, _key) = prepared();
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
        Ok(Some(5))
    );
    main
}

#[test]
fn each_hit_reads_a_fresh_root_and_does_not_repeat_the_persisted_proof() {
    let mut main = warmed();
    READS.with(|count| count.set(0));
    READ_MAC_PROOFS.with(|count| count.set(0));
    DERIVATIONS.with(|count| count.set(0));
    let mut out = [0xA5; 3];
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
        Ok(Some(5))
    );
    assert_eq!(&out, b"own");
    assert_eq!(READS.with(core::cell::Cell::get), 1);
    assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 0);
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB001, &mut []),
        Ok(None)
    );
    assert_eq!(READS.with(core::cell::Cell::get), 2);
    assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 0);
    assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 0);
}

#[test]
fn absence_seeds_only_after_a_bound_proof_from_the_same_root_observation() {
    let (mut main, _key) = prepared();
    READS.with(|count| count.set(0));
    READ_MAC_PROOFS.with(|count| count.set(0));
    DERIVATIONS.with(|count| count.set(0));
    CHANGE_AFTER_READ.with(|change| change.set(true));
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB001, &mut []),
        Ok(None)
    );
    assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 1);
    assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 1);
    assert_eq!(READS.with(core::cell::Cell::get), 1);
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB002, &mut []),
        Err(Error::MemoryFatal)
    );
    assert_eq!(READS.with(core::cell::Cell::get), 2);
    assert!(main.read_cache.is_none());
    assert!(main.authority.established());
}

#[test]
fn every_mount_tag_byte_is_required_even_for_absence() {
    for index in 0..32 {
        let mut main = warmed();
        let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
        let mut tag = main.read_tags.mount_tag(bound).unwrap();
        *tag.get_mut(index).unwrap() ^= 1;
        main.read_tags.bind(bound, tag);
        let mut out = [0xA5; 5];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB001, &mut out),
            Err(Error::MemoryFatal)
        );
        assert_eq!(out, [0xA5; 5]);
        assert!(main.read_tags.mount_tag(bound).is_none());
        assert!(main.authority.established());
    }
}

#[test]
fn a_wrong_root_cannot_seed_an_absence_proof() {
    let (mut main, _key) = prepared();
    ROOT.with(|root| root.set([0x79; 32]));
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB001, &mut []),
        Err(Error::MemoryFatal)
    );
    assert!(main.read_cache.is_none());
    assert!(main.authority.established());
}

#[test]
fn recovery_checks_both_fresh_root_observations_before_using_a_derived_key() {
    for changed_before_fetch in [false, true] {
        let mut main = warmed();
        block_on(main.map.store_item(
            main.buffer.expose_mut(),
            &0xB000,
            &b"too-long-to-fit".as_slice(),
        ))
        .unwrap();
        main.buffer.wipe();
        READS.with(|count| count.set(0));
        if changed_before_fetch {
            ROOT.with(|root| root.set([0x79; 32]));
            RESTORE_AFTER_READ.with(|change| change.set(true));
        } else {
            CHANGE_AFTER_READ.with(|change| change.set(true));
        }
        let mut out = [0xA5; 5];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
            Err(Error::MemoryFatal)
        );
        assert_eq!(
            READS.with(core::cell::Cell::get),
            if changed_before_fetch { 1 } else { 2 }
        );
        assert_eq!(out, [0xA5; 5]);
        assert!(main.read_cache.is_none());
        assert!(main.authority.established());
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
    }
}

#[test]
fn an_unchanged_root_can_recover_the_admitted_copy_after_a_bounded_fetch_miss() {
    let mut main = warmed();
    block_on(main.map.store_item(
        main.buffer.expose_mut(),
        &0xB000,
        &b"too-long-to-fit".as_slice(),
    ))
    .unwrap();
    main.buffer.wipe();
    READS.with(|count| count.set(0));
    DERIVATIONS.with(|count| count.set(0));
    let mut out = [0xA5; 5];
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
        Ok(Some(5))
    );
    assert_eq!(&out, b"owner");
    assert_eq!(READS.with(core::cell::Cell::get), 2);
    assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 1);
    assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
}

#[test]
fn a_same_length_forgery_on_a_miss_cannot_seed_a_payload_tag() {
    let (mut main, _key) = prepared();
    let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
    let entry = main.directory.find(0xB000).unwrap();
    block_on(
        main.map
            .store_item(main.buffer.expose_mut(), &0xB000, &b"forge".as_slice()),
    )
    .unwrap();
    for _ in 0..2 {
        READ_MAC_PROOFS.with(|count| count.set(0));
        let mut out = [0xA5; 5];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
            Ok(Some(5))
        );
        assert_eq!(&out, b"owner");
        assert!(main.read_tags.find(bound, entry).is_none());
        assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 1);
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
    }
}

#[test]
fn ready_hints_are_cleared_before_writes_and_configuration() {
    let (mut main, key) = prepared();
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
        Ok(Some(5))
    );
    let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
    assert!(main.read_tags.mount_tag(bound).is_some());
    main.write(key.expose(), 0xB000, Some(b"new")).unwrap();
    assert!(main.read_tags.mount_tag(bound).is_none());
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
        Ok(Some(3))
    );
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
        Ok(Some(3))
    );
    let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
    assert!(main.read_tags.mount_tag(bound).is_some());
    main.configure(EPOCH, RootArm::Otp);
    assert!(main.read_tags.mount_tag(bound).is_none());
}

#[test]
fn read_preparation_preserves_all_otp_classifications_and_latch_rules() {
    for arm in [RootArm::PreOtp, RootArm::Otp] {
        for latched in [false, true] {
            for mode in [RootRead::Blank, RootRead::Fused, RootRead::Unreadable] {
                MODE.with(|current| current.set(mode));
                CHANGE_AFTER_READ.with(|change| change.set(false));
                let source = KeySource::new([0x43; 32], root_read, latched);
                let allowed = match arm {
                    RootArm::PreOtp => !latched && mode != RootRead::Unreadable,
                    RootArm::Otp => mode == RootRead::Fused,
                };
                let old = source.key(arm);
                assert_eq!(old.is_ok(), allowed);
                for needs_key in [false, true] {
                    let proof = source.prepare_read(arm, needs_key);
                    assert_eq!(proof.is_ok(), allowed);
                    if let Ok(proof) = proof {
                        if needs_key {
                            assert_eq!(
                                Some(proof.persisted_key().unwrap()),
                                old.as_ref().ok().map(Secret::expose)
                            );
                        } else {
                            assert!(proof.persisted_key().is_err());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_short_output_still_authenticates_every_payload_byte() {
    for length in [0, 1, 63, 64, 65, 1000] {
        let value = vec![0x37; length];
        let (mut main, _key) = prepared_value(&value);
        for _ in 0..3 {
            assert_eq!(
                main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
                Ok(Some(length))
            );
        }
        let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
        let entry = main.directory.find(0xB000).unwrap();
        assert!(main.read_tags.find(bound, entry).is_some());
        DERIVATIONS.with(|count| count.set(0));
        READ_MAC_PROOFS.with(|count| count.set(0));
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
            Ok(Some(length))
        );
        assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 0);
        assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 0);
        if length != 0 {
            let mut changed = value;
            *changed.last_mut().unwrap() ^= 1;
            block_on(
                main.map
                    .store_item(main.buffer.expose_mut(), &0xB000, &changed.as_slice()),
            )
            .unwrap();
            assert_eq!(
                main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
                Err(Error::MemoryFatal)
            );
        }
    }
}

#[test]
fn one_root_observation_must_supply_both_the_old_proof_and_the_seed() {
    let (mut main, _key) = prepared();
    READS.with(|count| count.set(0));
    CHANGE_AFTER_READ.with(|change| change.set(true));
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
        Ok(Some(5))
    );
    let mut out = [0xA5; 5];
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xA5; 5]);
    assert_eq!(READS.with(core::cell::Cell::get), 2);
    assert!(main.read_cache.is_none());
    assert!(main.authority.established());
}

#[test]
fn every_root_byte_and_every_cached_tag_byte_is_required_with_no_output() {
    for index in 0..32 {
        let mut main = warmed();
        ROOT.with(|root| {
            let mut changed = root.get();
            *changed.get_mut(index).unwrap() ^= 1;
            root.set(changed);
        });
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
            Err(Error::MemoryFatal)
        );
        let mut main = warmed();
        let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
        let entry = main.directory.find(0xB000).unwrap();
        let mut tag = main.read_tags.find(bound, entry).unwrap();
        *tag.get_mut(index).unwrap() ^= 1;
        main.read_tags.clear();
        main.read_tags.insert(bound, entry, tag);
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
            Err(Error::MemoryFatal)
        );
        assert!(main.read_tags.find(bound, entry).is_none());
    }
}

#[test]
fn unreadable_or_blank_roots_and_changed_serial_refuse_a_hit() {
    for mode in [RootRead::Unreadable, RootRead::Blank] {
        let mut main = warmed();
        MODE.with(|current| current.set(mode));
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
            Err(Error::MemoryFatal)
        );
        assert!(main.read_cache.is_none());
        assert!(main.authority.established());
    }
    let mut main = warmed();
    let changed = KeySource::new([0x44; 32], root_read, false);
    assert_eq!(
        main.read_with_source(changed, RootArm::Otp, 0xB000, &mut []),
        Err(Error::MemoryFatal)
    );
}

#[test]
fn a_crc_valid_payload_substitution_refuses_a_hit_without_a_root_reread() {
    let mut main = warmed();
    block_on(
        main.map
            .store_item(main.buffer.expose_mut(), &0xB000, &b"forge".as_slice()),
    )
    .unwrap();
    READS.with(|count| count.set(0));
    let mut out = [0xA5; 5];
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(READS.with(core::cell::Cell::get), 1);
    assert_eq!(out, [0xA5; 5]);
    assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
}

#[test]
fn consistent_corruption_of_both_entry_copies_cannot_relabel_a_payload() {
    for (offset, replacement) in [(0, 1), (4, 0x80), (12, 0x80)] {
        let mut main = warmed();
        let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
        let entry = main.directory.find(0xB000).unwrap();
        let tag = main.read_tags.find(bound, entry).unwrap();
        let mut encoded = entry.encode().unwrap();
        *encoded.get_mut(offset).unwrap() ^= replacement;
        let changed = Entry::decode(&encoded).unwrap();
        main.directory.clear();
        main.directory
            .push_snapshot(changed, changed.generation())
            .unwrap();
        block_on(main.map.store_item(
            main.buffer.expose_mut(),
            &changed.fid(),
            &b"owner".as_slice(),
        ))
        .unwrap();
        main.read_tags.clear();
        main.read_tags.insert(bound, changed, tag);
        let mut out = [0xA5; 5];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, changed.fid(), &mut out),
            Err(Error::MemoryFatal)
        );
        assert_eq!(out, [0xA5; 5]);
    }
}

#[test]
fn consistent_corruption_of_both_bound_copies_cannot_change_the_floor_context() {
    for index in 0..3 {
        let mut main = warmed();
        let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
        let entry = main.directory.find(0xB000).unwrap();
        let tag = main.read_tags.find(bound, entry).unwrap();
        let changed = bound.alter_for_test(|snapshot, binding| match index {
            0 => snapshot.sequence ^= 1,
            1 => snapshot.digest[0] ^= 1,
            _ => binding[31] ^= 1,
        });
        main.authority = Authority::Stable(changed);
        main.read_tags.clear();
        main.read_tags.insert(changed, entry, tag);
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
            Err(Error::MemoryFatal)
        );
        assert!(main.authority.established());
    }
}

#[test]
fn a_corrupt_bound_cannot_seed_a_payload_proof() {
    let (mut main, _key) = prepared();
    let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
    main.authority = Authority::Stable(bound.alter_for_test(|_, tag| tag[31] ^= 1));
    let mut out = [0xA5; 5];
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xA5; 5]);
    assert!(main.read_cache.is_none());
    assert!(main.authority.established());
}

#[test]
fn several_record_hits_retain_their_proofs_without_repeating_hkdf() {
    let (mut main, key) = prepared();
    let fids = [0xB000, 0xB001, 0xB002];
    for fid in fids.into_iter().skip(1) {
        main.write(key.expose(), fid, Some(b"owner")).unwrap();
    }
    assert_eq!(main.read(key.expose(), fids[0], &mut []), Ok(Some(5)));
    for fid in fids {
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, fid, &mut []),
            Ok(Some(5))
        );
    }
    READS.with(|count| count.set(0));
    READ_MAC_PROOFS.with(|count| count.set(0));
    DERIVATIONS.with(|count| count.set(0));
    for fid in fids {
        let mut out = [0; 5];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, fid, &mut out),
            Ok(Some(5))
        );
        assert_eq!(&out, b"owner");
    }
    assert_eq!(READS.with(core::cell::Cell::get), fids.len());
    assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 0);
    assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 0);
}
