// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{KeySource, RootRead};
use crate::tests::{Effect, Io, Rule};

const PRIVATE: u16 = super::super::super::bound_counter::FIRST_BUCKET;
const PUBLIC: u16 = rsk_fs::counter::EF_SIG_COUNT.get();

std::thread_local! {
    static ROOT_BAD: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static ROOT_READS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static FUSED_ROOT: core::cell::Cell<u8> = const { core::cell::Cell::new(0x56) };
}

fn source() -> KeySource {
    KeySource::new(
        [0x43; 32],
        |_| {
            ROOT_READS.with(|value| value.set(value.get() + 1));
            if ROOT_BAD.with(core::cell::Cell::get) {
                RootRead::Unreadable
            } else {
                RootRead::Blank
            }
        },
        false,
    )
}

fn provision(flash: &FaultFlash) -> Counters<FaultFlash> {
    ROOT_BAD.with(|value| value.set(false));
    let mut pair = counters(flash);
    let key = source().key(RootArm::PreOtp).unwrap();
    pair.initialize(key.expose(), &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    pair.write_with_source(source(), RootArm::PreOtp, PRIVATE, Some(b"bound value"))
        .unwrap();
    pair.write_with_source(source(), RootArm::PreOtp, PUBLIC, Some(b"latest"))
        .unwrap();
    pair
}

#[test]
fn cached_counter_tags_read_the_root_and_payload_without_retaining_or_rederiving_keys() {
    use super::super::super::keys::DERIVATIONS;
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    DERIVATIONS.with(|value| value.set(0));
    ROOT_READS.with(|value| value.set(0));
    for _ in 0..3 {
        let mut out = [0; 11];
        assert_eq!(
            pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut out),
            Ok(Some(11))
        );
        assert_eq!(&out, b"bound value");
        assert_eq!(
            pair.read_with_source(source(), RootArm::PreOtp, PUBLIC, &mut out),
            Ok(Some(6))
        );
        assert_eq!(&out[..6], b"latest");
    }
    assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 0);
    assert_eq!(ROOT_READS.with(core::cell::Cell::get), 6);
    ROOT_BAD.with(|value| value.set(true));
    let mut out = [0xA5; 11];
    assert_eq!(
        pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xA5; 11]);
    ROOT_BAD.with(|value| value.set(false));
    pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut out)
        .unwrap();
    assert!(DERIVATIONS.with(core::cell::Cell::get) > 0);
}

#[test]
fn cold_addressed_reads_reuse_verified_record_tags() {
    use super::super::super::keys::DERIVATIONS;
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    pair.read_cache.clear();
    pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut [])
        .unwrap();
    DERIVATIONS.with(|value| value.set(0));
    for _ in 0..3 {
        let mut out = [0; 11];
        assert_eq!(
            pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut out),
            Ok(Some(11))
        );
        assert_eq!(&out, b"bound value");
    }
    assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 0);
}

#[test]
fn addressed_frames_require_a_complete_private_counter_scan() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let mut scan = pair.mount.unwrap()[0];
    let mut out = [0xA5; 48];
    assert_eq!(
        pair.banks[0].read_bound_frame(&scan, PUBLIC, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xA5; 48]);
    scan.status = JournalStatus::Empty;
    assert_eq!(
        pair.banks[0].read_bound_frame(&scan, PRIVATE, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xA5; 48]);
}

#[test]
fn cached_absence_and_empty_values_still_require_the_current_root() {
    for fid in [PRIVATE, PUBLIC] {
        for value in [None, Some(&[][..])] {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            let mut pair = provision(&flash);
            pair.write_with_source(source(), RootArm::PreOtp, fid, value)
                .unwrap();
            let mut out = [0xA5; 1];
            assert_eq!(
                pair.read_with_source(source(), RootArm::PreOtp, fid, &mut out),
                Ok(value.map(<[u8]>::len))
            );
            let other = KeySource::new([0x44; 32], |_| RootRead::Blank, false);
            assert_eq!(
                pair.read_with_source(other, RootArm::PreOtp, fid, &mut out),
                Err(Error::MemoryFatal)
            );
            assert_eq!(out, [0xA5; 1]);
            assert!(pair.mount.is_none());
        }
    }
}

#[test]
fn cached_public_counters_still_read_both_complete_banks() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    flash.arm(&[]);
    assert_eq!(
        pair.read_with_source(source(), RootArm::PreOtp, PUBLIC, &mut []),
        Ok(Some(6))
    );
    let events = flash.events();
    for range in Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES)
        .unwrap()
        .counter
    {
        for address in range {
            assert!(events.iter().any(|&(io, at, count)| io == Io::Read
                && at <= address
                && address < at + u32::try_from(count).unwrap()));
        }
    }
}

#[test]
fn cached_counter_tags_refuse_physical_changes_and_live_replay() {
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    for fid in [PRIVATE, PUBLIC] {
        for range in &layout.counter {
            let offsets: Vec<u32> = if fid == PRIVATE {
                let start = u32::try_from(super::super::super::CHECKPOINT_BYTES).unwrap();
                (start..start + 48).collect()
            } else {
                vec![0, 95, 96, 128, 144, 176, 208, 20479]
            };
            for offset in offsets {
                let flash = crate::tests::fault_flash_for_authenticated_tests();
                let mut pair = provision(&flash);
                let mut bad = flash.image();
                bad[usize::try_from(range.start + offset).unwrap()] ^= 1;
                flash.arm(&[]);
                flash.replace_image_before_read(0, bad);
                let mut out = [0xA5; 11];
                assert_eq!(
                    pair.read_with_source(source(), RootArm::PreOtp, fid, &mut out),
                    Err(Error::MemoryFatal),
                    "{fid:x} {offset}"
                );
                assert_eq!(out, [0xA5; 11]);
                assert!(pair.mount.is_none());
            }
        }
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        let old = flash.image();
        pair.write_with_source(source(), RootArm::PreOtp, fid, Some(b"advance"))
            .unwrap();
        flash.replace_image_before_read(0, old);
        for _ in 0..2 {
            let mut out = [0xA5; 11];
            assert_eq!(
                pair.read_with_source(source(), RootArm::PreOtp, fid, &mut out),
                Err(Error::MemoryFatal)
            );
            assert_eq!(out, [0xA5; 11]);
        }
    }
}

#[test]
fn matching_corruption_in_both_private_payload_copies_still_requires_the_mac() {
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    let payload = super::super::super::CHECKPOINT_BYTES + super::super::super::ENTRY_BYTES;
    for offset in 0..b"bound value".len() {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        let mut damaged = flash.image();
        for range in &layout.counter {
            let at = usize::try_from(range.start).unwrap() + payload + offset;
            damaged[at] ^= 1;
        }
        flash.replace_image_before_read(0, damaged);
        let mut out = [0xA5; 11];
        assert_eq!(
            pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut out),
            Err(Error::MemoryFatal)
        );
        assert_eq!(out, [0xA5; 11]);
    }
}

#[test]
fn cached_counter_reads_preserve_each_io_error_and_refuse_other_roots_or_arms() {
    for fid in [PRIVATE, PUBLIC] {
        let trace = crate::tests::fault_flash_for_authenticated_tests();
        let mut healthy = provision(&trace);
        trace.arm(&[]);
        healthy
            .read_with_source(source(), RootArm::PreOtp, fid, &mut [])
            .unwrap();
        for skip in 0..trace.events().len() {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            let mut pair = provision(&flash);
            flash.arm(&[Rule {
                io: Io::Read,
                skip,
                effect: Effect::Refuse,
                latched: false,
            }]);
            let mut out = [0xA5; 11];
            assert_eq!(
                pair.read_with_source(source(), RootArm::PreOtp, fid, &mut out),
                Err(Error::MemoryFatal)
            );
            assert_eq!(out, [0xA5; 11]);
            assert_eq!(flash.hits(), [1]);
        }
        let other = KeySource::new([0x44; 32], |_| RootRead::Blank, false);
        assert_eq!(
            healthy.read_with_source(other, RootArm::PreOtp, fid, &mut []),
            Err(Error::MemoryFatal)
        );
        healthy
            .read_with_source(source(), RootArm::PreOtp, fid, &mut [])
            .unwrap();
        assert_eq!(
            healthy.read_with_source(source(), RootArm::Otp, fid, &mut []),
            Err(Error::MemoryFatal)
        );
    }
}

#[test]
fn an_unchanged_private_value_cannot_lower_the_floor_of_another_counter() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let old = flash.image();
    pair.write_with_source(source(), RootArm::PreOtp, PUBLIC, Some(b"advance"))
        .unwrap();
    flash.replace_image_before_read(0, old);
    let mut out = [0; 11];
    assert_eq!(
        pair.read_with_source(source(), RootArm::PreOtp, PRIVATE, &mut out),
        Ok(Some(11))
    );
    assert_eq!(&out, b"bound value");
    for fid in [PUBLIC, PRIVATE, PUBLIC] {
        let mut out = [0xA5; 11];
        assert_eq!(
            pair.read_with_source(source(), RootArm::PreOtp, fid, &mut out),
            Err(Error::MemoryFatal)
        );
        assert_eq!(out, [0xA5; 11]);
    }
}

#[test]
fn cached_counter_tags_refuse_changed_fused_root_bytes_before_releasing_values() {
    use super::super::super::keys::DERIVATIONS;
    let source = KeySource::new(
        [0x43; 32],
        |out| {
            out.fill(FUSED_ROOT.with(core::cell::Cell::get));
            RootRead::Fused
        },
        true,
    );
    for fid in [PRIVATE, PUBLIC] {
        FUSED_ROOT.with(|value| value.set(0x56));
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = counters(&flash);
        pair.configure(EPOCH, RootArm::Otp);
        let key = source.key(RootArm::Otp).unwrap();
        pair.initialize(key.expose(), &Directory::new(), 0, |_, _| unreachable!())
            .unwrap();
        pair.write_with_source(source, RootArm::Otp, fid, Some(b"value"))
            .unwrap();
        DERIVATIONS.with(|value| value.set(0));
        assert_eq!(
            pair.read_with_source(source, RootArm::Otp, fid, &mut []),
            Ok(Some(5))
        );
        assert_eq!(DERIVATIONS.with(core::cell::Cell::get), 0);
        FUSED_ROOT.with(|value| value.set(0x79));
        for _ in 0..2 {
            let mut out = [0xA5; 5];
            assert_eq!(
                pair.read_with_source(source, RootArm::Otp, fid, &mut out),
                Err(Error::MemoryFatal)
            );
            assert_eq!(out, [0xA5; 5]);
        }
        FUSED_ROOT.with(|value| value.set(0x56));
        let mut out = [0; 5];
        assert_eq!(
            pair.read_with_source(source, RootArm::Otp, fid, &mut out),
            Ok(Some(5))
        );
        assert_eq!(&out, b"value");
    }
}

#[test]
fn an_addressed_frame_cannot_use_another_valid_private_counter_location() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let other = PRIVATE + 1;
    pair.write_with_source(source(), RootArm::PreOtp, other, Some(b"other value"))
        .unwrap();
    let mut scan = pair.mount.unwrap()[0];
    let requested = scan
        .locations
        .iter()
        .position(|location| location.is_some_and(|location| location.entry.fid() == PRIVATE))
        .unwrap();
    let other_location = scan
        .locations
        .iter()
        .flatten()
        .find(|location| location.entry.fid() == other)
        .copied()
        .unwrap();
    let mut out = [0xa5; ENTRY_BYTES + 16];
    assert_eq!(
        pair.banks[0].read_bound_frame(&scan, other, &mut out),
        Ok(Some(other_location.entry))
    );
    scan.locations[requested] = Some(other_location);
    flash.arm(&[]);
    assert_eq!(
        pair.banks[0].read_bound_frame(&scan, PRIVATE, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(&out[..ENTRY_BYTES], &other_location.entry.encode().unwrap());
    assert_eq!(&out[ENTRY_BYTES..ENTRY_BYTES + 11], b"other value");
    assert!(out[ENTRY_BYTES + 11..].iter().all(|&byte| byte == 0xff));
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}
