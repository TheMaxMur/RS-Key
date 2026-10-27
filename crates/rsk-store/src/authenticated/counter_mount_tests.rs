// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::Io;

const FID: u16 = rsk_fs::counter::EF_SIG_COUNT.get();

fn provision(flash: &FaultFlash) -> Counters<FaultFlash> {
    let mut pair = counters(flash);
    pair.initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    for value in 0u8..12 {
        pair.write(&KEY, FID, Some(&[value])).unwrap();
    }
    pair
}

#[test]
fn a_counter_mount_reads_both_entire_banks_and_reduces_replay_reads() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    let mut out = [0; 1];
    flash.arm(&[]);
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(Some(1)));
    assert_eq!(out, [11]);
    let warm = flash.events();
    for range in layout.counter {
        for address in range {
            assert!(warm.iter().any(|&(io, at, len)| io == Io::Read
                && at <= address
                && address < at + u32::try_from(len).unwrap()));
        }
    }
    assert!(warm.iter().all(|event| event.0 == Io::Read));
    pair.mount = None;
    flash.arm(&[]);
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(Some(1)));
    assert!(warm.len() < flash.events().len());
}

#[test]
fn a_counter_mount_observes_valid_publication_beyond_its_previous_end() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let mut writer = counters(&flash);
    writer.write(&KEY, FID, Some(b"new")).unwrap();
    let mut out = [0; 3];
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(Some(3)));
    assert_eq!(&out, b"new");
    writer.write(&KEY, FID, None).unwrap();
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(None));
    assert_eq!(&out, b"new");
}

#[test]
fn changed_counter_headers_entries_payloads_and_erased_tails_never_reuse_the_mount() {
    for offset in [0, 95, 96, 128, 20479] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        let layout =
            Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
        let mut changed = flash.image();
        for range in layout.counter {
            changed[usize::try_from(range.start + offset).unwrap()] ^= 1;
        }
        flash.arm(&[]);
        flash.replace_image_before_read(0, changed.clone());
        let mut out = [0xa5; 1];
        assert_eq!(pair.read(&KEY, FID, &mut out), Err(Error::MemoryFatal));
        assert_eq!(out, [0xa5]);
        assert!(pair.mount.is_none());
        assert_eq!(flash.image(), changed);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn a_counter_mount_remains_bound_to_the_root_key_and_configuration() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    assert_eq!(
        pair.read(&[0x36; 32], FID, &mut []),
        Err(Error::MemoryFatal)
    );
    assert!(pair.mount.is_none());
    assert_eq!(pair.read(&KEY, FID, &mut []), Ok(Some(1)));
    pair.configure(EPOCH, RootArm::Otp);
    assert!(pair.mount.is_none());
    assert_eq!(pair.read(&KEY, FID, &mut []), Err(Error::MemoryFatal));
}

#[test]
fn counter_mount_writes_preserve_the_exact_publication_and_final_flash_image() {
    let measure = |reuse: bool| {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        if !reuse {
            pair.mount = None;
        }
        flash.arm(&[]);
        pair.write(&KEY, FID, Some(b"next")).unwrap();
        (flash.image(), flash.events())
    };
    let (warm_image, warm) = measure(true);
    let (cold_image, cold) = measure(false);
    assert_eq!(warm_image, cold_image);
    assert_eq!(
        warm.iter().filter(|e| e.0 != Io::Read).collect::<Vec<_>>(),
        cold.iter().filter(|e| e.0 != Io::Read).collect::<Vec<_>>()
    );
    assert!(warm.len() < cold.len());
}

#[test]
fn accelerated_counter_mount_reads_refuse_every_io_error_without_falling_back() {
    use crate::tests::{Effect, Rule};
    fn digest(
        flash: &mut FaultFlash,
        range: core::ops::Range<u32>,
        end: u32,
        prefix: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        RawBank::new(flash.clone(), range)?.digest_if_erased_tail(end, prefix)
    }
    let setup = || {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        for bank in &mut pair.banks {
            bank.set_digest(digest);
        }
        flash.arm(&[]);
        (flash, pair)
    };
    let (trace, mut healthy) = setup();
    assert_eq!(healthy.read(&KEY, FID, &mut [0; 1]), Ok(Some(1)));
    let reads = trace.events().iter().filter(|e| e.0 == Io::Read).count();
    for skip in 0..reads {
        let (flash, mut pair) = setup();
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        let mut out = [0xa5; 1];
        assert_eq!(
            pair.read(&KEY, FID, &mut out),
            Err(Error::MemoryFatal),
            "read {skip}"
        );
        assert_eq!(out, [0xa5]);
        assert!(pair.mount.is_none());
        assert_eq!(flash.hits(), [1]);
    }
}

#[test]
fn a_configured_counter_digest_refusal_cannot_silently_use_the_software_fallback() {
    fn refused(
        _: &mut FaultFlash,
        _: core::ops::Range<u32>,
        _: u32,
        _: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        Err(Error::MemoryFatal)
    }
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    for bank in &mut pair.banks {
        bank.set_digest(refused);
    }
    let mut out = [0xa5];
    assert_eq!(pair.read(&KEY, FID, &mut out), Err(Error::MemoryFatal));
    assert_eq!(out, [0xa5]);
    assert!(pair.mount.is_none());
}
