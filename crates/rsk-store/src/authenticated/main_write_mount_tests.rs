// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::Io;

#[test]
fn a_verified_mount_reduces_reads_without_skipping_any_publication() {
    let measure = |reuse: bool| {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut main = main_on(flash.clone());
        main.initialize(&KEY, 0, &Directory::new()).unwrap();
        for value in 0u8..8 {
            main.write(&KEY, 0xB000, Some(&[value])).unwrap();
        }
        if !reuse {
            main.invalidate_read_cache();
        }
        flash.arm(&[]);
        main.write(&KEY, 0xB000, Some(b"next")).unwrap();
        (flash.image(), flash.events())
    };
    let (warm_image, warm) = measure(true);
    let (cold_image, cold) = measure(false);
    assert_eq!(warm_image, cold_image);
    assert_eq!(
        warm.iter()
            .filter(|event| event.0 != Io::Read)
            .collect::<Vec<_>>(),
        cold.iter()
            .filter(|event| event.0 != Io::Read)
            .collect::<Vec<_>>()
    );
    let warm_reads = warm.iter().filter(|event| event.0 == Io::Read).count();
    let cold_reads = cold.iter().filter(|event| event.0 == Io::Read).count();
    assert!(
        warm_reads < cold_reads,
        "warm {warm_reads}, cold {cold_reads}"
    );
}

#[test]
fn a_completed_write_never_reuses_a_changed_journal_for_the_next_publication() {
    let layout = super::super::super::Layout::new(
        32768..32768 + super::super::super::storage::AUTHORITY_BYTES,
    )
    .unwrap();
    for range in layout.main {
        for offset in [
            range.start,
            range.start + 95,
            range.start + 96,
            range.end - 1,
        ] {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            let mut main = main_on(flash.clone());
            main.initialize(&KEY, 0, &Directory::new()).unwrap();
            main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
            let mut damaged = flash.image();
            *damaged.get_mut(usize::try_from(offset).unwrap()).unwrap() ^= 1;
            flash.arm(&[]);
            flash.replace_image_before_read(0, damaged.clone());
            assert_eq!(
                main.write(&KEY, 0xB000, Some(b"new")),
                Err(Error::MemoryFatal)
            );
            assert_eq!(flash.image(), damaged);
            assert!(flash.events().iter().all(|event| event.0 == Io::Read));
            assert!(main.read_cache.is_none());
        }
    }
}

#[test]
fn a_completed_write_refuses_live_replay_before_any_subsequent_read() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"old")).unwrap();
    let old = flash.image();
    main.write(&KEY, 0xB000, Some(b"new")).unwrap();
    flash.arm(&[]);
    flash.replace_image_before_read(0, old.clone());
    assert_eq!(
        main.write(&KEY, 0xB000, Some(b"next")),
        Err(Error::MemoryFatal)
    );
    assert_eq!(flash.image(), old);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Err(Error::MemoryFatal));
}

#[test]
fn a_completed_write_still_authenticates_every_byte_of_the_next_read() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    let mut changed = flash.image();
    let offset = changed
        .windows(5)
        .position(|bytes| bytes == b"owner")
        .unwrap();
    *changed.get_mut(offset).unwrap() ^= 1;
    flash.arm(&[]);
    flash.replace_image_before_read(0, changed.clone());
    let mut out = [0xa5; 5];
    assert_eq!(main.read(&KEY, 0xB000, &mut out), Err(Error::MemoryFatal));
    assert_eq!(out, [0xa5; 5]);
    assert_eq!(flash.image(), changed);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}
