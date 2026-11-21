// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{KeySource, RootRead};
use crate::tests::Io;

#[test]
fn initialized_counters_cannot_be_reinitialized_over_the_mounted_floor() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut counters = counters(&flash);
    let fid = rsk_fs::counter::EF_COUNTER.get();
    counters
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    counters.write(&KEY, fid, Some(b"prior")).unwrap();
    let before = flash.image();
    flash.arm(&[]);
    assert_eq!(
        counters.initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!()),
        Err(Error::MemoryFatal)
    );
    assert!(flash.events().is_empty());
    assert_eq!(flash.image(), before);
    let mut out = [0; 5];
    assert_eq!(counters.read(&KEY, fid, &mut out), Ok(Some(5)));
    assert_eq!(&out, b"prior");
}

#[test]
fn erased_counter_replicas_cannot_reset_a_live_mounted_floor() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut counters = counters(&flash);
    let fid = rsk_fs::counter::EF_COUNTER.get();
    counters
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    counters.write(&KEY, fid, Some(b"prior")).unwrap();
    let mut erased = flash.image();
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    for range in layout.counter {
        erased[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()]
            .fill(0xFF);
    }
    flash.replace_image_before_read(0, erased.clone());
    flash.arm(&[]);
    let mut out = [0xA5; 5];
    assert_eq!(counters.read(&KEY, fid, &mut out), Err(Error::MemoryFatal));
    assert_eq!(out, [0xA5; 5]);
    assert_eq!(flash.image(), erased);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn a_counter_write_with_the_other_root_arm_cannot_publish() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut counters = counters(&flash);
    let source = KeySource::new([0x43; 32], |_| RootRead::Blank, false);
    let key = source.key(RootArm::PreOtp).unwrap();
    counters
        .initialize(key.expose(), &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    let fid = rsk_fs::counter::EF_COUNTER.get();
    counters.write(key.expose(), fid, Some(b"prior")).unwrap();
    let before = flash.image();
    flash.arm(&[]);
    assert_eq!(
        counters.write_with_source(source, RootArm::Otp, fid, Some(b"other")),
        Err(Error::MemoryFatal)
    );
    assert_eq!(flash.image(), before);
    assert!(flash.events().is_empty());
    let mut out = [0; 5];
    assert_eq!(counters.read(key.expose(), fid, &mut out), Ok(Some(5)));
    assert_eq!(&out, b"prior");
}
