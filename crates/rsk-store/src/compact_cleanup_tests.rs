// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn provision() -> (SharedMock, TestStore) {
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    store.write(CTR, b"counter").unwrap();
    flash.programs.borrow_mut().clear();
    (flash, store)
}

#[test]
fn a_failed_final_filler_removal_is_reported_and_recovered_without_losing_live_data() {
    let (clean, mut store) = provision();
    let counter_before = clean.snapshot(COUNTER);
    store.compact().unwrap();
    assert_eq!(read_vec(&mut store, SCRUB_FILLER_FID), None);
    assert_eq!(clean.snapshot(COUNTER), counter_before);
    let programs = clean.programs.borrow().clone();
    assert!(
        programs.len() > 32,
        "the existing early budgets cannot reach cleanup"
    );
    let last = programs.len() - 1;

    let (flash, mut store) = provision();
    let counter_before = flash.snapshot(COUNTER);
    flash.fail_write_after.set(Some(last));
    assert_eq!(store.compact(), Err(Error::MemoryFatal));
    assert_eq!(flash.refused_program.get(), Some(last));
    assert_eq!(*flash.programs.borrow(), programs);
    assert_eq!(flash.snapshot(COUNTER), counter_before);
    let mut recovered = mount(&flash);
    assert_eq!(
        read_vec(&mut recovered, CRED).as_deref(),
        Some(b"credential".as_slice())
    );
    assert_eq!(
        read_vec(&mut recovered, CTR).as_deref(),
        Some(b"counter".as_slice())
    );
    assert!(
        read_vec(&mut recovered, SCRUB_FILLER_FID).is_some(),
        "the failed program must be the filler removal"
    );
    recovered.compact().unwrap();
    assert_eq!(read_vec(&mut recovered, SCRUB_FILLER_FID), None);
    assert_eq!(
        read_vec(&mut recovered, CRED).as_deref(),
        Some(b"credential".as_slice())
    );
    assert_eq!(flash.snapshot(COUNTER), counter_before);
}
