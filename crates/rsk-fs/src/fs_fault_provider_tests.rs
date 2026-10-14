// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::storage::faults::{MetaStuck, ProbeStuck};

#[test]
fn metadata_fault_inventory_and_removal_match_the_physical_records() {
    let (mut backend, medium) = MetaStuck::new();
    assert!(!medium.live(KEY_DEV));
    backend.write(KEY_DEV, b"owner").unwrap();
    backend.write(KEY_DEV + 2, b"neighbor").unwrap();
    assert!(medium.live(KEY_DEV));
    let mut keys = std::vec::Vec::new();
    assert!(backend.for_each_key(&mut |fid| keys.push(fid)));
    keys.sort_unstable();
    assert_eq!(keys, [KEY_DEV, KEY_DEV + 2]);
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(backend.read(KEY_DEV, &mut [0; 8]), None);
    assert!(!medium.live(KEY_DEV));
    assert_eq!(backend.read(KEY_DEV + 2, &mut [0; 8]), Some(8));
}

#[test]
fn probe_faults_skip_only_target_probes_then_recover_and_forward_removals() {
    let (mut backend, medium) = ProbeStuck::new();
    backend.write(KEY_DEV, b"abc").unwrap();
    backend.write(KEY_DEV + 2, b"neighbor").unwrap();
    assert_eq!(medium.value(KEY_DEV), Some(b"abc".to_vec()));
    assert_eq!(medium.value(KEY_DEV + 1), None);
    medium.stick_once(KEY_DEV);
    assert_eq!(backend.read(KEY_DEV, &mut [0; 2]), None);
    assert!(backend.last_error());
    let mut out = [0; 2];
    assert_eq!(backend.read(KEY_DEV, &mut out), Some(3));
    assert_eq!(&out, b"ab");
    assert!(!backend.last_error());
    medium.stick_after(KEY_DEV, 2);
    assert_eq!(backend.size(KEY_DEV + 2), Some(8));
    assert_eq!(backend.read(KEY_DEV, &mut out), Some(3));
    assert_eq!(backend.size(KEY_DEV + 2), Some(8));
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert_eq!(backend.read(KEY_DEV, &mut out), None);
    assert!(backend.last_error());
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert!(!backend.last_error());
    medium.refuse_remove(Some(KEY_DEV));
    assert_eq!(backend.remove(KEY_DEV), Err(Error::MemoryFatal));
    assert_eq!(medium.value(KEY_DEV), Some(b"abc".to_vec()));
    medium.refuse_remove(None);
    assert_eq!(backend.remove(KEY_DEV), Ok(()));
    assert_eq!(medium.value(KEY_DEV), None);
}

#[test]
fn removal_faults_count_refused_and_served_calls_and_preserve_full_lengths() {
    let (mut backend, medium) = RemoveStuck::new();
    backend.write(KEY_DEV, b"abc").unwrap();
    let mut out = [0; 2];
    assert_eq!(backend.read(KEY_DEV, &mut out), Some(3));
    assert_eq!(&out, b"ab");
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert_eq!(backend.read(KEY_DEV + 1, &mut out), None);
    assert_eq!(backend.size(KEY_DEV + 1), None);
    assert_eq!(medium.attempts(), 0);
    medium.refuse_once(KEY_DEV);
    assert_eq!(backend.remove(KEY_DEV), Err(Error::MemoryFatal));
    assert_eq!(medium.attempts(), 1);
    assert!(medium.live(KEY_DEV));
    assert_eq!(backend.remove(KEY_DEV), Ok(()));
    assert_eq!(medium.attempts(), 2);
    assert!(!medium.live(KEY_DEV));
}

#[test]
fn truncated_inventory_still_forwards_value_lengths_and_removals() {
    let mut backend = TruncatedWalk::new();
    backend.write(KEY_DEV, b"abc").unwrap();
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert_eq!(backend.size(KEY_DEV + 1), None);
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(backend.read(KEY_DEV, &mut [0; 3]), None);
}

#[test]
fn rearm_order_ignores_weak_and_unrelated_writes() {
    let (mut backend, medium) = Cut::new();
    backend.write(KEY_DEV, b"weak").unwrap();
    backend.write(KEY_DEV + 2, b"strong").unwrap();
    backend.remove(crate::EF_HARDENED).unwrap();
    backend.write(KEY_DEV, b"strong").unwrap();
    medium.assert_re_armed_before(KEY_DEV, |value| value == b"weak", "strong rewrite");
    assert_eq!(backend.size(KEY_DEV), Some(6));
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(backend.read(KEY_DEV, &mut [0; 6]), None);
    assert_eq!(medium.value(KEY_DEV), None);
}

#[test]
fn factory_wipe_leaves_an_empty_first_batch_in_finite_steps() {
    let mut fs = fs();
    fs.put(KEY_DEV, b"owner").unwrap();
    let calls = core::cell::Cell::new(0);
    fs.factory_wipe(
        |_| false,
        |_| {
            calls.set(calls.get() + 1);
            assert!(calls.get() <= 2, "empty first batch must finish");
            false
        },
        |_| false,
    )
    .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(fs.read(KEY_DEV, &mut [0; 5]), None);
}
