// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::storage::faults::{Cut, Silent, Torn};
use std::vec::Vec;

fn cut_store() -> (Fs<Cut>, crate::storage::faults::CutMedium) {
    let (storage, medium) = Cut::new();
    (Fs::new(storage), medium)
}

#[test]
#[should_panic(expected = "the command failed without reaching a cut")]
fn restart_sweeps_refuse_a_command_failure_without_a_cut() {
    crate::cut::sweep_restarts(cut_store, |_| false, |_| {}, |_, _, _, _, _| {});
}

#[test]
#[should_panic(expected = "vacuous: no command mutation was cut")]
fn restart_sweeps_refuse_a_read_only_command() {
    crate::cut::sweep_restarts(cut_store, |_| true, |_| {}, |_, _, _, _, _| {});
}

#[test]
#[should_panic(expected = "vacuous: the command read nothing")]
fn read_sweeps_refuse_a_command_with_no_reads() {
    crate::probe::sweep(|_| (), |_, _| Some(Vec::new()), &[]);
}

#[test]
#[should_panic(expected = "is stale, its fault broke nothing")]
fn a_fault_that_is_handled_without_a_violation_needs_no_excuse() {
    crate::probe::sweep(
        |fs| fs.put(0xB000, b"owner").unwrap(),
        |fs, _| {
            fs.try_read(0xB000, &mut [0; 5])
                .ok()
                .flatten()
                .map(|_| Vec::new())
        },
        &[(0xB000, 1, "unused fixture excuse")],
    );
}

#[test]
fn persistent_read_faults_cover_reads_and_size_without_becoming_absence() {
    let (mut storage, medium) = Silent::new();
    storage.write(0xB000, b"owner").unwrap();
    medium.fault_read(Some(0xB000));
    for _ in 0..2 {
        assert_eq!(storage.read(0xB000, &mut [0xa5; 5]), None);
        assert!(storage.last_error());
        assert_eq!(storage.size(0xB000), None);
        assert!(storage.last_error());
    }
    assert_eq!(medium.read_faults(), 4);
    medium.fault_read(None);
    let mut out = [0; 5];
    assert_eq!(storage.read(0xB000, &mut out), Some(5));
    assert_eq!(&out, b"owner");
    assert!(!storage.last_error());
}

#[test]
fn a_tear_beyond_the_old_length_leaves_only_the_new_prefix() {
    let (mut storage, medium) = Torn::new();
    storage.write(0xB000, b"ab").unwrap();
    medium.arm(0xB000, 2);
    storage.write(0xB000, b"WXYZ").unwrap();
    assert_eq!(medium.attempts(), 1);
    assert_eq!(medium.value(0xB000), Some(b"WX".to_vec()));
}

#[test]
#[should_panic(expected = "was superseded BEFORE the lap was re-armed")]
fn the_rearm_oracle_refuses_the_reversed_write_order() {
    let (mut storage, medium) = Cut::new();
    storage.write(0xB000, b"replacement").unwrap();
    storage.remove(crate::EF_HARDENED).unwrap();
    medium.assert_re_armed_before(0xB000, |_| false, "reversed fixture");
}

#[path = "powercut_negative_tests.rs"]
mod model;
