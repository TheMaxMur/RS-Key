// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const RECORD: u16 = 0xB000;

#[test]
#[should_panic(expected = "succeeded where the clean run refused")]
fn the_read_fault_sweep_rejects_a_failure_that_opens_a_closed_gate() {
    sweep(
        |fs| fs.put(RECORD, b"closed").unwrap(),
        |fs, ()| {
            fs.read(RECORD, &mut [0; 6])
                .is_none()
                .then(|| b"allowed".to_vec())
        },
        &[],
    );
}

#[test]
#[should_panic(expected = "succeeded with another answer")]
fn the_read_fault_sweep_rejects_a_successful_fallback_answer() {
    sweep(
        |fs| fs.put(RECORD, b"original").unwrap(),
        |fs, ()| {
            let mut value = [0; 8];
            Some(match fs.read(RECORD, &mut value) {
                Some(_) => value.to_vec(),
                None => b"fallback".to_vec(),
            })
        },
        &[],
    );
}

#[test]
#[should_panic(expected = "command deliberately failed")]
fn the_read_fault_sweep_rethrows_a_command_panic() {
    sweep(
        |fs| fs.put(RECORD, b"value").unwrap(),
        |fs, ()| {
            let _ = fs.read(RECORD, &mut [0; 5]);
            panic!("command deliberately failed");
        },
        &[],
    );
}

#[test]
fn read_fault_exceptions_bind_to_both_the_fid_and_the_read_number() {
    let other = RECORD + 1;
    let answer = sweep(
        |fs| {
            fs.put(RECORD, &[1]).unwrap();
            fs.put(other, &[2]).unwrap();
        },
        |fs, ()| {
            let mut value = [0; 1];
            let first = (fs.read(RECORD, &mut value), fs.read(RECORD, &mut value));
            let second = (fs.read(other, &mut value), fs.read(other, &mut value));
            if (first.0.is_none() && first.1.is_none())
                || (second.0.is_none() && second.1.is_none())
            {
                None
            } else if first.0.is_none()
                || first.1.is_none()
                || second.0.is_none()
                || second.1.is_none()
            {
                Some(b"one-shot control".to_vec())
            } else {
                Some(b"clean".to_vec())
            }
        },
        &[
            (RECORD, 1, "first sample one-shot control"),
            (RECORD, 2, "second sample one-shot control"),
            (other, 1, "other fid first sample control"),
            (other, 2, "other fid second sample control"),
        ],
    );
    assert_eq!(answer, Some(b"clean".to_vec()));
}
