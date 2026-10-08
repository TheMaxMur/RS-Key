// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_recovery_that_finishes_at_the_last_budget_is_accepted() {
    const COMMAND: u16 = 0xB000;
    const REPAIR: u16 = 0xB001;
    let boundary = Cell::new(false);
    sweep_recovery(
        |_| (),
        |fs, ()| {
            let _ = fs.put(COMMAND, b"command");
        },
        |fs| {
            for value in 0..SWEEP_MAX - 1 {
                let byte = u8::try_from(value).unwrap();
                if fs.put(REPAIR, &[byte]).is_err() {
                    break;
                }
            }
        },
        |fs, _, second| {
            boundary.set(boundary.get() || second == SWEEP_MAX - 1);
            let mut value = [0; 1];
            assert_eq!(fs.read(REPAIR, &mut value), Some(1));
            assert_eq!(value, [u8::try_from(SWEEP_MAX - 2).unwrap()]);
        },
    );
    assert!(boundary.get());
}

#[test]
#[should_panic(expected = "no recovery budget under 64 let recovery finish")]
fn a_recovery_sweep_cannot_pass_without_reaching_a_complete_recovery() {
    const COMMAND: u16 = 0xB000;
    const REPAIR: u16 = 0xB001;
    sweep_recovery(
        |_| (),
        |fs, ()| {
            let _ = fs.put(COMMAND, b"command");
        },
        |fs| {
            for value in 0..=SWEEP_MAX {
                let byte = u8::try_from(value).unwrap();
                if fs.put(REPAIR, &[byte]).is_err() {
                    break;
                }
            }
        },
        |fs, _, _| {
            let mut value = [0; 1];
            assert_eq!(fs.read(REPAIR, &mut value), Some(1));
            assert_eq!(value, [u8::try_from(SWEEP_MAX).unwrap()]);
        },
    );
}

#[test]
#[should_panic(expected = "no recovery budget under 64 let recovery finish")]
fn completing_an_earlier_state_cannot_certify_a_later_recovery() {
    const COMMAND: u16 = 0xB000;
    const REPAIR: u16 = 0xB001;
    sweep_recovery(
        |_| (),
        |fs, ()| {
            let _ = fs.put(COMMAND, b"command");
        },
        |fs| {
            let writes = if fs.has_data(COMMAND) {
                SWEEP_MAX + 1
            } else {
                1
            };
            for value in 0..writes {
                let byte = u8::try_from(value).unwrap();
                if fs.put(REPAIR, &[byte]).is_err() {
                    break;
                }
            }
        },
        |fs, _, _| {
            let mut value = [0; 1];
            assert_eq!(fs.read(REPAIR, &mut value), Some(1));
            let expected = if fs.has_data(COMMAND) { SWEEP_MAX } else { 0 };
            assert_eq!(value, [u8::try_from(expected).unwrap()]);
        },
    );
}
