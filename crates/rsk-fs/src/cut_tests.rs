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

fn cut_fixture() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    fs.put(0xB000, &[0]).unwrap();
    (fs, medium)
}

#[test]
fn restarting_a_read_only_recovery_does_not_replay_the_command() {
    let mut reached = [false; 2];
    assert!(!sweep_restarts(
        cut_fixture,
        |fs| fs.put(0xB000, &[1]).is_ok(),
        |_| (),
        |fs, first, second, completed, _| {
            assert_eq!(second, 0);
            let mut value = [0];
            assert_eq!(fs.read(0xB000, &mut value), Some(1));
            assert_eq!(value, [u8::from(completed)]);
            reached[usize::from(completed)] = true;
            assert_eq!(first, u32::from(completed));
        }
    ));
    assert_eq!(reached, [true; 2]);
}

#[test]
fn each_recovery_budget_starts_from_the_same_command_snapshot() {
    let mut reached = [[false; 3]; 2];
    assert!(sweep_restarts(
        cut_fixture,
        |fs| fs.put(0xB000, &[1]).is_ok(),
        |fs| {
            let mut value = [0];
            fs.read(0xB000, &mut value).unwrap();
            if fs.put(0xB001, &value).is_ok() {
                let _ = fs.put(0xB002, &value);
            }
        },
        |fs, first, second, completed, medium| {
            reached[first as usize][second as usize] = true;
            let expected = vec![u8::from(completed)];
            assert_eq!(medium.value(0xB001), Some(expected.clone()));
            assert_eq!(medium.value(0xB002), Some(expected));
            assert!(fs.has_data(0xB000));
        }
    ));
    assert_eq!(reached, [[true; 3]; 2]);
}

#[test]
#[should_panic(expected = "no recovery budget under 64 let recovery finish")]
fn a_restart_sweep_requires_a_complete_recovery_for_each_command_state() {
    sweep_restarts(
        cut_fixture,
        |fs| fs.put(0xB000, &[1]).is_ok(),
        |fs| {
            for _ in 0..=SWEEP_MAX {
                if fs.put(0xB001, b"repair").is_err() {
                    return;
                }
            }
        },
        |_, _, _, _, _| {},
    );
}
