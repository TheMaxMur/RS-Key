// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn transition(fail: &[usize]) -> (ReadMode, Vec<ReadStep>) {
    let mut steps = Vec::new();
    let mode = continuous_read(|step| {
        steps.push(step);
        !fail.contains(&steps.len())
    });
    (mode, steps)
}

#[test]
fn continuous_read_primes_once_before_omitting_the_prefix_and_probing() {
    use ReadStep::*;
    assert_eq!(
        transition(&[]),
        (
            ReadMode::Continuous,
            vec![Prepare, Prime, OmitPrefix, Probe]
        )
    );
    assert_eq!(transition(&[1]), (ReadMode::Unchanged, vec![Prepare]));
    assert_eq!(
        transition(&[3]),
        (ReadMode::Fatal, vec![Prepare, Prime, OmitPrefix])
    );
}

#[test]
fn either_failed_read_releases_the_chip_before_restoring_and_reprobes() {
    use ReadStep::*;
    assert_eq!(
        transition(&[2]),
        (
            ReadMode::Restored,
            vec![Prepare, Prime, OmitPrefix, Release, Restore, Probe]
        )
    );
    assert_eq!(
        transition(&[4]),
        (
            ReadMode::Restored,
            vec![Prepare, Prime, OmitPrefix, Probe, Release, Restore, Probe]
        )
    );
}

#[test]
fn every_failed_rollback_step_is_fatal_and_stops_immediately() {
    use ReadStep::*;
    let steps = [Prepare, Prime, OmitPrefix, Probe, Release, Restore, Probe];
    for failed in 5..=7 {
        assert_eq!(
            transition(&[4, failed]),
            (ReadMode::Fatal, steps[..failed].to_vec())
        );
    }
    let steps = [Prepare, Prime, OmitPrefix, Release, Restore, Probe];
    for failed in 4..=6 {
        assert_eq!(
            transition(&[2, failed]),
            (ReadMode::Fatal, steps[..failed].to_vec())
        );
    }
}

struct Fake {
    id: [u8; 3],
    status: u8,
    status1: u8,
    refuse: Option<usize>,
    latch: bool,
    ignore_write: bool,
    written_status: u8,
    written_status1: u8,
    calls: Vec<(u8, Option<u8>)>,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            id: [0x85, 0x60, 0x16],
            status: 0,
            status1: 0,
            refuse: None,
            latch: false,
            ignore_write: false,
            written_status: 0,
            written_status1: 0x02,
            calls: Vec::new(),
        }
    }
}
impl Commands for Fake {
    fn transfer(&mut self, command: u8, payload: Option<u8>, out: &mut [u8]) -> bool {
        self.calls.push((command, payload));
        if self.refuse == Some(self.calls.len()) {
            return false;
        }
        match command {
            0x9f => out.copy_from_slice(&self.id),
            0x05 => out.copy_from_slice(&[self.status]),
            0x35 => out.copy_from_slice(&[self.status1]),
            0x50 => {
                assert!(out.is_empty() && payload.is_none());
                self.latch = true;
            }
            0x31 => {
                assert!(
                    out.is_empty() && self.latch,
                    "nonvolatile status write attempted"
                );
                assert_eq!(payload, Some(0x02));
                if !self.ignore_write {
                    self.status1 = self.written_status1;
                    self.status = self.written_status;
                }
                self.latch = false;
            }
            _ => panic!("unexpected flash command"),
        }
        true
    }
}

#[test]
fn sets_only_volatile_qe_and_reads_back_both_status_registers() {
    let mut commands = Fake::default();
    assert!(enable(&mut commands));
    assert_eq!(
        commands.calls,
        [
            (0x9f, None),
            (0x05, None),
            (0x35, None),
            (0x50, None),
            (0x31, Some(0x02)),
            (0x35, None),
            (0x05, None)
        ]
    );
    assert!(!commands.latch);
    commands.calls.clear();
    assert!(enable(&mut commands));
    assert_eq!(commands.calls, [(0x9f, None), (0x05, None), (0x35, None)]);
}

#[test]
fn unknown_ids_and_every_other_status_bit_refuse_without_a_write_enable() {
    for byte in 0..3 {
        let mut commands = Fake::default();
        commands.id[byte] ^= 1;
        assert!(!enable(&mut commands));
        assert_eq!(commands.calls, [(0x9f, None)]);
    }
    for bit in 0..8 {
        let mut commands = Fake {
            status: 1 << bit,
            ..Fake::default()
        };
        assert!(!enable(&mut commands));
        assert_eq!(commands.calls, [(0x9f, None), (0x05, None)]);
        if 1 << bit != 0x02 {
            let mut commands = Fake {
                status1: 1 << bit,
                ..Fake::default()
            };
            assert!(!enable(&mut commands));
            assert_eq!(commands.calls, [(0x9f, None), (0x05, None), (0x35, None)]);
        }
    }
}

#[test]
fn every_failed_command_or_ignored_qe_write_refuses() {
    for step in 1..=7 {
        let mut commands = Fake {
            refuse: Some(step),
            ..Fake::default()
        };
        assert!(!enable(&mut commands));
        assert_eq!(commands.calls.len(), step);
    }
    let mut commands = Fake {
        ignore_write: true,
        ..Fake::default()
    };
    assert!(!enable(&mut commands));
    assert_eq!(commands.calls.last(), Some(&(0x35, None)));
}

#[test]
fn a_changed_status_or_additional_status1_bit_after_the_write_refuses() {
    for bit in 0..8 {
        let mut commands = Fake {
            written_status: 1 << bit,
            ..Fake::default()
        };
        assert!(!enable(&mut commands));
        assert_eq!(commands.calls.last(), Some(&(0x05, None)));
        if 1 << bit != 0x02 {
            let mut commands = Fake {
                written_status1: 0x02 | (1 << bit),
                ..Fake::default()
            };
            assert!(!enable(&mut commands));
            assert_eq!(commands.calls.last(), Some(&(0x35, None)));
        }
    }
}
