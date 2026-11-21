// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn config_cut(data: &[u8]) -> power_cut::config::Outcome {
    match power_cut::run(data) {
        power_cut::Outcome::Config(out) => out,
        _ => panic!("configuration cut route"),
    }
}

#[test]
fn miri_configuration_replay_survives_both_cut_stages() {
    for command in 0..power_cut::config::CASE_COUNT {
        let mut reached = [false; 4];
        let churns: &[u8] = if cfg!(miri) { &[0] } else { &[0, 17] };
        let firsts: &[u16] = if cfg!(miri) {
            &[0, u16::MAX]
        } else {
            &[0, 17, 256, u16::MAX]
        };
        let seconds: &[u16] = if cfg!(miri) {
            &[0, u16::MAX]
        } else {
            &[0, 17, u16::MAX]
        };
        for &churn in churns {
            for &first in firsts {
                for &second in seconds {
                    let mut data = [power_cut::config::MODE_PREFIX, command, 0, 0, 0, 0, churn];
                    data[2..4].copy_from_slice(&first.to_be_bytes());
                    data[4..6].copy_from_slice(&second.to_be_bytes());
                    let out = config_cut(&data);
                    reached[0] |= out.interrupted;
                    reached[1] |= !out.interrupted;
                    reached[2] |= out.recovery_interrupted;
                    reached[3] |= !out.recovery_interrupted;
                }
            }
        }
        assert_eq!(reached, [true; 4], "command {command}");
    }
}

#[test]
#[cfg(not(miri))]
fn configuration_replay_cuts_each_operation_and_recovery_byte_on_clean_traces() {
    for command in 0..power_cut::config::CASE_COUNT {
        let mut data = [
            power_cut::config::MODE_PREFIX,
            command,
            255,
            255,
            255,
            255,
            0,
        ];
        let healthy = config_cut(&data);
        assert!(!healthy.interrupted && !healthy.recovery_interrupted);
        let operation_end = u16::try_from(
            healthy.operation_stats.bytes_written
                + healthy.operation_stats.erases * power_cut::backup::ERASE_BYTES as u64,
        )
        .unwrap();
        assert!(operation_end > 0);
        let mut reached = [false; 4];
        for first in 0..=operation_end {
            data[2..4].copy_from_slice(&first.to_be_bytes());
            let out = config_cut(&data);
            reached[0] |= out.interrupted;
            reached[1] |= !out.interrupted;
        }
        for first in [0, operation_end / 2, operation_end - 1] {
            data[2..4].copy_from_slice(&first.to_be_bytes());
            data[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            let replay = config_cut(&data);
            let recovery_end = u16::try_from(
                replay.recovery_stats.bytes_written
                    + replay.recovery_stats.erases * power_cut::backup::ERASE_BYTES as u64,
            )
            .unwrap();
            for second in 0..=recovery_end {
                data[4..6].copy_from_slice(&second.to_be_bytes());
                let out = config_cut(&data);
                reached[2] |= out.recovery_interrupted;
                reached[3] |= !out.recovery_interrupted;
            }
        }
        assert_eq!(reached, [true; 4], "command {command}");
    }
}
