// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn cut(data: &[u8]) -> power_cut::credentials::Outcome {
    match power_cut::run(data) {
        power_cut::Outcome::Credentials(out) => out,
        _ => panic!("credential cut route"),
    }
}

#[test]
fn miri_credential_creation_and_replacement_survive_both_restarts() {
    for mode in 0..power_cut::credentials::CASE_COUNT {
        let mut reached = [false; 3];
        for first in [0u16, 128, u16::MAX] {
            let seconds: &[u16] = if cfg!(miri) { &[0] } else { &[0, u16::MAX] };
            for &second in seconds {
                let mut data = [power_cut::credentials::MODE_PREFIX, mode, 0, 0, 0, 0, 0];
                data[2..4].copy_from_slice(&first.to_be_bytes());
                data[4..6].copy_from_slice(&second.to_be_bytes());
                let out = cut(&data);
                reached[0] |= out.interrupted;
                reached[1] |= !out.interrupted;
                reached[2] |= !out.recovery_interrupted;
            }
        }
        assert_eq!(reached, [true; 3], "mode {mode}");
    }
}

#[test]
#[cfg(not(miri))]
fn credential_command_and_recovery_byte_boundaries_preserve_the_surviving_counter() {
    for mode in 0..power_cut::credentials::CASE_COUNT {
        let mut data = [
            power_cut::credentials::MODE_PREFIX,
            mode,
            255,
            255,
            255,
            255,
            0,
        ];
        let healthy = cut(&data);
        assert!(!healthy.interrupted && !healthy.recovery_interrupted);
        let cost = |stats: &sequential_storage::mock_flash::FlashStatsResult| {
            u16::try_from(
                stats.bytes_written + stats.erases * power_cut::backup::ERASE_BYTES as u64,
            )
            .unwrap()
        };
        let end = cost(&healthy.operation_stats);
        assert!(end > 0);
        for first in 0..=end {
            data[2..4].copy_from_slice(&first.to_be_bytes());
            cut(&data);
        }
        let mut recovery_cut = false;
        for first in [0, end / 2, end - 1] {
            data[2..4].copy_from_slice(&first.to_be_bytes());
            data[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            let end = cost(&cut(&data).recovery_stats);
            for second in 0..=end {
                data[4..6].copy_from_slice(&second.to_be_bytes());
                recovery_cut |= cut(&data).recovery_interrupted;
            }
        }
        if mode == 0 {
            assert!(
                recovery_cut,
                "creation never reached an interrupted RP repair"
            );
        }
    }
}
