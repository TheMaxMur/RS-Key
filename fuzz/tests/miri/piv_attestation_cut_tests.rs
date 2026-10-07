// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn piv_cut(data: &[u8]) -> power_cut::piv::Outcome {
    match power_cut::run(data) {
        power_cut::Outcome::Piv(out) => out,
        _ => panic!("PIV input route"),
    }
}

#[test]
fn every_piv_provisioning_mode_reaches_both_operation_and_recovery_cut_arms() {
    for mode in [0xb0, 0xb1, 0xb2, 0xb3, 0xb6, 0xb7] {
        let mut reached = [false; 4];
        for churn in [0, 17] {
            for seed in [7, 255] {
                for cut in [0u16, 17, 256, u16::MAX] {
                    for recovery in [0u16, 17, u16::MAX] {
                        let mut data = [mode, seed, 0, 0, 0, 0, churn];
                        data[2..4].copy_from_slice(&cut.to_be_bytes());
                        data[4..6].copy_from_slice(&recovery.to_be_bytes());
                        let out = piv_cut(&data);
                        reached[0] |= out.interrupted;
                        reached[1] |= !out.interrupted;
                        reached[2] |= out.recovery_interrupted;
                        reached[3] |= !out.recovery_interrupted;
                    }
                }
            }
        }
        assert_eq!(reached, [true; 4], "mode {mode:02x}");
    }
}

#[test]
fn piv_provisioning_and_recovery_byte_boundaries_are_exhaustive_for_clean_traces() {
    for mode in [0xb0, 0xb1, 0xb2, 0xb3, 0xb6, 0xb7] {
        let mut data = [mode, 7, 255, 255, 255, 255, 0];
        let healthy = piv_cut(&data);
        let end = u16::try_from(
            healthy.operation_stats.bytes_written
                + healthy.operation_stats.erases * power_cut::backup::ERASE_BYTES as u64,
        )
        .unwrap();
        assert!(end > 0);
        eprintln!("PIV mode {mode:02x}: operation bytes {end}");
        let mut reached = [false; 4];
        for cut in 0..=end {
            data[2..4].copy_from_slice(&cut.to_be_bytes());
            let out = piv_cut(&data);
            reached[0] |= out.interrupted;
            reached[1] |= !out.interrupted;
        }
        for first in [0, end / 2, end.saturating_sub(1)] {
            data[2..4].copy_from_slice(&first.to_be_bytes());
            data[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            let clean = piv_cut(&data);
            let recovery_end = u16::try_from(
                clean.recovery_stats.bytes_written
                    + clean.recovery_stats.erases * power_cut::backup::ERASE_BYTES as u64,
            )
            .unwrap();
            eprintln!("PIV mode {mode:02x}: first {first}, recovery bytes {recovery_end}");
            for cut in 0..=recovery_end {
                data[4..6].copy_from_slice(&cut.to_be_bytes());
                let out = piv_cut(&data);
                reached[2] |= out.recovery_interrupted;
                reached[3] |= !out.recovery_interrupted;
            }
        }
        assert_eq!(reached, [true; 4], "mode {mode:02x}");
    }
}
