// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_crc_reference_matches_the_check_value_and_residual() {
    assert_eq!(crc16(b"123456789"), 0x6F91);
    let mut wire = b"123456789".to_vec();
    wire.extend_from_slice(&(!crc16(&wire)).to_le_bytes());
    assert_eq!(crc16(&wire), CRC_RESIDUAL);
}

#[test]
fn every_response_length_and_poll_boundary_can_be_replaced() {
    for n in 0..=RESPONSE_MAX + REPORT_DATA {
        for polls in 0..=DATA_REPORTS_MAX + 2 {
            let mut input = vec![n as u8, polls as u8];
            input.extend((0..n).map(|i| (i as u8) ^ 0x39));
            input.extend_from_slice(&[1, DATA_REPORTS_MAX as u8 + 2, 0xD3]);
            replay(&input);
        }
    }
}

#[test]
fn empty_and_truncated_history_records_still_exercise_tx() {
    for input in [
        vec![],
        vec![0],
        vec![255],
        vec![255, 255],
        vec![255, 255, 1],
    ] {
        replay(&input);
    }
}

#[test]
fn completed_and_corrupt_rx_frames_reach_the_same_tx_oracle() {
    let payload = [0x39; PAYLOAD_SIZE];
    let reports = rsk_otp::hid::split_frame(&payload, 0x30);
    let mut input: Vec<u8> = reports.iter().flatten().copied().collect();
    replay(&input);
    input[REPORT_SIZE - 2] ^= 1;
    replay(&input);
    input.extend_from_slice(&[0; REPORT_SIZE]);
    replay(&input);
}
