// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn record(kind: u8, seq: u8, capacity: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![u8::try_from(HEADER + body.len()).unwrap(), kind];
    record.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    record.extend_from_slice(&[0, seq, 0, capacity, 0]);
    record.extend_from_slice(body);
    record
}

#[test]
fn short_buffers_and_power_transitions_reach_the_framing_oracles() {
    for capacity in [0, 1, 9, 10, 11, 20] {
        let sequence: Vec<_> = [0x62, 0x65, 0x6C, 0x63, 0x73, 0xFF]
            .into_iter()
            .flat_map(|kind| record(kind, 0x71, capacity, &[]))
            .collect();
        replay(&sequence);
    }
}

#[test]
fn xfr_and_secure_ranges_are_exercised_at_the_header_boundary() {
    for capacity in [0, 9, 10] {
        for kind in [0x6F, 0x69] {
            for body in [&[][..], &[0, 0xA4, 4][..], &[0, 0xA4, 4, 0][..]] {
                let mut input = record(kind, 0x71, capacity, body);
                replay(&input);
                input[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
                replay(&input);
            }
        }
    }
}

#[test]
fn truncated_records_cannot_escape_the_input_or_output_buffer() {
    let sequence = record(0x6F, 0x71, 0, &[0, 0xA4, 4, 0]);
    for end in 0..sequence.len() {
        replay(&sequence[..end]);
    }
}
