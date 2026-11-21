// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn drain(tx: &mut FrameTx, body: &[u8]) {
    let body = &body[..body.len().min(PAYLOAD_SIZE)];
    let total = body.len() + 2;
    let reports = total.div_ceil(REPORT_DATA);
    let mut wire = Vec::new();
    for seq in 0..reports {
        assert!(tx.active(), "inactive before data report {seq}");
        let mut out = [0xAA; REPORT_SIZE];
        assert!(tx.next(&mut out));
        assert_eq!(out[REPORT_DATA], FLAG_RESP_PENDING | seq as u8);
        let copied = (total - wire.len()).min(REPORT_DATA);
        wire.extend_from_slice(&out[..copied]);
        assert_eq!(&out[copied..REPORT_DATA], &vec![0; REPORT_DATA - copied]);
        assert!(tx.active(), "inactive before the end marker");
    }
    assert_eq!(&wire[..body.len()], body);
    assert_eq!(crc16(&wire), 0xF0B8);
    let mut end = [0xAA; REPORT_SIZE];
    assert!(tx.next(&mut end));
    assert_eq!(end[..REPORT_DATA], [0; REPORT_DATA]);
    assert_eq!(end[REPORT_DATA], FLAG_RESP_PENDING);
    assert!(!tx.active());
    for _ in 0..2 {
        let mut out = [0xAA; REPORT_SIZE];
        assert!(!tx.next(&mut out));
        assert_eq!(out, [0xAA; REPORT_SIZE]);
        assert!(!tx.active());
    }
}

#[test]
fn every_body_length_stays_active_through_the_end_marker() {
    for len in 0..=FRAME_SIZE + 2 {
        let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut tx = FrameTx::new();
        assert!(!tx.active());
        tx.load(&body);
        drain(&mut tx, &body);
    }
}

#[test]
fn a_reload_at_every_report_boundary_replaces_the_entire_response() {
    for old_len in 0..=PAYLOAD_SIZE {
        let old = vec![0xD3; old_len];
        let reports = (old_len + 2).div_ceil(REPORT_DATA);
        for consumed in 0..=reports + 1 {
            for len in [
                0,
                1,
                5,
                6,
                7,
                20,
                PAYLOAD_SIZE - 1,
                PAYLOAD_SIZE,
                FRAME_SIZE,
            ] {
                let mut tx = FrameTx::new();
                tx.load(&old);
                for _ in 0..consumed {
                    assert!(tx.next(&mut [0; REPORT_SIZE]));
                }
                let replacement: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x39).collect();
                tx.load(&replacement);
                drain(&mut tx, &replacement);
            }
        }
    }
}
