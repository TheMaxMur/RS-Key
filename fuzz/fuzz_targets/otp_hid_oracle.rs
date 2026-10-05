// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_otp::hid::{FrameRx, FrameTx, PAYLOAD_SIZE, REPORT_DATA, REPORT_SIZE, RxOutcome};
use rsk_secret::Secret;

const RESPONSE_PENDING: u8 = 0x40;
const SENTINEL: u8 = 0xA5;
const CRC_RESIDUAL: u16 = 0xF0B8;
const CRC_POLYNOMIAL: u16 = 0x8408;
const RESPONSE_MAX: usize = PAYLOAD_SIZE + 2;
const DATA_REPORTS_MAX: usize = RESPONSE_MAX.div_ceil(REPORT_DATA);

fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(u16::MAX, |mut crc, byte| {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ ((crc & 1).wrapping_neg() & CRC_POLYNOMIAL);
        }
        crc
    })
}

fn poll(tx: &mut FrameTx, wire: &[u8], step: usize) {
    let reports = wire.len().div_ceil(REPORT_DATA);
    let mut out = [SENTINEL; REPORT_SIZE];
    if step < reports {
        assert!(tx.active(), "inactive before response data");
        assert!(tx.next(&mut out), "response data missing");
        assert_eq!(out[REPORT_DATA], RESPONSE_PENDING | step as u8);
        let offset = step * REPORT_DATA;
        let n = (wire.len() - offset).min(REPORT_DATA);
        assert_eq!(&out[..n], &wire[offset..offset + n]);
        assert!(out[n..REPORT_DATA].iter().all(|byte| *byte == 0));
        assert!(tx.active(), "inactive before the end marker");
    } else if step == reports {
        assert!(tx.active(), "end marker lost its pending state");
        assert!(tx.next(&mut out), "end marker missing");
        assert_eq!(out[..REPORT_DATA], [0; REPORT_DATA]);
        assert_eq!(out[REPORT_DATA], RESPONSE_PENDING);
        assert!(!tx.active(), "active after the end marker");
    } else {
        assert!(!tx.active(), "exhausted response is active");
        assert!(!tx.next(&mut out), "extra response report");
        assert_eq!(out, [SENTINEL; REPORT_SIZE]);
    }
}

fn response(tx: &mut FrameTx, body: &[u8], polls: usize) {
    tx.load(body);
    let body = &body[..body.len().min(PAYLOAD_SIZE)];
    let total = body.len() + 2;
    let mut wire = Secret::<[u8; RESPONSE_MAX]>::zeroed();
    wire.expose_mut()[..body.len()].copy_from_slice(body);
    wire.expose_mut()[body.len()..total].copy_from_slice(&(!crc16(body)).to_le_bytes());
    assert_eq!(crc16(&wire.expose()[..total]), CRC_RESIDUAL);
    for step in 0..polls {
        poll(tx, &wire.expose()[..total], step);
    }
}

pub fn replay(data: &[u8]) {
    let mut rx = FrameRx::new();
    let mut payload = Secret::<[u8; PAYLOAD_SIZE]>::zeroed();
    let mut tx = FrameTx::new();
    for chunk in data.chunks(REPORT_SIZE) {
        let mut report = [0u8; REPORT_SIZE];
        report[..chunk.len()].copy_from_slice(chunk);
        let before = Secret::new(*payload.expose());
        match rx.feed(&report, &mut payload) {
            RxOutcome::Frame { slot: _ } => {
                response(&mut tx, payload.expose(), DATA_REPORTS_MAX + 3);
            }
            RxOutcome::None | RxOutcome::Reset | RxOutcome::BadCrc => {
                assert_eq!(
                    *payload.expose(),
                    *before.expose(),
                    "refused RX report released bytes"
                );
            }
        }
    }
    response(&mut tx, &[], DATA_REPORTS_MAX + 3);
    let mut rest = data;
    while let Some((&length, tail)) = rest.split_first() {
        let Some((&polls, tail)) = tail.split_first() else {
            break;
        };
        let n = usize::from(length).min(tail.len());
        response(
            &mut tx,
            &tail[..n],
            usize::from(polls) % (DATA_REPORTS_MAX + 3),
        );
        rest = &tail[n..];
    }
    response(&mut tx, &[], DATA_REPORTS_MAX + 3);
}

#[cfg(test)]
#[path = "otp_hid_oracle_tests.rs"]
mod tests;
