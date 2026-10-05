// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "the proof checks its bounded fixture indexes before using them"
)]

use super::*;

// CRC arithmetic is outside these transport proofs; the suffix is still copied
// by the real load/next path. Fuzz and host tests check the actual CRC residual.
fn stub_crc16(_: &[u8]) -> u16 {
    0
}

fn poll(tx: &mut FrameTx, body: &[u8], step: usize) {
    let n = body.len().min(PAYLOAD_SIZE);
    let total = n + 2;
    let reports = total.div_ceil(REPORT_DATA);
    let mut out = [0xA5; REPORT_SIZE];
    if step < reports {
        let offset = step * REPORT_DATA;
        let copied = (total - offset).min(REPORT_DATA);
        assert!(tx.remaining == total - offset && usize::from(tx.seq) == step);
        assert!(usize::from(tx.expected) == reports);
        assert!(out.get(..copied).is_some());
        assert!(tx.buf.get(offset..offset + copied).is_some());
        assert!(tx.active() && tx.next(&mut out));
        assert!(out[REPORT_DATA] == FLAG_RESP_PENDING | step as u8);
        for (i, byte) in out[..REPORT_DATA].iter().enumerate() {
            let position = offset + i;
            let expected = if position < n {
                body[position]
            } else if position < total {
                0xFF
            } else {
                0
            };
            assert!(*byte == expected, "response bytes or padding changed");
        }
        assert!(tx.active(), "the end marker must remain pending");
    } else if step == reports {
        assert!(tx.remaining == 0 && tx.seq == tx.expected && tx.expected > 0);
        assert!(tx.active() && tx.next(&mut out));
        assert!(out[..REPORT_DATA] == [0; REPORT_DATA]);
        assert!(out[REPORT_DATA] == FLAG_RESP_PENDING && !tx.active());
    } else {
        assert!(!tx.active() && !tx.next(&mut out));
        assert!(out == [0xA5; REPORT_SIZE]);
    }
}

#[kani::proof]
#[kani::unwind(73)]
#[kani::stub(crate::crc16, stub_crc16)]
fn load_poll_and_reload_keep_response_bounds() {
    let old: [u8; FRAME_SIZE + 2] = kani::any();
    let old_len: u8 = kani::any();
    kani::assume(usize::from(old_len) <= old.len());
    let old = &old[..usize::from(old_len)];
    let old_reports = (old.len().min(PAYLOAD_SIZE) + 2).div_ceil(REPORT_DATA);
    let consumed: u8 = kani::any();
    kani::assume(usize::from(consumed) <= old_reports + 1);
    let replacement: [u8; FRAME_SIZE + 2] = kani::any();
    let len: u8 = kani::any();
    kani::assume(usize::from(len) <= replacement.len());
    kani::cover!(len == 0, "empty replacement");
    kani::cover!(usize::from(len) > PAYLOAD_SIZE, "capped replacement");
    kani::cover!(
        usize::from(consumed) == old_reports,
        "replace before the marker"
    );
    kani::cover!(
        usize::from(consumed) == old_reports + 1,
        "replace after the marker"
    );

    let mut tx = FrameTx::new();
    tx.load(old);
    let steps = (PAYLOAD_SIZE + 2).div_ceil(REPORT_DATA) + 3;
    for step in 0..steps {
        if step < usize::from(consumed) {
            poll(&mut tx, old, step);
        }
    }
    let body = &replacement[..usize::from(len)];
    tx.load(body);
    let reports = (body.len().min(PAYLOAD_SIZE) + 2).div_ceil(REPORT_DATA);
    for step in 0..steps {
        if step < reports + 3 {
            poll(&mut tx, body, step);
        }
    }
}

#[kani::proof]
#[kani::unwind(73)]
#[kani::stub(crate::crc16, stub_crc16)]
fn one_rx_report_respects_sequence_bounds_and_release() {
    let report: [u8; REPORT_SIZE] = kani::any();
    let flag = report[REPORT_DATA];
    let seq = usize::from(flag & SEQ_MASK);
    kani::cover!(flag == FLAG_WRITE, "first data report");
    kani::cover!(flag == FLAG_WRITE | 9, "last data report");
    kani::cover!(flag == FLAG_RESET, "reset report");
    let mut rx = FrameRx::new();
    let mut out = Secret::new([0xA5; PAYLOAD_SIZE]);
    if flag & FLAG_WRITE != 0 && seq <= 9 {
        assert!(rx.buf.expose().chunks_exact(REPORT_DATA).nth(seq).is_some());
    }
    let result = rx.feed(&report, &mut out);
    if flag == FLAG_RESET || flag & FLAG_WRITE != 0 && seq > 9 {
        assert!(result == RxOutcome::Reset);
    } else if flag & FLAG_WRITE == 0 || seq != 9 {
        assert!(result == RxOutcome::None);
    } else if report[2] == 0 && report[3] == 0 {
        assert!(result == RxOutcome::Frame { slot: report[1] });
        assert!(out.expose()[..PAYLOAD_SIZE - 1] == [0; PAYLOAD_SIZE - 1]);
        assert!(out.expose()[PAYLOAD_SIZE - 1] == report[0]);
    } else {
        assert!(result == RxOutcome::BadCrc);
    }
    if !matches!(result, RxOutcome::Frame { .. }) {
        assert!(*out.expose() == [0xA5; PAYLOAD_SIZE]);
    }
    if result != RxOutcome::None {
        assert!(*rx.buf.expose() == [0; FRAME_SIZE]);
    }
}
