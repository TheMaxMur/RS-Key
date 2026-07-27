// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn reassembles_a_full_frame() {
    let mut payload = [0u8; PAYLOAD_SIZE];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = i as u8;
    }
    let reports = split_frame(&payload, 0x30);
    let mut rx = FrameRx::new();
    for r in &reports[..9] {
        assert_eq!(rx.feed(r), RxOutcome::None);
    }
    match rx.feed(&reports[9]) {
        RxOutcome::Frame { slot, payload: p } => {
            assert_eq!(slot, 0x30);
            assert_eq!(p, payload);
        }
        other => panic!("expected Frame, got {other:?}"),
    }
}

#[test]
fn rejects_corrupted_crc() {
    let payload = [0xAAu8; PAYLOAD_SIZE];
    let mut reports = split_frame(&payload, 1);
    reports[9][0] ^= 0xFF; // corrupt the last payload slice
    let mut rx = FrameRx::new();
    for r in &reports[..9] {
        rx.feed(r);
    }
    assert_eq!(rx.feed(&reports[9]), RxOutcome::BadCrc);
}

#[test]
fn reset_byte_clears_state() {
    let mut rx = FrameRx::new();
    let mut reset = [0u8; REPORT_SIZE];
    reset[REPORT_DATA] = FLAG_RESET;
    assert_eq!(rx.feed(&reset), RxOutcome::Reset);
}

#[test]
fn dummy_write_aborts_like_a_reset() {
    // `0x8f` — a write whose sequence is out of range — is the host's documented
    // "force update or abort" (ykpers sends it to cancel a challenge waiting for a
    // touch, and again to reset the read mode after collecting a response).
    let mut rx = FrameRx::new();
    let mut dummy = [0u8; REPORT_SIZE];
    dummy[REPORT_DATA] = FLAG_WRITE | 0x0F;
    assert_eq!(rx.feed(&dummy), RxOutcome::Reset);
}

#[test]
fn a_frame_interrupted_by_a_dummy_write_is_abandoned() {
    // The abort must not leave half a frame behind for the next transfer to
    // inherit: what follows it parses on its own or not at all.
    let payload = [0x5Au8; PAYLOAD_SIZE];
    let reports = split_frame(&payload, 0x30);
    let mut rx = FrameRx::new();
    for r in &reports[..5] {
        rx.feed(r);
    }
    let mut dummy = [0u8; REPORT_SIZE];
    dummy[REPORT_DATA] = FLAG_WRITE | 0x0F;
    assert_eq!(rx.feed(&dummy), RxOutcome::Reset);
    // Resuming mid-frame yields nothing; a frame sent from its start still lands.
    assert_eq!(rx.feed(&reports[9]), RxOutcome::BadCrc);
    for r in &reports[..9] {
        assert_eq!(rx.feed(r), RxOutcome::None);
    }
    assert!(matches!(
        rx.feed(&reports[9]),
        RxOutcome::Frame { slot: 0x30, .. }
    ));
}

#[test]
fn tx_streams_body_then_end_marker_and_host_crc_checks() {
    // A 20-byte response (an HMAC-SHA1 chal-resp) → 22 bytes with CRC → 4
    // data frames (7+7+7+1) + an end marker.
    let body: Vec<u8> = (0..20u8).collect();
    let mut tx = FrameTx::new();
    tx.load(&body);
    let mut got = Vec::new();
    let mut seqs = Vec::new();
    let mut out = [0u8; REPORT_SIZE];
    while tx.next(&mut out) {
        if out[REPORT_DATA] & SEQ_MASK == 0 && got.len() >= 22 {
            break; // end marker
        }
        got.extend_from_slice(&out[..REPORT_DATA]);
        seqs.push(out[REPORT_DATA]);
    }
    assert_eq!(seqs, [0x40, 0x41, 0x42, 0x43]);
    // The host validates payload ‖ CRC against the X.25 residual.
    assert_eq!(&got[..20], &body[..]);
    assert_eq!(crc16(&got[..22]), 0xF0B8);
    assert!(!tx.active());
}

#[test]
fn status_frame_layout() {
    let s = status_frame([5, 7, 4, 3, 0x01, 0, 0]);
    assert_eq!(s, [0, 5, 7, 4, 3, 0x01, 0, 0]);
}
