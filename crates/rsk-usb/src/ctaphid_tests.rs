// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// Build an INIT report: cid | cmd | bcnt_hi | bcnt_lo | data...
fn init_frame(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    f[0..4].copy_from_slice(&cid.to_le_bytes());
    f[4] = cmd;
    f[5] = (bcnt >> 8) as u8;
    f[6] = (bcnt & 0xff) as u8;
    let n = data.len().min(INIT_DATA);
    f[7..7 + n].copy_from_slice(&data[..n]);
    f
}

// Build a CONT report: cid | seq | data...
fn cont_frame(cid: u32, seq: u8, data: &[u8]) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    f[0..4].copy_from_slice(&cid.to_le_bytes());
    f[4] = seq & !TYPE_INIT;
    let n = data.len().min(CONT_DATA);
    f[5..5 + n].copy_from_slice(&data[..n]);
    f
}

#[test]
fn single_frame_init() {
    let mut asm = Reassembler::new();
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let out = asm.feed(&init_frame(CID_BROADCAST, CTAPHID_INIT, 8, &nonce));
    assert_eq!(out, Outcome::Message(CID_BROADCAST, CTAPHID_INIT));
    assert_eq!(asm.message(), &nonce);
}

#[test]
fn single_frame_ping() {
    let mut asm = Reassembler::new();
    let payload = [0xAA; 20];
    let out = asm.feed(&init_frame(0x0100_0000, CTAPHID_PING, 20, &payload));
    assert_eq!(out, Outcome::Message(0x0100_0000, CTAPHID_PING));
    assert_eq!(asm.message(), &payload);
}

#[test]
fn multi_frame_reassembly() {
    let mut asm = Reassembler::new();
    let cid = 0x0100_0000;
    // 57 (INIT) + 59 (CONT0) + 10 (CONT1) = 126 bytes.
    let mut payload = [0u8; 126];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING, 126, &payload[..INIT_DATA])),
        Outcome::None
    );
    assert_eq!(
        asm.feed(&cont_frame(
            cid,
            0,
            &payload[INIT_DATA..INIT_DATA + CONT_DATA]
        )),
        Outcome::None
    );
    assert_eq!(
        asm.feed(&cont_frame(cid, 1, &payload[INIT_DATA + CONT_DATA..])),
        Outcome::Message(cid, CTAPHID_PING)
    );
    assert_eq!(asm.message(), &payload);
}

#[test]
fn zero_length_message() {
    let mut asm = Reassembler::new();
    let out = asm.feed(&init_frame(0x0100_0000, CTAPHID_WINK, 0, &[]));
    assert_eq!(out, Outcome::Message(0x0100_0000, CTAPHID_WINK));
    assert_eq!(asm.message(), &[] as &[u8]);
}

#[test]
fn scrub_wipes_message_and_next_message_still_works() {
    let mut asm = Reassembler::new();
    let cid = 0x0100_0000;
    let secret = [0x5A; 32];
    asm.feed(&init_frame(cid, CTAPHID_CBOR, 32, &secret));
    assert_eq!(asm.message(), &secret);
    asm.scrub();
    assert!(asm.message().is_empty());
    // The buffer behind the old message is zeroed, not just hidden.
    assert!(asm.msg[..32].iter().all(|&b| b == 0));
    // A fresh message reassembles normally after a scrub.
    let next = [0xC3; 16];
    let out = asm.feed(&init_frame(cid, CTAPHID_PING, 16, &next));
    assert_eq!(out, Outcome::Message(cid, CTAPHID_PING));
    assert_eq!(asm.message(), &next);
}

#[test]
fn invalid_channel_zero() {
    let mut asm = Reassembler::new();
    let out = asm.feed(&init_frame(0, CTAPHID_PING, 0, &[]));
    assert_eq!(out, Outcome::Error(0, ERR_INVALID_CHANNEL));
}

#[test]
fn broadcast_non_init_rejected() {
    let mut asm = Reassembler::new();
    let out = asm.feed(&init_frame(CID_BROADCAST, CTAPHID_PING, 0, &[]));
    assert_eq!(out, Outcome::Error(CID_BROADCAST, ERR_INVALID_CHANNEL));
}

#[test]
fn bcnt_too_large() {
    let mut asm = Reassembler::new();
    // Header claims more than CTAP_MAX_MESSAGE (7609 < 0xFFFF).
    let out = asm.feed(&init_frame(0x0100_0000, CTAPHID_PING, 0xFFFF, &[]));
    assert_eq!(out, Outcome::Error(0x0100_0000, ERR_INVALID_LEN));
}

#[test]
fn stray_cont_ignored() {
    let mut asm = Reassembler::new();
    let out = asm.feed(&cont_frame(0x0100_0000, 0, &[1, 2, 3]));
    assert_eq!(out, Outcome::None);
}

#[test]
fn wrong_seq_aborts() {
    let mut asm = Reassembler::new();
    let cid = 0x0100_0000;
    let payload = [7u8; 100];
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING, 100, &payload[..INIT_DATA])),
        Outcome::None
    );
    // Expected seq is 0; send 1.
    assert_eq!(
        asm.feed(&cont_frame(cid, 1, &payload[INIT_DATA..])),
        Outcome::Error(cid, ERR_INVALID_SEQ)
    );
    // Transaction aborted: a further CONT is now stray.
    assert_eq!(
        asm.feed(&cont_frame(cid, 1, &payload[INIT_DATA..])),
        Outcome::None
    );
}

#[test]
fn init_frame_mid_transaction_is_invalid_seq() {
    let mut asm = Reassembler::new();
    let cid = 0x0100_0000;
    let payload = [0xABu8; INIT_DATA];
    // Start a 200-byte PING (needs continuations).
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING, 200, &payload)),
        Outcome::None
    );
    assert!(asm.in_progress());
    // A non-INIT init-type frame on the same channel where a CONT was expected
    // → INVALID_SEQ, and the transaction is aborted.
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING, 200, &payload)),
        Outcome::Error(cid, ERR_INVALID_SEQ)
    );
    assert!(!asm.in_progress());
    // CTAPHID_INIT mid-transaction resyncs instead of erroring.
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING, 200, &payload)),
        Outcome::None
    );
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_INIT, 8, &[1u8; 8])),
        Outcome::Message(cid, CTAPHID_INIT)
    );
}

#[test]
fn midtx_init_type_frame_with_oversized_bcnt_is_seq_error() {
    // FIDO conformance HID-1 F-4: the tool corrupts the LAST continuation
    // frame's seq byte to CTAPHID_PING+1 (0x82) — an init-type frame mid-
    // transaction. Its "bcnt" is then random payload bytes; when they exceed
    // CTAP_MAX_MESSAGE (most runs) a length-first order wrongly answered
    // ERR_INVALID_LEN. The out-of-sequence error must win over the bcnt check.
    let mut asm = Reassembler::new();
    let cid = 0x0100_0000;
    let payload = [0xABu8; INIT_DATA];
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING, 1024, &payload)),
        Outcome::None
    );
    // 0x82 = CTAPHID_PING + 1 (INIT bit set); bcnt = 0xFFFF, well over the max.
    assert_eq!(
        asm.feed(&init_frame(cid, CTAPHID_PING + 1, 0xFFFF, &[])),
        Outcome::Error(cid, ERR_INVALID_SEQ)
    );
    assert!(!asm.in_progress());
}

#[test]
fn keepalive_status_suppresses_processing_for_u2f_msg() {
    // FIDO conformance U2F-Authenticate P-3 / F-2: a PROCESSING keepalive
    // before a fast U2F MSG response desyncs the host, so MSG stays silent
    // unless a touch is pending. CBOR keeps PROCESSING for slow CTAP2 ops.
    assert_eq!(keepalive_status(false, false), None); // U2F fast op — stay silent
    assert_eq!(keepalive_status(false, true), Some(STATUS_UPNEEDED)); // U2F touch wait
    assert_eq!(keepalive_status(true, false), Some(STATUS_PROCESSING)); // CBOR slow op
    assert_eq!(keepalive_status(true, true), Some(STATUS_UPNEEDED)); // CBOR touch wait
}

#[test]
fn cancel_frame_detected_only_for_active_channel() {
    // FIDO conformance HID-1 P-10/P-15: a CTAPHID_CANCEL on the channel whose
    // request is in flight aborts the worker's touch wait. Anything else read
    // mid-request is ignored.
    let cid = 0x0100_0000;
    let cancel = init_frame(cid, CTAPHID_CANCEL, 0, &[]);
    assert!(is_cancel_frame(&cancel, HID_RPT_SIZE, cid));
    // A CANCEL for a different channel is not ours to act on.
    assert!(!is_cancel_frame(&cancel, HID_RPT_SIZE, 0x0200_0000));
    // A different command on the active channel is not a cancel.
    assert!(!is_cancel_frame(
        &init_frame(cid, CTAPHID_PING, 0, &[]),
        HID_RPT_SIZE,
        cid
    ));
    // A short read (< 5 bytes) carries no command byte → ignored.
    assert!(!is_cancel_frame(&cancel, 4, cid));
}

#[test]
fn cont_wrong_cid_busy() {
    let mut asm = Reassembler::new();
    let payload = [7u8; 100];
    assert_eq!(
        asm.feed(&init_frame(
            0x0100_0000,
            CTAPHID_PING,
            100,
            &payload[..INIT_DATA]
        )),
        Outcome::None
    );
    let out = asm.feed(&cont_frame(0x0200_0000, 0, &payload[INIT_DATA..]));
    assert_eq!(out, Outcome::Error(0x0200_0000, ERR_CHANNEL_BUSY));
}

#[test]
fn init_other_channel_busy() {
    let mut asm = Reassembler::new();
    let payload = [7u8; 100];
    // Start a multi-frame transaction on channel A.
    assert_eq!(
        asm.feed(&init_frame(
            0x0100_0000,
            CTAPHID_PING,
            100,
            &payload[..INIT_DATA]
        )),
        Outcome::None
    );
    // A non-INIT command on channel B while busy → busy.
    assert_eq!(
        asm.feed(&init_frame(0x0200_0000, CTAPHID_PING, 0, &[])),
        Outcome::Error(0x0200_0000, ERR_CHANNEL_BUSY)
    );
    // But INIT itself on channel B is allowed (resyncs).
    let nonce = [9u8; 8];
    assert_eq!(
        asm.feed(&init_frame(0x0200_0000, CTAPHID_INIT, 8, &nonce)),
        Outcome::Message(0x0200_0000, CTAPHID_INIT)
    );
}

#[test]
fn max_length_message() {
    let mut asm = Reassembler::new();
    let cid = 0x0100_0000;
    let payload = [0x5Au8; CTAP_MAX_MESSAGE];
    let mut out = asm.feed(&init_frame(
        cid,
        CTAPHID_PING,
        CTAP_MAX_MESSAGE as u16,
        &payload[..INIT_DATA],
    ));
    assert_eq!(out, Outcome::None);
    let mut off = INIT_DATA;
    let mut seq = 0u8;
    while off < CTAP_MAX_MESSAGE {
        let end = (off + CONT_DATA).min(CTAP_MAX_MESSAGE);
        out = asm.feed(&cont_frame(cid, seq, &payload[off..end]));
        off = end;
        seq = seq.wrapping_add(1);
    }
    assert_eq!(out, Outcome::Message(cid, CTAPHID_PING));
    assert_eq!(asm.message().len(), CTAP_MAX_MESSAGE);
    assert!(asm.message().iter().all(|&b| b == 0x5A));
}

#[test]
fn tx_single_frame() {
    let data = [0xAB; 10];
    let frames: Vec<_> = TxFrames::new(0x0100_0000, CTAPHID_PING, &data).collect();
    assert_eq!(frames.len(), 1);
    let f = &frames[0];
    assert_eq!(u32::from_le_bytes([f[0], f[1], f[2], f[3]]), 0x0100_0000);
    assert_eq!(f[4], CTAPHID_PING);
    assert_eq!(((f[5] as usize) << 8) | f[6] as usize, 10);
    assert_eq!(&f[7..17], &data);
}

#[test]
fn tx_empty_still_emits_init() {
    let frames: Vec<_> = TxFrames::new(0x0100_0000, CTAPHID_WINK, &[]).collect();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][4], CTAPHID_WINK);
    assert_eq!(frames[0][5], 0);
    assert_eq!(frames[0][6], 0);
}

#[test]
fn tx_multi_frame_seq_increments() {
    let data = [0xCD; 200];
    let frames: Vec<_> = TxFrames::new(0x0100_0000, CTAPHID_MSG, &data).collect();
    // 200 = 57 (INIT) + 59 + 59 + 25 → 4 frames.
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0][4], CTAPHID_MSG);
    assert_eq!(frames[1][4], 0); // seq 0
    assert_eq!(frames[2][4], 1); // seq 1
    assert_eq!(frames[3][4], 2); // seq 2
}

// Drive every payload length through TX framing then RX reassembly.
#[test]
fn roundtrip() {
    for &len in &[0usize, 1, 56, 57, 58, 116, 200, 1000, CTAP_MAX_MESSAGE] {
        let cid = 0x0100_0000;
        let cmd = CTAPHID_PING;
        let mut data = [0u8; CTAP_MAX_MESSAGE];
        for (i, b) in data[..len].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut asm = Reassembler::new();
        let mut last = Outcome::None;
        for frame in TxFrames::new(cid, cmd, &data[..len]) {
            last = asm.feed(&frame);
        }
        assert_eq!(last, Outcome::Message(cid, cmd), "len={len}");
        assert_eq!(asm.message(), &data[..len], "len={len}");
    }
}

// ---- TX abandon-on-stall: regression guard for the USB-wedge fix (63cde79) ----

// Bounded manual poll with a no-op waker: returns None if `fut` is still
// pending after `max_polls`, so a TX path that fails to abandon a stalled
// frame surfaces as a failed assertion instead of hanging the test runner.
fn poll_bounded<F: core::future::Future>(fut: F, max_polls: usize) -> Option<F::Output> {
    use core::task::{Context, Poll};
    let mut cx = Context::from_waker(core::task::Waker::noop());
    let mut fut = core::pin::pin!(fut);
    for _ in 0..max_polls {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

// A sink whose every frame write never completes — models the host that has
// stopped draining the IN endpoint (the wedge condition).
struct StallSink {
    attempts: usize,
}
impl FrameSink for StallSink {
    async fn write_frame(&mut self, _frame: &[u8; HID_RPT_SIZE]) {
        self.attempts += 1;
        core::future::pending::<()>().await
    }
}

// A sink that accepts every frame immediately — models a host that keeps draining.
struct CountingSink {
    written: usize,
}
impl FrameSink for CountingSink {
    async fn write_frame(&mut self, _frame: &[u8; HID_RPT_SIZE]) {
        self.written += 1;
    }
}

#[test]
fn write_frames_abandons_when_host_stalls() {
    let mut sink = StallSink { attempts: 0 };
    let data = [0xAB; 200]; // multi-frame: a non-abandoning path would attempt >1 frame
    // Timeout is always ready, so the stalled write must lose the race and the
    // response is abandoned after the very first undeliverable frame.
    let done = poll_bounded(
        write_frames(&mut sink, 0x0100_0000, CTAPHID_PING, &data, || {
            core::future::ready(())
        }),
        10_000,
    );
    assert!(
        done.is_some(),
        "write_frames hung on a stalled host — the IN-endpoint timeout no longer abandons the write (USB-wedge regression)"
    );
    assert_eq!(
        sink.attempts, 1,
        "must abandon after the first stalled frame, not keep retrying"
    );
}

#[test]
fn write_frames_writes_every_frame_when_host_drains() {
    let mut sink = CountingSink { written: 0 };
    let data = [0xCD; 200]; // 57 + 59 + 59 + 25 → 4 frames
    // Timeout never fires, so each write wins its race and all frames go out.
    let done = poll_bounded(
        write_frames(&mut sink, 0x0100_0000, CTAPHID_MSG, &data, || {
            core::future::pending::<()>()
        }),
        10_000,
    );
    assert!(done.is_some(), "write_frames stalled with a draining host");
    assert_eq!(
        sink.written, 4,
        "every frame written when the host keeps draining"
    );
}

/// §11.2.9.1.3: each broadcast INIT allocates a *unique* channel — two applications
/// sharing an id would let either resynchronise the other's transaction. The counter
/// steps over the two reserved values as it wraps.
#[test]
fn cid_allocator_hands_out_unique_ids() {
    let mut a = CidAllocator::new();
    let first = a.next();
    let second = a.next();
    assert_ne!(first, second);
    assert_eq!(second, first + 1);

    // Wrapping skips 0 and the broadcast id.
    let mut a = CidAllocator(u32::MAX - 1);
    assert_eq!(a.next(), u32::MAX - 1);
    assert_eq!(a.next(), FIRST_CID, "0xffffffff is the broadcast CID");
    let mut a = CidAllocator(CID_BROADCAST);
    a.next();
    assert_eq!(a.next(), FIRST_CID, "0 is not a valid CID either");
}

/// §11.2.9.2.2: while a channel holds the lock, other channels are turned away; the
/// lock expires on its own so a crashed application cannot hold the device, and only
/// its owner can hand it back early.
#[test]
fn channel_lock_excludes_other_channels_until_it_expires() {
    let mut lock = ChannelLock::default();
    let (mine, theirs) = (0x0100_0000, 0x0100_0001);
    assert!(!lock.blocks(theirs, 0), "no lock, no exclusion");

    lock.arm(mine, 2, 1_000);
    assert!(lock.blocks(theirs, 1_500));
    assert!(!lock.blocks(mine, 1_500), "the owner is never blocked");
    // Two seconds on: expired.
    assert!(!lock.blocks(theirs, 3_000));

    // A release by a non-owner is not theirs to give.
    lock.arm(mine, 10, 10_000);
    lock.arm(theirs, 0, 10_100);
    assert!(lock.blocks(theirs, 10_200), "only the owner may release");
    lock.arm(mine, 0, 10_300);
    assert!(!lock.blocks(theirs, 10_400));
}
