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

/// ykpers `yk_wait_for_key_status` reading a blocking challenge: it returns on
/// the response-pending bit, arms itself on the touch-wait bit, and once armed
/// takes any byte carrying neither as "the key timed out waiting for the user".
fn ykpers_abandons_challenge(statuses: &[u8]) -> bool {
    let mut armed = false;
    for &s in statuses {
        if s & FLAG_RESP_PENDING == FLAG_RESP_PENDING {
            return false;
        }
        if s & FLAG_TIMEOUT_WAIT == FLAG_TIMEOUT_WAIT {
            armed = true;
        } else if armed {
            return true;
        }
    }
    false
}

#[test]
fn a_satisfied_touch_never_reads_as_a_timeout() {
    let mut st = ProcessingStatus::new();
    // The worker has not requested presence yet, then the wait goes up, then the
    // press lands and the HMAC is computed before `finish_response` — the window
    // measured at 9 ms on Windows and 11 ms on macOS.
    let mut polled: Vec<u8> = (0..2).map(|_| st.poll(false)).collect();
    polled.extend((0..4).map(|_| st.poll(true)));
    polled.extend((0..3).map(|_| st.poll(false)));
    assert_eq!(
        polled,
        [0x10, 0x10, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20]
    );
    assert!(!ykpers_abandons_challenge(&polled));

    // The response replacing the status is what ends the wait.
    polled.push(FLAG_RESP_PENDING);
    assert!(!ykpers_abandons_challenge(&polled));
}

#[test]
fn an_expired_touch_wait_still_ends_promptly() {
    let mut st = ProcessingStatus::new();
    let mut polled: Vec<u8> = (0..3).map(|_| st.poll(true)).collect();
    polled.extend((0..2).map(|_| st.poll(false)));
    // The timeout drops the transport back to `Idle`, whose cached status frame
    // carries neither bit — that is what tells the host to give up, not a flicker
    // mid-command.
    polled.push(status_frame([5, 7, 4, 1, 0x0F, 0, 0])[REPORT_DATA]);
    assert!(ykpers_abandons_challenge(&polled));
}

#[test]
fn each_command_starts_with_a_fresh_wait() {
    let mut st = ProcessingStatus::new();
    assert_eq!(st.poll(true), 0x20);
    st.reset();
    assert_eq!(st.poll(false), 0x10);
}

// ---------------- the state machine ----------------

/// Write one whole host frame, report by report, and hand back the last outcome.
fn write_frame(hid: &mut OtpHid, slot: u8, payload: &[u8; PAYLOAD_SIZE]) -> SetOutcome {
    let mut last = SetOutcome::None;
    for report in split_frame(payload, slot) {
        last = hid.set_report(&report);
    }
    last
}

fn get(hid: &mut OtpHid, touch_pending: bool) -> [u8; REPORT_SIZE] {
    let mut out = [0u8; REPORT_SIZE];
    hid.get_report(&mut out, touch_pending);
    out
}

/// An idle device answers every poll with its status record. `ykman` reads the
/// firmware version and the slot bits out of exactly this.
#[test]
fn an_idle_poll_serves_the_status_frame() {
    let mut hid = OtpHid::new();
    hid.set_status(status_frame([5, 7, 4, 1, 0x0F, 0, 0]));
    assert_eq!(get(&mut hid, false), [0, 5, 7, 4, 1, 0x0F, 0, 0]);
}

/// A complete frame is handed over exactly once — a second `take_request` would
/// run the command twice, and for a slot-configure that is two program-sequence
/// bumps for one host write.
#[test]
fn a_complete_frame_is_taken_once() {
    let mut hid = OtpHid::new();
    let mut payload = [0u8; PAYLOAD_SIZE];
    payload[..4].copy_from_slice(b"ping");
    assert_eq!(write_frame(&mut hid, 0x38, &payload), SetOutcome::Frame);
    assert_eq!(hid.take_request(), Some((0x38, payload)));
    assert_eq!(hid.take_request(), None);
}

/// The payload copy left behind is wiped: a slot-configure frame carries the AES
/// key, the private UID and the access code.
#[test]
fn taking_a_request_leaves_no_copy_of_its_payload() {
    let mut hid = OtpHid::new();
    let payload = [0xA5u8; PAYLOAD_SIZE];
    write_frame(&mut hid, 1, &payload);
    hid.take_request().unwrap();
    assert!(hid.req_payload.iter().all(|&b| b == 0));
}

/// While the command runs the host is told "working", and once a touch is
/// outstanding it is told "waiting" — and *keeps* being told so after the press,
/// because ykpers reads any other byte as the challenge having timed out.
#[test]
fn a_running_command_reports_working_then_latches_the_touch_wait() {
    let mut hid = OtpHid::new();
    write_frame(&mut hid, 0x38, &[0; PAYLOAD_SIZE]);
    assert_eq!(get(&mut hid, false)[REPORT_DATA], 0x10);
    assert_eq!(get(&mut hid, true)[REPORT_DATA], 0x20);
    assert_eq!(
        get(&mut hid, false)[REPORT_DATA],
        0x20,
        "the press must not un-announce the wait"
    );
}

/// A response is streamed back and then gives way to the refreshed status — the
/// host reads the end marker, polls once more, and must see the new record
/// rather than a repeat of the response.
#[test]
fn a_response_streams_then_falls_back_to_the_new_status() {
    let mut hid = OtpHid::new();
    write_frame(&mut hid, 0x38, &[0; PAYLOAD_SIZE]);
    hid.take_request().unwrap();
    let status = status_frame([5, 7, 4, 2, 0x0F, 0, 0]);
    hid.finish_response(status, &[0xEE; 20]);

    // 20 bytes + the 2-byte CRC suffix = 4 slices of at most 7, then the
    // end-of-response marker: sequence bits zero with the pending bit still set.
    let slices: Vec<[u8; REPORT_SIZE]> = (0..4).map(|_| get(&mut hid, false)).collect();
    for (seq, r) in slices.iter().enumerate() {
        assert_eq!(r[REPORT_DATA], 0x40 | seq as u8);
    }
    assert_eq!(slices[0][..7], [0xEE; 7]);
    assert_eq!(get(&mut hid, false), [0, 0, 0, 0, 0, 0, 0, 0x40]);
    assert_eq!(get(&mut hid, false), status);
}

/// A command with nothing to return — a configure or a swap — goes straight back
/// to idle with the status the bump produced.
#[test]
fn an_empty_response_goes_idle_with_the_bumped_status() {
    let mut hid = OtpHid::new();
    write_frame(&mut hid, 1, &[0; PAYLOAD_SIZE]);
    hid.take_request().unwrap();
    let status = status_frame([5, 7, 4, 3, 0x0F, 0, 0]);
    hid.finish_response(status, &[]);
    assert_eq!(get(&mut hid, false), status);
}

/// A frame that arrived while the previous command was still running keeps the
/// transport in "working": flashing the idle status at the host between the two
/// reads as the second command never having been accepted.
#[test]
fn a_frame_queued_mid_command_does_not_flash_idle() {
    let mut hid = OtpHid::new();
    write_frame(&mut hid, 1, &[0; PAYLOAD_SIZE]);
    hid.take_request().unwrap();
    write_frame(&mut hid, 2, &[0; PAYLOAD_SIZE]);
    hid.finish_response(status_frame([5, 7, 4, 3, 0, 0, 0]), &[]);
    assert_eq!(get(&mut hid, false)[REPORT_DATA], 0x10);
}

/// Both a frame and a reset end a touch wait the previous command started; a
/// partial frame ends nothing. This is the KeePassXC case (0x085B): a host that
/// meets the wait and moves on must get the device back.
#[test]
fn a_frame_or_a_reset_ends_a_pending_touch_wait() {
    assert!(SetOutcome::Frame.ends_touch_wait());
    assert!(SetOutcome::Reset.ends_touch_wait());
    assert!(!SetOutcome::None.ends_touch_wait());

    let mut hid = OtpHid::new();
    assert_eq!(hid.set_report(&[0; 7].map(|_| 0)), SetOutcome::None);
    assert_eq!(
        hid.set_report(&[0, 0, 0, 0, 0, 0, 0, 0xFF]),
        SetOutcome::Reset
    );
    // The dummy write ykpers sends (`0x8f` — an out-of-range sequence) too.
    assert_eq!(
        hid.set_report(&[0, 0, 0, 0, 0, 0, 0, 0x8F]),
        SetOutcome::Reset
    );
}

/// A reset drops a response still being streamed. Serving the rest of it to the
/// host that just abandoned the transfer splices one command's answer onto the
/// next.
#[test]
fn a_reset_drops_a_response_in_flight() {
    let mut hid = OtpHid::new();
    let status = status_frame([5, 7, 4, 1, 0, 0, 0]);
    hid.set_status(status);
    write_frame(&mut hid, 0x38, &[0; PAYLOAD_SIZE]);
    hid.take_request().unwrap();
    hid.finish_response(status, &[0xEE; 20]);
    hid.set_report(&[0, 0, 0, 0, 0, 0, 0, 0xFF]);
    assert_eq!(get(&mut hid, false), status);
}

/// The scrub reaches the response buffer, not just the reassembly one: a
/// challenge-response body with a fixed challenge (yubikey-luks) *is* the
/// credential, and nothing else clears it.
#[test]
fn the_scrub_reaches_the_response_body() {
    let mut hid = OtpHid::new();
    write_frame(&mut hid, 0x38, &[0; PAYLOAD_SIZE]);
    hid.take_request().unwrap();
    hid.finish_response(status_frame([5, 7, 4, 1, 0, 0, 0]), &[0xEE; 20]);
    hid.scrub();
    assert!(!hid.tx.active());
    let mut out = [0u8; REPORT_SIZE];
    assert!(!hid.tx.next(&mut out));
}
