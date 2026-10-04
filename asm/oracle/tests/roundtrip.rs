// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

// Host-side property tests over the CTAPHID TX→RX round trip: frames from
// TxFrames fed one-by-one into a fresh Reassembler must yield exactly one
// Outcome::Message with a byte-identical payload, nothing else terminal.
//
// Two rsk-usb behaviours observed while building this (2026-10-02, oracle +
// byte-level repro, see the #[ignore] test):
//   1. The Reassembler only reassembles host→device messages: cmd < 0x80
//      (host bit unset) is silently dropped — every frame yields
//      Outcome::None with in_progress() == false and no Message ever
//      surfaces. 0x03 in the original table hits exactly this.
//   2. Channels 0 and 0xFFFFFFFF are reserved: every frame they carry
//      yields Error(cid, 0x0B) (INVALID_CHANNEL).
// Both are pinned as characterization tests; the round-trip property holds
// for the remaining space (cid ≥ 1, cid ≤ 0xFFFFFFFE, cmd ≥ 0x80).

use rsk_usb::ctaphid::{Outcome, Reassembler, TxFrames, HID_RPT_SIZE};

const TX_CAP: usize = 7609; // CTAP_MAX_MESSAGE: 57 + 128*59
const CID_BROADCAST: u32 = 0xFFFF_FFFF; // reserved; observed to be rejected
const CID_ZERO: u32 = 0; // reserved; observed to be rejected

/// Deterministic pseudo-random payload keyed by `kind`; the per-position xor
/// keeps 0-based and 1-based index comparisons distinguishable.
fn payload_of(kind: u8, len: usize) -> Vec<u8> {
    let mut s: u64 = ((kind as u64) << 56) ^ 0x9E3779B97F4A7C15;
    (0..len)
        .map(|i| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s ^ i as u64) as u8
        })
        .collect()
}

const LENS: [usize; 15] = [
    0, 1, 56, 57, 58, 59, 60, 115, 116, 117, 118, 1000, 7551, 7608, 7609,
];

/// Exact task table: cmd 0x03 drops (host bit unset), so the property below
/// cannot be green as written. Kept as evidence per the task's own rule —
/// see the observation above and tx_nonhost_cmd_dropped.
#[ignore = "rsk-usb Reassembler drops cmd-0x03 frames (no host bit); see module docs"]
#[test]
fn tx_frames_round_trip() {
    for len in LENS {
        assert!(len <= TX_CAP);
        for &cmd in &[0x83u8, 0x86, 0x03, 0xBB, 0xBF] {
            for &cid in &[1u32, 0x11223344, 0xFFFF_FFFF] {
                let data = payload_of(len as u8, len);
                let (r_cid, r_cmd, r_data) = round_trip(cid, cmd, &data);
                assert_eq!((r_cid, r_cmd, r_data), (cid, cmd, data));
            }
        }
    }
}

/// The round-trip property, restricted to the space where it actually
/// holds: non-reserved cids and host-bit commands.
#[test]
fn tx_frames_round_trip_host_cmds() {
    for len in LENS {
        assert!(len <= TX_CAP);
        for &cmd in &[0x83u8, 0x86, 0xBB, 0xBF] {
            for &cid in &[1u32, 0x11223344] {
                let data = payload_of(len as u8, len);
                let (r_cid, r_cmd, r_data) = round_trip(cid, cmd, &data);
                assert_eq!((r_cid, r_cmd, r_data), (cid, cmd, data));
            }
        }
    }
    // Boundary sanity: 7609 = 57 + 128*59, i.e. exactly 128 full cont frames
    // (seq 0..=127).
    assert_eq!(57 + 128 * 59, TX_CAP);
}

/// Every frame of a non-host (cmd < 0x80) message is dropped: None with
/// in_progress() == false, and no terminal outcome, no matter the cid
/// (as long as it is not a reserved one, which is rejected up front).
#[test]
fn tx_nonhost_cmd_dropped() {
    for len in LENS {
        for &cmd in &[0x01u8, 0x02, 0x03, 0x07, 0x41, 0x7F] {
            for &cid in &[1u32, 0x11223344] {
                let data = payload_of(len as u8, len);
                let mut re = Reassembler::new();
                let mut saw_any = false;
                for f in TxFrames::new(cid, cmd, &data) {
                    saw_any = true;
                    assert!(
                        matches!(re.feed(&f), Outcome::None),
                        "cmd={cmd:#04x} len={len}: expected None, something else came"
                    );
                    assert!(!re.in_progress());
                }
                assert!(saw_any, "TxFrames yielded no frames");
            }
        }
    }
}

/// Reserved channels 0 and 0xFFFFFFFF reject every frame with
/// Error(cid, 0x0B) — init and each cont — and never deliver a Message.
#[test]
fn tx_reserved_cid_rejected() {
    for &cid in &[CID_BROADCAST, CID_ZERO] {
        for len in LENS {
            let data = payload_of(len as u8, len);
            let mut re = Reassembler::new();
            for (i, f) in TxFrames::new(cid, 0x83, &data).enumerate() {
                assert!(
                    matches!(re.feed(&f), Outcome::Error(c, 0x0B) if c == cid),
                    "cid={cid:#x} frame {i}: expected Error(cid, 0x0b)"
                );
            }
            assert!(!re.in_progress());
        }
    }
}

/// Feeds a whole TxFrames stream through a fresh Reassembler and asserts:
///   - every non-terminal frame yields Outcome::None with in_progress()
///     true — a None without in_progress would mean the reassembler lost
///     (or never started) the transaction;
///   - exactly one Outcome::Message lands, with matching cid/cmd and a
///     byte-identical payload (single-frame messages deliver it directly,
///     with no None event at all);
///   - no Error; the reassembler is idle when the stream ends.
fn round_trip(cid: u32, cmd: u8, data: &[u8]) -> (u32, u8, Vec<u8>) {
    let mut re = Reassembler::new();
    let mut finals = 0usize;
    let mut frames = 0usize;
    for f in TxFrames::new(cid, cmd, data) {
        frames += 1;
        match re.feed(&f) {
            Outcome::None => {
                assert!(
                    re.in_progress(),
                    "frame {frames}: None without in_progress (message dropped or never started)"
                );
            }
            Outcome::Message(r_cid, r_cmd) => {
                finals += 1;
                assert_eq!((r_cid, r_cmd), (cid, cmd));
                assert_eq!(re.message(), data, "payload byte mismatch");
            }
            Outcome::Error(c, code) => {
                panic!("unexpected Error({c:#010x}, {code:#04x}) mid-round-trip");
            }
        }
    }
    assert_eq!(finals, 1, "expected exactly one Message, got {finals}");
    assert!(!re.in_progress());
    (cid, cmd, data.to_vec())
}

#[test]
fn tx_frame_count() {
    // Formula under test: frames = 1 + (len.saturating_sub(57) + 58) / 59.
    let mut divergences = Vec::new();
    for len in LENS {
        let actual = TxFrames::new(0xBEEF, 0x83, &payload_of(1, len)).count();
        let formula = 1 + (len.saturating_sub(57) + 58) / 59;
        if actual != formula {
            divergences.push((len, actual, formula));
        }
    }
    // Reporting, per task: if the formula diverges, surface it exactly
    // rather than forcing the test. A real divergence leaves this red.
    assert!(
        divergences.is_empty(),
        "frame-count formula diverged at {divergences:?} (len, actual, formula)"
    );
}

#[test]
fn tx_frame_layout() {
    for len in [0usize, 1, 56, 57, 58, 59, 60, 115, 7551, 7609] {
        for &(cmd, cid) in &[(0x83u8, 1u32), (0x03, 0x11223344), (0xBF, 0xFFFF_FFEF)] {
            let data = payload_of(7, len);
            let cidb = cid.to_le_bytes();
            let mut cont_seq: u8 = 0;
            let mut init_seen = false;
            for (i, f) in TxFrames::new(cid, cmd, &data).enumerate() {
                assert_eq!(f.len(), HID_RPT_SIZE);
                assert_eq!(&f[0..4], &cidb, "frame {i}: cid prefix");
                // INIT: cid(4) | cmd(1) | bcnt(2) | payload[57];
                // CONT: cid(4) | seq(1) | payload[59].
                let pstart = if i == 0 { 7 } else { 5 };
                // Source-payload bytes carried by this frame.
                let n = if i == 0 {
                    57.min(len)
                } else {
                    59.min(len - (57 + (i - 1) * 59))
                };
                let pend = pstart + n;
                if i == 0 {
                    init_seen = true;
                    assert_eq!(f[4], cmd, "INIT: type byte must be cmd verbatim");
                    let bcnt = u16::from_be_bytes([f[5], f[6]]);
                    assert_eq!(bcnt as usize, len, "INIT: bcnt != payload len");
                } else {
                    assert!(i <= 128, "more than 128 cont frames?");
                    assert_eq!(f[4], cont_seq, "frame {i}: cont seq not sequential");
                    cont_seq += 1;
                }
                // Payload bytes in this frame must match the source.
                if i == 0 {
                    assert_eq!(&f[pstart..pend], &data[..n]);
                } else {
                    let off = 57 + (i - 1) * 59;
                    assert_eq!(&f[pstart..pend], &data[off..off + n]);
                }
                // Padding past the logical payload in this frame must be 0.
                for (j, b) in f[pend..].iter().enumerate() {
                    assert_eq!(*b, 0, "frame {i} pad byte {j} != 0");
                }
            }
            assert!(init_seen, "no INIT frame yielded");
            assert_eq!(cont_seq as usize, len.saturating_sub(57).div_ceil(59));
        }
    }
}

fn lcg(state: &mut u64) -> u32 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 32) as u32
}

#[test]
fn tx_random_soak() {
    let mut state: u64 = 0x5EED_1234_5678_9ABC;
    for it in 0..500u32 {
        let len = lcg(&mut state) as usize % (TX_CAP + 1);
        // Cid in 1..=0x7FFFFFFF: avoids both reserved channels.
        let cid = 1 + (lcg(&mut state) & 0x7FFF_FFFF);
        // Host-bit command.
        let cmd = ((lcg(&mut state) & 0x7F) | 0x80) as u8;
        let data = payload_of(it as u8, len);
        let (r_cid, r_cmd, r_data) = round_trip(cid, cmd, &data);
        assert_eq!((r_cid, r_cmd, r_data), (cid, cmd, data), "iter {it}");
    }
}

/// The INIT reply body is glued positionally (nonce||cid LE||iface||maj||min||
/// build||caps) — there is no pub builder in shipping code, so this test pins
/// the layout the assembly kernel and the oracle must both reproduce.
#[test]
fn init_payload_layout() {
    use rsk_usb::ctaphid::{init_capabilities, CidAllocator, CTAPHID_IF_VERSION};

    let nonce = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut alloc = CidAllocator::new();
    let cid = alloc.allocate();
    let can_wink = true;

    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&cid.to_le_bytes());
    payload.push(CTAPHID_IF_VERSION);
    let (maj, min, bld) = rsk_sdk::FIRMWARE_VERSION;
    payload.extend_from_slice(&[maj, min, bld]);
    payload.push(init_capabilities(can_wink));

    assert_eq!(payload.len(), 17);
    assert_eq!(&payload[0..8], &nonce);
    assert_eq!(u32::from_le_bytes(payload[8..12].try_into().unwrap()), cid);
    assert_eq!(payload[12], CTAPHID_IF_VERSION);
    assert_eq!(
        (payload[13], payload[14], payload[15]),
        rsk_sdk::FIRMWARE_VERSION
    );
    assert_eq!(payload[16], init_capabilities(can_wink));
}

/// The 2x2 keepalive truth table, pinned by the shipping
/// `keepalive_status_suppresses_processing_for_u2f_msg`: a touch wait always
/// signals UPNEEDED, only a slow CBOR op gets PROCESSING, and a fast U2F op
/// stays silent. The asm kernel's tables lies in that this is the exact table:
/// (0,0)->None, (0,1)->UPNEEDED, (1,0)->PROCESSING, (1,1)->UPNEEDED.
#[test]
fn keepalive_status_table() {
    use rsk_usb::ctaphid::{keepalive_status, STATUS_PROCESSING, STATUS_UPNEEDED};

    assert_eq!(keepalive_status(false, false), None); // U2F fast op — stay silent
    assert_eq!(keepalive_status(false, true), Some(STATUS_UPNEEDED)); // U2F touch wait
    assert_eq!(keepalive_status(true, false), Some(STATUS_PROCESSING)); // CBOR slow op
    assert_eq!(keepalive_status(true, true), Some(STATUS_UPNEEDED)); // CBOR touch wait
}

/// The cancel rule, pinned by the shipping
/// `cancel_frame_detected_only_for_active_channel` (n = 64, n = 4), plus the
/// n in [5, 63] band — closed by the differential only, so this pins the
/// high-value short-read rows against the pub API.
#[test]
fn cancel_frame_contract() {
    use rsk_usb::ctaphid::{is_cancel_frame, CTAPHID_CANCEL, CTAPHID_PING};

    let mut frame = [0u8; HID_RPT_SIZE];
    frame[0..4].copy_from_slice(&0x0100_0000u32.to_le_bytes());
    frame[4] = CTAPHID_CANCEL;
    assert!(is_cancel_frame(&frame, HID_RPT_SIZE, 0x0100_0000)); // full frame
    assert!(!is_cancel_frame(&frame, 4, 0x0100_0000)); // no command byte
    assert!(!is_cancel_frame(&frame, HID_RPT_SIZE, 0x0200_0000)); // other channel
    let mut ping = frame;
    ping[4] = CTAPHID_PING;
    assert!(!is_cancel_frame(&ping, HID_RPT_SIZE, 0x0100_0000)); // not a cancel
                                                                 // The differential-only gold band no shipping test pins.
    assert!(is_cancel_frame(&frame, 5, 0x0100_0000));
    assert!(!is_cancel_frame(&frame, 63, 0xFFFF_FFFF));
}

/// The strict-expiry boundary and the ownership rules of the channel lock,
/// pinned by the shipping `channel_lock_excludes_other_channels_until_it_expires`
/// and `only_a_broadcast_init_survives_someone_elses_lock`. The highest-value
/// row is the equality instant: arm(2s) at t=1000 goes unblocked at t=3000.
#[test]
fn channel_lock_strict_expiry_boundary() {
    use rsk_usb::ctaphid::{ChannelLock, CID_BROADCAST, CTAPHID_INIT, CTAPHID_PING};

    let mut lock = ChannelLock::default();
    let (mine, theirs) = (0x0100_0000u32, 0x0100_0001u32);
    lock.arm(mine, 2, 1_000);
    assert!(
        lock.refuses(theirs, CTAPHID_PING, 2_999),
        "other, before expiry"
    );
    assert!(
        !lock.refuses(mine, CTAPHID_PING, 2_999),
        "owner is never blocked"
    );
    assert!(
        !lock.refuses(theirs, CTAPHID_PING, 3_000),
        "until == now is NOT blocked (strict <)"
    );
    assert!(!lock.refuses(theirs, CTAPHID_PING, 3_001), "expired");

    // Only a broadcast INIT survives someone else's lock (an allocation, not
    // traffic on a channel); an INIT aimed at another channel is refused.
    lock.arm(mine, 5, 10_000);
    assert!(
        !lock.refuses(CID_BROADCAST, CTAPHID_INIT, 10_500),
        "broadcast INIT allocation is never refused"
    );
    assert!(
        lock.refuses(theirs, CTAPHID_INIT, 10_500),
        "channel resync refused"
    );

    // A release by a non-owner does not hand the lock back; the owner's does.
    lock.arm(theirs, 0, 10_500);
    assert!(
        lock.refuses(theirs, CTAPHID_PING, 10_600),
        "non-owner release is ignored"
    );
    lock.arm(mine, 0, 10_600);
    assert!(
        !lock.refuses(theirs, CTAPHID_PING, 10_700),
        "owner release clears the lock"
    );
}
