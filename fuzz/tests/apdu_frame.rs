// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The applet replay targets' framing, proved.
//!
//! `fuzz_targets/apdu_frame.rs` exists so those targets can build a command body
//! over 255 bytes. Two things have to hold for that to be worth anything, and
//! neither is visible from a fuzz run (a target that quietly stops reaching the
//! extended branch just keeps reporting "no crash"):
//!
//!   * every synthesised frame is an APDU `Apdu::parse` **accepts**, with the
//!     header and body it was asked for — the escape is pointless if the command
//!     is rejected before dispatch, which is what happens to most framed chunks
//!     today; and
//!   * the non-escape framing still splits the input exactly the way it did
//!     before the escape existed, or the accumulated corpora lose their meaning.
//!
//! Mutation guard for the first: drop the `0x00` marker, or encode the requested
//! length instead of the clamped one, and `parse_accepts_every_synthesised_frame`
//! goes red. For the second: change the escape byte to anything a corpus uses and
//! `plain_framing_is_unchanged` goes red.

#[path = "../fuzz_targets/apdu_frame.rs"]
mod apdu_frame;

use core::cell::RefCell;

use apdu_frame::{Frame, next_frame};
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_openpgp::consts::{INS_VERIFY, PW3_DEFAULT, PW3_MODE83};
use rsk_openpgp::files::MAX_DO_BYTES;
use rsk_openpgp::{AlwaysConfirm, OpenpgpApplet, Rng, scan_files};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// The splitter as every target wrote it before the escape.
fn legacy_split(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let n = data[i] as usize;
        i += 1;
        let end = (i + n).min(data.len());
        out.push(data[i..end].to_vec());
        i = end;
    }
    out
}

fn split(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some((frame, tail)) = next_frame(rest) {
        out.push(frame.as_slice().to_vec());
        rest = tail;
    }
    out
}

/// A deterministic byte soup: no fuzzer here, so the inputs have to cover the
/// escape, the clamp, the sentinel and the plain path by construction.
fn corpus() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x04, 0x00, 0xA4, 0x04, 0x00],
        vec![0xFE, 0x11, 0x22],
        // Escape with a body that is present in full.
        [
            vec![0xFF, 0x00, 0xDA, 0x7F, 0x21, 0x01, 0x2C],
            vec![0xEE; 300],
        ]
        .concat(),
        // Escape whose declared length overruns the input: must clamp.
        [
            vec![0xFF, 0x00, 0xDB, 0x00, 0x7A, 0xFF, 0xFF],
            vec![0x5A; 40],
        ]
        .concat(),
        // Escape with too few header bytes left: falls back to the old meaning.
        vec![0xFF, 0x00, 0xA4],
        // Escape declaring an empty body, then a plain frame after it.
        vec![
            0xFF, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x05, 0, 0x20, 0, 0x81, 0,
        ],
    ];
    // Every single byte as a lone length prefix, and as a prefix over a tail.
    for n in 0u8..=255 {
        v.push(vec![n]);
        v.push([&[n][..], &[0xA5; 9][..]].concat());
    }
    v
}

#[test]
fn parse_accepts_every_synthesised_frame() {
    let mut synthesised = 0usize;
    let mut longest = 0usize;
    for input in corpus() {
        let mut rest = &input[..];
        while let Some((frame, tail)) = next_frame(rest) {
            rest = tail;
            let Frame::Ext(raw) = &frame else { continue };
            synthesised += 1;
            let apdu = Apdu::parse(raw).expect("a synthesised frame must parse");
            assert_eq!(apdu.cla, raw[0]);
            assert_eq!(apdu.ins, raw[1]);
            assert_eq!(apdu.p1, raw[2]);
            assert_eq!(apdu.p2, raw[3]);
            // The whole point: `nc` is what the escape said, and the data the
            // applet sees is exactly the bytes that followed the header.
            assert_eq!(apdu.nc, raw.len() - 7);
            assert_eq!(apdu.data, &raw[7..]);
            longest = longest.max(apdu.nc);
        }
    }
    assert!(synthesised >= 3, "the corpus stopped exercising the escape");
    // A short Lc caps at 255; if this ever drops back there the escape is dead.
    assert!(longest > 255, "longest synthesised body was only {longest}");
}

#[test]
fn plain_framing_is_unchanged() {
    for input in corpus() {
        if input.contains(&0xFF) {
            continue; // the escape is the one deliberate divergence
        }
        assert_eq!(split(&input), legacy_split(&input), "input {input:02X?}");
    }
}

#[test]
fn zero_length_is_the_select_sentinel() {
    // The three applet targets that keep a selection branch on this variant, and
    // a non-empty frame must never reach that arm.
    let (frame, tail) = next_frame(&[0x00, 0x01, 0x02]).unwrap();
    assert!(matches!(frame, Frame::Select));
    assert!(frame.as_slice().is_empty());
    assert_eq!(tail, &[0x01, 0x02]);

    let (frame, _) = next_frame(&[0xFF, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00]).unwrap();
    assert!(!matches!(frame, Frame::Select));
}

/// What the escape is *for*, end to end: a real applet accepting a command body
/// no short Lc could have carried. `EF_CH_CERT` (7F21) is the write that goes
/// straight to flash at up to `MAX_DO_BYTES`, so it is the deepest thing the
/// length band reaches. The read-back is deliberately not asserted — GET DATA's
/// behaviour on a DO this size is open finding E25, and a test that pinned
/// today's answer would pin the defect.
#[test]
fn an_escape_frame_delivers_a_max_length_put_data() {
    const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
    const SERIAL_HASH: [u8; 32] = [0x22; 32];

    struct CountRng(u8);
    impl Rng for CountRng {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b.iter_mut() {
                *x = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    };
    scan_files(&dev, &mut fs, &mut CountRng(0)).expect("default files");
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    let mut drive = |raw: &[u8]| {
        let apdu = Apdu::parse(raw).expect("frame must parse");
        let mut buf = [0u8; 2048];
        let mut res = ResBuf::new(&mut buf);
        (app.process(&apdu, &mut fs, &mut res), apdu.nc)
    };

    // PW3, or the cardholder-certificate write is refused before its length
    // matters and this would pass for the wrong reason.
    let mut verify = vec![0x00, INS_VERIFY, 0x00, PW3_MODE83, PW3_DEFAULT.len() as u8];
    verify.extend_from_slice(PW3_DEFAULT);
    assert_eq!(drive(&verify).0, Sw::OK, "seed VERIFY PW3");

    // Exactly the bytes a target's replay loop would see: the escape prefix, the
    // six header bytes, then the body.
    let hi = (MAX_DO_BYTES >> 8) as u8;
    let lo = MAX_DO_BYTES as u8;
    let framed = [
        &[0xFF, 0x00, 0xDA, 0x7F, 0x21, hi, lo][..],
        &vec![0xA5; MAX_DO_BYTES][..],
    ]
    .concat();

    let (frame, tail) = next_frame(&framed).expect("one frame");
    assert!(tail.is_empty());
    assert!(matches!(frame, Frame::Ext(_)));
    let (sw, nc) = drive(frame.as_slice());
    assert_eq!(nc, MAX_DO_BYTES, "the applet saw a truncated body");
    assert_eq!(sw, Sw::OK, "PUT DATA 7F21 of MAX_DO_BYTES must be accepted");

    // The reach this buys: the old framing tops out at a 255-byte chunk, so the
    // largest body it could ever hand an applet is 250 bytes.
    for legacy in legacy_split(&framed) {
        let nc = Apdu::parse(&legacy).map(|a| a.nc).unwrap_or(0);
        assert!(nc <= 250, "a one-byte length reached nc = {nc}");
    }
}

#[test]
fn the_frame_stream_always_terminates() {
    // Every branch consumes at least the prefix byte, so no input can loop.
    for input in corpus() {
        let mut rest = &input[..];
        let mut steps = 0;
        while let Some((_, tail)) = next_frame(rest) {
            assert!(tail.len() < rest.len(), "a frame consumed nothing");
            rest = tail;
            steps += 1;
            assert!(steps <= input.len(), "more frames than bytes");
        }
    }
}
