// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! How the dispatcher cuts a response too long for one frame, against the frames a
//! YubiKey 5C NFC fw 5.8.0 (a test key) answers: PIV GET DATA of a 1000-byte
//! object, read twice in every encoding a host sends and drained with GET RESPONSE.

use super::*;

/// One frame of a response: its status word and its body's length.
type Frame = (u16, usize);
/// A form's name, its APDU and the frames it is answered with.
type Row<'a, A> = (&'a str, A, &'a [Frame]);

const BODY: usize = 1000;
/// A bound on the frames one response may take, so a mutant that never ends the
/// chain fails instead of hanging the suite.
const FRAMES_MAX: usize = 64;
const GR_LE_00: [u8; 5] = [0x00, 0xC0, 0x00, 0x00, 0x00];
/// GET DATA's command data, three bytes, as the forms below carry it.
const TAG: [u8; 3] = [0x5F, 0xC1, 0x05];

/// The status and length of each frame of a `BODY`-byte answer: one per APDU of
/// `apdus`, then `drain`'s while `61xx` says more is owed.
fn frames(apdus: &[&[u8]], drain: &[u8]) -> Vec<Frame> {
    frames_of(BODY, 2048, apdus, drain)
}

/// [`frames`] for a `body_len`-byte answer, with each `drain` answered into a
/// buffer of `room` bytes. Asserts the frames join into the whole body.
fn frames_of(body_len: usize, room: usize, apdus: &[&[u8]], drain: &[u8]) -> Vec<Frame> {
    let mut c = Chunky {
        body_len,
        chain: true,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 2048];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);
    let mut got = Vec::new();
    let mut body = Vec::new();
    let mut sw = Sw::OK;
    for a in apdus {
        sw = disp.process(a, &mut applets, &mut (), &mut res);
        got.push((sw.0, res.len()));
    }
    body.extend_from_slice(res.as_slice());
    let mut small = vec![0u8; room];
    let mut res = ResBuf::new(&mut small);
    while sw.sw1() == 0x61 && got.len() < FRAMES_MAX {
        sw = disp.process(drain, &mut applets, &mut (), &mut res);
        got.push((sw.0, res.len()));
        body.extend_from_slice(res.as_slice());
    }
    let whole: Vec<u8> = (0..body_len).map(|i| (i & 0xFF) as u8).collect();
    assert_eq!(
        body, whole,
        "{apdus:02X?}: the frames do not join into the body"
    );
    got
}

fn short(le: Option<u8>) -> Vec<u8> {
    let mut a = vec![0x00, 0xCA, 0x00, 0x00, TAG.len() as u8];
    a.extend_from_slice(&TAG);
    a.extend(le);
    a
}

fn ext(le: Option<u16>) -> Vec<u8> {
    let mut a = vec![0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, TAG.len() as u8];
    a.extend_from_slice(&TAG);
    a.extend(le.map(u16::to_be_bytes).into_iter().flatten());
    a
}

const QUARTERS: [Frame; 4] = [(0x6100, 256), (0x6100, 256), (0x61E8, 256), (0x9000, 232)];
const AFTER_16: [Frame; 5] = [
    (0x6100, 16),
    (0x6100, 256),
    (0x6100, 256),
    (0x61D8, 256),
    (0x9000, 216),
];
const WHOLE: [Frame; 1] = [(0x9000, BODY)];

#[test]
fn every_encoding_is_cut_where_a_yubikey_cuts_it() {
    let rows: [Row<Vec<u8>>; 10] = [
        ("short, no Le", short(None), &QUARTERS),
        ("short, Le 00", short(Some(0x00)), &QUARTERS),
        ("short, Le 10", short(Some(0x10)), &AFTER_16),
        (
            "short, Le FF",
            short(Some(0xFF)),
            &[(0x6100, 255), (0x6100, 256), (0x61E9, 256), (0x9000, 233)],
        ),
        ("extended, no Le", ext(None), &WHOLE),
        ("extended, Le 0000", ext(Some(0x0000)), &WHOLE),
        ("extended, Le 0010", ext(Some(0x0010)), &AFTER_16),
        ("extended, Le 0100", ext(Some(0x0100)), &QUARTERS),
        (
            "extended, Le 0101",
            ext(Some(0x0101)),
            &[(0x6100, 257), (0x6100, 256), (0x61E7, 256), (0x9000, 231)],
        ),
        (
            "extended, Le 0200",
            ext(Some(0x0200)),
            &[(0x6100, 512), (0x61E8, 256), (0x9000, 232)],
        ),
    ];
    for (form, apdu, want) in rows {
        assert_eq!(frames(&[&apdu[..]], &GR_LE_00), want, "{form}");
    }
}

#[test]
fn get_response_is_cut_by_its_own_encoding() {
    // The first frame is a short Le 00's 256 bytes; each row drains the other 744
    // with one form of GET RESPONSE. Its P1-P2, class and command data are not
    // judged while a tail is owed.
    let tail_whole: &[Frame] = &[(0x6100, 256), (0x9000, 744)];
    let rows: [Row<&[u8]>; 8] = [
        ("case 1", &[0x00, 0xC0, 0x00, 0x00], &QUARTERS),
        ("short, Le 00", &GR_LE_00, &QUARTERS),
        (
            "extended, Le 0000",
            &[0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00],
            tail_whole,
        ),
        (
            "extended, Le 0300",
            &[0x00, 0xC0, 0x00, 0x00, 0x00, 0x03, 0x00],
            tail_whole,
        ),
        (
            "short, data, no Le",
            &[0x00, 0xC0, 0x00, 0x00, 0x02, 0xAA, 0xBB],
            &QUARTERS,
        ),
        (
            "extended, data, no Le",
            &[0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB],
            tail_whole,
        ),
        ("P1-P2 12 34", &[0x00, 0xC0, 0x12, 0x34, 0x00], &QUARTERS),
        ("class 80", &[0x80, 0xC0, 0x00, 0x00, 0x00], &QUARTERS),
    ];
    for (form, gr, want) in rows {
        assert_eq!(
            frames(&[&short(Some(0x00))[..]], gr),
            want,
            "GET RESPONSE {form}"
        );
    }
}

#[test]
fn a_body_its_cap_holds_exactly_is_not_chained() {
    // A `61 00` over an empty tail is what `<` in place of `<=` answers here.
    let rows: [Row<Vec<u8>>; 3] = [
        ("short, no Le", short(None), &[(0x9000, 256)]),
        ("extended, Le 0100", ext(Some(0x0100)), &[(0x9000, 256)]),
        ("short, Le 10", short(Some(0x10)), &[(0x9000, 16)]),
    ];
    for (form, apdu, want) in rows {
        let len = want[0].1;
        assert_eq!(
            frames_of(len, 2048, &[&apdu[..]], &GR_LE_00),
            want,
            "{form}"
        );
    }
}

#[test]
fn get_response_takes_no_more_than_its_buffer_holds() {
    // An extended GET RESPONSE asks for the whole tail. Into a 300-byte buffer it
    // gets 300 bytes and `61xx` for the rest, not `9000` over an empty body.
    let gr: &[u8] = &[0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        frames_of(BODY, 300, &[&short(Some(0x00))[..]], gr),
        [(0x6100, 256), (0x6100, 300), (0x6190, 300), (0x9000, 144)]
    );
}

#[test]
fn a_chained_command_is_cut_by_its_final_segment() {
    // A short final segment with an Le is no row: the YubiKey reads that Le out
    // of its reassembled command data, at the final segment's Lc offset — `C1`
    // here, a 193-byte first frame. A slip in its parser, not a rule to follow.
    let seg: &[u8] = &[0x10, 0xCA, 0x00, 0x00, 0x02, 0x5C, 0x03];
    let seg_ext: &[u8] = &[0x10, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x02, 0x5C, 0x03];
    let short_last: &[u8] = &[0x00, 0xCA, 0x00, 0x00, 0x03, 0x5F, 0xC1, 0x05];
    let rows: [Row<[&[u8]; 2]>; 4] = [
        ("short, no Le", [seg, short_last], &QUARTERS),
        (
            "extended, no Le",
            [
                seg,
                &[0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x03, 0x5F, 0xC1, 0x05],
            ],
            &WHOLE,
        ),
        (
            "extended, Le 0000",
            [
                seg,
                &[
                    0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x03, 0x5F, 0xC1, 0x05, 0x00, 0x00,
                ],
            ],
            &WHOLE,
        ),
        // Whole on the YubiKey, which counts an extended segment anywhere in the
        // chain. The cap here is the final segment's, as ISO 7816-4 takes a
        // chain's Ne from its last command: a divergence kept on purpose.
        (
            "short, after an extended segment",
            [seg_ext, short_last],
            &QUARTERS,
        ),
    ];
    for (form, apdus, want) in rows {
        let mut all = vec![(0x9000, 0)];
        all.extend_from_slice(want);
        assert_eq!(frames(&apdus, &GR_LE_00), all, "final segment {form}");
    }
}
