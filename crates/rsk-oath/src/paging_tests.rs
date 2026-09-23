// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! How YKOATH hands out a response too long for one frame, held to a YubiKey
//! 5.8.0 read twice through raw APDUs: pages through SEND REMAINING (0xA5), and
//! what SEND REMAINING answers when no page is owed.

use super::*;

/// [`run`] into a response buffer of `cap` bytes, so a handful of credentials
/// overruns a frame.
fn run_cap(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8], cap: usize) -> (Sw, Vec<u8>) {
    let mut out = vec![0u8; cap];
    let mut res = ResBuf::new(&mut out);
    let apdu = Apdu::parse(raw).unwrap();
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

/// SEND REMAINING is no instruction until a page is owed: a YubiKey 5.8.0 answers
/// `6D00` with none pending under any P1-P2, and serves a pending page under any
/// P1-P2 as well — it never judges them.
#[test]
fn send_remaining_answers_6d00_with_no_page_and_never_judges_p1p2() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for (p1, p2) in [(0x00, 0x00), (0xFF, 0xFF), (0x01, 0x00), (0x00, 0x01)] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, p1, p2, &[])),
            (Sw::INS_NOT_SUPPORTED, vec![]),
            "no page pending, P1-P2 {p1:02X} {p2:02X}"
        );
    }

    for i in 0..8 {
        let data = put_data(&acct_name(i), 0x21, 6, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
    }
    let (sw, _) = run_cap(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]), 64);
    assert_eq!(sw.sw1(), 0x61, "fixture: the LIST owes a page");
    let (sw, page) = run_cap(
        &mut app,
        &mut fs,
        &apdu(INS_SEND_REMAINING, 0xFF, 0xFF, &[]),
        64,
    );
    assert!(
        (sw.sw1() == 0x61 || sw == Sw::OK) && !page.is_empty(),
        "a pending page refused over its P1-P2: {sw:?}"
    );
}

/// A response this suite pages ends well inside this many frames; one that does not
/// is a pager going round, and fails here instead of hanging the run.
const FRAMES_MAX: usize = 4096;

/// Every frame a command and the SEND REMAINING after it return, as `(SW, bytes)`,
/// and the bytes joined.
fn frames(
    app: &mut OathApplet,
    fs: &mut Fs<RamStorage>,
    first: &[u8],
) -> (Vec<(u16, usize)>, Vec<u8>) {
    let (mut sw, mut body) = run_fw(app, fs, first);
    let mut seen = vec![(sw.0, body.len())];
    while sw.sw1() == 0x61 {
        assert!(seen.len() < FRAMES_MAX, "the response never ended");
        let (s, b) = run_fw(app, fs, &[0x00, INS_SEND_REMAINING, 0x00, 0x00, 0x00]);
        seen.push((s.0, b.len()));
        body.extend(b);
        sw = s;
    }
    (seen, body)
}

/// A short APDU caps each frame at its `Le` — 256 where it carries none — and the
/// rest comes through SEND REMAINING, cut at the byte, inside an entry, with SW2
/// naming what is left once that is under 256. An extended one is answered whole.
/// Every expected row is what a YubiKey 5.8.0 returned for the same 24 accounts
/// with 49-character names, read twice through raw APDUs.
#[test]
fn frames_follow_the_le_as_a_yubikey_cuts_them() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for i in 0..24u8 {
        let mut name = format!("probe-{i:02}-").into_bytes();
        name.extend([b'x'; 40]);
        let data = put_data(&name, 0x21, 6, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
    }

    let (whole_list, list) = frames(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0, 0, 0]);
    assert_eq!(whole_list, [(0x9000, 1248)], "extended Le: one frame");
    let pages = [
        (0x6100, 256),
        (0x6100, 256),
        (0x6100, 256),
        (0x61E0, 256),
        (0x9000, 224),
    ];
    for (form, first) in [
        ("Le 00", &[0x00, INS_LIST, 0, 0, 0][..]),
        ("no Le", &[0x00, INS_LIST, 0, 0]),
    ] {
        let (seen, body) = frames(&mut app, &mut fs, first);
        assert_eq!(seen, pages, "LIST, short, {form}");
        assert_eq!(
            body, list,
            "LIST, short, {form}: the frames do not join into the list"
        );
    }
    let (seen, body) = frames(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0x10]);
    let small = [
        (0x6100, 16),
        (0x6100, 256),
        (0x6100, 256),
        (0x6100, 256),
        (0x61D0, 256),
        (0x9000, 208),
    ];
    assert_eq!(seen, small, "LIST, short, Le 10");
    assert_eq!(body, list);

    let mut calc = vec![0x00, INS_CALC_ALL, 0x00, 0x01, 0x00, 0x00, 0x0A];
    calc.extend(tlv(TAG_CHALLENGE, &[0, 0, 0, 0, 0x03, 0x5B, 0x5A, 0x3C]));
    let (whole_calc, codes) = frames(&mut app, &mut fs, &calc);
    assert_eq!(whole_calc, [(0x9000, 1392)], "extended, no Le: one frame");
    let mut short = vec![0x00, INS_CALC_ALL, 0x00, 0x01, 0x0A];
    short.extend_from_slice(&calc[7..]);
    let (seen, body) = frames(&mut app, &mut fs, &short);
    let pages = [
        (0x6100, 256),
        (0x6100, 256),
        (0x6100, 256),
        (0x6100, 256),
        (0x6170, 256),
        (0x9000, 112),
    ];
    assert_eq!(seen, pages, "CALCULATE ALL, short, no Le");
    assert_eq!(
        body, codes,
        "CALCULATE ALL: the frames do not join into the codes"
    );
}

/// Every frame drained with SEND REMAINING carrying Le `le`, joined.
fn drain_at(
    app: &mut OathApplet,
    fs: &mut Fs<RamStorage>,
    first: &[u8],
    le: u8,
) -> (Vec<(u16, usize)>, Vec<u8>) {
    let (mut sw, mut body) = run_fw(app, fs, first);
    let mut seen = vec![(sw.0, body.len())];
    while sw.sw1() == 0x61 {
        assert!(seen.len() < FRAMES_MAX, "the response never ended");
        let (s, b) = run_fw(app, fs, &[0x00, INS_SEND_REMAINING, 0x00, 0x00, le]);
        seen.push((s.0, b.len()));
        body.extend(b);
        sw = s;
    }
    (seen, body)
}

fn oath_with(names: &[Vec<u8>]) -> (Fs<RamStorage>, RefCell<CountRng>, RefCell<AlwaysConfirm>) {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    {
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        for name in names {
            let data = put_data(name, 0x21, 6, SECRET_SHA1, false, None);
            assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
        }
    }
    (fs, rng, touch)
}

/// Frames far smaller than an entry: every one of the 52-byte entries spans four
/// or five 16-byte frames, so a frame both starts and ends inside one. They still
/// join into the list byte for byte.
#[test]
fn an_entry_spread_over_many_frames_joins_whole() {
    let names: Vec<Vec<u8>> = (0..24u8)
        .map(|i| [format!("probe-{i:02}-").into_bytes(), vec![b'x'; 40]].concat())
        .collect();
    let (mut fs, rng, touch) = oath_with(&names);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (_, list) = frames(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0, 0, 0]);
    let (seen, body) = drain_at(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0x10], 0x10);
    assert_eq!(
        seen.len(),
        list.len() / 16,
        "one 16-byte frame per 16 bytes"
    );
    assert!(seen.iter().all(|&(_, n)| n == 16), "{seen:?}");
    assert_eq!(body, list, "the frames do not join into the list");
}

/// SW2 names the bytes left once fewer than 256 remain, and 255 is fewer: a
/// 511-byte list answers its first 256 bytes with `61FF`.
#[test]
fn exactly_255_bytes_left_is_61ff() {
    // Seven 67-byte entries and one of 42: 511 bytes.
    let mut names: Vec<Vec<u8>> = (0..7u8).map(|i| vec![b'a' + i; 64]).collect();
    names.push(vec![b'z'; 39]);
    let (mut fs, rng, touch) = oath_with(&names);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (seen, body) = frames(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0]);
    assert_eq!(body.len(), 511, "fixture: the list is 511 bytes");
    assert_eq!(seen, [(0x61FF, 256), (0x9000, 255)]);
}

/// A credential the read leaves out — here one sealed under another device — is
/// left out of the paged answer as of the one-frame one, wherever a frame boundary
/// falls around it.
#[test]
fn an_unreadable_credential_between_frames_is_left_out_the_same() {
    let names: Vec<Vec<u8>> = (0..6).map(acct_name).collect();
    let (mut fs, rng, touch) = oath_with(&names[..3]);
    foreign_sealed(&mut fs, KeyFid::new(EF_OATH_CRED + 3), &[0x5A; 40]);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for name in &names[3..] {
        let data = put_data(name, 0x21, 6, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
    }
    let (_, list) = frames(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0, 0, 0]);
    assert_eq!(
        count_tag(&list, TAG_NAME_LIST),
        6,
        "fixture: six readable credentials"
    );
    for le in [0x05, 0x0F, 0x10, 0x2D] {
        let (_, body) = drain_at(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, le], le);
        assert_eq!(
            body, list,
            "Le {le:#04x}: the pages differ from the one-frame answer"
        );
    }
}

/// A frame resumes at its entry's FID, not its place in a list rebuilt every
/// frame: a credential deleted behind the cursor moves nothing, and one deleted
/// UNDER it ends the response with `6581` instead of a tail it cannot tell.
#[test]
fn a_store_that_changes_between_frames_neither_shifts_nor_breaks_a_page() {
    let names: Vec<Vec<u8>> = (0..6).map(acct_name).collect();
    let (mut fs, rng, touch) = oath_with(&names);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut other = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (_, list) = frames(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0, 0, 0]);
    let delete = |name: &[u8]| apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, name));

    // 15-byte entries in 16-byte frames: the first frame ends one byte into the second.
    let (sw, mut body) = run_fw(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0x10]);
    assert_eq!(sw.sw1(), 0x61);
    assert_eq!(run(&mut other, &mut fs, &delete(&names[0])).0, Sw::OK);
    let (_, rest) = drain_at(
        &mut app,
        &mut fs,
        &[0x00, INS_SEND_REMAINING, 0, 0, 0x10],
        0x10,
    );
    body.extend(rest);
    assert_eq!(body, list, "a delete behind the cursor moved it");

    let (sw, _) = run_fw(&mut app, &mut fs, &[0x00, INS_LIST, 0, 0, 0x10]);
    assert_eq!(sw.sw1(), 0x61);
    assert_eq!(run(&mut other, &mut fs, &delete(&names[2])).0, Sw::OK);
    assert_eq!(
        run_fw(&mut app, &mut fs, &[0x00, INS_SEND_REMAINING, 0, 0, 0x10]),
        (Sw::MEMORY_FAILURE, vec![]),
        "the entry under the cursor went, and its tail was told anyway"
    );
    assert_eq!(
        run_fw(&mut app, &mut fs, &[0x00, INS_SEND_REMAINING, 0, 0, 0]).0,
        Sw::INS_NOT_SUPPORTED,
        "the lost response left a page owed"
    );
}
