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
