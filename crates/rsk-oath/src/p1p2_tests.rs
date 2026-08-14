// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E60: the parameter bytes. A YubiKey 5.7.4 answers `6B00` — not `6A86` — to a
//! pair a command does not take, and the pairs it takes are narrower than they
//! look: `00 00` everywhere, `01` in `P2` only on the two reads that truncate,
//! `DE AD` on RESET. We read `P1` in one command and `P2` in two, so the rest of
//! the table took whatever the host sent.
//!
//! Every row in [`MEASURED`] is a cell read off the card, each repeated at least
//! twice on a freshly selected applet (worklog TRACK-oath2 §E60).

use super::*;

fn app_and_fs() -> (Fs<RamStorage>, RefCell<CountRng>, RefCell<AlwaysConfirm>) {
    (
        new_fs(),
        RefCell::new(CountRng(7)),
        RefCell::new(AlwaysConfirm),
    )
}

/// `(instruction, P1, P2, does the card take it)`. "Takes it" means the pair
/// reaches the command — not that the command succeeds — so the table stays
/// about the parameter bytes and nothing else.
const MEASURED: &[(u8, u8, u8, bool)] = &[
    // The write and enumerate commands: `00 00` and nothing else. `00 01` is the
    // cell that mattered — it used to complete these.
    (INS_PUT, 0x00, 0x00, true),
    (INS_PUT, 0x00, 0x01, false),
    (INS_PUT, 0x01, 0x00, false),
    (INS_PUT, 0x00, 0x02, false),
    (INS_PUT, 0xFF, 0xFF, false),
    (INS_DELETE, 0x00, 0x00, true),
    (INS_DELETE, 0x00, 0x01, false),
    (INS_DELETE, 0x01, 0x00, false),
    (INS_DELETE, 0xFF, 0xFF, false),
    (INS_SET_CODE, 0x00, 0x00, true),
    (INS_SET_CODE, 0x00, 0x01, false),
    (INS_SET_CODE, 0x01, 0x00, false),
    (INS_SET_CODE, 0xFF, 0xFF, false),
    (INS_RENAME, 0x00, 0x00, true),
    (INS_RENAME, 0x00, 0x01, false),
    (INS_RENAME, 0x01, 0x00, false),
    (INS_RENAME, 0xFF, 0xFF, false),
    (INS_LIST, 0x00, 0x00, true),
    (INS_LIST, 0x00, 0x01, false),
    (INS_LIST, 0x00, 0x02, false),
    (INS_LIST, 0x00, 0xFF, false),
    (INS_LIST, 0x01, 0x00, false),
    (INS_LIST, 0x02, 0x00, false),
    (INS_LIST, 0xFF, 0x00, false),
    (INS_LIST, 0xFF, 0xFF, false),
    // The two reads, and the only place `P2 = 01` means anything.
    (INS_CALCULATE, 0x00, 0x00, true),
    (INS_CALCULATE, 0x00, 0x01, true),
    (INS_CALCULATE, 0x00, 0x02, false),
    (INS_CALCULATE, 0x01, 0x00, false),
    (INS_CALCULATE, 0xFF, 0xFF, false),
    (INS_CALC_ALL, 0x00, 0x00, true),
    (INS_CALC_ALL, 0x00, 0x01, true),
    (INS_CALC_ALL, 0x00, 0x02, false),
    (INS_CALC_ALL, 0x01, 0x00, false),
    (INS_CALC_ALL, 0xFF, 0xFF, false),
    // VALIDATE is the card's odd one out: it refuses only when both bytes are
    // set. Read twice with a code installed and twice without — the answer is
    // the same either way.
    (INS_VALIDATE, 0x00, 0x00, true),
    (INS_VALIDATE, 0x00, 0x01, true),
    (INS_VALIDATE, 0x00, 0x02, true),
    (INS_VALIDATE, 0x00, 0xFF, true),
    (INS_VALIDATE, 0x01, 0x00, true),
    (INS_VALIDATE, 0x02, 0x00, true),
    (INS_VALIDATE, 0xFF, 0x00, true),
    (INS_VALIDATE, 0x01, 0x01, false),
    (INS_VALIDATE, 0x01, 0x02, false),
    (INS_VALIDATE, 0x02, 0x01, false),
    (INS_VALIDATE, 0xFF, 0xFF, false),
    (INS_VALIDATE, 0xDE, 0xAD, false),
    // RESET's pair is its own.
    (INS_RESET, 0xDE, 0xAD, true),
    (INS_RESET, 0x00, 0x00, false),
    (INS_RESET, 0xDE, 0x00, false),
    (INS_RESET, 0x00, 0xAD, false),
    (INS_RESET, 0x01, 0xAD, false),
];

/// A body that would carry each command through, so a `6B00` is the parameter
/// bytes and never a malformed request.
fn body_for(ins: u8) -> Vec<u8> {
    let chal = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    match ins {
        INS_PUT => put_data(b"new", 0x21, 6, SECRET_SHA1, false, None),
        INS_DELETE => tlv(TAG_NAME, b"c"),
        INS_SET_CODE => tlv(TAG_KEY, &[]),
        INS_RENAME => [tlv(TAG_NAME, b"c"), tlv(TAG_NAME, b"c2")].concat(),
        INS_CALCULATE => [tlv(TAG_NAME, b"c"), chal].concat(),
        INS_CALC_ALL => chal,
        INS_VALIDATE => [tlv(TAG_RESPONSE, &[0u8; 20]), tlv(TAG_CHALLENGE, &[9u8; 8])].concat(),
        _ => Vec::new(),
    }
}

#[test]
fn only_the_measured_pairs_reach_their_command() {
    for &(ins, p1, p2, taken) in MEASURED {
        let (mut fs, rng, touch) = app_and_fs();
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(b"c", 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
        let sw = run(&mut app, &mut fs, &apdu(ins, p1, p2, &body_for(ins))).0;
        assert_eq!(
            sw != Sw::WRONG_P1P2,
            taken,
            "ins {ins:#04x}, P1 {p1:#04x}, P2 {p2:#04x} answered {sw:?}",
        );
    }
}

#[test]
fn every_command_judges_its_parameters_and_no_other_does() {
    // Driven over the whole instruction byte, so the table `p1p2_ok` carries and
    // the one `process` dispatches on are tied: an instruction added to either
    // alone shows up here. `FF FF` is the pair the card refuses on every command
    // it has, and an instruction that is not ours must still answer `6D00` —
    // ISO 7816-4 §5.3.4 judges INS before P1-P2.
    for ins in 0u8..=255 {
        let (mut fs, rng, touch) = app_and_fs();
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let known = run(&mut app, &mut fs, &apdu(ins, 0, 0, &[])).0 != Sw::INS_NOT_SUPPORTED;
        let (mut fs, rng, touch) = app_and_fs();
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let sw = run(&mut app, &mut fs, &apdu(ins, 0xFF, 0xFF, &[])).0;
        let want = if known {
            Sw::WRONG_P1P2
        } else {
            Sw::INS_NOT_SUPPORTED
        };
        assert_eq!(sw, want, "ins {ins:#04x}, P1 FF, P2 FF");
    }
}

#[test]
fn the_pairs_every_host_sends_are_still_taken() {
    // The control: `00 00` everywhere, `00 01` for the two reads that truncate,
    // `DE AD` for RESET. ykman 5.9.2 and the vendored pico-fido suite send
    // exactly these and nothing else — `P2 = 01` never leaves CALCULATE there.
    let (mut fs, rng, touch) = app_and_fs();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"c", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let chal = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    let mut one = tlv(TAG_NAME, b"c");
    one.extend(chal.clone());
    for (ins, p2, data) in [
        (INS_LIST, 0x00u8, &[][..]),
        (INS_CALCULATE, 0x00, &one),
        (INS_CALCULATE, 0x01, &one),
        (INS_CALC_ALL, 0x00, &chal),
        (INS_CALC_ALL, 0x01, &chal),
        (INS_SEND_REMAINING, 0x00, &[]),
    ] {
        let sw = run(&mut app, &mut fs, &apdu(ins, 0, p2, data)).0;
        assert_eq!(sw, Sw::OK, "ins {ins:#04x}, P2 {p2:#04x}");
    }
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[])).0,
        Sw::OK
    );
}

#[test]
fn a_refused_pair_changes_nothing_the_store_holds() {
    // The gate runs ahead of the dispatch, so a pair the card would refuse
    // cannot reach a handler that writes. `P2 = 01` is the cell this closes: it
    // used to complete a PUT, a DELETE, a RENAME and a SET CODE.
    let (mut fs, rng, touch) = app_and_fs();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"c", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let secret = [0xABu8; 16];
    let mut code = vec![ALG_HMAC_SHA1];
    code.extend_from_slice(&secret);
    let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let set = [
        tlv(TAG_KEY, &code),
        tlv(TAG_CHALLENGE, &chal),
        tlv(TAG_RESPONSE, &hmac_sha1(&secret, &chal)),
    ]
    .concat();
    for (label, ins, data) in [
        (
            "PUT",
            INS_PUT,
            put_data(b"new", 0x21, 6, SECRET_SHA1, false, None),
        ),
        ("DELETE", INS_DELETE, tlv(TAG_NAME, b"c")),
        (
            "RENAME",
            INS_RENAME,
            [tlv(TAG_NAME, b"c"), tlv(TAG_NAME, b"c2")].concat(),
        ),
        ("SET CODE", INS_SET_CODE, set),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(ins, 0, 0x01, &data)).0,
            Sw::WRONG_P1P2,
            "{label}",
        );
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK, "{label}");
        assert_eq!(
            find_tag(&body, TAG_NAME_LIST as u16),
            Some(&[0x21u8, b'c'][..]),
            "{label} reached the store",
        );
        assert!(
            find_tag(&select(&mut app, &mut fs).1, TAG_CHALLENGE as u16).is_none(),
            "{label} installed an access code",
        );
    }
}

#[test]
fn a_reset_with_parameters_the_card_refuses_wipes_nothing() {
    // The one command that destroys the store cannot reach its handler on a pair
    // the card would have refused.
    let (mut fs, rng, touch) = app_and_fs();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"c", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    for (p1, p2) in [(0x00u8, 0x00u8), (0xDE, 0x00), (0x00, 0xAD), (0x01, 0xAD)] {
        let sw = run(&mut app, &mut fs, &apdu(INS_RESET, p1, p2, &[])).0;
        assert_eq!(sw, Sw::WRONG_P1P2, "RESET {p1:#04x} {p2:#04x}");
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert!(
            !body.is_empty(),
            "RESET {p1:#04x} {p2:#04x} wiped the store"
        );
    }
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[])).0,
        Sw::OK
    );
    let (_, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert!(body.is_empty(), "DE AD is still the wipe");
}
