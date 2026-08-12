// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E58: the challenge both read paths take. A YubiKey 5.7.4 treats it as an
//! opaque 0..=64-byte string, HMACs exactly what it was sent and answers `6A80`
//! from 65 — identically on CALCULATE and CALCULATE ALL, before the credential
//! lookup and whatever the credential's type (worklog ORACLE-oathfido §E58).

use super::*;

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>) {
    (new_fs(), RefCell::new(CountRng(7)))
}

fn plain_totp(app: &mut OathApplet, fs: &mut Fs<RamStorage>, name: &[u8]) {
    assert_eq!(
        put(app, fs, &put_data(name, 0x21, 6, SECRET_SHA1, false, None)),
        Sw::OK
    );
}

/// CALCULATE at an arbitrary-width challenge: `(sw, the 4 truncated code bytes)`.
fn calc(
    app: &mut OathApplet,
    fs: &mut Fs<RamStorage>,
    name: &[u8],
    chal: &[u8],
) -> (Sw, Option<[u8; 4]>) {
    let mut d = tlv(TAG_NAME, name);
    d.extend(tlv(TAG_CHALLENGE, chal));
    let (sw, body) = run(app, fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
    if sw != Sw::OK {
        return (sw, None);
    }
    assert_eq!(body[0], TAG_RESPONSE + 1, "{body:02X?}");
    (sw, Some([body[3], body[4], body[5], body[6]]))
}

/// CALCULATE ALL over a one-credential store: `(sw, the 4 truncated code bytes)`.
fn calc_all(app: &mut OathApplet, fs: &mut Fs<RamStorage>, chal: &[u8]) -> (Sw, Option<[u8; 4]>) {
    let (sw, body) = run(
        app,
        fs,
        &apdu(INS_CALC_ALL, 0, 0x01, &tlv(TAG_CHALLENGE, chal)),
    );
    if sw != Sw::OK {
        return (sw, None);
    }
    // [71 len name][76 05 digits code4]
    let at = 2 + body[1] as usize;
    assert_eq!(body[at], TAG_RESPONSE + 1, "{body:02X?}");
    (
        sw,
        Some([body[at + 3], body[at + 4], body[at + 5], body[at + 6]]),
    )
}

/// The card's own answer, computed host-side: the RFC 4226 truncation of the
/// HMAC over the *whole* challenge, reduced to the six digits every credential
/// in this file carries. Independent of both read paths, so a clamp shows up as
/// a value and not just as a disagreement.
fn expected(chal: &[u8]) -> [u8; 4] {
    let mac = hmac_sha1(SECRET_SHA1, chal);
    let off = (mac[19] & 0xF) as usize;
    let trunc = u32::from_be_bytes([mac[off] & 0x7F, mac[off + 1], mac[off + 2], mac[off + 3]]);
    (trunc % 10u32.pow(6)).to_be_bytes()
}

#[test]
fn both_read_paths_hmac_the_whole_challenge() {
    // Measured on the card at every one of these widths: one code, whichever way
    // the host asks for it, and it is the HMAC of all the bytes sent.
    for len in [0usize, 1, 7, 8, 9, 15, 16, 20, 32, 63, 64] {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        plain_totp(&mut app, &mut fs, b"c");
        let chal: Vec<u8> = (0..len).map(|i| 0x40 + i as u8).collect();

        let (sw, one) = calc(&mut app, &mut fs, b"c", &chal);
        assert_eq!(sw, Sw::OK, "CALCULATE at {len} bytes");
        let (sw, all) = calc_all(&mut app, &mut fs, &chal);
        assert_eq!(sw, Sw::OK, "CALCULATE ALL at {len} bytes");
        assert_eq!(one, all, "the two read paths disagree at {len} bytes");
        assert_eq!(one, Some(expected(&chal)), "not the full HMAC at {len}");
    }
}

#[test]
fn calculate_all_does_not_stop_at_the_eighth_byte() {
    // The discriminating pair: two challenges that share their first 8 bytes.
    // A clamp to 8 makes the bulk read answer the same code for both.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    plain_totp(&mut app, &mut fs, b"c");
    let (_, eight) = calc_all(&mut app, &mut fs, &[0x11; 8]);
    let (_, nine) = calc_all(&mut app, &mut fs, &[0x11; 9]);
    assert_ne!(eight, nine, "the ninth byte changed nothing");
    assert_eq!(nine, Some(expected(&[0x11; 9])));
}

#[test]
fn a_challenge_of_sixty_five_bytes_is_refused_on_both_paths() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    plain_totp(&mut app, &mut fs, b"c");
    // A plain credential: nothing else in the applet can refuse this for us.
    assert_eq!(
        calc(&mut app, &mut fs, b"c", &[0x01; 65]).0,
        Sw::INCORRECT_PARAMS
    );
    assert_eq!(
        calc_all(&mut app, &mut fs, &[0x01; 65]).0,
        Sw::INCORRECT_PARAMS
    );
    // …and 64 still computes, so the bound is where the card puts it.
    assert_eq!(calc(&mut app, &mut fs, b"c", &[0x01; 64]).0, Sw::OK);
    assert_eq!(calc_all(&mut app, &mut fs, &[0x01; 64]).0, Sw::OK);
}

#[test]
fn the_bound_holds_for_hotp_which_ignores_the_challenge() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    assert_eq!(calc(&mut app, &mut fs, b"h", &[0x01; 64]).0, Sw::OK);
    assert_eq!(
        calc(&mut app, &mut fs, b"h", &[0x01; 65]).0,
        Sw::INCORRECT_PARAMS
    );
}

#[test]
fn the_bound_is_judged_after_p1p2_and_before_the_credential() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    plain_totp(&mut app, &mut fs, b"c");

    // No such credential: 6A80 at 65 bytes, 6984 at 8 — so the width is judged
    // before the lookup, exactly as the card orders it.
    assert_eq!(
        calc(&mut app, &mut fs, b"nope", &[0x01; 65]).0,
        Sw::INCORRECT_PARAMS
    );
    assert_eq!(
        calc(&mut app, &mut fs, b"nope", &[0x01; 8]).0,
        Sw::DATA_INVALID
    );

    // An undefined P2 outranks it, and answers with its own word (E60).
    let mut d = tlv(TAG_NAME, b"c");
    d.extend(tlv(TAG_CHALLENGE, &[0x01; 65]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x02, &d));
    assert_eq!(sw, Sw::WRONG_P1P2, "P1/P2 is judged first");
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x02, &d));
    assert_eq!(sw, Sw::WRONG_P1P2, "P1/P2 is judged first");
}

#[test]
fn the_bulk_read_marks_the_challenge_it_computed_from() {
    // E32 rides on E58: `advance_marks` has always compared the challenge the
    // host sent, so a clamped code meant the mark recorded bytes no code was
    // ever computed from. The two must be the same bytes.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut d = tlv(TAG_NAME, b"inc");
    let mut key = vec![0x21u8, 6];
    key.extend_from_slice(SECRET_SHA1);
    d.extend(tlv(TAG_KEY, &key));
    d.extend([TAG_PROPERTY, PROP_INCREASING]);
    assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);

    let mut chal = [0x11u8; 16];
    chal[15] = 0x22;
    let (sw, code) = calc_all(&mut app, &mut fs, &chal);
    assert_eq!(sw, Sw::OK);
    assert_eq!(code, Some(expected(&chal)));
    // The mark now stands at all 16 bytes: the same challenge is refused, and
    // one greater only in the sixteenth byte still computes.
    assert_eq!(
        calc(&mut app, &mut fs, b"inc", &chal).0,
        Sw::INCORRECT_PARAMS
    );
    chal[15] = 0x23;
    assert_eq!(calc(&mut app, &mut fs, b"inc", &chal).0, Sw::OK);
}

#[test]
fn an_over_wide_challenge_advances_no_only_increasing_mark() {
    // A guard, not a discriminator: `raise_mark` refuses a mark wider than it
    // can hold, so this cell also held before the bound existed. It is here so
    // that whichever of the two rules is rewritten next, the other still keeps
    // an over-wide challenge from consuming the store's marks.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut d = tlv(TAG_NAME, b"inc");
    let mut key = vec![0x21u8, 6];
    key.extend_from_slice(SECRET_SHA1);
    d.extend(tlv(TAG_KEY, &key));
    d.extend([TAG_PROPERTY, PROP_INCREASING]);
    assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);

    assert_eq!(
        calc_all(&mut app, &mut fs, &[0xFF; 65]).0,
        Sw::INCORRECT_PARAMS
    );
    // The mark never moved: a modest challenge still computes.
    assert_eq!(calc(&mut app, &mut fs, b"inc", &[0x01; 8]).0, Sw::OK);
}

#[test]
fn send_remaining_pages_carry_the_whole_challenge() {
    // The paged half of the bulk read recomputes from the stashed challenge, so
    // a stash narrower than the challenge would serve page 2 a different code
    // from page 1 — silently, under 9000.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let chal = [0x5Au8; 40];
    for i in 0..MAX_OATH_CRED {
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(&acct_name(i), 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
    }
    let (pages, body) = enumerate_all(
        &mut app,
        &mut fs,
        &apdu(INS_CALC_ALL, 0, 0x01, &tlv(TAG_CHALLENGE, &chal)),
    );
    assert!(pages >= 2, "the store must not fit one page");
    assert_eq!(count_tag(&body, TAG_NAME), MAX_OATH_CRED as usize);
    // Every entry — both pages — carries the same secret's code at this challenge.
    let want = expected(&chal);
    let mut i = 0;
    let mut seen = 0;
    while i + 2 <= body.len() {
        let len = body[i + 1] as usize;
        if body[i] == TAG_RESPONSE + 1 {
            assert_eq!(&body[i + 3..i + 7], &want, "entry {seen}");
            seen += 1;
        }
        i += 2 + len;
    }
    assert_eq!(seen, MAX_OATH_CRED as usize);
}
