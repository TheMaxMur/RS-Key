// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E44: a failed OTP-PIN CHANGE (`0xB3`) must drop the standing authentication,
//! exactly as its sibling VERIFY (`0xB2`) does.
//!
//! No YubiKey behaviour exists to copy — measured, not assumed: a 5.7.4 answers
//! `6D00` to all 256 INS bytes in this family and does not distinguish it from
//! any other unimplemented instruction (worklog TRACK-oath §8). So the applet's
//! own siblings decide, and they disagreed about one rule.

use super::*;

/// A store with one password-safe credential and an OTP PIN of `1234`.
fn safe_store(app: &mut OathApplet, fs: &mut Fs<RamStorage>) {
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(put(app, fs, &cred), Sw::OK);
    assert_eq!(
        run(
            app,
            fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
}

/// Whether `0xB5` GET CREDENTIAL still serves the stored password.
fn safe_open(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> bool {
    let (sw, _) = run(
        app,
        fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank")),
    );
    match sw {
        Sw::OK => true,
        Sw::SECURITY_STATUS_NOT_SATISFIED => false,
        other => panic!("unexpected GET CREDENTIAL status {other:?}"),
    }
}

fn verify(app: &mut OathApplet, fs: &mut Fs<RamStorage>, pin: &[u8]) -> Sw {
    run(
        app,
        fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, pin)),
    )
    .0
}

fn change(app: &mut OathApplet, fs: &mut Fs<RamStorage>, old: &[u8], new: &[u8]) -> Sw {
    let mut d = tlv(TAG_PASSWORD, old);
    d.extend(tlv(TAG_NEW_PASSWORD, new));
    run(app, fs, &apdu(INS_CHANGE_PIN, 0, 0, &d)).0
}

#[test]
fn a_failed_change_drops_the_standing_authentication() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);
    assert!(!safe_open(&mut app, &mut fs), "closed before any PIN");

    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs), "a correct PIN opens it");
    assert_eq!(
        change(&mut app, &mut fs, b"9999", b"5678"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(
        !safe_open(&mut app, &mut fs),
        "a failed CHANGE left the password safe open",
    );

    // The sibling, same store, same run: the rule they must agree on.
    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs));
    assert_eq!(
        verify(&mut app, &mut fs, b"9999"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(!safe_open(&mut app, &mut fs), "the control must fire");
}

#[test]
fn the_safe_closes_when_the_retry_budget_is_spent() {
    // The sharpest cell: the anti-bruteforce machinery worked perfectly and
    // protected nothing that was already open — the card refused even the
    // correct PIN while `0xB5` went on serving the stored password.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs));

    for i in 0..=MAX_OTP_COUNTER {
        assert_eq!(
            change(&mut app, &mut fs, b"9999", b"5678"),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "failed CHANGE {i}",
        );
    }
    // Locked out, as designed — and the safe is shut with it.
    assert_eq!(
        change(&mut app, &mut fs, b"1234", b"5678"),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the correct old PIN after lock-out",
    );
    assert!(
        !safe_open(&mut app, &mut fs),
        "the safe served secrets through a full lock-out",
    );
}

#[test]
fn a_malformed_change_keeps_the_standing_authentication() {
    // Where the sibling actually draws its line is "a PIN was compared", not
    // "at entry": VERIFY with no password TLV answers 6A80 and keeps the unlock.
    // CHANGE has to match the placement, not the comment above it.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);

    for (label, body) in [
        ("no 0x80 TLV", tlv(TAG_NEW_PASSWORD, b"5678")),
        ("no 0x81 TLV", tlv(TAG_PASSWORD, b"1234")),
    ] {
        assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &body));
        assert_eq!(sw, Sw::INCORRECT_PARAMS, "CHANGE with {label}");
        assert!(safe_open(&mut app, &mut fs), "CHANGE with {label}");
    }
    // And the sibling agrees on that half.
    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(0x71, b"x")),
    );
    assert_eq!(sw, Sw::INCORRECT_PARAMS);
    assert!(safe_open(&mut app, &mut fs));
}

#[test]
fn a_failed_change_drops_an_access_code_unlock_too() {
    // The fix's width. `validated` is reachable THROUGH the OTP PIN — VERIFY
    // sets it, doubling as VALIDATE for the nitropy flow — so one bool carries
    // both provenances and the applet cannot tell them apart. Leaving it
    // standing after a failed compare leaves a status that could have been
    // obtained by proving the very PIN the caller just failed. VERIFY already
    // makes that trade; the two siblings now make the same one.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
    // The code first: SET CODE deliberately drops any standing OTP-PIN.
    lock_with_code(&mut app, &mut fs);

    /// Answer the challenge the current SELECT handed out — nothing else.
    fn validate(app: &mut OathApplet, fs: &mut Fs<RamStorage>, body: &[u8]) -> Sw {
        let card_chal = find_tag(body, TAG_CHALLENGE as u16).unwrap().to_vec();
        let mut d = tlv(TAG_CHALLENGE, &[9u8, 9, 9, 9, 8, 8, 8, 8]);
        d.extend(tlv(TAG_RESPONSE, &hmac_sha1(&[0xAB; 16], &card_chal)));
        run(app, fs, &apdu(INS_VALIDATE, 0, 0, &d)).0
    }

    let (_, body) = select(&mut app, &mut fs);
    assert_eq!(validate(&mut app, &mut fs, &body), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );

    // A fresh session that proves ONLY the access code: the applet is open, the
    // password safe is not.
    let (_, body) = select(&mut app, &mut fs);
    assert_eq!(validate(&mut app, &mut fs, &body), Sw::OK);
    assert_eq!(run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0, Sw::OK);
    assert!(!safe_open(&mut app, &mut fs));

    assert_eq!(
        change(&mut app, &mut fs, b"9999", b"5678"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a failed PIN compare left the applet unlocked",
    );
}

#[test]
fn a_successful_change_does_not_open_the_safe() {
    // CHANGE never grants, only drops: it is a one-way loss, and stays one.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);
    assert_eq!(change(&mut app, &mut fs, b"1234", b"5678"), Sw::OK);
    assert!(!safe_open(&mut app, &mut fs), "CHANGE opened the safe");
    assert_eq!(verify(&mut app, &mut fs, b"5678"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs), "the new PIN opens it");
}
