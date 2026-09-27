// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Each OATH command with every flash read it makes failed in turn — the read half
//! of the fault sweep ([`rsk_fs::probe::sweep`]). SET CODE is not here: past its
//! SELECT it reads nothing, which the sweep refuses as vacuous.

use super::*;
use rsk_fs::probe::{Traced, sweep};

/// An applet over its own randomness and presence. Leaked: the applet borrows
/// them for the whole run, and a run is one sweep step.
fn applet() -> OathApplet<'static> {
    let rng: &'static RefCell<CountRng> = Box::leak(Box::new(RefCell::new(CountRng(7))));
    let touch: &'static RefCell<AlwaysConfirm> = Box::leak(Box::new(RefCell::new(AlwaysConfirm)));
    OathApplet::new(SERIAL, [0x22; 32], None, rng, touch)
}

fn put_ok(app: &mut OathApplet, fs: &mut Fs<Traced>, data: &[u8]) {
    assert_eq!(put(app, fs, data), Sw::OK);
}

/// A HOTP and a TOTP account and a password-safe entry, then a new connection.
fn stocked(fs: &mut Fs<Traced>) -> OathApplet<'static> {
    fs.scan();
    let mut app = applet();
    select(&mut app, fs);
    put_ok(
        &mut app,
        fs,
        &put_data(b"hotp", 0x11, 6, &[0xAA; 20], false, Some(5)),
    );
    put_ok(
        &mut app,
        fs,
        &put_data(b"totp", 0x21, 6, &[0xBB; 20], false, None),
    );
    let mut pws = put_data(b"bank", 0x21, 6, &[0xCC; 20], false, None);
    pws.extend(tlv(TAG_PWS_LOGIN, b"alice"));
    pws.extend(tlv(TAG_PWS_PASSWORD, b"hunter2"));
    put_ok(&mut app, fs, &pws);
    let mut app = applet();
    select(&mut app, fs);
    app
}

/// [`stocked`] with an OTP-PIN over the password safe, on a new connection.
fn pinned(fs: &mut Fs<Traced>) -> OathApplet<'static> {
    let mut app = stocked(fs);
    let set = apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"));
    assert_eq!(run(&mut app, fs, &set).0, Sw::OK);
    let mut app = applet();
    select(&mut app, fs);
    app
}

fn sends(raw: Vec<u8>) -> impl Fn(&mut Fs<Traced>, &mut OathApplet<'static>) -> bool {
    move |fs, app| run(app, fs, &raw).0 == Sw::OK
}

fn named(names: &[&[u8]]) -> Vec<u8> {
    names.iter().flat_map(|n| tlv(TAG_NAME, n)).collect()
}

/// One account per name: PUT over a taken name replaces it, RENAME onto one is
/// refused, and a slot the flash would not serve may hold either name.
#[test]
fn a_faulted_read_fails_an_account_write_or_lands_it_whole() {
    let fresh = put_data(b"new", 0x21, 6, &[0xDD; 20], false, None);
    let over = put_data(b"totp", 0x21, 8, &[0xEE; 20], false, None);
    for raw in [
        apdu(INS_PUT, 0, 0, &fresh),
        apdu(INS_PUT, 0, 0, &over),
        apdu(INS_DELETE, 0, 0, &named(&[b"totp"])),
        apdu(INS_RENAME, 0, 0, &named(&[b"totp", b"totp2"])),
        apdu(INS_RENAME, 0, 0, &named(&[b"totp", b"hotp"])),
    ] {
        sweep(stocked, sends(raw), &[]);
    }
}

/// HOTP advances its counter with every code; a fault may fail the code, never
/// hand out one for a counter already spent.
#[test]
fn a_faulted_read_fails_a_hotp_code_or_advances_the_counter() {
    let mut calc = named(&[b"hotp"]);
    calc.extend(tlv(TAG_CHALLENGE, &[]));
    sweep(stocked, sends(apdu(INS_CALCULATE, 0, 0x01, &calc)), &[]);
}

/// Behind an access code nothing is served before VALIDATE: SELECT reads whether a
/// code is set, and a probe the flash failed must lock the session, not open it.
#[test]
fn no_faulted_read_opens_a_code_locked_store() {
    sweep(
        |fs| {
            let mut app = stocked(fs);
            lock_with_code(&mut app, fs);
            applet()
        },
        |fs, app| {
            select(app, fs);
            run(app, fs, &apdu(INS_LIST, 0, 0, &[])).0 == Sw::OK
        },
        &[],
    );
}

/// The OTP-PIN is the password safe's own gate: GET CREDENTIAL without it is
/// refused, whatever a read did; with it, it answers as clean.
#[test]
fn no_faulted_read_opens_the_password_safe_without_its_pin() {
    let get = apdu(INS_GET_CREDENTIAL, 0, 0, &named(&[b"bank"]));
    sweep(pinned, sends(get.clone()), &[]);
    sweep(
        pinned,
        move |fs, app| {
            let verify = apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"));
            run(app, fs, &verify).0 == Sw::OK && run(app, fs, &get).0 == Sw::OK
        },
        &[],
    );
}

#[test]
fn a_faulted_read_fails_a_pin_command_or_lands_it_whole() {
    let mut change = tlv(TAG_PASSWORD, b"1234");
    change.extend(tlv(TAG_NEW_PASSWORD, b"5678"));
    for raw in [
        apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
        apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"0000")),
        apdu(INS_CHANGE_PIN, 0, 0, &change),
    ] {
        sweep(pinned, sends(raw), &[]);
    }
}
