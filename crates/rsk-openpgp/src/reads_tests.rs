// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Each OpenPGP command with every flash read it makes failed in turn — the read
//! half of the fault sweep ([`rsk_fs::probe::sweep`]).

use super::*;
use rsk_fs::probe::{Traced, sweep};

const OWNER_PW1: &[u8] = b"481629";
const OWNER_PW3: &[u8] = b"73915482";

/// An applet over its own randomness and presence. Leaked: the applet borrows
/// them for the whole run, and a run is one sweep step.
fn applet() -> OpenpgpApplet<'static> {
    let rng: &'static RefCell<CountRng> = Box::leak(Box::new(RefCell::new(CountRng(7))));
    let pres: &'static RefCell<crate::AlwaysConfirm> =
        Box::leak(Box::new(RefCell::new(crate::AlwaysConfirm)));
    OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, rng, pres)
}

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![0x00, ins, p1, p2, data.len() as u8];
    a.extend_from_slice(data);
    a
}

fn change(app: &mut OpenpgpApplet, fs: &mut Fs<Traced>, mode: u8, old: &[u8], new: &[u8]) {
    let body = [old, new].concat();
    assert_eq!(
        run(app, fs, &apdu(consts::INS_CHANGE_PIN, 0, mode, &body)).1,
        Sw::OK
    );
}

/// A card its owner took over — both passwords off their defaults — holding a
/// P-256 signing key, then disconnected: the next command starts a new session.
fn owned(fs: &mut Fs<Traced>) -> OpenpgpApplet<'static> {
    fs.scan();
    scan_files(&dev(), fs, &mut CountRng(0)).unwrap();
    let mut app = applet();
    change(
        &mut app,
        fs,
        consts::PW1_MODE81,
        consts::PW1_DEFAULT,
        OWNER_PW1,
    );
    change(
        &mut app,
        fs,
        consts::PW3_MODE83,
        consts::PW3_DEFAULT,
        OWNER_PW3,
    );
    verify_pin(&mut app, fs, consts::PW3_MODE83, OWNER_PW3);
    assert_eq!(put(&mut app, fs, 0x00, 0xC1, ATTR_P256), Sw::OK);
    assert_eq!(run(&mut app, fs, &ec_import(0xB6, &[0x11; 32])).1, Sw::OK);
    applet()
}

fn sends(raw: Vec<u8>) -> impl Fn(&mut Fs<Traced>, &mut OpenpgpApplet<'static>) -> bool {
    move |fs, app| run(app, fs, &raw).1 == Sw::OK
}

/// The boot-time file scan; one faulted probe of PW1 there once replaced the
/// owner's password with the default and answered Ok (0x0995).
#[test]
fn no_faulted_read_at_boot_reseeds_a_default_password() {
    sweep(
        owned,
        |fs, _| scan_files(&dev(), fs, &mut CountRng(0)).is_ok(),
        &[],
    );
}

#[test]
fn a_faulted_read_fails_a_verify_or_answers_it_as_clean() {
    for (mode, pw) in [
        (consts::PW1_MODE81, OWNER_PW1),
        (consts::PW1_MODE82, OWNER_PW1),
        (consts::PW3_MODE83, OWNER_PW3),
    ] {
        sweep(owned, sends(apdu(consts::INS_VERIFY, 0, mode, pw)), &[]);
    }
}

/// A default password is the wrong one now: refused, a retry spent, never admitted.
#[test]
fn no_faulted_read_admits_a_default_password() {
    for (mode, pw) in [
        (consts::PW1_MODE81, consts::PW1_DEFAULT),
        (consts::PW3_MODE83, consts::PW3_DEFAULT),
    ] {
        sweep(owned, sends(apdu(consts::INS_VERIFY, 0, mode, pw)), &[]);
    }
}

#[test]
fn a_faulted_read_fails_a_password_change_or_lands_it_whole() {
    for (mode, old, new) in [
        (consts::PW1_MODE81, OWNER_PW1, &b"55555555"[..]),
        (consts::PW3_MODE83, OWNER_PW3, &b"66666666"[..]),
    ] {
        let body = [old, new].concat();
        sweep(
            owned,
            sends(apdu(consts::INS_CHANGE_PIN, 0, mode, &body)),
            &[],
        );
    }
}

/// RESET RETRY COUNTER with PW3 standing: a new PW1 without the old one.
#[test]
fn a_faulted_read_fails_an_admin_reset_of_pw1_or_lands_it_whole() {
    sweep(
        |fs| {
            let mut app = owned(fs);
            verify_pin(&mut app, fs, consts::PW3_MODE83, OWNER_PW3);
            app
        },
        sends(apdu(
            consts::INS_RESET_RETRY,
            0x02,
            consts::PW1_MODE81,
            b"55555555",
        )),
        &[],
    );
}

/// An algorithm attribute change invalidates the key under it; a faulted read may
/// not skip that and leave the old key serving the new attribute (0x0995). Back to
/// the default as well: a faulted read of the stored attribute reads as the default,
/// so that is the change a fault could mistake for none.
#[test]
fn a_faulted_read_fails_an_attribute_change_or_lands_it_whole() {
    for attr in [ATTR_ED25519, consts::DEFAULT_ALGO] {
        sweep(
            |fs| {
                let mut app = owned(fs);
                verify_pin(&mut app, fs, consts::PW3_MODE83, OWNER_PW3);
                app
            },
            sends(apdu(consts::INS_PUT_DATA, 0x00, 0xC1, attr)),
            &[],
        );
    }
}

#[test]
fn a_faulted_read_fails_an_import_or_lands_it_whole() {
    sweep(
        |fs| {
            let mut app = owned(fs);
            verify_pin(&mut app, fs, consts::PW3_MODE83, OWNER_PW3);
            app
        },
        sends(ec_import(0xB6, &[0x22; 32])),
        &[],
    );
}

/// PSO:CDS advances the signature counter, which a fault may never roll back.
#[test]
fn a_faulted_read_fails_a_signature_or_advances_the_counter() {
    let mut pso = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, 32];
    pso.extend_from_slice(&[0x42; 32]);
    sweep(
        |fs| {
            let mut app = owned(fs);
            verify_pin(&mut app, fs, consts::PW1_MODE81, OWNER_PW1);
            app
        },
        sends(pso),
        &[],
    );
}
