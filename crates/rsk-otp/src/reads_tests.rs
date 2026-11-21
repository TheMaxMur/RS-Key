// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Each OTP command with every flash read it makes failed in turn — the read half
//! of the fault sweep ([`rsk_fs::probe::sweep`]).

use super::*;
use rsk_fs::probe::{Traced, sweep};

const ACC: [u8; 6] = [1, 2, 3, 4, 5, 6];

/// An applet over its own randomness and presence. Leaked: the applet borrows
/// them for the whole run, and a run is one sweep step.
fn applet() -> OtpApplet<'static> {
    let rng: &'static RefCell<CountRng> = Box::leak(Box::new(RefCell::new(CountRng(7))));
    let pres: &'static RefCell<AlwaysConfirm> = Box::leak(Box::new(RefCell::new(AlwaysConfirm)));
    OtpApplet::new(SERIAL, SERIAL_HASH, None, rng, pres)
}

/// Slot 1 a challenge-response credential behind an access code, slot 2 a typed
/// Yubico OTP; then a new connection.
fn stocked(fs: &mut Fs<Traced>) -> OtpApplet<'static> {
    fs.scan();
    let mut app = applet();
    let protected = chalresp_config(&[0x33; 20], &ACC, 0);
    assert_eq!(
        configure(&mut app, fs, P1_CONFIG_SLOT1, 0, &protected, &[0; 6]).0,
        Sw::OK
    );
    let typed = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
    assert_eq!(
        configure(&mut app, fs, P1_CONFIG_SLOT2, 0, &typed, &[0; 6]).0,
        Sw::OK
    );
    let mut app = applet();
    select(&mut app, fs);
    app
}

/// A slot write answers with the applet's status, whose valid-slot bits read each
/// slot the collapsing way on purpose (`status_bytes`): a status field, so only
/// the answer's word and the store are compared.
fn sends(raw: Vec<u8>) -> impl Fn(&mut Fs<Traced>, &mut OtpApplet<'static>) -> Option<Vec<u8>> {
    move |fs, app| (run(app, fs, &raw).0 == Sw::OK).then(Vec::new)
}

fn with_code(config: &[u8; CONFIG_SIZE], code: &[u8; 6]) -> Vec<u8> {
    let mut d = config.to_vec();
    d.extend_from_slice(code);
    d
}

/// The access code gates every rewrite of the slot it protects; a slot the flash
/// would not serve must not read as an unprotected one.
#[test]
fn no_faulted_read_rewrites_a_protected_slot_without_its_code() {
    let other = chalresp_config(&[0xCC; 20], &[0; 6], 0);
    for raw in [
        otp_apdu(P1_CONFIG_SLOT1, 0, &with_code(&other, &[0; 6])),
        otp_apdu(P1_UPDATE_SLOT1, 0, &with_code(&other, &[0; 6])),
        otp_apdu(P1_CONFIG_SLOT1, 0, &with_code(&[0; CONFIG_SIZE], &[0; 6])),
        otp_apdu(P1_SWAP, 0, &[]),
    ] {
        sweep(stocked, sends(raw), &[]);
    }
}

/// Each write with the code its slot asks for, so the clean run lands it. The swap
/// moves the protected slot 1 to the vacant slot 3: one code cannot match both of
/// two programmed slots with different codes, so 1↔2 is refused whole.
#[test]
fn a_faulted_read_fails_a_slot_write_or_lands_it_whole() {
    let other = chalresp_config(&[0xCC; 20], &[0; 6], 0);
    let mut swap = [0u8; 2 + ACC_CODE_SIZE];
    swap[1] = 1;
    swap[2..].copy_from_slice(&ACC);
    for raw in [
        otp_apdu(P1_CONFIG_SLOT1, 0, &with_code(&other, &ACC)),
        otp_apdu(P1_UPDATE_SLOT2, 0, &with_code(&other, &[0; 6])),
        otp_apdu(P1_CONFIG_SLOT1, 0, &with_code(&[0; CONFIG_SIZE], &ACC)),
        otp_apdu(P1_SWAP, 0, &swap),
    ] {
        assert!(
            sweep(stocked, sends(raw.clone()), &[]).is_some(),
            "vacuous: the clean run refused {raw:02X?}"
        );
    }
}
