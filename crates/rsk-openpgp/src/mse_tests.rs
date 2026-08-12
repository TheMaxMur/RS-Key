// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn apdu(p1: u8, p2: u8, data: &[u8]) -> Apdu<'_> {
    Apdu {
        cla: 0x00,
        ins: INS_MSE,
        p1,
        p2,
        nc: data.len(),
        ne: 0,
        data,
    }
}

#[test]
fn mse_ct_template_repoints_dec_slot() {
    let mut s = Session::new();
    // Default DEC slot.
    assert_eq!(s.pk_dec, EF_PK_DEC);
    assert_eq!(s.algo_dec, EF_ALGO_PRIV2);
    // P2=0xB8 (CT = PSO:DECIPHER), ref 3 → point DECIPHER at the AUT slot.
    assert_eq!(mse(&mut s, &apdu(0x41, 0xB8, &[0x83, 0x01, 0x03])), Sw::OK);
    assert_eq!(s.pk_dec, EF_PK_AUT);
    assert_eq!(s.algo_dec, EF_ALGO_PRIV3);
    // AUT slot untouched.
    assert_eq!(s.pk_aut, EF_PK_AUT);
}

#[test]
fn mse_at_template_repoints_aut_slot() {
    let mut s = Session::new();
    // P2=0xA4 (AT = INTERNAL AUTHENTICATE), ref 2 → point INT-AUT at the DEC
    // slot. This is §7.2.18's own worked example, `00 22 41 A4 03 83 01 02`.
    assert_eq!(mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x02])), Sw::OK);
    assert_eq!(s.pk_aut, EF_PK_DEC);
    assert_eq!(s.algo_aut, EF_ALGO_PRIV2);
    assert_eq!(s.pk_dec, EF_PK_DEC); // DEC untouched
}

#[test]
fn uif_follows_the_repointed_slot() {
    // The core of #100: after MSE cross-wires DEC → the AUT key, a DECIPHER
    // must enforce the AUT slot's touch policy (EF_UIF_AUT), not DEC's.
    let mut s = Session::new();
    assert_eq!(slot_uif(s.pk_dec), EF_UIF_DEC);
    mse(&mut s, &apdu(0x41, 0xB8, &[0x83, 0x01, 0x03])); // DEC → AUT
    assert_eq!(slot_uif(s.pk_dec), EF_UIF_AUT);
    // Symmetrically for AUT → DEC, and SIG always maps to its own UIF.
    mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x02])); // AUT → DEC
    assert_eq!(slot_uif(s.pk_aut), EF_UIF_DEC);
    assert_eq!(slot_uif(EF_PK_SIG), EF_UIF_SIG);
}

#[test]
fn mse_reset_restores_defaults() {
    let mut s = Session::new();
    mse(&mut s, &apdu(0x41, 0xB8, &[0x83, 0x01, 0x03]));
    s.reset();
    assert_eq!(s.pk_dec, EF_PK_DEC);
    assert_eq!(s.algo_dec, EF_ALGO_PRIV2);
    assert_eq!(s.pk_aut, EF_PK_AUT);
    assert_eq!(s.algo_aut, EF_ALGO_PRIV3);
}

#[test]
fn mse_rejects_bad_p1p2_and_data() {
    let mut s = Session::new();
    assert_eq!(
        mse(&mut s, &apdu(0x00, 0xA4, &[0x83, 0x01, 0x02])),
        Sw::WRONG_P1P2
    );
    assert_eq!(
        mse(&mut s, &apdu(0x41, 0x00, &[0x83, 0x01, 0x02])),
        Sw::WRONG_P1P2
    );
    assert_eq!(
        mse(&mut s, &apdu(0x41, 0xA4, &[0x82, 0x01, 0x02])),
        Sw::INCORRECT_PARAMS
    );
    assert_eq!(
        mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x04])),
        Sw::INCORRECT_PARAMS
    );
    assert_eq!(
        mse(&mut s, &apdu(0x41, 0xA4, &[0x83])),
        Sw::INCORRECT_PARAMS
    );
}
