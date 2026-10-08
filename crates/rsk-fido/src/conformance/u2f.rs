// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! U2F / CTAP1 conformance, driven through the U2F APDU dispatcher
//! (`process_u2f`): the version string, the registration response layout, a
//! register→authenticate round-trip (user-presence flag + counter + signature),
//! and the class/instruction error words.

use super::Authr;
use crate::consts::{
    CTAP_AUTHENTICATE, CTAP_REGISTER, CTAP_VERSION, U2F_AUTH_ENFORCE, U2F_AUTH_FLAG_TUP,
    U2F_REGISTER_ID,
};
use crate::keyderiv::KEY_HANDLE_LEN;
use rsk_sdk::sw::Sw;

const APP: [u8; 32] = [0x5A; 32];
const CHAL: [u8; 32] = [0xC4; 32];

/// A case-1 U2F APDU with no data field (CLA INS P1 P2=0x00).
fn short(cla: u8, ins: u8, p1: u8) -> Vec<u8> {
    std::vec![cla, ins, p1, 0x00]
}

/// An extended-length U2F APDU carrying `data` (extended Lc, extended Le = 0).
fn ext(cla: u8, ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut v = std::vec![
        cla,
        ins,
        p1,
        0x00,
        0x00,
        (data.len() >> 8) as u8,
        data.len() as u8
    ];
    v.extend_from_slice(data);
    v.extend_from_slice(&[0x00, 0x00]);
    v
}

/// The U2F register request body: challenge(32) ‖ application(32).
fn register_data() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&CHAL);
    d.extend_from_slice(&APP);
    d
}

#[test]
fn u2f_version() {
    let (sw, body) = Authr::fresh().send_u2f(&short(0x00, CTAP_VERSION, 0));
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body, b"U2F_V2");
}

#[test]
fn u2f_register_response_shape() {
    let (sw, r) = Authr::fresh().send_u2f(&ext(0x00, CTAP_REGISTER, 0, &register_data()));
    assert_eq!(sw, Sw::OK);
    // 0x05 ‖ 0x04||pubkey(64) ‖ khLen ‖ kh ‖ attestationCert(DER) ‖ signature(DER)
    assert_eq!(r[0], U2F_REGISTER_ID, "legacy reserved byte 0x05");
    assert_eq!(r[1], 0x04, "public key is an uncompressed EC point");
    assert_eq!(r[66] as usize, KEY_HANDLE_LEN, "key-handle length byte");
    let cert = &r[67 + KEY_HANDLE_LEN..];
    assert_eq!(cert[0], 0x30, "attestation certificate is a DER SEQUENCE");
}

#[test]
fn u2f_register_then_authenticate() {
    let mut a = Authr::fresh();
    let (sw, reg) = a.send_u2f(&ext(0x00, CTAP_REGISTER, 0, &register_data()));
    assert_eq!(sw, Sw::OK);
    let key_handle = reg[67..67 + KEY_HANDLE_LEN].to_vec();

    let mut ad = Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&key_handle);
    let (sw, r) = a.send_u2f(&ext(0x00, CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad));
    assert_eq!(sw, Sw::OK);
    // userPresence(1) ‖ counter(4) ‖ signature(DER).
    assert_eq!(
        r[0] & U2F_AUTH_FLAG_TUP,
        U2F_AUTH_FLAG_TUP,
        "user-presence flag set"
    );
    assert!(r.len() >= 5 + 8, "counter and signature present");
    assert_eq!(r[5], 0x30, "authentication signature is a DER SEQUENCE");
}

#[test]
fn u2f_class_and_instruction_errors() {
    let mut a = Authr::fresh();
    // U2F requires CLA 0x00.
    let (sw, _) = a.send_u2f(&short(0x01, CTAP_VERSION, 0));
    assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
    // An unknown instruction is rejected.
    let (sw, _) = a.send_u2f(&short(0x00, 0xEE, 0));
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
}

#[test]
fn u2f_authenticate_signature_verifies() {
    let mut a = Authr::fresh();
    let (sw, reg) = a.send_u2f(&ext(0x00, CTAP_REGISTER, 0, &register_data()));
    assert_eq!(sw, Sw::OK);
    // The registration response carries the credential public key: 0x04 ‖ x ‖ y.
    let x = &reg[2..34];
    let y = &reg[34..66];
    let key_handle = reg[67..67 + KEY_HANDLE_LEN].to_vec();

    let mut ad = Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&key_handle);
    let (sw, r) = a.send_u2f(&ext(0x00, CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad));
    assert_eq!(sw, Sw::OK);
    // U2F authenticate signs application ‖ userPresence(1) ‖ counter(4) ‖ challenge.
    let mut signed = Vec::new();
    signed.extend_from_slice(&APP);
    signed.extend_from_slice(&r[..5]);
    signed.extend_from_slice(&CHAL);
    super::verify_p256(x, y, &signed, &r[5..]);
}

#[test]
fn an_untouched_u2f_registration_returns_no_key_material() {
    let mut authenticator = Authr::declining();
    let generation = authenticator.fs.write_gen();
    assert_eq!(
        authenticator.send_u2f(&ext(0, CTAP_REGISTER, 0, &register_data())),
        (Sw::CONDITIONS_NOT_SATISFIED, vec![])
    );
    assert_eq!(authenticator.fs.write_gen(), generation);
}
