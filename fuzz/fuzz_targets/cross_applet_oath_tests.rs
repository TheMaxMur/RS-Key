// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::super::{Board, Finger, RescueBoard, SeqRng, VendorBoard, exercise};
use super::super::{FLASH_SIZE, KV_TOTAL, OPENPGP_MFR, SERIAL_HASH, SERIAL_ID};
use super::*;
use core::cell::RefCell;
use rsk_device::CcidApplets;
use rsk_fs::{Fs, storage::ram::RamStorage};

const CODE: [u8; 16] = [0x5A; 16];
const RAW: u8 = 0x08;

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut data = vec![tag, u8::try_from(value.len()).unwrap()];
    data.extend_from_slice(value);
    data
}

fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        raw.push(u8::try_from(data.len()).unwrap());
        raw.extend_from_slice(data);
    }
    raw
}

fn select(aid: &[u8]) -> Vec<u8> {
    apdu(0, 0xA4, 4, 0, aid)
}

fn put(name: &[u8]) -> Vec<u8> {
    let mut data = tlv(NAME, name);
    let mut key = vec![0x21, 6];
    key.extend_from_slice(&[0xAA; 20]);
    data.extend(tlv(KEY, &key));
    data
}

fn calculate(name: &[u8]) -> Vec<u8> {
    let mut data = tlv(NAME, name);
    data.extend(tlv(0x74, &[0; 8]));
    apdu(0, CALCULATE, 0, 1, &data)
}

// Check real status directions first, then replay the same bytes through the
// shipped fuzz entrypoint. Its oracle must accept the real card's transitions.
fn with_card(test: impl FnOnce(&mut dyn FnMut(&[u8]) -> Vec<u8>)) {
    let fs = RefCell::new(Fs::new(RamStorage::new()));
    fs.borrow_mut().scan();
    let rng = RefCell::new(SeqRng(1));
    let board = RefCell::new(Board);
    let finger = RefCell::new(Finger);
    let rescue = RefCell::new(RescueBoard::default());
    let fido = RefCell::new(rsk_fido::FidoState::new());
    let mut ccid = CcidApplets::new(
        &fs,
        &rng,
        &board,
        &finger,
        &fido,
        &rescue,
        VendorBoard,
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        KV_TOTAL,
        FLASH_SIZE,
        OPENPGP_MFR,
    );
    assert_eq!(
        status(ccid.handle_apdu(&select(rsk_oath::OATH_AID), 0)),
        Sw::OK
    );
    let mut replay = vec![OATH_INDEX as u8];
    {
        let mut send = |raw: &[u8]| {
            assert!(raw.len() < 0xFF);
            replay.extend([RAW, u8::try_from(raw.len()).unwrap()]);
            replay.extend_from_slice(raw);
            ccid.handle_apdu(raw, 0).to_vec()
        };
        test(&mut send);
    }
    exercise(&replay);
}

fn install(send: &mut dyn FnMut(&[u8]) -> Vec<u8>) {
    assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
    let mut key = vec![1];
    key.extend_from_slice(&CODE);
    let mut data = tlv(KEY, &key);
    data.extend(tlv(0x74, &[1; 8]));
    data.extend(tlv(0x75, &rsk_crypto::hmac_sha1(&CODE, &[1; 8])));
    assert_eq!(status(&send(&apdu(0, SET_CODE, 0, 0, &data))), Sw::OK);
}

fn validate(send: &mut dyn FnMut(&[u8]) -> Vec<u8>) {
    let response = send(&select(rsk_oath::OATH_AID));
    assert_eq!(status(&response), Sw::OK);
    let challenge = rsk_sdk::tlv::find_tag(&response[..response.len() - 2], 0x74).unwrap();
    let mut data = tlv(0x75, &rsk_crypto::hmac_sha1(&CODE, challenge));
    data.extend(tlv(0x74, &[9; 8]));
    assert_eq!(status(&send(&apdu(0, VALIDATE, 0, 0, &data))), Sw::OK);
}

#[test]
fn remove_code_opens_the_session_and_survives_reselect() {
    with_card(|send| {
        install(send);
        validate(send);
        assert_eq!(status(&send(&apdu(0, SET_CODE, 0, 0, &[KEY, 0]))), Sw::OK);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"removed")))), Sw::OK);
        assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
        assert_eq!(status(&send(&calculate(b"removed"))), Sw::OK);
    });
}

#[test]
fn rename_moves_the_live_name_and_delete_removes_the_new_name() {
    with_card(|send| {
        assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"old")))), Sw::OK);
        let mut rename = tlv(NAME, b"old");
        rename.extend([PROPERTY, 0]);
        rename.extend([NAME, 0x81, 3]);
        rename.extend_from_slice(b"new");
        assert_eq!(status(&send(&apdu(0, RENAME, 0, 0, &rename))), Sw::OK);
        assert_eq!(status(&send(&calculate(b"old"))), Sw::DATA_INVALID);
        assert_eq!(status(&send(&calculate(b"new"))), Sw::OK);
        assert_eq!(
            status(&send(&apdu(0, DELETE, 0, 0, &tlv(NAME, b"new")))),
            Sw::OK
        );
        assert_eq!(status(&send(&calculate(b"new"))), Sw::DATA_INVALID);
    });
}

#[test]
fn delete_uses_ber_fields_without_interpreting_their_payload_as_names() {
    with_card(|send| {
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"A")))), Sw::OK);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"B")))), Sw::OK);
        let body = [PROPERTY, 3, NAME, 1, b'A', NAME, 1, b'B'];
        assert_eq!(status(&send(&apdu(0, DELETE, 0, 0, &body))), Sw::OK);
        assert_eq!(status(&send(&calculate(b"A"))), Sw::OK);
        assert_eq!(status(&send(&calculate(b"B"))), Sw::DATA_INVALID);
    });
}

#[test]
fn raw_select_prefix_and_failed_select_preserve_the_right_grant() {
    with_card(|send| {
        install(send);
        validate(send);
        assert_eq!(status(&send(&select(&rsk_oath::OATH_AID[..6]))), Sw::OK);
        assert_eq!(status(&send(&select(&[0xFF]))), Sw::FILE_NOT_FOUND);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"kept")))), Sw::OK);
        assert_eq!(status(&send(&select(rsk_mgmt::MANAGEMENT_AID))), Sw::OK);
        assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
        assert_eq!(
            status(&send(&calculate(b"kept"))),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
    });
}

#[test]
fn failed_validate_does_not_grant_or_revoke_authorization() {
    with_card(|send| {
        install(send);
        let mut wrong = tlv(0x75, &[0; 20]);
        wrong.extend(tlv(0x74, &[9; 8]));
        assert_eq!(
            status(&send(&apdu(0, VALIDATE, 0, 0, &wrong))),
            Sw::WRONG_DATA
        );
        assert_eq!(
            status(&send(&apdu(0, PUT, 0, 0, &put(b"locked")))),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        validate(send);
        for data in [wrong, vec![0x75, 0]] {
            assert_eq!(
                status(&send(&apdu(0, VALIDATE, 0, 0, &data))),
                Sw::WRONG_DATA
            );
            assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"kept")))), Sw::OK);
        }
    });
}

#[test]
fn oath_reset_clears_code_and_records() {
    with_card(|send| {
        assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"old")))), Sw::OK);
        install(send);
        assert_eq!(status(&send(&apdu(0, RESET, 0xDE, 0xAD, &[]))), Sw::OK);
        assert_eq!(status(&send(&calculate(b"old"))), Sw::DATA_INVALID);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &put(b"new")))), Sw::OK);
    });
}

#[test]
fn chain_acknowledgement_is_not_a_completed_put() {
    with_card(|send| {
        assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
        let data = put(b"split");
        assert_eq!(status(&send(&apdu(0x10, PUT, 0, 0, &data[..3]))), Sw::OK);
        assert_eq!(status(&send(&apdu(0, PUT, 0, 0, &data[3..]))), Sw::OK);
        assert_eq!(status(&send(&calculate(b"split"))), Sw::OK);
        install(send);
        assert_eq!(status(&send(&apdu(0x10, PUT, 0, 0, &data[..3]))), Sw::OK);
        assert_eq!(
            status(&send(&apdu(0, PUT, 0, 0, &data[3..]))),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
    });
}

#[test]
fn unserved_class_does_not_produce_an_oracle_status_word() {
    with_card(|send| {
        assert_eq!(status(&send(&select(rsk_oath::OATH_AID))), Sw::OK);
        assert!(send(&apdu(0x01, PUT, 0, 0, &put(b"silent"))).is_empty());
    });
}

#[test]
fn card_reset_keeps_records_but_factory_wipe_does_not_reset_selection() {
    let mut model = OathOracle {
        selected: Some(OATH_INDEX),
        ..OathOracle::default()
    };
    model.command(PUT, &put(b"old"), &[0x90, 0], Sw::OK);
    model.code_set = true;
    model.validated = true;
    model.reset_card();
    assert_eq!(model.live, [b"old".to_vec()]);
    assert!(model.code_set && !model.validated && model.selected.is_none());
    model.selected = Some(OATH_INDEX);
    model.factory_wipe();
    assert!(model.live.is_empty() && !model.code_set);
    assert_eq!(model.selected, Some(OATH_INDEX));
    let mut replay = vec![OATH_INDEX as u8];
    let raw = apdu(0, PUT, 0, 0, &put(b"old"));
    replay.extend([RAW, u8::try_from(raw.len()).unwrap()]);
    replay.extend(raw);
    replay.push(super::super::OP_FACTORY_WIPE);
    for raw in [apdu(0, PUT, 0, 0, &put(b"new")), calculate(b"new")] {
        replay.extend([RAW, u8::try_from(raw.len()).unwrap()]);
        replay.extend(raw);
    }
    exercise(&replay);
}

#[test]
#[should_panic(expected = "without a validated code")]
fn an_injected_success_while_locked_still_fails_the_bypass_oracle() {
    let mut model = OathOracle {
        code_set: true,
        ..OathOracle::default()
    };
    model.command(VALIDATE, &[0x75, 0], &[0x6A, 0x80], Sw::WRONG_DATA);
    model.command(PUT, &put(b"bypass"), &[0x90, 0], Sw::OK);
}

#[test]
#[should_panic(expected = "no acknowledged PUT left live")]
fn an_injected_success_after_reset_still_fails_the_lifecycle_oracle() {
    let mut model = OathOracle::default();
    model.command(PUT, &put(b"old"), &[0x90, 0], Sw::OK);
    model.command(RESET, &[], &[0x90, 0], Sw::OK);
    model.command(CALCULATE, &tlv(NAME, b"old"), &[0x90, 0], Sw::OK);
}

#[test]
#[should_panic(expected = "without a validated code")]
fn raw_select_away_and_back_rearms_the_bypass_oracle() {
    let mut model = OathOracle {
        selected: Some(OATH_INDEX),
        code_set: true,
        validated: true,
        ..OathOracle::default()
    };
    model.observe(&select(rsk_mgmt::MANAGEMENT_AID), &[0x90, 0], [true; 8]);
    model.observe(
        &select(rsk_oath::OATH_AID),
        &select_response(Some(&[0x42; 8])),
        [true; 8],
    );
    model.observe(&apdu(0, PUT, 0, 0, &put(b"bypass")), &[0x90, 0], [true; 8]);
}

// -------------------------------------------------------------------------
// The independent HMAC the oracle checks SET CODE / VALIDATE against
// -------------------------------------------------------------------------

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn sha1_matches_rfc_3174_vectors() {
    assert_eq!(
        sha1(b"").to_vec(),
        hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    );
    assert_eq!(
        sha1(b"abc").to_vec(),
        hex("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
    assert_eq!(
        sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
    );
}

#[test]
fn hmac_matches_rfc_2202_and_4231_vectors() {
    // RFC 2202, HMAC-SHA1.
    assert_eq!(
        hmac(1, &[0x0b; 20], b"Hi There").unwrap(),
        hex("b617318655057264e28bc0b6fb378c8ef146be00")
    );
    assert_eq!(
        hmac(1, b"Jefe", b"what do ya want for nothing?").unwrap(),
        hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
    );
    assert_eq!(
        hmac(1, &[0xaa; 20], &[0xdd; 50]).unwrap(),
        hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3")
    );
    assert_eq!(
        hmac(
            1,
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )
        .unwrap(),
        hex("aa4ae5e15272d00e95705637ce8a3b55ed402112")
    );

    // RFC 4231, HMAC-SHA256.
    assert_eq!(
        hmac(2, &[0x0b; 20], b"Hi There").unwrap(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    assert_eq!(
        hmac(2, b"Jefe", b"what do ya want for nothing?").unwrap(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    assert_eq!(
        hmac(2, &[0xaa; 20], &[0xdd; 50]).unwrap(),
        hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    );
    assert_eq!(
        hmac(
            2,
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )
        .unwrap(),
        hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    );

    // RFC 4231, HMAC-SHA512.
    assert_eq!(
        hmac(3, &[0x0b; 20], b"Hi There").unwrap(),
        hex(concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        ))
    );
    assert_eq!(
        hmac(3, b"Jefe", b"what do ya want for nothing?").unwrap(),
        hex(concat!(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        ))
    );
    assert_eq!(
        hmac(3, &[0xaa; 20], &[0xdd; 50]).unwrap(),
        hex(concat!(
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
            "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        ))
    );
    assert_eq!(
        hmac(
            3,
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )
        .unwrap(),
        hex(concat!(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        ))
    );

    // A nibble the applet has no HMAC for is no oracle answer either.
    assert!(hmac(0, b"key", b"msg").is_none());
}

// -------------------------------------------------------------------------
// The oracle's own SET CODE / VALIDATE checks
// -------------------------------------------------------------------------

fn select_response(challenge: Option<&[u8; 8]>) -> Vec<u8> {
    let mut res = Vec::new();
    if let Some(challenge) = challenge {
        res.extend(tlv(CHALLENGE, challenge));
        res.extend(tlv(ALGO, &[ALG_HMAC_SHA1]));
    }
    res.extend([0x90, 0]);
    res
}

fn set_code_data(alg: u8, secret: &[u8], challenge: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut key = vec![alg];
    key.extend_from_slice(secret);
    let mut data = tlv(KEY, &key);
    data.extend(tlv(CHALLENGE, challenge));
    data.extend(tlv(RESPONSE, proof));
    data
}

fn validate_data(proof: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut data = tlv(RESPONSE, proof);
    data.extend(tlv(CHALLENGE, challenge));
    data
}

const SECRET: [u8; 16] = [0x5A; 16];
const HOST_CHALLENGE: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];

fn installed_model() -> OathOracle {
    let mut model = OathOracle {
        code_set: true,
        code: Some((1, SECRET.to_vec())),
        challenge: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        ..OathOracle::default()
    };
    model.validated = false;
    model
}

#[test]
fn set_code_success_requires_and_remembers_the_hmac() {
    let mut model = OathOracle {
        validated: true,
        ..OathOracle::default()
    };
    let challenge = [1; 8];
    let proof = hmac(1, &SECRET, &challenge).unwrap();
    model.command(
        SET_CODE,
        &set_code_data(1, &SECRET, &challenge, &proof),
        &[0x90, 0],
        Sw::OK,
    );
    assert!(model.code_set && !model.validated);
    assert_eq!(model.code, Some((1, SECRET.to_vec())));
    assert_eq!(model.challenge, None, "SET CODE regenerated the challenge");
}

#[test]
#[should_panic(expected = "SET CODE accepted a response that is not HMAC")]
fn set_code_with_a_wrong_proof_is_rejected() {
    let mut model = OathOracle {
        validated: true,
        ..OathOracle::default()
    };
    let challenge = [1; 8];
    let mut proof = hmac(1, &SECRET, &challenge).unwrap();
    proof[0] ^= 0xFF;
    model.command(
        SET_CODE,
        &set_code_data(1, &SECRET, &challenge, &proof),
        &[0x90, 0],
        Sw::OK,
    );
}

#[test]
fn set_code_removal_opens_the_code_less_applet() {
    let mut model = installed_model();
    model.validated = true;
    model.command(SET_CODE, &tlv(KEY, &[]), &[0x90, 0], Sw::OK);
    assert!(!model.code_set && model.validated);
    assert_eq!(model.code, None);
    assert_eq!(model.challenge, None);
}

#[test]
fn validate_success_requires_the_proof_and_the_mutual_answer() {
    let mut model = installed_model();
    let challenge = model.challenge.unwrap();
    let proof = hmac(1, &SECRET, &challenge).unwrap();
    let answer = hmac(1, &SECRET, &HOST_CHALLENGE).unwrap();
    let mut res = tlv(RESPONSE, &answer);
    res.extend([0x90, 0]);
    model.command(
        VALIDATE,
        &validate_data(&proof, &HOST_CHALLENGE),
        &res,
        Sw::OK,
    );
    assert!(model.validated);
}

#[test]
#[should_panic(expected = "VALIDATE accepted a response that is not HMAC")]
fn validate_with_a_wrong_proof_is_rejected() {
    let mut model = installed_model();
    let challenge = model.challenge.unwrap();
    let mut proof = hmac(1, &SECRET, &challenge).unwrap();
    proof[0] ^= 0xFF;
    let answer = hmac(1, &SECRET, &HOST_CHALLENGE).unwrap();
    let mut res = tlv(RESPONSE, &answer);
    res.extend([0x90, 0]);
    model.command(
        VALIDATE,
        &validate_data(&proof, &HOST_CHALLENGE),
        &res,
        Sw::OK,
    );
}

#[test]
#[should_panic(expected = "VALIDATE answer is not HMAC")]
fn validate_with_a_wrong_mutual_answer_is_rejected() {
    let mut model = installed_model();
    let challenge = model.challenge.unwrap();
    let proof = hmac(1, &SECRET, &challenge).unwrap();
    let mut answer = hmac(1, &SECRET, &HOST_CHALLENGE).unwrap();
    answer[0] ^= 0xFF;
    let mut res = tlv(RESPONSE, &answer);
    res.extend([0x90, 0]);
    model.command(
        VALIDATE,
        &validate_data(&proof, &HOST_CHALLENGE),
        &res,
        Sw::OK,
    );
}

#[test]
fn a_failed_validate_keeps_the_previous_grant() {
    let mut model = installed_model();
    model.validated = true;
    model.command(
        VALIDATE,
        &validate_data(&[0; 20], &HOST_CHALLENGE),
        &[0x6A, 0x80],
        Sw::WRONG_DATA,
    );
    assert!(model.validated, "a wrong proof revoked a standing grant");
}

#[test]
fn select_parses_and_replaces_the_challenge() {
    let mut model = installed_model();
    model.selected = Some(OATH_INDEX);
    model.challenge = Some([0; 8]);
    model.observe(
        &select(rsk_oath::OATH_AID),
        &select_response(Some(&[0x33; 8])),
        [true; 8],
    );
    assert_eq!(model.challenge, Some([0x33; 8]));
    assert!(!model.validated, "a new SELECT kept the old grant");

    model.code_set = false;
    model.code = None;
    model.observe(
        &select(rsk_oath::OATH_AID),
        &select_response(None),
        [true; 8],
    );
    assert_eq!(model.challenge, None);
    assert!(model.validated, "a code-less SELECT must open the applet");
}

#[test]
#[should_panic(expected = "a code-less SELECT carried a challenge")]
fn a_code_less_select_must_not_serve_a_challenge() {
    let mut model = OathOracle {
        selected: Some(OATH_INDEX),
        ..OathOracle::default()
    };
    model.observe(
        &select(rsk_oath::OATH_AID),
        &select_response(Some(&[0x44; 8])),
        [true; 8],
    );
}
