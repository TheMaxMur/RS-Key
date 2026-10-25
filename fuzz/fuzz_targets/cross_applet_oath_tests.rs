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
    model.command(PUT, &put(b"old"), Sw::OK);
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
    model.command(VALIDATE, &[0x75, 0], Sw::WRONG_DATA);
    model.command(PUT, &put(b"bypass"), Sw::OK);
}

#[test]
#[should_panic(expected = "no acknowledged PUT left live")]
fn an_injected_success_after_reset_still_fails_the_lifecycle_oracle() {
    let mut model = OathOracle::default();
    model.command(PUT, &put(b"old"), Sw::OK);
    model.command(RESET, &[], Sw::OK);
    model.command(CALCULATE, &tlv(NAME, b"old"), Sw::OK);
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
    model.observe(&select(rsk_oath::OATH_AID), &[0x90, 0], [true; 8]);
    model.observe(&apdu(0, PUT, 0, 0, &put(b"bypass")), &[0x90, 0], [true; 8]);
}
