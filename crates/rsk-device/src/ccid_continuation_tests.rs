// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn continuation_only_covers_a_pending_response_under_a_nonchaining_class() {
    let env = Env::new();
    let mut ccid = env.ccid();
    let fido = select(rsk_fido::consts::FIDO_AID);
    let get_info = apdu(0x80, 0x10, 0, 0, GET_INFO);
    ccid.handle_apdu(&fido, 0);
    let (whole, status) = exchange_chained(&mut ccid, &get_info);
    assert_eq!(status, Sw::OK);
    for cla in 0..=u8::MAX {
        ccid.handle_apdu(&fido, 0);
        let request = [cla, INS_GET_RESPONSE, 0, 0, 0];
        assert!(!ccid.continues_response(&request));
        let first = ccid.handle_apdu(&get_info, 0).to_vec();
        assert_eq!(sw(&first).sw1(), 0x61);
        assert_eq!(ccid.continues_response(&request), cla & 0x10 == 0);
        assert!(!ccid.continues_response(&fido));
        assert!(!ccid.continues_response(&get_info));
        assert!(!ccid.continues_response(&request[..3]));
        assert!(!ccid.continues_response(&[cla, INS_GET_RESPONSE, 0, 0, 2, 1]));
        if cla & 0x10 == 0 {
            let (rest, status) = exchange_chained(&mut ccid, &request);
            assert_eq!(status, Sw::OK);
            assert_eq!([&first[..first.len() - 2], &rest].concat(), whole);
            assert!(!ccid.continues_response(&request));
        } else {
            assert_eq!(sw(ccid.handle_apdu(&request, 0)), Sw::OK);
            assert!(ccid.continues_response(&[0, INS_GET_RESPONSE, 0, 0, 0]));
        }
    }
}

#[test]
fn selection_and_reset_end_a_continuation() {
    let env = Env::new();
    let mut ccid = env.ccid();
    let fido = select(rsk_fido::consts::FIDO_AID);
    let get_info = apdu(0x80, 0x10, 0, 0, GET_INFO);
    let request = [0, INS_GET_RESPONSE, 0, 0, 0];
    for reset in [false, true] {
        ccid.handle_apdu(&fido, 0);
        assert_eq!(sw(ccid.handle_apdu(&get_info, 0)).sw1(), 0x61);
        assert!(ccid.continues_response(&request));
        if reset {
            ccid.reset_card();
        } else {
            ccid.handle_apdu(&select(rsk_otp::OTP_AID), 0);
        }
        assert!(!ccid.continues_response(&request));
    }
}
