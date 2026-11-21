// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, SERIAL_HASH, SERIAL_ID, apdu, select, sw};

struct CapacityReporter;

impl rsk_vendor::Platform for CapacityReporter {
    fn keygen_bench(&mut self, _p1: u8, _data: &[u8], res: &mut ResBuf) -> rsk_sdk::Sw {
        res.clear();
        let capacity = u32::try_from(res.capacity()).unwrap().to_be_bytes();
        if res.extend(&capacity) {
            rsk_sdk::Sw::OK
        } else {
            rsk_sdk::Sw::WRONG_LENGTH
        }
    }
}

#[test]
fn a_vendor_provider_can_report_the_full_msg_body_capacity_after_clearing_its_limit() {
    let env = Env::new();
    let mut handler = AppletHandler::new(
        &env.fs,
        &env.rng,
        &env.board,
        &env.finger,
        &env.fido_state,
        CapacityReporter,
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
    );
    let selected = handler.handle_msg(&select(rsk_vendor::VENDOR_AID), 0);
    assert_eq!(sw(selected), rsk_sdk::Sw::OK);
    let generation = env.fs.borrow().write_gen();
    let response = handler.handle_msg(&apdu(0x00, 0x13, 0, 0, &[]), 0);
    assert_eq!(sw(response), rsk_sdk::Sw::OK);
    assert_eq!(response.len(), 6);
    let expected = u32::try_from(rsk_usb::ctaphid::CTAP_MAX_MESSAGE - 2)
        .unwrap()
        .to_be_bytes();
    assert_eq!(&response[..4], &expected);
    assert_eq!(env.fs.borrow().write_gen(), generation);
}
