// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A configuration lock shuts the phy and LED records on every host path that writes
/// them: CONFIG_WRITE over CCID and CTAPHID answers `NOT_ALLOWED` and applies
/// nothing live; rescue `1C/01` and the vendor SET LED answer `6986`.
#[test]
fn a_locked_configuration_shuts_the_phy_and_led_records_on_every_transport() {
    let env = Env::new();
    let mut code = std::vec![0x0A, 16];
    code.extend_from_slice(&[0xA5; 16]);
    rsk_devconf::persist_touched(&[0; 4], &mut env.fs.borrow_mut(), &code).unwrap();
    let phy = rsk_phy::PhyData {
        presence_timeout: Some(45),
        ..Default::default()
    };
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = phy.serialize(&mut blob).unwrap();
    let writes = [
        (
            "LED",
            crate::tests::vendor_config_write(rsk_fido::consts::CONFIG_TARGET_LED, &LED_BLOCK),
        ),
        (
            "phy",
            crate::tests::vendor_config_write(rsk_fido::consts::CONFIG_TARGET_PHY, &blob[..blen]),
        ),
    ];
    let not_allowed = rsk_fido::CtapError::NotAllowed.as_u8();
    let set_led = apdu(0x00, 0x10, 0x80, 0x03, &[]);

    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    for (name, body) in &writes {
        let (resp, status) = exchange_chained(&mut ccid, &ctap_msg(body));
        assert_eq!(
            (resp.first().copied(), status),
            (Some(not_allowed), rsk_sdk::Sw::OK),
            "{name} over CCID"
        );
    }
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_rescue::RESCUE_AID), 0)),
        rsk_sdk::Sw::OK
    );
    let rescue_write = apdu(0x80, 0x1C, 0x01, 0x00, &blob[..blen]);
    assert_eq!(
        sw(ccid.handle_apdu(&rescue_write, 0)),
        rsk_sdk::Sw::COMMAND_NOT_ALLOWED
    );
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_vendor::VENDOR_AID), 0)),
        rsk_sdk::Sw::OK
    );
    assert_eq!(
        sw(ccid.handle_apdu(&set_led, 0)),
        rsk_sdk::Sw::COMMAND_NOT_ALLOWED,
        "SET LED over CCID"
    );
    drop(ccid);

    let mut ctap = env.ctap();
    for (name, body) in &writes {
        assert_eq!(
            ctap.handle_cbor(1, body, 0)[0],
            not_allowed,
            "{name} over CTAPHID"
        );
    }
    assert_eq!(
        sw(ctap.handle_msg(&select(rsk_vendor::VENDOR_AID), 0)),
        rsk_sdk::Sw::OK
    );
    assert_eq!(
        sw(ctap.handle_msg(&set_led, 0)),
        rsk_sdk::Sw::COMMAND_NOT_ALLOWED,
        "SET LED over CTAPHID"
    );

    let board = env.board.borrow();
    assert_eq!(
        (board.config_written, board.reboots),
        (0, 0),
        "a refused write was applied"
    );
    assert!(
        !env.fs.borrow_mut().has_data(rsk_phy::EF_PHY),
        "a refused write stored the phy record"
    );
}
