// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn slot_offsets_and_missing_codes_refuse_without_changing_a_programmed_slot() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let cfg = chalresp_config(&[0xab; 20], &[1; ACC_CODE_SIZE], 0);
    assert_eq!(
        configure(
            &mut app,
            &mut fs,
            P1_CONFIG_SLOT1,
            0,
            &cfg,
            &[0; ACC_CODE_SIZE]
        )
        .0,
        Sw::OK
    );
    let mut before = [0; rsk_fs::MAX_VALUE_BYTES];
    let n = fs.read(EF_OTP_SLOT1, &mut before).unwrap();
    for (p1, p2, data, sw) in [
        (P1_CONFIG_SLOT1, 4, cfg.as_slice(), Sw::INCORRECT_P1P2),
        (P1_UPDATE_SLOT2, 1, cfg.as_slice(), Sw::INCORRECT_P1P2),
        (P1_CONFIG_SLOT1, 0, cfg.as_slice(), Sw::WRONG_LENGTH),
        (P1_UPDATE_SLOT1, 0, cfg.as_slice(), Sw::WRONG_LENGTH),
        (
            P1_CHAL_HMAC_SLOT1,
            4,
            &[0; hid::PAYLOAD_SIZE][..],
            Sw::INCORRECT_P1P2,
        ),
    ] {
        assert_eq!(run(&mut app, &mut fs, &otp_apdu(p1, p2, data)).0, sw);
        let mut after = [0; rsk_fs::MAX_VALUE_BYTES];
        assert_eq!(fs.read(EF_OTP_SLOT1, &mut after), Some(n));
        assert_eq!(after, before);
        assert_eq!(app.config_seq, 2);
    }
}

#[test]
fn configure_update_and_swap_never_ack_a_refused_slot_write() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let cfg = chalresp_config(&[0xab; 20], &[0; ACC_CODE_SIZE], 0);
    for p1 in [P1_CONFIG_SLOT1, P1_UPDATE_SLOT1, P1_SWAP] {
        let (backend, medium) = Cut::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        assert_eq!(
            configure(
                &mut app,
                &mut fs,
                P1_CONFIG_SLOT1,
                0,
                &cfg,
                &[0; ACC_CODE_SIZE]
            )
            .0,
            Sw::OK
        );
        let before = medium.value(EF_OTP_SLOT1).unwrap();
        medium.arm(0);
        let command = if p1 == P1_SWAP {
            otp_apdu(p1, 0, &[])
        } else {
            otp_apdu(p1, 0, &[cfg.as_slice(), &[0; ACC_CODE_SIZE]].concat())
        };
        assert_eq!(
            run(&mut app, &mut fs, &command).0,
            Sw::MEMORY_FAILURE,
            "p1={p1:#x}"
        );
        assert_eq!(app.config_seq, 2);
        assert_eq!(medium.value(EF_OTP_SLOT1), Some(before));
        assert_eq!(medium.value(EF_OTP_SLOT2), None);
    }
}

#[test]
fn a_challenge_response_slot_types_nothing_on_a_button_press() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let cfg = build_config(
        &[],
        &[1; 6],
        &[2; 16],
        &[0; 6],
        0,
        TKT_CHAL_RESP,
        CFG_CHAL_YUBICO,
    );
    assert_eq!(
        configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );
    let mut out = [0x55; ticket::MAX_TICKET];
    assert_eq!(app.button_ticket(1, 0, [1, 2], &mut fs, &mut out), None);
    assert_eq!(out, [0x55; ticket::MAX_TICKET]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &otp_apdu(P1_CHAL_HMAC_SLOT1, 0, &[0; hid::PAYLOAD_SIZE])
        )
        .0,
        SW_WRONG_DATA
    );
    let cfg = chalresp_config(&[0xab; 20], &[0; 6], 0);
    assert_eq!(
        configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(P1_CHAL_OTP_SLOT1, 0, &[0; 6])).0,
        SW_WRONG_DATA
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn device_info_refuses_a_length_that_exceeds_the_payload() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    for (body, sw) in [
        (&[][..], Sw::OK),
        (&[0][..], Sw::OK),
        (&[3, 0][..], Sw::WRONG_DATA),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &otp_apdu(P1_SET_DEVICE_INFO, 0, body)).0,
            sw
        );
        assert_eq!(fs.write_gen(), 0);
        assert_eq!(app.config_seq, 1);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn empty_ndef_and_short_scan_map_do_not_advance_the_sequence() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    for (p1, body, fid) in [
        (P1_NDEF1, &[][..], EF_OTP_NDEF1),
        (P1_NDEF2, &[][..], EF_OTP_NDEF2),
        (P1_SCAN_MAP, &[0x40; SCANMAP_LEN - 1][..], EF_OTP_SCANMAP),
    ] {
        assert_eq!(run(&mut app, &mut fs, &otp_apdu(p1, 0, body)).0, Sw::OK);
        assert_eq!(app.config_seq, 1);
        assert!(!fs.has_data(fid));
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn ndef_checks_the_code_of_every_programmed_slot() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let cfg = chalresp_config(&[0xab; 20], &[1; 6], 0);
    assert_eq!(
        configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 3, &cfg, &[0; 6]).0,
        Sw::OK
    );
    for p1 in [P1_NDEF1, P1_NDEF2] {
        let fid = if p1 == P1_NDEF1 {
            EF_OTP_NDEF1
        } else {
            EF_OTP_NDEF2
        };
        let mut body = vec![0xab; EF_OTP_NDEF_MAX];
        body.extend_from_slice(&[0; 6]);
        assert_eq!(
            run(&mut app, &mut fs, &otp_apdu(p1, 0, &body)).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert!(!fs.has_data(fid));
        body[EF_OTP_NDEF_MAX..].fill(1);
        assert_eq!(run(&mut app, &mut fs, &otp_apdu(p1, 0, &body)).0, Sw::OK);
        let mut readback = [0; EF_OTP_NDEF_MAX];
        assert_eq!(fs.read(fid, &mut readback), Some(EF_OTP_NDEF_MAX));
        assert_eq!(readback, [0xab; EF_OTP_NDEF_MAX]);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn an_unmapped_character_keeps_the_entire_ticket_in_ascii() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    fs.put(EF_OTP_SCANMAP, &[0x40; SCANMAP_LEN]).unwrap();
    let mut ticket = *b"cbzv";
    assert!(!app.apply_scanmap(&mut fs, &mut ticket));
    assert_eq!(ticket, *b"cbzv");
    let mut ticket = *b"cbuv";
    assert!(app.apply_scanmap(&mut fs, &mut ticket));
    assert_eq!(ticket, [0x40; 4]);
}
