// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const UNKNOWN_INS: u8 = 0xee;

#[derive(Clone, Copy)]
enum KeygenApplet {
    OpenPgp,
    Piv,
}

impl KeygenApplet {
    fn authorize(self, env: &Env, ccid: &mut Ccid<'_>) {
        match self {
            Self::Piv => piv_as_admin(ccid),
            Self::OpenPgp => {
                rsk_openpgp::scan_files(
                    &crate::tests::dev(),
                    &mut env.fs.borrow_mut(),
                    &mut *env.rng.borrow_mut(),
                )
                .unwrap();
                assert_eq!(
                    sw(ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0)),
                    Sw::OK
                );
                let verify = apdu(0, 0x20, 0, 0x83, rsk_openpgp::consts::PW3_DEFAULT);
                assert_eq!(sw(ccid.handle_apdu(&verify, 0)), Sw::OK);
            }
        }
    }

    fn command(self, ins: u8) -> Vec<u8> {
        match self {
            Self::Piv => apdu(0, ins, 0, 0x9a, &[0xac, 3, 0x80, 1, 7]),
            Self::OpenPgp => apdu(0, ins, 0x80, 0, &[0xb6, 0]),
        }
    }

    fn cap(self) -> u16 {
        match self {
            Self::Piv => rsk_devconf::CAP_PIV,
            Self::OpenPgp => rsk_devconf::CAP_OPENPGP,
        }
    }
}

#[test]
fn an_unknown_instruction_cannot_take_the_authenticated_rsa_fast_path() {
    for app in [KeygenApplet::OpenPgp, KeygenApplet::Piv] {
        let env = Env::new();
        env.board.borrow_mut().accelerator = true;
        let mut ccid = env.ccid();
        app.authorize(&env, &mut ccid);
        assert!(ccid.caps_enabled(app.cap()));
        env.board.borrow_mut().search_key = Some(rsa2048());
        let (answer, _) = frames(&mut ccid, &app.command(INS_KEYPAIR_GEN));
        assert_eq!(answer.last().map(|(sw, _)| *sw), Some(Sw::OK));
        assert!(env.board.borrow().search_key.is_none());
        env.board.borrow_mut().search_key = Some(rsa2048());
        let generation = env.fs.borrow().write_gen();
        assert_eq!(
            sw(ccid.handle_apdu(&app.command(UNKNOWN_INS), 0)),
            Sw::INS_NOT_SUPPORTED
        );
        assert!(env.board.borrow().search_key.is_some());
        assert_eq!(env.fs.borrow().write_gen(), generation);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn a_selected_authenticated_applet_cannot_generate_after_it_is_disabled() {
    for app in [KeygenApplet::OpenPgp, KeygenApplet::Piv] {
        let env = Env::new();
        env.board.borrow_mut().accelerator = true;
        let mut ccid = env.ccid();
        app.authorize(&env, &mut ccid);
        let generate = app.command(INS_KEYPAIR_GEN);
        env.board.borrow_mut().search_key = Some(rsa2048());
        let (answer, _) = frames(&mut ccid, &generate);
        assert_eq!(answer.last().map(|(sw, _)| *sw), Some(Sw::OK));
        assert!(env.board.borrow().search_key.is_none());
        let config = dev_conf(rsk_devconf::SUPPORTED_CAPS & !app.cap());
        assert!(ccid.ctap_mgmt(0x43, &config).is_some());
        assert_eq!(ccid.refresh_enabled() & app.cap(), 0);
        env.board.borrow_mut().search_key = Some(rsa2048());
        let generation = env.fs.borrow().write_gen();
        assert_eq!(sw(ccid.handle_apdu(&generate, 0)), Sw::INS_NOT_SUPPORTED);
        assert!(env.board.borrow().search_key.is_some());
        assert_eq!(env.fs.borrow().write_gen(), generation);
    }
}

#[test]
fn a_successful_hid_serial_command_keeps_its_four_byte_body() {
    let env = Env::new();
    let mut ccid = env.ccid();
    let generation = env.fs.borrow().write_gen();
    let (body, n, _) = ccid.handle_otp_hid(0x10, &[0; rsk_otp::hid::PAYLOAD_SIZE]);
    assert_eq!(n, 4);
    assert_eq!(&body[..n], &serial());
    assert_eq!(env.fs.borrow().write_gen(), generation);
}
