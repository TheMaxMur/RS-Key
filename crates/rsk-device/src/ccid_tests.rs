// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, apdu, dev_conf, select, sw};

/// The seven AIDs in registration order, so a test can walk the whole set.
const AIDS: [(&str, &[u8]); 7] = [
    ("vendor", rsk_vendor::VENDOR_AID),
    ("openpgp", rsk_openpgp::consts::OPENPGP_AID),
    ("management", rsk_mgmt::MANAGEMENT_AID),
    ("oath", rsk_oath::OATH_AID),
    ("otp", rsk_otp::OTP_AID),
    ("piv", rsk_piv::PIV_AID),
    ("rescue", rsk_rescue::RESCUE_AID),
];

#[test]
fn every_applet_is_selectable_on_a_fresh_device() {
    // No `EF_DEV_CONF` yet, so the mask defaults to every supported application.
    let env = Env::new();
    let mut ccid = env.ccid();
    for (name, aid) in AIDS {
        let res = ccid.handle_apdu(&select(aid)).to_vec();
        assert_eq!(sw(&res), rsk_sdk::Sw::OK, "{name} did not select");
    }
}

#[test]
fn a_disabled_application_is_invisible_not_just_unreported() {
    // `ykman config usb --disable X` must really remove X from the card, not only
    // from the DeviceInfo report: SELECT answers FILE_NOT_FOUND, exactly as if the
    // applet were never registered.
    for (name, aid, cap) in [
        (
            "openpgp",
            rsk_openpgp::consts::OPENPGP_AID,
            rsk_mgmt::CAP_OPENPGP,
        ),
        ("oath", rsk_oath::OATH_AID, rsk_mgmt::CAP_OATH),
        ("otp", rsk_otp::OTP_AID, rsk_mgmt::CAP_OTP),
        ("piv", rsk_piv::PIV_AID, rsk_mgmt::CAP_PIV),
    ] {
        let env = Env::new();
        let mut ccid = env.ccid();
        assert_eq!(sw(ccid.handle_apdu(&select(aid))), rsk_sdk::Sw::OK);

        let blob = dev_conf(rsk_mgmt::CAP_FIDO2); // everything else off
        rsk_mgmt::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
        assert!(!ccid.refresh_enabled() & cap != 0 || !ccid.caps_enabled(cap));

        let res = ccid.handle_apdu(&select(aid)).to_vec();
        assert_eq!(
            sw(&res),
            rsk_sdk::Sw::FILE_NOT_FOUND,
            "{name} is still selectable while disabled"
        );
    }
}

#[test]
fn the_recovery_applets_can_never_be_disabled() {
    // Management is the re-enable path and vendor/rescue are the recovery ones, so
    // none of the three is gated by a capability bit — otherwise a single
    // `ykman config usb --disable` would be irreversible.
    let env = Env::new();
    let mut ccid = env.ccid();
    let blob = dev_conf(0); // every capability off
    rsk_mgmt::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    ccid.refresh_enabled();
    for (name, aid) in [
        ("management", rsk_mgmt::MANAGEMENT_AID),
        ("vendor", rsk_vendor::VENDOR_AID),
        ("rescue", rsk_rescue::RESCUE_AID),
    ] {
        let res = ccid.handle_apdu(&select(aid)).to_vec();
        assert_eq!(sw(&res), rsk_sdk::Sw::OK, "{name} was gated off");
    }
}

#[test]
fn an_ungated_applet_is_enabled_whatever_the_mask_says() {
    assert!(rsk_mgmt::cap_enabled(0, 0), "cap 0 means always available");
    let env = Env::new();
    let ccid = env.ccid();
    assert!(ccid.caps_enabled(0));
}

#[test]
fn a_config_write_is_only_seen_after_a_refresh() {
    // The mask is cached; the worker refreshes it when a config write sets the
    // dirty latch. Until then the previous set stands — which is what makes the
    // refresh a required step rather than an optimisation.
    let env = Env::new();
    let mut ccid = env.ccid();
    assert!(ccid.caps_enabled(rsk_mgmt::CAP_OATH));
    let blob = dev_conf(rsk_mgmt::CAP_FIDO2);
    rsk_mgmt::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    assert!(
        ccid.caps_enabled(rsk_mgmt::CAP_OATH),
        "still the cached mask"
    );
    let mask = ccid.refresh_enabled();
    assert!(!rsk_mgmt::cap_enabled(mask, rsk_mgmt::CAP_OATH));
    assert!(!ccid.caps_enabled(rsk_mgmt::CAP_OATH));
}

// --- the device-wide wipe's gate set ---------------------------------------

#[cfg(any(not(feature = "strict-config"), feature = "display"))]
#[test]
fn the_wipe_defers_every_applets_own_gate_records() {
    // Audit run-36: OATH's `is_oath_lock_fid` was private, so it could not be named
    // here and was simply left out — and a torn device reset then served every
    // surviving TOTP secret unauthenticated. This asserts the fold is complete by
    // asking each applet's own predicate for a FID and checking the union covers
    // it, so deleting an arm fails here and not in the field.
    /// One applet's "is this a gate record?" predicate, named so the array of
    /// them stays readable.
    type Gate = fn(u16) -> bool;
    let predicates: [(&str, Gate); 4] = [
        ("fido", rsk_fido::is_fido_gate_fid),
        ("piv", rsk_piv::files::is_piv_gate_fid),
        ("oath", rsk_oath::is_oath_lock_fid),
        ("openpgp", rsk_openpgp::terminate::is_openpgp_gate_fid),
    ];
    for (name, owns) in predicates {
        let mine: std::vec::Vec<u16> = (0..=u16::MAX).filter(|&f| owns(f)).collect();
        assert!(!mine.is_empty(), "{name} claims no gate record at all");
        for fid in mine {
            assert!(
                gates_wiped_last(fid),
                "{name}'s gate {fid:#06x} is not deferred by the device-wide wipe"
            );
        }
    }
}

#[cfg(any(not(feature = "strict-config"), feature = "display"))]
#[test]
fn the_wipe_defers_nothing_it_was_not_asked_to() {
    // The other direction: everything deferred belongs to one of the four. A wipe
    // that holds back a record nobody owns leaves it behind for ever.
    for fid in 0..=u16::MAX {
        if gates_wiped_last(fid) {
            assert!(
                rsk_fido::is_fido_gate_fid(fid)
                    || rsk_piv::files::is_piv_gate_fid(fid)
                    || rsk_oath::is_oath_lock_fid(fid)
                    || rsk_openpgp::terminate::is_openpgp_gate_fid(fid),
                "{fid:#06x} is deferred but owned by no applet"
            );
        }
    }
}

// --- the management surface carried over CTAPHID ---------------------------

#[test]
fn read_config_over_the_fido_transport_answers() {
    // What `ykman` and Yubico Authenticator read to identify the key when only the
    // FIDO interface is present.
    let env = Env::new();
    let mut ccid = env.ccid();
    let res = ccid.ctap_mgmt(0x42, &[]).map(<[u8]>::to_vec);
    let body = res.expect("READ CONFIG must be served over CTAPHID");
    assert!(!body.is_empty(), "DeviceInfo cannot be empty");
}

#[test]
fn an_unknown_vendor_command_is_refused() {
    let env = Env::new();
    let mut ccid = env.ccid();
    assert!(ccid.ctap_mgmt(0x44, &[]).is_none());
    assert!(ccid.ctap_mgmt(0x00, &[]).is_none());
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn write_config_over_the_fido_transport_round_trips() {
    // The permissive build serves ykman's WRITE CONFIG here for parity; whatever it
    // stores has to come back out of every READ CONFIG, or ykman shows one thing
    // and the card does another.
    let env = Env::new();
    let mut ccid = env.ccid();
    let blob = dev_conf(rsk_mgmt::CAP_FIDO2 | rsk_mgmt::CAP_PIV);
    assert!(ccid.ctap_mgmt(0x43, &blob).is_some());
    assert_eq!(
        rsk_mgmt::read_enabled_caps(&mut env.fs.borrow_mut()),
        rsk_mgmt::CAP_FIDO2 | rsk_mgmt::CAP_PIV
    );
    assert!(
        ccid.ctap_mgmt(0x42, &[]).is_some(),
        "and READ still answers"
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn a_write_config_whose_length_byte_lies_is_refused() {
    let env = Env::new();
    let mut ccid = env.ccid();
    assert!(ccid.ctap_mgmt(0x43, &[]).is_none(), "an empty body");
    assert!(
        ccid.ctap_mgmt(0x43, &[0x40, 0x03, 0x02]).is_none(),
        "a length past the end of the payload"
    );
    assert_eq!(
        rsk_mgmt::read_enabled_caps(&mut env.fs.borrow_mut()),
        rsk_mgmt::SUPPORTED_CAPS,
        "and nothing was persisted"
    );
}

// --- the OTP keyboard interface --------------------------------------------

#[test]
fn disabling_otp_stops_the_function_slots_but_not_the_identify_ones() {
    // The identify/config slots have to stay live while OTP is off, or the host
    // cannot read DeviceInfo to turn it back on — the same irreversibility the
    // ungated applets avoid.
    let env = Env::new();
    let mut ccid = env.ccid();
    let blob = dev_conf(rsk_mgmt::CAP_FIDO2);
    rsk_mgmt::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    ccid.refresh_enabled();

    let payload = [0u8; 64];
    for slot in 0u8..=0x40 {
        let (_, n, status) = ccid.handle_otp_hid(slot, &payload);
        if rsk_otp::is_function_slot(slot) {
            assert_eq!(n, 0, "function slot {slot:#04x} answered while OTP is off");
        }
        // The status frame is always served, disabled or not: it is how the host
        // learns the sequence number changed.
        assert_eq!(status.len(), 8);
    }
}

#[test]
fn a_button_press_types_nothing_while_otp_is_disabled() {
    let env = Env::new();
    let mut ccid = env.ccid();
    let blob = dev_conf(rsk_mgmt::CAP_FIDO2);
    rsk_mgmt::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    ccid.refresh_enabled();
    assert!(ccid.otp_button_ticket(1, 0).is_none());
    assert!(ccid.otp_button_ticket(2, 0).is_none());
}

#[test]
fn an_empty_slot_types_nothing_either() {
    let env = Env::new();
    let mut ccid = env.ccid();
    assert!(
        ccid.otp_button_ticket(1, 0).is_none(),
        "a fresh device has no slot programmed"
    );
}

// --- state a card reset and a hand-off must not leak ------------------------

#[test]
fn a_card_reset_drops_the_selection() {
    // `SCardDisconnect(SCARD_RESET_CARD)` must really force re-selection and
    // re-authentication instead of leaving a verified PIN for whoever connects next.
    let env = Env::new();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID))),
        rsk_sdk::Sw::OK
    );
    assert_eq!(ccid.disp.current(), Some(5));
    ccid.reset_card();
    assert_eq!(
        ccid.disp.current(),
        None,
        "nothing is selected after a reset"
    );
}

#[test]
fn scrub_wipes_the_response_buffer() {
    // It can hold a deciphered session key or a PIN token after a dispatch.
    let env = Env::new();
    let mut ccid = env.ccid();
    ccid.handle_apdu(&select(rsk_mgmt::MANAGEMENT_AID));
    assert!(ccid.resp.iter().any(|&b| b != 0), "a response was written");
    ccid.scrub();
    assert!(ccid.resp.iter().all(|&b| b == 0));
}

#[test]
fn a_response_always_fits_one_ccid_frame() {
    // The applet body plus its two status bytes must fit a single `XfrBlock`;
    // sizing the buffer to the whole CCID message once let a long OATH LIST overrun
    // the frame, and `run_xfr` silently dropped the tail — including the SW.
    const { assert!(RESP_CAP + 10 <= rsk_usb::ccid::MAX_CCID_MSG) };
    let env = Env::new();
    let mut ccid = env.ccid();
    let res = ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID));
    assert!(res.len() <= RESP_CAP);
}

#[test]
fn a_keygen_fast_path_never_fires_for_the_wrong_applet() {
    // Both fast paths bypass the dispatcher, so each re-checks that its applet is
    // the selected one AND still enabled — the contrived window where OpenPGP was
    // selected and then disabled.
    let env = Env::new();
    let mut ccid = env.ccid();
    ccid.handle_apdu(&select(rsk_piv::PIV_AID));
    let generate = apdu(
        0x00,
        rsk_openpgp::consts::INS_KEYPAIR_GEN,
        0x80,
        0x00,
        &[0xB6, 0x00],
    );
    assert!(
        ccid.try_rsa_keygen(&generate).is_none(),
        "the OpenPGP fast path fired with PIV selected"
    );
}

#[test]
fn a_host_build_falls_through_to_the_applets_own_keygen() {
    // `Hooks::rsa_search` defaulting to `None` means "no accelerator here", which
    // must fall through to normal dispatch rather than report a failure — the
    // difference between `None` and `Some(None)` is load-bearing.
    let env = Env::new();
    let mut ccid = env.ccid();
    ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID));
    let generate = apdu(
        0x00,
        rsk_openpgp::consts::INS_KEYPAIR_GEN,
        0x80,
        0x00,
        &[0xB6, 0x00],
    );
    // Not `Some(2)` (an EXEC_ERROR answer): the command has to reach the applet.
    assert!(ccid.try_rsa_keygen(&generate).is_none());
}

#[test]
fn a_keygen_fast_path_judges_the_class_byte_too() {
    // Both fast paths run BEFORE `Dispatcher::process`, so its class-byte rule has
    // to be applied ahead of them or a GENERATE is the one command that escapes it.
    // Measured on a YubiKey 5.7.4: `04 47 00 9A …` is `6E00` where `00 47 …` is
    // `6982`, and `10 47 …` is accumulated as a chain segment, never executed.
    const DEFAULT_MGM: [u8; 24] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    const AES192: u8 = rsk_piv::files::ALGO_AES192;
    let env = Env::new();
    env.board.borrow_mut().accelerator = true;
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID))),
        rsk_sdk::Sw::OK
    );
    // The management key, so GENERATE is refused for its class and not for auth.
    let step1 = ccid
        .handle_apdu(&apdu(0x00, 0x87, AES192, 0x9B, &[0x7C, 0x02, 0x81, 0x00]))
        .to_vec();
    assert_eq!(sw(&step1), rsk_sdk::Sw::OK);
    let mut block: [u8; 16] = step1[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut block).unwrap();
    let mut answer = std::vec![0x7Cu8, 0x12, 0x82, 0x10];
    answer.extend_from_slice(&block);
    assert_eq!(
        sw(ccid.handle_apdu(&apdu(0x00, 0x87, AES192, 0x9B, &answer))),
        rsk_sdk::Sw::OK
    );
    // RSA-2048 into 9A: the one command the firmware runs off the dispatcher.
    let generate = |cla| {
        apdu(
            cla,
            rsk_piv::INS_ASYM_KEYGEN,
            0x00,
            0x9A,
            &[0xAC, 0x03, 0x80, 0x01, 0x07],
        )
    };
    // The control: with an accelerator the fast path really does fire and answer
    // for itself, so a class that still reaches it is visible here.
    assert_eq!(
        sw(ccid.handle_apdu(&generate(0x00))),
        rsk_sdk::Sw::EXEC_ERROR,
        "the fast path did not fire, so this test proves nothing"
    );
    assert_eq!(
        sw(ccid.handle_apdu(&generate(0x04))),
        rsk_sdk::Sw::CLA_NOT_SUPPORTED,
        "a secure-messaging class generated a key"
    );
    let seg = ccid.handle_apdu(&generate(0x10)).to_vec();
    assert_eq!(
        (sw(&seg), seg.len()),
        (rsk_sdk::Sw::OK, 2),
        "a chain segment was executed instead of accumulated"
    );
}

// --- the CCID pinpad gate (trusted-display builds only) ---------------------

#[cfg(feature = "display")]
mod pinpad {
    use super::*;

    const OPENPGP_REFS: [u8; 3] = [
        rsk_openpgp::consts::PW1_MODE81,
        rsk_openpgp::consts::PW1_MODE82,
        rsk_openpgp::consts::PW3_MODE83,
    ];

    #[test]
    fn nothing_selected_paints_no_pin_pad() {
        // Audit run-36: this path had no gate at all, so a bare `PC_to_RDR_Secure`
        // put the trusted display's PIN pad up for the presence timeout with
        // nothing selected — the capability check ran later, on the VERIFY, so it
        // stopped the authentication and not the screen.
        let env = Env::new();
        let ccid = env.ccid();
        for p2 in OPENPGP_REFS {
            assert!(!ccid.pin_ref_ready(p2));
        }
        assert!(!ccid.pin_ref_ready(rsk_usb::secure_pin::PIV_PIN_P2));
    }

    #[test]
    fn a_pin_reference_belongs_to_the_applet_that_is_selected() {
        let env = Env::new();
        let mut ccid = env.ccid();
        ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID));
        for p2 in OPENPGP_REFS {
            assert!(ccid.pin_ref_ready(p2), "OpenPGP {p2:#04x}");
        }
        assert!(
            !ccid.pin_ref_ready(rsk_usb::secure_pin::PIV_PIN_P2),
            "the PIV PIN is not OpenPGP's to collect"
        );

        ccid.handle_apdu(&select(rsk_piv::PIV_AID));
        assert!(ccid.pin_ref_ready(rsk_usb::secure_pin::PIV_PIN_P2));
        for p2 in OPENPGP_REFS {
            assert!(
                !ccid.pin_ref_ready(p2),
                "OpenPGP {p2:#04x} with PIV selected"
            );
        }
    }

    #[test]
    fn a_disabled_application_paints_no_pin_pad_either() {
        // The panel must never be painted for a credential the host cannot then
        // authenticate against.
        let env = Env::new();
        let mut ccid = env.ccid();
        ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID));
        assert!(ccid.pin_ref_ready(rsk_openpgp::consts::PW1_MODE81));

        let blob = dev_conf(rsk_mgmt::CAP_FIDO2);
        rsk_mgmt::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
        ccid.refresh_enabled();
        assert!(!ccid.pin_ref_ready(rsk_openpgp::consts::PW1_MODE81));
    }

    #[test]
    fn an_unknown_pin_reference_paints_nothing() {
        let env = Env::new();
        let mut ccid = env.ccid();
        ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID));
        assert!(!ccid.pin_ref_ready(0x00));
        assert!(!ccid.pin_ref_ready(0xFF));
    }
}
