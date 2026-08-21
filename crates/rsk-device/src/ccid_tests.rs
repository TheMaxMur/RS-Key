// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, TestRng, VendorBoard, apdu, dev_conf, select, sw};

/// The eight AIDs in registration order, so a test can walk the whole set.
const AIDS: [(&str, &[u8]); 8] = [
    ("vendor", rsk_vendor::VENDOR_AID),
    ("openpgp", rsk_openpgp::consts::OPENPGP_AID),
    ("management", rsk_mgmt::MANAGEMENT_AID),
    ("oath", rsk_oath::OATH_AID),
    ("otp", rsk_otp::OTP_AID),
    ("piv", rsk_piv::PIV_AID),
    ("rescue", rsk_rescue::RESCUE_AID),
    ("fido", rsk_fido::consts::FIDO_AID),
];

/// The CCID wrapper's return value is what the caller turns into a reboot that
/// looks like success, and it was asserted by nothing (the reverse mutation
/// pass, D2): replacing the whole function with `true` or with `false` left the
/// suite green. Audit run-32 is what the `true` direction costs — a wipe that
/// reports a range clear it never enumerated, with the trusted display painting
/// "RS-Key erased" over live credentials.
///
/// This pins the honest direction only: a wipe that really happened answers
/// `true`. The other one needs a backend that can fail, and `Env` is wired to
/// `RamStorage` — the layer below already has it
/// (`rsk-fs::factory_wipe_fails_on_a_truncated_enumeration`); the wrapper's
/// laundering of that refusal is still unowned.
// `factory_wipe` is a DEFAULT-build entry point; the strict-config image has
// no management RESET at all.
#[cfg(not(feature = "strict-config"))]
#[test]
fn a_completed_factory_wipe_reports_true_and_leaves_nothing() {
    let env = Env::new();
    env.fs
        .borrow_mut()
        .put(rsk_fido::consts::EF_CRED, &[0xC0; 32])
        .unwrap();
    assert!(env.fs.borrow_mut().has_data(rsk_fido::consts::EF_CRED));
    let wiped = env.ccid().factory_wipe();
    assert!(wiped, "a wipe that completed must report it");
    assert!(
        !env.fs.borrow_mut().has_data(rsk_fido::consts::EF_CRED),
        "and must actually have erased the credential it reported clear"
    );
}

#[test]
fn every_applet_is_selectable_on_a_fresh_device() {
    // No `EF_DEV_CONF` yet, so the mask defaults to every supported application.
    let env = Env::new();
    let mut ccid = env.ccid();
    for (name, aid) in AIDS {
        let res = ccid.handle_apdu(&select(aid), 0).to_vec();
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
            rsk_devconf::CAP_OPENPGP,
        ),
        ("oath", rsk_oath::OATH_AID, rsk_devconf::CAP_OATH),
        ("otp", rsk_otp::OTP_AID, rsk_devconf::CAP_OTP),
        ("piv", rsk_piv::PIV_AID, rsk_devconf::CAP_PIV),
    ] {
        let env = Env::new();
        let mut ccid = env.ccid();
        assert_eq!(sw(ccid.handle_apdu(&select(aid), 0)), rsk_sdk::Sw::OK);

        let blob = dev_conf(rsk_devconf::CAP_FIDO2); // everything else off
        rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
        assert!(!ccid.refresh_enabled() & cap != 0 || !ccid.caps_enabled(cap));

        let res = ccid.handle_apdu(&select(aid), 0).to_vec();
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
    rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    ccid.refresh_enabled();
    for (name, aid) in [
        ("management", rsk_mgmt::MANAGEMENT_AID),
        ("vendor", rsk_vendor::VENDOR_AID),
        ("rescue", rsk_rescue::RESCUE_AID),
    ] {
        let res = ccid.handle_apdu(&select(aid), 0).to_vec();
        assert_eq!(sw(&res), rsk_sdk::Sw::OK, "{name} was gated off");
    }
}

#[test]
fn an_ungated_applet_is_enabled_whatever_the_mask_says() {
    assert!(
        rsk_devconf::cap_enabled(0, 0),
        "cap 0 means always available"
    );
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
    assert!(ccid.caps_enabled(rsk_devconf::CAP_OATH));
    let blob = dev_conf(rsk_devconf::CAP_FIDO2);
    rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    assert!(
        ccid.caps_enabled(rsk_devconf::CAP_OATH),
        "still the cached mask"
    );
    let mask = ccid.refresh_enabled();
    assert!(!rsk_devconf::cap_enabled(mask, rsk_devconf::CAP_OATH));
    assert!(!ccid.caps_enabled(rsk_devconf::CAP_OATH));
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
fn no_applet_defers_another_applets_record() {
    // The union is an OR, so an applet that takes a record OUT of its own gate set
    // — FIDO moved the `pcmr` grant to phase 1 for exactly that reason — still has
    // it deferred if a neighbour's predicate claims it. FIDO and OpenPGP interleave
    // in the 0x10xx band, so this is not hypothetical.
    type Gate = fn(u16) -> bool;
    let predicates: [(&str, Gate); 4] = [
        ("fido", rsk_fido::is_fido_gate_fid),
        ("piv", rsk_piv::files::is_piv_gate_fid),
        ("oath", rsk_oath::is_oath_lock_fid),
        ("openpgp", rsk_openpgp::terminate::is_openpgp_gate_fid),
    ];
    for fid in 0..=u16::MAX {
        let owners: std::vec::Vec<&str> = predicates
            .iter()
            .filter(|(_, owns)| owns(fid))
            .map(|(name, _)| *name)
            .collect();
        assert!(
            owners.len() <= 1,
            "{fid:#06x} is claimed as a gate by {owners:?}"
        );
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
    let blob = dev_conf(rsk_devconf::CAP_FIDO2 | rsk_devconf::CAP_PIV);
    assert!(ccid.ctap_mgmt(0x43, &blob).is_some());
    assert_eq!(
        rsk_devconf::read_enabled_caps(&mut env.fs.borrow_mut()),
        rsk_devconf::CAP_FIDO2 | rsk_devconf::CAP_PIV
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
        rsk_devconf::read_enabled_caps(&mut env.fs.borrow_mut()),
        rsk_devconf::SUPPORTED_CAPS,
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
    let blob = dev_conf(rsk_devconf::CAP_FIDO2);
    rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
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
    let blob = dev_conf(rsk_devconf::CAP_FIDO2);
    rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
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
    // `SCardDisconnect(SCARD_RESET_CARD)` must really force re-selection. This is
    // the load-bearing half: everything else about re-authentication follows from
    // the fresh SELECT it forces — see the sibling below, which measures that.
    let env = Env::new();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)),
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
    ccid.handle_apdu(&select(rsk_mgmt::MANAGEMENT_AID), 0);
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
    let res = ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
    assert!(res.len() <= RESP_CAP);
}

#[test]
fn a_keygen_fast_path_never_fires_for_the_wrong_applet() {
    // Both fast paths bypass the dispatcher, so each re-checks that its applet is
    // the selected one AND still enabled — the contrived window where OpenPGP was
    // selected and then disabled.
    let env = Env::new();
    let mut ccid = env.ccid();
    ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0);
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
    ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
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
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)),
        rsk_sdk::Sw::OK
    );
    // The management key, so GENERATE is refused for its class and not for auth.
    let step1 = ccid
        .handle_apdu(
            &apdu(0x00, 0x87, AES192, 0x9B, &[0x7C, 0x02, 0x81, 0x00]),
            0,
        )
        .to_vec();
    assert_eq!(sw(&step1), rsk_sdk::Sw::OK);
    let mut block: [u8; 16] = step1[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut block).unwrap();
    let mut answer = std::vec![0x7Cu8, 0x12, 0x82, 0x10];
    answer.extend_from_slice(&block);
    assert_eq!(
        sw(ccid.handle_apdu(&apdu(0x00, 0x87, AES192, 0x9B, &answer), 0)),
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
        sw(ccid.handle_apdu(&generate(0x00), 0)),
        rsk_sdk::Sw::EXEC_ERROR,
        "the fast path did not fire, so this test proves nothing"
    );
    assert_eq!(
        sw(ccid.handle_apdu(&generate(0x04), 0)),
        rsk_sdk::Sw::CLA_NOT_SUPPORTED,
        "a secure-messaging class generated a key"
    );
    let seg = ccid.handle_apdu(&generate(0x10), 0).to_vec();
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
        ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
        for p2 in OPENPGP_REFS {
            assert!(ccid.pin_ref_ready(p2), "OpenPGP {p2:#04x}");
        }
        assert!(
            !ccid.pin_ref_ready(rsk_usb::secure_pin::PIV_PIN_P2),
            "the PIV PIN is not OpenPGP's to collect"
        );

        ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0);
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
        ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
        assert!(ccid.pin_ref_ready(rsk_openpgp::consts::PW1_MODE81));

        let blob = dev_conf(rsk_devconf::CAP_FIDO2);
        rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
        ccid.refresh_enabled();
        assert!(!ccid.pin_ref_ready(rsk_openpgp::consts::PW1_MODE81));
    }

    #[test]
    fn an_unknown_pin_reference_paints_nothing() {
        let env = Env::new();
        let mut ccid = env.ccid();
        ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
        assert!(!ccid.pin_ref_ready(0x00));
        assert!(!ccid.pin_ref_ready(0xFF));
    }
}

#[test]
fn a_card_reset_drops_the_verified_pin_too() {
    // The end-to-end half `a_card_reset_drops_the_selection` claimed in prose and
    // never checked: after a reset the card must ask for the PIN again.
    //
    // What HOLDS it is worth saying, because it is not the applets' `deselect`.
    // Co-refutation measured that: skip the deselect and this stays green, since
    // dropping `self.current` sends every later command through a fresh
    // `select(reselect = false)`, and all three status-carrying applets re-lock
    // there anyway. So the deselect is defence in depth and the SELECTION is the
    // load-bearing half — which is why the sibling above keeps asserting it.
    let env = Env::new();
    let mut ccid = env.ccid();
    let verify = apdu(0x00, 0x20, 0x00, 0x80, &rsk_piv::files::DEFAULT_PIN);
    // VERIFY with no body is SP 800-73-4's "am I verified" probe: 9000 while the
    // status stands, 63Cx once it is gone.
    let status = apdu(0x00, 0x20, 0x00, 0x80, &[]);

    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)),
        rsk_sdk::Sw::OK
    );
    assert_eq!(sw(ccid.handle_apdu(&verify, 0)), rsk_sdk::Sw::OK);
    assert_eq!(sw(ccid.handle_apdu(&status, 0)), rsk_sdk::Sw::OK);

    ccid.reset_card();

    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)),
        rsk_sdk::Sw::OK
    );
    assert_ne!(
        sw(ccid.handle_apdu(&status, 0)),
        rsk_sdk::Sw::OK,
        "the card reset left a verified PIN for whoever connects next",
    );
}

// ── FIDO over CCID ──────────────────────────────────────────────────────────

/// CTAP-over-ISO7816 (CTAP 2.1 §11.2.1): `80 10` carries one CTAP2 command.
fn ctap_msg(body: &[u8]) -> Vec<u8> {
    apdu(0x80, 0x10, 0x00, 0x00, body)
}

/// Drive one command the way `CtapPcscDevice._chain_apdus` does: send it, then
/// follow `61xx` with GET RESPONSE until the body is whole. A getInfo is ~400
/// bytes, so nothing about this member is observable without it.
fn exchange_chained(
    ccid: &mut CcidApplets<'_, rsk_fs::storage::ram::RamStorage, TestRng, VendorBoard>,
    command: &[u8],
) -> (Vec<u8>, rsk_sdk::Sw) {
    let mut body = Vec::new();
    let mut res = ccid.handle_apdu(command, 0).to_vec();
    loop {
        let status = sw(&res);
        body.extend_from_slice(&res[..res.len() - 2]);
        if status.sw1() != 0x61 {
            return (body, status);
        }
        res = ccid
            .handle_apdu(&apdu(0x00, 0xC0, 0x00, 0x00, &[]), 0)
            .to_vec();
    }
}

/// `getInfo` — the shortest CTAP2 command there is, and the one every host sends
/// first.
const GET_INFO: &[u8] = &[rsk_fido::consts::CTAP_GET_INFO];
/// `clientPIN { pinUvAuthProtocol: 2, subCommand: getKeyAgreement }`.
const GET_KEY_AGREEMENT: &[u8] = &[
    rsk_fido::consts::CTAP_CLIENT_PIN,
    0xA2,
    0x01,
    0x02,
    0x02,
    0x02,
];

#[test]
fn selecting_fido_over_ccid_answers_the_u2f_version_string() {
    // `CtapPcscDevice._select` raises unless SELECT returns 9000, and sets its
    // NMSG (CTAP1) capability on exactly this body.
    let env = Env::new();
    let mut ccid = env.ccid();
    let res = ccid
        .handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)
        .to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);
    assert_eq!(&res[..res.len() - 2], rsk_fido::consts::U2F_VERSION);
}

#[test]
fn a_ctap2_command_over_ccid_reaches_the_real_applet() {
    let env = Env::new();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    let (body, status) = exchange_chained(&mut ccid, &ctap_msg(GET_INFO));
    assert_eq!(status, rsk_sdk::Sw::OK);
    assert_eq!(body[0], 0x00, "CTAP2_OK leads the response");
    // A getInfo map, not an error byte alone: 0xA0 | n for n < 24, else 0xB8.
    assert!(body.len() > 100, "a getInfo body is hundreds of bytes");
    assert!(
        body[1] == 0xB8 || body[1] & 0xE0 == 0xA0,
        "the body after the status byte is a CBOR map, got {:#04x}",
        body[1]
    );
}

/// The reason the two transports share one `FidoState` rather than owning one
/// each. `getKeyAgreement` returns the ephemeral clientPIN key that lives in RAM
/// state and is generated once per power-up: two states would generate two, and
/// this would return different keys. A separate state would also give a host a
/// second per-boot `PIN_MISMATCH_LIMIT` budget, which is the part that matters and
/// the part no cheap test can see — this is its observable shadow.
#[test]
fn both_transports_answer_from_one_session_state() {
    let env = Env::new();
    let mut ctap = env.ctap();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );

    let over_hid = ctap.handle_cbor(1, GET_KEY_AGREEMENT, 0).to_vec();
    assert_eq!(over_hid[0], 0x00, "clientPIN over CTAPHID");
    let (over_ccid, status) = exchange_chained(&mut ccid, &ctap_msg(GET_KEY_AGREEMENT));
    assert_eq!(status, rsk_sdk::Sw::OK);

    assert_eq!(
        over_hid.as_slice(),
        over_ccid.as_slice(),
        "the same power cycle must have exactly one clientPIN key agreement"
    );
}

#[test]
fn u2f_over_ccid_answers_its_version_command() {
    let env = Env::new();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    // U2F VERSION: interindustry class, so it takes the CTAP1 arm.
    let res = ccid
        .handle_apdu(
            &apdu(0x00, rsk_fido::consts::CTAP_VERSION, 0x00, 0x00, &[]),
            0,
        )
        .to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);
    assert_eq!(&res[..res.len() - 2], rsk_fido::consts::U2F_VERSION);
}

/// One AID carries two applications that `ykman config usb --disable` names
/// separately, so disabling one must not leave the other's commands reachable
/// behind it — the cross-AID bypass in miniature, inside a single applet.
#[test]
fn disabling_one_fido_application_does_not_leave_the_other_reachable() {
    for (name, cap, probe) in [
        ("fido2", rsk_devconf::CAP_FIDO2, ctap_msg(GET_INFO)),
        (
            "u2f",
            rsk_devconf::CAP_U2F,
            apdu(0x00, rsk_fido::consts::CTAP_VERSION, 0x00, 0x00, &[]),
        ),
    ] {
        let env = Env::new();
        let mut ccid = env.ccid();
        // Everything on except this one.
        let blob = dev_conf(rsk_devconf::SUPPORTED_CAPS & !cap);
        rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
        ccid.refresh_enabled();

        // The AID still selects — its sibling application is still on.
        assert_eq!(
            sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
            rsk_sdk::Sw::OK,
            "{name}: the AID must stay selectable for the half still enabled"
        );
        assert_eq!(
            sw(ccid.handle_apdu(&probe, 0)),
            rsk_sdk::Sw::COMMAND_NOT_ALLOWED,
            "{name} is disabled but its commands still answer"
        );
    }
}

#[test]
fn disabling_both_fido_applications_removes_the_aid() {
    let env = Env::new();
    let mut ccid = env.ccid();
    let blob =
        dev_conf(rsk_devconf::SUPPORTED_CAPS & !(rsk_devconf::CAP_FIDO2 | rsk_devconf::CAP_U2F));
    rsk_devconf::persist_dev_conf(&mut env.fs.borrow_mut(), &blob[1..]).unwrap();
    ccid.refresh_enabled();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::FILE_NOT_FOUND,
        "with neither application enabled the applet is not there at all"
    );
}
