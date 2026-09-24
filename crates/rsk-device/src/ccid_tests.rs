// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
#[cfg(not(feature = "strict-config"))]
use crate::tests::WriteStuck;
use crate::tests::{Env, TestRng, VendorBoard, apdu, dev_conf, get_creds_metadata, select, sw};

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

/// The ack is all the host hears and `.is_ok()` decides it, so mutating it to
/// `true` acked a `persist_dev_conf` the medium refused and ykman then reported a
/// capability set the card does not have — `factory_wipe`'s laundering shape.
/// Measured here, of 78, both directions are 77 passed / 1 failed: `true` fails
/// this test, `false` fails `write_config_over_the_fido_transport_round_trips`.
///
/// The verdict is the FIRST assertion; the second is belt-and-braces, never a
/// second one — `WriteStuck` lands no record, so `read_enabled_caps` answers
/// `SUPPORTED_CAPS` by construction and all 78 pass with the first neutered.
#[cfg(not(feature = "strict-config"))]
#[test]
fn a_refused_config_write_is_never_acked_as_a_written_one() {
    let env = Env::with_storage(WriteStuck::new());
    let mut ccid = env.ccid();
    let blob = dev_conf(rsk_devconf::CAP_FIDO2 | rsk_devconf::CAP_PIV);
    assert!(
        ccid.ctap_mgmt(0x43, &blob).is_none(),
        "a config the medium refused must not be acked as stored"
    );
    assert_eq!(
        rsk_devconf::read_enabled_caps(&mut env.fs.borrow_mut()),
        rsk_devconf::SUPPORTED_CAPS,
        "and the card still reports what it actually has"
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
    // PW3 verified, so nothing but the missing accelerator can send it back.
    rsk_openpgp::scan_files(
        &crate::tests::dev(),
        &mut env.fs.borrow_mut(),
        &mut *env.rng.borrow_mut(),
    )
    .unwrap();
    let mut ccid = env.ccid();
    ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
    let pw3 = apdu(0x00, 0x20, 0x00, 0x83, rsk_openpgp::consts::PW3_DEFAULT);
    assert_eq!(sw(ccid.handle_apdu(&pw3, 0)), rsk_sdk::Sw::OK);
    let generate = apdu(
        0x00,
        rsk_openpgp::consts::INS_KEYPAIR_GEN,
        0x80,
        0x00,
        &[0xB6, 0x00],
    );
    // Not an EXEC_ERROR answer: the command has to reach the applet.
    assert!(ccid.try_rsa_keygen(&generate).is_none());
}

type Ccid<'a> = CcidApplets<'a, rsk_fs::storage::ram::RamStorage, TestRng, VendorBoard>;

/// PIV selected and its default AES-192 management key authenticated.
fn piv_as_admin(ccid: &mut Ccid<'_>) {
    const DEFAULT_MGM: [u8; 24] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    const AES192: u8 = rsk_piv::files::ALGO_AES192;
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)),
        rsk_sdk::Sw::OK
    );
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
}

#[test]
fn a_keygen_fast_path_judges_the_class_byte_too() {
    // Both fast paths run BEFORE `Dispatcher::process`, so its class-byte rule has
    // to be applied ahead of them or a GENERATE is the one command that escapes it.
    // Measured on a YubiKey 5.7.4: `04 47 00 9A …` is `6E00` where `00 47 …` is
    // `6982`, and `10 47 …` is accumulated as a chain segment, never executed.
    let env = Env::new();
    env.board.borrow_mut().accelerator = true;
    let mut ccid = env.ccid();
    // The management key, so GENERATE is refused for its class and not for auth.
    piv_as_admin(&mut ccid);
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

/// The frames of one command's answer, joined through GET RESPONSE: each frame's
/// status word and length, and the whole body.
fn frames(ccid: &mut Ccid<'_>, command: &[u8]) -> (Vec<(rsk_sdk::Sw, usize)>, Vec<u8>) {
    let mut got = Vec::new();
    let mut body = Vec::new();
    let mut res = ccid.handle_apdu(command, 0).to_vec();
    loop {
        let status = sw(&res);
        got.push((status, res.len() - 2));
        body.extend_from_slice(&res[..res.len() - 2]);
        if status.sw1() != 0x61 || got.len() > 16 {
            return (got, body);
        }
        res = ccid
            .handle_apdu(&[0x00, 0xC0, 0x00, 0x00, 0x00], 0)
            .to_vec();
    }
}

/// The fixed RSA-2048 key the test board's accelerator finds.
fn rsa2048() -> Box<rsk_rsa::RsaKey> {
    use rsk_rsa::vectors::{P_HEX, Q_HEX, hex};
    let key = rsk_rsa::keygen::rsa_from_pqe(rsk_rsa::RSA_PUB_EXP_BE, &hex(P_HEX), &hex(Q_HEX));
    Box::new(key.expect("the fixture's primes make a key"))
}

#[test]
fn a_fast_path_keygen_is_cut_at_the_frame_cap_like_any_answer() {
    // Both fast paths answer off the dispatcher, and wrote the public key whole
    // whatever the GENERATE's Le. A YubiKey 5.8.0 cuts an RSA-2048 GENERATE's
    // answer at 256 bytes for a short command, PIV and OpenPGP alike (measured
    // twice), and answers an extended one with no Le whole.
    let env = Env::new();
    env.board.borrow_mut().accelerator = true;
    // The boot block lays OpenPGP's files down, PW3 among them; nothing boots here.
    rsk_openpgp::scan_files(
        &crate::tests::dev(),
        &mut env.fs.borrow_mut(),
        &mut *env.rng.borrow_mut(),
    )
    .unwrap();
    let mut ccid = env.ccid();
    let piv = |ext: bool| {
        let t = [0xAC, 0x03, 0x80, 0x01, 0x07];
        match ext {
            false => [&[0x00, 0x47, 0x00, 0x9A, 0x05][..], &t[..], &[0x00][..]].concat(),
            true => [&[0x00, 0x47, 0x00, 0x9A, 0x00, 0x00, 0x05][..], &t[..]].concat(),
        }
    };
    let pgp = |ext: bool| match ext {
        false => std::vec![0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00],
        true => std::vec![0x00, 0x47, 0x80, 0x00, 0x00, 0x00, 0x02, 0xB6, 0x00],
    };
    for app in ["piv", "openpgp"] {
        for ext in [false, true] {
            match app {
                "piv" => piv_as_admin(&mut ccid),
                _ => {
                    ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
                    let pw3 = apdu(0x00, 0x20, 0x00, 0x83, rsk_openpgp::consts::PW3_DEFAULT);
                    assert_eq!(sw(ccid.handle_apdu(&pw3, 0)), rsk_sdk::Sw::OK);
                }
            }
            env.board.borrow_mut().search_key = Some(rsa2048());
            let command = if app == "piv" { piv(ext) } else { pgp(ext) };
            let (got, body) = frames(&mut ccid, &command);
            assert!(
                env.board.borrow().search_key.is_none(),
                "{app}: the fast path did not fire, so this test proves nothing"
            );
            // The joined frames are the key's public-key DO, byte for byte.
            let mut pubdo = [0u8; rsk_rsa::MAX_RSA_PUBDO];
            let n = rsk_rsa::make_rsa_response(&rsa2048(), &mut pubdo);
            assert_eq!(body, &pubdo[..n], "{app}, extended {ext}: another body");
            let whole = body.len();
            assert!(whole > 256, "{app}: a {whole}-byte key cannot tell");
            let want = match ext {
                false => std::vec![
                    (rsk_sdk::Sw::new(0x61, (whole - 256) as u8), 256),
                    (rsk_sdk::Sw::OK, whole - 256),
                ],
                true => std::vec![(rsk_sdk::Sw::OK, whole)],
            };
            assert_eq!(got, want, "{app}, extended {ext}");
        }
    }
}

#[test]
fn a_fast_path_keygen_drops_a_held_tail() {
    // Any command but GET RESPONSE drops the tail the dispatcher holds. The fast
    // paths answer off the dispatcher, so `Dispatcher::chain_response` drops it
    // for them.
    let env = Env::new();
    env.board.borrow_mut().accelerator = true;
    let mut ccid = env.ccid();
    piv_as_admin(&mut ccid);
    let template = [0xAC, 0x03, 0x80, 0x01, 0x07];
    let short = [
        &[0x00, 0x47, 0x00, 0x9A, 0x05][..],
        &template[..],
        &[0x00][..],
    ]
    .concat();
    let ext = [
        &[0x00, 0x47, 0x00, 0x9A, 0x00, 0x00, 0x05][..],
        &template[..],
    ]
    .concat();
    let generate = |ccid: &mut Ccid<'_>, command: &[u8]| {
        env.board.borrow_mut().search_key = Some(rsa2048());
        sw(ccid.handle_apdu(command, 0))
    };

    assert_eq!(generate(&mut ccid, &short).sw1(), 0x61, "no tail was held");
    assert_eq!(generate(&mut ccid, &ext), rsk_sdk::Sw::OK);
    let gr = ccid
        .handle_apdu(&[0x00, 0xC0, 0x00, 0x00, 0x00], 0)
        .to_vec();
    assert_eq!(
        (sw(&gr), gr.len()),
        (rsk_sdk::Sw::WRONG_DATA, 2),
        "the first key's tail outlived the second key's answer"
    );
}

#[test]
fn a_keygen_fast_path_yields_to_an_open_chain() {
    // With a chain open a GENERATE is the dispatcher's. Outside the chain it is
    // `6883` and runs nothing, as on a YubiKey 5.8.0 (read twice, after a stranded
    // GET DATA segment); as the chain's final segment it is joined to the chain.
    let env = Env::new();
    env.board.borrow_mut().accelerator = true;
    rsk_openpgp::scan_files(
        &crate::tests::dev(),
        &mut env.fs.borrow_mut(),
        &mut *env.rng.borrow_mut(),
    )
    .unwrap();
    let mut ccid = env.ccid();
    let segment = [0x10, 0xCB, 0x3F, 0xFF, 0x02, 0x5C, 0x03];
    let piv_generate = [0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x07];
    let pgp_generate = [0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00];
    // A key for the accelerator to hand out, so a fast path that fires takes it.
    let arm = || env.board.borrow_mut().search_key = Some(rsa2048());
    let untouched = || env.board.borrow().search_key.is_some();
    // The control: with no chain open the fast path fires, and with no key to find
    // answers EXEC_ERROR for itself.
    piv_as_admin(&mut ccid);
    assert_eq!(
        sw(ccid.handle_apdu(&piv_generate, 0)),
        rsk_sdk::Sw::EXEC_ERROR,
        "piv: the fast path did not fire, so this test proves nothing"
    );
    // 9A's certificate object, so the chain joined would read something.
    let object = [0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x03, 0x70, 0x01, 0x00];
    assert_eq!(
        sw(ccid.handle_apdu(&apdu(0x00, 0xDB, 0x3F, 0xFF, &object), 0)),
        rsk_sdk::Sw::OK
    );
    let joined = apdu(0x00, 0xCB, 0x3F, 0xFF, &[0x5C, 0x03, 0x5F, 0xC1, 0x05]);
    assert_eq!(
        sw(ccid.handle_apdu(&joined, 0)),
        rsk_sdk::Sw::OK,
        "control: the joined read finds 5FC105"
    );
    arm();
    assert_eq!(sw(ccid.handle_apdu(&segment, 0)), rsk_sdk::Sw::OK);
    assert_eq!(
        sw(ccid.handle_apdu(&piv_generate, 0)),
        rsk_sdk::Sw::LAST_CHAIN_EXPECTED,
        "piv, outside the chain"
    );
    assert!(untouched(), "piv: a GENERATE outside the chain ran");
    // The refusal dropped the chain, so its would-be final segment is read alone:
    // a list with no `5C`, `6A82`, where joined to the segment it reads 5FC105.
    let alone = [0x00, 0xCB, 0x3F, 0xFF, 0x03, 0x5F, 0xC1, 0x05];
    assert_eq!(sw(ccid.handle_apdu(&alone, 0)), rsk_sdk::Sw::FILE_NOT_FOUND);
    // Joined, PIV reads `FF FF AC 03 …`, a body its template does not open.
    let junk = [0x10, 0x47, 0x00, 0x9A, 0x02, 0xFF, 0xFF];
    assert_eq!(sw(ccid.handle_apdu(&junk, 0)), rsk_sdk::Sw::OK);
    assert_eq!(
        sw(ccid.handle_apdu(&piv_generate, 0)),
        rsk_sdk::Sw::WRONG_DATA,
        "piv, the chain's final segment"
    );
    // A segment with no data opens a chain as well; joined, the applet's own
    // keygen answers, and the accelerator is still not asked.
    assert_eq!(
        sw(ccid.handle_apdu(&[0x10, 0x47, 0x00, 0x9A], 0)),
        rsk_sdk::Sw::OK
    );
    assert_eq!(
        sw(ccid.handle_apdu(&piv_generate, 0)).sw1(),
        0x61,
        "piv, the final segment of an empty chain"
    );
    assert!(
        untouched(),
        "piv: the fast path took a chain's final segment"
    );

    ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0);
    let pw3 = apdu(0x00, 0x20, 0x00, 0x83, rsk_openpgp::consts::PW3_DEFAULT);
    assert_eq!(sw(ccid.handle_apdu(&pw3, 0)), rsk_sdk::Sw::OK);
    env.board.borrow_mut().search_key = None;
    assert_eq!(
        sw(ccid.handle_apdu(&pgp_generate, 0)),
        rsk_sdk::Sw::EXEC_ERROR,
        "openpgp: the fast path did not fire, so this test proves nothing"
    );
    arm();
    assert_eq!(sw(ccid.handle_apdu(&segment, 0)), rsk_sdk::Sw::OK);
    assert_eq!(
        sw(ccid.handle_apdu(&pgp_generate, 0)),
        rsk_sdk::Sw::LAST_CHAIN_EXPECTED,
        "openpgp, outside the chain"
    );
    assert!(untouched(), "openpgp: a GENERATE outside the chain ran");
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

#[test]
fn a_get_response_with_nothing_owed_is_wrong_data_on_piv_alone() {
    // Every form a YubiKey 5.8.0 was read in, twice, over an applet with no tail
    // owed: its PIV answers `6A80` to all of them, OpenPGP, management, OATH, OTP
    // and FIDO `6D00`. Vendor and rescue are this device's own, pinned as they are.
    let forms: [&[u8]; 8] = [
        &[0x00, 0xC0, 0x00, 0x00],
        &[0x00, 0xC0, 0x00, 0x00, 0x00],
        &[0x00, 0xC0, 0x00, 0x00, 0x10],
        &[0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x00, 0xC0, 0x12, 0x34, 0x00],
        &[0x00, 0xC0, 0x01, 0x00, 0x00],
        &[0x00, 0xC0, 0x00, 0x00, 0x01, 0x00],
        &[0x00, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00],
    ];
    let env = Env::new();
    let mut ccid = env.ccid();
    for (name, aid) in AIDS {
        let want = match name {
            "piv" => rsk_sdk::Sw::WRONG_DATA,
            // Rescue refuses any class but `80` before it reads the instruction.
            "rescue" => rsk_sdk::Sw::CLA_NOT_SUPPORTED,
            _ => rsk_sdk::Sw::INS_NOT_SUPPORTED,
        };
        for gr in forms {
            assert_eq!(sw(ccid.handle_apdu(&select(aid), 0)), rsk_sdk::Sw::OK);
            assert_eq!(sw(ccid.handle_apdu(gr, 0)), want, "{name}: {gr:02X?}");
        }
    }
    // PIV judges no class byte of its own, so `80` is `6A80` there too.
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)),
        rsk_sdk::Sw::OK
    );
    assert_eq!(
        sw(ccid.handle_apdu(&[0x80, 0xC0, 0x00, 0x00, 0x00], 0)),
        rsk_sdk::Sw::WRONG_DATA
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

/// The panel's clientPIN signal (a re-key, a rejected PIN, a wipe) ends the host's token on
/// both FIDO transports. They share one `FidoState`, but only the CTAPHID handler read the
/// signal, so over a smart-card reader the old token kept working.
#[test]
fn a_panel_pin_change_ends_the_token_over_ccid_too() {
    let env = Env::new();
    // A live cm-permission token, as getPinUvAuthTokenUsingPinWithPermissions leaves one.
    {
        let mut state = env.fido_state.borrow_mut();
        state.reset_pin_uv_auth_token(&mut *env.rng.borrow_mut());
        state.begin_using_token(false, 0);
        state.paut.permissions = rsk_fido::state::PERM_CM;
    }
    let metadata = ctap_msg(&get_creds_metadata(&env.fido_state.borrow().paut.token));
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );

    let (before, _) = exchange_chained(&mut ccid, &metadata);
    env.board.borrow_mut().local_pin_change = true;
    let (after, _) = exchange_chained(&mut ccid, &metadata);
    assert_eq!(
        (before[0], after[0]),
        (
            rsk_fido::CTAP2_OK,
            rsk_fido::CtapError::PinAuthInvalid.as_u8()
        ),
        "the token the old PIN authorized must stop verifying over CCID once the panel changed it"
    );
}

/// Three wrong PINs over CCID engage the §6.5.5.6 soft lock, and it has to reach the board
/// as CTAPHID's does: the vendor and rescue applets serve an ungated warm reboot on this
/// same interface, and a lock only RAM held gave a PC/SC host three guesses per reboot.
#[test]
fn a_soft_lock_engaged_over_ccid_is_handed_over_for_persisting() {
    let env = Env::new();
    let _power_up = env.ctap();
    rsk_fido::passkeys::store_local_pin(&crate::tests::dev(), &mut env.fs.borrow_mut(), b"123456")
        .expect("the test PIN meets the default policy");
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );

    let wrong = ctap_msg(&crate::tests::wrong_pin_token_request());
    let answers: Vec<u8> = (0..rsk_fido::consts::PIN_MISMATCH_LIMIT)
        .map(|_| exchange_chained(&mut ccid, &wrong).0[0])
        .collect();
    assert_eq!(
        answers.last().copied(),
        Some(rsk_fido::CtapError::PinAuthBlocked.as_u8()),
        "the wrong PINs did not engage the lock in RAM: {answers:?}"
    );
    assert_eq!(
        env.board.borrow().pin_locks.last().map(|lock| lock.engaged),
        Some(true),
        "the soft lock three wrong PINs engaged over CCID never reached the board"
    );
}

/// `credentialManagement { getNextRP }` (§6.8): subcommand 0x03, no params, no token.
fn get_next_rp() -> Vec<u8> {
    std::vec![
        rsk_fido::consts::CTAP_CREDENTIAL_MGMT,
        0xA1,
        0x01,
        rsk_fido::consts::CM_ENUMERATE_RPS_NEXT as u8,
    ]
}

/// A getNextRP carries no pinUvAuthParam — its authorization IS the channel whose
/// Begin opened the walk (§6.8). CCID stamped no channel, so it ran with the last
/// CTAPHID CID and could take the next leg of a walk a CTAPHID manager had opened,
/// reading the RP ids that manager's token had bought, having shown none of its own.
#[test]
fn a_credmgmt_walk_bound_to_a_ctaphid_channel_is_not_continuable_over_ccid() {
    // The first CID `rsk_usb::ctaphid::CidAllocator` hands out, so a CCID sentinel set
    // to any real channel (not just some arbitrary one) would collide with it here.
    const CHANNEL: u32 = 0x0100_0000;
    let env = Env::new();
    let mut ctap = env.ctap();
    let mut ccid = env.ccid();
    // FIDO is selected over CCID up front, as a PC/SC session does once: the getNextRP
    // below is then the first CCID APDU after the walk is bound, so the channel it runs
    // on has to be stamped BEFORE its dispatch, not swept by the next command's entry.
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    // A walk enumerateRPsBegin opened on CTAPHID channel CHANNEL, with a leg to serve.
    {
        let mut st = env.fido_state.borrow_mut();
        st.channel = CHANNEL;
        st.cm.channel = CHANNEL;
        st.cm.rp_counter = 1;
        st.cm.rp_total = 1;
    }
    // The channel that opened it may take the next leg: the store holds no RP, so the
    // gate passes and the scan reports NoCredentials rather than refusing the caller.
    assert_eq!(
        ctap.handle_cbor(CHANNEL, &get_next_rp(), 0)[0],
        rsk_fido::CtapError::NoCredentials.as_u8(),
        "the channel that opened the walk was refused its own next leg"
    );
    // Over CCID the same walk must be refused — a smart-card reader is not that channel.
    let (over_ccid, _) = exchange_chained(&mut ccid, &ctap_msg(&get_next_rp()));
    assert_eq!(
        over_ccid[0],
        rsk_fido::CtapError::NotAllowed.as_u8(),
        "a credMgmt walk opened on a CTAPHID channel was continued over CCID"
    );
}

/// A vendor (0x41) command over CCID must re-apply the LED block that lives outside
/// flash, as the CTAPHID handler does — else a `rsk led` write over PC/SC takes no
/// effect until the next reboot.
#[test]
fn a_vendor_command_over_ccid_reapplies_the_configuration() {
    let _phy = crate::tests::PHY_WRITE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let env = Env::new();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    exchange_chained(&mut ccid, &ctap_msg(&[rsk_fido::consts::CTAP_VENDOR]));
    assert_eq!(
        env.board.borrow().config_written,
        1,
        "a 0x41 command over CCID did not re-apply the live configuration"
    );
}

/// A phy write over CCID changes the boot-only USB identity, so it must warm-reboot on
/// the write. Left unhandled, the flag it set was taken by the next unrelated CTAPHID
/// 0x41 command, rebooting on that one — even an audit read.
#[test]
fn a_phy_write_over_ccid_reboots_on_the_write_not_a_later_command() {
    let _phy = crate::tests::PHY_WRITE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let env = Env::new();
    let phy = rsk_phy::PhyData {
        presence_timeout: Some(45),
        ..Default::default()
    };
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = phy.serialize(&mut blob).unwrap();
    let write = ctap_msg(&crate::tests::vendor_config_write(
        rsk_fido::consts::CONFIG_TARGET_PHY,
        &blob[..blen],
    ));
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    exchange_chained(&mut ccid, &write);
    assert_eq!(
        env.board.borrow().reboots,
        1,
        "a phy write over CCID must warm-reboot on the write"
    );
    // The one-shot flag must be gone: a later unrelated CTAPHID 0x41 does not inherit it.
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &[rsk_fido::consts::CTAP_VENDOR], 0);
    assert_eq!(
        env.board.borrow().reboots,
        1,
        "a later CTAPHID command inherited the phy write's reboot"
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
    // U2F VERSION, under the interindustry class U2F takes.
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
    // CTAP2 is taken under `00` too, and must be gated there as under `80`.
    let get_info_00 = apdu(0x00, 0x10, 0x00, 0x00, GET_INFO);
    for (name, cap, probe, other) in [
        ("fido2", rsk_devconf::CAP_FIDO2, ctap_msg(GET_INFO), None),
        (
            "fido2 under 00",
            rsk_devconf::CAP_FIDO2,
            get_info_00.clone(),
            None,
        ),
        (
            "u2f",
            rsk_devconf::CAP_U2F,
            apdu(0x00, rsk_fido::consts::CTAP_VERSION, 0x00, 0x00, &[]),
            Some(get_info_00.clone()),
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
        // …and the half still on answers, CTAP2 under `00` included.
        if let Some(other) = other {
            let (body, status) = exchange_chained(&mut ccid, &other);
            assert_eq!(
                (status, body.first()),
                (rsk_sdk::Sw::OK, Some(&0x00)),
                "{name}: CTAP2 under 00 went with it"
            );
        }
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

/// Issue #111: YubiKit selects OATH and OTP by the whole 8-byte instance AID, ykman
/// by a 7-byte prefix of it. A YubiKey 5.8.0 answers both and refuses anything past
/// or beside those 8 bytes — the same cells, measured there, are pinned here.
#[test]
fn oath_and_otp_select_by_the_aids_yubikit_and_ykman_send() {
    const OK: rsk_sdk::Sw = rsk_sdk::Sw::OK;
    const NOT_FOUND: rsk_sdk::Sw = rsk_sdk::Sw::FILE_NOT_FOUND;
    let env = Env::new();
    let mut ccid = env.ccid();
    for (who, aid, want) in [
        (
            "YubiKit OATH",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01][..],
            OK,
        ),
        (
            "ykman OATH",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01][..],
            OK,
        ),
        (
            "YubiKit OTP",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01][..],
            OK,
        ),
        (
            "ykman OTP",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01][..],
            OK,
        ),
        (
            "OATH, last byte wrong",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x00][..],
            NOT_FOUND,
        ),
        (
            "OATH, one byte past",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01, 0x00][..],
            NOT_FOUND,
        ),
        (
            "OTP, last byte wrong",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00][..],
            NOT_FOUND,
        ),
        (
            "OTP, one byte past",
            &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01, 0x00][..],
            NOT_FOUND,
        ),
    ] {
        let res = ccid.handle_apdu(&select(aid), 0).to_vec();
        assert_eq!(sw(&res), want, "{who}");
    }
}

#[test]
fn a_card_applet_serves_class_80_as_it_serves_00() {
    // A YubiKey 5.8.0, read twice: PIV, OpenPGP, OATH, management and OTP run a
    // known instruction under class 80 exactly as under 00, and answer an unknown
    // one 6D00 under either. Of the classes probed, macOS 27's PC/SC let only these
    // two reach it.
    let known: [(&str, &[u8], [u8; 4]); 5] = [
        ("piv", rsk_piv::PIV_AID, [0x00, 0xFD, 0x00, 0x00]),
        (
            "openpgp",
            rsk_openpgp::consts::OPENPGP_AID,
            [0x00, 0xCA, 0x00, 0x6E],
        ),
        ("oath", rsk_oath::OATH_AID, [0x00, 0xA1, 0x00, 0x00]),
        (
            "management",
            rsk_mgmt::MANAGEMENT_AID,
            [0x00, 0x1D, 0x00, 0x00],
        ),
        ("otp", rsk_otp::OTP_AID, [0x00, 0x03, 0x00, 0x00]),
    ];
    let env = Env::new();
    let mut ccid = env.ccid();
    for (name, aid, header) in known {
        for ins in [header[1], 0x12] {
            let mut answers = std::vec![];
            for cla in [0x00, 0x80] {
                assert_eq!(
                    sw(ccid.handle_apdu(&select(aid), 0)),
                    rsk_sdk::Sw::OK,
                    "{name}"
                );
                let res = ccid.handle_apdu(&[cla, ins, header[2], header[3], 0x00], 0);
                answers.push((sw(res), res.len()));
            }
            assert_eq!(
                answers[0], answers[1],
                "{name}, INS {ins:02X}: class 80 is not 00"
            );
            if ins == 0x12 {
                assert_eq!(answers[1].0, rsk_sdk::Sw::INS_NOT_SUPPORTED, "{name}");
            } else {
                assert!(
                    matches!(answers[1].0.sw1(), 0x90 | 0x61),
                    "{name}: {answers:04X?}"
                );
            }
        }
    }
}

#[test]
fn fido_over_ccid_answers_each_instruction_as_a_yubikey_does() {
    // A YubiKey 5.8.0, one command per process because some of its FIDO commands
    // wait for a touch: CTAP's three instructions are taken under `00` as under
    // `80`, U2F's only under `00` (`6E00` under `80`), and any other is `6D00`.
    use rsk_sdk::Sw;
    let env = Env::new();
    let mut ccid = env.ccid();
    let timeout = [rsk_fido::error::CtapError::UserActionTimeout as u8];
    let rows: [(&str, [u8; 4], Sw, &[u8]); 24] = [
        ("GETRESPONSE", [0x80, 0x11, 0x00, 0x00], Sw::OK, &timeout),
        (
            "GETRESPONSE, cancel",
            [0x80, 0x11, 0x11, 0x00],
            Sw::OK,
            &timeout,
        ),
        (
            "GETRESPONSE, P1 03",
            [0x80, 0x11, 0x03, 0x00],
            Sw::OK,
            &timeout,
        ),
        (
            "GETRESPONSE, P2 03",
            [0x80, 0x11, 0x00, 0x03],
            Sw::OK,
            &timeout,
        ),
        (
            "GETRESPONSE under 00",
            [0x00, 0x11, 0x00, 0x00],
            Sw::OK,
            &timeout,
        ),
        (
            "cancel under 00",
            [0x00, 0x11, 0x11, 0x00],
            Sw::OK,
            &timeout,
        ),
        ("CONTROL, end", [0x80, 0x12, 0x01, 0x00], Sw::OK, &[]),
        (
            "CONTROL, P1 00",
            [0x80, 0x12, 0x00, 0x00],
            Sw::INCORRECT_P1P2,
            &[],
        ),
        (
            "CONTROL, P1 02",
            [0x80, 0x12, 0x02, 0x00],
            Sw::INCORRECT_P1P2,
            &[],
        ),
        (
            "CONTROL, P2 01",
            [0x80, 0x12, 0x00, 0x01],
            Sw::INCORRECT_P1P2,
            &[],
        ),
        (
            "CONTROL, P1 FF",
            [0x80, 0x12, 0xFF, 0x00],
            Sw::INCORRECT_P1P2,
            &[],
        ),
        (
            "CONTROL under 00",
            [0x00, 0x12, 0x00, 0x00],
            Sw::INCORRECT_P1P2,
            &[],
        ),
        (
            "CONTROL, end under 00",
            [0x00, 0x12, 0x01, 0x00],
            Sw::OK,
            &[],
        ),
        // No reading reached a class past these two, so another goes to U2F as it did.
        (
            "MSG under A0",
            [0xA0, 0x10, 0x00, 0x00],
            Sw::CLA_NOT_SUPPORTED,
            &[],
        ),
        (
            "GETRESPONSE under 01",
            [0x01, 0x11, 0x00, 0x00],
            Sw::CLA_NOT_SUPPORTED,
            &[],
        ),
        (
            "U2F VERSION under 80",
            [0x80, 0x03, 0x00, 0x00],
            Sw::CLA_NOT_SUPPORTED,
            &[],
        ),
        (
            "U2F REGISTER under 80",
            [0x80, 0x01, 0x00, 0x00],
            Sw::CLA_NOT_SUPPORTED,
            &[],
        ),
        ("U2F VERSION", [0x00, 0x03, 0x00, 0x00], Sw::OK, b"U2F_V2"),
        (
            "U2F VERSION, P1 03",
            [0x00, 0x03, 0x03, 0x00],
            Sw::OK,
            b"U2F_V2",
        ),
        (
            "unknown 04",
            [0x80, 0x04, 0x00, 0x00],
            Sw::INS_NOT_SUPPORTED,
            &[],
        ),
        (
            "unknown 04, P1 03",
            [0x80, 0x04, 0x03, 0x00],
            Sw::INS_NOT_SUPPORTED,
            &[],
        ),
        (
            "unknown C0",
            [0x80, 0xC0, 0x00, 0x00],
            Sw::INS_NOT_SUPPORTED,
            &[],
        ),
        (
            "unknown 04 under 00",
            [0x00, 0x04, 0x00, 0x00],
            Sw::INS_NOT_SUPPORTED,
            &[],
        ),
        (
            "unknown FF under 00",
            [0x00, 0xFF, 0x00, 0x00],
            Sw::INS_NOT_SUPPORTED,
            &[],
        ),
    ];
    for (name, [cla, ins, p1, p2], want, body) in rows {
        let sel = ccid
            .handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)
            .to_vec();
        assert_eq!(sw(&sel), Sw::OK, "{name}: SELECT");
        let res = ccid.handle_apdu(&[cla, ins, p1, p2, 0x00], 0).to_vec();
        assert_eq!((sw(&res), &res[..res.len() - 2]), (want, body), "{name}");
    }
    // MSG under `00` is the same CTAP2 command: getInfo answers alike both ways.
    let get_info = |ccid: &mut Ccid<'_>, cla: u8| {
        ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0);
        exchange_chained(ccid, &apdu(cla, 0x10, 0x00, 0x00, GET_INFO))
    };
    let (under_80, under_00) = (get_info(&mut ccid, 0x80), get_info(&mut ccid, 0x00));
    assert_eq!(
        (under_80.1, under_80.0.first()),
        (Sw::OK, Some(&0x00)),
        "control: getInfo succeeds under 80"
    );
    assert_eq!(under_00, under_80, "MSG under 00");
}

/// FIDO takes its MSG under `00` as under `80`, so a vendor write sent under `00`
/// must run the same post-write side effects: here, the phy write's reboot.
#[test]
fn a_vendor_write_under_class_00_reboots_like_one_under_80() {
    let _phy = crate::tests::PHY_WRITE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let env = Env::new();
    let phy = rsk_phy::PhyData {
        presence_timeout: Some(45),
        ..Default::default()
    };
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = phy.serialize(&mut blob).unwrap();
    let mut write = ctap_msg(&crate::tests::vendor_config_write(
        rsk_fido::consts::CONFIG_TARGET_PHY,
        &blob[..blen],
    ));
    write[0] = 0x00;
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0)),
        rsk_sdk::Sw::OK
    );
    assert_eq!(exchange_chained(&mut ccid, &write).1, rsk_sdk::Sw::OK);
    assert_eq!(
        env.board.borrow().reboots,
        1,
        "a phy write under class 00 did not reboot"
    );
}

/// A chain segment is only buffered, so the router must not run a vendor write's
/// side effects on its `9000`: that would act for a command not yet executed.
#[test]
fn a_vendor_write_segment_runs_no_side_effects() {
    let env = Env::new();
    let body = crate::tests::vendor_config_write(rsk_fido::consts::CONFIG_TARGET_PHY, &[0; 8]);
    assert_eq!(
        body.first(),
        Some(&rsk_fido::consts::CTAP_VENDOR),
        "control"
    );
    let mut ccid = env.ccid();
    ccid.handle_apdu(&select(rsk_fido::consts::FIDO_AID), 0);
    let segment = apdu(0x90, 0x10, 0x00, 0x00, &body);
    assert_eq!(sw(ccid.handle_apdu(&segment, 0)), rsk_sdk::Sw::OK);
    assert_eq!(
        env.board.borrow().config_written,
        0,
        "the side effects ran on a segment"
    );
}
