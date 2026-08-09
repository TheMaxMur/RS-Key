// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, apdu, select, sw};

/// U2F VERSION — the one U2F command that touches no credential and needs no
/// touch, so it can stand for "did this reach the FIDO applet?".
fn u2f_version() -> std::vec::Vec<u8> {
    apdu(0x00, rsk_fido::consts::CTAP_VERSION, 0x00, 0x00, &[])
}

/// The CTAP2 command that answers unauthenticated, for exercising the CBOR path.
const GET_INFO: [u8; 1] = [rsk_fido::consts::CTAP_GET_INFO];

#[test]
fn a_u2f_command_reaches_fido_when_nothing_is_selected() {
    // U2F has no SELECT over CTAPHID, so its INS is routed straight to the FIDO
    // applet — but only while the dispatcher holds no selection.
    let env = Env::new();
    let mut ctap = env.ctap();
    let res = ctap.handle_msg(&u2f_version(), 0).to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);
    assert_eq!(&res[..6], b"U2F_V2");
}

#[test]
fn a_selected_vendor_aid_is_not_hijacked_by_a_u2f_ins() {
    // The routing rule that matters: once the vendor AID is selected, a command
    // carrying a U2F INS belongs to the vendor applet. Routing it to FIDO anyway
    // would let a host reach the U2F surface from inside another AID's session.
    let env = Env::new();
    let mut ctap = env.ctap();
    let res = ctap.handle_msg(&select(rsk_vendor::VENDOR_AID), 0).to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);

    let res = ctap.handle_msg(&u2f_version(), 0).to_vec();
    assert_ne!(
        &res[..res.len() - 2],
        b"U2F_V2",
        "a U2F INS was served by FIDO while the vendor AID was selected"
    );
}

#[test]
fn a_ctaphid_init_drops_a_stale_selection() {
    // A fresh session must start with nothing selected, or U2F — which never
    // selects anything — inherits whatever the previous one left behind.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_msg(&select(rsk_vendor::VENDOR_AID), 0);
    ctap.deselect_msg();
    let res = ctap.handle_msg(&u2f_version(), 0).to_vec();
    assert_eq!(&res[..6], b"U2F_V2", "U2F is reachable again");
}

#[test]
fn a_select_is_never_routed_to_u2f() {
    // The other half of the same rule: with nothing selected, INS 0xA4 has to reach
    // the dispatcher, or no AID could ever be selected over this transport.
    let env = Env::new();
    let mut ctap = env.ctap();
    let res = ctap.handle_msg(&select(rsk_vendor::VENDOR_AID), 0).to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);
    assert!(ctap.disp.current().is_some());
}

// --- the clientPIN soft lock across a warm reset ---------------------------

#[test]
fn every_cbor_dispatch_hands_the_soft_lock_over_for_persisting() {
    // CTAP 2.1 §6.5.5.6: only a physical power cycle clears the lock, and a host
    // can request a warm one ungated — so the RAM state has to be handed to the
    // board after every command, not at some convenient point.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(0x1234_5678, &GET_INFO, 0);
    assert_eq!(env.board.borrow().pin_locks.len(), 1);
    ctap.handle_cbor(0x1234_5678, &GET_INFO, 0);
    assert_eq!(env.board.borrow().pin_locks.len(), 2);
}

#[test]
fn a_warm_boot_is_inherited_from_the_board() {
    // Both §6.5.5.6 (the lock) and §6.6 (the reset window) key on whether this boot
    // was warm, and only the board can tell.
    let env = Env::new();
    env.board.borrow_mut().boot = crate::BootState {
        warm: true,
        ..Default::default()
    };
    let ctap = env.ctap();
    assert_eq!(
        env.board.borrow().boot_state_reads,
        1,
        "read once, at build"
    );
    assert!(ctap.fido_state.warm_boot);
}

#[test]
fn a_cold_boot_is_the_default() {
    // A build with nothing to remember a warm reset with sees every boot as a first
    // one, which is the safe reading of both clauses.
    let env = Env::new();
    let ctap = env.ctap();
    assert!(!ctap.fido_state.warm_boot);
}

#[test]
fn the_channel_asking_is_recorded_on_every_command() {
    // Cross-message state a second process on its own CTAPHID channel must not be
    // able to ride binds to this.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(0xDEAD_BEEF, &GET_INFO, 0);
    assert_eq!(ctap.fido_state.channel, 0xDEAD_BEEF);
    ctap.handle_cbor(0x0000_0001, &GET_INFO, 0);
    assert_eq!(ctap.fido_state.channel, 0x0000_0001);
}

// --- the trusted display's hand-off ----------------------------------------

#[test]
fn a_panel_pin_change_is_consumed_before_the_next_command_runs() {
    // Set on the display task and consumed here, once: a session credential the
    // old PIN authorized must not survive into the command after the re-key.
    let env = Env::new();
    env.board.borrow_mut().local_pin_change = true;
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &GET_INFO, 0);
    assert!(
        !env.board.borrow().local_pin_change,
        "the one-shot flag was not read"
    );
}

// --- the live-config reload -------------------------------------------------

#[test]
fn a_vendor_command_reapplies_the_configuration_outside_flash() {
    // A vendor CONFIG_WRITE persists the LED block, but its live copy is a set of
    // atomics the flash record does not reach — so the board is told after any
    // 0x41, matching the CCID SET_LED.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &[rsk_fido::consts::CTAP_VENDOR], 0);
    assert_eq!(env.board.borrow().config_written, 1);
}

#[test]
fn an_ordinary_command_does_not_touch_the_configuration() {
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &GET_INFO, 0);
    assert_eq!(env.board.borrow().config_written, 0);
    assert_eq!(env.board.borrow().reboots, 0);
}

#[test]
fn nothing_reboots_without_a_phy_write() {
    // The auto-reboot exists so a changed USB identity takes effect without a
    // replug; it must not fire for any other vendor command.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &[rsk_fido::consts::CTAP_VENDOR], 0);
    assert_eq!(env.board.borrow().reboots, 0);
}

// --- what a hand-off must not leave behind ---------------------------------

#[test]
fn scrub_wipes_the_response_buffer() {
    // It can hold a PIN token after a dispatch.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &GET_INFO, 0);
    assert!(ctap.resp.iter().any(|&b| b != 0));
    ctap.scrub();
    assert!(ctap.resp.iter().all(|&b| b == 0));
}

#[test]
fn a_secure_reboot_drops_the_auth_state_but_not_the_boot_verdict() {
    // The reboot path ends the PIN/UV token, session key and ephemeral scalar on
    // top of the buffer — but a scrub is not a power cycle, so the warm/cold
    // verdict §6.6's reset window keys on has to survive it. Clearing that here
    // would make the boot after a secure reboot look cold and re-open the window.
    let env = Env::new();
    env.board.borrow_mut().boot = crate::BootState {
        warm: true,
        ..Default::default()
    };
    let mut ctap = env.ctap();
    ctap.handle_cbor(0xABCD, &GET_INFO, 0);
    ctap.scrub_secrets();
    assert!(ctap.resp.iter().all(|&b| b == 0));
    assert!(ctap.fido_state.warm_boot);
}

#[test]
fn the_response_buffer_is_the_transport_maximum() {
    // getInfo advertises `maxMsgSize` from the transport constant; a buffer smaller
    // than it would truncate a response the host was told to expect (an ML-DSA-44
    // makeCredential runs ~4 KB).
    assert_eq!(RESP_CAP, rsk_usb::ctaphid::CTAP_MAX_MESSAGE);
}
