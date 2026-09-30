// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, apdu, dev, get_creds_metadata, select, sw, wrong_pin_token_request};

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
    assert!(ctap.fido_state.borrow().warm_boot);
}

#[test]
fn a_warm_boot_carries_the_soft_lock_in() {
    // The other half of the hand-over the first test pins: a lock the board
    // persisted must be RESTORED at build, or a host-requestable warm reset
    // frees the retry budget CTAP 2.1 §6.5.5.6 spends across it. Co-refutation
    // measured this as a gap — nothing drove boot_state() with a live lock and
    // asked whether it carried.
    let env = Env::new();
    env.board.borrow_mut().boot = crate::BootState {
        warm: true,
        lock: rsk_fido::state::PinLock {
            engaged: true,
            mismatches: 3,
        },
    };
    let ctap = env.ctap();
    let carried = ctap.fido_state.borrow().pin_lock();
    assert!(
        carried.engaged,
        "the soft lock did not survive the warm reset"
    );
    assert_eq!(carried.mismatches, 3, "the mismatch count was dropped");
}

#[test]
fn a_warm_boot_carries_a_sub_limit_batch_in() {
    // Not the values — `pin_lock_round_trips_and_boot_leaves_it_alone` (rsk-fido)
    // drives this pair already; erasing a sub-limit batch refunds a §6.5.5.6 budget.
    // Only this case reaches the WIRING: a guard on `boot.lock.engaged` here.
    let batch = rsk_fido::consts::PIN_MISMATCH_LIMIT - 1;
    let env = Env::new();
    env.board.borrow_mut().boot = crate::BootState {
        warm: true,
        lock: rsk_fido::state::PinLock {
            engaged: false,
            mismatches: batch,
        },
    };
    let ctap = env.ctap();
    let carried = ctap.fido_state.borrow().pin_lock();
    assert_eq!(carried.mismatches, batch, "the sub-limit batch was erased");
    assert!(!carried.engaged, "the restore invented a soft lock");
}

#[test]
fn a_cold_boot_is_the_default() {
    // A build with nothing to remember a warm reset with sees every boot as a first
    // one, which is the safe reading of both clauses.
    let env = Env::new();
    let ctap = env.ctap();
    assert!(!ctap.fido_state.borrow().warm_boot);
}

#[test]
fn the_soft_lock_handed_over_is_the_one_the_command_left() {
    // A hand-over taken before the dispatch counts the same and is one command stale:
    // a reboot right after the third wrong PIN would find the second one's batch.
    let env = Env::new();
    let mut ctap = env.ctap();
    rsk_fido::passkeys::store_local_pin(&dev(), &mut env.fs.borrow_mut(), b"123456")
        .expect("the test PIN meets the default policy");
    let wrong = wrong_pin_token_request();
    for _ in 0..rsk_fido::consts::PIN_MISMATCH_LIMIT {
        ctap.handle_cbor(1, &wrong, 0);
    }
    assert_eq!(
        env.board.borrow().pin_locks.last().copied(),
        Some(rsk_fido::state::PinLock {
            engaged: true,
            mismatches: rsk_fido::consts::PIN_MISMATCH_LIMIT,
        }),
        "the lock handed over after the third wrong PIN is not the one it left"
    );
}

#[test]
fn the_channel_asking_is_recorded_on_every_command() {
    // Cross-message state a second process on its own CTAPHID channel must not be
    // able to ride binds to this.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(0xDEAD_BEEF, &GET_INFO, 0);
    assert_eq!(ctap.fido_state.borrow().channel, 0xDEAD_BEEF);
    ctap.handle_cbor(0x0000_0001, &GET_INFO, 0);
    assert_eq!(ctap.fido_state.borrow().channel, 0x0000_0001);
}

// --- the trusted display's hand-off ----------------------------------------

#[test]
fn a_panel_pin_change_is_consumed_before_the_next_command_runs() {
    // Set on the display task and consumed here, once: a session credential the
    // old PIN authorized must not survive into the command after the re-key.
    let env = Env::new();
    let mut ctap = env.ctap();
    // A live cm-permission token, as getPinUvAuthTokenUsingPinWithPermissions leaves one.
    {
        let mut state = env.fido_state.borrow_mut();
        state.reset_pin_uv_auth_token(&mut *env.rng.borrow_mut());
        state.begin_using_token(false, 0);
        state.paut.permissions = rsk_fido::state::PERM_CM;
    }
    let metadata = get_creds_metadata(&env.fido_state.borrow().paut.token);

    let before = ctap.handle_cbor(1, &metadata, 0)[0];
    env.board.borrow_mut().local_pin_change = true;
    let after = ctap.handle_cbor(1, &metadata, 0)[0];
    assert_eq!(
        (before, after),
        (
            rsk_fido::CTAP2_OK,
            rsk_fido::CtapError::PinAuthInvalid.as_u8()
        ),
        "the token the old PIN authorized must stop verifying once the panel changed it"
    );
}

// --- the live-config reload -------------------------------------------------

#[test]
fn an_led_write_reapplies_the_configuration_outside_flash() {
    // A vendor CONFIG_WRITE persists the LED block, but its live copy is a set of
    // atomics the flash record does not reach — so the board is told after the
    // write, matching the CCID SET_LED, and after nothing else.
    let env = Env::new();
    let mut ctap = env.ctap();
    ctap.handle_cbor(1, &[rsk_fido::consts::CTAP_VENDOR], 0);
    assert_eq!(
        env.board.borrow().config_written,
        0,
        "a failed 0x41 reloaded"
    );
    let write = crate::tests::vendor_config_write(rsk_fido::consts::CONFIG_TARGET_LED, &[0x11; 32]);
    ctap.handle_cbor(1, &write, 0);
    assert_eq!(env.board.borrow().config_written, 1);
    // A replay writes no flash and is still applied live, as the CCID SET_LED is.
    ctap.handle_cbor(1, &write, 0);
    assert_eq!(env.board.borrow().config_written, 2, "a replayed LED write");
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
    assert!(ctap.fido_state.borrow().warm_boot);
}

/// Past the latch a fused key that did not read leaves FIDO no arm to open or seal
/// under: a CBOR command answers `CTAP1_ERR_OTHER` and a U2F one `6400`, before
/// either reaches the applet.
#[test]
fn past_the_latch_an_unread_key_refuses_before_the_applet() {
    fn unread(_: &mut [u8; 32]) -> bool {
        false
    }
    let env = Env::new();
    let mut ctap = env.ctap_fused(Some(rsk_crypto::FusedKey::latched(unread)));
    let resp = ctap.handle_cbor(0xABCD, &GET_INFO, 0).to_vec();
    assert_eq!(resp, [rsk_fido::CtapError::FUSED_KEY_UNREAD.as_u8()]);
    let res = ctap.handle_msg(&u2f_version(), 0).to_vec();
    assert_eq!(res, rsk_sdk::Sw::FUSED_KEY_UNREAD.to_bytes());
    // The same device before the latch still answers getInfo.
    let mut open = env.ctap_fused(Some(rsk_crypto::FusedKey::open(unread)));
    assert_eq!(open.handle_cbor(0xABCD, &GET_INFO, 0)[0], 0);
}

#[test]
fn a_secure_reboot_drops_the_vendor_dispatchers_chain() {
    // The vendor AID's dispatcher over CTAPHID holds a chain as the CCID one does,
    // and nothing after the reboot's command is there to clear it.
    let env = Env::new();
    let mut ctap = env.ctap();
    let res = ctap.handle_msg(&select(rsk_vendor::VENDOR_AID), 0).to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);
    let res = ctap
        .handle_msg(&apdu(0x10, 0x01, 0x00, 0x00, &[1, 2, 3]), 0)
        .to_vec();
    assert_eq!(sw(&res), rsk_sdk::Sw::OK);
    assert!(ctap.disp.chain_open());
    ctap.scrub_secrets();
    assert!(
        !ctap.disp.chain_open(),
        "the open chain outlived the reboot's wipe"
    );
    assert_eq!(ctap.disp.current(), None);
}

/// The number getInfo puts ON THE WIRE has to be the number the transport
/// enforces. A YubiKey 5.7.4 demonstrates the invariant: it advertises 1536 and
/// its largest accepted CTAPHID payload is exactly 1536, with 1537 killed by an
/// `ERR_INVALID_LEN` frame before any CBOR is parsed. Over-declare it and a
/// conforming platform sends a message that dies in the transport, with no way to
/// have predicted it. The old assertion here compared `RESP_CAP` with the constant
/// it is *defined as*, so it held for any value of the advertised one.
#[test]
fn getinfo_advertises_the_transport_maximum() {
    let env = Env::new();
    let mut ctap = env.ctap();
    let resp = ctap.handle_cbor(0xABCD, &GET_INFO, 0).to_vec();
    assert_eq!(resp[0], 0, "getInfo failed");
    let mut d = minicbor::Decoder::new(&resp[1..]);
    let n = d.map().unwrap().unwrap();
    let mut advertised = None;
    for _ in 0..n {
        let key = d.u8().unwrap();
        if key == 0x05 {
            advertised = Some(d.u64().unwrap());
        } else {
            d.skip().unwrap();
        }
    }
    assert_eq!(
        advertised,
        Some(rsk_usb::ctaphid::CTAP_MAX_MESSAGE as u64),
        "getInfo's maxMsgSize must be the CTAPHID transport ceiling"
    );
    // The response buffer has to hold what that promises (an ML-DSA-44
    // makeCredential runs ~4 KB).
    assert!(RESP_CAP >= advertised.unwrap() as usize);
}

#[test]
fn the_security_trace_reports_the_pad_and_not_a_constant() {
    // §6.1.2 step 6.3's arm of the token-less gate is stated in
    // `formal/TraceSecurity.tla` ONLY because the recording carries the pad's
    // availability per boundary — with a pad, `alwaysUv` upgrades a token-less
    // request instead of refusing it, and the mapper refuses such a boundary
    // rather than guess. But `builtin_uv` is `false` in every event of the
    // committed trace, so neither the replay nor its mutants can tell this
    // accessor from a hard-wired `false`. This is where that is decided.
    let env = Env::new();
    let ctap = env.ctap();
    assert!(
        !ctap.security_trace_builtin_uv(),
        "a button-only build has no way to collect a PIN and must record no pad"
    );
    env.finger.borrow_mut().pad = true;
    assert!(
        ctap.security_trace_builtin_uv(),
        "the recorded field is the backend's answer, not a constant"
    );
}

/// CTAPHID_MSG carries U2F in U2F HID's extended-length framing alone: a YubiKey
/// 5.8.0 answers each of these, measured, as written here, and a malformed length
/// is refused before the instruction is looked at.
#[test]
fn u2f_over_ctaphid_takes_the_extended_encoding_alone() {
    use rsk_sdk::Sw;
    let env = Env::new();
    // The seed the boot lays down, which an AUTHENTICATE's key-handle check reads.
    let seeded =
        rsk_fido::seed::ensure_seed(&dev(), &mut env.fs.borrow_mut(), &mut *env.rng.borrow_mut());
    seeded.expect("a blank store takes a seed");
    let mut ctap = env.ctap();
    let mut auth = vec![0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x81];
    auth.extend_from_slice(&[0u8; 64]);
    auth.push(64);
    auth.extend((0..64).map(|i| i as u8));
    let cells: [(&str, Vec<u8>, Sw); 11] = [
        ("VERSION, bare", vec![0x00, 0x03, 0x00, 0x00], Sw::OK),
        (
            "VERSION, short Le",
            vec![0x00, 0x03, 0x00, 0x00, 0x00],
            Sw::WRONG_LENGTH,
        ),
        (
            "VERSION, 00 Lc 0000",
            vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
            Sw::OK,
        ),
        (
            "VERSION, 00 Lc 0006",
            vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06],
            Sw::WRONG_LENGTH,
        ),
        ("AUTHENTICATE, extended", auth.clone(), Sw::WRONG_DATA),
        (
            "AUTHENTICATE, extended + Le",
            [&auth[..], &[0x00, 0x00]].concat(),
            Sw::WRONG_DATA,
        ),
        (
            "AUTHENTICATE, short Lc",
            [&[0x00, 0x02, 0x07, 0x00, 0x81][..], &auth[7..]].concat(),
            Sw::WRONG_LENGTH,
        ),
        (
            "REGISTER, short Lc",
            [&[0x00, 0x01, 0x00, 0x00, 0x40][..], &[0u8; 64]].concat(),
            Sw::WRONG_LENGTH,
        ),
        (
            "unknown, short Le",
            vec![0x00, 0x05, 0x00, 0x00, 0x00],
            Sw::WRONG_LENGTH,
        ),
        (
            "unknown, bare",
            vec![0x00, 0x05, 0x00, 0x00],
            Sw::INS_NOT_SUPPORTED,
        ),
        (
            "class 80, short Le",
            vec![0x80, 0x03, 0x00, 0x00, 0x00],
            Sw::CLA_NOT_SUPPORTED,
        ),
    ];
    for (name, command, want) in cells {
        let res = ctap.handle_msg(&command, 0).to_vec();
        assert_eq!(sw(&res), want, "{name}");
    }
    let res = ctap.handle_msg(&u2f_version(), 0).to_vec();
    assert_eq!(&res[..res.len() - 2], rsk_fido::consts::U2F_VERSION);
}

#[test]
fn a_select_with_a_byte_past_its_le_is_wrong_length_here_too() {
    // The dispatcher's parser is the CCID one, so its length rule holds on this
    // transport as well, and the refused SELECT selects nothing.
    let env = Env::new();
    let mut ctap = env.ctap();
    let past = [&select(rsk_vendor::VENDOR_AID)[..], &[0x00, 0xAA]].concat();
    assert_eq!(
        ctap.handle_msg(&past, 0),
        rsk_sdk::Sw::WRONG_LENGTH.to_bytes()
    );
    assert!(ctap.disp.current().is_none());
}
