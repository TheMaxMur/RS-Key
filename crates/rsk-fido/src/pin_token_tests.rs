// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E39: what a **failed** PIN check does to a pinUvAuthToken that is already
//! outstanding. A YubiKey 5.7.4 invalidates it, through every door — `0x05`,
//! `0x09` and changePIN's old-PIN check — while leaving it alone for
//! getKeyAgreement, getPINRetries and the passage of time. Measured ×4 per row,
//! both protocols, with those three as the controls that make the cell mean
//! something (worklog ORACLE-oathfido §E39).

use super::*;
use crate::credmgmt::cred_mgmt;
use crate::state::PERM_CM;
use crate::test_pins::{NEW_PIN, PIN, WRONG_PIN};

/// Mint a `cm` token the way a platform does, and hand back its plaintext.
fn mint_cm_token(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    plat: &Platform,
    pin: &[u8],
) -> [u8; 32] {
    let mut out = [0u8; 256];
    let n = run(
        fs,
        rng,
        state,
        &plat.get_token_perms_req(pin, PERM_CM as u64),
        &mut out,
    )
    .unwrap();
    plat.decrypt_token(&out[..n])
}

/// Spend the token on a real command: credentialManagement/getCredsMetadata,
/// which needs no touch and no user presence — so what it answers is the
/// token's own health and nothing else.
fn spend_token(fs: &mut Fs<RamStorage>, state: &mut FidoState, token: &[u8; 32]) -> CtapResult {
    let mut mac = [0u8; 32];
    let mlen = rsk_crypto::pinproto::authenticate(PinProto::Two, token, &[0x01], &mut mac).unwrap();
    let mut req = std::vec![0xA3, 0x01, 0x01, 0x03, 0x02, 0x04, 0x58, mlen as u8];
    req.extend_from_slice(&mac[..mlen]);
    let mut rng = SeqRng(7);
    let mut presence = crate::AlwaysConfirm;
    let mut out = [0u8; 256];
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut rng,
        state,
        now_ms: 100,
    };
    cred_mgmt(&mut ctx, &req, &mut out)
}

/// getPINRetries — one of the controls: clientPIN traffic on its own must not
/// cost the platform its token.
fn get_pin_retries_req() -> std::vec::Vec<u8> {
    std::vec![0xA2, 0x01, 0x02, 0x02, 0x01]
}

#[test]
fn a_wrong_pin_kills_an_outstanding_token_through_every_door() {
    // Each door is a separate applet run: the card was measured that way, and a
    // shared fixture would let one row's kill be read as the next row's.
    for (label, wrong) in [
        ("0x09 getPinUvAuthTokenUsingPinWithPermissions", 0u8),
        ("0x05 getPinToken", 1),
        ("changePIN with a wrong old PIN", 2),
    ] {
        let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
        let token = mint_cm_token(&mut fs, &mut rng, &mut state, &plat, PIN);
        assert!(
            spend_token(&mut fs, &mut state, &token).is_ok(),
            "{label}: the token must work before the attempt",
        );

        let plat2 = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let req = match wrong {
            0 => plat2.get_token_perms_req(WRONG_PIN, PERM_CM as u64),
            1 => plat2.get_token_req(WRONG_PIN),
            _ => plat2.change_pin_req(WRONG_PIN, NEW_PIN),
        };
        let mut out = [0u8; 256];
        assert_eq!(
            run(&mut fs, &mut rng, &mut state, &req, &mut out),
            Err(CtapError::PinInvalid),
            "{label}: the attempt itself",
        );
        assert_eq!(
            spend_token(&mut fs, &mut state, &token),
            Err(CtapError::PinAuthInvalid),
            "{label}: the token outlived a failed PIN check",
        );
    }
}

#[test]
fn the_controls_leave_the_token_alone() {
    // Without these the cell above says nothing: a token that dies of any
    // clientPIN traffic, or of a timer, would pass it for the wrong reason.
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let token = mint_cm_token(&mut fs, &mut rng, &mut state, &plat, PIN);
    let mut out = [0u8; 256];

    assert!(spend_token(&mut fs, &mut state, &token).is_ok(), "idle");
    key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    assert!(
        spend_token(&mut fs, &mut state, &token).is_ok(),
        "getKeyAgreement",
    );
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &get_pin_retries_req(),
        &mut out,
    )
    .unwrap();
    assert!(
        spend_token(&mut fs, &mut state, &token).is_ok(),
        "getPINRetries",
    );
}

#[test]
fn a_wrong_pin_on_the_pad_kills_it_too() {
    // The fourth door, and the one no YubiKey 5C can answer for: built-in UV
    // goes through the same verify, so it inherits the rule rather than being a
    // second place that has to remember it.
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let token = mint_cm_token(&mut fs, &mut rng, &mut state, &plat, PIN);
    assert!(spend_token(&mut fs, &mut state, &token).is_ok());

    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(WRONG_PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::UvInvalid),
    );
    assert_eq!(
        spend_token(&mut fs, &mut state, &token),
        Err(CtapError::PinAuthInvalid),
    );
}

#[test]
fn the_persistent_token_is_not_swept_along() {
    // `pcmr` is a different credential with a different promise — it lives in
    // flash and survives replugs "until a PIN change or a reset"
    // (docs/protocol.md). A failed attempt is neither, and no YubiKey behaviour
    // exists to copy: the card has no such permission.
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let ppuat = crate::seed::ensure_ppuat(&dev(), &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 256];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(WRONG_PIN, PERM_CM as u64),
            &mut out,
        ),
        Err(CtapError::PinInvalid),
    );
    assert!(spend_token(&mut fs, &mut state, &ppuat).is_ok());
}

#[test]
fn the_surrounding_cells_are_unchanged() {
    // Everything measured next to the token on the card, so a fix aimed at it
    // cannot quietly move one of them: the key-agreement key is regenerated by
    // a wrong PIN, the retry counter drops by one and a correct PIN restores it.
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let before = state.ephemeral_public().unwrap();
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(WRONG_PIN, PERM_CM as u64),
            &mut out,
        ),
        Err(CtapError::PinInvalid),
    );
    assert_ne!(state.ephemeral_public().unwrap(), before, "key agreement");
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 1);

    let plat2 = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let token = mint_cm_token(&mut fs, &mut rng, &mut state, &plat2, PIN);
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    assert!(spend_token(&mut fs, &mut state, &token).is_ok());
}
