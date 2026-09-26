// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

/// A `UserPresence` returning a fixed outcome.
struct Fixed(Presence);
impl crate::UserPresence for Fixed {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> Presence {
        self.0
    }
}

fn run(presence: &mut dyn crate::UserPresence) -> CtapResult {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let mut state = FidoState::new();
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut ctx = Ctx {
        presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    selection(&mut ctx)
}

#[test]
fn selection_confirmed_returns_ok() {
    assert_eq!(run(&mut crate::AlwaysConfirm), Ok(0));
}

#[test]
fn selection_timeout_maps_user_action_timeout() {
    assert_eq!(
        run(&mut Fixed(Presence::Timeout)),
        Err(CtapError::UserActionTimeout)
    );
}

#[test]
fn selection_declined_maps_operation_denied() {
    assert_eq!(
        run(&mut Fixed(Presence::Declined)),
        Err(CtapError::OperationDenied)
    );
}

#[test]
fn selection_cancelled_maps_keepalive_cancel() {
    // A CTAPHID_CANCEL during the touch wait → CTAP2_ERR_KEEPALIVE_CANCEL.
    assert_eq!(
        run(&mut Fixed(Presence::Cancelled)),
        Err(CtapError::KeepAliveCancel)
    );
}

// authenticatorSelection's touch is not the makeCredential / getAssertion
// user-presence test CTAP 2.1 §6.5.5.7 spends a token on: a live one survives it.
#[test]
fn a_selection_touch_leaves_a_live_token_unspent() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let mut state = FidoState::new();
    let armed = crate::state::PERM_MC | crate::state::PERM_GA | crate::state::PERM_ACFG;
    state.paut.permissions = armed;
    state.begin_using_token(false, 0);
    let mut presence = Fixed(Presence::Confirmed);
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        },
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(selection(&mut ctx), Ok(0));
    assert_eq!(state.paut.permissions, armed);
    assert!(state.user_verified());
}
