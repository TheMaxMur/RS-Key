// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{CM_ENUMERATE_RPS_NEXT, PIN_MISMATCH_LIMIT};
use crate::credmgmt::cred_mgmt;
use crate::error::{CtapError, CtapResult};
use crate::{AlwaysConfirm, Ctx};
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

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

const LOCKED: PinLock = PinLock {
    engaged: true,
    mismatches: PIN_MISMATCH_LIMIT,
};

#[test]
fn pin_lock_round_trips_and_boot_leaves_it_alone() {
    // The firmware's boot order: `new()`, then `restore_pin_lock` from the
    // watchdog-scratch canary (firmware/src/handler.rs), then the clientPIN
    // pre-generation. A fresh state starts clear, so the canary is the only source.
    let mut st = FidoState::new();
    assert_eq!(st.pin_lock(), PinLock::default());

    st.restore_pin_lock(LOCKED);
    assert_eq!(st.pin_lock(), LOCKED);

    // Everything the rest of boot runs must leave the restored pair untouched —
    // both halves, or a host stops at two mismatches and reboots to start over.
    let mut rng = SeqRng(1);
    st.ensure_initialized(&mut rng);
    st.regenerate(&mut rng);
    st.reset_pin_uv_auth_token(&mut rng);
    assert_eq!(st.pin_lock(), LOCKED);

    // A partial restore is exactly what the pair exists to prevent.
    st.restore_pin_lock(PinLock {
        engaged: false,
        mismatches: 2,
    });
    assert_eq!(st.pin_lock().mismatches, 2);
    assert!(!st.pin_lock().engaged);
}

#[test]
fn warm_boot_survives_reset_but_session_state_does_not() {
    let mut st = FidoState::new();
    // Power-cycle facts.
    st.warm_boot = true;
    st.audit_boot_logged = true;
    st.devk = Some([0x7C; 32]);
    // Session state.
    st.paut.permissions = PERM_ACFG;
    st.begin_using_token(true, 0);
    st.mse_active = true;
    st.mse_key = [0x11; 32];
    st.cm.rp_total = 4;
    st.gna.active = true;
    st.restore_pin_lock(LOCKED);

    st.reset();

    assert!(
        st.warm_boot,
        "the reset window keys on how the cycle started"
    );
    assert!(st.audit_boot_logged);
    assert_eq!(st.devk, Some([0x7C; 32]));
    assert!(!st.paut.in_use);
    assert_eq!(st.paut.permissions, 0);
    assert!(!st.user_verified());
    assert!(!st.mse_active);
    assert_eq!(st.mse_key, [0; 32]);
    assert_eq!(st.cm.rp_total, 0);
    assert!(!st.gna.active);
    // An authenticatorReset wipes EF_PIN, so the soft lock has nothing left to hold.
    assert_eq!(st.pin_lock(), PinLock::default());
}

/// A `credentialManagement` state mid-walk: a *Begin* counted two RPs / two
/// credentials and handed the first of each back.
fn mid_walk() -> FidoState {
    let mut st = FidoState::new();
    st.paut.token = [0x99; 32];
    st.paut.permissions = PERM_CM;
    st.begin_using_token(false, 0);
    st.cm.rp_total = 2;
    st.cm.rp_counter = 2;
    st.cm.cred_total = 2;
    st.cm.cred_counter = 2;
    st.cm.rp_id_hash = [0x5A; 32];
    st
}

/// Drive a bare `{1: getNextRP}` — a *Next* carries no pinUvAuthParam of its own,
/// so the cursor is the whole authorization. The store is empty, which separates
/// the two outcomes: `NotAllowed` means the cursor refused, `NoCredentials` means
/// it let the walk run.
fn next_rp(state: &mut FidoState) -> CtapResult {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(3);
    let mut presence = AlwaysConfirm;
    let mut out = [0u8; 256];
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state,
        now_ms: 0,
    };
    cred_mgmt(
        &mut ctx,
        &[0xA1, 0x01, CM_ENUMERATE_RPS_NEXT as u8],
        &mut out,
    )
}

#[test]
fn a_live_cursor_still_walks() {
    // The baseline the two invalidation tests are measured against: an untouched
    // mid-walk cursor is not refused, it runs (and finds nothing here).
    assert_eq!(next_rp(&mut mid_walk()), Err(CtapError::NoCredentials));
}

#[test]
fn stop_using_token_strands_the_credmgmt_walk() {
    let mut st = mid_walk();
    st.stop_using_token();
    assert!(st.cm.rp_counter > st.cm.rp_total);
    assert!(st.cm.cred_counter > st.cm.cred_total);
    assert_eq!(st.cm.rp_id_hash, [0; 32]);
    assert_eq!(next_rp(&mut st), Err(CtapError::NotAllowed));
}

#[test]
fn reset_pin_uv_auth_token_strands_the_credmgmt_walk() {
    let mut st = mid_walk();
    st.reset_pin_uv_auth_token(&mut SeqRng(5));
    assert!(st.cm.rp_counter > st.cm.rp_total);
    assert!(st.cm.cred_counter > st.cm.cred_total);
    assert_eq!(next_rp(&mut st), Err(CtapError::NotAllowed));
}

#[test]
fn expiring_token_strands_the_credmgmt_walk() {
    // `expire_stale_token` runs before every CBOR command, so a walk left idle past
    // the usage window loses its cursor with the token that granted it.
    let mut st = mid_walk();
    st.expire_stale_token(PUAT_INITIAL_USAGE_LIMIT_MS);
    assert_eq!(next_rp(&mut st), Err(CtapError::NotAllowed));
}
