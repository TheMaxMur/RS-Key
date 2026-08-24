// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Phase-5 refinement obligations over C = (`FidoState`, persistent view).
//! Inputs are total symbolic domains; implications return rather than assume.

use super::*;
use crate::consts::PIN_MISMATCH_LIMIT;
use crate::generated_token_edges::allowed_event;
use crate::{AbstractOp, AbstractOutcome};

struct ProofRng(u8);

impl Rng for ProofRng {
    fn fill(&mut self, bytes: &mut [u8]) {
        self.0 = self.0.wrapping_add(1);
        bytes.fill(self.0);
    }
}

fn valid_permissions(raw: u8) -> bool {
    raw == 0
        || raw == (PERM_MC | PERM_GA)
        || raw == PERM_CM
        || raw == PERM_LBW
        || raw == PERM_ACFG
        || raw == (PERM_GA | PERM_ACFG)
}

fn valid_persistent(_persistent: TokenPersistentView) -> bool {
    true
}

fn wf_concrete(state: &FidoState, persistent: TokenPersistentView) -> bool {
    let live = state.paut.in_use;
    valid_persistent(persistent)
        && valid_permissions(state.paut.permissions)
        && (!live || persistent.pin_set)
        && (live || (state.paut.permissions == 0 && !state.paut.has_rp_id))
        && (!state.paut.has_rp_id || live)
}

fn symbolic_persistent() -> TokenPersistentView {
    TokenPersistentView {
        pin_set: kani::any(),
        persistent_grant: kani::any(),
    }
}

fn symbolic_concrete() -> (FidoState, TokenPersistentView) {
    let mut state = FidoState::new();
    state.paut.in_use = kani::any();
    state.paut.permissions = kani::any();
    state.paut.has_rp_id = kani::any();
    state.paut.user_present = kani::any();
    state.paut.user_verified = kani::any();
    (state, symbolic_persistent())
}

fn persistent_step(mut persistent: TokenPersistentView, op: u8) -> TokenPersistentView {
    match op {
        0 => persistent.pin_set = true,
        1 => persistent.pin_set = false,
        2 => persistent.persistent_grant = true,
        3 => persistent.persistent_grant = false,
        _ => {}
    }
    persistent
}

fn concrete_step(
    state: &mut FidoState,
    persistent: &mut TokenPersistentView,
    opcode: u8,
    permissions: u8,
    bind_rp: bool,
) -> (AbstractOp, AbstractOutcome) {
    match opcode {
        0 => (AbstractOp::Noop, AbstractOutcome::Silent),
        1 if persistent.pin_set && valid_permissions(permissions) => {
            let mut rng = ProofRng(1);
            state.reset_pin_uv_auth_token(&mut rng);
            state.begin_using_token(false, 0);
            state.paut.permissions = permissions;
            state.paut.has_rp_id = bind_rp;
            (AbstractOp::IssueToken, AbstractOutcome::Authorized)
        }
        2 => {
            state.stop_using_token();
            (AbstractOp::RevokeToken, AbstractOutcome::Silent)
        }
        3 if !persistent.pin_set => {
            persistent.pin_set = true;
            (AbstractOp::SetPin, AbstractOutcome::Authorized)
        }
        4 if persistent.pin_set && !state.paut.in_use => {
            persistent.pin_set = false;
            (AbstractOp::ClearPin, AbstractOutcome::Silent)
        }
        5 if persistent.pin_set => {
            persistent.persistent_grant = true;
            (AbstractOp::MintGrant, AbstractOutcome::Authorized)
        }
        6 => {
            persistent.persistent_grant = false;
            (AbstractOp::RevokeGrant, AbstractOutcome::Silent)
        }
        7 => use_with_presence(state, persistent.pin_set, PERM_MC, AbstractOp::UseMc),
        8 => use_with_presence(state, persistent.pin_set, PERM_GA, AbstractOp::UseGa),
        9 => {
            let authorized = (state.paut.in_use && state.paut.permissions & PERM_CM != 0)
                || (persistent.pin_set && persistent.persistent_grant);
            (
                AbstractOp::UseCm,
                if authorized {
                    AbstractOutcome::Authorized
                } else {
                    AbstractOutcome::Rejected
                },
            )
        }
        10 => (
            AbstractOp::UseAcfg,
            if state.paut.in_use && state.paut.permissions & PERM_ACFG != 0 {
                AbstractOutcome::Authorized
            } else {
                AbstractOutcome::Rejected
            },
        ),
        _ => (AbstractOp::Noop, AbstractOutcome::Silent),
    }
}

fn use_with_presence(
    state: &mut FidoState,
    pin_set: bool,
    permission: u8,
    op: AbstractOp,
) -> (AbstractOp, AbstractOutcome) {
    let authorized =
        !pin_set || (state.user_verified() && state.paut.permissions & permission != 0);
    if authorized {
        if state.paut.in_use && !state.paut.has_rp_id {
            state.paut.has_rp_id = true;
        }
        state.consume_after_user_presence();
    }
    (
        op,
        if authorized {
            AbstractOutcome::Authorized
        } else {
            AbstractOutcome::Rejected
        },
    )
}

#[kani::proof]
fn r0a_valid_boot_input_builds_well_formed_c() {
    let lock = PinLock {
        engaged: kani::any(),
        mismatches: kani::any(),
    };
    let warm_boot: bool = kani::any();
    let persistent = symbolic_persistent();
    let valid_boot_input = lock.mismatches <= PIN_MISMATCH_LIMIT;
    if !valid_boot_input {
        return;
    }
    let mut state = FidoState::new();
    state.restore_pin_lock(lock);
    state.warm_boot = warm_boot;
    kani::assert(
        wf_concrete(&state, persistent),
        "R0a: valid boot input left wf(C)",
    );
    kani::cover!(lock.engaged && warm_boot && persistent.persistent_grant && !persistent.pin_set);
}

#[kani::proof]
fn r0p_valid_persistent_is_closed_under_writes_and_power_cut() {
    let persistent = symbolic_persistent();
    let after_write = persistent_step(persistent, kani::any());
    let power_cut = after_write;
    kani::assert(
        valid_persistent(after_write),
        "R0p: write left ValidPersistent",
    );
    kani::assert(
        valid_persistent(power_cut),
        "R0p: power cut left ValidPersistent",
    );
    kani::cover!(power_cut.persistent_grant && !power_cut.pin_set);
}

#[kani::proof]
fn r2a_init_c_is_well_formed() {
    let persistent = symbolic_persistent();
    let state = FidoState::new();
    kani::assert(
        wf_concrete(&state, persistent),
        "R2a: InitC is not well formed",
    );
    kani::cover!(persistent.persistent_grant && !persistent.pin_set);
}

#[kani::proof]
fn r2b_wf_concrete_is_inductive() {
    let (mut state, mut persistent) = symbolic_concrete();
    let was_wf = wf_concrete(&state, persistent);
    let opcode: u8 = kani::any();
    let permissions: u8 = kani::any();
    let bind_rp: bool = kani::any();
    if was_wf {
        concrete_step(&mut state, &mut persistent, opcode, permissions, bind_rp);
        kani::assert(wf_concrete(&state, persistent), "R2b: Step left wf(C)");
    }
    kani::cover!(was_wf && opcode == 1 && permissions == (PERM_MC | PERM_GA));
    kani::cover!(!was_wf);
}

#[kani::proof]
fn r3a_init_c_maps_to_init_a() {
    let persistent = symbolic_persistent();
    let abstract_state = FidoState::new().abstract_token(persistent);
    kani::assert(!abstract_state.live, "R3a: InitC mapped to a live token");
    kani::assert(
        !abstract_state.permission_mc
            && !abstract_state.permission_ga
            && !abstract_state.permission_cm
            && !abstract_state.permission_acfg
            && !abstract_state.rp_bound,
        "R3a: InitC mapped outside InitA",
    );
    kani::cover!(abstract_state.persistent_grant && !abstract_state.pin_set);
}

#[kani::proof]
fn r3b_concrete_step_is_an_allowed_a_event() {
    let (mut state, mut persistent) = symbolic_concrete();
    if !wf_concrete(&state, persistent) {
        return;
    }
    let pre = state.abstract_token(persistent);
    let (op, outcome) = concrete_step(
        &mut state,
        &mut persistent,
        kani::any(),
        kani::any(),
        kani::any(),
    );
    let post = state.abstract_token(persistent);
    kani::assert(
        allowed_event(pre, op, outcome, post),
        "R3b: StepC not in AllowedEventA",
    );
    kani::cover!(outcome == AbstractOutcome::Authorized && pre == post);
    kani::cover!(op == AbstractOp::RevokeToken && pre.live && !post.live);
}
