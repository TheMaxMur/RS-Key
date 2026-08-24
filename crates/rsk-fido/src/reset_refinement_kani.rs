// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Phase-6 C→B reset obligations, including the power-cut/boot epoch boundary.
//! Inputs are total symbolic domains; invalid induction states return explicitly.

use super::*;

fn symbolic_persistent() -> ResetPersistentView {
    ResetPersistentView {
        owner_seed: kani::any(),
        owner_locked_seed: kani::any(),
        credential: kani::any(),
        pin: kani::any(),
        always_uv: kani::any(),
        backup_sealed: kani::any(),
    }
}

fn symbolic_snapshot() -> ResetSnapshot {
    ResetSnapshot {
        seen: kani::any(),
        credential: kani::any(),
        pin: kani::any(),
        always_uv: kani::any(),
        owner_seed: kani::any(),
        backup_sealed: kani::any(),
    }
}

fn symbolic_progress(raw: u8) -> ResetProgress {
    match raw % 5 {
        0 => ResetProgress::Idle,
        1 => ResetProgress::Seeds,
        2 => ResetProgress::Secrets,
        3 => ResetProgress::Gates,
        _ => ResetProgress::Reprovision,
    }
}

fn symbolic_volatile() -> ResetVolatileView {
    ResetVolatileView {
        owner_seed: kani::any(),
        token_active: kani::any(),
    }
}

fn symbolic_refinement() -> ResetRefinement {
    ResetRefinement {
        persistent: symbolic_persistent(),
        snapshot: symbolic_snapshot(),
        progress: symbolic_progress(kani::any()),
    }
}

fn apply_symbolic_step(reset: &mut ResetRefinement, volatile: &mut ResetVolatileView, action: u8) {
    match action % 13 {
        0 => {
            reset.begin(volatile);
        }
        1 => {
            reset.delete(EF_KEY_DEV.get());
        }
        2 => {
            reset.delete(EF_KEY_DEV_ENC.get());
        }
        3 => {
            reset.delete(EF_CRED);
        }
        4 => {
            reset.delete(EF_PIN);
        }
        5 => {
            reset.delete(EF_ALWAYS_UV);
        }
        6 => {
            reset.delete(EF_BACKUP_SEALED);
        }
        7 => {
            reset.advance();
        }
        8 => {
            reset.finish();
        }
        9 => {
            reset.abort();
        }
        10 => reset.power_cut_and_boot(volatile),
        11 => {
            reset.delete(0x1083); // an OpenPGP record: outside the FIDO wipe
        }
        _ => {}
    }
}

#[kani::proof]
fn reset_never_weakens_surviving_state_across_reboot() {
    let initial_volatile = symbolic_volatile();
    let initial = ResetRefinement::new(symbolic_persistent());
    kani::assert(
        initial.well_formed(&initial_volatile),
        "ResetNeverWeakensSurvivingState: initialization left the induction domain",
    );

    let mut reset = symbolic_refinement();
    let mut volatile = symbolic_volatile();
    if !reset.well_formed(&volatile) {
        return;
    }
    let action: u8 = kani::any();
    let had_snapshot = reset.snapshot.seen;
    let had_owner = reset.owner_seed_reachable(&volatile);
    apply_symbolic_step(&mut reset, &mut volatile, action);
    kani::assert(
        reset.well_formed(&volatile),
        "ResetNeverWeakensSurvivingState: concrete step left the induction domain",
    );
    kani::cover!(action % 13 == 10 && had_snapshot && had_owner);
}

#[kani::proof]
fn reset_keeps_the_pin_gate() {
    let mut reset = symbolic_refinement();
    let mut volatile = symbolic_volatile();
    if !reset.well_formed(&volatile) {
        return;
    }
    apply_symbolic_step(&mut reset, &mut volatile, kani::any());
    kani::assert(
        reset.reset_keeps_the_pin_gate(&volatile),
        "ResetKeepsThePinGate",
    );
    kani::cover!(
        reset.snapshot.seen
            && reset.snapshot.pin
            && reset.owner_credential_usable(&volatile)
            && reset.persistent.pin
    );
}

#[kani::proof]
fn reset_keeps_the_always_uv_gate() {
    let mut reset = symbolic_refinement();
    let mut volatile = symbolic_volatile();
    if !reset.well_formed(&volatile) {
        return;
    }
    apply_symbolic_step(&mut reset, &mut volatile, kani::any());
    kani::assert(
        reset.reset_keeps_the_always_uv_gate(&volatile),
        "ResetKeepsTheAlwaysUvGate",
    );
    kani::cover!(
        reset.snapshot.seen
            && reset.snapshot.always_uv
            && reset.owner_credential_usable(&volatile)
            && reset.persistent.always_uv
    );
}

#[kani::proof]
fn reset_keeps_the_backup_seal() {
    let mut reset = symbolic_refinement();
    let mut volatile = symbolic_volatile();
    if !reset.well_formed(&volatile) {
        return;
    }
    apply_symbolic_step(&mut reset, &mut volatile, kani::any());
    kani::assert(
        reset.reset_keeps_the_backup_seal(&volatile),
        "ResetKeepsTheBackupSeal",
    );
    kani::cover!(
        reset.snapshot.seen
            && reset.snapshot.owner_seed
            && reset.owner_seed_reachable(&volatile)
            && reset.persistent.backup_sealed
    );
}
