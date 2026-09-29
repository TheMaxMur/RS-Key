// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn protected() -> ResetPersistentView {
    ResetPersistentView {
        owner_seed: true,
        owner_locked_seed: false,
        credential: true,
        pin: true,
        always_uv: true,
        backup_sealed: true,
    }
}

#[test]
fn reset_projection_stitches_a_torn_epoch_to_the_next_boot() {
    let mut state = FidoState::new();
    state.keydev_dec = Some(rsk_secret::Secret::new([0x5a; 32]));
    state.paut.in_use = true;
    let mut volatile = ResetVolatileView::from_state(&state);
    let mut reset = ResetRefinement::new(protected());
    state.reset();
    assert!(reset.begin(&mut volatile));
    assert!(state.keydev_dec.is_none());
    assert!(!state.paut.in_use);
    assert!(reset.delete(EF_KEY_DEV.get()));
    reset.power_cut_and_boot(&mut volatile);
    assert_eq!(reset.progress, ResetProgress::Idle);
    assert!(reset.well_formed(&volatile));
    assert!(reset.reset_never_weakens_surviving_state(&volatile));
}

#[test]
fn reset_projection_rejects_a_gate_delete_before_the_secrets_phase_empties() {
    let mut volatile = ResetVolatileView::default();
    let mut reset = ResetRefinement::new(protected());
    assert!(reset.begin(&mut volatile));
    assert!(!reset.delete(EF_PIN));
    assert!(!reset.delete(EF_ALWAYS_UV));
    assert!(!reset.delete(EF_BACKUP_SEALED));
}

#[test]
fn reset_property_controls_go_red_on_each_early_gate_mutant() {
    let mut volatile = ResetVolatileView::default();

    let mut pin = ResetRefinement::new(protected());
    assert!(pin.begin(&mut volatile));
    pin.persistent.pin = false;
    assert!(!pin.reset_keeps_the_pin_gate(&volatile));

    let mut always_uv = ResetRefinement::new(protected());
    assert!(always_uv.begin(&mut volatile));
    always_uv.persistent.always_uv = false;
    assert!(!always_uv.reset_keeps_the_always_uv_gate(&volatile));

    let mut backup = ResetRefinement::new(protected());
    assert!(backup.begin(&mut volatile));
    backup.persistent.backup_sealed = false;
    assert!(!backup.reset_keeps_the_backup_seal(&volatile));
}

#[test]
fn reset_projection_finishes_only_after_every_ordered_phase() {
    let mut volatile = ResetVolatileView::default();
    let mut reset = ResetRefinement::new(protected());
    assert!(reset.begin(&mut volatile));
    assert!(reset.delete(EF_KEY_DEV.get()));
    assert!(reset.advance());
    assert!(reset.delete(EF_CRED));
    assert!(reset.advance());
    assert!(reset.delete(EF_PIN));
    assert!(reset.delete(EF_ALWAYS_UV));
    assert!(reset.delete(EF_BACKUP_SEALED));
    assert!(reset.advance());
    assert!(reset.finish());
    assert!(reset.well_formed(&volatile));
}

/// The seed loop is a fixed two-fid `for` with nothing to enumerate, so the wipe
/// enters the SECRET sweep whatever the medium answered — and that sweep's own
/// predicate covers the seed fids, which is what stops it before the gates
/// (0x098B). The projection has to be able to hold that state: while it could not,
/// every obligation about the gate phase over a live seed was discharged
/// vacuously, and merging the two sweeps left all four Kani harnesses green.
#[test]
fn the_secret_sweep_is_where_a_seed_the_medium_kept_stops_the_wipe() {
    let mut volatile = ResetVolatileView::default();
    let mut reset = ResetRefinement::new(protected());
    assert!(reset.begin(&mut volatile));
    // The seed loop could not remove it; the code falls through regardless.
    assert!(reset.advance());
    assert_eq!(reset.progress, ResetProgress::Secrets);
    assert!(reset.persistent.owner_seed);
    assert!(
        reset.well_formed(&volatile),
        "a live seed inside the secret sweep is a state the wipe really reaches"
    );
    // However empty the rest of the range gets, the gate phase must not open.
    assert!(reset.delete(EF_CRED));
    assert!(!reset.advance(), "the gate phase opened over a live seed");
    // The seed is re-yielded HERE, and removing it there is what unblocks.
    assert!(reset.delete(EF_KEY_DEV.get()));
    assert!(reset.advance());
    assert_eq!(reset.progress, ResetProgress::Gates);
}

/// SEC-FIDO-006C stated over the CLASSIFIER, which is the half no test asked.
///
/// The two tests that fall when `EF_BACKUP_SEALED` leaves `is_fido_gate_record`
/// both transcribe that function's match arm, so they answer "did somebody edit
/// the list" — measured: demoting `EF_MINPINLEN`, which `crates/rsk-fido/src/reset.rs:244-250` says
/// out loud is in the phase and in no clause, kills the slice the same way,
/// 3 of 3 runs. And the one test that states the defect behaviourally,
/// `reset_tests.rs::a_seed_the_medium_kept_stops_the_wipe_before_the_gates`, is a
/// COIN FLIP: `RamStorage` is a `HashMap`
/// (`crates/rsk-fs/src/storage.rs:78`) and `for_each_key` iterates it
/// (`crates/rsk-fs/src/storage.rs:105`), so whether the aborted sweep reaches
/// 0xCC02 before it stops on the refused 0xCC00 is a fresh permutation per
/// process — 167 of 400 fixtures lose the marker.
///
/// This asks the property instead. `delete` derives its phase from the
/// production `reset_phase`, so a classifier that moves the marker out of the
/// gate set lets a `Secrets`-phase delete through while the owner seed is still
/// reachable — which is exactly the clause. Deterministic in both directions:
/// green on the shipped tree, red on that mutant, with no map in the path.
#[test]
fn a_backup_seal_swept_with_the_secrets_is_a_reopened_export_window() {
    let mut volatile = ResetVolatileView::default();
    let mut reset = ResetRefinement::new(protected());
    assert!(reset.begin(&mut volatile));
    assert!(reset.advance());
    assert_eq!(reset.progress, ResetProgress::Secrets);
    // The seed the medium would not remove: still reachable, so the clause is
    // about a live secret rather than vacuously true.
    assert!(reset.persistent.owner_seed);
    assert!(reset.owner_seed_reachable(&volatile));
    // Whatever phase the classifier assigns it. On the shipped tree this is a
    // Gate record and the delete is refused here; the assertion below is what
    // says why that refusal matters.
    let swept = reset.delete(EF_BACKUP_SEALED);
    assert!(
        reset.reset_keeps_the_backup_seal(&volatile),
        "the one-time export marker went in the secrets phase over a seed that is \
         still reachable (swept={swept})"
    );
}
