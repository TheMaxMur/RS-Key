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
    state.keydev_dec = Some([0x5a; 32]);
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
