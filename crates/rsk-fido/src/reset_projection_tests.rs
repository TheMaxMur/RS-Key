// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn reset_clauses_do_not_protect_facts_absent_from_the_snapshot() {
    let snapshot = ResetSnapshot {
        seen: true,
        credential: true,
        pin: true,
        always_uv: true,
        owner_seed: true,
        backup_sealed: true,
    };
    for (snapshot, expected) in [
        (snapshot, (false, false, false)),
        (ResetSnapshot::default(), (true, true, true)),
        (
            ResetSnapshot {
                credential: false,
                ..snapshot
            },
            (true, true, false),
        ),
        (
            ResetSnapshot {
                pin: false,
                ..snapshot
            },
            (true, false, false),
        ),
        (
            ResetSnapshot {
                always_uv: false,
                ..snapshot
            },
            (false, true, false),
        ),
        (
            ResetSnapshot {
                owner_seed: false,
                ..snapshot
            },
            (false, false, true),
        ),
        (
            ResetSnapshot {
                backup_sealed: false,
                ..snapshot
            },
            (false, false, true),
        ),
    ] {
        let reset = ResetRefinement {
            persistent: ResetPersistentView {
                pin: false,
                always_uv: false,
                backup_sealed: false,
                ..protected()
            },
            snapshot,
            progress: ResetProgress::Idle,
        };
        let volatile = ResetVolatileView::default();
        assert_eq!(
            (
                reset.reset_keeps_the_pin_gate(&volatile),
                reset.reset_keeps_the_always_uv_gate(&volatile),
                reset.reset_keeps_the_backup_seal(&volatile),
            ),
            expected,
            "each reset clause applies only to its protected pre-state"
        );
    }
}

#[test]
fn volatile_projection_reads_seed_and_token_presence_before_retirement() {
    for owner_seed in [false, true] {
        for token_active in [false, true] {
            let mut state = FidoState::new();
            if owner_seed {
                state.keydev_dec = Some(rsk_secret::Secret::new([0x5a; 32]));
            }
            state.paut.in_use = token_active;
            assert_eq!(
                ResetVolatileView::from_state(&state),
                ResetVolatileView {
                    owner_seed,
                    token_active,
                },
                "the reset projection must retain both volatile presence facts"
            );
            state.reset();
            assert_eq!(
                ResetVolatileView::from_state(&state),
                ResetVolatileView::default()
            );
        }
    }
}
