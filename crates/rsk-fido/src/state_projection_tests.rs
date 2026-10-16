// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn token_projection_keeps_each_permission_and_persistent_fact_independent() {
    for (permissions, (mc, ga, cm, acfg)) in [
        (0, (false, false, false, false)),
        (PERM_MC, (true, false, false, false)),
        (PERM_GA, (false, true, false, false)),
        (PERM_CM, (false, false, true, false)),
        (PERM_ACFG, (false, false, false, true)),
        (PERM_BE | PERM_LBW | PERM_PCMR, (false, false, false, false)),
        (u8::MAX, (true, true, true, true)),
    ] {
        for bits in 0..16 {
            let mut state = FidoState::new();
            state.paut.in_use = bits & 1 != 0;
            state.paut.permissions = permissions;
            state.paut.has_rp_id = bits & 2 != 0;
            let persistent = TokenPersistentView {
                pin_set: bits & 4 != 0,
                persistent_grant: bits & 8 != 0,
            };
            assert_eq!(
                state.abstract_token(persistent),
                AState {
                    live: state.paut.in_use,
                    permission_mc: mc,
                    permission_ga: ga,
                    permission_cm: cm,
                    permission_acfg: acfg,
                    rp_bound: state.paut.has_rp_id,
                    pin_set: persistent.pin_set,
                    persistent_grant: persistent.persistent_grant,
                },
                "the token projection must preserve independent permissions and facts"
            );
        }
    }
}
