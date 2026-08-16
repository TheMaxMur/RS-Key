// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only token projection, excluded from production builds.

use super::*;
use crate::AState;

/// Persistent inputs that do not live in [`FidoState`] but participate in the
/// token abstraction used by the formal trace/refinement checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TokenPersistentView {
    pub pin_set: bool,
    pub persistent_grant: bool,
}

/// The complete persistent half of C visible to the token abstraction.
/// `EF_ALWAYS_UV` is deliberately excluded: it constrains whether a token is
/// required, but is not itself token-lifecycle state. A therefore safely
/// over-approximates no-PIN builds whose runtime `alwaysUv` is enabled.
pub const TOKEN_PERSISTENT_FIDS: [u16; 2] =
    [crate::consts::EF_PIN, crate::consts::EF_PAUTHTOKEN.get()];

impl FidoState {
    /// Implementation-side abstraction α. Phase 4 treats this as an untrusted
    /// hint and compares it with γ over the independently reconstructed B state.
    pub fn abstract_token(&self, persistent: TokenPersistentView) -> AState {
        AState {
            live: self.paut.in_use,
            permission_mc: self.paut.permissions & PERM_MC != 0,
            permission_ga: self.paut.permissions & PERM_GA != 0,
            permission_cm: self.paut.permissions & PERM_CM != 0,
            permission_acfg: self.paut.permissions & PERM_ACFG != 0,
            rp_bound: self.paut.has_rp_id,
            pin_set: persistent.pin_set,
            persistent_grant: persistent.persistent_grant,
        }
    }
}
