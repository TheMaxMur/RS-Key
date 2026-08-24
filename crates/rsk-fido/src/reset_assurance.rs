// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only concrete reset projection, excluded from production builds.
//!
//! The projection keeps identity separate from mere presence: a seed regenerated
//! after reboot is live, but it is not the owner's seed that entered the reset.
//! That distinction is the cross-epoch seam the phase-5 token pilot omitted.

use crate::FidoState;
use crate::consts::{EF_ALWAYS_UV, EF_BACKUP_SEALED, EF_CRED, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_PIN};
use crate::reset::{ResetPhase, reset_phase};

/// The persistent facts from C that the reset property observes. Credential is
/// raw-record presence; it is usable only while the owner's seed is reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ResetPersistentView {
    pub owner_seed: bool,
    pub owner_locked_seed: bool,
    pub credential: bool,
    pub pin: bool,
    pub always_uv: bool,
    pub backup_sealed: bool,
}

/// The relational pre-state captured after volatile state has been retired and
/// before the first persistent delete, matching `ResetConfirmed` in TLA+.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ResetSnapshot {
    pub seen: bool,
    pub credential: bool,
    pub pin: bool,
    pub always_uv: bool,
    pub owner_seed: bool,
    pub backup_sealed: bool,
}

/// The only volatile facts the reset property observes. Keeping the projection
/// this small avoids asking the model checker to unwind unrelated crypto buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ResetVolatileView {
    pub owner_seed: bool,
    pub token_active: bool,
}

impl ResetVolatileView {
    pub fn from_state(state: &FidoState) -> Self {
        Self {
            owner_seed: state.keydev_dec.is_some(),
            token_active: state.paut.in_use,
        }
    }

    fn retire(&mut self) {
        self.owner_seed = false;
        self.token_active = false;
    }
}

/// Where the concrete wipe is between two security-visible operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetProgress {
    Idle,
    Seeds,
    Secrets,
    Gates,
    Reprovision,
}

/// C's reset-relevant persistent state plus the proof-only pre-state snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetRefinement {
    pub persistent: ResetPersistentView,
    pub snapshot: ResetSnapshot,
    pub progress: ResetProgress,
}

impl ResetRefinement {
    pub const fn new(persistent: ResetPersistentView) -> Self {
        Self {
            persistent,
            snapshot: ResetSnapshot {
                seen: false,
                credential: false,
                pin: false,
                always_uv: false,
                owner_seed: false,
                backup_sealed: false,
            },
            progress: ResetProgress::Idle,
        }
    }

    /// The owner's pre-reset seed is reachable from flash or the unlocked RAM
    /// copy. A fresh seed provisioned by the next boot is deliberately absent.
    pub fn owner_seed_reachable(&self, volatile: &ResetVolatileView) -> bool {
        self.persistent.owner_seed || self.persistent.owner_locked_seed || volatile.owner_seed
    }

    pub fn owner_credential_usable(&self, volatile: &ResetVolatileView) -> bool {
        self.persistent.credential && self.owner_seed_reachable(volatile)
    }

    /// The implementation-side abstraction α from concrete reset state to the
    /// three relational clauses in `RSKeySecurityState`.
    pub fn reset_keeps_the_pin_gate(&self, volatile: &ResetVolatileView) -> bool {
        !self.snapshot.seen
            || !self.snapshot.credential
            || !self.snapshot.pin
            || !self.owner_credential_usable(volatile)
            || self.persistent.pin
    }

    pub fn reset_keeps_the_always_uv_gate(&self, volatile: &ResetVolatileView) -> bool {
        !self.snapshot.seen
            || !self.snapshot.credential
            || !self.snapshot.always_uv
            || !self.owner_credential_usable(volatile)
            || self.persistent.always_uv
    }

    pub fn reset_keeps_the_backup_seal(&self, volatile: &ResetVolatileView) -> bool {
        !self.snapshot.seen
            || !self.snapshot.owner_seed
            || !self.snapshot.backup_sealed
            || !self.owner_seed_reachable(volatile)
            || self.persistent.backup_sealed
    }

    pub fn reset_never_weakens_surviving_state(&self, volatile: &ResetVolatileView) -> bool {
        self.reset_keeps_the_pin_gate(volatile)
            && self.reset_keeps_the_always_uv_gate(volatile)
            && self.reset_keeps_the_backup_seal(volatile)
    }

    /// Project the real reset order: retire all volatile state first, then take
    /// the ghost snapshot against what can still survive the flash work.
    pub fn begin(&mut self, volatile: &mut ResetVolatileView) -> bool {
        if self.progress != ResetProgress::Idle {
            return false;
        }
        volatile.retire();
        let owner_seed = self.owner_seed_reachable(volatile);
        self.snapshot = ResetSnapshot {
            seen: true,
            credential: self.persistent.credential && owner_seed,
            pin: self.persistent.pin,
            always_uv: self.persistent.always_uv,
            owner_seed,
            backup_sealed: self.persistent.backup_sealed,
        };
        self.progress = ResetProgress::Seeds;
        true
    }

    /// Apply one `force_delete` at the phase the production classifier assigns.
    pub fn delete(&mut self, fid: u16) -> bool {
        let phase = match self.progress {
            ResetProgress::Seeds => ResetPhase::Seed,
            ResetProgress::Secrets => ResetPhase::Secret,
            ResetProgress::Gates => ResetPhase::Gate,
            ResetProgress::Idle | ResetProgress::Reprovision => return false,
        };
        if reset_phase(fid) != Some(phase) {
            return false;
        }
        match fid {
            f if f == EF_KEY_DEV.get() => self.persistent.owner_seed = false,
            f if f == EF_KEY_DEV_ENC.get() => self.persistent.owner_locked_seed = false,
            EF_CRED => self.persistent.credential = false,
            EF_PIN => self.persistent.pin = false,
            EF_ALWAYS_UV => self.persistent.always_uv = false,
            EF_BACKUP_SEALED => self.persistent.backup_sealed = false,
            _ => {}
        }
        true
    }

    /// Cross one completed enumeration boundary. The guards are the concrete
    /// meaning of “the phase is empty”, not an assumed scheduling order.
    pub fn advance(&mut self) -> bool {
        match self.progress {
            ResetProgress::Seeds
                if !self.persistent.owner_seed && !self.persistent.owner_locked_seed =>
            {
                self.progress = ResetProgress::Secrets;
                true
            }
            ResetProgress::Secrets if !self.persistent.credential => {
                self.progress = ResetProgress::Gates;
                true
            }
            ResetProgress::Gates
                if !self.persistent.pin
                    && !self.persistent.always_uv
                    && !self.persistent.backup_sealed =>
            {
                self.progress = ResetProgress::Reprovision;
                true
            }
            _ => false,
        }
    }

    /// Complete `ensure_seed`. The new seed belongs to the next identity epoch,
    /// so it does not resurrect either `owner_seed` fact in this projection.
    pub fn finish(&mut self) -> bool {
        if self.progress != ResetProgress::Reprovision {
            return false;
        }
        self.progress = ResetProgress::Idle;
        self.snapshot = ResetSnapshot::default();
        true
    }

    /// A storage error returns to the command loop in the same boot epoch.
    pub fn abort(&mut self) -> bool {
        if self.progress == ResetProgress::Idle {
            return false;
        }
        self.progress = ResetProgress::Idle;
        true
    }

    /// A real power cut clears C's volatile half and boots a new epoch. Boot-time
    /// `ensure_seed` may create a fresh seed, but never the owner's old identity.
    pub fn power_cut_and_boot(&mut self, volatile: &mut ResetVolatileView) {
        volatile.retire();
        self.progress = ResetProgress::Idle;
    }

    /// The induction domain shared by Kani's initialization and step obligations.
    pub fn well_formed(&self, volatile: &ResetVolatileView) -> bool {
        let volatile_retired = matches!(self.progress, ResetProgress::Idle)
            || (!volatile.owner_seed && !volatile.token_active);
        let phase_order = match self.progress {
            ResetProgress::Idle | ResetProgress::Seeds => true,
            ResetProgress::Secrets => {
                !self.persistent.owner_seed && !self.persistent.owner_locked_seed
            }
            ResetProgress::Gates => {
                !self.persistent.owner_seed
                    && !self.persistent.owner_locked_seed
                    && !self.persistent.credential
            }
            ResetProgress::Reprovision => {
                !self.persistent.owner_seed
                    && !self.persistent.owner_locked_seed
                    && !self.persistent.credential
                    && !self.persistent.pin
                    && !self.persistent.always_uv
                    && !self.persistent.backup_sealed
            }
        };
        volatile_retired && phase_order && self.reset_never_weakens_surviving_state(volatile)
    }
}

#[cfg(test)]
#[path = "reset_assurance_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "reset_refinement_kani.rs"]
mod proofs;
