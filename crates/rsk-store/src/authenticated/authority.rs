// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{ct_eq, hmac_sha256};
use rsk_sdk::error::{Error, Result};

use super::record::field;
use super::{Entry, FORMAT, Identity, Prepared, RootArm};

const MOUNT_DOMAIN: &[u8; 8] = b"RSKV2RAM";

#[cfg(test)]
std::thread_local! {
    pub(super) static READ_MAC_PROOFS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub identity: Identity,
    pub arm: RootArm,
    pub sequence: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy)]
pub(super) struct Bound {
    snapshot: Snapshot,
    tag: [u8; 32],
}

impl Bound {
    #[cfg(test)]
    pub(super) fn alter_for_test(
        mut self,
        change: impl FnOnce(&mut Snapshot, &mut [u8; 32]),
    ) -> Self {
        change(&mut self.snapshot, &mut self.tag);
        self
    }

    pub(super) fn same_context(self, other: Self) -> bool {
        self.snapshot == other.snapshot && ct_eq(&self.tag, &other.tag)
    }

    fn new(key: &[u8; 32], snapshot: Snapshot) -> Result<Self> {
        Self::new_with(snapshot, |frame| hmac_sha256(key, frame))
    }

    fn new_with(snapshot: Snapshot, tag: impl FnOnce(&[u8]) -> [u8; 32]) -> Result<Self> {
        let frame = Self::frame(snapshot)?;
        Ok(Self {
            snapshot,
            tag: tag(&frame),
        })
    }

    fn frame(snapshot: Snapshot) -> Result<[u8; 68]> {
        let mut frame = [0; 68];
        field(&mut frame, 0, MOUNT_DOMAIN)?;
        field(
            &mut frame,
            8,
            &[
                FORMAT,
                snapshot.identity.partition.code(),
                snapshot.arm.code(),
            ],
        )?;
        field(&mut frame, 12, &snapshot.identity.epoch)?;
        field(&mut frame, 28, &snapshot.sequence.to_le_bytes())?;
        field(&mut frame, 36, &snapshot.digest)?;
        Ok(frame)
    }

    pub(super) fn read_frame(self) -> Result<[u8; 100]> {
        let mut frame = [0; 100];
        field(&mut frame, 0, &Self::frame(self.snapshot)?)?;
        field(&mut frame, 68, &self.tag)?;
        Ok(frame)
    }

    fn verify(self, key: &[u8; 32], snapshot: Snapshot) -> Result<()> {
        self.verify_with(snapshot, |frame| hmac_sha256(key, frame))
    }

    fn verify_with(self, snapshot: Snapshot, tag: impl FnOnce(&[u8]) -> [u8; 32]) -> Result<()> {
        if self.snapshot != snapshot || !ct_eq(&self.tag, &Self::new_with(snapshot, tag)?.tag) {
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Preparation {
    Staged(Entry),
    Located(Prepared),
    Observed(Prepared),
}

#[derive(Clone, Copy)]
pub(super) struct Pending {
    pub prepared: Prepared,
    pub digest: [u8; 32],
}

/// The mounted floor survives errors; only exact trusted transitions can advance it.
#[derive(Clone, Copy)]
pub(super) enum Authority {
    New,
    Stable(Bound),
    Writing {
        base: Bound,
        target: Bound,
        preparation: Preparation,
    },
    Replacing {
        base: Bound,
        target: Bound,
    },
}

impl Authority {
    pub(super) fn established(&self) -> bool {
        !matches!(self, Self::New)
    }

    pub(super) fn verify_read(
        &self,
        key: &[u8; 32],
        identity: Identity,
        arm: RootArm,
    ) -> Result<()> {
        let bound = self.read_bound(identity, arm)?;
        bound.verify(key, bound.snapshot)
    }

    pub(super) fn verify_read_with_mac(
        &self,
        mac: &rsk_crypto::mac::HmacSha256,
        identity: Identity,
        arm: RootArm,
    ) -> Result<()> {
        #[cfg(test)]
        READ_MAC_PROOFS.with(|count| count.set(count.get() + 1));
        let bound = self.read_bound(identity, arm)?;
        bound.verify_with(bound.snapshot, |frame| mac.tag(frame))
    }

    pub(super) fn read_bound(&self, identity: Identity, arm: RootArm) -> Result<Bound> {
        let Self::Stable(bound) = *self else {
            return Err(Error::MemoryFatal);
        };
        if bound.snapshot.identity != identity || bound.snapshot.arm != arm {
            return Err(Error::MemoryFatal);
        }
        Ok(bound)
    }

    pub(super) fn stage_write(
        &mut self,
        key: &[u8; 32],
        entry: Entry,
        digest: [u8; 32],
    ) -> Result<()> {
        let Self::Stable(base) = *self else {
            return Err(Error::MemoryFatal);
        };
        base.verify(key, base.snapshot)?;
        let sequence = base
            .snapshot
            .sequence
            .checked_add(1)
            .ok_or(Error::MemoryFatal)?;
        if entry.generation() != sequence {
            return Err(Error::MemoryFatal);
        }
        let target = Bound::new(
            key,
            Snapshot {
                sequence,
                digest,
                ..base.snapshot
            },
        )?;
        *self = Self::Writing {
            base,
            target,
            preparation: Preparation::Staged(entry),
        };
        Ok(())
    }

    pub(super) fn locate(&mut self, prepared: Prepared) -> Result<()> {
        let Self::Writing { preparation, .. } = self else {
            return Err(Error::MemoryFatal);
        };
        let Preparation::Staged(entry) = *preparation else {
            return Err(Error::MemoryFatal);
        };
        if entry != prepared.entry {
            return Err(Error::MemoryFatal);
        }
        *preparation = Preparation::Located(prepared);
        Ok(())
    }

    pub(super) fn observe_prepare(&mut self) -> Result<()> {
        let Self::Writing { preparation, .. } = self else {
            return Err(Error::MemoryFatal);
        };
        let Preparation::Located(prepared) = *preparation else {
            return Err(Error::MemoryFatal);
        };
        *preparation = Preparation::Observed(prepared);
        Ok(())
    }

    pub(super) fn stage_replace(
        &mut self,
        old: &[u8; 32],
        new: &[u8; 32],
        snapshot: Snapshot,
    ) -> Result<()> {
        let Self::Stable(base) = *self else {
            return Err(Error::MemoryFatal);
        };
        base.verify(old, base.snapshot)?;
        if snapshot.identity != base.snapshot.identity
            || snapshot.sequence
                != base
                    .snapshot
                    .sequence
                    .checked_add(1)
                    .ok_or(Error::MemoryFatal)?
            || !(snapshot.arm == base.snapshot.arm
                || (base.snapshot.arm == RootArm::PreOtp && snapshot.arm == RootArm::Otp))
            || (snapshot.arm == base.snapshot.arm && !ct_eq(old, new))
        {
            return Err(Error::MemoryFatal);
        }
        *self = Self::Replacing {
            base,
            target: Bound::new(new, snapshot)?,
        };
        Ok(())
    }

    pub(super) fn admit(
        &mut self,
        key: &[u8; 32],
        snapshot: Snapshot,
        pending: Option<Pending>,
    ) -> Result<()> {
        match *self {
            Self::New => {
                let base = Bound::new(key, snapshot)?;
                *self = if let Some(pending) = pending {
                    let sequence = snapshot.sequence.checked_add(1).ok_or(Error::MemoryFatal)?;
                    if pending.prepared.entry.generation() != sequence {
                        return Err(Error::MemoryFatal);
                    }
                    Self::Writing {
                        base,
                        target: Bound::new(
                            key,
                            Snapshot {
                                sequence,
                                digest: pending.digest,
                                ..snapshot
                            },
                        )?,
                        preparation: Preparation::Observed(pending.prepared),
                    }
                } else {
                    Self::Stable(base)
                };
            }
            Self::Stable(bound) => {
                bound.verify(key, snapshot)?;
                if pending.is_some() {
                    return Err(Error::MemoryFatal);
                }
            }
            Self::Replacing { base, target } => {
                if pending.is_some() {
                    return Err(Error::MemoryFatal);
                }
                if snapshot == target.snapshot {
                    target.verify(key, snapshot)?;
                    *self = Self::Stable(target);
                } else {
                    base.verify(key, snapshot)?;
                }
            }
            Self::Writing {
                base,
                target,
                preparation,
            } => {
                base.verify(key, base.snapshot)?;
                if snapshot == base.snapshot {
                    match (preparation, pending) {
                        (Preparation::Staged(_) | Preparation::Located(_), None) => {}
                        (
                            Preparation::Located(known) | Preparation::Observed(known),
                            Some(pending),
                        ) if pending.prepared == known
                            && pending.digest == target.snapshot.digest =>
                        {
                            *self = Self::Writing {
                                base,
                                target,
                                preparation: Preparation::Observed(known),
                            };
                        }
                        _ => return Err(Error::MemoryFatal),
                    }
                } else {
                    let abort = Snapshot {
                        digest: base.snapshot.digest,
                        ..target.snapshot
                    };
                    if !matches!(preparation, Preparation::Observed(_))
                        || pending.is_some()
                        || (snapshot != target.snapshot && snapshot != abort)
                    {
                        return Err(Error::MemoryFatal);
                    }
                    *self = Self::Stable(Bound::new(key, snapshot)?);
                }
            }
        }
        Ok(())
    }

    pub(super) fn check_snapshot(&self, key: &[u8; 32], snapshot: Snapshot) -> Result<()> {
        let mut trial = *self;
        trial.admit(key, snapshot, None)
    }

    pub(super) fn finish(&mut self, key: &[u8; 32], snapshot: Snapshot) -> Result<()> {
        let Self::Stable(bound) = *self else {
            return Err(Error::MemoryFatal);
        };
        bound.verify(key, snapshot)
    }

    // Both complete physical banks must have been resolved to this exact base.
    // A checkpoint inside an operation cannot provide that cancellation proof.
    pub(super) fn cancel_unpublished(&mut self, key: &[u8; 32], snapshot: Snapshot) -> Result<()> {
        let base = match *self {
            Self::Stable(bound) => bound,
            Self::Writing {
                base,
                preparation: Preparation::Staged(_) | Preparation::Located(_),
                ..
            }
            | Self::Replacing { base, .. } => base,
            Self::New
            | Self::Writing {
                preparation: Preparation::Observed(_),
                ..
            } => return Err(Error::MemoryFatal),
        };
        base.verify(key, snapshot)?;
        *self = Self::Stable(base);
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Fixed authenticated state-machine fixtures fail on setup errors"
)]
#[path = "authority_tests.rs"]
mod tests;
