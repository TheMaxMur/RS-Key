// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use crate::authenticated::{Entry, authority::Bound, read_proof::ReadProof};
use rsk_crypto::ct_eq;
use rsk_sdk::error::{Error, Result};

const RECORDS: usize = 4;

#[derive(Clone, Copy)]
pub(super) struct ValueTag {
    entry: Entry,
    bound: Bound,
    tag: [u8; 32],
}

impl ValueTag {
    pub(super) fn binds(&self, bound: Bound) -> bool {
        self.bound.same_context(bound)
    }

    pub(super) fn verify(&self, proof: &ReadProof, entry: Entry, value: &[u8]) -> Result<()> {
        if self.entry != entry
            || entry.length() != Some(value.len())
            || !ct_eq(
                &self.tag,
                &proof.payload_tag(self.bound, entry, &rsk_crypto::sha256(value))?,
            )
        {
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }
}

pub(in crate::authenticated) struct ReadCache {
    mount: Option<(Bound, [u8; 32])>,
    values: [Option<ValueTag>; RECORDS],
    next: usize,
}

impl ReadCache {
    pub(in crate::authenticated) const fn new() -> Self {
        Self {
            mount: None,
            values: [None; RECORDS],
            next: 0,
        }
    }

    pub(in crate::authenticated) fn clear(&mut self) {
        *self = Self::new();
    }

    pub(super) fn mount(&self, bound: Bound) -> Option<[u8; 32]> {
        self.mount
            .as_ref()
            .filter(|(current, _)| current.same_context(bound))
            .map(|(_, tag)| *tag)
    }

    pub(super) fn find(&self, entry: Entry) -> Option<&ValueTag> {
        self.values
            .iter()
            .flatten()
            .find(|value| value.entry == entry)
    }

    pub(super) fn bind(&mut self, proof: &ReadProof, bound: Bound) -> Result<()> {
        self.mount = Some((bound, proof.mount_tag(bound)?));
        Ok(())
    }

    pub(super) fn verify(
        &mut self,
        proof: &ReadProof,
        bound: Bound,
        entry: Entry,
        value: &[u8],
    ) -> Result<()> {
        let cached = self.find(entry).ok_or(Error::MemoryFatal)?;
        cached.verify(proof, entry, value)?;
        if !cached.binds(bound) {
            self.remember(proof, bound, entry, value)?;
        }
        Ok(())
    }

    pub(super) fn remember(
        &mut self,
        proof: &ReadProof,
        bound: Bound,
        entry: Entry,
        value: &[u8],
    ) -> Result<()> {
        let tag = ValueTag {
            entry,
            bound,
            tag: proof.payload_tag(bound, entry, &rsk_crypto::sha256(value))?,
        };
        // Unchanged entries retain their proof; every lookup also requires the live directory entry.
        if let Some(slot) = self.values.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|old| old.entry.fid() == entry.fid())
        }) {
            *slot = Some(tag);
        } else {
            *self.values.get_mut(self.next).ok_or(Error::MemoryFatal)? = Some(tag);
            self.next = (self.next + 1) % RECORDS;
        }
        Ok(())
    }
}
