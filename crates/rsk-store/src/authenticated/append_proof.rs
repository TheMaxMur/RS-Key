// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{
    ct_eq,
    hash::{Sha256Prefix, Sha256State},
    hmac_sha256,
};
use rsk_sdk::error::{Error, Result};

/// Only an authenticated scan or an exactly confirmed append can seed this state.
pub(super) struct AppendProof {
    state: Sha256Prefix,
    tail: usize,
    end: u32,
    tag: [u8; 32],
    digest: [u8; 32],
}

#[cfg(test)]
#[path = "append_proof_tests.rs"]
mod tests;

impl AppendProof {
    pub(super) fn new(state: Sha256State, end: u32, key: &[u8; 32]) -> Self {
        let digest = Self::digest(&state, end);
        let tag = hmac_sha256(key, &digest);
        let (state, tail) = state.into_prefix();
        Self {
            state,
            tail,
            end,
            tag,
            digest,
        }
    }

    fn seal(state: &Sha256State, end: u32, key: &[u8; 32]) -> [u8; 32] {
        hmac_sha256(key, &Self::digest(state, end))
    }

    fn digest(state: &Sha256State, end: u32) -> [u8; 32] {
        let mut finished = state.clone();
        finished.update(&end.to_le_bytes());
        finished.finish()
    }

    pub(super) fn raw_digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn tag(&self) -> [u8; 32] {
        self.tag
    }

    pub(super) fn end(&self) -> u32 {
        self.end
    }

    pub(super) fn tail(&self) -> usize {
        self.tail
    }

    pub(super) fn extend(
        self,
        key: &[u8; 32],
        start: u32,
        tail: &[u8],
        parts: &[&[u8]],
    ) -> Result<Self> {
        if start != self.end || tail.len() != self.tail {
            return Err(Error::MemoryFatal);
        }
        let mut state = self.state.resume(tail);
        if !ct_eq(&self.tag, &Self::seal(&state, self.end, key)) {
            return Err(Error::MemoryFatal);
        }
        let mut end = self.end;
        for bytes in parts {
            end = end
                .checked_add(u32::try_from(bytes.len()).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            state.update(bytes);
        }
        Ok(Self::new(state, end, key))
    }
}
