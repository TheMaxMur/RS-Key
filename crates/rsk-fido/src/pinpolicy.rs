// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! EF_MINPINLEN keeps its legacy header and RP hashes; bit 1 enables complexity.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use crate::consts::{EF_MINPINLEN, MIN_PIN_LENGTH, PIN_COMPLEXITY_POLICY};
use rsk_fs::{Fs, Storage};

pub(crate) const FORCE_CHANGE: u8 = 1;
pub(crate) const COMPLEXITY: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    pub min: u8,
    pub force: bool,
    pub complexity: bool,
}

impl Policy {
    pub fn decode(record: &[u8]) -> Self {
        Self {
            min: record.first().copied().unwrap_or(MIN_PIN_LENGTH),
            force: record.get(1).is_some_and(|flags| flags & FORCE_CHANGE != 0),
            complexity: PIN_COMPLEXITY_POLICY
                || record.get(1).is_some_and(|flags| flags & COMPLEXITY != 0),
        }
    }

    pub fn flags(self) -> u8 {
        (if self.force { FORCE_CHANGE } else { 0 }) | (if self.complexity { COMPLEXITY } else { 0 })
    }

    pub fn read<S: Storage>(fs: &mut Fs<S>) -> rsk_sdk::error::Result<Self> {
        let mut head = [0u8; 2];
        let n = fs
            .try_read(EF_MINPINLEN, &mut head)?
            .unwrap_or(0)
            .min(head.len());
        Ok(Self::decode(head.get(..n).unwrap_or(&[])))
    }
}
