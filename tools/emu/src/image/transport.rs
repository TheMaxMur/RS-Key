// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Socket transaction timing at USB completion, before host scheduling delays.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use rsk_usb::ccid::{CCID_DATA_BLOCK_RET, HEADER, STATUS_TIMEEXT};
use rsk_usb::ctaphid::{CTAPHID_CBOR, CTAPHID_KEEPALIVE};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    Hid([u8; 4]),
    Ccid(u8),
}

#[derive(Default)]
pub enum Trace {
    #[default]
    Idle,
    Armed,
    Running(Timing),
    Complete(Timing),
}

pub struct Timing {
    owner: Owner,
    start: u64,
    last: u64,
    end: u64,
    keepalives: u64,
    max_gap: u64,
}

impl Trace {
    pub fn running(&self) -> bool {
        matches!(self, Self::Running(_))
    }

    pub fn arm(&mut self) {
        *self = Self::Armed;
    }

    fn start(&mut self, owner: Owner, now: u64) {
        if matches!(self, Self::Armed) {
            *self = Self::Running(Timing {
                owner,
                start: now,
                last: now,
                end: now,
                keepalives: 0,
                max_gap: 0,
            });
        }
    }

    fn answer(&mut self, owner: Owner, keepalive: bool, now: u64) {
        let Self::Running(timing) = self else { return };
        if timing.owner != owner {
            return;
        }
        timing.max_gap = timing.max_gap.max(now.saturating_sub(timing.last));
        timing.last = now;
        timing.end = now;
        if keepalive {
            timing.keepalives += 1;
        } else if let Self::Running(timing) = std::mem::take(self) {
            *self = Self::Complete(timing);
        }
    }

    pub fn hid_out(&mut self, report: &[u8], now: u64) {
        if let Some(&[a, b, c, d, CTAPHID_CBOR]) = report.first_chunk::<5>() {
            self.start(Owner::Hid([a, b, c, d]), now);
        }
    }

    pub fn hid_in(&mut self, report: &[u8], now: u64) {
        if let Some(&[a, b, c, d, command]) = report.first_chunk::<5>()
            && command & 0x80 != 0
        {
            self.answer(Owner::Hid([a, b, c, d]), command == CTAPHID_KEEPALIVE, now);
        }
    }

    pub fn ccid_out(&mut self, message: &[u8], now: u64) {
        if let Some(&[_, _, _, _, _, 0, sequence, _, _, _]) = message.first_chunk::<HEADER>() {
            self.start(Owner::Ccid(sequence), now);
        }
    }

    pub fn ccid_in(&mut self, message: &[u8], now: u64) {
        if let Some(&[kind, _, _, _, _, 0, sequence, status, _, _]) =
            message.first_chunk::<HEADER>()
            && kind & 0x80 != 0
        {
            self.answer(
                Owner::Ccid(sequence),
                kind == CCID_DATA_BLOCK_RET && status & 0xC0 == STATUS_TIMEEXT,
                now,
            );
        }
    }

    pub fn report(&self) -> Result<String, String> {
        let Self::Complete(timing) = self else {
            return Err("no completed transport measurement".into());
        };
        Ok(format!(
            "elapsed_ns={} keepalives={} max_gap_ns={}",
            timing.end.saturating_sub(timing.start),
            timing.keepalives,
            timing.max_gap,
        ))
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
