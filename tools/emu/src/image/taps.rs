// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The existing tap grammar, timed by the image's clock at controller reads.

use crate::taps::Tap;
use std::collections::VecDeque;
use std::sync::mpsc::Receiver;

enum Phase {
    Gap(u64),
    Hold(u64),
}

pub struct Pad {
    queue: VecDeque<Tap>,
    receiver: Option<Receiver<Tap>>,
    current: Option<(Tap, Phase)>,
}

impl Pad {
    pub fn new(script: Vec<Tap>, receiver: Option<Receiver<Tap>>) -> Self {
        Self {
            queue: script.into(),
            receiver,
            current: None,
        }
    }

    pub fn read(&mut self, now: u64) -> Option<rsk_ui::Point> {
        if matches!(self.current, Some((_, Phase::Hold(end))) if now >= end) {
            self.current = None;
        }
        if self.current.is_none() {
            let tap = self
                .queue
                .pop_front()
                .or_else(|| self.receiver.as_ref()?.try_recv().ok())?;
            let gap = u64::try_from(tap.gap.as_nanos()).unwrap_or(u64::MAX);
            self.current = Some((tap, Phase::Gap(now.saturating_add(gap))));
            return None;
        }
        match self.current.as_mut()? {
            (tap, phase @ Phase::Gap(_)) => {
                if matches!(phase, Phase::Gap(end) if now < *end) {
                    return None;
                }
                let hold = u64::try_from(tap.hold.as_nanos()).unwrap_or(u64::MAX);
                *phase = Phase::Hold(now.saturating_add(hold));
                Some(tap.at)
            }
            (tap, Phase::Hold(_)) => Some(tap.at),
        }
    }

    pub fn reboot(&mut self, now: u64) {
        if let Some((_, Phase::Gap(end) | Phase::Hold(end))) = &mut self.current {
            *end = end.saturating_sub(now);
        }
    }
}

#[cfg(test)]
#[path = "taps_tests.rs"]
mod tests;
