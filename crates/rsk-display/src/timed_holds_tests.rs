// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Opening,
    First,
    Second,
    Cancel,
}

pub struct TimedHolds {
    phase: Phase,
    deadline: Option<Instant>,
    on: rsk_ui::Point,
    cancel: Option<rsk_ui::Point>,
    pub completed: u8,
}

impl TimedHolds {
    pub fn new(on: rsk_ui::Point, cancel: rsk_ui::Point) -> Self {
        Self {
            phase: Phase::Opening,
            deadline: None,
            on,
            cancel: Some(cancel),
            completed: 0,
        }
    }
}

impl TouchPad for TimedHolds {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        match self.phase {
            Phase::Opening => {
                self.phase = Phase::First;
                None
            }
            Phase::First | Phase::Second => {
                let now = Instant::now();
                // Poll counts stretch with rendering; release at the real deadline.
                let deadline = self
                    .deadline
                    .get_or_insert(now + Duration::from_millis(HOLD_MS * 3 / 4));
                if now < *deadline {
                    return Some(self.on);
                }
                self.deadline = None;
                self.completed += 1;
                self.phase = if self.phase == Phase::First {
                    Phase::Second
                } else {
                    Phase::Cancel
                };
                None
            }
            Phase::Cancel => self.cancel.take(),
        }
    }
}
