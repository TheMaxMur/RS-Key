// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Secure bus admission; only hardware observation and accepted EP0 update it.

const LAST_EPOCH: u32 = rsk_usb::usb_abi::OVERFLOW - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Default,
    Configured,
    Suspended { configured: bool },
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    Reset,
    Suspend,
    ConfigurationLoss,
}

/// Matches raw observations to the HAL events that acknowledge their IRQs.
#[derive(Default)]
pub struct BusEvents {
    reset_seen: bool,
    suspended: bool,
    suspend_covered: bool,
}

impl BusEvents {
    pub const fn new() -> Self {
        Self {
            reset_seen: false,
            suspended: false,
            suspend_covered: false,
        }
    }

    pub fn begin(&mut self, reset: bool, suspended: bool) -> Option<Revocation> {
        self.reset_seen &= reset;
        let new_suspend = suspended && !self.suspended;
        self.suspended = suspended;
        if !suspended {
            self.suspend_covered = false;
        }
        if reset && !self.reset_seen {
            self.reset_seen = true;
            Some(Revocation::Reset)
        } else if new_suspend {
            self.suspend_covered = true;
            Some(Revocation::Suspend)
        } else {
            None
        }
    }

    pub fn observe_hal(&mut self, reason: Revocation) -> bool {
        match reason {
            Revocation::Reset => !core::mem::replace(&mut self.reset_seen, false),
            Revocation::Suspend => {
                self.suspended = true;
                !core::mem::replace(&mut self.suspend_covered, false)
            }
            Revocation::ConfigurationLoss => true,
        }
    }

    pub fn finish(&mut self, reset: bool, suspended: bool) {
        self.reset_seen &= reset;
        // SUSPENDED is a level: acknowledging its IRQ does not clear that level.
        if !suspended {
            self.suspended = false;
            self.suspend_covered = false;
        }
    }
}

pub struct BusEpoch {
    epoch: u32,
    state: State,
}

impl Default for BusEpoch {
    fn default() -> Self {
        Self::new()
    }
}

impl BusEpoch {
    pub const fn new() -> Self {
        Self {
            epoch: 1,
            state: State::Default,
        }
    }
    pub fn current(&self) -> u32 {
        self.epoch
    }
    pub fn accepts(&self, epoch: u32) -> bool {
        self.epoch == epoch && self.state == State::Configured
    }
    pub fn exhausted(&self) -> bool {
        self.state == State::Exhausted
    }
    pub fn revoke(&mut self, reason: Revocation) {
        if self.epoch >= LAST_EPOCH || self.state == State::Exhausted {
            self.state = State::Exhausted;
            return;
        }
        self.epoch += 1;
        self.state = match reason {
            Revocation::Reset | Revocation::ConfigurationLoss => State::Default,
            Revocation::Suspend => match self.state {
                State::Default => State::Suspended { configured: false },
                State::Configured => State::Suspended { configured: true },
                State::Suspended { configured } => State::Suspended { configured },
                State::Exhausted => State::Exhausted,
            },
        };
    }
    pub fn resume(&mut self) {
        self.state = match self.state {
            State::Suspended { configured: true } => State::Configured,
            State::Suspended { configured: false } => State::Default,
            State::Default => State::Default,
            State::Configured => State::Configured,
            State::Exhausted => State::Exhausted,
        };
    }
    pub fn configure(&mut self) -> bool {
        if matches!(self.state, State::Exhausted | State::Suspended { .. }) {
            return false;
        }
        self.state = State::Configured;
        true
    }
}

#[cfg(test)]
#[path = "usb_epoch_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "usb_epoch_kani.rs"]
mod proofs;
