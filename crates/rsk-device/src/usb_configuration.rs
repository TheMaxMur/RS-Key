// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A copied SET_CONFIGURATION is effective only after its armed status was ACKed.

#[derive(Default)]
pub enum Configuration {
    #[default]
    Idle,
    Queued(u32),
    Armed(u32),
}

impl Configuration {
    pub const fn new() -> Self {
        Self::Idle
    }

    pub fn queue(&mut self, ticket: u32) {
        *self = Self::Queued(ticket);
    }

    pub fn arm(&mut self, ticket: u32) -> bool {
        if matches!(self, Self::Queued(queued) if *queued == ticket) {
            *self = Self::Armed(ticket);
            true
        } else {
            false
        }
    }

    pub fn acknowledge(&mut self) -> bool {
        if matches!(self, Self::Armed(_)) {
            self.reset();
            true
        } else {
            false
        }
    }

    pub fn abandon(&mut self, ticket: u32) {
        if matches!(self, Self::Queued(id) | Self::Armed(id) if *id == ticket) {
            self.reset();
        }
    }

    pub fn reset(&mut self) {
        *self = Self::Idle;
    }
}

#[cfg(test)]
#[path = "usb_configuration_tests.rs"]
mod tests;
