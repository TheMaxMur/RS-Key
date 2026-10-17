// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Cancel-safe handoff to an interrupt-masked SRAM idle loop on the other core.

use core::sync::atomic::{AtomicU8, Ordering};

#[repr(u8)]
#[derive(Clone, Copy)]
enum State {
    Idle,
    Requested,
    Parked,
    Released,
}

pub struct Pause(AtomicU8);
impl Default for Pause {
    fn default() -> Self {
        Self::new()
    }
}
impl Pause {
    pub const fn new() -> Self {
        Self(AtomicU8::new(State::Idle as u8))
    }
    #[inline(always)]
    fn transition(&self, from: State, to: State) -> bool {
        self.0
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    #[inline(always)]
    pub fn request_park(&self) -> bool {
        self.transition(State::Idle, State::Requested)
    }
    #[inline(always)]
    pub fn acknowledge(&self) -> bool {
        self.transition(State::Requested, State::Parked)
    }
    #[inline(always)]
    pub fn cancel(&self) -> bool {
        self.transition(State::Requested, State::Idle)
    }
    #[inline(always)]
    pub fn release(&self) -> bool {
        self.transition(State::Parked, State::Released)
    }
    #[inline(always)]
    pub fn finish(&self) -> bool {
        self.transition(State::Released, State::Idle)
    }
    #[inline(always)]
    pub fn is_parked(&self) -> bool {
        self.0.load(Ordering::Acquire) == State::Parked as u8
    }
}

#[cfg(test)]
#[path = "xip_pause_tests.rs"]
mod tests;
