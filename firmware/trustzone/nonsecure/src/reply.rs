// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::{Deref, DerefMut};

/// The complete NS reply span, cleared before releasing its pending ticket.
pub struct ReplyGuard<'a>(&'a mut [u8]);

impl<'a> ReplyGuard<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self(bytes)
    }
}

impl Deref for ReplyGuard<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl DerefMut for ReplyGuard<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Drop for ReplyGuard<'_> {
    fn drop(&mut self) {
        super::sweep_buffer::wipe_bytes(self.0);
    }
}

#[cfg(test)]
#[path = "reply_tests.rs"]
mod tests;
