// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A staging buffer aligned to the flash write unit.
//!
//! RP2350's ROM program wants a word-aligned data pointer: `embassy-rp`'s
//! `Flash::write` documents "the offset and buffer must be aligned" and hands a
//! RAM slice straight to the ROM, and the vendored mock asserts the same in
//! `third_party/sequential-storage/src/mock_flash.rs`. A bare `[u8; N]` is
//! align 1, so it meets that only by how the compiler happened to lay the stack
//! out — which native runs get and Miri does not. Every buffer this crate hands
//! to `NorFlash::write`/`read` goes through [`FlashBuf`] instead.

use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// A byte buffer whose pointer is 4-byte aligned. `repr(align)` takes a literal,
/// so the flash word width is named here once, in prose: RP2350 programs words.
#[repr(align(4))]
pub struct FlashBuf<const N: usize>([u8; N]);

impl<const N: usize> FlashBuf<N> {
    /// A zeroed buffer.
    pub const fn new() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Default for FlashBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for FlashBuf<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> DerefMut for FlashBuf<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Zeroize for FlashBuf<N> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the wipe behind Secret<FlashBuf>"
    )]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// The alignment the flash contract needs, held at compile time. `repr(align)`
/// is the only thing that sets it, so this is what a dropped attribute trips.
const _: () = assert!(core::mem::align_of::<FlashBuf<1>>() == 4);
