// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Key-grade material in a type that wipes itself.
//!
//! [`Secret`] has no `Copy`, `Clone`, `Debug` or `PartialEq`: a secret cannot be
//! duplicated, printed, or compared in variable time by accident — compare one
//! through `rsk_crypto::ct_eq(s.expose(), …)` — and its `Drop` zeroizes it on
//! every exit, a `?` included, which an explicit `.zeroize()` at the end of a
//! function never covered. [`WipeGuard`] gives a borrowed buffer that outlives
//! the scope (a static transport buffer, a caller's `&mut [u8]`) the same
//! guarantee.
//!
//! What a type cannot reach: a move is a `memcpy` and its source is not wiped, so
//! a secret is best built in place — [`Secret::zeroed`], then filled through
//! [`Secret::expose_mut`] — and handed on by reference rather than by value.
//! `drop(secret)` is such a move: it wipes the copy. [`Secret::wipe`] does not.
//!
//! None of these compile:
//!
//! ```compile_fail
//! let a = rsk_secret::Secret::<[u8; 4]>::zeroed();
//! let _b = a.clone();
//! ```
//! ```compile_fail
//! let a = rsk_secret::Secret::<[u8; 4]>::zeroed();
//! let b = rsk_secret::Secret::<[u8; 4]>::zeroed();
//! let _ = a == b;
//! ```
//! ```compile_fail
//! let a = rsk_secret::Secret::<[u8; 4]>::zeroed();
//! let _ = format!("{:?}", a);
//! ```
//! ```compile_fail
//! let a = rsk_secret::Secret::<[u8; 4]>::zeroed();
//! let b = a;
//! let _ = (a.expose(), b.expose());
//! ```
//!
//! and their twin does:
//!
//! ```
//! let mut a = rsk_secret::Secret::<[u8; 4]>::zeroed();
//! a.expose_mut()[0] = 1;
//! let b = a;
//! assert_eq!(b.expose(), &[1, 0, 0, 0]);
//! ```

#![cfg_attr(not(test), no_std)]
#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

use core::ops::{Deref, DerefMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A value wiped when it drops. The crate docs list what it refuses.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Take ownership of `value`. The place it was moved out of is not wiped:
    /// prefer [`Secret::zeroed`] for bytes. `const` so a `static` can hold one.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Zeroize the value now, in place, for a wipe point before the scope's end;
    /// the drop wipes it again.
    #[expect(clippy::disallowed_methods, reason = "the in-place early wipe")]
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Secret<[u8; N]> {
    pub const fn zeroed() -> Self {
        Self([0; N])
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    #[expect(clippy::disallowed_methods, reason = "the one wipe every Secret runs")]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

/// Exclusive access to a buffer that outlives the scope, wiped whole when the
/// guard drops — on every exit of the scope that holds it.
pub struct WipeGuard<'a>(&'a mut [u8]);

impl<'a> WipeGuard<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self(buf)
    }
}

impl Deref for WipeGuard<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl DerefMut for WipeGuard<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Drop for WipeGuard<'_> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the one wipe every WipeGuard runs"
    )]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests;
