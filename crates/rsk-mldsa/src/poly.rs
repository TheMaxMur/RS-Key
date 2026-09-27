// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The ring element and the two pointwise operations the core needs. A single
//! [`Poly`] type carries both the normal and the NTT/Montgomery domain — which
//! one holds is a usage convention at each call site (FIPS 204's R/T split
//! without separate types), which lets the NTT run in place and buffers be
//! reused across the signing loop.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::N;
use crate::reduce::mont_reduce;

/// A ring element: 256 signed coefficients. Zeroizes on drop — secret
/// polynomials (s1/s2/y/z and the expanded key's NTT halves) pass through here.
#[derive(Clone)]
#[repr(align(8))]
pub struct Poly(pub [i32; N]);

impl Drop for Poly {
    #[expect(
        clippy::disallowed_methods,
        reason = "a Poly's drop is its wipe, as a Secret's is"
    )]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Poly {}

impl Poly {
    /// The zero polynomial.
    pub const fn zero() -> Self {
        Poly([0; N])
    }
}

impl Default for Poly {
    fn default() -> Self {
        Poly::zero()
    }
}

/// A length-`M` vector of ring elements, all zero.
pub(crate) fn zero_vec<const M: usize>() -> [Poly; M] {
    core::array::from_fn(|_| Poly::zero())
}

/// Pointwise Montgomery product: `out[n] = mont_reduce(a[n]·b[n])`. Exactly one
/// operand must already carry the extra 2^32 Montgomery factor (see the call
/// sites: the twiddle table and `to_mont` supply it).
pub(crate) fn pointwise_mont(a: &Poly, b: &Poly) -> Poly {
    let mut out = Poly::zero();
    for n in 0..N {
        out.0[n] = mont_reduce(i64::from(a.0[n]) * i64::from(b.0[n]));
    }
    out
}
