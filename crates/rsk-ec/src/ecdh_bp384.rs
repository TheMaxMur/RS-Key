// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use bp384::BrainpoolP384r1 as Curve;
use bp384::r1::{AffinePoint, ProjectivePoint, Scalar};
type PublicKey = elliptic_curve::PublicKey<Curve>;
type FieldElement = <Curve as elliptic_curve::hazmat::FieldArithmetic>::FieldElement;
const SCALAR_BITS: usize = 384;

include!("ecdh_brainpool.rs");

#[cfg(test)]
#[path = "ecdh_brainpool_tests.rs"]
mod tests;
