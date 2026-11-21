// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use bp256::BrainpoolP256r1 as Curve;
use bp256::r1::{AffinePoint, ProjectivePoint, Scalar};
type PublicKey = elliptic_curve::PublicKey<Curve>;
type FieldElement = <Curve as elliptic_curve::hazmat::FieldArithmetic>::FieldElement;
const SCALAR_BITS: usize = 256;

include!("ecdh_brainpool.rs");

#[cfg(test)]
#[expect(
    clippy::duplicate_mod,
    reason = "the same multiplication contract is instantiated for both Brainpool fields"
)]
#[path = "ecdh_brainpool_tests.rs"]
mod tests;
