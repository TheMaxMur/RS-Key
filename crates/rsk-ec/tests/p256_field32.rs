// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Exercise the production 32-bit field backend against the host's 64-bit field.
#![cfg(target_pointer_width = "64")]

extern crate self as elliptic_curve;

#[path = "p256_field32/bigint.rs"]
pub mod bigint;

struct FieldParams;
impl bigint::modular::ConstMontyParams for FieldParams {
    const PARAMS: bigint::modular::Params = bigint::modular::Params;
}

#[path = "../../../third_party/p256/src/arithmetic/field/field32.rs"]
mod candidate;

#[path = "p256_field32/cases.rs"]
mod tests;
