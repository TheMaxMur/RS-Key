// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only reader for the phase-4 trace, excluded from production builds.
//!
//! A clientPIN that RE-ISSUES a token carrying the permissions it already holds
//! moves no raw field, so the recording could not tell it from a
//! `getKeyAgreement` — which is legitimately state-free — and the replay had to
//! shrug at both (`NO-OPINION`). The SUBCOMMAND is the input that separates
//! them. Inputs only, as in `makecredential_assurance.rs`: the answer stays
//! `outcome_raw`, and reading that back would be the model confirming itself.
//!
//! A `#[path]` child of `clientpin.rs` so the command's OWN parser decides what
//! the request said — a second decoder here would be a second thing to drift.

use super::*;

/// The clientPIN subcommand, or `None` for a body the device itself would refuse
/// to decode — a request that never parsed has no issuance to attribute.
pub fn trace_subcommand(params: &[u8]) -> Option<u64> {
    Some(parse(params).ok()?.subcommand)
}
