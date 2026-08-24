// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only reader for the phase-4 trace, excluded from production builds.
//!
//! §6.1.2's token-less gate is a function of two REQUEST fields and of state the
//! trace already records, so `formal/TraceSecurity.tla` can PREDICT a recorded
//! refusal instead of shrugging at it (`AMBIGUOUS`). Inputs only: the answer is
//! `outcome_raw`, and reading that back would be the model confirming itself.
//!
//! A `#[path]` child of `makecredential.rs` so the command's OWN parser decides
//! what the request said — a second decoder here would be a second thing to
//! drift, and it is exactly the field a drifted copy would get wrong.

use super::*;

/// `(rk, carried a pinUvAuthParam)`, or `None` for a body the device itself
/// would refuse to decode — a request that never parsed has no gate answer.
pub fn trace_request_flags(params: &[u8]) -> Option<(bool, bool)> {
    let req = parse(params).ok()?;
    Some((req.rk, req.pin_uv_auth_param.is_some()))
}
