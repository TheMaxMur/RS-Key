// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PINs the tests set, chosen so the suite means the same thing under every build
//! profile.
//!
//! The suite used to type `1234` almost everywhere, which is fine under CTAP's
//! four-code-point floor and refused twice over under `strong-pin` / `fips-profile`
//! — too short, and a ±1 run. So `cargo test --features strong-pin` failed 61 cases,
//! and had done for as long as the feature existed: CI *builds* that flavor and
//! `scripts/check.sh` tests the default one, so nothing ever ran the shipped
//! `firmware-strong-pin` / `firmware-fips` behaviour past the handful of cases
//! written for it by hand.
//!
//! Each value clears every rule of the strictest profile: six code points, no
//! repeated period, no ±1 run, six distinct digits, not on the denylist. They are the
//! same values `rsk-display`'s test module uses, so one vocabulary spans both crates.
//!
//! A test that is ABOUT a refused PIN keeps its own literal — `1234` where the point
//! is the floor, `123456` where the point is the run. Those must not be swept, or the
//! policy's own regressions would stop testing the policy.

/// The PIN a test sets when it just needs one.
pub(crate) const PIN: &[u8] = b"481629";
/// What a change-PIN flow replaces [`PIN`] with.
pub(crate) const NEW_PIN: &[u8] = b"739154";
/// Same length, different digits: the wrong-PIN half of a retry ladder.
pub(crate) const WRONG_PIN: &[u8] = b"481620";
/// The **device** PIN — a credential independent of the FIDO clientPIN, so the tests
/// that prove that independence need a value that is visibly not [`PIN`].
pub(crate) const DEVICE_PIN: &[u8] = b"305271";
