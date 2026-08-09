// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! USB transport layer: CTAPHID (FIDO HID) and the CCID smart-card class.

pub mod ccid;
pub mod ctaphid;
pub mod kbd;
pub mod secure_pin;

/// Abandon an IN-endpoint response when the host stops draining it for this
/// long — an unbounded write blocks the transport task and wedges the whole
/// interface; a live host drains within milliseconds.
pub(crate) const TX_TIMEOUT_MS: u64 = 500;
