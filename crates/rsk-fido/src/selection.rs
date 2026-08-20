// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorSelection`: the user confirms this is the authenticator to use
//! by touching it. With no button configured the presence source confirms
//! instantly; timeout / cancel map to USER_ACTION_TIMEOUT / OPERATION_DENIED.

use rsk_fs::Storage;

use crate::error::{CtapError, CtapResult};
use crate::{Ctx, Presence, Rng};

/// `authenticatorSelection`: wait for a touch, then reply with only the status byte.
pub fn selection<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    match ctx
        .presence
        .request_ceremony(crate::Confirm::titled("Use this key?"))
    {
        Presence::Confirmed => Ok(0),
        Presence::Timeout => Err(CtapError::UserActionTimeout),
        Presence::Declined => Err(CtapError::OperationDenied),
        // CTAPHID_CANCEL during the touch wait (FIDO conformance HID-1 P-15).
        Presence::Cancelled => Err(CtapError::KeepAliveCancel),
    }
}

#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;
