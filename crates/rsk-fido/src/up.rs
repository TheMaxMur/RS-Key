// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The makeCredential / getAssertion user-presence test and the pinUvAuthToken it
//! spends. Once that test succeeds for a request asserting `up`, CTAP 2.1 §6.5.5.7
//! clears the token's UP and UV flags and every permission but largeBlobWrite, so a
//! follow-on authenticatorConfig cannot ride the touch (GHSA-wqjm-653g-hgw3). Only
//! [`Ctx::user_presence_test`] makes an [`UpFlag`], which the two commands' responses
//! build their UP bit from (getNextAssertion repeats the first leg's).

use rsk_fs::Storage;

use crate::consts::FLAG_UP;
use crate::error::CtapError;
use crate::{Confirm, Ctx, Rng};

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::makecredential::Request<'_> {}
    impl Sealed for crate::getassertion::Request<'_> {}
}

/// A request whose user-presence test spends the pinUvAuthToken: makeCredential's
/// and getAssertion's, and no other command's (sealed). A selection touch, a
/// zero-length `pinUvAuthParam` probe, U2F, reset and the vendor ceremonies test
/// presence without spending anything.
pub(crate) trait UpTested: sealed::Sealed {
    /// The `up` the response asserts.
    fn asserts_up(&self) -> bool;
}

/// makeCredential's `up` is implicitly true and cannot be disabled (§6.1.2).
impl UpTested for crate::makecredential::Request<'_> {
    fn asserts_up(&self) -> bool {
        true
    }
}

/// getAssertion's raw `up` option, which built-in UV has already set (§6.2.2 step
/// 8) — NOT whether the button is polled: a `strict-up` build polls an `up:false`
/// pre-flight too, and that probe must stay inert, UP=0 and the token unspent.
impl UpTested for crate::getassertion::Request<'_> {
    fn asserts_up(&self) -> bool {
        self.up
    }
}

/// The UP bit of a makeCredential / getAssertion response.
#[must_use]
pub(crate) struct UpFlag(bool);

impl UpFlag {
    /// The bit as authenticator data's flags byte carries it.
    pub(crate) fn bits(&self) -> u8 {
        if self.0 { FLAG_UP } else { 0 }
    }
}

impl<S: Storage, R: Rng> Ctx<'_, S, R> {
    /// The user-presence test: poll `ask` when there is one — a CTAPHID_CANCEL
    /// answers `KEEPALIVE_CANCEL`, any other refusal `OPERATION_DENIED`, and spends
    /// nothing — then spend the token if the request asserts `up`.
    pub(crate) fn user_presence_test<Q: UpTested>(
        &mut self,
        req: &Q,
        ask: Option<Confirm<'_>>,
    ) -> Result<UpFlag, CtapError> {
        if let Some(confirm) = ask {
            self.require_presence(confirm)?;
        }
        let up = req.asserts_up();
        if up {
            self.state.consume_after_user_presence();
        }
        Ok(UpFlag(up))
    }
}
