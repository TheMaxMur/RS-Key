// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! One bounded state-sequence proof that drives a **real authorization call
//! site** rather than the state predicates behind it.
//!
//! Only one of the four token gates can be reached this way. The other three
//! (`config.rs:243`, `getassertion.rs:384`, `makecredential.rs:513`) are inline
//! in functions that need a `Ctx`, and a `Ctx` drags `p256` into the reachable
//! set, where Kani 0.67.0 does not merely time out — it aborts in codegen:
//! `crypto-bigint 0.7.5 UintRef::lowest_u64` panics cprover_bindings' typecheck
//! (`BinaryOperation Expression does not typecheck Plus … FlexibleArray`).
//! [`verify_cm_token`] is reachable because it touches nothing but HMAC-SHA-256.
//!
//! No `kani::assume` and no `#[kani::unwind]`; see `state_kani.rs` for why
//! neither is needed.

use super::*;
use crate::Rng;
use crate::state::PERM_LBW;

/// A counter RNG, so a reroll is observable. See `state_kani.rs`.
struct StepRng(u8);
impl Rng for StepRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0 = self.0.wrapping_add(1);
        buf.fill(self.0);
    }
}

/// Four symbolic steps. Every operation in this alphabet leaves the token
/// **bytes** untouched, which is what keeps one HMAC-SHA-256 evaluation concrete
/// and this harness inside a CI budget; a reroll would make the MAC's key a
/// merge of three values and the formula symbolic. `state_kani.rs` covers the
/// rerolling operations, on the state predicates.
const STEPS: usize = 4;

const OP_MARK_USED: u8 = 0;
const OP_CONSUME_AFTER_UP: u8 = 1;
const OP_STOP: u8 = 2;

/// `NoTokenAfterInvalidation`, at the call site — the bounded, code-level
/// instance of the TLA+ invariant of that name, driving the real
/// [`verify_cm_token`] (`credmgmt.rs:278-288`) that `deleteCredential` and
/// `updateUserInformation` authorize with.
///
/// The platform mints a genuine `pinUvAuthParam` while the grant is live, then a
/// symbolic four-operation sequence runs, then that param is **replayed**. Two
/// claims, and the second is the load-bearing one:
///
/// - **C1** the call site refuses unless the `cm` permission genuinely survived;
/// - **C2** the replayed MAC still *verifies* — `stop_using_token` and
///   `consume_after_user_presence` do not touch the token bytes
///   (`state.rs:547-562`, `:523-535`). So at this call site, and at
///   `config.rs:243-245`, zeroing `permissions` is not defence in depth: it is
///   the only defence. The TLA+ mutation experiment found exactly this by
///   failing to catch `BugStopUsingKeepsPerms` under a guard that also tested
///   "the token is in use" — a conjunct these two sites do not have.
///
/// What this does **not** prove: only the `cm` permission and only this call
/// site; the persistent `pcmr` grant that `authorize_cm` consults *before* this
/// (`credmgmt.rs:240-242`) is in flash and out of reach here — finding 2 of the
/// TLA+ run, closed at the consumer by `32b9fa3` and at the producer by
/// `31c6e73`, and pinned by host tests rather than by this harness; four
/// operations, one starting state; and
/// the MAC is exercised on one concrete payload, so this says nothing about
/// `pinproto::verify` as a MAC.
#[kani::proof]
fn no_token_after_invalidation_at_call_site() {
    let mut rng = StepRng(0xA4);
    let mut st = FidoState::new();
    let proto = PinProto::Two;

    // Issuance, in `clientpin.rs:417-423`'s order, with a symbolic permission set.
    let perms0: u8 = kani::any();
    st.reset_pin_uv_auth_token(&mut rng);
    st.begin_using_token(false, 1_000);
    st.paut.permissions = perms0;

    // The param a platform holds after a legitimate getCredsMetadata request.
    let payload = [CM_GET_CREDS_METADATA as u8];
    let mut param = [0u8; 32];
    let n = pinproto::authenticate(proto, &st.paut.token, &payload, &mut param)
        .expect("32-byte buffer fits a v2 MAC");

    // `cm` is not the permission §6.5.5.7 lets a consumed token keep, so both
    // invalidating operations below take it away.
    const _: () = assert!(PERM_CM & PERM_LBW == 0);
    let mut cm_allowed = perms0 & PERM_CM != 0;
    let ops: [u8; STEPS] = kani::any();
    for op in ops {
        match op {
            OP_MARK_USED => st.mark_token_used(1_000),
            OP_CONSUME_AFTER_UP => {
                st.consume_after_user_presence();
                cm_allowed = false; // §6.5.5.7 keeps largeBlobWrite and nothing else
            }
            OP_STOP => {
                st.stop_using_token();
                cm_allowed = false;
            }
            _ => {}
        }
    }

    // C1 — the real gate. `kani::assert`, not `assert!`, so the name reaches the
    // solver's output (see `state_kani.rs`).
    kani::assert(
        verify_cm_token(&mut st, proto, &payload, &param[..n]).is_ok() == cm_allowed,
        "NoTokenAfterInvalidation/C1: credentialManagement authorized on a retired grant",
    );
    // C2 — and it is not the MAC that refused.
    kani::assert(
        st.verify_token(proto, &payload, &param[..n]),
        "NoTokenAfterInvalidation/C2: the replayed MAC stopped verifying, so C1 proves less \
         than it claims — permissions is no longer the only defence at this call site",
    );
    kani::cover!(cm_allowed); // the grant can still authorize: C1 is not vacuous
}
