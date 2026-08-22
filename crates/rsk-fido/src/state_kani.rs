// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bounded state-*sequence* proofs over the real [`FidoState`].
//!
//! Every other harness in this tree proves `∀x ∈ D_bounded : P(x)` about **one
//! call** — a parser, a codec, an arithmetic step. RS-Key's dangerous defects
//! have not lived there; they have lived in sequences (a token surviving a PIN
//! change, one channel continuing another's walk). These two drive a symbolic
//! sequence of the real transition methods and assert the same invariants
//! `formal/RSKeySecurityState.tla` states abstractly, so one property is
//! traceable TLA+ invariant → Rust construct → Kani harness by its name.
//!
//! What a green run here does **not** carry over from the model, and vice versa:
//! the TLA+ model is abstract but unbounded in sequence length; these are the
//! real code but bounded at [`STEPS`] operations from one starting state.
//! Neither subsumes the other, and neither is a proof about the firmware image.
//!
//! Clauses are asserted with `kani::assert`, not `assert!`: Rust lowers
//! `assert!(c, "msg")` through `panic_fmt`, and Kani then prints "message
//! formatted at runtime" in place of the text — which would cost each clause the
//! one thing it is for, its name in the solver's output.
//!
//! **No `kani::assume` and no `#[kani::unwind]` here.** Each opcode alphabet is
//! total over `u8` — a value outside the named set is a no-op — so no input is
//! assumed away, and every loop in the reachable set walks a fixed-size array (a
//! 32-byte `zeroize` or `Rng::fill`), so CBMC's unwinding saturates on its own.
//! An insufficient bound would be a hard failure, not a silent
//! under-approximation, and none was reported.

use super::*;
use crate::consts::{
    CTAP_CREDENTIAL_MGMT, CTAP_GET_ASSERTION, PUAT_INITIAL_USAGE_LIMIT_MS,
    PUAT_MAX_USAGE_PERIOD_MS, STATEFUL_WALK_IDLE_MS,
};

/// Sequence length. Five symbolic operations after a concrete opening one: long
/// enough for invalidate → re-grant → invalidate again (the shape every "the
/// token came back" defect has taken), short enough to stay in a CI budget.
const STEPS: usize = 5;

/// Distinguishable token bytes, so `paut.token == TOK0` is a real question. Must
/// not be `0x00`: [`FidoState::reset`] leaves the token all-zero, and a zero
/// `TOK0` would make "the reset rerolled it" vacuously false.
const TOK0: u8 = 0xA5;

/// The two instants the proof needs. Every deadline in the reachable code
/// (`PUAT_MAX_USAGE_PERIOD_MS`, `PUAT_INITIAL_USAGE_LIMIT_MS`,
/// `STATEFUL_WALK_IDLE_MS`) is crossed by `JUMP` and by none of `0`, so a
/// two-valued clock decides every timer here exactly rather than approximately.
const T0: u64 = 1_000;
const JUMP: u64 = PUAT_MAX_USAGE_PERIOD_MS;
const _: () = assert!(JUMP >= PUAT_INITIAL_USAGE_LIMIT_MS && JUMP >= STATEFUL_WALK_IDLE_MS);

/// A counter RNG: successive fills differ, so "the token was rerolled" is
/// observable. `FidoState` only ever asks it for the 32-byte token here.
struct StepRng(u8);
impl Rng for StepRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0 = self.0.wrapping_add(1);
        buf.fill(self.0);
    }
}

// Symbolic opcodes. Any value outside this set is a no-op, so nothing is
// `assume`d away: the sequence alphabet is total over `u8`.
const OP_BEGIN: u8 = 0;
const OP_MARK_USED: u8 = 1;
const OP_CONSUME_AFTER_UP: u8 = 2;
const OP_STOP: u8 = 3;
const OP_RESET_TOKEN: u8 = 4;
const OP_AUTHENTICATOR_RESET: u8 = 5;
const OP_POWER_CYCLE: u8 = 6;
const OP_TIME_PASSES: u8 = 7;

/// The token issuance `clientpin::issue_token` performs, in its own order
/// (`clientpin.rs:415-421`): fresh token, begin using it, then the permission
/// set. Its rpId binding (`:422-428`) is left out — `paut.has_rp_id` starts
/// false and no clause here reads the hash. Reproduced rather than called
/// because the real function needs a whole `Ctx` — flash, a device identity and
/// a presence source — none of which this sequence has. Not because *holding* a
/// `Ctx` codegens p256: measured, it does not. The three inline call-site gates
/// are the different case — their bodies reach the curve (docs/testing.md).
fn issue_token(st: &mut FidoState, rng: &mut StepRng, permissions: u8, now_ms: u64) {
    st.reset_pin_uv_auth_token(rng);
    st.begin_using_token(false, now_ms);
    st.paut.permissions = permissions;
}

/// `NoTokenAfterInvalidation` — the bounded, code-level instance of the TLA+
/// invariant of that name (`formal/README.md`, row 3).
///
/// A grant invalidated by `stopUsingPinUvAuthToken`, a token reroll, an
/// `authenticatorReset`, a power cycle or its own usage timer never authorizes
/// again; only a fresh issuance brings one back. Checked after **every** step of
/// a symbolic five-operation sequence, against the two guard shapes the call
/// sites actually use:
///
/// - the **UV** shape — `getassertion.rs:376-379`, `makecredential.rs:513-516` —
///   whose distinguishing conjunct is `user_verified()`;
/// - the **bare** shape — `config.rs:222-224`, `credmgmt.rs:277` — which tests
///   the MAC and the permission bits and *nothing else*. For those two the only
///   thing between a stopped token and a live authorization is that
///   `stop_using_token` zeroes `permissions`: the token bytes stay put, so the
///   MAC keeps verifying. That asymmetry is asserted here on purpose (`A4`) —
///   it is what the TLA+ mutation experiment found when a single uniform guard
///   made a real defect undetectable.
///
/// Every clause is an **equality**, not an implication. One-directional ghosts
/// are the invariant analogue of a test that cannot fail: each of them is also
/// satisfied by an authenticator that retires everything on sight.
///
/// What this does **not** prove: the call sites are represented by the state
/// predicates they read, not invoked (their bodies need a `Ctx`); the sequence
/// is five operations from one starting state, not all sequences; `largeBlobs`,
/// `getNextAssertion` and the built-in-UV path are absent; and a *persistent*
/// `pcmr` grant is out of scope entirely — it lives in flash (`EF_PAUTHTOKEN`),
/// not here, which is finding 2 of the TLA+ run.
#[kani::proof]
fn no_token_after_invalidation() {
    let mut rng = StepRng(TOK0 - 1);
    let mut st = FidoState::new();
    let mut now = T0;

    // The opening grant, with a symbolic permission set — an empty one and an
    // lbw-only one are inside the range on purpose.
    let perms0: u8 = kani::any();
    issue_token(&mut st, &mut rng, perms0, now);
    let tok0 = st.paut.token;

    // Ghosts: what the *sequence* says should be true, recomputed from the
    // opcode alone. Each is set by exactly the operations named in CTAP 2.1
    // §6.5.5.7 / §6.5.5.8, never read back out of `st`.
    let mut granted = true; // a token is in use
    let mut verified = true; // `user_verified()` should hold
    let mut privileged = perms0 & !PERM_LBW != 0; // a non-largeBlobWrite permission remains
    let mut same_token = true; // the bytes are still `tok0`
    let mut issued_late = false; // this grant was issued after the clock jump
    let mut jumped = false;

    let ops: [u8; STEPS] = kani::any();
    let perms: [u8; STEPS] = kani::any();
    for i in 0..STEPS {
        // The dispatch prologue every CBOR command runs first (`lib.rs:207`).
        // A grant issued before the jump has outrun both windows by now.
        st.expire_stale_token(now);
        if jumped && granted && !issued_late {
            granted = false;
            verified = false;
            privileged = false;
        }

        match ops[i] {
            OP_BEGIN => {
                issue_token(&mut st, &mut rng, perms[i], now);
                granted = true;
                verified = true;
                privileged = perms[i] & !PERM_LBW != 0;
                same_token = false;
                issued_late = jumped;
            }
            OP_MARK_USED => st.mark_token_used(now),
            OP_CONSUME_AFTER_UP => {
                // §6.5.5.7's post-presence triad keeps the token in use and keeps
                // largeBlobWrite; `granted` therefore stays.
                st.consume_after_user_presence();
                verified = false;
                privileged = false;
            }
            OP_STOP => {
                st.stop_using_token();
                granted = false;
                verified = false;
                privileged = false;
            }
            OP_RESET_TOKEN => {
                st.reset_pin_uv_auth_token(&mut rng);
                granted = false;
                verified = false;
                privileged = false;
                same_token = false;
            }
            OP_AUTHENTICATOR_RESET => {
                st.reset();
                granted = false;
                verified = false;
                privileged = false;
                same_token = false;
            }
            OP_POWER_CYCLE => {
                st = FidoState::new();
                granted = false;
                verified = false;
                privileged = false;
                same_token = false;
            }
            OP_TIME_PASSES => {
                now = T0 + JUMP;
                jumped = true;
            }
            _ => {}
        }

        // A1 — the UV-shaped call sites (getassertion.rs:376-379,
        // makecredential.rs:513-516): their `user_verified()` conjunct is false after
        // an invalidation and true after an issuance, and at no other time.
        kani::assert(
            verified == st.user_verified(),
            "NoTokenAfterInvalidation/A1: user_verified() does not track the grant",
        );
        // A2 — the bare-shaped call sites (config.rs:222-224, credmgmt.rs:277)
        // read the permission bits and the MAC, nothing else. §6.5.5.7 keeps
        // largeBlobWrite across a consumed presence test and drops the rest.
        kani::assert(
            privileged == (st.paut.permissions & !PERM_LBW != 0),
            "NoTokenAfterInvalidation/A2: the permission set does not track the grant",
        );
        // A3 — a fully retired grant leaves nothing usable behind at all, and its
        // rpId binding goes with it (§6.5.5.8).
        kani::assert(
            granted == st.paut.in_use,
            "NoTokenAfterInvalidation/A3: in_use does not track the grant",
        );
        kani::assert(
            granted || (st.paut.permissions == 0 && !st.paut.has_rp_id),
            "NoTokenAfterInvalidation/A3: a retired token kept permissions or its rpId",
        );
        // A4 — the token bytes move exactly when a reroll or a wipe moved them.
        // `stop_using_token` deliberately does not reroll, which is why A2/A3
        // above are the whole defence for the bare-shaped sites.
        kani::assert(
            same_token == (st.paut.token == tok0),
            "NoTokenAfterInvalidation/A4: the token bytes moved unexpectedly",
        );
    }

    // Non-vacuity, enforced by `scripts/kani.sh`'s cover row and not by Kani,
    // which exits 0 on a cover nothing satisfies: without these the clauses above
    // are satisfied by a sequence alphabet whose interesting states never arise.
    kani::cover!(granted && st.user_verified() && st.paut.permissions != 0);
    kani::cover!(!granted && st.paut.token == tok0); // stopped, bytes intact
    kani::cover!(!verified && st.paut.in_use); // consumed after presence
}

/// The `enumerateRPsBegin` cursor write, `credmgmt.rs:334-337` plus the totals
/// and the leg stamp its serving tail sets (`:380-386`). `total` is symbolic:
/// how many RPs the store held is not this proof's business.
///
/// The leading `cm.reset()` is `credmgmt.rs:164` — every credentialManagement
/// subcommand that is not a *Next* ends the walk in flight before it runs. Its
/// absence was the first counterexample this harness produced: a
/// `enumerateCredentialsBegin` on a second channel adopted the first channel's
/// live RP cursor, because `begin_creds` writes `cm.channel` and leaves
/// `rp_counter`/`rp_total` alone. A modelling artifact, not a defect — but only
/// because that one line stands between the two.
fn begin_rps(st: &mut FidoState, total: u16, now_ms: u64) {
    st.cm.reset();
    st.cm.channel = st.channel;
    st.cm.rp_counter = 1;
    st.cm.rp_total = total;
    st.cm.rp_next_slot = 0;
    st.cm.rp_counter = st.cm.rp_counter.saturating_add(1);
    st.cm.last_leg_ms = now_ms;
}

/// `enumerateCredentialsBegin`, the same shape (`credmgmt.rs:164`, `:420-423`, `:503-504`).
fn begin_creds(st: &mut FidoState, total: u16, now_ms: u64) {
    st.cm.reset();
    st.cm.channel = st.channel;
    st.cm.cred_counter = 1;
    st.cm.cred_total = total;
    st.cm.cred_next_slot = 0;
    st.cm.cred_counter = st.cm.cred_counter.saturating_add(1);
    st.cm.last_leg_ms = now_ms;
}

/// B1/B2 — a *Next* is servable **exactly** to the channel whose Begin opened
/// the walk, and only while no retiring event has intervened. An equality, not
/// an implication, so a guard that refuses everything fails it too. Probed on
/// both channels, and run **before and after** every operation: a step that both
/// consults the guard and advances the cursor would otherwise consume its own
/// violation.
fn check_walk_owner(st: &FidoState, rp_owner: Option<u32>, cred_owner: Option<u32>) {
    for probe in [C1, C2] {
        kani::assert(
            st.cm.may_walk_rps(probe) == (rp_owner == Some(probe)),
            "NoAuthorizationBypass/B1: the RP walk is servable to the wrong set of channels",
        );
        kani::assert(
            st.cm.may_walk_creds(probe) == (cred_owner == Some(probe)),
            "NoAuthorizationBypass/B2: the credential walk is servable to the wrong set of channels",
        );
    }
}

/// Two channels, as the TLA+ model uses: one opens a walk, the other interlopes.
const C1: u32 = 1;
const C2: u32 = 2;

const W_BEGIN_RPS: u8 = 0;
const W_BEGIN_CREDS: u8 = 1;
const W_NEXT_LEG: u8 = 2;
const W_OTHER_COMMAND: u8 = 3;
const W_OTHER_CM_SUBCOMMAND: u8 = 4;
const W_STOP_TOKEN: u8 = 5;
const W_AUTHENTICATOR_RESET: u8 = 6;
const W_TIME_PASSES: u8 = 7;

/// `NoAuthorizationBypass`, walk-owner clause — the bounded, code-level instance
/// of the TLA+ invariant's `state.rs:169-179` / `credmgmt.rs:338` row.
///
/// CTAP 2.1 §6.8 exempts `enumerateRPsGetNextRP` / `enumerateCredentialsGetNext`
/// from carrying a `pinUvAuthParam` of their own: they inherit the *Begin*'s
/// authorization. The pair `(channel, counter)` is therefore the whole
/// authorization check for a *Next*, and this asserts that over a symbolic
/// five-operation interleaving: a walk is servable only by the channel whose
/// Begin opened it, and only while nothing has retired it — an unrelated command
/// (`lib.rs:214`), another credentialManagement subcommand (`credmgmt.rs:164`),
/// `stopUsingPinUvAuthToken`, an `authenticatorReset`, or the §6 idle window.
///
/// This is the channel half of the maintainer's `cancel(transport, channel)`
/// property. The transport half — one transport cancelling another's touch — is
/// not expressible over `FidoState`; it is proved in
/// `crates/rsk-device/src/presence_kani.rs`, where the arbitration moved out of
/// `firmware/src/presence.rs` so a harness could reach it at all.
///
/// What this does **not** prove: the Begin is reproduced from its call site's
/// cursor writes rather than invoked (`enumerate_rps` needs flash and the device
/// seed); `rp_index`/`rp_index_gen` staleness is untouched; the assertion walk
/// (`gna`, which times itself in `getassertion.rs`) is not modelled; and a
/// CTAPHID channel id is a routing label the sender writes, so channel ownership
/// is a scoping rule, not an authentication one (`state.rs:327-332`).
#[kani::proof]
fn no_authorization_bypass_walk_owner() {
    let mut st = FidoState::new();
    let mut now = T0;

    // The channel that owns a live walk and how many legs it has left. Both are
    // set from the *opcode*, never read back out of `st` — reading the cursor
    // would weaken B1/B2 to their channel conjunct alone.
    let mut rp_owner: Option<u32> = None;
    let mut cred_owner: Option<u32> = None;
    let mut rp_left: u16 = 0;
    let mut cred_left: u16 = 0;
    let mut last_leg_late = false;
    let mut jumped = false;

    let ops: [u8; STEPS] = kani::any();
    let chans: [bool; STEPS] = kani::any();
    let totals: [u16; STEPS] = kani::any();
    for i in 0..STEPS {
        // The firmware stamps the in-flight request's channel before every
        // dispatch (`state.rs:355-359`).
        st.channel = if chans[i] { C1 } else { C2 };

        // The dispatch prologue (`lib.rs:207-214`); `retire_sequences_except`
        // belongs to the opcode below, which is what knows the command. A walk
        // whose last leg predates the jump has outrun the §6 idle window.
        st.expire_stale_sequences(now);
        if jumped && !last_leg_late {
            rp_owner = None;
            cred_owner = None;
        }
        check_walk_owner(&st, rp_owner, cred_owner);

        match ops[i] {
            W_BEGIN_RPS => {
                begin_rps(&mut st, totals[i], now);
                // The Begin serves leg 1 itself, so a Next exists iff the store
                // held a second RP.
                rp_left = totals[i].saturating_sub(1);
                rp_owner = (rp_left > 0).then_some(st.channel);
                // A Begin of either walk retires the other (§6 "exclusively
                // preceded"): both cursors live in one `CredMgmtState`.
                cred_owner = None;
                cred_left = 0;
                last_leg_late = jumped;
            }
            W_BEGIN_CREDS => {
                begin_creds(&mut st, totals[i], now);
                cred_left = totals[i].saturating_sub(1);
                cred_owner = (cred_left > 0).then_some(st.channel);
                rp_owner = None;
                rp_left = 0;
                last_leg_late = jumped;
            }
            W_NEXT_LEG => {
                // A *Next* the guard admits: serve it exactly as `enumerate_rps`
                // does (`credmgmt.rs:382-386`). The guard was just checked above,
                // so an admission it should not have made is already recorded.
                if st.cm.may_walk_rps(st.channel) {
                    st.cm.rp_counter = st.cm.rp_counter.saturating_add(1);
                    st.cm.last_leg_ms = now;
                    rp_left = rp_left.saturating_sub(1);
                    rp_owner = (rp_left > 0).then_some(st.channel);
                    last_leg_late = jumped;
                } else if st.cm.may_walk_creds(st.channel) {
                    st.cm.cred_counter = st.cm.cred_counter.saturating_add(1);
                    st.cm.last_leg_ms = now;
                    cred_left = cred_left.saturating_sub(1);
                    cred_owner = (cred_left > 0).then_some(st.channel);
                    last_leg_late = jumped;
                }
            }
            W_OTHER_COMMAND => {
                st.retire_sequences_except(CTAP_GET_ASSERTION);
                rp_owner = None;
                cred_owner = None;
            }
            W_OTHER_CM_SUBCOMMAND => {
                // credentialManagement survives `retire_sequences_except`; the
                // subcommand demux ends the walk itself (`credmgmt.rs:164`).
                st.retire_sequences_except(CTAP_CREDENTIAL_MGMT);
                st.cm.reset();
                rp_owner = None;
                cred_owner = None;
            }
            W_STOP_TOKEN => {
                st.stop_using_token();
                rp_owner = None;
                cred_owner = None;
            }
            W_AUTHENTICATOR_RESET => {
                st.reset();
                rp_owner = None;
                cred_owner = None;
            }
            W_TIME_PASSES => {
                now = T0 + JUMP;
                jumped = true;
            }
            _ => {}
        }
        check_walk_owner(&st, rp_owner, cred_owner);
    }

    // Non-vacuity, enforced by `scripts/kani.sh`'s cover row and not by Kani: a
    // walk really is servable to its owner on either channel, and the idle window
    // really does retire one, or B1/B2 hold over a device that walks nothing.
    kani::cover!(rp_owner == Some(C1) && st.cm.may_walk_rps(C1));
    kani::cover!(cred_owner == Some(C2) && st.cm.may_walk_creds(C2));
    kani::cover!(jumped && !st.cm.may_walk_rps(C1) && !st.cm.may_walk_rps(C2));
}
