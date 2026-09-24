// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! One bounded state-sequence proof that drives a **real authorization call
//! site** rather than the state predicates behind it.
//!
//! Only one of the four token gates can be reached this way. The other three
//! (`config.rs:243`, `getassertion.rs:420`, `makecredential.rs:559`) are inline
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
///   (`state.rs:564-579`, `:540-552`). So at this call site, and at
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

    // Issuance, in `clientpin.rs:420-426`'s order, with a symbolic permission set.
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

/// The two channels `state_kani.rs` uses: one opens a walk, the other interlopes.
const W_C1: u32 = 1;
const W_C2: u32 = 2;

/// The relying party the session token is bound to, and one that is not it.
const RP_OWNED: [u8; 32] = [0x11; 32];
const RP_OTHER: [u8; 32] = [0x22; 32];

/// `enumerateCredentialsBegin`'s `subCommandParams` as the demux hands them to
/// the MAC. Concrete, and so is the subcommand byte beside it: the payload is
/// what the HMAC is taken over, and a payload whose LENGTH is symbolic makes the
/// compression function symbolic with it. Measured — one harness over both
/// Begins, choosing the payload from a `kani::any()`, had not converged after
/// 40 minutes and 8 GiB; two harnesses with a concrete payload each are the
/// same claim inside the tier's budget.
const RAW_SUBPARA: [u8; 3] = [0xA1, 0x01, 0x58];

const NOW: u64 = 1_000;

/// **D3** — the flag the two harnesses below reason with means what it says.
///
/// Both of them compute `authorized` from `forged`, which is the harness's own
/// choice, and never read `verify_token`'s answer back: reading it would let one
/// broken MAC satisfy the equality with another. That leaves one obligation, and
/// it is this one — a `pinUvAuthParam` with a single bit of its tag flipped does
/// not verify, and an untouched one does.
///
/// Its own harness, and the reason is a number. A third HMAC-SHA-256 evaluation
/// inside `no_authorization_bypass_rps_begin_at_call_site` took it to 448 s and
/// **14.5 GiB** — over what a hosted runner has, and the `state` tier runs on one.
/// Here the same fact costs two evaluations and nothing else.
#[kani::proof]
fn no_authorization_bypass_begin_mac_is_the_flag() {
    let mut rng = StepRng(0xC9);
    let mut st = FidoState::new();
    let proto = PinProto::Two;
    st.reset_pin_uv_auth_token(&mut rng);
    st.begin_using_token(false, NOW);

    let payload = [CM_ENUMERATE_RPS_BEGIN as u8];
    let mut param = [0u8; 32];
    let n = pinproto::authenticate(proto, &st.paut.token, &payload, &mut param)
        .expect("32-byte buffer fits a v2 MAC");
    let forged: bool = kani::any();
    if forged {
        param[0] ^= 1;
    }
    kani::assert(
        st.verify_token(proto, &payload, &param[..n]) == !forged,
        "NoAuthorizationBypass/D3: the MAC's verdict does not track the flipped tag bit",
    );
    kani::cover!(forged);
}

/// A stand-in for HMAC-SHA-256 in the two call-site harnesses, and the first
/// `kani::stub` in this tree. It abstracts the primitive under
/// `pinproto::authenticate` and `pinproto::verify`, so both keep their real
/// bodies — `mac_len`, the length gate, `ct_eq` — and only the compression
/// function goes.
///
/// It takes nothing away, because those two never read `verify_token`'s answer:
/// they compute `authorized` from `forged`, treating the MAC as an oracle, and
/// D3 above is the harness that earns that treatment against the real thing.
/// What they need of a MAC is that a flipped tag byte compares unequal and an
/// untouched one compares equal, which this gives by folding key and message
/// into byte 0.
///
/// The number that made it necessary: two real evaluations per Begin killed a
/// hosted runner 11 minutes into this harness, twice (2026-09-08), at 35 min of
/// a 90 min job with no cap firing and 66 of 67 harnesses already verified. The
/// D3 note above measured a THIRD evaluation at 14.5 GiB and split it out for
/// exactly this reason; the split was not enough.
#[cfg(kani)]
fn stub_hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // A BOUNDED fold, and the bound is the point: the first version walked the
    // whole of `key` and `msg`, and CBMC unwound that 1699 times — more than the
    // primitive it replaces. Sixteen bytes from the END, because a CTAP
    // pinUvAuth message opens with 32 bytes of 0xff pad and the command and its
    // parameters sit after it.
    let mut acc: u8 = 0x9e ^ (msg.len() as u8) ^ key.first().copied().unwrap_or(0);
    let start = msg.len().saturating_sub(16);
    let mut i = 0usize;
    while i < 16 {
        if let Some(&b) = msg.get(start + i) {
            acc = acc.wrapping_mul(31).wrapping_add(b);
        }
        i += 1;
    }
    let mut out = [0u8; 32];
    out[0] = acc;
    out[1] = msg.len() as u8;
    out
}

/// What the Begin under test decided, and what the walk it opened looks like.
struct Begin {
    /// The gate's answer — the real one, from the real functions.
    decided: bool,
    /// What the request alone says it should have been, never read back out of
    /// `st`: a guard that refuses everything must fail this too.
    authorized: bool,
    /// The channel whose Begin left a servable walk, if any.
    owner: Option<u32>,
    /// The relying party the request named and the binding was checked against.
    /// Not the one the TOKEN is bound to: an unscoped token may manage any rp,
    /// which is what the first run of this harness refuted about D5's wording.
    rp: [u8; 32],
}

/// One `credentialManagement` *Begin*, from the demux's `cm.reset()` through
/// `authorize_cm`'s session-token arm to the cursor writes its call site makes.
///
/// `rps` picks which Begin, and it is a CONCRETE argument: each harness below
/// passes a literal, so the payload the MAC covers is concrete in both.
fn drive_begin(
    st: &mut FidoState,
    proto: PinProto,
    rps: bool,
    payload: &[u8],
    param: &[u8],
    forged: bool,
) -> Begin {
    let scoped = st.paut.has_rp_id;
    let perms0 = st.paut.permissions;
    let mine: bool = kani::any();
    // Full symbolic u16, as `state_kani.rs` uses. Narrowing it to a u8 was
    // measured and REFUTED as a saving: 305 s / 15.71 GiB against 311 s /
    // 13.35 GiB, which is SAT nondeterminism and not a shrink. A bound that buys
    // nothing costs coverage for nothing.
    let total: u16 = kani::any(); // how many records the scan found
    let late: bool = kani::any(); // `load_keydev()` answers None
    let second: bool = kani::any(); // which channel the Begin arrives on
    let want_rp = if mine { RP_OWNED } else { RP_OTHER };
    let chan = if second { W_C2 } else { W_C1 };
    st.channel = chan;

    // The demux, `credmgmt.rs:164`: past the two *Next* subcommands, every
    // credentialManagement command ends the walk in flight before anything else.
    st.cm.reset();

    // THE DECISION, and it is the real one: `authorize_cm`'s session-token arm,
    // in its own order (`credmgmt.rs:243-245`).
    let decided = verify_cm_token(st, proto, payload, param)
        .and_then(|()| check_rp_binding(st, if rps { None } else { Some(&want_rp) }));
    if decided.is_ok() {
        st.mark_token_used(NOW);
    }

    // The ghost, computed from the REQUEST and never read back out of `st`:
    // `forged` is the harness's own choice, not `verify_token`'s answer. Reading
    // the answer back would let one broken MAC satisfy D1 with another. That the
    // flag means what it says is D3's job, one level out.
    // §6.8.3: 0x02 names no rp, so a scoped token may not use it at all; 0x04
    // carries one and must match it.
    let authorized = !forged && perms0 & PERM_CM != 0 && (!scoped || (!rps && mine));

    // The Begin's body, verbatim from its call site, run only where the gate let
    // it — an empty scan refuses BEFORE the totals move (`credmgmt.rs:383-385`,
    // `:497-499`), which is why a zero total opens nothing.
    if authorized {
        if rps {
            st.cm.channel = st.channel;
            st.cm.rp_counter = 1;
            st.cm.rp_total = 0;
            st.cm.rp_next_slot = 0;
            if total > 0 {
                // `credmgmt.rs:386-393`, and every line of it is BEFORE the seed
                // load at `:398`.
                st.cm.rp_total = total;
                st.cm.rp_counter = 1u16.saturating_add(1);
                st.cm.last_leg_ms = NOW;
            }
        } else {
            st.cm.channel = st.channel;
            st.cm.cred_counter = 1;
            st.cm.cred_total = 0;
            st.cm.cred_next_slot = 0;
            // `credmgmt.rs:506-509`, and every line of it is AFTER the seed load
            // at `:501`. The opposite side from the walk above.
            if total > 0 && !late {
                st.cm.cred_total = total;
                st.cm.rp_id_hash = want_rp;
                st.cm.cred_counter = 1u16.saturating_add(1);
                st.cm.last_leg_ms = NOW;
            }
        }
    }
    let servable = total >= 2 && (rps || !late);
    Begin {
        decided: decided.is_ok(),
        authorized,
        owner: (authorized && servable).then_some(chan),
        rp: want_rp,
    }
}

/// The four claims, on both channels. Every one is an EQUALITY, so a device that
/// refuses everything fails them as surely as one that serves everybody.
fn check_begin(st: &FidoState, begin: &Begin, rps: bool) {
    kani::assert(
        begin.decided == begin.authorized,
        "NoAuthorizationBypass/D1: the Begin's gate admitted the wrong set of requests",
    );
    let rp_owner = if rps { begin.owner } else { None };
    let cred_owner = if rps { None } else { begin.owner };
    for probe in [W_C1, W_C2] {
        kani::assert(
            st.cm.may_walk_rps(probe) == (rp_owner == Some(probe)),
            "NoAuthorizationBypass/D2: the RP walk is servable to the wrong set of channels",
        );
        kani::assert(
            st.cm.may_walk_creds(probe) == (cred_owner == Some(probe)),
            "NoAuthorizationBypass/D2: the credential walk is servable to the wrong set of channels",
        );
    }
}

/// `NoAuthorizationBypass`, `enumerateRPsBegin` — the bounded, code-level
/// instance of the walk-owner clause taken **at its call site**.
///
/// `state_kani.rs`'s `no_authorization_bypass_walk_owner` proves what follows an
/// authorization it assumes: its `begin_rps` reproduces the cursor writes, and
/// the Begin's own gate — the `pinUvAuthParam` MAC, the `cm` permission bit and
/// the rpId binding — is never evaluated. The property is about the
/// authorization, so this drives the real one: [`verify_cm_token`] then
/// [`check_rp_binding`] then `mark_token_used`, in `authorize_cm`'s own order
/// (`credmgmt.rs:233-247`), behind the `cm.reset()` the subcommand demux
/// performs first (`credmgmt.rs:164`).
///
/// Four claims, and each is an equality:
///
/// - **D1** the decision: `Ok` exactly when the MAC verifies, the token carries
///   `cm`, and the rpId binding is satisfied. 0x02 names no rp, so §6.8.3 refuses
///   a scoped token here outright;
/// - **D2** the consequence, on **both** channels: the walk is servable exactly
///   to the channel whose *authorized* Begin opened it, and only where the store
///   held a second record. A refused Begin leaves neither cursor live, because
///   the demux's `cm.reset()` has already ended the walk in flight;
/// - **D3** lives in [`no_authorization_bypass_begin_mac_is_the_flag`], not here,
///   and the split is a measurement: a third HMAC-SHA-256 evaluation in this
///   harness cost 448 s and **14.5 GiB**, over the 16 GiB a hosted runner has.
///   Without it D1's `forged` flag would be an assumption; with it in its own
///   harness the flag is a proved fact and this one costs two evaluations;
/// - **D4** `enumerate_rps` writes `rp_total` at `credmgmt.rs:386-393`, BEFORE
///   the seed load at `:398`, so an authorized Begin that then fails to the host
///   leaves a live walk cursor behind. Not a bypass — the authorization had
///   already succeeded — and asserted here because "checked by hand" was the
///   reason it was written down rather than the reason it could be omitted.
///
/// What this does **not** prove: the persistent `pcmr` arm `authorize_cm` tries
/// first (`credmgmt.rs:240-242`) is in flash behind `get_sealed32`'s AEAD and out
/// of budget here, so this is the session-token arm only; the scan is a symbolic
/// total rather than a store, which over-approximates it past
/// `MAX_RESIDENT_CREDENTIALS`; one Begin from one starting state, not a sequence;
/// and the MAC is exercised on one concrete payload, so it says nothing about
/// `pinproto::verify` as a MAC.
#[kani::proof]
#[kani::stub(rsk_crypto::hmac_sha256, stub_hmac_sha256)]
fn no_authorization_bypass_rps_begin_at_call_site() {
    let mut rng = StepRng(0xC7);
    let mut st = FidoState::new();
    let proto = PinProto::Two;

    // Issuance in `clientpin.rs:420-434`'s order, with the permission set and the
    // rpId binding both symbolic — the two halves the Begin's gate reads.
    let perms0: u8 = kani::any();
    let scoped: bool = kani::any();
    st.reset_pin_uv_auth_token(&mut rng);
    st.begin_using_token(false, NOW);
    st.paut.permissions = perms0;
    st.paut.has_rp_id = scoped;
    st.paut.rp_id_hash = RP_OWNED;

    // A live RP walk on C1, written directly: it is this proof's PRECONDITION,
    // not its subject. That a Begin of either kind ends it is `state_kani.rs`'s
    // `W_OTHER_CM_SUBCOMMAND`; what is proved here is that a REFUSED one does too.
    st.cm.channel = W_C1;
    st.cm.rp_counter = 1;
    st.cm.rp_total = 2;

    let payload = [CM_ENUMERATE_RPS_BEGIN as u8];
    let mut param = [0u8; 32];
    let n = pinproto::authenticate(proto, &st.paut.token, &payload, &mut param)
        .expect("32-byte buffer fits a v2 MAC");
    let forged: bool = kani::any();
    if forged {
        param[0] ^= 1; // one bit of the tag, which a v2 verify compares in full
    }

    let begin = drive_begin(&mut st, proto, true, &payload, &param[..n], forged);
    check_begin(&st, &begin, true);
    // D4 — the seed failure lands on the far side of this call site's writes.
    kani::assert(
        begin.owner.is_none() || st.cm.may_walk_rps(begin.owner.unwrap()),
        "NoAuthorizationBypass/D4: enumerate_rps stopped writing rp_total before load_keydev",
    );

    // Non-vacuity, enforced by `scripts/kani.sh`'s cover row and not by Kani.
    kani::cover!(begin.owner == Some(W_C2)); // an authorized Begin really opens one
    kani::cover!(!begin.authorized && scoped && perms0 & PERM_CM != 0); // refused by the binding
}

/// `NoAuthorizationBypass`, `enumerateCredentialsBegin` — [`no_authorization_bypass_rps_begin_at_call_site`]
/// one subcommand over, and the three things that differ are the point of it
/// being its own harness rather than a branch inside that one.
///
/// - the MAC covers `subcommand ‖ <raw subCommandParams>` (`credmgmt.rs:190-192`)
///   rather than the bare subcommand byte, and it is built by the real
///   [`payload_with_subpara`];
/// - the request NAMES an rp, so §6.8.4's binding is a match rather than a
///   refusal: a scoped token may use this subcommand exactly for its own rp;
/// - **D5**, which the RP walk has no counterpart for: `enumerate_creds` writes
///   `cm.rp_id_hash` (`credmgmt.rs:508`) and the demux reads it back to serve a
///   *Next* (`:153-154`). `state_kani.rs`'s `begin_creds` never writes it, so the
///   rp a *Next* is served for was outside that harness's shape entirely. Here it
///   is asserted to be the rp **the request named**, which is what the binding
///   was checked against. Its first wording said the rp the TOKEN is bound to and
///   this harness refuted it in 305 s: an UNSCOPED token is authorized for any
///   rp, so the cursor legitimately holds one the token was never bound to.
///
/// And **D4 in the other direction**: `enumerate_creds` writes its totals AFTER
/// the seed load (`credmgmt.rs:501` then `:506-509`), so the same failure that
/// leaves an RP walk live leaves this one dead. The two call sites sit on
/// opposite sides of one call, which is the kind of thing a projection over the
/// guard alone cannot see.
///
/// Same limits as its sibling.
#[kani::proof]
#[kani::stub(rsk_crypto::hmac_sha256, stub_hmac_sha256)]
fn no_authorization_bypass_creds_begin_at_call_site() {
    let mut rng = StepRng(0xC8);
    let mut st = FidoState::new();
    let proto = PinProto::Two;

    let perms0: u8 = kani::any();
    let scoped: bool = kani::any();
    st.reset_pin_uv_auth_token(&mut rng);
    st.begin_using_token(false, NOW);
    st.paut.permissions = perms0;
    st.paut.has_rp_id = scoped;
    st.paut.rp_id_hash = RP_OWNED;

    st.cm.channel = W_C1;
    st.cm.rp_counter = 1;
    st.cm.rp_total = 2;

    let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
    let payload = payload_with_subpara(CM_ENUMERATE_CREDS_BEGIN, &RAW_SUBPARA, &mut pbuf)
        .expect("3 bytes fit MAX_RAW_SUBPARA");
    let mut param = [0u8; 32];
    let n = pinproto::authenticate(proto, &st.paut.token, payload, &mut param)
        .expect("32-byte buffer fits a v2 MAC");
    let forged: bool = kani::any();
    if forged {
        param[0] ^= 1;
    }

    let begin = drive_begin(&mut st, proto, false, payload, &param[..n], forged);
    check_begin(&st, &begin, false);
    // D4, the other side: the totals are written after the seed load here.
    kani::assert(
        begin.owner.is_some() || !st.cm.may_walk_creds(W_C1) && !st.cm.may_walk_creds(W_C2),
        "NoAuthorizationBypass/D4: enumerate_creds left a cursor a failed Begin should not have",
    );
    // D5 — a Next is served for the rp the Begin was authorized against.
    kani::assert(
        begin.owner.is_none() || st.cm.rp_id_hash == begin.rp,
        "NoAuthorizationBypass/D5: the credential cursor kept an rpId the Begin was not authorized for",
    );

    kani::cover!(begin.owner == Some(W_C2));
    kani::cover!(begin.authorized && scoped); // a scoped token serving its own rp
}
