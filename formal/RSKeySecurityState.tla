-------------------------- MODULE RSKeySecurityState --------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* A model of RS-Key's SECURITY STATE -- not of CTAP 2.3, not of the applets *)
(* and not of any wire format. It covers exactly the surface named in the    *)
(* mandate: PIN retries, the pinUvAuthToken and its permissions, rpId        *)
(* binding, the touch owner, the transport/channel owner, the reset window,  *)
(* the soft lock, the persistent gate records, and the position at which     *)
(* power is lost inside a multi-write sequence.                              *)
(*                                                                           *)
(* Every transition cites the Rust it models by file:line. Where the model   *)
(* deliberately abstracts (a clock replaced by nondeterminism, one           *)
(* credential per relying party), the comment says so. `formal/README.md`    *)
(* states what this does and does not cover; do not read a green TLC run as  *)
(* a claim about anything outside that list.                                 *)
(*                                                                           *)
(* THE METHOD. Each protected operation carries two predicates:              *)
(*   *Guard  -- what the Rust actually tests, mutable by a Bug* switch;      *)
(*   *Policy -- what the security requirement is, never mutated.             *)
(* When a Guard admits a step its Policy forbids, the step records the       *)
(* violated invariant's name in `viol`. That is what makes these invariants  *)
(* falsifiable rather than restatements of the code: the Bug* switches       *)
(* rebuild historical RS-Key defects, and each one must make TLC produce a   *)
(* counterexample. An invariant no mutant can break is a test that cannot    *)
(* fail.                                                                     *)
(*****************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    RPs,                \* relying parties (>= 2 to exercise rpId binding)
    Channels,           \* CTAPHID channel ids (>= 2 to exercise walk ownership)
    MaxRetries,         \* models MAX_PIN_RETRIES = 8   (consts.rs:330)
    MismatchLimit,      \* models PIN_MISMATCH_LIMIT = 3 (consts.rs:334)
    MaxClock,           \* coarse tick ceiling
    ResetWindow         \* models RESET_WINDOW_MS = 10_000 (consts.rs:366)

(* Mutation switches. All FALSE is the shipped tree. Each rebuilds one real  *)
(* defect; `formal/README.md` maps every switch to its commit or audit id.   *)
CONSTANTS
    BugResetGatesFirst,           \* reset.rs:58-59   two-phase wipe order
    BugCredBeforeRp,              \* credential.rs:808-827 registration order
    BugTokenSurvivesPinChange,    \* clientpin.rs:313  resetPinUvAuthToken
    BugSetPinKeepsPpuat,          \* clientpin.rs:214-218
    BugChangePinKeepsPpuat,       \* clientpin.rs:302-306
    BugStopUsingKeepsPerms,       \* state.rs:584-599  stopUsingPinUvAuthToken
    BugNoConsumeAfterUp,          \* state.rs:560-571  GHSA-wqjm-653g-hgw3
    \* the three below cite crates/rsk-device/src/presence.rs -- the bare name
    \* also resolves to firmware/src/presence.rs since the arbitration was lifted
    BugUnscopedCancel,            \* crates/rsk-device/src/presence.rs:118-122
    BugTouchNotSpent,             \* crates/rsk-device/src/presence.rs:203-211,226
    BugSoftLockLostOnWarmReset,   \* ctap.rs:215-222   PinLock across sys_reset
    BugWarmResetReopensWindow,    \* reset.rs:132-134  in_reset_window
    BugCmWalkIgnoresChannel,      \* state.rs:169-180  may_walk_rps
    BugDeleteRpBeforeCred,        \* credmgmt.rs:665-672 deleteCredential order
    BugBackupSealedNotAGate,      \* reset.rs:112-125  is_fido_gate_fid (run-36)
    BugConsumeKeepsMcGa,          \* state.rs:566-571  a narrowed 6.5.5.7 triad
    BugNoDropStaleCancelAtEntry,  \* crates/rsk-device/src/presence.rs:195-196
    BugWrongPinKeepsToken,        \* clientpin.rs:783  the pre-E38 tree
    BugSeedDoesNotLead,           \* reset.rs:62-66 / fs.rs `first`, pre-0x08BF
    BugNoTouchRequired,           \* the presence gate on mc / ga
    BugStateResetAfterWipe,       \* reset.rs:58-61 ctx.state.reset() ordering
    BugPanelCancelable,           \* the panel's half of request_cancel's scope test
    BugUnscopedOtpCancel,         \* crates/rsk-device/src/presence.rs:127
    BugLocalPinKeepsToken,        \* crates/rsk-display/src/gates.rs:146
    BugSetPinOverExisting,        \* clientpin.rs:185-187 setPIN over a live PIN
    BugHostPreemptsLocalWait,     \* the button's owner, taken by a host command
    BugLocalPinIgnoresBudget,     \* crates/rsk-display/src/gates.rs:126-128
    BugPpuatIsAGate,              \* eab4b5c: EF_PAUTHTOKEN in the deferred phase
    BugPinWriteBeforeRevoke       \* clientpin.rs:214-218, :300-304 -- the order

(* Mutation switches for the LIVENESS properties. Kept apart from the set above *)
(* because they break no invariant -- a wedge is a perfectly safe state -- so    *)
(* listing them in the safety matrix would mean 3 mutants nothing catches.       *)
CONSTANTS
    BugAssertWedgesOnTimeout,     \* getassertion.rs: only a confirm completes it
    BugWaitScopeNotCleared,       \* worker.rs:521  set_wait_scope(SCOPE_NONE)
    BugWalkNeverExpires           \* state.rs:657-663 expire_stale_sequences

(* A switch on the SHAPE of the fairness assumption rather than on a behaviour: *)
(* E160 verbatim, LocalCeremonyEnds folded back into OpAdvances, where          *)
(* WF over the disjunction lets the PIN ladder discharge a panel wait's         *)
(* obligation. It breaks an invariant, not a property, so it is neither a       *)
(* BUGS nor a LIVE_BUGS member and gets its own pair of configurations.         *)
CONSTANT BugFairnessFoldsLocalCeremony

(* A PROPOSED fix, not a defect: order phase 1 of the reset sweep so no EF_RP  *)
(* entry is dropped while its EF_CRED record is still live. The shipped        *)
(* `sweep` batches both in `for_each_key` order, which fs.rs:258-261 documents *)
(* as store order rather than FID order, so the batch can delete the metadata  *)
(* first. TRUE models the fix; FALSE is the tree as it stands.                 *)
CONSTANT FixSweepDropsCredsBeforeRpEntries

(* A second PROPOSED fix. `authorize_cm` consults the persistent grant FIRST   *)
(* and returns Ok with no PIN check (credmgmt.rs:240-242), so a leftover       *)
(* EF_PAUTHTOKEN on a PIN-less key still authorizes the three read            *)
(* subcommands. clientpin.rs:214-218 already names that torn state but closes  *)
(* only the exit where the user sets a PIN again. TRUE models refusing a       *)
(* persistent grant when EF_PIN is absent -- one owner, one line.              *)
CONSTANT FixPpuatRequiresPin

NoOwner == "none"          \* SCOPE_NONE            (crates/rsk-device/src/presence.rs:26)
Fido    == "fido"          \* SCOPE_FIDO -- CTAPHID (crates/rsk-device/src/presence.rs:28)
Ccid    == "ccid"          \* SCOPE_CCID -- CCID    (crates/rsk-device/src/presence.rs:30)
Otp     == "otp"           \* SCOPE_OTP             (crates/rsk-device/src/presence.rs:31-32)

\* SCOPE_NONE with a wait OPEN. The firmware stores one byte for two states --
\* "no host request is in flight" and "an on-panel flow owns the button"
\* (crates/rsk-device/src/presence.rs:25-26) -- and they are different states:
\* request_cancel refuses in both, but only one of them can be ENDED by a touch.
\* Collapsing them left the panel unable to own a ceremony at all, so a physical
\* hold spent on an on-panel flow was invisible to the one-hold-one-ceremony rule
\* and E45's ruling -- the panel owns the session -- had nothing to be true of.
Panel   == "panel"

\* The transports a CTAP-shaped ceremony can arrive on. Otp and Panel are wait
\* OWNERS but not hosts of a makeCredential, so they are not in here.
Transports == {Fido, Ccid}
Owners     == Transports \cup {Otp, Panel, NoOwner}

NoRp   == "norp"           \* PinUvAuthToken.has_rp_id = FALSE (state.rs:253)
NoChan == "nochan"

\* Relying parties and channels are interchangeable: no action, invariant or
\* initial state names a particular one, so a permutation maps behaviours to
\* behaviours and TLC may quotient by it. Safety configurations only -- its
\* liveness check is not sound under symmetry.
Symm == Permutations(RPs) \cup Permutations(Channels)

(* PERM_* bits, state.rs:22-28. Restricted to the sets a host actually asks  *)
(* for, which keeps the token's value space at 5 instead of 16: getPinToken  *)
(* 0x05 grants exactly {mc,ga} (clientpin.rs:388-392), and                   *)
(* consume_after_user_presence leaves {} (lbw only, state.rs:568).           *)
Perms    == {"mc", "ga", "cm", "acfg"}
PermSets == { {}, {"mc","ga"}, {"cm"}, {"acfg"}, {"ga","acfg"} }

Decisions == {"none", "confirm", "cancel", "timeout"}
OpKinds   == {"none", "assert", "register", "reset", "chpin", "setpin",
              "delcred"}

InvNames == { "NoAuthorizationBypass",
              "NoCrossTransportTouchConsumption",
              "NoTokenAfterInvalidation",
              "NoAccessibleSecretWithoutGate",
              "NoUnmanageableCredential",
              "ResetNeverWeakensSurvivingState" }

VARIABLES
    pin,    \* EF_PIN:  [set, retries, everSet]                (clientpin.rs:35)
    \* The gate records: [ppuat, ppuatStale, alwaysUv, backupSealed].
    \* `backupSealed` is EF_BACKUP_SEALED and it runs the other way round from
    \* the rest: its ABSENCE is the permissive state (reset.rs:112-119), so what
    \* a torn wipe can re-open is a window the owner had closed.
    gate,   \*                                                 (reset.rs:118-126)
    \* The secrets: [cred, rpent, seed]. `cred` and `rpent` are the records that
    \* still OPEN, not the records that still occupy a slot: every credential box,
    \* rpId box and EF_RP domain is sealed under the seed, and `credential_load` /
    \* `for_each_rp` are the chokepoints every reader goes through (a430f2d). So
    \* deleting the seed empties both here while the flash records remain, which
    \* is exactly what the shipped wipe buys and the only thing these invariants
    \* can be about -- an unopenable record is neither usable nor manageable.
    store,  \*                                                  (reset.rs:169-197)
    lock,   \* the soft lock: [soft, mism, policyMism]         (state.rs:285-293)
    tok,    \* device-side session token: [live, perms, rp]    (state.rs:248-262)
    plat,   \* the platform's copy: [held, verifies, revoked]  (ghost + wire)
    pres,   \* presence: [scope,cancelReq,cancelBy,granted,pressing,spent,usedBy]
    walk,   \* credentialManagement enumerate cursor: [open, chan] (state.rs:109)
    sys,    \* [warmBoot, clock]                               (state.rs:373-383)
    op,     \* the in-flight multi-flash-write sequence: [kind, t, rp, step]
    \* Ghost snapshot taken when a reset's touch lands:
    \* [seen, pin, auv, surv, seed, sealed]. `surv` starts as the credentials
    \* that existed then and only ever SHRINKS, as the sweep deletes them. It
    \* must not grow on a later registration, or the relational claim would
    \* blame the reset for a credential created after it -- on a key whose PIN
    \* the user knowingly erased. `seed` is the same discipline for the master
    \* seed: TRUE while the OWNER's seed is still the live one, cleared the
    \* moment the sweep deletes it, so a seed a boot regenerated afterwards is
    \* never mistaken for the one the reset was handed.
    snap,
    upSpent,\* ghost: a user-presence test has been spent since the token issued
    viol,   \* ghost: the set of invariant names some step has violated
    \* `state.keydev_dec` (state.rs:360-362): the seed a vendor UNLOCK decrypted
    \* into RAM on a soft-locked device. NOT a second seed -- it is the SAME
    \* owner's seed by another route, and `Ctx::load_keydev` PREFERS it
    \* (crates/rsk-fido/src/lib.rs:183-187), so deleting the flash record does
    \* not end reachability
    \* while this stands. That preference is the whole of E110: the model used to
    \* have only the flash record, so a wipe whose flash half succeeded read as
    \* "the seed is gone" when the power cycle was still running on this copy.
    ram

vars == << pin, gate, store, lock, tok, plat, pres, walk, sys, op, snap,
           upSpent, viol, ram >>

NoOp == [kind |-> "none", t |-> NoOwner, rp |-> NoRp, step |-> 0]

\* Retiring the reset snapshot. ResetNeverWeakensSurvivingState compares the
\* state a reset was handed against the state the RESET produced, so any later
\* AUTHORIZED gate change -- an authenticatorConfig toggling alwaysUv, a
\* setPIN, a changePIN -- ends the comparison. Without this the claim would
\* blame a torn reset for a decision the owner made afterwards with a token.
NoSnap == [seen |-> FALSE, pin |-> FALSE, auv |-> FALSE, surv |-> {},
           seed |-> FALSE, sealed |-> FALSE]

TypeOK ==
    /\ pin   \in [set: BOOLEAN, retries: 0..MaxRetries, everSet: BOOLEAN]
    /\ gate  \in [ppuat: BOOLEAN, ppuatStale: BOOLEAN, alwaysUv: BOOLEAN,
                  backupSealed: BOOLEAN]
    /\ store \in [cred: SUBSET RPs, rpent: SUBSET RPs, seed: BOOLEAN]
    /\ lock  \in [soft: BOOLEAN, mism: 0..MismatchLimit,
                  policyMism: 0..MismatchLimit]
    /\ tok   \in [live: BOOLEAN, perms: PermSets, rp: RPs \cup {NoRp}]
    /\ plat  \in [held: BOOLEAN, verifies: BOOLEAN, revoked: BOOLEAN]
    /\ pres  \in [scope: Owners, cancelReq: BOOLEAN,
                  cancelBy: Owners, granted: Decisions,
                  pressing: BOOLEAN, spent: BOOLEAN,
                  usedBy: Owners]
    /\ walk  \in [open: BOOLEAN, chan: Channels \cup {NoChan}]
    /\ sys   \in [warmBoot: BOOLEAN, clock: 0..MaxClock]
    /\ op    \in [kind: OpKinds, t: Owners,
                  rp: RPs \cup {NoRp}, step: 0..3]
    /\ snap  \in [seen: BOOLEAN, pin: BOOLEAN, auv: BOOLEAN,
                  surv: SUBSET RPs, seed: BOOLEAN, sealed: BOOLEAN]
    /\ upSpent \in BOOLEAN
    /\ viol  \in SUBSET InvNames
    /\ ram   \in BOOLEAN

Init ==
    /\ pin   = [set |-> FALSE, retries |-> MaxRetries, everSet |-> FALSE]
    /\ gate  = [ppuat |-> FALSE, ppuatStale |-> FALSE, alwaysUv |-> FALSE,
                backupSealed |-> FALSE]
    /\ store = [cred |-> {}, rpent |-> {}, seed |-> TRUE]
    /\ lock  = [soft |-> FALSE, mism |-> 0, policyMism |-> 0]
    /\ tok   = [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat  = [held |-> FALSE, verifies |-> FALSE, revoked |-> FALSE]
    /\ pres  = [scope |-> NoOwner, cancelReq |-> FALSE, cancelBy |-> NoOwner,
                granted |-> "none", pressing |-> FALSE, spent |-> FALSE,
                usedBy |-> NoOwner]
    /\ walk  = [open |-> FALSE, chan |-> NoChan]
    /\ sys   = [warmBoot |-> FALSE, clock |-> 0]
    /\ op    = NoOp
    /\ snap  = NoSnap
    /\ upSpent = FALSE
    /\ viol  = {}
    /\ ram   = FALSE

(***************************************************************************)
(* The seed's TWO homes. Every credential box, rpId box, credBlob,          *)
(* hmac-secret key and large-blob key is derived from the device seed       *)
(* (reset.rs:116-120), and `Ctx::load_keydev` reads it from RAM first and   *)
(* flash second (crates/rsk-fido/src/lib.rs:183-187). So "the records still  *)
(* open" is a claim                                                         *)
(* about BOTH, and the wipe's own claim -- that what a tear leaves behind is *)
(* undecryptable -- holds only once the last copy is gone.                   *)
(***************************************************************************)

SeedReachable == store.seed \/ ram

\* What is left openable once `reach` is the whole truth about the seed. The
\* records themselves stay on flash either way; `store.cred` / `store.rpent`
\* mean the records that still OPEN, so losing the last copy empties them and
\* takes the reset snapshot's survivors with it.
KeepOpen(s, reach) == IF reach THEN s ELSE [s EXCEPT !.cred = {}, !.rpent = {}]
KeepSurv(sn, reach) == IF reach THEN sn
                                ELSE [sn EXCEPT !.seed = FALSE, !.surv = {}]

(***************************************************************************)
(* Presence -- one physical button serves every applet, so the wait carries *)
(* an owner. crates/rsk-device/src/presence.rs:25-169, 190-250.            *)
(***************************************************************************)

Idle == op.kind = "none"
WaitOpen == pres.scope # NoOwner /\ pres.granted = "none"

\* ONE BUTTON, ONE CEREMONY: a host command may not open a wait over one that is
\* already running. The worker is synchronous and the panel yields to a queued
\* host command only outside a hold (crates/rsk-display/src/lib.rs:190-196), so
\* the firmware never reassigns WAIT_SCOPE out from under a live ceremony.
\*
\* FOUR sites carry it: RegisterStart, AssertStart, ResetStart and
\* LocalCeremonyStart. BugHostPreemptsLocalWait keeps the name of the case it was
\* found on -- a host command over a live on-panel ceremony -- and loosens all
\* four, because it is one rule with one meaning.
\*
\* This was an enabling conjunct on all three *Start actions and nothing more,
\* which is the family that hid the presence gate over 9 658 460 states: a step
\* that is merely never ENABLED cannot notice a build that stopped refusing.
\* Removing it let a host command take the button from a live on-panel ceremony
\* and left the reachable space BIT-IDENTICAL at 79 985 500 -- zero new states,
\* because OpenWaitFor overwrites scope, cancelReq, cancelBy and granted, so
\* nothing was left to record who owned the wait first. That is E45's ruling
\* having nothing to be true of, one layer up from the cancel.
ButtonFreeGuard  == IF BugHostPreemptsLocalWait THEN TRUE
                                                ELSE pres.scope = NoOwner
ButtonFreePolicy == pres.scope = NoOwner

\* ButtonWait::wait entry: crates/rsk-device/src/presence.rs:195-196 drops a
\* cancel left over from an already-finished request, so each wait starts clean.
\* It is the ONLY thing that eats a cancel latched by a dispatch that never
\* waited -- see HostCancelLatched; the exit clear at :225-226 cannot help there.
OpenWaitFor(t) ==
    IF BugNoDropStaleCancelAtEntry
      THEN [pres EXCEPT !.scope = t, !.granted = "none"]
      ELSE [pres EXCEPT !.scope = t, !.cancelReq = FALSE, !.cancelBy = NoOwner,
                        !.granted = "none"]

\* The dispatch is over; set_wait_scope(SCOPE_NONE) so an on-panel ceremony is
\* nobody's to cancel (crates/rsk-device/src/presence.rs:103-105), and
\* :226 clears a cancel that raced in.
ClosedWait(p) ==
    IF BugWaitScopeNotCleared
      THEN [p EXCEPT !.cancelReq = FALSE, !.cancelBy = NoOwner,
                     !.granted = "none"]
      ELSE [p EXCEPT !.scope = NoOwner, !.cancelReq = FALSE,
                     !.cancelBy = NoOwner, !.granted = "none"]

\* The user's finger. PressUp clears `spent` exactly as
\* crates/rsk-device/src/presence.rs:210 does.
\* `usedBy` is a ghost naming the transport that has already been served by the
\* CURRENT continuous hold, so it is cleared by every release: a second press
\* is a second consent, and only an uninterrupted hold can be double-spent.
PressDown ==
    /\ ~pres.pressing
    /\ pres' = [pres EXCEPT !.pressing = TRUE, !.usedBy = NoOwner]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

PressUp ==
    /\ pres.pressing
    /\ pres' = [pres EXCEPT !.pressing = FALSE, !.spent = FALSE,
                            !.usedBy = NoOwner]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

\* CTAPHID_CANCEL for the channel being processed. rsk-usb ctaphid.rs:757-762
\* raises it; crates/rsk-device/src/presence.rs:118-122 is the scope check that decides
\* whether it may end THIS wait. Only the CTAPHID transport can send one.
\* E45's ruling in one line: request_cancel accepts ONLY while the wait it would
\* end belongs to CTAPHID, so a host cancel is a no-op against a CCID ceremony,
\* an OTP one, and an on-panel one -- "an on-panel ceremony is nobody's to
\* cancel". BugPanelCancelable loosens exactly the panel half of that test, which
\* is the narrow mistake somebody could make while keeping the CCID half.
CancelGuard  == IF BugUnscopedCancel THEN TRUE
                ELSE IF BugPanelCancelable THEN pres.scope \in {Fido, Panel}
                ELSE pres.scope = Fido
HostCancel ==
    /\ WaitOpen
    /\ CancelGuard
    /\ pres' = [pres EXCEPT !.cancelReq = TRUE, !.cancelBy = Fido]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

\* WAIT_SCOPE is set around the whole DISPATCH (worker.rs:429, :521), not around
\* the touch wait, so Arbiter::request_cancel accepts a cancel during a FIDO
\* command that never opens one -- getInfo, a denied CBOR, getAssertion up:false.
\* Nothing clears `cancel_requested` when that dispatch ends, so the latch
\* survives into the next transport's wait and only the wait-entry clear eats it.
\* Modelling the cancel as raisable ONLY inside an open wait made that defence
\* look redundant. Wider than the firmware in one direction (a CCID dispatch
\* holds SCOPE_CCID, which request_cancel refuses) -- sound for safety.
HostCancelLatched ==
    /\ pres.scope = NoOwner
    /\ ~pres.cancelReq
    /\ pres' = [pres EXCEPT !.cancelReq = TRUE, !.cancelBy = Fido]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

\* crates/rsk-device/src/presence.rs:203-208: a press the previous
\* ceremony already consumed is not
\* consent for this one. `stillHeld` is the debounce at :277-288 giving up with
\* the finger down (TRUE) or the user releasing (FALSE); both are reachable.
TouchConfirm ==
    /\ WaitOpen
    /\ pres.pressing
    /\ ~pres.spent
    /\ \E stillHeld \in BOOLEAN :
         pres' = [pres EXCEPT !.granted = "confirm",
                              !.pressing = stillHeld,
                              !.spent = IF BugTouchNotSpent THEN FALSE
                                                            ELSE stillHeld,
                              !.usedBy = IF stillHeld THEN pres.scope
                                                      ELSE NoOwner]
    \* One physical hold may satisfy at most one transport's ceremony.
    /\ viol' = IF pres.usedBy \in {NoOwner, pres.scope}
                 THEN viol
                 ELSE viol \cup {"NoCrossTransportTouchConsumption"}
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, ram >>

\* crates/rsk-device/src/presence.rs:212-214. A cancel raised by
\* transport A must never end a wait
\* owned by transport B.
TouchCancel ==
    /\ WaitOpen
    /\ pres.cancelReq
    /\ pres' = [pres EXCEPT !.granted = "cancel"]
    /\ viol' = IF pres.cancelBy = pres.scope
                 THEN viol
                 ELSE viol \cup {"NoCrossTransportTouchConsumption"}
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, ram >>

\* crates/rsk-device/src/presence.rs:215-217. Modelled as always
\* enabled rather than tied to the
\* clock: an over-approximation (more behaviours), sound for safety.
TouchTimeout ==
    /\ WaitOpen
    /\ pres' = [pres EXCEPT !.granted = "timeout"]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

\* THE PANEL AND THE OTP FRAME PROTOCOL ALSO OPEN WAITS, and neither is a host's
\* to cancel. An on-panel ceremony -- Settings, Backup's reveal-recovery hold,
\* the Passkeys delete -- runs BETWEEN dispatches, where the worker has left
\* WAIT_SCOPE at SCOPE_NONE (firmware/src/worker.rs:519-521); an OTP frame's wait
\* runs under SCOPE_OTP (firmware/src/worker.rs:652-654). Both clear a stale
\* cancel at their own wait's entry -- the panel in its own loop
\* (crates/rsk-display/src/presence.rs:45-48), not in ButtonWait::wait -- so
\* OpenWaitFor stands for two different drops here and
\* BugNoDropStaleCancelAtEntry removes both at once.
\*
\* NARROWER than a display build in one way, stated because it is the risk
\* direction: that build compiles ButtonWait out entirely
\* (firmware/src/presence.rs:99-106) and the panel's own release debounce takes
\* over the `spent` latch, so the model keeps a defence the display build
\* implements somewhere else rather than one it does not have.
\* THE FOURTH SITE OF THE SAME RULE, and it was the one still written as a bare
\* conjunct after the other three got their Policy. `pres.scope = NoOwner` here
\* is one-hold-one-ceremony seen from the panel's side; removing it let an OTP
\* frame take the button from a live on-panel flow and back, and left the
\* reachable space BIT-IDENTICAL at 7 903 336 states (reduced constants) with
\* 4.8 M extra transitions -- the same mechanism as the host half, since
\* OpenWaitFor overwrites scope, cancelReq, cancelBy and granted and leaves
\* nothing to record who held it first.
LocalCeremonyStart(o) ==
    /\ Idle
    /\ ButtonFreeGuard
    /\ viol' = IF ButtonFreePolicy THEN viol
                                   ELSE viol \cup {"NoAuthorizationBypass"}
    /\ pres' = OpenWaitFor(o)
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, ram >>

\* The ceremony ends and WAIT_SCOPE goes back to SCOPE_NONE.
LocalCeremonyEnds ==
    /\ pres.scope \in {Otp, Panel}
    /\ pres.granted # "none"
    /\ pres' = ClosedWait(pres)
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

\* cancel_otp_wait (crates/rsk-device/src/presence.rs:126-137): the host's dummy
\* 0x8f write, or a frame that supersedes the wait, ends an OTP ceremony. It is a
\* SECOND writer of the same `cancel_requested` AtomicBool the CTAPHID door
\* writes, and the only thing keeping the two apart is its own scope test -- the
\* same shape of defence, in a different function, which is why it needs its own
\* mutant rather than riding BugUnscopedCancel.
OtpCancelGuard == IF BugUnscopedOtpCancel THEN TRUE ELSE pres.scope = Otp
OtpCancelWait ==
    /\ WaitOpen
    /\ OtpCancelGuard
    /\ pres' = [pres EXCEPT !.cancelReq = TRUE, !.cancelBy = Otp]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol, ram >>

(***************************************************************************)
(* Authorization. Guard = the Rust; Policy = the requirement.              *)
(***************************************************************************)

\* THE FOUR CALL SITES DO NOT TEST THE SAME THING, and the difference is
\* load-bearing. makeCredential (makecredential.rs:488-491) and getAssertion
\* (getassertion.rs:384-387) test the MAC, `user_verified()` -- which is
\* `in_use && user_verified` (state.rs:666-668) -- the permission bit and the
\* rpId binding. authenticatorConfig (config.rs:222-224) and
\* credentialManagement (credmgmt.rs:278) test the MAC and the permission bit
\* ONLY: neither consults `in_use`.
\*
\* So for those two the sole thing separating a stopped or expired token from a
\* live authorization is that stopUsingPinUvAuthToken ALSO zeroes the
\* permissions (state.rs:589-590). `verify_token` is a MAC over bytes that stay
\* put, so it keeps succeeding. Modelling one uniform guard hid that, and hid
\* the BugStopUsingKeepsPerms mutant with it.
TokenGuardUv(p, rp) ==
    /\ plat.held /\ plat.verifies
    /\ tok.live                            \* user_verified(): in_use && uv
    /\ p \in tok.perms
    /\ (tok.rp = NoRp \/ tok.rp = rp)      \* getassertion.rs:387 rpId binding

\* config.rs:222-224 / credmgmt.rs:278 -- no `in_use` conjunct exists here.
TokenGuardBare(p, rp) ==
    /\ plat.held /\ plat.verifies
    /\ p \in tok.perms
    /\ (tok.rp = NoRp \/ tok.rp = rp)

\* The requirement: same, but keyed on whether the grant has been revoked
\* rather than on whether the device happened to rotate the bytes.
TokenPolicy(p, rp) ==
    /\ plat.held /\ ~plat.revoked
    /\ tok.live
    /\ p \in tok.perms
    /\ (tok.rp = NoRp \/ tok.rp = rp)

\* UV is required when a clientPIN exists or alwaysUv is on; otherwise a touch
\* alone authorizes (getassertion.rs:385 `if uv_required`).
UvRequired == pin.set \/ gate.alwaysUv

OpGuard(p, rp)  == IF UvRequired THEN TokenGuardUv(p, rp) ELSE TRUE
OpPolicy(p, rp) == IF UvRequired THEN TokenPolicy(p, rp) ELSE TRUE

\* The names ONE admitted-but-unauthorized token step records. The four sibling
\* call sites used to disagree -- makeCredential/getAssertion wrote both,
\* authenticatorConfig only the first, the two credentialManagement sites only
\* the second -- so a Solo_* run coming back green meant either "not violated"
\* or "violated under the other name", and there was no way to tell which.
\* Every one of them is a protected operation, so a step its Policy forbids is
\* NoAuthorizationBypass; it is ALSO NoTokenAfterInvalidation exactly when what
\* got through was a grant the device had already retired or revoked.
TokenBypass ==
    {"NoAuthorizationBypass"}
      \cup (IF tok.live /\ ~plat.revoked
              THEN {} ELSE {"NoTokenAfterInvalidation"})

\* CTAP 2.1 6.5.5.7 post-user-presence triad (state.rs:560-571). Spending the
\* token down to largeBlobWrite is what stops a follow-on authenticatorConfig
\* riding the touch that a getAssertion just collected (GHSA-wqjm-653g-hgw3).
\* BugConsumeKeepsMcGa is the narrow fix somebody could have written for that
\* advisory instead: strip the config-carrying permissions and leave the
\* getPinToken 0x05 pair standing, so a SECOND assertion still rides the touch
\* the first one collected. It is here because the model could not see it --
\* `upSpent` had exactly one reader, ConfigPolicy.
ConsumedTok ==
    IF BugNoConsumeAfterUp \/ ~tok.live
      THEN tok
      ELSE IF BugConsumeKeepsMcGa /\ tok.perms = {"mc", "ga"}
             THEN tok
             ELSE [tok EXCEPT !.perms = {}]

\* makeCredential/getAssertion bind an unbound pinUvAuthToken to the request's
\* rpId before consuming its permissions (makecredential.rs:496-498,
\* getassertion.rs:394-396).
BoundConsumedTok(r) ==
    LET consumed == ConsumedTok IN
      IF tok.live /\ tok.rp = NoRp
        THEN [consumed EXCEPT !.rp = r]
        ELSE consumed

(***************************************************************************)
(* clientPIN. clientpin.rs:318-395 (getPinToken) and :718-803 (the verify). *)
(***************************************************************************)

\* clientpin.rs:343-346 -- a PIN must exist, have budget, and the RAM soft lock
\* must not be engaged. clientpin.rs:739 self-defends the decrement at zero.
PinAttemptEnabled == pin.set /\ pin.retries > 0 /\ ~lock.soft

\* The requirement the soft lock encodes: after MismatchLimit consecutive
\* mismatches no further attempt is accepted until a REAL power cycle. The
\* policy counter is cleared only by PowerCut, never by a host-requested warm
\* reset -- which is the whole point of ctap.rs:215-222.
PinAttemptPolicy == pin.set /\ pin.retries > 0 /\ lock.policyMism < MismatchLimit

\* clientpin.rs:742-808. The lockout ladder: spend, read back, compare.
PinAttempt(correct) ==
    /\ Idle
    /\ PinAttemptEnabled
    /\ viol' = IF PinAttemptPolicy THEN viol
                                   ELSE viol \cup {"NoAuthorizationBypass"}
    /\ IF correct
         THEN \* clientpin.rs:802-803 reset the budget and the mismatch batch.
              /\ pin' = [pin EXCEPT !.retries = MaxRetries]
              /\ lock' = [soft |-> FALSE, mism |-> 0, policyMism |-> 0]
         ELSE LET r == pin.retries - 1 IN
              /\ pin' = [pin EXCEPT !.retries = r]
              /\ lock' = IF r = 0
                           THEN lock            \* clientpin.rs:784-789 hard lock
                           ELSE [lock EXCEPT
                                   !.mism = lock.mism + 1,
                                   !.policyMism =
                                      IF lock.policyMism < MismatchLimit
                                        THEN lock.policyMism + 1
                                        ELSE lock.policyMism,
                                   !.soft = (lock.mism + 1) >= MismatchLimit]

\* getPinUvAuthTokenUsingPinWithPermissions: a correct PIN mints a fresh
\* session token (clientpin.rs:418-431) and resets the credMgmt cursor
\* (state.rs:525-539).
GetPinToken(ps, r) ==
    /\ PinAttempt(TRUE)
    /\ ps \in PermSets
    /\ r \in RPs \cup {NoRp}
    /\ tok'  = [live |-> TRUE, perms |-> ps, rp |-> r]
    /\ plat' = [held |-> TRUE, verifies |-> TRUE, revoked |-> FALSE]
    /\ walk' = [open |-> FALSE, chan |-> NoChan]
    /\ upSpent' = FALSE
    /\ UNCHANGED << gate, store, pres, sys, op, snap, ram >>

\* clientpin.rs:775 regenerates the ECDH key on a mismatch and :779 drops any
\* outstanding pinUvAuthToken with it, through all three doors -- measured off a
\* YubiKey rather than taken from the spec, and it is the safe direction. The
\* model used to say the token was untouched here, which is the tree as it stood
\* BEFORE that landed; BugWrongPinKeepsToken is that tree.
WrongPin ==
    /\ PinAttempt(FALSE)
    /\ tok'  = IF BugWrongPinKeepsToken
                 THEN tok ELSE [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat' = [plat EXCEPT !.verifies = IF BugWrongPinKeepsToken
                                           THEN plat.verifies ELSE FALSE,
                            !.revoked = TRUE]
    \* reset_pin_uv_auth_token calls cm.reset() (state.rs:529): the cursor dies
    \* with the token that granted it.
    /\ walk' = IF BugWrongPinKeepsToken THEN walk
                                        ELSE [open |-> FALSE, chan |-> NoChan]
    /\ UNCHANGED << gate, store, pres, sys, op, snap, upSpent, ram >>

\* getPinUvAuthTokenUsingPinWithPermissions with `pcmr`: mints the PERSISTENT
\* token, a flash record that outlives the power cycle (clientpin.rs:411-416,
\* seed.rs:290-301). Holding it IS the grant (credmgmt.rs:249-266).
MintPpuat ==
    /\ PinAttempt(TRUE)
    /\ gate' = [gate EXCEPT !.ppuat = TRUE, !.ppuatStale = FALSE]
    /\ UNCHANGED << store, tok, plat, pres, walk, sys, op, snap, upSpent,
                    ram >>

(***************************************************************************)
(* THE PANEL'S PIN PAD IS A FOURTH DOOR ONTO EF_PIN.                       *)
(* crates/rsk-display/src/gates.rs:114-200 (`local_pin_gate`).             *)
(***************************************************************************)

\* It spends the SAME persistent retry counter the wire path spends -- a correct
\* PIN refills it, a wrong one costs a try -- because
\* `spend_and_verify_local_pin` is `spend_and_verify_pin_at(EF_PIN, ..)`
\* (crates/rsk-fido/src/clientpin.rs:1023-1029). What it deliberately does NOT
\* touch is the CTAP session: no ECDH regeneration, no RAM 3-strikes lock, no
\* journal (crates/rsk-fido/src/clientpin.rs:1017-1021). So this is not a
\* PinAttempt: the pad neither consults `lock.soft` nor arms it, and the
\* persistent 8-try counter is the whole gate. A host-soft-locked device still
\* takes PIN entry at the pad, which is the documented recovery.
\* The budget test is the gate, and the model's own comment called it "the real
\* gate" while nothing could see it move: deleting it left the reachable space
\* BIT-IDENTICAL at 79 985 500 states. `spend_and_verify_pin_at` refuses at zero
\* before any compare and a correct PIN at zero must not refill
\* (crates/rsk-fido/src/clientpin.rs:1057-1059), which is the same shape
\* PinAttemptEnabled / PinAttemptPolicy carry for the wire path.
LocalPinGuard  == IF BugLocalPinIgnoresBudget THEN pin.set
                                              ELSE pin.set /\ pin.retries > 0
LocalPinPolicy == pin.set /\ pin.retries > 0
LocalPinEnabled == Idle /\ LocalPinGuard

\* E66. A clientPIN refused at the pad is changePIN's failed old-PIN check
\* performed locally, and over USB that check ends the host's outstanding
\* pinUvAuthToken (clientpin.rs:783) -- so it must here too, or the panel is a
\* door the revocation rule does not cover. `ends_host_token`
\* (crates/rsk-display/src/gates.rs:139-146) is the Rust's own test and it is
\* deliberately narrow in two ways the model reproduces: the FIDO scope only (the
\* device PIN is no CTAP credential, and EF_DEVICE_PIN is not modelled), and only
\* with budget left to spend, because a `Blocked` verdict reached at zero was
\* turned away before any compare -- which `LocalPinEnabled` already excludes.
\*
\* Modelled as taking effect at once. The hook is consumed at the head of the
\* next CBOR dispatch (crates/rsk-device/src/ctap.rs:184-187), not inside
\* gates.rs, but nothing can use the token in between: every command that reads
\* it is a CBOR command and the flag is spent before the dispatch runs.
LocalPinWrong ==
    /\ LocalPinEnabled
    /\ viol' = IF LocalPinPolicy THEN viol
                                 ELSE viol \cup {"NoAuthorizationBypass"}
    /\ pin'  = [pin EXCEPT !.retries = IF pin.retries > 0
                                         THEN pin.retries - 1 ELSE 0]
    /\ tok'  = IF BugLocalPinKeepsToken
                 THEN tok ELSE [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat' = [plat EXCEPT !.verifies = IF BugLocalPinKeepsToken
                                           THEN plat.verifies ELSE FALSE,
                            !.revoked = TRUE]
    /\ walk' = IF BugLocalPinKeepsToken THEN walk
                                        ELSE [open |-> FALSE, chan |-> NoChan]
    /\ UNCHANGED << gate, store, lock, pres, sys, op, snap, upSpent, ram >>

\* A correct PIN at the pad refills the persistent budget
\* (crates/rsk-fido/src/clientpin.rs:1023-1029) and grants NOTHING host-visible:
\* no token, no `pcmr`, no CCID security status. It also leaves the RAM soft lock
\* armed, which fails closed -- the host stays blocked until a replug.
LocalPinOk ==
    /\ LocalPinEnabled
    /\ viol' = IF LocalPinPolicy THEN viol
                                 ELSE viol \cup {"NoAuthorizationBypass"}
    /\ pin' = [pin EXCEPT !.retries = MaxRetries]
    /\ UNCHANGED << gate, store, lock, tok, plat, pres, walk, sys, op, snap,
                    upSpent, ram >>

(***************************************************************************)
(* setPIN / changePIN -- multi-write, so a power cut has a position.        *)
(***************************************************************************)

\* clientpin.rs:185-187: a PIN already set may only be replaced by changePIN,
\* which spends a retry and verifies the old one. setPIN carries no such check,
\* so this test IS the authorization -- and it needs a Policy like every other
\* gate here, not just an enabling conjunct. A step that is merely never ENABLED
\* over a live PIN cannot notice a build that stopped refusing: remove it and a
\* stranger sets their own PIN, mints a token and reads the credential directory,
\* which every invariant here stayed green over for 21 393 948 states.
SetPinGuard  == IF BugSetPinOverExisting THEN TRUE ELSE ~pin.set
SetPinPolicy == ~pin.set

SetPinStart ==
    /\ Idle
    /\ SetPinGuard
    /\ viol' = IF SetPinPolicy THEN viol
                               ELSE viol \cup {"NoAuthorizationBypass"}
    /\ op' = [kind |-> "setpin", t |-> Fido, rp |-> NoRp, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, ram >>

\* THE ORDER IS THE REQUIREMENT, at both PIN flows (clientpin.rs:214-218 and
\* :300-304, step 15 of 6.5.5.6). Revoke the persistent grant BEFORE the new
\* verifier lands, or a power cut between the two writes leaves the old holder
\* authorized against a PIN they no longer know -- and with the new PIN in place
\* FixPpuatRequiresPin's consumer check is satisfied too, so the one defence
\* downstream agrees. It was step sequencing and nothing else: swapping the two
\* writes left every invariant GREEN over 55 425 408 states.
PinVerifierLandsPolicy == ~gate.ppuat

SetPinClearPpuat ==
    /\ op.kind = "setpin"
    /\ op.step = (IF BugPinWriteBeforeRevoke THEN 1 ELSE 0)
    /\ gate' = IF BugSetPinKeepsPpuat
                 THEN [gate EXCEPT !.ppuatStale = TRUE]
                 ELSE [gate EXCEPT !.ppuat = FALSE, !.ppuatStale = FALSE]
    /\ op' = IF BugPinWriteBeforeRevoke THEN NoOp ELSE [op EXCEPT !.step = 1]
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, viol, ram >>

SetPinWrite ==
    /\ op.kind = "setpin"
    /\ op.step = (IF BugPinWriteBeforeRevoke THEN 0 ELSE 1)
    /\ viol' = IF PinVerifierLandsPolicy THEN viol
                                          ELSE viol \cup {"NoTokenAfterInvalidation"}
    /\ pin' = [set |-> TRUE, retries |-> MaxRetries, everSet |-> TRUE]
    /\ lock' = [lock EXCEPT !.soft = FALSE, !.mism = 0, !.policyMism = 0]
    /\ op' = IF BugPinWriteBeforeRevoke THEN [op EXCEPT !.step = 1] ELSE NoOp
    /\ snap' = NoSnap
    /\ UNCHANGED << gate, store, tok, plat, pres, walk, sys, upSpent, ram >>

ChangePinStart == \* clientpin.rs:237-278: gates, then spend-and-verify.
    /\ PinAttempt(TRUE)
    /\ op' = [kind |-> "chpin", t |-> Fido, rp |-> NoRp, step |-> 0]
    /\ UNCHANGED << gate, store, tok, plat, pres, walk, sys, snap, upSpent,
                    ram >>

\* clientpin.rs:302-306, step 15 of 6.5.5.6: revoke the persistent grant BEFORE
\* the new verifier lands, or a power cut leaves the old holder authorized
\* against a PIN they no longer know.
ChangePinClearPpuat ==
    /\ op.kind = "chpin"
    /\ op.step = (IF BugPinWriteBeforeRevoke THEN 1 ELSE 0)
    /\ gate' = IF BugChangePinKeepsPpuat
                 THEN [gate EXCEPT !.ppuatStale = TRUE]
                 ELSE [gate EXCEPT !.ppuat = FALSE, !.ppuatStale = FALSE]
    /\ op' = [op EXCEPT !.step = IF BugPinWriteBeforeRevoke THEN 2 ELSE 1]
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, viol, ram >>

ChangePinWrite == \* clientpin.rs:307 store_new_pin
    /\ op.kind = "chpin"
    /\ op.step = (IF BugPinWriteBeforeRevoke THEN 0 ELSE 1)
    /\ viol' = IF PinVerifierLandsPolicy THEN viol
                                          ELSE viol \cup {"NoTokenAfterInvalidation"}
    /\ pin' = [pin EXCEPT !.retries = MaxRetries, !.everSet = TRUE]
    /\ lock' = [lock EXCEPT !.soft = FALSE, !.mism = 0, !.policyMism = 0]
    /\ op' = [op EXCEPT !.step = IF BugPinWriteBeforeRevoke THEN 1 ELSE 2]
    /\ snap' = NoSnap
    /\ UNCHANGED << gate, store, tok, plat, pres, walk, sys, upSpent, ram >>

\* clientpin.rs:313 resetPinUvAuthToken -- RAM only, and it must end every
\* session credential the old PIN authorized (state.rs:525-539).
ChangePinRotateToken ==
    /\ op.kind = "chpin" /\ op.step = 2
    /\ tok'  = IF BugTokenSurvivesPinChange
                 THEN tok
                 ELSE [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat' = [plat EXCEPT !.verifies = IF BugTokenSurvivesPinChange
                                           THEN plat.verifies ELSE FALSE,
                            !.revoked = TRUE]
    /\ walk' = IF BugTokenSurvivesPinChange THEN walk
                                            ELSE [open |-> FALSE, chan |-> NoChan]
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, pres, sys, snap, upSpent, viol,
                    ram >>

\* stopUsingPinUvAuthToken (state.rs:584-599) / expire_stale_token (:633-645).
\* The bytes stay put; in_use = FALSE and zero permissions make every
\* downstream check fail closed. Modelled as always enabled -- an
\* over-approximation of the 30 s / 600 s timers.
StopUsingToken ==
    /\ Idle
    /\ tok.live
    /\ tok'  = IF BugStopUsingKeepsPerms
                 THEN [tok EXCEPT !.live = FALSE]
                 ELSE [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat' = [plat EXCEPT !.revoked = TRUE]
    /\ walk' = [open |-> FALSE, chan |-> NoChan]
    /\ UNCHANGED << pin, gate, store, lock, pres, sys, op, snap, upSpent,
                    viol, ram >>

(***************************************************************************)
(* makeCredential / getAssertion.                                          *)
(***************************************************************************)

\* makecredential.rs:486-494. Needs PERM_MC and a touch.
RegisterStart(r, t) ==
    /\ Idle
    /\ ButtonFreeGuard
    \* Every credential box is derived from the seed, so a registration without
    \* one cannot complete either. It was only ever AssertStart's conjunct, which
    \* let `store.cred` -- "the records that still open" -- hold a record with no
    \* seed to open it once ResetAborts could strand a seedless running device.
    /\ SeedReachable
    /\ ~(gate.alwaysUv /\ ~pin.set)          \* alwaysUv with no PIN fails closed
    /\ OpGuard("mc", r)
    /\ viol' = (IF OpPolicy("mc", r) THEN viol ELSE viol \cup TokenBypass)
         \cup (IF ButtonFreePolicy THEN {} ELSE {"NoAuthorizationBypass"})
    /\ pres' = OpenWaitFor(t)
    /\ op' = [kind |-> "register", t |-> t, rp |-> r, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, ram >>

\* THE TOUCH IS AN AUTHORIZATION, and on a key with no PIN and no alwaysUv it is
\* the only one -- so it needs a Policy like every other gate here, not just an
\* enabling conjunct. A step that is merely never ENABLED without a confirm
\* cannot notice a build that stopped requiring one: the review removed the
\* presence gate from makeCredential AND getAssertion at once and every invariant
\* stayed green over 9 658 460 states.
TouchGuard  == IF BugNoTouchRequired THEN pres.granted # "none"
                                     ELSE pres.granted = "confirm"
TouchPolicy == pres.granted = "confirm"

RegisterTouched ==
    /\ op.kind = "register" /\ op.step = 0
    /\ TouchGuard
    /\ viol' = IF TouchPolicy THEN viol
                              ELSE viol \cup {"NoAuthorizationBypass"}
    /\ tok' = BoundConsumedTok(op.rp)
    /\ upSpent' = TRUE
    /\ op' = [op EXCEPT !.step = 1]
    /\ UNCHANGED << pin, gate, store, lock, plat, pres, walk, sys, snap, ram >>

RegisterRefused ==
    /\ op.kind = "register" /\ op.step = 0
    /\ pres.granted \in {"cancel", "timeout"}
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, viol, ram >>

\* credential.rs:805-827. Order so that any truncation leaves an RP entry
\* without a credential -- invisible but harmless -- never a credential
\* without an RP entry, which enumerateRPs and the display can neither list
\* nor delete while getAssertion authenticates with it happily (audit run-35).
RegisterWriteA ==
    /\ op.kind = "register" /\ op.step = 1
    /\ store' = IF BugCredBeforeRp
                  THEN [store EXCEPT !.cred = store.cred \cup {op.rp}]
                  ELSE [store EXCEPT !.rpent = store.rpent \cup {op.rp}]
    /\ op' = [op EXCEPT !.step = 2]
    /\ UNCHANGED << pin, gate, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, viol, ram >>

RegisterWriteB ==
    /\ op.kind = "register" /\ op.step = 2
    /\ store' = IF BugCredBeforeRp
                  THEN [store EXCEPT !.rpent = store.rpent \cup {op.rp}]
                  ELSE [store EXCEPT !.cred = store.cred \cup {op.rp}]
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, lock, tok, plat, walk, sys, snap, upSpent,
                    viol, ram >>

\* getassertion.rs:382-390. Needs PERM_GA, the rpId binding, and a touch.
AssertStart(r, t) ==
    /\ Idle
    /\ ButtonFreeGuard
    /\ r \in store.cred
    /\ SeedReachable                         \* a credential without the seed is dead
    /\ ~(gate.alwaysUv /\ ~pin.set)
    /\ OpGuard("ga", r)
    /\ viol' = (IF OpPolicy("ga", r) THEN viol ELSE viol \cup TokenBypass)
         \cup (IF ButtonFreePolicy THEN {} ELSE {"NoAuthorizationBypass"})
    /\ pres' = OpenWaitFor(t)
    /\ op' = [kind |-> "assert", t |-> t, rp |-> r, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, ram >>

AssertFinish ==
    /\ op.kind = "assert"
    /\ IF BugAssertWedgesOnTimeout THEN pres.granted = "confirm"
                                   ELSE pres.granted # "none"
    \* `issued` is whether the assertion is actually served, which is what the
    \* touch gates; the other outcomes only end the operation.
    /\ LET issued == BugNoTouchRequired \/ pres.granted = "confirm" IN
         /\ viol' = IF issued /\ ~TouchPolicy
                      THEN viol \cup {"NoAuthorizationBypass"} ELSE viol
         /\ tok' = IF issued THEN BoundConsumedTok(op.rp) ELSE tok
         /\ upSpent' = IF issued THEN TRUE ELSE upSpent
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, plat, walk, sys, snap, ram >>

(***************************************************************************)
(* authenticatorConfig -- no touch of its own. config.rs:223.              *)
(***************************************************************************)

\* The requirement GHSA-wqjm-653g-hgw3 states: an acfg operation may not be
\* authorized by a token whose user-presence test some other command already
\* spent.
\* config.rs:222-224 tests the MAC and PERM_ACFG and NOTHING else -- no `in_use`,
\* and no rpId binding either. The shared TokenGuardBare carries the binding
\* because credentialManagement's check_rp_binding does; here it is a guard the
\* Rust does not have, and it was inert only because it stood in the policy too.
ConfigGuard  == plat.held /\ plat.verifies /\ "acfg" \in tok.perms
ConfigPolicy == plat.held /\ ~plat.revoked /\ tok.live /\ "acfg" \in tok.perms
                /\ ~upSpent

\* No `pin.set` conjunct: config.rs:222-224 tests the MAC and PERM_ACFG and
\* nothing else. It carried one until the review measured it inert (a live token
\* implies a PIN was set on every reachable path) -- inert or not, a model whose
\* selling point is that its guards are what the Rust tests may not carry a
\* guard the Rust does not have.
ConfigOp ==
    /\ Idle
    /\ ConfigGuard
    /\ viol' = IF ConfigPolicy THEN viol ELSE viol \cup TokenBypass
    /\ gate' = [gate EXCEPT !.alwaysUv = ~gate.alwaysUv]
    /\ snap' = NoSnap
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, op, upSpent,
                    ram >>

(***************************************************************************)
(* Vendor BACKUP_FINALIZE -- vendor.rs:894-901, and its on-device twin      *)
(* mark_backup_sealed (vendor.rs:962-968).                                  *)
(***************************************************************************)

\* Writing EF_BACKUP_SEALED closes the one-time seed-export window: after it,
\* BACKUP_EXPORT refuses (vendor.rs:799) and the display's recovery-phrase
\* reveal is gone, until a reset reopens the window. Modelled UNGATED -- the
\* real one carries the PIN half and a deliberate hold -- which widens only the
\* states the marker can be SET in, never the states it can be LOST in, and it
\* is the loss that the invariant is about.
BackupFinalize ==
    /\ Idle
    /\ ~gate.backupSealed
    /\ gate' = [gate EXCEPT !.backupSealed = TRUE]
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, op, snap,
                    upSpent, viol, ram >>

\* Vendor UNLOCK (vendor.rs:543-566): the host presents the 32-byte lock key over
\* the MSE channel, the wrapped seed on flash decrypts, and `state.keydev_dec`
\* holds it until power-off. No PIN and no touch -- knowing the lock key IS the
\* authorization -- so this is not modelled as a gate, only as the one door
\* through which a second copy of the seed comes into existence.
\*
\* WIDER than the firmware in two directions, both sound: the model has no device
\* lock, so it does not require the seed to be stored WRAPPED (only a locked
\* device has an EF_KEY_DEV_ENC to open), and it omits AUT_DISABLE
\* (config.rs:394-395), which only ever CLEARS the copy.
DeviceUnlock ==
    /\ Idle
    /\ store.seed
    /\ ~ram
    /\ ram' = TRUE
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys, op,
                    snap, upSpent, viol >>

(***************************************************************************)
(* credentialManagement -- the enumerate walk, its channel, and the        *)
(* persistent grant. credmgmt.rs:240-297, 328-340; state.rs:169-180.       *)
(***************************************************************************)

\* credmgmt.rs:249-266: a holder of the persistent token IS the pcmr grant.
\* It carries no rpId binding and no usage timer, so it authorizes alone --
\* which is exactly why every path that invalidates it must delete the record.
PpuatGuard  == IF FixPpuatRequiresPin THEN gate.ppuat /\ pin.set ELSE gate.ppuat

CmBeginViaToken(ch, r) ==
    /\ Idle
    /\ TokenGuardBare("cm", r)
    /\ viol' = IF TokenPolicy("cm", r) THEN viol ELSE viol \cup TokenBypass
    /\ walk' = [open |-> TRUE, chan |-> ch]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, sys, op, snap,
                    upSpent, ram >>

\* A persistent grant that outlived what authorized it is NoTokenAfterInvalidation;
\* one that reads the credential directory on a key whose PIN record is gone is
\* NoAccessibleSecretWithoutGate. A torn reset produces both at once, which is
\* the honest reading -- it is one state wearing two names.
CmBeginViaPpuat(ch) ==
    /\ Idle
    /\ PpuatGuard
    \* Deliberately NOT recording the PIN-less case under NoAuthorizationBypass
    \* too: the grant presented is a valid one that nothing invalidated, and the
    \* proposed fix refuses it at the guard rather than stopping the record from
    \* being stranded. What is missing is the GATE, which is the other name.
    /\ viol' = viol
         \cup (IF gate.ppuatStale
                 THEN {"NoAuthorizationBypass", "NoTokenAfterInvalidation"}
                 ELSE {})
         \cup (IF pin.set THEN {} ELSE {"NoAccessibleSecretWithoutGate"})
    /\ walk' = [open |-> TRUE, chan |-> ch]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, sys, op, snap,
                    upSpent, ram >>

\* state.rs:169-180 may_walk_rps: a *Next* carries no pinUvAuthParam of its own
\* (6.8 exempts it) -- the (channel, counter) pair IS the authorization check.
CmNextGuard(ch)  == IF BugCmWalkIgnoresChannel THEN walk.open
                                               ELSE walk.open /\ walk.chan = ch
CmNextPolicy(ch) == walk.open /\ walk.chan = ch

CmNext(ch) ==
    /\ Idle
    /\ CmNextGuard(ch)
    /\ viol' = IF CmNextPolicy(ch) THEN viol
                                   ELSE viol \cup {"NoAuthorizationBypass"}
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys, op,
                    snap, upSpent, ram >>

\* 0x06 deleteCredential (credmgmt.rs:658-713). It calls verify_cm_token
\* DIRECTLY rather than going through authorize_cm, so the persistent grant
\* authorizes no writes -- which is why CmBeginViaPpuat has no delete twin.
DeleteCredStart(r) ==
    /\ Idle
    /\ r \in store.cred
    /\ TokenGuardBare("cm", r)
    /\ viol' = IF TokenPolicy("cm", r) THEN viol ELSE viol \cup TokenBypass
    /\ op' = [kind |-> "delcred", t |-> Fido, rp |-> r, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, ram >>

\* Two flash writes, so a cut has a position: `delete_credential` drops the
\* EF_CRED record first (credmgmt.rs:665-667) and `decrement_rp` deletes the
\* EF_RP entry only once its count reaches zero (:697-699). That order leaves a
\* torn delete showing an RP entry with no credential -- invisible but harmless.
\* Reversed, it strands exactly the credential finding 1 strands.
DeleteCredWriteA ==
    /\ op.kind = "delcred" /\ op.step = 0
    /\ IF BugDeleteRpBeforeCred
         THEN /\ store' = [store EXCEPT !.rpent = store.rpent \ {op.rp}]
              /\ UNCHANGED snap
         ELSE /\ store' = [store EXCEPT !.cred = store.cred \ {op.rp}]
              \* a deleted credential no longer survives an earlier reset either
              /\ snap' = [snap EXCEPT !.surv = snap.surv \ {op.rp}]
    /\ op' = [op EXCEPT !.step = 1]
    /\ UNCHANGED << pin, gate, lock, tok, plat, pres, walk, sys, upSpent,
                    viol, ram >>

DeleteCredWriteB ==
    /\ op.kind = "delcred" /\ op.step = 1
    /\ IF BugDeleteRpBeforeCred
         THEN /\ store' = [store EXCEPT !.cred = store.cred \ {op.rp}]
              /\ snap' = [snap EXCEPT !.surv = snap.surv \ {op.rp}]
         ELSE /\ store' = [store EXCEPT !.rpent = store.rpent \ {op.rp}]
              /\ UNCHANGED snap
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, lock, tok, plat, pres, walk, sys, upSpent,
                    viol, ram >>

(***************************************************************************)
(* authenticatorReset -- reset.rs:31-67. Two phases, each a batch of        *)
(* force_delete calls; `for_each_key` yields in FLASH-RING order, so the    *)
(* order WITHIN a phase is not controlled and is modelled as arbitrary.     *)
(***************************************************************************)

\* reset.rs:151-156. A warm boot CLOSES the window rather than opening one:
\* sys_reset is host-requestable ungated, so a window the host can restart at
\* will is no window at all. Modelled on a button build, where
\* presence.shows_confirm() is FALSE and the window therefore applies.
InResetWindowGuard ==
    IF BugWarmResetReopensWindow
      THEN sys.clock <= ResetWindow
      ELSE ~sys.warmBoot /\ sys.clock <= ResetWindow

InResetWindowPolicy == ~sys.warmBoot /\ sys.clock <= ResetWindow

ResetStart ==
    /\ Idle
    /\ ButtonFreeGuard
    /\ InResetWindowGuard
    /\ viol' = IF InResetWindowPolicy /\ ButtonFreePolicy
                 THEN viol
                 ELSE viol \cup {"NoAuthorizationBypass"}
    /\ pres' = OpenWaitFor(Fido)
    /\ op' = [kind |-> "reset", t |-> Fido, rp |-> NoRp, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, ram >>

ResetRefused ==
    /\ op.kind = "reset" /\ op.step = 0
    /\ pres.granted \in {"cancel", "timeout"}
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, viol, ram >>

\* The touch is in (reset.rs:38-46); the wipe begins. Snapshot what the
\* surviving state was gated by, so ResetNeverWeakensSurvivingState is a
\* relational claim rather than a restatement of the post state.
\*
\* THE LIVE SESSION GOES FIRST, ahead of every flash write (reset.rs:58-61). That
\* is not tidiness: with the flash seed deleted first, a sweep that then FAILS
\* leaves the rest of the power cycle running on `state.keydev_dec` -- the seed
\* nothing stores any more -- and BACKUP_EXPORT reads through `Ctx::load_keydev`
\* like everything else. BugStateResetAfterWipe is that ordering taken back out.
ResetConfirmed ==
    /\ op.kind = "reset" /\ op.step = 0
    \* The SAME Guard/Policy pair mc and ga carry, and for the same reason: the
    \* wipe's touch was an enabling conjunct here long after that lesson landed,
    \* so removing the presence gate from authenticatorReset left every invariant
    \* green over 17 911 536 states -- a factory reset served with no touch at
    \* all, inside a window a replug opens.
    /\ TouchGuard
    /\ viol' = IF TouchPolicy THEN viol
                              ELSE viol \cup {"NoAuthorizationBypass"}
    /\ ram' = IF BugStateResetAfterWipe THEN ram ELSE FALSE
    \* A previous attempt may have aborted with the flash record already gone, so
    \* dropping the RAM copy here can be the moment the last one dies.
    /\ store' = KeepOpen(store, store.seed \/ ram')
    /\ snap' = [seen |-> TRUE, pin |-> pin.set, auv |-> gate.alwaysUv,
                surv |-> store'.cred, seed |-> store.seed \/ ram',
                sealed |-> gate.backupSealed]
    \* Deliberately NOT marking the persistent grant stale here. A reset that is
    \* torn did not happen: the PIN that bought the grant may still stand, and
    \* the user retries. The grant becomes illegitimate when the PIN record it
    \* was bought with is gone -- which CmBeginViaPpuat's own recorder tests.
    /\ op' = [op EXCEPT !.step = IF BugResetGatesFirst THEN 2 ELSE 1]
    \* `ctx.state.reset()` in full, not only its `keydev_dec` half: the session
    \* token, the platform's copy of it and the enumerate cursor die here too
    \* (state.rs:442-458). Modelling only the seed left a live token outliving
    \* the deletion of EF_PIN once ResetAborts could strand one, which is
    \* 2 152 364 states the firmware cannot be in -- and it refuted ConfigGuard's
    \* own justification, that a live token implies a PIN was set. The clientPIN
    \* soft lock is NOT cleared here, and that is the one narrowing: `lock`
    \* carries a policy ghost (`policyMism`) the firmware has no field for, so
    \* whether a reset that then aborts may launder the RAM lock is a question
    \* this model states rather than answers.
    /\ tok'  = IF BugStateResetAfterWipe THEN tok
                                         ELSE [live |-> FALSE, perms |-> {},
                                               rp |-> NoRp]
    /\ plat' = IF BugStateResetAfterWipe THEN plat
                                         ELSE [held |-> FALSE,
                                               verifies |-> FALSE,
                                               revoked |-> TRUE]
    /\ walk' = IF BugStateResetAfterWipe THEN walk
                                         ELSE [open |-> FALSE, chan |-> NoChan]
    /\ upSpent' = IF BugStateResetAfterWipe THEN upSpent ELSE FALSE
    /\ UNCHANGED << pin, gate, lock, pres, sys >>

\* Which phase EF_BACKUP_SEALED belongs to is the audit run-36 class fix itself
\* (reset.rs:112-119): it is in the GATE set, so the marker outlives the seed it
\* protects. BugBackupSealedNotAGate moves it back into phase 1, where it sat.
SealedIsAGate == ~BugBackupSealedNotAGate /\ gate.backupSealed
SealedIsASecret == BugBackupSealedNotAGate /\ gate.backupSealed

\* EF_PAUTHTOKEN is a SECRET, not a gate (eab4b5c). `is_fido_gate_fid`'s own rule
\* is "records whose ABSENCE is permissive", and a grant is a permission, so its
\* absence is restrictive -- it was the one member that never met the rule, and
\* it sat there from cd87e8c until E82 read the predicate rather than the order.
\* BugPpuatIsAGate is that tree. It matters because phase 2 cannot start until
\* phase 1 is EMPTY, so with the grant in phase 1 the torn state is unreachable
\* rather than merely refused at the consumer -- which is what the structural
\* clause on NoAccessibleSecretWithoutGate can now say.
PpuatIsAGate   == BugPpuatIsAGate /\ gate.ppuat
PpuatIsASecret == ~BugPpuatIsAGate /\ gate.ppuat

SecretsLive == store.seed \/ store.cred # {} \/ store.rpent # {} \/ SealedIsASecret
               \/ PpuatIsASecret
GatesLive   == pin.set \/ gate.alwaysUv \/ PpuatIsAGate \/ SealedIsAGate

\* reset.rs:62-66 -- the seed goes in its own force_delete AHEAD of the batch, so
\* nothing the sweep leaves behind still opens. Modelled as an ordering rule over
\* the same phase rather than a fourth step: the tear between the touch and the
\* seed delete leaves the store untouched, which is a state the model already has.
SeedLeadsTheWipe == ~BugSeedDoesNotLead

\* Phase 1, reset.rs:68 -- every live FIDO-owned fid that is NOT a gate. One
\* force_delete per step, in an order the flash ring picks.
ResetSweepSecrets ==
    /\ op.kind = "reset" /\ op.step = 1
    /\ IF SecretsLive
         THEN /\ \/ /\ store.seed
                    \* Every box the applet holds hangs off this record, so its
                    \* deletion is what makes the rest unopenable -- the wipe's
                    \* whole claim, and now its first write. UNLESS a RAM copy
                    \* stands: then this write ends nothing, and the per-record
                    \* deletes below are what empties the store. That is E110.
                    /\ store' = KeepOpen([store EXCEPT !.seed = FALSE], ram)
                    \* the owner's seed is gone, and with it every credential
                    \* that could have survived the reset
                    /\ snap' = KeepSurv(snap, ram)
                    /\ UNCHANGED gate
                 \/ \E r \in store.cred :
                       \* Once the flash record has gone the batch still has to
                       \* run: with the seed leading, it has nothing left to
                       \* delete -- with a RAM copy live, it has everything.
                       /\ (SeedLeadsTheWipe => ~store.seed)
                       /\ store' = [store EXCEPT !.cred = store.cred \ {r}]
                       \* this credential no longer survives the reset
                       /\ snap' = [snap EXCEPT !.surv = snap.surv \ {r}]
                       /\ UNCHANGED gate
                 \/ /\ (SeedLeadsTheWipe => ~store.seed)
                    /\ \E r \in store.rpent :
                         store' = [store EXCEPT !.rpent = store.rpent \ {r}]
                    /\ FixSweepDropsCredsBeforeRpEntries => store.cred = {}
                    /\ UNCHANGED << gate, snap >>
                 \/ /\ SealedIsASecret
                    /\ SeedLeadsTheWipe => ~store.seed
                    /\ gate' = [gate EXCEPT !.backupSealed = FALSE]
                    /\ UNCHANGED << store, snap >>
                 \/ /\ PpuatIsASecret
                    /\ SeedLeadsTheWipe => ~store.seed
                    /\ gate' = [gate EXCEPT !.ppuat = FALSE,
                                            !.ppuatStale = FALSE]
                    /\ UNCHANGED << store, snap >>
              /\ UNCHANGED op
         ELSE /\ op' = [op EXCEPT !.step = IF BugResetGatesFirst THEN 3 ELSE 2]
              /\ UNCHANGED << store, snap, gate >>
    /\ UNCHANGED << pin, lock, tok, plat, pres, walk, sys, upSpent, viol,
                    ram >>

\* `everSet` is the ghost obligation "a PIN record must gate the secrets this
\* device holds". Deleting EF_PIN discharges it only when the secrets phase has
\* already emptied the store -- delete it with a secret still live and the
\* obligation stands, which is the whole defect BugResetGatesFirst rebuilds.
\* Without this a torn reset left `everSet` set for the device's LIFETIME and
\* the invariant blamed credentials the owner created afterwards, on a key whose
\* PIN they had themselves asked to erase.
PinRecordDeleted == [pin EXCEPT !.set = FALSE, !.everSet = SecretsLive]

\* Phase 2, reset.rs:59 -- the records that GATE the applet rather than being
\* the secret. Same arbitrary intra-phase order.
ResetSweepGates ==
    /\ op.kind = "reset" /\ op.step = 2
    /\ IF GatesLive
         THEN /\ \/ (pin.set /\ pin' = PinRecordDeleted
                              /\ UNCHANGED gate)
                 \/ (gate.alwaysUv /\ gate' = [gate EXCEPT !.alwaysUv = FALSE]
                                    /\ UNCHANGED pin)
                 \/ (PpuatIsAGate /\ gate' = [gate EXCEPT !.ppuat = FALSE,
                                                         !.ppuatStale = FALSE]
                                  /\ UNCHANGED pin)
                 \/ (SealedIsAGate /\ gate' = [gate EXCEPT !.backupSealed = FALSE]
                                    /\ UNCHANGED pin)
              /\ UNCHANGED op
         ELSE /\ op' = [op EXCEPT !.step = IF BugResetGatesFirst THEN 1 ELSE 3]
              /\ UNCHANGED << pin, gate >>
    /\ UNCHANGED << store, lock, tok, plat, pres, walk, sys, snap, upSpent,
                    viol, ram >>

\* reset.rs:70: ensure_seed. The session already died at reset.rs:61, ahead of the
\* flash, so `ram` is only still standing here on the BugStateResetAfterWipe tree.
ResetFinish ==
    /\ op.kind = "reset" /\ op.step = 3
    /\ ram'   = FALSE
    /\ store' = [store EXCEPT !.seed = TRUE]
    /\ tok'   = [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat'  = [held |-> FALSE, verifies |-> FALSE, revoked |-> TRUE]
    /\ lock'  = [soft |-> FALSE, mism |-> 0, policyMism |-> 0]
    /\ walk'  = [open |-> FALSE, chan |-> NoChan]
    /\ pres'  = ClosedWait(pres)
    /\ pin'   = [pin EXCEPT !.retries = MaxRetries, !.everSet = FALSE]
    /\ op' = NoOp
    /\ upSpent' = FALSE
    \* The reset ran to completion: nothing survived it, so the relational
    \* claim is discharged and must not follow the device into its next life.
    /\ snap' = NoSnap
    /\ UNCHANGED << gate, sys, viol >>

\* Any `?` in reset.rs:65-70 -- a force_delete that errors, a truncated
\* `for_each_key` (reset.rs:97-101), the RESET_MAX_DELETES backstop, a failed
\* ensure_seed. The command answers with an error and THE DEVICE KEEPS RUNNING:
\* no boot, no ensure_seed, RAM intact. That is the transition the model did not
\* have, and without it the RAM copy above is unobservable -- every other tear
\* here goes through PowerCut / WarmReset, which clear RAM on the way past.
ResetAborts ==
    /\ op.kind = "reset" /\ op.step \in {1, 2, 3}
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, viol, ram >>

(***************************************************************************)
(* Power. A cut may land anywhere, including between two flash writes of    *)
(* one operation -- that is the "power-cut position" the mandate names.     *)
(***************************************************************************)

VolatileCleared ==
    /\ ram'  = FALSE
    /\ tok'  = [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat' = [held |-> FALSE, verifies |-> FALSE, revoked |-> TRUE]
    /\ walk' = [open |-> FALSE, chan |-> NoChan]
    /\ pres' = [scope |-> NoOwner, cancelReq |-> FALSE, cancelBy |-> NoOwner,
                granted |-> "none", pressing |-> FALSE, spent |-> FALSE,
                usedBy |-> NoOwner]
    /\ op' = NoOp
    /\ upSpent' = FALSE

\* EVERY boot runs ensure_seed, not just the one at the end of a reset:
\* firmware/src/main.rs:609 and tools/emu/src/device.rs:264. A cut that stranded
\* the device mid-wipe therefore comes back WITH a seed and can hold usable
\* credentials again. Leaving it out made the model less permissive than the
\* firmware -- the one direction a safety argument cannot absorb.
\*
\* The boot is also where a RAM-only seed dies: a cut taken with the flash record
\* already deleted comes back with a FRESH seed and nothing that opens under the
\* old one, so KeepOpen/KeepSurv settle up here for whatever the wipe left.
BootEnsuresSeed ==
    /\ store' = [KeepOpen(store, store.seed) EXCEPT !.seed = TRUE]
    /\ snap'  = KeepSurv(snap, store.seed)

\* A real power cycle: the RAM soft lock and its mismatch batch are gone
\* because the thing they were counting -- this power cycle -- has ended.
PowerCut ==
    /\ VolatileCleared
    /\ BootEnsuresSeed
    /\ lock' = [soft |-> FALSE, mism |-> 0, policyMism |-> 0]
    /\ sys'  = [warmBoot |-> FALSE, clock |-> 0]
    /\ pin'  = [pin EXCEPT !.retries = pin.retries]
    /\ UNCHANGED << gate, viol >>

\* A host-requestable warm reset (SCB::sys_reset -- vendor 0x1F P1=0, the
\* rescue twin, the phy config-write auto-reboot). ctap.rs:215-222 carries the
\* PinLock across it; reset.rs:132 makes it CLOSE the reset window.
WarmReset ==
    /\ VolatileCleared
    /\ BootEnsuresSeed                 \* sys_reset re-enters main: same boot path
    /\ lock' = IF BugSoftLockLostOnWarmReset
                 THEN [soft |-> FALSE, mism |-> 0, policyMism |-> lock.policyMism]
                 ELSE [soft |-> lock.soft, mism |-> lock.mism,
                       policyMism |-> lock.policyMism]
    /\ sys'  = [warmBoot |-> TRUE, clock |-> 0]
    /\ UNCHANGED << pin, gate, viol >>

Tick ==
    /\ sys.clock < MaxClock
    /\ sys' = [sys EXCEPT !.clock = sys.clock + 1]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, op, snap,
                    upSpent, viol, ram >>

\* expire_stale_sequences (state.rs:657-663): an enumerate cursor idle past
\* STATEFUL_WALK_IDLE_MS is reset, WHATEVER opened it. The model closed a walk
\* only through the session token, and that docstring says in as many words why
\* the token is not enough -- "a `pcmr` token never expires", so a walk opened by
\* the persistent grant had no closer at all here. Modelled as always enabled,
\* like the other timers.
WalkExpires ==
    /\ ~BugWalkNeverExpires
    /\ walk.open
    /\ walk' = [open |-> FALSE, chan |-> NoChan]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, sys, op, snap,
                    upSpent, viol, ram >>

(***************************************************************************)

Next ==
    \/ PressDown \/ PressUp \/ HostCancel \/ HostCancelLatched
    \/ WalkExpires \/ OtpCancelWait \/ LocalCeremonyEnds
    \/ \E o \in {Otp, Panel} : LocalCeremonyStart(o)
    \/ LocalPinWrong \/ LocalPinOk
    \/ TouchConfirm \/ TouchCancel \/ TouchTimeout
    \/ \E ps \in PermSets, r \in RPs \cup {NoRp} : GetPinToken(ps, r)
    \/ WrongPin \/ MintPpuat
    \/ SetPinStart \/ SetPinClearPpuat \/ SetPinWrite
    \/ ChangePinStart \/ ChangePinClearPpuat \/ ChangePinWrite
    \/ ChangePinRotateToken \/ StopUsingToken
    \/ \E r \in RPs, t \in Transports : RegisterStart(r, t)
    \/ RegisterTouched \/ RegisterRefused \/ RegisterWriteA \/ RegisterWriteB
    \/ \E r \in RPs, t \in Transports : AssertStart(r, t)
    \/ AssertFinish \/ ConfigOp \/ BackupFinalize \/ DeviceUnlock
    \/ \E ch \in Channels, r \in RPs \cup {NoRp} : CmBeginViaToken(ch, r)
    \/ \E ch \in Channels : CmBeginViaPpuat(ch)
    \/ \E ch \in Channels : CmNext(ch)
    \/ \E r \in RPs : DeleteCredStart(r)
    \/ DeleteCredWriteA \/ DeleteCredWriteB
    \/ ResetStart \/ ResetRefused \/ ResetConfirmed
    \/ ResetSweepSecrets \/ ResetSweepGates \/ ResetFinish \/ ResetAborts
    \/ PowerCut \/ WarmReset \/ Tick

Spec == Init /\ [][Next]_vars

\* Canonical roster for phase-5 R1o. The refinement module owns one outcome
\* clause per name; adding a producer here without a clause fails its guard.
TokenOutcomeActions ==
    {"GetPinToken", "WrongPin", "MintPpuat", "LocalPinWrong", "LocalPinOk",
     "SetPinWrite", "ChangePinWrite", "RegisterTouched", "RegisterRefused",
     "RegisterWriteB", "AssertFinish", "ConfigOp", "BackupFinalize",
     "DeviceUnlock", "CmBeginViaToken", "CmBeginViaPpuat", "CmNext",
     "DeleteCredStart", "ResetRefused", "ResetFinish", "ResetAborts"}

(***************************************************************************)
(* LIVENESS. All six invariants are safety -- "the bad thing does not        *)
(* happen" -- and a device that starts a ceremony and never finishes it       *)
(* satisfies every one of them. A WEDGE is a liveness failure, and RS-Key has *)
(* shipped one, so the safety-only reading was a real blind spot rather than  *)
(* a theoretical one.                                                         *)
(*                                                                            *)
(* A fairness assumption that is not true of the implementation makes its      *)
(* property meaningless, so each is justified against the code and the         *)
(* environment gets NONE of them.                                             *)
(***************************************************************************)

\* WEAK fairness, and weak is the right strength for all three: each of these is
\* continuously enabled from the moment it becomes enabled until it fires, so
\* strong fairness would buy nothing and would assert more than the code does.
\*
\* The worker is synchronous -- one `Exchange` at a time, under a lock, and the
\* dispatch runs to completion before the next is accepted (worker.rs:637-660).
\* So every step that ADVANCES an in-flight sequence eventually happens: nothing
\* in the firmware can park one. What it cannot survive is a power cut, and
\* PowerCut is not fair, so "eventually" here still admits the cut.
\* WHAT MAKES THIS DISJUNCTION SOUND, and it is the thing E160 got wrong one
\* action over: `WF_vars(A \/ B)` promises only that SOME disjunct fires, which
\* is a fair reading of "the in-flight sequence advances" exactly while every
\* disjunct belongs to the SAME sequence. Every one of the eighteen is gated on
\* `op.kind`, and `Idle` gates every *Start, so there is only ever one. Fold in
\* an action that can be enabled beside a sequence -- which is precisely what
\* folding `LocalCeremonyEnds` in here did -- and the promise is satisfied by the
\* other activity while this one waits for ever.
\*
\* `OpAdvancesIsOneActivity` is that argument as an invariant rather than as a
\* paragraph, and BugFairnessFoldsLocalCeremony is E160 verbatim.
OpAdvances ==
    \/ (BugFairnessFoldsLocalCeremony /\ LocalCeremonyEnds)
    \/ RegisterTouched \/ RegisterRefused \/ RegisterWriteA \/ RegisterWriteB
    \/ AssertFinish
    \/ SetPinClearPpuat \/ SetPinWrite
    \/ ChangePinClearPpuat \/ ChangePinWrite \/ ChangePinRotateToken
    \/ DeleteCredWriteA \/ DeleteCredWriteB
    \/ ResetRefused \/ ResetConfirmed \/ ResetSweepSecrets \/ ResetSweepGates
    \/ ResetFinish \/ ResetAborts

\* The presence wait carries PRESENCE_TIMEOUT_MS
\* (crates/rsk-device/src/presence.rs:215-216),
\* so it resolves with no finger and no cancel. This is the assumption that makes
\* every ceremony terminate, and it is the one the firmware most clearly owes.
\*
\* NOT fair, deliberately: PressDown, PressUp, HostCancel, HostCancelLatched,
\* PowerCut, WarmReset, Tick and every *Start. Assuming a user eventually
\* touches, a host eventually sends, or a device is eventually replugged would
\* prove liveness the device does not have.
\* Its OWN conjunct, not a disjunct of OpAdvances, and the difference is a
\* counterexample rather than a preference. WF over a disjunction only promises
\* that SOME disjunct fires, and a local ceremony is the first thing here that
\* can be in flight beside another sequence -- LocalCeremonyStart takes the
\* button, but setPIN and changePIN need only `Idle`. So a panel wait that had
\* taken its confirm sat open for ever while the PIN ladder kept OpAdvances
\* satisfied on its own, and EveryWaitReleases failed in 423 900 states.
\* Justified the same way worker.rs:519-521 justifies the FIDO half: the
\* ceremony's own dispatch runs to completion and puts WAIT_SCOPE back.
FairSpec == Spec /\ WF_vars(OpAdvances)
                 /\ WF_vars(TouchTimeout)
                 /\ WF_vars(WalkExpires)
                 /\ WF_vars(LocalCeremonyEnds)

\* No wedge: a ceremony that has begun reaches quiescence, by finishing, by
\* being refused, or by losing power. This is the class the getAssertion wedge
\* belongs to, and no invariant in this file can see it.
EveryOpQuiesces == (op.kind # "none") ~> Idle

\* The touch is one physical button shared by every applet, so a wait that never
\* releases `WAIT_SCOPE` is not one stuck ceremony -- it is every later ceremony
\* on any transport, and a cancel that can reach across.
EveryWaitReleases == WaitOpen ~> (pres.scope = NoOwner)

\* A stateful enumerate cursor is a per-channel resource; one left open forever
\* is the same shape one leg down.
EveryWalkCloses == walk.open ~> ~walk.open

\* The one fairness conjunct that is a DISJUNCTION, checked rather than argued.
\* If no disjunct of OpAdvances can be enabled while the device is quiescent,
\* then every disjunct that IS enabled belongs to the single in-flight `op`, and
\* `WF_vars(OpAdvances)` means what its comment says. This is a safety invariant
\* over `Spec`, not a temporal property -- Fairness.cfg checks it at the liveness
\* constants, where `ENABLED` over eighteen actions is affordable.
\*
\* The other three conjuncts are single actions and need no such argument;
\* formal/README.md carries the audit of all four.
OpAdvancesIsOneActivity == ENABLED OpAdvances => ~Idle

(***************************************************************************)
(* THE INVARIANTS. The names are load-bearing: the same six must appear on  *)
(* the Rust side, in the Kani harnesses and in the stateful fuzz targets,   *)
(* so one property can be traced end to end. formal/README.md carries the   *)
(* invariant -> Rust construct table.                                       *)
(***************************************************************************)

\* A `"Name" \notin viol` clause is only as strong as the completeness of the
\* assignments that populate it, and an action that should record and does not
\* makes its invariant silently pass. So each of the three below leads with
\* whatever part of the property can be read out of the STATE -- those clauses
\* need no cooperation from any action and cannot be defeated by forgetting one
\* -- and keeps the ghost only for the part that is genuinely about a STEP.
\* Where a ghost clause survives, the comment says which actions must maintain
\* it, exhaustively.

\* No protected operation completes without the live authorization its own
\* gate requires -- the token and its permission, the retry budget, the soft
\* lock, the reset window, the walk's owning channel.
\*
\* Ghost half: the reset window (ResetStart), the walk's owning channel
\* (CmNext), the retry budget and soft lock (PinAttempt, hence GetPinToken /
\* WrongPin / MintPpuat / ChangePinStart), and a token step admitted against
\* policy (RegisterStart, AssertStart, ConfigOp, CmBeginViaToken,
\* CmBeginViaPpuat, DeleteCredStart, via TokenBypass). Those eleven are the
\* whole list; no other action is gated by an authorization.
NoAuthorizationBypass ==
    /\ "NoAuthorizationBypass" \notin viol
    \* CTAP 2.1 6.5.5.7: once a user-presence test is spent the token carries
    \* largeBlobWrite and nothing else, so nothing can ride that touch -- not
    \* the authenticatorConfig the advisory named and not a second assertion.
    /\ (upSpent /\ tok.live) => tok.perms = {}
    \* The RAM soft lock must reflect the policy it stands for: MismatchLimit
    \* consecutive mismatches and no real power cycle since (ctap.rs:215-222).
    /\ (lock.policyMism >= MismatchLimit) => lock.soft

\* A presence decision produced for one transport is never applied to
\* another: neither a confirm (one hold, one ceremony) nor a cancel.
\*
\* Ghost half: TouchConfirm only. TouchConfirm rewrites `usedBy` in the same
\* step it reads it, so the pre-state -- which transport the current hold has
\* already served -- is visible to nothing else.
NoCrossTransportTouchConsumption ==
    /\ "NoCrossTransportTouchConsumption" \notin viol
    \* The cancel half reads structurally: TouchCancel leaves `cancelBy`
    \* standing, so a decision wearing the wrong owner's name is a state.
    /\ (pres.granted = "cancel") => (pres.cancelBy = pres.scope)

\* A grant that has been invalidated -- by a PIN change, a PIN set, a reset,
\* stopUsingPinUvAuthToken or a power cycle -- never authorizes again.
\*
\* Ghost half: the rpId binding, which is the one way to use a grant that is
\* live and yet not yours (RegisterStart, AssertStart, ConfigOp,
\* CmBeginViaToken, DeleteCredStart via TokenBypass; CmBeginViaPpuat for a
\* stale persistent record). It leaves no bad state behind -- only a bad step.
NoTokenAfterInvalidation ==
    /\ "NoTokenAfterInvalidation" \notin viol
    \* Every path that retires a session token must leave nothing behind that
    \* still opens a door. `verify_token` is a MAC over bytes that stay put, so
    \* zero permissions is the whole defence (state.rs:589-590).
    /\ ~(plat.held /\ plat.revoked /\ tok.perms # {})
    \* And every path that revokes the persistent grant must DELETE the record,
    \* not merely stop honouring it (clientpin.rs:214-218, :300-304).
    /\ ~(gate.ppuat /\ gate.ppuatStale)

\* The three flash-shaped invariants below are asserted over QUIESCENT states
\* only (`Idle`), and that is the strong reading rather than a weakening. A
\* multi-write sequence is necessarily inconsistent between its writes; what
\* matters is whether an inconsistency can SURVIVE. PowerCut sets op' = NoOp,
\* so every state a cut can leave the device in -- and then serve requests
\* from -- is quiescent. Asserting them mid-sequence would instead report
\* every non-atomic write as a defect.

\* No live secret sits behind a gate record that is no longer there: a usable
\* credential on a key that has ever had a PIN implies the PIN record, and a
\* persistent grant with credentials to read implies the PIN that bought it.
\*
\* The second half stays a ghost DELIBERATELY, and CmBeginViaPpuat is its only
\* writer. The structural form -- `gate.ppuat => pin.set`, no stranded grant
\* record may exist at all -- is a strictly stronger claim than the fix under
\* consideration: FixPpuatRequiresPin refuses the record at the guard and
\* leaves it stranded, so a structural clause would call the accepted fix a
\* defect. What the invariant is about is REACHABILITY, and reachability here
\* is a step.
NoAccessibleSecretWithoutGate ==
    /\ "NoAccessibleSecretWithoutGate" \notin viol
    /\ Idle => ((store.cred # {} /\ SeedReachable /\ pin.everSet) => pin.set)
    \* AND THE STRUCTURAL FORM, which this invariant could not carry until
    \* eab4b5c: no stranded grant record may EXIST, not merely be refused. It was
    \* a strictly stronger claim than the fix under consideration while
    \* FixPpuatRequiresPin was the only defence -- that fix refuses the record and
    \* leaves it stranded, so the clause would have called the accepted fix a
    \* defect. With the grant swept in phase 1 the state is unreachable, because
    \* phase 2 provably cannot start until phase 1 is empty, and unreachable is
    \* the claim worth making. BugPpuatIsAGate is the tree that cannot make it.
    /\ Idle => (gate.ppuat => pin.set)

(***************************************************************************)
(* TWO FACTS THE MODEL HAS BEEN RELYING ON IN PROSE. Neither is one of the  *)
(* six, and neither is a security requirement -- each is a structural       *)
(* property of the shipped tree that an ARGUMENT elsewhere in this file     *)
(* rests on. An argument nothing checks is the shape that has cost this     *)
(* model most, so both are asserted on Shipped.cfg and both carry a mutant. *)
(***************************************************************************)

\* WHY SeedReachable's `ram` disjunct is inert. `DeviceUnlock` needs a live flash
\* seed and `ResetConfirmed` drops the RAM copy ahead of the flash one, so the
\* second home never outlives the first -- measured once over 17 190 324 states,
\* written into the README, and then relied on. Asserting it makes the day it
\* stops being true a RED row rather than a discovery: the disjunct would start
\* doing work, and the three clauses restated in terms of it with it.
\* BugStateResetAfterWipe is the tree where it is false, which is exactly the
\* regression that made the disjunct necessary.
RamNeverOutlivesFlashSeed == ram => store.seed

\* ConfigGuard carries no `pin.set` conjunct because config.rs:222-224 does not,
\* and the justification for the model's own `~(gate.alwaysUv /\ ~pin.set)` on
\* makeCredential and getAssertion is the same sentence: a live token implies a
\* PIN was set on every reachable path. That sentence was refuted once already --
\* modelling only the `keydev_dec` half of `ctx.state.reset()` left a live token
\* outliving the deletion of EF_PIN -- and the repair put it back without
\* checking it. Measured now rather than argued: with the conjunct removed from
\* both call sites the reachable space is bit-identical AND the transition count
\* is unchanged, so it disables nothing, because this holds.
NoLiveTokenWithoutPinRecord == tok.live => pin.set

\* Every live credential is reachable by the management surface: enumerateRPs
\* and the trusted-display Passkeys view both walk EF_RP, so a credential
\* without its RP entry can be authenticated with but neither listed nor
\* deleted (credential.rs:805-812, audit run-35).
NoUnmanageableCredential == Idle => store.cred \subseteq store.rpent

\* No prefix of an authenticatorReset -- torn or complete -- leaves a
\* surviving usable secret whose gate has already gone (reset.rs:52-59).
\* Shipped twin: reset_tests.rs::a_torn_reset_never_unseals_a_surviving_seed.
\*
\* THE THREE CLAUSES ARE NAMED because `Solo_*` names an INVARIANT and never a
\* clause, and that turned out to matter: all four reset-family mutants reported
\* this invariant and all four traces were the THIRD clause, so "caught by the
\* invariant that names it" was true while two thirds of the invariant had no
\* owner at all. A conjunction is only as tested as its weakest clause, and
\* nothing in the apparatus could see which one that was. `SoloClause_*.cfg`
\* names one clause and one mutant; formal/README.md carries the ownership grid
\* those runs produced.
ResetKeepsThePinGate ==
    (Idle /\ snap.seen) =>
      ((snap.surv # {} /\ SeedReachable /\ snap.pin) => pin.set)

ResetKeepsTheAlwaysUvGate ==
    (Idle /\ snap.seen) =>
      ((snap.surv # {} /\ SeedReachable /\ snap.auv) => gate.alwaysUv)

\* The run-36 direction, and the one whose gate reads backwards: the OWNER's seed
\* still live with EF_BACKUP_SEALED gone means the wipe re-opened a one-time
\* export window over a seed it did not manage to destroy.
ResetKeepsTheBackupSeal ==
    (Idle /\ snap.seen) => ((snap.seed /\ snap.sealed) => gate.backupSealed)

ResetNeverWeakensSurvivingState ==
    /\ ResetKeepsThePinGate
    /\ ResetKeepsTheAlwaysUvGate
    /\ ResetKeepsTheBackupSeal

=============================================================================
