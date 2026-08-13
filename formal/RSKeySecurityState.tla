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
EXTENDS Naturals, FiniteSets

CONSTANTS
    RPs,                \* relying parties (>= 2 to exercise rpId binding)
    Channels,           \* CTAPHID channel ids (>= 2 to exercise walk ownership)
    MaxRetries,         \* models MAX_PIN_RETRIES = 8   (consts.rs:314)
    MismatchLimit,      \* models PIN_MISMATCH_LIMIT = 3 (consts.rs:318)
    MaxClock,           \* coarse tick ceiling
    ResetWindow         \* models RESET_WINDOW_MS = 10_000 (consts.rs:345)

(* Mutation switches. All FALSE is the shipped tree. Each rebuilds one real  *)
(* defect; `formal/README.md` maps every switch to its commit or audit id.   *)
CONSTANTS
    BugResetGatesFirst,           \* reset.rs:57-58   two-phase wipe order
    BugCredBeforeRp,              \* credential.rs:807-826 registration order
    BugTokenSurvivesPinChange,    \* clientpin.rs:311  resetPinUvAuthToken
    BugSetPinKeepsPpuat,          \* clientpin.rs:213-217
    BugChangePinKeepsPpuat,       \* clientpin.rs:300-304
    BugStopUsingKeepsPerms,       \* state.rs:545-556  stopUsingPinUvAuthToken
    BugNoConsumeAfterUp,          \* state.rs:518-530  GHSA-wqjm-653g-hgw3
    BugUnscopedCancel,            \* rsk-device presence.rs:116-120 cancel scope
    BugTouchNotSpent,             \* rsk-device presence.rs:200-208,222 `spent`
    BugSoftLockLostOnWarmReset,   \* ctap.rs:215-222   PinLock across sys_reset
    BugWarmResetReopensWindow,    \* reset.rs:130-132  in_reset_window
    BugCmWalkIgnoresChannel,      \* state.rs:169-179  may_walk_rps
    BugDeleteRpBeforeCred,        \* credmgmt.rs:664-671 deleteCredential order
    BugBackupSealedNotAGate,      \* reset.rs:110-123  is_fido_gate_fid (run-36)
    BugWrongPinKeepsToken         \* clientpin.rs:779  the pre-E38 tree

(* A PROPOSED fix, not a defect: order phase 1 of the reset sweep so no EF_RP  *)
(* entry is dropped while its EF_CRED record is still live. The shipped        *)
(* `sweep` batches both in `for_each_key` order, which fs.rs:238-241 documents *)
(* as store order rather than FID order, so the batch can delete the metadata  *)
(* first. TRUE models the fix; FALSE is the tree as it stands.                 *)
CONSTANT FixSweepDropsCredsBeforeRpEntries

(* A second PROPOSED fix. `authorize_cm` consults the persistent grant FIRST   *)
(* and returns Ok with no PIN check (credmgmt.rs:240-242), so a leftover       *)
(* EF_PAUTHTOKEN on a PIN-less key still authorizes the three read            *)
(* subcommands. clientpin.rs:213-217 already names that torn state but closes  *)
(* only the exit where the user sets a PIN again. TRUE models refusing a       *)
(* persistent grant when EF_PIN is absent -- one owner, one line.              *)
CONSTANT FixPpuatRequiresPin

NoOwner == "none"          \* SCOPE_NONE            (crates/rsk-device/src/presence.rs:26)
Fido    == "fido"          \* SCOPE_FIDO -- CTAPHID (crates/rsk-device/src/presence.rs:28)
Ccid    == "ccid"          \* SCOPE_CCID -- CCID    (crates/rsk-device/src/presence.rs:30)
Transports == {Fido, Ccid}

NoRp   == "norp"           \* PinUvAuthToken.has_rp_id = FALSE (state.rs:252)
NoChan == "nochan"

(* PERM_* bits, state.rs:22-28. Restricted to the sets a host actually asks  *)
(* for, which keeps the token's value space at 5 instead of 16: getPinToken  *)
(* 0x05 grants exactly {mc,ga} (clientpin.rs:386-390), and                   *)
(* consume_after_user_presence leaves {} (lbw only, state.rs:526).           *)
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
    \* the rest: its ABSENCE is the permissive state (reset.rs:110-117), so what
    \* a torn wipe can re-open is a window the owner had closed.
    gate,   \*                                                 (reset.rs:116-124)
    store,  \* the secrets: [cred, rpent, seed]                (reset.rs:141-169)
    lock,   \* the soft lock: [soft, mism, policyMism]         (state.rs:284-291)
    tok,    \* device-side session token: [live, perms, rp]    (state.rs:247-261)
    plat,   \* the platform's copy: [held, verifies, revoked]  (ghost + wire)
    pres,   \* presence: [scope,cancelReq,cancelBy,granted,pressing,spent,usedBy]
    walk,   \* credentialManagement enumerate cursor: [open, chan] (state.rs:109)
    sys,    \* [warmBoot, clock]                               (state.rs:349-359)
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
    viol    \* ghost: the set of invariant names some step has violated

vars == << pin, gate, store, lock, tok, plat, pres, walk, sys, op, snap,
           upSpent, viol >>

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
    /\ pres  \in [scope: Transports \cup {NoOwner}, cancelReq: BOOLEAN,
                  cancelBy: Transports \cup {NoOwner}, granted: Decisions,
                  pressing: BOOLEAN, spent: BOOLEAN,
                  usedBy: Transports \cup {NoOwner}]
    /\ walk  \in [open: BOOLEAN, chan: Channels \cup {NoChan}]
    /\ sys   \in [warmBoot: BOOLEAN, clock: 0..MaxClock]
    /\ op    \in [kind: OpKinds, t: Transports \cup {NoOwner},
                  rp: RPs \cup {NoRp}, step: 0..3]
    /\ snap  \in [seen: BOOLEAN, pin: BOOLEAN, auv: BOOLEAN,
                  surv: SUBSET RPs, seed: BOOLEAN, sealed: BOOLEAN]
    /\ upSpent \in BOOLEAN
    /\ viol  \in SUBSET InvNames

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

(***************************************************************************)
(* Presence -- one physical button serves every applet, so the wait carries *)
(* an owner. crates/rsk-device/src/presence.rs:25-166, 190-241.            *)
(***************************************************************************)

Idle == op.kind = "none"
WaitOpen == pres.scope # NoOwner /\ pres.granted = "none"

\* ButtonWait::wait entry: crates/rsk-device/src/presence.rs:193-194
\* drops a cancel left over from an already-finished request, so each wait
\* starts clean.
OpenWaitFor(t) ==
    [pres EXCEPT !.scope = t, !.cancelReq = FALSE, !.cancelBy = NoOwner,
                 !.granted = "none"]

\* The dispatch is over; set_wait_scope(SCOPE_NONE) so an on-panel ceremony is
\* nobody's to cancel (crates/rsk-device/src/presence.rs:103-105), and
\* :226 clears a cancel that raced in.
ClosedWait(p) ==
    [p EXCEPT !.scope = NoOwner, !.cancelReq = FALSE, !.cancelBy = NoOwner,
              !.granted = "none"]

\* The user's finger. PressUp clears `spent` exactly as
\* crates/rsk-device/src/presence.rs:207 does.
\* `usedBy` is a ghost naming the transport that has already been served by the
\* CURRENT continuous hold, so it is cleared by every release: a second press
\* is a second consent, and only an uninterrupted hold can be double-spent.
PressDown ==
    /\ ~pres.pressing
    /\ pres' = [pres EXCEPT !.pressing = TRUE, !.usedBy = NoOwner]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol >>

PressUp ==
    /\ pres.pressing
    /\ pres' = [pres EXCEPT !.pressing = FALSE, !.spent = FALSE,
                            !.usedBy = NoOwner]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol >>

\* CTAPHID_CANCEL for the channel being processed. rsk-usb ctaphid.rs:757-762
\* raises it; crates/rsk-device/src/presence.rs:116-120 is the scope check that decides
\* whether it may end THIS wait. Only the CTAPHID transport can send one.
CancelGuard  == IF BugUnscopedCancel THEN TRUE ELSE pres.scope = Fido
HostCancel ==
    /\ WaitOpen
    /\ CancelGuard
    /\ pres' = [pres EXCEPT !.cancelReq = TRUE, !.cancelBy = Fido]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol >>

\* crates/rsk-device/src/presence.rs:200-205: a press the previous
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
                    upSpent >>

\* crates/rsk-device/src/presence.rs:209-211. A cancel raised by
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
                    upSpent >>

\* crates/rsk-device/src/presence.rs:212-214. Modelled as always
\* enabled rather than tied to the
\* clock: an over-approximation (more behaviours), sound for safety.
TouchTimeout ==
    /\ WaitOpen
    /\ pres' = [pres EXCEPT !.granted = "timeout"]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, op, snap,
                    upSpent, viol >>

(***************************************************************************)
(* Authorization. Guard = the Rust; Policy = the requirement.              *)
(***************************************************************************)

\* THE FOUR CALL SITES DO NOT TEST THE SAME THING, and the difference is
\* load-bearing. makeCredential (makecredential.rs:454-457) and getAssertion
\* (getassertion.rs:384-387) test the MAC, `user_verified()` -- which is
\* `in_use && user_verified` (state.rs:623-625) -- the permission bit and the
\* rpId binding. authenticatorConfig (config.rs:222-224) and
\* credentialManagement (credmgmt.rs:277) test the MAC and the permission bit
\* ONLY: neither consults `in_use`.
\*
\* So for those two the sole thing separating a stopped or expired token from a
\* live authorization is that stopUsingPinUvAuthToken ALSO zeroes the
\* permissions (state.rs:546-547). `verify_token` is a MAC over bytes that stay
\* put, so it keeps succeeding. Modelling one uniform guard hid that, and hid
\* the BugStopUsingKeepsPerms mutant with it.
TokenGuardUv(p, rp) ==
    /\ plat.held /\ plat.verifies
    /\ tok.live                            \* user_verified(): in_use && uv
    /\ p \in tok.perms
    /\ (tok.rp = NoRp \/ tok.rp = rp)      \* getassertion.rs:387 rpId binding

\* config.rs:222-224 / credmgmt.rs:277 -- no `in_use` conjunct exists here.
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

\* CTAP 2.1 6.5.5.7 post-user-presence triad (state.rs:518-530). Spending the
\* token down to largeBlobWrite is what stops a follow-on authenticatorConfig
\* riding the touch that a getAssertion just collected (GHSA-wqjm-653g-hgw3).
ConsumedTok ==
    IF BugNoConsumeAfterUp \/ ~tok.live THEN tok ELSE [tok EXCEPT !.perms = {}]

(***************************************************************************)
(* clientPIN. clientpin.rs:317-394 (getPinToken) and :719-804 (the verify). *)
(***************************************************************************)

\* clientpin.rs:341-344 -- a PIN must exist, have budget, and the RAM soft lock
\* must not be engaged. clientpin.rs:735 self-defends the decrement at zero.
PinAttemptEnabled == pin.set /\ pin.retries > 0 /\ ~lock.soft

\* The requirement the soft lock encodes: after MismatchLimit consecutive
\* mismatches no further attempt is accepted until a REAL power cycle. The
\* policy counter is cleared only by PowerCut, never by a host-requested warm
\* reset -- which is the whole point of ctap.rs:215-222.
PinAttemptPolicy == pin.set /\ pin.retries > 0 /\ lock.policyMism < MismatchLimit

\* clientpin.rs:738-804. The lockout ladder: spend, read back, compare.
PinAttempt(correct) ==
    /\ Idle
    /\ PinAttemptEnabled
    /\ viol' = IF PinAttemptPolicy THEN viol
                                   ELSE viol \cup {"NoAuthorizationBypass"}
    /\ IF correct
         THEN \* clientpin.rs:798-799 reset the budget and the mismatch batch.
              /\ pin' = [pin EXCEPT !.retries = MaxRetries]
              /\ lock' = [soft |-> FALSE, mism |-> 0, policyMism |-> 0]
         ELSE LET r == pin.retries - 1 IN
              /\ pin' = [pin EXCEPT !.retries = r]
              /\ lock' = IF r = 0
                           THEN lock            \* clientpin.rs:780-785 hard lock
                           ELSE [lock EXCEPT
                                   !.mism = lock.mism + 1,
                                   !.policyMism =
                                      IF lock.policyMism < MismatchLimit
                                        THEN lock.policyMism + 1
                                        ELSE lock.policyMism,
                                   !.soft = (lock.mism + 1) >= MismatchLimit]

\* getPinUvAuthTokenUsingPinWithPermissions: a correct PIN mints a fresh
\* session token (clientpin.rs:415-428) and resets the credMgmt cursor
\* (state.rs:486-487).
GetPinToken(ps, r) ==
    /\ PinAttempt(TRUE)
    /\ ps \in PermSets
    /\ r \in RPs \cup {NoRp}
    /\ tok'  = [live |-> TRUE, perms |-> ps, rp |-> r]
    /\ plat' = [held |-> TRUE, verifies |-> TRUE, revoked |-> FALSE]
    /\ walk' = [open |-> FALSE, chan |-> NoChan]
    /\ upSpent' = FALSE
    /\ UNCHANGED << gate, store, pres, sys, op, snap >>

\* clientpin.rs:771 regenerates the ECDH key on a mismatch and :779 drops any
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
    \* reset_pin_uv_auth_token calls cm.reset() (state.rs:487): the cursor dies
    \* with the token that granted it.
    /\ walk' = IF BugWrongPinKeepsToken THEN walk
                                        ELSE [open |-> FALSE, chan |-> NoChan]
    /\ UNCHANGED << gate, store, pres, sys, op, snap, upSpent >>

\* getPinUvAuthTokenUsingPinWithPermissions with `pcmr`: mints the PERSISTENT
\* token, a flash record that outlives the power cycle (clientpin.rs:408-413,
\* seed.rs:290-301). Holding it IS the grant (credmgmt.rs:249-265).
MintPpuat ==
    /\ PinAttempt(TRUE)
    /\ gate' = [gate EXCEPT !.ppuat = TRUE, !.ppuatStale = FALSE]
    /\ UNCHANGED << store, tok, plat, pres, walk, sys, op, snap, upSpent >>

(***************************************************************************)
(* setPIN / changePIN -- multi-write, so a power cut has a position.        *)
(***************************************************************************)

\* clientpin.rs:184-186: a PIN already set may only be replaced by changePIN.
SetPinStart ==
    /\ Idle
    /\ ~pin.set
    /\ op' = [kind |-> "setpin", t |-> Fido, rp |-> NoRp, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, viol >>

\* clientpin.rs:213-217 / write_pin_verifier :824-828 -- revoke BEFORE the new
\* verifier lands. A torn authenticatorReset can drop EF_PIN and lose power
\* before EF_PAUTHTOKEN; establishing a PIN over that leftover would hand the
\* old holder read access to the credentials created next.
SetPinClearPpuat ==
    /\ op.kind = "setpin" /\ op.step = 0
    /\ gate' = IF BugSetPinKeepsPpuat
                 THEN [gate EXCEPT !.ppuatStale = TRUE]
                 ELSE [gate EXCEPT !.ppuat = FALSE, !.ppuatStale = FALSE]
    /\ op' = [op EXCEPT !.step = 1]
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, viol >>

SetPinWrite ==
    /\ op.kind = "setpin" /\ op.step = 1
    /\ pin' = [set |-> TRUE, retries |-> MaxRetries, everSet |-> TRUE]
    /\ lock' = [lock EXCEPT !.soft = FALSE, !.mism = 0, !.policyMism = 0]
    /\ op' = NoOp
    /\ snap' = NoSnap
    /\ UNCHANGED << gate, store, tok, plat, pres, walk, sys, upSpent, viol >>

ChangePinStart == \* clientpin.rs:235-276: gates, then spend-and-verify.
    /\ PinAttempt(TRUE)
    /\ op' = [kind |-> "chpin", t |-> Fido, rp |-> NoRp, step |-> 0]
    /\ UNCHANGED << gate, store, tok, plat, pres, walk, sys, snap, upSpent >>

\* clientpin.rs:300-304, step 15 of 6.5.5.6: revoke the persistent grant BEFORE
\* the new verifier lands, or a power cut leaves the old holder authorized
\* against a PIN they no longer know.
ChangePinClearPpuat ==
    /\ op.kind = "chpin" /\ op.step = 0
    /\ gate' = IF BugChangePinKeepsPpuat
                 THEN [gate EXCEPT !.ppuatStale = TRUE]
                 ELSE [gate EXCEPT !.ppuat = FALSE, !.ppuatStale = FALSE]
    /\ op' = [op EXCEPT !.step = 1]
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent, viol >>

ChangePinWrite == \* clientpin.rs:305 store_new_pin
    /\ op.kind = "chpin" /\ op.step = 1
    /\ pin' = [pin EXCEPT !.retries = MaxRetries, !.everSet = TRUE]
    /\ lock' = [lock EXCEPT !.soft = FALSE, !.mism = 0, !.policyMism = 0]
    /\ op' = [op EXCEPT !.step = 2]
    /\ snap' = NoSnap
    /\ UNCHANGED << gate, store, tok, plat, pres, walk, sys, upSpent, viol >>

\* clientpin.rs:311 resetPinUvAuthToken -- RAM only, and it must end every
\* session credential the old PIN authorized (state.rs:486-497).
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
    /\ UNCHANGED << pin, gate, store, lock, pres, sys, snap, upSpent, viol >>

\* stopUsingPinUvAuthToken (state.rs:542-556) / expire_stale_token (:593-602).
\* The bytes stay put; in_use = FALSE and zero permissions make every
\* downstream check fail closed. Modelled as always enabled -- an
\* over-approximation of the 30 s / 600 s timers.
StopUsingToken ==
    /\ tok.live
    /\ tok'  = IF BugStopUsingKeepsPerms
                 THEN [tok EXCEPT !.live = FALSE]
                 ELSE [live |-> FALSE, perms |-> {}, rp |-> NoRp]
    /\ plat' = [plat EXCEPT !.revoked = TRUE]
    /\ walk' = [open |-> FALSE, chan |-> NoChan]
    /\ UNCHANGED << pin, gate, store, lock, pres, sys, op, snap, upSpent, viol >>

(***************************************************************************)
(* makeCredential / getAssertion.                                          *)
(***************************************************************************)

\* makecredential.rs:452-460. Needs PERM_MC and a touch.
RegisterStart(r, t) ==
    /\ Idle
    /\ pres.scope = NoOwner
    /\ ~(gate.alwaysUv /\ ~pin.set)          \* alwaysUv with no PIN fails closed
    /\ OpGuard("mc", r)
    /\ viol' = IF OpPolicy("mc", r)
                 THEN viol
                 ELSE viol \cup {"NoAuthorizationBypass", "NoTokenAfterInvalidation"}
    /\ pres' = OpenWaitFor(t)
    /\ op' = [kind |-> "register", t |-> t, rp |-> r, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap, upSpent >>

RegisterTouched ==
    /\ op.kind = "register" /\ op.step = 0
    /\ pres.granted = "confirm"
    /\ tok' = ConsumedTok
    /\ upSpent' = TRUE
    /\ op' = [op EXCEPT !.step = 1]
    /\ UNCHANGED << pin, gate, store, lock, plat, pres, walk, sys, snap, viol >>

RegisterRefused ==
    /\ op.kind = "register" /\ op.step = 0
    /\ pres.granted \in {"cancel", "timeout"}
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, viol >>

\* credential.rs:804-826. Order so that any truncation leaves an RP entry
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
                    upSpent, viol >>

RegisterWriteB ==
    /\ op.kind = "register" /\ op.step = 2
    /\ store' = IF BugCredBeforeRp
                  THEN [store EXCEPT !.rpent = store.rpent \cup {op.rp}]
                  ELSE [store EXCEPT !.cred = store.cred \cup {op.rp}]
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, lock, tok, plat, walk, sys, snap, upSpent, viol >>

\* getassertion.rs:382-390. Needs PERM_GA, the rpId binding, and a touch.
AssertStart(r, t) ==
    /\ Idle
    /\ pres.scope = NoOwner
    /\ r \in store.cred
    /\ store.seed                            \* a credential without the seed is dead
    /\ ~(gate.alwaysUv /\ ~pin.set)
    /\ OpGuard("ga", r)
    /\ viol' = IF OpPolicy("ga", r)
                 THEN viol
                 ELSE viol \cup {"NoAuthorizationBypass", "NoTokenAfterInvalidation"}
    /\ pres' = OpenWaitFor(t)
    /\ op' = [kind |-> "assert", t |-> t, rp |-> r, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap, upSpent >>

AssertFinish ==
    /\ op.kind = "assert"
    /\ pres.granted # "none"
    /\ tok' = IF pres.granted = "confirm" THEN ConsumedTok ELSE tok
    /\ upSpent' = IF pres.granted = "confirm" THEN TRUE ELSE upSpent
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, plat, walk, sys, snap, viol >>

(***************************************************************************)
(* authenticatorConfig -- no touch of its own. config.rs:223.              *)
(***************************************************************************)

\* The requirement GHSA-wqjm-653g-hgw3 states: an acfg operation may not be
\* authorized by a token whose user-presence test some other command already
\* spent.
ConfigPolicy == TokenPolicy("acfg", NoRp) /\ ~upSpent

\* No `pin.set` conjunct: config.rs:222-224 tests the MAC and PERM_ACFG and
\* nothing else. It carried one until the review measured it inert (a live token
\* implies a PIN was set on every reachable path) -- inert or not, a model whose
\* selling point is that its guards are what the Rust tests may not carry a
\* guard the Rust does not have.
ConfigOp ==
    /\ Idle
    /\ TokenGuardBare("acfg", NoRp)
    /\ viol' = IF ConfigPolicy THEN viol
                               ELSE viol \cup {"NoAuthorizationBypass"}
    /\ gate' = [gate EXCEPT !.alwaysUv = ~gate.alwaysUv]
    /\ snap' = NoSnap
    /\ UNCHANGED << pin, store, lock, tok, plat, pres, walk, sys, op,
                    upSpent >>

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
                    upSpent, viol >>

(***************************************************************************)
(* credentialManagement -- the enumerate walk, its channel, and the        *)
(* persistent grant. credmgmt.rs:240-296, 328-340; state.rs:169-179.       *)
(***************************************************************************)

\* credmgmt.rs:249-265: a holder of the persistent token IS the pcmr grant.
\* It carries no rpId binding and no usage timer, so it authorizes alone --
\* which is exactly why every path that invalidates it must delete the record.
PpuatGuard  == IF FixPpuatRequiresPin THEN gate.ppuat /\ pin.set ELSE gate.ppuat
PpuatPolicy == gate.ppuat /\ ~gate.ppuatStale /\ pin.set

CmBeginViaToken(ch, r) ==
    /\ Idle
    /\ TokenGuardBare("cm", r)
    /\ viol' = IF TokenPolicy("cm", r)
                 THEN viol
                 ELSE viol \cup {"NoTokenAfterInvalidation"}
    /\ walk' = [open |-> TRUE, chan |-> ch]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, sys, op, snap,
                    upSpent >>

\* A persistent grant that outlived what authorized it is NoTokenAfterInvalidation;
\* one that reads the credential directory on a key whose PIN record is gone is
\* NoAccessibleSecretWithoutGate. A torn reset produces both at once, which is
\* the honest reading -- it is one state wearing two names.
CmBeginViaPpuat(ch) ==
    /\ Idle
    /\ PpuatGuard
    /\ viol' = viol
         \cup (IF gate.ppuatStale THEN {"NoTokenAfterInvalidation"} ELSE {})
         \cup (IF pin.set THEN {} ELSE {"NoAccessibleSecretWithoutGate"})
    /\ walk' = [open |-> TRUE, chan |-> ch]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, sys, op, snap,
                    upSpent >>

\* state.rs:169-179 may_walk_rps: a *Next* carries no pinUvAuthParam of its own
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
                    snap, upSpent >>

\* 0x06 deleteCredential (credmgmt.rs:657-711). It calls verify_cm_token
\* DIRECTLY rather than going through authorize_cm, so the persistent grant
\* authorizes no writes -- which is why CmBeginViaPpuat has no delete twin.
DeleteCredStart(r) ==
    /\ Idle
    /\ r \in store.cred
    /\ TokenGuardBare("cm", r)
    /\ viol' = IF TokenPolicy("cm", r)
                 THEN viol
                 ELSE viol \cup {"NoTokenAfterInvalidation"}
    /\ op' = [kind |-> "delcred", t |-> Fido, rp |-> r, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys, snap,
                    upSpent >>

\* Two flash writes, so a cut has a position: `delete_credential` drops the
\* EF_CRED record first (credmgmt.rs:664-666) and `decrement_rp` deletes the
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
    /\ UNCHANGED << pin, gate, lock, tok, plat, pres, walk, sys, upSpent, viol >>

DeleteCredWriteB ==
    /\ op.kind = "delcred" /\ op.step = 1
    /\ IF BugDeleteRpBeforeCred
         THEN /\ store' = [store EXCEPT !.cred = store.cred \ {op.rp}]
              /\ snap' = [snap EXCEPT !.surv = snap.surv \ {op.rp}]
         ELSE /\ store' = [store EXCEPT !.rpent = store.rpent \ {op.rp}]
              /\ UNCHANGED snap
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, lock, tok, plat, pres, walk, sys, upSpent, viol >>

(***************************************************************************)
(* authenticatorReset -- reset.rs:30-66. Two phases, each a batch of        *)
(* force_delete calls; `for_each_key` yields in FLASH-RING order, so the    *)
(* order WITHIN a phase is not controlled and is modelled as arbitrary.     *)
(***************************************************************************)

\* reset.rs:126-132. A warm boot CLOSES the window rather than opening one:
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
    /\ pres.scope = NoOwner
    /\ InResetWindowGuard
    /\ viol' = IF InResetWindowPolicy
                 THEN viol
                 ELSE viol \cup {"NoAuthorizationBypass"}
    /\ pres' = OpenWaitFor(Fido)
    /\ op' = [kind |-> "reset", t |-> Fido, rp |-> NoRp, step |-> 0]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap, upSpent >>

ResetRefused ==
    /\ op.kind = "reset" /\ op.step = 0
    /\ pres.granted \in {"cancel", "timeout"}
    /\ pres' = ClosedWait(pres)
    /\ op' = NoOp
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, walk, sys, snap,
                    upSpent, viol >>

\* The touch is in (reset.rs:37-45); the wipe begins. Snapshot what the
\* surviving state was gated by, so ResetNeverWeakensSurvivingState is a
\* relational claim rather than a restatement of the post state.
ResetConfirmed ==
    /\ op.kind = "reset" /\ op.step = 0
    /\ pres.granted = "confirm"
    /\ snap' = [seen |-> TRUE, pin |-> pin.set, auv |-> gate.alwaysUv,
                surv |-> store.cred, seed |-> store.seed,
                sealed |-> gate.backupSealed]
    \* Deliberately NOT marking the persistent grant stale here. A reset that is
    \* torn did not happen: the PIN that bought the grant may still stand, and
    \* the user retries. The grant becomes illegitimate when the PIN record it
    \* was bought with is gone -- which PpuatPolicy tests directly.
    /\ op' = [op EXCEPT !.step = IF BugResetGatesFirst THEN 2 ELSE 1]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, sys,
                    upSpent, viol >>

\* Which phase EF_BACKUP_SEALED belongs to is the audit run-36 class fix itself
\* (reset.rs:110-117): it is in the GATE set, so the marker outlives the seed it
\* protects. BugBackupSealedNotAGate moves it back into phase 1, where it sat.
SealedIsAGate == ~BugBackupSealedNotAGate /\ gate.backupSealed
SealedIsASecret == BugBackupSealedNotAGate /\ gate.backupSealed

SecretsLive == store.seed \/ store.cred # {} \/ store.rpent # {} \/ SealedIsASecret
GatesLive   == pin.set \/ gate.alwaysUv \/ gate.ppuat \/ SealedIsAGate

\* Phase 1, reset.rs:57 -- every live FIDO-owned fid that is NOT a gate. One
\* force_delete per step, in an order the flash ring picks.
ResetSweepSecrets ==
    /\ op.kind = "reset" /\ op.step = 1
    /\ IF SecretsLive
         THEN /\ \/ /\ store.seed
                    /\ store' = [store EXCEPT !.seed = FALSE]
                    \* the owner's seed is gone; whatever a later boot
                    \* regenerates is a different one
                    /\ snap' = [snap EXCEPT !.seed = FALSE]
                    /\ UNCHANGED gate
                 \/ \E r \in store.cred :
                       /\ store' = [store EXCEPT !.cred = store.cred \ {r}]
                       \* this credential no longer survives the reset
                       /\ snap' = [snap EXCEPT !.surv = snap.surv \ {r}]
                       /\ UNCHANGED gate
                 \/ /\ \E r \in store.rpent :
                         store' = [store EXCEPT !.rpent = store.rpent \ {r}]
                    /\ FixSweepDropsCredsBeforeRpEntries => store.cred = {}
                    /\ UNCHANGED << gate, snap >>
                 \/ /\ SealedIsASecret
                    /\ gate' = [gate EXCEPT !.backupSealed = FALSE]
                    /\ UNCHANGED << store, snap >>
              /\ UNCHANGED op
         ELSE /\ op' = [op EXCEPT !.step = IF BugResetGatesFirst THEN 3 ELSE 2]
              /\ UNCHANGED << store, snap, gate >>
    /\ UNCHANGED << pin, lock, tok, plat, pres, walk, sys, upSpent, viol >>

\* `everSet` is the ghost obligation "a PIN record must gate the secrets this
\* device holds". Deleting EF_PIN discharges it only when the secrets phase has
\* already emptied the store -- delete it with a secret still live and the
\* obligation stands, which is the whole defect BugResetGatesFirst rebuilds.
\* Without this a torn reset left `everSet` set for the device's LIFETIME and
\* the invariant blamed credentials the owner created afterwards, on a key whose
\* PIN they had themselves asked to erase.
PinRecordDeleted == [pin EXCEPT !.set = FALSE, !.everSet = SecretsLive]

\* Phase 2, reset.rs:58 -- the records that GATE the applet rather than being
\* the secret. Same arbitrary intra-phase order.
ResetSweepGates ==
    /\ op.kind = "reset" /\ op.step = 2
    /\ IF GatesLive
         THEN /\ \/ (pin.set /\ pin' = PinRecordDeleted
                              /\ UNCHANGED gate)
                 \/ (gate.alwaysUv /\ gate' = [gate EXCEPT !.alwaysUv = FALSE]
                                    /\ UNCHANGED pin)
                 \/ (gate.ppuat /\ gate' = [gate EXCEPT !.ppuat = FALSE,
                                                        !.ppuatStale = FALSE]
                                 /\ UNCHANGED pin)
                 \/ (SealedIsAGate /\ gate' = [gate EXCEPT !.backupSealed = FALSE]
                                    /\ UNCHANGED pin)
              /\ UNCHANGED op
         ELSE /\ op' = [op EXCEPT !.step = IF BugResetGatesFirst THEN 1 ELSE 3]
              /\ UNCHANGED << pin, gate >>
    /\ UNCHANGED << store, lock, tok, plat, pres, walk, sys, snap, upSpent, viol >>

\* reset.rs:59-60: state.reset() then ensure_seed. The session dies with it.
ResetFinish ==
    /\ op.kind = "reset" /\ op.step = 3
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

(***************************************************************************)
(* Power. A cut may land anywhere, including between two flash writes of    *)
(* one operation -- that is the "power-cut position" the mandate names.     *)
(***************************************************************************)

VolatileCleared ==
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
BootEnsuresSeed == store' = [store EXCEPT !.seed = TRUE]

\* A real power cycle: the RAM soft lock and its mismatch batch are gone
\* because the thing they were counting -- this power cycle -- has ended.
PowerCut ==
    /\ VolatileCleared
    /\ BootEnsuresSeed
    /\ lock' = [soft |-> FALSE, mism |-> 0, policyMism |-> 0]
    /\ sys'  = [warmBoot |-> FALSE, clock |-> 0]
    /\ pin'  = [pin EXCEPT !.retries = pin.retries]
    /\ UNCHANGED << gate, snap, viol >>

\* A host-requestable warm reset (SCB::sys_reset -- vendor 0x1F P1=0, the
\* rescue twin, the phy config-write auto-reboot). ctap.rs:215-222 carries the
\* PinLock across it; reset.rs:130 makes it CLOSE the reset window.
WarmReset ==
    /\ VolatileCleared
    /\ BootEnsuresSeed                 \* sys_reset re-enters main: same boot path
    /\ lock' = IF BugSoftLockLostOnWarmReset
                 THEN [soft |-> FALSE, mism |-> 0, policyMism |-> lock.policyMism]
                 ELSE [soft |-> lock.soft, mism |-> lock.mism,
                       policyMism |-> lock.policyMism]
    /\ sys'  = [warmBoot |-> TRUE, clock |-> 0]
    /\ UNCHANGED << pin, gate, snap, viol >>

Tick ==
    /\ sys.clock < MaxClock
    /\ sys' = [sys EXCEPT !.clock = sys.clock + 1]
    /\ UNCHANGED << pin, gate, store, lock, tok, plat, pres, walk, op, snap,
                    upSpent, viol >>

(***************************************************************************)

Next ==
    \/ PressDown \/ PressUp \/ HostCancel
    \/ TouchConfirm \/ TouchCancel \/ TouchTimeout
    \/ \E ps \in PermSets, r \in RPs \cup {NoRp} : GetPinToken(ps, r)
    \/ WrongPin \/ MintPpuat
    \/ SetPinStart \/ SetPinClearPpuat \/ SetPinWrite
    \/ ChangePinStart \/ ChangePinClearPpuat \/ ChangePinWrite
    \/ ChangePinRotateToken \/ StopUsingToken
    \/ \E r \in RPs, t \in Transports : RegisterStart(r, t)
    \/ RegisterTouched \/ RegisterRefused \/ RegisterWriteA \/ RegisterWriteB
    \/ \E r \in RPs, t \in Transports : AssertStart(r, t)
    \/ AssertFinish \/ ConfigOp \/ BackupFinalize
    \/ \E ch \in Channels, r \in RPs \cup {NoRp} : CmBeginViaToken(ch, r)
    \/ \E ch \in Channels : CmBeginViaPpuat(ch)
    \/ \E ch \in Channels : CmNext(ch)
    \/ \E r \in RPs : DeleteCredStart(r)
    \/ DeleteCredWriteA \/ DeleteCredWriteB
    \/ ResetStart \/ ResetRefused \/ ResetConfirmed
    \/ ResetSweepSecrets \/ ResetSweepGates \/ ResetFinish
    \/ PowerCut \/ WarmReset \/ Tick

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS. The names are load-bearing: the same six must appear on  *)
(* the Rust side, in the Kani harnesses and in the stateful fuzz targets,   *)
(* so one property can be traced end to end. formal/README.md carries the   *)
(* invariant -> Rust construct table.                                       *)
(***************************************************************************)

\* No protected operation completes without the live authorization its own
\* gate requires -- the token and its permission, the retry budget, the soft
\* lock, the reset window, the walk's owning channel.
NoAuthorizationBypass == "NoAuthorizationBypass" \notin viol

\* A presence decision produced for one transport is never applied to
\* another: neither a confirm (one hold, one ceremony) nor a cancel.
NoCrossTransportTouchConsumption ==
    "NoCrossTransportTouchConsumption" \notin viol

\* A grant that has been invalidated -- by a PIN change, a PIN set, a reset,
\* stopUsingPinUvAuthToken or a power cycle -- never authorizes again.
NoTokenAfterInvalidation == "NoTokenAfterInvalidation" \notin viol

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
NoAccessibleSecretWithoutGate ==
    /\ "NoAccessibleSecretWithoutGate" \notin viol
    /\ Idle => ((store.cred # {} /\ store.seed /\ pin.everSet) => pin.set)

\* Every live credential is reachable by the management surface: enumerateRPs
\* and the trusted-display Passkeys view both walk EF_RP, so a credential
\* without its RP entry can be authenticated with but neither listed nor
\* deleted (credential.rs:804-811, audit run-35).
NoUnmanageableCredential == Idle => store.cred \subseteq store.rpent

\* No prefix of an authenticatorReset -- torn or complete -- leaves a
\* surviving usable secret whose gate has already gone (reset.rs:51-58).
\* The third clause is the run-36 direction, and it is the one whose gate reads
\* backwards: the OWNER's seed still live with EF_BACKUP_SEALED gone means the
\* wipe re-opened a one-time export window over a seed it did not manage to
\* destroy. Shipped twin: reset_tests.rs::a_torn_reset_never_unseals_a_surviving_seed.
ResetNeverWeakensSurvivingState ==
    (Idle /\ snap.seen) =>
      /\ (snap.surv # {} /\ store.seed /\ snap.pin) => pin.set
      /\ (snap.surv # {} /\ store.seed /\ snap.auv) => gate.alwaysUv
      /\ (snap.seed /\ snap.sealed) => gate.backupSealed

=============================================================================
