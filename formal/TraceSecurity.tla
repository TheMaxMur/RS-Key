---------------------------- MODULE TraceSecurity ----------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 RS-Key contributors                                  *)
(*                                                                         *)
(* Replay of emulator raw security snapshots against RSKeySecurityState.   *)
(* TraceSecurityData is generated independently by scripts/security_trace.py*)
(* from JSONL. `action_hint` is never used to choose a model transition.    *)
(***************************************************************************)
EXTENDS TraceSecurityData, RSKeyTokenView

CONSTANTS MutateBeta, MutateAlpha, MutateOutcome, CheckR4b
CONSTANTS MutateUvNotRqd, MutateResetWindow

VARIABLE tracePc
traceVars == << vars, tracePc >>

PermsFromRaw(raw) ==
    CASE raw = 0  -> {}
      [] raw = 1  -> {"mc"}
      [] raw = 2  -> {"ga"}
      [] raw = 3  -> {"mc", "ga"}
      [] raw = 4  -> {"cm"}
      [] raw = 16 -> {}
      [] raw = 32 -> {"acfg"}
      [] raw = 34 -> {"ga", "acfg"}
      [] OTHER    -> {"unsupported-raw-permissions"}

Beta(raw) ==
    [ pinSet       |-> raw.pinRecordLen = 35,
      pinRetries   |-> IF raw.pinRetriesRaw = -1
                         THEN MaxRetries ELSE raw.pinRetriesRaw,
      alwaysUv     |-> raw.alwaysUvRecordLen = 1 /\ raw.alwaysUvRaw = 1,
      grant        |-> raw.persistentGrantRecord,
      backupSealed |-> raw.backupSealedRecord,
      seed         |-> raw.seedPlainRecord \/ raw.seedEncryptedRecord,
      credAny      |-> raw.credentialSlotsRaw > 0,
      rpAny        |-> raw.rpSlotsRaw > 0,
      tokenLive    |-> raw.tokenInUseRaw,
      tokenPerms   |-> PermsFromRaw(raw.tokenPermissionsRaw),
      tokenBound   |-> raw.tokenHasRpIdRaw,
      softLock     |-> raw.softLockRaw,
      mismatches   |-> raw.pinMismatchesRaw,
      walkOpen     |-> raw.cmRpCounterRaw <= raw.cmRpTotalRaw \/
                         raw.cmCredCounterRaw <= raw.cmCredTotalRaw,
      warmBoot     |-> raw.warmBootRaw,
      keydevRam    |-> raw.keydevRamRaw ]

ModelProjection ==
    [ pinSet       |-> pin.set,
      pinRetries   |-> pin.retries,
      alwaysUv     |-> gate.alwaysUv,
      grant        |-> gate.ppuat,
      backupSealed |-> gate.backupSealed,
      seed         |-> store.seed,
      credAny      |-> store.cred # {},
      rpAny        |-> store.rpent # {},
      tokenLive    |-> tok.live,
      tokenPerms   |-> tok.perms,
      tokenBound   |-> tok.rp # NoRp,
      softLock     |-> lock.soft,
      mismatches   |-> lock.mism,
      walkOpen     |-> walk.open,
      warmBoot     |-> sys.warmBoot,
      keydevRam    |-> ram ]

TraceInit == Init /\ tracePc = 0

TraceNext ==
    \/ /\ tracePc < TraceSteps
       /\ TraceAction(tracePc)
       /\ tracePc' = tracePc + 1
    \/ /\ tracePc = TraceSteps
       /\ UNCHANGED traceVars

TraceSpec == TraceInit /\ [][TraceNext]_traceVars

RawAtBoundary ==
    IF MutateBeta /\ tracePc = BetaMutationBoundary
      THEN [BoundaryRaw(tracePc) EXCEPT !.pinRetriesRaw = @ - 1]
      ELSE BoundaryRaw(tracePc)

AbstractAtBoundary ==
    IF MutateAlpha /\ tracePc = AlphaMutationBoundary
      THEN [BoundaryAbstract(tracePc) EXCEPT !.live = ~@]
      ELSE BoundaryAbstract(tracePc)

R4aRawRefinesB ==
    tracePc \in BoundaryPcs => Beta(RawAtBoundary) = ModelProjection

R4bAlphaMatchesGamma ==
    ~CheckR4b \/ tracePc \notin BoundaryPcs \/
      AbstractAtBoundary = TokenGamma(pin, gate, tok, NoRp)

OutcomeAtBoundary ==
    IF MutateOutcome /\ tracePc = OutcomeMutationBoundary
      THEN IF BoundaryOutcomeRaw(tracePc) = "Authorized"
             THEN "Rejected" ELSE "Authorized"
      ELSE BoundaryOutcomeRaw(tracePc)

R4bEventConsensus ==
    tracePc \in OutcomeBoundaryPcs => OutcomeAtBoundary = BoundaryOutcomeB(tracePc)

(***************************************************************************)
(* R4c -- the gate answers.                                                *)
(*                                                                         *)
(* A refusal the model expresses by DISABLING an action is a refusal it     *)
(* cannot PREDICT. Both halves of makeCredential's token-less gate leave B  *)
(* exactly where it was -- a discoverable request is refused before any     *)
(* ceremony, a non-discoverable one is served on presence alone and stores  *)
(* nothing -- so both reached the replay as stutters and R4b-event had to   *)
(* answer AMBIGUOUS. So did the reset the window had closed. The rules are  *)
(* stated here, over B's OWN state, and the recording is held to them.      *)
(*                                                                         *)
(* Stated here and not in RSKeySecurityState because `Next` does not carry  *)
(* the token-less registration as a behaviour: the exhaustive model still   *)
(* never explores one, and formal/README.md lists that among the places the *)
(* model is narrower than the firmware. Folding it in is the next widening. *)
(***************************************************************************)

\* CTAP 2.1 6.1.2 step 10, crates/rsk-fido/src/makecredential.rs:540-546: with a
\* PIN configured a DISCOVERABLE credential still needs a token, a
\* non-discoverable one does not. `rk` is the request's, and it is an input.
\*
\* Step 6's alwaysUv arm is NOT here. It refuses only where built-in UV is
\* unavailable (makecredential.rs:528-536), which needs `req.uv` and the pad's
\* availability recorded; asserting it from `gate.alwaysUv` alone would be a
\* claim the code does not make, uncited, and false on a display build.
McTokenlessRefused(rk) == pin.set /\ rk

\* CTAP 2.1 6.6, crates/rsk-fido/src/reset.rs:187 -- the same predicate the
\* model already gates ResetStart on, read for its answer instead of its
\* enabling. `InResetWindowGuard` is the Guard and not the Policy on purpose:
\* what is being predicted is what the DEVICE does.
ResetGateRefuses == ~InResetWindowGuard

GateRefusesB(i) ==
    CASE GateKind(i) = "mc" ->
           McTokenlessRefused(IF MutateUvNotRqd THEN FALSE ELSE GateRk(i))
      [] GateKind(i) = "reset" ->
           IF MutateResetWindow THEN FALSE ELSE ResetGateRefuses
      [] OTHER -> CHOOSE x : FALSE

R4cGateAnswers ==
    tracePc \notin GateBoundaryPcs \/
      (IF GateRefusesB(tracePc) THEN "Rejected" ELSE "Authorized")
        = GateOutcomeRaw(tracePc)

\* `TraceComplete == tracePc <= TraceSteps` stood here and could not fail:
\* `TraceNext` only advances under `tracePc < TraceSteps`, so it was an
\* invariant of the transition relation. What it read as promising — that the
\* replay reached the END of its evidence — is asserted from outside now, by
\* scripts/security_trace.py holding the reported distinct count to
\* `TraceSteps + 1`, and by the deadlock check that is no longer suppressed.

=============================================================================
