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

TraceComplete == tracePc <= TraceSteps

=============================================================================
