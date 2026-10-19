-------------------------- MODULE RSKeyAppletPolicies --------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* The stateful operation policies left after the retry lattice: PIV slot    *)
(* PIN policy, OpenPGP key/algorithm binding, OATH access-code and touch      *)
(* gates, and Yubico OTP slot-code and moving-counter rules.                  *)
(*                                                                           *)
(* OATH's YKOATH access code and OTP's six-byte slot code have no retry       *)
(* counter. Modelling invented budgets for them would prove the wrong        *)
(* protocol, so RSKeyRetryLattice owns only the real PIV/OpenPGP counters.    *)
(* This module checks the four applets' real stateful doors instead.          *)
(*****************************************************************************)
EXTENDS Naturals

CONSTANTS
    CounterMax,
    SessionMax,
    Slots,
    BugPivPolicyIgnored,
    BugPivAlwaysDoesNotSpend,
    BugPgpAttributeKeepsKey,
    BugOathCodeIgnored,
    BugOathTouchIgnored,
    BugOtpCodeIgnored,
    BugOtpCounterRepeats,
    BugOtpPressTypesUnpersisted,
    BugOtpBootKeepsPosition,
    BugOtpSwapKeepsSession

PivPolicies == {"never", "once", "always"}
Algorithms  == {"a", "b"}

(* The replay position a typed Yubico OTP carries: the persisted use counter *)
(* and the RAM session counter, as one pair, because that is the ordering a  *)
(* validation server rejects a replay by (crates/rsk-otp/src/ticket.rs:166). *)
Positions == (0..CounterMax) \X (0..SessionMax)
ZeroPos   == << 0, 0 >>

InvNames == {
    "PivOperationNeedsSlotPolicy",
    "PivAlwaysSpendsFreshness",
    "OathCredentialNeedsItsGates",
    "OtpSlotMutationNeedsItsCode",
    "OtpCounterNeverRepeats"
}

VARIABLES
    pivPolicy,
    pivVerified,
    pivFresh,
    pgpAttribute,
    pgpKeyAttribute,
    pgpKeyPresent,
    oathCodeSet,
    oathValidated,
    oathTouchRequired,
    otpPresent,
    otpProtected,
    otpUse,
    otpSess,
    otpMarked,
    otpMark,
    viol

(* Grouped because the OTP half is six functions now and every one of the    *)
(* ten actions outside it leaves all six alone: spelled out, that is a       *)
(* sixty-line restatement of one fact.                                       *)
otpVars == << otpPresent, otpProtected, otpUse, otpSess, otpMarked, otpMark >>

vars == << pivPolicy, pivVerified, pivFresh,
           pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
           oathCodeSet, oathValidated, oathTouchRequired,
           otpVars, viol >>

TypeOK ==
    /\ pivPolicy \in PivPolicies
    /\ pivVerified \in BOOLEAN
    /\ pivFresh \in BOOLEAN
    /\ pgpAttribute \in Algorithms
    /\ pgpKeyAttribute \in Algorithms
    /\ pgpKeyPresent \in BOOLEAN
    /\ oathCodeSet \in BOOLEAN
    /\ oathValidated \in BOOLEAN
    /\ oathTouchRequired \in BOOLEAN
    /\ otpPresent \in [Slots -> BOOLEAN]
    /\ otpProtected \in [Slots -> BOOLEAN]
    /\ otpUse \in [Slots -> 0..CounterMax]
    /\ otpSess \in [Slots -> 0..SessionMax]
    /\ otpMarked \in [Slots -> BOOLEAN]
    /\ otpMark \in [Slots -> Positions]
    /\ viol \in SUBSET InvNames

Init ==
    /\ pivPolicy = "never"
    /\ pivVerified = FALSE
    /\ pivFresh = FALSE
    /\ pgpAttribute = "a"
    /\ pgpKeyAttribute = "a"
    /\ pgpKeyPresent = FALSE
    /\ oathCodeSet = FALSE
    /\ oathValidated = TRUE
    /\ oathTouchRequired = FALSE
    /\ otpPresent = [k \in Slots |-> FALSE]
    /\ otpProtected = [k \in Slots |-> FALSE]
    /\ otpUse = [k \in Slots |-> 0]
    /\ otpSess = [k \in Slots |-> 0]
    /\ otpMarked = [k \in Slots |-> FALSE]
    /\ otpMark = [k \in Slots |-> ZeroPos]
    /\ viol = {}

(***************************************************************************)
(* PIV. `pin_satisfied` resolves NEVER/ONCE/ALWAYS, and `spend_pin` clears *)
(* freshness after a PIN-gated key operation                               *)
(* (crates/rsk-piv/src/auth.rs:62-69, 118-122).                            *)
(***************************************************************************)
PivAllowed ==
    CASE pivPolicy = "never"  -> TRUE
      [] pivPolicy = "once"   -> pivVerified
      [] pivPolicy = "always" -> pivVerified /\ pivFresh

PivChoosePolicy(p) ==
    /\ pivPolicy' = p
    /\ UNCHANGED << pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpVars, viol >>

PivVerify ==
    /\ pivVerified' = TRUE
    /\ pivFresh' = TRUE
    /\ UNCHANGED << pivPolicy,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpVars, viol >>

PivKeyOp ==
    LET guard == IF BugPivPolicyIgnored THEN TRUE ELSE PivAllowed
        spent == IF pivPolicy # "never" /\ ~BugPivAlwaysDoesNotSpend
                   THEN FALSE ELSE pivFresh
    IN /\ guard
       /\ pivFresh' = spent
       /\ viol' = viol
            \cup (IF ~PivAllowed THEN {"PivOperationNeedsSlotPolicy"} ELSE {})
            \cup (IF pivPolicy = "always" /\ pivFresh /\ spent
                    THEN {"PivAlwaysSpendsFreshness"} ELSE {})
       /\ UNCHANGED << pivPolicy, pivVerified,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired,
                       otpVars >>

(***************************************************************************)
(* OpenPGP. A generated/imported key records its algorithm attribute; an   *)
(* operation must agree with that stored metadata                          *)
(* (crates/rsk-openpgp/src/keypairgen.rs:79-122 and keys.rs' algorithm     *)
(* checks), even if the public C1/C2/C3 DO later changes.                  *)
(***************************************************************************)
PgpSetAttribute(a) ==
    /\ pgpAttribute' = a
    /\ pgpKeyPresent' = IF a # pgpAttribute /\ ~BugPgpAttributeKeepsKey
                               THEN FALSE ELSE pgpKeyPresent
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpKeyAttribute,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpVars, viol >>

PgpGenerate ==
    /\ pgpKeyPresent' = TRUE
    /\ pgpKeyAttribute' = pgpAttribute
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh, pgpAttribute,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpVars, viol >>

PgpDelete ==
    /\ pgpKeyPresent' = FALSE
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpVars, viol >>

(***************************************************************************)
(* OATH. `cmd_calculate` first requires the access-code session, then a    *)
(* confirmed touch for PROP_TOUCH credentials                              *)
(* (crates/rsk-oath/src/lib.rs:585-617).                                   *)
(***************************************************************************)
OathSetCode ==
    /\ oathCodeSet' = TRUE
    /\ oathValidated' = FALSE
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathTouchRequired, otpVars, viol >>

OathValidate(correct) ==
    /\ oathValidated' = IF oathCodeSet /\ correct THEN TRUE ELSE oathValidated
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathTouchRequired,
                    otpVars, viol >>

OathSetTouch(required) ==
    /\ oathTouchRequired' = required
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated,
                    otpVars, viol >>

OathCalculate(touched) ==
    LET codePolicy  == ~oathCodeSet \/ oathValidated
        touchPolicy == ~oathTouchRequired \/ touched
        codeGuard   == codePolicy \/ BugOathCodeIgnored
        touchGuard  == touchPolicy \/ BugOathTouchIgnored
    IN /\ codeGuard /\ touchGuard
       /\ viol' = IF codePolicy /\ touchPolicy THEN viol
                    ELSE viol \cup {"OathCredentialNeedsItsGates"}
       /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired,
                       otpVars >>

(***************************************************************************)
(* Yubico OTP. Existing-slot configure, update and swap each state the     *)
(* stored-six-byte-code rule at their OWN gate, so the citation names all  *)
(* three (crates/rsk-otp/src/lib.rs:457-474, 519-533, 608-615): a range    *)
(* resolving to a prologue reads as a gate nothing checks.                 *)
(*                                                                         *)
(* The position is a PAIR, per slot, because the two halves live in        *)
(* different memories and only one of them moves on a press                *)
(* (crates/rsk-otp/src/counter.rs:16-26): the RAM session rolls every      *)
(* press and the persisted use counter advances only at its wrap. `Slots`  *)
(* is a set and not a scalar because the two halves are also indexed       *)
(* differently: the use counter belongs to the RECORD, the session to      *)
(* the slot number, and a swap is where that difference becomes a defect.  *)
(***************************************************************************)

(***************************************************************************)
(* HOW THE REPEAT IS CAUGHT, and what it costs. A record's whole emission  *)
(* history is unbounded, so `OtpUse` instead MARKS one position it emits,  *)
(* nondeterministically, and reports the invariant when that record emits  *)
(* the marked pair again. Every repeat has a first occurrence and the      *)
(* marker may decline every press before it, so nothing is missed; what is *)
(* bought is one pair of state variables instead of a set per slot.        *)
(*                                                                         *)
(* `OtpConfigure` clears the mark: a re-programmed slot is a new           *)
(* secret with a new public id, so reusing a pair under it is not          *)
(* a replay. That is the "since its CONFIGURE" in the property, and        *)
(* it is why the model reaches a re-configure as delete-then-              *)
(* configure rather than as one step -- the device's one-step form         *)
(* differs only in leaving the RAM session alone, which the two-step       *)
(* form does too (crates/rsk-otp/src/tests.rs:1485).                       *)
(***************************************************************************)

(***************************************************************************)
(* WHAT THE `otpUse[k] < CounterMax` GUARD IS. It is a bound on the CLAIM, *)
(* not a fact about the device. At the real ceiling the device goes on     *)
(* typing and the pair repeats once the session rolls; the guard stops     *)
(* the model before that, so what is proved here is the claim BELOW the    *)
(* ceiling. That residual, and the warm reset -- ungated, deliberately     *)
(* unbumped, so a cycle's pairs are typeable again -- are stated in        *)
(* docs/threat-model.md#TM-HOST-OTP-REPLAY, and neither is modelled.       *)
(***************************************************************************)
OtpConfigure(k, protected) ==
    /\ ~otpPresent[k]
    /\ otpPresent' = [otpPresent EXCEPT ![k] = TRUE]
    /\ otpProtected' = [otpProtected EXCEPT ![k] = protected]
    /\ otpUse' = [otpUse EXCEPT ![k] = 0]
    /\ otpMarked' = [otpMarked EXCEPT ![k] = FALSE]
    /\ otpMark' = [otpMark EXCEPT ![k] = ZeroPos]
    (* The RAM session counter is not the record's and is not rewound with it. *)
    /\ UNCHANGED << otpSess,
                    pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated, oathTouchRequired, viol >>

OtpMutate(k, codeMatches, keep) ==
    LET policy == ~otpProtected[k] \/ codeMatches
        guard  == policy \/ BugOtpCodeIgnored
    IN /\ otpPresent[k]
       /\ guard
       /\ otpPresent' = [otpPresent EXCEPT ![k] = keep]
       /\ otpProtected' = [otpProtected EXCEPT ![k] =
                             IF keep THEN otpProtected[k] ELSE FALSE]
       /\ otpUse' = [otpUse EXCEPT ![k] = IF keep THEN otpUse[k] ELSE 0]
       /\ otpMarked' = [otpMarked EXCEPT ![k] = IF keep THEN otpMarked[k] ELSE FALSE]
       /\ otpMark' = [otpMark EXCEPT ![k] = IF keep THEN otpMark[k] ELSE ZeroPos]
       /\ viol' = IF policy THEN viol
                            ELSE viol \cup {"OtpSlotMutationNeedsItsCode"}
       /\ UNCHANGED << otpSess,
                       pivPolicy, pivVerified, pivFresh,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired >>

(***************************************************************************)
(* SLOT_SWAP moves the record; the volatile half of the position has to    *)
(* travel with it, or the moved record is re-paired with a session used    *)
(* fewer times (crates/rsk-otp/src/lib.rs:643-649). The mark travels for   *)
(* the same reason: it is the RECORD's history, not the slot's. A          *)
(* programmed slot's stored code gates its move exactly as it gates an     *)
(* overwrite, so an absent slot imposes no gate                            *)
(* (crates/rsk-otp/src/lib.rs:611-615).                                    *)
(***************************************************************************)
OtpSwap(j, k, codeMatches) ==
    LET gated(s) == otpPresent[s] /\ otpProtected[s]
        policy   == (~gated(j) /\ ~gated(k)) \/ codeMatches
        guard    == policy \/ BugOtpCodeIgnored
    (* The unordered pair, taken here rather than beside the `\E`: a disjunct  *)
    (* of `Next` that is not a bare application is an action TLC does not NAME, *)
    (* and COVERAGE=1's dead-action rule reads names. Measured -- as            *)
    (* `j < k /\ OtpSwap(...)` this fired under `<Next>` and was invisible.     *)
    IN /\ j < k
       /\ guard
       /\ otpPresent' = [otpPresent EXCEPT ![j] = otpPresent[k], ![k] = otpPresent[j]]
       /\ otpProtected' = [otpProtected EXCEPT ![j] = otpProtected[k],
                                               ![k] = otpProtected[j]]
       /\ otpUse' = [otpUse EXCEPT ![j] = otpUse[k], ![k] = otpUse[j]]
       /\ otpMarked' = [otpMarked EXCEPT ![j] = otpMarked[k], ![k] = otpMarked[j]]
       /\ otpMark' = [otpMark EXCEPT ![j] = otpMark[k], ![k] = otpMark[j]]
       /\ otpSess' = IF BugOtpSwapKeepsSession THEN otpSess
                     ELSE [otpSess EXCEPT ![j] = otpSess[k], ![k] = otpSess[j]]
       /\ viol' = IF policy THEN viol
                            ELSE viol \cup {"OtpSlotMutationNeedsItsCode"}
       /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired >>

(***************************************************************************)
(* A cold boot: the RAM session restarts at zero, so `power_up_bump`       *)
(* advances the persisted half of every plain slot it can read that still  *)
(* has room, before USB is up (crates/rsk-otp/src/lib.rs:1146-1191). That  *)
(* is what keeps one power cycle's pairs out of the next one's, so the mark*)
(* deliberately SURVIVES the cycle.                                        *)
(***************************************************************************)
OtpPowerCycle ==
    /\ otpSess' = [k \in Slots |-> 0]
    /\ otpUse' = IF BugOtpBootKeepsPosition THEN otpUse
                 ELSE [k \in Slots |-> IF otpPresent[k] /\ otpUse[k] < CounterMax
                                         THEN otpUse[k] + 1 ELSE otpUse[k]]
    /\ UNCHANGED << otpPresent, otpProtected, otpMarked, otpMark,
                    pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated, oathTouchRequired, viol >>

OtpUse(k) ==
    LET pos      == << otpUse[k], otpSess[k] >>
        wrapped  == otpSess[k] = SessionMax
        persist  == wrapped /\ otpUse[k] < CounterMax
        frozen   == BugOtpCounterRepeats
        nextSess == IF frozen THEN otpSess[k]
                    ELSE IF wrapped THEN 0 ELSE otpSess[k] + 1
        (* The press that owes flash an advance and types without it: the RAM *)
        (* half rolls anyway, so the next press re-pairs the old counter with *)
        (* this cycle's first session (crates/rsk-otp/src/lib.rs:334-349).    *)
        nextUse  == IF frozen \/ BugOtpPressTypesUnpersisted THEN otpUse[k]
                    ELSE IF persist THEN otpUse[k] + 1 ELSE otpUse[k]
        repeat   == otpMarked[k] /\ otpMark[k] = pos
    IN /\ otpPresent[k]
       /\ otpUse[k] < CounterMax
       /\ otpSess' = [otpSess EXCEPT ![k] = nextSess]
       /\ otpUse' = [otpUse EXCEPT ![k] = nextUse]
       /\ \/ /\ ~otpMarked[k]
             /\ otpMarked' = [otpMarked EXCEPT ![k] = TRUE]
             /\ otpMark' = [otpMark EXCEPT ![k] = pos]
          \/ /\ otpMarked' = otpMarked
             /\ otpMark' = otpMark
       /\ viol' = IF repeat THEN viol \cup {"OtpCounterNeverRepeats"} ELSE viol
       /\ UNCHANGED << otpPresent, otpProtected,
                       pivPolicy, pivVerified, pivFresh,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired >>

Next ==
    \/ \E p \in PivPolicies : PivChoosePolicy(p)
    \/ PivVerify
    \/ PivKeyOp
    \/ \E a \in Algorithms : PgpSetAttribute(a)
    \/ PgpGenerate
    \/ PgpDelete
    \/ OathSetCode
    \/ \E correct \in BOOLEAN : OathValidate(correct)
    \/ \E required \in BOOLEAN : OathSetTouch(required)
    \/ \E touched \in BOOLEAN : OathCalculate(touched)
    \/ \E k \in Slots, protected \in BOOLEAN : OtpConfigure(k, protected)
    \/ \E k \in Slots, codeMatches \in BOOLEAN, keep \in BOOLEAN :
          OtpMutate(k, codeMatches, keep)
    \/ \E j \in Slots, k \in Slots, codeMatches \in BOOLEAN :
          OtpSwap(j, k, codeMatches)
    \/ OtpPowerCycle
    \/ \E k \in Slots : OtpUse(k)

Spec == Init /\ [][Next]_vars

PivOperationNeedsSlotPolicy == "PivOperationNeedsSlotPolicy" \notin viol
PivAlwaysSpendsFreshness == "PivAlwaysSpendsFreshness" \notin viol
AttributeChangeInvalidatesTheKey == ~pgpKeyPresent \/ pgpKeyAttribute = pgpAttribute
OathCredentialNeedsItsGates == "OathCredentialNeedsItsGates" \notin viol
OtpSlotMutationNeedsItsCode == "OtpSlotMutationNeedsItsCode" \notin viol
OtpCounterNeverRepeats == "OtpCounterNeverRepeats" \notin viol

=============================================================================
