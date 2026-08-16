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
    BugPivPolicyIgnored,
    BugPivAlwaysDoesNotSpend,
    BugPgpAttributeKeepsKey,
    BugOathCodeIgnored,
    BugOathTouchIgnored,
    BugOtpCodeIgnored,
    BugOtpCounterRepeats

PivPolicies == {"never", "once", "always"}
Algorithms  == {"a", "b"}

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
    otpCounter,
    viol

vars == << pivPolicy, pivVerified, pivFresh,
           pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
           oathCodeSet, oathValidated, oathTouchRequired,
           otpPresent, otpProtected, otpCounter, viol >>

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
    /\ otpPresent \in BOOLEAN
    /\ otpProtected \in BOOLEAN
    /\ otpCounter \in 0..CounterMax
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
    /\ otpPresent = FALSE
    /\ otpProtected = FALSE
    /\ otpCounter = 0
    /\ viol = {}

(***************************************************************************)
(* PIV. `pin_satisfied` resolves NEVER/ONCE/ALWAYS, and `spend_pin` clears   *)
(* freshness after a PIN-gated key operation (rsk-piv/src/auth.rs:58-66,    *)
(* 114-118).                                                                *)
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
                    otpPresent, otpProtected, otpCounter, viol >>

PivVerify ==
    /\ pivVerified' = TRUE
    /\ pivFresh' = TRUE
    /\ UNCHANGED << pivPolicy,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpPresent, otpProtected, otpCounter, viol >>

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
                       otpPresent, otpProtected, otpCounter >>

(***************************************************************************)
(* OpenPGP. A generated/imported key records its algorithm attribute; an     *)
(* operation must agree with that stored metadata (keypairgen.rs:79-117 and  *)
(* keys.rs' algorithm checks), even if the public C1/C2/C3 DO later changes. *)
(***************************************************************************)
PgpSetAttribute(a) ==
    /\ pgpAttribute' = a
    /\ pgpKeyPresent' = IF a # pgpAttribute /\ ~BugPgpAttributeKeepsKey
                               THEN FALSE ELSE pgpKeyPresent
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpKeyAttribute,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpPresent, otpProtected, otpCounter, viol >>

PgpGenerate ==
    /\ pgpKeyPresent' = TRUE
    /\ pgpKeyAttribute' = pgpAttribute
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh, pgpAttribute,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpPresent, otpProtected, otpCounter, viol >>

PgpDelete ==
    /\ pgpKeyPresent' = FALSE
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute,
                    oathCodeSet, oathValidated, oathTouchRequired,
                    otpPresent, otpProtected, otpCounter, viol >>

(***************************************************************************)
(* OATH. `cmd_calculate` first requires the access-code session, then a       *)
(* confirmed touch for PROP_TOUCH credentials (rsk-oath/src/lib.rs:555-587). *)
(***************************************************************************)
OathSetCode ==
    /\ oathCodeSet' = TRUE
    /\ oathValidated' = FALSE
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathTouchRequired, otpPresent, otpProtected, otpCounter,
                    viol >>

OathValidate(correct) ==
    /\ oathValidated' = IF oathCodeSet /\ correct THEN TRUE ELSE oathValidated
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathTouchRequired,
                    otpPresent, otpProtected, otpCounter, viol >>

OathSetTouch(required) ==
    /\ oathTouchRequired' = required
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated,
                    otpPresent, otpProtected, otpCounter, viol >>

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
                       otpPresent, otpProtected, otpCounter >>

(***************************************************************************)
(* Yubico OTP. Existing-slot configure/update/delete/swap all require the    *)
(* stored six-byte code (rsk-otp/src/lib.rs:438-450, 564-569), while each    *)
(* emitted OTP advances the combined persisted-use/RAM-session position.     *)
(***************************************************************************)
OtpConfigure(protected) ==
    /\ ~otpPresent
    /\ otpPresent' = TRUE
    /\ otpProtected' = protected
    /\ otpCounter' = 0
    /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                    pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                    oathCodeSet, oathValidated, oathTouchRequired, viol >>

OtpMutate(codeMatches, keep) ==
    LET policy == ~otpProtected \/ codeMatches
        guard  == policy \/ BugOtpCodeIgnored
    IN /\ otpPresent
       /\ guard
       /\ otpPresent' = keep
       /\ otpProtected' = IF keep THEN otpProtected ELSE FALSE
       /\ otpCounter' = IF keep THEN otpCounter ELSE 0
       /\ viol' = IF policy THEN viol
                            ELSE viol \cup {"OtpSlotMutationNeedsItsCode"}
       /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired >>

OtpUse ==
    LET nextCounter == IF BugOtpCounterRepeats THEN otpCounter
                       ELSE otpCounter + 1
    IN /\ otpPresent
       /\ otpCounter < CounterMax
       /\ otpCounter' = nextCounter
       /\ viol' = IF nextCounter > otpCounter THEN viol
                    ELSE viol \cup {"OtpCounterNeverRepeats"}
       /\ UNCHANGED << pivPolicy, pivVerified, pivFresh,
                       pgpAttribute, pgpKeyAttribute, pgpKeyPresent,
                       oathCodeSet, oathValidated, oathTouchRequired,
                       otpPresent, otpProtected >>

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
    \/ \E protected \in BOOLEAN : OtpConfigure(protected)
    \/ \E codeMatches \in BOOLEAN, keep \in BOOLEAN : OtpMutate(codeMatches, keep)
    \/ OtpUse

Spec == Init /\ [][Next]_vars

PivOperationNeedsSlotPolicy == "PivOperationNeedsSlotPolicy" \notin viol
PivAlwaysSpendsFreshness == "PivAlwaysSpendsFreshness" \notin viol
AttributeChangeInvalidatesTheKey == ~pgpKeyPresent \/ pgpKeyAttribute = pgpAttribute
OathCredentialNeedsItsGates == "OathCredentialNeedsItsGates" \notin viol
OtpSlotMutationNeedsItsCode == "OtpSlotMutationNeedsItsCode" \notin viol
OtpCounterNeverRepeats == "OtpCounterNeverRepeats" \notin viol

=============================================================================
