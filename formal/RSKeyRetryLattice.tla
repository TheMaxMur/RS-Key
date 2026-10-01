--------------------------- MODULE RSKeyRetryLattice ---------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* The RETRY & RECOVERY BUDGET LATTICE of the two applets that have one:     *)
(* PIV (the PIN and its PUK) and OpenPGP (PW1, PW3 and the resetting code    *)
(* RC). Not the applets' command sets, not their status LIFETIME -- that is  *)
(* RSKeyAppletSeams's job, who holds which status and what a SELECT or a     *)
(* refusal does to it. This module is one layer beneath that: the finite     *)
(* retry counter behind each reference, the maximum it is refilled to, the   *)
(* recovery reference that can refill it, and the anti-bruteforce arithmetic *)
(* that is the same at every one -- spend on a wrong attempt, refuse at      *)
(* zero, refill only on a correct secret or an authorised administrative     *)
(* command. CountWithinMaximum assumes a history without storage faults.   *)
(*                                                                           *)
(* WHY MODEL THIS, and why here rather than by measurement. The applets have *)
(* a YubiKey oracle and their WIRE surface was attacked with it (~47 group-E *)
(* findings). The retry ladder has NO safe oracle: measuring a real PUK      *)
(* ladder to exhaustion blocks that reference, and recovery depends on      *)
(* other secrets or administrative statuses. The model explores every       *)
(* verify/block/recover interleaving without risking a real card. A fourth  *)
(* module and not more of the seam one because the two share no variable --  *)
(* the seam has statuses and selections, this has counters -- so a product   *)
(* multiplies state and buys no interleaving, the measured reason the seam   *)
(* module gave for being a second. Administrative doors read statuses, so   *)
(* the statuses a VERIFY raises are tracked beside the counters (`held`),   *)
(* more coarsely than the seam module keeps them.                           *)
(*                                                                           *)
(* THE METHOD is the three siblings': a Guard the Rust tests (mutable by a   *)
(* Bug* switch) against a Policy the requirement fixes; a step the Policy     *)
(* forbids records the violated invariant in `viol`. Each Bug* rebuilds a    *)
(* real defended site, and each must make TLC produce a counterexample.      *)
(*                                                                           *)
(* THE SECRET IS ABSTRACTED to matched / not-matched: `correct` is a         *)
(* nondeterministic BOOLEAN standing for "the presented value equalled the   *)
(* stored verifier". The comparison's cryptography, the PIN bytes and the    *)
(* wire framing are elsewhere -- this model is only the counter arithmetic   *)
(* around the comparison's answer.                                           *)
(*****************************************************************************)
EXTENDS Naturals

CONSTANTS
    Max,   \* the ceiling a stored maximum may take: SET PIN RETRIES's byte, at TLC scale
    \* The `left == 0 => PIN_BLOCKED` floor, checked BEFORE the comparison at
    \* crates/rsk-piv/src/lib.rs:1355-1357 (check_ref) and
    \* crates/rsk-openpgp/src/pin.rs:245-247 (check_pin). One switch: the same
    \* floor guards a direct verify AND a recovery reference (the PUK/RC that
    \* check_ref/check_pin is called on), so removing it opens both.
    BugUseWhenBlocked,
    \* The decrement that IS the anti-bruteforce gate: crates/rsk-piv/src/lib.rs:1375
    \* (`set_retries_left(fs, retry, left - 1)`, spent BEFORE the compare) and
    \* crates/rsk-openpgp/src/pin.rs:152 (`pw[idx] -= 1`). Removing it lets a wrong
    \* attempt cost nothing -- unlimited guesses at full speed.
    BugWrongDoesNotSpend,
    \* The recovery reference verified BEFORE the target is refilled:
    \* crates/rsk-piv/src/lib.rs:1512 (`check_ref(EF_PUK, ..)` opens
    \* unblock_pin_with_puk) and crates/rsk-openpgp/src/pin.rs:949 (`check_pin(EF_RC,
    \* ..)` opens reset_retry's P1=0 branch). Removing it refills the target on a
    \* WRONG recovery secret.
    BugRecoveryWithoutSecret,
    \* SET PIN RETRIES's admin guard, crates/rsk-openpgp/src/retries.rs:33-35,
    \* dropped: every budget the command names rises with no status held at all.
    BugSetRetriesWithoutAdmin,
    \* The same guard taking the USER's status for the admin's: a budget raised
    \* under PW1 alone, the non-admin refill.
    BugSetRetriesOnUserStatus,
    \* SET PIN RETRIES resetting a count to the maximum it REPLACES rather than to
    \* the one it sets (crates/rsk-openpgp/src/retries.rs:65-69): a lowered maximum
    \* over a spent count hands the old maximum's tries back.
    BugSetRetriesRefillsOldMaximum,
    \* F2 changes a maximum but leaves its count above the lowered limit.
    BugSetRetriesKeepsCount,
    \* PIV FA needs both statuses (crates/rsk-piv/src/lib.rs:609-612).
    BugPivSetRetriesWithoutMgm,
    BugPivSetRetriesWithoutPin,
    \* Each OpenPGP replacement door checks PW3 before load_dek can use PW1.
    BugResetRetryWithoutAdmin,
    BugResetCodeWithoutAdmin,
    BugKdfWithoutAdmin,
    \* PUT DATA F9 refuses to reseed beside any existing private key.
    BugKdfWithKeys

\* Every reference that carries a retry counter. PW2 (PW1 mode 0x82) is NOT here:
\* it shares PW1's verifier and counter (crates/rsk-openpgp/src/pin.rs:709), so it
\* is PW1's counter under another name. The OATH access code and the OTP slot code
\* are NOT here either: a MAC / equality challenge-response has NO retry counter
\* (a wrong answer costs nothing), so they are the seam module's exempt-refusal
\* territory and their acceptance is the group-E oracle's, not this lattice's.
Refs == {"pivPin", "pivPuk", "pw1", "pw3", "rc"}

\* The references a host VERIFY targets directly. `pivPuk` and `rc` are absent:
\* neither is verified on its own, only PRESENTED as the recovery secret inside a
\* RESET RETRY (crates/rsk-piv/src/lib.rs:596-603, crates/rsk-openpgp/src/pin.rs:926-977),
\* where a wrong one still spends its counter.
VerifyTargets == {"pivPin", "pw1", "pw3"}

\* Presented-secret recovery is distinct from the administrative doors below.
\* Neither a blocked PW3 nor a PUK has another presented recovery reference;
\* PIV FA may restore a blocked PUK while the PIN and management key are held.
RecoveryOf(r) ==
    CASE r = "pivPin" -> {"pivPuk"}
      [] r = "pw1"    -> {"rc"}
      [] OTHER        -> {}

\* F2 names only OpenPGP's three references. FA has its own action and guard.
PgpRefs == {"pw1", "rc", "pw3"}

InvNames == { "NoAuthWhenBlocked", "WrongAttemptIsCharged",
              "BudgetRisesOnlyWithItsSecret" }

VARIABLES
    retries,  \* [Refs -> 0..Max]: the remaining attempts at each reference
    maxima,   \* [Refs -> 1..Max]: each reference's stored maximum (EF_PW_RETRIES)
    held,     \* the VerifyTargets whose status a correct VERIFY raised and holds
    mgm,      \* PIV's management-key status, which has no retry counter
    rcSet,    \* whether a resetting-code verifier exists (not whether blocked)
    viol      \* ghost: the set of invariant names some step has violated

vars == << retries, maxima, held, mgm, rcSet, viol >>

TypeOK ==
    /\ retries \in [Refs -> 0..Max]
    /\ maxima \in [Refs -> 1..Max]
    /\ held \in SUBSET VerifyTargets
    /\ mgm \in BOOLEAN
    /\ rcSet \in BOOLEAN
    /\ viol \in SUBSET InvNames

\* A fresh card: every maximum at the ceiling, every counter at its maximum, no
\* status held.
Init ==
    /\ maxima = [r \in Refs |-> Max]
    /\ retries = [r \in Refs |-> IF r = "rc" THEN 0 ELSE Max]
    /\ held = {}
    /\ mgm = FALSE
    /\ rcSet = FALSE
    /\ viol = {}

(***************************************************************************)
(* VERIFY. crates/rsk-piv/src/lib.rs:1350-1417 (check_ref) and              *)
(* crates/rsk-openpgp/src/pin.rs:222-317 (check_pin): refuse at zero, spend  *)
(* on a wrong value, refill on a correct one -- to the reference's own      *)
(* maximum, which pin_reset_retries reads (crates/rsk-openpgp/src/pin.rs:183).*)
(* The status: a grant raises it (crates/rsk-openpgp/src/pin.rs:314), a      *)
(* wrong value drops it (clear_access_status,                              *)
(* crates/rsk-openpgp/src/pin.rs:206-216). A card reset, a SELECT elsewhere  *)
(* and the RESET RETRY that drops all three                                 *)
(* (crates/rsk-openpgp/src/pin.rs:957-959) end it too; those are the seam    *)
(* module's, and leaving them out here only keeps a status up LONGER.       *)
(***************************************************************************)
\* Always enabled: a blocked card still ANSWERS every VERIFY -- it returns
\* PIN_BLOCKED and changes nothing, which is a step, not a dead end. So a blocked
\* reference's verify is a no-op refusal here, never a disabled action, and the
\* all-blocked state (a locked-out card) has successors rather than deadlocking.
Verify(r) ==
    \E correct \in BOOLEAN :
        LET blocked  == retries[r] = 0
            \* a grant needs a correct secret AND an unblocked counter -- unless the
            \* switch drops the floor and lets a blocked reference authenticate
            grants   == correct /\ ((~blocked) \/ BugUseWhenBlocked)
            \* a wrong attempt spends one, but only at an unblocked reference
            doCharge == (~correct) /\ (~blocked)
            spent    == IF doCharge /\ (~BugWrongDoesNotSpend)
                          THEN retries[r] - 1 ELSE retries[r]
        IN /\ retries' = [retries EXCEPT ![r] = IF grants THEN maxima[r] ELSE spent]
           \* PW1 has two modes sharing one counter: a wrong mode may leave the
           \* other mode's status up (clear_access_status clears only its P2).
           /\ held' \in IF grants THEN {held \cup {r}}
                        ELSE IF correct THEN {held}
                        ELSE IF r = "pw1" THEN {held, held \ {r}}
                        ELSE {held \ {r}}
           /\ UNCHANGED << maxima, mgm, rcSet >>
           \* A grant on a reference that was at zero is the whole point of the
           \* blocked floor. It is a step, not a state: the success path refills
           \* the counter to its maximum, so no reachable state shows the exhaustion.
           /\ viol' = viol
                \cup (IF grants /\ blocked
                        THEN {"NoAuthWhenBlocked"} ELSE {})
                \cup (IF doCharge /\ (spent # (retries[r] - 1))
                        THEN {"WrongAttemptIsCharged"} ELSE {})

(***************************************************************************)
(* RECOVER. RESET RETRY COUNTER: present the recovery secret `via`, and on a *)
(* correct one refill the target `r` to its maximum. A wrong `via` spends   *)
(* VIA's counter (check_ref/check_pin is called on it); a blocked `via`      *)
(* refuses.                                                                 *)
(***************************************************************************)
\* Always enabled for a reference that has a recovery, for the same reason: a
\* RESET RETRY against a blocked PUK/RC is answered, not deadlocked.
Recover(r) ==
    \E via \in RecoveryOf(r), correct \in BOOLEAN :
        LET viaBlocked == retries[via] = 0
            proceeds   == (via # "rc" \/ rcSet) /\ ((~viaBlocked) \/ BugUseWhenBlocked)
            \* the target is refilled iff a usable secret was presented -- a
            \* correct one that got past the floor, or the switch that skips it
            refills    == proceeds /\ (correct \/ BugRecoveryWithoutSecret)
            \* a wrong recovery secret at an unblocked reference spends one of ITS
            doCharge   == proceeds /\ (~refills) /\ (~viaBlocked)
            spentVia   == IF doCharge /\ (~BugWrongDoesNotSpend)
                            THEN retries[via] - 1 ELSE retries[via]
        IN /\ retries' =
                IF refills THEN [retries EXCEPT ![r] = maxima[r], ![via] = maxima[via]]
                           ELSE [retries EXCEPT ![via] = spentVia]
           /\ UNCHANGED << maxima, held, mgm, rcSet >>
           \* refilling through a blocked recovery reference is the recovery-side
           \* face of the blocked floor; refilling on a WRONG secret is a budget
           \* raised out of nothing.
           /\ viol' = viol
                \cup (IF refills /\ viaBlocked
                        THEN {"NoAuthWhenBlocked"} ELSE {})
                \cup (IF refills /\ (~correct)
                        THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})
                \cup (IF doCharge /\ (spentVia # (retries[via] - 1))
                        THEN {"WrongAttemptIsCharged"} ELSE {})

(***************************************************************************)
(* SET PIN RETRIES. OpenPGP INS F2, set_pin_retries at                      *)
(* crates/rsk-openpgp/src/retries.rs:32-80: with PW3 held                   *)
(* (crates/rsk-openpgp/src/retries.rs:33-35), one byte per reference in     *)
(* PgpRefs -- 0 leaves it as it is, any other value sets its maximum AND its *)
(* count to that value (crates/rsk-openpgp/src/retries.rs:65-69), a blocked *)
(* one included. No secret is presented and no status changes. An unset RC *)
(* keeps its zero count (crates/rsk-openpgp/src/retries.rs:66-67); D3 sets   *)
(* its verifier and activates its counter, and KDF reseeding clears it.                                             *)
(***************************************************************************)
\* The guard: PW3's status, and the two ways a mutant lets F2 through without it.
SetRetriesGuard ==
    \/ "pw3" \in held
    \/ BugSetRetriesWithoutAdmin
    \/ BugSetRetriesOnUserStatus /\ "pw1" \in held

\* Enabled only where its guard holds: a refused F2 (6982) changes nothing, so the
\* stuttering step it would be adds no behaviour.
SetRetries ==
    /\ SetRetriesGuard
    /\ \E b \in [PgpRefs -> 0..Max] :
        LET named(r)   == r \in PgpRefs /\ b[r] # 0
            newLeft(r) == IF ~named(r) \/ (r = "rc" /\ ~rcSet)
                             \/ BugSetRetriesKeepsCount THEN retries[r]
                          ELSE IF BugSetRetriesRefillsOldMaximum THEN maxima[r]
                          ELSE b[r]
            \* the requirement: a count this step raises is raised with PW3 held,
            \* at a reference whose new maximum the step sets, and to that maximum
            earned(r)  == "pw3" \in held /\ named(r) /\ newLeft(r) = b[r]
        IN /\ maxima' = [r \in Refs |-> IF named(r) THEN b[r] ELSE maxima[r]]
           /\ retries' = [r \in Refs |-> newLeft(r)]
           /\ UNCHANGED << held, mgm, rcSet >>
           /\ viol' = viol
                \cup (IF \E r \in Refs : newLeft(r) > retries[r] /\ ~earned(r)
                        THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})

\* Management authentication has no retry budget; its comparison is abstracted.
ManagementAuth ==
    /\ mgm' \in BOOLEAN
    /\ UNCHANGED << retries, maxima, held, rcSet, viol >>

\* FA writes both totals/counts before replacing the PIN and PUK verifiers.
\* A refused replacement can leave the new counts; the two statuses authorise
\* that rise already (crates/rsk-piv/src/lib.rs:609-649).
PivSetRetries ==
    /\ (mgm \/ BugPivSetRetriesWithoutMgm)
    /\ ("pivPin" \in held \/ BugPivSetRetriesWithoutPin)
    /\ \E pinMax \in 1..Max, pukMax \in 1..Max :
        /\ maxima' = [maxima EXCEPT !["pivPin"] = pinMax, !["pivPuk"] = pukMax]
        /\ retries' = [retries EXCEPT !["pivPin"] = pinMax, !["pivPuk"] = pukMax]
        /\ held' = held \ {"pivPin"}
        /\ UNCHANGED << mgm, rcSet >>
        /\ viol' = viol \cup
            (IF (pinMax > retries["pivPin"] \/ pukMax > retries["pivPuk"])
                    /\ ~(mgm /\ "pivPin" \in held)
             THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})

\* RESET RETRY P1=02 replaces PW1 under PW3; no old PW1 is presented.
\* With the guard removed, PW1 still supplies the session needed by load_dek.
\* The refilled maximum is unchanged (crates/rsk-openpgp/src/pin.rs:982-999).
ResetRetryAdmin ==
    /\ "pw3" \in held \/ (BugResetRetryWithoutAdmin /\ "pw1" \in held)
    /\ retries' = [retries EXCEPT !["pw1"] = maxima["pw1"]]
    /\ UNCHANGED << maxima, held, mgm, rcSet >>
    /\ viol' = viol \cup
        (IF maxima["pw1"] > retries["pw1"] /\ "pw3" \notin held
         THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})

\* PUT DATA D3 activates or clears RC under PW3. Clearing never raises a count.
\* crates/rsk-openpgp/src/pin.rs:1018-1044.
PutResetCode ==
    /\ "pw3" \in held \/ (BugResetCodeWithoutAdmin /\ "pw1" \in held)
    /\ rcSet' \in BOOLEAN
    /\ retries' = [retries EXCEPT !["rc"] = IF rcSet' THEN maxima["rc"] ELSE 0]
    /\ UNCHANGED << maxima, held, mgm >>
    /\ viol' = viol \cup
        (IF retries'["rc"] > retries["rc"] /\ "pw3" \notin held
         THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})

\* F9 reseeds PW1/PW3 and clears RC only under PW3 and with every key slot empty.
\* Key presence is an input here, like `correct`; key lifetimes are elsewhere.
\* crates/rsk-openpgp/src/kdf.rs:142-158, crates/rsk-openpgp/src/kdf.rs:177-184.
KdfReseed ==
    /\ "pw3" \in held \/ (BugKdfWithoutAdmin /\ "pw1" \in held)
    /\ \E keysPresent \in BOOLEAN :
        /\ ~keysPresent \/ BugKdfWithKeys
        /\ retries' = [retries EXCEPT !["pw1"] = maxima["pw1"],
                                       !["pw3"] = maxima["pw3"], !["rc"] = 0]
        /\ rcSet' = FALSE
        /\ UNCHANGED << maxima, held, mgm >>
        /\ viol' = viol \cup
            (IF (maxima["pw1"] > retries["pw1"] \/ maxima["pw3"] > retries["pw3"])
                    /\ ("pw3" \notin held \/ keysPresent)
             THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})

Next ==
    \/ \E r \in VerifyTargets : Verify(r)
    \/ \E r \in Refs : Recover(r)
    \/ SetRetries
    \/ ManagementAuth
    \/ PivSetRetries
    \/ ResetRetryAdmin
    \/ PutResetCode
    \/ KdfReseed

Spec == Init /\ [][Next]_vars

\* These three record a step, because a refill erases its preceding exhaustion.
NoAuthWhenBlocked == "NoAuthWhenBlocked" \notin viol
WrongAttemptIsCharged == "WrongAttemptIsCharged" \notin viol
BudgetRisesOnlyWithItsSecret == "BudgetRisesOnlyWithItsSecret" \notin viol

\* In fault-free histories from Init or an in-bound state. A torn F2 increase
\* can leave its new count under the old maximum: its count write leads.
CountWithinMaximum == \A r \in Refs : retries[r] <= maxima[r]

\* One step from any admitted counter/maximum/status assignment. The bound is
\* a state invariant, so this probe excludes counts already above their maxima.
IndInv == TypeOK /\ NoAuthWhenBlocked /\ WrongAttemptIsCharged
            /\ BudgetRisesOnlyWithItsSecret /\ CountWithinMaximum
            /\ (~rcSet => retries["rc"] = 0)

=============================================================================
