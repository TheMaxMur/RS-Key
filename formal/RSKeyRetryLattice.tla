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
(* retry counter behind each reference, the recovery reference that can      *)
(* refill it, and the anti-bruteforce arithmetic that is the same at every   *)
(* one -- spend on a wrong attempt, refuse at zero, refill only on a correct *)
(* secret.                                                                    *)
(*                                                                           *)
(* WHY MODEL THIS, and why here rather than by measurement. The applets have *)
(* a YubiKey oracle and their WIRE surface was attacked with it (~47 group-E *)
(* findings). The retry ladder has NO safe oracle: measuring a real PUK      *)
(* ladder to exhaustion BLOCKS the card, and once blocked the only way back  *)
(* takes the keys. So the one place an exhaustive check of every             *)
(* verify/block/recover interleaving can run at all is a model. A fourth     *)
(* module and not more of the seam one because the two share no variable --  *)
(* the seam has statuses and selections, this has counters -- so a product   *)
(* multiplies state and buys no interleaving, the measured reason the seam   *)
(* module gave for being a second.                                           *)
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
    Max,   \* the retry ceiling; models MAX_PIN_RETRIES / the per-reference default
    \* The `left == 0 => PIN_BLOCKED` floor, checked BEFORE the comparison at
    \* crates/rsk-piv/src/lib.rs:1232-1234 (check_ref) and
    \* crates/rsk-openpgp/src/pin.rs:200-202 (check_pin). One switch: the same
    \* floor guards a direct verify AND a recovery reference (the PUK/RC that
    \* check_ref/check_pin is called on), so removing it opens both.
    BugUseWhenBlocked,
    \* The decrement that IS the anti-bruteforce gate: crates/rsk-piv/src/lib.rs:1250
    \* (`set_retries_left(fs, retry, left - 1)`, spent BEFORE the compare) and
    \* crates/rsk-openpgp/src/pin.rs:108 (`pw[idx] -= 1`). Removing it lets a wrong
    \* attempt cost nothing -- unlimited guesses at full speed.
    BugWrongDoesNotSpend,
    \* The recovery reference verified BEFORE the target is refilled:
    \* crates/rsk-piv/src/lib.rs:1383 (`check_ref(EF_PUK, ..)` opens
    \* unblock_pin_with_puk) and crates/rsk-openpgp/src/pin.rs:766 (`check_pin(EF_RC,
    \* ..)` opens reset_retry's P1=0 branch). Removing it refills the target on a
    \* WRONG recovery secret.
    BugRecoveryWithoutSecret

\* Every reference that carries a retry counter. PW2 (PW1 mode 0x82) is NOT here:
\* it shares PW1's verifier and counter (crates/rsk-openpgp/src/pin.rs:537), so it
\* is PW1's counter under another name. The OATH access code and the OTP slot code
\* are NOT here either: a MAC / equality challenge-response has NO retry counter
\* (a wrong answer costs nothing), so they are the seam module's exempt-refusal
\* territory and their acceptance is the group-E oracle's, not this lattice's.
Refs == {"pivPin", "pivPuk", "pw1", "pw3", "rc"}

\* The references a host VERIFY targets directly. `pivPuk` and `rc` are absent:
\* neither is verified on its own, only PRESENTED as the recovery secret inside a
\* RESET RETRY (crates/rsk-piv/src/lib.rs:580-587, crates/rsk-openpgp/src/pin.rs:743-793),
\* where a wrong one still spends its counter.
VerifyTargets == {"pivPin", "pw1", "pw3"}

\* The recovery graph: which reference's correct presentation refills the target's
\* counter. PIV's PUK unblocks the PIN (RESET RETRY COUNTER); OpenPGP's RC unblocks
\* PW1 (RESET RETRY, P1=0). PW3's admin path to PW1 (P1=0x02) is DELIBERATELY out:
\* it gates on a live PW3 SESSION (`sess.has_pw3`, crates/rsk-openpgp/src/pin.rs:798),
\* which is the seam
\* module's status, not a secret presented in the call. `pivPuk`, `pw3` and `rc`
\* have no recovery -- blocked is terminal for them, TERMINATE DF / factory RESET
\* being the only way back, which those own reset models cover.
RecoveryOf(r) ==
    CASE r = "pivPin" -> {"pivPuk"}
      [] r = "pw1"    -> {"rc"}
      [] OTHER        -> {}

InvNames == { "NoAuthWhenBlocked", "WrongAttemptIsCharged",
              "BudgetRisesOnlyWithItsSecret" }

VARIABLES
    retries,  \* [Refs -> 0..Max]: the remaining attempts at each reference
    viol      \* ghost: the set of invariant names some step has violated

vars == << retries, viol >>

TypeOK ==
    /\ retries \in [Refs -> 0..Max]
    /\ viol \in SUBSET InvNames

\* A fresh card: every counter at its ceiling.
Init ==
    /\ retries = [r \in Refs |-> Max]
    /\ viol = {}

(***************************************************************************)
(* VERIFY. crates/rsk-piv/src/lib.rs:1227-1290 (check_ref) and              *)
(* crates/rsk-openpgp/src/pin.rs:177-259 (check_pin): refuse at zero, spend  *)
(* on a wrong value, refill on a correct one.                              *)
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
        IN /\ retries' = [retries EXCEPT ![r] = IF grants THEN Max ELSE spent]
           \* A grant on a reference that was at zero is the whole point of the
           \* blocked floor. It is a step, not a state: the success path refills
           \* the counter to Max, so no reachable state shows the exhaustion.
           /\ viol' = viol
                \cup (IF grants /\ blocked
                        THEN {"NoAuthWhenBlocked"} ELSE {})
                \cup (IF doCharge /\ (spent # (retries[r] - 1))
                        THEN {"WrongAttemptIsCharged"} ELSE {})

(***************************************************************************)
(* RECOVER. RESET RETRY COUNTER: present the recovery secret `via`, and on a *)
(* correct one refill the target `r`. A wrong `via` spends VIA's counter     *)
(* (check_ref/check_pin is called on it); a blocked `via` refuses.          *)
(***************************************************************************)
\* Always enabled for a reference that has a recovery, for the same reason: a
\* RESET RETRY against a blocked PUK/RC is answered, not deadlocked.
Recover(r) ==
    \E via \in RecoveryOf(r), correct \in BOOLEAN :
        LET viaBlocked == retries[via] = 0
            proceeds   == (~viaBlocked) \/ BugUseWhenBlocked
            \* the target is refilled iff a usable secret was presented -- a
            \* correct one that got past the floor, or the switch that skips it
            refills    == proceeds /\ (correct \/ BugRecoveryWithoutSecret)
            \* a wrong recovery secret at an unblocked reference spends one of ITS
            doCharge   == proceeds /\ (~refills) /\ (~viaBlocked)
            spentVia   == IF doCharge /\ (~BugWrongDoesNotSpend)
                            THEN retries[via] - 1 ELSE retries[via]
        IN /\ retries' =
                IF refills THEN [retries EXCEPT ![r] = Max]
                           ELSE [retries EXCEPT ![via] = spentVia]
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

Next ==
    \/ \E r \in VerifyTargets : Verify(r)
    \/ \E r \in Refs : Recover(r)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS. All three are ghosts, and honestly so: each is a fact     *)
(* about a STEP -- "this attempt was granted / charged / refilled" -- not    *)
(* about a state, because the counter arithmetic erases its own history      *)
(* (a success refills to Max, so the exhaustion a bad grant rode is gone     *)
(* from every reachable state). The seam module carries the same shape for   *)
(* the same reason; the writers are enumerated so the ghost is only as       *)
(* strong as a closed list, and the list is checked by the mutants.          *)
(***************************************************************************)

\* No reference authenticates on an exhausted budget: neither a direct VERIFY at
\* zero, nor a RESET RETRY that leans on a recovery reference already at zero.
\* Writers: Verify, Recover.
NoAuthWhenBlocked == "NoAuthWhenBlocked" \notin viol

\* Every wrong attempt against an UNBLOCKED reference spends exactly one from its
\* counter -- the anti-bruteforce gate. Not "at least one" and not "sometimes":
\* a wrong VERIFY spends the target's, a wrong RESET RETRY spends the recovery
\* reference's. Writers: Verify, Recover.
WrongAttemptIsCharged == "WrongAttemptIsCharged" \notin viol

\* A reference's counter rises only on a correct presentation of a secret -- its
\* own (a correct VERIFY refills it to Max) or its recovery reference's (a correct
\* RESET RETRY does). Never out of nothing. This is the one the recovery path is
\* about, and its only writer is Recover: VERIFY cannot raise a counter without
\* `correct`, so it is not a writer here.
BudgetRisesOnlyWithItsSecret == "BudgetRisesOnlyWithItsSecret" \notin viol

=============================================================================
