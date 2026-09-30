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
(* zero, refill only on a correct secret, or through OpenPGP's SET PIN       *)
(* RETRIES while the admin reference PW3 is held.                            *)
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
(* module gave for being a second. SET PIN RETRIES is the one door here that *)
(* reads a status, so the statuses a VERIFY raises are tracked beside the    *)
(* counters (`held`), more coarsely than the seam module keeps them.         *)
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
    BugSetRetriesRefillsOldMaximum

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

\* The recovery graph a PRESENTED secret draws: which reference's correct
\* presentation refills the target's counter. PIV's PUK unblocks the PIN (RESET
\* RETRY COUNTER); OpenPGP's RC unblocks PW1 (RESET RETRY, P1=0). No presented
\* secret refills `pivPuk`, `pw3` or `rc`. PW3's STATUS refills without one:
\* SET PIN RETRIES (SetRetries below) gives PW1, the RC and PW3 new tries while
\* PW3 is held, so a blocked RC comes back that way. A blocked PW3 cannot be held
\* -- every wrong attempt drops its status -- so it stays terminal with the PUK,
\* TERMINATE DF / factory RESET the only way back, which the reset models cover.
\* RESET RETRY P1=0x02, which REPLACES PW1 under PW3's session
\* (`sess.has_pw3`, crates/rsk-openpgp/src/pin.rs:982), is out: it presents no
\* secret either, and it is not SET PIN RETRIES.
RecoveryOf(r) ==
    CASE r = "pivPin" -> {"pivPuk"}
      [] r = "pw1"    -> {"rc"}
      [] OTHER        -> {}

\* The references SET PIN RETRIES (OpenPGP INS F2) names, one byte each: OpenPGP's
\* three. PIV's PIN and PUK take the applet's own SET RETRIES (INS FA,
\* crates/rsk-piv/src/lib.rs:609), which resets both references to their defaults
\* and is not modelled here (MX-LAT-005).
PgpRefs == {"pw1", "rc", "pw3"}

InvNames == { "NoAuthWhenBlocked", "WrongAttemptIsCharged",
              "BudgetRisesOnlyWithItsSecret" }

VARIABLES
    retries,  \* [Refs -> 0..Max]: the remaining attempts at each reference
    maxima,   \* [Refs -> 1..Max]: each reference's stored maximum (EF_PW_RETRIES)
    held,     \* the VerifyTargets whose status a correct VERIFY raised and holds
    viol      \* ghost: the set of invariant names some step has violated

vars == << retries, maxima, held, viol >>

TypeOK ==
    /\ retries \in [Refs -> 0..Max]
    /\ maxima \in [Refs -> 1..Max]
    /\ held \in SUBSET VerifyTargets
    /\ viol \in SUBSET InvNames

\* A fresh card: every maximum at the ceiling, every counter at its maximum, no
\* status held.
Init ==
    /\ maxima = [r \in Refs |-> Max]
    /\ retries = [r \in Refs |-> Max]
    /\ held = {}
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
           /\ held' = IF grants THEN held \cup {r}
                      ELSE IF correct THEN held ELSE held \ {r}
           /\ UNCHANGED maxima
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
            proceeds   == (~viaBlocked) \/ BugUseWhenBlocked
            \* the target is refilled iff a usable secret was presented -- a
            \* correct one that got past the floor, or the switch that skips it
            refills    == proceeds /\ (correct \/ BugRecoveryWithoutSecret)
            \* a wrong recovery secret at an unblocked reference spends one of ITS
            doCharge   == proceeds /\ (~refills) /\ (~viaBlocked)
            spentVia   == IF doCharge /\ (~BugWrongDoesNotSpend)
                            THEN retries[via] - 1 ELSE retries[via]
        IN /\ retries' =
                IF refills THEN [retries EXCEPT ![r] = maxima[r]]
                           ELSE [retries EXCEPT ![via] = spentVia]
           /\ UNCHANGED << maxima, held >>
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
(* one included. No secret is presented and no status changes. The RC is    *)
(* always set in this module, its activation abstracted as it always was;   *)
(* over an unset one F2 stores the maximum and gives no tries                *)
(* (crates/rsk-openpgp/src/retries.rs:66-67), a step that raises nothing, so *)
(* leaving it out drops no rise.                                             *)
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
            newLeft(r) == IF ~named(r) THEN retries[r]
                          ELSE IF BugSetRetriesRefillsOldMaximum THEN maxima[r]
                          ELSE b[r]
            \* the requirement: a count this step raises is raised with PW3 held,
            \* at a reference whose new maximum the step sets, and to that maximum
            earned(r)  == "pw3" \in held /\ named(r) /\ newLeft(r) = b[r]
        IN /\ maxima' = [r \in Refs |-> IF named(r) THEN b[r] ELSE maxima[r]]
           /\ retries' = [r \in Refs |-> newLeft(r)]
           /\ UNCHANGED held
           /\ viol' = viol
                \cup (IF \E r \in Refs : newLeft(r) > retries[r] /\ ~earned(r)
                        THEN {"BudgetRisesOnlyWithItsSecret"} ELSE {})

Next ==
    \/ \E r \in VerifyTargets : Verify(r)
    \/ \E r \in Refs : Recover(r)
    \/ SetRetries

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS. All three are ghosts, and honestly so: each is a fact     *)
(* about a STEP -- "this attempt was granted / charged / refilled" -- not    *)
(* about a state, because the counter arithmetic erases its own history      *)
(* (a success refills to the maximum, so the exhaustion a bad grant rode is  *)
(* gone from every reachable state). The seam module carries the same shape *)
(* for the same reason; the writers are enumerated so the ghost is only as   *)
(* strong as a closed list, and the list is checked by the mutants.         *)
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
\* own (a correct VERIFY refills it to its maximum) or its recovery reference's (a
\* correct RESET RETRY does) -- or when OpenPGP's SET PIN RETRIES, with the admin
\* reference PW3 held, sets a new maximum for it, and then to that maximum. Never
\* out of nothing: not on a wrong recovery secret, not under the user's status
\* alone, not with no status at all, not to a count the step did not set.
\* Writers: Recover, SetRetries. VERIFY raises a counter only through `correct`,
\* so it is not one.
BudgetRisesOnlyWithItsSecret == "BudgetRisesOnlyWithItsSecret" \notin viol

(***************************************************************************)
(* THE INDUCTION PROBE. Everything above is checked over what `Init` can     *)
(* REACH. `LatInduction.cfg` asks the stronger question with the same        *)
(* checker: does one step from ANY type-correct state the three invariants   *)
(* admit land in one that still does?                                        *)
(*                                                                           *)
(* Here the answer is cheap to predict and was still worth measuring, because *)
(* the three are STEP recorders: a state satisfying them carries `viol = {}`  *)
(* and nothing else, so the probe's initial states are every counter,        *)
(* maximum and status assignment rather than the ones a ladder can reach --  *)
(* counts above their maximum among them. That is the whole difference        *)
(* between this row and `Lattice.cfg`, and it is the one that matters for     *)
(* the source obligation: an inductive invariant needs no reachability        *)
(* argument, which is what a deductive prover would be bought for.            *)
(*                                                                           *)
(* What it still does NOT give is the maximum. `Max` is a TLC CONSTANT, so a  *)
(* GREEN row here is GREEN at that one value; the production ceiling is the   *)
(* `u8` stored beside each counter, and it is                                 *)
(* `crates/rsk-piv/src/retry_lattice_kani.rs` that ranges over all 256 of     *)
(* them, against the functions VERIFY and RESET RETRY COUNTER call.           *)
(***************************************************************************)
IndInv == TypeOK /\ NoAuthWhenBlocked /\ WrongAttemptIsCharged
            /\ BudgetRisesOnlyWithItsSecret

=============================================================================
