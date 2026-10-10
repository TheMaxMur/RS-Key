-------------------------- MODULE RSKeyBootHardening --------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* THE CROSS-BOOT HARDENING STATE: what a reboot must carry and what a boot  *)
(* must finish before the device serves. Two machines share the module       *)
(* because both live at the same seam -- the reset line -- and neither is    *)
(* any other module's variable:                                              *)
(*                                                                           *)
(* 1. THE ONE-SHOT AT-REST SCRUB LAP. Seal migrations re-key secrets from    *)
(*    the pre-OTP (chip-serial) root to the OTP root, and the log-structured *)
(*    store keeps the superseded weak-sealed copy readable in a raw flash    *)
(*    dump until a compaction lap pushes it off the medium. `EF_HARDENED`    *)
(*    is the marker that says the lap has run (crates/rsk-fs/src/lib.rs:28-78);*)
(*    the boot runs the lap iff the marker is ABSENT and sets it only after  *)
(*    `compact()` returns Ok (crates/rsk-fs/src/lib.rs:80-98) -- marker      *)
(*    AFTER scrub, so a torn lap re-runs. Every LAZY re-key OR DELETE after  *)
(*    the lap must re-arm it (`request_rescrub`) -- a tombstone appends too  *)
(*    -- or the superseded copy stays readable forever: run-35 found FOUR OF *)
(*    FIVE lazy re-keys skipping that, and its sweep landed the CALL at      *)
(*    crates/rsk-fido/src/clientpin.rs:811-813,                              *)
(*    crates/rsk-fido/src/clientpin.rs:1210-1213,                            *)
(*    crates/rsk-piv/src/lib.rs:621, crates/rsk-oath/src/lib.rs:1206,       *)
(*    crates/rsk-openpgp/src/pin.rs:330 -- three of those five used to name  *)
(*    the comment or the write ABOVE the call, which is what a mechanical    *)
(*    re-number leaves behind. Run-35's five is a HISTORICAL set, not        *)
(*    today's: `git grep -n request_rescrub` outside rsk-fs's own            *)
(*    definition and the tests is the live one, and no count of it is        *)
(*    written here, because the count is what rotted.                        *)
(*                                                                           *)
(* 2. THE SCRATCH-WORD LOCK CARRY. The clientPIN soft lock rides a warm      *)
(*    reset in WATCHDOG.scratch2 (firmware/src/pin_lock.rs) so a host-       *)
(*    requestable reboot cannot launder the three-strikes batch. The rule    *)
(*    the file states is THE WHOLE LOCK MOVES (firmware/src/pin_lock.rs:18-21):*)
(*    carrying the engaged flag without the mismatch batch that arms it lets *)
(*    a host stop at two wrong PINs, reboot, and restart the batch -- the    *)
(*    budget laundered two attempts at a time. The security module already   *)
(*    owns the TOTAL drop (BugSoftLockLostOnWarmReset); this module owns the *)
(*    PARTIAL one, which that mutant cannot express.                         *)
(*                                                                           *)
(* WHY A SEVENTH MODULE. firmware/ is the one workspace member with no host  *)
(* tests by construction, and the scratch decode is checked at build time    *)
(* and on hardware, nowhere in between. "Model where you cannot measure" is  *)
(* this tree's stated rule, and these two machines are its purest case: the  *)
(* model is the only instrument that can exercise their interleavings at     *)
(* all. The lap's marker ORDER was in that class until it was lifted into    *)
(* crates/rsk-fs, which is where its code twin now lands -- an exclusion     *)
(* reasoned about the MODULE had been covering a rule that never had to      *)
(* live in firmware/ at all.                                                 *)
(*                                                                           *)
(* WHAT IS ABSTRACTED. The device is OTP-provisioned (`mkek.is_some()` --    *)
(* a pre-OTP board never laps and has nothing to scrub). `weak` counts       *)
(* superseded weak-sealed copies without naming which record each shadows.   *)
(* Cold power clearing WATCHDOG.scratch2 is an explicit named assumption     *)
(* below, not a conclusion of this model. The TAG still makes an unrelated  *)
(* undefined value read as clear (firmware/src/pin_lock.rs:36-37).           *)
(* The 0x0854                                                            *)
(* legacy-canary aliasing that motivated the derived-engaged rule is a       *)
(* decode compatibility fact below this model's floor. Both invariants are   *)
(* STRUCTURAL -- no viol ghost in this module: the liar marker and the       *)
(* half-carried lock are visible states, not erased steps.                   *)
(*****************************************************************************)
EXTENDS Naturals

CONSTANTS
    PowerOnClearsScratch2,
    MaxWeak,  \* saturation bound on the counted superseded copies (>= 1)
    \* Whether the record write and the re-arm are two STEPS. FALSE keeps them
    \* one action -- what every configuration the tiers are about runs, and what
    \* leaves a power cut between them nowhere to sit. TRUE splits the pair
    \* around `rekeying`; the switch below says which half lands first.
    RekeyOrderModelled,
    \* Under that split, the record first and the re-arm after it -- the order
    \* the tree shipped until the re-arm was hoisted AHEAD of the write. The pair
    \* this switch orders is crates/rsk-fido/src/clientpin.rs:811-821, and it
    \* reads the FALSE arm there now: the `rsk_fs::request_rescrub` and then the
    \* `fs.put` below it. TRUE is the arm a cut could catch -- between the two the
    \* marker stands over a copy the write has already superseded, and a reset
    \* ends the worker that owed the re-arm -- while FALSE costs at worst a lap
    \* that re-runs over nothing, which is why its row is GREEN and TRUE's is RED.
    BugRecordWriteBeforeRearm,
    \* Audit run-35's shape: a lazy re-key that leaves the marker standing, so
    \* the copy it superseded -- sealed under a root the PUBLIC chip serial
    \* derives -- stays in the flash ring as an offline dictionary target and
    \* no future boot will ever scrub it. The shipped tree clears the marker at
    \* every lazy re-key; the switch removes the re-arm at its DEFINITION
    \* (crates/rsk-fs/src/lib.rs:62), which dominates every call site -- so how
    \* many there are is not a number this model has to carry.
    BugRekeyKeepsTheMarker,
    \* The marker written on a lap that did NOT complete:
    \* crates/rsk-fs/src/lib.rs:99 short-circuits `fs.compact().is_ok()`
    \* BEFORE the `fs.put(EF_HARDENED)`,
    \* so a torn or failed lap leaves the marker absent and the next boot
    \* retries. The switch sets the marker regardless -- the same
    \* write-order family as the store module's delete and the PIN flows'
    \* revoke-before-write.
    BugMarkerBeforeScrub,
    \* The partial carry the pin_lock module names as the rule: the engaged
    \* flag rides the warm reset but the mismatch batch is dropped, so a host
    \* that stops one short of the limit and reboots restarts the batch --
    \* the laundering the whole-word write exists to prevent. The security
    \* module's BugSoftLockLostOnWarmReset drops BOTH; this drops one half,
    \* which that mutant cannot express.
    BugPartialLockCarry

\* OPEN HARDWARE ASSUMPTION, MODELLED BOTH WAYS: whether a real RP2350 power-on
\* clears WATCHDOG.scratch2 is unconfirmed on silicon. It was an `ASSUME` that
\* nothing branched on -- deleting the line left every Boot configuration
\* bit-identical -- so it named the question without letting anyone ask it.
\* `ColdReset` reads the constant now and `BootCarry.cfg` runs the FALSE arm.

\* The soft-lock states the scratch word distinguishes: no strikes, a live
\* mismatch batch below the limit, and the engaged lock. One value stands for
\* every sub-limit batch -- the laundering question is whether a batch survives,
\* not its exact count (the in_range clamp is a decode detail below the floor).
Locks == {"clear", "batch", "engaged"}

VARIABLES
    phase,    \* "serving" (the worker is up) or "down" (between reset and boot)
    marker,   \* EF_HARDENED present: the at-rest lap has run and nothing awaits it
    weak,     \* 0..MaxWeak: superseded weak-sealed copies awaiting the scrub
    \* What WATCHDOG.scratch2 holds -- the last `set()` before the reset
    \* (firmware/src/pin_lock.rs:52-54, written whole on every CBOR dispatch).
    \* Survives a warm reset; a power-on reset clears it, and the TAG makes an
    \* undefined register read as clear too.
    recorded,
    lock,     \* the running cycle's in-RAM PinLock, rebuilt at boot
    \* A lazy re-key with one half done and the other still owed. FALSE
    \* throughout unless `RekeyOrderModelled`: with the pair atomic there is no
    \* in-flight state, which is what keeps the configurations that collapse it
    \* running over the state space they always ran over.
    rekeying

vars == << phase, marker, weak, recorded, lock, rekeying >>

TypeOK ==
    /\ phase \in {"serving", "down"}
    /\ marker \in BOOLEAN
    /\ weak \in 0..MaxWeak
    /\ recorded \in Locks
    /\ lock \in Locks
    /\ rekeying \in IF RekeyOrderModelled THEN BOOLEAN ELSE {FALSE}

\* A fresh OTP-provisioned device after its first completed boot: lap done,
\* nothing pending, no strikes.
Init ==
    /\ phase = "serving"
    /\ marker = TRUE
    /\ weak = 0
    /\ recorded = "clear"
    /\ lock = "clear"
    /\ rekeying = FALSE

(***************************************************************************)
(* SERVING. A lazy re-key supersedes one more weak-sealed copy and must     *)
(* re-arm the lap; the FIDO layer moves the soft lock and every move writes  *)
(* the whole scratch word.                                                   *)
(***************************************************************************)
\* The re-arm itself, which every arm below shares: `request_rescrub` clears the
\* marker (crates/rsk-fs/src/lib.rs:62) unless the switch that keeps it standing
\* is armed.
Rearmed == IF BugRekeyKeepsTheMarker THEN marker ELSE FALSE

\* THE WRITE AND THE RE-ARM AS ONE STEP, which is what the configurations the
\* tiers are about run. Collapsing the pair leaves a power cut between them no
\* state to sit in, so the ORDER is unfalsifiable here -- and that is a choice
\* the switch above makes visible rather than a gap. Splitting it FREE-FLOATING
\* was measured and refused: Boot, BootCarry and BootInduction then fall at
\* depth 2 on the transient, and the three BugMarkerBeforeScrub rows stop
\* reaching their own defect while still reporting MarkerNeverLies -- a kill for
\* the wrong reason no verdict column can see.
LazyRekey ==
    /\ ~RekeyOrderModelled
    /\ phase = "serving"
    /\ weak < MaxWeak
    /\ weak' = weak + 1
    /\ marker' = Rearmed
    /\ UNCHANGED << phase, recorded, lock, rekeying >>

\* THE SAME RE-KEY AS TWO STEPS, so a reset can land between them. Which half is
\* which is the whole question: the tree wrote the record and re-armed after it
\* (d703c15 names that as the less fail-safe order) until the re-arm was hoisted
\* ahead of the write, and `rekeying` is the window in which the marker may
\* disagree with the medium because the second half is still owed. A reset ends
\* the worker that owed it.
RekeyBegin ==
    /\ RekeyOrderModelled
    /\ phase = "serving"
    /\ ~rekeying
    /\ weak < MaxWeak
    /\ rekeying' = TRUE
    /\ IF BugRecordWriteBeforeRearm
         THEN /\ weak' = weak + 1
              /\ UNCHANGED marker
         ELSE /\ marker' = Rearmed
              /\ UNCHANGED weak
    /\ UNCHANGED << phase, recorded, lock >>

\* The two guards `RekeyBegin` already carries. Without them the atomic arm is
\* disabled only by `TypeOK`'s `{FALSE}` pin and the increment is unbounded -- a
\* type bound doing an action's work: the induction probe drove weak 2 -> 3 past
\* MaxWeak, RED on TypeOK at depth 2. The saturation bound is the half that
\* increments; under the other order `RekeyBegin` holds it.
RekeyFinish ==
    /\ RekeyOrderModelled
    /\ phase = "serving"
    /\ rekeying
    /\ (BugRecordWriteBeforeRearm \/ weak < MaxWeak)
    /\ rekeying' = FALSE
    /\ IF BugRecordWriteBeforeRearm
         THEN /\ marker' = Rearmed
              /\ UNCHANGED weak
         ELSE /\ weak' = weak + 1
              /\ UNCHANGED marker
    /\ UNCHANGED << phase, recorded, lock >>

LockMoves ==
    /\ phase = "serving"
    /\ \E l \in Locks :
          /\ lock' = l
          /\ recorded' = l
    /\ UNCHANGED << phase, marker, weak, rekeying >>

(***************************************************************************)
(* THE RESETS. A warm reset (host-requestable sys_reset) keeps the scratch   *)
(* word; a power-on reset clears it -- and the TAG magic makes the           *)
(* undefined-at-cold-boot register indistinguishable from cleared, which is  *)
(* why the model may collapse the two.                                       *)
(***************************************************************************)
WarmReset ==
    /\ phase = "serving"
    /\ phase' = "down"
    \* The reset takes the worker with it: a half-done re-key never finishes.
    /\ rekeying' = FALSE
    /\ UNCHANGED << marker, weak, recorded, lock >>

ColdReset ==
    /\ phase = "serving"
    /\ phase' = "down"
    \* FALSE is a chip whose power-on leaves the word standing, which makes a
    \* cold reset indistinguishable from a warm one -- and the TAG cannot tell
    \* them apart either, because a carried word carries a valid tag. The tag
    \* defends against UNDEFINED, which is a third case and reads as clear.
    /\ recorded' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded
    /\ rekeying' = FALSE
    /\ UNCHANGED << marker, weak, lock >>

(***************************************************************************)
(* BOOT. Restore the lock from the scratch word -- the whole word, unless    *)
(* the partial-carry switch drops the batch half -- and run the at-rest lap  *)
(* iff the marker is absent. The lap either completes (everything weak is    *)
(* scrubbed, THEN the marker lands) or tears (nothing is claimed: the        *)
(* marker stays absent and the next boot retries) -- unless the order        *)
(* switch claims completion the medium does not hold.                        *)
(***************************************************************************)
Boot ==
    /\ phase = "down"
    /\ phase' = "serving"
    /\ lock' = IF BugPartialLockCarry /\ recorded = "batch" THEN "clear" ELSE recorded
    /\ IF ~marker
         THEN \E completed \in BOOLEAN :
                IF completed
                  THEN /\ weak' = 0
                       /\ marker' = TRUE
                  ELSE /\ weak' = weak
                       /\ marker' = IF BugMarkerBeforeScrub THEN TRUE ELSE FALSE
         ELSE UNCHANGED << marker, weak >>
    /\ UNCHANGED << recorded, rekeying >>

Next ==
    \/ LazyRekey
    \/ RekeyBegin
    \/ RekeyFinish
    \/ LockMoves
    \/ WarmReset
    \/ ColdReset
    \/ Boot

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS -- both structural, deliberately: a liar marker and a      *)
(* half-carried lock are STATES the machine sits in, not steps it erases,   *)
(* so no ghost is needed and the strong form is available.                  *)
(***************************************************************************)

\* THE MARKER NEVER LIES: EF_HARDENED present means nothing weak awaits the
\* scrub, outside the window of a re-key that is half done. Both storage mutants
\* break exactly this -- the lazy re-key that keeps the marker standing over its
\* new leftover, and the lap that claims completion it did not earn. While it
\* holds, "marker absent => a future boot scrubs" is the liveness half, carried
\* by the boot gate's own retry (a failed compact leaves the marker unset,
\* crates/rsk-fs/src/lib.rs:99).
\*
\* `~rekeying` is the whole of what the split arm costs, and it costs the atomic
\* one nothing: with the pair collapsed the flag is FALSE in every state, so
\* this is the predicate it always was. Under the split it says the window may
\* exist and may not OUTLIVE the worker that owed the second half -- once the
\* re-key is gone, a marker standing over a leftover is a lie no later boot can
\* hear, because the marker is exactly what stops the lap running again.
MarkerNeverLies == ~(marker /\ weak > 0 /\ ~rekeying)

\* THE WHOLE LOCK RIDES: while serving, the in-RAM lock equals the scratch word.
\* Every writer keeps them equal -- LockMoves writes both, a boot restores one
\* from the other -- so the only way to split them is a restore that carries
\* half the word, which is the laundering pin_lock.rs:18-21 names.
TheWholeLockRides == (phase = "serving") => (lock = recorded)

(***************************************************************************)
(* THE INDUCTION PROBE. Everything above is checked over the states `Init`   *)
(* can REACH. This asks the stronger question TLC can also answer alone:     *)
(* does one step of `Next` from ANY type-correct state satisfying the two    *)
(* invariants land in one that still does?                                   *)
(*                                                                           *)
(* `BootInduction.cfg` runs it as `INIT IndInv` / `NEXT Next` -- so TLC       *)
(* starts from every such state rather than from `Init`, and a violation is   *)
(* a one-step counterexample to inductiveness rather than to the invariant.   *)
(* A GREEN row is a proof that needs no reachability argument, which is what  *)
(* a deductive prover would be bought for; a RED one names the conjunct the   *)
(* invariant is missing, which is the more useful answer of the two.          *)
(***************************************************************************)
IndInv == TypeOK /\ MarkerNeverLies /\ TheWholeLockRides

=============================================================================
