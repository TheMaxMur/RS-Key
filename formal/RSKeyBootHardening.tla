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
(*    is the marker that says the lap has run (crates/rsk-fs/src/lib.rs:26-46);*)
(*    the boot runs the lap iff the marker is ABSENT and sets it only after  *)
(*    `compact()` returns Ok (firmware/src/main.rs:615-626) -- marker AFTER  *)
(*    scrub, so a torn lap re-runs. Every LAZY re-key after the lap must     *)
(*    re-arm it (`request_rescrub`) or its superseded copy stays readable    *)
(*    forever: audit run-35 found FOUR OF FIVE lazy re-keys skipping that,   *)
(*    and the sweep landed at crates/rsk-fido/src/clientpin.rs:811-813 and   *)
(*    :1117-1119, crates/rsk-piv/src/lib.rs:1226-1229,                       *)
(*    crates/rsk-oath/src/lib.rs:1185, crates/rsk-openpgp/src/pin.rs:313.    *)
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
(* tests by construction -- the lap's marker order and the scratch decode    *)
(* are checked at build time and on hardware, nowhere in between. "Model     *)
(* where you cannot measure" is this tree's stated rule, and these two       *)
(* machines are its purest case: the model is the only instrument that can   *)
(* exercise their interleavings at all.                                      *)
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
    \* Audit run-35's shape: a lazy re-key that leaves the marker standing, so
    \* the copy it superseded -- sealed under a root the PUBLIC chip serial
    \* derives -- stays in the flash ring as an offline dictionary target and
    \* no future boot will ever scrub it. The shipped tree clears the marker at
    \* every one of the five sites; the switch removes the re-arm.
    BugRekeyKeepsTheMarker,
    \* The marker written on a lap that did NOT complete: firmware/src/main.rs:625
    \* short-circuits `fs.compact().is_ok()` BEFORE the `fs.put(EF_HARDENED)`,
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
    lock      \* the running cycle's in-RAM PinLock, rebuilt at boot

vars == << phase, marker, weak, recorded, lock >>

TypeOK ==
    /\ phase \in {"serving", "down"}
    /\ marker \in BOOLEAN
    /\ weak \in 0..MaxWeak
    /\ recorded \in Locks
    /\ lock \in Locks

\* A fresh OTP-provisioned device after its first completed boot: lap done,
\* nothing pending, no strikes.
Init ==
    /\ phase = "serving"
    /\ marker = TRUE
    /\ weak = 0
    /\ recorded = "clear"
    /\ lock = "clear"

(***************************************************************************)
(* SERVING. A lazy re-key supersedes one more weak-sealed copy and must     *)
(* re-arm the lap; the FIDO layer moves the soft lock and every move writes  *)
(* the whole scratch word.                                                   *)
(***************************************************************************)
LazyRekey ==
    /\ phase = "serving"
    /\ weak < MaxWeak
    /\ weak' = weak + 1
    /\ marker' = IF BugRekeyKeepsTheMarker THEN marker ELSE FALSE
    /\ UNCHANGED << phase, recorded, lock >>

LockMoves ==
    /\ phase = "serving"
    /\ \E l \in Locks :
          /\ lock' = l
          /\ recorded' = l
    /\ UNCHANGED << phase, marker, weak >>

(***************************************************************************)
(* THE RESETS. A warm reset (host-requestable sys_reset) keeps the scratch   *)
(* word; a power-on reset clears it -- and the TAG magic makes the           *)
(* undefined-at-cold-boot register indistinguishable from cleared, which is  *)
(* why the model may collapse the two.                                       *)
(***************************************************************************)
WarmReset ==
    /\ phase = "serving"
    /\ phase' = "down"
    /\ UNCHANGED << marker, weak, recorded, lock >>

ColdReset ==
    /\ phase = "serving"
    /\ phase' = "down"
    \* FALSE is a chip whose power-on leaves the word standing, which makes a
    \* cold reset indistinguishable from a warm one -- and the TAG cannot tell
    \* them apart either, because a carried word carries a valid tag. The tag
    \* defends against UNDEFINED, which is a third case and reads as clear.
    /\ recorded' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded
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
    /\ UNCHANGED recorded

Next ==
    \/ LazyRekey
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
\* scrub. Both storage mutants break exactly this -- the lazy re-key that keeps
\* the marker standing over its new leftover, and the lap that claims completion
\* it did not earn. While it holds, "marker absent => a future boot scrubs" is
\* the liveness half, carried by the boot gate's own retry (a failed compact
\* leaves the marker unset, firmware/src/main.rs:625).
MarkerNeverLies == ~(marker /\ weak > 0)

\* THE WHOLE LOCK RIDES: while serving, the in-RAM lock equals the scratch word.
\* Every writer keeps them equal -- LockMoves writes both, a boot restores one
\* from the other -- so the only way to split them is a restore that carries
\* half the word, which is the laundering pin_lock.rs:18-21 names.
TheWholeLockRides == (phase = "serving") => (lock = recorded)

=============================================================================
