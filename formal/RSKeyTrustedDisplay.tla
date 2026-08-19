-------------------------- MODULE RSKeyTrustedDisplay --------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* THE TRUSTED-DISPLAY CONFIRM CEREMONY -- the anti-phishing promise the     *)
(* display build ships, WhatIsConfirmedIsWhatIsShown, decomposed into the    *)
(* three rules a model checker can hold: an operation that names a relying   *)
(* party completes only through the card that names it; a press that         *)
(* predates the card approves nothing; and no exit but a deliberate Allow    *)
(* ever reads as Confirmed. Not the screens' rendering, not the menus, not   *)
(* the PIN pad's arithmetic (the security module owns the fourth PIN door)   *)
(* -- only the ceremony: what is on the glass when a Confirmed leaves the    *)
(* device.                                                                   *)
(*                                                                           *)
(* WHY A SIXTH MODULE. It shares no variable with the other five: what the   *)
(* panel SHOWS is neither the FIDO security state, an applet status, a       *)
(* retry counter, a flash record nor the capability mask. And two of its     *)
(* three mutants rebuild defects that actually shipped on the display        *)
(* build, both of the same cruel shape -- every check passed while the      *)
(* OPERATOR was the one being lied to.                                       *)
(*                                                                           *)
(* THE METHOD is the five siblings': a Guard the Rust computes (mutable by   *)
(* a Bug* switch) against a Policy the requirement fixes; a step the Policy  *)
(* forbids records the violated invariant in `viol`. Every invariant here    *)
(* is a ghost, and honestly so: a completed ceremony leaves nothing on the   *)
(* glass, so no state predicate can tell a phished Confirmed from an honest  *)
(* one -- the whole property is about the STEP that produced it.             *)
(*                                                                           *)
(* WHAT IS ABSTRACTED. The card's CONTENT is one bit -- "names the           *)
(* operation" -- because the ceremony is modal: `confirm_wait` /             *)
(* `run_add_passkey` render the card and block until an exit                 *)
(* (crates/rsk-display/src/presence.rs:91), so no second operation can       *)
(* repaint the glass mid-wait; card-swap is structurally absent and the one  *)
(* bit is faithful. The touch controller reports LEVEL, not edges            *)
(* (crates/rsk-display/src/power.rs:55-65) -- which is exactly why the       *)
(* stale-press question exists and is modelled. Timeouts and CTAPHID cancel  *)
(* collapse into the one Dismiss exit: every non-Allow exit must read the    *)
(* same, and that collapse IS the third invariant.                           *)
(*****************************************************************************)
EXTENDS Naturals

(* Mutation switches. All FALSE is the shipped tree. *)
CONSTANTS
    \* Audit run-28 F1, SHIPPED: built-in UV deleted the RP card. The pad
    \* collects user presence, `UvOutcome::BUILTIN` carries `up_collected`, and
    \* the pre-fix gate was `!up_collected` alone -- so on the build whose whole
    \* point is showing WHO you are authenticating to, the card was skipped
    \* whenever the pad had already run. The PIN pad's title is 'static and can
    \* never carry RP data; only the card can. The fix is
    \* `needs_confirm = !up_collected || shows_confirm`
    \* (crates/rsk-fido/src/clientpin.rs:536-537), consumed at
    \* getassertion.rs:616-617, makecredential.rs:643-644 and u2f.rs:93. The
    \* switch restores the pre-fix gate.
    BugPadSubstitutesForCard,
    \* Audit run-33, SHIPPED (the onboarding "Continue without PIN" committed by
    \* a pre-screen touch, and the ambient-screen class swept with it): the
    \* panel reports contact LEVEL, not edges, so a finger already down when a
    \* screen paints reads as a tap ON that screen. The defence is the release
    \* edge, twice: `Ui::touch_armed` + `armed_touch`
    \* (crates/rsk-display/src/power.rs:55-65 -- a contact predating this
    \* screen stays disarmed) and the
    \* ceremony's own `wait_release_ceremony` at card entry
    \* (crates/rsk-display/src/presence.rs:190 -- "a finger already down
    \* approves the card in the same frame it is painted, too fast to read").
    \* The switch removes the edge.
    BugPreScreenTouchApproves,
    \* The Allow/Deny separation taken out: `hit_confirm` maps a tap to the
    \* button whose disjoint rectangle contains it, a stray touch above the
    \* band to None (crates/rsk-ui/src/lib.rs:248-256), and every other exit --
    \* Deny, the power button mid-ceremony, timeout, CTAPHID cancel -- ends the
    \* ceremony as Cancelled, "no signature is ever produced without the
    \* deliberate on-screen hold" (crates/rsk-display/src/presence.rs:120-124).
    \* The switch is the collapse where any exit tap reads as the approval.
    BugAnyTapApproves

InvNames == { "ConfirmNamesTheOperation", "StaleTouchApprovesNothing",
              "OnlyAllowConfirms" }

VARIABLES
    \* Whether a host operation is awaiting authorization. One at a time: the
    \* worker is single-threaded and the ceremony blocks it.
    pending,
    \* What the glass shows: nothing, the built-in-UV PIN pad, or the card that
    \* names the operation. "pad" precedes "card" on the built-in-UV route; the
    \* plain-UP route paints the card directly.
    shown,
    \* Whether the current contact predates the screen now showing -- the level-
    \* not-edges fact. Nondeterministic at every paint (the finger may still be
    \* down from the pad tap or an ambient interaction), cleared by a lift.
    stale,
    viol      \* ghost: the set of invariant names some step has violated

vars == << pending, shown, stale, viol >>

NoScreen == "none"
Pad      == "pad"
Card     == "card"

TypeOK ==
    /\ pending \in BOOLEAN
    /\ shown \in {NoScreen, Pad, Card}
    /\ stale \in BOOLEAN
    /\ viol \in SUBSET InvNames

Init ==
    /\ pending = FALSE
    /\ shown = NoScreen
    /\ stale = FALSE
    /\ viol = {}

(***************************************************************************)
(* ARRIVAL. A host operation lands and the ceremony opens -- through the     *)
(* built-in-UV pad (collect PIN first) or straight onto the card (plain UP). *)
(* Either paint may find a finger already down: `stale'` is free.            *)
(***************************************************************************)
Arrive ==
    /\ ~pending
    /\ pending' = TRUE
    /\ \E first \in {Pad, Card}, s \in BOOLEAN :
          /\ shown' = first
          /\ stale' = s
    /\ UNCHANGED viol

(***************************************************************************)
(* THE PAD HANDS OFF. On the shipped tree a named operation ALWAYS proceeds  *)
(* to the card -- `needs_confirm` keeps the confirm when `shows_confirm`,    *)
(* regardless of the presence the pad collected. Under the run-28 switch the *)
(* pad's collected presence completes the operation directly and the         *)
(* operator never sees who they authenticated to.                            *)
(***************************************************************************)
PadDone ==
    /\ shown = Pad
    /\ IF BugPadSubstitutesForCard
         THEN /\ pending' = FALSE
              /\ shown' = NoScreen
              /\ stale' = FALSE
              /\ viol' = viol \cup {"ConfirmNamesTheOperation"}
         ELSE /\ \E s \in BOOLEAN :
                    /\ shown' = Card
                    /\ stale' = s
              /\ UNCHANGED << pending, viol >>

\* The finger lifts: the level-based controller sees no contact, `armed_touch`
\* re-arms, and the next press is fresh (crates/rsk-display/src/power.rs:56-59).
Lift ==
    /\ shown = Card
    /\ stale
    /\ stale' = FALSE
    /\ UNCHANGED << pending, shown, viol >>

(***************************************************************************)
(* THE ALLOW EXIT -- the only one that may read as Confirmed. The Guard is   *)
(* the release edge: a stale press cannot approve unless the switch removes  *)
(* the edge. The Policy is `~stale`, always.                                 *)
(***************************************************************************)
AllowGuard  == IF BugPreScreenTouchApproves THEN TRUE ELSE ~stale
AllowPolicy == ~stale

Allow ==
    /\ shown = Card
    /\ AllowGuard
    /\ pending' = FALSE
    /\ shown' = NoScreen
    /\ stale' = FALSE
    /\ viol' = IF AllowPolicy
                 THEN viol ELSE viol \cup {"StaleTouchApprovesNothing"}

(***************************************************************************)
(* EVERY OTHER EXIT -- Deny, the power button, timeout, CTAPHID cancel --    *)
(* ends the ceremony as Cancelled. Under the collapse switch the exit reads  *)
(* as the approval instead, which is the "spurious approve" every one of     *)
(* those paths individually refuses.                                         *)
(***************************************************************************)
Dismiss ==
    /\ shown \in {Pad, Card}
    /\ pending' = FALSE
    /\ shown' = NoScreen
    /\ stale' = FALSE
    /\ viol' = IF BugAnyTapApproves /\ shown = Card
                 THEN viol \cup {"OnlyAllowConfirms"} ELSE viol

Next ==
    \/ Arrive
    \/ PadDone
    \/ Lift
    \/ Allow
    \/ Dismiss

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS -- all ghosts, because a completed ceremony leaves nothing *)
(* on the glass: no reachable STATE distinguishes a phished Confirmed from   *)
(* an honest one, so each rule lives at the step that produced the outcome.  *)
(***************************************************************************)

\* An operation that names a relying party completes only through the card that
\* names it. The pad cannot substitute: its title is 'static, never RP data.
\* Ghost, one writer: PadDone.
ConfirmNamesTheOperation == "ConfirmNamesTheOperation" \notin viol

\* A press that began before the card was painted approves nothing; only a
\* fresh press -- one the release edge has armed -- can. Ghost, one writer:
\* Allow.
StaleTouchApprovesNothing == "StaleTouchApprovesNothing" \notin viol

\* No exit but a deliberate Allow reads as Confirmed: Deny, sleep, timeout and
\* cancel are all Cancelled. Ghost, one writer: Dismiss.
OnlyAllowConfirms == "OnlyAllowConfirms" \notin viol

=============================================================================
