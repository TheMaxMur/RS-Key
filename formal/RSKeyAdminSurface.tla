--------------------------- MODULE RSKeyAdminSurface ---------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* THE ADMINISTRATIVE & RECOVERY SURFACE: the enabled-applications mask      *)
(* (`rsk-mgmt`, the ykman `config usb` capability set), the always-on carve- *)
(* out that keeps it reversible (the `APPLET_CAPS` table in `rsk-device`),   *)
(* and the operator-presence gate on the privileged `rsk-rescue` commands    *)
(* (device-key signing, cert/config writes, reboot-to-BOOTSEL, fuse burns).  *)
(* Not the applets' own command sets, not the seal, not the CTAP state --    *)
(* those are the other four modules'. This is the surface that decides which *)
(* applets EXIST and who may touch device identity, one layer above them.    *)
(*                                                                           *)
(* WHY A FIFTH MODULE. It shares no variable with the other four: the mask   *)
(* is neither an applet status (RSKeyAppletSeams) nor a retry counter        *)
(* (RSKeyRetryLattice) nor a flash record (RSKeyStore) nor the FIDO security *)
(* state. A product would multiply state and buy no interleaving -- the same *)
(* measured reason each sibling gave. And the properties here are genuinely  *)
(* SEQUENCE properties a single-call proof cannot see: "no sequence of       *)
(* config writes can strand the device unable to re-enable an applet" is a   *)
(* reachability claim over the mask, not a fact about one write.             *)
(*                                                                           *)
(* THE METHOD is the four siblings': a Guard the Rust computes (mutable by a *)
(* Bug* switch) against a Policy the requirement fixes; a step the Policy     *)
(* forbids records the violated invariant in `viol`, or a structural         *)
(* invariant reads the Guard out of the state directly. Each Bug* rebuilds a *)
(* real shipped defect or a defence the tree carries, and each must make TLC *)
(* produce a counterexample.                                                 *)
(*                                                                           *)
(* WHAT IS ABSTRACTED. The mask is a set of opaque capabilities, not the     *)
(* 16-bit USB_ENABLED bitmask -- the clamp to SUPPORTED_CAPS                 *)
(* (crates/rsk-mgmt/src/lib.rs:654) is modelled as "the mask stays a subset  *)
(* of the gateable caps" and enforced by construction. The config-lock TLV   *)
(* is present only as the class of write that carries no capability change   *)
(* (`LockCodeWrite`); its unsealed-disclosure hole (audit run-30) is a       *)
(* data-handling property, not a state-machine one, and stays in the strip   *)
(* function's own unit tests. The strict-config presence gate on the CONFIG  *)
(* write is a build flag ORTHOGONAL to every invariant here: its absence on  *)
(* the default build is a documented, reversible DoS, so the config write is *)
(* modelled ungated and the presence property covers only the rescue         *)
(* commands, which gate unconditionally on both builds.                      *)
(*****************************************************************************)
EXTENDS Naturals, FiniteSets

(* Mutation switches, and the one scope constant. All FALSE is the shipped
   tree. *)
CONSTANTS
    \* The gateable capability domain. Every mutant here fires over ONE cap,
    \* so three is padding the measurement does not need -- kept because it
    \* is the shipped vocabulary, now visible as a scope (formal/scopes.txt).
    Caps,
    \* crates/rsk-device/src/ccid.rs:67-74 -- APPLET_CAPS marks management,
    \* vendor and rescue as cap `0` (always available), because gating them off
    \* would make `ykman config usb --disable` irreversible. The switch ties the
    \* admin channel to the mask being non-empty, the shape a naive
    \* "nothing selectable when all disabled" would take.
    BugAdminGateable,
    \* crates/rsk-rescue/src/lib.rs:161-163 -- `require_presence` gates every
    \* privileged runtime command (keydev sign, cert/config write, BOOTSEL
    \* reboot, fuse burns) so a USB host alone cannot drive them. The switch
    \* removes the gate.
    BugPrivilegedOpUngated,
    \* audit run-35: a config write that changes only the lock code strips to
    \* zero bytes; storing that verbatim left an EMPTY record, and
    \* `read_enabled_caps` reads empty as SUPPORTED_CAPS, so a lock-code write
    \* silently re-enabled every disabled application. The fix MERGES onto the
    \* stored record (crates/rsk-mgmt/src/lib.rs:322-336); the switch replaces it.
    BugLockWriteResetsCaps,
    \* The pre-0x084A tree, shipped and fixed: USB_ENABLED was REPORTING-ONLY --
    \* the persisted mask echoed in DeviceInfo while SELECT and dispatch never
    \* consulted it, so `ykman config usb --disable PIV` disabled nothing. The
    \* enforcement is Dispatcher::set_enabled (crates/rsk-sdk/src/applet.rs:203-205)
    \* fed from the mask (crates/rsk-device/src/ccid.rs:235-243) and consulted at
    \* select AND dispatch-to-current (crates/rsk-device/src/ccid.rs:332). The
    \* switch removes exactly that consultation.
    BugMaskIsCosmetic

\* The gateable applet capabilities -- the SUPPORTED_CAPS vocabulary, reduced to
\* three representatives (the reversibility argument does not depend on the count;
\* what matters is that the admin channel is orthogonal to this set). The admin
\* applets -- management, vendor, rescue -- are DELIBERATELY not in here: they are
\* the always-on carve-out, represented by `WriteConfig` being unconditionally
\* enabled rather than by a capability in the mask.

InvNames == { "PrivilegedOpNeedsPresence", "DisableSetSurvivesLockWrite",
              "DisabledAppletNeverDispatches" }

VARIABLES
    enabled,  \* SUBSET Caps: the currently-enabled applications (USB_ENABLED)
    viol      \* ghost: the set of invariant names some step has violated

vars == << enabled, viol >>

TypeOK ==
    /\ enabled \in SUBSET Caps
    /\ viol \in SUBSET InvNames

\* A factory device: every gateable application enabled (the default record's
\* USB_ENABLED is SUPPORTED_CAPS, crates/rsk-mgmt/src/lib.rs:658).
Init ==
    /\ enabled = Caps
    /\ viol = {}

\* Whether the administrative channel (READ/WRITE CONFIG, the management applet)
\* is reachable in the current state. The shipped tree: ALWAYS -- APPLET_CAPS
\* gives management cap `0`. The bug: only while some applet is enabled, so
\* disabling everything strands the re-enable path.
AdminChannelOpen ==
    IF BugAdminGateable THEN enabled # {} ELSE TRUE

(***************************************************************************)
(* WRITE CONFIG. crates/rsk-mgmt/src/lib.rs:311 (persist_dev_conf) via the   *)
(* CCID applet and the FIDO vendor config-write. Sets the enabled set to any  *)
(* subset of the gateable caps. Modelled UNCONDITIONALLY enabled: the default *)
(* build does not presence-gate it (a documented, reversible DoS), and the    *)
(* management applet that carries it is the always-on carve-out, so the write *)
(* is reachable from every state -- which is exactly what keeps a disable      *)
(* reversible.                                                                *)
(***************************************************************************)
WriteConfig ==
    \E new \in SUBSET Caps :
        /\ enabled' = new
        /\ UNCHANGED viol

\* A config write that changes ONLY the lock code -- ykman `config set-lock-code`
\* sends the 0x0A TLV and nothing else. It carries no USB_ENABLED, so it must
\* leave the enabled set exactly as it was. The bug rebuilds the empty-record
\* path that read back as SUPPORTED_CAPS (all enabled).
LockCodeWrite ==
    /\ enabled' = IF BugLockWriteResetsCaps THEN Caps ELSE enabled
    /\ viol' = IF enabled' = enabled
                 THEN viol ELSE viol \cup {"DisableSetSurvivesLockWrite"}

(***************************************************************************)
(* A PRIVILEGED RESCUE COMMAND. crates/rsk-rescue/src/lib.rs -- keydev_sign   *)
(* (:173), write cert (:219), write config (:239), reboot-to-BOOTSEL (:363),  *)
(* the page-58 / rollback fuse burns (:413). Each completes only on a         *)
(* Confirmed operator presence; a USB host alone (Denied / Timeout) must not   *)
(* drive it. `present` is the presence request's answer, nondeterministic     *)
(* here -- the presence machinery is RSKeySecurityState's, this is only       *)
(* whether the gate is consulted.                                            *)
(***************************************************************************)
PrivilegedOp ==
    \E present \in BOOLEAN :
        LET guard  == IF BugPrivilegedOpUngated THEN TRUE ELSE present
            \* a completed op that the host drove without the operator present
            completes == guard
        IN /\ UNCHANGED enabled
           /\ viol' = IF completes /\ ~present
                        THEN viol \cup {"PrivilegedOpNeedsPresence"} ELSE viol

(***************************************************************************)
(* DISPATCH to a gateable applet. The firmware refreshes the effective mask  *)
(* at the top of every transport dispatch (`refresh_caps_if_dirty`), so the   *)
(* persisted set IS the effective one at every command boundary and the       *)
(* model needs no second variable for it. The guard is the whole enforcement: *)
(* remove it and the mask is DeviceInfo prose -- the pre-0x084A tree.         *)
(***************************************************************************)
DispatchGuard(a)  == IF BugMaskIsCosmetic THEN TRUE ELSE a \in enabled
DispatchPolicy(a) == a \in enabled

Dispatch ==
    \E a \in Caps :
        /\ DispatchGuard(a)
        /\ viol' = IF DispatchPolicy(a)
                     THEN viol ELSE viol \cup {"DisabledAppletNeverDispatches"}
        /\ UNCHANGED enabled

Next ==
    \/ WriteConfig
    \/ LockCodeWrite
    \/ PrivilegedOp
    \/ Dispatch

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS.                                                          *)
(***************************************************************************)

\* THE REVERSIBILITY GUARANTEE, read straight out of the state: the
\* administrative channel is reachable in EVERY state, so no sequence of config
\* writes can strand the device unable to re-enable a disabled applet. Structural
\* -- it needs no cooperation from any action, the strong form. This is the
\* `APPLET_CAPS` cap-`0` carve-out (crates/rsk-device/src/ccid.rs:67-74) as an
\* invariant: management/vendor/rescue are never gated by the mask, so `enabled =
\* {}` (everything off) is not a dead end -- READ/WRITE CONFIG still answer there.
AdminSurfaceAlwaysReachable == AdminChannelOpen

\* No privileged rescue command completes without a Confirmed operator presence.
\* A step, not a state (the op changes device identity, it does not leave a mask
\* bit), so it is a ghost with one writer: PrivilegedOp.
PrivilegedOpNeedsPresence == "PrivilegedOpNeedsPresence" \notin viol

\* A lock-code-only config write never changes the enabled set (audit run-35).
\* Ghost, one writer: LockCodeWrite. WriteConfig legitimately changes the set, so
\* it is not a writer here -- this is specifically the write that carries no
\* capability change and must therefore leave the owner's disable in place.
DisableSetSurvivesLockWrite == "DisableSetSurvivesLockWrite" \notin viol

\* A disabled application never serves a command -- the enforcement that made
\* `ykman config usb --disable` real (0x084A) rather than a DeviceInfo report.
\* Ghost, one writer: Dispatch. It has to be a step fact: serving a command
\* leaves no mask bit behind, so no state predicate can tell a served-while-
\* disabled history from a clean one.
DisabledAppletNeverDispatches == "DisabledAppletNeverDispatches" \notin viol

=============================================================================
