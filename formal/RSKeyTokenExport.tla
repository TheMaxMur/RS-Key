-------------------------- MODULE RSKeyTokenExport --------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 RS-Key contributors                                  *)
(*                                                                         *)
(* A serialization shell around RSKeyTokenAbstract.  Domain and transition *)
(* semantics remain in TLA+; the host exporter only captures these strings. *)
(***************************************************************************)
EXTENDS TLC, Sequences

VARIABLE item

Abs == INSTANCE RSKeyTokenAbstract WITH a <- item

Bit(b) == IF b THEN "1" ELSE "0"

EncodeState(s) ==
    Bit(s.live) \o Bit(s.permissionMc) \o Bit(s.permissionGa)
      \o Bit(s.permissionCm) \o Bit(s.permissionAcfg) \o Bit(s.rpBound)
      \o Bit(s.pinSet) \o Bit(s.persistentGrant)

ExportItems ==
    {"TOKEN|SCHEMA|live:bool,permission_mc:bool,permission_ga:bool,permission_cm:bool,permission_acfg:bool,rp_bound:bool,pin_set:bool,persistent_grant:bool"}
      \cup {"TOKEN|STATE|" \o EncodeState(s) : s \in Abs!AStates}
      \cup {"TOKEN|OP|" \o x : x \in Abs!Ops}
      \cup {"TOKEN|OUTCOME|" \o x : x \in Abs!Outcomes}
      \cup {"TOKEN|EDGE|" \o EncodeState(e[1]) \o "|" \o e[2] \o "|"
               \o e[3] \o "|" \o EncodeState(e[4]) : e \in Abs!AllowedRelation}

ExportInit == item \in ExportItems /\ PrintT(item)
ExportNext == UNCHANGED item
ExportSpec == ExportInit /\ [][ExportNext]_<<item>>

=============================================================================
