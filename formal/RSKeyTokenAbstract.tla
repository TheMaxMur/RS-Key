------------------------- MODULE RSKeyTokenAbstract -------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 RS-Key contributors                                  *)
(*                                                                         *)
(* Tier A of the token-lifecycle refinement.  Outcomes label transitions;  *)
(* they are deliberately not state, so an unauthorized successful stutter  *)
(* remains distinguishable from an ordinary stutter.                       *)
(***************************************************************************)
EXTENDS FiniteSets

VARIABLE a

Ops == {"Noop", "IssueToken", "RevokeToken", "SetPin", "ClearPin",
        "MintGrant", "RevokeGrant", "UseMc", "UseGa", "UseCm", "UseAcfg"}

Outcomes == {"Silent", "Authorized", "Rejected"}

ValidPermissionShape(s) ==
    \/ /\ ~s.permissionMc /\ ~s.permissionGa
       /\ ~s.permissionCm /\ ~s.permissionAcfg
    \/ /\ s.permissionMc /\ s.permissionGa
       /\ ~s.permissionCm /\ ~s.permissionAcfg
    \/ /\ ~s.permissionMc /\ ~s.permissionGa
       /\ s.permissionCm /\ ~s.permissionAcfg
    \/ /\ ~s.permissionMc /\ ~s.permissionGa
       /\ ~s.permissionCm /\ s.permissionAcfg
    \/ /\ ~s.permissionMc /\ s.permissionGa
       /\ ~s.permissionCm /\ s.permissionAcfg

AStates ==
    {s \in [live            : BOOLEAN,
             permissionMc    : BOOLEAN,
             permissionGa    : BOOLEAN,
             permissionCm    : BOOLEAN,
             permissionAcfg  : BOOLEAN,
             rpBound         : BOOLEAN,
             pinSet          : BOOLEAN,
             persistentGrant : BOOLEAN] :
       ValidPermissionShape(s)
       /\ (s.live \/
             (~s.permissionMc /\ ~s.permissionGa /\ ~s.permissionCm
                /\ ~s.permissionAcfg /\ ~s.rpBound))}

SameVolatile(pre, post) ==
    /\ post.live = pre.live
    /\ post.permissionMc = pre.permissionMc
    /\ post.permissionGa = pre.permissionGa
    /\ post.permissionCm = pre.permissionCm
    /\ post.permissionAcfg = pre.permissionAcfg
    /\ post.rpBound = pre.rpBound

SamePersistent(pre, post) ==
    /\ post.pinSet = pre.pinSet
    /\ post.persistentGrant = pre.persistentGrant

Retired(post) ==
    /\ ~post.live
    /\ ~post.permissionMc /\ ~post.permissionGa
    /\ ~post.permissionCm /\ ~post.permissionAcfg
    /\ ~post.rpBound

Consumed(pre, post) ==
    /\ post.live = pre.live
    /\ ~post.permissionMc /\ ~post.permissionGa
    /\ ~post.permissionCm /\ ~post.permissionAcfg
    /\ post.rpBound = (pre.live \/ pre.rpBound)
    /\ SamePersistent(pre, post)

(***************************************************************************)
(* The sole semantic definition of A's transition relation.  Both Next and *)
(* the generated Rust table are derived from this four-argument relation.  *)
(***************************************************************************)
AllowedEventRel(pre, op, outcome, post) ==
    /\ pre \in AStates /\ post \in AStates
    /\ op \in Ops /\ outcome \in Outcomes
    /\ CASE op = "Noop" ->
               /\ outcome \in Outcomes /\ post = pre
         [] op = "IssueToken" ->
               /\ outcome = "Authorized" /\ pre.pinSet
               /\ post.live /\ SamePersistent(pre, post)
         [] op = "RevokeToken" ->
               /\ outcome \in {"Silent", "Rejected"} /\ Retired(post)
               /\ SamePersistent(pre, post)
         [] op = "SetPin" ->
               /\ outcome = "Authorized" /\ ~pre.pinSet /\ post.pinSet
               /\ post.persistentGrant = pre.persistentGrant
               /\ SameVolatile(pre, post)
         [] op = "ClearPin" ->
               /\ outcome = "Silent" /\ pre.pinSet /\ ~post.pinSet
               /\ post.persistentGrant = pre.persistentGrant
               /\ SameVolatile(pre, post)
         [] op = "MintGrant" ->
               /\ outcome = "Authorized" /\ pre.pinSet
               /\ post.persistentGrant /\ post.pinSet = pre.pinSet
               /\ SameVolatile(pre, post)
         [] op = "RevokeGrant" ->
               /\ outcome = "Silent" /\ ~post.persistentGrant
               /\ post.pinSet = pre.pinSet /\ SameVolatile(pre, post)
         [] op = "UseMc" ->
               \/ /\ outcome \in {"Authorized", "Silent"}
                     /\ (~pre.pinSet \/ (pre.live /\ pre.permissionMc))
                     /\ Consumed(pre, post)
                  \/ /\ outcome = "Rejected" /\ post = pre
         [] op = "UseGa" ->
               \/ /\ outcome \in {"Authorized", "Silent"}
                     /\ (~pre.pinSet \/ (pre.live /\ pre.permissionGa))
                     /\ Consumed(pre, post)
                  \/ /\ outcome = "Rejected" /\ post = pre
         [] op = "UseCm" ->
               \/ /\ outcome = "Authorized"
                     /\ ((pre.live /\ pre.permissionCm)
                           \/ (pre.pinSet /\ pre.persistentGrant))
                     /\ post = pre
                  \/ /\ outcome = "Rejected" /\ post = pre
         [] op = "UseAcfg" ->
               \/ /\ outcome = "Authorized"
                     /\ pre.live /\ pre.permissionAcfg /\ post = pre
                  \/ /\ outcome = "Rejected" /\ post = pre
         [] OTHER -> FALSE

AllowedEvent(op, outcome) == AllowedEventRel(a, op, outcome, a')

Next == \E op \in Ops, outcome \in Outcomes : AllowedEvent(op, outcome)

Init == a \in AStates /\ Retired(a)

TypeOK == a \in AStates

Spec == Init /\ [][Next]_<<a>>

AllowedRelation ==
    {edge \in AStates \X Ops \X Outcomes \X AStates :
       AllowedEventRel(edge[1], edge[2], edge[3], edge[4])}

=============================================================================
