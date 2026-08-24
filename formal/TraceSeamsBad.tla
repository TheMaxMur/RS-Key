---------------------------- MODULE TraceSeamsBad ----------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* The falsifiability half of TraceSeams.tla: the same replay harness over a *)
(* trace the model must REFUSE (TraceSeamsBadData -- a key operation with no *)
(* authorization behind it). floors.txt requires this row RED: a deadlock at *)
(* the refused step is the harness demonstrating it can reject a session.    *)
(* The harness is duplicated from TraceSeams.tla because EXTENDS cannot be   *)
(* parameterized by a configuration; keep the two in lockstep.               *)
(*****************************************************************************)
EXTENDS RSKeyAppletSeams, Sequences, TraceSeamsBadData

VARIABLE idx
tvars == << sel, held, fresh, pfresh, oneShotSig, psig, oathCodeSet,
            refused, viol, idx >>

TraceInit == Init /\ idx = 1

Event(e) ==
    CASE e.act = "SelectOther" -> SelectOther(e.a)
      [] e.act = "Reselect"    -> Reselect(e.a)
      [] e.act = "PivVerify"   -> PivVerify(e.ok)
      [] e.act = "PgpVerify"   -> PgpVerify(e.r, e.ok)
      [] e.act = "PivKeyOp"    -> PivKeyOp
      [] e.act = "CardReset"   -> CardReset
      [] e.act = "PowerCycle"  -> PowerCycle

TraceNext ==
    \/ /\ idx <= Len(Trace)
       /\ Event(Trace[idx])
       /\ idx' = idx + 1
    \/ /\ idx > Len(Trace)
       /\ UNCHANGED tvars

TraceSpec == TraceInit /\ [][TraceNext]_tvars

=============================================================================
