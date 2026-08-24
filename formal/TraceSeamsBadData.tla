---- MODULE TraceSeamsBadData ----
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* HAND-WRITTEN, deliberately: a session the model must REFUSE, so the       *)
(* replay harness is proven able to reject one. A PIV key operation lands    *)
(* with no VERIFY behind it -- PivKeyOpGuard needs `held["pivPin"] /\ fresh` *)
(* -- so the replay has no successor at step 2 and TLC reports the deadlock. *)
(* If TraceSeamsBad.cfg ever goes GREEN, the harness has stopped replaying   *)
(* the trace it was handed; floors.txt requires it RED.                      *)
(*****************************************************************************)

Trace == <<
    [act |-> "SelectOther", a |-> "piv"],
    [act |-> "PivKeyOp"]
>>

====
