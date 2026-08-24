--------------------------- MODULE RSKeyTokenView ---------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 RS-Key contributors                                  *)
(*                                                                         *)
(* The canonical refinement map γ from RSKeySecurityState (B) to the token *)
(* view (A). Phase 4 and the phase-5 INSTANCE consume this one definition.  *)
(***************************************************************************)

TokenGamma(pin, gate, tok, noRp) ==
    [ live            |-> tok.live,
      permissionMc    |-> "mc" \in tok.perms,
      permissionGa    |-> "ga" \in tok.perms,
      permissionCm    |-> "cm" \in tok.perms,
      permissionAcfg  |-> "acfg" \in tok.perms,
      rpBound         |-> tok.rp # noRp,
      pinSet          |-> pin.set,
      persistentGrant |-> gate.ppuat ]

=============================================================================
