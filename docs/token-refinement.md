<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Token refinement pilot

Phase 5 connects three deliberately different descriptions of one narrow
property: the per-boot lifecycle of the FIDO `pinUvAuthToken` and its persistent
credential-management grant. It does **not** establish whole-firmware formal
verification, cross-reset refinement, or liveness.

## The three tiers

- A is `formal/RSKeyTokenAbstract.tla`: 44 states and an outcome-labelled
  `AllowedEventRel`. `Next` is its existential closure, not a second relation.
- B is `formal/RSKeySecurityState.tla`. TLC checks native `INSTANCE` refinement
  in `TokenRefinement.cfg`, and checks labelled outcomes separately in
  `TokenRefinementOutcome.cfg`.
- C is `(FidoState, TokenPersistentView)`. The persistent view contains exactly
  `EF_PIN` and `EF_PAUTHTOKEN`. `EF_ALWAYS_UV` is excluded: it decides when UV
  is required, but it is not token-lifecycle state. A therefore
  over-approximates the no-PIN state when the runtime flag is enabled.

The TLA+ module owns `AStates`, `Ops`, `Outcomes`, and `AllowedRelation`.
`scripts/export_token_relation.py` only captures TLA+-serialized values;
`scripts/generate_token_edges.py` generates the Rust enums, `AState`, and exact
bitset. The exhaustive host test checks all 63,888 tuples. The current export is
44 states, 11 operations, 3 outcomes, and 871 allowed edges; these are printed
facts, not hand-maintained requirements.

## Concrete domain and boot boundary

`InitC` is the real boot shape relevant to this projection: `FidoState::new`,
the valid `BootState` lock/warm restoration performed by `AppletHandler::new`,
and clientPIN initialization. Initialization rerolls secret bytes but leaves the
abstract token retired. `ValidBootInput` bounds the restored mismatch byte by
`PIN_MISMATCH_LIMIT`; the board decoder clamps older or corrupt scratch values
to that range.

`ValidPersistent` admits all four presence combinations of `EF_PIN` and
`EF_PAUTHTOKEN`. This is intentional, including `grant && !pinSet`: firmware
before 0x08BF and a torn reset could leave that shape. Because A observes only
record presence, not record contents, no older-firmware version assumption is
needed for R0p. Every projected write and power cut remains inside those four
states.

`wf_concrete(F, P)` requires the production permission shapes represented by B,
`live(F) => P.pin_set`, a retired token to have no permission or rp binding, and
an rp binding to imply a live token. R2a checks `InitC`; R2b checks inductiveness
without `kani::assume`. R3a checks the initial map and R3b checks every bounded
named concrete step against the generated relation.

## Reset evidence table

| Reset class | Required `BootState` | Evidence status |
|---|---|---|
| Cold power cycle | `warm=false`, lock clear | Decoder and model agree; physical scratch2 clearing is M7-Q1 |
| Host `sys_reset` | `warm=true`, whole lock restored | Encoded/decoded in `firmware/src/pin_lock.rs`; emulator boot tests cover the consumer |
| Return from BOOTSEL | Cold semantics required | M7-Q2: measure whether the ROM path clears watchdog scratch2 before relying on it |

There is no `Compatible` premise. No additional boot restriction was found; R0a
uses only `ValidBootInput`. M7-Q1 and M7-Q2 are hardware-evidence tasks, not
assumptions silently added to the refinement theorem.

## Outcomes and completeness

Outcomes are labels, not A variables. `Authorized` on a dead-token stutter is
therefore still a distinct, forbidden tuple. R1o checks B action labels, while
the emulator trace carries `outcome_raw` copied from the real CTAP response.
The validator derives possible B outcomes independently and accepts only
consensus: one singleton equal to δC. Multiple interpretations are
`AMBIGUOUS`, never a selected witness; `formal/floors.txt` ratchets their count.

`assurance/token_refinement.toml` and
`scripts/token_refinement_gate.py` enforce the three completeness axes across
the tree: volatile A-visible writers, persistent writers for the keys derived
from `TokenPersistentView`, and authorization outcome producers.
`assurance-trace` exposes verification artifacts to the host emulator and is
never a firmware feature. `check.sh` poisons every assurance-only module in a
throwaway tree, proves the poison reaches a host feature build but not firmware,
and requires the pristine and poisoned firmware images to be byte-identical.

## Reproduce

```sh
nix develop -c ./scripts/token_refinement.sh --check
nix develop -c ./formal/run-tlc.sh TokenRefinement.cfg
nix develop -c ./formal/run-tlc.sh TokenRefinementOutcome.cfg
nix develop -c ./scripts/kani.sh state
```

The state/outcome mutants, wrong generated edge tests, broken-stop test,
dead-token authorized stutter test, and ambiguous-consensus test are part of the
same tree. Cross-reset behavior remains phase 6.
