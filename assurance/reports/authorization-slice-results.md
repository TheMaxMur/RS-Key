<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Authorization slice results

## Found and deliberately not fixed

Recorded here because they were measured while writing this page and each belongs
to a different work item:

- the `NoAuthorizationBypass` comment says eleven actions record it; the tree has
  21, and nothing compares the two;
- `formal/floors.txt` matches `Solo_RamNeverOutlivesFlashSeed.cfg` and
  `Solo_NoLiveTokenWithoutPinRecord.cfg` through the `Solo_*.cfg` wildcard, `RED`
  with no invariant named, and `formal/run-tlc.sh` skips the wrong-reason
  comparison exactly there. The hole is **narrow, not open**: both cfgs check only
  `TypeOK` and their own invariant, so the reasons that could pass unexamined are
  `RED: TypeOK` and a runner error. `floors.txt` says the column exists for rows
  whose own `INVARIANTS` block does not name one — which is the argument for
  leaving it, and it is still an unexamined pair;
- no `slice` in `formal/comutants.toml` runs `cargo kani`, so no Kani harness in
  the tree is falsified by a recorded mutant;
- five of the seven files co-refutation patches for this property carry no
  `Refines … — SEC-FIDO-001` tag, which is why the derived owner count is 2;
- the recorded session reaches 22 of 53 model actions and 10 of this
  invariant's 21, and the `security trace refinement` row ratchets the
  *counts* — `@TraceSecurityActionsMin 22` — without asking which actions.
  A recording that swapped ten reached actions for ten others would pass;
- **this page is itself the shape it warns about.** Five of its numbers sit in
  the `` `NAME` (`value`) `` form `scripts/docs_constants.py` holds against the
  code; the other forty-odd — every registry, matrix, threat, verdict, comutant
  and trace total — are copies beside a derivable gate, and no exit criterion
  protects them. `scripts/citation_gate.py` does not scan `docs/`. Each is
  reproducible from a command named in the section that states it, which is the
  most a design page can offer; making them derived is a sweep this page is not.

## What the implementation measured

The page above is the design, written before the proof code existed, and it is
left as it was written — with one exception, which is this section. Three of its
present-tense claims are now false, and each was made false deliberately:

- *"the retry budget, the soft lock, the reset window and the walk owner have no
  ledger anywhere"* — they have one.
  `assurance/token_refinement.toml` gained three **guard** axes beside its three
  writer axes, derived rather than listed, and `scripts/token_refinement_gate.py`
  holds 4 walk sites, 12 soft-lock sites and 2 reset-window sites both ways. The
  soft-lock scan reaches `crates/rsk-device` and `firmware/` because
  `FidoState::pin_lock` has **zero** callers inside `rsk-fido`;
- *"nothing in the tree compares the sentence to the set"* — `scripts/ghost_gate.py`
  does. 21 actions, 24 routes, and routes rather than names because three actions
  record twice;
- *"0 of the 67 `slice` invocations run `cargo kani`"* — one does.
  `BugCmWalkIgnoresChannel` carries a `proof` half that must redden
  `NoAuthorizationBypass/B1`, and a CBMC timeout or an unsupported construct is
  refused by name rather than counted as a kill.

The raw evidence is `assurance/bundle/SEC-FIDO-001.toml`, held to stage 1A's
ten-group contract by `scripts/bundle_gate.py`, with every log it points at
committed beside it under `assurance/bundle/logs/`. Two numbers from it are worth
repeating here because they answer questions this page could only pose:

- **the degeneracy check.** 31 disagreeing `(state, operation)` pairs over 22
  states, in two families. Every state disagrees on `ClearPin`, where the
  relation's `pre.pinSet` is a frame condition and §6.6's real gate is a window
  and a touch tier A cannot see; nine also disagree on `UseCm`, where §6.8.2 lets
  the persistent grant authorize on its own and RS-Key additionally demands
  `EF_PIN`. The second family is the shipped tree being **stricter than the
  requirement** — which an oracle transcribed from the code could not have shown;
- **the matrix closed no cell, and the reason is a number.** The model half of
  the `firmware-always-uv` settling question is answered — `AlwaysUv.cfg` runs
  the nine invariants its own `INVARIANTS` block names, with `alwaysUv` as the
  compiled default — but `cargo test -p rsk-fido --features always-uv` was
  446 passed and **172 failed** at `f52b720`, as recorded in
  `assurance/bundle/logs/cargo-test-always-uv.log` records. Read the pair
  with its run or not at all: the suite grows, so a later count of the same
  command is a second true measurement and not a correction of this one, and a
  bare pair names neither run. Re-running the command is what the settling
  question in `assurance/configurations.toml` does, spelling the target the way
  `scripts/check.sh` writes a host row; this page keeps the log's, because a
  second pair transcribed here is only a third copy to hold in step — that
  register's own was typed at `b245fee` and the command already answers
  differently. alwaysUv with no PIN answers `PUAT_REQUIRED` and the suite is
  written against the default door. No `check.sh` row exercises that column, and
  `covered` may rest only on the default build or on such a row. The nine is
  read off that block rather than restated here: this bullet said "all six
  invariants" from the day it was typed, and the file has never named fewer than
  nine, so the number was wrong when written rather than gone stale.
