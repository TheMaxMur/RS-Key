<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Formal model

`formal/` in the repository holds a TLA+ model of the authenticator's security
state, the mutation matrix that keeps it falsifiable, and the registry that
ties its properties to the code. This page is the map; the deep prose — every
abstraction with its direction, every hole a review found and what closing it
cost — lives in `formal/README.md` next to the model itself.

**RS-Key is not formally verified**, and the model's own page opens by saying
so. What exists is narrower and it is measured: the paragraph to quote is in
[Testing](testing.md), under "Formal claims — what is and is not verified".

## The nine modules

`RSKeySecurityState.tla` models the FIDO security state: PIN retries, the
`pinUvAuthToken` and its permissions, which transport owns the touch, which
channel owns a stateful walk, the reset window, the persistent gate records,
and the position at which power is lost inside a multi-write flash sequence.
TLC checks its invariants exhaustively at small constants.

`RSKeyAppletSeams.tla` models what the first module deliberately leaves out:
the applets' access statuses — PIV, OpenPGP and OATH's seven doors, what a
SELECT means for each, what a refused authentication costs, and the
access-code removal gate.

`RSKeyStore.tla` models the flash layer one level beneath both — `rsk-fs`'s
key/value store over a `Storage` backend: whether a torn `delete` can orphan a
file's metadata, and whether the in-RAM present-cache can read a committed key
as absent. It is a lift of the Rust power-cut oracle (`powercut.rs`) that had
been reachable only by the fuzzer, and it is the store model the roadmap's
refinement pilot inducts its persistent-state invariant over.

`RSKeyRetryLattice.tla` models the retry & recovery budget lattice of the two
applets that have one — PIV (PIN, PUK) and OpenPGP (PW1, PW3, RC): the finite
counter behind each reference, the recovery reference that refills it, and the
anti-bruteforce arithmetic that is identical at every one. It is the part of the
applet surface with no safe oracle — exhausting a real PUK ladder blocks the
card and the only way back takes the keys — so an exhaustive check of every
verify/block/recover interleaving can run only in a model.

`RSKeyAppletPolicies.tla` covers the four applets' remaining stateful doors:
PIV NEVER/ONCE/ALWAYS slot policy and freshness spending, OpenPGP algorithm-
attribute invalidation, OATH access-code plus touch gates, and Yubico OTP slot-
code mutation plus its combined use/session replay position. OATH and OTP codes
have no retry counter; keeping this separate avoids proving invented budgets.
All four fit in one exhaustive graph: 2,268 distinct states at depth 14.

`RSKeyAdminSurface.tla` models the surface above all of them: the
enabled-applications mask, the always-on carve-out that keeps `ykman config usb
--disable` reversible, and the operator-presence gate on the privileged rescue
commands. Two of its four mutants rebuild defects that actually shipped — the
mask that was a DeviceInfo report rather than an enforcement, and the lock-code
write that silently re-enabled every disabled application.

`RSKeyTrustedDisplay.tla` models the confirm ceremony — the display build's
anti-phishing promise, *what is confirmed is what is shown*, as three
machine-checkable rules: an RP-naming operation completes only through the card
that names it, a press that predates the card approves nothing, and no exit but
a deliberate Allow ever reads as Confirmed. Two of its three mutants are
shipped display-build defects.

`RSKeyBootHardening.tla` models the two machines at the reset line — the
one-shot at-rest scrub lap (`EF_HARDENED` never lies about superseded
weak-sealed copies, and every lazy re-key re-arms it) and the scratch-word
lock carry (a warm reset moves the whole soft lock, never half of it). It
exists because `firmware/` has no host tests by construction: the model is
the only instrument that exercises these interleavings. Its
`PowerOnClearsScratch2` assumption is deliberately explicit and still awaits
an RP2350 hardware measurement; TLC does not turn it into a hardware fact.

`RSKeyTransport.tla` models the CTAPHID frame reassembler — the channel,
sequence and length checks a multi-frame message passes before dispatch: one
host application's continuation never assembles into another's message, an
out-of-order frame aborts rather than fills the gap, and a declared length
never overruns the buffer. It is already unit-tested and fuzzed per frame;
the model checks the invariants that live in the interleaving, which those
do not assert.

## Refinement pilots

The [token pilot](token-refinement.md) connects a small abstract token machine
to the detailed FIDO model and a bounded projection of `FidoState`. The
[cross-reset pilot](reset-refinement.md) closes the deliberately deferred reboot
seam for `ResetNeverWeakensSurvivingState`: concrete reset phases share the
production FID classifier, Kani proves the finite projection inductive, and the
existing `rsk-fs` oracle drives the full reset through byte-granular power cuts.
The real-board script is a destructive witness, not a proof, and its presence in
the evidence graph does not assert that a current hardware run passed.

## Trace validation

The models' fidelity to the code is kept by hand — citations, mutants,
co-refutation — and one thing none of that measures is whether the code *as
it runs* stays inside a model's behaviors. `TraceSeams.tla` closes that
empirically: a real session recorded from the software emulator is replayed
against the applet-seams model step by step, and a step the model refuses is
a TLC deadlock at that exact position. A second, hand-written session the
model must *reject* is required to go red, so the replay harness is proven
able to refuse. A green replay is evidence about the recorded sessions, not
a proof about all runs; coverage grows by recording richer sessions.

## The checks of the checks

An invariant no defect can violate is the TLA+ analogue of a test that cannot
fail, and this tree has been bitten by that class enough times to check for it
mechanically:

- **every invariant carries mutants** — each `Bug*` switch rebuilds a real
  RS-Key defect or removes a defence the tree has, and its `Solo_*.cfg` run
  must come back RED;
- **every green run has a floor** (`formal/floors.txt`) — a GREEN that got
  smaller than its recorded distinct-state count is reported as FLOOR, because
  a collapsed state space passes every invariant vacuously and once did;
- **a vacuous run is named** — a spec nothing enabled exits non-zero rather
  than reading as a pass;
- **the source is linted first** — two TLA+ traps that leave a spec
  well-formed and meaningless (a precedence slip turning an assignment into a
  guard, an action pinned to a no-op by its own `UNCHANGED`) are refused
  before TLC runs.

`scripts/test_run_tlc.py` keeps the runner itself falsifiable in the merge
gate. Its four artificial corruptions are a broken jar, a Solo invariant that
misses its mutant, a one-state VACUOUS run, and a muted Mut switch. Direct RED
and FLOOR cases keep all three job verdict boundaries explicit.

## Co-refutation

TLC proving that a model invariant rejects a defect does not show that the
production tests reject the same defect. `scripts/comutate.py` closes that gap:
each model mutant is an exact patch that re-injects the same semantic defect
into Rust, then runs the smallest relevant host-test slice in a throwaway git
worktree. A failing test is `co-refuted`; a green slice is an abstraction gap;
a defect made impossible by a shipped structural fix is `unreachable` only
with recorded evidence. A compile failure is never counted as a kill.

The roadmap's fixed phase-2 denominator is the original 28 FIDO mutants. The
generated table in `formal/README.md` records all 28, their target invariant,
model verdict and code-level verdict: **26/28 are co-refuted, two are
unreachable, and none is a gap**. Deriving that roster found six real coverage
gaps; each now has a regression harness. Later modules extend the live roster
to 43 entries: all 41 executable patches are killed and two are unreachable.

The merge gate cheaply checks the closed roster, patch anchors, expectations,
floors and generated table freshness. The expensive full measurement runs
weekly next to `cargo-mutants`; `run --write-readme` publishes the 28-row table
only after measuring every executable phase-2 patch.

## The registry

Every property TLC checks has an entry in `assurance/properties.toml` — id,
statement, source and status, nothing else hand-written. A `check.sh` row,
`scripts/assurance_gate.py`, derives the rest per run: which module defines
the property, which configurations check it, which mutants target it, which
Kani harnesses, fuzz targets, Rust files and device tests carry its name. The
gate holds the graph closed in both directions — nothing TLC checks may be
unregistered, nothing registered may be unchecked — and a status must equal
the evidence ceiling: a Kani harness carrying the property's name forces
BOUNDED, and PROVEN is refused until that evidence class exists in the tree.

The owner functions carry the property back into the code: a doc line of the
form ``Refines `RSKeySecurityState!NoTokenAfterInvalidation` — SEC-FIDO-003``
sits on each function the model's ownership table names, the gate validates
every tag, and every invariant in all nine shipped baseline configurations must
be named in production Rust somewhere. Firmware sources count as owners for the
boot module. The shared check runs from both `assurance_gate.py` and
`citation_gate.py`.

The evidence table and 26-member workspace coverage ledger in
`formal/README.md` are generated from that same audit. Cross-model `Supports`
tags close the two FIDO properties whose persistent half is owned by the store
module. The ordinary gate rejects a stale block; regenerate it after evidence
moves with `python scripts/assurance_gate.py --write-readme`.

`assurance/crates.toml` is the same discipline one level up: all 26 workspace
members classified — state modelled, modelled in part with the gap named,
unmodelled with the roadmap module named, pure with the differential or proof
files named, or out of scope with a reason. The ledger exists because
enumerating crates from memory has already missed four of them.

## Running it

```sh
nix develop                       # pins TLC and exports TLA2TOOLS_JAR
cd formal
./run-tlc.sh safety               # model + mutants + floors, ~30 min
./run-tlc.sh liveness             # the temporal half — needs a 12g heap
./run-tlc.sh all                  # both
./run-tlc.sh Shipped.cfg          # one configuration
./run-tlc.sh --tiers              # what each tier runs, for the gate
python3 ../scripts/assurance_gate.py   # the registry, held against the tree
python3 ../scripts/assurance_gate.py --write-readme  # refresh its README table
python3 ../scripts/comutate.py --lint  # closed roster + patch/table freshness
python3 ../scripts/comutate.py run     # re-inject the whole live defect roster
python3 ../scripts/comutate.py run --write-readme  # measure + refresh 28 rows
```

CI runs the `safety` tier weekly (`deep-checks.yml`, the `formal` job) and on
any push touching `formal/`, so an edit to the model is checked at once. The
`liveness` tier is deliberately not in CI: `Liveness.cfg` needs the 12 GB heap
`floors.txt` records for it, and a hosted runner has already died under less.
The registry and co-refutation lint gates run on every pull request as part of
`check.sh`; the full co-refutation roster runs weekly.
