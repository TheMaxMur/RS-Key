<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# FIDO authorization slice — design

The scope, the maps, the bounds, the mutants and the exit for the first
end-to-end assurance slice: `SEC-FIDO-001`, `NoAuthorizationBypass`. This page is
the **design and the measurement plan**, written before any of the proof code it
describes exists. It closes nothing, moves no property status, and adds no gate
row.

**RS-Key is not formally verified**, and a design page is the easiest place to
forget it: nothing below is evidence, and the closed slice it plans does not make
the firmware proven either.

Its purpose is narrow and worth stating so nobody reads more into it: fix a scope
that can be checked, so that the cost of actually closing the slice can be
*observed* rather than estimated. The three completed pilots — [token](token-refinement.md),
[cross-reset](reset-refinement.md) and [store](store-refinement.md) — are the
rehearsals this plans against; [Formal model](formal.md) is the overview. Every number below was measured on the tree at
the commit this page landed in, with the command named beside it.

One warning belongs at the top rather than at the bottom. `SEC-FIDO-001` leads
the registry on all four of the evidence columns — 46 configurations, 11 model
mutants, 11 co-refuted, and 4 Kani harnesses against `SEC-STORE-002`'s three,
which is the tree's next-best. On the axes this slice is about it is the strongest row there
is, so the cost of closing it is a **floor and not a price**. The weak-end counterpart is designed alongside it, at the end of this
page, for exactly that reason.

## What the tree already discharges

The slice is mostly assembly. Nine mechanisms already exist; each discharges part
of the obligation and none discharges the whole, and the value of this section is
the second column.

| Artifact | Discharges | Does **not** |
|---|---|---|
| `formal/RSKeyTokenAbstract.tla` | tier A: 44 abstract token states, 11 `Ops`, 3 `Outcomes`, one four-argument `AllowedEventRel`, outcomes as *labels* so an unauthorized success stays distinguishable from a stutter | state `NoAuthorizationBypass` at all — A carries no invariant, and has no presence, channel, retry, soft-lock or reset-window vocabulary |
| `formal/RSKeyTokenRefinement.tla`, `RSKeyTokenView.tla` | native `INSTANCE` refinement B→A over `TokenGamma`, plus `R1oStep`'s outcome obligation and `R1oOutcomeCoverage`'s equality guard on 23 outcome-producing action names | any coverage guard on the `viol` ghost — the outcome set and the authorization-recording set are different sets |
| `formal/RSKeyTokenExport.tla`, `scripts/export_token_relation.py`, `scripts/generate_token_edges.py` | the A relation serialized to Rust and checked exhaustively on the host, so A's semantics cannot drift from the generated table | give A an oracle *independent* of A: the export is A, so it can only catch transcription errors |
| `assurance/token_refinement.toml` + `scripts/token_refinement_gate.py` | the ownership ledger for the token half: 11 volatile writers, 14 persistent writers, 7 outcome producers, each with a derived-and-checked disposition | own anything outside the token: the retry budget, the soft lock, the reset window and the walk owner have no ledger anywhere |
| `formal/RSKeySecurityState.tla` | tier B: 53 actions, the named invariants `docs/testing.md`'s generated row counts off `Shipped.cfg` — six of them are the ones `formal/README.md` maps to Rust, and this cell read `six` for the whole set — `Guard`/`Policy` separation so an invariant can be falsified rather than restated | close the ghost's completeness — see the B map below, where the count is off by ten |
| `formal/TraceSecurity*.tla`, `scripts/security_trace.py`, `formal/traces/security-phase4.jsonl` | runtime correspondence: a 40-line recorded emulator session replayed as 74 steps, 41 state boundaries, 15 outcome boundaries, 7 gate boundaries, with `R4c` predicting the gate's answer, and eight `TraceSecurityBad*.cfg` — seven registered RED with the invariant each must break named, one a deliberate GREEN control — proving the replay can refuse | reach the property. The row itself prints `distinct_actions=22` of the model's 53, and only **10 of the 21** actions that record this invariant are among them — the whole `credentialManagement` family is unreached, which is the family the one existing Kani harness is about. Nor does it witness a board: the apparatus is `tools/emu` and its fidelity is an assumption nothing here discharges |
| `formal/comutants.toml` + `scripts/comutate.py` | 69 patched code twins and 4 recorded-unreachable, floored at 0 pending; 11 of them belong to `NoAuthorizationBypass` and all 11 are `expect = "killed"` | falsify a **proof**. Measured: 0 of the 69 `slice` invocations run `cargo kani` — every one is a `cargo test -p …`. The property's only Kani harness is reddened by no recorded mutant |
| `assurance/configurations.toml` + `scripts/matrix_gate.py` + [assurance matrix](assurance-matrix.md) | the configuration axis: 40 P0-family properties × 31 build configurations = 1240 cells, of which 37 covered, 139 equivalent, 0 conditional, 106 out-of-scope and 958 gap | decide this row's 24 gaps. `SEC-FIDO-001` is `covered` on `firmware`, `equivalent` on `firmware-pico` and `waveshare-one`, `out-of-scope` on the four `no-touch` images, and `gap` on the other 24 |
| `assurance/threat_clauses.toml` + `scripts/threat_gate.py` | the root: `SEC-FIDO-001`'s `source` names a clause of the [threat model](threat-model.md), `TM-HOST-GATES`, and 39 of 40 P0-family properties are traced across 50 clauses (37 defence, 13 context), 1 untraced | say anything about *sufficiency* — a clause is an anchor, not an argument that the property covers it |

Measured with `python3 scripts/assurance_gate.py`, `python3 scripts/matrix_gate.py`,
`python3 scripts/threat_gate.py`, `python3 scripts/token_refinement_gate.py`,
`python3 scripts/comutate.py --lint`, `python3 scripts/verdict_gate.py` and
`python3 scripts/kani_gate.py`.

## The row as it stands

`python3 scripts/assurance_gate.py` prints the three rows this page is about —
the slice's own `SEC-FIDO-001` and the two candidates for the calibration
counterpart, `SEC-FIDO-007` and `SEC-FIDO-008` — and
[`docs/assurance-vector.md`](assurance-vector.md) carries them generated, with
every column derived on each gate run.

They are **not** copied here. Three rows of that table stood in this section and
were right the day they were typed: within the week `e456d50` taught the
co-refutation credit to read the invariant-named configuration, `SEC-FIDO-007`'s
and `SEC-FIDO-008`'s `co` moved 0 -> 1, and the copy said 0 with every gate
green — the status half stayed true, so nothing about it looked stale. That is
the shape `scripts/claims_gate.py` now refuses outright.

The registry-wide line — how many properties, how many at each status, how many
crates ledgered and how many configurations tiered — is what
`python3 scripts/assurance_gate.py` prints, and it is not copied here. It was:
"199 configurations tiered plus 2 exempt" stood in this paragraph and was right
at the commit that wrote it; three configurations landed six minutes later and
nothing said so.

`SEC-FIDO-001`'s configuration column is `firmware` — the default image, no
cargo feature and no build knob. Everything below is about that column, and
about `firmware-pico` and `waveshare-one` only through the derived
same-cargo-features equivalence the matrix already carries.

### What is in this slice, and what is not

One registry row, four clauses. **In:** the token and its permission; the retry
budget and the soft lock; the reset window; the walk's owning channel. Those are
the four things the invariant's ghost and its two structural conjuncts are
about, and each gets an A/B/C treatment below.

**Out, and each for a stated reason** — a slice whose edges are vague is a slice
whose cost cannot be measured:

- `SEC-FIDO-002`'s cross-transport touch obligation is a separate registry row
  with seven harnesses of its own in `crates/rsk-device/src/presence_kani.rs`,
  two of them carrying its name. It appears here only where a mutant is shared;
- `getNextAssertion` ownership. The stateful assertion walk appears in **no**
  `formal/*.tla` module, and the walk-owner harness's own "what this does not
  prove" list says the `gna` walk is not modelled. It is a stage-4 obligation
  this slice does not take;
- `EF_DEVICE_PIN` and `EF_MINPINLEN`. The model carries one PIN record and says
  so in as many words above `LocalPinEnabled` — *"the device PIN is no CTAP
  credential, and EF_DEVICE_PIN is not modelled"* — while `EF_MINPINLEN` appears
  in no module at all. Both are stage-4, neither is here;
- every configuration column but the three named above. The slice's evidence is
  produced on `firmware` and the matrix keeps it there.

## The A map

**The statement.** For every abstract event `(pre, op, outcome, post)` the
relation admits, an `Authorized` outcome implies the gate that operation's
requirement names held in `pre`:

```
NoAuthorizationBypassA ==
    \A e \in AllowedRelation :
        e[3] = "Authorized" => RequiredGate(e[2], e[1])
```

**The domain.** `AStates` has 44 elements — five permission shapes × the
`live`/`rpBound`/`pinSet`/`persistentGrant` combinations the shape constraint
admits, which is 12 for the empty shape and 8 for each of the other four. With 12
`Ops` and 3 `Outcomes` the candidate tuple space is 44 × 12 × 3 × 44 = 69 696,
which is the space the generated Rust table is already checked over
exhaustively.

**Where the oracle comes from, and why that is the whole design.** `RequiredGate`
must be transcribed from CTAP 2.3 §6.5 and §6.8 — from the requirement — and
**not** read off `AllowedEventRel`. Defined the second way it is algebraically
the relation, the check cannot fail, and §4.3's eleventh condition refuses the
claim regardless of the other ten. This tree has already paid for that mistake
once, in the per-FID projection whose oracle was the code and which reported 0
divergences over 5⁴ inputs. So the design carries a **disagreement obligation**:
the set of tuples on which `RequiredGate` and `AllowedEventRel` differ is
computed, enumerated and written into the bundle. If it is empty, the A map is
degenerate and the slice does not proceed.

**What A deliberately does not say.** This is the load-bearing limitation of the
whole slice and it must not be discovered later:

- A has no presence, no channel, no retry counter, no soft lock and no reset
  window. `NoAuthorizationBypass` at tier B is a **four-clause** property — the
  token and its permission, the retry budget and soft lock, the reset window, and
  the walk's owning channel — and only the first has an image in A. The other
  three are complementary source obligations, not A-level claims;
- `rpBound` is a boolean, so a token bound to the *wrong* relying party is
  invisible at A. The rpId-identity half belongs to B;
- A observes record *presence*, never record contents, so nothing about PIN
  entropy, verifier derivation or MAC verification is in scope;
- `persistentGrant` is that record, not a platform holding it. Since 0x09CB the
  device writes `EF_PAUTHTOKEN` itself at a boot, a finished reset or a backup
  load (`ProvisionGrant`), so `UseCm`'s grant arm is met by a record nobody may
  have been handed. Possession is the token's secrecy and has no image in A. B
  keeps the issued grant apart as `gate.ppuat` and `PpuatGuard` reads it, but no
  mutant in the roster takes that half of the guard out;
- A has no time, so `PUAT_MAX_USAGE_PERIOD_MS` (`600000`) and
  `RESET_WINDOW_MS` (`10000`) are outside it by construction.

## The B map

B is `formal/RSKeySecurityState.tla`. The invariant is three conjuncts:

1. the ghost — `"NoAuthorizationBypass" \notin viol`;
2. the §6.5.5.7 triad, read out of state — `(upSpent /\ tok.live) => tok.perms = {}`;
3. the soft lock reflecting its policy — `(lock.policyMism >= MismatchLimit) => lock.soft`,
   with `PIN_MISMATCH_LIMIT` (`3`) and `MAX_PIN_RETRIES` (`8`) as the shipped
   constants the configuration pins.

**Mechanised.** TLC checks the invariant over the whole reachable space of each
of the 46 configurations that name it (`grep -lw NoAuthorizationBypass
formal/*.cfg | wc -l` — `-w`, because the bare `-l` also matches the tier-A
`NoAuthorizationBypassA` in two more and printed 48). `formal/Shipped.cfg` pins `RPs = {r1, r2}`,
`Channels = {c1, c2}`, `MaxRetries = 8`, `MismatchLimit = 3`, `MaxClock = 1`,
`ResetWindow = 0`; the roster as a whole is not one scope, and
`python3 scripts/scope_gate.py` prints the spread it runs at. The
B→A step is mechanised for the token clause only, natively: `R1sTokenStateRefinement
== Abs!Spec` in `TokenRefinement.cfg` and `R1oTokenOutcomes` plus
`R1oOutcomeCoverage` in `TokenRefinementOutcome.cfg`, both floored GREEN, with
`TokenRefinementBadMap.cfg` and `TokenRefinementDeadToken.cfg` registered RED as
the negative witnesses.

**Asserted, not mechanised — and this is the gap the slice owns.** The ghost
clause is only as strong as the completeness of the actions that populate it. The
invariant's own comment says *"Those eleven are the whole list; no other action is
gated by an authorization."* Measured over the module, **21 of the model's 53
actions** can add the name:

- through `PinAttempt` — `GetPinToken`, `WrongPin`, `MintPpuat`, `ChangePinStart`;
- directly — `LocalCeremonyStart`, `LocalPinWrong`, `LocalPinOk`, `SetPinStart`,
  `RegisterTouched`, `RegisterNdTouched`, `AssertFinish`, `CmBeginViaPpuat`,
  `CmNext`, `ResetStart`, `ResetConfirmed`;
- through `TokenBypass` — `RegisterStart`, `RegisterNdStart`, `AssertStart`,
  `ConfigOp`, `CmBeginViaToken`, `DeleteCredStart`.

The comment names twelve of them once `PinAttempt` is expanded into its four
callers, and calls the list "eleven" — a count that matches neither its nine
written items nor the twelve actions they stand for. **Nine actions it names
nowhere** record the invariant: `LocalCeremonyStart`, `LocalPinWrong`,
`LocalPinOk`, `SetPinStart`, `RegisterTouched`, `RegisterNdStart`,
`RegisterNdTouched`, `AssertFinish` and `ResetConfirmed`: three for the on-panel
ceremony, two for the token-less registration arm, three continuations of flows
whose *Start* the comment does list (`RegisterTouched`, `AssertFinish`,
`ResetConfirmed`) — and `SetPinStart`, which is a *Start* of a flow the comment
omits entirely. Nothing in
the tree compares the sentence to the set. `R1oOutcomeCoverage` is the only
completeness equality inside the models and it guards a *different* set: the 23
names of `TokenOutcomeActions`. So the design's B-level obligation is a second such
equality, over the authorization-recording set, derived from the module rather
than listed.

## The C map

Three production surfaces, and the registry sees only the first. Naming the
difference is the point.

**Level 1 — what the registry derives (`rust = 2`).** `assurance_gate.py` greps
production Rust for the literal invariant name, so the column is exactly the files
carrying a `Refines RSKeySecurityState!NoAuthorizationBypass — SEC-FIDO-001` tag:
`crates/rsk-fido/src/state.rs` (twice: `CredMgmtState::may_walk_rps`, and
`PinLock`) and `crates/rsk-fido/src/clientpin.rs` (`spend_and_verify_pin_hash`).

**Level 2 — what co-refutation already drives.** The 11 killed twins patch **7
files across 3 crates**: `rsk-fido/src/state.rs` (`BugCmWalkIgnoresChannel`,
`BugConsumeKeepsMcGa`, `BugNoConsumeAfterUp`), `rsk-fido/src/clientpin.rs`
(`BugSetPinOverExisting`), `rsk-fido/src/makecredential.rs`
(`BugUvNotRqdIgnoresRk`, `BugTokenlessIgnoresAlwaysUv`), `rsk-fido/src/reset.rs`
(`BugWarmResetReopensWindow`), `rsk-device/src/presence.rs`
(`BugHostPreemptsLocalWait`, `BugNoTouchRequired`), `rsk-device/src/ctap.rs`
(`BugSoftLockLostOnWarmReset`) and `rsk-display/src/gates.rs`
(`BugLocalPinIgnoresBudget`). Five of those seven files carry no tag, which is
why the derived column says 2.

**Level 3 — what the property is about.** The 21 actions' owners. The token half
is ledgered already (`assurance/token_refinement.toml`); the retry/soft-lock,
reset-window and walk-owner clauses are not ledgered anywhere.

### The callers

A projection over a function nobody calls the way the model assumes is where the
last pilot died, so the callers are written down first and the projection second.

| Concrete gate | Production callers | Reached by the harness? |
|---|---|---|
| `CredMgmtState::may_walk_rps` | one — `enumerate_rps`, `crates/rsk-fido/src/credmgmt.rs`, the `else if !…` arm | no — reproduced |
| `CredMgmtState::may_walk_creds` | one — `enumerate_creds`, same file, same shape | no — reproduced |
| `spend_and_verify_pin_hash` | three — changePIN's old-PIN check, the getPinToken door, and the on-pad PIN door, all in `crates/rsk-fido/src/clientpin.rs` | no harness exists |
| — | *counted the way the registry counts: production files only, dropping any filename containing `kani` or `tests`, which is `assurance_gate.py`'s own rule. Stating it is the difference between a table a reader can reproduce and one they must trust* | |
| `FidoState::pin_lock` / `restore_pin_lock` | `crates/rsk-device/src/ctap.rs` on both sides of a warm reset, with the board half in `firmware/src/pin_lock.rs` | no harness exists |
| `enforce_pin` | **two distinct private functions**, one in `makecredential.rs` and one in `getassertion.rs`, one call site each — not one gate with two callers | no |
| `verify_cm_token` | three, all in `credmgmt.rs` | no |
| `authorized_by_ppuat` | one — `authorize_cm`, `credmgmt.rs` | no |
| `authenticator_config` | one — the CBOR dispatch in `crates/rsk-fido/src/lib.rs` | no |
| `vendor::pin_gate` | six sites in `crates/rsk-fido/src/vendor.rs` | no |
| `consume_after_user_presence` | one — `Ctx::user_presence_test` in `crates/rsk-fido/src/up.rs`, which the four makeCredential / getAssertion user-presence tests (two in `makecredential.rs`, two in `getassertion.rs`) go through; the two success paths build their UP bit from the `UpFlag` it returns | no |

**What the one existing harness actually proves.**
`no_authorization_bypass_walk_owner` in `crates/rsk-fido/src/state_kani.rs` runs a
symbolic five-operation interleaving over an eight-symbol opcode alphabet with two
channels, and asserts an *equality* — `may_walk_rps(probe) == (rp_owner ==
Some(probe))` — before and after every operation, on both channels. Its oracle is
non-degenerate by construction and the file says how: `rp_owner`/`cred_owner` are
tracked from the **opcode** and never read back out of `st`, so a guard that
refuses everything fails it too. It carries three `kani::cover!`s, counted into
the tier ratchets `scripts/kani_gate.py` holds against the tree.

What it does not do is call either real caller. `begin_rps` and `begin_creds` are
local re-implementations of the cursor writes in `enumerate_rps` /
`enumerate_creds`, composed by hand with the `cm.reset()` that the
`credentialManagement` subcommand demux performs one frame out.

What is missing is the **decision, not the state**. The state a refused
`authorize_cm` leaves behind is reachable in the harness — `W_OTHER_CM_SUBCOMMAND`
performs the same `retire_sequences_except` plus `cm.reset()` — but the Begin's
own gate, the `pinUvAuthParam` MAC and the `cm` permission bit and the rpId
binding, is never evaluated. The harness proves what follows an authorization it
assumes; the property is about the authorization.

Three further divergences the phrase "reproduces the cursor writes" covers over,
and a design that does not list them is making them silently:

1. `begin_rps` writes `rp_total` in one shot. The real `enumerate_rps` sets
   `rp_total = 0` first and returns `Err(NoCredentials)` on an empty scan
   **before** advancing `rp_counter` or stamping `last_leg_ms` — an intermediate
   state the harness has no shape for;
2. the real Begin reaches `load_keydev()` and can fail to the host *after* all
   three cursor fields are written, so an errored Begin can leave a live walk
   cursor behind. The harness cannot express an errored Begin at all;
3. `begin_creds` never writes `cm.rp_id_hash`, which the real
   `enumerate_creds(begin = true)` does and which the demux reads back to serve a
   *Next*. That is a cursor field, not an abstraction the page defers to B.

None of the three breaks B1 or B2 in any state checked by hand — `may_walk_rps`
is false throughout — but "checked by hand" is the reason they are listed rather
than the reason they can be omitted.

So the C map's obligation is stated as a composition, not as a rewrite: prove the
guard **at its call site**, with the authorization step in the harness rather than
assumed away. `credmgmt_kani.rs`'s existing `no_token_after_invalidation_at_call_site`
is the shape to copy, and the only harness in the two crates named for a call
site rather than for a function.

## The assumptions

Each is named, classed, and given a discharger. The last column is the one that
matters for planning: `scripts/assumption_gate.py` structurally accepts only a
**boolean TLA constant that some configuration assigns both ways and some
reachable definition reads**. Anything else has nowhere to be written down *in
that registry* — which was the finding, and the split below is what chose the
answer to it. The class has a second registry now,
[platform assumptions](platform-assumptions.md), whose gate derives these very
ids from this page.

| id | Assumption | Class | Who could discharge it | Expressible in `assumption_gate` today |
|---|---|---|---|---|
| `AS-AUTH-1` | `tools/emu` implements the same authorization gates as the firmware, so a recorded session is evidence about the firmware | tool fidelity | a board recording of the same session, compared boundary by boundary | **no** — not a model constant |
| `AS-AUTH-2` | The build does not ship `always-uv`, so `gate.alwaysUv` is a free state variable rather than pinned true | build configuration | the [matrix](assurance-matrix.md)'s `firmware-always-uv` column, whose settling question already names `SEC-FIDO-001` | **yes, with work** — its *content* is a boolean over `gate.alwaysUv`, which reachable definitions already read (`UvRequired`, `McTokenlessPolicy`, the `mc`/`ga` guards) and `ConfigOp` already flips. A constant pinning it in `Init` and disabling that flip, generated both ways by `gen-configs.sh`, is the same shape `PowerOnClearsScratch2` needed. The obstacle is work, not the gate |
| `AS-AUTH-3` | A CTAPHID channel id is a routing label the sender writes, so channel ownership is a scoping rule and never an authentication one | threat model | a clause of the [threat model](threat-model.md); `state.rs` states it in prose today | **no** |
| `AS-AUTH-4` | `PowerOnClearsScratch2` — a real power-on clears the watchdog word the soft lock rides in | platform | the board measurement `assurance/assumptions.toml` already describes | **registered, but not against this slice.** The constant is declared and read only in `RSKeyBootHardening`, and the overlap between the 13 configurations that assign it and the 46 that check `NoAuthorizationBypass` is **zero** (`comm -12` over the two `grep -lw` lists). The soft lock is this slice's clause 3 and the assumption underneath it is the boot module's; borrowing the row without saying so would be the same slice-boundary error this page is written against |
| `AS-AUTH-5` | `PermSets`, five of the sixteen subsets, is the set a host can actually obtain | model fidelity | reading the two production sites that mint permissions; it is argued in the module, not measured | **no** |
| `AS-AUTH-6` | One credential per relying party | model abstraction | the store slice; `MAX_RESIDENT_CREDENTIALS` (`256`) is the shipped cardinality | **no** |
| `AS-AUTH-7` | Kani/CBMC is sound for the harness's arithmetic and the pinned solver is the one that ran | tool TCB | the pinned toolchain and a recorded tool hash | **no** |
| `AS-AUTH-8` | `ea-conformance-rpid`'s enterprise-attestation allowlist is not an authorization gate | build configuration | the matrix's own settling question for that column, which asks exactly this | **no** |

**Zero of the eight were registered against this slice, and measuring that is
what this page contributed.** `AS-AUTH-4` was registered, but in another module
and reachable from none of this slice's configurations; `AS-AUTH-2`, and arguably
`-3` and `-8`, could be encoded today at the cost of writing the constant and its
two arms; `AS-AUTH-5` (a set, not a boolean), `-6` (a cardinality), `-1` and `-7`
(facts about a tool, not about the model) have no expressible form at all. That
last group is what `assurance/platform.toml` was stood up for, and all eight have
an entry there now — `scripts/platform_gate.py` derives these ids from this page
and from this slice's own bundle, and reddens on one no entry claims. Registered
is not discharged: the [platform assumptions](platform-assumptions.md) page
prints that ratio in its first sentence, and `AS-AUTH-4`'s route still ends at a
board.

## The bounds

Every shrink, and what each stops proving, is now [the bounds page](assurance-bounds.md):
generated from `assurance/bundle/*.toml` by `scripts/bounds_gate.py` and
byte-diffed on every gate run. Fourteen rows stood here instead, and they were
this stage's own exit criterion failing on its own page — no script read them,
so a bound moved here while the bundle stood still was green on all eight gates,
as was the reverse, as was a row named after a constant that does not exist.

`formal/scopes.txt` still records the measured per-constant minima and which
invariant each was measured against. What the generated page adds is the
attribution — which property, which `[[method]]` obligation, which artifact —
and the consequence, which is the column worth keeping and the one that has to
travel *with* the number rather than beside it. So it is carried per bound in
the bundle, `stops_<name>` next to `bound_<name>`, the way `shipped_relation`
already travels with a method row.

Three rows that stood here name no bundle key at all: the two `cfg(not(kani))`
compile-time assertions on the path, the safety-only symmetry argument, and the
one-credential-per-relying-party cardinality. Their absence from the generated
page is what "derived from the bundle" costs — a consequence with no measured
bound behind it was a sentence this page asserted on its own authority.

## The mutants

What must redden which level, and with which reason. A red run is not evidence
until the direction is read — `AGENTS.md` records two of twenty-four
co-refutation patches scoring a kill for the *inverse* defect, and the tell was
that every failure said "should have succeeded" and none said "should have been
refused".

| Level | Mutant | Must redden | Expected reason |
|---|---|---|---|
| A | an edge added to `AllowedRelation` that is `Authorized` with `~pinSet` and no live token | the new A-level configuration | `NoAuthorizationBypassA` violated on that edge, naming the op |
| A | `RequiredGate` weakened to `TRUE` for one op | E4a's disagreement configuration, **not** the invariant | it stops being RED for that op's tuples. A disagreement configuration that goes GREEN is a refusal, not a pass |
| B | the 11 existing switches | 11 `Solo_*.cfg` and the `Mut_*` family — already registered RED in `formal/floors.txt` | the invariant named by each `Solo_*` |
| B | deleting one action's `viol` write | the new ghost-completeness row | the row names the action whose write is gone |
| B→A | `MutateTokenGamma`, `BugDeadTokenAuthorized` | `TokenRefinementBadMap.cfg`, `TokenRefinementDeadToken.cfg` — already RED | the refinement or the outcome clause |
| C | `BugCmWalkIgnoresChannel` re-driven against the **harness** rather than the unit suite | `cargo kani -p rsk-fido --harness no_authorization_bypass_walk_owner` | assertion `NoAuthorizationBypass/B1` or `/B2` |
| C | a new `authorize_cm`-weakening patch at the call site | the new at-call-site harness | the authorization assertion, not the cursor assertion |
| trace | `MutateUvNotRqd`, `MutateAlwaysUvArm`, `MutateResetWindow`, `MutatePinSet` | four `TraceSecurityBad*.cfg` — already RED, each with its reason recorded | `R4cGateAnswers`, at one of the 7 gate boundaries |

The sixth row is the finding this table exists for. **No recorded mutant reddens
any Kani harness in this tree**: all 67 patched co-mutants run `cargo test -p …`.
The property's single proof is therefore falsified by nothing, which is the same
shape as a guard whose wiring nothing exercises — one layer in.

## Exit criteria

Each row names a **command** and the value that command must print. The failure
column is not decoration: an exit nobody can make red is the defect three stages
of this programme shipped, and the reviewer of this page found five of an earlier
nine in that state — satisfiable by prose, by a wildcard, or by doing nothing.
What survives is below, with the repairs named.

| # | Command and the value it must print | What would make it fail |
|---|---|---|
| E1 | **not** the `rust` column. `python3 scripts/assurance_gate.py` prints `rust=N` by grepping whole file text, doc comments included, so pasting the `Refines … — SEC-FIDO-001` line into five files moves it from 2 to 7 with no other work. The predicate is instead: `python3 scripts/token_refinement_gate.py` accepts the retry/soft-lock, reset-window and walk-owner clauses as ledgered sites, and rejects an unowned one | the ledger is extended by hand without extending what the gate *derives*, so a new gate site arrives as silence rather than as an unowned site. That is the failure `assurance/properties.toml`'s header records, one register over |
| E2 | the A-level configuration has an **exact** row in `formal/floors.txt` naming its invariant, not a `Solo_*`/`Mut_*` wildcard match, and `python3 scripts/verdict_gate.py` exits 0 | naming it `Mut_…` or `Solo_…`. `verdict_gate.py` reports 25 wildcard families covering 165 of 200 configurations, every one `RED -`; a new mutant swallowed by one of those satisfies a weaker E2 and lands in exactly the hole this page's own last section reports. `formal/run-tlc.sh` compares the reason only where the row names an invariant |
| E3 | for each of the 21 recording actions, a script deletes **every** route by which that action adds the name and asserts the new completeness row goes red naming it | deleting only one route. `RegisterStart`, `RegisterNdStart` and `AssertStart` each record by **two** independent routes — `viol \cup TokenBypass` *and* a `ButtonFreePolicy` disjunct — so a per-action single deletion leaves the other standing, the row stays green, and E3 reports a pass over a half-deleted guard. Also fails if the completeness set is derived from the same expression it checks |
| E4a | at tier A: a configuration whose invariant is `RequiredGate(op, s) = GateFromRelation(op, s)` goes **RED**, and its counterexample set is written into the bundle | the two agree everywhere. Note the direction — `NoAuthorizationBypassA` is only about `Authorized` tuples, so a green A tier is compatible with agreement on all of them; the non-degeneracy evidence must therefore be this *separate* red configuration, over all three outcomes, and not the invariant itself |
| E4b | at tier C: for each new harness, the bundle records the input class on which the **requirement** and the code differ, demonstrated by a patch that makes the harness red — not by a disagreement in the shipped tree | there is no such class, i.e. the oracle was transcribed from the code. A Kani oracle that disagrees with shipped code *is* a failed proof, so at this tier non-degeneracy can only be shown by mutation, never by a divergence count. This is the D5 refutation, restated so it is checkable at the tier it actually applies to |
| E5 | `cargo kani -p rsk-fido --harness no_authorization_bypass_walk_owner` goes red under the `BugCmWalkIgnoresChannel` patch, and names `NoAuthorizationBypass/B1` or `/B2` | it reddens on a different assertion. The patch rewrites `may_walk_rps`'s body to drop the channel conjunct, so B1's equality must fail on the non-owning probe specifically; a different assertion means a different defect |
| E6 | a schema check over the bundle: every one of the ten groups present, every leaf non-empty, and every numeric cost field a number rather than a range | ten headings with one line each. "Unabridged" is not a predicate until something counts leaves, so the contract below is written as leaves and the check is over them |
| E7 | after the slice, each matrix cell it closed carries a `[[cell]]` whose `basis` `python3 scripts/matrix_gate.py` re-derives; cells it did not close still read `gap` | using the existing state as the criterion. `matrix_gate.py` exits 0 today and the row already shows 24 `gap`, so "still shows 24 gap" was a no-op — it could only redden if someone edited the matrix, never as a consequence of failing to do the work |
| E8 | `SEC-FIDO-001`'s `status` is still `BOUNDED` | nothing — and this is **not an exit**, it is a guard-rail, kept in the table under its own name so a reader counting ten rows does not read ten exits. It reddens only if someone moves the scalar `assurance_gate.py` derives from a harness *name* |
| E9 | `nix develop -c ./scripts/check.sh` and `nix develop -c ./scripts/check-assurance.sh` each exit 0, taken **without a pipe**, and print `ALL CHECKS PASSED` and `ALL ASSURANCE CHECKS PASSED` — the slice's bundle and bounds rows run in the second | reading the exit code through a pipe. `check.sh` prints no row count — only `== <name> ==` per row and the final line — so the earlier form of this criterion compared a hand-counted number against a number the same work item wrote, and a bundle recording a lower count passed |

Nine exits and one guard-rail — E8, which reddens only if someone moves the
scalar. **E4a and E4b decide whether the slice was worth doing; E2, E3 and E5
decide whether its guards are wired to anything.** The rest is hygiene, and
hygiene is where this programme has actually lost rows.

## The raw-bundle contract

Stage 1A's minimal contract, in current formats, unabridged — the ten groups the
implementation must emit. This is not the evidence schema; it exists so the first
closed slice hands the schema work a real migration fixture instead of data
scattered across logs. A missing field blocks exit.

1. **Property, subject and owners** — the registry id `SEC-FIDO-001`, the
   invariant name, the statement as the registry words it, the subject class per
   §4.1 (requirement / abstract model / Rust source / FFI / binary / hardware /
   integration), and every production owner by repo path.
2. **Exact commit, build and features** — the commit hash the evidence was
   produced at, the tree state (`git status --short`), the matrix column, the
   cargo feature set, the board knobs, and the target triple for each artifact.
3. **Method and scope/bounds** — the method per §4.1 (review / model-check /
   bounded proof / deductive proof / exhaustive sweep / mutation / trace /
   measurement / accepted risk / KAT/differential), and for each obligation its
   bound as structured data: sequence length, symbolic byte count, cardinalities,
   unwind, `cfg` and feature set, and the relation between each bound and the
   shipped constant. `KAT/differential` is published vectors, or a reference
   implementation, run against this one; it is discharged by the `#[test]` or the
   `tests/*.py` that RAN them, never by the table they sit in — and the gate
   holds the second half as literally as the first, a `.py` outside `tests/`
   needing to name a `def` of its own that a test runner collects, which in
   Python is the name and not an attribute. It is not `measurement`, which in this
   contract means a result taken off a board and owes the silicon revision it was
   taken on.
4. **Tool, version, invocation and execution environment** — for every artifact:
   tool name, exact version, the full command line, the environment
   (`WORKERS`, `HEAP`, `TIMEOUT`), the machine, and the tool hash where one
   exists. Measured in the dev shell at this commit: `rustc 1.96.0`, `cargo 1.96.0`,
   `cargo-kani 0.67.0`, `tlaplus 1.7.4`, `openjdk 1.8.0_492`, `mdbook 0.5.2`,
   `lychee 0.24.1`. Six of the seven come from the flake; **Kani does not** — it
   is not packaged in nixpkgs and CI installs it with `cargo install --locked
   kani-verifier`, so its version is pinned by a workflow variable and not by
   `flake.lock`. A bundle that records the number without that provenance
   records a version nothing in the tree holds.
5. **Principal result** — for each artifact the verdict, and for a TLC run the
   distinct-state count, the depth, the workers and the invariant actually
   checked; for a Kani run the harness name, the assertion set and each
   `kani::cover!` verdict.
6. **Raw artifact or log** — the path to the unedited output of every run, kept
   whole. A summarized log is not an artifact.
7. **Assumptions and TCB / trust dependencies** — the eight `AS-AUTH-*` rows
   above, each with its class, its discharger and whether it is expressible in
   `assurance/assumptions.toml` today; plus every solver, compiler and platform
   dependency on the path.
8. **Mutation verdicts** — per mutant: the level, the patch anchor, the
   invocation, the verdict, **the assertion that fell and its direction**, and
   the `reading` that argues whether it describes the modelled defect or its
   inverse. A row whose direction is `inverse` is a finding about the *mutant*
   and not a result about the property, so it also carries a `disposition`:
   either `superseded`, naming in `superseded_by` another row of the group that
   corrects it — a chain that must end at a row which is not itself `inverse`,
   because a cycle corrects nothing — or `kept-as-a-finding`. Both arms owe the
   `reading`, and the success line counts the disposed rows apart from the
   verdicts so one cannot be read as a kill.
9. **Timestamp, freshness and revalidation inputs** — when each run happened, and
   the triggers that expire it: toolchain bump, Kani or TLC version, RP2350
   stepping, linker script, dependency change, a change to any named Rust owner,
   the feature set, or a trace schema change.
10. **Measured costs** — human time, runner wall time, and peak memory, per
    artifact. These three are what item 11 exists to observe; an estimate in any
    of them voids the measurement.

## The calibration counterpart

A cost taken at the strongest end of the scale is a floor, so the design names
the other end too. The counterpart is the
weak end: `SEC-FIDO-007` `RamNeverOutlivesFlashSeed` and `SEC-FIDO-008`
`NoLiveTokenWithoutPinRecord`, each measured at 4 configurations, 1 model mutant,
0 Kani, 0 fuzz, 0 device tests and 1 production owner
(`crates/rsk-fido/src/seed.rs` and `crates/rsk-fido/src/clientpin.rs`
respectively). The co-refuted column read **0** when this was written and reads
**1** now, which is the correction below carried out rather than described.

**The correction, now made.** What that `co = 0` meant was never "no killed
twin": Both rows' solo
configurations set the *same* switch, `BugStateResetAfterWipe` — and that switch's
code twin is in `formal/comutants.toml` with `status = "patch"` and
`expect = "killed"` against `crates/rsk-fido/src/reset.rs`. The `0` is an artifact
of attribution: `comutate.solo_invariant` resolves a bug to the one configuration
named `Solo_<bug>.cfg`, which here checks `ResetNeverWeakensSurvivingState`, so the
kill is credited to `SEC-FIDO-006`. The weak end was weaker in the ledger than it is
in the tree, and no amount of reading the column would have shown that.
`comutate.solo_index` reads the invariant-named solo configurations too now, so
the column says what the tree proves: in the launch tranche
`SEC-FIDO-004` moved 1→2 and `006A`, `006B`, `007` and `008` each moved 0→1, so
the rows standing at `co = 0` went from six to two. The prerequisite this section called a hard
one is therefore discharged, and what the counterpart still owes is the
measurement itself.

**The estimate, stated as an estimate.** Same bundle contract, applied to
`SEC-FIDO-007`:

- groups 1, 2, 4 and 9 cost the same on both rows — they are properties of the
  run, not of the property. That fixed part is what item 11's floor measures
  honestly;
- groups 3, 5 and 6 are cheaper: both invariants are single structural
  implications over B state with no ghost half, already model-checked on two
  configurations, and `NoLiveTokenWithoutPinRecord` maps to A almost directly as
  `live => pinSet`;
- groups 7, 8 and 10 are **more expensive**, and that is the direction the
  intuition gets wrong. On `SEC-FIDO-001` those fields are transcription — the
  assumptions are argued in the module, the mutation verdicts exist, the caller
  set is short. On `SEC-FIDO-007` every one of them has to be produced from
  nothing: the `keydev_dec` RAM copy's reachability argument spans
  `crates/rsk-fido/src/seed.rs`, the field's home in `state.rs` and the load
  preference in `crates/rsk-fido/src/lib.rs`, so the caller audit is a
  three-file argument rather than one function with one call site;
- and one field **could not be filled at all** without a decision outside the
  slice: a co-refutation verdict attributable to `SEC-FIDO-007` needed either a
  dedicated `Bug*` switch per invariant or a change to how `comutate.py`
  attributes a bug to an invariant. Naming that blocker was this counterpart's
  real deliverable, and the second option is the one taken — `comutate.solo_index`
  reads the invariant-named solo configurations, so the field is fillable and the
  prerequisite is spent rather than owed.

Estimate: **1.5× to 3× the human time of the strong row for the same contract**,
dominated by groups 7 and 8. The attribution decision was priced as a hard
prerequisite rather than a cost, and it stayed one — it was discharged before the
measurement rather than inside it. That range is an estimate and is labelled as
one; the whole point of the exercise is that only the measurement replaces it.

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
  446 passed and **172 failed** at `f52b720` on 2026-08-27, over the 619 tests the
  suite held that day, which is the run
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
