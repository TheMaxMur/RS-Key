<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# `formal/` — a TLA+ model of RS-Key's security state

## What this is, and what it is not

`RSKeySecurityState.tla` models **one thing**: the authenticator's *security
state machine* — PIN retries, the pinUvAuthToken and its permissions, rpId
binding, which transport owns the touch, which channel owns a stateful walk,
the reset window, the clientPIN soft lock, the persistent gate records
(`EF_PIN`, `EF_ALWAYS_UV`, `EF_PAUTHTOKEN`, `EF_BACKUP_SEALED`), and the
position at which power is lost inside a multi-write flash sequence. It models **none** of: CTAP 2.3 as a
protocol, CBOR or APDU encoding, the applets (PIV, OpenPGP, OATH, OTP),
cryptography, the flash layout, USB, or timing. A green TLC run says the six
named invariants hold **in this model, at these constant sizes** — it is
evidence about the state machine's shape, not a proof about the firmware
binary. Kani remains the tool that proves things about the actual Rust; this
model exists because Kani proves `∀x ∈ D_bounded : P(x)` over *one call*, and
RS-Key's dangerous defects have overwhelmingly lived in *sequences* of states.

**RS-Key is not formally verified.** The claim these two layers actually support
— what Kani proves and up to what bound, what a green TLC run does and does not
mean — is written out in
[`docs/testing.md` → "Formal claims"](../docs/testing.md), which is the
published copy and the one to quote. Do not paraphrase it upward from here.

The sentence that governs everything below: **a green TLC run is a result about
`RSKeySecurityState.tla`, not about the firmware binary**, and the model's
fidelity to the code is maintained by hand. The review that produced this
revision found a fidelity gap that had been holding the green run up (see
"Abstractions"), which is what that sentence is for.

## Running it

`tlaplus` is in the dev shell, which exports `TLA2TOOLS_JAR`; run everything
through `nix develop`. It used to be out of the flake, with the jar realized by
hand and named by a `/nix/store` path in `run-tlc.sh` — correct on one machine,
unreadable everywhere else, and the reason no workflow could run any of this.
The 208 MB people quote is the *closure*: the tool is 2.2 MB and the rest is the
JDK it wraps, which is the point — `java` used to come from the host PATH, so
the prover's runtime differed per contributor. The pinned jar is byte-identical
to the hand-realized one (sha256 `936a2620…`), so `floors.txt` still describes
the TLC that measured it.

```console
$ nix develop
$ ./gen-configs.sh            # regenerate every .cfg
$ ./run-tlc.sh safety         # the CI tier: model + mutants + floors, ~30 min
$ ./run-tlc.sh liveness       # the temporal properties — needs a 12g heap
$ ./run-tlc.sh all            # both, sequentially
$ ./run-tlc.sh Shipped.cfg    # one configuration; log lands in out/
$ python3 tla-lint.py         # the two source traps, standalone
```

The tiers are drawn by heap, not by taste, and their membership lives in
`run-tlc.sh` and nowhere else. `deep-checks.yml`'s weekly `formal` row runs
`safety`; `liveness` is not in CI because `Liveness.cfg` needs the 12g
`floors.txt` gives it, and 11.1 GB is where that workflow's `kani` `heavy`
runner has already died twice. The row also fires on any push touching
`formal/`, so a change to the model is checked at once rather than up to a week
later.

`run-tlc.sh` runs `tla-lint.py` first and refuses (exit 2) if it fails, and
checks every row against `floors.txt` — the verdict each configuration must
produce and, for the exhaustive ones, the minimum distinct-state count and the
heap it needs. A row that does not match exits 1. "What now catches a run nobody
watched" below is why both exist and how each was mutation-tested.

`run-tlc.sh` caps TLC at 2 workers on purpose — this tree is worked on by
several agents at once and a run that starves them is worse than a slow one.

## The six invariants → the Rust that owns each

The names are load-bearing. The same property name carries each available
evidence edge through Rust, Kani, stateful fuzz and device tests. The graph is
derived in "Traceability" below rather than inferred from this ownership table.
Phase 6 is the first vertical slice with all of those owners:
`ResetNeverWeakensSurvivingState` and its clauses now have bounded Kani,
power-cut fuzz and a real-power HIL harness. The HIL column records an owned
test, not a claim that a current board run passed.

Paths are relative to the repository root, because three of these basenames
match more than one file in the tree.

| Invariant | What it asserts here | The Rust construct that owns it |
|---|---|---|
| `NoAuthorizationBypass` | No protected operation completes without the live authorization its own gate requires | `crates/rsk-fido/src/`: `getassertion.rs:384-387` · `makecredential.rs:513-516` · `config.rs:243-245` · `credmgmt.rs:278` · retry ladder `clientpin.rs:723-808` · soft lock `state.rs:285-293` + `crates/rsk-device/src/ctap.rs:228-235` · reset window `reset.rs:182-188` · walk owner `state.rs:169-180`, `credmgmt.rs:339` |
| `NoCrossTransportTouchConsumption` | A presence decision produced for one transport is never applied to another — neither a confirm nor a cancel | `crates/rsk-device/src/presence.rs`: `Arbiter::pending_for` · `::request_cancel` / `::cancel_otp_wait` (the scope guards) · `ButtonWait::wait` (the `spent` latch). `firmware/src/presence.rs` keeps only the board half. **The stale-cancel drop that carries this property is the one at the wait's ENTRY.** The exit clear cannot substitute for it — a cancel latched by a dispatch that never entered `wait` is never seen by the exit — see "The cancel that no wait was open for" |
| `NoTokenAfterInvalidation` | A grant invalidated by a PIN change, PIN set, reset, `stopUsingPinUvAuthToken` or power cycle never authorizes again | `crates/rsk-fido/src/`: `state.rs:488-502` (`reset_pin_uv_auth_token`) · `state.rs:547-562` (`stop_using_token`) · `state.rs:596-609` (`expire_stale_token`) · `clientpin.rs:302-313` · `seed.rs:312-313` (`clear_ppuat`) |
| `NoAccessibleSecretWithoutGate` | No live secret is reachable while the gate record that protects it is gone | `crates/rsk-fido/src/`: `reset.rs:153-180` (`is_fido_gate_fid`) · `reset.rs:52-67` (phase order) · `credmgmt.rs:249-266` (`authorized_by_ppuat`) · `clientpin.rs:214-218`, `:824-828` |
| `NoUnmanageableCredential` | Every live credential is reachable by the management surface (its `EF_RP` entry exists) | `crates/rsk-fido/src/`: `credential.rs:805-827` (registration write order) · `credmgmt.rs:658-713` (`delete_credential` / `decrement_rp`) · `passkeys.rs:90-152` (`for_each_rp`, the `EF_RP` walk the display lists from) |
| `ResetNeverWeakensSurvivingState` | No prefix of an `authenticatorReset` — torn or complete — leaves a surviving usable secret whose gate has already gone, where "surviving" counts the RAM copy of the seed as well as the flash record | `crates/rsk-fido/src/`: `reset.rs:31-76` (`reset`, session then seed then two phases) · `reset.rs:58-61` (`ctx.state.reset()` ahead of every flash write) · `reset.rs:78-114` (`sweep`, and the `Err` at `:95-99` that leaves the device running) · `reset.rs:153-180` (`is_fido_gate_fid`, incl. `EF_BACKUP_SEALED`) · `reset.rs:234-242` (`survives_factory_reset`) · `crates/rsk-fido/src/lib.rs:104-108` (`Ctx::load_keydev`, the RAM copy that wins) · `state.rs:426-436` (`FidoState::reset`, what drops it). Shipped twin for its third clause: `reset_tests.rs::a_torn_reset_never_unseals_a_surviving_seed` |

### Two more that are not among the six, and three clauses that now have names

`ResetNeverWeakensSurvivingState` is a conjunction of three clauses, and
`Solo_*` names an **invariant, never a clause** — which mattered more than it
sounds. All four reset-family mutants reported that invariant and all four
traces were its third clause, so "27 of 27 caught by the invariant that names
it" was true while two thirds of one invariant had no owner at all. The clauses
are named now — `ResetKeepsThePinGate`, `ResetKeepsTheAlwaysUvGate`,
`ResetKeepsTheBackupSeal` — and "The clause nobody owned" below is the grid of
which mutant breaks which.

And two structural facts that are **not** requirements: each is a property of
the shipped tree that an argument elsewhere in the model rests on, and an
argument nothing checks is the shape that has cost this model most.

| Claim | What it says | Why it is asserted rather than argued |
|---|---|---|
| `RamNeverOutlivesFlashSeed` | `ram => store.seed` | It is *why* `SeedReachable`'s `ram` disjunct is inert. Measured once over 17 190 324 states, written down, then relied on — so the day it stopped being true would have been a discovery, not a red row |
| `NoLiveTokenWithoutPinRecord` | `tok.live => pin.set` | The sentence `ConfigGuard`'s justification is made of, and the same sentence that makes the alwaysUv-with-no-PIN conjunct on mc/ga inert. **Already refuted once**: modelling only the `keydev_dec` half of `ctx.state.reset()` left a live token outliving the deletion of `EF_PIN`, and the repair put the sentence back without checking it |

Both are on `Shipped.cfg` and deliberately **not** in `ALL_INV`: a mutant reports
the first invariant it violates, so a seventh in the 27 mutant configs would move
verdicts that are the record of which invariant names which defect. Each has its
own `Solo_*` run against `BugStateResetAfterWipe` — RED in 2 368 and 135 420.

Two of the six overlap by design and the overlap is stated rather than hidden:
`NoAccessibleSecretWithoutGate` is the **steady-state** claim on every path,
while `ResetNeverWeakensSurvivingState` is the **relational** one — it compares
the state a reset was handed against the state the reset produced, which the
steady-state form cannot see.

`EF_BACKUP_SEALED` is the one gate here that reads backwards: its **absence** is
the permissive state (`reset.rs:158-179`), so what a torn wipe can do is
*re-open* the one-time seed-export window over a seed it did not manage to
destroy. That is the audit run-36 class fix, and it is the third clause of
`ResetNeverWeakensSurvivingState`, not of the steady-state invariant — on a
fresh device the marker is absent and the seed is live, which is normal, so the
claim only means anything relative to a marker that existed.

The three flash-shaped invariants are asserted over **quiescent** states
(`Idle`) only. That is the strong reading, not a weakening: a multi-write
sequence is necessarily inconsistent between its writes, and what matters is
whether an inconsistency can *survive*. `PowerCut` leaves `op = NoOp`, so every
state a cut can strand the device in — and then serve requests from — is
quiescent.

### The `everSet` repair, and the trade it makes

`NoAccessibleSecretWithoutGate`'s state clause is

```
(store.cred # {} /\ store.seed /\ pin.everSet) => pin.set
```

and `pin.everSet` used to be a device-lifetime flag that only a *completed*
`ResetFinish` cleared. Once `PowerCut` modelled the firmware's boot-time
`ensure_seed` (see "Abstractions"), that became a false alarm in 18 states: a
torn reset leaves `everSet` set forever, so the clause blamed credentials the
owner created **afterwards**, on a key whose PIN they had themselves asked to
erase. Not a defect — a blunt ghost.

`everSet` now retires when the gate phase deletes `EF_PIN`, **but only over a
store the secrets phase has already emptied** (`PinRecordDeleted`). The
condition is the whole repair. Retiring unconditionally would also have matched
the words "retire when the gate phase completes", and it would have left the
clause **unfalsifiable by any reset-ordering defect at all** — delete `EF_PIN`
ahead of the secrets and the ghost would discharge itself on the way past. Read
it as an obligation: *this device holds secrets a PIN record is supposed to
gate.* Destroying the record with nothing left to gate discharges it; destroying
it with a secret still live **is** the violation, and it must not be able to
cancel its own alarm.

Measured both ways. With the condition, `BugResetGatesFirst` still falls solo on
this invariant in 454 454 states. Without it, that run comes back green.

## Can these invariants fail? — the mutation experiment

An invariant no bug can violate is the TLA+ analogue of a test that cannot
fail, and this project has been bitten by that class repeatedly. So every
invariant carries at least one mutant that must break it. Each `Bug*` switch
rebuilds a real RS-Key defect or removes a defence the tree currently has;
`Solo_*.cfg` checks **only** that mutant's own target invariant, so a mutant
caught by a sibling cannot be mistaken for one that names its own.

"Caught in" is the `Solo_*.cfg` run's distinct-state count — the run that
checks **only** the named invariant. **Read it as an order of magnitude, not a
figure**: a counterexample search halts at the first violation, so the count is
worker-scheduling dependent and moves between runs of the identical command
(`Solo_BugPanelCancelable` measured 184 at one worker, 223 and 228 at two, 256
at four, 153 at eight). The verdict and the invariant are the result; the count
says how deep TLC had to go to find it, roughly.

| Mutation switch | Removes | Target invariant | Caught in |
|---|---|---|---|
| `BugResetGatesFirst` | `reset.rs:68-69` phase order | `ResetNeverWeakensSurvivingState` | 2 352 states |
| `BugBackupSealedNotAGate` | `reset.rs:158-179` — `EF_BACKUP_SEALED` back in phase 1 (audit run-36) | `ResetNeverWeakensSurvivingState` | 2 347 states |
| `BugCredBeforeRp` | `credential.rs:808-827` write order | `NoUnmanageableCredential` | 820 states |
| `BugDeleteRpBeforeCred` | `credmgmt.rs:665-673` — `decrement_rp` ahead of the `EF_CRED` delete | `NoUnmanageableCredential` | 111 503 states |
| `BugTokenSurvivesPinChange` | `clientpin.rs:313` | `NoTokenAfterInvalidation` | 15 299 states |
| `BugSetPinKeepsPpuat` | `clientpin.rs:214-218` | `NoTokenAfterInvalidation` | 416 314 states |
| `BugChangePinKeepsPpuat` | `clientpin.rs:302-306` | `NoTokenAfterInvalidation` | 11 183 states |
| `BugStopUsingKeepsPerms` | `state.rs:552-553` zeroing perms | `NoTokenAfterInvalidation` | 1 404 states |
| `BugNoConsumeAfterUp` | `state.rs:523-535` (GHSA-wqjm-653g-hgw3) | `NoAuthorizationBypass` | 275 564 states |
| `BugUnscopedCancel` | `Arbiter::request_cancel`'s scope check | `NoCrossTransportTouchConsumption` | 127 states |
| `BugTouchNotSpent` | `ButtonWait::wait`'s `spent` latch | `NoCrossTransportTouchConsumption` | 5 717 states |
| `BugSoftLockLostOnWarmReset` | `ctap.rs:228-235` `PinLock` carry | `NoAuthorizationBypass` | 4 993 states |
| `BugWarmResetReopensWindow` | `reset.rs:187` `!warm_boot` | `NoAuthorizationBypass` | 126 states |
| `BugCmWalkIgnoresChannel` | `state.rs:173` channel equality | `NoAuthorizationBypass` | 1 242 states |
| `BugSeedDoesNotLead` | `reset.rs:62-66` / `fs.rs`'s `first` — the pre-0x08BF wipe | `NoUnmanageableCredential` | 55 765 states |
| `BugWrongPinKeepsToken` | `clientpin.rs:783` — the pre-E38 tree, a mismatch that keeps the token | `NoTokenAfterInvalidation` | 623 states |
| `BugConsumeKeepsMcGa` | `state.rs:527-533` — a §6.5.5.7 triad narrowed to the config permissions | `NoAuthorizationBypass` | 3 383 states |
| `BugNoDropStaleCancelAtEntry` | the wait-entry clear (`crates/rsk-device/src/presence.rs:195-196`) — the wait-entry cancel drop | `NoCrossTransportTouchConsumption` | 151 states |
| `BugStateResetAfterWipe` | `reset.rs:58-61` — `ctx.state.reset()` moved back behind the flash work, which is the regression E76's own review caught | `ResetNeverWeakensSurvivingState` | 38 880 states |
| `BugPanelCancelable` | the panel half of `request_cancel`'s scope test (`crates/rsk-device/src/presence.rs:118-122`) — E45's ruling | `NoCrossTransportTouchConsumption` | 230 states |
| `BugHostPreemptsLocalWait` | the button's owner, at **all four** `*Start` sites — the name is the case it was found on, a host command opening a wait over a live on-panel ceremony | `NoAuthorizationBypass` | 46 states |
| `BugLocalPinIgnoresBudget` | the pad honouring the exhausted `EF_PIN` counter (`crates/rsk-display/src/gates.rs:126-128`) | `NoAuthorizationBypass` | 10 370 states |
| `BugPpuatIsAGate` | `eab4b5c` — `EF_PAUTHTOKEN` back in the deferred phase, where a torn wipe strands a grant with no PIN | `NoAccessibleSecretWithoutGate` | 218 421 states |
| `BugPinWriteBeforeRevoke` | `clientpin.rs:214-218` / `:300-304` — the new verifier landing before the persistent grant is revoked, at both PIN flows | `NoTokenAfterInvalidation` | 5 296 states |
| `BugUnscopedOtpCancel` | `cancel_otp_wait`'s own scope test (`crates/rsk-device/src/presence.rs:126-137`) — the second writer of the same cancel flag | `NoCrossTransportTouchConsumption` | 237 states |
| `BugLocalPinKeepsToken` | `ends_host_token` (`crates/rsk-display/src/gates.rs:139-146`) — E66, the panel's PIN pad as a fourth door | `NoTokenAfterInvalidation` | 1 662 states |
| `BugSetPinOverExisting` | `clientpin.rs:185-187` — setPIN refusing to overwrite a live PIN | `NoAuthorizationBypass` | 741 states |

And the three that break a **liveness** property rather than an invariant. They
are a separate `LIVE_BUGS` list in `gen-configs.sh` on purpose: a wedge is a
perfectly safe state, so putting them in the table above would have meant three
mutants nothing catches.

| Mutation switch | Removes | Target property | Caught in |
|---|---|---|---|
| `BugAssertWedgesOnTimeout` | only a confirm completes a getAssertion | `EveryOpQuiesces` | 79 523 states |
| `BugWaitScopeNotCleared` | `worker.rs:528` `set_wait_scope(SCOPE_NONE)` | `EveryWaitReleases` | 76 446 states |
| `BugWalkNeverExpires` | `state.rs:620-626` `expire_stale_sequences` | `EveryWalkCloses` | 93 607 states |

**Two mutants need a companion, and that is a result.** `BugBackupSealedNotAGate`
rebuilds audit run-36's class — the backup marker swept ahead of the seed it
protects — and once the seed leads the wipe unconditionally (0x08BF) the window
it re-opens is over a seed that is already gone, so it is **not falsifiable on
its own any more**. `BugSetPinKeepsPpuat` went the same way under `eab4b5c`: with
the grant swept in phase 1 and `EF_PIN` in phase 2, and phase 2 unable to start
until phase 1 is empty, `~pin.set /\ gate.ppuat` is unreachable — so setPIN can
never meet a stranded grant to keep. That is not an inference: it is the same
fact `NoAccessibleSecretWithoutGate`'s new structural clause asserts, and the
clause is green on the whole reachable space. Measured from the other side too —
without its companion the mutant explored **40 459 667 distinct states without a
counterexample** before the run was stopped, against 639 550 with it.

Both carry their companion from a `companion_bug` table in `gen-configs.sh`. A
mutant that stops firing because a fix subsumed it is worth knowing; a mutant
that stops firing silently is the failure this file exists to avoid.

**28 of 28 mutants are caught, each by the invariant that names it**, and 3 of 3
liveness mutants by the property that names them, and the one fairness-shape
mutant by `OpAdvancesIsOneActivity`.
`NoAccessibleSecretWithoutGate` is the one invariant no switch names as its
target; `BugResetGatesFirst` breaks it too, and
`Solo_NoAccessibleSecretWithoutGate.cfg` shows that alone in 454 454 states.
The shipped tree breaks it as well — see finding 2.

### Co-refutation — generated phase-2 fidelity baseline

The model column is the RED `Mut_*.cfg` result above. The code column is the
same defect re-injected into production Rust by `scripts/comutate.py`; the table
is published only after a complete run and the merge gate rejects a stale
block. Later model modules have their own batches below — this is deliberately
the roadmap's original 28-row phase-2 denominator.

#### The direction it does not run in, and the first thing that came back

Co-refutation asks whether the code level catches what the model catches. It has
never asked the reverse — whether the model catches what the code level misses —
and that is the question the pair's fidelity actually turns on. The reverse pass
is mechanical: `cargo-mutants`' MISSED set (no unit test kills it), intersected
with the lines the model *itself cites*, is a list of code the model claims to
describe and nothing tests.

First batch, over the reassembler and the store (`ctaphid.rs`, `fs.rs`,
`powercut.rs`), ran 394 mutants for 88 MISSED, of which **12 sit on a line the model cites**. Triaged, they
split three ways, and the split is the point.

| | |
|---|---|
| **Equivalent, not a defect** | `ctaphid.rs:420` `\|` → `^` on `(f[5] << 8) \| f[6]` — disjoint bits, the two operators agree |
| **Fail-safe direction** | `ctaphid.rs:431` `>` → `>=` refuses an exactly-maximum message: stricter, so `NoBufferOverrun` still holds. `fs.rs:147` and `fs.rs:190` `\|=` → `&=` clear *decided* bits, which sends more reads to the reliable backend |
| **Model-blind** | the dynamic-file registry in `scan` (`fs.rs:195` and `fs.rs:198`, three mutants), `has_data`'s zero-length test (`fs.rs:250`), `factory_wipe`'s 64-key batch bound (`fs.rs:363`), the registry retain in `delete` (`fs.rs:447`), and **`meta_delete`'s fault guard (`fs.rs:583`)** |

The last one was worth the exercise on its own. `Fs::meta_add_reserve` refuses a
FAILED EF_META read and the model carries that as `BugMetaAddDropsOnFault`; its
sibling `Fs::meta_delete` has the identical guard at `fs.rs:585`, and **nothing
held it at either level**. No test killed it, and `MetaDelete` was modelled as an
unconditional single write with no read to fail. Worse than a lost delete: the
mutant caches EF_META as *absent*, and the next `meta_add` legitimately trusts
`known_absent` and rebuilds the blob from empty (`fs.rs:546`), so the records go
on the write **after** the defect. That is why it is `NoFalseMetaAbsent`,
SEC-STORE-004, a step recorder — once the cache has lied, the losing write is
correct code and no state predicate over `meta` can tell the two apart.

Closed at both levels in one pass: the model gains `metaAbsent`, the fault
disjunct and the invariant (`Store.cfg` 272 → 364 distinct, still GREEN and
exhaustive; `StoreMut_BugMetaDeleteDropsOnFault` RED in 57);
`a_faulted_ef_meta_read_never_caches_the_blob_as_absent` closes the Rust half,
proved by driving the real mutation — **exactly one test fails, and on the
assertion that names the defect** rather than its inverse.

The other five model-blind rows are closed as **test** gaps, not model gaps, and
the distinction is deliberate: the dynamic-file registry is the capacity budget's
bookkeeping and `factory_wipe`'s 64-key batching is a loop bound, neither of
which this module carries or should. Four tests own them —
`a_boot_scan_registers_every_dynamic_key_and_neither_shared_record` (three
mutations at once), `a_delete_frees_its_own_registration_and_no_other`,
`an_empty_record_is_not_data`, `a_factory_wipe_clears_more_keys_than_one_batch_holds` —
and each was proved by driving its real mutation, one at a time, with the whole
suite watched: six for six, exactly one failure each, always the intended test.

**One of those six came back SURVIVED on the first pass, and the test was mine.**
`retain(|f| f != fid)` inverted keeps exactly one entry too — just the wrong one
— so an assertion on `free_dynamic()`'s *count* held while the registry now
listed a deleted key and had dropped a live one. Re-writing the survivor is what
separates them: under the defect it is not registered, so the budget moves. The
count-only version would have shipped as a test that cannot fail, and only
driving the mutation said so.

#### Batch two, and the first measured answer to "what does the model buy"

The same pass over the other 23 property-tagged files — 4 357 mutants, 3 124
measured before the run was interrupted — returned **572 MISSED, of which 78 sit
on a line the model cites**. The whole 78 are not triaged; three were, chosen
because each maps onto an invariant this page already claims, and all three came
back the same way:

| Site | The defect | The model's own mutant |
|---|---|---|
| `crates/rsk-fs/src/lib.rs:46` | `request_rescrub` → `()`: the at-rest lap is never re-armed | `BugRekeyKeepsTheMarker`, RED on `MarkerNeverLies` |
| `crates/rsk-oath/src/lib.rs:1173` | `deselect` → `()`: the VALIDATE unlock outlives its selection | `BugSelectKeepsOtherApplet`, RED on `NoStatusOutsideItsSelection` |
| `crates/rsk-piv/src/lib.rs:391` | `deselect` → `()`: the verified PIN outlives its selection | the same |

That is **model-catches** three times: a defect the suite could not tell from
correct code, on a line carrying the property's own tag, which the model reddens.
It is the first quantitative thing this apparatus has said about its own worth,
and it is worth exactly three rows — not a claim about the other 75.

All three code halves are closed now, each proved by driving its real mutation
with the whole suite watched: `requesting_a_rescrub_clears_the_hardened_marker`,
`a_deselect_drops_the_validate_unlock`, `a_deselect_drops_the_pin_status`, one
failure each, always the intended test. Note what the first one means for M7's
recorded exclusion: co-refutation skips `RSKeyBootHardening` because `firmware/`
has no host tests, and that is still true — but `request_rescrub` lives in
`crates/rsk-fs`, is host-testable, and had no test. The exclusion was reasoned
about the module and quietly covered a crate it did not have to.

The completed sweep is 4 357 mutants, **716 MISSED, 98 on a cited line**. Eight
of the 98 are triaged so far, taken from the PIN and selection paths because
those are where a hole costs the most:

| Mutation | Verdict | Owned by |
|---|---|---|
| `crates/rsk-sdk/src/applet.rs:387` `==` → `!=` — the dispatcher's reselect decision | **model-catches**: `BugReselectResetsStatus` / `ReselectPreservesAccessStatus` | `reselect_is_true_only_for_the_applet_already_current` |
| `clientpin.rs:238` `+` → `*` — the padded-length bound | **model-blind, real** | `change_pin_over_protocol_one` |
| `clientpin.rs:327` `\|\|` → `&&` — the legacy token's argument check | **model-blind, real** | `the_legacy_get_pin_token_refuses_an_rp_id` |
| `clientpin.rs:388` `\|` → `^` on `PERM_MC \| PERM_GA` | equivalent — `0x01` and `0x02` are disjoint | — |
| `clientpin.rs:761` `&&` → `\|\|` — the kbase-migration fallback | equivalent by construction: the inner `ct_eq` cannot match in either case the widened guard admits | — |
| `clientpin.rs:238` `>` → `<` | conformance only — the `!=` two lines down still refuses; the status word moves from `PinPolicyViolation` to `InvalidParameter` | recorded |
| `clientpin.rs:242` `\|\|` → `&&` | survived; the consequence is not yet determined | **open** |

Two of those are real defects the suite could not see, and the second one names
a whole missing dimension rather than a line: **`PinProto::One` appears once in
`clientpin_tests.rs` against twenty-five uses of `Two`**, so every length rule in
`changePIN` was measured at `PADDED_PIN_LEN + 16` and never at `+ 0`. Written
`*` instead of `+`, that expression turns the over-long guard into "refuse every
changePIN" on protocol 1 — a complete denial of the command, invisible to a
suite that only speaks protocol 2. The legacy-token one is the same shape one
door over: `issue_token` is handed `req.rp_id` whatever the subcommand, so
relaxing the guard mints a **subCommand-5 token bound to an rp the caller
named**, which CTAP 2.1 §6.5.5.7 does not allow.

The dispatcher row is the third `model-catches`, and the cleanest: every fake
applet in `applet_tests.rs` took `_reselect` and ignored it, so the flag the
whole seam module is about was handed to nobody who looked.

#### The ninth row, and the column number that decided it

`crates/rsk-piv/src/lib.rs:1263` `&&` → `||` is the sharpest thing this pass has
produced. The PIV PIN gate ends in

```rust
if !matched && dev.otp_key.is_some() && ct_eq(&dev.without_otp().pin_derive_verifier(pin), stored)
```

and `&&` binds tighter than `||`, so relaxing the **second** one leaves
`(!matched && otp_key.is_some()) || ct_eq(..)`. On an OTP-provisioned device any
**wrong** PIN satisfies the left side, short-circuits past the comparison, and
falls into the migration body — which calls `put_pin_verifier` with the PIN just
offered and sets `matched = true`. Wrong PIN accepted, and stored as the new one.

Why no test saw it: the fallback is only reachable when `otp_key.is_some()`, and
every PIV test that offers a **wrong** PIN runs on a device without one. The one
test that does provision an OTP key only ever offers the correct PIN.
`a_wrong_pin_is_refused_on_the_kbase_fallback_path` closes it — proved by driving
the real mutation, one failure, the intended test.

**And the first attempt at that proof was a red for the wrong reason.** The
report reads `1217:9`; the *first* `&&` is `1216:9`. Mutating 1216 turns eighteen
existing tests red, which reads as "cargo-mutants was wrong about this being
MISSED" — it is not, they are different mutants one line apart. The column
number is what separated them, and nothing but re-reading the report would have.
The FIDO twin at `clientpin.rs:761` looks identical and is **not**: there the
`ct_eq` sits inside the block rather than in the condition, so a widened guard
still cannot write. Same shape, opposite verdict, and only reading both bodies
says which.

#### Seven more, and two of them the tree had already tested one applet over

| Mutation | Verdict | Owned by |
|---|---|---|
| `crates/rsk-fido/src/reset.rs:89` `<` → `<=` — `sweep`'s 64-key batch bound | test gap; the mutation indexes past `keys` | `a_reset_sweeps_more_secrets_than_one_batch_holds` |
| `crates/rsk-openpgp/src/pin.rs:208` `&&` → `\|\|`, and the same guard → `true` | test gap; a record too short to be `[len, fmt, verifier]`, or with a zeroed length, read as a verifier | `a_malformed_pw_record_is_reference_not_found_not_a_verifier` |
| `crates/rsk-openpgp/src/pin.rs:202` `<` → `<=` | fail-safe — a short `EF_PW_PRIV` makes a live reference answer `PIN_BLOCKED`; wrong, but in the refusing direction | recorded |
| `crates/rsk-openpgp/src/pin.rs:763` guard → `true` | effectively equivalent — an empty `EF_RC` yields `rc_len = 0`, and the `check_pin` below re-reads `EF_RC` and refuses on its own guard | recorded |
| `crates/rsk-fido/src/reset.rs:104` `>` → `>=` | conformance — the runaway valve trips one delete early | recorded |
| `crates/rsk-fido/src/reset.rs:104` `>` → `==` | **the valve stops guarding**: `deleted` rises a whole batch at a time and can step past the threshold without ever equalling it. Not drivable in a unit test at `RESET_MAX_DELETES = 4 × 256 + 15` | **open** |

Both closures are the tree's own rule about sweeping by class rather than by
site, and both were one applet away from being closed already. PIV has
`reset_sweeps_more_files_than_one_batch` for its reset; FIDO's `sweep` is the
same 64-key loop and had nothing. PIV has
`a_poisoned_reference_keeps_every_exit_it_had` for a zeroed PIN record; OpenPGP's
`check_pin` reads the same shape and had nothing. Neither gap needed a new idea
— only the question "who else does this".

#### Eight more, and the cardinality lesson one layer down

`decrement_rp` addresses its slot four times — read, delete, nickname-delete,
write-back — and **every one of them could have been `EF_RP - j`** with the
suite green. The match beside them, `m >= RP_PREFIX && hash == wanted`, could
have been `||` and matched on length alone. The reason is exactly what
`formal/scopes.txt` records one layer up: the tests ran at **cardinality one**,
where `EF_RP + 0` and `EF_RP - 0` are the same file and the only slot is always
the right one. Two relying parties in distinct slots, one of them carrying two
credentials so the write-back path is reached, and a planted nickname on each —
and four of the five fall. `for_each_rp`'s skip needed the other axis: a record
too short for its own header, and a zeroed count.

One row is left open and it is a decision, not a test. `for_each_rp` skips at
`n < RP_PREFIX`; widening that to `<=` survives, and the measurement says why —
a record of exactly `RP_PREFIX` bytes is **enumerated today**, because
`unseal_rp_id` falls through to its legacy cleartext domain and an empty tail
decodes as the empty string, so a header with no payload arrives as a relying
party whose `rp_id` is `""`. The mutation makes the code stricter, which is
arguably better; the tree has no opinion on that boundary, and a test pinning
either side would cement an accident rather than record a rule.

#### Nine more, and two of them are not gaps at all

Not every MISSED row is a hole, and this batch is where the other two verdicts
earn their place.

`SUPPORTED_CAPS` is `CAP_FIDO2 | CAP_U2F | CAP_OPENPGP | CAP_OATH | CAP_OTP |
CAP_PIV`, and five separate mutations turn one `|` into `^`. The capability bits
are `0x200`, `0x02`, `0x08`, `0x20`, `0x01` and `0x10` — disjoint powers of two,
so the two operators agree. **Equivalent, all five**, and reading the constants
is the whole proof.

`persist_dev_conf` refuses a merged configuration over `EF_DEV_CONF_MAX`, and
relaxing that `>` to `==` or `>=` survives. Measured rather than assumed: the
cap is `MIN_CONFIG_RES_CAP − CONFIG_TLV_FIXED` = 64 − 22 = **42 bytes**, and the
APDU layer refuses a blob of unknown tags outright — 32 bytes and 80 bytes both
come back `6A80` before `persist_dev_conf` is reached. The known writable set
cannot merge past 42. So the inner check is defence in depth against a shape the
current tag vocabulary cannot produce: **unreachable**, the same verdict
co-refutation records for a defect a shipped fix made impossible, not a test gap.

What is a gap is the CCID wrapper. `CcidApplets::factory_wipe` returns whether
the wipe completed, and its caller turns that into a reboot; replacing the whole
function with `true` OR with `false` left the suite green. Audit run-32 is what
the `true` direction costs — a wipe reporting a range clear it never enumerated,
with the trusted display painting "RS-Key erased" over live credentials.
`a_completed_factory_wipe_reports_true_and_leaves_nothing` pins the honest
direction. The other stays **open** and the reason is a fixture: `Env` is wired
to `RamStorage` and cannot fail, so the wrapper's laundering of a refusal has
nowhere to be observed. The layer below is covered
(`rsk-fs::factory_wipe_fails_on_a_truncated_enumeration`); this is the one seam
between them, and closing it means making `Env` generic over its backend.

Two size-arithmetic rows in `rsk-devconf` (`CONFIG_TLV_FIXED`, and the room
computation in `config_tlv`) survive because no test is tight against the
response buffer's edge. Recorded, untriaged.

#### The OTP slot's flag merge, and an asymmetry inside one test

`SLOT_UPDATE` merges three flag bytes, each under its own update mask, and the
existing `update_merges_flag_masks_only` pins two of them — through `status-ext`,
which carries `tkt` and `cfg` and **no ext byte at all**. So the third merge was
observable nowhere, and both of its mutations survived: `stored & !MASK` losing
its `!`, and the `|` that folds in the update becoming `&`.

`EXTFLAG_UPDATE_MASK` is `0xFF` — every extended-flag bit is updateable, so the
shipped semantics is *replacement*, not merging. Reading the stored record
directly (`tests.rs` is a `#[path]` child module, so the applet's own
`read_slot_m` is in reach) and asserting the byte stands alone kills both.

`rsk-otp` is fully triaged now — all 25 of its rows on cited lines. **20 killed**
by four tests, **3 equivalent**, **2 unviable** (they do not compile, which is
the verdict `cargo-mutants` gives them too). The eight that closed together are
UPDATE's own validation: the slot bound, the length floor, both RFU bytes, the
CRC and the `base + p2` that decides which slot is addressed at all. Every one
of those rules is already pinned on the CONFIGURE path by
`configure_validates_crc_and_rfu`, and UPDATE repeats all of them and had none —
**the third time in this pass that a rule was tested one door over and not
here.**

The three equivalents are worth their own line, because they look like the
dangerous kind. `merged[X] = (stored[X] & !MASK) | (data[X] & MASK)` folds two
operands that live on **complementary bit sets**, so `|` and `^` cannot
disagree; the mutation is real, the behaviour is not. All three of the crate's
`| → ^` rows are that shape, and the three `delete !` rows beside them — which
break the complement and therefore the disjointness — all fall.

One more from the same crate, and it is the conjunction rather than the mask:
`cfg & CFG_CHAL_YUBICO != 0 && tkt & TKT_CHAL_RESP != 0` is what makes a
challenge-response slot type nothing on a press. Relaxed to `||` it silences a
slot carrying only one of the two bits — a press that should have produced an
OTP produces nothing. No slot in the suite carried one bit alone, so the
conjunction was free. Two slots, one bit each, close it.

#### The panel's key grids, and a date helper nobody could reach

Two more crates close together, and both were held by the same absence: a test
that walks a **grid** rather than a case.

`rsk-ui`'s thirteen rows are the touch hit-test — the loop bounds in `hit_pin`
and `hit_rename`, both `+` inside `t9_key_rect`, the centring arithmetic in
`T9_LEFT`, and `hit_del_hold` replaced outright. Nine fall to one test; four do
not compile, which is the verdict `cargo-mutants` gives them too.

The trap that test had to avoid is worth stating, because the obvious version of
it cannot fail. Asserting that a key's own centre hits that key is **self-
consistent under a wrong formula**: change `origin + i * (size + gap)` and the
computed centre moves with it, so the assertion holds over a broken grid. The
properties that do bite come from outside the formula — every key lies inside
the panel, columns advance left to right by exactly one gap, rows likewise, the
T9 block is centred on the panel — and, for the loop bounds, a tap **past the
last row and past the last column**. The first version had only the row probe,
and both column bounds survived it.

`rsk-rescue`'s `days_from_civil` is Hinnant's algorithm, and four of its
operators were free: the `m > 2` that picks the March-based month shift, the
`+ 2` in the day-of-year numerator, and the `− yoe / 100` that IS the Gregorian
century rule. That last one only differs once the year-of-era reaches 100, so a
table of recent dates cannot see it; 1900 and 2100 are in the table for exactly
that reason, alongside two February 29ths for the month branch.

#### The last nineteen, and a cap that stopped being a cap

The rows left at the end are `rsk-devconf`'s size arithmetic, and every one of them
survives. That is the answer, not a gap in it.

Five are equivalent by inspection: `SUPPORTED_CAPS` folds six capability bits
that are disjoint powers of two, so `|` and `^` cannot disagree. The other
fourteen mutate `CONFIG_TLV_FIXED`, from which `EF_DEV_CONF_MAX` is derived, and
each was driven and measured — `*` binds tighter than `+`, so a mutation
multiplies its two adjacent operands rather than re-associating the sum, and the
cap lands somewhere in **28..46** instead of 42. Every one of those is above 24,
which is the widest record the writer's own validator will accept: since
`well_formed_writable` grew a per-tag width table (audit run-34 #25), the widths
sum to 4+4+4+3+4+3+2. The cap is documented as making the writer and the smallest
transport meet exactly. It has not bound anything for two audits.

The test that appeared to hold it is the more useful finding.
`read_config_body_fits_the_smallest_transport_buffer` builds its blob **from
`EF_DEV_CONF_MAX`**, so both sides of the comparison move together and the only
thing it can observe is that the cap equals itself — and its single over-wide
entry fails the read gate, which routes the read to the synthesised fallback
instead of the echo path the test names. Its two assertions, non-empty and
self-consistent, are both satisfied by a response whose echo was **dropped
entirely**, which is the audit run-33 wedge itself.

The replacement scans `writable_tag` over `0..=255` and takes each width from
`max_value_len`, so the record widens with the tag set rather than ageing beside
it; a writable tag with no width bound fails the test outright, because that is
the one change that makes the cap binding again. Driven against
`MIN_CONFIG_RES_CAP` 64 → 44 it reports `cap 22 is below the 24-byte record the
validator accepts`; against a widened `TAG_DEVICE_FLAGS` it reports the same
inequality from the other side. Neither number can drift into the other without
a red row now, and the constant's own comment says what actually binds.

#### Three boundaries nothing had crossed

The remaining singles are one shape each, and none of them is arithmetic.

`rsk-rescue`'s `fs_usage` sums the first 512 files and counts them all. No test
had ever put more than two files in the store, so relaxing `<` to `<=` — a write
to `fids[512]` on the 513th file — survived. The window is a named constant now,
and the test crosses it by exactly one file and asserts both halves of the
contract: the count stays exact past the window, the sum stops at it. Driven, the
mutant reports `index out of bounds: the len is 512 but the index is 512`.

`rsk-fido`'s `process_cbor` carries two rosters over the same commands — the
canonical-form gate and the dispatch match — and nothing tied them together.
Every vendor test calls `vendor()` directly, and the gate's own row for `0x41`
sends a malformed body, which is refused before the match is reached; so deleting
the `CTAP_VENDOR` arm left 579 tests green while the command answered
INVALID_COMMAND, the status a YubiKey keeps for a command it does not implement.
Driving all seven arms shows the shape exactly: the other six are killed by 5 to
44 tests each, `CTAP_VENDOR` by one, and that one is new.

`rsk-display`'s `ceremony_begin` drops a cancel an earlier wait left behind and
returns the LED status the exit restores. `Board::cancel_in` exists *because* of
the first half — its comment states the rule — and nothing ever read it back.
Three of four mutations fall to one test, including the whole-body replacement;
the fourth, dropping the touch LED during a synchronous wait, is not observable
from outside and stays open as such. Worth noting where the model already stood:
`NoCrossTransportTouchConsumption` holds this rule, and co-mutant 11
`BugNoDropStaleCancelAtEntry` is **co-refuted** — but it patches
`rsk-device/src/presence.rs`, the BOOTSEL wait. The display ceremony is a second
implementation of the same rule, and it was held by nothing at either level. That
is the third time in this pass that a rule already tested one door over was
missing here.

`Drop for FidoState` is closed as **not falsifiable by a host unit test**. The
impl zeroizes four secret fields, and observing that from inside the language
means reading a value whose destructor has run — which Miri, a weekly gate row,
would report as the defect. The risk it actually carries is a *new* secret field
added without a scrub line, and that is a compile-time question, not a test one:
`drop` now destructures `self` with a pattern that names all eighteen fields and
no `..`, each non-secret one bound to `_` beside the reason it is not one. Adding
a nineteenth field stops the crate compiling — driven, and the compiler answers
`error[E0027]: pattern does not mention field`, pointing at `drop` itself.

<!-- phase2-comutants:start -->
<!-- Generated by scripts/comutate.py run --write-readme; do not edit. -->
| # | Mutant | Target invariant | Model | Code level |
|---:|---|---|---|---|
| 1 | `BugBackupSealedNotAGate` | `ResetNeverWeakensSurvivingState` | RED | **unreachable** |
| 2 | `BugChangePinKeepsPpuat` | `NoTokenAfterInvalidation` | RED | **co-refuted** |
| 3 | `BugCmWalkIgnoresChannel` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 4 | `BugConsumeKeepsMcGa` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 5 | `BugCredBeforeRp` | `NoUnmanageableCredential` | RED | **co-refuted** |
| 6 | `BugDeleteRpBeforeCred` | `NoUnmanageableCredential` | RED | **co-refuted** |
| 7 | `BugHostPreemptsLocalWait` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 8 | `BugLocalPinIgnoresBudget` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 9 | `BugLocalPinKeepsToken` | `NoTokenAfterInvalidation` | RED | **co-refuted** |
| 10 | `BugNoConsumeAfterUp` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 11 | `BugNoDropStaleCancelAtEntry` | `NoCrossTransportTouchConsumption` | RED | **co-refuted** |
| 12 | `BugNoTouchRequired` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 13 | `BugPanelCancelable` | `NoCrossTransportTouchConsumption` | RED | **co-refuted** |
| 14 | `BugPinWriteBeforeRevoke` | `NoTokenAfterInvalidation` | RED | **co-refuted** |
| 15 | `BugPpuatIsAGate` | `NoAccessibleSecretWithoutGate` | RED | **co-refuted** |
| 16 | `BugResetGatesFirst` | `ResetNeverWeakensSurvivingState` | RED | **co-refuted** |
| 17 | `BugSeedDoesNotLead` | `NoUnmanageableCredential` | RED | **co-refuted** |
| 18 | `BugSetPinKeepsPpuat` | `NoTokenAfterInvalidation` | RED | **unreachable** |
| 19 | `BugSetPinOverExisting` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 20 | `BugSoftLockLostOnWarmReset` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 21 | `BugStateResetAfterWipe` | `ResetNeverWeakensSurvivingState` | RED | **co-refuted** |
| 22 | `BugStopUsingKeepsPerms` | `NoTokenAfterInvalidation` | RED | **co-refuted** |
| 23 | `BugTokenSurvivesPinChange` | `NoTokenAfterInvalidation` | RED | **co-refuted** |
| 24 | `BugTouchNotSpent` | `NoCrossTransportTouchConsumption` | RED | **co-refuted** |
| 25 | `BugUnscopedCancel` | `NoCrossTransportTouchConsumption` | RED | **co-refuted** |
| 26 | `BugUnscopedOtpCancel` | `NoCrossTransportTouchConsumption` | RED | **co-refuted** |
| 27 | `BugWarmResetReopensWindow` | `NoAuthorizationBypass` | RED | **co-refuted** |
| 28 | `BugWrongPinKeepsToken` | `NoTokenAfterInvalidation` | RED | **co-refuted** |

**Measured phase-2 fidelity:** 26/28 code-level kills; 2 unreachable by construction; 0 open gaps; 0 pending.
<!-- phase2-comutants:end -->

That last one is not a formality. `NoAccessibleSecretWithoutGate` was repaired
in an earlier revision (`pin.everSet` now retires when the gate phase deletes
`EF_PIN` over an already-emptied store — see "The `everSet` repair"), and a
loosened invariant that stops crying wolf can just as easily stop catching real
defects. The solo run is the measurement that says it did not: **454 454 states,
still red, on the same mutant as before the repair.**

One mutant was **not** caught on the first attempt, and that mattered more than
the eleven that were. `BugStopUsingKeepsPerms` ran green over 6 275 376 distinct states
because the model gave every call site one uniform guard including "the token
is in use". The code does not: `getassertion.rs:385` and `makecredential.rs:516`
test `user_verified()`, but `config.rs:243-245` and `credmgmt.rs:278` test the
MAC and the permission bits **only**. For those two the single thing standing
between a stopped or expired token and a live authorization is that
`stop_using_token` also zeroes `permissions` — `verify_token` is a MAC over
bytes that stay put and keeps succeeding. Splitting the guard in two
(`TokenGuardUv` / `TokenGuardBare`) made the mutant fall in 840 states. A model
that flatters the code proves nothing about it.

## The `viol` ghost, and the three holes an audit found in it

Three of the six invariants and half of a fourth are `"Name" \notin viol` — a
ghost set the actions themselves write into. Such an invariant is only as strong
as the completeness of those writers, and **the mutation experiment above
structurally cannot find a writer that is missing**: it tests the assignments
that exist. Every action in `Next` was therefore read against every invariant,
and each hole below is proved by taking its repair back out and watching the
mutant that should catch it come back green.

Where a property can be read out of the STATE it now is, because a structural
clause needs no cooperation from any action. Six of the pre-existing mutants no
longer depend on the ghost at all: `(upSpent /\ tok.live) => tok.perms = {}`,
`(lock.policyMism >= MismatchLimit) => lock.soft`,
`~(plat.held /\ plat.revoked /\ tok.perms # {})`,
`~(gate.ppuat /\ gate.ppuatStale)` and
`(pres.granted = "cancel") => (pres.cancelBy = pres.scope)`. What stays a ghost
is named as such in the model's comments, with its writers enumerated: the rpId
binding and the confirm half of the touch rule leave no bad *state*, only a bad
*step*, and `NoAccessibleSecretWithoutGate`'s `pcmr` clause stays deliberately —
the structural form would call the shipped fix a defect, because that fix refuses
the record rather than preventing it.

### The cancel that no wait was open for

`HostCancel` required an open wait, so the model could not raise a
`CTAPHID_CANCEL` at any other moment. The firmware can, and it matters:
`set_wait_scope` is called around the whole **dispatch** (`worker.rs:434`,
`:521`), not around the touch wait, so `Arbiter::request_cancel` (`crates/rsk-device/src/presence.rs:118-122`)
accepts a cancel during a FIDO command that never opens one — getInfo, a
capability-denied CBOR, a silent `up:false`. **Nothing clears
`CANCEL_REQUESTED` when that dispatch ends**, and the next dispatch may be CCID
or OTP, where every applet's presence goes through the same
`ButtonPresence::wait` reading the same global.

the wait-entry clear (`crates/rsk-device/src/presence.rs:195-196`) eats it at wait entry, and that is the whole defence.
`:230` cannot help, because the dispatch that took the cancel never entered
`wait`. `HostCancelLatched` models the latch and `BugNoDropStaleCancelAtEntry`
removes the drop: **RED in 127 distinct states at depth 5**, the trace being a
CTAPHID cancel ending a CCID ceremony. Without the action the same mutant is
**GREEN over 6 580 784 states** — which is how "either owner alone carries the
property" came to be written here, and it is wrong.

### And a fourth the review found, which was not a missing writer at all

`RegisterTouched` and `AssertFinish` had `pres.granted = "confirm"` as an
enabling conjunct, not as a Guard with a Policy. A step that is merely never
*enabled* without a confirm cannot notice a build that stopped requiring one:
the review removed the presence gate from makeCredential **and** getAssertion at
once — a credential written to flash and an assertion served with no touch at
all — and every invariant stayed **GREEN over 9 658 460 states**. On a key with
no PIN and no `alwaysUv` the touch is the only authorization there is, which is
exactly what `NoAuthorizationBypass` claims to cover. `TouchGuard` /
`TouchPolicy` fix it and `BugNoTouchRequired` catches it in 121 states at
depth 5.

Worth stating plainly, because it is the point of the exercise: the audit above
read every action against every invariant and still missed this one. It was
looking for a `viol` writer that should exist and does not; this was a gate with
no writer at all, and it took an independent reviewer whose only job was to break
things.

### And the next reviewer found two more of exactly the same shape

The repair above fixed the two call sites it was found on and **left the class
open at two others**, which is the more useful result: the lesson did not
generalise by itself.

- **`authenticatorReset`'s touch.** `ResetConfirmed` had `pres.granted =
  "confirm"` as an enabling conjunct with no Policy, long after `TouchGuard` /
  `TouchPolicy` had been written for exactly this. Removing the presence gate
  from the wipe left every invariant **GREEN over 17 911 536 states** — a factory
  reset served with no touch at all. `ResetConfirmed` carries the same pair now;
  with makeCredential and getAssertion lifted out of `Next` so they cannot mask
  it, `BugNoTouchRequired` is **RED through the reset alone in 254 states**, on a
  trace whose middle step is `TouchTimeout`.
- **setPIN over an existing PIN.** `clientpin.rs:185-187` is the only thing
  standing between a stranger with physical access and their own clientPIN —
  changePIN spends a retry and verifies the old one, setPIN does not. It was
  `~pin.set`, an enabling conjunct, and removing it left everything **GREEN over
  21 393 948 states** while a token minted under the new PIN read the credential
  directory. `SetPinGuard` / `SetPinPolicy` and `BugSetPinOverExisting` close it
  in 741.

Two other things that review measured are corrections rather than defects, and
they belong here because they change what this page may claim:

- **`SeedReachable`'s `ram` disjunct is inert, and the three clauses restated in
  terms of it are inert with it.** `ram => store.seed` holds over **all 17 190 324
  states** of the tree as it stood when that was measured, because `DeviceUnlock`
  needs a live flash seed and `ResetConfirmed` drops the RAM copy before the
  flash one goes. Dropping the disjunct leaves the state set *identical* and
  flips no verdict. So the credit for closing E110 belongs to `KeepSurv`'s
  `reach` argument — which is what carries `snap.seed` past the flash delete on
  the mutant tree — together with `ResetAborts` and `DeviceUnlock`, and **not**
  to the restatement. The restatement stays because it is the faithful reading of
  `Ctx::load_keydev`, not because it does work. **And the reason it is inert is
  asserted now** rather than measured once: `RamNeverOutlivesFlashSeed` is
  `ram => store.seed`, GREEN on the whole reachable space and RED under
  `BugStateResetAfterWipe` in 2 368 states. That is the honest resolution of
  "make it bite or drop it" — nothing available makes it bite on the shipped
  tree, because `DeviceUnlock` needs a live flash seed and `ResetConfirmed` drops
  the RAM copy first, and those two facts are exactly what the invariant pins.
  What would make it bite is the second reset path (`Fs::factory_wipe`, still
  unmodelled) if its reboot were ever separated from the wipe; on the day that
  happens this row goes red and says so, instead of the disjunct quietly starting
  to do work nobody asked it to.
- **Two of the three `ram' = FALSE` assignments are dead.** `ResetFinish`'s can
  never differ (the RAM copy is already gone by step 3) and `VolatileCleared`'s
  is unobservable while `DeviceUnlock` is ungated. Both, removed, give back the
  *identical* state graph. They are kept as statements of what the code does.

### The clause nobody owned

`Solo_*` names an **invariant**, never a clause, and that was recorded as a
limitation of the convention rather than measured. Measured now: every
reset-family mutant against every clause of
`ResetNeverWeakensSurvivingState`, one clause per configuration, at the liveness
constants.

| | `BugResetGatesFirst` | `BugBackupSealedNotAGate` | `BugStateResetAfterWipe` | `BugSeedDoesNotLead` |
|---|---|---|---|---|
| `ResetKeepsThePinGate` | **RED** 496 352, depth 16 | green 10 370 540 | green 12 512 574 | green 9 283 984 |
| `ResetKeepsTheAlwaysUvGate` | **RED** 996 729, depth 18 | green | green | green |
| `ResetKeepsTheBackupSeal` | **RED** 4 345, depth 8 | **RED** 4 314, depth 8 | **RED** 49 866, depth 11 | green |

The previous round's guess was exactly right, and the reason is in the depth
column: clause 3 falls at **depth 8** where clauses 1 and 2 need **16 and 18**,
so the search reached it first and reported it, every time, for all four
mutants. Two thirds of an invariant had **one** owner between them and the
apparatus could not say so — "caught by the invariant that names it" was true
and told you nothing about which clause was carrying the claim.

`SoloClause_*.cfg` names one clause and one mutant, and all three clauses have an
owner: RED in 983 327, 2 248 941 and 5 895 at the full constants.
`BugSeedDoesNotLead` owns none of them, which is correct — its target is
`NoUnmanageableCredential`.

### And a third round swept every action, and found two more

Three separate readers had now found the same defect five times in one session,
in a file whose own README explains it. So the question stopped being "are those
fixed" and became **"can another one be written"**. Every conjunct in both
modules was classified — Guard-with-a-Policy, structural, sequencing, or bare —
and every bare one was removed and measured. Two were real, and an independent
reviewer briefed only on the history found the same two.

- **`PgpSetPwStatus`'s `held["pw3"]`.** PUT DATA `0xC4` is the only writer of the
  status byte that makes PW1.81 valid for exactly one PSO:CDS, and it is an
  administrative write gated on PW3 (`crates/rsk-openpgp/src/putdata.rs:181-183`,
  behind the ACL at `:59-65`). The gate was one conjunct and nothing else.
  Removed, the reachable space is **bit-identical at 666 distinct states** —
  while anyone who can select the applet clears the one-shot flag and then signs
  for ever on a single PW1 VERIFY. That is `BugSigPinNotSpent`'s requirement
  taken from underneath rather than through the door it watches.
  `PwStatusGuard` / `PwStatusPolicy` close it; `BugPwStatusIgnoresAdmin` falls in
  49.

  **And it is the sharper of the two, for a reason worth naming.**
  `PgpKeyOpPolicy` is conditioned on `oneShotSig` — `held[r] /\ (r = "pw1" /\
  oneShotSig => psig)` — and `PgpSetPwStatus` is that variable's *only* writer.
  An ungated write of `oneShotSig := FALSE` therefore does not **violate** the
  Policy, it **rewrites** it. No `viol` can fire and no state count can move,
  by construction. A Policy whose own premise is attacker-writable is
  unfalsifiable no matter how many mutants are aimed at it, and the only repair
  is to gate the write.
- **`LocalCeremonyStart`'s `pres.scope = NoOwner`.** `ButtonFreeGuard` /
  `ButtonFreePolicy` were written for exactly this rule when the previous round's
  reviewer showed that dropping it from `RegisterStart` / `AssertStart` /
  `ResetStart` produced zero new states. The **fourth** site kept the raw
  conjunct. Removed, the reachable space is **bit-identical at 61 215 504
  distinct states** with ~39.7 M extra transitions — an OTP frame taking the
  button from a live on-panel flow and back, invisible for the same reason as the
  host half: `OpenWaitFor` overwrites `scope`, `cancelReq`, `cancelBy` and
  `granted`, so nothing is left to record who held it first.

Both are the *same* repair, at sites the previous two repairs did not reach.
That is now three rounds running in which the lesson did not generalise by being
written down, and the thing that found it every time was a reviewer whose only
job was to remove a gate and watch the run stay green.

**One conjunct was measured and is NOT a hole**, which is worth as much:
`~(gate.alwaysUv /\ ~pin.set)` on `RegisterStart` and `AssertStart`. Removed from
both, the reachable space is bit-identical **and the transition count is
unchanged** — it disables nothing at all, because `tok.live => pin.set` and
`OpGuard` therefore already implies the PIN whenever `UvRequired`. It stays,
because the Rust has it; what changed is that the fact subsuming it is
`NoLiveTokenWithoutPinRecord` now rather than a sentence. It is also what taught
the method the *generated*-column rule above.

And a third, found by the reviewer rather than by the sweep, because it is not a
conjunct at all: **the two PIN flows' revoke-before-write order was `op.step`
numbers and nothing else.** `clientpin.rs:214-218` and `:300-304` revoke the
persistent grant before the new verifier lands; swap the two writes and every
invariant stayed GREEN over 55 425 408 states. It is worse than a plain torn
window — with the *new* PIN in place, `NoAccessibleSecretWithoutGate`'s
structural clause `gate.ppuat => pin.set` is satisfied (*a* PIN is set, just not
the one that bought the grant) and `FixPpuatRequiresPin`'s consumer check agrees,
so `CmBeginViaPpuat` serves the old holder and nothing records it.
`PinVerifierLandsPolicy` is `~gate.ppuat` at the moment the verifier lands, at
both flows, and `BugPinWriteBeforeRevoke` falls in 5 296.

The setPIN twin cannot fall on its own, for the reason `BugSetPinKeepsPpuat`
needs a companion: `~pin.set /\ gate.ppuat` has been unreachable since the grant
moved to phase 1. The changePIN half is what makes the mutant fire; both sites
carry the rule because the Rust does.

### And a trap that was scanned for by hand and survived the scan

`CardReset` assigned `psig' = FALSE` in its `ELSE` branch while the action's own
trailing `UNCHANGED` also named `psig`. The conjunction is simply false unless
the new value equals the old, so the action was **disabled in every state where
PW1 stood verified under the one-shot status** — a card reset from that state was
not modelled at all, and the mutant `BugCardResetKeepsStatus` was enabled where
the shipped tree was not.

The previous round found this exact trap at `PgpSetPwStatus`, ran a hand scan for
it, and reported *"the four other hits in both modules are legitimate IF-branch
pairs"*. Four of the five were. Three independent measurements say this one was
not: an `ENABLED CardReset` probe RED at depth 4, TLC's own `-coverage` reporting
`CardReset` firing from **330 of 666** states against 666 for each of its
siblings, and 666 − 330 = **336**, exactly the transition delta the repair adds.

A hand scan is not a guard. `tla-lint.py` is.

### The other two holes

`upSpent` — a user-presence test has been spent — had exactly **one** reader,
`ConfigPolicy`, so the model saw CTAP 2.1 §6.5.5.7 only through the advisory
that named authenticatorConfig. `BugConsumeKeepsMcGa` is the narrow fix somebody
could have written instead, and a second assertion then rides the touch the
first one collected: **GREEN over 9 087 628 states** before the structural
clause, RED in 4 823 after.

And four sibling call sites disagreed about which name they wrote —
makeCredential and getAssertion both, authenticatorConfig only
`NoAuthorizationBypass`, the two credentialManagement sites only
`NoTokenAfterInvalidation` — so a `Solo_*` run coming back green meant either
"not violated" or "violated under the other name". One `TokenBypass` recorder
serves all four now. Measured with `ConfigOp` lifted out of `Next` so it cannot
mask the pair: **GREEN over 11 088 688 states** with the old recorders, RED in
1 489 with the shared one.

## Findings on the tree as it stands — both are FIXED

`Shipped.cfg` is **green**. The two findings below were produced by this model
and closed in `a430f2d` (0x08BF) and `32b9fa3` (0x08C0); each is kept as a
`Historical_*.cfg` — the tree with exactly that fix taken back out — so the
counterexample stays reproducible and the fix stays demonstrably load-bearing.


`Shipped.cfg` (every switch off) is **RED**, and that is the result, not a
broken model. Both findings are one class: **the two-phase wipe controls the
order *between* phases but nothing controls the order *within* a phase.**
`sweep` batches whatever `for_each_key` yields, and `fs.rs:253-256` documents
that walk as log-structured *store* order, not FID order; each `force_delete`
is its own flash write, so a power cut can land between any two of them.

Both are reachable independently — `Shipped_OnlyFinding1.cfg` and
`Shipped_OnlyFinding2.cfg` each disable the other's proposed fix.

### Finding 1 — a torn phase 1 can strand an unmanageable credential

`NoUnmanageableCredential`, 72 128 distinct states, depth 13. Register a credential;
start `authenticatorReset`; the touch lands; phase 1 deletes the `EF_RP` entry
first; power is cut. The device reboots with `EF_CRED` live, `EF_RP` gone and
the seed still present — a usable discoverable passkey that `enumerateRPs` and
the trusted-display Passkeys view cannot list (both walk `EF_RP`) and that
`enumerateCredentials` therefore cannot reach to delete, while `getAssertion`
(which scans `EF_CRED`) authenticates with it happily. That is precisely the
state `credential.rs:829-836` orders registration to avoid and that audit
run-35 recorded as one that "never self-heals" — reached here from the *other*
direction, the wipe rather than the write.

Severity **LOW**: it needs a power cut inside a touch-gated factory reset, it
discloses nothing, and re-running the reset clears it (`EF_CRED` is in the
phase-1 predicate). Modelled fix `FixSweepDropsCredsBeforeRpEntries`: order
phase 1 so no `EF_RP` entry is dropped while a credential is live. **Not the fix
that shipped** — see the status section below.

### Finding 2 — a torn phase 2 can strand a persistent grant on a PIN-less key

`NoAccessibleSecretWithoutGate`, 102 523 distinct states, depth 14. Set a PIN, take a
`pcmr` grant (`EF_PAUTHTOKEN`), start a reset; phase 2 deletes `EF_PIN` and
power is cut before `EF_PAUTHTOKEN`. `authorize_cm` consults the persistent
grant **first** and returns `Ok` with no PIN check at all
(`credmgmt.rs:240-242`), so the old grant holder can still drive
`getCredsMetadata` / `enumerateRPsBegin` / `enumerateCredsBegin` against
whatever the owner registers next. The "registers next" half needs a seed, and
before `BootEnsuresSeed` the model could not reach it — the finding was real but
**understated** by the abstraction the review caught.

`clientpin.rs:214-218` already names this exact torn state — but the defence it
installs (`clear_ppuat` on set-PIN) only closes the exit where the user
establishes a PIN again. The exit where the user simply carries on with a
PIN-less, touch-only key is open. `deleteCredential` and
`updateUserInformation` are **not** affected: they call `verify_cm_token`
directly rather than `authorize_cm`, so the grant does not authorize writes.

Severity **LOW**: it needs a prior `pcmr` grant, a power cut at a specific
point, and the user never re-setting a PIN; the exposure is the credential
directory (rp ids, credential ids, user names), not keys or assertions.
Modelled fix `FixPpuatRequiresPin`: refuse a persistent grant when `EF_PIN` is
absent — one owner, one line, at `authorized_by_ppuat`. **This is the fix that
shipped**, verbatim.

### Both are fixed in the tree now — one of them differently

Landed after this model was written: **Finding 2** at bcdDevice `0x08C0`, by exactly
the modelled `FixPpuatRequiresPin` — `authorized_by_ppuat` refuses when `EF_PIN` is
absent. **Finding 1** at `0x08BF`, but *not* by `FixSweepDropsCredsBeforeRpEntries`:
the maintainer's fix deletes the seed (`EF_KEY_DEV`, and `EF_KEY_DEV_ENC` for a
soft-locked device) in its own write ahead of both sweep phases, so the strand still
happens and the survivor no longer decrypts. `Fs::factory_wipe` took the same lead
phase in the same commit.

**Both have been re-run, and both counterexamples are gone.** `Shipped.cfg` — the
tree, no proposed fixes, no switches — is exhaustively GREEN over 6 664 764
distinct states at depth 49. Each fix taken back out on its own brings its own
counterexample straight back (`Historical_E76.cfg`, `Historical_E77.cfg`), which
is what says the fixes are load-bearing rather than incidental.

Finding 2 needed a config flip: `FixPpuatRequiresPin` is ON everywhere now,
because it is the tree. Finding 1 needed a model change, and it is the one the
note above asked for. `NoUnmanageableCredential` asked for *prevention*; the
shipped mitigation delivers *unopenability*; and `store.cred` meant "a record
exists". It means **"a record that still opens"** now — justified by the fix's own
verified premise, that every credential box, rpId box and `EF_RP` domain hangs
off the seed and `credential_load` / `for_each_rp` are the chokepoints every
reader goes through. `SeedLeadsTheWipe` is the ordering rule that no other delete
may precede the seed's, and `BugSeedDoesNotLead` is the tree before 0x08BF.

One thing the re-run turned up is **still** unfixed, and is recorded rather than
closed: **the model has one reset path.** `Fs::factory_wipe` — the Management
RESET and the on-screen factory reset — is a second producer of the state
`NoUnmanageableCredential` forbids, and it took the same `first` predicate in the
same commit. It is unmodelled.

### The blindness that regression exposed — closed

The second one *was* the sharpest result this model had produced about itself:
**it could not have caught the regression that fix's own review caught.**
`Ctx::load_keydev` prefers the in-RAM `state.keydev_dec`
(`crates/rsk-fido/src/lib.rs:91-95`), so
with the flash seed always deleted first a *failed* sweep would have left the
power cycle running on a seed nothing stores — `BACKUP_EXPORT` included — which
is why `ctx.state.reset()` moved ahead of the flash work (`reset.rs:58-61`).

Both halves of the blindness are now modelled, and each had to be closed
separately:

- **The RAM copy.** `ram` is `state.keydev_dec` (`state.rs:338-340`);
  `SeedReachable == store.seed \/ ram` is what "the owner's seed is still
  reachable" means; `DeviceUnlock` is the vendor `UNLOCK` (`vendor.rs:549-572`)
  that is its only door. `KeepOpen` / `KeepSurv` move the wipe's own claim — that
  what a tear leaves behind is undecryptable — from the flash delete to the
  moment the **last** copy dies.
- **The failed sweep.** `ResetAborts` is any `?` in `reset.rs:65-70` returning
  `Err`: the command answers with an error and the device **keeps running**, no
  boot, no `ensure_seed`, RAM intact. Every other tear in the model goes through
  `PowerCut` / `WarmReset`, which clear RAM on the way past — which is precisely
  why the RAM copy was unobservable without this action.

`BugStateResetAfterWipe` is the regression, and it is **RED on
`ResetNeverWeakensSurvivingState` in 38 880 distinct states at depth 11**: seal
the backup window, unlock the device so the seed is in RAM, start the reset, let
the flash seed go, let phase 2 take `EF_BACKUP_SEALED`, then abort. The one-time
`BACKUP_EXPORT` window is re-opened over a seed the device can still reach.

Each new action is load-bearing, measured one at a time against that mutant:
lift `ResetAborts` out of `Next` and it is **GREEN over 13 443 648 distinct
states**; lift `DeviceUnlock` out instead and it is **GREEN over 10 330 542**.
Round two's "no, in two independent ways" was exact.

## Results

| Configuration | Verdict | States generated | Distinct | Depth | Wall |
|---|---|---|---|---|---|
| `Shipped.cfg` (the tree as it stands, `SYMMETRY` on, firmware constants) | **GREEN, exhaustive** | 699 350 223 | 48 679 968 | 55 | **539 s** |
| `Historical_E76.cfg` (the seed-lead taken back out) | RED `NoUnmanageableCredential` | 2 286 995 | 246 718 | 13 | 4 s |
| `Historical_E77.cfg` (the grant back in phase 2 **and** the consumer fix out) | RED `NoAccessibleSecretWithoutGate` | 2 060 496 | 221 977 | 13 | 3 s |
| 28 × `Mut_*.cfg` | RED, each caught | 65 – 3 926 726 | 40 – 410 556 | 4 – 14 | ≤ 6 s |
| 28 × `Solo_*.cfg` + 3 structural | RED, each on its **own** target | 65 – 6 430 819 | 40 – 658 903 | 4 – 15 | ≤ 9 s |
| 3 × `SoloClause_*.cfg` | RED, each on **one clause** | 25 216 – 22 897 118 | 5 867 – 2 231 576 | 8 – 18 | ≤ 30 s |
| `Fairness.cfg` (`ENABLED OpAdvances => ~Idle`, liveness constants) | **GREEN** | 85 388 061 | 7 903 336 | 43 | 117 s |
| `FairMut_BugFairnessFoldsLocalCeremony.cfg` | RED `OpAdvancesIsOneActivity` | 57 | 36 | 4 | < 1 s |
| `Seams.cfg` (the second module) | **GREEN, exhaustive** | 6 045 | 410 | 11 | 1 s |
| 14 × `SeamMut_*.cfg` / 14 × `SeamSolo_*.cfg` | RED, each on its own target | — | 27 – 381 | 3 – 8 | ≤ 1 s |
| `Store.cfg` | **GREEN, exhaustive** | 3 041 | 272 | 7 | < 1 s |
| `Lattice.cfg` | **GREEN, exhaustive** | 2 431 | 243 | 11 | < 1 s |
| `Policies.cfg` (all four applets in one module) | **GREEN, exhaustive** | 45 253 | 2 268 | 14 | 1 s |
| `Admin.cfg` / `Display.cfg` / `Boot.cfg` / `Transport.cfg` | **GREEN, exhaustive** | 15 – 127 | 5 – 24 | 3 – 5 | < 1 s each |
| `Liveness.cfg` (reduced constants, `HEAP=12g` from `floors.txt`) | **GREEN** | 85 388 061 | 7 903 336 | 43 | **1591 s** |
| `Liveness.cfg` at the old 4 GB default | **out of memory** in the temporal check, state search complete | 85 388 061 | 7 903 336 | 43 | 1500 s |
| 3 × `LiveMut_*.cfg` | RED, each on its own property | 579 360 – 733 606 | 79 706 – 100 162 | — | ≤ 4 s |

Every named baseline above, plus `Fairness.cfg` and `Liveness.cfg`, is an exhaustive
search and its count is reproducible; every RED row stops at the first
counterexample, so its count is **worker-scheduling dependent** and moves between
runs of the identical command. TLC's reported *depth* is not quite deterministic
under 2 workers either. The verdict and the invariant are the result; the count
says how deep TLC had to go, roughly.

**Every row above is from one `./run-tlc.sh all` on the final tree**, which now
exits non-zero if any row misses what `floors.txt` requires of it. The
`Shipped.cfg` figure is **bit-identical to the pre-change baseline** — every
Guard/Policy pair, structural invariant, clause name and recorder this round
added removed and added exactly zero states.

The green row is **9× the state space this model carried two rounds ago and 15×
the wall clock**, and both the growth and the one shrink are fidelity. `ram` and
`ResetAborts` took it from 6 664 764 to 17 190 324; the panel, the OTP owner and
the on-panel PIN door took it to 79 985 500 — `LocalPinOk` refilling the
persistent retry budget without clearing the RAM soft lock is the expensive one,
because it makes `(retries, lock)` pairs reachable that were not, and it is a
state the device really is in.

Then it went **down** to 61 215 504, by 23%, while gaining four Policies. (Every
count in this section and the two experiments above it was taken at the old
3 : 2 constants with no symmetry, which is why they do not match the Results
table.) Two
fidelity repairs did that: `ctx.state.reset()` modelled in full rather than only
its `keydev_dec` half, and `makeCredential` requiring the seed as `getAssertion`
already did. Every state they removed was one the firmware cannot be in — the
same shape as the boot-time `ensure_seed` repair two revisions ago, and the
second time on this model that being *more* faithful has made it *smaller*.

Constants: `RPs = {r1,r2}`, `Channels = {c1,c2}`, **`MaxRetries = 8`,
`MismatchLimit = 3`** — the firmware's own `MAX_PIN_RETRIES` and
`PIN_MISMATCH_LIMIT` (`consts.rs:361,334`) — `MaxClock = 1`, `ResetWindow = 0`.

They used to be 3 : 2, and the reduction was the largest standing question on
this page. `SYMMETRY` is what answered it. Relying parties and channels are
interchangeable — no action, invariant or initial state names one — so TLC may
quotient by `Permutations`, and doing so takes the reduced-constant run from
61 215 504 distinct to 25 829 584. The firmware's real constants then cost
**48 679 968, still fewer than the 61 215 504 the reduced scope explored
before**, at depth 55 rather than 50, and all thirty mutants stay RED on their
own invariant. Symmetry is applied to the safety configurations only: TLC's
liveness check is not sound under it, so `Liveness*` and `Fairness*` keep their
own smaller constants and no symmetry. The floor did not move — 20 000 000 is
still under the measurement, and stricter than the "near a third" rule, which is
the safe direction to be wrong in.

### What the review's repairs cost

The model got **3.3× bigger and 3.4× slower**, and one repair made it *smaller*
because the states it removed were states the firmware can never be in. Each row
is a `ShippedFixed.cfg` run with everything above it applied.

| Change | Distinct | Wall |
|---|---|---|
| as reviewed | 4 041 344 | 46 s |
| `+ BootEnsuresSeed` (D1 fidelity) alone | — | **RED** `NoAccessibleSecretWithoutGate` at 248 049 |
| `+` the `everSet` repair (D1 invariant) | 2 654 832 | 28 s |
| `+ ConfigOp` loses `/\ pin.set` (D2) | 2 654 832 | 30 s |
| `+ deleteCredential` (D3) | 2 861 128 | 34 s |
| `+ EF_BACKUP_SEALED` + `BackupFinalize` + 2 snapshot fields (D3) | **13 232 120** | 154 s |

Two of those numbers are worth more than the rest. **The D2 row is
bit-identical** — the `pin.set` conjunct removed exactly zero states, so it was
inert as well as unfaithful; it is gone because a model whose selling point is
that its guards are what the Rust tests may not carry a guard the Rust does not
have. And **the D1 rows fell by a third**: modelling a boot that regenerates the
seed *deleted* 1.4 M states, all of them states in which a device sat
permanently seedless — which the firmware cannot do. A model can be too big for
the wrong reason.

**The dead-action check is the vacuity question**, and it is the same one
`kani::cover!` answers on the Kani side: a transition that never fires makes
every clause guarding it free. It is `COVERAGE=1 ./run-tlc.sh <cfg>` now, and
it refuses on a zero — see "the dead-action check" above; the seam module fires
**20 of 20**. An earlier revision measured the FIDO module with `-coverage` and
found no zero-total row among 41 actions plus `Init`. That measurement has
**not been repeated since the model reached 50 actions**, and the reason it
matters is no longer hypothetical: `-coverage` is what pinned `CardReset` firing
from 330 of 666 states against 666 for each of its siblings, which is the pinned
trap seen from the other side.

## The trusted display — a wait owner and a fourth PIN door

The panel was absent from this model entirely, and it carries the project's
strongest security promise. Two settled findings are exactly the cross-surface
authorization claims this model shape exists to express, so those two are what
got modelled — not the panel's screens, its device PIN record, or its build.

**E45 — the panel owns the session.** `WAIT_SCOPE` is one byte carrying two
different states: "no host request is in flight" and "an on-panel flow owns the
button", both `SCOPE_NONE` (`crates/rsk-device/src/presence.rs:25-26`). The
model used to have one value for both, which left the panel unable to own a
ceremony at all — so a physical hold spent on an on-panel flow was invisible to
the one-hold-one-ceremony rule, and E45's ruling had nothing to be true of.
`Panel` is a distinct owner here, `SCOPE_OTP` is a third
(`firmware/src/worker.rs:661-663`), and `request_cancel`'s single `if`
(`crates/rsk-device/src/presence.rs:118-122`) is what refuses a host cancel
against any of them. `BugPanelCancelable` loosens exactly the panel half of that
test — the narrow mistake somebody could make while keeping the CCID half — and
falls in 238 states.

**E66 — the on-panel PIN pad is a fourth PIN door.** `local_pin_gate`
(`crates/rsk-display/src/gates.rs:114-200`) spends the **same** persistent
`EF_PIN` retry counter the wire path spends, because
`spend_and_verify_local_pin` is `spend_and_verify_pin_at(EF_PIN, ..)`
(`crates/rsk-fido/src/clientpin.rs:1023-1029`). A clientPIN refused there is
changePIN's failed old-PIN check performed locally, so it must end the host's
outstanding grant exactly as `clientpin.rs:783` does. `ends_host_token`
(`crates/rsk-display/src/gates.rs:139-146`) is the Rust's own test and it is
deliberately narrow twice over: the FIDO scope only, and only with budget left,
because a `Blocked` verdict at zero was turned away before any compare.
`BugLocalPinKeepsToken` is the door that does not close: 1 604 states.

What the pad does **not** do is go through the CTAP session at all — no ECDH
regeneration, no RAM 3-strikes lock, no journal
(`crates/rsk-fido/src/clientpin.rs:1017-1021`) — so `LocalPinWrong` is not a
`PinAttempt` here either. The persistent 8-try counter is the whole gate, and a
host-soft-locked device still takes PIN entry at the pad, which is the
documented recovery.

**`SCOPE_OTP` needed its own mutant, not a share of `BugUnscopedCancel`.**
`cancel_otp_wait` (`crates/rsk-device/src/presence.rs:126-137`) is a **second
writer of the same `cancel_requested` AtomicBool** the CTAPHID door writes; the
only thing keeping the two apart is its own scope test, in a different function.
`BugUnscopedOtpCancel` removes that one: 237 states.

Three things are **not** modelled and are named rather than implied. The device
PIN (`EF_DEVICE_PIN`) is a separate flash record with its own budget and it
gates every on-panel flow that reveals a secret; none of that is here. The
display **build** is not modelled either — `presence.shows_confirm()` stays
FALSE, so the reset window still applies where a display build bypasses it
(`reset.rs:32`), and `ButtonWait`'s `spent` latch stays where that build
compiles it out (`firmware/src/presence.rs:99-106`) in favour of the panel's own
release debounce. And `OpenWaitFor` now stands for **two** different stale-cancel
drops — `ButtonWait::wait`'s and the display's own
(`crates/rsk-display/src/presence.rs:45-48`) — so
`BugNoDropStaleCancelAtEntry` removes both at once where the firmware has two
owners.

## The second module — `RSKeyAppletSeams.tla`

`RSKeySecurityState.tla` is all FIDO. The applets' own security statuses —
PIV's PIN / PUK / management key and its `pin_fresh`, OpenPGP's PW1 / PW2 / PW3,
OATH's access code and OTP PIN — live in `RSKeyAppletSeams.tla`, and it models
**the seams only**: who holds which status, and what ends it. None of the three
command sets is in it, because the defects have not been in the command sets.

### Why a second module and not more variables in the first

Because the two state machines share no variable, and that is measured rather
than assumed. The CCID side owns a `Dispatcher` and the only instances of
openpgp / oath / piv / otp / management / rescue / vendor
(`crates/rsk-device/src/ccid.rs:91-109`); the CTAPHID side owns a **separate**
`Dispatcher` whose applet array is literally one element, its own `VendorApplet`
(`crates/rsk-device/src/ctap.rs:171-175`). PIV, OpenPGP and OATH are not
reachable over CTAPHID at all, so no status can be established on one transport
and honoured on the other. A product of the two models would multiply 17 M
states by this one's 205 and buy exactly zero new interleavings. What they do
share — one flash, one button — appears here as events (`FactoryWipe`,
`PowerCycle`), and that is stated in the module as the abstraction it is.

### What it asserts

| Invariant | What it asserts | The Rust that owns it |
|---|---|---|
| `NoStatusOutsideItsSelection` | An applet holds a security status only while it is the **selected** applet. Structural — it reads straight out of the state | `crates/rsk-sdk/src/applet.rs:374-390` (the one place that decides what a selection does to the applet that was current) · `crates/rsk-piv/src/lib.rs:199-203` · `crates/rsk-openpgp/src/pin.rs:67-80` · `crates/rsk-oath/src/lib.rs:1171-1175` · `crates/rsk-device/src/ccid.rs:348-363` (the ICC power transition) |
| `NoStatusAfterARefusedAuth` | A reference whose authentication was just refused is not authenticated | `crates/rsk-piv/src/lib.rs:183-186` · `crates/rsk-openpgp/src/pin.rs:158-170` · `crates/rsk-oath/src/lib.rs:1119-1120` |
| `NoKeyOpOnTheAdminStatus` | No key operation runs on a status its own specification does not name | `crates/rsk-openpgp/src/pso.rs:80-92` · `crates/rsk-openpgp/src/internalaut.rs:45-48` · `crates/rsk-piv/src/auth.rs:57-65`, `:113-117` |
| `ReselectPreservesAccessStatus` | A re-SELECT of the same AID changes no access status. **A conformance claim, labelled as one** | `crates/rsk-piv/src/lib.rs:365-368` · `crates/rsk-openpgp/src/lib.rs:335-338` |
| `AccessCodeRemovalNeedsTheCode` | Removing the OATH access code needs the validated status the code bought. **A step rule — its violation produces exactly the exempt code-less state, so no state predicate can see it** | `crates/rsk-oath/src/lib.rs:327-329` (the shared gate) · `:334-340` (the removal path) |

The fourth one points the other way from the first three and that is why it is
separate: `637ed98` **widened** the authentication window, so no safety
invariant here can see it, and without a property of its own the switch that
rebuilds the pre-`637ed98` tree would be a mutant nothing catches. Its authority
is SP 800-73-4 pt 2 §3.1.1 (a `shall`), OpenPGP 3.4.1 §4.2, and a YubiKey 5.7.4
measured keeping every status through a re-SELECT on both applets.

### What a refused authentication costs — three applets, three rules

**There is no single cross-applet rule, and writing one would make the shipped
tree red for two deliberate reasons.** That is the answer, and it is not a
shrug: each applet's rule has an authority, and each is now falsifiable in the
direction it actually goes.

| Command | What a refusal costs | The authority | The mutant |
|---|---|---|---|
| PIV `VERIFY` | `has_pin` **and** `pin_fresh` (`crates/rsk-piv/src/lib.rs:183-186` is the only writer of either) | the applet's own session discipline | `NoStatusAfterARefusedAuth` |
| PIV `CHANGE REFERENCE DATA` / `RESET RETRY COUNTER` | **nothing** — it takes no `&mut Session` at all (`crates/rsk-piv/src/lib.rs:543-577`) | SP 800-73-4 pt 2 §3.2.2/§3.2.3, plus a measured YubiKey 5.7.4 | `BugPivChangeResetsStatus`, RED in 46 |
| OpenPGP `VERIFY` / `CHANGE` | exactly the **addressed** reference, keyed on the FID compared rather than on P2 (`crates/rsk-openpgp/src/pin.rs:158-170`, `:229-231`) | OpenPGP 3.4.1, and the `RESET RETRY COUNTER` case that compares `EF_RC` while passing `p2 = 0x81` | `NoStatusAfterARefusedAuth` |
| OATH OTP-PIN `CHANGE` | **both** flags (`crates/rsk-oath/src/lib.rs:1119-1120`) | `aa47867` — before it the whole retry budget could be burned through the door that did not close | `BugFailedChangeKeepsStatus` |
| OATH access-code `VALIDATE` | **nothing** — the standing unlock survives (`crates/rsk-oath/src/lib.rs:510-512`) | a MAC challenge-response has no retry counter for a refusal to protect; a YubiKey 5.7.4 measured keeping it from a genuinely locked applet | `BugRefusedValidateDropsUnlock`, RED in 46 |

So `NoStatusAfterARefusedAuth` is keyed on the reference the model's own actions
report as refused, and the two exempt actions deliberately report nothing —
while `ExemptRefusalPreservesStatus` is the other half, with those same two as
its only writers. Both directions of the OATH recorder are separated on purpose:
granting on a refusal is the safety defect, dropping the unlock is the
conformance one, and one recorder for both would have made the verdict ambiguous
the way four sibling call sites once made `NoAuthorizationBypass`'s.

`PivChangeRefused` used to be `UNCHANGED vars` — a stutter step, which
`[][Next]_vars` admits anyway, so the action was indistinguishable from not
existing and the exemption it stood for was a comment with an action's name on
it.

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugSelectKeepsOtherApplet` | `crates/rsk-sdk/src/applet.rs:379-387` — the `deselect` a select of a *different* AID runs | `NoStatusOutsideItsSelection` | 27 states |
| `BugReselectResetsStatus` | `637ed98` taken back out: PIV and OpenPGP resetting on every select | `ReselectPreservesAccessStatus` | 42 states |
| `BugCardResetKeepsStatus` | `crates/rsk-device/src/ccid.rs:348-363` — the ICC power transition | `NoStatusOutsideItsSelection` | 29 states |
| `BugAdminOpensKeyOps` | `e5da38b` taken back out: PW3 standing in for PW1/PW2 | `NoKeyOpOnTheAdminStatus` | 67 states |
| `BugFailedChangeKeepsStatus` | `aa47867` taken back out: a refused OTP-PIN change that leaves the safe open | `NoStatusAfterARefusedAuth` | 74 states |
| `BugPinFreshNotSpent` | `crates/rsk-piv/src/auth.rs:113-117` — one VERIFY, one key operation | `NoKeyOpOnTheAdminStatus` | 45 states |
| `BugPinFreshOutlivesPin` | the selection clamp removed, so `pin_fresh` survives after `has_pin` is cleared | `NoKeyOpOnTheAdminStatus` | 42 states |
| `BugSigPinNotSpent` | `crates/rsk-openpgp/src/keys.rs:405-409` — the same shape one applet over, PW1 valid for one PSO:CDS | `NoKeyOpOnTheAdminStatus` | 212 states |
| `BugUserStatusOpensAdmin` | a *user* status opening the admin surface — the converse `BugAdminOpensKeyOps` cannot express | `NoKeyOpOnTheAdminStatus` | 48 states |
| `BugRefusedValidateGrants` | a refused OATH access-code `VALIDATE` that grants the unlock | `NoStatusAfterARefusedAuth` | 73 states |
| `BugPwStatusIgnoresAdmin` | a *user* status writing the PW status byte — PUT DATA `0xC4` is PW3's (`crates/rsk-openpgp/src/putdata.rs:181-183`, and the ACL one layer up at `:59-65`) | `NoKeyOpOnTheAdminStatus` | 49 states |
| `BugPivChangeResetsStatus` | PIV's refused `CHANGE REFERENCE DATA` clearing the standing status | `ExemptRefusalPreservesStatus` | 46 states |
| `BugRefusedValidateDropsUnlock` | a refused OATH access-code `VALIDATE` dropping the standing unlock | `ExemptRefusalPreservesStatus` | 46 states |
| `BugRemoveCodeUnvalidated` | the access-code removal (`73 00`) reached without the validated status (`crates/rsk-oath/src/lib.rs:327-329`) — the hole the abstractions list carried for two revisions as definitionally invisible to any state predicate | `AccessCodeRemovalNeedsTheCode` | 71 states |

`Seams.cfg` is **GREEN, exhaustive, 6 045 states generated / 410 distinct at
depth 11**, and 14 of 14 mutants are caught by the invariant that names them.
The final reduction comes from keeping `psig`, the requirement-side one-shot
status, scoped to the OpenPGP selection just like the status it shadows.

**The shape holes are structural now.** `BugPinFreshNotSpent` ran **green** as written:
stopping `pin_fresh`
from being spent also leaves the Policy that reads `pin_fresh` satisfied, so a
second key operation on one VERIFY looked legal to the invariant that was meant
to forbid it. The repair is a ghost `pfresh` — the freshness the *requirement*
leaves behind, always spent — beside the `fresh` the Rust holds. The two are
equal in every state of the shipped tree, and they diverge under both the spend
mutant (45 states) and the selection-clamp mutant (42). OpenPGP's `psig` twin
does the same for one-shot PW1 (212). The OATH removal is the third shape: its
step recorder falls in 71 despite the resulting state already being reachable.

### The four gaps a second review found, and the two it could not close

An adversarial reviewer took both modules apart. Its two most valuable results
are **bit-identical GREENs**, which is the strongest form of "nothing could see
this": deleting the pad's retry-budget gate, and letting a host command open a
wait over a live on-panel ceremony, each left the reachable space at exactly
79 985 500 states. The mechanism for the second is that `OpenWaitFor` overwrites
`scope`, `cancelReq`, `cancelBy` and `granted`, so nothing was left to record
who owned the button first — E45's ruling with nothing to be true of, one layer
up from the cancel it had been modelled at. `ButtonFreeGuard`/`Policy` and
`LocalPinGuard`/`Policy` close both.

In the seam module it found that **`NoKeyOpOnTheAdminStatus` had no admin
surface to be about**: `pivMgm` was written by one action and read by no guard,
so the invariant's converse — a *user* status opening the *admin* surface — was
unfalsifiable. `AdminOp` costs a handful of states and `BugUserStatusOpensAdmin`
falls in 48. It also found the second `pin_fresh`-shaped hole, one applet over:
OpenPGP's `inc_sig_count` clears `has_pw1` under the one-shot PW status
(`crates/rsk-openpgp/src/keys.rs:405-409`), which `PgpKeyOp` had no term for —
`BugSigPinNotSpent`, RED in 361 once `oneShotSig`/`psig` exist. And a **refused
OATH `VALIDATE` that GRANTS the unlock was invisible**, because the `refused`
ghost provably never names that reference: exempting the action from the refusal
rule had exempted it from everything.

Two things it measured that are corrections to this page rather than defects:
`Reselect` contributes **zero** distinct states on the shipped tree, so
`ReselectPreservesAccessStatus` distinguishes exactly the two branches written
to make it distinguishable — a self-check, and it cannot see `pin_fresh` at all.
And `FactoryWipe` separated from the reboot its callers queue is **GREEN with 93
new states**: the fused step is load-bearing and had not said so.

### And a `GREEN` verdict that meant nothing

`Seams.cfg` first came back **GREEN over one distinct state at depth 1**, with
every invariant holding vacuously, because `fresh' = held'["pivPin"] /\ fresh`
is `(fresh' = held'["pivPin"]) /\ fresh` — `=` binds tighter than `/\` in
TLA+ — which turned an assignment into an extra guard and disabled both SELECT
actions. `run-tlc.sh` now reports `VACUOUS: nothing was enabled` instead of
`GREEN` when a passing run has fewer than 2 distinct states or a depth below 2.
Two is not a judgement call: below it the `Next` relation fired nothing at all.
Mutation-tested by putting the parentheses back and watching the row change.

## The third module — `RSKeyStore.tla`

The security model has a `PowerCut`, but it abstracts the store to per-record
present/absent flags and asserts its flash invariants over quiescent states.
There are two questions one layer beneath that abstraction it cannot ask: does a
torn `delete` leave metadata naming a file whose value is gone, and can the
in-RAM present-cache read a *committed* key as absent? Both are `rsk-fs`'s `Fs`
contract, not the security state machine's; both have shipped as defects; and
both are what the roadmap's refinement pilot inducts its persistent envelope
over. So the store gets its own module, for the reason the seams got theirs — a
product with the first module would multiply its state space and buy no new
interleavings, because the two share no variable.

It is a lift of the Rust abstract model that already sits beside the code:
`powercut.rs`'s four `*_landed` predicates and `powercut_model.rs`'s reboot loop,
which were reachable only by `cargo fuzz` until they became `cargo test`. The
model's variables are the committed store (`val`, `meta`), the tri-state present-
cache (`present`, `decided`) and a `dead` flag for the window a torn write leaves
the device in. `Fids` is two and `Vals` is two — the smallest sizes that
exercise every invariant: one FID to delete, one whose record a `meta_add` of the
other must not wipe, and two values so an overwrite is observable.

**The three named oracle properties, mapped onto three invariants.**
`powercut.rs` names Atomicity, Durability and Enumeration.

- **Atomicity** — a torn write lands the old value or the new one, never a third
  thing — is a property of the log-structured backend's *append*, so it is a
  **modelling assumption** here (`Put` and `MetaAdd` land atomically) rather than
  a falsifiable invariant. The Rust oracle's `Tear::Garbage` control is what
  checks it at the code level; there is no code path that produces a third value,
  so there is no mutant that can, and an invariant no mutant can break is a test
  that cannot fail. Stated, not asserted.
- **Durability** is two invariants. `NoFalseAbsent` is the reader half — the
  confirmed-absent cache bit is set only over a genuinely absent FID, because a
  false-absent *is* the "committed key lost" disaster and it opens every gate
  that reads `has_data` (audit run-36). It is **structural**: it reads straight
  out of the cache and the store, needing no cooperation from any action.
  `NoRecordLostToMetaWrite` is the writer half — a `meta_add` of one FID never
  drops another's record, the "torn `meta_add` wiped every existing record"
  crash.
- **Enumeration** is `NoOrphanedMetadata` — no `delete` leaves a metadata record
  for the file it removed. It cannot be a plain state predicate: a meta-only file
  (a `meta_add` with no `put`) legally has metadata and no value, so the
  violation is a record *outliving a delete*, which is a step. It is a `viol`
  ghost with one writer, `Delete`.

**Five mutants, each a shipped defect, each RED on the invariant that names it.**

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugDeleteValueBeforeMeta` | `fs.rs:434-439` — the two backend writes reversed, so a torn delete leaves value-gone-meta-alive (`delete_landed`) | `NoOrphanedMetadata` | 54 states |
| `BugDeleteMetaOnlyUnderPresent` | the 0x077C databug — `delete` dropping `EF_META` only under `if present_bit`, so a meta-only file keeps its record | `NoOrphanedMetadata` | 55 states |
| `BugCacheFaultAsAbsent` | audit run-36 — `record` in place of `record_unless_faulted`, caching a faulted read as a decided absence | `NoFalseAbsent` | 23 states |
| `BugTruncatedScanDecidesAll` | `fs.rs:211-213` — `scan` deciding the whole FID space after a *truncated* walk, so a missed live key reads absent | `NoFalseAbsent` | 24 states |
| `BugMetaAddDropsOnFault` | the 0x077C databug's meta half — a faulted `EF_META` read rebuilt from empty, dropping every other record | `NoRecordLostToMetaWrite` | 51 states |

`Store.cfg` is **GREEN, exhaustive** over 272 distinct states at depth 7 in
about a second; every `StoreSolo_*.cfg` — the run that checks *only* the mutant's
own target — is RED, so no mutant here is caught by a sibling. The counts are an
order of magnitude, not a pin, the same as everywhere else.

**And all five are co-refuted** (`scripts/comutate.py`, whose roster now covers
`StoreMut_*`): each defect re-injected into `fs.rs` reddens `cargo test -p
rsk-fs` too. The measurement surfaced ONE gap on the way, which is the point of
running it: `meta_add_keeps_records_when_ef_meta_unknown` drives the
unknown-cache door, and nothing drove a `meta_add` over an `EF_META` read that
*faults* — the mutant that treats the fault as an empty blob stayed green.
`a_faulted_ef_meta_read_never_rebuilds_the_blob_from_empty` closes it,
re-measured killed. `SeamMut_*` joined the roster with the applet batch below;
until then it was excluded on the argument that the seam defects' fixes carry
their own YubiKey-measured regression tests — which was true of the fixes and
said nothing about the rules, three of which turned out to be asserted by the
model alone.

**What it abstracts, stated in the risk direction.** Values are two opaque
tokens: the model sees "which of two values, or absent", never a length or a
byte, so a defect that corrupts *content* while preserving presence is out of its
reach (`powercut_kani.rs` proves the byte-level `*_landed` rules Kani-side). The
`rsk-store` backend beneath `Storage` — the two-partition counter/main ring, the
`is_counter_fid` routing, wear and page reclaim, and `compact` — is a modelling
assumption: the model takes `Storage`'s contract (atomic append, a completeness
flag on enumeration) as given and does not re-derive it. `Fs::factory_wipe`'s
two-phase sweep is **not** modelled here — its ordering lives in the security
module (`SeedLeadsTheWipe`), and its own truncation guard is named as an M5/M7
gap in `crates.toml`. So `rsk-fs` and `rsk-store` are `state-partial`, not
`state-modelled`, and the ledger says exactly where the line is.

**Why it is the pilot's precondition.** The refinement pilot's persistent-
envelope obligation (R0p in the roadmap) inducts an invariant over the store's
committed state across a boot — precisely `NoFalseAbsent` restricted to a
post-`scan` state together with the durability of `val`/`meta` that `Reboot`
gives structurally. That obligation had no object while the store was unmodelled;
this module is it.

## The fourth module — `RSKeyRetryLattice.tla`

The seam module has the applets' status *lifetime* — who holds which access
status, what a SELECT or a refusal does to it. It does not have the arithmetic
*behind* establishing that status: the finite retry counter on each reference,
the recovery reference that can refill it, and the rule that a wrong attempt
costs exactly one try from a budget that refuses at zero. That is this module —
PIV's PIN and PUK, OpenPGP's PW1, PW3 and RC — one layer beneath the seam.

**It is the applet surface with no safe oracle, which is the whole reason to
model it.** The wire behaviour of these applets was attacked with a real YubiKey
(the ~47 group-E findings). The retry ladder cannot be: measuring a real PUK
ladder to exhaustion *blocks the card*, and once blocked the only way back takes
the keys. So the one place an exhaustive check of every verify/block/recover
interleaving runs at all is here. A fourth module and not more of the seam one
for the measured reason the seam gave for being a second: the two share no
variable — the seam has statuses and selections, this has counters — so a
product multiplies state and buys no new interleaving.

**Three invariants, all honestly ghosts.** The counter arithmetic erases its own
history — a success refills to `Max`, so no reachable *state* shows the
exhaustion a bad grant rode past — which makes each of these a fact about a
*step*, not a state, exactly as the seam module's mostly are:

- `NoAuthWhenBlocked` — no reference authenticates on an exhausted budget,
  neither a direct VERIFY at zero nor a RESET RETRY leaning on a recovery
  reference already at zero;
- `WrongAttemptIsCharged` — a wrong attempt against an unblocked reference spends
  *exactly one*, the anti-bruteforce gate (a wrong VERIFY charges the target, a
  wrong RESET RETRY charges the recovery reference);
- `BudgetRisesOnlyWithItsSecret` — a counter rises only on a correct secret, its
  own or its recovery reference's, never out of nothing.

**Three mutants, one per defended code site** — the discipline the store and
seam modules keep, so a switch is one real thing a reviewer could break:

| Mutation switch | Removes | Target invariant | Caught in |
|---|---|---|---|
| `BugUseWhenBlocked` | the `left == 0 => PIN_BLOCKED` floor (`crates/rsk-piv/src/lib.rs:1232-1234` / `crates/rsk-openpgp/src/pin.rs:200-202`), which guards a direct verify AND a recovery reference | `NoAuthWhenBlocked` | 30 states |
| `BugWrongDoesNotSpend` | the decrement that IS the gate (`crates/rsk-piv/src/lib.rs:1250` / `crates/rsk-openpgp/src/pin.rs:108`) | `WrongAttemptIsCharged` | 2 states |
| `BugRecoveryWithoutSecret` | the recovery secret verified before the refill (`crates/rsk-piv/src/lib.rs:1383` / `crates/rsk-openpgp/src/pin.rs:766`) | `BudgetRisesOnlyWithItsSecret` | 9 states |

`Lattice.cfg` is **GREEN, exhaustive** over 243 distinct states at depth 11, with
no dead action; every `LatSolo_*.cfg` is RED on its own target. The all-blocked
state — a locked-out card — is not a deadlock: a blocked card still *answers*
every VERIFY (it returns `PIN_BLOCKED` and changes nothing), so a blocked
reference's verify is a no-op refusal here, an enabled step rather than a dead
end. That was a real bug in the first draft, caught by TLC's deadlock check.

**What it does NOT cover, stated.** The OATH access code and the OTP slot code
are absent: a MAC / equality challenge-response has *no retry counter*, so a
wrong answer costs nothing — the seam module's exempt-refusal territory, and
their acceptance is the group-E oracle's. OpenPGP's admin path to PW1 (RESET
RETRY `P1 = 0x02`) is out too: it gates on a live PW3 *session*, which is the
seam module's status, not a secret presented in the call. `LatMut_*` is
co-refuted since the applet batch below, and the exclusion it carried until then
had a real reason: a naive injection measures a `u8` underflow rather than a
blocked reference authenticating, because the floor and the counter's type are
two layers. The patch that resolves it is one substitution — rebinding `left` to
`left.max(1)` removes the floor AND keeps the arithmetic under it in range, so
what the slice fails on is the property rather than a panic.

## The fifth module — `RSKeyAppletPolicies.tla`

The lattice above contains every applet reference that actually has a retry
counter. OATH's YKOATH MAC access code and Yubico OTP's six-byte slot code do
not; assigning them invented counters would prove a different protocol. The
remaining M4 work therefore lives in a separate stateful-policy module:

- PIV `NEVER` / `ONCE` / `ALWAYS` slot policy and the freshness an `ALWAYS`
  operation spends;
- OpenPGP algorithm-attribute changes invalidating the old private/public key
  pair before the new attribute is visible;
- OATH access-code and per-credential touch gates;
- Yubico OTP configure/update/delete/swap under the stored slot code, plus the
  combined persisted-use/RAM-session replay position.

The four applets **fit in one module**: `Policies.cfg` is GREEN and exhaustive
over **45 253 generated / 2 268 distinct states at depth 14**, with a floor of
750. Seven solo mutants each break their own target:

| Mutation switch | Target invariant | Distinct before counterexample |
|---|---|---:|
| `BugPivPolicyIgnored` | `PivOperationNeedsSlotPolicy` | 14 |
| `BugPivAlwaysDoesNotSpend` | `PivAlwaysSpendsFreshness` | 107 |
| `BugPgpAttributeKeepsKey` | `AttributeChangeInvalidatesTheKey` | 49 |
| `BugOathCodeIgnored` | `OathCredentialNeedsItsGates` | 61 |
| `BugOathTouchIgnored` | `OathCredentialNeedsItsGates` | 65 |
| `BugOtpCodeIgnored` | `OtpSlotMutationNeedsItsCode` | 71 |
| `BugOtpCounterRepeats` | `OtpCounterNeverRepeats` | 69 |

The OpenPGP mutant exposed a real implementation gap: PUT DATA C1/C2/C3 could
change an attribute while the old key pair remained. The tree now deletes the
private and public slot records before publishing a changed attribute; the
host regression `changing_algo_attr_invalidates_the_key_pair` fails on the old
ordering. This is a firmware behaviour change, hence `bcdDevice` 0x095B.

All seven `PolicyMut_*` are co-refuted since the applet batch below — the
"later batch" this paragraph used to promise. Each of the other six reddens its
own crate's slice: PIV's two at `auth.rs`, OATH's two at `cmd_calculate`, and
OTP's at the configure/update gate and at `next_use_counter`.

### The applet batch — 24 mutants, and the five rules nothing held

The first 43 co-refutation patches put 31 of themselves in `rsk-fido`,
`rsk-device` and `rsk-fs`. `rsk-piv`, `rsk-openpgp`, `rsk-oath` and `rsk-otp` —
33 773 lines, and the subject of four of the nine modules — held **none**. So
"the applet models are green" was fidelity nobody had measured, and each of the
three exclusions above was an argument rather than a measurement. Extending the
roster over `SeamMut_*`, `LatMut_*` and `PolicyMut_*` measured them.

**Nineteen of the 24 were co-refuted on the first run. Five came back `gap` —
and an adversarial review of the batch then found that two of those five were
not the tree's fault but the batch's:** the patch modelled a different defect
from the switch it was named after. Both halves are worth recording, because the
first is what co-refutation is for and the second is what it costs.

**Three real gaps, each closed by a regression:**

| Gap | What the code level could not see |
|---|---|
| `BugSigPinNotSpent` | `inc_sig_count` clearing PW1 under the one-shot PW status — the §7.2.10 rule that one VERIFY signs once. No host test wrote C4 = `00` at all. |
| `BugRemoveCodeUnvalidated` | SEC-SEAM-006's own defect. The model's blindness here was closed two revisions ago; the Rust half was asserted by nobody, so `73 00` past the gate was a green run. |
| `BugRefusedValidateGrants` / `BugRefusedValidateDropsUnlock` | Both directions of a refused OATH VALIDATE — one that *unlocks* while answering `6A80`, and one that drops a standing unlock a MAC challenge-response has no counter to protect. |

`the_one_shot_pw_status_spends_pw1_at_the_signature`,
`the_removal_is_behind_the_same_gate_as_the_install` and
`a_refused_validate_neither_grants_nor_drops_the_unlock` close them, each
re-measured killed with its mutant applied and each failing on exactly one
assertion rather than taking a suite down with it.

**Two were the batch's own defects, and both resolve to `unreachable`:**

- `BugPinFreshOutlivesPin` was patched by deleting `self.pin_fresh = verified`
  from `Session::set_pin` — which is the **inverse** defect. That writer is the
  only one that ever sets freshness true, so the patch makes an ALWAYS slot
  permanently unusable: fail-closed, where the switch is fail-open. All eleven
  failures read "expected 9000, got 6982" — not one was an operation that should
  have been refused succeeding. The faithful mutant is green, and the reason is
  the finding: `pin_fresh` has exactly one reader,
  `crates/rsk-piv/src/auth.rs:63`, **conjoined** with the status it refines, so a freshness that outlives `has_pin` authorises
  nothing.
- `BugCardResetKeepsStatus` was patched by neutering the whole `reset_card`
  call, which also stops the SELECTION being dropped — and the only test that
  fell asserts the selection and never verifies a PIN. With the faithful mutant
  (an empty applet slice; the selection still goes) the slice is green, because
  every route back to an applet after a card reset is a fresh
  `select(reselect = false)` and all three status-carrying applets re-lock there.

Neither is a hole in the tests: both are defence in depth whose removal changes
no observable behaviour, which is a stronger answer than a gap and a weaker one
than a kill. The lesson is the one this file keeps relearning one layer at a
time — **a red run is not evidence until you read WHY it went red.** A kill for
the wrong reason is the same failure as a green that proves nothing, wearing
the opposite colour. Two of 24 patches had it, and no amount of staring at
verdict columns would have shown it; reading the panic messages did.

A third entry needed re-deriving without changing its verdict:
`BugPwStatusIgnoresAdmin` widened `put_pw_status`'s inner PW3 gate, which the
dispatch's `write_authorized` shadows — the wire command still answered `6982`,
so the kill measured a defence in depth rather than the modelled defect. It now
widens both layers, and `put_data_c4_refuses_a_user_status` drives the command
so the outer gate is asserted too.

The live roster is **67 entries: 63 executable patches killed, four unreachable
with recorded evidence, zero gaps.**

## The sixth module — `RSKeyAdminSurface.tla`

The surface that decides which applets EXIST and who may touch device identity:
the enabled-applications mask (`rsk-devconf`, ykman's `config usb` set), the
always-on carve-out that keeps a disable reversible, and the operator-presence
gate on the privileged `rsk-rescue` commands. A separate module because it shares
no variable with the others, and because its central claim is a *sequence*
property — "no series of config writes can strand the device unable to
re-enable an applet" is about the reachable space of the mask, not about one
write.

Four invariants, three of them ghosts and one structural, each with a mutant on
a real defended site — and two of the four mutants are **shipped defects**, not
removed defences:

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugMaskIsCosmetic` | **the pre-`0x084A` tree, shipped**: `USB_ENABLED` echoed in DeviceInfo while SELECT and dispatch never consulted it — `ykman config usb --disable` disabled nothing (`crates/rsk-sdk/src/applet.rs:208-210`, fed at `crates/rsk-device/src/ccid.rs:237-245`, consulted at `:334`) | `DisabledAppletNeverDispatches` | 10 states |
| `BugLockWriteResetsCaps` | **audit run-35, shipped**: a lock-code-only write strips to zero bytes, stored verbatim as an EMPTY record that `read_enabled_caps` reads as `SUPPORTED_CAPS` — every disabled application silently re-enabled (`crates/rsk-devconf/src/lib.rs:264-277`, the merge) | `DisableSetSurvivesLockWrite` | 9 states |
| `BugAdminGateable` | the `APPLET_CAPS` cap-`0` carve-out removed (`crates/rsk-device/src/ccid.rs:67-74`): management/vendor/rescue gated by the mask, so one disable-everything write is irreversible | `AdminSurfaceAlwaysReachable` | 2 states |
| `BugPrivilegedOpUngated` | `require_presence` removed (`crates/rsk-rescue/src/lib.rs:141-143`): keydev signing, cert/config writes, BOOTSEL reboot and fuse burns driven by the USB host alone | `PrivilegedOpNeedsPresence` | 10 states |

`Admin.cfg` is **GREEN, exhaustive over 8 distinct states** — honestly tiny,
because the state *is* the 3-capability mask's power set and every property
beyond reachability is a step ghost. The structural one is the interesting
shape: `AdminSurfaceAlwaysReachable` is `TRUE` in every state on the shipped
tree precisely because the admin channel is *not* a function of the mask; the
mutant ties it to the mask and the empty set falls out immediately.

**All four are co-refuted** — the first batch to measure **4/4 killed with no
gap**: the enforcement pair falls to
`a_disabled_application_is_invisible_not_just_unreported` and
`set_enabled_hides_a_disabled_applet`, the carve-out to
`the_recovery_applets_can_never_be_disabled`, the presence gate to the rescue
suite's denied-presence cases, and the run-35 merge to its own regression pair
(`a_partial_write_config_keeps_the_fields_it_does_not_mention`,
`trimming_an_over_cap_record_never_evicts_the_enabled_applications_policy`).

**What it does NOT cover, stated.** The config write is modelled ungated
because the default build ships it ungated — ykman parity, a maintainer ruling,
and a documented *reversible* DoS in the threat model; the `strict-config`
presence gate is a build flag orthogonal to every invariant here. The
config-lock code's unsealed-disclosure hole (audit run-30: never persist, never
echo) is data handling inside one write, carried by
`config_lock_code_is_stripped_and_not_echoed` rather than by a state machine.
The rescue commands' payloads — phy records, KEYDEV signing, the fuse and
rollback machinery — are single-step and live in that crate's five test files.

## The seventh module — `RSKeyTrustedDisplay.tla`

The display build's whole reason to exist is one promise —
**WhatIsConfirmedIsWhatIsShown** — and until now it had no model. The ledger
carried it as `rsk-display`'s named gap; this module is the discharge,
decomposed into the three rules a model checker can actually hold, because the
umbrella sentence is a conjunction and a registered property nothing checks is
what the registry refuses:

- `ConfirmNamesTheOperation` — an operation that names a relying party
  completes only through the card that names it. The PIN pad cannot substitute:
  its title is `'static`, *never* RP data
  (`crates/rsk-fido/src/clientpin.rs:536-537`, consumed at
  `getassertion.rs:616-617`, `makecredential.rs:660-661`, `u2f.rs:94`);
- `StaleTouchApprovesNothing` — the touch controller reports *level, not
  edges*, so a finger already down when the card paints would read as a tap on
  it; the release edge is the whole defence, and it is two layers — the ambient
  chokepoint (`crates/rsk-display/src/power.rs:55-65`) and the ceremony's own
  release wait (`crates/rsk-display/src/presence.rs:190`);
- `OnlyAllowConfirms` — Deny, the power button, timeout and CTAPHID cancel all
  end as Cancelled (`crates/rsk-display/src/presence.rs:120-124`); the
  Allow/Deny rectangles are disjoint and a stray touch above the band is no
  button at all (`crates/rsk-ui/src/lib.rs:248-256`).

All three are ghosts, and the module says why plainly: a completed ceremony
leaves nothing on the glass, so no reachable *state* distinguishes a phished
Confirmed from an honest one — the property lives entirely at the step that
produced the outcome.

**Two of the three mutants are shipped display-build defects.**

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugPadSubstitutesForCard` | **audit run-28 F1, shipped**: built-in UV deleted the RP card — `up_collected` from the pad skipped the confirm on the very build whose point is showing WHO you authenticate to | `ConfirmNamesTheOperation` | 6 states |
| `BugPreScreenTouchApproves` | **audit run-33's class, shipped**: the onboarding choice committed by a pre-screen touch; the level-not-edges hazard, ambient chokepoint removed | `StaleTouchApprovesNothing` | 6 states |
| `BugAnyTapApproves` | the `hit_confirm` separation collapsed — a deny is an approve, a stray brush signs | `OnlyAllowConfirms` | 6 states |

`Display.cfg` is **GREEN, exhaustive over 5 distinct states** — the ceremony is
modal (the worker blocks in `confirm_wait`), so the space is genuinely this
small and the floor sits one under it rather than at a third: at this size
losing even one state means an action died.

**All three are co-refuted, the second consecutive zero-gap batch**: run-28
F1's own regressions kill the `needs_confirm` collapse (3 tests), the ambient
chokepoint falls to `a_finger_already_down_is_not_a_tap_on_what_just_appeared`
(with the ceremony layer's own kill,
`a_finger_still_down_when_the_prompt_appears_cannot_approve_it`, recorded as
the second edge), and the zone collapse to `a_deny_tap_is_a_real_decline` and
its siblings.

**What it does NOT cover, stated.** Card-swap mid-wait is structurally absent —
the ceremony is modal and single-threaded, so "the card's content" is honestly
one bit here; the day a second painter can reach the glass mid-ceremony, that
abstraction is the first thing to attack. The PIN pad's own arithmetic is the
security module's fourth door; the menus and settings flows are navigation over
the same armed-touch chokepoint, not separate security state; and the screens'
rendering geometry (paint == hit-test) is `rsk-ui`'s reviewed, tested territory.

## The eighth module — `RSKeyBootHardening.tla`

`firmware/` is the one workspace member with **no host tests by construction**:
its checks run at build time and on hardware, nowhere in between. "Model where
you cannot measure" is this tree's stated rule, and the two machines living at
the reset line are its purest case — the model is the only instrument that can
exercise their interleavings at all.

**The one-shot at-rest lap.** Seal migrations re-key secrets from the pre-OTP
(chip-serial) root to the OTP root, and the log-structured store keeps the
superseded weak copy readable in a raw flash dump until a compaction lap pushes
it off the medium. `EF_HARDENED` says the lap has run
(`crates/rsk-fs/src/lib.rs:26-46`); the boot runs it iff the marker is absent
and writes the marker only after `compact()` returns Ok
(`firmware/src/main.rs:615-626`) — marker AFTER scrub, the same write-order
family as the store's delete and the PIN flows' revoke. Every *lazy* re-key
after the lap must re-arm it: **audit run-35 found four of five sites skipping
exactly that**, and the swept sites are the module's citations.

**The scratch-word lock carry.** The clientPIN soft lock rides a warm reset in
`WATCHDOG.scratch2` so a host-requestable reboot cannot launder the
three-strikes batch, and the rule the file itself states is THE WHOLE LOCK
MOVES (`firmware/src/pin_lock.rs:18-21`): carrying the engaged flag without the
mismatch batch lets a host stop at two wrong PINs and reboot — the budget
laundered two attempts at a time. The security module owns the *total* drop
(`BugSoftLockLostOnWarmReset`); this module owns the *partial* one, which that
mutant cannot express.

**Two invariants, both structural — deliberately no `viol` ghost**: a liar
marker and a half-carried lock are *states* the machine sits in, not steps it
erases, so the strong form is available.

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugRekeyKeepsTheMarker` | **audit run-35, shipped at 4 of 5 sites**: the lazy re-key leaves the marker standing over its new weak leftover — no future boot ever scrubs it | `MarkerNeverLies` | 2 states |
| `BugMarkerBeforeScrub` | the `compact().is_ok()` short-circuit dropped: a torn lap claims completion, and the weak copies it left ride under a set marker forever | `MarkerNeverLies` | 26 states |
| `BugPartialLockCarry` | the half carry `pin_lock.rs` names as the laundering: engaged rides, the batch is dropped | `TheWholeLockRides` | 26 states |

`Boot.cfg` is **GREEN, exhaustive over 24 distinct states at depth 5**, no dead
action.

**Co-refutation is deliberately out for this module and the exclusion is
load-bearing**: two of the three defended sites live in `firmware/`, which
`cargo test` cannot reach — that is M7's point, not its weakness. The one
host-testable family — the lazy re-keys — got direct code-level closure
instead: `pin_verifier_and_pinwrapped_seed_migrate_at_verify` (rsk-fido) and
`kbase_migration_reseals_slots_and_pin_falls_back` (rsk-piv) now pin
`EF_HARDENED` cleared after the migration, and each was proved able to fail by
removing its own site's re-arm in a worktree — the first probe removed the
*panel* site by mistake and the fido test rightly stayed green, which doubles
as the asserts' specificity check. The panel path's own twin
(`spend_and_verify_pin_at`, the fourth PIN door) and the OATH/OpenPGP site
asserts remain open, recorded here rather than implied.

**The open hardware assumption, and what running it the other way cost.**
`PowerOnClearsScratch2` was a named Boolean `ASSUME` that every generated Boot
configuration assigned `TRUE` — and that no action read. Deleting the `ASSUME`
line left `Boot.cfg` bit-identical: 77 states, 24 distinct, depth 5, before and
after. It named the open question in a way that made it impossible to ask.

`ColdReset` reads the constant now, and `BootCarry.cfg` runs the `FALSE` arm — a
chip whose power-on leaves the word standing, which makes a cold reset
indistinguishable from a warm one. (The tag cannot separate them either: a
carried word carries a valid tag. The tag defends against an *undefined*
register, which is a third case and reads as clear.) Both arms are in the safety
tier, and the measurement is this:

| | states | distinct | `MarkerNeverLies` | `TheWholeLockRides` |
|---|---:|---:|---|---|
| `Boot.cfg` — clears | 77 | 24 | GREEN | GREEN |
| `BootCarry.cfg` — carries | 67 | 18 | GREEN | GREEN |

All three boot mutants redden on **both** arms, and on the same invariant each
time — and that is a row now rather than a sentence. `BootCarryMut_*.cfg` runs
each of the three on the `FALSE` arm, one invariant apiece, so a RED there names
the same defect its `BootSolo_*` twin names and cannot be a sibling invariant
reporting a mutant gone unreachable. Measured: `MarkerNeverLies` in 2 and 20
distinct, `TheWholeLockRides` in 20, against 2 and 26 and 26 on the arm that
clears (at the runner's default two workers — a RED row's distinct count belongs
to the search rather than to the model, and one worker gives 2/21/21 and
2/17/17). It was measured once when the arm landed and then thrown away, which is
how "both arms behave" becomes something nobody can re-check. What no ROW holds
is that these three files exist at all, because `run-tlc.sh` lists the family
with `ls`; `test_every_boot_mutant_runs_on_the_arm_that_carries_too` pins their
count and their arm instead.

So the assumption buys **reachability, not safety**: six distinct states go
unreachable without it, and no invariant this module checks — nor the detection
of any defect it models — rests on the silicon fact. The board measurement is
still worth taking, and `assurance/assumptions.toml` says what would settle it;
but its risk direction is *usability*, not security, because a word that rides a
power cycle carries the mismatch batch with it, which locks harder rather than
softer.

**And the rule that came out of it.** `scripts/assumption_gate.py` refuses an
assumption that every configuration pins the same way, and one no *reachable*
definition reads — the two halves of the shape above, each checked directly
rather than inferred from a state count nobody would think to compare. Driven
against the pre-change model it reports both. A defect switch (`Bug*`, `Fix*`,
`Mutate*`, `Check*`) is *meant* to be pinned per configuration and is excluded by
name.

The second half started out weaker than its own message. It asked whether the
module mentions the name **anywhere** outside its declaration and its `ASSUME`,
and `Orphan == PowerOnClearsScratch2` with nothing mentioning `Orphan` passes
that while being exactly as inert as the `ASSUME` the rule was written for —
measured on a toy module, `NO PROBLEMS`. It walks the definition graph from the
names the configurations actually run or check now, and both directions are in
its table: an orphan definition is refused, a constant two hops from a checked
name is clean.

**What it does NOT cover, stated.** The device is OTP-provisioned (`mkek`
present — a pre-OTP board never laps and has nothing to scrub); the 0x0854
legacy-canary aliasing that motivated the derived-engaged decode is below this
floor; `ensure_seed`, the reset window's warm keying and the full BootState
carry are the security module's; the seal migrations' own torn-write safety is
the store module's and the power-cut oracle's; TRNG health gating and USB
bring-up order are M8's transport territory.

## The ninth module — `RSKeyTransport.tla`

`rsk-usb` was the last workspace member no module covered, and the CTAPHID
frame reassembler (`crates/rsk-usb/src/ctaphid.rs:386-456`) is a genuine
sequence machine — `in_tx` carries across the frames of a multi-frame message.
It is already unit-tested and fuzzed, and that is exactly the point of also
modelling it: every one of those exercises a *single* `feed`, or a fuzzer's
random stream checked for "no panic". The security properties are not about one
frame — they are about what an interleaving of channels can *assemble*, which is
an invariant over a transaction's reachable space that a per-frame test does not
assert and a sampling fuzzer does not prove.

- `NoCrossChannelSplice` — a continuation on a channel other than the
  in-progress transaction's is `CHANNEL_BUSY`, the owner's transaction left
  intact (`crates/rsk-usb/src/ctaphid.rs:433-435`); one host application's bytes
  must never assemble into another's message;
- `NoSequenceGap` — an out-of-order continuation aborts rather than filling the
  gap (`:437-440`); the reassembler never completes a message the host did not
  send in that order;
- `NoBufferOverrun` — an INIT declaring more than `CTAP_MAX_MESSAGE` is refused
  (`:417-419`), and the chunk count never passes the ceiling; in a `no_std`
  image passing it is an out-of-bounds write, so this one is **structural** (the
  other two are ghosts — a splice and a desync leave no trace in the completed
  message, they are steps).

| Mutation switch | Removes | Target invariant | Caught in |
|---|---|---|---|
| `BugContIgnoresChannel` | the `cid != self.cid` busy check on a continuation | `NoCrossChannelSplice` | 11 states |
| `BugContIgnoresSeq` | the `seq != self.seq` abort | `NoSequenceGap` | 10 states |
| `BugInitLenUnchecked` | the `bcnt > CTAP_MAX_MESSAGE` refusal | `NoBufferOverrun` | 8 states |

`Transport.cfg` is **GREEN, exhaustive over 13 distinct states at depth 4**, no
dead action — `CTAPHID_INIT` always resyncs, so `Init` is enabled in every state
and the graph never dead-ends. **All three are co-refuted, the third
consecutive zero-gap batch**: `cont_wrong_cid_busy`, `wrong_seq_aborts` and
`bcnt_too_large` each catch their mutant in `cargo test -p rsk-usb`.

**What it does NOT cover, stated.** A chunk is one bit of provenance, not 57/59
payload bytes — the three properties never look at contents; a `CTAPHID_INIT`
mid-transaction is a legal resync (a takeover, not a splice: B's fresh buffer
holds B's chunks). The bounded IN-endpoint write that fixed the runtime
interface wedge (0x075D, `TX_TIMEOUT_MS`) is a liveness property of the async
`run` loop (`crates/rsk-usb/src/ctaphid.rs:565`), already guarded by the
`FrameSink` seam's own mutation-tested regression; the CCID and keyboard framing
and the `secure_pin`
codec are single-step, Kani-proved and unit-tested.

## Phase 4 — trace validation: recorded sessions replayed against the model

Everything above keeps model↔code fidelity by hand — citations name the code
each action claims to abstract, mutants prove the model *can* catch defects,
co-refutation proves the code level catches the same defects. What none of it
measures is whether the code **as it runs** stays inside the model's behaviors.
Phase 4 adds that empirical half, MongoDB-style: record a real session, force
the model through it step by step, and let TLC judge.

The pipeline, each stage falsifiable:

1. **Record** — `formal/record-seam-trace.py` drives a scripted CCID session
   against a live `tools/emu` (SELECTs across all three applets, a failed and a
   successful PIV VERIFY, PW1/PW3, a card reset, a power cycle) and writes
   `formal/traces/seams-session.jsonl`: wire-level events with the *observed*
   status words. The committed trace really was recorded — the `63C2` in it is
   the emulator's own retry counter answering a wrong PIN.
2. **Map** — `scripts/trace_map.py` turns wire events into model actions, and
   is deliberately STRICT: an unknown event, an unmappable status word, a
   verify against an unselected applet are hard errors, never silent stutters —
   a mapper that skips what it does not understand is a checker that stopped
   checking. The one state it keeps is the current selection, which decides
   `Reselect` vs `SelectOther` exactly as the Dispatcher's `reselect` flag
   does. A `check.sh` row holds the committed `TraceSeamsData.tla` against the
   committed trace (neither can drift alone), and the mapper carries its own
   12-case mutation table.
3. **Replay** — `TraceSeams.tla` extends the seam model with a position index:
   `TraceNext` at step `i` takes *exactly* the recorded action, so the whole
   behavior space is the one linear run and a step the model refuses leaves no
   successor — **a divergence is a TLC deadlock at the exact step**. The
   model's own invariants are checked along the way. The committed session
   replays GREEN: 13 actions, distinct = 14 = length + 1.
4. **Refuse** — `TraceSeamsBad.tla` replays a hand-written session the model
   must reject (a PIV key operation with no VERIFY behind it) and `floors.txt`
   requires that row **RED**: it deadlocks at step 2, which is the harness
   demonstrating it can reject a session at all. Both rows are in the weekly
   `safety` tier.

**What a GREEN row claims, precisely.** "These recorded sessions are behaviors
of the model" — evidence about the sessions, not a proof about all runs.
Coverage grows by recording richer sessions (the OATH doors, the refused
CHANGE flows, longer interleavings); regenerating is three commands, documented
at the top of the recorder. The two harness modules duplicate ~15 lines because
`EXTENDS` cannot be parameterized by a configuration — kept in lockstep, said
in both.

That seam replay is supplemental evidence. The roadmap's R4a/R4b target is the
full `RSKeySecurityState`, and that pipeline is separate:

1. `tools/emu --security-trace` emits only raw, non-secret C-state fields around
   each CBOR boundary: record sizes/presence, retry and permission bytes, token
   flags, slot counts, cursor counters, lock and boot flags. It never exports a
   PIN verifier, token, seed, credential, or rpId hash. `action_hint` and the
   implementation's `abstract_token()` result travel beside the raw fields but
   are explicitly untrusted.
2. `scripts/security_trace.py` independently infers B micro-actions from raw
   before/after differences. Unknown state changes are fatal. Each instrumentation
   point declares `coarse, k=8`; a no-change command maps to an explicit B
   stutter, while setPIN, token issuance, makeCredential and getAssertion expand
   to their real `RSKeySecurityState` action paths.
3. `TraceSecurity.tla` computes β from the raw record and compares it with B at
   every boundary (R4a). It also compares the untrusted Rust α with
   `RSKeyTokenView!TokenGamma(B)` (R4b). `RSKeyTokenView.tla` is the one γ
   definition the phase-5 INSTANCE will consume too.
4. The committed trace is three suites through one emulator lifetime —
   `21_pin_webauthn`, `20_clientpin`, `27_reset_window` — and has 21 CBOR
   boundaries, 49 B steps, 21 distinct model actions and 3 gate boundaries. Those
   are ratchets in `floors.txt` beside every other one, not literals in the
   script, and every run prints both the reached set and the model actions no real
   traffic reached. The same validation runs inside the socket emulator-suites CI
   row.
5. A **power cycle is a recorded boundary** (`command_raw` `0xFF`, schema 4).
   Without it the replug between suites moved security state outside every
   boundary and the replay saw a discontinuity it could not explain — which is
   why the trace used to be one suite. It is also the only way `PowerCut` is
   reached.
6. The reset sweeps run once per live **secret**, and that count is B's rather
   than the device's twice over. `RegisterStart("rp1", …)` folds every real
   credential of one relying party onto one model element, so the raw slot
   counters cannot say how many there are — and the seed is not one record among
   them: `ResetSweepSecrets`'s first arm is `KeepOpen([store EXCEPT !.seed =
   FALSE], ram)` over a `ram` that `ResetConfirmed` has already cleared, so `cred`
   and `rpent` go with the seed in the SAME step. The phase is two steps however
   many credentials B holds. `scripts/security_trace.py` keeps a small ledger of
   what B holds, updated only from the actions it has itself emitted — never read
   back from the trace.
7. `TraceSecurityBadBeta.cfg` shifts one raw retry field and is RED under R4a.
   `TraceSecurityBadAlpha.cfg` shifts α's `live` field and is RED under R4b;
   `TraceSecurityBadAlphaNoR4b.cfg` is GREEN, demonstrating that only R4b catches
   that second divergence. `TraceSecurityBadUvNotRqd.cfg` and
   `TraceSecurityBadResetWindow.cfg` take one half each out of R4c's gate rule.

### R4c — the answers a model gives by disabling an action

`R4bEventConsensus` compares B's inferred outcome with the device's, and it had
two boundaries it could only answer `AMBIGUOUS`. Both were a `makeCredential`
carrying no `pinUvAuthParam`, and the reason is structural rather than a want of
cleverness: **the model expresses a refusal by DISABLING an action**, so a
refused command reaches a replay as a stutter — and a *successful* one that
stores nothing is the same stutter. `rk` is the only thing that separates them,
CTAP 2.1 §6.1.2 step 10 being the whole rule (`makecredential.rs:540-546`): a
discoverable credential still needs a token where a PIN is set, a non-discoverable
one is served on presence alone. Step 6's `alwaysUv` arm is deliberately NOT in
`McTokenlessRefused`: it refuses only where built-in UV is unavailable
(`makecredential.rs:528-536`), which would need `req.uv` and the pad's
availability recorded, and asserting it from `gate.alwaysUv` alone would be an
uncited claim the code does not make.

So the request's `rk` and whether it carried a `pinUvAuthParam` join the
recording (trace schema 4, decoded by the applet's *own* parser), B states the
gate rule over its own variables, and `R4cGateAnswers` holds the recorded outcome
to it. The line that keeps this honest is **inputs, never the answer**: the
status word is read only to REFUSE an event the rule does not reach — a
`makeCredential` refused downstream of the gate by an excludeList hit leaves the
same empty footprint, and predicting that would make R4c cry wolf on a recording
that is perfectly correct. A build that answered `PUAT_REQUIRED` where it used to
serve still produces a gate row, and B's own rule is what turns it into a
violation; driving exactly that (seq 12's outcome flipped to `0x36` in a copy of
the trace) gives `Error: Invariant R4cGateAnswers is violated`, and flipping the
refused reset's `0x30` to `0x00` gives the same on the other arm.

The reset window is the second gate and the same shape one level up. A reset
outside `RESET_WINDOW_MS` is refused, and refusing it changes nothing — so over
an already-emptied store it has the exact raw footprint of a second *successful*
wipe, and the mapper read the refusal that ends `27_reset_window` as one for as
long as it existed. `now_ms` is what separates them (`reset.rs:187`) and
`ResetGateRefuses` is `~InResetWindowGuard`, the predicate the model already
gates `ResetStart` on, read for its answer instead of its enabling.

**Where B's clock comes from is the whole of that arm's honesty.** Spending the
`Tick`s inside the out-of-window branch — the first version — made
`~InResetWindowGuard` true BY CONSTRUCTION at every reset gate boundary, so R4c's
reset arm was a constant and the check reduced to the mapper's own status test.
`clock_ticks` advances B from `now_ms` at *every* boundary instead, before the
event is mapped and whatever it turns out to be. A reset mis-read as in-window is
then forced onto a `ResetStart` the closed window disables — driven: `Deadlock
reached`, TLC exit 11, once the gate and step ratchets are lowered out of the way,
since they see the lost gate row first. A refusal whose recorded answer is `0x00`
disagrees with a B that refuses: `Error: Invariant R4cGateAnswers is violated`. Both directions are exercised: `TraceSecurityBadResetWindow.cfg` takes
B's rule out, and `the_reset_gate_carries_the_answer_the_device_gave_either_way`
holds the mapper to the other outcome.

#### The arm that was left out was wrong, and the recording proved it

`McTokenlessRefused` was `pin.set /\ rk` — step 10 alone. Step 6's `alwaysUv` arm
was deliberately excluded, on the argument above: it refuses only where built-in
UV is unavailable, so asserting it from `gate.alwaysUv` alone would be false on a
display build. **That argument is right about the display build and wrong about
the rule.** With a pad, §6.1.2 step 6.3 *upgrades* a token-less request to
built-in UV; the answer is to RECORD the pad and refuse such a boundary, not to
drop the arm. Recording it is one boolean —
`Ctap::security_trace_builtin_uv`, trace schema 4 → 5 — and
`scripts/security_trace.py` now dies on a token-less makeCredential recorded on a
build that has one, so the rule's scope is checked rather than assumed.

`tests/16_always_uv_gate.py` is the session that settles it. Measured, with
`alwaysUv` on and no pad, the device answers **PUAT_REQUIRED for both values of
`rk`** — where `pin.set /\ rk` predicts *served* for `rk` false.
`TraceSecurityBadAlwaysUvArm.cfg` is that old rule kept as a mutant, and it is
RED at exactly the boundary that refutes it: `tracePc = 36`, `gate.alwaysUv`
TRUE, `GateRk` FALSE, recorded `Rejected`, predicted `Authorized`. The direction
matches the defect the mutant models (a rule that stops refusing), which is the
half a verdict column cannot show.

The gate grid the recording now covers, and the cell it cannot:

| `pin.set` | `gate.alwaysUv` | `rk` | recorded | boundary |
|---|---|---|---|---|
| TRUE | FALSE | TRUE | Rejected | 29 |
| TRUE | FALSE | FALSE | Authorized | 30 |
| TRUE | TRUE | FALSE | Rejected | 36 |
| TRUE | TRUE | TRUE | Rejected | 37 |

**`pin.set` is still TRUE at every gate boundary, and no correct build can make
it FALSE at one.** The combination that would decide the conjunct — no PIN and
`rk` true — is *served*, and a served discoverable registration writes a
credential, so it reaches the replay as a `RegisterWrite` and not as the stutter
a gate row is made of. The conjunct is not decoration: a build that started
refusing there would produce the stutter and R4c would catch it. It is simply
not falsifiable from a recording of a correct build, which is a different
statement from "unexercised" and is why it is written down here.

Coverage moved with the session: commands 21 → 32, steps 49 → 60, distinct
actions 21 → 22 (`ConfigOp` is new), **gate boundaries 3 → 5**, AMBIGUOUS still
0. `floors.txt` carries all four.

The rules are stated in `TraceSecurity.tla` and not in `RSKeySecurityState.tla`,
because `Next` still does not carry a token-less registration as a behaviour —
the exhaustive model never explores one, and that is listed with the other places
the model is narrower than the firmware. Folding it in is the next widening; the
replay is what made the gap visible.

**AMBIGUOUS is 0 and the floor now says so**, together with `@TraceSecurityGatesMin`
— without a floor on the gate boundaries R4c goes vacuous the moment a re-record
loses them, which is the failure every other ratchet in this file exists for.

### The replay had stopped following the recording, and every observer said GREEN

R4c's own falsification found it. `TraceSecurity.cfg` was GREEN over a replay that
reached **44 of 59 states**: the recorded reset ran fifteen steps past the point
where the model stopped following it, because the sweep expansion emitted one step
per live record while the seed arm empties `cred` and `rpent` with the seed. Three
things had to line up for that to read as a pass, and all three did:

* `scripts/security_trace.py` ran TLC with **`-deadlock`**, so the divergence — a
  forced step with no successor, the mechanism this whole pipeline rests on — was
  not checked at all;
* `TraceComplete` was `tracePc <= TraceSteps`, a tautology that can only catch a
  replay running PAST its evidence, never one stopping short — it is retired, and
  the obligation it read as carrying is now the runner's count check;
* the floor was 30, well under 44.

`-deadlock` is gone, the two GREEN rows are pinned at `TraceSteps + 1` rather than
floored at a third, and the runner asserts the reported distinct count directly,
because the exit code alone cannot say it. Driven, in that order: the sweep
mutation alone gives `Deadlock reached`, TLC exit 11; with `-deadlock` back it
gives `44 distinct states for 51 steps — the replay did not reach the end of the
recording`; with the count check *also* removed it is GREEN and silent, which is
the shape that shipped.

The first real replay found a fidelity defect: B consumed permissions after
makeCredential but failed to retain Rust's first-use rpId binding.
`BoundConsumedTok` is the resulting model correction. This is empirical
conformance of the recorded traffic, not a proof that unrecorded code refines B.

## The induction probes — and the one that found something

Every row above is checked over the states `Init` can REACH. TLC can answer a
stronger question with no extra tooling: run the invariant as the INIT predicate
and `Next` as the next-state relation, and a violation is a **one-step
counterexample to inductiveness** rather than to the invariant. `INIT IndInv` /
`NEXT Next` is the whole mechanism — no TLAPS, no second checker.

The runner needed one rule for it, and the first version of that rule was
inert. Such a run's successors are already initial states, so the search ends at
**depth 1**, and the generic vacuity heuristic reads that as nothing having been
enabled. Exempting `INIT` rows from the depth floor and holding them to
`states > distinct` instead looked reasonable and could never fail: with
deadlock checking on, a run where `Next` fired nothing is reported RED before the
vacuity branch is reached, so `states > distinct` is true on every run that gets
there. **Depth 1 is not the exemption — it is the claim.** Every successor
already being an initial state IS `IndInv /\ Next => IndInv'`, so an `INIT` row
is held to `depth = 1` and depth 2 reads `NOT INDUCTIVE: a step left IndInv`.
That matters because the INVARIANTS block need not carry every conjunct of
`IndInv`: without the depth rule, an `IndInv` strengthened with something the
model does not preserve comes back GREEN — driven, with `/\ ~dead`, which
`Delete` falsifies in one step: GREEN before, `NOT INDUCTIVE (depth 2)` after.
Three cases in `scripts/test_run_tlc.py`, one of them proving the rule does not
reach an ordinary `SPECIFICATION` row.

**`RSKeyBootHardening` is inductive as it stands.** `TypeOK /\ MarkerNeverLies
/\ TheWholeLockRides` admits 48 of the module's 108 type-correct states, and one
step from any of them lands inside: 180 states generated, 48 distinct, GREEN.

**`RSKeyStore` is not, and the counterexample named the missing conjunct.** The
first run came back RED on `NoRecordLostToMetaWrite` in two states:

```
State 1  metaAbsent = TRUE   meta = [a |-> FALSE, b |-> TRUE]
State 2  MetaAdd("a")        meta = [a |-> TRUE,  b |-> FALSE]
```

The cache says `EF_META` is absent while `b`'s record stands. Nothing in
`TypeOK` or the four invariants forbids that state, and from it `MetaAdd` does
exactly what the shipped code does — trusts the cache and rebuilds the blob from
empty (`fs.rs:546`), losing `b`. This is SEC-STORE-004's damage arriving from a
STATE rather than from the step that made the cache lie, and the model had no
way to say the cache is honest. One conjunct fixes it:

```tla
CacheHonest == metaAbsent => \A f \in Fids : ~meta[f]
```

and `StoreInduction.cfg` is then GREEN over 1000 admitted states (11 460
generated). **That is the probe's whole worth: it named a state fact the model
relies on and never stated.** `CacheHonest` is `SEC-STORE-005` now, checked on
the reachable states by `Store.cfg` as well — an induction step without
`Init => IndInv` proves nothing — and that costs nothing: 364 distinct, the same
number as before.

**One mutant probe per module, and the reason is that the rest would be
ceremony.** `Init` satisfies `IndInv` in both modules, so reachable states are a
subset of the ones the probe starts from: any defect its `*Solo_` twin catches,
the induction row catches too. The implication runs the other way from what one
would want — the induction rows fire on a SUPERSET of their twins' conditions, so
they cannot see a mutant that has stopped firing, which is exactly what
`floors.txt`'s verdict column exists for. Measured: delete `Put` from `Next` and
`StoreSolo_BugCacheFaultAsAbsent` correctly goes GREEN-when-RED-was-expected while
the induction row stays RED and notices nothing. So one row per module, to show
the INIT/NEXT wiring can go red at all; the `*Solo_` rows carry the defects.

Both probes pin `PowerOnClearsScratch2` cleared. What they vary is the state, not
the hardware assumption — that is the carry arm's job, one section up.

Two things fell out beside it. `"NoFalseAbsent"` was a member of `InvNames` that
**no step ever wrote** — `NoFalseAbsent` is structural and needs no ghost slot —
so `viol`'s domain carried a name nothing records, doubling the probe's initial
set for nothing. Removing it leaves `Store.cfg` bit-identical at 3825 states and
364 distinct, which is what says it was never reachable. And the floor comment
for that row still said 272, from before `metaAbsent` joined the module.

**The TLAPS question, answered by measurement the way Verus was.** Not now. The
one result a deductive prover would have been bought for — an inductive
invariant, independent of reachability — TLC produced for both modules in a
second, and the useful half was the counterexample, which is what a model checker
gives and a prover does not. What TLAPS would add is the unbounded scope, and
`formal/scopes.txt` records that no mutant in the roster probes above two
anywhere; buying an unbounded proof before the bounded one is exercised at three
is paying for the wrong thing first.

## What now catches a run nobody watched

That `VACUOUS` rule was one heuristic and a **reporting** guard: it printed a
word and returned 0, and it only sees the collapse all the way to nothing. Five
things stand between this model and a pass it did not earn now, and each is
mutation-tested rather than argued.

**1. `tla-lint.py`, before TLC runs at all.** Two traps that leave a spec
well-formed and a run GREEN, caught at the source:

| Check | The trap | Mutation test |
|---|---|---|
| precedence | `x' = e /\ y` parses as `(x' = e) /\ y`, so an assignment becomes an extra guard | the parentheses taken back out at both SELECT actions and at `PgpSetPwStatus` — **3 of 3** caught |
| pinned | a variable assigned in a branch while the action's own **top-level** `UNCHANGED` names it, which disables the action wherever it would change anything | `CardReset`, the one live site, found by running it |

A branch-local `UNCHANGED` is the legitimate IF-branch pair and is not flagged;
the four such hits in both modules are silent. `run-tlc.sh` exits 2 rather than
check a spec the lint rejects.

**2. A floor per configuration** (`floors.txt`), because a GREEN that got
*smaller* is the same failure with a survivor. The floor sits near a third of the
measured count — this model has legitimately shrunk 23% in one round, so a pin
would be noise — and a GREEN below it is reported `FLOOR` with a non-zero exit.

**3. A measured minimum per scope constant** (`scopes.txt`), because the two
guards above both watch the *search* and neither watches the CONSTANTS the
search runs over. A configuration can sit far above its floor, fire every action
and still be blind, because the domain it quantifies over is too small to hold
the defect. Measured on this tree, three of the fifty-three mutants are GREEN one
element below the shipped scope:

| Mutant | GREEN at | RED at | Why it needs the second element |
|---|---|---|---|
| `BugCmWalkIgnoresChannel` | `Channels = {c1}`, 43 M+ distinct, no counterexample | `{c1,c2}` | the credential walk it hijacks has to belong to somebody else |
| `BugContIgnoresChannel` | `Channels = {a}` | `{a,b}` | the same shape at the reassembler: one channel owns the transaction, one splices |
| `BugMetaAddDropsOnFault` | `Fids = {a}` | `{a,b}` | one FID to `meta_add`, one whose record must survive it |

Nothing stopped those domains being narrowed to a singleton before this file —
and `Fids`, `Channels` (transport) and `Caps` were not even configuration
constants; they were literals inside the modules, so no configuration *could*
have said what scope it ran at. `scripts/scope_gate.py` derives which constants
exist, which module owns each configuration and what each one assigns; two
columns are written by hand, the minimum and **the invariant it was measured
against**, because a minimum only binds configurations that check that
invariant. `Fairness.cfg` is in the safety tier, runs one channel deliberately
and checks `OpAdvancesIsOneActivity`; holding it to a number measured on
`NoAuthorizationBypass` would be a red for the wrong reason.

What the profile also says, and it is not flattering: **every one of the thirty
security configurations fires with a single relying party**, including both
registration-order mutants. The module asks for `RPs >= 2` "to exercise rpId
binding" and no mutant in the roster backs that. The record says 1 rather than
repeating the claim. Above two, nothing in the roster probes at all — a minimum
equal to the shipped value means "nothing here looks higher", never "higher is
safe".

**4. An expected verdict per configuration**, which catches the other silent
pass: a mutant that stops firing. `BugSetPinKeepsPpuat` explored **40 459 667
states without a counterexample** after a fix made its defect unreachable, and
the only thing that noticed was a human reading the matrix. Every `Mut_*`,
`Solo_*` and every module's mutant/solo rows must be RED; every named baseline
(`Shipped`, `Seams`, `Store`, `Lattice`, `Policies`, `Admin`, `Display`, `Boot`,
`Transport`) plus `Fairness` and `Liveness` must be GREEN. `run-tlc.sh` exits 1
on any row that is not.

Measured end to end on E164 itself, with the parentheses taken back out:

| Net | Verdict | Exit |
|---|---|---|
| `tla-lint.py` | 2 findings, named by line | **2** |
| floor + expectation, with the lint hook removed so nothing else can see it | `VACUOUS: nothing was enabled  !! expected GREEN` | **1** |
| the tree as it stood when E164 happened | `GREEN` | 0 |

And on E171's shape, a mutant config with its switch turned off:
`GREEN … !! expected RED`, exit 1.

Those cases are no longer only a dated experiment. `scripts/test_run_tlc.py`
feeds controlled TLC output through the real runner and its real floors on
every merge gate. It keeps the four roadmap corruptions (broken jar, missed
Solo invariant, one-state VACUOUS and a muted Mut switch), plus direct RED and
FLOOR cases; each must produce its named non-zero verdict.

`floors.txt` also carries the **per-config heap**. `Liveness.cfg` runs out of
memory at the 4 GB default *after* its state search completes, which had left
`./run-tlc.sh all` reporting a red row for a property that is true.

**5. The configurations against their generator** (`scripts/config_gen_gate.py`,
the `generated TLC configs` row). 187 of the 188 `.cfg` files open with
"Generated by formal/gen-configs.sh -- do not edit by hand", and until that row
nothing made the sentence true. Two edits were silent, and the first was
measured by a reviewer, not imagined: **delete all three
`BootCarryMut_*.cfg` and every gate row stays green**, because
`assurance_gate.check_tiers` compares what `run-tlc.sh --tiers` lists against
what `formal/` holds — and the tiers name whole families with `ls`, so `tiered`
and `present` shrink together. Flipping a constant inside a generated file was
equally silent. The row regenerates into a temp directory and diffs, which is
why `gen-configs.sh` now takes an output directory; a missing file, a
hand-edited file and a generator changed without regenerating are one finding
here, because all three mean the committed matrix is not the one the generator
describes. Falsified through the row itself, exit codes taken with no pipe:

| Mutation | What the row said | Exit |
|---|---|---|
| the tree as it stands | `187 generated configuration(s) reproduce byte-for-byte, 1 hand-written` | 0 |
| one `BootCarryMut_*.cfg` deleted | `… writes it and formal/ does not have it` | **1** |
| `MaxWeak = 2` → `1` inside one generated file | `differs … line 5: generator writes '    MaxWeak = 2', the tree has '    MaxWeak = 1'` | **1** |
| the same edit made in the *generator* instead | 13 rows `differs …` — every `Boot*` configuration | **1** |
| a new family emitted, nothing regenerated | `BootProbe.cfg: … runs nothing` | **1** |
| an unregistered `.cfg` added by hand | `neither generated nor registered hand-written` | **1** |
| `TokenExport.cfg` (the one hand-written file) deleted | `registered hand-written but no such file — stale entry` | **1** |
| `TokenExport.cfg` given the generated header | `tells its next reader not to edit the one file they may` | **1** |
| the generator made to die mid-run | `formal/gen-configs.sh exited 1: <its stderr>`, and nothing else | **1** |
| the generator made to write nothing | `wrote 0 configurations, under the floor of 100` | **1** |
| the header rewritten in the generator, tree regenerated to agree | 187 rows `writes it without the … header` | **1** |
| `TokenExport.cfg` generated as well as carved out | `registered hand-written but … writes it` | **1** |
| one generated file rewritten with CRLF | `line 1: …` — bytes, not decoded text | **1** |
| its final newline removed | `every line they share is equal; … 12 part(s) … 11` | **1** |

The last four are the first review's, and the first two of them are the family
this tree keeps shipping: **the header rule ran in one direction only.** The row
is named after making "do not edit by hand" true and it asked that question of
the ONE hand-written file, never of the 187 — rewrite the generator's header,
regenerate, and every configuration stopped telling its reader anything while the
row said ok. The `HAND_WRITTEN` docstring promised both directions and the second
was not implemented at all. Neither was reachable from the ten cases above,
because each of those mutates the *tree* and both of these live in the generator.

What it deliberately does not catch: a family deleted from `gen-configs.sh`
*and* from `formal/` in one commit. That is a visible diff in the file whose
whole content is the roster, and a guard cannot tell a deletion from a decision.
And it says nothing about `floors.txt`, which carries two of the five defences
above — flip `Mut_*.cfg RED` to `GREEN` there and every mutant row's expectation
is disarmed with no gate row the wiser. That is the largest remaining instance of
this family in `formal/`, measured by the same review, and it wants a guard of
its own rather than a rule bolted onto this one.

### And the citations the row did not read — 19 of 42

`scripts/citation_gate.py` held the `formal/` pages and nothing else, and the
same claim is written twice in this tree. The three token-gate call sites are
cited on `formal/README.md` **and** in the Kani proof headers that drive them,
and only the gated copy had followed the code:

| Call site | `formal/README.md` | `state_kani.rs` / `credmgmt_kani.rs` | out by |
|---|---|---|---|
| getAssertion's UV gate | `getassertion.rs:384-387` | `376`–`379` — the zero-length-probe error mapping | 8 |
| authenticatorConfig's gate | `config.rs:243-245` | `222-224` — a comment about `pinUvAuthProtocol: 0` | 21 |
| credentialManagement's gate | `credmgmt.rs:278`, the item | `277` — the doc comment line `/// has been located.`, repaired to `284`, the condition | 7 |

The worst was 79: "the dispatch prologue every CBOR command runs first
(`lib.rs` line 207)" pointed at `out[0] = CTAP2_OK;`, the response *epilogue*. Read by
hand against the code, the 42 code citations came out **13 correct, 9 with a
drifted endpoint, 1 unresolvable by construction** (a line number with no
filename in front of it, which no rule can bind) **and 19 naming something the prose was never
about**. All 29 are re-pointed; the gate reads them now.

A second review round found four more of the same family, and two of them were
in the thirteen this pass had called correct: `state.rs` lines 327-332 and
355-359 open on the last line of the *previous* field's doc comment,
carry the wrong field's declaration, and stop before the one their sentence
names. The oracle that found them is worth keeping — *first cited line is a
comment whose predecessor is also a comment, and the last is a comment whose
successor is also a comment* — it flagged three of the 42 and two were real.
Repaired to `329-335` and `357-361`. The other two are outside the read set and
were rotted anyway: `docs/guides/fips.md` cited the RSA-1024 **import** gate
~355 lines off (a `drop_slot_meta` doc comment), and
`assurance/assumptions.toml` named `pin_lock.rs` line 52, the `Refines` line,
for a write two lines below it.

The code half is **derived**, not named: any tracked `.rs` under `crates/`,
`firmware/` or `fuzz/` that cites by line is a page, so the next proof header
does not have to be added to a tuple to be checked. What ratchets it is the same
lock the model pages use — a page that stops being read turns every entry it had
into a named orphan — and `CODE_PAGES_FLOOR` catches the derivation finding
nothing at all. Deliberately outside: `CHANGELOG.md`, whose entries cite the tree
as it stood and **must** be allowed to rot; the guard's own fixtures, which name
files that exist only inside a fixture; and `docs/guides/fips.md`, which writes
`piv/keygen.rs` line 48, a path fragment that resolves to nothing.

### And the dead-action check, which is the vacuity question

An action that never fires makes every clause guarding it free — the same
question `kani::cover!` answers on the Kani side, and one this page has been
promising to re-run since the model had 41 actions. `COVERAGE=1 ./run-tlc.sh
<cfg>` asks TLC for the per-action firing counts and refuses on a zero:

```console
$ COVERAGE=1 ./run-tlc.sh Seams.cfg
run-tlc: DEAD ACTION in Seams.cfg -- never fired: NeverEnabled
```

Mutation-tested both ways on the seam module: an action written to be
unreachable is named and the run exits 1; the module as it stands fires **20 of
20** and exits 0. It is opt-in because coverage costs wall clock, and the FIDO
module's 61 M states have **not** been swept this way — that measurement is one
command and is still owed.

### A bit-identical count is only the signature when *generated* rises

The strongest evidence in three rounds of this exercise has been "the reachable
state count did not move" — and this round it produced a false positive, which is
worth more than another true one. `~(gate.alwaysUv /\ ~pin.set)` removed came
back at 813 099 753 generated / 61 215 504 distinct: identical in **both**
numbers. That is a conjunct that removed **zero transitions** — redundant, not
unwatched.

The two real findings are identical in *distinct* and higher in *generated*:
`LocalCeremonyStart` +39.7 M, `PgpSetPwStatus` +280. So the rule is: **equal
distinct with more generated** means the mutant took steps nobody recorded;
**equal distinct with equal generated** means the mutant took no step at all.
Reading the distinct column alone would have scored the inert conjunct as the
strongest result in the set.

## Traceability — measured, not asserted

One property should be greppable from its model to the Rust that owns it, the
mutants that challenge it, and every stronger evidence layer that exists. The
registry stores only the requirement; `scripts/assurance_gate.py` derives the
evidence columns and validated cross-model support edges below on every gate run.

<!-- assurance-table:start -->
<!-- Generated by scripts/assurance_gate.py --write-readme; do not edit. -->
| ID | Property | Status | Model | Support | Rust | Mutants | Co-refuted | Kani | Fuzz | Runtime |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| `SEC-REF-001` | `R1sTokenStateRefinement` | MODELLED-ONLY | `RSKeyTokenRefinement` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-REF-002` | `R1oTokenOutcomes` | MODELLED-ONLY | `RSKeyTokenRefinement` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-REF-003` | `R1oOutcomeCoverage` | MODELLED-ONLY | `RSKeyTokenRefinement` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-REF-004` | `R4bEventConsensus` | MODELLED-ONLY | `TraceSecurity` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-FIDO-001` | `NoAuthorizationBypass` | BOUNDED | `RSKeySecurityState` | — | 2 | 9 | 9 | 1 | 0 | 0 |
| `SEC-FIDO-002` | `NoCrossTransportTouchConsumption` | BOUNDED | `RSKeySecurityState` | — | 2 | 5 | 5 | 2 | 0 | 0 |
| `SEC-FIDO-003` | `NoTokenAfterInvalidation` | BOUNDED | `RSKeySecurityState` | — | 3 | 7 | 6 | 2 | 1 | 0 |
| `SEC-FIDO-004` | `NoAccessibleSecretWithoutGate` | MODELLED-ONLY | `RSKeySecurityState` | `RSKeyStore` | 2 | 2 | 1 | 0 | 0 | 0 |
| `SEC-FIDO-005` | `NoUnmanageableCredential` | MODELLED-ONLY | `RSKeySecurityState` | `RSKeyStore` | 3 | 3 | 3 | 0 | 0 | 0 |
| `SEC-FIDO-006` | `ResetNeverWeakensSurvivingState` | BOUNDED | `RSKeySecurityState` | — | 3 | 3 | 2 | 1 | 1 | 1 |
| `SEC-FIDO-006A` | `ResetKeepsThePinGate` | BOUNDED | `RSKeySecurityState` | — | 0 | 1 | 0 | 1 | 1 | 1 |
| `SEC-FIDO-006B` | `ResetKeepsTheAlwaysUvGate` | BOUNDED | `RSKeySecurityState` | — | 0 | 1 | 0 | 1 | 1 | 1 |
| `SEC-FIDO-006C` | `ResetKeepsTheBackupSeal` | BOUNDED | `RSKeySecurityState` | — | 0 | 1 | 0 | 1 | 1 | 1 |
| `SEC-FIDO-007` | `RamNeverOutlivesFlashSeed` | MODELLED-ONLY | `RSKeySecurityState` | — | 1 | 1 | 0 | 0 | 0 | 0 |
| `SEC-FIDO-008` | `NoLiveTokenWithoutPinRecord` | MODELLED-ONLY | `RSKeySecurityState` | — | 1 | 1 | 0 | 0 | 0 | 0 |
| `SEC-FIDO-009` | `OpAdvancesIsOneActivity` | MODELLED-ONLY | `RSKeySecurityState` | — | 0 | 1 | 0 | 0 | 0 | 0 |
| `SEC-FIDO-L01` | `EveryOpQuiesces` | MODELLED-ONLY | `RSKeySecurityState` | — | 0 | 1 | 0 | 0 | 0 | 0 |
| `SEC-FIDO-L02` | `EveryWaitReleases` | MODELLED-ONLY | `RSKeySecurityState` | — | 0 | 1 | 0 | 0 | 0 | 0 |
| `SEC-FIDO-L03` | `EveryWalkCloses` | MODELLED-ONLY | `RSKeySecurityState` | — | 0 | 1 | 0 | 0 | 0 | 0 |
| `SEC-TRACE-001` | `R4aRawRefinesB` | MODELLED-ONLY | `TraceSecurity` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-TRACE-002` | `R4bAlphaMatchesGamma` | MODELLED-ONLY | `TraceSecurity` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-TRACE-004` | `R4cGateAnswers` | MODELLED-ONLY | `TraceSecurity` | — | 0 | 0 | 0 | 0 | 0 | 0 |
| `SEC-SEAM-001` | `NoStatusOutsideItsSelection` | MODELLED-ONLY | `RSKeyAppletSeams` | — | 1 | 2 | 1 | 0 | 0 | 0 |
| `SEC-SEAM-002` | `NoStatusAfterARefusedAuth` | MODELLED-ONLY | `RSKeyAppletSeams` | — | 1 | 2 | 2 | 0 | 0 | 0 |
| `SEC-SEAM-003` | `NoKeyOpOnTheAdminStatus` | MODELLED-ONLY | `RSKeyAppletSeams` | — | 1 | 6 | 5 | 0 | 0 | 0 |
| `SEC-SEAM-004` | `ReselectPreservesAccessStatus` | MODELLED-ONLY | `RSKeyAppletSeams` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-SEAM-005` | `ExemptRefusalPreservesStatus` | MODELLED-ONLY | `RSKeyAppletSeams` | — | 1 | 2 | 2 | 0 | 0 | 0 |
| `SEC-SEAM-006` | `AccessCodeRemovalNeedsTheCode` | MODELLED-ONLY | `RSKeyAppletSeams` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-STORE-001` | `NoOrphanedMetadata` | MODELLED-ONLY | `RSKeyStore` | — | 2 | 2 | 2 | 0 | 0 | 0 |
| `SEC-STORE-002` | `NoFalseAbsent` | BOUNDED | `RSKeyStore` | — | 2 | 2 | 2 | 3 | 0 | 0 |
| `SEC-STORE-003` | `NoRecordLostToMetaWrite` | MODELLED-ONLY | `RSKeyStore` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-STORE-004` | `NoFalseMetaAbsent` | MODELLED-ONLY | `RSKeyStore` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-STORE-005` | `CacheHonest` | MODELLED-ONLY | `RSKeyStore` | — | 1 | 0 | 0 | 0 | 0 | 0 |
| `SEC-LAT-001` | `NoAuthWhenBlocked` | MODELLED-ONLY | `RSKeyRetryLattice` | — | 2 | 1 | 1 | 0 | 0 | 0 |
| `SEC-LAT-002` | `WrongAttemptIsCharged` | MODELLED-ONLY | `RSKeyRetryLattice` | — | 2 | 1 | 1 | 0 | 0 | 0 |
| `SEC-LAT-003` | `BudgetRisesOnlyWithItsSecret` | MODELLED-ONLY | `RSKeyRetryLattice` | — | 2 | 1 | 1 | 0 | 0 | 0 |
| `SEC-POL-001` | `PivOperationNeedsSlotPolicy` | MODELLED-ONLY | `RSKeyAppletPolicies` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-POL-002` | `PivAlwaysSpendsFreshness` | MODELLED-ONLY | `RSKeyAppletPolicies` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-POL-003` | `AttributeChangeInvalidatesTheKey` | MODELLED-ONLY | `RSKeyAppletPolicies` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-POL-004` | `OathCredentialNeedsItsGates` | MODELLED-ONLY | `RSKeyAppletPolicies` | — | 1 | 2 | 2 | 0 | 0 | 0 |
| `SEC-POL-005` | `OtpSlotMutationNeedsItsCode` | MODELLED-ONLY | `RSKeyAppletPolicies` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-POL-006` | `OtpCounterNeverRepeats` | MODELLED-ONLY | `RSKeyAppletPolicies` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-ADM-001` | `AdminSurfaceAlwaysReachable` | MODELLED-ONLY | `RSKeyAdminSurface` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-ADM-002` | `PrivilegedOpNeedsPresence` | MODELLED-ONLY | `RSKeyAdminSurface` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-ADM-003` | `DisableSetSurvivesLockWrite` | MODELLED-ONLY | `RSKeyAdminSurface` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-ADM-004` | `DisabledAppletNeverDispatches` | MODELLED-ONLY | `RSKeyAdminSurface` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-DISP-001` | `ConfirmNamesTheOperation` | MODELLED-ONLY | `RSKeyTrustedDisplay` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-DISP-002` | `StaleTouchApprovesNothing` | MODELLED-ONLY | `RSKeyTrustedDisplay` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-DISP-003` | `OnlyAllowConfirms` | MODELLED-ONLY | `RSKeyTrustedDisplay` | — | 1 | 1 | 1 | 0 | 0 | 0 |
| `SEC-BOOT-001` | `MarkerNeverLies` | MODELLED-ONLY | `RSKeyBootHardening` | — | 1 | 2 | 0 | 0 | 0 | 0 |
| `SEC-BOOT-002` | `TheWholeLockRides` | MODELLED-ONLY | `RSKeyBootHardening` | — | 1 | 1 | 0 | 0 | 0 | 0 |
| `SEC-TRANS-001` | `NoCrossChannelSplice` | BOUNDED | `RSKeyTransport` | — | 1 | 1 | 1 | 2 | 0 | 0 |
| `SEC-TRANS-002` | `NoSequenceGap` | BOUNDED | `RSKeyTransport` | — | 1 | 1 | 1 | 1 | 0 | 0 |
| `SEC-TRANS-003` | `NoBufferOverrun` | BOUNDED | `RSKeyTransport` | — | 2 | 1 | 1 | 1 | 0 | 0 |
| `SEC-RISK-001` | `PerDeviceAttestationCertIsACorrelationHandle` | ACCEPTED-RISK | — | — | — | — | — | — | — | — |
| `SEC-RISK-002` | `FlashSnapshotRollsBackPinRetries` | ACCEPTED-RISK | — | — | — | — | — | — | — | — |

### Workspace coverage ledger — generated

| Crate | Class | Model / evidence | Named gap / disposition |
|---|---|---|---|
| `firmware` | embedded-binary | — | no_std binary: boot, worker sequencing, board halves of Hooks/Platform. The boot path's cross-boot state — the EF_HARDENED lap and scratch-word lock carry — is RSKeyBootHardening (M7), precisely because this crate has no host tests; the FIDO state it builds is reconstructed host-side in rsk-device (ctap.rs:76-87). Worker scheduling and USB bring-up remain implementation mechanics, with transport state owned by RSKeyTransport. |
| `rsk-bench` | out-of-scope | — | latency statistics for the on-device harness; not part of the security argument. |
| `rsk-bip39` | pure | `crates/rsk-bip39/src/kani.rs` | — |
| `rsk-crypto` | pure | `crates/rsk-crypto/src/base64url_kani.rs`<br>`fuzz/fuzz_targets/aes_gcm.rs`<br>`fuzz/fuzz_targets/chachapoly.rs` | — |
| `rsk-devconf` | state-partial | `RSKeyAdminSurface` | the enabled-set lifecycle is modelled (mask writes, the lock-code-only write, the clamp as a construction). This crate DOES touch flash — it owns EF_DEV_CONF end to end (validate, merge onto the stored record, trim to cap, put) and the DEV_CONF_DIRTY latch the composition roots drain to reload their cached mask; who may drive a write is the four callers' gate, not this crate's. The TLV codec itself — well-formedness, merge widths, the two-parsers refusal — is single-step and carried by the crate's tests; still zero Kani proofs. |
| `rsk-device` | state-partial | `RSKeySecurityState` | presence arbitration is modelled and Kani-proved; capability gating is RSKeyAdminSurface. Dispatcher selection/reset semantics are RSKeyAppletSeams; the remaining fast-path wiring is single-dispatch glue rather than a separately modelled state machine. |
| `rsk-display` | state-partial | `RSKeyTrustedDisplay` | the confirm ceremony (WhatIsConfirmedIsWhatIsShown, decomposed as SEC-DISP-001..003) is modelled; the wait owner and the fourth PIN door stay in RSKeySecurityState. The menus, settings flows and the device-PIN screens are navigation over that same armed-touch chokepoint, not separate security state. |
| `rsk-ec` | pure | `crates/rsk-ec/src/tests.rs`<br>`crates/rsk-ec/src/key_tests.rs`<br>`crates/rsk-ec/src/key_x25519_tests.rs`<br>`crates/rsk-ec/src/key_bp_kat.rs`<br>`crates/rsk-ec/src/curve_tests.rs`<br>`crates/rsk-ec/src/pubdo_tests.rs` | — |
| `rsk-fido` | state-modelled | `RSKeySecurityState` | — |
| `rsk-fs` | state-partial | `RSKeyStore` | the committed store, the delete write-order and the present-cache soundness are modelled (M3 lifted powercut_model.rs to TLA+ and ties R0p to it); phase 6 composes the FIDO reset projection with delete_landed and the real byte-cuttable Fs stack. Values are still two opaque tokens, so a content-corrupting defect is out of reach, and Fs::factory_wipe's two-phase sweep remains the security module's ordering (SeedLeadsTheWipe), not this one's. |
| `rsk-led` | pure | `crates/rsk-led/src/kani.rs` | — |
| `rsk-mgmt` | state-partial | `RSKeyAdminSurface` | what is left after the EF_DEV_CONF codec moved to rsk-devconf: the CCID command surface (INS 0x1C/0x1D/0x1E/0x1F), the strict-config presence gate on WRITE CONFIG, and the process-global DEVICE_RESET latch the firmware drains after the SW_OK. AdminSurfaceAlwaysReachable models this applet as the always-on carve-out; the wipe the latch requests is the firmware's own factory_wipe, which this crate cannot observe, and the applet holds no flash state of its own. |
| `rsk-mldsa` | pure | `crates/rsk-mldsa/src/round_kani.rs`<br>`fuzz/fuzz_targets/mldsa_roundtrip.rs`<br>`fuzz/fuzz_targets/mldsa_verify.rs` | — |
| `rsk-oath` | state-partial | `RSKeyAppletSeams` | status lifetime and access-code removal are RSKeyAppletSeams; calculation's access-code and touch gates are RSKeyAppletPolicies. The MAC access code has no retry budget, so its byte-level mutual-auth acceptance remains differential-oracle territory rather than a fabricated lattice counter. |
| `rsk-openpgp` | state-partial | `RSKeyAppletSeams` | status lifetime is RSKeyAppletSeams; PW1/PW3/RC budgets are RSKeyRetryLattice; algorithm-attribute changes invalidating the old key pair are RSKeyAppletPolicies. MSE repointing and the per-slot UIF value space remain below the abstraction. |
| `rsk-otp` | state-partial | `RSKeyAppletSeams` | oathOtpPin status is in RSKeyAppletSeams; protected-slot configure/update/delete/swap and the combined use/session anti-replay step are RSKeyAppletPolicies. The six-byte slot code has no retry counter; four physical slots collapse to one symmetric lifecycle in the model. |
| `rsk-phy` | pure | `crates/rsk-phy/src/kani.rs`<br>`fuzz/fuzz_targets/phy_tlv.rs` | — |
| `rsk-piv` | state-partial | `RSKeyAppletSeams` | status lifetime is RSKeyAppletSeams; PIN/PUK budgets are RSKeyRetryLattice; NEVER/ONCE/ALWAYS slot policy and freshness spending are RSKeyAppletPolicies. Key material and touch I/O stay below these state abstractions. |
| `rsk-rescue` | state-partial | `RSKeyAdminSurface` | the operator-presence gate on every privileged command is modelled (PrivilegedOpNeedsPresence); the commands' own payloads — the phy identity record (its codec is rsk-phy now), KEYDEV signing, the fuse/rollback state machines — are single-step data handling carried by the crate's four test files, not a state machine. |
| `rsk-rsa` | pure | `crates/rsk-rsa/src/kani.rs` | — |
| `rsk-sdk` | state-partial | `RSKeyAppletSeams` | Dispatcher::current is the seam module's sel. APDU command chaining remains outside RSKeyTransport, which covers CTAPHID framing rather than the SDK's per-applet chain buffer. |
| `rsk-sha512` | pure | `fuzz/fuzz_targets/sha512_diff.rs` | — |
| `rsk-slip39` | pure | `crates/rsk-slip39/src/kani.rs`<br>`crates/rsk-slip39/src/tests.rs` | — |
| `rsk-store` | state-partial | `RSKeyStore` | the Storage contract it implements — atomic append, an enumeration-completeness flag — is taken as RSKeyStore's backend assumption; the two-partition counter/main ring, is_counter_fid routing, wear and page reclaim, and compact are backend mechanics the model abstracts. |
| `rsk-ui` | state-partial | `RSKeyTrustedDisplay` | hit_confirm's disjoint Allow/Deny zones are the modelled seam (OnlyAllowConfirms's Rust owner); rendering, fonts and the settings codec are pure functions under their own 12 Kani proofs and render tests — no screen-transition state lives in this crate (the ceremony state machine is rsk-display's). |
| `rsk-usb` | state-partial | `RSKeyTransport` | the CTAPHID reassembler's channel/sequence/length state machine is modelled (M8); the async transport loop's bounded-write liveness (the 0x075D wedge fix) is guarded by the FrameSink seam's own mutation-tested regression, and the CCID/keyboard framing and secure_pin codec are single-step, Kani-proved and unit-tested. |
| `rsk-vendor` | state-partial | `RSKeySecurityState` | ConfigOp/plat in the security model; the config-write pipeline it shares with rsk-devconf (persist_dev_conf) is RSKeyAdminSurface now. Still open: UNLOCK is modelled wider than its real gate (mse_ready + lock_engaged). |
| `rsk-wipe` | out-of-scope | — | flash-erase utility, runs once in a maintainer's hands; not part of the runtime security argument. |
<!-- assurance-table:end -->

`python scripts/assurance_gate.py --write-readme` regenerates the table. The
ordinary gate refuses a stale block, so this published view and the tree cannot
drift independently. A non-zero cell means that evidence names the property;
it does not promote MODELLED-ONLY to a proof or turn bounded Kani into PROVEN.

## Abstractions — where the model deliberately departs from the firmware

**This section used to open by claiming every abstraction here admits *more*
behaviour than the firmware, "which is sound for safety". That was false**, and
the one that broke it was holding the green run up: `PowerCut` left the seed as
the cut found it, while the firmware regenerates a missing seed on **every**
boot (`firmware/src/main.rs:613`, `tools/emu/src/device.rs:264`). A cut device
was permanently seedless in the model and could never hold a usable credential
again — the model was *narrower* than the code, which is the one direction a
safety argument cannot absorb. It is fixed (`BootEnsuresSeed`), and every
departure is now listed **with its direction**.

Read a counterexample back against the code before believing it either way: two
of the three modelling artifacts caught while building this were wider-than-code
abstractions producing traces the firmware cannot follow.

### Wider than the firmware — sound for safety, noisy for counterexamples

- **Time is nondeterminism.** Token expiry (`PUAT_INITIAL_USAGE_LIMIT_MS` /
  `PUAT_MAX_USAGE_PERIOD_MS`), the stateful-walk idle window and the presence
  timeout are actions enabled at any moment rather than clocks. Only the reset
  window uses the coarse `clock`, because its *boundary* is the property.
- **`WarmReset` is enabled mid-sequence**, which the synchronous worker would
  not permit; `PowerCut` reaches the same flash states and is the realistic
  interrupter.
- **`BackupFinalize` is ungated.** The real `BACKUP_FINALIZE` carries the PIN
  half of the gate and a deliberate hold (`vendor.rs:895-907`). Widening where
  the marker can be **set** never widens where it can be **lost**, and the loss
  is what the invariant is about.
- **A regenerated seed still opens the credentials made under the old one.**
  `store.seed` is one boolean, so the model cannot tell the owner's seed from
  the one a boot minted after a torn wipe; in the firmware those credentials are
  cryptographically dead. The reset snapshot's `snap.seed` *does* make that
  distinction, but only for the backup-marker clause.
- **The order within a sweep phase is arbitrary.** `for_each_key` yields in
  flash-ring order (`fs.rs:253-256`), which is *a* fixed order per device state,
  not a free choice. Both findings below need only that some reachable ring
  order puts one delete before another.
- **`DeviceUnlock` is ungated and needs no device lock.** The real vendor
  `UNLOCK` (`vendor.rs:549-572`) requires the seed to be stored *wrapped* — only
  a soft-locked device has an `EF_KEY_DEV_ENC` to open — and the host to present
  the 32-byte lock key. The model requires only a live flash seed. It also omits
  `AUT_DISABLE` (`config.rs:417-418`), which only ever *clears* the RAM copy.
  Both widen where `ram` can be TRUE, never where it must be FALSE, and it is
  the RAM copy **surviving** that the invariant is about.
- **`ResetAborts` fires at any of the wipe's three positions** and models every
  `?` in `reset.rs:65-70` as one transition — a `force_delete` error, a truncated
  `for_each_key` (`reset.rs:97-101`), the `RESET_MAX_DELETES` backstop, a failed
  `ensure_seed`. Which of them a real device can be made to hit, and by whom, is
  not modelled: the abort is available unconditionally, which is the sound
  direction and is why the counterexample it produces is about the *strength of
  the ordering*, not a reachable attack.

### Narrower than the firmware — the risk direction, and the whole list

Anything here can hide a real defect, so each one is a standing question rather
than a settled abstraction.

- **One credential per relying party**, `MAX_RESIDENT_CREDENTIALS` = 2 rather
  than 256, two RPs, two channels. The retry pair is **no longer** narrower:
  `MaxRetries` : `MismatchLimit` is the shipped 8 : 3 now, bought with symmetry,
  so "a defect that needs the sixth retry" is in reach and finds nothing. What
  remains narrow is the cardinality: a defect needing a third credential or a
  third channel is still out of reach, and `formal/scopes.txt` records what the
  roster actually needs — two channels (`BugCmWalkIgnoresChannel` is GREEN at
  one), and, measured rather than assumed, **one** relying party, which every
  mutant here fires at. Nothing in the roster probes above two anywhere. That is
  a measurement of the roster, not a proof about defects it does not contain.
- **Permission sets are the five a host actually requests**, not all 16 subsets
  (`PermSets`); `largeBlobWrite` is modelled as the empty set that
  `consume_after_user_presence` leaves behind. A defect reachable only from an
  unusual permission combination is not modelled.
- **The wait's scope is modelled as the owner of an open touch wait**, where the
  worker sets it around the whole dispatch (`Arbiter::set_wait_scope`). The
  review showed this is exactly as narrow as it sounds: the cancel is dropped at
  **both** ends of a wait (`crates/rsk-device/src/presence.rs:196` *and*
  `:230`), so removing either alone leaves the model green — a reviewer trusting
  one citation would see nothing fall. The Kani harness has the same blind spot
  and says so; the unit test `w8_…` is what pins the drop at exit.
- **The button build only** (`presence.shows_confirm() = FALSE`), so the reset
  window always applies; a display build bypasses it by design (`reset.rs:32`)
  and that path is unmodelled.
- **A registration with a PIN set and no token is not a behaviour of `Next`.**
  CTAP 2.1 §6.1.2 steps 7/10 serve a NON-discoverable credential on presence
  alone even where a PIN is set (`makecredential.rs:540-546`). `RegisterStart`
  conjoins `OpGuard("mc", r)`, which is `TRUE` when `~UvRequired` — so the model
  does explore a token-less registration on a PIN-less key, and never the
  carve-out itself, which is exactly the region a defect in it would live in. The
  rule is stated and checked, but only against a recorded session
  (`TraceSecurity!McTokenlessRefused`, R4c); the replay is what made the gap
  visible, and folding it into `Next` is the widening it argues for.
- **`largeBlobs`, `getNextAssertion`, the MSE seed-backup channel, built-in UV
  and the trusted-display flows are absent.** They carry their own
  channel-ownership rules (`state.rs:33-51`, `:326-333`) that this model does
  not check — the most obvious place to extend it.
- **Two transports** (CTAPHID, CCID). `SCOPE_OTP` and the on-panel
  `SCOPE_NONE` ceremonies are not modelled.
- **OATH's access-code REMOVAL is modelled now — CLOSED, and the closure proves
  the diagnosis.** The hole stood recorded for two revisions: an ungated removal
  is *definitionally* invisible to `NoStatusOutsideItsSelection`, whose
  `oathCode` exemption fires exactly when `~oathCodeSet` — the very state the
  removal produces. The repair is therefore a recorder at the STEP, not a change
  to the exemption: `OathRemoveCode` carries the gate
  (`crates/rsk-oath/src/lib.rs:327-329`) as a Guard/Policy pair and
  `AccessCodeRemovalNeedsTheCode` is its own invariant. Measured exactly as the
  diagnosis predicted: the action adds no new kind of state, while
  `BugRemoveCodeUnvalidated` falls RED in 71 — a violation no state
  predicate could ever have seen, caught by the step recorder.
- **The two assignment-shaped holes are closed.** `NoKeyOpOnTheAdminStatus`
  now asserts `fresh = pfresh` and, while OpenPGP is selected under one-shot
  PW1, `held["pw1"] = psig`. `BugPinFreshOutlivesPin`,
  `BugPinFreshNotSpent` and `BugSigPinNotSpent` therefore fall structurally in
  42, 45 and 212 distinct states; they no longer depend on their own `viol`
  assignment to report the defect.
- **Three of `is_fido_gate_fid`'s FIVE records are modelled** — `EF_PIN`,
  `EF_ALWAYS_UV` and `EF_BACKUP_SEALED`. `EF_DEVICE_PIN` and `EF_MINPINLEN` are
  absent. It was six until `eab4b5c` moved `EF_PAUTHTOKEN` out: the predicate's
  own rule is "records whose *absence* is permissive", a grant is a permission,
  so its absence is restrictive, and it was the one member that never met the
  rule. It is a secret here now, swept in phase 1.

### Liveness — three properties, and what is deliberately NOT asserted

`Spec` is still safety-only; `FairSpec` adds weak fairness on three things and
`Liveness.cfg` checks `EveryOpQuiesces`, `EveryWaitReleases` and
`EveryWalkCloses` against it. The fairness is the load-bearing part, because an
assumption the implementation does not honour makes its property meaningless:
the synchronous worker (`worker.rs:646-669`) never parks a sequence, the
presence wait carries `PRESENCE_TIMEOUT_MS` (`crates/rsk-device/src/presence.rs:215-216`), and
`expire_stale_sequences` (`state.rs:620-626`) retires an idle cursor. Nothing
else is fair — not a press, a release, a host cancel, a power cut, a warm reset
or any `*Start` — because assuming a user eventually touches or a device is
eventually replugged would prove liveness the device does not have.

That is why **`lock.soft ~> ~lock.soft` is not asserted.** The soft lock clears
only on a correct PIN or a real power cycle, and neither is the device's to
promise; asserting it would need `WF(PowerCut)`, which is a claim about the user.

### The fairness audit, and the one conjunct that needed checking

`WF_vars(A \/ B)` promises only that **some** disjunct fires, and that is what
E160 was: `LocalCeremonyEnds` folded into `OpAdvances`, so the PIN ladder
discharged the obligation while a panel wait that had taken its confirm sat open
for ever. The repair pulled it out; the reason it mattered stayed a paragraph.
All four conjuncts read against the code:

| Conjunct | Shape | What owes it in the firmware | Verdict |
|---|---|---|---|
| `WF_vars(OpAdvances)` | **18 actions** | the synchronous worker: one `Exchange` at a time, under a lock, dispatch runs to completion (`worker.rs:646-669`) | sound **because** every disjunct is gated on `op.kind` while `Idle` gates every `*Start` — now asserted, not argued |
| `WF_vars(TouchTimeout)` | one action | `PRESENCE_TIMEOUT_MS` (`crates/rsk-device/src/presence.rs:215-216`) | sound |
| `WF_vars(WalkExpires)` | one action | `expire_stale_sequences` (`state.rs:620-626`) | sound |
| `WF_vars(LocalCeremonyEnds)` | one action | the ceremony's own dispatch puts `WAIT_SCOPE` back (`worker.rs:526-528`) | sound — the E160 repair |

`OpAdvancesIsOneActivity == ENABLED OpAdvances => ~Idle` is the first row's
argument as an invariant: if no disjunct can be enabled while the device is
quiescent, then every disjunct that *is* enabled belongs to the single in-flight
`op`, and the promise means what its comment says. GREEN over 7 903 336 distinct
states at the liveness constants, for about 5% more wall clock than the plain
safety run — eighteen `ENABLED` evaluations per state are cheap.
`BugFairnessFoldsLocalCeremony` is E160 verbatim and falls in **36 distinct
states at depth 4**, where the liveness layer needed 423 900 states and a
temporal check to see the same defect.

One thing the audit turned up that is a statement rather than a repair:
`OpAdvances` includes `ResetAborts`, which the firmware promises nothing about.
It is harmless because it is never the *only* enabled disjunct — `ResetSweepSecrets`
and `ResetSweepGates` are enabled at every step where the abort is, both having
an `ELSE` branch that advances — so `WF` over the disjunction never rests on it.

### The liveness layer had outgrown its heap, and `floors.txt` is the one line

`Liveness.cfg` runs at **smaller constants than the safety matrix** — one relying
party, one channel, `MaxRetries` 2 : `MismatchLimit` 1 — and the reduction is a
parameter of the same generator function, not a hand-edited file. Two rounds ago
that config was 805 268 distinct states in 118 s, against `Liveness_Full.cfg`'s
6 664 764 in 1475 s: a measured 15.7× for the same verdict, which is why the
routine configuration is the small one.

It is **7 903 336 distinct states now**, and the state graph is no longer the
cost. TLC builds a behaviour graph on top of it — **23 710 008 nodes** — and at
`run-tlc.sh`'s default 4 GB heap the final temporal check **runs out of memory**
after 1500 s, with the state search already complete. So the reduced constants
are no longer reduced enough — but the ceiling is the JVM's rather than TLC's,
and **`HEAP=12g ./run-tlc.sh Liveness.cfg` is GREEN** over the same 7 903 336
distinct states at depth 43, in **1555 s**. So the three properties do hold at
these constants; what changed is that the routine command no longer established
it.

**`floors.txt` carries that heap per config now**, so the routine command
establishes the verdict again: `./run-tlc.sh all` runs `Liveness.cfg` at 12 GB
and it is **GREEN over 7 903 336 distinct states at depth 43 in 1591 s**, in the
same matrix run as everything else in the Results table.

`Liveness_Full.cfg`, the same properties over the safety matrix's 61 M states,
was not attempted: the reduced config already needs 12 GB and 27 minutes. Its
floor row carries a 24 GB heap it has never been run at.

The three `LiveMut_*` configs are unaffected either way and all three still fall
on the property that names them in 4 s each — a counterexample search halts long
before the graph is built.

There is still no `SYMMETRY` on `RPs`/`Channels`, which costs time and not
soundness.

## Phase 5: bounded token refinement pilot

`RSKeyTokenAbstract.tla` is tier A; `RSKeySecurityState.tla` is B; production C
is `(FidoState, TokenPersistentView)`. TLC's native `INSTANCE` checks R1s in
`TokenRefinement.cfg`; `TokenRefinementOutcome.cfg` checks R1o separately so a
successful state stutter cannot hide behind `[Next]_vars`. The dead-token
outcome mutant is RED while the corresponding state projection still stutters.

`AllowedEventRel` is A's only relation. `Next` existentially closes it, and
`RSKeyTokenExport.tla` serializes the complete TLA-owned domains and allowed
relation. The host exporter contains no operation list or transition guard.
Codegen currently reports 44 states, 11 operations, 3 outcomes, 63,888 checked
tuples, and 871 allowed edges; the generated Rust self-test exhausts that full
product rather than sampling non-edges.

The lower bridge is bounded: Kani owns R0a/R0p, R2a/R2b, and R3a/R3b harnesses.
`wf_concrete` is an implication premise tested without `kani::assume`, and R2b
establishes that named steps preserve it. The complete InitC, older-firmware
persistent boundary, reset-class evidence table, `EF_ALWAYS_UV` decision, and
the strict scope of the claim are in `docs/token-refinement.md`.

Trace schema 4 adds `outcome_raw` from the response byte, the power-cycle
boundary, and the two request fields §6.1.2's token-less gate is a function of.
R4b-event uses consensus over all inferred B interpretations; it never picks a
convenient witness. It used to answer `AMBIGUOUS` at two boundaries — both a
`makeCredential` for a **non-discoverable** credential, which writes nothing, so
a success and a refusal have identical raw footprints. The note here said
reaching 0 needed a projection field B can also predict rather than a cleverer
inference, and that was right: `rk` is an INPUT, B answers the gate from it and
from its own state, and `R4cGateAnswers` holds the recording to that answer. The
ratchet is `@TraceSecurityAmbiguousMax 0` now. The fifth falsification feeds one
Authorized and one Rejected interpretation for the same boundary and requires
`AMBIGUOUS`, so the shrug is still proven reachable where it belongs.

## Phase 6: cross-reset refinement over `rsk-fs`

`ResetNeverWeakensSurvivingState` now has a concrete phase projection in
`crates/rsk-fido/src/reset_assurance.rs`. It observes the two old-seed records,
one representative credential, PIN, alwaysUv, the backup seal, the RAM seed
copy and token liveness. Deletes are classified by the same
`reset_phase(fid)` function that delegates to production's seed/FIDO/gate
predicates; the proof has no second gate list to drift.

Four Kani harnesses establish initialization and one-step induction across
begin, each relevant delete, guarded phase advances, abort, finish, real reboot
and an unrelated FID. Each clause has its own satisfiable cover and a unit-test
mutant that makes only that clause red. The persistent atomicity assumption is
the existing `rsk-fs::powercut::delete_landed` rule and its Kani proof. The
`power_cut` fuzzer supplies the missing byte-level composition by running the
complete real reset over `SeqStorage`, dropping power inside writes/erases,
rebuilding fresh caches, running boot `ensure_seed`, and mounting again.

The Verus/Creusot decision is **not now**, based on a measured Kani limit. A
direct proof through full `FidoState::reset()` was stopped after 72.45 s while
CBMC expanded at least 398 unrelated `zeroize` iterations. The security-visible
volatile projection solved the parent in 0.52 s and each clause in 0.45–0.48 s
on Kani 0.67.0, all covers reached. That is an abstraction boundary Kani handles,
not an unbounded-state obligation a third verifier would remove.

The exact C→B map, limits, run commands and destructive real-power procedure
are in `docs/reset-refinement.md`. `tests/29_reset_power_cut.py` is intentionally
unsupported by the emulator and requires a maintainer-operated throwaway board;
its existence is not a recorded hardware PASS.


## What MODELLED-ONLY does not mean

The status ladder has three rungs and only one of them looks at code:
`BOUNDED` is set by a Kani harness carrying the property's name. So a property
whose concrete face is covered by an exhaustive unit suite reads identically to
one covered by nothing — and the summary line "42 modelled-only" invites exactly
the wrong conclusion.

Measured, going the other way: **27 of those 42 have a model mutant whose CODE
twin was patched into the real tree and caught by the real suite.** The whole
retry lattice is one example — `NoAuthWhenBlocked`, `WrongAttemptIsCharged` and
`BudgetRisesOnlyWithItsSecret` each carry a driven, killed co-mutant, and driving
five further mutations of `check_ref`'s counter arithmetic by hand killed five of
five, one of them by a test module (`dying_tests`) written for precisely the
glitch the read-back guards. That is not a gap waiting for a bridge; it is
evidence the ladder had no column for.

It has one now. `Co-refuted` is derived by `scripts/assurance_gate.py` from
`formal/comutants.toml`, reusing `comutate.py`'s own invariant lookup rather than
a second copy of it, and counts only entries that patch real code *and* expect the
suite to catch them. Whether a driven code mutant deserves its own rung between
MODELLED-ONLY and BOUNDED is a policy question for the maintainer; the column
states the fact either way, which is the part that was missing.

## Phase 8: the reassembler, and the mutant a proof had to name

`RSKeyTransport` was the eighth module and the ninth to get a code bridge — five
harnesses in `crates/rsk-usb/src/transport_refinement_kani.rs` over a projection
(`transport_assurance.rs`) that reads the real `Reassembler` fields and drives the
real `feed`. What the model counts in chunks the code counts in bytes; that is the
whole abstraction, and `Cap` chunks is `INIT_DATA + Cap * CONT_DATA` here.

`CTAP_MAX_MESSAGE` is `INIT_DATA + 2 * CONT_DATA` under `cfg(kani)` against the
shipped 128 continuations. Unlike the store's shrink this one was not a choice
between fast and slow: at the shipped width CBMC **ran out of memory**, so
bounding the posed pre-state while keeping the 7609-byte buffer was a dead end
rather than a slower road. The definition stays an EXPRESSION, so
`scripts/docs_constants.py` indexes no literal and the 7609 in `docs/protocol.md`,
`docs/interop.md` and the frame diagram is untouched — the coupling the store
pilot walked into an hour earlier. `rsk-device`'s only harnesses are the presence
arbitration and `firmware` does not build under Kani, so the shrink reaches
nothing else. What it stops covering is carried by a compile-time assertion about
the SHIPPED width: the buffer is a whole number of frames, which is what lets an
assembled message land exactly on `bcnt` instead of straddling it.

The five run in 0.18, 1.76, 3.03, 10.94 and 52.3 seconds, so `rsk-usb` stays in
the FAST tier with room.

### The mutant the tests could not reach, and why

Six mutations of `feed`'s guards, and the first pass killed five. The survivor was
the copy bound — `CONT_DATA.min(bcnt - cur)` relaxed to `CONT_DATA` — and the
reason is worth stating, because it is a property of the constant rather than of
the tests: **`CTAP_MAX_MESSAGE - INIT_DATA` divides by `CONT_DATA` exactly.** Every
continuation of a maximum-length message is therefore full, `bcnt - cur` is never
below `CONT_DATA`, and the `min` never bites. The edge test that drives a
full-size message is blind to it by construction.

Kani killed it, on two checks: the projection's own `cur <= bcnt` and a slice-index
panic. Only the first is at a state the machine reaches — a 100-byte message with
`cur = 57` leaves a 43-byte remainder, and without the bound `cur` steps to 116
past a `bcnt` of 100. The panic comes from a posed pre-state the reachable
`cur \in {57, 116, 175, …}` may never occupy. That is sound for a safety claim —
proving over a superset is stronger — but it means a counterexample can be
spurious, and the reachable half is the one that names the defect.

So the fix was a test, not a narrowing: `a_partial_last_frame_advances_by_its_
remainder_and_no_further` drives a message whose last frame is part-full, and the
mutation table is 6 of 6 at the PR gate. This is the first measured case in this
tree of the weekly proof catching what the pull-request suite could not, rather
than restating it.

## Phase 7: the store's cache half, and the FID next door

`RSKeyStore` has seven variables, and five of them were already covered: `val`,
`meta`, `dead`, `metaAbsent` and the FID map are the persistent side, which is
where `powercut.rs`'s four `*_landed` predicates, their Kani proofs and the
`power_cut` fuzz target already live — the module was lifted from them. The
in-RAM pair, `present` and `decided`, had nothing. They are private to `fs.rs`,
so no other crate's test reaches them; no power-cut oracle sees RAM; and their
clauses read as obvious. One of those obvious clauses — a faulted read cached as
a decided absence — is audit run-36, and it shipped.

Six harnesses in `crates/rsk-fs/src/store_refinement_kani.rs` close that half,
one per model action, over a projection (`store_assurance.rs`) that reads the
**real** bitmaps and calls the **real** primitives — a `#[path]` child of `fs.rs`,
so the private methods are reachable without widening them.

The content is the **second symbolic FID** every harness carries. The model says
`[present EXCEPT ![f] = …]` — one element moves, every other stands — while the
code reaches its bit through `fid >> 3` and `1 << (fid & 7)`. A shift that
disagreed would alias two files onto one bit, and a `mark_absent` on one would
read as a decided absence for the other: `NoFalseAbsent`'s disaster reached
through arithmetic instead of through a fault, and invisible to any single-FID
harness.

`FID_PRESENT_BYTES` is 3 under `cfg(kani)` and 8 KiB shipped. That is a measured
decision, not a convenience: at full width the writing harnesses cost 149, 273,
302, 520 and 794 seconds, two of them past `scripts/kani.sh`'s five-minute FAST
cap — whose own rule is to move the crate to SLOW, which would have taxed the
four half-second `powercut` rules for this pilot's arithmetic. At three bytes each
runs in 0.04–0.08 s. Three is the smallest width with both a within-byte and a
cross-byte neighbour, which is exactly what the aliasing clause needs, and the
harnesses take their domain from the constant rather than restating it.

What the shrink stops proving — that no FID can index past the map, which fell
out of the full-width runs as a discharged bounds check — is a compile-time
assertion now, and that is the stronger form: it is about the *shipped* width,
where a proof would only have covered the FIDs a harness enumerated.

`SEC-STORE-002` is `BOUNDED` on the strength of three of these; the other three
store properties stay `MODELLED-ONLY`.

**The obvious way to bridge them was tried, and it is a copy compared to
itself.** Write the model's per-FID steps as Rust predicates — `Delete(f)`'s
`\E k \in 1..2` as `k1 || k2 || stutter`, and so on — then hold them against
`powercut.rs`'s four `*_landed` rules. Measured over a five-valued domain, wider
than any test would walk: **0 disagreements, for all four actions.** They are the
same boolean function. `delete_landed`'s `untouched` disjunct expands to
`stutter \/ k1` and its second disjunct IS `k2`; the conjuncts a comparison
"holds at their old value" to avoid cancelling are constantly true instead, and
mutating them away kills nothing.

The reason is in the module's own comments, and it says what a real bridge needs:

* `NoOrphanedMetadata` and `NoFalseMetaAbsent` are **step recorders**. A
  meta-only file — a `meta_add` with no `put` — legally has metadata and no
  value, so the violation is a record OUTLIVING a delete, not a state. A state
  predicate over one observed record is a strictly stronger, wrong claim, and it
  **panics on correct `Fs` behaviour**: a meta-only file whose delete is cut
  before the metadata write lands leaves exactly that shape, which the
  `power_cut` fuzz target can reach.
* `NoRecordLostToMetaWrite` is **cross-FID** — a `meta_add` of one FID dropping
  another's committed record. One `Record` cannot express it, and neither can
  `meta_add_landed`, so the two agree by shared blindness rather than by
  agreement.
* `dead` and `metaAbsent`, the two variables such a bridge would be named after,
  have no per-FID face at all.

So the persistent half needs a multi-FID projection with step recorders — the
same shape the module itself had to adopt — and not four more predicates. What
this attempt did leave behind is one power-cut shape nothing had driven: the
delete of a **meta-only** file, from both sides of the cut. Honest limit: every
mutation driven against it is killed by a sibling test as well; what it adds is
the state shape, which is the one the module singles out. `Scan`'s
truncated-walk clause needs a medium that can truncate rather than a bitmap, so
it stays a unit test. The full map and its limits are in
`docs/store-refinement.md`.