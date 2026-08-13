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

TLA+ is deliberately **not** in `flake.nix` — the `tlaplus` package is 208 MB
and that is a maintainer decision. Only the 2.2 MB `tla2tools.jar` is needed;
the JRE comes from the host. Realize just the jar:

```console
$ nix build --no-link --print-out-paths \
    '/nix/store/58f325n6n42bn2iqb6ssqj2rgcakwwlx-tla2tools.jar.drv^out'
/nix/store/kvrhq0951riz03ffwiskcyr0dymg6k5g-tla2tools.jar
```

That drv is `nixpkgs#tlaplus`'s own `tla2tools.jar` input — a fixed-output
download of the upstream v1.7.4 release, `sha256-k2omIGHJFGlN/…` — so the path
is reproducible under the pinned nixpkgs. Point `TLA2TOOLS_JAR` at your own
copy if you have one. `nix run nixpkgs#tlaplus -- …` also works and needs no
jar path, but pulls the full 208 MB closure for a JRE the host already has.

```console
$ ./gen-configs.sh          # regenerate every .cfg
$ ./run-tlc.sh all          # the whole matrix, sequentially
$ ./run-tlc.sh Shipped.cfg  # one configuration; log lands in out/
```

`run-tlc.sh` caps TLC at 2 workers on purpose — this tree is worked on by
several agents at once and a run that starves them is worse than a slow one.

## The six invariants → the Rust that owns each

The names are load-bearing. The intent is that the same six appear in the Rust,
in the Kani harnesses and in the stateful fuzz targets, so one property can be
traced from this model to the code that implements it. **That traceability is
the deliverable and it is two-thirds unbuilt** — measured status in
"Traceability" below, which is where to look before quoting this section.

Paths are relative to the repository root, because three of these basenames
match more than one file in the tree.

| Invariant | What it asserts here | The Rust construct that owns it |
|---|---|---|
| `NoAuthorizationBypass` | No protected operation completes without the live authorization its own gate requires | `crates/rsk-fido/src/`: `getassertion.rs:376-379` · `makecredential.rs:437-441` · `config.rs:222-224` · `credmgmt.rs:277` · retry ladder `clientpin.rs:719-804` · soft lock `state.rs:284-291` + `crates/rsk-device/src/ctap.rs:215-222` · reset window `reset.rs:148-154` · walk owner `state.rs:169-179`, `credmgmt.rs:338` |
| `NoCrossTransportTouchConsumption` | A presence decision produced for one transport is never applied to another — neither a confirm nor a cancel | `crates/rsk-device/src/presence.rs`: `Arbiter::pending_for` · `::request_cancel` / `::cancel_otp_wait` (the scope guards) · `ButtonWait::wait` (the `spent` latch). `firmware/src/presence.rs` keeps only the board half. **The stale-cancel drop has two owners, the clear at the wait's entry and the one at its exit** — either alone carries the property, so removing one does not fall over, which is why only the unit test `w8_…` pins the exit one |
| `NoTokenAfterInvalidation` | A grant invalidated by a PIN change, PIN set, reset, `stopUsingPinUvAuthToken` or power cycle never authorizes again | `crates/rsk-fido/src/`: `state.rs:484-497` (`reset_pin_uv_auth_token`) · `state.rs:542-556` (`stop_using_token`) · `state.rs:590-602` (`expire_stale_token`) · `clientpin.rs:300-311` · `seed.rs:310-311` (`clear_ppuat`) |
| `NoAccessibleSecretWithoutGate` | No live secret is reachable while the gate record that protects it is gone | `crates/rsk-fido/src/`: `reset.rs:127-146` (`is_fido_gate_fid`) · `reset.rs:51-66` (phase order) · `credmgmt.rs:249-265` (`authorized_by_ppuat`) · `clientpin.rs:213-217`, `:824-828` |
| `NoUnmanageableCredential` | Every live credential is reachable by the management surface (its `EF_RP` entry exists) | `crates/rsk-fido/src/`: `credential.rs:804-826` (registration write order) · `credmgmt.rs:652-706` (`delete_credential` / `decrement_rp`) · `passkeys.rs:89-151` (`for_each_rp`, the `EF_RP` walk the display lists from) |
| `ResetNeverWeakensSurvivingState` | No prefix of an `authenticatorReset` — torn or complete — leaves a surviving usable secret whose gate has already gone | `crates/rsk-fido/src/`: `reset.rs:30-75` (`reset`, seed then two phases) · `reset.rs:77-112` (`sweep`) · `reset.rs:127-146` (`is_fido_gate_fid`, incl. `EF_BACKUP_SEALED`) · `reset.rs:193-201` (`survives_factory_reset`). Shipped twin for its third clause: `reset_tests.rs::a_torn_reset_never_unseals_a_surviving_seed` |

Two of these overlap by design and the overlap is stated rather than hidden:
`NoAccessibleSecretWithoutGate` is the **steady-state** claim on every path,
while `ResetNeverWeakensSurvivingState` is the **relational** one — it compares
the state a reset was handed against the state the reset produced, which the
steady-state form cannot see.

`EF_BACKUP_SEALED` is the one gate here that reads backwards: its **absence** is
the permissive state (`reset.rs:132-139`), so what a torn wipe can do is
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
this invariant in 252 430 states. Without it, that run comes back green.

## Can these invariants fail? — the mutation experiment

An invariant no bug can violate is the TLA+ analogue of a test that cannot
fail, and this project has been bitten by that class repeatedly. So every
invariant carries at least one mutant that must break it. Each `Bug*` switch
rebuilds a real RS-Key defect or removes a defence the tree currently has;
`Solo_*.cfg` checks **only** that mutant's own target invariant, so a mutant
caught by a sibling cannot be mistaken for one that names its own.

"Caught in" is the `Solo_*.cfg` run's distinct-state count — the run that
checks **only** the named invariant.

| Mutation switch | Removes | Target invariant | Caught in |
|---|---|---|---|
| `BugResetGatesFirst` | `reset.rs:67-68` phase order | `ResetNeverWeakensSurvivingState` | 2 352 states |
| `BugBackupSealedNotAGate` | `reset.rs:132-145` — `EF_BACKUP_SEALED` back in phase 1 (audit run-36) | `ResetNeverWeakensSurvivingState` | 2 347 states |
| `BugCredBeforeRp` | `credential.rs:804-814` write order | `NoUnmanageableCredential` | 820 states |
| `BugDeleteRpBeforeCred` | `credmgmt.rs:659-665` — `decrement_rp` ahead of the `EF_CRED` delete | `NoUnmanageableCredential` | 111 503 states |
| `BugTokenSurvivesPinChange` | `clientpin.rs:311` | `NoTokenAfterInvalidation` | 15 299 states |
| `BugSetPinKeepsPpuat` | `clientpin.rs:213-217` | `NoTokenAfterInvalidation` | 416 314 states |
| `BugChangePinKeepsPpuat` | `clientpin.rs:300-304` | `NoTokenAfterInvalidation` | 11 183 states |
| `BugStopUsingKeepsPerms` | `state.rs:546-547` zeroing perms | `NoTokenAfterInvalidation` | 1 404 states |
| `BugNoConsumeAfterUp` | `state.rs:518-530` (GHSA-wqjm-653g-hgw3) | `NoAuthorizationBypass` | 275 564 states |
| `BugUnscopedCancel` | `presence.rs:93` scope check | `NoCrossTransportTouchConsumption` | 127 states |
| `BugTouchNotSpent` | `presence.rs:288` `spent` latch | `NoCrossTransportTouchConsumption` | 5 717 states |
| `BugSoftLockLostOnWarmReset` | `ctap.rs:215-222` `PinLock` carry | `NoAuthorizationBypass` | 4 993 states |
| `BugWarmResetReopensWindow` | `reset.rs:153` `!warm_boot` | `NoAuthorizationBypass` | 126 states |
| `BugCmWalkIgnoresChannel` | `state.rs:172` channel equality | `NoAuthorizationBypass` | 1 242 states |

**14 of 14 mutants are caught, each by the invariant that names it.**
`NoAccessibleSecretWithoutGate` is the one invariant no switch names as its
target; `BugResetGatesFirst` breaks it too, and
`Solo_NoAccessibleSecretWithoutGate.cfg` shows that alone in 252 430 states.
The shipped tree breaks it as well — see finding 2.

That last one is not a formality. `NoAccessibleSecretWithoutGate` was repaired
in this revision (`pin.everSet` now retires when the gate phase deletes `EF_PIN`
over an already-emptied store — see "The `everSet` repair"), and a loosened
invariant that stops crying wolf can just as easily stop catching real defects.
The solo run is the measurement that says it did not: **252 430 states, still
red, on the same mutant as before the repair.**

One mutant was **not** caught on the first attempt, and that mattered more than
the eleven that were. `BugStopUsingKeepsPerms` ran green over 6 275 376 distinct states
because the model gave every call site one uniform guard including "the token
is in use". The code does not: `getassertion.rs:377` and `makecredential.rs:440`
test `user_verified()`, but `config.rs:222-224` and `credmgmt.rs:277` test the
MAC and the permission bits **only**. For those two the single thing standing
between a stopped or expired token and a live authorization is that
`stop_using_token` also zeroes `permissions` — `verify_token` is a MAC over
bytes that stay put and keeps succeeding. Splitting the guard in two
(`TokenGuardUv` / `TokenGuardBare`) made the mutant fall in 840 states. A model
that flatters the code proves nothing about it.

## Findings on the tree as it stands

`Shipped.cfg` (every switch off) is **RED**, and that is the result, not a
broken model. Both findings are one class: **the two-phase wipe controls the
order *between* phases but nothing controls the order *within* a phase.**
`sweep` batches whatever `for_each_key` yields, and `fs.rs:238-241` documents
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
state `credential.rs:804-811` orders registration to avoid and that audit
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

`clientpin.rs:213-217` already names this exact torn state — but the defence it
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

**The configurations below have not been re-run, and two of them no longer describe
the tree.** Whoever re-runs them:

- `Shipped.cfg` still has `FixPpuatRequiresPin` off. Turn it on; `Shipped.cfg` then
  models the shipped tree for Finding 2 and `Shipped_OnlyFinding2.cfg` becomes the
  historical record of a fixed defect.
- `NoUnmanageableCredential` asks that no live credential outlive its `EF_RP` entry
  — *prevention*. The shipped mitigation makes the survivor unopenable instead, and
  this spec has no notion of a record's key, so the property cannot express it and
  `Shipped.cfg` stays RED on it. Re-scoping it to "live **and openable**" needs the
  credential record to carry whether the seed that opens it is still present; that is
  a model change, not a config flip, and it is the honest way to make this row green.

## Results

| Configuration | Verdict | States generated | Distinct | Depth | Wall |
|---|---|---|---|---|---|
| `ShippedFixed.cfg` (both fixes) | **GREEN, exhaustive** | 92 091 537 | 13 232 120 | 49 | 154 s |
| `Shipped.cfg` (tree as it stands) | RED `NoUnmanageableCredential` | 396 416 | 72 646 | 13 | 3 s |
| `Shipped_OnlyFinding1.cfg` | RED `NoUnmanageableCredential` | 393 857 | 72 128 | 13 | 1 s |
| `Shipped_OnlyFinding2.cfg` | RED `NoAccessibleSecretWithoutGate` | 565 888 | 102 523 | 14 | 2 s |
| 14 × `Mut_*.cfg` | RED, each caught | 251 – 2 435 962 | 125 – 416 917 | 5 – 17 | ≤ 5 s |
| 14 × `Solo_*.cfg` | RED, each on its **own** target | 260 – 2 440 300 | 126 – 416 314 | 5 – 17 | ≤ 5 s |
| `Solo_NoAccessibleSecretWithoutGate.cfg` | RED, the repaired clause | 1 460 850 | 252 430 | 16 | 5 s |

Only `ShippedFixed.cfg` is an exhaustive search; every RED row stops at the
first counterexample, so its counts move a few percent between runs with the
BFS order the two workers happen to take. The green row's 13 232 120 distinct
states is the reproducible figure. TLC's reported *depth* is not quite
deterministic under 2 workers (49 or 50 between runs of the same config); the
single-worker run says **49**, and that is the figure in the table. The full
table is regenerated by `./run-tlc.sh all` into `out/MATRIX.txt`.

Constants: `RPs = {r1,r2}`, `Channels = {c1,c2}`, `MaxRetries = 3`,
`MismatchLimit = 2`, `MaxClock = 1`, `ResetWindow = 0`. `MaxRetries` must
exceed `MismatchLimit` or the soft lock is unreachable — the shipped ratio is
8 : 3 (`consts.rs:313,317`). Measured on an 18-core Apple Silicon under load
from four other workstreams, 2 TLC workers, 4 GB heap.

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

**No action is dead**: `-coverage` reports all 41 actions (plus `Init`) taken
at least once in the green run — no zero-total row in
`out/ShippedFixed.coverage.log`. That is this model's answer to the vacuity
question `kani::cover` answers on the Kani side: a transition that never fires
makes every clause guarding it free.

## Traceability — measured, not asserted

The point of naming the invariants was that one property should be greppable
from this model to the Rust that implements it, to the Kani harness that proves
a bounded slice of it, to the fuzz target that hammers it. Grepped over the
whole tree (untracked files included) on 2026-08-12:

| Invariant | `.tla` | non-test Rust | Kani harness | fuzz target |
|---|---|---|---|---|
| `NoAuthorizationBypass` | ✓ | ✗ | ✓ `state_kani.rs` | ✗ |
| `NoTokenAfterInvalidation` | ✓ | ✗ | ✓ `state_kani.rs`, `credmgmt_kani.rs` | ✗ |
| `NoCrossTransportTouchConsumption` | ✓ | ✗ | ✗ | ✗ |
| `NoAccessibleSecretWithoutGate` | ✓ | ✗ | ✗ | ✗ |
| `NoUnmanageableCredential` | ✓ | ✗ | ✗ | ✗ |
| `ResetNeverWeakensSurvivingState` | ✓ | ✗ | ✗ | ✗ |

**Two of six reach a Kani harness. None reaches any of the 54 fuzz targets, and
none appears in non-test Rust.** So the traceability is a plan, and it is stated
here as one. The obstacles are known and unequal, which is why this is not just
a to-do list:

- `NoCrossTransportTouchConsumption` **cannot** get a Kani harness today. Its
  whole mechanism now lives in `crates/rsk-device/src/presence.rs`, host-testable
  at last, but no harness has been written over it yet.
- `NoAccessibleSecretWithoutGate` and `ResetNeverWeakensSurvivingState` are
  about flash records, so a harness needs an `Fs`. `rsk-fs` already carries
  sequence proofs; that is the natural home, not `rsk-fido`.
- `NoUnmanageableCredential` is the cheapest one left, and its counterexamples
  are the shortest (820 states) — which also makes it the honest calibration for
  whether the fuzz layer can see this class at all.

## Abstractions — where the model deliberately departs from the firmware

**This section used to open by claiming every abstraction here admits *more*
behaviour than the firmware, "which is sound for safety". That was false**, and
the one that broke it was holding the green run up: `PowerCut` left the seed as
the cut found it, while the firmware regenerates a missing seed on **every**
boot (`firmware/src/main.rs:609`, `tools/emu/src/device.rs:264`). A cut device
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
  half of the gate and a deliberate hold (`vendor.rs:889-901`). Widening where
  the marker can be **set** never widens where it can be **lost**, and the loss
  is what the invariant is about.
- **A regenerated seed still opens the credentials made under the old one.**
  `store.seed` is one boolean, so the model cannot tell the owner's seed from
  the one a boot minted after a torn wipe; in the firmware those credentials are
  cryptographically dead. The reset snapshot's `snap.seed` *does* make that
  distinction, but only for the backup-marker clause.
- **The order within a sweep phase is arbitrary.** `for_each_key` yields in
  flash-ring order (`fs.rs:238-241`), which is *a* fixed order per device state,
  not a free choice. Both findings below need only that some reachable ring
  order puts one delete before another.

### Narrower than the firmware — the risk direction, and the whole list

Anything here can hide a real defect, so each one is a standing question rather
than a settled abstraction.

- **One credential per relying party**, `MAX_RESIDENT_CREDENTIALS` = 2 rather
  than 256, two RPs, two channels, `MaxRetries` 3 : `MismatchLimit` 2 against a
  shipped 8 : 3. A defect that needs a third credential, a third channel or the
  sixth retry is out of reach. Nothing in these six invariants depends on the
  slot count, but that is an argument, not a proof.
- **Permission sets are the five a host actually requests**, not all 16 subsets
  (`PermSets`); `largeBlobWrite` is modelled as the empty set that
  `consume_after_user_presence` leaves behind. A defect reachable only from an
  unusual permission combination is not modelled.
- **The wait's scope is modelled as the owner of an open touch wait**, where the
  worker sets it around the whole dispatch (`Arbiter::set_wait_scope`). The
  review showed this is exactly as narrow as it sounds: the cancel is dropped at
  **both** ends of a wait (`crates/rsk-device/src/presence.rs:193` *and*
  `:226`), so removing either alone leaves the model green — a reviewer trusting
  one citation would see nothing fall. The unit test `w8_…` is what pins the
  drop at exit.
- **The button build only** (`presence.shows_confirm() = FALSE`), so the reset
  window always applies; a display build bypasses it by design (`reset.rs:31`)
  and that path is unmodelled.
- **`largeBlobs`, `getNextAssertion`, the MSE seed-backup channel, built-in UV
  and the trusted-display flows are absent.** They carry their own
  channel-ownership rules (`state.rs:33-51`, `:326-333`) that this model does
  not check — the most obvious place to extend it.
- **Two transports** (CTAPHID, CCID). `SCOPE_OTP` and the on-panel
  `SCOPE_NONE` ceremonies are not modelled.
- **Three of `is_fido_gate_fid`'s six records are modelled** — `EF_PIN`,
  `EF_ALWAYS_UV`, `EF_PAUTHTOKEN`, plus `EF_BACKUP_SEALED` since the review.
  `EF_DEVICE_PIN` and `EF_MINPINLEN` are still absent.

### Safety only

`Spec == Init /\ [][Next]_vars`: no fairness, no `PROPERTY` in any `.cfg`. A
device that starts a reset and never finishes it satisfies all six invariants.
Nothing here says an operation ever *completes* — only that no reachable state
is bad. There is also no `SYMMETRY` on `RPs`/`Channels`, which costs time and
not soundness.
