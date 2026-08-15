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

The names are load-bearing. The intent is that the same six appear in the Rust,
in the Kani harnesses and in the stateful fuzz targets, so one property can be
traced from this model to the code that implements it. **That traceability is
the deliverable and it is two-thirds unbuilt** — measured status in
"Traceability" below, which is where to look before quoting this section.

Paths are relative to the repository root, because three of these basenames
match more than one file in the tree.

| Invariant | What it asserts here | The Rust construct that owns it |
|---|---|---|
| `NoAuthorizationBypass` | No protected operation completes without the live authorization its own gate requires | `crates/rsk-fido/src/`: `getassertion.rs:384-387` · `makecredential.rs:454-457` · `config.rs:222-224` · `credmgmt.rs:278` · retry ladder `clientpin.rs:723-808` · soft lock `state.rs:285-293` + `crates/rsk-device/src/ctap.rs:215-222` · reset window `reset.rs:154-160` · walk owner `state.rs:169-180`, `credmgmt.rs:339` |
| `NoCrossTransportTouchConsumption` | A presence decision produced for one transport is never applied to another — neither a confirm nor a cancel | `crates/rsk-device/src/presence.rs`: `Arbiter::pending_for` · `::request_cancel` / `::cancel_otp_wait` (the scope guards) · `ButtonWait::wait` (the `spent` latch). `firmware/src/presence.rs` keeps only the board half. **The stale-cancel drop that carries this property is the one at the wait's ENTRY.** The exit clear cannot substitute for it — a cancel latched by a dispatch that never entered `wait` is never seen by the exit — see "The cancel that no wait was open for" |
| `NoTokenAfterInvalidation` | A grant invalidated by a PIN change, PIN set, reset, `stopUsingPinUvAuthToken` or power cycle never authorizes again | `crates/rsk-fido/src/`: `state.rs:488-502` (`reset_pin_uv_auth_token`) · `state.rs:547-562` (`stop_using_token`) · `state.rs:596-609` (`expire_stale_token`) · `clientpin.rs:302-313` · `seed.rs:311-312` (`clear_ppuat`) |
| `NoAccessibleSecretWithoutGate` | No live secret is reachable while the gate record that protects it is gone | `crates/rsk-fido/src/`: `reset.rs:129-152` (`is_fido_gate_fid`) · `reset.rs:52-67` (phase order) · `credmgmt.rs:249-266` (`authorized_by_ppuat`) · `clientpin.rs:214-218`, `:824-828` |
| `NoUnmanageableCredential` | Every live credential is reachable by the management surface (its `EF_RP` entry exists) | `crates/rsk-fido/src/`: `credential.rs:805-827` (registration write order) · `credmgmt.rs:658-713` (`delete_credential` / `decrement_rp`) · `passkeys.rs:90-152` (`for_each_rp`, the `EF_RP` walk the display lists from) |
| `ResetNeverWeakensSurvivingState` | No prefix of an `authenticatorReset` — torn or complete — leaves a surviving usable secret whose gate has already gone, where "surviving" counts the RAM copy of the seed as well as the flash record | `crates/rsk-fido/src/`: `reset.rs:31-76` (`reset`, session then seed then two phases) · `reset.rs:58-61` (`ctx.state.reset()` ahead of every flash write) · `reset.rs:78-114` (`sweep`, and the `Err` at `:95-99` that leaves the device running) · `reset.rs:140-149` (`is_fido_gate_fid`, incl. `EF_BACKUP_SEALED`) · `reset.rs:202-204` (`survives_factory_reset`) · `crates/rsk-fido/src/lib.rs:183-187` (`Ctx::load_keydev`, the RAM copy that wins) · `state.rs:426-436` (`FidoState::reset`, what drops it). Shipped twin for its third clause: `reset_tests.rs::a_torn_reset_never_unseals_a_surviving_seed` |

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
the permissive state (`reset.rs:134-141`), so what a torn wipe can do is
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
| `BugBackupSealedNotAGate` | `reset.rs:134-148` — `EF_BACKUP_SEALED` back in phase 1 (audit run-36) | `ResetNeverWeakensSurvivingState` | 2 347 states |
| `BugCredBeforeRp` | `credential.rs:808-827` write order | `NoUnmanageableCredential` | 820 states |
| `BugDeleteRpBeforeCred` | `credmgmt.rs:665-672` — `decrement_rp` ahead of the `EF_CRED` delete | `NoUnmanageableCredential` | 111 503 states |
| `BugTokenSurvivesPinChange` | `clientpin.rs:313` | `NoTokenAfterInvalidation` | 15 299 states |
| `BugSetPinKeepsPpuat` | `clientpin.rs:214-218` | `NoTokenAfterInvalidation` | 416 314 states |
| `BugChangePinKeepsPpuat` | `clientpin.rs:302-306` | `NoTokenAfterInvalidation` | 11 183 states |
| `BugStopUsingKeepsPerms` | `state.rs:552-553` zeroing perms | `NoTokenAfterInvalidation` | 1 404 states |
| `BugNoConsumeAfterUp` | `state.rs:523-535` (GHSA-wqjm-653g-hgw3) | `NoAuthorizationBypass` | 275 564 states |
| `BugUnscopedCancel` | `Arbiter::request_cancel`'s scope check | `NoCrossTransportTouchConsumption` | 127 states |
| `BugTouchNotSpent` | `ButtonWait::wait`'s `spent` latch | `NoCrossTransportTouchConsumption` | 5 717 states |
| `BugSoftLockLostOnWarmReset` | `ctap.rs:215-222` `PinLock` carry | `NoAuthorizationBypass` | 4 993 states |
| `BugWarmResetReopensWindow` | `reset.rs:159` `!warm_boot` | `NoAuthorizationBypass` | 126 states |
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
| `BugWaitScopeNotCleared` | `worker.rs:521` `set_wait_scope(SCOPE_NONE)` | `EveryWaitReleases` | 76 446 states |
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

That last one is not a formality. `NoAccessibleSecretWithoutGate` was repaired
in an earlier revision (`pin.everSet` now retires when the gate phase deletes
`EF_PIN` over an already-emptied store — see "The `everSet` repair"), and a
loosened invariant that stops crying wolf can just as easily stop catching real
defects. The solo run is the measurement that says it did not: **454 454 states,
still red, on the same mutant as before the repair.**

One mutant was **not** caught on the first attempt, and that mattered more than
the eleven that were. `BugStopUsingKeepsPerms` ran green over 6 275 376 distinct states
because the model gave every call site one uniform guard including "the token
is in use". The code does not: `getassertion.rs:385` and `makecredential.rs:457`
test `user_verified()`, but `config.rs:222-224` and `credmgmt.rs:278` test the
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
`set_wait_scope` is called around the whole **dispatch** (`worker.rs:429`,
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
state `credential.rs:805-812` orders registration to avoid and that audit
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
(`crates/rsk-fido/src/lib.rs:183-187`), so
with the flash seed always deleted first a *failed* sweep would have left the
power cycle running on a seed nothing stores — `BACKUP_EXPORT` included — which
is why `ctx.state.reset()` moved ahead of the flash work (`reset.rs:58-61`).

Both halves of the blindness are now modelled, and each had to be closed
separately:

- **The RAM copy.** `ram` is `state.keydev_dec` (`state.rs:338-340`);
  `SeedReachable == store.seed \/ ram` is what "the owner's seed is still
  reachable" means; `DeviceUnlock` is the vendor `UNLOCK` (`vendor.rs:543-566`)
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
| `Shipped.cfg` (the tree as it stands) | **GREEN, exhaustive** | 813 099 753 | 61 215 504 | 50 | **1137 s** |
| `Historical_E76.cfg` (the seed-lead taken back out) | RED `NoUnmanageableCredential` | 2 286 995 | 246 718 | 13 | 4 s |
| `Historical_E77.cfg` (the grant back in phase 2 **and** the consumer fix out) | RED `NoAccessibleSecretWithoutGate` | 2 060 496 | 221 977 | 13 | 3 s |
| 28 × `Mut_*.cfg` | RED, each caught | 65 – 3 926 726 | 40 – 410 556 | 4 – 14 | ≤ 6 s |
| 28 × `Solo_*.cfg` + 3 structural | RED, each on its **own** target | 65 – 6 430 819 | 40 – 658 903 | 4 – 15 | ≤ 9 s |
| 3 × `SoloClause_*.cfg` | RED, each on **one clause** | 25 216 – 22 897 118 | 5 867 – 2 231 576 | 8 – 18 | ≤ 30 s |
| `Fairness.cfg` (`ENABLED OpAdvances => ~Idle`, liveness constants) | **GREEN** | 85 388 061 | 7 903 336 | 43 | 117 s |
| `FairMut_BugFairnessFoldsLocalCeremony.cfg` | RED `OpAdvancesIsOneActivity` | 57 | 36 | 4 | < 1 s |
| `Seams.cfg` (the second module) | **GREEN, exhaustive** | 9 617 | 662 | 12 | 1 s |
| 13 × `SeamMut_*.cfg` / 13 × `SeamSolo_*.cfg` | RED, each on its own target | 77 – 3 523 | 27 – 381 | 4 – 8 | ≤ 1 s |
| `Liveness.cfg` (reduced constants, `HEAP=12g` from `floors.txt`) | **GREEN** | 85 388 061 | 7 903 336 | 43 | **1591 s** |
| `Liveness.cfg` at the old 4 GB default | **out of memory** in the temporal check, state search complete | 85 388 061 | 7 903 336 | 43 | 1500 s |
| 3 × `LiveMut_*.cfg` | RED, each on its own property | 579 360 – 733 606 | 79 706 – 100 162 | — | ≤ 4 s |

`Shipped.cfg`, `Seams.cfg`, `Fairness.cfg` and `Liveness.cfg` are the exhaustive
searches and their counts are reproducible; every RED row stops at the first
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

Then it went **down** to 61 215 504, by 23%, while gaining four Policies. Two
fidelity repairs did that: `ctx.state.reset()` modelled in full rather than only
its `keydev_dec` half, and `makeCredential` requiring the seed as `getAssertion`
already did. Every state they removed was one the firmware cannot be in — the
same shape as the boot-time `ensure_seed` repair two revisions ago, and the
second time on this model that being *more* faithful has made it *smaller*.

Constants: `RPs = {r1,r2}`, `Channels = {c1,c2}`, `MaxRetries = 3`,
`MismatchLimit = 2`, `MaxClock = 1`, `ResetWindow = 0`. `MaxRetries` must
exceed `MismatchLimit` or the soft lock is unreachable — the shipped ratio is
8 : 3 (`consts.rs:314,318`). Measured on an 18-core Apple Silicon under load
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
(`firmware/src/worker.rs:652-654`), and `request_cancel`'s single `if`
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
(`crates/rsk-device/src/ccid.rs:86-102`); the CTAPHID side owns a **separate**
`Dispatcher` whose applet array is literally one element, its own `VendorApplet`
(`crates/rsk-device/src/ctap.rs:160-164`). PIV, OpenPGP and OATH are not
reachable over CTAPHID at all, so no status can be established on one transport
and honoured on the other. A product of the two models would multiply 17 M
states by this one's 205 and buy exactly zero new interleavings. What they do
share — one flash, one button — appears here as events (`FactoryWipe`,
`PowerCycle`), and that is stated in the module as the abstraction it is.

### What it asserts

| Invariant | What it asserts | The Rust that owns it |
|---|---|---|
| `NoStatusOutsideItsSelection` | An applet holds a security status only while it is the **selected** applet. Structural — it reads straight out of the state | `crates/rsk-sdk/src/applet.rs:374-390` (the one place that decides what a selection does to the applet that was current) · `crates/rsk-piv/src/lib.rs:153-157` · `crates/rsk-openpgp/src/pin.rs:67-80` · `crates/rsk-oath/src/lib.rs:1200-1204` · `crates/rsk-device/src/ccid.rs:327-342` (the ICC power transition) |
| `NoStatusAfterARefusedAuth` | A reference whose authentication was just refused is not authenticated | `crates/rsk-piv/src/lib.rs:140-143` · `crates/rsk-openpgp/src/pin.rs:158-170` · `crates/rsk-oath/src/lib.rs:1148-1149` |
| `NoKeyOpOnTheAdminStatus` | No key operation runs on a status its own specification does not name | `crates/rsk-openpgp/src/pso.rs:80-92` · `crates/rsk-openpgp/src/internalaut.rs:45-48` · `crates/rsk-piv/src/auth.rs:58-66`, `:114-118` |
| `ReselectPreservesAccessStatus` | A re-SELECT of the same AID changes no access status. **A conformance claim, labelled as one** | `crates/rsk-piv/src/lib.rs:319-322` · `crates/rsk-openpgp/src/lib.rs:372-375` |
| `AccessCodeRemovalNeedsTheCode` | Removing the OATH access code needs the validated status the code bought. **A step rule — its violation produces exactly the exempt code-less state, so no state predicate can see it** | `crates/rsk-oath/src/lib.rs:356-358` (the shared gate) · `:363-369` (the removal path) |

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
| PIV `VERIFY` | `has_pin` **and** `pin_fresh` (`crates/rsk-piv/src/lib.rs:140-143` is the only writer of either) | the applet's own session discipline | `NoStatusAfterARefusedAuth` |
| PIV `CHANGE REFERENCE DATA` / `RESET RETRY COUNTER` | **nothing** — it takes no `&mut Session` at all (`crates/rsk-piv/src/lib.rs:497-531`) | SP 800-73-4 pt 2 §3.2.2/§3.2.3, plus a measured YubiKey 5.7.4 | `BugPivChangeResetsStatus`, RED in 46 |
| OpenPGP `VERIFY` / `CHANGE` | exactly the **addressed** reference, keyed on the FID compared rather than on P2 (`crates/rsk-openpgp/src/pin.rs:158-170`, `:229-231`) | OpenPGP 3.4.1, and the `RESET RETRY COUNTER` case that compares `EF_RC` while passing `p2 = 0x81` | `NoStatusAfterARefusedAuth` |
| OATH OTP-PIN `CHANGE` | **both** flags (`crates/rsk-oath/src/lib.rs:1148-1149`) | `aa47867` — before it the whole retry budget could be burned through the door that did not close | `BugFailedChangeKeepsStatus` |
| OATH access-code `VALIDATE` | **nothing** — the standing unlock survives (`crates/rsk-oath/src/lib.rs:539-541`) | a MAC challenge-response has no retry counter for a refusal to protect; a YubiKey 5.7.4 measured keeping it from a genuinely locked applet | `BugRefusedValidateDropsUnlock`, RED in 46 |

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
| `BugCardResetKeepsStatus` | `crates/rsk-device/src/ccid.rs:327-342` — the ICC power transition | `NoStatusOutsideItsSelection` | 29 states |
| `BugAdminOpensKeyOps` | `e5da38b` taken back out: PW3 standing in for PW1/PW2 | `NoKeyOpOnTheAdminStatus` | 67 states |
| `BugFailedChangeKeepsStatus` | `aa47867` taken back out: a refused OTP-PIN change that leaves the safe open | `NoStatusAfterARefusedAuth` | 74 states |
| `BugPinFreshNotSpent` | `crates/rsk-piv/src/auth.rs:114-118` — one VERIFY, one key operation | `NoKeyOpOnTheAdminStatus` | 79 states |
| `BugSigPinNotSpent` | `crates/rsk-openpgp/src/keys.rs:977-981` — the same shape one applet over, PW1 valid for one PSO:CDS | `NoKeyOpOnTheAdminStatus` | 361 states |
| `BugUserStatusOpensAdmin` | a *user* status opening the admin surface — the converse `BugAdminOpensKeyOps` cannot express | `NoKeyOpOnTheAdminStatus` | 48 states |
| `BugRefusedValidateGrants` | a refused OATH access-code `VALIDATE` that grants the unlock | `NoStatusAfterARefusedAuth` | 73 states |
| `BugPwStatusIgnoresAdmin` | a *user* status writing the PW status byte — PUT DATA `0xC4` is PW3's (`crates/rsk-openpgp/src/putdata.rs:181-183`, and the ACL one layer up at `:59-65`) | `NoKeyOpOnTheAdminStatus` | 49 states |
| `BugPivChangeResetsStatus` | PIV's refused `CHANGE REFERENCE DATA` clearing the standing status | `ExemptRefusalPreservesStatus` | 46 states |
| `BugRefusedValidateDropsUnlock` | a refused OATH access-code `VALIDATE` dropping the standing unlock | `ExemptRefusalPreservesStatus` | 46 states |
| `BugRemoveCodeUnvalidated` | the access-code removal (`73 00`) reached without the validated status (`crates/rsk-oath/src/lib.rs:356-358`) — the hole the abstractions list carried for two revisions as definitionally invisible to any state predicate | `AccessCodeRemovalNeedsTheCode` | 77 states |

`Seams.cfg` is **GREEN, exhaustive, 9 665 states generated / 662 distinct at
depth 12**, and 13 of 13 mutants are caught by the invariant that names them.
It went DOWN by 4 when `PowerCycle` and `FactoryWipe` started retiring the
`psig` ghost with the status it belongs to, and those four are states the
firmware cannot be in — the third time on this pair of modules that being more
faithful has made one smaller.

**One of those six needed the property repaired first, and it is the useful
result.** `BugPinFreshNotSpent` ran **green** as written: stopping `pin_fresh`
from being spent also leaves the Policy that reads `pin_fresh` satisfied, so a
second key operation on one VERIFY looked legal to the invariant that was meant
to forbid it. The repair is a ghost `pfresh` — the freshness the *requirement*
leaves behind, always spent — beside the `fresh` the Rust holds. The two are
equal in every state of the shipped tree (`Seams.cfg`'s 205 distinct states are
bit-identical before and after), and they diverge only under the mutant, which
now falls in 83.

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
(`crates/rsk-openpgp/src/keys.rs:977-981`), which `PgpKeyOp` had no term for —
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
| `BugDeleteValueBeforeMeta` | `fs.rs:419-424` — the two backend writes reversed, so a torn delete leaves value-gone-meta-alive (`delete_landed`) | `NoOrphanedMetadata` | 54 states |
| `BugDeleteMetaOnlyUnderPresent` | the 0x077C databug — `delete` dropping `EF_META` only under `if present_bit`, so a meta-only file keeps its record | `NoOrphanedMetadata` | 55 states |
| `BugCacheFaultAsAbsent` | audit run-36 — `record` in place of `record_unless_faulted`, caching a faulted read as a decided absence | `NoFalseAbsent` | 23 states |
| `BugTruncatedScanDecidesAll` | `fs.rs:196-198` — `scan` deciding the whole FID space after a *truncated* walk, so a missed live key reads absent | `NoFalseAbsent` | 24 states |
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
re-measured killed. `SeamMut_*` stays outside the co-refutation roster
deliberately — the seam defects' fixes carry their own YubiKey-measured
regression tests, and their co-refutation is M4's work; the exclusion is stated
in `comutate.py`'s docstring rather than implied by a glob.

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
| `BugUseWhenBlocked` | the `left == 0 => PIN_BLOCKED` floor (`crates/rsk-piv/src/lib.rs:1186-1188` / `crates/rsk-openpgp/src/pin.rs:200-202`), which guards a direct verify AND a recovery reference | `NoAuthWhenBlocked` | 30 states |
| `BugWrongDoesNotSpend` | the decrement that IS the gate (`crates/rsk-piv/src/lib.rs:1204` / `crates/rsk-openpgp/src/pin.rs:108`) | `WrongAttemptIsCharged` | 2 states |
| `BugRecoveryWithoutSecret` | the recovery secret verified before the refill (`crates/rsk-piv/src/lib.rs:1337` / `crates/rsk-openpgp/src/pin.rs:766`) | `BudgetRisesOnlyWithItsSecret` | 9 states |

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
seam module's status, not a secret presented in the call. And the co-refutation
apparatus does not reach these mutants yet — a naive injection measures a `u8`
underflow rather than a blocked reference authenticating (the floor and the
counter's type are two layers), so `LatMut_*` is stated as excluded in
`comutate.py` rather than silently skipped.

## The fifth module — `RSKeyAdminSurface.tla`

The surface that decides which applets EXIST and who may touch device identity:
the enabled-applications mask (`rsk-mgmt`, ykman's `config usb` set), the
always-on carve-out that keeps a disable reversible, and the operator-presence
gate on the privileged `rsk-rescue` commands. A fifth module because it shares
no variable with the other four, and because its central claim is a *sequence*
property — "no series of config writes can strand the device unable to
re-enable an applet" is about the reachable space of the mask, not about one
write.

Four invariants, three of them ghosts and one structural, each with a mutant on
a real defended site — and two of the four mutants are **shipped defects**, not
removed defences:

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugMaskIsCosmetic` | **the pre-`0x084A` tree, shipped**: `USB_ENABLED` echoed in DeviceInfo while SELECT and dispatch never consulted it — `ykman config usb --disable` disabled nothing (`crates/rsk-sdk/src/applet.rs:208-210`, fed at `crates/rsk-device/src/ccid.rs:217-225`, consulted at `:313`) | `DisabledAppletNeverDispatches` | 10 states |
| `BugLockWriteResetsCaps` | **audit run-35, shipped**: a lock-code-only write strips to zero bytes, stored verbatim as an EMPTY record that `read_enabled_caps` reads as `SUPPORTED_CAPS` — every disabled application silently re-enabled (`crates/rsk-mgmt/src/lib.rs:333-346`, the merge) | `DisableSetSurvivesLockWrite` | 9 states |
| `BugAdminGateable` | the `APPLET_CAPS` cap-`0` carve-out removed (`crates/rsk-device/src/ccid.rs:64-71`): management/vendor/rescue gated by the mask, so one disable-everything write is irreversible | `AdminSurfaceAlwaysReachable` | 2 states |
| `BugPrivilegedOpUngated` | `require_presence` removed (`crates/rsk-rescue/src/lib.rs:161-163`): keydev signing, cert/config writes, BOOTSEL reboot and fuse burns driven by the USB host alone | `PrivilegedOpNeedsPresence` | 10 states |

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

## What now catches a run nobody watched

That `VACUOUS` rule was one heuristic and a **reporting** guard: it printed a
word and returned 0, and it only sees the collapse all the way to nothing. Three
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

**3. An expected verdict per configuration**, which catches the other silent
pass: a mutant that stops firing. `BugSetPinKeepsPpuat` explored **40 459 667
states without a counterexample** after a fix made its defect unreachable, and
the only thing that noticed was a human reading the matrix. Every `Mut_*`,
`Solo_*`, `SeamMut_*`, `SeamSolo_*`, `LiveMut_*`, `FairMut_*` and `Historical_*`
row must be RED; `Shipped.cfg`, `Seams.cfg`, `Fairness.cfg` and `Liveness.cfg`
must be GREEN. `run-tlc.sh` exits 1 on any row that is not.

Measured end to end on E164 itself, with the parentheses taken back out:

| Net | Verdict | Exit |
|---|---|---|
| `tla-lint.py` | 2 findings, named by line | **2** |
| floor + expectation, with the lint hook removed so nothing else can see it | `VACUOUS: nothing was enabled  !! expected GREEN` | **1** |
| the tree as it stood when E164 happened | `GREEN` | 0 |

And on E171's shape, a mutant config with its switch turned off:
`GREEN … !! expected RED`, exit 1.

`floors.txt` also carries the **per-config heap**. `Liveness.cfg` runs out of
memory at the 4 GB default *after* its state search completes, which had left
`./run-tlc.sh all` reporting a red row for a property that is true.

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

The point of naming the invariants was that one property should be greppable
from this model to the Rust that implements it, to the Kani harness that proves
a bounded slice of it, to the fuzz target that hammers it.

**The measurement is continuous now, not a dated snapshot:** every property
has an entry in `assurance/properties.toml` (id, statement, source, status —
nothing else is hand-written), and `scripts/assurance_gate.py`, a `check.sh`
row, derives the rest per run — defining module, checking configurations,
targeting mutants, Kani harnesses, fuzz targets, Rust files, device tests —
and holds the graph closed in both directions. The tables below are the
2026-08-12 hand grep that motivated it, kept for the prose around them; the
gate's output is the current truth.

Grepped over the whole tree (untracked files included) on 2026-08-12:

| Invariant | `.tla` | non-test Rust | Kani harness | fuzz target |
|---|---|---|---|---|
| `NoAuthorizationBypass` | ✓ | ✗ | ✓ `state_kani.rs` | ✗ |
| `NoTokenAfterInvalidation` | ✓ | ✗ | ✓ `state_kani.rs`, `credmgmt_kani.rs` | ✓ `fido_session.rs` |
| `NoCrossTransportTouchConsumption` | ✓ | ✗ | ✓ `presence_kani.rs` | ✗ |
| `NoAccessibleSecretWithoutGate` | ✓ | ✗ | ✗ | ✗ |
| `NoUnmanageableCredential` | ✓ | ✗ | ✗ | ✗ |
| `ResetNeverWeakensSurvivingState` | ✓ | ✗ | ✗ | ✗ |

And the second module's three, which start where the first module's did:

| Invariant | `.tla` | non-test Rust | Kani harness | fuzz target |
|---|---|---|---|---|
| `NoStatusOutsideItsSelection` | ✓ | ✗ | ✗ | ✗ |
| `NoStatusAfterARefusedAuth` | ✓ | ✗ | ✗ | ✗ |
| `NoKeyOpOnTheAdminStatus` | ✓ | ✗ | ✗ | ✗ |
| `ReselectPreservesAccessStatus` | ✓ | ✗ | ✗ | ✗ |

**Three of six reach a Kani harness. One of six reaches a fuzz target, and none
appears in non-test Rust.** Neither number moved this round, and the two
proposals the previous one left behind were both re-judged rather than landed:

- **`fuzz/fuzz_targets/power_cut.rs` — the proposal no longer applies to that
  file.** `2d18903` lifted the whole oracle out of it: the shadow model, the
  legal post-cut states and the durability sweep are `rsk_fs::powercut` now, and
  what is left in the target is the medium — a mock NOR chip that can lose power
  inside a write, and the decoder that turns fuzzer bytes into operations. There
  is no assertion left there to name. The one the proposal pointed at is
  `crates/rsk-fs/src/powercut_model.rs:338`, and the ordering rule it checks is
  a named predicate with a docstring and a Kani harness of its own
  (`crates/rsk-fs/src/powercut.rs`, `delete_landed`) — a strictly better home
  than a fuzz target, and the natural place for
  `ResetNeverWeakensSurvivingState`'s Fs-layer instance.
- **`fuzz/fuzz_targets/kv_durability.rs` — still no.** `:135` and `:150` are
  pure KV atomicity over one key at a time ("neither old nor new", "not
  garbage") and `:171` is durability. No ordering claim, no security state, no
  FIDO fids. Naming any of the six there would be the wrong mapping.

`fuzz/fuzz_targets/cross_applet.rs`'s `OP_RESET_CARD` arm was looked at again
now that the seam invariants exist, and **refused again**: it asserts
`pin_ref_ready` is false for every PIN reference after the transition, and that
function reads `disp.current()` (`crates/rsk-device/src/ccid.rs:305-313`) — the
selection, not the status. `NoStatusOutsideItsSelection` is about the status.
The oracle that would carry it is a behavioural probe (re-SELECT and expect
`6982` from a PIN-gated operation), and the previous round's rule stands: an
oracle nobody can run enough executions to trust costs another agent a night.

So the traceability is still mostly a plan, and it is stated here as one. The
obstacles are known and unequal, which is why this is not just a to-do list:

- `NoCrossTransportTouchConsumption` **is proved now**, and the row above is the
  first one this table changed. It could not be while its whole mechanism lived
  in `firmware/src/presence.rs`, a `no_std` embassy-rp binary that no
  `cargo kani -p` can build; the arbitration was lifted into
  `crates/rsk-device/src/presence.rs`, behaviour unchanged, and the two clauses
  the model names — `TouchCancel`'s `cancelBy = scope` and `TouchConfirm`'s
  `usedBy`— are `no_cross_transport_touch_consumption_cancel` and
  `..._confirm` in `presence_kani.rs`.
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
- **`DeviceUnlock` is ungated and needs no device lock.** The real vendor
  `UNLOCK` (`vendor.rs:543-566`) requires the seed to be stored *wrapped* — only
  a soft-locked device has an `EF_KEY_DEV_ENC` to open — and the host to present
  the 32-byte lock key. The model requires only a live flash seed. It also omits
  `AUT_DISABLE` (`config.rs:394-395`), which only ever *clears* the RAM copy.
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
  **both** ends of a wait (`crates/rsk-device/src/presence.rs:196` *and*
  `:230`), so removing either alone leaves the model green — a reviewer trusting
  one citation would see nothing fall. The Kani harness has the same blind spot
  and says so; the unit test `w8_…` is what pins the drop at exit.
- **The button build only** (`presence.shows_confirm() = FALSE`), so the reset
  window always applies; a display build bypasses it by design (`reset.rs:32`)
  and that path is unmodelled.
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
  (`crates/rsk-oath/src/lib.rs:356-358`) as a Guard/Policy pair and
  `AccessCodeRemovalNeedsTheCode` is its own invariant. Measured exactly as the
  diagnosis predicted: the action added is **bit-identical at 662 distinct
  states** (+48 transitions, all into already-reachable states), while
  `BugRemoveCodeUnvalidated` still falls RED in 77 — a violation no state
  predicate could ever have seen, caught by the step recorder.
- **`pin_fresh` never outliving `has_pin` is written as an ASSIGNMENT**
  (`fresh' = (held'["pivPin"] /\ fresh)`), so breaking it is invisible: the
  reviewer's mutant is GREEN at 1 056 against 666, and the consequence is masked
  because `PivKeyOpGuard` also tests `held["pivPin"]`. The same shape as
  `RamNeverOutlivesFlashSeed` before it was asserted, one module over, and the
  same repair would close it.
- **`NoKeyOpOnTheAdminStatus` rests entirely on two assignments.** Deleting the
  single `viol` write from `AdminOp`, `PgpKeyOp` or `OathChangeRefused` makes
  their own mutants GREEN at bit-identical counts. That is what a ghost-only
  invariant means and it is expected — but the sibling module has moved half its
  ghosts to structural clauses and this one has not.
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
the synchronous worker (`worker.rs:637-660`) never parks a sequence, the
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
| `WF_vars(OpAdvances)` | **18 actions** | the synchronous worker: one `Exchange` at a time, under a lock, dispatch runs to completion (`worker.rs:637-660`) | sound **because** every disjunct is gated on `op.kind` while `Idle` gates every `*Start` — now asserted, not argued |
| `WF_vars(TouchTimeout)` | one action | `PRESENCE_TIMEOUT_MS` (`crates/rsk-device/src/presence.rs:215-216`) | sound |
| `WF_vars(WalkExpires)` | one action | `expire_stale_sequences` (`state.rs:620-626`) | sound |
| `WF_vars(LocalCeremonyEnds)` | one action | the ceremony's own dispatch puts `WAIT_SCOPE` back (`worker.rs:519-521`) | sound — the E160 repair |

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
