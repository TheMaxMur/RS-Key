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
| `NoAuthorizationBypass` | No protected operation completes without the live authorization its own gate requires | `crates/rsk-fido/src/`: `getassertion.rs:384-387` · `makecredential.rs:454-457` · `config.rs:222-224` · `credmgmt.rs:277` · retry ladder `clientpin.rs:719-804` · soft lock `state.rs:284-291` + `crates/rsk-device/src/ctap.rs:215-222` · reset window `reset.rs:151-157` · walk owner `state.rs:169-179`, `credmgmt.rs:338` |
| `NoCrossTransportTouchConsumption` | A presence decision produced for one transport is never applied to another — neither a confirm nor a cancel | `crates/rsk-device/src/presence.rs`: `Arbiter::pending_for` · `::request_cancel` / `::cancel_otp_wait` (the scope guards) · `ButtonWait::wait` (the `spent` latch). `firmware/src/presence.rs` keeps only the board half. **The stale-cancel drop that carries this property is the one at the wait's ENTRY.** The exit clear cannot substitute for it — a cancel latched by a dispatch that never entered `wait` is never seen by the exit — see "The cancel that no wait was open for" |
| `NoTokenAfterInvalidation` | A grant invalidated by a PIN change, PIN set, reset, `stopUsingPinUvAuthToken` or power cycle never authorizes again | `crates/rsk-fido/src/`: `state.rs:484-497` (`reset_pin_uv_auth_token`) · `state.rs:542-556` (`stop_using_token`) · `state.rs:590-602` (`expire_stale_token`) · `clientpin.rs:300-311` · `seed.rs:310-311` (`clear_ppuat`) |
| `NoAccessibleSecretWithoutGate` | No live secret is reachable while the gate record that protects it is gone | `crates/rsk-fido/src/`: `reset.rs:127-149` (`is_fido_gate_fid`) · `reset.rs:51-66` (phase order) · `credmgmt.rs:249-265` (`authorized_by_ppuat`) · `clientpin.rs:213-217`, `:824-828` |
| `NoUnmanageableCredential` | Every live credential is reachable by the management surface (its `EF_RP` entry exists) | `crates/rsk-fido/src/`: `credential.rs:804-826` (registration write order) · `credmgmt.rs:657-711` (`delete_credential` / `decrement_rp`) · `passkeys.rs:89-151` (`for_each_rp`, the `EF_RP` walk the display lists from) |
| `ResetNeverWeakensSurvivingState` | No prefix of an `authenticatorReset` — torn or complete — leaves a surviving usable secret whose gate has already gone, where "surviving" counts the RAM copy of the seed as well as the flash record | `crates/rsk-fido/src/`: `reset.rs:30-75` (`reset`, session then seed then two phases) · `reset.rs:57-60` (`ctx.state.reset()` ahead of every flash write) · `reset.rs:77-112` (`sweep`, and the `Err` at `:95-99` that leaves the device running) · `reset.rs:138-146` (`is_fido_gate_fid`, incl. `EF_BACKUP_SEALED`) · `reset.rs:199-201` (`survives_factory_reset`) · `crates/rsk-fido/src/lib.rs:183-187` (`Ctx::load_keydev`, the RAM copy that wins) · `state.rs:422-432` (`FidoState::reset`, what drops it). Shipped twin for its third clause: `reset_tests.rs::a_torn_reset_never_unseals_a_surviving_seed` |

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
this invariant in 454 454 states. Without it, that run comes back green.

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
| `BugCredBeforeRp` | `credential.rs:807-826` write order | `NoUnmanageableCredential` | 820 states |
| `BugDeleteRpBeforeCred` | `credmgmt.rs:664-671` — `decrement_rp` ahead of the `EF_CRED` delete | `NoUnmanageableCredential` | 111 503 states |
| `BugTokenSurvivesPinChange` | `clientpin.rs:311` | `NoTokenAfterInvalidation` | 15 299 states |
| `BugSetPinKeepsPpuat` | `clientpin.rs:213-217` | `NoTokenAfterInvalidation` | 416 314 states |
| `BugChangePinKeepsPpuat` | `clientpin.rs:300-304` | `NoTokenAfterInvalidation` | 11 183 states |
| `BugStopUsingKeepsPerms` | `state.rs:546-547` zeroing perms | `NoTokenAfterInvalidation` | 1 404 states |
| `BugNoConsumeAfterUp` | `state.rs:518-530` (GHSA-wqjm-653g-hgw3) | `NoAuthorizationBypass` | 275 564 states |
| `BugUnscopedCancel` | `Arbiter::request_cancel`'s scope check | `NoCrossTransportTouchConsumption` | 127 states |
| `BugTouchNotSpent` | `ButtonWait::wait`'s `spent` latch | `NoCrossTransportTouchConsumption` | 5 717 states |
| `BugSoftLockLostOnWarmReset` | `ctap.rs:215-222` `PinLock` carry | `NoAuthorizationBypass` | 4 993 states |
| `BugWarmResetReopensWindow` | `reset.rs:156` `!warm_boot` | `NoAuthorizationBypass` | 126 states |
| `BugCmWalkIgnoresChannel` | `state.rs:172` channel equality | `NoAuthorizationBypass` | 1 242 states |
| `BugSeedDoesNotLead` | `reset.rs:61-65` / `fs.rs`'s `first` — the pre-0x08BF wipe | `NoUnmanageableCredential` | 55 765 states |
| `BugWrongPinKeepsToken` | `clientpin.rs:779` — the pre-E38 tree, a mismatch that keeps the token | `NoTokenAfterInvalidation` | 623 states |
| `BugConsumeKeepsMcGa` | `state.rs:522-528` — a §6.5.5.7 triad narrowed to the config permissions | `NoAuthorizationBypass` | 3 383 states |
| `BugNoDropStaleCancelAtEntry` | the wait-entry clear (`crates/rsk-device/src/presence.rs:192-193`) — the wait-entry cancel drop | `NoCrossTransportTouchConsumption` | 151 states |
| `BugStateResetAfterWipe` | `reset.rs:57-60` — `ctx.state.reset()` moved back behind the flash work, which is the regression E76's own review caught | `ResetNeverWeakensSurvivingState` | 38 880 states |
| `BugPanelCancelable` | the panel half of `request_cancel`'s scope test (`crates/rsk-device/src/presence.rs:116-120`) — E45's ruling | `NoCrossTransportTouchConsumption` | 238 states |
| `BugUnscopedOtpCancel` | `cancel_otp_wait`'s own scope test (`crates/rsk-device/src/presence.rs:124-134`) — the second writer of the same cancel flag | `NoCrossTransportTouchConsumption` | 237 states |
| `BugLocalPinKeepsToken` | `ends_host_token` (`crates/rsk-display/src/gates.rs:139-146`) — E66, the panel's PIN pad as a fourth door | `NoTokenAfterInvalidation` | 1 604 states |

And the three that break a **liveness** property rather than an invariant. They
are a separate `LIVE_BUGS` list in `gen-configs.sh` on purpose: a wedge is a
perfectly safe state, so putting them in the table above would have meant three
mutants nothing catches.

| Mutation switch | Removes | Target property | Caught in |
|---|---|---|---|
| `BugAssertWedgesOnTimeout` | only a confirm completes a getAssertion | `EveryOpQuiesces` | 79 523 states |
| `BugWaitScopeNotCleared` | `worker.rs:521` `set_wait_scope(SCOPE_NONE)` | `EveryWaitReleases` | 76 446 states |
| `BugWalkNeverExpires` | `state.rs:613-619` `expire_stale_sequences` | `EveryWalkCloses` | 93 607 states |

**One mutant needs a companion, and that is a result.** `BugBackupSealedNotAGate`
rebuilds audit run-36's class — the backup marker swept ahead of the seed it
protects — and once the seed leads the wipe unconditionally (0x08BF) the window
it re-opens is over a seed that is already gone, so it is **not falsifiable on
its own any more**. Its configuration therefore carries `BugSeedDoesNotLead`
under it, from a `companion_bug` table in `gen-configs.sh`. A mutant that stops
firing because a fix subsumed it is worth knowing; a mutant that stops firing
silently is the failure this file exists to avoid.

**23 of 23 mutants are caught, each by the invariant that names it**, and 3 of 3
liveness mutants by the property that names them.
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
test `user_verified()`, but `config.rs:222-224` and `credmgmt.rs:277` test the
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
`:521`), not around the touch wait, so `Arbiter::request_cancel` (`crates/rsk-device/src/presence.rs:116-120`)
accepts a cancel during a FIDO command that never opens one — getInfo, a
capability-denied CBOR, a silent `up:false`. **Nothing clears
`CANCEL_REQUESTED` when that dispatch ends**, and the next dispatch may be CCID
or OTP, where every applet's presence goes through the same
`ButtonPresence::wait` reading the same global.

the wait-entry clear (`crates/rsk-device/src/presence.rs:192-193`) eats it at wait entry, and that is the whole defence.
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
is why `ctx.state.reset()` moved ahead of the flash work (`reset.rs:57-60`).

Both halves of the blindness are now modelled, and each had to be closed
separately:

- **The RAM copy.** `ram` is `state.keydev_dec` (`state.rs:336-338`);
  `SeedReachable == store.seed \/ ram` is what "the owner's seed is still
  reachable" means; `DeviceUnlock` is the vendor `UNLOCK` (`vendor.rs:543-566`)
  that is its only door. `KeepOpen` / `KeepSurv` move the wipe's own claim — that
  what a tear leaves behind is undecryptable — from the flash delete to the
  moment the **last** copy dies.
- **The failed sweep.** `ResetAborts` is any `?` in `reset.rs:64-69` returning
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
| `Shipped.cfg` (the tree as it stands) | **GREEN, exhaustive** | 962 227 379 | 79 985 500 | 52 | **1971 s** |
| `Historical_E76.cfg` (the seed-lead taken back out) | RED `NoUnmanageableCredential` | 665 750 | 99 770 | 13 | 2 s |
| `Historical_E77.cfg` (`FixPpuatRequiresPin` taken back out) | RED `NoAccessibleSecretWithoutGate` | 1 001 124 | 148 629 | 14 | 2 s |
| 23 × `Mut_*.cfg` | RED, each caught | 255 – 1 833 544 | 137 – 266 831 | 5 – 15 | ≤ 4 s |
| 23 × `Solo_*.cfg` | RED, each on its **own** target | 272 – 1 802 948 | 150 – 264 030 | 5 – 15 | ≤ 3 s |
| `Solo_NoAccessibleSecretWithoutGate.cfg` | RED, the repaired clause | 2 950 708 | 454 454 | 16 | 6 s |
| `Seams.cfg` (the second module) | **GREEN, exhaustive** | 2 858 | 205 | 9 | < 1 s |
| 6 × `SeamMut_*.cfg` / 6 × `SeamSolo_*.cfg` | RED, each on its own target | 77 – 483 | 27 – 83 | 4 – 5 | ≤ 1 s |

Only `ShippedFixed.cfg` is an exhaustive search; every RED row stops at the
first counterexample, so its counts move a few percent between runs with the
BFS order the two workers happen to take. The green row's 13 232 120 distinct
states is the reproducible figure. TLC's reported *depth* is not quite
deterministic under 2 workers (49 or 50 between runs of the same config); the
single-worker run says **49**, and that is the figure in the table. The full
table is regenerated by `./run-tlc.sh all` into `out/MATRIX.txt`.

The green row is **12× the state space this model carried two rounds ago and
24× the wall clock**, and the growth is all fidelity: `ram` and `ResetAborts`
took it from 6 664 764 to 17 190 324, and the panel, the OTP owner and the
on-panel PIN door took it from there to 79 985 500. The last of those three is
the expensive one — `LocalPinOk` refills the persistent retry budget without
clearing the RAM soft lock, which makes `(retries, lock)` pairs reachable that
were not. It is a state the firmware really is in; the cost of saying so is on
this row.

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
every clause guarding it free. An earlier revision measured it with `-coverage`
over the green run and found no zero-total row among 41 actions plus `Init`.
That measurement has **not been repeated since the model reached 48 actions and
1971 s** — what is measured for the seven added this round is narrower and is
stated as such: five of them appear in a counterexample trace, which is proof
they fire (`DeviceUnlock` and `ResetAborts` in `Solo_BugStateResetAfterWipe`,
`LocalCeremonyStart` in `Solo_BugPanelCancelable`, `OtpCancelWait` in
`Solo_BugUnscopedOtpCancel`, `LocalPinWrong` in `Solo_BugLocalPinKeepsToken`).
`LocalCeremonyEnds` and `LocalPinOk` are unmeasured.

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
(`crates/rsk-device/src/presence.rs:116-120`) is what refuses a host cancel
against any of them. `BugPanelCancelable` loosens exactly the panel half of that
test — the narrow mistake somebody could make while keeping the CCID half — and
falls in 238 states.

**E66 — the on-panel PIN pad is a fourth PIN door.** `local_pin_gate`
(`crates/rsk-display/src/gates.rs:114-200`) spends the **same** persistent
`EF_PIN` retry counter the wire path spends, because
`spend_and_verify_local_pin` is `spend_and_verify_pin_at(EF_PIN, ..)`
(`crates/rsk-fido/src/clientpin.rs:1019-1026`). A clientPIN refused there is
changePIN's failed old-PIN check performed locally, so it must end the host's
outstanding grant exactly as `clientpin.rs:779` does. `ends_host_token`
(`crates/rsk-display/src/gates.rs:139-146`) is the Rust's own test and it is
deliberately narrow twice over: the FIDO scope only, and only with budget left,
because a `Blocked` verdict at zero was turned away before any compare.
`BugLocalPinKeepsToken` is the door that does not close: 1 604 states.

What the pad does **not** do is go through the CTAP session at all — no ECDH
regeneration, no RAM 3-strikes lock, no journal
(`crates/rsk-fido/src/clientpin.rs:1013-1017`) — so `LocalPinWrong` is not a
`PinAttempt` here either. The persistent 8-try counter is the whole gate, and a
host-soft-locked device still takes PIN entry at the pad, which is the
documented recovery.

**`SCOPE_OTP` needed its own mutant, not a share of `BugUnscopedCancel`.**
`cancel_otp_wait` (`crates/rsk-device/src/presence.rs:124-134`) is a **second
writer of the same `cancel_requested` AtomicBool** the CTAPHID door writes; the
only thing keeping the two apart is its own scope test, in a different function.
`BugUnscopedOtpCancel` removes that one: 237 states.

Three things are **not** modelled and are named rather than implied. The device
PIN (`EF_DEVICE_PIN`) is a separate flash record with its own budget and it
gates every on-panel flow that reveals a secret; none of that is here. The
display **build** is not modelled either — `presence.shows_confirm()` stays
FALSE, so the reset window still applies where a display build bypasses it
(`reset.rs:31`), and `ButtonWait`'s `spent` latch stays where that build
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
| `ReselectPreservesAccessStatus` | A re-SELECT of the same AID changes no access status. **A conformance claim, labelled as one** | `crates/rsk-piv/src/lib.rs:319-322` · `crates/rsk-openpgp/src/lib.rs:357-360` |

The fourth one points the other way from the first three and that is why it is
separate: `637ed98` **widened** the authentication window, so no safety
invariant here can see it, and without a property of its own the switch that
rebuilds the pre-`637ed98` tree would be a mutant nothing catches. Its authority
is SP 800-73-4 pt 2 §3.1.1 (a `shall`), OpenPGP 3.4.1 §4.2, and a YubiKey 5.7.4
measured keeping every status through a re-SELECT on both applets.

**There is no cross-applet rule for what a refused authentication costs, and
writing one would have made the shipped tree red for two deliberate reasons.**
PIV's `CHANGE REFERENCE DATA` takes no `&mut Session` at all
(`crates/rsk-piv/src/lib.rs:494-518`) — SP 800-73-4 and a measured YubiKey both
keep the status through a refused change. OATH's access-code `VALIDATE` keeps
the standing unlock too (`crates/rsk-oath/src/lib.rs:539-541`), because a MAC
challenge-response has no retry counter for a refusal to protect. OATH's OTP-PIN
`CHANGE` **does** drop it (`aa47867`), and OpenPGP's refused CHANGE clears the
addressed reference. Three applets, three rules, each settled by a different
authority — so `NoStatusAfterARefusedAuth` is keyed on the reference the model's
own actions report as refused, and the two exempt actions deliberately report
nothing.

| Mutation switch | Rebuilds | Target invariant | Caught in |
|---|---|---|---|
| `BugSelectKeepsOtherApplet` | `crates/rsk-sdk/src/applet.rs:379-387` — the `deselect` a select of a *different* AID runs | `NoStatusOutsideItsSelection` | 27 states |
| `BugReselectResetsStatus` | `637ed98` taken back out: PIV and OpenPGP resetting on every select | `ReselectPreservesAccessStatus` | 42 states |
| `BugCardResetKeepsStatus` | `crates/rsk-device/src/ccid.rs:327-342` — the ICC power transition | `NoStatusOutsideItsSelection` | 29 states |
| `BugAdminOpensKeyOps` | `e5da38b` taken back out: PW3 standing in for PW1/PW2 | `NoKeyOpOnTheAdminStatus` | 67 states |
| `BugFailedChangeKeepsStatus` | `aa47867` taken back out: a refused OTP-PIN change that leaves the safe open | `NoStatusAfterARefusedAuth` | 74 states |
| `BugPinFreshNotSpent` | `crates/rsk-piv/src/auth.rs:114-118` — one VERIFY, one key operation | `NoKeyOpOnTheAdminStatus` | 83 states |

`Seams.cfg` is **GREEN, exhaustive, 2 858 states generated / 205 distinct at
depth 9**, and 6 of 6 mutants are caught by the invariant that names them.

**One of those six needed the property repaired first, and it is the useful
result.** `BugPinFreshNotSpent` ran **green** as written: stopping `pin_fresh`
from being spent also leaves the Policy that reads `pin_fresh` satisfied, so a
second key operation on one VERIFY looked legal to the invariant that was meant
to forbid it. The repair is a ghost `pfresh` — the freshness the *requirement*
leaves behind, always spent — beside the `fresh` the Rust holds. The two are
equal in every state of the shipped tree (`Seams.cfg`'s 205 distinct states are
bit-identical before and after), and they diverge only under the mutant, which
now falls in 83.

### And a `GREEN` verdict that meant nothing

`Seams.cfg` first came back **GREEN over one distinct state at depth 1**, with
every invariant holding vacuously, because `fresh' = held'["pivPin"] /\ fresh`
is `(fresh' = held'["pivPin"]) /\ fresh` — `=` binds tighter than `/\` in
TLA+ — which turned an assignment into an extra guard and disabled both SELECT
actions. `run-tlc.sh` now reports `VACUOUS: nothing was enabled` instead of
`GREEN` when a passing run has fewer than 2 distinct states or a depth below 2.
Two is not a judgement call: below it the `Next` relation fired nothing at all.
Mutation-tested by putting the parentheses back and watching the row change.

## Traceability — measured, not asserted

The point of naming the invariants was that one property should be greppable
from this model to the Rust that implements it, to the Kani harness that proves
a bounded slice of it, to the fuzz target that hammers it. Grepped over the
whole tree (untracked files included) on 2026-08-12:

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
  `?` in `reset.rs:64-69` as one transition — a `force_delete` error, a truncated
  `for_each_key` (`reset.rs:95-99`), the `RESET_MAX_DELETES` backstop, a failed
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
  **both** ends of a wait (`crates/rsk-device/src/presence.rs:193` *and*
  `:230`), so removing either alone leaves the model green — a reviewer trusting
  one citation would see nothing fall. The Kani harness has the same blind spot
  and says so; the unit test `w8_…` is what pins the drop at exit.
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

### Liveness — three properties, and what is deliberately NOT asserted

`Spec` is still safety-only; `FairSpec` adds weak fairness on three things and
`Liveness.cfg` checks `EveryOpQuiesces`, `EveryWaitReleases` and
`EveryWalkCloses` against it. The fairness is the load-bearing part, because an
assumption the implementation does not honour makes its property meaningless:
the synchronous worker (`worker.rs:637-660`) never parks a sequence, the
presence wait carries `PRESENCE_TIMEOUT_MS` (`crates/rsk-device/src/presence.rs:212-213`), and
`expire_stale_sequences` (`state.rs:613-619`) retires an idle cursor. Nothing
else is fair — not a press, a release, a host cancel, a power cut, a warm reset
or any `*Start` — because assuming a user eventually touches or a device is
eventually replugged would prove liveness the device does not have.

That is why **`lock.soft ~> ~lock.soft` is not asserted.** The soft lock clears
only on a correct PIN or a real power cycle, and neither is the device's to
promise; asserting it would need `WF(PowerCut)`, which is a claim about the user.

`Liveness.cfg` runs at **smaller constants than the safety matrix** — one
relying party, one channel, `MaxRetries` 2 : `MismatchLimit` 1 — and the
reduction is a parameter of the same generator function, not a hand-edited file.
`Liveness_Full.cfg` is the same three properties at the safety matrix's own
constants, so the price is measured rather than assumed — and the measurement is
**15.7×**. Over the identical 6 664 764 distinct states, `Shipped.cfg` checks six
invariants in 94 s and `Liveness_Full.cfg` checks three properties in **1475 s**;
TLC builds a behaviour graph on top of the state graph (19 994 292 nodes here)
and walks it for each temporal branch. Both are GREEN, so the reduction costs
nothing in confidence at these constants — it costs 22 minutes of wall clock,
which is why the routine configuration is the small one.

There is still no `SYMMETRY` on `RPs`/`Channels`, which costs time and not
soundness.
