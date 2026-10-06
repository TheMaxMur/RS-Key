<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Testing roadmap using SQLite methods

This plan extends RS-Key's existing tests toward the methods described in
[How SQLite Is Tested](https://www.sqlite.org/testing.html) and
[TH3](https://www.sqlite.org/th3.html). The goal is measurable coverage of
decisions, independent checks of results, systematic failure injection and
repeatable testing of the delivered firmware. This is planned work, not a
claim that RS-Key has reached SQLite's assurance level.

SQLite reports 100% branch coverage and MC/DC for its core, with a narrower
scope than its whole repository. Its testing also includes independent
harnesses, combined input and database fuzzing, failure injection and tests of
compiled products. Those methods fit an authenticator after adapting the
inputs and failure model. SQL workloads and malloc failures do not directly
describe a firmware that has no heap.

## Current baseline

Measured on 2026-10-04 at `cc6757dd` on `develop`:

| Measurement | Result | Scope |
|---|---|---|
| Unit source lines | 38379/39591, 96.94% | Default host workspace, excluding `firmware` and `rsk-wipe` |
| Unit functions | 3244/3272, 99.14% | Same selection |
| Fuzz source lines | 20568/32545, 63.20% | Union of repository-source LCOV records, including vendored sources |
| Branch outcomes | 6509/7646, 85.13% | Pinned nightly, default host workspace before this slice's new cases |
| MC/DC | Unsupported by the pinned rustc | No percentage is established |

The unit run passed 3064 unique tests, with five existing ignored tests. All
52 fuzz targets were replayed; clean timed campaigns executed 99077751 inputs
without a crash. These execution counts measure different things.
[Testing](testing.md#host-tests) records the scopes and controls. The local
raw reports are in `target/coverage-100-20261004/`; they are not committed
release evidence.

After the first slice's four new tests, the isolated condition run passed 3068
unique tests plus the child-process repeat, with the same five ignored cases.
It recorded 38384/39591 lines (96.95%) and 6790/7975 condition outcomes (85.14%).
Its denominator contains 329 more outcomes than the older `--branch` run;
this is a different instrumentation mode, not a like-for-like improvement.
LargeBlobs itself reached 48/48 instrumented branch outcomes, up from 42/48, with identical
branch selection in both modes. Raw exports, calibration, feature closure and
residuals are in `target/coverage-decisions-20261004/`.

Existing checks already include stateful fuzzing, byte-level NOR power cuts,
command-level cut sweeps, Miri, cargo-mutants, TLA+/TLC, Kani, native and image
emulation, USB/IP, interoperability and device tests. Extend those facilities
rather than duplicating them. The [formal roadmap](roadmap.md#where-the-work-is-going)
and [assurance matrix](assurance-matrix.md) retain their own meanings.

## Scope and completion target

The first coverage scope is the production code in the host-testable firmware
crates, including transports, applets, storage, display and cryptography.
Report test fixtures and verification helpers separately while retaining the
current raw workspace report. Treat `firmware`, `rsk-wipe`, C/assembly backends,
vendored dependencies and each host-tool workspace as separate evidence
scopes. A host Rust percentage cannot stand for all of them.

The target is 100% reachable statement, function and branch coverage in each
declared core configuration, and 100% MC/DC of the instrumentable Boolean
decisions, starting with security decisions. MC/DC requires evidence that
each condition independently changes the decision. Merely taking both
branches or enumerating Boolean values is insufficient.

Preserve the raw percentages and list every residual. A proven unreachable
exit may be explained with its invariant and supporting evidence, but it
still remains in the raw report. A report with exclusions must label its
scope and show the exclusions. Unsupported instrumentation remains unknown;
it cannot establish a whole-core 100% claim. Do not remove defensive checks,
lower capacities or weaken assertions to meet a number.

## Implementation order

Phase 1 has calibrated condition instrumentation and separate raw reports for
the default workspace and seventeen feature profiles. Phases 2 through 7 have
additional authorization, recovery, fuzzing and delivered-image evidence;
their whole-scope criteria remain open. Phase 8 retains profile evidence in the
existing CI jobs, whose changes have only been exercised locally. The dated
results below identify their compiler, host and source selection. Mapping
warnings, unsupported MC/DC and device-only gaps remain visible limitations.

| Phase | Work | Depends on |
|---|---|---|
| 1 | Establish trustworthy coverage measurements | Current baseline |
| 2 | Cover branches and independent conditions | 1 |
| 3 | Extend systematic failure injection | 1; feeds 2 |
| 4 | Strengthen independent oracles and mutation tests | 2 and 3 |
| 5 | Extend fuzzing across commands, state and faults | 3 and 4 |
| 6 | Exercise build configurations and integration stress | 1; applies 2 through 5 |
| 7 | Verify the delivered image and resource limits | 3, 4 and representative configurations from 6 |
| 8 | Make the evidence reproducible in CI and before release | Incrementally from 1; completion after 2 through 7 |

## Phase 1 Establish trustworthy coverage measurements

Start with `rsk-fido` authorization decisions, then `rsk-fs`/`rsk-store` and
USB transports. Probe the existing pinned nightly shell and installed
`cargo-llvm-cov` for branch and MC/DC support. The upstream tool documents
`--branch` and `--mcdc` as unstable; rustc's condition instrumentation is not
by itself an MC/DC result. Verify the actual pinned versions before choosing
a command. A toolchain change is a separate maintainer decision.
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) and the
[Rust coverage options](https://doc.rust-lang.org/unstable-book/compiler-flags/coverage-options.html)
describe the available mechanisms, not what our pinned shell has proved.

The 2026-10-04 probe used rustc `1.98.0-nightly` (`61d7280f3`, LLVM 22.1.6)
and `cargo-llvm-cov` 0.8.5. `--branch` compiled and recorded branch outcomes.
`--mcdc` failed at compilation: this rustc accepts `block`, `branch` and
`condition`, but rejects `mcdc`. Rust removed the incomplete implementation
in [rust-lang/rust#144999](https://github.com/rust-lang/rust/pull/144999).
The tool still exposing the flag is not evidence that its compiler supports it.

For a returning `a && b`, `--branch` counted only the first operand; setting
`RUSTFLAGS='-Z coverage-options=condition'` counted both. The calibrated pairs
were `(true, true)`, `(false, true)` and `(true, false)`: 4/4 outcomes with all
three, 3/4 after omitting the scope refusal, and 4/4 after restoring it.
Condition outcomes remain distinct from MC/DC: their aggregate counts do not
record the independence of each condition in every production decision.

A separate language-shape probe executed every `match` arm, both `?` exits
and empty/nonempty `for` iterations. It recorded 16/16 lines and 20/20 regions
but zero branches. Those constructs need region/exit checks and semantic
oracles in addition to the reported condition counters. Neither a 0/0 subtotal
nor 100% of instrumented outcomes establishes complete decision coverage.

For each measurement, save the source SHA, target, compiler and LLVM versions,
feature closure, commands, file selection, covered/total counters and raw
JSON/HTML. Keep profile outputs isolated; combine only compatible coverage
maps. Separate source lines from generic instantiations and explain missing
or unsupported decisions. Publish per-crate and per-profile results before
any union, so a large crate cannot hide an untested small one.

**Done when:** a known compound decision has nonzero branch and MC/DC counters
where supported; omitting a case removes the expected counter; the restored
suite restores it. A full host baseline is reproducible with an explicit
list of unsupported constructs and residuals. Missing profiles and zero tests
are reported as missing evidence rather than success.

## Phase 2 Cover branches and independent conditions

Work in this order: authorization and PIN/token invalidation; retries and
reset; storage recovery and commit ordering; CTAPHID/CCID ownership, chaining
and cancellation; applet policies; trusted display; cryptographic validation;
remaining codecs and utilities. Use public command paths wherever they are
the security boundary, with private helpers covered as supporting tests.

For each compound guard, hold the other conditions at values that permit the
operation and change the condition under test. Assert the returned status,
the protected effect and required failure transitions, including retry
consumption and grant invalidation. Include time boundaries,
capacity boundaries, short outputs and each error-return path. Add tests to
the existing sibling test files; do not refactor production code just to make
its private guard easier to call.

Review uncovered lines and unexecuted functions individually in each declared
profile. Classify real missing cases, invariant-unreachable exits, compile-time code and test
helpers. Use existing tests or bounded proofs to support an unreachable claim.
Do not turn every residual into an exclusion.

**Done when:** every reachable branch and function in the declared core scope
is exercised, and every supported Boolean decision has MC/DC evidence. The
critical subset reaches that bar first; it does not establish completion for
the rest. Every residual has a location, reason and evidence, and raw totals
remain visible.

## Phase 3 Extend systematic failure injection

Extend `rsk_fs::cut::sweep`, the storage doubles and `power_cut` over the real
store backend. For every persistent command, vary the failure position through
reads, writes, erases, compaction, commit and recovery. Cover one-shot and
latched faults, corrupt/truncated records, storage exhaustion and failed
read-back. Explicitly model a backend that reports success without applying a
write where the command relies on verification.

After each interruption, reconstruct the store with fresh caches and check
the committed state. Then interrupt recovery itself, reopen again, and verify
that the second recovery remains safe. Exercise upgrades from older supported
record layouts, migration, reset, counters, credentials, attestation, OTP
updates and backup/rekey. Use each operation's contract: some operations
require atomic old-or-new state; accepted non-atomic operations need their
own documented invariant.

For this no-heap firmware, allocation-failure analogues are exhausted bounded
buffers, full stores and unavailable services. Also inject crypto, presence
and panel failures where existing traits support them. A failed read must not
silently turn into an absent secret or a newly provisioned identity.

**Done when:** each persistent command has an explicit recovery oracle and
bounded cut sweep; both torn and completed cases are reached. Combined failure
and recovery scenarios preserve the command's security and durability
contract. Omitted commit/read-back protections are caught by the real suite.

## Phase 4 Strengthen independent oracles and mutation tests

Keep crypto reference vectors and independent implementations, storage shadow
models, protocol specifications and native/image comparisons as distinct
oracles. A round trip through one implementation is useful but insufficient
when both directions can share the same defect. Add checks of status, output,
side effects, permission lifetime and persistent state to existing scenarios.

Use specification vectors and applicable OpenSK, SoloKeys, pico-fido and
OpenPGP cases already present in the repository. Add genuinely missing cases
with source and licence attribution. Check the private Go conformance runner's
licence before redistributing its code. Keep upstream assertion disagreements
visible under the existing divergence policy; repairing a harness failure
does not authorize weakening its assertion. Hardware comparisons against a
YubiKey remain a separate, explicitly authorized lane.

Run `scripts/mutants-all.sh` on changed production lines and the existing full
weekly shards. Prioritize weakened authorization conjunctions, omitted wipes,
wrong counter updates, wrong errors and interrupted commit ordering. Classify
every survivor as a missing oracle, equivalent mutation or unsupported run;
compile failures are not kills. Read the assertion that failed and confirm its
direction. Reuse `scripts/mutants-accepted.txt` and the existing co-mutant
apparatus for justified survivors and model/code comparisons.

Extend Kani and TLA+ evidence where a finite invariant or sequence property
benefits from it. Keep bounds, code correspondence and compiled configurations
explicit. Formal evidence supports the tests; it does not supply an unmeasured
coverage percentage or a whole-firmware theorem.

**Done when:** every critical policy has an oracle that catches its relevant
semantic defects, all supported non-equivalent critical mutations are killed,
and remaining survivors have reviewed reasons. The actual test/fuzz runner
fails on selected controls and passes after byte-identical source restoration.

## Phase 5 Extend fuzzing across commands state and faults

Extend `fido_session`, `cross_applet`, `fs_ops` and `power_cut` first. Generate
command sequences together with initial persistent state, fault positions,
clock advances, cancellation, SELECT and reboot. Include valid authenticated
sequences so deeper states are reached, then vary tokens, permissions, channels
and corrupt state. Exercise successful and refused operations deliberately.

Use semantic oracles from phases 3 and 4 throughout the sequence. Check
authorization, atomicity, recovery, counters, output bounds, cleanup and
agreement with an independent model, rather than only absence of crashes.
Add seeds for branch gaps with known preparation paths and replay them under
Miri when supported. Promote every real finding to a minimized deterministic
regression and retained corpus input with provenance.

Measure throughput, runtime, memory and coverage progress before allocating
longer campaigns. Report per-target and per-profile coverage, plus the union.
Fuzzing must reach its declared input surface, but a target need not reach all
source lines reachable by unit tests. Keep authentication, configuration and
invariant restrictions visible in its residuals.

**Done when:** the stateful targets reach their intended privileged and failure
paths, their semantic oracles kill controls, and their saved corpora replay
deterministically. Long runs retain artifacts and accumulated corpora. The
current 63.20% union is remeasured; target counts or execution totals alone do
not establish completion.

## Phase 6 Exercise configurations and integration stress

Take the build inventory from `firmware/Cargo.toml`, `nix/firmware.nix`, board
presets and the existing assurance matrix. Measure supported configurations
separately, including security profiles, display/headless, relevant crypto and
large-blob options. Use actual per-crate feature closures. The current fuzz
`flavours` union does not prove every individual profile or feature interaction.
Assert observable behavior that confirms the intended branch is compiled and
executed. Reuse equivalent configurations only with evidence.

Run the relevant native and image protocol cases across the declared build
scope. Cover fragmented and pipelined traffic, channel contention, CANCEL,
disconnect/reconnect, timeouts, simultaneous applet requests and USB service
during RSA core1 work. Stress store capacity and compaction using the real
limits. Exercise Linux and macOS hosts; classify Windows/device interoperability
separately where automation is unavailable.

Measure `tools/emu`, `tools/tui`, the Python CLI and test runners in their own
workspaces. Include invalid arguments, transport failure, cancellation and
machine-readable output contracts. These reports must not be folded into the
firmware core percentage.

**Done when:** every declared shipping configuration has applicable tests and
separate results, with gaps and equivalent builds visible. Stress cases have
bounded completion and observable state assertions. No union build or skipped
hardware case is presented as coverage of an untested configuration.

## Phase 7 Verify the delivered image and resource limits

Extend the existing image laboratory and USB/IP checks to execute the release
ELF with its real partition table, worker sequencing, USB stack and core1.
Replay representative command histories through both native and image
backends. Compare protocol meaning and persistent effects; verify randomized
crypto results independently instead of normalizing away meaningful failures.
Run instrumented and ordinary optimized builds against the same contracts.
Where portable and device-specific crypto paths differ, run known vectors
through both and check results independently. Include ordinary unoptimized
builds to expose differences caused by optimization.

Complete the stack and secret-residue matrix for FIDO, PIV, OpenPGP, OATH/OTP,
backup, reset and key generation, including errors and cancellation. Preserve
the existing crypto-size, core1, upgrade, power-cut, PICOBOOT and MSC checks.
Add deterministic resource and latency bounds after measuring stable baselines;
avoid wall-clock assertions whose result depends on parallel test load.

Emulated OTP changes and health faults are laboratory inputs. Emulator results
do not prove silicon behavior, entropy quality, physical timing or physical
attacks. Keep real-board measurements and official FIDO/pico-fido case-ID
comparisons separate, with their exact build, profile, tool version and pending
outcomes. Hardware writes require the maintainer's explicit instruction.

**Done when:** applicable histories pass on the delivered image, including
reload/reboot and boot transports; resource/residue checks have positive
controls. Device-only gaps remain explicitly marked. Selected image defects
are detected by the integration runner, not only a host helper.

## Phase 8 Reproduce the evidence in CI and before release

Extend the existing workflows and runners. Keep a fast PR lane for host tests,
critical decision cases, deterministic corpus regressions, native/image smoke
tests and the existing fast proof tier. Keep daily coverage, fuzzing and Miri;
use the weekly lane for full mutations, formal runs, configuration sweeps,
compound failures and longer stress. Allocate jobs after measuring costs so
the merge gate remains usable.

Keep raw coverage artifacts, profile results, corpus provenance, actual run
counts, unsupported cases and survivor reasons tied to the source SHA. Measure
stable Linux baselines before tightening existing thresholds; the macOS raw
percentage is not an interchangeable Linux floor. Demonstrate detection
through the actual workflow command with a known defect and with missing
evidence, then restore and observe success. Timeouts and infrastructure errors
are incomplete runs, not product passes or semantic mutation kills.

A continuously running fuzz worker is a later deployment option after corpus
persistence and cost measurements. Scheduled CI is not evidence of 24/7
fuzzing. Any future worker must archive minimized findings and retain its
corpus, with periodic deterministic replay in the repository's ordinary tests.

Before release, run the applicable fast and deep suites on the same source
revision and record the exact delivered artifacts. Use the existing
`scripts/check.sh`, `scripts/check-assurance.sh` and release evidence process.
No additional gate registry or numeric test-count pin is required by this
plan. Changes remain local until the maintainer chooses to publish them.

**Done when:** the configured CI rows have actually run on the implementation
revision, a saved report can be reproduced, and every declared release scope
has a verdict or a visible gap. The methods are comparable to SQLite only
within those completed scopes; open phases prevent a project-wide claim.

## First implementation slice

Start with phase 1 on FIDO authorization, storage and transport decisions.
Produce the branch/MC/DC feasibility result and a full branch baseline before
choosing additional thresholds. Then pair each critical gap with its command
test and a semantic mutation, beginning with authorization conjunctions, failed
storage read-back and cancellation ownership. This gives a measurable first
result without changing firmware behavior or duplicating the test apparatus.

The first CTAPHID control relaxed broadcast validation so a continuation frame
was silently ignored instead of refused. The old full USB suite passed all 97
tests with that defect. The new case failed with `None` where
`ERR_INVALID_CHANNEL` was required; after byte-identical production-source
restoration, all 98 USB tests passed. The same case checks that a refusal
preserves the owner's partial request and that its proper continuation still
completes. A development compile error is retained separately and is not a
mutation kill. `mutants-all.sh --in-diff HEAD` selected no production mutants
because this slice changes only test files under `crates/`.

LargeBlobs cases add duplicate-map-key refusal, a protocol-only read parameter,
an oversized write fragment, a zero declared length, repeated continuation
length and continuation overrun. They preserve the stored array on refusal and
complete an authenticated transfer after refused continuations. These tests
exercise existing behavior; neither firmware behavior nor its version changes.

Both gate layers were checked on this slice through composed runs: repair the
failed row, retest the changed cases, then execute rows the first run did not
reach. Formal citations were moved to the unchanged USB tests' new locations.
A pre-existing cold-boot test was missing from the token ledger at `cc6757dd`
as well as in the working tree; it is now registered as test-only, with the
existing gate readings refreshed. Fraction and owner-binding controls now
check current values and owner uniqueness rather than stale total counts.
Disabling fraction matching or owner deduplication failed the intended
assertions, and the ordinary runners passed afterward. No gate was added or
weakened. The next cases target ClientPIN authorization and storage residuals;
the instrumentation limitations above still prevent closing phase 1.

## ClientPIN and store slice

The next seven tests cover missing set/change authorization, legacy token
permissions (including bits above the permission byte), skipped or duplicate
mandatory map keys, PIN text boundaries and failures of either local retry-counter
write. Refusals preserve the PIN/session or the spent budget, with clean controls
showing that the PIN remains usable. These are default and strict-profile host
tests of existing behavior, not changes to the firmware.

The real `SeqStorage` tests run all four combinations of main/counter read
availability. A failed main walk must still yield the healthy counter partition,
and global completion requires both walks. A second case fails one flash program
at each of the first 32 program positions during compaction; it checks the error,
filler removal, live records after remount, an unchanged counter partition and a
successful recovery lap. This is a selected program-failure sweep, not every
power-cut position or a simultaneous-fault proof.

Three semantic controls compiled and survived the previous complete package
suites. The new cases failed in the intended direction: a forbidden legacy
request issued a token, a healthy partition's key was omitted and an interrupted
lap left a live filler (at program budget 3). Production sources were restored
byte for byte and the ordinary suites passed afterward. Compile errors from
developing the test fixture are separate diagnostics, not mutation kills.

The same scoped condition measurement increased ClientPIN from 210/234 to
215/234 outcomes (91.88%), and `rsk-store/src/lib.rs` from 12/14 to 14/14 outcomes
and from 85/88 to 88/88 lines. `rsk-fs/src/fs.rs` remains at 82/88 outcomes in the
raw file summary. These are instrumented source-file subtotals; they do not
establish exhaustive control-flow coverage or coverage of the vendored backend.
Raw before/after JSON, the test-only workspace report, HTML, control logs and source
identity are retained in `target/coverage-clientpin-store-20261004/`.

An eighth case combines a pending forced change with a failure at each flash
read of an authenticated change to the current PIN. It reproduced a real defect
at `cc6757dd`: failure of the fifth EF_PIN read accepted the unchanged PIN and
cleared the policy flag. The verifier comparison now propagates unread storage
as `CTAP2_ERR_OTHER`, preserving the pending change. The automatic read sweep
passes after the fix; it does not hard-code the number of reads. Existing PIN
records remain compatible, and the firmware version is `0x0A8C`.

The final condition report in `target/coverage-clientpin-store-fix-20261004/`
passed 3076 unique tests plus one child-process repeat, with five ignored cases:
38398/39598 lines (96.97%) and 6797/7975 outcomes (85.23%). MC/DC support and
the SDK mapping warning remain unresolved. The TLA+ models were not extended to
prove this storage-read failure; their code references were updated, while the
new command-level regression supplies the evidence for this fix.

## Further ClientPIN and recovery decisions

Eight more tests cover an omitted `pinHashEnc` without spending retries or
replacing a token, each runtime-enabled complexity family over both PIN
protocols and the local pad, missing/short/oversized verifiers, the legacy
one-byte minimum-PIN record and failed local migration of a legacy seed. The
seed test separates a refused append from corrupted authentication data: a
latched write fault alone would hide a missing migration-error guard behind
the later retry-reset failure. Restoring the medium and remounting permits
the correct PIN and recovers the original seed.

Metadata reservation failures preserve all existing records without a backend
write. A failed scrub followed by two marker-write failures retries across
fresh mounts, preserves live data and stops retrying only after the marker
lands. This is a command-level fault double, not a NOR power-cut proof. CCID's
header encoder leaves short buffers untouched and preserves the body. A new
Kani harness checks arbitrary fields and bytes in a twelve-byte buffer, all
slice lengths through that bound, with three reached cover scenarios.

Two compiled semantic controls survived the previous default FIDO suite and
failed the new assertions: skipping the denylist accepted `159753`, and
ignoring a seed-migration error authorized local verification over corrupted
seed authentication data. Production sources were restored byte for byte.
These controls do not claim that every existing build profile missed them.

The unchanged default-host condition scope passed 3084 unique tests plus one
child-process repeat, with five ignored cases. It recorded 38399/39598 lines
(96.97%) and 6805/7975 outcomes (85.33%). ClientPIN increased from 215/234 to
222/234 outcomes (94.87%), and CCID from 31/34 to 32/34 (94.12%). Fs remains
82/88 in the raw summary, although every merged branch coordinate has both
outcomes; that diagnostic does not replace the raw counter. MC/DC remains
unsupported and the 27 SDK mapping warnings persist. Raw reports, controls
and proof logs are in `target/coverage-decisions-next-20261004/`. No firmware
behavior, coverage exclusions or coverage floors changed; fuzz coverage is unchanged.

## Credential codec and combined recovery slice

Eleven more tests cover every short record/output/scratch length at the selected
credential boundaries, invalid resident IDs and oversized cached points, serial
source bounds, truncated trailers and authenticated malformed CBOR or UTF-8.
Credential-management refusals preserve the authorized enumeration, token and
store; oversized authenticated subparameters cannot update or delete credentials,
and short or zero-count records do not enter the returned lists. Positive controls
still decode, enumerate and authenticate valid records.

Two cases sweep command-level mutation faults in both an operation and its first
recovery attempt, then remount and recover on a healthy medium. Deleting either
one of two credentials for an RP or the last credential for another RP preserves
every unrelated raw credential byte and reconciles RP counts. Legacy RP sealing
preserves both domains and hashes, re-arms the scrub and becomes idempotent. The
latched `Snap` faults are not byte-level NOR power cuts or proof that obsolete
cleartext has already been erased.

Two compiled semantic controls survived the previous default FIDO suite. Removing
the mandatory first-map-key guard failed the new exact error assertion; removing
the cached-point bound accepted a point one byte too long. Production sources
were restored byte for byte. These controls do not establish that other build
profiles missed the defects.

A Kani harness checks five-byte, definite two-field maps with symbolic first key
and subcommand in `0..24`, followed by either a duplicate subcommand key or a
protocol key. It proves the corresponding refusal or parsed subcommand, with
unwinding assertions enabled at bound 3. Two helpers assert their unreachability
for this alphabet rather than replacing reachable parser behavior. The harness
passed with zero of 337 failed checks and all three source cover scenarios
reached (three of four generated properties satisfied). Removing the first-key
guard failed the error assertion and both unreachability assertions. Earlier
attempts timed out and are retained as diagnostics. This proves the declared map
shapes, not arbitrary CBOR, authorization or independent-condition coverage.

The same default-host condition scope passed 3095 unique tests plus one child
repeat, with five ignored cases. A fresh build recorded 38411/39598 lines
(97.00%) and 6819/7975 outcomes (85.50%): twelve more lines and fourteen more
outcomes. Credential codecs increased from 141/180 to 150/180 outcomes (83.33%),
and credential management from 121/147 to 126/147 (85.71%). Reusing the previous
build directory produced 113 mapping warnings; an empty build directory restored
the known 27 SDK warnings and reproduced the totals. The underlying SDK mapping
limitation and unsupported MC/DC remain open. Raw reports, controls and proof logs
are in `target/coverage-credentials-20261004/`. Firmware behavior, exclusions and
coverage floors are unchanged; existing Kani roster floors now include the new
harness and its covers. Fuzz coverage is unchanged.

## OATH and OpenPGP PIN persistence decisions

Eleven cases extend the command paths around stored PINs and retry counters.
OATH VERIFY and CHANGE refuse a rejected or silently dropped retry write, a
short read-back and a read-back with the wrong counter. Each refusal closes
standing authentication, retains the verifier and keeps the password safe
closed; a healthy retry still opens the unchanged credential. Invalid stored
PIN lengths are not comparisons. If a correct VERIFY cannot re-arm the scrub,
it retains the old verifier and the charged attempt rather than superseding
that verifier under the latched marker; a later healthy attempt migrates it.

OpenPGP refuses missing retry slots, short or absent retry maxima, empty
read-back at the last retry and malformed verifier records. The tests distinguish an
uncharged record fault from a correct comparison whose retry reset failed.
RESET RETRY without a new PIN preserves the standing admin session and records.
An RC or admin DEK copy that does not open cannot replace PW1 or RC. A healthy
DEK load can defer stale-stage retirement when the scrub re-arm is refused,
then retire the stage on a later healthy load without changing the active DEK.

Two compiled controls survived the previous default applet suites. Removing
OATH's read-back length equality or OpenPGP's addressed-counter length guard
made a correct PIN authorize after a short read-back. Each new test failed
on that unintended success, not on setup or a compiler error. Both isolated
sources were restored byte for byte.

A Kani harness checks arbitrary bytes at lengths zero through four for the
three DEK targets. At unwind bound 5 it proves that a staged header reaches
the authenticated reader only with its target's owner byte, the supported
format and a body byte. All 205 checks passed, with eight unreachable checks;
all four generated cover properties were satisfied. The cover expressions
evaluate their Boolean operands without short-circuiting, avoiding duplicated
unreachable copies. Removing the owner check failed exactly the owner
assertion. This proves the header gate, not AEAD authentication or recovery.
The standard Kani PR runner also proved all 67 selected harnesses and reached
all 49 source covers through its existing floor and vacuity checks.
The roster now counts 99 harnesses and 78 source covers; the full roster was
not solved in this slice, and its previously measured timings are unchanged.

The same raw default-host condition scope passed 3106 unique tests plus the
child-process repeat, with five ignored cases. A new empty build directory
recorded 38419/39598 lines (97.02%) and 6830/7975 outcomes (85.64%): eight more
lines and eleven more outcomes. OATH increased from 433/488 to 436/488 outcomes
(89.34%), and OpenPGP PIN from 165/202 to 173/202 (85.64%). The 27 SDK mapping
warnings and unsupported MC/DC remain unresolved. Reports, source identity,
controls and proof logs are in `target/coverage-pins-20261004/`. This slice
changes no firmware behavior, exclusions, coverage floors or dependencies.
Fuzz coverage is unchanged.

## PIV reference persistence and state proof covers

Four cases cover VERIFY, CHANGE PIN, CHANGE PUK and PUK-based RESET RETRY.
A read-back of zero through three bytes cannot confirm the last charged
attempt, even when the unread buffer byte would equal the expected zero.
Refusals preserve both verifiers and keep that attempt spent; the next attempt
is blocked. Restoring a healthy fixture's budget allows the same command to
complete. A refused reset after a correct comparison also reports a memory
failure, retains the charged attempt and cannot change either verifier.

Refused verifier writes preserve the old references and their usability.
Malformed stored lengths cause no write or retry charge. An empty PIN record
at VERIFY is an absent reference and preserves standing status; other record
faults at VERIFY drop PIN status and freshness. CHANGE and RESET RETRY retain
standing PIN status on these failures, while management authentication remains
in force on all four paths.

One compiled control accepts a zero-byte retry read-back as complete. It passed
the previous default PIV suite's 245 tests, with one ignored, and the new
last-attempt test failed on the unintended `9000` response. Ignoring a refused
retry reset failed both the new test and four existing migration/read-fault
tests; it is additional path coverage, not a newly discovered oracle gap.
Both production sources in the isolated clone were restored byte for byte.

The bounded FIDO two-field-map proof previously generated four properties
for three source covers, with one redundant unreachable copy. Moving the
covers ahead of the assertion branches and evaluating pure Boolean operands
without short-circuiting reached all three generated properties. Its input
alphabet, unwind bound and refusal assertions are unchanged. Removing the
mandatory first-key guard still fails its exact missing-parameter assertion
with all three covers reached. The standard Kani state runner proved all
32 selected harnesses and reached 39 source covers. Its existing allowance
of one dead generated copy remains unchanged; this is not a run of all
99 harnesses or the weekly shards.

The same raw default-host condition scope passed 3110 unique tests plus one
child-process repeat, with five ignored cases. A fresh build recorded
38420/39598 lines (97.03%) and 6831/7975 outcomes (85.66%): one additional
line and condition outcome. PIV's applet root increased from 297/347 to
298/347 outcomes (85.88%). Function coverage remains 3244/3272 (99.14%).
The 27 SDK mapping warnings, unsupported MC/DC and uncounted `match`/`?`
outcomes remain open. Reports, source identity, controls and proof logs are in
`target/coverage-piv-state-20261005/`. Firmware behavior, exclusions, coverage
floors and dependencies are unchanged. Fuzz coverage is unchanged.

## PIV private operations and handshake decisions

Twelve cases exercise GENERAL AUTHENTICATE through the applet's APDU path.
Signing and agreement cover NEVER, ONCE, ALWAYS, a legacy DEFAULT and an
undefined stored PIN policy, before VERIFY, after VERIFY and after a key
operation. Authorization is checked before touch; denied operations return no
private output, preserve the standing management status and cannot acquire PIN
freshness. All four presence results are checked under NEVER, ALWAYS, CACHED,
legacy DEFAULT and undefined touch policies. Only NEVER bypasses the prompt;
every non-confirmation at another policy preserves freshness for a later touch.

A sealed curve inconsistent with the metadata head is refused after touch but
before the PIN spend. Restoring the head makes the same key usable without
another VERIFY. An Ed25519 agreement request is refused before touch; the next
signature verifies independently. Short response buffers at P-256, P-384,
Ed25519 and X25519 operations return a length error after consuming freshness,
and an immediate retry is PIN-gated. Malformed dynamic templates consume neither
touch nor freshness.

Handshake cases reject management answers at private slots, a single-auth
answer to a mutual witness and non-block-sized answers. A mutual witness cannot
be replayed as a single-auth answer using only the encrypted bytes supplied by
the card. Incorrect-length answers consume their challenge without authenticating;
a missing or empty host challenge leaves the mutual witness usable. A correct
witness with a nonempty, incorrect-length host challenge authenticates the host
but refuses its requested cryptogram: the existing command ordering, checked by
the following protected write and read-back. No firmware behavior changed.

Three compiled controls survived all 249 prior default PIV tests, with one
ignored, and failed the expanded suite. Removing the sealed-curve binding and
allowing mutual witnesses at the single-auth verifier both failed on an
unintended `9000`; refunding freshness after a short response failed its spent-PIN
assertion. All three controls were compiled in an isolated clone and the
production source was restored byte for byte.

A fresh raw default-host condition build passed 3122 unique tests plus one
child-process repeat, with five ignored cases. It recorded 38429/39598 lines
(97.05%), 6842/7975 outcomes (85.79%) and unchanged 3244/3272 function coverage
(99.14%). GENERAL AUTHENTICATE reached 299/304 lines and 86/90 outcomes (95.56%),
up from 290/304 and 75/90. Its remaining coordinate diagnostics concern the
key-reference guard at PIN spend and the two challenge-algorithm bindings.
Coordinate aggregation does not replace the four raw missing outcomes. The
normal session writers preserve `pin_fresh` implying `has_pin`; independently
toggling `has_pin` while freshness stays true would require a fabricated state,
not a public command history. These constraints are not exclusions or a new
bounded proof of all histories, including faulted storage.

Reports, source hashes and controls are in `target/coverage-piv-auth-20261005/`.
The 27 SDK mapping warnings, unsupported MC/DC and uncounted `match`/`?`
outcomes remain open. No production source, dependency, exclusion, coverage floor
or proof roster changed. Fuzz coverage is unchanged; no new Kani solve is
claimed for this slice.

## OTP command decisions

Ten cases exercise OTP through the applet's APDU path. Each reserved config
byte is independently refused with a valid CRC at all four slots; refusal
preserves the records, write generation and program sequence. Extended status
checks complete TLV bodies for plain Yubico OTP, HMAC/Yubico challenge-response,
six/eight-digit HOTP and short/static tickets. Only plain Yubico OTP carries
the fixed public-id field.

Both challenge modes cover all four presence answers with and without touch.
Non-confirmation returns no response, writes nothing and advances neither
counter; subsequent confirmation works. HMAC is checked against its digest,
and Yubico responses are independently decrypted to the host challenge and
serial. Short Yubico challenges and both slot-two command offsets are refused.
SELECT checks a lone second classic slot and the extended pair's deliberate
absence from the classic status sequence.

SWAP tests both offset bounds, all valid pairs including self-swaps, and the
first refused write with both source records occupied. A healthy retry moves
both records. Either delete arm accepts an erase that completed despite an
unrelated metadata-read failure, checking the resulting slot contents. These
tests preserve the existing non-atomic SWAP contract. DEFAULT-only cases cover
an omitted scan-map code at each protected slot and an empty legacy device
configuration over an existing record; strict-config compiles those writes out.

Four compiled controls passed all 113 prior default OTP tests and failed the
expanded suite. Ignoring the second CONFIGURE RFU byte returned an unintended
`9000`; removing the HOTP status filter disclosed an extra public-id TLV;
ignoring slot two at SELECT reset the sequence to zero. Removing SWAP's first
offset bound reached an out-of-bounds session-counter swap. All controls ran in
an isolated clone, and its production source was restored byte for byte.

A fresh raw default-host condition build passed 3132 unique tests plus one
child-process repeat, with five ignored cases. It recorded 38430/39598 lines
(97.05%), 6856/7975 outcomes (85.97%) and unchanged 3244/3272 function coverage
(99.14%). OTP's root increased from 219/270 to 233/270 outcomes (86.30%),
and from 589/616 to 590/616 lines. Its 37 raw missing outcomes remain visible.
Coordinate diagnostics include checked APDU-length/slot-array bounds and mode
implications, but also the use-counter ceiling, fused-key read failure between
operations and boot-migration refusals. They are not all unreachable, and
coordinate aggregation does not replace LLVM's raw totals or a bounded proof.

Reports, source hashes and controls are in `target/coverage-otp-decisions-20261005/`.
The 27 SDK mapping warnings, unsupported MC/DC and uncounted `match`/`?`
outcomes remain open. No production source, dependency, exclusion, coverage floor
or proof roster changed. Fuzz coverage is unchanged; no new Kani solve is
claimed for this slice.

## OTP recovery and counter boundaries

Ten cases extend OTP through actual button presses, APDUs and fresh `Fs`
instances over the same medium. A record at `0x7FFE` advances once to `0x7FFF`.
Both a session wrap and a fresh boot leave the saturated counter unchanged
without a write. Older above-ceiling records also stay unchanged. Two refused final
advances across separate boots preserve the stored record and leave the RAM
advance owed; a healthy retry persists it before releasing a ticket.

These tests pin the existing saturation contract. They do not establish ticket
uniqueness past the ceiling: the `(use, session)` position can repeat there.
The [OTP guide](guides/otp.md#yubico-otp-validation) now states that limit and
the need to reprogram with new verifier secrets before reaching it.

CONFIGURE, UPDATE and a first press refuse a fused key lost between the slot
probe and the write; the stored bytes, sequence and counters stay unchanged.
The reader deliberately supplies plausible key bytes even when it returns
failure. Restoring it makes the command work. SWAP refuses an unread latched
key before moving either occupied record, and both writes share one successful
read even if the later status probes fail. Challenge responses verify the
keys after the move; the existing non-atomic SWAP contract remains.

Two refused migration writes preserve plaintext or pre-OTP records through
fresh boots, with and without a fused key. Recovery preserves the full counter
tail, opens the current seal, stays idempotent and produces the next position.
Repeated read faults at each migration probe preserve the old medium and the
scrub marker until a healthy pass. Six inconsistent lengths are refused when
calling the public `Apdu` API directly; that scope is distinct from parsed wire
inputs, whose parser already enforces the advertised length.

Three compiled controls passed all 123 prior default OTP tests and failed the
expanded suite. Acknowledging a failed fused-key write returned an unintended
`9000` and released a ticket; acknowledging truncated CONFIGURE data returned
`9000` instead of `6700`. Re-reading the fused key inside SWAP's writes wrongly
refused a move that had already obtained its device context. Its failing
assertion expects success and measures that coherence contract, not an
authorization refusal. Production source in the isolated clone was restored.

A fresh raw default-host build passed 3142 unique tests plus one child-process
repeat, with five ignored cases: 38444/39598 lines (97.09%), 6870/7975 condition
outcomes (86.14%) and unchanged 3244/3272 functions (99.14%). OTP's root reached
246/270 outcomes (91.11%) and 603/616 lines. Its 24 raw missing outcomes remain
visible; coordinate diagnostics do not replace them. The two existing counter
Kani harnesses verified and reached all four source covers. They assume a
stored counter within the ceiling and prove arithmetic, not whole faulted
histories or uniqueness at saturation.

Reports, source hashes and controls are in `target/coverage-otp-recovery-20261005/`.
The 27 SDK mapping warnings, unsupported MC/DC and uncounted `match`/`?`
outcomes remain open. No production source, dependency, exclusion, coverage
floor or proof roster changed. All ten cases run in both default and
strict-config. Fuzz coverage is unchanged.

## OTP HID transmission and plaintext record bounds

Five cases extend the transport and record tests. `FrameTx` responses of every
length from zero through 72 bytes check the capped payload, CRC residual,
sequence tags, zero padding and exactly one end marker. `active()` stays true
after the last data report until that marker is emitted. Replacing a response
at every report boundary, including before its marker and after draining it,
starts the replacement at sequence zero without carrying old bytes forward.

Plaintext reads preserve every accepted length from 52 through 60 bytes and
clear the previous record's unused tail. Each other length through 88 bytes,
plus 89 and 176, is refused without writing or truncating the medium. A healthy
read then succeeds on the same scratch. Two persistent read faults preserve
the error, clear the old secret and leave the medium unchanged; restoring the
reader allows recovery.

Four compiled controls passed all 133 prior default OTP tests and failed the
expanded suite. Dropping the pending-marker state made `active()` false too
early. Retaining the old sequence started a replacement at `0x41` instead of
`0x40`. Accepting a short plaintext record returned `Some(0)` instead of
absence, and removing the scratch wipe left the previous `0xD3` bytes behind.
These are assertion failures in compiled tests; production source in the
isolated clone was restored.

The remaining checked-copy guards need reachability evidence. A capped TX body
has at most 66 bytes including CRC in its 72-byte buffer; while sending data,
`offset + copied` cannot exceed that total. An accepted plaintext length is at
most 60 in buffers of 60 and 88 bytes. RX accepts only sequence 0 through 9 in
ten complete seven-byte chunks. These arithmetic observations do not constitute
a new Kani solve or erase the raw uncovered outcomes.

A fresh raw default-host build passed 3147 unique tests plus one child-process
repeat, with five ignored cases: 38445/39598 lines (97.09%), 6873/7975 condition
outcomes (86.18%) and unchanged 3244/3272 functions (99.14%). HID reached 34/38
outcomes and the record codec 19/20, gaining three outcomes and one line.
Four raw missing HID outcomes and one record outcome remain visible. Reports,
source hashes and controls are in `target/coverage-otp-hid-record-20261005/`.
All five cases run in default and strict-config. The 27 SDK mapping warnings,
unsupported MC/DC and uncounted `match`/`?` outcomes remain open. No production
source, dependency, exclusion, coverage floor or proof roster changed. Fuzz
coverage is unchanged.

## OTP HID fuzz oracle and copy proofs

`otp_hid` and its Miri mirror now call one shared oracle. RX still consumes
eight-byte reports and refuses to release payload bytes on reset, bad CRC or
an incomplete frame. A second interpretation reads independent response
histories: body length, poll count and body bytes. TX therefore runs without
waiting for a valid RX CRC. Loading another body replaces any pending stream.

Assertions check the capped body, CRC suffix against a separate bitwise
reference, sequence flags, zero padding, one end marker and unchanged output
after exhaustion. Empty input also runs TX, so the existing empty-input gate
row checks these assertions. Four sibling tests exercise every body length
through 73 and every poll boundary, truncated histories, a valid RX frame and
its corrupt counterpart. The Miri roster now contains 55 unique tests in both
default and flavours; listing a roster alone is not execution evidence.

All five OTP oracle tests, including the existing seed replay, passed on the
host in both configurations. The same five passed under Miri's strict
provenance policy with seeds 0 through 7 on the final source. The exhaustive
replacement test runs inside that interpreter, not only as a native fixture.

Three new Kani harnesses run in the existing `pr` and `light3` tiers. The full
`pr` runner verified 70 harnesses and reached 58 source covers. The new nine
covers are reachable without raising the dead-cover allowance. TX uses real
load/next calls and symbolic bodies through 72 bytes; replacing at each data
or marker boundary preserves copy bounds, sequence and exhaustion. RX proves
one arbitrary report from a fresh receiver, including its checked chunk index
and release/reset behavior. Both stub CRC arithmetic; they prove transport
behavior under that abstraction, rather than the CRC function or RX histories.

The plaintext proof uses the real reader and `Fs`, a modeled successful
backend and arbitrary bytes and stored lengths through `MAX_VALUE_BYTES`.
Accepted lengths preserve exactly the returned bytes, rejected lengths clear
the old record, and no read writes the medium. Its valid-slot predicate maps
one slot to FID 7 inside `Fs`'s 24-FID Kani cache. This proof excludes slot
authorization, backend faults and other FIDs; host tests retain those cases.

Three compiled fuzz controls passed the old target and failed the shared
oracle. Losing the pending marker also failed the actual `check.sh` fuzz row,
with its full 52-target build and external replay; other gate rows were skipped
in that isolated experiment. Retaining the old sequence emitted `0x41` instead
of `0x40`, and returning zero from CRC emitted `FF FF` instead of `00 00` for
an empty response. The latter two controls replay fixed inputs through the
compiled libFuzzer target. Two Kani controls failed through `kani.sh` on the
pending-marker assertion and the required refusal of a short record. Failure
locations were inspected; neither was a timeout or a compilation failure.

Fresh default `otp_hid` coverage replayed the same 460 frozen inputs before
and after, including four declared fixtures, with raw profiles cleared for
each stage. HID moved from 89/224 to 92/224 lines and 131/296 to 135/296
regions. This is one target's footprint, not aggregate fuzz coverage. Reports,
source snapshots, binary hashes and controls are in
`target/coverage-otp-hid-assurance-20261005/`. No firmware behavior, dependency
or coverage exclusion changed. The previous default unit result remains the
last measurement: 97.09% lines and 86.18% condition outcomes. It was not
re-measured here; the last aggregate fuzz result remains 63.20%.

## Independent FIDO token authorization conditions

Two wire-level tests exercise makeCredential and getAssertion through
`process_cbor` under PIN protocols 1 and 2. Each ceremony has eleven cases:
valid bound and unbound tokens; bad MAC, missing command permission, missing
UV and inactive tokens in both binding states; and a token bound to another RP.
An unbound token's stale RP hash does not authorize or refuse the request;
successful use binds it to the requested RP. The other conditions remain
permissive while the condition under test changes.

Every refusal must return PIN_AUTH_INVALID with only the status byte, leave
the output tail untouched, request no presence, preserve all stored records
and the store's mutation generation, and leave the token's bytes, flags,
binding and timers unchanged. Repairing only the rejected condition allows
the same token to retry. Successful use asserts UP and UV, refreshes only the
usage timer, binds the RP and consumes permissions down to largeBlobWrite.

Eight compiled controls passed the previous 947 unique default FIDO unit
tests and failed the expanded suite. Removing the permission or RP check in
either command, or UV enforcement in makeCredential, incorrectly returned
success instead of PIN_AUTH_INVALID. Refreshing either command's token before
a refusal changed its usage timer. Binding getAssertion's unbound token before
a refusal changed its RP state. The failing assertions were inspected in
each case; compilation failures and timeouts are not counted as kills.
An isolated clone and separate build directory retain binary hashes before
and after adding the tests. Production source was restored in that clone.
On the final `*_tests.rs` source, removing getAssertion's permission check
also failed the actual `check.sh` host-test row in that clone: success was
returned instead of PIN_AUTH_INVALID. Other rows were skipped for this
isolated control; the normal full gate runs separately.

The five Boolean conditions in each authorization guard now have both
outcomes in the raw per-instantiation counters: the coordinate subtotal moved
from 15/20 to 20/20 across the two guards. This selected subtotal is distinct
from LLVM's file summaries, which remain 178/212 outcomes for makeCredential
and 209/238 for getAssertion. It does not replace those summaries or establish
whole-core MC/DC. The test cases pair the authorization inputs independently;
native MC/DC instrumentation remains unsupported.

A small generic probe reproduces the distinction. Splitting the three
`a && b` input pairs between two instantiations reaches all four coordinate
outcomes, while LLVM's file summary reports 3/4. Running all three pairs in
one instantiation makes that summary 4/4. Both stages use the same compiler,
condition instrumentation and source function, with profiles cleared between
runs. A merged coordinate subtotal therefore cannot silently replace the
standard denominator.

A full default-host condition run passed 3149 unique unit tests plus one
child-process repeat, with five ignored cases. The raw workspace result is
38445/39598 lines (97.09%), 6873/7975 condition outcomes (86.18%) and
3244/3272 functions (99.14%), unchanged from the previous measurement.
The existing report selection omits the new `*_tests.rs` file and retains
verification helpers. The new guard observations do not increase those
aggregate source summaries.
The 27 SDK HTML mapping warnings and uncounted language constructs remain.
Both new tests also passed under strict-config. Raw exports, source snapshots,
reproduction commands and controls are in
`target/coverage-fido-token-20261005/`. Firmware behavior, dependencies,
coverage exclusions and floors are unchanged. Fuzz coverage was not re-measured.

## 2026-10-05 Assertion failure and retry boundaries

Eleven wire-level tests now exercise every truncated prefix of a resident
record, an inconsistent RP-hash prefix, all insufficient output capacities
for getAssertion and getNextAssertion with and without UV, repair of a corrupt
next box, channel refusal near expiry, transient/persistent seed and counter
read failures, and a cut before the next counter write. They check returned
status, published reply length, untouched buffer canaries, persistent records,
counter position and the idle timer. Successful retries verify the signature
against the public key registered earlier and check the expected user and
per-credential signCount. A failed Begin must disarm its walk; a retriable
failed Next must preserve its leg and timer.
They also cover oversized allowList IDs, all UV/allowList combinations for
credProtect=2, and silent discovery through every Next leg without UP or UV.

Seven compiled controls survived the previous default FIDO suite and fail
these tests: persisting either command's counter before encoding its reply,
refreshing the Next timer before refusal, keeping a walk after a failed Begin,
ignoring the stored RP prefix during discovery or allowList lookup, and
ignoring a refused Next counter write. The assertions show the protected
effect or wrong status, rather than counting a compile failure as a kill.
The premature Next counter control also fails the actual `check.sh` host-test
row in the isolated clone; other rows are skipped only for that control.

The existing `fido_session` target also varies assertion output capacities and
checks counter/Next-position preservation on refusal. Seven locally encoded
seeds register another resident credential with a valid token, discover both
accounts, and mix short and complete Next replies with retries. They pass under
default and `flavours`. Two compiled controls pass with the corresponding new oracle
removed and fail through `cargo fuzz run` with it present: a premature counter
write changes stored bytes, and premature timer refresh changes the leg's
timestamp. Restoring the source reproduces the passing binary hash.

| Fuzz control | Oracle removed | Oracle present | Observed defect |
|---|---|---|---|
| Counter persisted before Next output | Exit 0 | Exit 1 | Stored count changes from 1 to 2 on a refused reply |
| Timer refreshed before Next error | Exit 0 | Exit 1 | Timestamp changes from 999 to 1996 on a refused reply |

The fresh raw default-host run passes 3160 unique unit tests plus one
child-process repeat, with five ignored cases. It covers 38446/39598 lines
(97.09%), 6879/7975 condition outcomes (86.26%) and 3244/3272 functions
(99.14%). This adds one line, six condition outcomes and fifteen regions.
The production getAssertion file's standard summary moves from 209/238 to
215/238 condition outcomes. Function totals remain unchanged.
MC/DC, the 27 SDK HTML mapping warnings and the
uncounted language constructs remain open. The full 52-target fuzz union
was not re-measured. Reproduction commands, raw exports, control logs and
seed provenance are in `target/coverage-assertion-failures-20261005/`.
Firmware behavior, dependencies, coverage selection and floors are unchanged.

## 2026-10-06 Profiles, shared fuzz replay and delivered images

The fresh default macOS arm64 condition run passed 3163 unique unit tests,
one child-process repeat and five ignored cases. Its raw result is
38449/39598 lines (97.10%), 6879/7975 condition outcomes (86.26%) and
3245/3272 functions (99.17%). The added display case exercises shared
borrows and PIN state through a cloned `Parked` value. Two retired-slot PIV
cut sweeps cover EC generation and RSA persistence: another slot stays byte
identical, a committed key receives its generated policy, and a key left
without a metadata head cannot authenticate. Ignoring a failed head write
compiles and fails the success oracle in both sweeps; restoring it passes.
These are command-level record cuts, not a replacement for byte-level NOR
cuts or interrupted recovery. PIV keygen's raw line and condition summaries
did not increase. `metrics-after-retired-cuts/` and `retired-cut-controls/`
under `target/testing-completion-20261005/` retain the reports and controls.

The same host-testable workspace also passed with both dev and test
`opt-level=0` under pinned stable Rust: 3163 unique unit tests, one child-process
repeat, five ignored cases and nineteen passing doctests. It took 380 seconds;
`host-unoptimized/` retains the command, compiler, source hashes and output.
This is separate from the failed unoptimized device image described below.

Seventeen separate profiles passed on ARM Linux with the pinned nightly
compiler. They retain JSON, HTML, feature closure, source hashes, exits and
elapsed costs in `linux-profiles/`. These measurements precede the three tests
above; their source snapshots identify that boundary. Their maps are kept
separate, including profiles that change the denominator:

| Firmware features | Raw lines | Condition outcomes |
|---|---|---|
| advertise-pqc | 38448/39598 | 6878/7975 |
| fips-profile | 38383/39598 | 6858/7975 |
| fips-profile,advertise-pqc | 38385/39598 | 6858/7975 |
| strong-pin | 38443/39598 | 6871/7973 |
| strong-pin,advertise-pqc | 38445/39598 | 6871/7973 |
| always-uv | 38446/39598 | 6879/7975 |
| always-uv,advertise-pqc | 38448/39598 | 6879/7975 |
| strict-up | 38440/39598 | 6865/7968 |
| strict-up,advertise-pqc | 38442/39598 | 6865/7968 |
| display | 38453/39609 | 6883/7979 |
| strict-config | 38321/39475 | 6833/7929 |
| largeblob-ext | 38476/39641 | 6867/7976 |
| preview-sign | 39001/40185 | 6948/8055 |
| preview-sign,largeblob-ext | 39035/40228 | 6938/8056 |
| display,strong-pin | 38450/39609 | 6875/7977 |
| display,fips-profile | 38390/39609 | 6862/7979 |
| fido-conformance | 38440/39598 | 6865/7968 |

All seventeen original HTML exports retain six SDK mapping warnings. LLVM's
dump names `Apdu::is_secure_messaging` at hash zero. A separate isolated ARM
Linux full-workspace `fido-conformance` pair removes all six by withholding
`inline` on that fifth SDK method under `cfg(coverage)`. Every raw total and SDK
file summary stays identical. The pair includes the three new PIV/display cases
and records 38443/39598 lines and 6865/7968 outcomes in both builds. Its JSON,
HTML, compiler, commands and source hashes remain in `linux-sdk-mapping-pair/`.
The older seventeen reports are retained with their warnings.
These ARM results also do not establish the x86_64 GitHub lane or whole-core
MC/DC, which the pinned rustc still cannot instrument.

Fresh 52-target corpus replays cover 20569/32552 repository lines (63.19%) in
default and 20216/32806 (61.62%) in `flavours`; vendored sources remain in
both denominators. The maps are incompatible and are not combined. Seven
encoded assertion/retry histories are retained in the existing corpus path.
Miri now imports the actual `fido_session` target body; both configurations
passed its eight declared seeds. The ordinary native replay passed all 52
targets. `fuzz-default/`, `fuzz-flavours/` and `shared-session-miri*.log`
retain these independent results.

Separate host-tool measurements precede the later image fixes. TUI has
1637/3424 lines and 192/302 condition outcomes. The emulator report has
3882/6878 lines and 690/1216 outcomes, including five covered lines of eight
from a standard-library TLS helper. The Python CLI has 3640/4618 statements
and 560/1012 branch outcomes. The ordinary runner tests have 13007/28171
statements and 2001/6988 outcomes with `scripts` as their source scope;
the 2700 assurance cases were not part of that coverage run. None of these
denominators belongs in the firmware-core percentage. Raw reports and source
hashes are bound by `host-tools-manifest.json`.

The ordinary optimized, partitioned 4 MiB image passed the complete laboratory:
native comparison, ML-DSA-87, 81 native/89 image operation entries, RSA-2048,
3072 and 4096 generation with core1, stack/residue controls and nineteen power
cuts. A separately built local v0.4.11 tag upgraded with its OATH key, resident
FIDO signing key and changed OpenPGP PIN intact. PICOBOOT and MSC passed the
full ARM Linux USB/IP runner after a bounded detach retry fixed a reboot race.
These runs are retained in `image-release/`, `release-upgrade/` and
`usbip-linux-arm-retry/`; their manifests identify the tested binaries.
The full USB/IP runner passed again with the capacity and panic fixes in
`usbip-linux-panic-final/`: nine suites, PICOBOOT reload/reboot and OTP checks,
and MSC UF2 reload with OATH persistence. The physical key was not involved.

Larger images exposed a fixed 4 MiB assumption in the flash model. Capacity now
follows the ELF through identity, upper-address reads, erase and persistence;
ordinary 4 and 8 MiB images pass the native comparison and residue controls.
The unoptimized 4 MiB build exceeds the code partition. An 8 MiB build links,
but its storage constructor drives SP below SRAM and then panics before USB.
It remains a failed image scenario. The diagnostic instruction trace is in
`unoptimized-instruction-trace.txt`; it does not prove silicon stack-fault
behavior. The laboratory now detects a sampled PC anywhere inside either
core's panic handler and resolves the caller before the return address enters
the next symbol. Removing either fix fails the actual `check.sh` emulator
test row; restoration passes all 206 tests. macOS and ARM Linux tests and
Clippy pass. Hardware state, official FIDO results and firmware behavior were
not changed by these emulator and test-only commits.

## 2026-10-06 Seed replacement and interrupted certificate recovery

Two vendor-command tests sweep every record mutation during seed import and
then every mutation during the next boot's certificate repair. After remount,
the seed is exactly old or new. A new seed has a new credential-store state;
any surviving certificate has the matching public key and verifies under an
independent RustCrypto signing key. Healthy recovery preserves the chosen seed,
restores a missing certificate and becomes write-free on its next invocation.
The sealed export window, global sign counter, largeBlob and LED record survive.
These are record-level cuts; byte-level NOR cuts remain a separate scope.

Removing the old-certificate deletion fails the new pre-recovery cut oracle,
while all pre-existing default FIDO cases pass. Removing the credential-store
state renewal fails both new tests and existing cases. Both controls compile
and fail the actual `check.sh` host-test row in an isolated copy; restoration
passes. The default FIDO suite and selected FIPS, always-UV, conformance,
strong-PIN and strict-config recovery cases pass. Raw command and control logs
are retained under `target/testing-completion-20261005/`.

A fresh default-host condition run passes 3165 unique unit tests plus the
child-process repeat, with five ignored cases. Its line, function and condition
totals are unchanged: 38449/39598, 3245/3272 and 6879/7975. Both the semantic
improvement and the unchanged raw percentage matter. `metrics-after-backup-recovery/`
retains source selection, commands, JSON, LCOV and HTML. Its export has no SDK
mapping warnings; unsupported MC/DC and uncounted language constructs remain.
The new test file was still untracked during this measurement and was absent
from its saved diff; its later local commit `461de8dd` retains the source.

The metrics runner now saves staged changes in the diff from `HEAD`, hashes
the declared build inputs, saves untracked inputs, and records its Rust flags.
Different input hashes at the end leave the report incomplete. Eight runner
cases pass. Removing staged-diff capture, untracked-file retention or the final
hash comparison fails the corresponding case through `check.sh`'s existing
pytest row selected with `-k metrics`; restoring the source passes. These
controls remain in `metrics-provenance-row-controls.json`. Older reports are
kept with their original provenance limitations.

## 2026-10-06 Registry reset and source snapshots

Two SDK command-path cases cover an enabled applet above mask bit 31 and a
selected applet removed before card reset. Reset clears selection, command
chaining and the entire held response even when the old slot no longer exists.
The next GET RESPONSE cannot replay its tail. Disabling the higher slot or
returning before reset cleanup fails the corresponding case through the existing
host-test row selected to these cases; restoration passes all 76 SDK tests.

The latest default-host report passes 3167 unique unit tests plus the child
repeat, with five ignored cases. It records 38449/39598 lines (97.10%),
6880/7975 condition outcomes (86.27%) and 3245/3272 functions (99.17%).
`metrics-after-sdk-registry/` retains the compiler, commands, raw exports,
Rust flags and hashes of 563 build inputs. Its untracked SDK test file was
saved byte for byte under `untracked/` and later committed as `58984cae`.
The start/end input hashes agree and HTML has no SDK mapping warnings.
These results do not establish MC/DC or cover the uncounted language constructs.

## 2026-10-06 Backup on the delivered image

The full optimized, partitioned-image laboratory passes with fifteen new
backup operation rows: export, seed replacement, restored identity, certificate
binding and signatures, stale-credential refusal, invalid AEAD-tag refusal,
finalization and sealed state after reboot. The whole matrix has 96 native and
105 image entries, including diagnostic controls. Backup's maximum observed
core0 stack use is 33536 bytes; core1 uses at most 520 bytes in these rows.
The known old/new seed and spent MSE key have zero matches in the four declared
prefix/suffix scans; planting the seed in SRAM makes the residue check fail.
These searches do not prove absence of every possible secret representation.

The existing image CI command selected to native operations fails with a
valid certificate over the superseded seed. Removing the backup matrix hook
makes that same control pass; restoring all source bytes passes again. The
ordinary full laboratory then passes on both backends, including ML-DSA-87,
RSA-2048/3072/4096 generation in both applets and nineteen power cuts.
`image-backup-final/` retains binary hashes and reports; the selected wiring
controls are in `backup-image-native-row-controls.json`. No GitHub job or
physical-key operation is implied by these local commands.

## 2026-10-06 Byte-level seed recovery and PIV attestation

The existing `power_cut` target now drives LOAD over the real `SeqStorage`
with a latched, byte-granular NOR fault. Input bytes select preceding store
churn, the LOAD cut, a second cut during certificate repair and the replacement
seed. Fresh caches after each cut must observe exactly the old or new seed,
a matching surviving certificate, a renewed credential-store tag with the new
seed and unchanged backup seal, sign counter and largeBlob. Healthy repair
preserves that seed and becomes write-free on its next invocation.

A deterministic run covers 3505 histories: LOAD positions zero through 700
at three initial churn states, then recovery positions zero through 700 at two
interrupted LOAD positions. Its checks reach torn LOAD, torn repair, replaced
seed and completed LOAD. Forty-five retained inputs replay through the existing
`check.sh` fuzz row. Omitting certificate deletion or tag renewal fails the
corresponding semantic assertion; omitting the new corpus inputs hides the
certificate defect. Restored sources pass all 52 targets and the corpus row.
The imported target body also passes Miri's eight execution seeds in both
default and `flavours`; neither result is a physical flash experiment.
The earlier separate Miri storage mirror was removed in `80e07f21`.

Three PIV APDU tests cover missing F9/slot keys, incomplete and unsupported
metadata, torn RSA/EC/Curve25519 records and short certificate output. Refusals
return no certificate, write nothing and preserve standing PIN freshness and
management authentication. Restoring healthy records permits attestation again.
A control returning `9000` after a refused response append passes all 263
previous PIV tests, with one ignored, but fails the new short-output case through
the selected host-test row. Restoring the source passes. The new cases also
pass under the FIPS profile. `backup-byte-*` and `piv-attestation-*` logs and
control manifests remain under `target/testing-completion-20261005/`.

A separate native/image backup repeat now signs with the same resident key
created before a refused LOAD. The independent signature verifies and its image
row has no known seed matches, with 14400 bytes of observed core0 stack use.
That selected matrix has sixteen native rows and seventeen image entries,
including its planted-leak control. It is retained in `backup-image-refusal/`;
the earlier full image matrix retains its original counts.

Reviewing the latest default report's 27 unexecuted function coordinates finds
24 verification helpers, two compile-time UI initializers and one host thread-local
storage helper. The selected file list and summed instantiations are retained in
`raw-function-residual-classification.json`. The UI helpers run in constant
assertions and the constant breathe palette; the ML-DSA probe belongs to an
ignored stack test. Raw function coverage remains 3245/3272. This classification
does not resolve the unexecuted production lines or condition outcomes, and
other profiles still require their own residual review.
