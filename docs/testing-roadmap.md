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

The default host lane in phase 1 has measured branch counters and calibrated
condition instrumentation. Phase 2 has started with LargeBlobs, ClientPIN,
storage and USB regressions. Other configurations, whole-core decision coverage and phases
3 through 8 remain open. The criteria below still govern completion; one
default host report does not complete every scope. Phase 1 also retains an
SDK coverage-mapping warning described in [Testing](testing.md#branch-and-condition-measurements);
it is not marked complete while that limitation remains.

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
