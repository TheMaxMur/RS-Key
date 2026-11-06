<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Floyd MC/DC pilot, 2026-11-05

Floyd 0.2.9 failed the [MC/DC pilot criteria](testing-roadmap.md#mcdc-decision-recorded-on-2026-10-08).
It reported complete independence for a function called only with `true, true`,
using observations from another function. The retained LLVM profiles contradict
that result. This version is unsuitable as RS-Key's MC/DC evidence producer.

The pilot adds no coverage credit to the [six-decision review](mcdc-independence.md).
It left the candidate pairs, including OpenPGP PW1/PW2 and FIDO permission/UV
separation, awaiting validation. The subsequent [Supercov work](mcdc-independence.md)
supplies scoped measurements; this Floyd run itself adds no credit. The
production compiler, dependencies and gates were unchanged by this pilot.

## Source and execution scope

| Input | Recorded identity |
|---|---|
| Floyd | 0.2.9, upstream commit `ca2cefa2c95339ca06bfb2ebfbcbd97d830e1c9d`, unchanged source and lockfile |
| RS-Key | `a25b5de2` plus the pre-existing working-tree changes, including the transferred power-cut oracle repair |
| Compiler | `rustc 1.101.0-nightly (92ffebece 2026-10-28)`, existing `.#fuzz` shell |
| LLVM | 23.1.4, tools from that compiler's sysroot |
| Execution target | `aarch64-apple-darwin` |
| Calibration | Standalone test files, default optimization; separate default and alternative cfg cases |
| RS-Key | Existing host test profiles and actual feature closures retained in each Cargo artifact record |

The downloaded source was newer than the 0.2.2 described by the indexed project
page. The pilot tests the recorded 0.2.9 commit, not the earlier release.

Unadapted Floyd invokes `rustc +nightly`, which fails with Nix's direct compiler
binary: it treats `+nightly` as an input filename. Two local executable adapters
strip that argument and call the existing Nix `rustc` and `cargo`. The alternative
cfg case additionally passes `--cfg pilot_alternative`. No rustup installation,
compiler replacement or Floyd source patch was used.

Artifacts live under `target/floyd-pilot-20261105/`: sources, adapters, complete
JSON reports, stderr, exit codes, ordinary-test results, raw profiles, LLVM
exports, emitted MIR, source/binary hashes and the pre-existing diff snapshot.
`evidence.tar.gz` retains the small reproductions and reports; large native
binaries and full MIR remain in the local directory with their hashes recorded.

## Calibration results

Each source has ordinary assertions about the function's real result. Floyd runs
each named test separately. The report's count below is scoped to the decision
it selected; it is not a percentage of a file, crate or firmware.

| Case | Independent expectation | Observed Floyd result |
|---|---|---|
| 01, conjunction | Both conditions independently exercised | 2/2 |
| 02, disjunction | Both conditions independently exercised | 2/2 |
| 03, `(a && b) \|\| c`, missing witness | All condition outcomes and both decision outcomes occur, but `b` has no independence pair | 2/3, `b` unexercised |
| 04, restore the missing witness | All three conditions independently exercised | 3/3 |
| 05, `!a && b` | Complete three-row witness set | 0/2, no observations |
| 06, short-circuit call with side effects | Complete witness set; skipped call has zero side effects | No recognized decision; ordinary assertions pass |
| 07, four evaluations in one test | Same complete inputs as 04 | 0/3; four evaluations collapsed into one synthetic observation |
| 08, same names in two functions | `gate` always receives `true, true`; only `decoy` has independent inputs | **False 2/2 for `gate`** |
| 09, two functions with distinct condition names | Two decisions, four condition occurrences | Only `gate` reported, 2/2; the other decision omitted |
| 10, `a && (b \|\| a)` | Three source occurrences; repeated `a` is coupled and `b` cannot change the result independently | 1/2 under unique names; no occurrence-level disposition |
| 11, expression macro | Both conditions independently exercised | 2/2 for this one macro; no general macro support established |
| 12, repeated generic comparison | Coupled comparison occurrences need a scoped disposition | No recognized decision |
| 13, default cfg | Complete AND witness set | 2/2 |
| 14, closure with capture | Complete AND witness set | 2/2, attributed to the closure |
| 15, no tests | No runtime evidence | Explicit refusal |
| 16, constant-only function | No recovered Boolean decision | Explicit refusal |
| 17, deliberately failing assertions | Coverage exists, but functional tests fail | 2/2 and CLI exit 0; ordinary test run exits 101 |
| 18, rename only `decoy` parameters | Same executions as 08; `gate` still lacks all pairs | 0/2 for `gate` |
| 19, alternative cfg | Complete OR witness set | 2/2 |
| 20, independent generic comparison and bool | Complete three-row witness set | No recognized decision |

Case 03 to 04 verifies a missing pair and its restoration, rather than merely
checking that the analyzer can report success. Case 18 is the causal control
for case 08: changing another function's parameter names changes the verdict
for an unchanged `gate`.

## False independence and lost execution identity

The essential case 08 input is:

```rust
pub fn gate(a: bool, b: bool) -> bool { a && b }
pub fn decoy(a: bool, b: bool) -> bool { a && b }
```

Each test asserts `gate(true, true)`, then checks one of `decoy(false, true)`,
`decoy(true, false)` and `decoy(true, true)`. All ordinary assertions pass.
The three raw LLVM exports give both `gate` branches counts `(true=1, false=0)`.
Nevertheless Floyd attributes false-result rows and two independence pairs to
`gate`. `collision-raw-gate-counts.json` extracts the contradictory counters;
`verify.py` checks them against all three original exports.

The source explains the contamination. In
[`observation_from_coverage`](https://github.com/Gordion-Solutions/Floyd/blob/ca2cefa2c95339ca06bfb2ebfbcbd97d830e1c9d/floyd/src/correlate.rs#L127-L146),
the correlation result contains multiple functions, but their conditions are
inserted into one map keyed only by variable name. Later functions overwrite
earlier values. The selected decision's result is then computed from that map,
rather than observed independently.

The same function prioritizes `true_count > 0` over `false_count > 0`. In case 07
the separate evaluated vectors are `(T,T,-)`, `(F,-,F)`, `(T,F,T)` and `(T,F,F)`.
The report instead contains one `(T,T,T)` row. That vector was never evaluated:
with `a` and `b` both true, `c` is skipped. It also loses every genuine pair.

Separately, the CLI's
[`pick_best`](https://github.com/Gordion-Solutions/Floyd/blob/ca2cefa2c95339ca06bfb2ebfbcbd97d830e1c9d/cargo-floyd/src/selector.rs#L36-L60)
chooses one candidate by observation count and condition count. A complete
selected decision is therefore insufficient evidence of complete project
enumeration. Case 09 reproduces the omission with two recognized functions.

## Application to RS-Key

Six existing host test binaries were built with `-Cinstrument-coverage`,
`-Zcoverage-options=condition`, `-Zmir-include-spans` and `--emit=mir,link`, in an
independent Cargo target directory. The real library/test sources were unchanged.
The native build took 51.03 seconds. All 22 selected tests passed individually,
and all 22 LLVM exports succeeded. These passes establish the selected tests'
ordinary behavior, not MC/DC.

| Crate | Tests passed | Full emitted MIR through Floyd's public parser |
|---|---:|---|
| `rsk-fido` | 6 | Returns success and 398 functions, but omits the selected `getassertion::enforce_pin` and `expire_stale_token` definitions present in the file |
| `rsk-openpgp` | 3 | Fails on a function-pointer argument in `keys::unseal_with` |
| `rsk-piv` | 3 | Fails on the function-pointer argument in `files::sweep` |
| `rsk-device` | 4 | Fails on an `impl FnOnce` argument in `ccid_fido::with_ctx` |
| `rsk-store` | 2 | Fails on the emitted `coroutine layout` |
| `rsk-fs` | 4 | Fails on an `impl Fn` argument in a fault-test helper |

After these full-file failures, a diagnostic adapter supplied exact, unedited
MIR function fragments to Floyd's public parser and decomposer. Each fragment
records its parent hash, line range and own hash. This does not bypass the
failed whole-file test or establish runtime correspondence.

The fragments do not recover the target authorization, expiry, PIV PIN/touch,
DEK selection or presence/CANCEL decisions. Storage's asynchronous body still
fails parsing; two simple nested storage/oracle closures are recovered, which
does not recover their enclosing commit/read-back decisions. Rewriting the
production code into convenient Boolean helpers was outside this pilot.

## Verification and disposition

Floyd's own suite passed: 8 CLI tests, 93 library tests and 2 end-to-end tests,
including the normally ignored end-to-end cases. Those tests do not detect the
counterexamples above. The pilot's evidence verifier confirms the collision
against raw LLVM counters and checks all selected RS-Key test/export exits.

One warm end-to-end run of case 01 took 0.58 seconds. macOS `time -l` reported
maximum resident set size 110116864 bytes. This single host run is not a
whole-workspace cost estimate or evidence about firmware resources.

Floyd 0.2.9 is rejected for adoption here. A replacement or repaired version
needs per-evaluation records, function/decision/condition-occurrence identity,
complete decision enumeration with explicit unsupported entries, and successful
calibration against these counterexamples before any RS-Key coverage credit.
The scoped independence review remains the active method for the six decisions.

Reproduction from this checkout, with the retained upstream source:

```sh
nix develop .#fuzz --profile target/floyd-pilot-20261105/nix-profile -c \
  bash target/floyd-pilot-20261105/run-env.sh \
  python target/floyd-pilot-20261105/calibrate.py
nix develop .#fuzz --profile target/floyd-pilot-20261105/nix-profile -c \
  bash target/floyd-pilot-20261105/run-env.sh \
  python target/floyd-pilot-20261105/verify.py
```

The artifact README records the preceding tool/native build commands and the
diagnostic steps. This experiment did not run either full RS-Key gate. The
documentation build and offline link check passed with zero link errors.
