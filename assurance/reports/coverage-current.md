<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Current host-profile coverage

This audit covers the eighteen host feature profiles declared by
`.github/workflows/deep-checks.yml`, including authenticated storage v2.
Firmware glue and `rsk-wipe` are outside the host measurement. MC/DC remains
[decision-only](testing-campaigns.md).

## Measured results, 2026-10-11

All eighteen declared host profiles completed on source matching
`eadea4e7e41f80d9101a8adeb015459c14dfb293`.
Every profile rebuilt its 28 selected library-test binaries and checked their
actual test rosters before executing or reusing an identical successful binary.
The [finite profile catalogue](../../tests/coverage/coverage-profile-audit.toml) binds every missing
condition side, zero-DA line and unexecuted function group to that profile's
source hashes, resolved features and reviewed scope. No residual is unreviewed;
raw percentages retain all measured residuals.

| Profile | Condition outcomes | Lines | Function groups |
|---|---|---|---|
| `default` | 8207/8723 (94.08%) | 42688/43370 (98.43%) | 3607/3609 (99.94%) |
| `advertise-pqc` | 8207/8723 (94.08%) | 42690/43370 (98.43%) | 3607/3609 (99.94%) |
| `fips-profile` | 8191/8723 (93.90%) | 42651/43370 (98.34%) | 3605/3609 (99.89%) |
| `fips-profile,advertise-pqc` | 8191/8723 (93.90%) | 42653/43370 (98.35%) | 3605/3609 (99.89%) |
| `strong-pin` | 8198/8721 (94.00%) | 42684/43370 (98.42%) | 3606/3609 (99.92%) |
| `strong-pin,advertise-pqc` | 8198/8721 (94.00%) | 42686/43370 (98.42%) | 3606/3609 (99.92%) |
| `always-uv` | 8207/8723 (94.08%) | 42688/43370 (98.43%) | 3607/3609 (99.94%) |
| `always-uv,advertise-pqc` | 8207/8723 (94.08%) | 42690/43370 (98.43%) | 3607/3609 (99.94%) |
| `strict-up` | 8196/8716 (94.03%) | 42684/43370 (98.42%) | 3607/3609 (99.94%) |
| `strict-up,advertise-pqc` | 8196/8716 (94.03%) | 42686/43370 (98.42%) | 3607/3609 (99.94%) |
| `display` | 8211/8727 (94.09%) | 42699/43381 (98.43%) | 3609/3611 (99.94%) |
| `strict-config` | 8164/8677 (94.09%) | 42567/43247 (98.43%) | 3595/3597 (99.94%) |
| `largeblob-ext` | 8199/8724 (93.98%) | 42721/43413 (98.41%) | 3606/3610 (99.89%) |
| `preview-sign` | 8283/8803 (94.09%) | 43253/43957 (98.40%) | 3655/3658 (99.92%) |
| `preview-sign,largeblob-ext` | 8275/8804 (93.99%) | 43286/44000 (98.38%) | 3654/3659 (99.86%) |
| `display,strong-pin` | 8202/8725 (94.01%) | 42695/43381 (98.42%) | 3608/3611 (99.92%) |
| `display,fips-profile` | 8195/8727 (93.90%) | 42662/43381 (98.34%) | 3607/3611 (99.89%) |
| `fido-conformance` | 8196/8716 (94.03%) | 42684/43370 (98.42%) | 3607/3609 (99.94%) |

This closes the declared host-profile reachability review, including storage v2
and callable test-util/helper inputs. Cryptographic assumptions and primitive
failure hooks retain the scope described below. It does not establish native
MC/DC, embedded-glue/C-backend coverage or physical interruption coverage.

## Source review

The `39235395677f` default baseline recorded 8114/8723 raw condition outcomes,
42444/43336 lines and 3593/3602 function groups. Its LCOV source-coordinate
inventory contained 472 zero-DA rows. The committed
[baseline source audit](../../tests/coverage/coverage-baseline-audit.toml) accounts for every one,
including `match` arms, `?` projections and test-support code. It preserves the
baseline dispositions and exact current source locations/hashes; runtime closure
is assessed separately for each profile.

New tests cover raw-bank geometry, signed checkpoint and delta contradictions,
main/counter bank recovery and rollover, import manifests/backups, full directory
capacity, root-read refusals and direct managed-storage APIs. Two proposed
invariants were rejected: a freshly scanned authenticated counter peer may have
the expected sequence while omitting an owner. Rekey and rollover tests now reach
those refusals with valid replacement checkpoints.

The applet tests consume nested unknown CBOR fields before recognized fields,
refuse truncated skipped values, check public labels, absent service records,
changed records between probe/read, storage exhaustion during publication, valid
sealed keys that contradict their declared role, and late key/metadata read
failures. Display tests prove dispatch into the cancelled modal, cancellation at
the second PIN pad and fused-key failure after successful verification.

FIPS-specific gaps include repeated MSE, refusal at the shared backup-load gate,
empty Edwards imports, backup hit testing and recovery-modal power/host yields.
Their tests run independently of menu policy. A direct recovery-helper test does
not establish that the FIPS production menu allows export. Existing sealed 3DES
management keys are tested through both single and mutual authentication; the
fixture writes the older stored key representation without asking FIPS to accept
a new key through `SET_MGMKEY`.

Direct helper tests also cover arbitrary policy flags, the serializer's explicit
large-blob output argument, non-grid PIN captions, unknown OpenPGP FIDs, PIV retry
indices and slots without certificate mappings, OATH's no-chain entry and absent
conformance option/extension lookups. A healthy fault model has no fault landing;
its explicit panic contract is tested as `should_panic`. Negative oracle tests
also reject unknown corpus verdicts, a missing credential algorithm, a missing
hmac-secret-mc output, an algorithm/key-type mismatch and exhaustion of all three
command-cut sweep budgets. They require the intended panic message; another
parser failure does not satisfy them.

The strict-config, largeblob-ext and preview-sign reviews rejected seven further
caller-only arguments. Tests now exercise a refused OTP configure frame with unchanged
status/storage, every direct `DevConfError` status mapping, both independent
large-blob serializer arguments and every short response capacity. A valid
sealed credential with the older largeBlobKey opt-in is enumerated through the
normal command and must omit the retired field under largeblob-ext. The
unsigned-extension oracle handles unknown fields before the wanted field,
absent wanted fields and malformed values.
PreviewSign's makeCredential/getAssertion parsers consume unknown integer-keyed
nested values before the known fields and refuse a truncated skipped value with
`InvalidCbor`.

A proposed ML-DSA short-parameter probe panicked before the target decoder error
and was rejected as refusal evidence. The retained argument is the wrappers'
exact public-key widths and the complete 10-bit coefficient range; boundary
encodings for coefficients 0 and 1023 decode successfully.

Source invariants are scoped to the actual types, checked producers and private
state transitions they cite. A private caller invariant describes the current
reachable call graph; it is not a claim about arbitrary fabricated private state
or a future caller. Fixed-profile outcomes are assessed using that profile's
resolved feature closure. Cryptographic assumptions are recorded explicitly and
are not mathematical proofs that a collision or exhausted derivation is
impossible. No raw outcomes, lines or function groups are excluded.

The [storage invariant catalogue](../../tests/coverage/coverage-store-invariants.toml) records the
checked geometry, private lifecycle state and authenticated replay arguments.
It distinguishes structural constraints from the conditional assumption that
an identical verified checkpoint and journal scan reconstructs the same
directory. Primitive hooks are evidence for the refusal handlers, not proofs that
the assumed cryptographic event can occur under ordinary inputs.

For the current default profile, 516 raw missing outcomes reconcile as
`190 + 337 - 19 + 8`: 190 missing source-coordinate sides, 337 additional
missing outcomes from LLVM's maximum over generic instantiations, 19 folded-span
adjustments and eight repeated coordinates. The finite source review and the
raw report answer different questions; neither replaces the other. Test-only
failure formatting and standard-library TLS alternatives retain their own
typed scope instead of being labelled unreachable firmware paths.

## Primitive failure and mutation controls

One-shot test-only hooks feed `None` into the existing U2F derived-key refusal and
`RsaError::Failed` into the existing PIV generation error mapping. Their flags are
thread-local and consumed before returning. These tests exercise the real error
handlers and wipe/publication ordering; they do not construct an HKDF preimage or
show that a valid prime generator normally fails.

Isolated controls replace each U2F/PIV refusal with `OK` and replace the staged
OpenPGP DEK's bad-tag refusal with success. All three compile, have passing clean
baselines and fail the exact refusal assertion in the modelled direction. The
ordinary in-diff sweep separately produced three unviable function replacements:
`Sw` has no `Default` implementation. Those compiler failures are not semantic
kills or survivors.

A fourth isolated control removes the largeblob-ext suppression from credential
enumeration. Its clean baseline passes; the changed guard exposes field `0x0B`
and fails the exact forbidden-key assertion. This validates the stored-credential
fixture and refusal direction independently of a coverage count.

## Measurement method

The pinned nightly is `1.98.0-nightly (61d7280f3 2026-06-06)` with condition
instrumentation, on `aarch64-unknown-linux-gnu`. Each profile has an isolated
JSON/LCOV/HTML export and a source-hashed manifest. The host feature closure is
resolved from the corresponding firmware features using Cargo metadata.

A warm Cargo cache labelled an older FIPS+PQC test executable `fresh` even though
three new test names were absent. That report was rejected. The final matrix
cleans workspace-package artifacts before each profile build, verifies that all
28 selected libtest artifacts were rebuilt, and saves each actual test roster.
Unconditional new-test sentinels must be present before execution reuse is allowed.
Roster listing raw profiles are kept outside the exported execution-profile set.

The local matrix builds every selected workspace unit-test binary and executes
each distinct SHA256 binary with its ordinary complete test suite. Existing
manual stack/KAT and slow RSA benchmark ignores remain explicit in the test logs.
Successful runs retain executable, raw-profile and test-log hashes. A different
binary executes again; equality is checked before reuse. Reports include only the
binary set selected for that profile. This is explicit execution reuse, not
eighteen independent fresh runs or a union presented as individual coverage.

Export reconstruction was calibrated against the ordinary default runner:
all raw totals, file summaries, branches and segments match exactly. Removing the
`rsk-bench` executable changes the source map and is detected. The ordinary runner
is unchanged and can reproduce one profile without reuse:

```sh
COVERAGE_PROFILE=strict-config COVERAGE_OUT=target/coverage-strict-config-fresh \
  nix develop .#fuzz -c ./scripts/metrics.sh --coverage
```

Raw evidence, calibration, source inventories, binary hashes, mutation diagnostics
and gate logs are retained in `target/profile-coverage-20261010/`. The initial
`final-linux/` run was stopped while its source was superseded; `store-complete/`
is an explicitly limited full-package run. Neither substitutes for the final
source-refreshed profile matrix. `current-linux/`, `tip-linux/`,
`verified-linux/` and `closed-linux/` retain
earlier partial attempts. A stale FIPS+PQC executable was detected in the last
attempt despite current source hashes. `rebuilt-linux/` first established the
corrected compiler-to-source binding before each binary SHA256 comparison.
It remains a discovery snapshot, not current all-profile completion evidence.

The subsequent `rebuilt-linux/` thirteen-profile run and five-profile
`extension-discovery-linux/` run exposed seven additional callable API/parser
cases. Their ledgers retain pending measured dispositions against that older
source. The final `audited-linux/` matrix includes all seven fixes and is the
current eighteen-profile evidence; none of the earlier attempts substitutes for
it. Publisher CLI controls reject an added untracked source file, changed
inventory bytes and a declaration/report profile mismatch, then validate the
restored complete evidence again.
