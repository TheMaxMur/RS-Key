<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# MC/DC measurements

Supercov now measures Boolean decisions in the six security groups chosen in
the [testing roadmap](testing-roadmap.md#mcdc-decision-recorded-on-2026-10-08).
The 2026-11-05 run retains source-condition vectors, skipped operands, outcomes
and pairs from real command/library tests. The OpenPGP PW1/PW2 and getAssertion
permission/RP gaps have executable witnesses. Reachable-state and backend-result
couplings are recorded separately from tool credit. This is a declared host-source
subset, not whole-core coverage, compiler instrumentation, ARM image coverage
or a qualification claim.

The [2026-11-06 source-decision extension](mcdc-source-decisions.md) measures
previously omitted let-else, equality assertions and predicate callbacks. Its
host results and separate ARM campaigns retain their expanded denominators
and source-bound residuals.

## Tool, sources and calibration

The compiler is the existing Nix `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM
23.1.1, host `aarch64-apple-darwin`. Source is `a25b5de2` plus the pre-existing
working changes, including the power-cut oracle repair, and this slice's tests.
The selected authorization expressions and compiler pins are unchanged. Each
selection uses its package's default host test feature closure.

[Supercov](https://github.com/supercorp-ai/supercov) 4.22.0 at
`bd6c9d76426d446fb57bcbe5df7791820c97fac1` needs a
[small local patch](mcdc-supercov-anonymous-const.patch) for anonymous
`const _: ...` items. Its constant lookup otherwise aborts while inspecting a
named loop bound in a file that also contains an anonymous constant. The fix
skips unnamed constants during name lookup; witness arithmetic is unchanged.
The local executable's SHA-256 is
`2f0ade2b934537a67b2cfd4e32aab7373fda911165448623a55f732ebc662147`.

Twenty calibration inputs exercise AND/OR, mixed expressions, negation, side
effects, multiple evaluations, colliding parameter names in different functions,
repeated conditions, generics, cfg, closures, empty maps, macros and failing
assertions. They retain the released binary's results after the patch. A
twenty-first input reproduces the anonymous-constant abort on the release and
now completes with 2/2 conditions covered.

The incomplete `(a && b) || c` input reports 1/3; restoring the missing row gives
3/3. The partial result agrees with independent Clang/LLVM 21.1.8 MC/DC.
Four evaluations remain four vectors, unrelated functions do not share data,
and failed tests return 101 with `valid=false`. Unsupported macros and zero
denominators receive no coverage credit here. The [Floyd pilot](mcdc-floyd-pilot.md)
remains rejected.

These host runs instrument an isolated copy; the host runtime links `std` into
that copy of a `no_std` library. The ARM experiment below has a separate runtime
and source scope. No probes enter a deployed image. Evidence and the copied
source snapshot are retained in `target/mcdc-security-20261105/`. Each
`runs/<selection>/run-id.txt` identifies the raw run in
`source/.supercov/runs/`; `source-sha256.json` identifies every Rust input.

## Measured decisions

Counts apply only to named decisions, under Supercov's evaluated-vector
criterion. A skipped operand is `-`, never false. Different selections are
not added into a firmware percentage.

| Group | Source decision | Tool witnesses | Tests and protected effects |
|---|---|---|---|
| D1, getAssertion token | `crates/rsk-fido/src/getassertion.rs:452`: bad MAC, UV absent, GA permission absent, RP bound, RP differs | **5/5**, with UV coupling below | `clientpin::tests::assertion::issued_tokens_exercise_each_getassertion_condition` obtains tokens through ECDH/clientPIN. It checks UV/UP assertions and counter progress; refusals preserve response bytes, flash generation, token bytes, binding, use timer and presence count |
| D2, expiry | `crates/rsk-fido/src/state.rs:714`, inactive token; `crates/rsk-fido/src/state.rs:719`, absolute or rolling deadline | **1/1; 2/2** | Five `pin_uv_auth_token_` tests check idle/wrap, expiry, refresh, the absolute cap and retired grants |
| D3, PIV | `crates/rsk-piv/src/auth.rs:45`, touch bypass; `crates/rsk-piv/src/auth.rs:63`, PIN and freshness | **1/1; 2/2**, with PIN-state coupling below | Seven `auth_decisions` tests drive signing/agreement policy and Confirmed/Declined/Timeout/Cancelled, checking status, output, freshness and retries. The presence enum match retains branch/functional evidence |
| D4, OpenPGP | `crates/rsk-openpgp/src/pin.rs:403`, PW1 or PW2; `crates/rsk-openpgp/src/pin.rs:405`, PW3; `crates/rsk-openpgp/src/pin.rs:407`, RC | **2/2; 1/1; 1/1** | The new `dek_selection` test uses VERIFY/logout, checks the selected DEK FID and plaintext, and proves revoked access reads no key and changes neither output nor flash. The complete PIN selection passes 88 tests |
| D5, presence | `crates/rsk-device/src/presence.rs:111`, pending and matching scope; `crates/rsk-device/src/presence.rs:119`, FIDO cancel; `crates/rsk-device/src/presence.rs:130`, OTP cancel | **2/2; 1/1; 1/1** | Twenty-five arbiter tests cover fresh state, scope mismatch, owning/cross-transport cancellation, spent holds and races |
| D6, storage | `crates/rsk-store/src/verified_flash.rs:60`, readback mismatch; `crates/rsk-fs/src/fs.rs:279`, read failure; `crates/rsk-fs/src/fs.rs:336`, complete scan; `crates/rsk-fs/src/fs.rs:578`, complete range walk; `crates/rsk-fs/src/fs.rs:924`, metadata read failure | **1/1; 2/2; 1/1; 1/1; 2/2**, with read-result coupling below | The late-chunk/erase-word fault test takes both readback outcomes. All 168 Fs tests pass under instrumentation, including read-error, incomplete-walk and power-cut-oracle controls |

The focused OpenPGP test records `FF -> F`, `FT -> T`, `T- -> T`.
Fresh MODE81/MODE82 sessions hold the other latch false. Both select
`EF_DEK_PW1`, never `EF_DEK_PW3` or `EF_DEK_RC`. Logout returns the real
`load_dek` path to `CONDITIONS_NOT_SATISFIED` before any key read.

The earlier RP test spent UV on its first successful assertion, so its second
request never reached the RP comparison. It now declines the first touch,
asserts binding while UV and GA remain live, refuses the wrong RP, then
successfully retries the matching RP with the same token. Its report witnesses
both RP conditions with MAC, UV and permission fixed.

## D1 vectors and coupled UV

Let `A=bad MAC`, `B=UV absent`, `C=GA permission absent`, `D=RP bound`,
`E=RP differs`. Rejection is `A || B || C || (D && E)`.

| Row | Real input/state | A B C D E | Reject |
|---|---|---|---|
| U | Fresh unbound GA token | `F F F F -` | F |
| M | Fresh GA token bound to this RP | `F F F T F` | F |
| R | Fresh GA token bound to another RP | `F F F T T` | T |
| P | Fresh MC-only token, UV live | `F F T - -` | T |
| A | Fresh matching GA token, corrupt request MAC | `T - - - -` | T |
| S | Matching token after a real assertion spent UV/grants | `F T - - -` | T |

Supercov chooses U/A, U/S, U/P, U/R and M/R for A through E. Other evaluated
operands agree; later operands are skipped after rejection is decided. For D,
U's reset token hash differs from the request RP hash, but that comparison is
deliberately not executed. M/R directly varies E with its peers still allowing.

UV needs a separate security interpretation. `PinUvAuthToken::new` starts with
zero permissions and UV false (`crates/rsk-fido/src/state.rs:275`). Production
`issue_token` calls `begin_using_token` before publishing permissions
(`crates/rsk-fido/src/clientpin.rs:469-471`). Beginning sets in-use and UV
(`crates/rsk-fido/src/state.rs:626-634`). The other writers are reset, stop and
`consume_after_user_presence`; each revokes GA before or with UV
(`crates/rsk-fido/src/state.rs:608-620,650-670`). These are the token-state writers
in the firmware and app libraries. Arbitrary proof/test assignments do not
prove reachability.

An accepted production token therefore cannot retain GA while UV is false.
S really clears both. The tool credits B with later C skipped; that is **not**
a pair holding actual GA permission constant. Removing only UV leaves S
refused by the permission check. That isolated control passes as expected:
independent observability of UV is infeasible under this reachable-state
invariant. B remains a coupled defense; P supplies the genuine independent C
witness. No fabricated private-state row is credited.

## D3 and D6 coupling boundaries

For PIV's ALWAYS policy, `has_pin && pin_fresh` has reachable command-boundary
states `FF`, `TT` and `TF`. `Session::set_pin` writes both flags together
(`crates/rsk-piv/src/lib.rs:193-195`); reset, logout and VERIFY paths use it.
Only a private operation clears freshness alone (`crates/rsk-piv/src/auth.rs:117`).
Thus `pin_fresh` implies `has_pin` at every `pin_satisfied` call. The exclusive
mutable session cannot be observed between the assignments in `set_pin`.
This is a source observation-boundary invariant, not an arbitrary RAM/fault proof.

The tool observes `F-`, `TT`, `TF` and credits 2/2. Freshness has a genuine
`TT`/`TF` pair. A separate `has_pin` pair holding actual freshness true would
need unreachable `FT`. In an isolated copy, removing only `has_pin` from the
ALWAYS conjunction leaves all seven real-command tests passing. Removing only
freshness instead makes three tests return `9000` (including a signature)
where a spent PIN must return `6982`. The fallback `_ => sess.has_pin` is
unchanged and remains independently observable for other policies. The source
is restored; logs and hashes are in
`target/mcdc-controls-final-20261105/piv-coupling-results.json`.
An existing helper test fabricates `FT` to test `spend_pin`; it neither proves
command reachability nor supplies an authorization witness.

For both Fs read-error guards, let `A=r.is_none()` and `B=last_error()`.
The `Storage` contract (`crates/rsk-fs/src/storage.rs:70-84`) distinguishes a
successful value, confirmed absence and failed read. Their actual rows are
`FF`, `TF`, `TT`, observed as `F-`, `TF`, `TT`. A value plus a failed-read flag
would violate that contract. B therefore has an independent absence/error
pair; A's tool credit is coupled to the backend result. Both raw 2/2 counts
remain, with this qualification. Functional tests separately assert returned
values, confirmed absence, actual errors and preservation of metadata.

## Falsification and limits

In separate source copies, removing MAC, GA permission or RP-match checks makes
the new FIDO test sign a request it must refuse. Applying the RP comparison
unconditionally instead refuses the valid unbound token. Removing PW1/PW2
from selection, or choosing the wrong DEK FID, refuses a DEK load that must
succeed. All seven controls fail in runtime assertions in those intended
directions, not at compilation. Removing UV passes for the coupled reason
above. Sources are restored after every control.

Macro-expanded conditions, including inside `matches!`, and const evaluation
remain declared limitations. Pattern matching, `?`, iteration and the oracle's
assertion macros retain separate branch/functional evidence. ARM correspondence,
device glue and C/assembly remain separate scopes. No whole-core 100% follows.

The pinned rustc still rejects `coverage-options=mcdc`; condition counters
cannot supply independence. Supercov is adopted for this host-source subset,
without a new CI gate, registry or compiler pin.

The scoped runs execute 296 unique native tests. Their initial advisory Docker
run failed before mutation testing because its Linux Nix shell could not build
picotool without `/bin/sh`. The later whole-library extension below repairs the
isolated runner and records a completed mutation run; the initial failure is
not a mutation verdict.

## Whole-library extension, 2026-11-05

The six selected groups have executable witnesses and explicit coupling
disposition above. The extension also measures the host libraries, adds tests
for feasible residuals, repairs CTAPHID reset handling, and reviews every
remaining default condition. It does not establish whole-firmware 100% MC/DC.
The default report retains `valid=true`, `stale=false`, `complete=false` and
`structurallyComplete=false`; explanations do not change these flags.

The initial whole-library baseline passed 4,753 tests and skipped five, with
4,063/4,286 conditions witnessed. The final isolated default passes **4,819
tests, five skipped; 4,148/4,286 conditions have tool pairs (96.78%), with 138
raw residuals**. This adds 85 tool witnesses over that baseline. All 3,168
decisions execute, and 3,045 have pairs for every condition. These are raw
workspace counts, including verification helpers. The whole-library tool pairs
have not all received a semantic coupling review; they do not by themselves
establish independent security enforcement by every defensive predicate.

### Isolated feature profiles

Each of the eighteen existing profiles uses its own fresh project and Cargo
target. A previous shared-project experiment is superseded: Supercov collects
compiled-source scope from cached depinfo, including older feature builds.
That left 29 preview-only condition identities in three non-preview profiles.
Those denominators were invalid even though the tests passed. A calibration
reproduces the defect: the extra-feature run has 4/4 pairs, a default run in
the same project incorrectly retains 2/4, and a fresh default correctly has
2/2. `instrumentedBuildCache.reused=false` alone does not prevent this error.

| Profile | Tests passed / skipped | Conditions with tool pairs | Raw residuals |
|---|---:|---:|---:|
| `default` | 4,819 / 5 | 4,148/4,286 (96.78%) | 138 |
| `advertise-pqc` | 4,819 / 5 | 4,148/4,286 (96.78%) | 138 |
| `fips-profile` | 4,805 / 5 | 4,136/4,286 (96.50%) | 150 |
| `fips-profile,advertise-pqc` | 4,806 / 5 | 4,136/4,286 (96.50%) | 150 |
| `strong-pin` | 4,824 / 5 | 4,142/4,286 (96.64%) | 144 |
| `strong-pin,advertise-pqc` | 4,824 / 5 | 4,142/4,286 (96.64%) | 144 |
| `always-uv` | 4,820 / 5 | 4,148/4,286 (96.78%) | 138 |
| `always-uv,advertise-pqc` | 4,820 / 5 | 4,148/4,286 (96.78%) | 138 |
| `strict-up` | 4,818 / 5 | 4,138/4,286 (96.55%) | 148 |
| `strict-up,advertise-pqc` | 4,818 / 5 | 4,138/4,286 (96.55%) | 148 |
| `display` | 4,825 / 5 | 4,150/4,288 (96.78%) | 138 |
| `strict-config` | 4,801 / 5 | 4,130/4,267 (96.79%) | 137 |
| `largeblob-ext` | 4,813 / 5 | 4,141/4,286 (96.62%) | 145 |
| `preview-sign` | 4,859 / 5 | 4,184/4,324 (96.76%) | 140 |
| `preview-sign,largeblob-ext` | 4,853 / 5 | 4,177/4,324 (96.60%) | 147 |
| `display,strong-pin` | 4,829 / 5 | 4,144/4,288 (96.64%) | 144 |
| `display,fips-profile` | 4,811 / 5 | 4,138/4,288 (96.50%) | 150 |
| `fido-conformance` | 4,818 / 5 | 4,138/4,286 (96.55%) | 148 |

Every row is a separate binary and denominator. No cross-profile pair or
production-only aggregate is asserted. The source/target isolation calibration
is retained in `target/mcdc-profile-scope-calibration-20261105/`.

The first three profiles (`default`, `advertise-pqc`, `fips-profile`) use source
revision 1. The remaining profiles use revision 2, which adds only
`getassertion_component_tests.rs` and its test-module hook. Production logic
and Boolean obligations are unchanged. This is a declared test-only extension,
not eighteen runs of an identical test snapshot. `source-revisions.json` and
each profile's `source-sha256.json` record the actual inputs.

Sources, commands, run IDs, summaries, complete paginated residuals and
archived compiler depinfo are retained in
`target/mcdc-isolated-profiles-20261105/`. The default run is
`run_111e7b2c800910ab`; its `default-missing.json` and TSV contain all 138
conditions. Queries follow every `pagination.nextOffset`: `--limit 0` alone
still truncates large responses. Each collected file count is checked against
its summary. Older runs in `target/mcdc-complete-20261105/` and
`target/mcdc-reviewed-20261105/` remain historical evidence.

The orchestration reported ENOTEMPTY while deleting a completed profile's
rebuildable cache after a `.DS_Store` appeared. Completion metadata was also
recovered for another successful profile with only that metadata file left in
its target. Tests, valid raw reports, paginated residuals and depinfo archives
were checked before restoring completion records. These cleanup interruptions
are not failing measurements or second test runs; each recovered profile
records the observed or inferred cause explicitly.

### Added witnesses and the CTAPHID repair

The tests drive the existing implementation and check its effects:

- U2F registration with PIN presence and no confirming display exercises
  `!owes_card`; an independent P-256 verifier checks the signature. This is an
  admitted presence-backend contract. Current display/button implementations
  expose `(shows_confirm, uv_available)` as `(true, true)` or `(false, false)`.
- Transport tests revoke CCID epochs during APDU/Secure time extensions,
  revoke held HID frames, and reset a fragmented request before timeout or
  continuation. They check dispatch, responses, locks and wipes. Session reset
  completion is exercised in all seven non-scrubbing states.
- Display tests persist a presence-timeout-only change before host handoff.
  Thirteen fault-panel tests reach the generic draw-error assertions at their
  intended call sites. The concrete `BandCoverage` renderer has an Infallible
  error type and retains its separate infeasibility argument.
- Rescue rejects an incomplete root-key page with a nonzero OTP lock row,
  without modifying bytes. Storage tests refuse root downgrade/key replacement,
  wrong pending generation, malformed bucket/counter widths, wrong root arm,
  reinitialization and erased live replicas. Equal-generation empty/populated
  slots distinguish absence from generation mismatch.
- Cold counter rekey/rollover controls now time faults against a cold baseline,
  reaching the intended wrong-sequence and empty-directory rows. Authenticated
  component tests exercise a wrong scan location, a wrong cached value width,
  aligned read geometry, page-marker faults and an old-owner prefix misread.
  The last must preserve the verified old owner's physical bytes and CRC.
- OATH migration waits after a detached HOTP read error, preserves owner/counter
  bytes, then succeeds on retry. PIV refuses a valid-width AES management key
  with an invalid touch policy. OpenPGP loads a valid five-field legacy CRT
  representation without opportunistic migration when `rsa_from_pqe` refuses
  its parameters, preserving legacy AES-CFB ciphertext and flash generation.
- Vendor parsing refuses undefined subcommands before interpreting their array
  parameter. Direct makeCredential/getAssertion component matrices exercise
  extension/prestate combinations and check exact CBOR, writes and independently
  verified assertion signatures. Private request combinations are component
  contracts, not claims about inputs admitted by the public feature parser.
- SDK/UI/ML-DSA/RSA negative cases verify the specific invariant assertion they
  target. Sixteen Fs tests exercise nineteen oracle/test-util conditions,
  including read failure, stale excuses, torn-prefix direction, invalid model
  contents and a second recovery cut. These check the verification machinery;
  their failures are not deployed-firmware fault coverage or mutation kills.

The HID tests first exposed a real defect: `Reassembler::scrub` cleared payload
bytes and length while leaving the transaction active. A partial old request
could block a new channel with `CHANNEL_BUSY`; an old continuation could also
produce a stale-channel error. `reset_if_new_session` now calls `abort` before
`scrub`, preserving the old declared length for wiping while clearing ownership
and transaction state. `bcdDevice` advances to `0x0BDF`; the protocol, FIDO guide
and changelog record the behavior.

The oversized reassembler and authenticated component inputs are explicitly
verification-constructor/helper contracts. They are not credited as reachable
USB requests or states ordinary writers necessarily produce.

### Residuals and measurement limits

The [residual annex](mcdc-residuals.md) enumerates all **138** remaining default
conditions by file, decision line, condition index, missing vector and reason.
It distinguishes producer/type/arithmetic invariants, fixed profiles, semantic
coupling and cryptographic assumptions. All identities remain in the raw
denominator. In particular:

- Checked lengths and earlier validators make later bounded-slice failure
  outcomes impossible under the admitted producer contract.
- A fixed binary cannot flip `cfg!` or a derived policy constant. Alternate
  builds supply separate evidence, never one runtime pair.
- Two-variant root arms and FIDO UV/grants retain explicit semantic coupling.
  The counter-entry mismatch helpers are likewise distinguished from separately
  observable authentication checks; a direct mismatch is not a pure type proof.
- Main-directory digest equality depends on the documented fingerprint
  collision assumption. That is weaker than unconditional mathematical
  infeasibility and is recorded as such.
- `READ_SIZE=0` and `512` constructor controls both fail compilation with
  E0080 at `VerifiedFlash::new`'s existing inline-const geometry assertion.
  These controls establish an instantiation contract, not runtime pairs.

The frontend declares **79 source-scope limitations in 75 files** with the
qualified-pin extension. The annex inventories the const/macro surfaces and
the targeted experiments below. Literal includes are followed separately;
generated tables, uncompiled Kani/device code, dependencies, firmware glue and
C/assembly retain separate scopes. No whole-core 100% claim follows from
disposition of the host residuals or from branch coverage.

### Qualified pin-expression extension

A later [expression-view patch](mcdc-supercov-pin-expression.patch), applied
after the anonymous-constant patch, exposes the ordinary expression argument
of `core::pin::pin!` and `std::pin::pin!` to the existing instrumenter. It does
not expand the macro itself or change witness arithmetic. The exact path
allowlist relies on the reviewed repository bindings; it is not name resolution.
Unqualified user macros remain opaque.

Four calibration tests cross a real `Pending` poll and verify the returned
values and short-circuit call counts. The old tool sees zero conditions behind
the macros; the extension witnesses AND 2/2, mixed 3/3 and a deliberately
incomplete mixed expression 1/3. The custom unqualified macro keeps its
limitation. Both measured suites pass with `valid=true` and `stale=false`.

The same 141 USB tests then pass under both tools. Both retain 114/118 condition
pairs; the real pinned body has a `match` and calls, so opening it adds two
statements and five branch obligations, rather than new Boolean decisions.
The USB source-scope limitations fall from three to one (the const context).
The isolated eighteen-profile matrix uses this extension. The separate USB
comparison does not add its counts to the whole-library score. Its SHA-256 is
`aa9a356c2404d3196be34837b12c74b67bd8046d678130e0a9ed9db0c0c02b8d`.
Sources, commands, source hashes, calibration and reports are retained in
`target/mcdc-pin-20261105/` and `target/mcdc-pin-usb-20261105/`. The original
tool executable and source are restored byte-for-byte after building the prototype.

### Const runtime-body experiment

The native frontend skips `const fn` bodies. A separate
[experimental adapter](mcdc-supercov-const-runtime.patch) keeps the public
const function and creates sibling const/runtime helpers whose bodies are
byte-identical to the original. An isolated wrapper uses
[`core::intrinsics::const_eval_select`](https://doc.rust-lang.org/core/intrinsics/fn.const_eval_select.html)
to preserve compile-time calls while routing runtime calls to the instrumented
non-const helper. Only measurement copies enable the unstable intrinsic with
`RUSTC_BOOTSTRAP=1`; the firmware sources and compiler pin are unchanged.

The selected set is **132 functions in 51 files**. Metadata records original
byte ranges, source hashes, helper identities and exact body equality after
reparsing. Current bodies are revalidated against the measured set. The audit
finds no body-local statics, location/caller/link identity constructs or mutable
by-value parameters in this set. The generator rejects unsupported forms,
including unknown macros nested inside assertion token trees. Eight negative
fixtures fail at the intended guard before writing transformed output.
These checks support this audited set, not arbitrary Rust clone equivalence;
source locations in panic diagnostics change and retain a source mapping.

The automatically generated calibration keeps const tables, mutable `self`,
const generics and lifetime-bound references working in both ordinary builds.
Runtime measurement has **6/8 pairs**. The incomplete mixed decision remains
1/3 even though its compile-time table enumerates all eight rows: compile-time
execution does not fill runtime gaps. Original/adapted tests both pass; the
mutable counter advances exactly three times. The final calibration run is
`run_0aadda07d5523f0f`.

The earlier complete adapter suite passes **4,773 tests, five skipped**, with
4,188/4,384 pairs (95.53%), 196 residuals and 79 declared limitations. Its run
`run_427f12ad219317b2` predates the final test additions. Against its matching
native source set, the adapter exposes **98 additional conditions: 94 have
pairs and four are fixed-data generator residuals**: three assertions and the
tail-run guard. The annex gives the
independent artwork recomputation for those four; they remain raw residuals.
This transformed-source result is separate from the final native default and
is not added to its numerator or percentage.

A preceding qualifier-removal experiment could only make 50 of the 132 bodies
non-const; the compiler required const evaluation for the other 82. It passes
4,771 tests with 4,119/4,316 pairs, but is retained as an earlier partial
experiment, not the adopted whole-set adapter. Sources, transformations,
calibrations, hashes and logs are in `target/mcdc-const-select-20261105/` and
`target/mcdc-const-runtime-20261105/`.

### Explicit EC macro expansion

Four isolated instantiations (two `brainpool!`, two `comb_mul_fn!`) are expanded
from their exact repository templates, with bindings and hashes retained.
Expression metavariables remain parenthesized to preserve macro grouping.
An initial substitution that lost this grouping failed compilation and is not
coverage evidence. The corrected build passes **108 EC tests**, witnessing
**20/25 conditions** in `run_e45fe68a05590951`.

Both new Brainpool signature-selection conditions have pairs. Two comb bit
extractor outcomes require `n>=256`, while callers construct
`n=j*COMB_D+t<=255`; a P-521 normalization policy is a fixed dependency
constant. The other two residuals are pre-existing key-helper decisions whose
FIDO consumers are measured in the whole-library scope. This supplementary
result does not erase native macro limitations. Exact transformations and
reports are in `target/mcdc-ec-expanded-20261105/`.

### ARM runtime experiment

An isolated port of Supercov's existing memory-channel runtime builds with the
pinned compiler for `thumbv8m.main-none-eabihf`. It uses `core`, the already
locked `portable-atomic` version for 64-bit counters, and core/exception context
identities. The Boolean instrumenter and witness arithmetic remain upstream's.
This runtime is experimental and is not installed in the repository's build.

A calibration-only image executes AND, OR, mixed and repeated predicates,
checks short-circuit call counts, and reaches USB-ready. The upstream region
reader and witness search return 2/2, 2/2, 3/3, 1/3 and 1/4 respectively. The
1/3 control observes both values of every condition and both decision results,
but lacks the necessary independence pairs. Repeated conditions retain their
individual occurrences and coupling. Trace overflow and loss flags are zero.

A separate image instruments only `firmware/src/worker.rs`. After boot,
getInfo, USB reset and getInfo again, the region reader recovers real vectors;
**4/35 conditions in the 29 declared decisions have pairs** before cfg
settlement: the compiled scope is 26 decisions and 31 conditions. This is a working
transport/runtime pilot, not worker completion or ARM image MC/DC. Its static
region is 16 KiB with the upstream eight decision slots. A prior 32-slot image
failed startup; restoring eight slots succeeds, but the precise cause has not
been established. Timing, memory-layout equivalence, full-image coverage and
silicon correspondence are not inferred.

The [combined const/macro and worker follow-up](mcdc-expansion.md) records
fresh host defaults of 4,244/4,388 conditions with the const/EC adapters and
4,255/4,399 after guarded `matches!` expansion. It extends the worker campaigns
to 29/31 compiled conditions in a fresh button/ABI image with fault and reseed
campaigns. Its two raw worker residuals retain producer/state invariants. The
follow-up also measures the ARM C/assembly component scope, with explicit
compiler, API-defect and hardware correspondence boundaries; these results do
not establish whole-image MC/DC.

Source/probe manifests, runtime code, build logs, ELF symbols, raw SRAM regions
and decoded vectors are in `target/mcdc-arm-20261105/` and
`target/mcdc-arm-calibration-20261105/`. The preparation, build and extraction
scripts are retained in `target/mcdc-core-20261105/`. Each emulator uses owned
loopback ports and disposable flash/OTP files; no hardware operation was run.

### Verification

The final 2026-11-06 closure passes fresh full runs of both gate layers:

```sh
nix develop -c env RUST_TEST_THREADS=4 ./scripts/check.sh
nix develop -c ./scripts/check-assurance.sh
```

The project run uses four host test threads. An earlier default-parallel run
failed the vendor no-touch wall-clock assertion; its exact replays pass, but
default-parallel timing stability remains unestablished. The separate CANCEL
socket-fixture repair and its controls are recorded in the
[follow-up report](mcdc-expansion.md#evidence-and-reproduction).
Source checks retain the original measurement snapshots and qualify that
test-only amendment separately. Final logs and their hashes are recorded in
`target/mcdc-closure-20261105/closure-status.json`.

The advisory in-diff Docker mutation run now completes: **20/20 caught** on
Linux `aarch64-unknown-linux-gnu`, including the pre-existing Fs oracle repair
and the current USB diff. The isolated runner repairs its missing shell/env
links and measures a source-only snapshot, avoiding unrelated ignored build
trees that exhausted the container's filesystem. The standard gate and shared
mutation container are unchanged. Its raw outcomes and failure logs are in
`target/mcdc-complete-20261105/mutants/`.

Fourteen additional manual controls remove the HID abort, quiet presence flush,
OTP lock distinction, root downgrade/key/generation checks, bucket/counter
width checks, empty-slot check, OATH migration refusal, PIV touch-policy check,
vendor selector, old-owner retirement prefix and PIV freshness guard. Each fails in the intended
runtime assertion; the earlier seven authorization/DEK controls remain separate.
The final controls and restored
sources are retained in
`target/mcdc-controls-final-20261105/`. These finite controls are not a
whole-core mutation score.

## Reproduction

Build the external tool inside the existing Nix shell. This patch changes only
Supercov:

```sh
git clone --branch v4.22.0 --depth 1 https://github.com/supercorp-ai/supercov.git target/supercov-security
git -C target/supercov-security apply ../../docs/mcdc-supercov-anonymous-const.patch
git -C target/supercov-security apply ../../docs/mcdc-supercov-pin-expression.patch
nix develop -c cargo build --locked --manifest-path target/supercov-security/Cargo.toml \
  --target aarch64-apple-darwin --target-dir target/supercov-security-build -p supercov
```

Set `SUPERCOV_SOURCE_ROOTS` to the reviewed files, then wrap the existing test
command. For D1 on freshly issued tokens:

```sh
nix develop -c env SUPERCOV_SOURCE_ROOTS=crates/rsk-fido/src/getassertion.rs \
  target/supercov-security-build/aarch64-apple-darwin/debug/supercov -- \
  cargo test --locked --target aarch64-apple-darwin -p rsk-fido --lib \
  issued_tokens_exercise_each_getassertion_condition
```

`supercov runs latest decision crates/rsk-fido/src/getassertion.rs:452 --json`
prints vectors and pairs. Use the table's filters/files for other groups. Keep
logs outside measured inputs. The recorded run retains exact commands, source
hashes, tool patch, raw evidence, functional outcomes and falsification logs.

For the whole-library profiles, use a fresh source-only project and a fresh
Cargo target for **each** feature set, with the tool/runtime outside that source
scope. Inside the existing Nix shell, run this from the fresh copy:

```sh
SUPERCOV_SOURCE_ROOTS=crates SUPERCOV_KEEP_WORKSPACE=1 \
  /absolute/path/to/supercov -- \
  cargo test --locked --target aarch64-apple-darwin --workspace \
  --exclude firmware --exclude firmware-ns --exclude rsk-wipe --lib
```

Add `--features <profile>` for a non-default row. Preserve the exact test
snapshot, `Cargo.lock`, source hashes, raw run and compiled depinfo before
discarding rebuildable caches. Reusing the same Cargo target across profiles
reproduces the scope defect above.

The const adapter is a separate executable example in the external tool tree:

```sh
git -C target/supercov-security apply ../../docs/mcdc-supercov-const-runtime.patch
nix develop -c cargo build --locked --manifest-path target/supercov-security/Cargo.toml \
  --target aarch64-apple-darwin --target-dir target/supercov-security-build \
  -p supercov-engine --example const_runtime
```

It takes `input.rs output.rs metadata.json`. Apply it only to the audited
measurement copy, keep both helpers' bodies equal to the input, enable the
documented intrinsic features in that copy, and run both ordinary and measured
tests with `RUSTC_BOOTSTRAP=1`. The adapter's metadata and rejection calibrations
are part of its evidence; successful compilation alone is insufficient.
