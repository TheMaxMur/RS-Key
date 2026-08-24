<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Cross-reset refinement pilot

This is the phase-6 bridge for `SEC-FIDO-006`,
`ResetNeverWeakensSurvivingState`. It joins the existing TLA+ reset machine to
the concrete FIDO reset order, the `rsk-fs` power-cut contract, and a real-board
test. It does **not** make RS-Key formally verified: the C→B step is bounded,
the flash composition has an executable oracle rather than a deductive proof of
the storage backend, and a HIL result witnesses only the cut that was run.

## The property

The registry requirement is relational: no prefix of `authenticatorReset`,
whether it returns, aborts, or loses power, may keep an owner's usable secret
after removing the gate that protected it. The three independently named
clauses are:

| ID | Clause | Surviving fact | Gate that must still exist |
|---|---|---|---|
| `SEC-FIDO-006A` | `ResetKeepsThePinGate` | owner credential + owner seed | `EF_PIN` |
| `SEC-FIDO-006B` | `ResetKeepsTheAlwaysUvGate` | owner credential + owner seed | `EF_ALWAYS_UV` |
| `SEC-FIDO-006C` | `ResetKeepsTheBackupSeal` | owner's pre-reset seed | `EF_BACKUP_SEALED` |

The last gate reads backwards: deleting the seal is permissive because it
re-opens the one-time seed-export window. A newly provisioned seed after reboot
is therefore not the owner's surviving seed and does not violate the clause.

## Evidence ladder

| Layer | Owner | What it establishes |
|---|---|---|
| Requirement | `assurance/properties.toml` | Stable IDs, statements, and the bounded evidence ceiling |
| TLA+ B | `formal/RSKeySecurityState.tla` | Arbitrary ordering within the secret and gate phases; abort, real power cut, boot-time seed provisioning, and all three clauses |
| Rust refinement | `crates/rsk-fido/src/reset_assurance.rs` | The concrete phase machine and abstraction of the persistent/volatile facts observed by the clauses |
| Kani | `crates/rsk-fido/src/reset_refinement_kani.rs` | Initialization and one-step induction across begin, every relevant delete, phase advances, abort, finish, reboot, and an unrelated FID |
| Power-cut fuzz | `fuzz/fuzz_targets/power_cut.rs` | The real `rsk_fido::reset::reset` over `SeqStorage`, with byte-granular cuts inside writes/erases, fresh caches, `Fs::scan`, `ensure_seed`, and a second boot |
| Real board | `tests/29_reset_power_cut.py` | The same owner seed/PIN/alwaysUv/resident-credential scenario with physical USB power removed while RESET is in flight |

The generated table in `formal/README.md` derives the Kani, fuzz, and runtime
columns by property name. A runtime column of one means that the HIL harness is
owned and discoverable; it is not a stored claim that a particular board run
passed.

## Concrete projection C→B

`ResetPersistentView` observes both seed records, one representative resident
credential, the PIN and alwaysUv gates, and the backup seal. The credential is
usable only while the **owner's** old seed is reachable. `ResetVolatileView`
observes only the RAM seed copy and live token; all other `FidoState` buffers are
irrelevant to this property.

The transition projection uses production's own `reset_phase(fid)` classifier.
That classifier delegates to the shipped `is_fido_seed_fid`, `is_fido_fid`, and
`is_fido_gate_fid` predicates, so the proof cannot silently acquire a second
hand-written gate list. Its phases match the implementation:

1. retire volatile state;
2. delete `FIDO_SEED_FIDS`;
3. sweep non-gate FIDO secrets until enumeration completes;
4. sweep gates until enumeration completes;
5. provision the next identity epoch.

`well_formed` is the induction domain. It requires retired volatile state once a
reset is active, completed earlier phases before advancing, and all three
relational clauses. Kani proves that construction starts inside this domain and
that every modeled concrete step preserves it. Each harness has a satisfiable
`kani::cover!`; the ordinary unit tests also inject one early-gate mutant per
clause and require its exact property to fail.

This is a finite Boolean projection and a one-step induction proof, not an
unbounded proof of the `sweep` loop. Loop termination and truncated enumeration
remain production tests; byte-level atomicity is composed below.

## The `rsk-fs` composition and reboot seam

The projection treats one completed `force_delete` as a record transition. The
lower contract is the existing `rsk-fs::powercut` oracle and its Kani rules:
`delete_landed` allows the old record or a fully deleted record, never a value
gone behind surviving metadata. The `power_cut` target now feeds a separate
input class through the complete real FIDO reset on the same cuttable flash
stack rather than adding another fuzz target.

After a cut the target drops the dead store, rebuilds `SeqStorage` with fresh
caches over the surviving bytes, scans it, runs boot-time `ensure_seed`, and
checks the three clauses. It then boots and scans once more so a verdict cannot
depend on the recovery mount's cache. A local corpus run on 2026-08-16 completed
4,608 executions without a finding; that is sampled evidence, not an exhaustive
result.

## Real-power HIL

The test is deliberately destructive and is not run by the emulator:

```sh
nix develop -c python tests/29_reset_power_cut.py
```

Use a throwaway board running the no-touch test image. The script exports and
seals the owner seed, sets a PIN, enables alwaysUv, creates a resident
credential, starts RESET, and asks for a real cable pull. A relay can be supplied
through `RSK_POWER_CUT_CMD`; `RSK_POWER_CUT_DELAY_MS` moves the cut point. A
RESET that finishes before power disappears is `INCONCLUSIVE`, not PASS.

Flashing and operating the hardware remain maintainer actions. Consequently a
fresh real-board PASS must be recorded separately before calling the roadmap's
hardware witness complete.

## Verus / Creusot decision

No third verifier is added for this pilot. The decision is measured rather than
based on modeling convenience:

- a direct Kani run through the full `FidoState::reset()` was stopped after
  72.45 s without a verdict while CBMC expanded `zeroize` loops through at
  least 398 iterations; the unrelated crypto buffers dominated the formula;
- after projecting the two volatile facts the property actually observes, the
  parent harness solved in 0.52 s and the three clause harnesses in 0.45–0.48 s
  on Kani 0.67.0; all four covers were reachable;
- the byte-level and full-state links are exercised by the real reset unit tests
  and power-cut fuzz, where the complete storage and `FidoState` are affordable.

This is a tractable bounded-proof boundary, not evidence that an unbounded loop
or state-size limit prevents the required argument. Verus or Creusot would add a
third toolchain without removing the abstraction obligation, so the decision is
**not now**. Revisit it only if a later requirement needs an unbounded sweep or
multi-step state space that cannot be reduced without dropping a security-
visible fact.
