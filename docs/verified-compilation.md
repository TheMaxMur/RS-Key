<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Verified compilation decision

Stage 11's level 11C is a research question, not a work item: could a critical
kernel of this firmware move to a language or a C subset with a **verified
compiler** — CompCert, or an F\*/Low\* pipeline that extracts to C — and would
that shrink the toolchain TCB more than the second language grows it.

The answer is **no**, and no pilot is scheduled. The reasons are measured below,
each with the command that produced it, and the last section says what would
overturn them.

**RS-Key is not formally verified.** This page is a decision about a research
direction. It reports no verification result, moves no property status, and
discharges nothing — `PLAT-TOOLCHAIN-001`, the row that says the compiler's
output is outside every proof this tree runs, is untouched by it and stays
`pending`.

## The decision

A verified C compiler cannot compile this firmware's chip, cannot compile the
part of the one already-foreign kernel that matters, and would add tools to the
toolchain TCB without removing any — so level 11C is declined for the RP2350,
and the source-to-binary gap stays where `assurance/platform.toml` already
records it.

## The candidate kernels

Stage 11B names five. Measured over the tree, one of them is portable to a C
subset, one is already C, and three are not code a C compiler could accept.

| Candidate | Where | Size | Portable to a verified C subset? |
|---|---|---|---|
| gate / transition functions | the ten concrete gates `docs/authorization-slice.md` lists, over `crates/rsk-fido/src/state.rs` | 724 lines in `state.rs` alone | **No.** Half are generic over two traits (`<S: Storage, R: Rng>`); the other half take a Rust struct by reference, whose layout Rust owns |
| zeroization routines | 16 `scrub` / `wipe_*` sites across `crates/` and `firmware/` | 16 sites, 68 files using `zeroize` | **No.** Each is a method on a Rust type, and the drop glue that makes it sound is the compiler's |
| the RSA C/asm wrapper and fault check | `crates/rsk-rsa/src/lib.rs` over `crates/rsk-rsa/csrc/` | 760 Rust, 397 C, 1082 asm | **Already C — and that is the finding.** The assembly is 73% of the foreign half by line and no verified compiler compiles assembly |
| ML-DSA reductions | `crates/rsk-mldsa/src/reduce.rs`, `ntt.rs`, `round.rs` | 249 lines | **Yes, in principle.** Branch-free integer arithmetic, no generic function in any of the three |
| linker-generated boundaries | five of the ten `[[boundary]]` rows in `assurance/toolchain.toml` | 5 symbols | **Not code.** The datum is a symbol's address; a compiler has nothing to say about it |

The genericity is the load-bearing number. Across the production modules of
`crates/rsk-fido/src/`, 215 of 396 functions are generic and 169 of those carry
`<S: Storage`. C has no traits and no monomorphisation, so "port the gate" means
"hand-instantiate and rewrite it", and the rewrite is the risk the verification
was meant to remove.

The one candidate that would port cleanly is the smallest and the least
exposed. `crates/rsk-mldsa/src/round.rs` already carries a Kani proof
(`round_kani.rs`), which is evidence about the source — exactly the layer a
verified compiler does not reach — so moving it to C would trade a proof this
tree runs for one it cannot.

## What the existing FFI boundary costs

This tree already pays for one foreign-language boundary, so "a second one
costs at least as much again" is a measurement rather than a guess. What the
first one costs today:

- **three `unsafe` call sites** — `docs/unsafe.md` sites 17–19, at
  `crates/rsk-rsa/src/lib.rs:387`, `crates/rsk-rsa/src/lib.rs:480` and
  `crates/rsk-rsa/src/lib.rs:573`, behind the `unsafe extern "C"` block at
  `crates/rsk-rsa/src/lib.rs:291` — plus a fourth, build-time, in
  `crates/rsk-rsa/build.rs`;
- **five registry rows** in `assurance/toolchain.toml`: three `import:` and two
  `unit:`, each owing a `provider` that is a pinned tool;
- **two pinned producers**, `arm-none-eabi-gcc` and `arm-none-eabi-as`, which
  are two of the six categories the toolchain criterion counts;
- **a contract in a header the Rust compiler never reads** —
  `crates/rsk-rsa/csrc/bignum_high_level.h`, 271 lines of widths, endianness
  and temp-buffer sizes. `MAX_MOD` (`256`) is the Rust side of it, and nothing
  but a person holds the two together;
- **a containment argument**, which is the reason the sites are allowed at all:
  a power-on known-answer self-test and a Bellcore fault check on every
  signature. A new boundary owes an argument of that shape or it owes
  `docs/unsafe.md` an entry it cannot fill;
- **three citations no gate resolves.** `scripts/citation_gate.py` reads `.rs`,
  `.sh`, `.txt` and `.py`, on `formal/` pages, `.rs` under five roots, `.py`
  under `scripts/` and the evidence bundles. The three `csrc/…c:NNN` citations
  in `assurance/toolchain.toml` match none of that on either axis — suffix or
  page — so the tree's existing foreign half is cited in prose a person checks.
  Checked by hand for this record: all three land on the function they name.

"At least that much again" is therefore, in units: three more `unsafe` sites
owing `docs/unsafe.md`, at least two more registry rows, one more pinned
producer, one more unreadable contract, and one more containment argument.

## The TCB delta

`scripts/check.sh:"toolchain TCB registry"` prints the live roster, and
`assurance/toolchain.toml` is what it prints from: 13 registered tools
carrying 7 distinct roles, of which 12 name a file that pins them and 1 is
unpinned against an open obligation. The FFI boundaries are the ten above. Of
the six TCB categories the criterion counts, the registry reaches 4 and says
why the other two are out of reach.

A verified-compiler pipeline moves that in one direction only.

**It removes nothing.** The intuition is that CompCert replaces LLVM for the
kernel, but LLVM is not in the roster: it is one of the two categories
`assurance/toolchain.toml` records as out of reach, because rustc's LLVM
version is written in no file of this tree and its pass pipeline is written
nowhere at all. Replacing an unenumerated tool for one kernel does not
enumerate it. And `arm-none-eabi-gcc` and `arm-none-eabi-as` both stay, because
the assembly stays.

**It adds at least one tool and plausibly three.** CompCert alone is a
`[[tool]]` with role `compiler` and a `provenance` a gate must open on every
run. An F\*/Low\* pipeline adds its checker and its extractor, and the
extractor is the awkward one: the C it emits is what a C compiler verifies, so
the extraction step is inside the TCB and is not itself what "verified
compiler" refers to.

**The enumerated-category count does not move.** It would still reach the same
four: LLVM stays out of reach for the reason above, and the bootrom is burned
into the RP2350 with no version or hash recorded anywhere.

Net: **+1 to +3 tools, 0 removed, +2 or more FFI boundary rows, and the
category count unchanged.**

## Ecosystem and build

**CompCert does not target this chip.** Its manual lists "ARM v6, v7, and v8 in
32-bit mode, with VFP coprocessor", and its configure script takes the ARM
refinements `armv6-`, `armv7a-`, `armv7r-` and `armv7m-`. The firmware's target
is `thumbv8m.main-none-eabihf` — Armv8-M Mainline, Cortex-M33 — which no
CompCert target names. The nearest, `armv7m-`, is a different architecture
profile, and the build also passes `-mfpu=fpv5-sp-d16`
(`crates/rsk-rsa/build.rs`), a single-precision FPv5 unit that is not the
VFPv3-d16 the ARM ports assume.

**The pinned nixpkgs has CompCert and this project may not use it.** The same
nixpkgs revision `assurance/toolchain.toml` pins for `arm-none-eabi-gcc`
carries `compcert` 3.17. Its `meta.platforms` names six host platforms and no
32-bit ARM among them, and its `meta.license` is the INRIA Non-Commercial
License Agreement, with `free = false` and `redistributable = false` —
evaluating its derivation path fails the unfree assertion outright. The tree is
`AGPL-3.0-only` and the release publishes artifacts a third party is meant to
rebuild bit-for-bit; a non-redistributable compiler in the build closure means
only someone who has separately licensed it can do that.

**The release pipeline has no place for a second language.** From
`scripts/check.sh:"release manifest"`: 15 steps over 6 subjects. Three of the
fifteen are touched, and the third is the one that fails quietly.

| Step | Subject | What a second language does to it |
|---|---|---|
| build the firmware | `none` | the derivation must carry a second toolchain |
| reproducibility gate | `bit-for-bit` | the second compiler must be deterministic, and reproducible by whoever holds its licence |
| CycloneDX SBOM | `inventory` | `cargo cyclonedx` (`.github/workflows/release-build.yml:164`) enumerates cargo packages; a non-Rust kernel is simply absent from the published inventory, with no error |

The remaining twelve — checkout, the installers, the caches, tag admission,
checksums, provenance, signing, notes, publication — are language-agnostic.

## What it costs the gate

`scripts/check.sh` runs 127 rows: 58 invoke `cargo`, 48 are Python, 21 are
neither. A kernel outside Rust is invisible to a measured nine of them, and
would need a twin for many more.

**Structurally blind, all nine:** `cargo-audit` on three lockfiles,
`cargo-deny`, `cargo-vet`, `crate roster`, `crate graph`, `kani roster` and
`kani shrink roster`. Every one derives its subject from cargo metadata or from
`.rs` source — `scripts/crate_graph.py` and `scripts/roster_gate.py` from the
workspace manifests, `scripts/kani_gate.py` from files with an `.rs` suffix —
so a C or extracted-C kernel is not a thing they can fail about.

**Would need a twin:** 20 clippy rows, 9 rustdoc rows, 4 fmt rows and 14
`cargo test` rows. A second language does not inherit `-D warnings`, a
formatter the gate can run, a doc build, or a test harness whose empty
selection is already caught.

That is the cost to a project the README opens by calling experimental, with
one maintainer. It is the argument that decides this even where the technical
ones are close, and here they are not close.

## What would reverse this

A decision with no falsifier is a preference. Any one of these overturns it:

- **A verified compiler targets Armv8-M Mainline.** A CompCert release whose
  configure script accepts a `thumbv8m`-class target, or a comparable verified
  backend for Cortex-M33, removes the first and largest reason.
- **The licence stops being a blocker.** A verified compiler for this target
  under terms that let an AGPL project publish a reproducible build anyone can
  reproduce.
- **The ML-DSA reduction kernel gets a pilot that pays.** It is the one
  candidate that ports: 249 lines, no generic function, branch-free integer
  arithmetic. A measured pilot showing the extracted C is byte-comparable in
  speed and that the proof obligations it discharges are ones Kani does not
  already reach on the Rust would reopen the question for that kernel alone —
  never for the whole firmware.
- **The assembly stops being 73% of the foreign half.** If the RSA core were
  ever replaced by a pure-C implementation fast enough for on-card key
  generation, verifying that C would cover the whole kernel instead of a
  quarter of it.
- **The gate stops being Rust-shaped.** If the tree acquires a second language
  for an unrelated reason and pays the 20-clippy-row-shaped cost anyway, the
  marginal cost of this decision falls to the toolchain delta alone.

None of the five is close. The first two are outside this project's control.

## Reproduce

```sh
nix develop -c python scripts/toolchain_gate.py     # the roster and its FFI boundaries
nix develop -c python scripts/release_gate.py       # 15 steps over 6 subjects
nix develop -c python scripts/docs_constants.py     # MAX_MOD, held against the code

# the candidate kernels
wc -l crates/rsk-rsa/csrc/bignum_high_level.c crates/rsk-rsa/csrc/bignum_asm.S
wc -l crates/rsk-mldsa/src/reduce.rs crates/rsk-mldsa/src/ntt.rs crates/rsk-mldsa/src/round.rs

# the FIDO gate surface: functions, generic functions, and the storage bound.
# `:(glob)` so `*` stops at a `/` — the plain pathspec is depth-blind and pulls
# in the conformance fixtures, which are not the surface a port would carry.
fn='^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[a-z_][a-z_0-9]*'
git grep -hE "$fn"  -- ':(glob)crates/rsk-fido/src/*.rs' ':!*kani*' ':!*tests*' | wc -l
git grep -hE "$fn<" -- ':(glob)crates/rsk-fido/src/*.rs' ':!*kani*' ':!*tests*' | wc -l
git grep -hE '<S: Storage' -- ':(glob)crates/rsk-fido/src/*.rs' ':!*kani*' ':!*tests*' | wc -l

# the gate's shape
grep -cE '^[[:space:]]*(run|run_tests)[[:space:]]+"' scripts/check.sh
grep -E '^[[:space:]]*(run|run_tests)[[:space:]]+"' scripts/check.sh | grep -c cargo

# the compiler this decision is about, in the nixpkgs this tree already pins
nix eval "github:NixOS/nixpkgs/331800de5053fcebacf6813adb5db9c9dca22a0c#compcert.meta.license" --json
nix eval "github:NixOS/nixpkgs/331800de5053fcebacf6813adb5db9c9dca22a0c#compcert.meta.platforms"
```

The CompCert target list is the manual's, section 1.4.1 and the configure
options beside it, at <https://compcert.org/man/>. It is the one measurement on
this page that is not this tree's to re-derive.
