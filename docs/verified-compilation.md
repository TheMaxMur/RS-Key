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

The compiler targets reviewed below lack Armv8-M Mainline support. Moving a
Rust kernel to verified C would add tools and an FFI boundary. Level 11C is
declined for the RP2350. The source-to-binary gap is recorded in
`assurance/platform.toml`.

## The candidate kernels

Stage 11B names five. Measured over the tree, one of them is portable to a C
subset. RSA and three other candidates fall outside the verified C subset.

| Candidate | Where | Size | Portable to a verified C subset? |
|---|---|---|---|
| gate / transition functions | the ten concrete gates `docs/authorization-slice.md` lists, over `crates/rsk-fido/src/state.rs` | 856 lines in `state.rs` alone | **No.** Half are generic over two traits (`<S: Storage, R: Rng>`); the other half take a Rust struct by reference, whose layout Rust owns |
| zeroization routines | 16 `scrub` / `wipe_*` sites across `crates/` and `firmware/`, and `rsk_secret`'s drops | 16 sites, 49 files using `zeroize` | **No.** Each is a method on a Rust type, and the drop glue that makes it sound is the compiler's |
| RSA exponentiation and CRT | Rust with shared host and device Montgomery arithmetic | 349 lines in `montgomery.rs` | Moving the kernels to C would require a source rewrite and a new FFI contract |
| ML-DSA reductions | `crates/rsk-mldsa/src/reduce.rs`, `ntt.rs`, `round.rs` | 256 lines | **Yes, in principle.** Branch-free integer arithmetic, no generic function in any of the three |
| linker-generated boundaries | 15 of the 32 `[[boundary]]` rows in `assurance/toolchain.toml` | 15 symbol imports | **Not code.** The datum is a symbol's address; a compiler has nothing to say about it |

The genericity is the load-bearing number. Across the production modules of
`crates/rsk-fido/src/`, 243 of 470 functions are generic and 177 of those carry
`<S: Storage`. C has no traits and no monomorphisation, so "port the gate" means
"hand-instantiate and rewrite it", and the rewrite is the risk the verification
was meant to remove.

The one candidate that would port cleanly is the smallest and the least
exposed. `crates/rsk-mldsa/src/round.rs` already carries a Kani proof
(`round_kani.rs`), which is evidence about the source — exactly the layer a
verified compiler does not reach — so moving it to C would trade a proof this
tree runs for one it cannot.

## RSA and the remaining FFI boundary

The Rust RSA kernels have **0 RSA native imports**. The Secure TrustZone
gateway still uses C, with a calling convention and native source inventory
recorded in `assurance/toolchain.toml`.

## The TCB delta

`scripts/check-assurance.sh:"toolchain TCB registry"` prints the live roster, and
`assurance/toolchain.toml` is what it prints from: 13 registered tools
carrying 7 distinct roles, of which 12 name a file that pins them and 1 is
unpinned against an open obligation. The registry records 32 boundaries,
including 15 linker-symbol imports. The remaining 17 cover the TrustZone
gateway, interrupt vectors, probe symbols and Secure fault entry. Of
the six TCB categories the criterion counts, the registry reaches 4 and says
why the other two are out of reach.

A verified-compiler pipeline moves that in one direction only.

**It removes nothing.** The intuition is that CompCert replaces LLVM for the
kernel, but LLVM is not in the roster: it is one of the two categories
`assurance/toolchain.toml` records as out of reach, because rustc's LLVM
version is written in no file of this tree and its pass pipeline is written
nowhere at all. Replacing an unenumerated tool for one kernel does not
enumerate it. And `arm-none-eabi-gcc` and `arm-none-eabi-as` both stay, because the Secure gateway still uses that toolchain.

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
profile.

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
`scripts/check-assurance.sh:"release manifest"`: 15 steps over 6 subjects. Three of the
fifteen are touched, and the third is the one that fails quietly.

| Step | Subject | What a second language does to it |
|---|---|---|
| build the firmware | `none` | the derivation must carry a second toolchain |
| reproducibility gate | `bit-for-bit` | the second compiler must be deterministic, and reproducible by whoever holds its licence |
| CycloneDX SBOM | `inventory` | `cargo cyclonedx` (`.github/workflows/release-build.yml:171`) enumerates cargo packages; a non-Rust kernel is simply absent from the published inventory, with no error |

The remaining twelve — checkout, the installers, the caches, tag admission,
checksums, provenance, signing, notes, publication — are language-agnostic.

## What it costs the gate

`scripts/check.sh` runs 109 rows: 61 invoke `cargo`, 18 are Python, 30 are
neither. A kernel outside Rust is invisible to a measured nine of them, and
would need a twin for many more.

**Structurally blind, all nine:** `cargo-audit` on three lockfiles,
`cargo-deny`, `cargo-vet`, `crate roster`, `crate graph`, `kani roster` and
`kani shrink roster`. Every one derives its subject from cargo metadata or from
`.rs` source — `scripts/crate_graph.py` and `scripts/roster_gate.py` from the
workspace manifests, `scripts/kani_gate.py` from files with an `.rs` suffix —
so a C or extracted-C kernel is not a thing they can fail about.

**Would need a twin:** 24 clippy rows, 8 rustdoc rows, 5 fmt rows and 18
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
  candidate that ports: 256 lines, no generic function, branch-free integer
  arithmetic. A measured pilot showing the extracted C is byte-comparable in
  speed and that the proof obligations it discharges are ones Kani does not
  already reach on the Rust would reopen the question for that kernel alone —
  never for the whole firmware.
- **The gate stops being Rust-shaped.** If the tree acquires a second language
  for an unrelated reason and pays the linting cost listed above anyway, the
  marginal cost of this decision falls to the toolchain delta alone.

None of these is close. The first two are outside this project's control.

## Reproduce

```sh
nix develop -c python scripts/toolchain_gate.py     # the roster and its FFI boundaries
nix develop -c python scripts/release_gate.py       # 15 steps over 6 subjects
nix develop -c python scripts/docs_constants.py     # MAX_MOD, held against the code

# the candidate kernels
wc -l crates/rsk-rsa/src/montgomery.rs
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
