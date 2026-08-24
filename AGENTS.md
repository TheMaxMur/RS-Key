<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# AGENTS.md

Operating guide for AI coding agents (Claude Code, Cursor, Codex, …) working in
this repo. This is the short, imperative version; the authoritative process is
[CONTRIBUTING.md](CONTRIBUTING.md) and the codebase map is
[docs/architecture.md](docs/architecture.md) — read both before a non-trivial
change. If this file disagrees with the tree, the tree wins; send a fix for this
file too.

## What this is

RS-Key is open-source security-key firmware for the Raspberry Pi **RP2350**,
written in Rust (`no_std`, [embassy](https://embassy.dev)), plus the host tooling
that drives it. An RP2350 board is made to behave like a USB authenticator
(FIDO2/CTAP, PIV, OpenPGP, OATH). It is an experimental, single-maintainer
project — see [README.md](README.md) and
[docs/threat-model.md](docs/threat-model.md).

## Golden rules

- **The gate is the source of truth.** Run `nix develop -c ./scripts/check.sh`
  and make it fully green before you call a change done. Don't infer success
  from a partial build — CI runs exactly this script, so green locally is the
  whole bar.
- **Bump `bcdDevice` on a firmware-behaviour change.** `config.device_release`
  in [firmware/src/main.rs](firmware/src/main.rs), +1 hex. Host-only changes
  (CLI, docs, CI) do **not** bump it. (Background, plus the separate
  anti-rollback epoch it must not be confused with: CONTRIBUTING.md →
  "Firmware changes bump bcdDevice".)
- **`no_std`, no alloc.** If a firmware change needs a heap, it's the wrong
  change. Clippy runs `-D warnings`; justify any `#[allow]` inline at the
  smallest scope.
- **`unsafe` and new dependencies are not free.** A new `unsafe` site needs an
  entry in [docs/unsafe.md](docs/unsafe.md); a new dependency needs a stated
  reason — it's joining an authenticator's trust base.
- **Every new file starts with the SPDX header** (`AGPL-3.0-only` — copy it from
  any neighbouring source file).
- **Don't commit, push, flash, sign, or write OTP fuses unless asked.** The
  maintainer owns git history and everything that touches hardware (see
  "Maintainer-only"). When you do commit on request, do it from inside
  `nix develop` — a pre-commit hook (gitleaks + fmt + clippy) rejects commits
  made outside the shell.
- **Commits follow the repo's prefix style** — see `git log` and CONTRIBUTING.md
  → "Commits and PRs". History reads as a changelog; one topic per change, with
  refactors kept separate from behaviour changes.

## Working discipline

- **Surface assumptions; don't code through confusion.** If the task has several
  reasonable readings or an important detail is unclear, say so and ask before
  writing code. State the assumptions the implementation depends on.
- **Surgical diffs.** Touch only what the task requires; no refactoring adjacent
  code "while you're there". Unrelated dead code or design problems: mention
  them separately, don't fold them into the diff.
- **Define done as something checkable.** A bug fix starts by reproducing the
  bug — a failing host test where the logic is host-testable, a `tests/*.py`
  repro otherwise — then fixes it. A refactor preserves behaviour and proves it
  with the existing tests and an unchanged wire surface. For multi-step work,
  each step names its verification.
- **Never report unverified success.** Don't claim a fix works, a command
  succeeded, or the gate is green unless you observed it. If something couldn't
  be verified (e.g. it needs hardware), say exactly what remains unchecked.
- **A red run is not evidence until you know why it went red.** A check that
  fails for the wrong reason proves as little as one that cannot fail — it just
  wears the opposite colour, and a verdict column hides it either way. So when a
  mutation, a fuzz oracle or a deliberately broken input reports failure, read
  *which* assertion fell and in *which* direction, and ask whether that describes
  the defect or its inverse. (Measured: 2 of 24 co-refutation patches modelled the
  inverse defect and scored a kill; the tell was that every failure said "should
  have succeeded" and none said "should have been refused".)
- **A new guard is falsified through the row that runs it, not just its own
  function.** Prove the *gate* goes red — the `check.sh` row, the CI step — and
  not only that the helper returns a problem when called directly. A guard whose
  wiring nothing exercises can be deleted with the suite still green, and the
  weekly rows that call a script rather than pytest are then unprotected. This is
  the same rule as "a guard's mutation table goes in the diff", one layer out,
  and it is where that rule has actually failed.

## Code style

Match the file you're editing — naming, error-handling pattern, and comment
density included. New code should be indistinguishable from what surrounds it,
not stamped with a different house style. Then:

- **Comments earn their place.** Explain *why*, never *what* — the reader can see
  what the line does. **A comment is at most 3 lines**; if it needs more, fix the
  code or the design, not the comment. No narrating the obvious
  (`// loop over the items`), no commented-out code left behind, no changelog
  prose, no `// this function will …` preambles. Worth words: a constraint, a
  spec reference (`// CTAP 2.1 §6.5.5.7`), power-cut ordering, a why-this-not-that.
- **Smallest surface that works (KISS, YAGNI).** Focused functions; the
  iterator/idiom the neighbours already use; no trait, generic, or config knob
  for a future that isn't here yet. If the same result takes materially less
  code, choose the smaller solution. But simple ≠ incomplete: a "simple" change
  still satisfies the whole current contract — every affected layer, state,
  test, and doc (see "When you change X, also do Y") — not an MVP slice of it.
- **Names carry the domain vocabulary** (`rpIdHash`, `KeyFid`, `bcdDevice`), not
  invented synonyms.
- **No magic values; define once, reuse (DRY).** Anything protocol- or
  policy-shaped — an INS or tag, a FID, a timeout, a retry budget, a buffer
  size — is defined once under a domain name and reused (pattern:
  `crates/rsk-fido/src/consts.rs`); the same goes for duplicated status/label
  mappings. Self-evident literals in place (`0`, `1`, an obvious length) are fine.
- **Typed state, not string matching.** Control flow follows enums and typed
  states, never display text or ad-hoc literal comparison. A flow with more than
  3–4 states, retries, or cancellation gets an explicit state machine kept
  separate from transport and rendering, with its invalid transitions tested.
- **No hidden side effects.** A function named like `get`/`parse`/`validate`/
  `format` must not write flash, mutate state, or do I/O; if it must, make that
  visible in its name and at the call site.
- **Fail explicitly.** Don't swallow errors into vague fallbacks; map a failure
  to the status word or error variant that preserves the cause. An intentional
  fallback is named, scoped, and tested.
- **Don't grow oversized files.** A sizeable new unit (a command handler, a
  screen, a codec) goes in its own module — or a `crates/rsk-*` crate if it's
  host-testable — not appended to an already-long file. Split an oversized file
  along existing applet/command/screen boundaries only when a task touches it,
  as its own refactor commit; never split just to hit a line count.
- **UI text is presentation only** (`rsk-ui`, `tools/tui`, `tools/rsk`): map
  typed state to text at the edge, never branch on a display string, and keep
  each domain's status→label/colour mapping in one place.

The rest — `no_std`/no-alloc, `-D warnings`, `unsafe`, new dependencies, the
Python conventions for `tools/rsk` — is in the Golden rules above and
CONTRIBUTING.md → "Code".

## Build & test

- **Everything runs inside `nix develop`** (it pins Rust stable + the
  `thumbv8m.main-none-eabihf` target, picotool, gitleaks, the Python stack).
  Prefix one-off commands with `nix develop -c …`.
- **The default cargo target is the firmware's `thumbv8m` (embedded).** Host
  clippy and tests need an explicit `--target <host triple>` — `check.sh` has
  the exact invocations. On Linux, run
  `HOST_TARGET=x86_64-unknown-linux-gnu ./scripts/check.sh`.
- **`firmware/` is a `no_std` binary with embassy-rp (RP2350) deps — it does NOT
  build or test on the host.** So host-testable logic belongs in a `crates/`
  lib, not in `firmware/`. When you add logic worth unit-testing (a parser, a
  codec, a state machine), put it in a `crates/rsk-*` crate with `#[cfg(test)]`
  tests — and a `#[cfg(kani)]` proof where a round-trip or invariant warrants
  one — and keep `firmware/` as the thin glue that calls it. Worked example: the
  `EF_LED_CONF` codec lives in `crates/rsk-led` (host-tested + Kani); `led.rs`
  only marshals its atomics through it.
- **Tests and Kani proofs live in sibling files, not inline.** Don't grow
  `#[cfg(test)] mod tests { … }` / `#[cfg(kani)] mod proofs { … }` blocks at the
  bottom of a source file — keep the code file to code and hook the modules in
  by path:

  ```rust
  #[cfg(test)]
  #[path = "foo_tests.rs"]
  mod tests;

  #[cfg(kani)]
  #[path = "foo_kani.rs"]
  mod proofs;
  ```

  `foo_tests.rs` / `foo_kani.rs` sit next to `foo.rs`; a crate root (`lib.rs`)
  uses `tests.rs` / `kani.rs` (worked example: `crates/rsk-slip39/src/tests.rs`).
  Each starts with the SPDX header and `use super::*;`. The `#[path]`
  child-module form is deliberate: it keeps the tests' access to the parent's
  private items, which a plain sibling `mod` would lose. cfg-gated code never
  reaches the firmware image, so moving it is not a behaviour change (no
  `bcdDevice` bump).
- **`check.sh` leaves the *no-touch* test image** at
  `target/.../release/firmware`. Anything meant to be flashed must be rebuilt
  with `cargo build --release -p firmware` first — flag this if your change
  affects which image is produced. A bare `cargo build` also carries **no
  partition table** (it is applied after linking), so a key flashed straight from
  that ELF has an unfenced KV store: run `scripts/pt.sh <elf> <out>` over it
  first, or build with `nix build .#firmware`, which does it for you
  ([docs/build.md](docs/build.md#the-partition-table)).

## Layout

| Path | What |
|---|---|
| `firmware/` | The binary: boot, USB, the worker's sequencing, LED, presence, and the board halves of `rsk-device`'s `Hooks` / `rsk-vendor`'s `Platform`. `no_std`, embedded-only. |
| `crates/rsk-*` | The libraries, and the one thing that separates them from `firmware/`: they are **host-tested**, so host-testable logic belongs here. Which crates exist is [`docs/architecture.md`](docs/architecture.md#crates) — `scripts/crate_graph.py` holds that table to the workspace members, so it is the list that cannot go stale. Naming them here instead is what drifted across four refactors. |
| `tools/rsk/` | The Python host CLI (`rsk …`). Match the neighbouring modules: `register(sub)`, `die()`, flake-provided deps (no pip). |
| `tools/tui/` | The Rust TUI cockpit — **its own workspace** (build/clippy/test via its own manifest). |
| `tools/emu/` | The software emulator — **its own workspace**. Runs the applet crates on the host over TCP, so `tests/*.py` need no board. |
| `docs/` | mdBook (`SUMMARY.md` = nav). [`docs/protocol.md`](docs/protocol.md) is the **third-party / PicoForge wire spec** — keep it in sync when a wire format changes. |
| `fuzz/` | Fuzz targets (nightly, own workspace): `nix develop .#fuzz -c cargo fuzz run <target>`. |
| `tests/*.py` | On-device tests, run by hand against a no-touch board — or against `tools/emu` with no board (`python tests/emu.py tests/NN_*.py`). |

Read [docs/architecture.md](docs/architecture.md) for the boot flow, crate graph,
flash layout, and device identity.

## When you change X, also do Y

- **A wire format / the protocol surface** (`EF_LED_CONF`, the phy record
  `EF_PHY`, an applet APDU, a CTAP map) → update
  [docs/protocol.md](docs/protocol.md), the host tool that speaks it
  (`tools/rsk/…`), and add a `CHANGELOG.md` `[Unreleased]` entry. A
  persistent-flash change must keep an already-provisioned device working across
  the upgrade — say how, and load older record layouts forward-compatibly.
- **User-visible behaviour** → the matching `docs/guides/*.md` and a CHANGELOG
  `[Unreleased]` entry.
- **A `tools/rsk` (Python CLI) or `tools/tui` (Rust TUI) change** → bump that
  package's version (`tools/rsk/__init__.py` `__version__` /
  `tools/tui/Cargo.toml` `version`). It's the host-tool analog of the bcdDevice
  bump: `pipx` / `pip` / a published `uvx` install key off the version, so an
  unbumped change leaves those users on a **stale build** (e.g. an old `rsk led`
  silently mis-parsing a new device's config). For local dev, run current source
  with `uv run --project tools rsk …` (or `nix develop` → `rsk`) — NOT
  `uvx --from tools/`, which caches the built env regardless of the version
  (`uv cache clean` busts it if you must).
- **A new `unsafe` site** → [docs/unsafe.md](docs/unsafe.md).
- **The meaning of something shared** — a constant's value, an invariant, an
  ownership rule, a signature → **read every other user of it before calling the
  change done**, and ask of each whether it still holds. Nothing fails on its
  own here: the value still type-checks, and a test written against the old
  meaning still passes, so a green gate proves nothing about the sites you did
  not open. For a persisted record, also ask what an *older build* could have
  written there. `scripts/impact.py` lists the unreviewed users for the
  compiler-blind cases (a Rust `const`/`static` value, a Python constant or
  `def` signature) and the pre-commit hook prints it; the rest is on you — a
  narrowed `EF_DEV_CONF_MAX` sized two readers as well as the writer it was
  narrowed for, and only the writer got looked at.
- **Anything protocol-visible** → a test at the level it's visible: a host test
  if the logic is host-testable, a `tests/*.py` script if only the USB stack
  exercises it.

## Maintainer-only — do not attempt

- **Flashing, secure-boot signing, and OTP fuse writes.** Irreversible and
  key-dependent: propose the change, never perform it. The anti-rollback epoch
  (`picotool seal --rollback N`) is a release-time decision, not a code edit.
- **Pushing and tagging.** Leave `git push`, release tags, and the release
  pipeline to the maintainer.
- **Bumping the embassy / toolchain pins**, or weakening the gate, the at-rest
  seals, or a threat-model assumption — only with the maintainer's explicit
  say-so, and flag it loudly in the PR.

## Pointers

- [CONTRIBUTING.md](CONTRIBUTING.md) — the full process: setup, gate, code, tests, commits.
- [docs/architecture.md](docs/architecture.md) — the codebase map.
- [docs/build.md](docs/build.md) · [docs/testing.md](docs/testing.md) · [docs/versioning.md](docs/versioning.md) — build knobs, test layers, versioning.
- [docs/protocol.md](docs/protocol.md) — the host / third-party wire spec.
- [docs/threat-model.md](docs/threat-model.md) · [docs/limitations.md](docs/limitations.md) — what this defends against, and what it doesn't.
