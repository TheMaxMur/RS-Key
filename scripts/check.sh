#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Full quality + security suite: formatting, lint, tests, no_std build, SCA, secrets.
# Run locally or in CI. Host target defaults to macOS arm64 (override with HOST_TARGET).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-aarch64-apple-darwin}"

run() { echo; echo "== $1 =="; shift; "$@"; }

# `cargo test` calls a selection of nothing a pass: a name filter that matches
# no test prints "0 passed; …; N filtered out" and exits 0. Five rows below take
# such a filter, so renaming a test turned one of them into a no-op while the
# gate stayed green — measured, `cargo test -p rsk-fido zzz_no_such_test` → 527
# filtered out, rc 0. Every `cargo test` row goes through this instead, filtered
# or not, and has to show a test that actually passed. The unit is the row: a
# crate with no tests of its own is not what this catches, a row that ran none is.
run_tests() {
  local name=$1 log
  shift
  log=$(mktemp)
  echo; echo "== $name =="
  # `tee`, not a redirect: the output belongs on the console like every other
  # row's. `pipefail` (set above) keeps cargo's own failure the pipeline's, so a
  # genuinely failing test stops the gate here rather than reaching the grep.
  "$@" 2>&1 | tee "$log"
  if ! grep -qE '^test result: ok\. [1-9][0-9]* passed' "$log"; then
    echo "FAIL: $name ran no test at all." >&2
    echo "      A name filter matching nothing exits 0 and reads as a pass." >&2
    exit 1
  fi
  rm -f "$log"
}

# flake.lock must stay in sync with flake.nix: regenerate the lock (without
# upgrading existing pins, unlike `nix flake update`) and fail if it changed. A
# stale committed lock means a "green" run no longer matches flake.nix, silently
# undermining the reproducible-build / SBOM provenance. Cheap when in sync (no
# fetch); only an added/removed input in flake.nix produces a diff.
lock_in_sync() {
  nix flake lock
  git diff --exit-code -- flake.lock
}

# `tools/emu` and `fuzz/` are detached workspaces, so each resolves the embassy
# git dependency on its own clock: `branch = "main"` in three manifests is three
# different commits, and nothing says so. The emulator had drifted two months
# ahead — which, now that it runs the real USB stack, means the descriptors a host
# enumerates were not the ones the device ships. Same failure as the vendored
# sequential-storage fork it silently replaced with upstream. One pin, the
# firmware's; every other lock follows it.
embassy_revs_match() {
  local want got lock
  want=$(grep -oh 'embassy?branch=main#[0-9a-f]\{40\}' Cargo.lock | sort -u)
  if [ "$(printf '%s' "$want" | grep -c '')" -ne 1 ]; then
    echo "FAIL: the root Cargo.lock does not pin exactly one embassy rev." >&2
    exit 1
  fi
  for lock in tools/*/Cargo.lock fuzz/Cargo.lock; do
    got=$(grep -oh 'embassy?branch=main#[0-9a-f]\{40\}' "$lock" | sort -u || true)
    [ -n "$got" ] || continue
    if [ "$got" != "$want" ]; then
      echo "FAIL: $lock is on ${got#*#} but the firmware is on ${want#*#}." >&2
      echo "      cargo update --manifest-path ${lock%Cargo.lock}Cargo.toml \\" >&2
      echo "        --precise ${want#*#} \$(grep -o '^name = \"embassy-[a-z-]*\"' $lock | cut -d'\"' -f2)" >&2
      exit 1
    fi
  done
  echo "every workspace is on embassy ${want#*#}"
}

# The shipping image must fit the 2560K code region (firmware/memory.x); this
# ceiling is a *ratchet* well under that hard limit. It hugs the current image
# (876 KiB) plus a small margin, so a runaway — an accidental fat dependency
# (one extra EC curve is ~150 KiB) — or any surprise growth trips it, while
# ordinary build noise does not. Ratchet discipline: when the image shrinks,
# lower this to lock the win in; when a real feature grows it, raise this in the
# same commit. Measured on the default (shipping) build before the display/
# no-touch rebuilds overwrite the ELF; arm-none-eabi-size ships in the dev shell.
FIRMWARE_FLASH_BUDGET_KIB=918
firmware_size_budget() {
  local elf="target/thumbv8m.main-none-eabihf/release/firmware"
  local bytes kib
  bytes=$(arm-none-eabi-size "$elf" | awk 'NR==2 { print $1 + $2 }')
  kib=$(( (bytes + 1023) / 1024 ))
  echo "flash image ${kib} KiB / ${FIRMWARE_FLASH_BUDGET_KIB} KiB ceiling ($(( kib * 100 / FIRMWARE_FLASH_BUDGET_KIB ))%); code region is 2560K"
  if [ "$kib" -gt "$FIRMWARE_FLASH_BUDGET_KIB" ]; then
    echo "FAIL: firmware image ${kib} KiB exceeds the ${FIRMWARE_FLASH_BUDGET_KIB} KiB budget." >&2
    echo "      If the growth is intended, raise FIRMWARE_FLASH_BUDGET_KIB in scripts/check.sh." >&2
    exit 1
  fi
}

# Everything between `_stack_end` and `_stack_start` is stack, and every byte of
# `.data`/`.bss` growth takes one from it — silently, since no build step reads
# it. That has already cost a device: at 0x082A ML-DSA-65 keygen met the statics
# and wedged the key. Same ratchet discipline as the flash budget, floor instead
# of ceiling. The two symbols swap ends under flip-link, so subtract, don't
# assume which is on top.
FIRMWARE_STACK_FLOOR_KIB=168
firmware_stack_floor() {
  local elf="target/thumbv8m.main-none-eabihf/release/firmware"
  local top bot kib
  top=$(arm-none-eabi-nm "$elf" | awk '$3 == "_stack_start" { print $1 }')
  bot=$(arm-none-eabi-nm "$elf" | awk '$3 == "_stack_end" { print $1 }')
  kib=$(( (0x$top - 0x$bot) / 1024 ))
  echo "stack ${kib} KiB / ${FIRMWARE_STACK_FLOOR_KIB} KiB floor; ML-DSA-65 makeCredential peaks near 114 KiB"
  if [ "$kib" -lt "$FIRMWARE_STACK_FLOOR_KIB" ]; then
    echo "FAIL: only ${kib} KiB of stack left, under the ${FIRMWARE_STACK_FLOOR_KIB} KiB floor." >&2
    echo "      Static RAM grew into the stack. Shrink it, or lower the floor deliberately." >&2
    exit 1
  fi
}

# `assurance-trace` exposes α and generated proof domains to host tooling only.
# Build two clean default images in one throwaway source tree, poisoning every
# assurance-only module before the second. The poison must break a feature build
# while remaining absent from firmware; compare loadable bytes, not ELF metadata.
assurance_trace_is_image_neutral() {
  local dir src elf_before elf_poison control
  dir=$(mktemp -d)
  src="$dir/src"
  rsync -a --exclude .git --exclude target --exclude result --exclude formal/out ./ "$src/"

  if cargo tree -p firmware -e features | grep -q 'rsk-fido feature "assurance-trace"'; then
    echo "FAIL: firmware enables rsk-fido/assurance-trace." >&2
    exit 1
  fi

  CARGO_TARGET_DIR="$dir/target-before" cargo build --manifest-path "$src/Cargo.toml" --release -p firmware
  elf_before="$dir/target-before/thumbv8m.main-none-eabihf/release/firmware"
  arm-none-eabi-objcopy -O binary "$elf_before" "$dir/before.bin"

  for f in generated_token_edges.rs state_assurance.rs state_refinement_kani.rs \
      reset_assurance.rs reset_refinement_kani.rs; do
    printf '\ncompile_error!("assurance source reached production");\n' \
      >> "$src/crates/rsk-fido/src/$f"
  done
  CARGO_TARGET_DIR="$dir/target-poison" cargo build --manifest-path "$src/Cargo.toml" --release -p firmware
  elf_poison="$dir/target-poison/thumbv8m.main-none-eabihf/release/firmware"
  arm-none-eabi-objcopy -O binary "$elf_poison" "$dir/poison.bin"

  control="$dir/feature-control.log"
  if CARGO_TARGET_DIR="$dir/target-control" cargo check --manifest-path "$src/Cargo.toml" \
      -p rsk-fido --features assurance-trace > "$control" 2>&1; then
    echo "FAIL: the assurance poison did not reach an assurance-trace build." >&2
    exit 1
  fi
  if ! grep -q "assurance source reached production" "$control"; then
    echo "FAIL: the assurance feature control failed for the wrong reason." >&2
    tail -10 "$control" >&2
    exit 1
  fi
  if ! cmp -s "$dir/before.bin" "$dir/poison.bin"; then
    echo "FAIL: assurance-only source changed the firmware's loadable bytes." >&2
    exit 1
  fi
  echo "assurance sources are absent from firmware; poisoned/default images are byte-identical"
}

# The vendor AID's three debug commands (INS 12/13/14) are timing oracles — over
# the RSA keygen prime search and the EC/KDF hot paths — so each is feature-gated
# and none may reach a shipped image. A `#[cfg]` is only as good as the default
# feature set, and nothing else here reads the artifact, so read it: `opt-level=s`
# inlines the method away but `debug = 2` keeps its linkage name. `led_block` is
# the positive control — the same `impl Platform for VendorPlatform` produces it —
# so an image that simply lost its names fails instead of passing vacuously.
# Mutation table, each observed red — and note a bare `#[cfg]` removal is a COMPILE
# error (the bodies need feature-gated items), so the mutations are whole builds:
# the pre-gate image → `core1_stats` fires; `--features bench,keygen-bench,core1-stats`
# → all three names present, row red; `strip --strip-debug` → the control fires.
DEBUG_VENDOR_METHODS=(core1_stats keygen_bench latency_bench)
debug_vendor_commands_absent() {
  local elf="target/thumbv8m.main-none-eabihf/release/firmware" m
  if [ ! -f "$elf" ]; then
    echo "FAIL: $elf was not built, so there is nothing to check." >&2
    exit 1
  fi
  if [ "${#DEBUG_VENDOR_METHODS[@]}" -ne 3 ]; then
    echo "FAIL: the debug-command list lost an entry; an empty loop reads as a pass." >&2
    exit 1
  fi
  if ! LC_ALL=C grep -qa "led_block" "$elf"; then
    echo "FAIL: no VendorPlatform method name in $elf, so the search below proves nothing." >&2
    echo "      Restore \`debug\` in [profile.release] or re-point this check." >&2
    exit 1
  fi
  for m in "${DEBUG_VENDOR_METHODS[@]}"; do
    if LC_ALL=C grep -qa "$m" "$elf"; then
      echo "FAIL: the debug vendor command \`$m\` is compiled into the default image." >&2
      echo "      It is a timing oracle; keep it behind its feature. Matched:" >&2
      # An unanchored match over 17 MB of .debug_str: print it, so an unrelated
      # name colliding with one of these is diagnosable rather than just red.
      LC_ALL=C grep -ao ".\{0,60\}$m.\{0,20\}" "$elf" | head -3 >&2
      exit 1
    fi
  done
  echo "no debug vendor command in the default image (${DEBUG_VENDOR_METHODS[*]})"
}

# `scripts/pt.sh` fences the KV store off from the USB bootloader. A table whose
# bounds drift from the store is worse than no table at all: the image still
# links, still boots, and the gate still passes, but the running firmware loses
# writes to its own flash. So assert the emitted table against the ELF's own
# symbols — not against pt.sh's arithmetic, which is the thing under test.
partition_table_fences_the_store() {
  local elf="target/thumbv8m.main-none-eabihf/release/firmware"
  local out line want got
  out=$(mktemp -d)/pt.elf
  scripts/pt.sh "$elf" "$out"
  want="$(arm-none-eabi-nm "$elf" | awk '$3 == "__kvmain_start" { print $1 }')"
  want="$want->$(arm-none-eabi-nm "$elf" | awk '$3 == "__kvcnt_end" { print $1 }')"
  for p in "0:NSBOOT(rw)" "1:NSBOOT(-)"; do
    line=$(picotool info -a "$out" | grep -E "^ +partition ${p%%:*} ") || {
      echo "FAIL: no partition ${p%%:*} in the emitted table" >&2; exit 1
    }
    grep -q -- "${p#*:}" <<<"$line" || {
      echo "FAIL: partition ${p%%:*} is not ${p#*:}: $line" >&2; exit 1
    }
  done
  got=$(picotool info -a "$out" | grep -E '^ +partition 1 ' | grep -oE '[0-9a-f]{8}->[0-9a-f]{8}')
  if [ "$got" != "$want" ]; then
    echo "FAIL: the store partition is $got but __kvmain_start..__kvcnt_end is $want." >&2
    echo "      A table that misses the store locks the firmware out of its own data." >&2
    exit 1
  fi
  echo "store partition $got, NSBOOT denied; firmware partition writable"
}

# `picotool seal --sign` retires the image's own IMAGE_DEF — the one the linker
# put in `.start_block`, which carries no signature and no rollback version — by
# rewriting it to `ignored`, and appends its signed one. It only does that when
# it is handed the **ELF**. Given a UF2 it appends and leaves the original live,
# and a board with SECURE_BOOT_ENABLE + ROLLBACK_REQUIRED walks the chain, meets
# that first block, and refuses the whole image. Nothing on the host notices:
# `picotool info` still says "signature: verified", because it reports the block
# it found last. The documented ritual said UF2, so every signed release since
# the partition table landed (0x0871) would have bricked a provisioned key until
# it was reflashed — measured on one. A throwaway key keeps this offline; the
# real one never enters the gate.
release_image_retires_its_unsigned_image_def() {
  local elf dir key first
  elf="target/thumbv8m.main-none-eabihf/release/firmware"
  dir=$(mktemp -d)
  key="$dir/throwaway.pem"
  openssl ecparam -genkey -name secp256k1 -noout -out "$key" 2>/dev/null
  scripts/pt.sh "$elf" "$dir/pt.elf" 2>/dev/null
  picotool seal --sign --hash "$dir/pt.elf" -t elf "$dir/signed.elf" -t elf \
    "$key" "$dir/otp.json" --major 1 --minor 0 --rollback 1 >/dev/null
  first=$(picotool info -a "$dir/signed.elf" |
    awk '/Metadata Block 1/ { f = 1 } f && /block type:/ { print $3; exit }')
  if [ "$first" != "ignored" ]; then
    echo "FAIL: the sealed image's first metadata block is '$first', want 'ignored'." >&2
    echo "      A live unsigned IMAGE_DEF ahead of the signed one does not boot on a" >&2
    echo "      secure-boot device. Seal the ELF, then convert to UF2 — not the reverse." >&2
    exit 1
  fi
  echo "sealed image retires its unsigned IMAGE_DEF (block 1 = ignored)"
}

# The `fmt (fuzz)` and `clippy (fuzz)` rows compile `fuzz/` and never run it, so a
# behaviour change in `crates/` can leave a harness dead with the PR green. It did:
# `oath_apdu` asserts its hard-coded seed PUT succeeded, PUT gained the card's
# key-length bounds at 0x08A0, and the target panicked on EVERY input — the empty
# one included — until the nightly reported it as a crash ~13 h later. libFuzzer
# replays one input with no instrumentation, so this uses the same stable
# toolchain as every row above (no nightly, no `.#fuzz` shell) and runs each
# target on the empty file. Liveness only — no sanitizer, no coverage, no
# fuzzing; those stay in deep-checks.
#
# Same floor, and the same reason, as scripts/fuzz-coverage.sh and
# scripts/fuzz-all.sh: a `for` over an empty word list runs nothing and exits
# 0. Lower all three in the commit that removes a target.
FUZZ_TARGET_FLOOR=53
fuzz_targets_are_alive() {
  local manifest log empty bins dead=""
  manifest=$(mktemp)
  log=$(mktemp)
  empty=$(mktemp)
  # Diagnostics still render to stderr, and `set -e` still stops the gate on a
  # compile error; only the JSON goes to the file.
  cargo build --manifest-path fuzz/Cargo.toml --bins --target "$HOST" \
    --message-format=json-render-diagnostics >"$manifest"
  # cargo's own artifact list, not a directory listing: a binary left behind by a
  # deleted target would otherwise read as alive forever.
  mapfile -t bins < <(grep -o '"executable":"[^"]*"' "$manifest" | cut -d'"' -f4)
  echo "${#bins[@]} fuzz targets (floor ${FUZZ_TARGET_FLOOR}), one execution each on the empty input"
  if [ "${#bins[@]}" -lt "$FUZZ_TARGET_FLOOR" ]; then
    echo "FAIL: the build yielded ${#bins[@]} fuzz targets, under the ${FUZZ_TARGET_FLOOR} floor." >&2
    exit 1
  fi
  for b in "${bins[@]}"; do
    "$b" "$empty" >"$log" 2>&1 || { dead="$dead ${b##*/}"; cat "$log" >&2; }
  done
  rm -f "$manifest" "$log" "$empty"
  if [ -n "$dead" ]; then
    echo "FAIL: these fuzz targets die before they read a fuzzer byte:$dead" >&2
    echo "      A harness whose hard-coded preamble stopped working fuzzes nothing." >&2
    exit 1
  fi
}

# First because it is the cheapest row in the file (~0.2 s over eight files) and
# because the class it catches makes a *different* check silently wrong: OpenSSF
# Scorecard's SAST row parses EVERY file under `.github/workflows` with this same
# actionlint, so one workflow that will not parse returns score -1 for the whole
# check rather than merely failing detection — measured, a single tab in
# `codeql.yml` did it. Nothing in the tree read that directory until now.
#
# No file arguments on purpose. actionlint discovers the workflows from the git
# root itself, which covers `.yaml` as well as `.yml` (a `*.yml` glob does not),
# and which is what makes an empty or missing directory an ERROR — `no YAML file
# was found`, exit 3 — instead of the silent pass over nothing that this repo
# keeps rediscovering. The nixpkgs package wraps shellcheck and pyflakes, so the
# `run:` blocks are linted too even though neither is on PATH.
#
# Mutation table, each driven through THIS row and each exit code taken with no
# pipe. Red, all stopping at row 1 of 1 with rc 1: `runs-on: ubunut-latest` →
# `runner-label`; `${{ matrix.lang }}` → `expression`; a tab after `jobs:` →
# `syntax-check`; an unquoted `$var` in a `run:` block → shellcheck SC2086. And
# the direction that matters — with this row deleted, that same tab left all 98
# rows green (`ALL CHECKS PASSED`, rc 0), so nothing else here reads a workflow.
run "workflow lint"            actionlint -no-color -oneline
run "fmt"                      cargo fmt --all --check
# `BOARD` because `rsk-wipe`'s build script refuses to guess a flash size (see
# the rsk-wipe steps below); `waveshare-one` is the reference board, whose
# values are the same defaults every other knob falls back to.
run "clippy (embedded)"        env BOARD=waveshare-one cargo clippy --workspace -- -D warnings
# Every host row below selects the same way: the whole workspace less the two
# members that are not under `crates/`. `firmware` and `rsk-wipe` are
# thumbv8m-only, so a host target cannot build them; nothing else is excluded.
run "clippy (host tests)"      cargo clippy --workspace --exclude firmware --exclude rsk-wipe --target "$HOST" --all-targets -- -D warnings
# tools/tui is its own workspace (host-only), so the --all/--workspace runs
# above never see it — gate it explicitly. Its lockfile was scanned by nobody
# until Dependabot flagged a transitive advisory from the GitHub side.
run "fmt (tui)"                cargo fmt --manifest-path tools/tui/Cargo.toml --check
run "clippy (tui)"             cargo clippy --manifest-path tools/tui/Cargo.toml --target "$HOST" --all-targets -- -D warnings
# …and its tests, which nothing ran either. Both host suites belong in the same
# gate as the firmware's. Gating them was necessary and not sufficient: the three
# checks named as the reason — the typed confirmations, the refuse-to-guess device
# binding, the "revoking would leave no valid key" brick guard — were asserted at
# their helpers and at no caller, so all three stayed deletable with every test
# green (audit run-34 #9 proved it by mutation). They are asserted at the callers
# now: `rsk/test_refuse_to_guess.py`, `rsk/test_secureboot.py`'s stage commands,
# and `device_tests.rs`'s `every_hid_open_site_is_classified`.
run_tests "test (tui)"               cargo test --manifest-path tools/tui/Cargo.toml --target "$HOST"
# tools/emu is the third host-only workspace (the software emulator) — same
# reason it is gated here: nothing in the --workspace runs above can see it, and
# an emulator that stops compiling is found when someone tries to run the
# protocol suites without a board, which is exactly when they have no board.
run "fmt (emu)"                cargo fmt --manifest-path tools/emu/Cargo.toml --check
run "clippy (emu)"             cargo clippy --manifest-path tools/emu/Cargo.toml --target "$HOST" --all-targets -- -D warnings
run "clippy (emu conformance)" cargo clippy --manifest-path tools/emu/Cargo.toml --target "$HOST" --all-targets --features fido-conformance -- -D warnings
# fuzz/ is also its own (nightly) workspace. rustfmt needs no toolchain, so the
# stable gate can format-check it here. Format fuzz/ with this same stable
# rustfmt — not the .#fuzz nightly one, which lays imports out differently.
run "fmt (fuzz)"               cargo fmt --manifest-path fuzz/Cargo.toml --check
# The fuzz targets call into the applet crates, so a crate signature change can
# leave a target uncompilable — but the full `cargo fuzz build` only runs weekly
# in .#fuzz, so that drift used to surface days later (it did: a `new()` arity
# change silently broke three targets). This row typechecks every target's calls
# on stable instead, on the HOST target (the fuzz workspace inherits the thumbv8m
# default, so `--target` is required); the instrumented build stays in deep-checks.
# It must be `--all-targets`, not `--tests`: the fuzz targets are `[[bin]]`s and
# `--tests` compiles only test targets, so this row typechecked tests/miri.rs and
# nothing else — the very drift it names went on unseen in `fido_vendor` and
# `oath_otp_pin` while the row reported green. And it must be clippy, not
# `cargo check`: `fuzz/` was the one workspace no lint row in the tree reached,
# and five diagnostics sat in it committed and red. Clippy subsumes the check, so
# it replaces that row rather than joining it — two rows thrash one target-dir.
run "clippy (fuzz)"            cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --target "$HOST" -- -D warnings
run "fuzz targets alive"       fuzz_targets_are_alive
# No row in this script or in any workflow had ever run rustdoc, so every
# intra-doc link in the tree was unchecked and 19 of the units below had rotted
# to 75 broken ones. `RUSTDOCFLAGS` is what makes these rows able to go red at
# all — a broken link is only a warning, and plain `cargo doc` exits 0 over every
# one of them. It pairs with `--no-deps`, which keeps that `-D` off dependency
# docs nobody here can fix.
#
# Two permutations per unit, because a doc link crosses a cfg boundary in both
# directions and neither run sees the other's half: the default build cannot see
# a link written INSIDE feature-gated code (rsk-fido's `bench` module hid three),
# and an all-features build cannot see a link TO an item a feature removes
# (`--features display` drops `Blinker`/`ButtonPresence`, which the default
# firmware docs link to). `tools/tui` declares no features and `tools/emu`'s two
# only forward to rsk-fido, which `--no-deps` excludes, so for those a second
# permutation would re-document the same source.
#
# What these rows still do NOT check, so nobody reads them as more than they are:
# `missing_docs` is off (an undocumented item is nobody's failure here); a plain
# `//` comment is not parsed for links, so a dead name in one rots unseen.
run "rustdoc (host)"           env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude firmware --exclude rsk-wipe --no-deps --target "$HOST"
run "rustdoc (host all-feat)"  env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude firmware --exclude rsk-wipe --no-deps --all-features --target "$HOST"
# A third permutation, because the two above document only public items and so
# resolve only the links a public item carries: 28 more were broken at the commit
# that fixed the first 75, in eight crates, two of them on that commit's clean
# list. One row is enough for the whole class — firmware, rsk-wipe, tui, emu and
# fuzz are bin-only, and rustdoc documents a binary's private items by default, so
# the flag is a no-op over all five (each of their rows goes red on a broken link
# in a private `fn main` already); its `--all-features` half found the identical
# 28, so a fourth permutation would only re-report them. It is the dearest row in
# the block, and the row above pays for it too — their flags differ, so each run
# invalidates the other's fingerprint. Deliberately no seconds: the pair timed
# 8.5 s -> 15.6 s when this line was written and 21 s -> 43 s when re-timed later
# in the same tree, so a figure here is a claim that does not survive re-reading.
run "rustdoc (host private)"   env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude firmware --exclude rsk-wipe --no-deps --document-private-items --target "$HOST"
# `firmware` and `rsk-wipe` are the workspace's only thumbv8m-only members, so
# these two rows take the default target instead of $HOST. `BOARD` because
# rsk-wipe refuses to guess a flash size, `LED_KIND=none` because `--all-features`
# turns on `display`, whose compile_error guard demands it. rsk-wipe declares no
# features, so only the firmware needs the second permutation.
run "rustdoc (embedded)"       env BOARD=waveshare-one RUSTDOCFLAGS="-D warnings" cargo doc -p firmware -p rsk-wipe --no-deps
run "rustdoc (firmware all-feat)" env BOARD=waveshare-one LED_KIND=none RUSTDOCFLAGS="-D warnings" cargo doc -p firmware --no-deps --all-features
run "rustdoc (tui)"            env RUSTDOCFLAGS="-D warnings" cargo doc --manifest-path tools/tui/Cargo.toml --no-deps --target "$HOST"
run "rustdoc (emu)"            env RUSTDOCFLAGS="-D warnings" cargo doc --manifest-path tools/emu/Cargo.toml --no-deps --target "$HOST"
# `--bins` is load-bearing: cargo-fuzz writes `doc = false` on all 53 targets, so
# a plain `cargo doc` here documents nothing, prints no `Documenting` line and
# exits 0 in 0.1 s — a green row over an empty set, the defect this block exists
# to prevent. The flag overrides `doc = false`; `--all-targets` is not a `doc` flag.
run "rustdoc (fuzz)"           env RUSTDOCFLAGS="-D warnings" cargo doc --manifest-path fuzz/Cargo.toml --bins --no-deps --target "$HOST"
run_tests "test (host)"              cargo test --workspace --exclude firmware --exclude rsk-wipe --target "$HOST"
# The PQC-advertisement opt-in changes the getInfo shape — test both forms.
run_tests "test (advertise-pqc)"     cargo test -p rsk-fido --features advertise-pqc --target "$HOST" getinfo
# fido-conformance suppresses the default EdDSA (-8) advertisement (the
# shipping/default build advertises -8; this drops it for the tool) and implies
# `strict-up`, which drops the U2F don't-enforce control byte. Run the WHOLE suite,
# not a name filter: the build for this permutation happens either way, so the extra
# cost is seconds, and a `getinfo`-only filter left a stale U2F expectation failing
# here unnoticed. This is also the only gate coverage `strict-up` gets.
run_tests "test (fido-conformance)"  cargo test -p rsk-fido --features fido-conformance --target "$HOST"
# The FIPS-style profile changes algorithm menus / PIN floor / export policy;
# run its tests (name-filtered: the regular fixtures assume the 4-char PIN
# floor) and type-check the locked firmware image.
run_tests "test (fips: rsk-fido)"    cargo test -p rsk-fido --features fips-profile --target "$HOST" fips
run_tests "test (fips: rsk-piv)"     cargo test -p rsk-piv --features fips-profile --target "$HOST" fips
run "clippy (fips firmware)"   cargo clippy -p firmware --features fips-profile -- -D warnings
# `strong-pin` raises the same 6-code-point floor and adds a trivial-PIN block, so it
# reuses the fips name-filter dodge (regular fixtures assume the 4-char floor).
run_tests "test (strong-pin)"        cargo test -p rsk-fido --features strong-pin --target "$HOST" strong_pin
run "clippy (strong-pin fw)"   cargo clippy -p firmware --features strong-pin -- -D warnings
# `strict-config` restores today's strict admin-write authorization (the DEFAULT
# build is the permissive full-YubiKey-compat surface). The default path is what
# every run above lints/tests; gate the strict path explicitly or it rots.
run "clippy (strict-config fw)"  cargo clippy -p firmware --features strict-config -- -D warnings
run "clippy (strict-config host)" cargo clippy -p rsk-mgmt -p rsk-otp -p rsk-fido -p rsk-vendor -p rsk-device --features strict-config --target "$HOST" --all-targets -- -D warnings
run_tests "test (strict-config)"       cargo test -p rsk-mgmt -p rsk-otp -p rsk-fido -p rsk-vendor -p rsk-device --features strict-config --target "$HOST"
# `largeblob-ext` swaps the CTAP 2.1 large-blob design for the CTAP 2.3 extension
# (§12.4 forbids serving both). Unlike the profiles above this one runs the WHOLE
# suite: the tests that describe the withdrawn design are cfg'd out, everything
# else — canonical getInfo included — must hold in either build, and a bare
# name-filter would have hidden exactly the fallout this swap can cause.
run "clippy (largeblob-ext fw)"   cargo clippy -p firmware --features largeblob-ext -- -D warnings
run "clippy (largeblob-ext host)" cargo clippy -p rsk-fido --features largeblob-ext --target "$HOST" --all-targets -- -D warnings
run_tests "test (largeblob-ext)"        cargo test -p rsk-fido --features largeblob-ext --target "$HOST"
run "clippy (emu largeblob-ext)"  cargo clippy --manifest-path tools/emu/Cargo.toml --target "$HOST" --all-targets --features largeblob-ext -- -D warnings
# The `bench` latency-harness vendor command (never shipped) is only compiled with
# its feature on, so gate that build here — otherwise a signature change to the EC /
# KDF hot paths it times would rot the bench module unseen (keep it compiling). The
# host test proves each selector still drives the REAL primitive, not an error path.
run "clippy (bench fw)"        cargo clippy -p firmware --features bench -- -D warnings
run "clippy (bench host)"      cargo clippy -p rsk-fido --features bench --target "$HOST" --all-targets -- -D warnings
run_tests "test (bench)"             cargo test -p rsk-fido --features bench --target "$HOST" bench
# Same reason for core1's counter read (INS 0x12): gated out of every build above,
# so nothing would notice `core1::stats` rotting against the atomics it packs.
run "clippy (core1-stats fw)"  cargo clippy -p firmware --features core1-stats -- -D warnings
# The display path (panel driver + touch) is `LED_KIND=none`-only, so the default
# embedded clippy above never lints it — gate it explicitly, like the fips firmware.
run "clippy (display firmware)" env LED_KIND=none cargo clippy -p firmware --features display -- -D warnings
# The trusted-display PIN pad's trivial-PIN reject is display+strong-pin-gated, so the
# plain display clippy above never compiles it — lint the combination explicitly.
run "clippy (display strong-pin)" env LED_KIND=none cargo clippy -p firmware --features display,strong-pin -- -D warnings
# The `display` feature of the WIRING adds the CCID secure-PIN gate
# (`pin_ref_ready`) and the chaining reset the on-pad VERIFY needs. Neither is
# compiled by any run above, and the gate is the one that decides whether the
# trusted display is painted for a credential the host has not addressed — it had
# no gate at all until audit run-36, so it does not go back to having no test.
run_tests "test (display wiring)"    cargo test -p rsk-device --features display --target "$HOST"
run "clippy (display wiring)"  cargo clippy -p rsk-device --features display --target "$HOST" --all-targets -- -D warnings
run "build firmware (release)" cargo build --release -p firmware
run "assurance-trace image identity" assurance_trace_is_image_neutral
run "firmware size budget"     firmware_size_budget
run "firmware stack floor"     firmware_stack_floor
run "no debug vendor command in the image" debug_vendor_commands_absent
run "partition table fences the store" partition_table_fences_the_store
run "sealed image retires its unsigned IMAGE_DEF" release_image_retires_its_unsigned_image_def
# The 16 MB geometry is the one that broke: the store used to end at the top of
# the XIP window, where the bootrom's RP2350-E10 absolute block lives, and
# `picotool partition create` refuses a table claiming it — a build the release
# makes (display, 16mb) and the 4 MB gate above never exercised.
run "build firmware (16M)"     env FLASH_SIZE=16M cargo build --release -p firmware
run "partition table fences the store (16M)" partition_table_fences_the_store
# The trusted-display flavor must keep building from the same tree. Built
# `LED_KIND=none` (the panel replaces the addressable LED and its backlight uses
# GPIO16 — the compile_error guard in main.rs enforces this), and before the
# no-touch build below, which stays the last `-p firmware` build so target/ keeps
# the no-touch test image (see docs/build.md).
run "build firmware (display)" env LED_KIND=none cargo build --release -p firmware --features display
# Machine-checked "no size cost for keys without a screen": the display UI crate
# and its driver stack must be absent from the DEFAULT firmware dependency tree, so
# a standard key can not pull any of the screen code in.
run "display code absent from default image" sh -c '
  if ! out=$(cargo tree -p firmware -e normal 2>&1); then echo "$out"; exit 1; fi
  if printf "%s\n" "$out" | grep -qE "rsk-ui|rsk-bip39|rsk-slip39|mipidsi"; then
    echo "FAIL: display code (rsk-ui/rsk-bip39/rsk-slip39/mipidsi) leaked into the default (no-display) firmware image"; exit 1
  fi'
# The test build: no BOOTSEL presence, so the automated suites don't hang on a touch.
run "build firmware (test, --features no-touch)" cargo build --release -p firmware --features no-touch
# rsk-wipe bakes its erase length AND its LED wiring in at build time, and it is
# the signed recovery hatch: build it for every board, so a change that stops
# `BOARD` reaching it (which once left a 16 MB board's whole KV store intact behind
# a "successful" wipe) fails here rather than in the field.
for board in firmware/boards/*.toml; do
  b=$(basename "$board" .toml)
  run "build rsk-wipe ($b)" env BOARD="$b" cargo build --release -p rsk-wipe
done
# …and the step above only means something because a build that names NO board
# refuses to link. It used to fall back to 4 MB and exit 0, so the gate passed
# whether or not `BOARD` was reaching the wiper at all (audit run-34 #30/#31).
run "rsk-wipe refuses an unknown flash size" sh -c '
  if out=$(env -u BOARD -u FLASH_SIZE cargo build --release -p rsk-wipe 2>&1); then
    echo "FAIL: rsk-wipe linked without BOARD or FLASH_SIZE — it guessed its erase length"; exit 1
  fi
  printf "%s\n" "$out" | grep -q "needs the target flash size" || {
    echo "FAIL: rsk-wipe failed for the wrong reason:"; printf "%s\n" "$out" | tail -5; exit 1
  }'
run "flake.lock in sync"       lock_in_sync
run "one embassy for all"      embassy_revs_match
# No `--ignore`: the tree carries no vulnerability advisory. RUSTSEC-2023-0071
# (the `rsa` crate, no fixed release) was the last one and left with the crate.
run "cargo-audit (SCA)"        cargo audit
run "cargo-audit (tui SCA)"    cargo audit --file tools/tui/Cargo.lock
# The emulator's own host tests — today the USB/IP codec, whose struct layouts are
# the Linux kernel's and whose framing rule decides how many bytes come off the
# socket next; both fail silently on the wire rather than loudly.
run_tests "test (emu)"               cargo test --manifest-path tools/emu/Cargo.toml --target "$HOST"
run_tests "test (emu security trace)" cargo test --manifest-path tools/emu/Cargo.toml --target "$HOST" --features security-trace
run_tests "test (emu conformance)"   cargo test --manifest-path tools/emu/Cargo.toml --target "$HOST" --features fido-conformance
run "cargo-audit (emu SCA)"    cargo audit --file tools/emu/Cargo.lock
# Also the crate-tier rule (deny.toml `[bans] deny`): an applet may not name
# another applet, and a crypto backend may only be named by the facade.
# `-D unused-wrapper` is what keeps that allowlist honest — without it a wrapper
# name whose edge is gone stays in the file as decoration and nothing says so.
run "cargo-deny"               cargo deny check -D unused-wrapper
# Supply-chain provenance-of-review: every dependency must be covered by an
# imported audit (mozilla/google/isrg/zcash) or a recorded exemption. Fails when
# a new, unreviewed crate enters the tree. --locked uses the committed
# supply-chain/imports.lock (offline, no fetch). See docs/supply-chain.md.
run "cargo-vet (supply-chain)" cargo vet --locked
# The device-wide wipe's phase-2 set is a hand-maintained union across four crates
# and nothing in the type system notices a missing arm. OATH's was absent for a
# release (audit run-36); this is the check that would have caught it.
run "gate-union (device wipe)" python scripts/gate_union.py
# CI skips jobs on these rules, and a wrong one skips a job silently — the one
# failure direction nothing else would report.
run "ci scope rules"           ./scripts/ci-scope.sh --self-test
# Deep-checks runs this nightly, which is where it kept being discovered — twice
# now the tree went red for a hotspot that had been sitting in a commit for hours.
# It costs ~7 s and needs nothing the shell has not already fetched.
run "complexity ratchet"       ./scripts/complexity_gate.sh
run "ci knob groups"           ./scripts/ci-knobs.sh --self-test
# The Kani proofs run nightly, but their roster is a hand-written `-p` list and a
# crate absent from it is simply not proven — `rsk-ui` and `rsk-led` never were,
# under a row named "prove every harness". Checking the roster is a grep, so it
# belongs here, where the harness gets written; the solver stays nightly.
run "kani roster"              python scripts/kani_gate.py
# Same failure one file closer to home, and the reason the host rows above say
# `--workspace --exclude firmware --exclude rsk-wipe` rather than naming crates:
# the list they used to name was written out nine times over four files and had
# rotted to 16 of 24 in the docs, 20 on the nightly coverage row, 12 in the
# flake. This holds every copy of that selection to the tree.
run "crate roster"             python scripts/roster_gate.py
# The crate-layer drawing was hand-kept under a footer claiming the manifests
# were its source: it named 17 of 28 crates, so 57 of the 100 edges had an
# endpoint it could not draw, and it showed seven applets against eight. It is
# emitted from the manifests now, and this row notices when it drifts.
run "crate graph"              python scripts/crate_graph.py --check
# Three conventions AGENTS.md states and nothing enforced: the `bcdDevice` bump
# (skipped three times in two days), the CHANGELOG entry that owes it, and the
# SPDX header on every source file. Ported from Wasefire's `ci-changelog.sh` and
# `ci-copyright.sh` — their trick is that an artifact is stale when the sources
# moved after it last did. The fourth is the same shape one layer out: the TLA+
# model's ~175 `file.rs:line` citations were checked once, by hand, and a model
# pointing at a line that has moved reads as authoritative while being wrong.
run "bcd bump + CHANGELOG"     python scripts/bcd_gate.py
run "SPDX headers"             python scripts/spdx_gate.py
run "formal citations"         python scripts/citation_gate.py
run "assurance registry"       python scripts/assurance_gate.py
# A model constant that stands for a fact about the world, not a defect switch.
# `PowerOnClearsScratch2` was TRUE in all seven Boot configurations and read by
# no action: deleting its `ASSUME` left every run bit-identical.
run "standing assumptions"     python scripts/assumption_gate.py
# `floors.txt` catches a run that got smaller; this catches one whose
# CONSTANTS are too small to express the defect its own mutants rebuild.
# Two of the twenty-five module mutants go GREEN one element down.
run "formal scopes"            python scripts/scope_gate.py
run "comutants lint"           python scripts/comutate.py --lint
run "seam trace map"           python scripts/trace_map.py
run "security trace refinement" python scripts/security_trace.py --check-data formal/TraceSecurityData.tla formal/traces/security-phase4.jsonl
run "token refinement export" ./scripts/token_refinement.sh --check
run "token refinement completeness" python scripts/token_refinement_gate.py
# The two guards above decide whether the gate covers the tree, and neither had
# a single test while five commits rewrote them by hand. This is that hand
# battery kept: a fixture workspace, one mutation per case, both directions.
run "pytest (gate scripts)"    python -m pytest scripts -q
run "docs constants match code" python scripts/docs_constants.py
run "pytest (tools/rsk)"       python -m pytest tools/rsk -q
# The interop allow-list is the only thing that tells an expected RS-Key/YubiKey
# divergence from a fidelity gap, and it goes stale silently — a firmware change
# moved maxSerializedLargeBlobArray and nobody noticed until the next two-key run.
run "pytest (tests/interop)"   python -m pytest tests/interop -q
run "gitleaks (tree)"          gitleaks detect --redact --no-banner

echo
echo "ALL CHECKS PASSED"
