#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Full quality + security suite: formatting, lint, tests, no_std build, SCA, secrets.
# Run locally or in CI. Host target defaults to macOS arm64 (override with HOST_TARGET).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-aarch64-apple-darwin}"

# Five rows below allocate a temp, and this was the one script in scripts/ with
# no cleanup: ~10 GB of build trees per run, until a full volume took the machine
# down mid-gate. Bash keeps exactly ONE EXIT trap, so the neighbours' per-site
# `trap 'rm -rf "$tmp"' EXIT` cannot simply be repeated here — the second call
# silently replaces the first. Register the paths instead; remove the lot once.
#
# The `if` is what protects the verdict, not the `return 0`. Measured on bash
# 5.3: a handler whose `rm` fails exits a GREEN run 1 and flattens `exit 7` to 1,
# and a trailing `return 0` does NOT save it — errexit leaves the function at the
# failing `rm` and never reaches it. In an `if` condition `rm` is exempt, so the
# failure is reported and the run's own status survives it.
#
# Register in the shell that made the temp. A `GATE_TMP+=` inside a command
# substitution appends to a subshell's copy and is lost, so a helper returning a
# path cannot do the registering for you — the two lines stay at the site.
GATE_TMP=()
gate_cleanup() {
  if [ "${#GATE_TMP[@]}" -gt 0 ] && ! rm -rf -- "${GATE_TMP[@]}"; then
    echo "warning: gate temporaries left behind: ${GATE_TMP[*]}" >&2
  fi
  return 0
}
trap gate_cleanup EXIT
# The EXIT trap already runs on a fatal signal here (measured), so these are for
# the verdict, not the cleanup: without the INT one, a SIGINT delivered to this
# script alone lets the interrupted run report rc 0.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The other temp this file makes, and the one with no `mktemp` in it: pytest's
# `tmp_path` lives under $TMPDIR, and `nix develop` hands every invocation a
# FRESH /tmp/nix-shell.XXXXXX it never removes — so pytest's own "keep the last
# three runs" retention never meets a previous run, and every gate leaves its
# scratch behind for good. 361 orphaned bases and 8.9 GB in one day; 351 MB of
# that per run is the gate-scripts row, spread over ~1400 directories with no
# fat one to slim. Same volume-to-zero as the mktemp sites above.
#
# A pinned --basetemp is removed and recreated by pytest at startup, so a row
# holds one run instead of every run. It must not be inside the checkout: under
# `target/`, `git rev-parse` answers from RS-Key's own .git and test_verdict_gate's
# "git cannot answer here" case goes red (measured, 1788 of 1789). pytest makes the
# leaf, not its parents. It wipes what it is pointed at, so each row gets a leaf
# and each checkout a base: one per user let one worktree's gate wipe another's.
GATE_PYTEST_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest/$(git rev-parse --show-toplevel | git hash-object --stdin | cut -c1-12)"
mkdir -p "$GATE_PYTEST_TMP"
# A passing test's directory goes as it passes, a failing one's stays — the only
# kind anybody opens. 351 MB → 1 MB on the row above, which is what keeps a base
# in a cache directory nobody thinks to sweep from becoming a hoard.
GATE_PYTEST_KEEP=(-o tmp_path_retention_policy=failed)

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
  GATE_TMP+=("$log")
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

# The display flavor's floor. Two things share that stack and the linker can see
# neither: the same ML-DSA-65 keygen peak as above, and one retained display frame
# — `rsk_ui::scene::RETAINED_FRAME_STACK_BYTES`, 32 KiB, held there by a const
# assert over `size_of::<Scene>()` plus the DMA bands. 114 + 32 = 146 KiB if they
# ever nest, against the 171 KiB this build has.
#
# It needs its own row because the plain floor above CANNOT see the regression that
# matters here: the retained compositor deleted a 4 KiB static pixel buffer and put
# ~26 KiB on the stack instead, which moves `_stack_start - _stack_end` the RIGHT
# way while the peak grows. A shared row would have reported an improvement.
DISPLAY_STACK_FLOOR_KIB=168
display_stack_floor() {
  local elf="target/thumbv8m.main-none-eabihf/release/firmware"
  local top bot kib
  top=$(arm-none-eabi-nm "$elf" | awk '$3 == "_stack_start" { print $1 }')
  bot=$(arm-none-eabi-nm "$elf" | awk '$3 == "_stack_end" { print $1 }')
  kib=$(( (0x$top - 0x$bot) / 1024 ))
  echo "display stack ${kib} KiB / ${DISPLAY_STACK_FLOOR_KIB} KiB floor; ML-DSA-65 makeCredential near 114 KiB + a retained frame under 32 KiB"
  if [ "$kib" -lt "$DISPLAY_STACK_FLOOR_KIB" ]; then
    echo "FAIL: the display build has only ${kib} KiB of stack, under the ${DISPLAY_STACK_FLOOR_KIB} KiB floor." >&2
    echo "      It carries a retained frame on top of the crypto peak the default build has." >&2
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
  GATE_TMP+=("$dir")
  src="$dir/src"
  # `formal/states` too: TLC's on-disk state queues are gitignored run output, hold
  # no Rust, no manifest and nothing any `include_*!` reaches, so they cannot move
  # the ELF this row builds three times — and at ~6 GB they were the difference
  # between the row running and the whole gate dying on ENOSPC.
  rsync -a --exclude .git --exclude target --exclude result --exclude formal/out \
    --exclude formal/states ./ "$src/"

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
  # Eagerly, not only via the trap: this is the largest temp in the file (a source
  # copy plus three target dirs) and ~60 rows still run after it.
  rm -rf "$dir"
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
  local dir out line want got
  dir=$(mktemp -d)
  GATE_TMP+=("$dir")
  out="$dir/pt.elf"
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
  GATE_TMP+=("$dir")
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
  GATE_TMP+=("$manifest" "$log" "$empty")
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

# First because it is the cheapest row in the file (~0.2 s over every file) and
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
run "rustdoc (firmware all-feat)" env BOARD=waveshare-one LED_KIND=none RUSTDOCFLAGS="-D warnings" cargo doc -p firmware --no-deps --features display,no-touch,advertise-pqc,fips-profile,strong-pin,keygen-bench,core1-stats,bench,fido-conformance,ea-conformance-rpid,strict-up,always-uv,largeblob-ext,strict-config
# `display-keys` (screen + button) is mutually exclusive with `display` (screen +
# touch): both claim the same panel/PIO on a real board, so all-features cannot
# cover both. Document the touchless build on its own permutation instead.
run "rustdoc (firmware keys)"   env BOARD=waveshare-geek LED_KIND=none RUSTDOCFLAGS="-D warnings" cargo doc -p firmware --no-deps --features display-keys
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
# run its tests and type-check the locked firmware image. The WHOLE suite, as for
# fido-conformance above: the name filter these rows used to carry hid 63 failing
# rsk-fido cases and 6 rsk-piv ones for as long as the feature existed — the
# fixtures typed a PIN and provisioned a key size the profile refuses, so the
# shipped image's only coverage was the handful of cases named after it.
run_tests "test (fips: rsk-fido)"    cargo test -p rsk-fido --features fips-profile --target "$HOST"
run_tests "test (fips: rsk-piv)"     cargo test -p rsk-piv --features fips-profile --target "$HOST"
run "clippy (fips firmware)"   cargo clippy -p firmware --features fips-profile -- -D warnings
# `strong-pin` raises the same 6-code-point floor and adds a trivial-PIN block —
# same reasoning as fips above, and its own filter hid 61 failing cases.
run_tests "test (strong-pin)"        cargo test -p rsk-fido --features strong-pin --target "$HOST"
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
# The touchless screen + button form (the fork-adapted GEEK board): its own
# feature and board file, mutually exclusive with `display`.
run "clippy (display keys)" env BOARD=waveshare-geek LED_KIND=none cargo clippy -p firmware --features display-keys -- -D warnings
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
# Reads the image the row above just sealed, and it has to be HERE: the 16 MB,
# display and no-touch builds below overwrite this path, so the same row run with
# the Python gates would audit the no-touch binary and say nothing about the one
# that ships.
run "constant-time sites in the image" python scripts/ct_gate.py
# Same window and the same reason: segments, the memory map, the vector table
# and the allocator surface of the DEFAULT image, before the three builds below
# overwrite it with another profile's.
run "image segments and allocator" python scripts/elf_gate.py
# Third reader of the same window: 22 of the 47 owners assurance/token_refinement.toml
# names have NO symbol — they survive only as an inlined call site in this image's
# DWARF — and three MUST be absent from it. Which profile it reads is the DISPLAY
# build below, not the no-touch one: measured over both binaries, the no-touch
# image (sha cb1830ac…) gives all 47 dispositions and call-site counts of the
# default image (08dad541…) unchanged, so the earlier claim here that "both
# answers are profile-specific" was false in the direction it was written for.
# The display build at line ~600 is what moves them — 17 symbol / 21 inlined /
# 6 absent — and there this row FALSE-ALARMS: rsk-display links, its two
# clientpin.rs doors bind, and their `unlinked-crate` rows read as stale
# exemptions. Recorded rather than handled: the row's window is above that build,
# and those two absences are absences OF THE DEFAULT IMAGE.
run "registered owners in the shipped image" python scripts/owner_binding_gate.py
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
#
# `FLASH_SIZE=16M` because that is what the SHIPPED flavor is: `nix/firmware.nix`
# gives `firmware-display` `flashSize = "16M"` and `ledKind = "none"` together,
# and this row used to compile the display feature at the DEFAULT 4 MB geometry —
# a combination no published package is. The settling question on that matrix
# column says so in as many words. It does not make the `SEC-DISP-*` rows
# `covered`: this compiles the shipped image, and their EVIDENCE is still
# produced at 4 MB.
run "build firmware (display)" env LED_KIND=none FLASH_SIZE=16M cargo build --release -p firmware --features display
run "firmware stack floor (display)" display_stack_floor
# And the touchless screen + button form, so the second panel build cannot rot
# unnoticed; it stays before the no-touch build below, which owns target/.
run "build firmware (display keys)" env BOARD=waveshare-geek LED_KIND=none cargo build --release -p firmware --features display-keys
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
# The row above proves the lock is not STALE and nothing proves what it pins is
# in the TCB at all: `flip-link`, `rust-lld` and `arm-none-eabi-as` appeared in no
# registry, no gate and no page, and `cargo-kani` is in no nix file whatsoever —
# its only pin is an `env:` written three times, of which `kani_gate.py` reads
# one. This holds every tool's recorded pin against the file that pins it and
# prints the TCB into docs/supply-chain.md.
run "toolchain TCB registry"   python scripts/toolchain_gate.py
# The same question one register out. docs/verified-compilation.md DECIDES about
# that TCB — whether a kernel of this firmware should move to a language with a
# verified compiler — and every reason it gives is a number about this tree. A
# decision record whose numbers nothing re-derives is a decision that was true
# the day it was typed, which is what the registry above exists to prevent.
run "11C decision measurements" python scripts/level11c_gate.py
run "one embassy for all"      embassy_revs_match
# The same rule one library in, and the case `embassy_revs_match` names in its
# own comment: the vendored `sequential-storage` fork reaches a build only
# through `[patch.crates-io]`, wired in three manifests, so a workspace that
# lost its copy links upstream 8.0.0 — whose walk reports a page it could not
# read as a COMPLETE enumeration, and whose torn remove leaves an older copy
# live. The subject is the LOCK and not the stanza: a patched dependency is
# recorded with no `source` and no `checksum`, which is the half that cannot be
# talked round. Driven through THIS row, exit taken with no pipe: each of the
# three stanzas deleted in turn -> rc 1 naming that manifest; a lock entry given
# a registry `source` -> rc 1 naming that lock. The table is
# scripts/test_vendored_fork_gate.py.
run "vendored fork linked"     python scripts/vendored_fork_gate.py
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
run "preview publisher"        node --test .github/scripts/publish-preview.test.mjs
# Deep-checks runs this nightly, which is where it kept being discovered — twice
# now the tree went red for a hotspot that had been sitting in a commit for hours.
# It costs ~7 s and needs nothing the shell has not already fetched.
run "complexity ratchet"       ./scripts/complexity_gate.sh
run "ci knob groups"           ./scripts/ci-knobs.sh --self-test
# The reproduction runner an external reviewer is handed. Its own phase list is
# the thing that rots: a new evidence runner, a new weekly job or a gate row that
# starts needing something a clean checkout has not got would leave the script
# claiming to reproduce a tree it no longer describes. `--self-test` holds all
# three against the tree, and this row is what drives it -- the same shape as the
# two rows above, and the reason they are rows rather than comments.
run "reproduction runner"      ./scripts/reproduce.sh --self-test
# The Kani proofs run nightly, but their roster is a hand-written `-p` list and a
# crate absent from it is simply not proven — `rsk-ui` and `rsk-led` never were,
# under a row named "prove every harness". Checking the roster is a grep, so it
# belongs here, where the harness gets written; the solver stays nightly.
run "kani roster"              python scripts/kani_gate.py
# The other half of that roster: production source that means something different
# under the model checker, so every proof over it says less than its name. The
# page enumerating those shrinks was hand-kept and rotted twice — "the tree's only
# one" while there were three, then "one of four" while there were five — so the
# set is derived from the crates now, in both directions.
run "kani shrink roster"       python scripts/shrink_gate.py
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
# The panel links committed coverage tables, not the host fonts. Rebuild them
# from the Nix-pinned IBM Plex files and fail if the checked-in copy drifted.
run "IBM Plex font data"       python scripts/generate_ui_fonts.py --check
# Three conventions AGENTS.md states and nothing enforced: the `bcdDevice` bump
# (skipped three times in two days), the CHANGELOG entry that owes it, and the
# SPDX header on every source file. Ported from Wasefire's `ci-changelog.sh` and
# `ci-copyright.sh` — their trick is that an artifact is stale when the sources
# moved after it last did. The fourth is the same shape one layer out: the TLA+
# model's ~175 `file.rs:line` citations were checked once, by hand, and a model
# pointing at a line that has moved reads as authoritative while being wrong.
run "bcd bump + CHANGELOG"     python scripts/bcd_gate.py
run "anti-rollback marker"     python scripts/rollback_marker_gate.py
run "SPDX headers"             python scripts/spdx_gate.py
# The same shape one sentence in: a docstring that spells how many bullets are
# under it, over a list that has since grown or shrunk. Three shipped that way --
# platform_gate said Seven over six, threat_gate Three over four, elf_gate Two
# over three -- each found by hand, each on a different day, and nothing held
# them. The count is the cheapest number in this tree to derive; the expensive
# part is not calling a correct docstring wrong, so the rule reads what the
# bullets SAY (comutate's Three families really do live on two bullets) and stays
# silent where no cardinal survives its clauses.
run "docstring list counts"    python scripts/docstring_count_gate.py
# 229 of the 230 configurations say "do not edit by hand" in their first line,
# and nothing made that true: deleting a whole mutant family left every row
# green, because run-tlc.sh lists families with `ls` so the tiers shrank with
# them. This regenerates into a temp tree and diffs.
run "generated TLC configs"    python scripts/config_gen_gate.py
run "formal citations"         python scripts/citation_gate.py
run "assurance registry"       python scripts/assurance_gate.py
# The registry above says WHAT is claimed; this says of WHICH IMAGE. `nix build`
# makes twenty-two, `largeblob-ext` swaps the CTAP surface with no flake package
# at all, and four no-touch builds remove the consent gate the authorization
# properties are about — so a claim proved on the default build was being
# asserted about twenty-one others by silence.
run "build-configuration matrix" python scripts/matrix_gate.py
# And of WHICH THREAT. The threat model is the root of every evidence chain here
# and was cited by the file name alone on 33 rows, which names no threat. This
# derives the page's clauses, holds each P0-family row to one of them, and makes
# a row with none say which of the two things that is.
run "threat-model traceability" python scripts/threat_gate.py
# Every caller of the delete family owes a disposition: allowed best-effort wipe,
# or a device reporting success over a secret still in flash. The audit that
# wrote them found `force_delete` hiding a faulted metadata drop on the reset
# path, behind a doc sentence that named the wrong caller as the only one.
run "delete-caller dispositions" python scripts/deleter_gate.py
# A dispatch holds four RefCells across the whole CBOR command and then calls the
# trusted display through them, so a `borrow_mut()` anywhere a host ceremony can
# reach is a BorrowMutError -- under `panic-halt`, a key that answers nothing
# until it is unplugged, from one unauthenticated command (issue #107). The
# comment that would have stopped it existed and said `fs`; the pad drew from
# `rng`. Cells derived from the dispatch, roots from the handle, reach by call
# walk. The table is scripts/test_display_borrow_gate.py, driven through THIS row.
run "display borrows vs dispatch" python scripts/display_borrow_gate.py
# The same question about RAM rather than flash, and it had no register at all.
# The threat model has always said key-grade material is wiped "at end of scope
# including error paths" and nothing held that sentence: 300 of the 444 wipes in
# the image sit below an early exit of their own function, and the one exit the
# clause never mentions is the one where nothing runs -- `panic-halt` spins with
# no unwinding, no Drop, every secret in the frame resident, and that was
# recorded nowhere. This derives the roster (wipes, `Zeroizing`, self-wiping
# types -- ELEVEN, not the two a ZeroizeOnDrop grep finds), derives the panic
# strategy and the reboot's own scrubs, and holds the register both ways.
# Driven through THIS row, exit taken with no pipe, 48 clauses x 2 arms: each
# defect -> rc 1 with the message naming THAT defect, and the same defect with
# that clause alone disabled -> rc 0, which is what makes each one load-bearing
# rather than decorative. An adversarial review then found nine ways past it,
# five overclaiming: `n/a` on an exit nothing derives it for (the master seed's
# row could answer "the error exit cannot happen here"), `explicit` on the reboot
# exit (escaping the wiper rule and the residual rule at once), a `wiper` row
# naming ANY of the five scrubs rather than its own, a register-wide residual
# discharging a per-row `not-wiped`, and `28 of its 22` in the prose. All five
# redden now. Two more were derivation holes: an inline `#[cfg(test)]` counted as
# shipped (the highest-value row read 37 where the image has 35) and a `return
# Sw::…` invisible as an early exit, which is how `rsk-piv/src/lib.rs` derived
# ZERO over eleven. The table is scripts/test_secrets_gate.py.
run "secret lifetimes"         python scripts/secrets_gate.py
# The same shape one crate over, and the finding that asked for it: the OTP use
# counter's own two files each stated a roster of its writers from memory and
# each was wrong. `counter.rs` said "both writers … take their step from here"
# and `counter_kani.rs` said four sites "are every writer of the first two tail
# bytes". There are eight — `cmd_swap` writes them twice per command and
# `migrate_seal` twice per boot, and neither sentence mentioned either. A proof
# whose scope is a sentence has no way to notice a ninth arriving; this derives
# the roster and the harness cites it. Driven through THIS row, exit taken with
# no pipe: a ninth writer in a new `crates/rsk-otp/src/*.rs` -> rc 1 naming that
# file and function; removed -> rc 0. An adversarial review then found four ways
# past it, three overclaiming: a BARE `seal_put(` (the receiver test), a grouped
# `use rsk_otp::{…, seal}`, a ledger entry certifying its own coverage through a
# `via` hop it never calls, and a same-named stepper in another file. All four
# redden now. A fifth was measured later and is the one every other clause was
# blind to by construction: they all read PRODUCTION code, so deleting both
# `#[kani::proof]`s from counter_kani.rs left this row at rc 0 still printing
# "2 functions take their step from counter.rs" over an empty proof. A rule the
# ledger's `proved` column is about must now be called by a harness in that file.
# The table is scripts/test_counter_writers_gate.py, 32 cases, three of them
# controls that must stay GREEN: twelve lines inserted above every site, a local
# renamed at one call site, and the harness itself renamed. The second is why the
# key is (file, fn, ordinal) — keyed on the call TEXT, a rename or a rustfmt
# reflow was a false red; the third says what this row does NOT measure, since
# assurance_gate.py forces BOUNDED from a harness NAME.
run "OTP counter writers"      python scripts/counter_writers_gate.py
# The same shape one crate down, and the set that has drifted twice already.
# `rsk_store::is_counter_fid` routes a record to the counter partition or the
# main one, and it is a `matches!` over four bare literals whose named homes are
# in rsk-fido, rsk-openpgp and rsk-vendor — so the table and the constants drift
# with no compile error. `EF_CRED_CTR` joined the table at 0x0821 after 0x081D
# had been writing it to main, and the `power_cut` mirror listed three of the
# four with a `& 7` selector over nine entries, so the counter FID could never be
# written by any input while the sweep asserted it absent on every one. A record
# on the wrong side reads absent while its old value stays live in the other
# ring, and every `for_each_key` yields a copy nothing can delete. The values are
# derived from the applet crates now and all four copies are held to them.
# Driven through THIS row, exit taken with no pipe: a literal changed in any one
# of the four -> rc 1 naming that copy and the direction; the constant renamed at
# its home -> rc 1 saying the name resolves nowhere. The table is
# scripts/test_partition_routing_gate.py.
run "partition routing"        python scripts/partition_routing_gate.py
# A model constant that stands for a fact about the world, not a defect switch.
# `PowerOnClearsScratch2` was TRUE in all seven Boot configurations and read by
# no action: deleting its `ASSUME` left every run bit-identical.
run "standing assumptions"     python scripts/assumption_gate.py
# And the assumptions no constant can carry, which the row above refuses by
# construction: a board question, a recorded PASS, emulator fidelity. Their
# candidates are DERIVED from five sources — the slice bundle's own ids said
# "registered: no" on eight of ten rows, and `assurance/crates.toml`'s `abstracts`
# is what anchors a store-backend row so deleting one is a diff — and so is how
# many are discharged: the row prints the live tally on a green run, because the
# copy typed here read "one of the eighteen" long after both numbers had moved.
run "platform assumptions"     python scripts/platform_gate.py
# `floors.txt` catches a run that got smaller; this catches one whose
# CONSTANTS are too small to express the defect its own mutants rebuild.
# Two of the twenty-five module mutants go GREEN one element down.
run "formal scopes"            python scripts/scope_gate.py
# The scope row is a `>=`, so `Cap = 3 -> 4` on the transport configuration
# clears it and no Rust file mentions Cap at all. This holds the four numbers
# the chunk-to-byte bridge is proved through against each other.
run "transport bridge"         python scripts/transport_bridge_gate.py
# And the abstractions no scope constant can express: the "Narrower than the
# firmware" roster, ten bullets on formal/README.md that NO script read — a
# whole one could be deleted at exit 0 on citation, claims, run-count, threat,
# evidence, scope, config-gen and comutants. The list is generated from
# assurance/abstractions.toml now, and each row's disposition is held to the
# artifact it rests on: a `closed` needs a mutant a tier runs and floors.txt
# requires RED, an `open-obligation` reddens when its question is settled.
run "narrow abstractions"      python scripts/narrow_gate.py
# And `floors.txt` itself, which only the weekly TLC matrix reads — so between
# two weeklies it could be weakened with every row here green. Measured: the two
# layers that did reach it name 2 of its 25 wildcard families, and flipping
# `SeamMut_*.cfg` from RED to GREEN passed all 98 rows. This one derives the
# verdict from each configuration's own CONSTANTS instead of trusting the column.
run "TLA verdict registry"     python scripts/verdict_gate.py
run "comutants lint"           python scripts/comutate.py --lint
run "seam trace map"           python scripts/trace_map.py
run "security trace refinement" python scripts/security_trace.py --check-data formal/TraceSecurityData.tla formal/traces/security-phase4.jsonl
# A `"Name" \notin viol` clause is only as strong as the set of actions that
# write the name, and this model named that set in a COMMENT that said eleven.
# It is 21, over 24 routes -- and three of them record TWICE, so a name-set
# equality stays green over a half-deleted guard. This derives both.
run "ghost completeness"       python scripts/ghost_gate.py
# And the other end of the same question: not what a ghost's writers are, but
# where a model deliberately stops being about the product. `RSKeyAppletSeams`
# hard-codes `\/ a = Oath` TWICE -- once to re-lock OATH on a re-SELECT, once to
# keep the conformance recorder quiet about it -- and deleting either changed the
# input of no gate. Nothing was a registry for that class: `git grep -i exempt
# scripts/` found only tier exclusions. This derives the narrowings out of the
# `.tla` (a narrowing operand, a set literal that omits what its sibling has, a
# CASE that answers for part of its domain) and holds them to
# assurance/model_exceptions.toml both ways -- an exception with no row, and a
# row whose clause the model no longer has. How many there are and how many still
# owe a mutant is DERIVED and printed on every green run; the ledger records the
# debt with the file that would pay it, and holds that the file is not there yet.
run "model exceptions"         python scripts/model_exception_gate.py
# The first closed slice's raw evidence, held to stage 1A's ten-group contract.
# Ten headings with one line each satisfy "all ten groups are present", so this
# counts LEAVES and floors them per group — and refuses a cost written as a
# range, which is an estimate wearing a measurement's field.
run "slice evidence bundle"    python scripts/bundle_gate.py
# And the registry's one word, split into the six questions it was mixing. The
# slice above moved SEC-FIDO-001 from one Kani harness to four and its `status`
# would have read the same with either, because the word derives from a harness
# NAME. This derives six axes apart, rebuilds the word from two of them, and
# writes the public page so a release sentence cannot outrun the axes.
run "evidence vector"          python scripts/evidence_gate.py
# And the bundles' OTHER half: the numbers each obligation was measured at. The
# row above floors them at 2 per method row and 24 per bundle -- on COUNT and
# TYPE, never on value -- while the scope table a reader actually reads was
# fourteen rows typed by hand into docs/authorization-slice.md that nothing read.
# Six mutations proved it: a docs bound moved while the bundle stood still, the
# bundle moved while the docs stood still, a row renamed after a constant that
# does not exist, a row deleted -- exit 0 on all eight gates. This writes all 295
# from assurance/bundle/*.toml and refuses a second table anywhere.
run "bundle bounds table"      python scripts/bounds_gate.py
# And what the pages SAY a run was. Seven were stale the day this row landed --
# `safety` published as 190 rows against a tier of 195, the model's state space
# at 63% of the measured count in the paragraph the docs call the one to quote,
# and five more between them -- because every one was typed. The sentences are
# written from `formal/runs.toml`, which holds the runner's own matrix per tier
# and TLC's own summary of the same run beside it, so no number in either has
# one source. A count typed in any tracked text file under docs/, formal/ or
# .github/, or on any page at the root, is a finding: by DIRECTORY, because the
# suffix whitelist this said before let a count into a new formal/*.md, a .tla
# comment, a .github/*.json, SECURITY.md and eighteen more, all driven at
# exit 0. `formal/runs.toml` itself and CHANGELOG.md are the two carve-outs.
run "published run-counts"     python scripts/run_count_gate.py
# And what the pages SAY a property IS. Stage 0 п.3 and the last exit of stage 4
# are one predicate -- a public claim about a registered id is generated, and one
# written by hand fails on a docs row -- and this file carried no docs row at all,
# so four false sentences including "`SEC-FIDO-001` ... PROVEN on hardware" in
# README.md were exit 0 on all eight gates. The CI step `docs.sh check` is
# `mdbook build` plus a link check and never reads a claim. Not "generated or
# refused", which would refuse true prose no table replaces: a hand-written
# status is held to the status the registry HOLDS for the id beside it, so
# `PROVEN` -- no row's status anywhere -- is refused of every id.
run "published claims"         python scripts/claims_gate.py
# And what the pages SAY a RELEASE RUNS. Same shape, one layer out: it was prose
# transcribed from a workflow nothing held it to -- "rebuilds all fourteen
# flavors", "builds every artifact reproducibly, hashes it, and signs the
# manifest" -- and that transcription has already rotted once, when the signature
# asset was renamed `.cosign.bundle` -> `.sigstore.json` and every published
# verify command went on naming a file that no longer exists. Every command,
# flavor, action pin and asset name is read out of release.yml, release-build.yml
# and nix/firmware.nix here and printed into docs/supply-chain.md. Two things it
# refuses that no other row can see: a rebuild loop covering thirteen of the
# fourteen images the build loop makes, so the fourteenth is signed and attested
# with nothing having compared its bytes; and an entry claiming `source->binary`
# off the reproducibility gate -- determinism is not semantic preservation, and
# PLAT-TOOLCHAIN-001 is the row that owns that gap. It binds to no tag and no
# artifact: that half needs a release, and the region says so.
run "release manifest"        python scripts/release_gate.py
run "token refinement export" ./scripts/token_refinement.sh --check
run "token refinement completeness" python scripts/token_refinement_gate.py
# The two guards above decide whether the gate covers the tree, and neither had
# a single test while five commits rewrote them by hand. This is that hand
# battery kept: a fixture workspace, one mutation per case, both directions.
run "pytest (gate scripts)"    python -m pytest scripts -q \
  --basetemp="$GATE_PYTEST_TMP/gate" "${GATE_PYTEST_KEEP[@]}"
run "docs constants match code" python scripts/docs_constants.py
run "pytest (tools/rsk)"       python -m pytest tools/rsk -q \
  --basetemp="$GATE_PYTEST_TMP/rsk" "${GATE_PYTEST_KEEP[@]}"
# The interop allow-list is the only thing that tells an expected RS-Key/YubiKey
# divergence from a fidelity gap, and it goes stale silently — a firmware change
# moved maxSerializedLargeBlobArray and nobody noticed until the next two-key run.
run "pytest (tests/interop)"   python -m pytest tests/interop -q \
  --basetemp="$GATE_PYTEST_TMP/interop" "${GATE_PYTEST_KEEP[@]}"
run "gitleaks (tree)"          gitleaks detect --redact --no-banner

echo
echo "ALL CHECKS PASSED"
