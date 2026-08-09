#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Full quality + security suite: formatting, lint, tests, no_std build, SCA, secrets.
# Run locally or in CI. Host target defaults to macOS arm64 (override with HOST_TARGET).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-aarch64-apple-darwin}"

run() { echo; echo "== $1 =="; shift; "$@"; }

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

run "fmt"                      cargo fmt --all --check
# `BOARD` because `rsk-wipe`'s build script refuses to guess a flash size (see
# the rsk-wipe steps below); `waveshare-one` is the reference board, whose
# values are the same defaults every other knob falls back to.
run "clippy (embedded)"        env BOARD=waveshare-one cargo clippy --workspace -- -D warnings
run "clippy (host tests)"      cargo clippy -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-sha512 -p rsk-ec -p rsk-mldsa -p rsk-mgmt -p rsk-oath -p rsk-otp -p rsk-piv -p rsk-rescue -p rsk-vendor -p rsk-device -p rsk-display -p rsk-store -p rsk-led -p rsk-ui -p rsk-bip39 -p rsk-slip39 -p rsk-bench --target "$HOST" --all-targets -- -D warnings
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
run "test (tui)"               cargo test --manifest-path tools/tui/Cargo.toml --target "$HOST"
# tools/emu is the third host-only workspace (the software emulator) — same
# reason it is gated here: nothing in the --workspace runs above can see it, and
# an emulator that stops compiling is found when someone tries to run the
# protocol suites without a board, which is exactly when they have no board.
run "fmt (emu)"                cargo fmt --manifest-path tools/emu/Cargo.toml --check
run "clippy (emu)"             cargo clippy --manifest-path tools/emu/Cargo.toml --target "$HOST" --all-targets -- -D warnings
# fuzz/ is also its own (nightly) workspace. rustfmt needs no toolchain, so the
# stable gate can format-check it here; building/clippy stay in the .#fuzz shell
# (deep-checks CI). Format fuzz/ with this same stable rustfmt — not the .#fuzz
# nightly one, which lays imports out differently.
run "fmt (fuzz)"               cargo fmt --manifest-path fuzz/Cargo.toml --check
# The fuzz targets call into the applet crates, so a crate signature change can
# leave a target uncompilable — but the full `cargo fuzz build` only runs weekly
# in .#fuzz, so that drift used to surface days later (it did: a `new()` arity
# change silently broke three targets). A plain `cargo check` on the HOST target
# (the fuzz workspace inherits the thumbv8m default, so `--target` is required)
# typechecks every target's calls now, on stable, in the gate — no nightly, no
# sanitizer build. The instrumented `cargo fuzz build` + run stays in deep-checks.
# `--tests` also covers tests/miri.rs, which mirrors the same constructors (its
# drift went unseen for a wave of unpushed commits until a local miri run).
run "check (fuzz)"             cargo check --manifest-path fuzz/Cargo.toml --tests --target "$HOST"
run "test (host)"              cargo test -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-sha512 -p rsk-ec -p rsk-mldsa -p rsk-mgmt -p rsk-oath -p rsk-otp -p rsk-piv -p rsk-rescue -p rsk-vendor -p rsk-device -p rsk-display -p rsk-store -p rsk-led -p rsk-ui -p rsk-bip39 -p rsk-slip39 -p rsk-bench --target "$HOST"
# The PQC-advertisement opt-in changes the getInfo shape — test both forms.
run "test (advertise-pqc)"     cargo test -p rsk-fido --features advertise-pqc --target "$HOST" getinfo
# fido-conformance suppresses the default EdDSA (-8) advertisement (the
# shipping/default build advertises -8; this drops it for the tool) and implies
# `strict-up`, which drops the U2F don't-enforce control byte. Run the WHOLE suite,
# not a name filter: the build for this permutation happens either way, so the extra
# cost is seconds, and a `getinfo`-only filter left a stale U2F expectation failing
# here unnoticed. This is also the only gate coverage `strict-up` gets.
run "test (fido-conformance)"  cargo test -p rsk-fido --features fido-conformance --target "$HOST"
# The FIPS-style profile changes algorithm menus / PIN floor / export policy;
# run its tests (name-filtered: the regular fixtures assume the 4-char PIN
# floor) and type-check the locked firmware image.
run "test (fips: rsk-fido)"    cargo test -p rsk-fido --features fips-profile --target "$HOST" fips
run "test (fips: rsk-piv)"     cargo test -p rsk-piv --features fips-profile --target "$HOST" fips
run "clippy (fips firmware)"   cargo clippy -p firmware --features fips-profile -- -D warnings
# `strong-pin` raises the same 6-code-point floor and adds a trivial-PIN block, so it
# reuses the fips name-filter dodge (regular fixtures assume the 4-char floor).
run "test (strong-pin)"        cargo test -p rsk-fido --features strong-pin --target "$HOST" strong_pin
run "clippy (strong-pin fw)"   cargo clippy -p firmware --features strong-pin -- -D warnings
# `strict-config` restores today's strict admin-write authorization (the DEFAULT
# build is the permissive full-YubiKey-compat surface). The default path is what
# every run above lints/tests; gate the strict path explicitly or it rots.
run "clippy (strict-config fw)"  cargo clippy -p firmware --features strict-config -- -D warnings
run "clippy (strict-config host)" cargo clippy -p rsk-mgmt -p rsk-otp -p rsk-fido -p rsk-vendor -p rsk-device --features strict-config --target "$HOST" --all-targets -- -D warnings
run "test (strict-config)"       cargo test -p rsk-mgmt -p rsk-otp -p rsk-fido -p rsk-vendor -p rsk-device --features strict-config --target "$HOST"
# The `bench` latency-harness vendor command (never shipped) is only compiled with
# its feature on, so gate that build here — otherwise a signature change to the EC /
# KDF hot paths it times would rot the bench module unseen (keep it compiling). The
# host test proves each selector still drives the REAL primitive, not an error path.
run "clippy (bench fw)"        cargo clippy -p firmware --features bench -- -D warnings
run "clippy (bench host)"      cargo clippy -p rsk-fido --features bench --target "$HOST" --all-targets -- -D warnings
run "test (bench)"             cargo test -p rsk-fido --features bench --target "$HOST" bench
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
run "test (display wiring)"    cargo test -p rsk-device --features display --target "$HOST"
run "clippy (display wiring)"  cargo clippy -p rsk-device --features display --target "$HOST" --all-targets -- -D warnings
run "build firmware (release)" cargo build --release -p firmware
run "firmware size budget"     firmware_size_budget
run "firmware stack floor"     firmware_stack_floor
run "partition table fences the store" partition_table_fences_the_store
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
# RUSTSEC-2023-0071: rsa Marvin timing side-channel — no fixed release; it is the
# OpenPGP RSA backend, mitigated by blinding. Justification in deny.toml.
run "cargo-audit (SCA)"        cargo audit --ignore RUSTSEC-2023-0071
run "cargo-audit (tui SCA)"    cargo audit --file tools/tui/Cargo.lock
# Same RUSTSEC-2023-0071 carve-out as the workspace run above: the emulator pulls
# the OpenPGP applet, and with it `rsa`.
# The emulator's own host tests — today the USB/IP codec, whose struct layouts are
# the Linux kernel's and whose framing rule decides how many bytes come off the
# socket next; both fail silently on the wire rather than loudly.
run "test (emu)"               cargo test --manifest-path tools/emu/Cargo.toml --target "$HOST"
run "cargo-audit (emu SCA)"    cargo audit --file tools/emu/Cargo.lock --ignore RUSTSEC-2023-0071
run "cargo-deny"               cargo deny check
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
run "docs constants match code" python scripts/docs_constants.py
run "pytest (tools/rsk)"       python -m pytest tools/rsk -q
# The interop allow-list is the only thing that tells an expected RS-Key/YubiKey
# divergence from a fidelity gap, and it goes stale silently — a firmware change
# moved maxSerializedLargeBlobArray and nobody noticed until the next two-key run.
run "pytest (tests/interop)"   python -m pytest tests/interop -q
run "gitleaks (tree)"          gitleaks detect --redact --no-banner

echo
echo "ALL CHECKS PASSED"
