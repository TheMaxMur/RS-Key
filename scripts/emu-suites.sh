#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Every suite that needs no board, in one command — the on-device `tests/*.py`
# and the vendored OpenPGP conformance suite, all against `tools/emu`.
#
# One script so CI is a thin caller and the local run is the same thing, the way
# `check.sh` is for the gate. What is NOT here is the half that wants real USB
# (`02`, `61`, `65`, `73`, `77`, and pico-fido): those need a Linux host with
# `vhci_hcd` and `tools/emu --usbip`, and they get their own runner.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-aarch64-apple-darwin}"
EMU="tools/emu/target/$HOST/release/rsk-emu"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

pass=0
fail=0
skip=0
failed=()

# Start a fresh emulator on a fresh flash image and wait for it to be listening.
# A blank store per session is what keeps one suite's leftovers out of the next
# session's assertions.
start_emu() {
  "$EMU" --store "$WORK/$1.store" --security-trace "$WORK/$1.security.jsonl" \
    "${@:2}" >"$WORK/$1.log" 2>&1 &
  for _ in $(seq 50); do
    grep -q "device ready" "$WORK/$1.log" && return 0
    sleep 0.2
  done
  echo "FAIL: the emulator did not come up:" >&2
  cat "$WORK/$1.log" >&2
  exit 1
}

stop_emu() {
  kill %1 2>/dev/null || true
  wait %1 2>/dev/null || true
}

# Run one suite through the shim and bucket the result. Exit 77 is the suite
# refusing itself by name (`tests/emu.py`'s UNSUPPORTED), which is a skip and not
# a failure — that distinction is the whole reason the refusals are named.
run_suite() {
  local name
  name="$(basename "$1")"
  local rc=0
  python tests/emu.py "$@" >"$WORK/$name.out" 2>&1 || rc=$?
  case $rc in
    0) pass=$((pass + 1)) ;;
    77) skip=$((skip + 1)) ;;
    *)
      fail=$((fail + 1))
      failed+=("$name")
      echo "--- $name (exit $rc)"
      tail -20 "$WORK/$name.out"
      ;;
  esac
}

echo "== building the emulator"
cargo build --release --manifest-path tools/emu/Cargo.toml --target "$HOST" \
  --features security-trace

echo
echo "== on-device suites (socket transports)"
start_emu default
for t in tests/[0-9]*.py; do
  case "$(basename "$t")" in
    # Their own sessions below: `30` wants the Yubico card identity, and `28`/`76`
    # want a PIN already set. `16` wants one too and has no session of its own —
    # it exists for the recording, which runs it where `21` has just set it.
    30_* | 28_* | 76_* | 16_*) continue ;;
    *) run_suite "$t" ;;
  esac
done
stop_emu

# A bounded, security-dense slice of the real suite is replayed against the full
# RSKeySecurityState model. Other sessions are traced too, but this one owns the
# five coverage ratchets in formal/floors.txt.
#
# These three suites in ONE emulator lifetime are what those ratchets were
# measured on (formal/README.md, phase 4) — the replug between them is a recorded
# boundary, and it is the only way `PowerCut` is reached. Recording fewer misses
# the floors; keep this list and the committed trace moving together.
# An entry may carry its own arguments; `16` needs the PIN `21` has just set.
SECURITY_TRACE_SUITES=(
  21_pin_webauthn
  "16_always_uv_gate --pin 1234"
  20_clientpin
  27_reset_window
)

echo
echo "== formal security-state trace (${SECURITY_TRACE_SUITES[*]})"
start_emu security --auto-touch-ms 1
for suite in "${SECURITY_TRACE_SUITES[@]}"; do
  read -r name args <<<"$suite"
  # shellcheck disable=SC2086 -- `args` is a suite's own argument list, split on purpose
  python tests/emu.py "tests/$name.py" $args >"$WORK/security-$name.out" 2>&1 || {
    echo "FAIL: the security trace suite $name failed"
    cat "$WORK/security-$name.out"
    exit 1
  }
done
stop_emu
python scripts/security_trace.py "$WORK/security.security.jsonl"

# `28` and `76` need a PIN on the device, and `21_pin_webauthn` is what sets it.
# Their own session, because several suites in between reset the authenticator —
# running them in sweep order leaves them asking for a PIN that a factory reset
# took away three suites ago.
echo
echo "== on-device suites (with a PIN, set by 21)"
start_emu pinned
# Setup, not a result: `21` already ran and was counted in the sweep above.
python tests/emu.py tests/21_pin_webauthn.py >"$WORK/pin-setup.out" 2>&1 || {
  echo "FAIL: could not set the PIN 28/76 need"; cat "$WORK/pin-setup.out"; exit 1
}
for t in tests/28_*.py tests/76_*.py; do run_suite "$t" --pin 1234; done
stop_emu

echo
echo "== on-device suites (Yubico card identity)"
start_emu yubico --yubico
for t in tests/30_*.py; do run_suite "$t"; done
stop_emu

echo
echo "== third_party: the OpenPGP card conformance suite"
tp_note=""
tp=0
if [ "$(uname)" = "Darwin" ]; then
  # The Gnuk-derived suite reaches libgcrypt through cffi, and nix Python's
  # libffi aborts building a closure on macOS 26+ (`closures.c:258`) — the same
  # defect that breaks the `rsk` CLI there. Refused by name rather than run into
  # a SIGABRT that would read as a test result.
  tp_note="not run here — nix Python cffi aborts on macOS (libffi closures.c:258)"
else
  start_emu openpgp
  python tests/third_party.py openpgp -q || tp=$?
  stop_emu
  tp_note="pytest exit $tp"
fi

echo
echo "on-device: $pass passed, $fail failed, $skip refused by name"
if [ ${#failed[@]} -gt 0 ]; then
  printf 'failed: %s\n' "${failed[*]}"
fi
echo "third_party (openpgp): $tp_note"

[ "$fail" -eq 0 ] || exit 1
[ "$tp" -eq 0 ] || exit 1
echo
echo "EMULATOR SUITES PASSED"
