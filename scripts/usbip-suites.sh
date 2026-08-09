#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The other half of `emu-suites.sh`: the suites that need a real USB stack.
#
# `emu-suites.sh` runs everything the emulator can serve over a socket. These
# five (`02`, `61`, `65`, `73`, `77`) and the pico-fido conformance suite cannot
# be served that way — they read USB descriptors, or go through python-fido2's and
# pyscard's own transports, which want a device the kernel enumerated. So the
# emulator serves USB/IP here, and a Linux guest with `vhci_hcd` attaches it:
#
#   [ this host ]  rsk-emu --usbip  <--- TCP 3240 --->  [ VM ]  vhci_hcd -> /dev/hidraw*
#
# The emulator stays on THIS side. It is a TCP peer, not a device, so the guest
# needs nothing but a kernel — which keeps it a fixed appliance and keeps the
# emulator's build the same `cargo` one as everywhere else.
#
# Linux only: the guest is a QEMU VM built by `nix build .#usbip-vm`, and there is
# no `vhci_hcd` to attach to on macOS. Run it on Linux, or in a Linux VM — QEMU
# needs no KVM here (a GitHub-hosted runner has none), only patience.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST_TARGET="${HOST_TARGET:-x86_64-unknown-linux-gnu}"
EMU="tools/emu/target/$HOST_TARGET/release/rsk-emu"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

if [ "$(uname)" != "Linux" ]; then
  echo "usbip-suites: Linux only — the guest is a QEMU VM and macOS has no vhci_hcd" >&2
  exit 77
fi

echo "== building the emulator"
cargo build --release --manifest-path tools/emu/Cargo.toml --target "$HOST_TARGET"

echo "== building the guest"
nix build .#usbip-vm --no-link --print-out-paths >"$WORK/vm-path"
VM="$(cat "$WORK/vm-path")"

echo "== starting the emulators (USB/IP + the card socket the reset window needs)"
# Bound to every interface, not loopback: the guest reaches this host as a peer
# on QEMU's user network, so a 127.0.0.1 bind would be invisible to it.
#
# Two of them, on separate ports, because two suites need the Yubico identity and
# the rest must NOT have it (the default identity is the one whose CCID interface
# a stock driver skips — see `scripts/usbip-guest.sh`). Both at once rather than
# in sequence so the guest boots once: under TCG a boot costs more than a process.
start_emu() { # <tag> <fido port> <ccid port> <usbip port> [extra…]
  # stdin closed: `--touch` reads its confirmations from the terminal, and here
  # there is no operator — which is the point. `77` asserts that a touch-gated
  # challenge does not wedge the transport *during* the wait, so what it needs is
  # a device that waits and a press that never comes.
  "$EMU" --host 0.0.0.0 --fido-port "$2" --ccid-port "$3" --usbip "0.0.0.0:$4" \
    --store "$WORK/$1.store" "${@:5}" </dev/null >"$WORK/$1.log" 2>&1 &
  for _ in $(seq 50); do
    grep -q "device ready" "$WORK/$1.log" && return 0
    sleep 0.2
  done
  echo "FAIL: the $1 emulator did not come up" >&2
  cat "$WORK/$1.log" >&2
  exit 1
}
start_emu default 7799 7800 3240
start_emu yubico 7801 7802 3241 --yubico --touch

echo "== booting the guest (no KVM: this is software emulation, give it a minute)"
mkdir -p "$WORK/out"
# `$RSK_REPO` / `$RSK_OUT` are read by the VM's own run script when it expands the
# 9p shares — that indirection is what lets one built guest serve any checkout.
RSK_REPO="$PWD" RSK_OUT="$WORK/out" \
  "$VM"/bin/run-*-vm </dev/null 2>&1 | tee "$WORK/vm.log" || true

status="$(cat "$WORK/out/status" 2>/dev/null || echo "")"
if [ -z "$status" ]; then
  echo
  echo "FAIL: the guest never wrote a status — it did not reach the suites" >&2
  echo "--- the emulators' side" >&2
  tail -20 "$WORK/default.log" "$WORK/yubico.log" >&2
  exit 1
fi

echo
echo "guest exit: $status"
[ "$status" -eq 0 ] || {
  echo "--- the emulators' side"
  tail -20 "$WORK/default.log" "$WORK/yubico.log"
  exit 1
}
echo "USBIP SUITES PASSED"
