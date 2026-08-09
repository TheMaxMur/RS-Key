#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The guest half of the USB-stack suites — see `scripts/usbip-suites.sh`, which
# is what you run. This runs INSIDE the VM `nix/usbip-vm.nix` builds, with the
# emulators already listening on the VM host (`10.0.2.2` under QEMU's user-mode
# networking).
#
# It lives in the repo rather than inside the VM's Nix closure on purpose: the
# suite list and the attach sequence are the part that changes, and a change here
# must not mean rebuilding a virtual machine.
#
# Two identities, because two suites need one the others must not have. `73`
# drives ykman's own `OtpConnection`, which binds Yubico USB ids and nothing else,
# and `77` needs a slot ykman armed with `--touch`. The rest must run on the
# DEFAULT identity — that is the one whose CCID interface a stock driver skips,
# the whole reason `nix/ccid.nix` exists. So the host runs both emulators at once
# on separate ports and the guest attaches one at a time; `emu-suites.sh` splits
# the same way, with sessions instead of ports.
set -uo pipefail
cd /repo

HOST=10.0.2.2
PORT_DEFAULT=3240
PORT_YUBICO=3241

pass=0
fail=0
failed=()

run() {
  local name
  name="$(basename "$1" .py)"
  echo "::: $name"
  if timeout 900 python "$@"; then
    pass=$((pass + 1))
  else
    local rc=$?
    fail=$((fail + 1))
    failed+=("$name(exit $rc)")
  fi
}

# Every hidraw node's product string, one per line.
#
# NOT a count of `/dev/hidraw*`, and not `hidraw0` in particular: QEMU gives the
# guest its own emulated USB keyboard and tablet, so those nodes exist before
# anything is attached and never go away. Waiting on them is a wait that always
# succeeds, which is how this scaffolding managed to assert nothing at all while
# the suites — which find the device themselves, by USB id and usage page — kept
# passing beside it.
hid_names() {
  sed -n 's/^HID_NAME=//p' /sys/class/hidraw/*/device/uevent 2>/dev/null
}

attach() { # <tcp port> <ccid port> <expected product-string fragment>
  # `boot.kernelModules` loads vhci_hcd, but usbip talks to it through sysfs and
  # the first call can land before that appears — which reads as "is vhci_hcd
  # loaded?" on a module that is.
  for _ in $(seq 60); do
    [ -d /sys/devices/platform/vhci_hcd.0 ] && break
    sleep 0.5
  done
  # `--tcp-port` is a global option, before the subcommand — `attach` itself takes
  # only the remote and the busid.
  usbip --tcp-port="$1" attach -r "$HOST" -b rsk-emu || { echo "FAIL: attach on $1"; return 1; }
  # The kernel enumerates asynchronously, so wait for the device — by name, which
  # also settles WHICH one it is. The two phases differ only by identity, and a
  # detach the kernel has not finished would leave the previous one in place: the
  # suites would run against the wrong emulator and the log would read the same.
  for _ in $(seq 120); do
    hid_names | grep -qF "$3" && break
    sleep 0.5
  done
  if ! hid_names | grep -qF "$3"; then
    echo "FAIL: '$3' never appeared after attaching :$1 — saw:"
    hid_names | sed 's/^/      /'
    usbip port
    return 1
  fi
  export RSK_EMU_CCID="$HOST:$2"
  echo "attached :$1 — $(hid_names | grep -cF "$3") node(s) of '$3'"
}

detach() { # <the product-string fragment that must go away>
  usbip detach -p 0 2>/dev/null || true
  for _ in $(seq 60); do
    hid_names | grep -qF "$1" || return 0
    sleep 0.5
  done
  echo "FAIL: '$1' is still enumerated after detach — the next phase would run"
  echo "      against the identity this one just finished with"
  return 1
}

echo "== phase 1: the default identity"
# The default identity's product string; the Yubico one below must differ,
# which is the whole point of asserting it.
attach "$PORT_DEFAULT" 7800 "RS-Key Security Key" || exit 1
# The CTAP 2.1 §6.6 reset window runs from the attach, and several suites reset.
# Let it lapse so they exercise `replug.py`'s power-cycle stand-in rather than
# happening to land inside the initial window — which once made a whole run look
# green for the wrong reason.
sleep 12

# `02` reads the descriptors and the interface ORDER — the issue #55 class, and
# the one thing no socket shim can check. `61`/`65` go through python-fido2's own
# HID transport, so faking it would leave them testing the fake.
for t in tests/02_*.py tests/61_*.py tests/65_*.py; do run "$t"; done

echo
echo "== third_party: the pico-fido conformance suite"
tp=0
python tests/third_party.py fido -q || tp=$?
detach "RS-Key Security Key" || exit 1

echo
echo "== phase 2: the Yubico identity (ykman's OtpConnection binds no other)"
attach "$PORT_YUBICO" 7802 "YubiKey" || exit 1
run tests/73_otp_keyboard.py

# `77` watches a touch-gated challenge hold the transport and then let go, so it
# needs a slot that waits — armed here, because that is ykman's job and not the
# suite's. The emulator behind this port runs `--touch` with its stdin held open
# by the runner, so the wait is real and nobody ever ends it.
if ykman otp chalresp --touch --force 2 000102030405060708090a0b0c0d0e0f10111213; then
  run tests/77_otp_touch_wait.py --slot 2
  ykman otp delete --force 2 || true
else
  echo "FAIL: could not arm a touch slot — 77 not run"
  fail=$((fail + 1))
  failed+=("otp-arming")
fi
detach "YubiKey" || exit 1

echo
echo "usb suites: $pass passed, $fail failed"
if [ ${#failed[@]} -gt 0 ]; then
  printf 'failed: %s\n' "${failed[*]}"
fi
echo "third_party (fido): pytest exit $tp"

[ "$fail" -eq 0 ] || exit 1
[ "$tp" -eq 0 ] || exit 1
echo
echo "USB SUITES PASSED"
