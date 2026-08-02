#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Power-cycle helper for the suites that reset (CTAP 2.1 §6.6, bcdDevice 0x0854+).

A key with no screen accepts `authenticatorReset` only within RESET_WINDOW_S of the
USB attach, and a warm reboot does not reopen that window — only real power does. So
a suite that resets asks the operator to unplug and plug back in, the same physical
step as the BOOTSEL prompts, and sends the reset the moment the device re-enumerates
(`ykman fido reset` asks for exactly this). A trusted-display build is exempt — it
paints the operation the touch approves — so there the prompt is merely redundant.

Two transports, because the suites have two: `reset` for the raw CTAPHID scripts,
`reset_fido2` for the ones driven through python-fido2.
"""
import sys
import time

CTAP_RESET = 0x07
CTAP2_OK = 0x00
# consts::RESET_WINDOW_MS, in seconds: what the host has after the attach.
RESET_WINDOW_S = 10.0
REPLUG_TIMEOUT_S = 60.0
POLL_S = 0.05


def _prompt(why):
    print(f"\n👉 UNPLUG the key, then plug it straight back in — {why} needs the "
          f"CTAP 2.1 §6.6 power-up window ({RESET_WINDOW_S:.0f}s from the attach).")


def _wait(probe, want, failure, timeout=REPLUG_TIMEOUT_S):
    """Poll `probe` until the key is (want=True) or is not (want=False) there, and
    return whatever it found. Exits with `failure` on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        found = probe()
        if bool(found) == want:
            return found
        time.sleep(POLL_S)
    sys.exit(f"FAIL: {failure}")


def wait_gone(timeout=REPLUG_TIMEOUT_S):
    """Block until the FIDO HID device is no longer enumerated."""
    from ctaphid import find

    _wait(find, False, "the key is still enumerated — unplug it when asked", timeout)


def wait_back(timeout=REPLUG_TIMEOUT_S):
    """Open the FIDO HID device as soon as it reappears -> (dev, cid, first_seen)."""
    from ctaphid import ctaphid_init, find, hid

    deadline = time.time() + timeout
    seen = None
    while time.time() < deadline:
        info = find()
        if info:
            seen = seen or time.time()
            dev = hid.device()
            try:
                dev.open_path(info["path"])
                return dev, ctaphid_init(dev), seen
            except OSError:
                dev.close()  # enumerated but not ready for reports yet
        time.sleep(POLL_S)
    sys.exit("FAIL: the FIDO HID device did not come back")


def reset(dev=None, why="this authenticatorReset"):
    """Replug the key, then reset it inside the window. Closes `dev` — the caller's
    handle dies with the power cycle — and returns the fresh (dev, cid)."""
    from ctaphid import send_cbor

    if dev is not None:
        dev.close()
    _prompt(why)
    wait_gone()
    print("   unplugged — plug it back in…")
    dev, cid, seen = wait_back()
    status = send_cbor(dev, cid, bytes([CTAP_RESET]))[0]
    if status != CTAP2_OK:
        dev.close()
        sys.exit(f"FAIL: reset {time.time() - seen:.1f}s after the key re-appeared: "
                 f"{status:#04x} (0x30 = past the window, just rerun; on a touch "
                 f"build press the button when it blinks)")
    print(f"   reset inside the window ({time.time() - seen:.1f}s after enumeration)")
    return dev, cid


def reset_fido2(dev=None, why="this authenticatorReset"):
    """`reset` for the suites driven through python-fido2. Those run in a bare fido2
    venv with no hidapi, so this path enumerates with python-fido2 and never imports
    ctaphid. Closes `dev` and returns the fresh CtapHidDevice."""
    from _device import find_fido2
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2

    def probe():
        try:
            return find_fido2()
        except OSError:
            return None  # enumerated but not ready for reports yet

    if dev is not None:
        dev.close()
    _prompt(why)
    _wait(probe, False, "the key is still enumerated — unplug it when asked")
    print("   unplugged — plug it back in…")
    dev = _wait(probe, True, "the FIDO HID device did not come back")
    try:
        Ctap2(dev).reset()
    except CtapError as e:
        dev.close()
        sys.exit(f"FAIL: reset after the replug: {e} (NOT_ALLOWED = past the "
                 f"window, just rerun; on a touch build press the button)")
    print("   reset inside the window")
    return dev
