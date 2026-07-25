#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: the authenticatorReset power-up window (CTAP 2.1 §6.6, bcdDevice 0x0854+).

    nix develop -c python tests/27_reset_window.py

⚠ DESTRUCTIVE: the accepted reset wipes every FIDO credential and the PIN.

Needs the no-touch test image (`--features no-touch`) on a NON-display build: the
trusted display paints the operation it is asking about, which exempts it from the
window (`UserPresence::shows_confirm`), and a touch build wants a real press.

  1. replug (a real power-on reset), then reset the moment the HID device shows up
     -> CTAP2_OK. This is the regression: the window is measured from the USB
     attach, not from the time driver's zero, so the seconds boot spends on the
     TRNG seed, the seal migrations and the one-shot hardening lap are not charged
     against the host's ten. A device that boots slowly (hardening lap, many
     resident credentials) must still be resettable.
  2. reset again past the window -> 0x30 NOT_ALLOWED — it really is a window.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaphid import send_cbor  # noqa: E402
from replug import CTAP_RESET, CTAP2_OK, RESET_WINDOW_S, wait_back, wait_gone  # noqa: E402

CTAP2_ERR_NOT_ALLOWED = 0x30
LATE_S = RESET_WINDOW_S + 3.0  # past the window, with room for the retry to land


def main():
    print("Unplug the key …")
    wait_gone()
    print("Now plug it back in …")
    dev, cid, seen = wait_back()
    try:
        status = send_cbor(dev, cid, bytes([CTAP_RESET]))[0]
        dt = time.time() - seen
        if dt >= RESET_WINDOW_S:
            sys.exit(f"INCONCLUSIVE: the first reset only landed {dt:.1f}s after the "
                     f"device appeared, past the {RESET_WINDOW_S:.0f}s window — rerun")
        assert status == CTAP2_OK, f"reset {dt:.1f}s after enumeration: {status:#04x}"
        print(f"reset inside the window ({dt:.1f}s after enumeration): OK")

        time.sleep(max(0.0, LATE_S - (time.time() - seen)))
        status = send_cbor(dev, cid, bytes([CTAP_RESET]))[0]
        dt = time.time() - seen
        assert status == CTAP2_ERR_NOT_ALLOWED, f"late reset ({dt:.1f}s): {status:#04x}"
        print(f"reset past the window ({dt:.1f}s): NOT_ALLOWED")
    finally:
        dev.close()
    print("PASS")


if __name__ == "__main__":
    main()
