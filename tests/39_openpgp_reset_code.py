#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP reset-code test — PUT reset code (0xD3) + RESET RETRY via RC (P1=0)
+ PUT PW status (0xC4).

    nix develop -c python tests/39_openpgp_reset_code.py

Exercises the reset-code (RC) <-> DEK wiring:

  * PUT PW status (0xC4) toggles the "PW1 valid for multiple signatures" flag while
    preserving the retry counters.
  * PUT reset code (0xD3) seals the DEK under a new resetting code.
  * RESET RETRY P1=0 verifies the RC, unseals the DEK via the RC, and re-wraps it
    under a new PW1 — proven by VERIFYing the new PW1 and a CHANGE PIN back to the
    default (which itself needs the DEK).

WARNING: changes the user PIN (PW1) and the reset code; the test restores PW1 to the
default (123456) at the end. PW3 must still be the default (12345678). Re-runnable.
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID + [0x00]

PW1_DEFAULT = b"123456"
PW3_DEFAULT = b"12345678"
RC = b"reset123"
NEW_PW1 = b"111111"

INS_VERIFY = 0x20
INS_CHANGE_PIN = 0x24
INS_RESET_RETRY = 0x2C
INS_GET_DATA = 0xCA
INS_PUT_DATA = 0xDA
MODE_PW1 = 0x81
MODE_PW3 = 0x83
DO_RESET_CODE = 0xD3
DO_PW_STATUS = 0xC4


def apdu(ins, p1, p2, data=b"", le=None):
    # Case 1/2 (no command data) must NOT carry an Lc byte; case 3/4 do.
    a = [0x00, ins, p1, p2]
    if data:
        a += [len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")
    conn = target.createConnection()
    conn.connect()

    def tx(cmd, what, expect=(0x90, 0x00)):
        data, sw1, sw2 = conn.transmit(cmd)
        shown = toHexString(data) if data else ""
        print("%-36s -> %s %02X%02X" % (what, shown[:36], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")

    # ---------------- PUT PW status (0xC4) ----------------
    before, _, _ = tx(apdu(INS_GET_DATA, 0x00, DO_PW_STATUS, le=0x00), "GET PW status")
    if len(before) != 7:
        fail(f"PW status not 7 bytes: {len(before)}")
    new_flag = 0x00 if before[0] != 0x00 else 0x01
    tx(apdu(INS_PUT_DATA, 0x00, DO_PW_STATUS, bytes([new_flag])), "PUT PW status (toggle flag)")
    after, _, _ = tx(apdu(INS_GET_DATA, 0x00, DO_PW_STATUS, le=0x00), "GET PW status (after)")
    if after[0] != new_flag:
        fail(f"PW1-valid flag not updated: {after[0]:#x} != {new_flag:#x}")
    if list(after[4:7]) != list(before[4:7]):
        fail("PUT PW status clobbered the retry counters")
    tx(apdu(INS_PUT_DATA, 0x00, DO_PW_STATUS, bytes([before[0]])), "PUT PW status (restore)")
    print("  PW status flag toggled, retry counters preserved")

    # ---------------- PUT reset code (0xD3) ----------------
    tx(apdu(INS_PUT_DATA, 0x00, DO_RESET_CODE, RC), "PUT reset code (0xD3)")

    # ---------------- RESET RETRY via the reset code (P1=0) ----------------
    tx(SELECT, "SELECT (reset session)")
    tx(apdu(INS_RESET_RETRY, 0x00, MODE_PW1, RC + NEW_PW1), "RESET RETRY via RC (P1=0)")

    # ---------------- the new PW1 works; the old one does not ----------------
    tx(SELECT, "SELECT (reset session)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, NEW_PW1), "VERIFY new PW1")
    tx(SELECT, "SELECT (reset session)")
    _, s1, s2 = tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY old PW1 (expect fail)", expect=None)
    if (s1, s2) == (0x90, 0x00):
        fail("the old PW1 still verifies after the reset")
    print(f"  old PW1 correctly rejected ({s1:02X}{s2:02X})")

    # ---------------- CHANGE PIN back to default (needs the DEK) ----------------
    tx(SELECT, "SELECT (reset session)")
    tx(apdu(INS_CHANGE_PIN, 0x00, MODE_PW1, NEW_PW1 + PW1_DEFAULT), "CHANGE PIN new->default")
    tx(SELECT, "SELECT (reset session)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY PW1 default (restored)")

    print("\nPASS (reset code + RESET RETRY via RC + PW status)")


if __name__ == "__main__":
    main()
