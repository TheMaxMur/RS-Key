#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP lifecycle test — GET CHALLENGE + ACTIVATE FILE + TERMINATE DF.

    nix develop -c python tests/37_openpgp_lifecycle.py

Drives the three lifecycle/management commands over CCID:

  * GET CHALLENGE (0x84)  — request N random bytes; two calls must differ.
  * ACTIVATE FILE (0x44)  — no-op, must answer 9000.
  * TERMINATE DF  (0xE6)  — factory-reset the OpenPGP applet. Refused without the
                            admin PIN (PW3) while PW3 is unblocked; with PW3 it
                            wipes the OpenPGP files and re-seeds the defaults.

WARNING: TERMINATE is DESTRUCTIVE — it erases every OpenPGP key/DO and resets the
PINs to their factory defaults (123456 / 12345678). Run it knowing the OpenPGP
slots provisioned by earlier OpenPGP keygen runs will be gone. FIDO is
unaffected (the wipe is scoped to OpenPGP FIDs).

Re-runnable.
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

INS_VERIFY = 0x20
INS_CHALLENGE = 0x84
INS_ACTIVATE = 0x44
INS_TERMINATE = 0xE6
INS_PUT_DATA = 0xDA
INS_GET_DATA = 0xCA
MODE_PW1 = 0x81
MODE_PW3 = 0x83

DO_LOGIN = 0x5E  # login data — free read, PW3 to write


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
        print("%-36s -> %s %02X%02X" % (what, shown[:48], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")

    # ---------------- GET CHALLENGE ----------------
    c1, _, _ = tx(apdu(INS_CHALLENGE, 0x00, 0x00, le=0x08), "GET CHALLENGE (8)")
    c2, _, _ = tx(apdu(INS_CHALLENGE, 0x00, 0x00, le=0x08), "GET CHALLENGE (8) again")
    if len(c1) != 8 or len(c2) != 8:
        fail(f"GET CHALLENGE wrong length: {len(c1)}, {len(c2)}")
    if c1 == c2:
        fail("two challenges are identical — RNG not advancing")
    big, _, _ = tx(apdu(INS_CHALLENGE, 0x00, 0x00, le=0x20), "GET CHALLENGE (32)")
    if len(big) != 32:
        fail(f"GET CHALLENGE(32) wrong length: {len(big)}")
    print("  challenges distinct and correctly sized")

    # ---------------- ACTIVATE FILE ----------------
    tx(apdu(INS_ACTIVATE, 0x00, 0x00), "ACTIVATE FILE")

    # ---------------- TERMINATE DF: refused without PW3 ----------------
    tx(SELECT, "SELECT (reset session)")
    tx(apdu(INS_TERMINATE, 0x00, 0x00), "TERMINATE w/o PW3 (expect 6982)", expect=(0x69, 0x82))

    # ---------------- TERMINATE DF: wipes under PW3 ----------------
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")
    marker = b"lifecycle-marker"
    tx(apdu(INS_PUT_DATA, 0x00, DO_LOGIN, marker), "PUT login data (marker)")
    got, _, _ = tx(apdu(INS_GET_DATA, 0x00, DO_LOGIN, le=0x00), "GET login data")
    if bytes(got) != marker:
        fail(f"login marker not stored: {bytes(got)!r}")

    tx(apdu(INS_TERMINATE, 0x00, 0x00), "TERMINATE DF (with PW3)")
    tx(apdu(INS_ACTIVATE, 0x00, 0x00), "ACTIVATE FILE")

    # Card is alive and factory-reset: the marker is gone, defaults restored.
    tx(SELECT, "SELECT OpenPGP AID (post-terminate)")
    got, _, _ = tx(apdu(INS_GET_DATA, 0x00, DO_LOGIN, le=0x00), "GET login data (post-terminate)")
    if bytes(got):
        fail(f"login data survived TERMINATE: {bytes(got)!r}")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY PW1 default (PIN reset)")
    print("  TERMINATE wiped the marker and reset the PINs to default")

    print("\nPASS (GET CHALLENGE + ACTIVATE FILE + TERMINATE DF)")


if __name__ == "__main__":
    main()
