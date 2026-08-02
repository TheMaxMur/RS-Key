#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP PIN + PUT DATA test — drive the card over PC/SC (pyscard).

    nix develop -c python tests/32_openpgp_pins.py
    # or from the validation venv (has pyscard):
    nix develop -c python tests/32_openpgp_pins.py

Exercises the OpenPGP write path over CCID:

    VERIFY (PW1/PW3) -> PUT DATA (cardholder DOs) -> CHANGE PIN (DEK re-wrap)

Self-contained and re-runnable: every PIN change is reverted and wrong-PIN
attempts are followed by a correct one (resetting the retry counter), so the card
is left on the default PINs ("123456" / "12345678").

After it passes, `gpg --card-status` should show the Login/Name/URL it set.
Needs pyscard + a PC/SC daemon (built in on macOS).
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
INS_CHANGE = 0x24
INS_PUT_DATA = 0xDA
INS_GET_DATA = 0xCA
MODE_PW1 = 0x81
MODE_PW3 = 0x83


def apdu(ins, p1, p2, data=b""):
    return [0x00, ins, p1, p2, len(data)] + list(data)


def get_data(tag):
    return [0x00, INS_GET_DATA, (tag >> 8) & 0xFF, tag & 0xFF, 0x00]


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
        print("%-32s -> %s %02X%02X" % (what, toHexString(data) or "", sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")

    # --- VERIFY (admin) + PUT DATA cardholder DOs ---
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (default)")

    tx(apdu(INS_PUT_DATA, 0x00, 0x5E, b"alice@example"), "PUT login (5E)")
    tx(apdu(INS_PUT_DATA, 0x00, 0x5B, b"Doe<<John"), "PUT name (5B)")
    tx(apdu(INS_PUT_DATA, 0x5F, 0x50, b"https://example/key.asc"), "PUT URL (5F50)")

    login, _, _ = tx(get_data(0x005E), "GET login (5E)")
    if bytes(login) != b"alice@example":
        fail(f"login round-trip mismatch: {bytes(login)!r}")

    # PUT without (re)auth still works here because PW3 stays verified; verify a
    # denial by logging out admin first.
    tx(apdu(INS_VERIFY, 0xFF, MODE_PW3), "VERIFY logout PW3")
    tx(
        apdu(INS_PUT_DATA, 0x00, 0x5E, b"nope"),
        "PUT login after logout (denied)",
        expect=(0x69, 0x82),
    )

    # --- VERIFY PW1 + wrong-PIN retry ladder ---
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY PW1 (default)")
    _, sw1, sw2 = tx(
        apdu(INS_VERIFY, 0x00, MODE_PW1, b"000000"),
        "VERIFY PW1 (wrong)",
        expect=None,
    )
    if sw1 != 0x63 or (sw2 & 0xF0) != 0xC0:
        fail(f"wrong PIN should return 63Cx, got {sw1:02X}{sw2:02X}")
    # A correct verify resets the counter (leaves the card clean).
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY PW1 (reset counter)")

    # --- CHANGE PIN PW1 (DEK re-wrap), then revert ---
    tx(apdu(INS_CHANGE, 0x00, MODE_PW1, PW1_DEFAULT + b"654321"), "CHANGE PW1 -> 654321")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, b"654321"), "VERIFY PW1 (new)")
    tx(
        apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT),
        "VERIFY PW1 (old, now wrong)",
        expect=None,
    )
    tx(apdu(INS_CHANGE, 0x00, MODE_PW1, b"654321" + PW1_DEFAULT), "CHANGE PW1 -> default")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY PW1 (default again)")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
