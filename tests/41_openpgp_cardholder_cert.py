#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP cardholder certificate test (SELECT DATA + GET/PUT 7F21) over PC/SC.

DO 7F21 has three occurrences (one per key: the standard order is AUT/DEC/SIG),
selected with SELECT DATA (INS 0xA5) and stored independently in EF_CH_1/2/3.
This exercises:

    PUT DATA 7F21          -> writes the selected occurrence (PW3)
    GET DATA 7F21          -> reads it back (free)
    SELECT DATA <occ>      -> A5 <occ> 04 | 60 04 5C 02 7F 21

Verified by writing distinct blobs to occurrences 0/1/2 and reading each back
(they must be independent). Idempotent: deletes the three certs at the end
(an empty PUT deletes). A small blob is used (short APDU); real X.509 certs go
over extended-length APDUs, which the card also supports (see tests/34_openpgp_rsa.py).

    nix develop -c python tests/41_openpgp_cardholder_cert.py
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
INS_VERIFY, INS_GET_DATA, INS_PUT_DATA, INS_SELECT_DATA = 0x20, 0xCA, 0xDA, 0xA5
MODE_PW3, PW3_DEFAULT = 0x83, b"12345678"


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def select_data_cert(occ):
    # A5 <occ> 04 | 60 04 5C 02 7F 21  — pick occurrence `occ` of DO 7F21.
    return [0x00, INS_SELECT_DATA, occ, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")
    conn = target.createConnection()
    conn.connect()

    def tx(cmd, what, expect=(0x90, 0x00)):
        data, sw1, sw2 = conn.transmit(cmd)
        print("%-34s -> %s %02X%02X" % (what, toHexString(data)[:30], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return bytes(data)

    def get_cert():
        return tx([0x00, INS_GET_DATA, 0x7F, 0x21, 0x00], "GET DATA 7F21")

    def put_cert(blob):
        tx([0x00, INS_PUT_DATA, 0x7F, 0x21, len(blob)] + list(blob), f"PUT DATA 7F21 ({len(blob)}B)")

    tx(SELECT, "SELECT OpenPGP AID")
    tx([0x00, INS_VERIFY, 0x00, MODE_PW3, len(PW3_DEFAULT)] + list(PW3_DEFAULT), "VERIFY PW3")

    # Three distinct blobs, one per occurrence.
    certs = [bytes([0x30, 0x06, 0xC0 + i] + [i] * 5) for i in range(3)]
    for occ in range(3):
        tx(select_data_cert(occ), f"SELECT DATA occ {occ}")
        put_cert(certs[occ])

    # Read each back independently — proves the three instances don't alias.
    for occ in range(3):
        tx(select_data_cert(occ), f"SELECT DATA occ {occ}")
        got = get_cert()
        if got != certs[occ]:
            fail(f"occ {occ}: read {got.hex()} != written {certs[occ].hex()}")
    print("  all three occurrences read back independently")

    # SELECT DATA validation: unknown tag and out-of-range occurrence are rejected.
    _, s1, s2 = conn.transmit([0x00, INS_SELECT_DATA, 0, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x00, 0x65])
    if (s1, s2) != (0x6A, 0x88):
        fail(f"SELECT DATA unknown tag: SW {s1:02X}{s2:02X} != 6A88")
    _, s1, s2 = conn.transmit(select_data_cert(3))
    if (s1, s2) != (0x6A, 0x88):
        fail(f"SELECT DATA occ 3: SW {s1:02X}{s2:02X} != 6A88")
    print("  SELECT DATA validation OK (bad tag / occ -> 6A88)")

    # Cleanup: delete all three (empty PUT).
    for occ in range(3):
        tx(select_data_cert(occ), f"SELECT DATA occ {occ}")
        tx([0x00, INS_PUT_DATA, 0x7F, 0x21], f"DELETE 7F21 occ {occ}")
        if get_cert() != b"":
            fail(f"occ {occ} not empty after delete")
    print("  cleanup OK (all certs deleted)")

    print("\nPASS (cardholder certificates read/write per occurrence)")


if __name__ == "__main__":
    main()
