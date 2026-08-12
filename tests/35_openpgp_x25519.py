#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP Cv25519 (X25519) ECDH test over PC/SC.

    nix develop -c python tests/35_openpgp_x25519.py

Imports an X25519 private key into the DEC slot as OpenPGP "Cv25519" and drives
PSO:DECIPHER, verifying the shared secret against `cryptography` (an independent
RFC 7748 implementation):

    PUT DEC algo-attr (C2 = cv25519) -> IMPORT (0xDB) -> PSO:DECIPHER (8086)

Wire-format notes (the gotcha): the private scalar is sent as a big-endian OpenPGP
MPI (so cryptography's little-endian raw key, reversed); the ephemeral peer key is
the 0x40-prefixed native little-endian u-coordinate; the card returns the 32-byte
little-endian shared secret. All values are < 255 bytes, so plain short APDUs.

PW3 (admin, default "12345678"); re-runnable. rsk-wipe first if PINs were changed.
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID + [0x00]

PW1_DEFAULT = b"123456"
PW3_DEFAULT = b"12345678"
INS_VERIFY, INS_PSO, INS_PUT_DATA, INS_IMPORT = 0x20, 0x2A, 0xDA, 0xDB
MODE_PW1_81 = 0x81
MODE_PW1_82 = 0x82
MODE_PW3 = 0x83
CRT_DEC = 0xB8

# cv25519 algorithm attribute (algo-id ‖ OID): ECDH (0x12).
ATTR_CV25519 = bytes([0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01])

RAW = serialization.Encoding.Raw
RAWPRIV = serialization.PrivateFormat.Raw
RAWPUB = serialization.PublicFormat.Raw
NOENC = serialization.NoEncryption()


def apdu(ins, p1, p2, data=b"", le=None):
    a = [0x00, ins, p1, p2, len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def import_apdu(crt, scalar):
    """IMPORT extended-header-list for an EC/Montgomery key (private key = tag 0x92)."""
    tmpl = bytes([0x92, len(scalar)])
    f7f48 = bytes([0x7F, 0x48, len(tmpl)]) + tmpl
    f5f48 = bytes([0x5F, 0x48, len(scalar)]) + scalar
    body = bytes([crt, 0x00]) + f7f48 + f5f48
    header = bytes([0x4D, len(body)]) + body
    return [0x00, INS_IMPORT, 0x3F, 0xFF, len(header)] + list(header)


def decipher_apdu(peer_point):
    f86 = bytes([0x86, len(peer_point)]) + peer_point
    f7f49 = bytes([0x7F, 0x49, len(f86)]) + f86
    a6 = bytes([0xA6, len(f7f49)]) + f7f49
    return [0x00, INS_PSO, 0x80, 0x86, len(a6)] + list(a6) + [0x00]


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
        print("%-34s -> %s %02X%02X" % (what, shown[:48], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_82, PW1_DEFAULT), "VERIFY PW1 (82, decrypt/auth)")

    dec = X25519PrivateKey.generate()
    scalar_le = dec.private_bytes(RAW, RAWPRIV, NOENC)
    scalar_be = scalar_le[::-1]  # OpenPGP MPI is big-endian
    tx(apdu(INS_PUT_DATA, 0x00, 0xC2, ATTR_CV25519), "PUT DEC algo-attr (C2, cv25519)")
    tx(import_apdu(CRT_DEC, scalar_be), "IMPORT Cv25519 DEC key")

    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(RAW, RAWPUB)  # 32-byte LE u-coordinate
    peer = bytes([0x40]) + eph_pub  # OpenPGP native point format
    z, _, _ = tx(decipher_apdu(peer), "PSO:DECIPHER (Cv25519 ECDH)")
    z = bytes(z)

    expected = dec.exchange(eph.public_key())
    if z != expected:
        fail(f"ECDH shared secret mismatch:\n  card={z.hex()}\n  host={expected.hex()}")
    print("  Cv25519 shared secret MATCHES host (RFC 7748)")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
