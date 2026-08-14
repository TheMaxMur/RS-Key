#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP MSE test — MANAGE SECURITY ENVIRONMENT key-slot swap.

    nix develop -c python tests/38_openpgp_mse.py

Imports a *different* P-256 ECDH key into the DEC slot and the AUT slot, then proves
that MANAGE SECURITY ENVIRONMENT (0x22) repoints DECIPHER from the DEC key to the AUT
key:

    DECIPHER (default)  -> ECDH with the DEC key
    MSE 41 B8 {83 01 03} -> point the confidentiality template (PSO:DECIPHER,
                            ISO 7816-8 CT) at key ref 3 (AUT slot)
    DECIPHER again       -> ECDH with the AUT key  (different shared secret)

Both shared secrets are checked against host ECDH with `cryptography`.

WARNING: leaves a P-256 ECDH key in the AUT slot (the test provisions it). Re-runnable.
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID + [0x00]
PW1_DEFAULT = b"123456"
PW3_DEFAULT = b"12345678"

INS_VERIFY = 0x20
INS_PSO = 0x2A
INS_PUT_DATA = 0xDA
INS_IMPORT = 0xDB
INS_MSE = 0x22
MODE_PW1_81 = 0x81
MODE_PW1_82 = 0x82
MODE_PW3 = 0x83

OID_P256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
ATTR_P256_ECDH = bytes([0x12] + OID_P256)
CRT_DEC, CRT_AUT = 0xB8, 0xA4


def apdu(ins, p1, p2, data=b"", le=None):
    # Case 1/2 (no command data) must NOT carry an Lc byte; case 3/4 do.
    a = [0x00, ins, p1, p2]
    if data:
        a += [len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def import_apdu(crt, scalar):
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
        print("%-34s -> %s %02X%02X" % (what, shown[:40], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_82, PW1_DEFAULT), "VERIFY PW1 (82, decrypt/auth)")

    # Two distinct P-256 ECDH keys, one per slot.
    dec_priv = ec.generate_private_key(ec.SECP256R1())
    aut_priv = ec.generate_private_key(ec.SECP256R1())
    dec_scalar = dec_priv.private_numbers().private_value.to_bytes(32, "big")
    aut_scalar = aut_priv.private_numbers().private_value.to_bytes(32, "big")
    tx(apdu(INS_PUT_DATA, 0x00, 0xC2, ATTR_P256_ECDH), "PUT DEC algo-attr (C2, ECDH)")
    tx(import_apdu(CRT_DEC, dec_scalar), "IMPORT DEC key")
    tx(apdu(INS_PUT_DATA, 0x00, 0xC3, ATTR_P256_ECDH), "PUT AUT algo-attr (C3, ECDH)")
    tx(import_apdu(CRT_AUT, aut_scalar), "IMPORT AUT key")

    # One ephemeral peer key, reused.
    eph = ec.generate_private_key(ec.SECP256R1())
    peer_point = eph.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )

    z_dec, _, _ = tx(decipher_apdu(peer_point), "PSO:DECIPHER (default = DEC)")
    z_dec = bytes(z_dec)

    tx(apdu(INS_MSE, 0x41, CRT_DEC, bytes([0x83, 0x01, 0x03])), "MSE DEC->ref3 (AUT slot)")

    z_aut, _, _ = tx(decipher_apdu(peer_point), "PSO:DECIPHER (after MSE = AUT)")
    z_aut = bytes(z_aut)

    if z_dec == z_aut:
        fail("MSE did not change the decipher result")
    host_dec = dec_priv.exchange(ec.ECDH(), eph.public_key())
    host_aut = aut_priv.exchange(ec.ECDH(), eph.public_key())
    if z_dec != host_dec:
        fail("default DECIPHER did not match host ECDH with the DEC key")
    if z_aut != host_aut:
        fail("post-MSE DECIPHER did not match host ECDH with the AUT key")
    print("  DECIPHER used the DEC key, then the AUT key after MSE — both verified")

    print("\nPASS (MANAGE SECURITY ENVIRONMENT key-slot swap)")


if __name__ == "__main__":
    main()
