#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP AES symmetric PSO test (encipher / decipher) over PC/SC.

The OpenPGP card AES operation uses the symmetric key minted on the DEC slot
(`EF_AES_KEY`, tag D5), in raw AES-CBC with a zero IV and no padding:

    PSO:ENCIPHER (86 80)  plaintext            -> 0x02 || cryptogram
    PSO:DECIPHER (80 86)  0x02 || cryptogram   -> plaintext

The key is sealed under the DEK and never leaves the card, so this verifies by
round-trip (encipher then decipher must recover the plaintext). Needs PW2 (the
DEC password, default "123456"); the DEC keypair is (re)generated each run to
mint a fresh AES key, so the test is idempotent.

    nix develop -c python tests/40_openpgp_aes_pso.py
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

INS_VERIFY, INS_PSO, INS_PUT_DATA, INS_KEYPAIR_GEN = 0x20, 0x2A, 0xDA, 0x47
MODE_PW1_82, MODE_PW3 = 0x82, 0x83
PW1_DEFAULT, PW3_DEFAULT = b"123456", b"12345678"
ATTR_P256_ECDH = bytes([0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
CRT_DEC = 0xB8


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
        print("%-32s -> %s %02X%02X" % (what, toHexString(data)[:36], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return bytes(data)

    tx(SELECT, "SELECT OpenPGP AID")
    tx([0x00, INS_VERIFY, 0x00, MODE_PW3, len(PW3_DEFAULT)] + list(PW3_DEFAULT), "VERIFY PW3")
    # Generate the DEC keypair — this mints the DEC slot's AES-256 key. PW3 (admin)
    # also authorises the AES PSO (gate is `!has_pw3 && !has_pw2`), so no separate
    # PW2 verify is needed — which also avoids depending on PW1's state.
    tx([0x00, INS_PUT_DATA, 0x00, 0xC2, len(ATTR_P256_ECDH)] + list(ATTR_P256_ECDH),
       "PUT DEC algo-attr (P-256 ECDH)")
    # Extended-length GENERATE (00 00 02 Lc | B8 00 | 00 00 Le), as in the keygen test.
    tx([0x00, INS_KEYPAIR_GEN, 0x80, 0x00, 0x00, 0x00, 0x02, CRT_DEC, 0x00, 0x00, 0x00],
       "GENERATE DEC (mints AES key)")

    pt = bytes(range(32))  # two AES blocks
    enc = tx([0x00, INS_PSO, 0x86, 0x80, len(pt)] + list(pt) + [0x00], "PSO:ENCIPHER (86 80)")
    if not enc or enc[0] != 0x02:
        fail(f"ENCIPHER response must start with the 0x02 indicator: {enc.hex()}")
    if len(enc) != len(pt) + 1:
        fail(f"ENCIPHER length {len(enc)} != plaintext+1")
    if enc[1:] == pt:
        fail("ENCIPHER returned the plaintext unchanged")
    print(f"  cryptogram: {enc.hex()}")

    dec = tx([0x00, INS_PSO, 0x80, 0x86, len(enc)] + list(enc) + [0x00], "PSO:DECIPHER (80 86)")
    if dec != pt:
        fail(f"DECIPHER did not recover the plaintext: {dec.hex()} != {pt.hex()}")
    print("  round-trip OK: decipher(encipher(pt)) == pt")

    # Raw CBC, no padding: a non-block-aligned plaintext must be rejected (6700).
    _, sw1, sw2 = conn.transmit([0x00, INS_PSO, 0x86, 0x80, 15] + [0] * 15 + [0x00])
    if (sw1, sw2) != (0x67, 0x00):
        fail(f"non-block-aligned ENCIPHER: SW {sw1:02X}{sw2:02X} != 6700")
    print("  block-alignment enforced (15-byte plaintext -> 6700)")

    print("\nPASS (AES encipher/decipher round-trip)")


if __name__ == "__main__":
    main()
