#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP AES symmetric PSO test (encipher / decipher) over PC/SC.

The OpenPGP card AES operation uses the symmetric key at `EF_AES_KEY` (tag D5) —
minted on the DEC slot by GENERATE, or written by the host with `PUT DATA D5` —
in raw AES-CBC with a zero IV and no padding:

    PSO:ENCIPHER (86 80)  plaintext            -> 0x02 || cryptogram
    PSO:DECIPHER (80 86)  0x02 || cryptogram   -> plaintext

The minted key is sealed under the DEK and never leaves the card, so that half is
verified by round-trip. A host-written key is known, so the second half checks the
cryptogram byte-for-byte against an independent AES-CBC. Needs PW2 (the DEC
password, default "123456") to use the key and PW3 to write it; the DEC keypair is
(re)generated each run to mint a fresh one, so the test is idempotent.

    nix develop -c python tests/40_openpgp_aes_pso.py
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

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
    # PW3 authorises GENERATE; the AES PSO itself takes PW1 no. 82 and nothing
    # else (OpenPGP 3.4 §7.2.11), so verify that too.
    tx([0x00, INS_VERIFY, 0x00, MODE_PW1_82, len(PW1_DEFAULT)] + list(PW1_DEFAULT),
       "VERIFY PW1 (82)")
    # Generate the DEC keypair — this mints the DEC slot's AES-256 key.
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

    # PUT DATA D5: the host supplies the key itself (OpenPGP 3.4 §7.2.11), which
    # is what Extended Capabilities b2 announces. AES-128 and AES-256 only.
    for bad in (0, 1, 15, 17, 24, 31, 33):
        _, sw1, sw2 = conn.transmit([0x00, INS_PUT_DATA, 0x00, 0xD5, bad] + [0x22] * bad)
        if (sw1, sw2) != (0x6A, 0x80):
            fail(f"PUT DATA D5 with {bad} bytes: SW {sw1:02X}{sw2:02X} != 6A80")
    print("  PUT DATA D5 takes 16 or 32 bytes and nothing else")

    for key in (bytes(range(16)), bytes(range(32))):
        tx([0x00, INS_PUT_DATA, 0x00, 0xD5, len(key)] + list(key),
           f"PUT DATA D5 ({len(key) * 8}-bit key)")
        enc = tx([0x00, INS_PSO, 0x86, 0x80, len(pt)] + list(pt) + [0x00],
                 "PSO:ENCIPHER under it")
        enc_ctx = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
        want = enc_ctx.update(pt) + enc_ctx.finalize()
        if enc[1:] != want:
            fail(f"the D5 key is not the key the PSO used: {enc[1:].hex()} != {want.hex()}")
        dec = tx([0x00, INS_PSO, 0x80, 0x86, len(enc)] + list(enc) + [0x00],
                 "PSO:DECIPHER under it")
        if dec != pt:
            fail(f"round-trip under a host-supplied key: {dec.hex()} != {pt.hex()}")
    print("  the host-supplied key is the key the PSO uses (AES-CBC, zero IV)")

    print("\nPASS (AES encipher/decipher round-trip, host-supplied D5 key)")


if __name__ == "__main__":
    main()
