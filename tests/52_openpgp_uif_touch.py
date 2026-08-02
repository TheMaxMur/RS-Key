#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP UIF (touch policy) test — a BOOTSEL touch gates PSO:CDS.

    # needs pyscard + cryptography (the validation venv has both):
    nix develop -c python tests/52_openpgp_uif_touch.py

Imports a P-256 SIG key, enables the SIG User-Interaction-Flag DO (0xD6 = on),
then drives PSO:CDS. With firmware built `--features up-button` the card blocks
until BOOTSEL is pressed (the CCID transport streams T=1 time-extensions
meanwhile, so pcsc doesn't time out); a missed touch → 0x6600
(SECURE_MESSAGE_EXEC_ERROR). The same applies to DECIPHER (0xD7) and INTERNAL
AUTHENTICATE (0xD8); SIG is the cleanest single-shot demo.

On the default build (no feature) the touch is auto-confirmed instantly, so this
is a no-op and the OpenPGP suites are unaffected. The tool restores UIF=off on
exit, leaving the card clean.
"""
import hashlib
import os
import sys
import time

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID + [0x00]

PW1_DEFAULT = b"123456"
PW3_DEFAULT = b"12345678"
INS_VERIFY, INS_PSO, INS_PUT_DATA, INS_IMPORT = 0x20, 0x2A, 0xDA, 0xDB
MODE_PW1, MODE_PW3 = 0x81, 0x83
OID_P256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
ATTR_P256_ECDSA = bytes([0x13] + OID_P256)
CRT_SIG = 0xB6
UIF_SIG_DO = 0xD6
SW_SECURE_MESSAGE_EXEC_ERROR = (0x66, 0x00)


def apdu(ins, p1, p2, data=b"", le=None):
    a = [0x00, ins, p1, p2, len(data)] + list(data)
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
        print("%-32s -> %s %02X%02X" % (what, (toHexString(data) if data else "")[:40], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: want {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")

    sig_priv = ec.generate_private_key(ec.SECP256R1())
    sig_scalar = sig_priv.private_numbers().private_value.to_bytes(32, "big")
    tx(apdu(INS_PUT_DATA, 0x00, 0xC1, ATTR_P256_ECDSA), "PUT SIG algo-attr (C1, P-256)")
    tx(import_apdu(CRT_SIG, sig_scalar), "IMPORT P-256 SIG key")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), "VERIFY PW1")
    tx(apdu(INS_PUT_DATA, 0x00, UIF_SIG_DO, bytes([0x01, 0x20])), "PUT UIF_SIG = on")

    try:
        msg = b"UIF-gated signature"
        digest = hashlib.sha256(msg).digest()
        print("\nPSO:CDS — 👉 press the BOOTSEL button now (within 30s)...")
        t0 = time.time()
        sig, sw1, sw2 = tx(apdu(INS_PSO, 0x9E, 0x9A, digest, le=0x00), "PSO:CDS (touch)", expect=None)
        dt = time.time() - t0
        if (sw1, sw2) == SW_SECURE_MESSAGE_EXEC_ERROR:
            fail(f"PSO returned 0x6600 after {dt:.1f}s — no touch detected (timeout)")
        if (sw1, sw2) != (0x90, 0x00):
            fail(f"PSO:CDS unexpected status {sw1:02X}{sw2:02X}")

        sig = bytes(sig)
        if len(sig) != 64:
            fail(f"expected 64-byte r‖s, got {len(sig)}")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        try:
            sig_priv.public_key().verify(
                encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            fail("signature did not verify")
        print(f"  signature VERIFIED after {dt:.1f}s")
        if dt < 0.5:
            print(
                "\n⚠ returned instantly — firmware built WITHOUT --features up-button "
                "(UIF auto-confirmed, no touch required)."
            )
        else:
            print("\nPASS — UIF touch gated PSO:CDS.")
    finally:
        # Leave the card clean: disable the touch policy again.
        tx(apdu(INS_PUT_DATA, 0x00, UIF_SIG_DO, bytes([0x00, 0x20])), "PUT UIF_SIG = off (cleanup)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
