#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP RSA test — IMPORT + PSO + INTERNAL AUTHENTICATE over PC/SC.

    # needs pyscard AND cryptography in the same interpreter — the validation venv has both:
    nix develop -c python tests/34_openpgp_rsa.py

Generates RSA-2048 keys on the host, imports them (E/P/Q) into the SIG / DEC /
AUT slots over CCID, then drives the card's crypto and verifies the result with
`cryptography`:

    PUT algo-attr (C1/C2/C3 = RSA-2048) -> IMPORT (0xDB) -> PSO:CDS (9E9A)
                                                         -> PSO:DECIPHER (8086)
                                                         -> INTERNAL AUTHENTICATE (0x88)

The IMPORT header list (~281 B) and the DECIPHER ciphertext (257 B) exceed 255
bytes, so they go in extended-length APDUs — the path gpg/scdaemon uses on this
extended-length-capable card (command chaining is the host-tested fallback).

Re-runnable: it sets the slot algorithm attributes to RSA-2048 (overriding any EC
attributes left by tests/33_openpgp_ec_crypto.py) and IMPORT overwrites the keys. Uses PW3
(admin, default "12345678"), which authorises IMPORT and all three crypto ops; if
a prior session changed the PINs, rsk-wipe for a clean slate first.
"""
import hashlib
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
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
INS_INTERNAL_AUT = 0x88
INS_PUT_DATA = 0xDA
INS_IMPORT = 0xDB
MODE_PW1_81 = 0x81
MODE_PW1_82 = 0x82
MODE_PW3 = 0x83

# RSA-2048 algorithm attribute: ALGO_RSA, 2048-bit modulus, 32-bit exponent field,
# import format 0 (E/P/Q).
ATTR_RSA2K = bytes([0x01, 0x08, 0x00, 0x00, 0x20, 0x00])

CRT_SIG, CRT_DEC, CRT_AUT = 0xB6, 0xB8, 0xA4

# SHA-256 DigestInfo prefix (what gpg prepends to the 32-byte hash for RSA).
DI_SHA256 = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
])


def apdu(ins, p1, p2, data=b"", le=None):
    a = [0x00, ins, p1, p2, len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def apdu_ext(ins, p1, p2, data=b"", ne=None):
    """Extended-length APDU: 00-marker, 2-byte Lc, then an optional 2-byte Le."""
    a = [0x00, ins, p1, p2, 0x00, len(data) >> 8, len(data) & 0xFF] + list(data)
    if ne is not None:
        a += [ne >> 8, ne & 0xFF]
    return a


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def rsa_import_header(crt, e, p, q):
    """4D { <CRT> 7F48 { 91 92 93 tag-lengths } 5F48 { E ‖ P ‖ Q } }."""
    tmpl = b""
    for tag, v in ((0x91, e), (0x92, p), (0x93, q)):
        tmpl += bytes([tag]) + ber_len(len(v))
    f7f48 = bytes([0x7F, 0x48]) + ber_len(len(tmpl)) + tmpl
    kd = e + p + q
    f5f48 = bytes([0x5F, 0x48]) + ber_len(len(kd)) + kd
    body = bytes([crt, 0x00]) + f7f48 + f5f48
    return bytes([0x4D]) + ber_len(len(body)) + body


def decipher_data(ct):
    """PSO:DECIPHER data field: the OpenPGP padding-indicator byte then ciphertext."""
    return bytes([0x00]) + ct


def key_parts(priv):
    nums = priv.private_numbers()
    e = (priv.public_key().public_numbers().e).to_bytes(3, "big")
    p = nums.p.to_bytes(128, "big")
    q = nums.q.to_bytes(128, "big")
    return e, p, q


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
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_81, PW1_DEFAULT), "VERIFY PW1 (81, signing)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_82, PW1_DEFAULT), "VERIFY PW1 (82, decrypt/auth)")

    # ---------------- RSA-2048 SIG: IMPORT + PSO:CDS ----------------
    sig_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e, p, q = key_parts(sig_priv)
    tx(apdu(INS_PUT_DATA, 0x00, 0xC1, ATTR_RSA2K), "PUT SIG algo-attr (C1, RSA-2048)")
    tx(apdu_ext(INS_IMPORT, 0x3F, 0xFF, rsa_import_header(CRT_SIG, e, p, q)),
       "IMPORT RSA SIG key (ext-len)")

    msg = b"sign with the imported RSA-2048 key"
    di = DI_SHA256 + hashlib.sha256(msg).digest()
    sig, _, _ = tx(apdu(INS_PSO, 0x9E, 0x9A, di, le=0x00), "PSO:CDS (RSA-2048)")
    sig = bytes(sig)
    if len(sig) != 256:
        fail(f"expected a 256-byte RSA signature, got {len(sig)}")
    try:
        sig_priv.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        print("  RSA-2048 signature VERIFIED")
    except InvalidSignature:
        fail("RSA signature did not verify")

    # ---------------- RSA-2048 DEC: IMPORT + PSO:DECIPHER ----------------
    dec_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e, p, q = key_parts(dec_priv)
    tx(apdu(INS_PUT_DATA, 0x00, 0xC2, ATTR_RSA2K), "PUT DEC algo-attr (C2, RSA-2048)")
    tx(apdu_ext(INS_IMPORT, 0x3F, 0xFF, rsa_import_header(CRT_DEC, e, p, q)),
       "IMPORT RSA DEC key (ext-len)")

    session = os.urandom(24)
    ct = dec_priv.public_key().encrypt(session, padding.PKCS1v15())
    pt, _, _ = tx(apdu_ext(INS_PSO, 0x80, 0x86, decipher_data(ct), ne=0x0000),
                  "PSO:DECIPHER (RSA-2048)")
    pt = bytes(pt)
    if pt != session:
        fail(f"decipher mismatch:\n  card={pt.hex()}\n  host={session.hex()}")
    print("  RSA-2048 decipher RECOVERED the session key")

    # ---------------- RSA-2048 AUT: IMPORT + INTERNAL AUTHENTICATE ----------------
    aut_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e, p, q = key_parts(aut_priv)
    tx(apdu(INS_PUT_DATA, 0x00, 0xC3, ATTR_RSA2K), "PUT AUT algo-attr (C3, RSA-2048)")
    tx(apdu_ext(INS_IMPORT, 0x3F, 0xFF, rsa_import_header(CRT_AUT, e, p, q)),
       "IMPORT RSA AUT key (ext-len)")

    chal = b"internal-authenticate challenge"
    di = DI_SHA256 + hashlib.sha256(chal).digest()
    asig, _, _ = tx(apdu(INS_INTERNAL_AUT, 0x00, 0x00, di, le=0x00), "INTERNAL AUTHENTICATE")
    asig = bytes(asig)
    if len(asig) != 256:
        fail(f"expected a 256-byte RSA signature, got {len(asig)}")
    try:
        aut_priv.public_key().verify(asig, chal, padding.PKCS1v15(), hashes.SHA256())
        print("  RSA-2048 INTERNAL-AUT signature VERIFIED")
    except InvalidSignature:
        fail("RSA INTERNAL-AUT signature did not verify")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
