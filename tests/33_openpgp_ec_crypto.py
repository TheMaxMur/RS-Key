#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP EC crypto test — IMPORT + PSO + INTERNAL AUTHENTICATE over PC/SC.

    # needs pyscard AND cryptography in the same interpreter — the validation venv has both:
    nix develop -c python tests/33_openpgp_ec_crypto.py

Generates EC keys on the host (so it knows both the private scalar to import and
the public key to check against), imports them into the SIG / DEC / AUT slots
over CCID, then drives the card's crypto and verifies the result with
`cryptography`:

    PUT algo-attr (C1/C2/C3) -> IMPORT (0xDB) -> PSO:CDS (9E9A) / DECIPHER (8086)
                                              -> INTERNAL AUTHENTICATE (0x88)

  * P-256 ECDSA  — PSO COMPUTE SIGNATURE, verify the signature.
  * Ed25519      — INTERNAL AUTHENTICATE, verify the (PureEdDSA) signature.
  * P-256 ECDH   — PSO DECIPHER, verify the shared secret equals host ECDH.

Re-runnable: IMPORT overwrites the slots and the PINs are left on their defaults
("123456" / "12345678").
"""
import hashlib
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

try:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives import hashes, serialization
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

INS_VERIFY = 0x20
INS_PSO = 0x2A
INS_INTERNAL_AUT = 0x88
INS_PUT_DATA = 0xDA
INS_IMPORT = 0xDB
MODE_PW1 = 0x81
MODE_PW2 = 0x82
MODE_PW1_81 = 0x81
MODE_PW1_82 = 0x82
MODE_PW3 = 0x83

# Algorithm-attribute values (algo-id ‖ OID): P-256 tagged ECDSA on the signing
# keys, ECDH on the decipher key; Ed25519 tagged EdDSA.
OID_P256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
OID_ED25519 = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
ATTR_P256_ECDSA = bytes([0x13] + OID_P256)
ATTR_P256_ECDH = bytes([0x12] + OID_P256)
ATTR_ED25519 = bytes([0x16] + OID_ED25519)

# Control-reference template tags / slot algorithm-attribute DOs.
CRT_SIG, CRT_DEC, CRT_AUT = 0xB6, 0xB8, 0xA4


def apdu(ins, p1, p2, data=b"", le=None):
    a = [0x00, ins, p1, p2, len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def import_apdu(crt, scalar):
    """Build the IMPORT extended-header-list APDU for an EC key (tag 0x92)."""
    tmpl = bytes([0x92, len(scalar)])
    f7f48 = bytes([0x7F, 0x48, len(tmpl)]) + tmpl
    f5f48 = bytes([0x5F, 0x48, len(scalar)]) + scalar
    body = bytes([crt, 0x00]) + f7f48 + f5f48
    header = bytes([0x4D, len(body)]) + body
    return [0x00, INS_IMPORT, 0x3F, 0xFF, len(header)] + list(header)


def decipher_apdu(peer_point):
    """Wrap a peer public point as A6 { 7F49 { 86 <point> } } for PSO:DECIPHER."""
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
    # PW3 (admin) authorises IMPORT; the crypto ops take PW1 and only PW1 —
    # no. 81 for PSO:CDS, no. 82 for DECIPHER and INTERNAL AUTHENTICATE
    # (OpenPGP 3.4 §7.2.10/§7.2.11/§7.2.13). So this needs PW1 at its default,
    # which a prior gpg session against the same key may have changed.
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_81, PW1_DEFAULT), "VERIFY PW1 (81, signing)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_82, PW1_DEFAULT), "VERIFY PW1 (82, decrypt/auth)")

    # ---------------- P-256 ECDSA: IMPORT + PSO:CDS ----------------
    sig_priv = ec.generate_private_key(ec.SECP256R1())
    sig_scalar = sig_priv.private_numbers().private_value.to_bytes(32, "big")
    tx(apdu(INS_PUT_DATA, 0x00, 0xC1, ATTR_P256_ECDSA), "PUT SIG algo-attr (C1, P-256)")
    tx(import_apdu(CRT_SIG, sig_scalar), "IMPORT P-256 SIG key")

    msg = b"sign with the imported P-256 key"
    digest = hashlib.sha256(msg).digest()
    sig, _, _ = tx(apdu(INS_PSO, 0x9E, 0x9A, digest, le=0x00), "PSO:CDS (P-256)")
    sig = bytes(sig)
    if len(sig) != 64:
        fail(f"expected 64-byte r‖s, got {len(sig)}")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    try:
        sig_priv.public_key().verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
        print("  P-256 ECDSA signature VERIFIED")
    except InvalidSignature:
        fail("P-256 signature did not verify")

    # ---------------- Ed25519: IMPORT + INTERNAL AUTHENTICATE ----------------
    aut_priv = ed25519.Ed25519PrivateKey.generate()
    aut_seed = aut_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    tx(apdu(INS_PUT_DATA, 0x00, 0xC3, ATTR_ED25519), "PUT AUT algo-attr (C3, Ed25519)")
    tx(import_apdu(CRT_AUT, aut_seed), "IMPORT Ed25519 AUT key")

    chal = b"internal-authenticate challenge"
    asig, _, _ = tx(apdu(INS_INTERNAL_AUT, 0x00, 0x00, chal, le=0x00), "INTERNAL AUTHENTICATE")
    asig = bytes(asig)
    if len(asig) != 64:
        fail(f"expected 64-byte EdDSA signature, got {len(asig)}")
    try:
        aut_priv.public_key().verify(asig, chal)
        print("  Ed25519 signature VERIFIED")
    except InvalidSignature:
        fail("Ed25519 signature did not verify")

    # ---------------- P-256 ECDH: IMPORT + PSO:DECIPHER ----------------
    dec_priv = ec.generate_private_key(ec.SECP256R1())
    dec_scalar = dec_priv.private_numbers().private_value.to_bytes(32, "big")
    tx(apdu(INS_PUT_DATA, 0x00, 0xC2, ATTR_P256_ECDH), "PUT DEC algo-attr (C2, P-256 ECDH)")
    tx(import_apdu(CRT_DEC, dec_scalar), "IMPORT P-256 DEC key")

    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    z, _, _ = tx(decipher_apdu(eph_pub), "PSO:DECIPHER (P-256 ECDH)")
    z = bytes(z)
    expected = dec_priv.exchange(ec.ECDH(), eph_priv.public_key())
    if z != expected:
        fail(f"ECDH shared secret mismatch:\n  card={z.hex()}\n  host={expected.hex()}")
    print("  P-256 ECDH shared secret MATCHES host")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
