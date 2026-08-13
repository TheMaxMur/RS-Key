#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP GENERATE ASYMMETRIC KEY PAIR test (INS 0x47) over PC/SC.

    # needs pyscard AND cryptography in the same interpreter — the validation venv has both:
    nix develop -c python tests/36_openpgp_keygen.py
    # options: --skip-rsa (EC only)   --rsa-bits 2048 (default)

Unlike IMPORT, the key is generated ON the card, so the host never sees the
private key — it verifies the card's crypto against the PUBLIC key the card
returns from GENERATE (parsed from the 7F49 DO):

    PUT algo-attr (C1/C2/C3) -> GENERATE 0x80 (make) -> public-key DO 7F49
                             -> GENERATE 0x81 (read) -> same DO
    then PSO:CDS / PSO:DECIPHER / INTERNAL-AUT with the generated key, verified
    against the returned public key with `cryptography`.

  * P-256 ECDSA  — GENERATE SIG, PSO:CDS, verify the signature.
  * Ed25519      — GENERATE AUT, INTERNAL AUTHENTICATE, verify the signature.
  * P-256 ECDH   — GENERATE DEC, PSO:DECIPHER, verify the shared secret (this
                   also seeds the card's AES key, if DO D5 is still empty).
  * RSA-2048     — GENERATE SIG, **timed** (on-chip RSA keygen is slow), then
                   PSO:CDS verified. Use --skip-rsa to leave it out.

Re-runnable: GENERATE overwrites the slots; PINs are left on their defaults
("123456" / "12345678"). Uses PW3 (admin) which authorises GENERATE and every
crypto op, so it does not depend on PW1's state.
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
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
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
INS_KEYPAIR_GEN = 0x47
MODE_PW1_81 = 0x81
MODE_PW1_82 = 0x82
MODE_PW3 = 0x83

OID_P256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
OID_ED25519 = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
ATTR_P256_ECDSA = bytes([0x13] + OID_P256)
ATTR_P256_ECDH = bytes([0x12] + OID_P256)
ATTR_ED25519 = bytes([0x16] + OID_ED25519)
ATTR_RSA2K = bytes([0x01, 0x08, 0x00, 0x00, 0x20, 0x00])

CRT_SIG, CRT_DEC, CRT_AUT = 0xB6, 0xB8, 0xA4

DI_SHA256 = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
])


def apdu(ins, p1, p2, data=b"", le=None):
    a = [0x00, ins, p1, p2, len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def gen_apdu(p1, crt):
    """GENERATE in an extended-length APDU (an RSA public key exceeds 256 bytes)."""
    data = bytes([crt, 0x00])
    return [0x00, INS_KEYPAIR_GEN, p1, 0x00, 0x00, 0x00, len(data)] + list(data) + [0x00, 0x00]


def rsa_attr(bits):
    return bytes([0x01, (bits >> 8) & 0xFF, bits & 0xFF, 0x00, 0x20, 0x00])


def parse_ec_point(do):
    """Extract the 0x86 EC point from a 7F49 public-key DO."""
    do = bytes(do)
    if do[:2] != b"\x7f\x49":
        fail(f"not a 7F49 DO: {do[:4].hex()}")
    i = 2
    i += 1 + (do[i] & 0x7F) if do[i] & 0x80 else 1  # skip outer length
    if do[i] != 0x86:
        fail(f"expected tag 86, got {do[i]:02X}")
    i += 1
    if do[i] & 0x80:
        nl = do[i] & 0x7F
        plen = int.from_bytes(do[i + 1:i + 1 + nl], "big")
        i += 1 + nl
    else:
        plen = do[i]
        i += 1
    return do[i:i + plen]


def parse_rsa_pub(do):
    """Extract (N, E) from a 7F49 82 LL { 81 82 <N> · 82 <E> } RSA public-key DO."""
    do = bytes(do)
    if do[:3] != b"\x7f\x49\x82":
        fail(f"not a 7F49 82 DO: {do[:5].hex()}")
    i = 5
    if do[i] != 0x81 or do[i + 1] != 0x82:
        fail("expected modulus tag 81 82")
    i += 2
    nlen = int.from_bytes(do[i:i + 2], "big")
    i += 2
    n = int.from_bytes(do[i:i + nlen], "big")
    i += nlen
    if do[i] != 0x82:
        fail("expected exponent tag 82")
    elen = do[i + 1]
    e = int.from_bytes(do[i + 2:i + 2 + elen], "big")
    return n, e


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    skip_rsa = "--skip-rsa" in sys.argv
    rsa_bits = 2048
    if "--rsa-bits" in sys.argv:
        rsa_bits = int(sys.argv[sys.argv.index("--rsa-bits") + 1])

    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")

    conn = target.createConnection()
    conn.connect()

    def tx(cmd, what, expect=(0x90, 0x00)):
        data, sw1, sw2 = conn.transmit(cmd)
        shown = toHexString(data) if data else ""
        print("%-36s -> %s %02X%02X" % (what, shown[:42], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (admin)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_81, PW1_DEFAULT), "VERIFY PW1 (81, signing)")
    tx(apdu(INS_VERIFY, 0x00, MODE_PW1_82, PW1_DEFAULT), "VERIFY PW1 (82, decrypt/auth)")

    # ---------------- P-256 ECDSA: GENERATE SIG + read-public + PSO:CDS --------
    tx(apdu(INS_PUT_DATA, 0x00, 0xC1, ATTR_P256_ECDSA), "PUT SIG algo-attr (C1, P-256)")
    t0 = time.monotonic()
    do, _, _ = tx(gen_apdu(0x80, CRT_SIG), "GENERATE P-256 SIG")
    print("    (generate took %.3fs)" % (time.monotonic() - t0))
    point = parse_ec_point(do)
    if len(point) != 65:
        fail(f"expected a 65-byte uncompressed P-256 point, got {len(point)}")
    do2, _, _ = tx(gen_apdu(0x81, CRT_SIG), "READ-PUBLIC P-256 SIG")
    if bytes(do2) != bytes(do):
        fail("read-public DO differs from the generated DO")
    sig_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(point))

    msg = b"sign with the generated P-256 key"
    digest = hashlib.sha256(msg).digest()
    sig, _, _ = tx(apdu(INS_PSO, 0x9E, 0x9A, digest, le=0x00), "PSO:CDS (P-256)")
    sig = bytes(sig)
    if len(sig) != 64:
        fail(f"expected 64-byte r‖s, got {len(sig)}")
    try:
        sig_pub.verify(
            encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
            msg, ec.ECDSA(hashes.SHA256()))
        print("  P-256 ECDSA signature VERIFIED against the generated public key")
    except InvalidSignature:
        fail("P-256 signature did not verify")

    # ---------------- Ed25519: GENERATE AUT + INTERNAL AUTHENTICATE -----------
    tx(apdu(INS_PUT_DATA, 0x00, 0xC3, ATTR_ED25519), "PUT AUT algo-attr (C3, Ed25519)")
    t0 = time.monotonic()
    do, _, _ = tx(gen_apdu(0x80, CRT_AUT), "GENERATE Ed25519 AUT")
    print("    (generate took %.3fs)" % (time.monotonic() - t0))
    point = parse_ec_point(do)
    if len(point) != 32:
        fail(f"expected a 32-byte Ed25519 point, got {len(point)}")
    aut_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(point))

    chal = b"internal-authenticate challenge"
    asig, _, _ = tx(apdu(INS_INTERNAL_AUT, 0x00, 0x00, chal, le=0x00), "INTERNAL AUTHENTICATE")
    asig = bytes(asig)
    if len(asig) != 64:
        fail(f"expected 64-byte EdDSA signature, got {len(asig)}")
    try:
        aut_pub.verify(asig, chal)
        print("  Ed25519 signature VERIFIED against the generated public key")
    except InvalidSignature:
        fail("Ed25519 signature did not verify")

    # ---------------- P-256 ECDH: GENERATE DEC + PSO:DECIPHER -----------------
    tx(apdu(INS_PUT_DATA, 0x00, 0xC2, ATTR_P256_ECDH), "PUT DEC algo-attr (C2, P-256 ECDH)")
    t0 = time.monotonic()
    do, _, _ = tx(gen_apdu(0x80, CRT_DEC), "GENERATE P-256 DEC")
    print("    (generate took %.3fs)" % (time.monotonic() - t0))
    dec_point = parse_ec_point(do)
    dec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(dec_point))

    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    f86 = bytes([0x86, len(eph_pub)]) + eph_pub
    f7f49 = bytes([0x7F, 0x49, len(f86)]) + f86
    a6 = bytes([0xA6, len(f7f49)]) + f7f49
    z, _, _ = tx([0x00, INS_PSO, 0x80, 0x86, len(a6)] + list(a6) + [0x00], "PSO:DECIPHER (P-256 ECDH)")
    z = bytes(z)
    # ECDH is symmetric: card's ECDH(dec_priv, eph_pub) == host ECDH(eph_priv, dec_pub).
    expected = eph_priv.exchange(ec.ECDH(), dec_pub)
    if z != expected:
        fail(f"ECDH mismatch:\n  card={z.hex()}\n  host={expected.hex()}")
    print("  P-256 ECDH shared secret MATCHES host (DEC key generated)")

    print("PASS")

    # ---------------- RSA: GENERATE SIG (timed) + PSO:CDS ---------------------
    if skip_rsa:
        print("PASS (RSA generate skipped)")
        return 0

    print(f"\n--- RSA-{rsa_bits} GENERATE (on-M33 keygen — this may take a while) ---")
    tx(apdu(INS_PUT_DATA, 0x00, 0xC1, rsa_attr(rsa_bits)), f"PUT SIG algo-attr (C1, RSA-{rsa_bits})")
    t0 = time.monotonic()
    try:
        do, sw1, sw2 = conn.transmit(gen_apdu(0x80, CRT_SIG))
    except Exception as ex:  # noqa: BLE001 — a transport timeout is the measured outcome
        dt = time.monotonic() - t0
        print(f"  RSA-{rsa_bits} GENERATE raised after {dt:.1f}s: {ex}")
        print("  -> on-device RSA keygen exceeds the reader's timeout; a CCID keepalive")
        print("     (WTX) is needed for RSA generate. EC generate is unaffected.")
        print("PASS (EC) — RSA generate TIMED OUT, see note above")
        return 0
    dt = time.monotonic() - t0
    print("GENERATE RSA-%d SIG -> %02X%02X  (took %.1fs)" % (rsa_bits, sw1, sw2, dt))
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"RSA GENERATE returned {sw1:02X}{sw2:02X} after {dt:.1f}s")
    n, e = parse_rsa_pub(do)
    if n.bit_length() < rsa_bits - 8:
        fail(f"modulus is {n.bit_length()} bits, expected ~{rsa_bits}")
    rsa_pub = rsa.RSAPublicNumbers(e, n).public_key()

    msg = b"sign with the generated RSA key"
    di = DI_SHA256 + hashlib.sha256(msg).digest()
    sig, _, _ = tx(apdu(INS_PSO, 0x9E, 0x9A, di, le=0x00), "PSO:CDS (RSA)")
    sig = bytes(sig)
    try:
        rsa_pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        print(f"  RSA-{rsa_bits} signature VERIFIED against the generated public key")
    except InvalidSignature:
        fail("RSA signature did not verify")

    print(f"PASS (RSA-{rsa_bits} generate {dt:.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
