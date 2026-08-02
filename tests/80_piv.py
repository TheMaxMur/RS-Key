#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV applet test — drive the PIV application over PC/SC the way `ykman
piv` / `yubico-piv-tool` do, verifying every crypto result host-side.

Covers: SELECT (APT), GET VERSION / GET SERIAL, PIN verify + retry counter,
GENERAL AUTHENTICATE management-key mutual auth (default AES-192 key),
GENERATE for P-256 / P-384 (+ optional RSA-2048), sign + ECDSA-verify against
the returned public key, ECDH (calculate_secret) on the key-management slot,
GET METADATA, the certificate object (70/71/FE wrapper, self-signature checked),
ATTESTATION (chains to the F9 cert), PUT/GET DATA object round-trip, CHANGE PIN
and a final factory RESET that requires both PIN and PUK blocked.

Idempotent: a RESET at the end returns the applet to defaults. PIV files are
disjoint from FIDO / OpenPGP / OATH / OTP, so those are untouched — but the
final RESET only fires once both references are blocked (the test blocks them
deliberately), so re-runs start clean.

Run from the venv that has pyscard + cryptography:

    nix develop -c python tests/80_piv.py

Flags: --skip-rsa (default; RSA-2048 generate is ~20 s), --rsa to include it.
"""
import os
import sys

try:
    from smartcard.Exceptions import NoCardException
except ImportError:
    sys.exit("missing dependency: pip install pyscard")
try:
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.x509 import load_der_x509_certificate
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

PIV_AID = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]

INS_VERIFY, INS_CHANGE_PIN, INS_RESET_RETRY = 0x20, 0x24, 0x2C
INS_GENERATE, INS_AUTH = 0x47, 0x87
INS_GET_DATA, INS_PUT_DATA = 0xCB, 0xDB
INS_GET_METADATA, INS_YK_SERIAL, INS_ATTEST = 0xF7, 0xF8, 0xF9
INS_SET_RETRIES, INS_RESET, INS_VERSION, INS_IMPORT = 0xFA, 0xFB, 0xFD, 0xFE
INS_SET_MGM = 0xFF

ALGO_RSA2048, ALGO_ECCP256, ALGO_ECCP384 = 0x07, 0x11, 0x14
DEFAULT_PIN = b"123456\xff\xff"
DEFAULT_PUK = b"12345678"
DEFAULT_MGM = bytes([1, 2, 3, 4, 5, 6, 7, 8] * 3)

SLOT_9A, SLOT_9C, SLOT_9D, SLOT_9E = 0x9A, 0x9C, 0x9D, 0x9E
OBJ_9A = [0x5F, 0xC1, 0x05]   # 5FC105 cert object for slot 9A
OBJ_CHUID = [0x5F, 0xC1, 0x02]
OBJ_ATTEST = [0x5F, 0xFF, 0x01]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def tlv(tag, value):
    if len(value) < 0x80:
        ln = bytes([len(value)])
    elif len(value) < 0x100:
        ln = bytes([0x81, len(value)])
    else:
        ln = bytes([0x82, len(value) >> 8, len(value) & 0xFF])
    return bytes([tag]) + ln + bytes(value)


def parse_tlv(data):
    """Flat one-level TLV parse → dict{tag: value} (1-byte tags only)."""
    out, i = {}, 0
    data = bytes(data)
    while i < len(data):
        tag = data[i]
        i += 1
        ln = data[i]
        i += 1
        if ln == 0x81:
            ln = data[i]
            i += 1
        elif ln == 0x82:
            ln = (data[i] << 8) | data[i + 1]
            i += 2
        out[tag] = data[i:i + ln]
        i += ln
    return out


class Piv:
    def __init__(self, conn):
        self.conn = conn

    def raw(self, ins, p1, p2, data=b"", le=False):
        cmd = [0x00, ins, p1, p2]
        if data:
            if len(data) < 256:
                cmd += [len(data)] + list(data)
            else:
                cmd += [0, len(data) >> 8, len(data) & 0xFF] + list(data)
        elif le:
            cmd += [0x00]
        resp, sw1, sw2 = self.conn.transmit(cmd)
        body = bytes(resp)
        sw = (sw1 << 8) | sw2
        # Drain 61xx (more data) — pyscard's reader may not auto-GET-RESPONSE.
        while sw1 == 0x61:
            r2, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            body += bytes(r2)
            sw = (sw1 << 8) | sw2
        return body, sw

    def apdu(self, ins, p1, p2, data=b"", want=0x9000, le=False):
        body, sw = self.raw(ins, p1, p2, data, le)
        if want is not None and sw != want:
            fail(f"INS {ins:02X} P1={p1:02X} P2={p2:02X}: SW {sw:04X} != {want:04X}")
        return body, sw

    def select(self):
        resp, sw1, sw2 = self.conn.transmit(
            [0x00, 0xA4, 0x04, 0x00, len(PIV_AID)] + PIV_AID
        )
        sw = (sw1 << 8) | sw2
        if sw == 0x6A82:
            fail("PIV AID not found — device runs firmware without the PIV applet?")
        if sw != 0x9000:
            fail(f"SELECT PIV: SW {sw:04X}")
        return bytes(resp)

    def auth_mgm(self):
        # Mutual auth against the default AES-192 management key (algo 0x0A).
        resp, _ = self.apdu(INS_AUTH, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, b"")))
        wit = parse_tlv(parse_tlv(resp)[0x7C])[0x80]
        dec = Cipher(algorithms.AES(DEFAULT_MGM), modes.ECB()).decryptor()
        witness = dec.update(wit) + dec.finalize()
        challenge = os.urandom(16)
        body = tlv(0x7C, tlv(0x80, witness) + tlv(0x81, challenge))
        resp, _ = self.apdu(INS_AUTH, 0x0A, 0x9B, body)
        enc_chal = parse_tlv(parse_tlv(resp)[0x7C])[0x82]
        want = Cipher(algorithms.AES(DEFAULT_MGM), modes.ECB()).encryptor()
        if enc_chal != want.update(challenge) + want.finalize():
            fail("management-key mutual auth: card response mismatch")

    def verify_pin(self, pin=DEFAULT_PIN, want=0x9000):
        return self.apdu(INS_VERIFY, 0x00, 0x80, pin, want=want)

    def generate(self, slot, algo):
        body, _ = self.apdu(INS_GENERATE, 0x00, slot, tlv(0xAC, tlv(0x80, [algo])), le=True)
        return parse_tlv(body)[0x7F49] if 0x7F49 in parse_tlv(body) else body

    def slot_public_point(self, slot, algo):
        body, _ = self.apdu(INS_GENERATE, 0x00, slot, tlv(0xAC, tlv(0x80, [algo])), le=True)
        # 7F49 has a 2-byte tag; parse manually.
        b = bytes(body)
        assert b[0] == 0x7F and b[1] == 0x49
        inner = parse_tlv(b[3:] if b[2] < 0x80 else b[4:])
        return inner[0x86]


def curve_for(algo):
    return ec.SECP256R1() if algo == ALGO_ECCP256 else ec.SECP384R1()


def hash_for(algo):
    return hashes.SHA256() if algo == ALGO_ECCP256 else hashes.SHA384()


def test_sign(piv, slot, algo, point):
    piv.verify_pin()
    msg = b"rs-key PIV sign test"
    digest_algo = hash_for(algo)
    h = hashes.Hash(digest_algo)
    h.update(msg)
    digest = h.finalize()
    body = tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest))
    resp, _ = piv.apdu(INS_AUTH, algo, slot, body, le=True)
    sig = parse_tlv(parse_tlv(resp)[0x7C])[0x82]
    pub = ec.EllipticCurvePublicKey.from_encoded_point(curve_for(algo), point)
    # Prehashed verify takes the digest, not the message.
    pub.verify(sig, digest, ec.ECDSA(utils.Prehashed(digest_algo)))
    print(f"  slot {slot:02X} {('P-256' if algo==ALGO_ECCP256 else 'P-384')}: sign+verify OK")


def test_ecdh(piv, slot, point):
    piv.verify_pin()
    host = ec.generate_private_key(ec.SECP256R1())
    host_pub = host.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    body = tlv(0x7C, tlv(0x82, b"") + tlv(0x85, host_pub))
    resp, _ = piv.apdu(INS_AUTH, ALGO_ECCP256, slot, body, le=True)
    shared = parse_tlv(parse_tlv(resp)[0x7C])[0x82]
    card_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    want = host.exchange(ec.ECDH(), card_pub)
    if shared != want:
        fail("ECDH shared secret mismatch")
    print(f"  slot {slot:02X} ECDH: shared secret matches host")


def test_cert_object(piv, point):
    obj, _ = piv.apdu(INS_GET_DATA, 0x3F, 0xFF, tlv(0x5C, OBJ_9A), le=True)
    body = parse_tlv(obj)[0x53]
    fields = parse_tlv(body)
    cert_der = fields[0x70]
    if fields.get(0x71) != b"\x00":
        fail("cert object CertInfo != 0 (expected uncompressed)")
    cert = load_der_x509_certificate(cert_der)
    cn = cert.subject.rfc4514_string()
    if "RS-Key PIV Slot 9A" not in cn:
        fail(f"unexpected cert subject: {cn}")
    # Self-signature verifies against the slot public key.
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    pub.verify(cert.signature, cert.tbs_certificate_bytes,
               ec.ECDSA(cert.signature_hash_algorithm))
    print("  cert object: 70/71/FE wrapper + self-signature OK")


def test_attestation(piv):
    att, _ = piv.apdu(INS_ATTEST, SLOT_9A, 0x00, le=True)
    att_cert = load_der_x509_certificate(bytes(att))
    if "Attestation 9A" not in att_cert.subject.rfc4514_string():
        fail("attestation subject wrong")
    if "Slot F9" not in att_cert.issuer.rfc4514_string():
        fail("attestation issuer is not the F9 key")
    # F9 cert from its object, verify the chain.
    f9obj, _ = piv.apdu(INS_GET_DATA, 0x3F, 0xFF, tlv(0x5C, OBJ_ATTEST), le=True)
    f9der = parse_tlv(parse_tlv(f9obj)[0x53])[0x70]
    f9 = load_der_x509_certificate(f9der)
    f9.public_key().verify(att_cert.signature, att_cert.tbs_certificate_bytes,
                           ec.ECDSA(att_cert.signature_hash_algorithm))
    # Yubico statement OIDs present.
    oids = {e.oid.dotted_string for e in att_cert.extensions}
    for o in ("1.3.6.1.4.1.41482.3.3", "1.3.6.1.4.1.41482.3.7",
              "1.3.6.1.4.1.41482.3.8", "1.3.6.1.4.1.41482.3.9"):
        if o not in oids:
            fail(f"attestation missing Yubico OID {o}")
    print("  attestation: chains to F9 + Yubico extensions present")


def test_objects(piv):
    chuid = bytes([0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED])
    piv.apdu(INS_PUT_DATA, 0x3F, 0xFF, tlv(0x5C, OBJ_CHUID) + tlv(0x53, chuid))
    got, _ = piv.apdu(INS_GET_DATA, 0x3F, 0xFF, tlv(0x5C, OBJ_CHUID), le=True)
    if parse_tlv(got)[0x53] != chuid:
        fail("CHUID object round-trip mismatch")
    print("  PUT/GET DATA object: round-trip OK")


def test_rsa(piv):
    print("  RSA-2048 generate (slow ~20 s)…", flush=True)
    body, _ = piv.apdu(INS_GENERATE, 0x00, SLOT_9C, tlv(0xAC, tlv(0x80, [ALGO_RSA2048])), le=True)
    b = bytes(body)
    inner = parse_tlv(b[3:] if b[2] < 0x80 else (b[4:] if b[2] == 0x81 else b[5:]))
    n = int.from_bytes(inner[0x81], "big")
    e = int.from_bytes(inner[0x82], "big")
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    pub = rsa_mod.RSAPublicNumbers(e, n).public_key()
    piv.verify_pin()
    msg = b"rs-key PIV RSA"
    h = hashes.Hash(hashes.SHA256())
    h.update(msg)
    digest = h.finalize()
    di = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    em = b"\x00\x01" + b"\xff" * (256 - 3 - len(di)) + b"\x00" + di
    body = tlv(0x7C, tlv(0x82, b"") + tlv(0x81, em))
    resp, _ = piv.apdu(INS_AUTH, ALGO_RSA2048, SLOT_9C, body, le=True)
    sig = parse_tlv(parse_tlv(resp)[0x7C])[0x82]
    pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    print("  slot 9C RSA-2048: generate + sign + verify OK")


def block_and_reset(piv):
    # Block PIN then PUK, then RESET (the only path that wipes PIV state).
    for _ in range(8):
        _, sw = piv.verify_pin(b"00000000", want=None)
    bad = b"00000000" + b"99999999"
    for _ in range(8):
        piv.raw(INS_RESET_RETRY, 0x00, 0x80, bad)
    _, sw = piv.apdu(INS_RESET, 0x00, 0x00, want=None)
    if sw != 0x9000:
        fail(f"RESET after blocking both references: SW {sw:04X}")
    piv.verify_pin(DEFAULT_PIN)  # default PIN works again
    print("  factory RESET: defaults restored")


def main():
    do_rsa = "--rsa" in sys.argv
    # Marker required: this blocks both PIN references and factory-RESETs the applet,
    # and the old matcher also accepted "Yubico"/"PIV" — i.e. a real YubiKey's PIV.
    target = find_reader(require_marker=True)
    if target is None:
        fail("no RSK CCID reader found (gpgconf --kill scdaemon if held)")
    try:
        conn = target.createConnection()
        conn.connect()
    except NoCardException:
        fail(f"{target} has no card powered on")

    piv = Piv(conn)
    piv.select()
    print("SELECT PIV OK")

    ver, _ = piv.apdu(INS_VERSION, 0, 0, le=True)
    if bytes(ver) != b"\x05\x07\x04":
        fail(f"version {bytes(ver).hex()} != 050704")
    serial, _ = piv.apdu(INS_YK_SERIAL, 0, 0, le=True)
    print(f"  version 5.7.4, serial {int.from_bytes(serial, 'big')}")

    # Retry counter on a fresh applet (default PIN, 3 tries).
    _, sw = piv.verify_pin(b"", want=None)
    if sw & 0xFFF0 != 0x63C0:
        fail(f"retry query SW {sw:04X} not 63Cx")
    print(f"  PIN retry counter: {sw & 0xF} remaining")

    piv.auth_mgm()
    print("management-key mutual auth OK")

    for slot, algo in ((SLOT_9A, ALGO_ECCP256), (SLOT_9E, ALGO_ECCP384)):
        point = piv.slot_public_point(slot, algo)
        test_sign(piv, slot, algo, point)
        md, _ = piv.apdu(INS_GET_METADATA, 0x00, slot, le=True)
        fields = parse_tlv(md)
        if fields[0x01][0] != algo:
            fail("metadata algorithm mismatch")
        if 0x04 not in fields:
            fail("metadata missing public key (tag 04)")
    print("GET METADATA OK")

    point_9a = piv.slot_public_point(SLOT_9A, ALGO_ECCP256)
    test_cert_object(piv, point_9a)
    test_attestation(piv)

    point_9d = piv.slot_public_point(SLOT_9D, ALGO_ECCP256)
    test_ecdh(piv, SLOT_9D, point_9d)

    test_objects(piv)

    if do_rsa:
        test_rsa(piv)
    else:
        print("  (RSA-2048 skipped; pass --rsa to include it)")

    # CHANGE PIN round-trip then restore.
    piv.apdu(INS_CHANGE_PIN, 0x00, 0x80, DEFAULT_PIN + b"654321\xff\xff")
    piv.verify_pin(b"654321\xff\xff")
    piv.apdu(INS_CHANGE_PIN, 0x00, 0x80, b"654321\xff\xff" + DEFAULT_PIN)
    print("CHANGE PIN OK")

    block_and_reset(piv)

    print("\nPASS" + (" (incl. RSA-2048)" if do_rsa else ""))


if __name__ == "__main__":
    main()
