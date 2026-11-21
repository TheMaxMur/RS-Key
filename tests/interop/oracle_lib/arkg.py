# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Public ARKG-P256 derivation for previewSign v4, checked against draft vectors."""
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
FIELD = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


def scalar(message, domain):
    if len(message) > 32 or len(domain) > 255:
        raise ValueError("ARKG input exceeds profile bounds")
    dst = domain + bytes([len(domain)])
    base = hashlib.sha256(bytes(64) + message + b"\x00\x30\x00" + dst).digest()
    first = hashlib.sha256(base + b"\x01" + dst).digest()
    second = hashlib.sha256(bytes(a ^ b for a, b in zip(base, first)) + b"\x02" + dst).digest()
    return int.from_bytes((first + second)[:48], "big") % ORDER


def encoded(point):
    from cryptography.hazmat.primitives import serialization
    return point.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def derive(blinding, kem, ikm, context):
    if len(context) > 64:
        raise ValueError("ARKG context exceeds 64 bytes")
    private = ec.derive_private_key(scalar(ikm, b"ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256"), ec.SECP256R1())
    ephemeral = encoded(private.public_key())
    shared = private.exchange(ec.ECDH(), kem)
    kem_context = b"ARKG-Derive-Key-KEM." + bytes([len(context)]) + context
    def expand(label):
        return HKDF(hashes.SHA256(), 32, b"", label + b"ARKG-ECDH.ARKG-P256" + kem_context).derive(shared)
    mac_key, secret = expand(b"ARKG-KEM-HMAC-mac."), expand(b"ARKG-KEM-HMAC-shared.")
    handle = hmac.digest(mac_key, ephemeral, "sha256")[:16] + ephemeral
    factor = scalar(secret, b"ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL." + bytes([len(context)]) + context)
    a = blinding.public_numbers()
    b = ec.derive_private_key(factor, ec.SECP256R1()).public_key().public_numbers()
    if a.x == b.x:
        if a.y != b.y:
            raise ValueError("ARKG produced point at infinity")
        slope = ((3 * a.x * a.x - 3) * pow(2 * a.y, -1, FIELD)) % FIELD
    else:
        slope = ((b.y - a.y) * pow(b.x - a.x, -1, FIELD)) % FIELD
    x = (slope * slope - a.x - b.x) % FIELD
    y = (slope * (a.x - x) - a.y) % FIELD
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(), handle
