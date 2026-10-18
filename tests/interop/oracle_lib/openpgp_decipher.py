# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""RSA padding and ECDH input grammar keep the DEC key and grant usable."""
from enum import Enum
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519

from . import codec
from .card_keys import PGP_ALGORITHMS
from .openpgp_operations import operation_key

ALGORITHMS = tuple(value for value in PGP_ALGORITHMS if value != "ED25519")


class RsaInput(Enum):
    INDICATOR = "indicator"
    PLAINTEXT = "plaintext"
    EMPTY = "empty"
    WIDTH = "width"
    INTEGER = "integer"
    BLOCK_TYPE = "wrong-block-type"
    LEADING_BYTE = "nonzero-leading-byte"
    DELIMITER = "missing-delimiter"
    PADDING_LENGTH = "padding-too-short"


def rsa_inputs(width):
    for value in (0, 1, 3, 127, 255):
        yield f"indicator-{value}", RsaInput.INDICATOR, value
    for size in (0, 1, width - 12, width - 11):
        yield f"plaintext-size-{size}", RsaInput.PLAINTEXT, size
    yield "empty", RsaInput.EMPTY, None
    for size in (0, 1, width - 1, width + 1):
        yield f"ciphertext-width-{size}", RsaInput.WIDTH, size
    for label, value in (("0", 0), ("1", 1), ("modulus-minus-one", -1), ("modulus", None)):
        yield "ciphertext-integer-" + label, RsaInput.INTEGER, value
    for kind in (RsaInput.BLOCK_TYPE, RsaInput.LEADING_BYTE, RsaInput.DELIMITER, RsaInput.PADDING_LENGTH):
        yield kind.value, kind, None


def peer_for(session, private):
    if isinstance(private, x25519.X25519PrivateKey):
        peer = x25519.X25519PrivateKey.from_private_bytes(session.fixture("OpenPGP.DEC.peer"))
        encoded = peer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        peer = ec.derive_private_key(312, private.curve)
        encoded = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return peer, encoded


def wrapped(point):
    return codec.tlv(0xa6, codec.tlv(0x7f49, codec.tlv(0x86, point)))


def point_vectors(point, montgomery):
    base = wrapped(point)
    yield "valid", base, 0x9000
    yield "empty", b"", 0x6a80
    yield "missing-container", codec.tlv(0x86, point), 0x6a80
    yield "missing-public-template", codec.tlv(0xa6, codec.tlv(0x86, point)), 0x6a80
    yield "missing-point", codec.tlv(0xa6, codec.tlv(0x7f49, b"")), 0x6a80
    yield "wrong-point-tag", codec.tlv(0xa6, codec.tlv(0x7f49, codec.tlv(0x85, point))), 0x6a80
    yield "unknown-before-point", codec.tlv(0xa6, codec.tlv(0x7f49, codec.tlv(0x99, b"x") + codec.tlv(0x86, point))), 0x6a80
    yield "truncated-point", base[:-1], 0x6a80
    yield "point-empty", wrapped(b""), 0x6a80
    yield "point-short", wrapped(point[:-1]), 0x6a80
    yield "point-long", wrapped(point + b"x"), 0x6a80
    yield "trailing-unknown", base + codec.tlv(0x99, b"ignored"), 0x9000
    yield "outer-zero-length", b"\xa6\x00" + codec.tlv(0x7f49, codec.tlv(0x86, point)), 0x9000
    yield "inner-zero-length", codec.tlv(0xa6, b"\x7f\x49\x00" + codec.tlv(0x86, point)), 0x9000
    yield "duplicate-point", codec.tlv(0xa6, codec.tlv(0x7f49, codec.tlv(0x86, point) * 2)), 0x9000
    if montgomery:
        for value in (0, 1):
            yield f"low-order-{value}", wrapped(value.to_bytes(32, "little")), 0x6581
    else:
        yield "compressed", wrapped(bytes([2 | (point[-1] & 1)]) + point[1:1 + (len(point) - 1) // 2]), 0x6a80
        yield "compact", wrapped(point[1:]), 0x6a80
        yield "infinity", wrapped(b"\x00"), 0x6a80
        yield "off-curve", wrapped(b"\x04" + bytes(len(point) - 1)), 0x6581
        yield "outside-field", wrapped(b"\x04" + b"\xff" * (len(point) - 1)), 0x6581


def rsa_vectors(private, plaintext):
    public = private.public_key().public_numbers()
    width = private.key_size // 8
    encrypted = private.public_key().encrypt(plaintext, padding.PKCS1v15())
    pads = {
        RsaInput.BLOCK_TYPE: b"\x00\x01" + b"\x01" * (width - 3) + b"\x00",
        RsaInput.LEADING_BYTE: b"\x01\x02" + b"\x01" * (width - 3) + b"\x00",
        RsaInput.DELIMITER: b"\x00\x02" + b"\x01" * (width - 2),
        RsaInput.PADDING_LENGTH: b"\x00\x02" + b"\x01" * 7 + b"\x00" + b"p" * (width - 10),
    }
    for label, kind, value in rsa_inputs(width):
        status, expected = 0x6581, None
        if kind == RsaInput.INDICATOR:
            body, status, expected = bytes([value]) + encrypted, 0x9000, plaintext
        elif kind == RsaInput.PLAINTEXT:
            expected = bytes(index % 251 for index in range(value))
            body, status = b"\x00" + private.public_key().encrypt(expected, padding.PKCS1v15()), 0x9000
        elif kind == RsaInput.EMPTY:
            body, status = b"", 0x6a80
        elif kind == RsaInput.WIDTH:
            body = b"\x00" + encrypted[:value].ljust(value, b"x")
        elif kind == RsaInput.INTEGER:
            integer = public.n if value is None else public.n - 1 if value == -1 else value
            body = b"\x00" + integer.to_bytes(width, "big")
        else:
            body = b"\x00" + pow(int.from_bytes(pads[kind], "big"), public.e, public.n).to_bytes(width, "big")
        yield label, body, status, expected


def run(session):
    from yubikit.openpgp import KEY_REF
    for algorithm in ALGORITHMS:
        labels = (label for label, _, _ in rsa_inputs(int(algorithm[3:]) // 8)) if algorithm.startswith("RSA") else (label for label, _, _ in point_vectors(bytes([4]) + bytes(64), algorithm == "X25519"))
        for label in labels:
            with session.case(f"openpgp.DECIPHER.{algorithm}.{label}", ("O02", "O10", "O13", "O14", "O22", "G01", "G03", "G04", "G07", "G10", "G13", "G14"), effects=("replace_openpgp_keys", "config_change"), touch=True,
                    parameters={"algorithm": algorithm, "defect": label}):
                with operation_key(session, KEY_REF.DEC, algorithm) as (sdk, private):
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    before = sdk.get_signature_counter()
                    if isinstance(private, rsa.RSAPrivateKey):
                        expected_plain = session.fixture("OpenPGP.DEC.plaintext", 16)
                        vectors = rsa_vectors(private, expected_plain)
                        control = b"\x00" + private.public_key().encrypt(expected_plain, padding.PKCS1v15())
                    else:
                        peer, point = peer_for(session, private)
                        expected_plain = peer.exchange(private.public_key()) if isinstance(peer, x25519.X25519PrivateKey) else peer.exchange(ec.ECDH(), private.public_key())
                        vectors = ((name, value, status, expected_plain) for name, value, status in point_vectors(point, isinstance(private, x25519.X25519PrivateKey)))
                        control = wrapped(point)
                    _, body, status, expected_result = next(value for value in vectors if value[0] == label)
                    result = session.apdu(codec.apdu(0x2a, 0x80, 0x86, body))
                    session.check("DECIPHER grammar, point and padding refusals are distinct", result.status, status)
                    if status == 0x9000:
                        session.check("accepted DECIPHER independently recovers the exact shared secret or plaintext", session.card_value(result), expected_result)
                    else:
                        session.check("refused DECIPHER emits no private bytes", result.data[:-2], b"")
                    session.check("DECIPHER never advances the signature counter", sdk.get_signature_counter(), before)
                    session.check("DECIPHER refusal preserves PW1.82 status", session.apdu(codec.apdu(0x20, p2=0x82)).status, 0x9000)
                    session.check("valid DECIPHER after refusal retains the exact private key", session.card_value(session.apdu(codec.apdu(0x2a, 0x80, 0x86, control))), expected_plain)
