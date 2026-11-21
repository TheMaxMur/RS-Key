# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""ATT_IMPORT validates DER framing; chain trust and key coherence are separate."""
import hashlib
from itertools import product

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .fido import info, u2f_apdu, verified
from .fido_fixtures import credential
from .vendor_cases import handshake, vendor
from .vendor_lifecycle import identity_fixture, wrap
from .vendor_matrix import authenticated

MAX_CERTS = 4
MAX_CHAIN = 2200 - (1 + 1 + 2 + 60 + 1 + 3)


def sequence(total):
    width = 0 if total <= 129 else 1 if total <= 258 else 2
    payload = total - 2 - width
    header = bytes([payload]) if width == 0 else bytes([0x80 | width]) + payload.to_bytes(width, "big")
    return b"\x30" + header + bytes(payload)


def parts(data):
    result = []
    while data:
        length = data[1]
        header = 2
        if length & 128:
            width = length & 127
            header += width
            length = int.from_bytes(data[2:header], "big")
        result.append(data[:header + length])
        data = data[header + length:]
    return result


def commitment(chain):
    certs = parts(chain)
    return hashlib.sha256(bytes([len(certs)]) + b"".join(len(cert).to_bytes(2, "little") + cert for cert in certs)).digest()


def identity_control(session, private, chain):
    state = session.ctap_value(vendor(session, 11))
    session.check("organization identity has the exact packed-chain commitment", state, {1: True, 2: commitment(chain)})
    challenge, application = session.fixture("chain.registration.challenge"), session.fixture("chain.registration.application")
    raw = session.card_value(session.hid_call(3, u2f_apdu(1, data=challenge + application)))
    session.check("organization U2F registration has its marker and public point", raw[:2], b"\x05\x04")
    key_end = 67 + raw[66]
    handle, point, leaf = raw[67:key_end], raw[1:66], parts(chain)[0]
    session.check("organization registration returns exactly the configured leaf bytes", raw[key_end:key_end + len(leaf)], leaf)
    verified(session, "organization private key remains usable independently of leaf parsing/trust", private.public_key(), -7,
        raw[key_end + len(leaf):], b"\x00" + application + challenge + handle + point)
    try:
        certificate = x509.load_der_x509_certificate(leaf)
    except ValueError:
        session.observe("imported_leaf_semantics", "profile accepted DER sequence framing that is not an X.509 certificate")
    else:
        encoded = lambda key: key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        if encoded(certificate.public_key()) != encoded(private.public_key()):
            try:
                certificate.public_key().verify(raw[key_end + len(leaf):], b"\x00" + application + challenge + handle + point, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                session.check("accepted leaf/scalar mismatch is observable as a failed certificate-key verification", True)
            else:
                session.check("accepted leaf/scalar mismatch is observable as a failed certificate-key verification", False)


def vectors(valid):
    for count in (0, 1, 2, 3, MAX_CERTS, MAX_CERTS + 1):
        yield "certificate-count-" + str(count), b"\x30\x00" * count, 0 if 1 <= count <= MAX_CERTS else 2
    for size in (1, 2, 127, 128, 255, 256, MAX_CHAIN - 1, MAX_CHAIN, MAX_CHAIN + 1):
        data = sequence(size) if size >= 2 else b"\x30"
        yield "chain-byte-length-" + str(size), data if size != 1 else b"\x30", 0 if 2 <= size <= MAX_CHAIN else 2
    for label, data in (("wrong-tag", b"\x31\x00"), ("missing-length", b"\x30"), ("indefinite-length", b"\x30\x80\x00\x00"),
        ("unsupported-length-width", b"\x30\x83\x00\x00\x00"), ("short-long-header", b"\x30\x82\x00"),
        ("short-value", b"\x30\x03xx"), ("trailing-item", valid + b"\x00"), ("valid-prefix-short-tail", valid + b"\x30\x05x")):
        yield label, data, 2
    yield "non-minimal-short-length", b"\x30\x81\x00", 0
    yield "non-minimal-wide-length", b"\x30\x82\x00\x00", 0
    yield "repeated-real-certificate", valid * 2, 0
    original = x509.load_der_x509_certificate(valid)
    other = ec.derive_private_key(43, ec.SECP256R1())
    alien = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(original.issuer).public_key(other.public_key())
        .serial_number(43).not_valid_before(original.not_valid_before_utc).not_valid_after(original.not_valid_after_utc)
        .sign(other, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    yield "mismatched-leaf-scalar", alien, 0
    yield "leaf-first-untrusted-chain", valid + alien, 0
    yield "reversed-chain", alien + valid, 0


def run(session):
    for version, label, defect in product((1, 2), ("framing", "scalar"), ("valid", "missing-auth", "missing-protocol", "unknown-protocol", "wrong-permission", "bad-MAC")):
        with session.case(f"rsk.identity-chain.populated.protocol-{version}.{label}.{defect}", ("V01", "V06", "U02", "G01", "G03", "G04", "G05", "G09", "G10", "G11", "G13", "G14"),
                effects=("replace_identity", "create_fido_credential"), touch=True):
            session.require(session.profile == "rsk", "organization chain profile requires RS-Key", "excluded_by_profile")
            session.require(session.hid is not None and info(session).get(4, {}).get("clientPin") and session.options.pin, "populated chain controls need a known host PIN and selected FIDO HID")
            session.require(not info(session).get(4, {}).get("alwaysUv"), "raw U2F identity witness needs the ordinary UV policy")
            session.require(not session.ctap_value(vendor(session, 11))[1], "existing organization identity cannot be exported for restoration")
            private, original = identity_fixture(session)
            scalar = private.private_numbers().private_value.to_bytes(32, "big")
            try:
                session.ctap_value(vendor(session, 9, {1: wrap(session, scalar), 2: original}, authenticated=True))
                with credential(session, session.current.name) as retained:
                    cases = vectors(original) if label == "framing" else (("zero", bytes(32), 2), ("curve-order", bytes.fromhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"), 2))
                    for name, candidate, status in cases:
                        chain = candidate if label == "framing" else original
                        imported_scalar = scalar if label == "framing" else candidate
                        blob = wrap(session, imported_scalar)
                        params = {1: blob, 2: chain}
                        result = authenticated(session, 0x41, 9, params, defect, version=version)
                        expected = status if status else 0x36 if defect == "missing-auth" else 0x14 if defect == "missing-protocol" else 2 if defect == "unknown-protocol" else 0x33 if defect != "valid" else 0
                        # A scalar is checked after the gate; framing is checked before it.
                        if label == "scalar" and defect != "valid":
                            expected = 0x36 if defect == "missing-auth" else 0x14 if defect == "missing-protocol" else 2 if defect == "unknown-protocol" else 0x33
                        session.check("populated identity import isolates framing, authorization and scalar precedence", result.status, expected)
                        session.check("every parsed identity import spends its MSE channel", vendor(session, 6).status, 0x30)
                        identity_control(session, private, chain if expected == 0 else original)
                        retained.assertion(session)
                        session.ctap_value(vendor(session, 9, {1: wrap(session, scalar), 2: original}, authenticated=True))
                        identity_control(session, private, original)
                        session.observe("chain-policy-" + name, "DER sequence framing only; semantic X.509 validity, chain trust and scalar/leaf coherence are not enforced by this import")
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    handshake(session)
                    session.ctap_value(vendor(session, 10, authenticated=True))
                    session.check("owned identity fixture is cleared without replacing prior user identity", session.ctap_value(vendor(session, 11))[1], False)
