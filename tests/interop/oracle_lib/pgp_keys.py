# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Use advertised OpenPGP attributes without SDK enum or exponent-width loss."""
from cryptography.hazmat.primitives.asymmetric import rsa

from . import codec


def attributes(session, slot, desired):
    reply = session.apdu(codec.apdu(0xCA, 0, 0xFA), "openpgp.advertised-key-algorithms")
    outer = dict(codec.parse_tlv(session.card_value(reply)))
    choices = [value for tag, value in codec.parse_tlv(outer[0xFA]) if tag == int(slot.algorithm_attributes_do)]
    def same(candidate):
        if desired[0] == 1:
            return len(candidate) == len(desired) == 6 and candidate[:3] == desired[:3] and candidate[-1] == desired[-1]
        return candidate == desired
    admitted = next((value for value in choices if same(value)), None)
    session.require(admitted is not None, "selected algorithm is absent from the confirmed RS-Key DO FA catalog", "excluded_by_profile")
    session.observe("advertised_algorithm_attributes", admitted)
    return admitted


def put_key(session, sdk, slot, private):
    if session.profile != "rsk":
        return sdk.put_key(slot, private)
    from yubikit.openpgp import EcAttributes, OID
    from .openpgp_matrix import import_body
    desired = bytes([1]) + private.key_size.to_bytes(2, "big") + b"\x00\x20\x00" if isinstance(private, rsa.RSAPrivateKey) else bytes(EcAttributes.create(slot, OID._from_key(private)))
    selected = attributes(session, slot, desired)
    session.card_value(session.apdu(codec.apdu(0xDA, int(slot.algorithm_attributes_do) >> 8, int(slot.algorithm_attributes_do) & 255, selected)))
    body = import_body(slot, private, "", "valid")
    session.card_value(session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, body), "openpgp.IMPORT.advertised-key"))


def generate(session, sdk, slot, algorithm):
    from yubikit.openpgp import RSA_SIZE, OID, EcAttributes
    if session.profile != "rsk":
        if algorithm.startswith("RSA"):
            session.require(algorithm in RSA_SIZE.__members__, "SDK cannot represent this RSA size; device support is unmeasured", "unknown")
            return sdk.generate_rsa_key(slot, RSA_SIZE[algorithm])
        return sdk.generate_ec_key(slot, OID["Ed25519" if algorithm == "ED25519" else algorithm])
    desired = bytes([1]) + int(algorithm[3:]).to_bytes(2, "big") + b"\x00\x20\x00" if algorithm.startswith("RSA") else bytes(EcAttributes.create(slot, OID["Ed25519" if algorithm == "ED25519" else algorithm]))
    selected = attributes(session, slot, desired)
    session.card_value(session.apdu(codec.apdu(0xDA, int(slot.algorithm_attributes_do) >> 8, int(slot.algorithm_attributes_do) & 255, selected)))
    session.card_value(session.apdu(codec.apdu(0x47, 0x80, data=slot.crt), "openpgp.GENERATE.advertised-key"))
    return sdk.get_public_key(slot)


def delete_key(session, sdk, slot):
    if session.profile != "rsk":
        return sdk.delete_key(slot)
    for bits in (4096, 2048):
        value = bytes([1]) + bits.to_bytes(2, "big") + b"\x00\x20\x00"
        session.card_value(session.apdu(codec.apdu(0xDA, int(slot.algorithm_attributes_do) >> 8, int(slot.algorithm_attributes_do) & 255, value), "openpgp.DELETE.attribute-transition"))


def set_algorithm(session, sdk, slot, desired):
    if session.profile != "rsk":
        return sdk.set_algorithm_attributes(slot, desired)
    selected = attributes(session, slot, bytes(desired))
    session.card_value(session.apdu(codec.apdu(0xDA, int(slot.algorithm_attributes_do) >> 8, int(slot.algorithm_attributes_do) & 255, selected)))
