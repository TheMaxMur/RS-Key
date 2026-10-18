# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Malformed key commands and KDF changes retain populated private-key controls."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import pgp_keys
from . import codec
from .cards import encoded_public, fixture_key, sdk_supported
from .card_keys import PGP_ALGORITHMS, private_operation
from .openpgp_lifecycle import fixture_session, request


def import_body(slot, private, algorithm, defect):
    if isinstance(private, rsa.RSAPrivateKey):
        numbers = private.private_numbers()
        half = private.key_size // 16
        components = [(0x91, b"\x01\x00\x01"), (0x92, numbers.p.to_bytes(half, "big")), (0x93, numbers.q.to_bytes(half, "big"))]
    else:
        scalar = private.private_numbers().private_value.to_bytes((private.curve.key_size + 7) // 8, "big") if isinstance(private, ec.EllipticCurvePrivateKey) else private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        components = [(0x92, scalar)]
    if defect == "missing-component":
        components = components[1:]
    elif defect in ("short-component", "long-component", "invalid-scalar"):
        index = 1 if isinstance(private, rsa.RSAPrivateKey) else 0
        tag, value = components[index]
        components[index] = (tag, value[:-1] if defect == "short-component" else value + b"\x00" if defect == "long-component" else bytes(len(value)))
    elif defect == "wrong-exponent":
        components[0] = (0x91, b"\x03")
    # Header lengths describe the concatenated key data, without per-component values.
    headers = b"".join(codec.tlv(tag, value)[:-len(value)] if value else codec.tlv(tag, value) for tag, value in components)
    data = b"".join(value for _, value in components)
    header = b"" if defect == "missing-header" else codec.tlv(0x7F48, headers)
    values = b"" if defect == "missing-key-data" else codec.tlv(0x5F48, data)
    packed = slot.crt + header + values
    result = codec.tlv(0x4D, packed)
    return result[:-1] if defect == "truncated-template" else result


def keys(session):
    from yubikit.openpgp import KEY_REF
    for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        for algorithm in PGP_ALGORITHMS:
            if algorithm == "X25519" and slot != KEY_REF.DEC or algorithm == "ED25519" and slot == KEY_REF.DEC:
                continue
            defects = ("missing-component", "short-component", "long-component", "missing-header", "missing-key-data", "truncated-template", "missing-admin")
            if algorithm.startswith("RSA"):
                defects += ("wrong-exponent",)
            elif algorithm not in ("ED25519", "X25519"):
                defects += ("invalid-scalar",)
            for defect in defects:
                with session.case(f"openpgp.IMPORT.{slot.name}.{algorithm}.{defect}", ("O08", "O09", "O10", "O11", "O12", "O13", "O22", "G01", "G03", "G05", "G14"),
                                  effects=("replace_openpgp_keys",), touch=True):
                    session.require(session.profile == "rsk", "OpenPGP import rejection catalog is RS-Key only", "excluded_by_profile")
                    sdk = fixture_session(session)
                    private = fixture_key(session, algorithm)
                    created = False
                    try:
                        sdk_supported(session, lambda: pgp_keys.put_key(session, sdk, slot, private))
                        created = True
                        attributes = bytes(sdk.get_algorithm_attributes(slot))
                        before = sdk.get_signature_counter()
                        if defect == "missing-admin":
                            request(session, 0x20, 0xFF, 0x83)
                        reply = session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, import_body(slot, private, algorithm, defect)))
                        session.check("malformed OpenPGP import refused", reply.protocol, "applet_error")
                        session.check("import refusal preserves signature counter", sdk.get_signature_counter(), before)
                        session.check("import refusal preserves attributes", bytes(sdk.get_algorithm_attributes(slot)), attributes)
                        session.check("import refusal preserves public identity", encoded_public(sdk.get_public_key(slot)), encoded_public(private.public_key()))
                        sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                        private_operation(session, sdk, slot, private.public_key(), algorithm)
                    finally:
                        if created and not session.broken:
                            session.trace.phase = "cleanup"
                            sdk.verify_admin(session.options.openpgp_admin)
                            sdk_supported(session, lambda: pgp_keys.delete_key(session, sdk, slot))


def attributes(session):
    from yubikit.openpgp import KEY_REF, RsaAttributes, RSA_SIZE
    invalid = (b"\x7f", b"\x13\x2b\x81\x04\x00\xff", b"\x12\x2b\x81\x04\x00", b"\x01\x02\x00\x00\x20\x00",
               b"\x01\x06\x00\x00\x20\x00", b"\x01\x0f\xff\x00\x20\x00", b"\x01\x08\x00\x00\x00\x00")
    for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        for value in invalid:
            with session.case(f"openpgp.attributes.{slot.name}.{value.hex()}", ("O08", "O09", "O22", "G03", "G04", "G14"), effects=("replace_openpgp_keys",), touch=True):
                sdk = fixture_session(session)
                private = fixture_key(session, "ECCP256")
                created = False
                try:
                    pgp_keys.put_key(session, sdk, slot, private)
                    created = True
                    original = bytes(sdk.get_algorithm_attributes(slot))
                    reply = session.apdu(codec.apdu(0xDA, 0, slot.algorithm_attributes_do, value))
                    session.check("unsupported algorithm attributes refused", reply.status, 0x6A80)
                    session.check("invalid attributes retain original", bytes(sdk.get_algorithm_attributes(slot)), original)
                    session.check("invalid attributes retain private-key identity", encoded_public(sdk.get_public_key(slot)), encoded_public(private.public_key()))
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    private_operation(session, sdk, slot, private.public_key(), "ECCP256")
                    sdk.verify_admin(session.options.openpgp_admin)
                    pgp_keys.set_algorithm(session, sdk, slot, RsaAttributes.create(RSA_SIZE.RSA2048))
                    result = session.apdu(codec.apdu(0x47, 0x81, data=slot.crt))
                    session.check("changed algorithm retires populated key", result.status, 0x6A88)
                    pgp_keys.put_key(session, sdk, slot, private)
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    private_operation(session, sdk, slot, private.public_key(), "ECCP256")
                finally:
                    if created and not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        sdk_supported(session, lambda: pgp_keys.delete_key(session, sdk, slot))


def generation(session):
    from yubikit.openpgp import KEY_REF
    for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        for defect in ("empty-CRT", "truncated-CRT", "unknown-CRT", "wrong-reference", "wrong-P1", "wrong-P2", "missing-admin"):
            with session.case(f"openpgp.GENERATE.{slot.name}.{defect}", ("O09", "O14", "O22", "G03", "G04", "G14"), effects=("replace_openpgp_keys",), touch=True):
                sdk = fixture_session(session)
                private, created = fixture_key(session, "ECCP256"), False
                try:
                    pgp_keys.put_key(session, sdk, slot, private)
                    created = True
                    body, p1, p2 = slot.crt, 0x80, 0
                    if defect == "empty-CRT":
                        body = b""
                    elif defect == "truncated-CRT":
                        body = body[:-1]
                    elif defect == "unknown-CRT":
                        body = b"\xff\x00"
                    elif defect == "wrong-reference":
                        body = body[:1] + b"\x03\x84\x01\xff"
                    elif defect == "wrong-P1":
                        p1 = 0x82
                    elif defect == "wrong-P2":
                        p2 = 1
                    else:
                        request(session, 0x20, 0xFF, 0x83)
                    before = sdk.get_signature_counter()
                    result = session.apdu(codec.apdu(0x47, p1, p2, body))
                    session.check("invalid generation request refused", result.protocol, "applet_error")
                    session.check("refused generation preserves counter", sdk.get_signature_counter(), before)
                    session.check("refused generation preserves key", encoded_public(sdk.get_public_key(slot)), encoded_public(private.public_key()))
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    private_operation(session, sdk, slot, private.public_key(), "ECCP256")
                finally:
                    if created and not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        sdk_supported(session, lambda: pgp_keys.delete_key(session, sdk, slot))


def kdf_keys(session):
    from .openpgp_kdf import populated
    populated(session)


def terminated(session):
    commands = ((0xCA, 0, 0x5E, b""), (0xCC, 0x7F, 0x21, b""), (0x20, 0, 0x81, b"123456"),
        (0x24, 0, 0x81, b"123456654321"), (0x2C, 2, 0x81, b"654321"), (0xDA, 0, 0x5E, b"marker"),
        (0xDB, 0x3F, 0xFF, b""), (0x47, 0x81, 0, b"\xb6\x00"), (0x2A, 0x9E, 0x9A, bytes(32)),
        (0x88, 0, 0, bytes(32)), (0x22, 0x41, 0xA4, b"\x83\x01\x03"), (0x84, 0, 0, b""),
        (0xF1, 0, 0, b""), (0xF2, 0, 0, b"\x03\x03\x03"), (0xFB, 1, 0, b""),
        (0xA5, 0, 4, bytes.fromhex("60045c027f21")), (0xE6, 0, 0, b""))
    with session.case("openpgp.TERMINATE.all-command-gates-and-ACTIVATE", ("O21", "O22", "G09", "G10", "G14"), effects=("applet_reset", "replace_openpgp_sig_key"), touch=True):
        session.require(session.profile == "rsk", "terminated command catalog requires RS-Key", "excluded_by_profile")
        sdk = fixture_session(session)
        private = fixture_key(session, "ECCP256")
        from yubikit.openpgp import KEY_REF
        pgp_keys.put_key(session, sdk, KEY_REF.SIG, private)
        terminated = False
        try:
            request(session, 0xE6)
            terminated = True
            for ins, p1, p2, body in commands:
                reply = session.apdu(codec.apdu(ins, p1, p2, body, cla=0x80 if ins == 0xFB else 0))
                session.check("terminated state refuses command before authorization or parsing", reply.status, 0x6285)
        finally:
            if terminated and not session.broken:
                session.trace.phase = "cleanup"
                request(session, 0x44)
                session.options.openpgp_pin, session.options.openpgp_admin = "123456", "12345678"
                session.failed_auth.discard(("openpgp", 0x81))
                session.failed_auth.discard(("openpgp", 0x83))
                sdk = fixture_session(session)
                session.check("activation resets old private key", session.apdu(codec.apdu(0x47, 0x81, data=KEY_REF.SIG.crt)).status, 0x6A88)
                sdk.put_data(0x5E, b"oracle-active-marker")
                request(session, 0x44)
                session.check("ACTIVATE on active card preserves state", sdk.get_data(0x5E), b"oracle-active-marker")
                sdk.put_data(0x5E, b"")


def run(session):
    keys(session)
    attributes(session)
    generation(session)
    kdf_keys(session)
