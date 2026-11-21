# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV malformed operations retain a populated key and a valid private control."""
from contextlib import contextmanager
from itertools import product

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import codec
from .cards import connection, encoded_public, fixture_key, sdk_supported
from .card_keys import PIV_ALGORITHMS, private_operation
from .piv_lifecycle import fixture_session, status

FIXTURE_SLOT = 0x82
POOL_OBJECT = 0x5F0077
MANAGEMENT_ALGORITHMS = ("TDES", "AES128", "AES192", "AES256")


@contextmanager
def key_fixture(session, algorithm="ECCP256", policy=None):
    from yubikit.piv import SLOT, PIN_POLICY
    sdk = fixture_session(session)
    private = fixture_key(session, algorithm)
    created = False
    try:
        sdk_supported(session, lambda: sdk.put_key(SLOT(FIXTURE_SLOT), private, policy or PIN_POLICY.NEVER))
        created = True
        yield sdk, private
    finally:
        if created and not session.broken:
            session.trace.phase = "cleanup"
            sdk.authenticate(session.options.management_key)
            sdk_supported(session, lambda: sdk.delete_key(SLOT(FIXTURE_SLOT)))


def import_parts(private, algorithm):
    if isinstance(private, rsa.RSAPrivateKey):
        numbers = private.private_numbers()
        width = private.key_size // 16
        return [(index, value.to_bytes(width, "big")) for index, value in enumerate((numbers.p, numbers.q), 1)]
    if isinstance(private, ec.EllipticCurvePrivateKey):
        return [(6, private.private_numbers().private_value.to_bytes((private.curve.key_size + 7) // 8, "big"))]
    return [(7 if algorithm == "ED25519" else 8, private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))]


def malformed_keys(session):
    from yubikit.piv import KEY_TYPE, SLOT
    for algorithm in PIV_ALGORITHMS:
        for operation in ("generate", "import", "private"):
            defects = ("missing-algorithm", "unknown-algorithm", "invalid-PIN-policy", "invalid-touch-policy", "truncated-template", "missing-management") if operation == "generate" else (
                "missing-component", "short-component", "long-component", "zero-component", "truncated-TLV", "missing-management") if operation == "import" else (
                "empty-template", "missing-input", "truncated-TLV", "unknown-tag", "wrong-algorithm", "empty-slot", "wrong-length", "invalid-point")
            for defect in defects:
                if operation == "import" and defect == "zero-component" and algorithm in ("ED25519", "X25519"):
                    continue
                if operation == "private" and defect == "invalid-point" and not (algorithm.startswith("ECC") or algorithm == "X25519"):
                    continue
                if operation == "private" and defect == "wrong-length" and algorithm in ("ED25519", "X25519"):
                    continue
                with session.case(f"piv.semantic.{algorithm}.{operation}.{defect}", ("P02", "P06", "P09", "P10", "P11", "P12", "P14", "P17", "G01", "G03", "G04", "G05", "G10", "G14"),
                                  effects=("replace_piv_keys",), touch=True, parameters={"algorithm": algorithm, "operation": operation, "defect": defect}):
                    session.require(session.profile == "rsk", "malformed PIV key catalog is RS-Key only", "excluded_by_profile")
                    with key_fixture(session, algorithm) as (sdk, private):
                        public, key_type = private.public_key(), KEY_TYPE[algorithm]
                        sdk.verify_pin(session.options.piv_pin)
                        private_operation(session, sdk, SLOT(FIXTURE_SLOT), public, algorithm, piv=True)
                        before = sdk.get_slot_metadata(SLOT(FIXTURE_SLOT))
                        if operation == "generate":
                            fields = [(0x80, bytes([key_type]))]
                            if defect == "missing-algorithm":
                                fields = []
                            elif defect == "unknown-algorithm":
                                fields = [(0x80, b"\xff")]
                            elif defect in ("invalid-PIN-policy", "invalid-touch-policy"):
                                fields.append((0xAA if defect == "invalid-PIN-policy" else 0xAB, b"\xff"))
                            body = codec.tlv(0xAC, b"".join(codec.tlv(tag, value) for tag, value in fields))
                            if defect == "truncated-template":
                                body = body[:-1]
                            ins, p1, p2 = 0x47, 0, FIXTURE_SLOT
                        elif operation == "import":
                            fields = import_parts(private, algorithm)
                            if defect == "missing-component":
                                fields = fields[1:]
                            elif defect in ("short-component", "long-component", "zero-component"):
                                tag, value = fields[0]
                                fields[0] = (tag, value[:-1] if defect == "short-component" else value + b"\x00" if defect == "long-component" else bytes(len(value)))
                            body = b"".join(codec.tlv(tag, value) for tag, value in fields)
                            if defect == "truncated-TLV":
                                body = body[:-1]
                            ins, p1, p2 = 0xFE, int(key_type), FIXTURE_SLOT
                        else:
                            payload = session.fixture("piv.semantic.digest", 32)
                            if algorithm.startswith("RSA"):
                                payload = b"\x00" + session.fixture("piv.semantic.rsa", int(algorithm[3:]) // 8 - 1)
                            if defect == "wrong-length":
                                payload = payload[:-1] if algorithm.startswith("RSA") else bytes((public.curve.key_size + 7) // 8 + 1)
                            fields = [(0x82, b""), (0x85 if defect == "invalid-point" else 0x81, b"\x04" + bytes(64) if defect == "invalid-point" else payload)]
                            if defect == "empty-template":
                                fields = []
                            elif defect == "missing-input":
                                fields = fields[:1]
                            elif defect == "unknown-tag":
                                fields = [(0x99, payload)]
                            body = codec.tlv(0x7C, b"".join(codec.tlv(tag, value) for tag, value in fields))
                            if defect == "truncated-TLV":
                                body = body[:-1]
                            if defect == "empty-slot":
                                session.require(session.apdu(codec.apdu(0xf7, p2=0x83)).status == 0x6a88, "private-operation empty-slot fixture requires an unpopulated asymmetric reference")
                            ins, p1, p2 = 0x87, 0xFF if defect == "wrong-algorithm" else int(key_type), 0x83 if defect == "empty-slot" else FIXTURE_SLOT
                        if defect == "missing-management":
                            session.select("openpgp")
                            session.select("piv")
                        outcome = session.apdu(codec.apdu(ins, p1, p2, body), "piv.semantic." + operation)
                        session.check("malformed populated-key operation refused", outcome.protocol, "applet_error")
                        after = sdk.get_slot_metadata(SLOT(FIXTURE_SLOT))
                        session.check("refused operation preserves key identity", encoded_public(after.public_key), encoded_public(public))
                        session.check("refused operation preserves policies", (after.pin_policy, after.touch_policy), (before.pin_policy, before.touch_policy))
                        sdk.verify_pin(session.options.piv_pin)
                        private_operation(session, sdk, SLOT(FIXTURE_SLOT), public, algorithm, piv=True)


def private_lengths(session):
    from yubikit.piv import KEY_TYPE
    for algorithm in ("ECCP256", "ECCP384", "RSA1024", "RSA2048", "RSA3072", "RSA4096", "ED25519", "X25519"):
        for boundary in ("empty", "one", "width-minus-one", "width", "width-plus-one"):
            with session.case(f"piv.private-length.{algorithm}.{boundary}", ("P11", "P12", "G03", "G14"), effects=("replace_piv_keys",), touch=True):
                session.require(session.profile == "rsk", "raw private-operation lengths require the RS-Key profile", "excluded_by_profile")
                with key_fixture(session, algorithm) as (sdk, private):
                    width = int(algorithm[3:]) // 8 if algorithm.startswith("RSA") else 48 if algorithm == "ECCP384" else 32
                    size = {"empty": 0, "one": 1, "width-minus-one": width - 1, "width": width, "width-plus-one": width + 1}[boundary]
                    payload = session.fixture("piv.length.payload", size)
                    if algorithm.startswith("RSA") and payload:
                        payload = b"\x00" + payload[1:]
                    tag = 0x85 if algorithm == "X25519" else 0x81
                    body = codec.tlv(0x7C, codec.tlv(0x82, b"") + codec.tlv(tag, payload))
                    reply = session.apdu(codec.apdu(0x87, int(KEY_TYPE[algorithm]), FIXTURE_SLOT, body))
                    valid = size == width if algorithm.startswith("RSA") or algorithm == "X25519" else size <= width if algorithm.startswith("ECC") else True
                    if valid:
                        response = dict(codec.parse_tlv(dict(codec.parse_tlv(session.card_value(reply)))[0x7C]))[0x82]
                        if algorithm.startswith("RSA"):
                            numbers = private.public_key().public_numbers()
                            session.check("raw RSA independently exponentiated", pow(int.from_bytes(response, "big"), numbers.e, numbers.n), int.from_bytes(payload, "big"))
                        elif algorithm.startswith("ECC"):
                            padded = payload.rjust(width, b"\x00")
                            digest = hashes.SHA256() if width == 32 else hashes.SHA384()
                            private.public_key().verify(response, padded, ec.ECDSA(utils.Prehashed(digest)))
                            session.check("raw digest ECDSA verified", True)
                        elif algorithm == "ED25519":
                            private.public_key().verify(response, payload)
                            session.check("raw-message EdDSA verified", True)
                        else:
                            from cryptography.hazmat.primitives.asymmetric import x25519
                            expected = private.exchange(x25519.X25519PublicKey.from_public_bytes(payload))
                            session.check("raw X25519 independently computed", response, expected)
                    else:
                        session.check("private-operation length refused", reply.protocol, "applet_error")
                    sdk.verify_pin(session.options.piv_pin)
                    from yubikit.piv import SLOT
                    private_operation(session, sdk, SLOT(FIXTURE_SLOT), private.public_key(), algorithm, piv=True)


def crypt(key, algorithm, body, decrypt=False):
    block = TripleDES(key) if algorithm == 3 else algorithms.AES(key)
    context = Cipher(block, modes.ECB()).decryptor() if decrypt else Cipher(block, modes.ECB()).encryptor()
    return context.update(body) + context.finalize()


def handshake(session):
    from yubikit.piv import MANAGEMENT_KEY_TYPE, TOUCH_POLICY
    for scheme, algorithm_name in product(("single", "mutual"), MANAGEMENT_ALGORITHMS):
        for defect in ("none", "missing-step", "wrong-answer", "old-key", "new-challenge", "short-answer", "long-answer", "replay", "wrong-scheme", "version", "management-metadata", "PIN-metadata", "unknown-command", "wrong-GA", "missing-host-challenge", "short-host-challenge", "same-SELECT", "other-SELECT"):
            if scheme == "single" and defect in ("missing-host-challenge", "short-host-challenge"):
                continue
            with session.case(f"piv.management-auth.{algorithm_name}.{scheme}.{defect}", ("P01", "P06", "P07", "G03", "G09", "G10", "G11", "G14"), effects=("config_change", "write_piv_fixture_object"), touch=True):
                session.require(session.profile == "rsk", "handshake grant persistence is profiled for RS-Key", "excluded_by_profile")
                session.require(algorithm_name != "TDES" or "fips-profile" not in session.options.features, "declared FIPS profile excludes provisioning a new 3DES management key", "excluded_by_profile")
                sdk = fixture_session(session)
                original_type = sdk.management_key_type
                original_touch = sdk.get_management_key_metadata().touch_policy != TOUCH_POLICY.NEVER
                selected = MANAGEMENT_KEY_TYPE[algorithm_name]
                algorithm = int(selected)
                key = session.fixture("PIV.management.handshake." + algorithm_name, selected.key_len)
                width, tag = (8 if algorithm == 3 else 16), (0x81 if scheme == "single" else 0x80)
                original = session.apdu(codec.apdu(0xCB, 0x3F, 0xFF, codec.tlv(0x5C, POOL_OBJECT.to_bytes(3, "big"))))
                session.require(original.status in (0x9000, 0x6A82), "fixture object's initial state is unavailable")
                old = dict(codec.parse_tlv(original.data[:-2]))[0x53] if original.status == 0x9000 else None
                installed = False
                try:
                    sdk.set_management_key(selected, key)
                    installed = True
                    session.select("piv")
                    first = status(session, 0x87, algorithm, 0x9B, codec.tlv(0x7C, codec.tlv(tag, b"")))
                    value = dict(codec.parse_tlv(dict(codec.parse_tlv(first))[0x7C]))[tag]
                    answer = crypt(key, algorithm, value, decrypt=scheme == "mutual")
                    host_challenge = session.fixture("piv.mutual.host", width)
                    answer_tag = 0x82 if scheme == "single" else 0x80
                    if defect in ("missing-step", "same-SELECT", "other-SELECT"):
                        if defect in ("missing-step", "other-SELECT"):
                            session.select("openpgp")
                        session.select("piv")
                    elif defect == "version":
                        status(session, 0xFD)
                    elif defect in ("management-metadata", "PIN-metadata"):
                        status(session, 0xf7, p2=0x9b if defect == "management-metadata" else 0x80)
                    elif defect == "wrong-GA":
                        status(session, 0x87, 0xff, 0xff, codec.tlv(0x7c, codec.tlv(0x99, b"x")), expected=0x6a80)
                    elif defect == "unknown-command":
                        status(session, 0xee, expected=0x6d00)
                    elif defect == "new-challenge":
                        fresh = status(session, 0x87, algorithm, 0x9b, codec.tlv(0x7c, codec.tlv(tag, b"")))
                        fresh_value = dict(codec.parse_tlv(dict(codec.parse_tlv(fresh))[0x7c]))[tag]
                        session.check("a new challenge supersedes distinct previous bytes", fresh_value != value)
                    if defect == "wrong-answer":
                        answer = bytes([answer[0] ^ 1]) + answer[1:]
                    elif defect == "old-key" and int(original_type) == algorithm:
                        answer = crypt(session.options.management_key, algorithm, value, decrypt=scheme == "mutual")
                    elif defect in ("short-answer", "long-answer"):
                        answer = answer[:-1] if defect == "short-answer" else answer + b"x"
                    if defect == "wrong-scheme":
                        answer_tag = 0x80 if scheme == "single" else 0x82
                    host_body = b"" if defect == "missing-host-challenge" else codec.tlv(0x81, host_challenge[:-1] if defect == "short-host-challenge" else host_challenge)
                    body = codec.tlv(0x7C, codec.tlv(answer_tag, answer) + (host_body if answer_tag == 0x80 else b""))
                    reply = session.apdu(codec.apdu(0x87, int(original_type) if defect == "old-key" else algorithm, 0x9B, body))
                    valid = defect in ("none", "management-metadata", "wrong-GA", "replay", "same-SELECT")
                    session.check("management challenge outcome", reply.protocol, "success" if valid else "applet_error")
                    if valid and scheme == "mutual":
                        response = dict(codec.parse_tlv(dict(codec.parse_tlv(session.card_value(reply)))[0x7C]))[0x82]
                        session.check("mutual response proves management key", response, crypt(key, algorithm, host_challenge))
                    if defect == "replay":
                        session.check("completed management answer cannot replay", session.apdu(codec.apdu(0x87, algorithm, 0x9B, body)).protocol, "applet_error")
                    marker = b"oracle-management-grant"
                    protected = session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, codec.tlv(0x5C, POOL_OBJECT.to_bytes(3, "big")) + codec.tlv(0x53, marker)))
                    session.check("protected write witnesses handshake grant", protected.status, 0x9000 if valid or defect == "short-host-challenge" else 0x6982)
                    sdk.authenticate(key)
                    sdk.put_object(POOL_OBJECT, marker)
                    session.check("valid management authentication recovers protected write", sdk.get_object(POOL_OBJECT), marker)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.authenticate(key if installed else session.options.management_key)
                        sdk.put_object(POOL_OBJECT, old)
                        if installed:
                            sdk.set_management_key(original_type, session.options.management_key, original_touch)
                            sdk.authenticate(session.options.management_key)


def run(session):
    malformed_keys(session)
    private_lengths(session)
    handshake(session)
