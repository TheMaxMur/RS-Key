# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Slot/algorithm/policy fixtures with public-key and certificate verification."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

from . import codec
from .cards import encoded_public, fixture_key, sdk_supported
from .fido import verified
from .piv_lifecycle import fixture_session as piv_session
from .openpgp_lifecycle import fixture_session as pgp_session, request

PIV_SLOTS = (*range(0x82, 0x96), 0x9A, 0x9C, 0x9D, 0x9E)
PIV_ALGORITHMS = ("RSA1024", "RSA2048", "RSA3072", "RSA4096", "ECCP256", "ECCP384", "ED25519", "X25519")
PGP_ALGORITHMS = ("RSA2048", "RSA3072", "RSA4096", "SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1",
                  "BrainpoolP256R1", "BrainpoolP384R1", "BrainpoolP512R1", "ED25519", "X25519")


def certificate(session, leaf, issuer, public):
    session.check("attestation public key matches slot", encoded_public(leaf.public_key()), encoded_public(public))
    session.check("attestation issuer binds chain", leaf.issuer, issuer.subject)
    leaf.verify_directly_issued_by(issuer)
    session.check("attestation certificate signature", True)


def private_operation(session, sdk, slot, public, algorithm, piv=False):
    message = session.fixture("card.matrix.message", 48)
    if isinstance(public, x25519.X25519PublicKey):
        peer = fixture_key(session, "X25519")
        got = sdk.calculate_secret(slot, peer.public_key()) if piv else sdk.decrypt(peer.public_key())
        session.check("X25519 independent shared secret", got, peer.exchange(public))
    elif isinstance(public, ec.EllipticCurvePublicKey) and not piv and slot.name == "DEC":
        peer = ec.generate_private_key(public.curve)
        session.check("ECDH independent shared secret", sdk.decrypt(peer.public_key()), peer.exchange(ec.ECDH(), public))
    elif isinstance(public, rsa.RSAPublicKey) and not piv and slot.name == "DEC":
        plain = session.fixture("card.matrix.rsa", 32)
        session.check("RSA independently encrypted plaintext", sdk.decrypt(public.encrypt(plain, padding.PKCS1v15())), plain)
    else:
        if piv:
            from yubikit.piv import KEY_TYPE
            signature = sdk.sign(slot, KEY_TYPE[algorithm], message, hashes.SHA256(), padding.PKCS1v15() if isinstance(public, rsa.RSAPublicKey) else None)
        else:
            operation = sdk.sign if slot.name == "SIG" else sdk.authenticate
            signature = operation(message, hashes.SHA256())
        algorithm_id = -8 if isinstance(public, ed25519.Ed25519PublicKey) else -257 if isinstance(public, rsa.RSAPublicKey) else -7
        verified(session, "slot/algorithm signature", public, algorithm_id, signature, message)
        if piv and isinstance(public, ec.EllipticCurvePublicKey):
            sdk.verify_pin(session.options.piv_pin)
            peer = ec.generate_private_key(public.curve)
            session.check("slot/algorithm ECDH", sdk.calculate_secret(slot, peer.public_key()), peer.exchange(ec.ECDH(), public))
        elif piv and isinstance(public, rsa.RSAPublicKey):
            sdk.verify_pin(session.options.piv_pin)
            plain = session.fixture("card.matrix.rsa", 32)
            session.check("slot/algorithm RSA decryption", sdk.decrypt(slot, public.encrypt(plain, padding.PKCS1v15()), padding.PKCS1v15()), plain)


def piv(session):
    from yubikit.piv import KEY_TYPE, PIN_POLICY, TOUCH_POLICY, SLOT
    for slot_index, slot_number in enumerate(PIV_SLOTS):
        for alg_index, algorithm in enumerate(PIV_ALGORITHMS):
            for origin in ("generate", "import"):
                for policy_index in range(4):
                    pin_policy = tuple(PIN_POLICY)[policy_index]
                    touch_policy = tuple(TOUCH_POLICY)[(policy_index + slot_index + alg_index) % len(TOUCH_POLICY)]
                    label = f"piv.matrix.{slot_number:02x}.{algorithm}.{origin}.{pin_policy.name}.{touch_policy.name}"
                    with session.case(label, ("P02", "P09", "P10", "P11", "P12", "P14", "P15", "P17"),
                                      effects=("replace_piv_keys",), touch=True,
                                      parameters={"slot": slot_number, "algorithm": algorithm, "origin": origin,
                                                  "pin_policy": pin_policy.name, "touch_policy": touch_policy.name},
                                      method="full slot/algorithm/origin/PIN product; rotating touch policy covers policy pairs across the slot/algorithm product"):
                        sdk = piv_session(session)
                        slot = SLOT(slot_number)
                        created = False
                        try:
                            if origin == "generate":
                                public = sdk_supported(session, lambda: sdk.generate_key(slot, KEY_TYPE[algorithm], pin_policy, touch_policy))
                            else:
                                key = fixture_key(session, algorithm)
                                sdk_supported(session, lambda: sdk.put_key(slot, key, pin_policy, touch_policy))
                                public = key.public_key()
                            created = True
                            session.observe("public_key", encoded_public(public), "presence" if origin == "generate" or algorithm.startswith("RSA") else "exact")
                            metadata = sdk_supported(session, lambda: sdk.get_slot_metadata(slot))
                            session.check("slot metadata public key", encoded_public(metadata.public_key), encoded_public(public))
                            sdk.verify_pin(session.options.piv_pin)
                            private_operation(session, sdk, slot, public, algorithm, piv=True)
                            if origin == "generate":
                                attestation = sdk_supported(session, lambda: sdk.attest_key(slot))
                                issuer = sdk.get_certificate(SLOT.ATTESTATION)
                                certificate(session, attestation, issuer, public)
                            else:
                                result = session.apdu(codec.apdu(0xF9, slot_number), "piv.attest-imported")
                                session.check("imported origin cannot attest as generated", result.protocol, "applet_error")
                        finally:
                            if created and not session.broken:
                                session.trace.phase = "cleanup"
                                sdk.authenticate(session.options.management_key)
                                sdk_supported(session, lambda: sdk.delete_key(slot))
                                result = session.apdu(codec.apdu(0xF7, p2=slot_number), "piv.deleted.metadata")
                                session.check("deleted slot metadata absent", result.status, 0x6A88)


def openpgp(session):
    from yubikit.openpgp import KEY_REF, OID, RSA_SIZE
    for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        for algorithm in PGP_ALGORITHMS:
            if algorithm == "X25519" and slot != KEY_REF.DEC or algorithm == "ED25519" and slot == KEY_REF.DEC:
                continue
            for origin in ("generate", "import"):
                with session.case(f"openpgp.matrix.{slot.name}.{algorithm}.{origin}", ("O08", "O09", "O10", "O11", "O12", "O13", "O20", "O22"),
                                  effects=("replace_openpgp_keys", "write_openpgp_certificates"), touch=True):
                    sdk = pgp_session(session)
                    created = False
                    try:
                        if origin == "import":
                            key = fixture_key(session, algorithm)
                            sdk_supported(session, lambda: sdk.put_key(slot, key))
                            public = key.public_key()
                        elif algorithm.startswith("RSA"):
                            public = sdk_supported(session, lambda: sdk.generate_rsa_key(slot, RSA_SIZE[algorithm]))
                        else:
                            oid_name = "Ed25519" if algorithm == "ED25519" else algorithm
                            public = sdk_supported(session, lambda: sdk.generate_ec_key(slot, OID[oid_name]))
                        created = True
                        session.check("generated/imported public readback", encoded_public(sdk.get_public_key(slot)), encoded_public(public))
                        attributes = sdk.get_algorithm_attributes(slot)
                        sdk.put_data(slot.algorithm_attributes_do, bytes(attributes))
                        session.check("identical attributes preserve existing key", encoded_public(sdk.get_public_key(slot)), encoded_public(public))
                        before = sdk.get_signature_counter()
                        sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                        private_operation(session, sdk, slot, public, algorithm)
                        session.check("slot signature-counter scope", sdk.get_signature_counter() - before, 1 if slot == KEY_REF.SIG else 0)
                        if origin == "generate":
                            sdk.verify_pin(session.options.openpgp_pin)
                            leaf = sdk_supported(session, lambda: sdk.attest_key(slot))
                            issuer = sdk.get_certificate(KEY_REF.ATT)
                            certificate(session, leaf, issuer, public)
                        else:
                            sdk.verify_pin(session.options.openpgp_pin)
                            result = session.apdu(codec.apdu(0xFB, int(slot), cla=0x80), "openpgp.attest-imported")
                            session.check("imported OpenPGP key cannot attest as generated", result.status, 0x6985)
                    finally:
                        if created and not session.broken:
                            session.trace.phase = "cleanup"
                            sdk.verify_admin(session.options.openpgp_admin)
                            sdk_supported(session, lambda: sdk.delete_key(slot))


def mse(session):
    from yubikit.openpgp import KEY_REF, OID, EcAttributes
    with session.case("openpgp.MSE.key-reference-isolation", ("O14", "O13", "G09", "G14"), effects=("replace_openpgp_keys",), touch=True):
        sdk = pgp_session(session)
        keys = {}
        try:
            for index, slot in enumerate((KEY_REF.DEC, KEY_REF.AUT)):
                key = ec.derive_private_key(int.from_bytes(session.fixture(f"mse.{index}", 24), "big") + 1, ec.SECP256R1())
                keys[slot] = key
                sdk.set_algorithm_attributes(slot, EcAttributes.create(KEY_REF.DEC, OID.SECP256R1))
                scalar = key.private_numbers().private_value.to_bytes(32, "big")
                body = slot.crt + codec.tlv(0x7F48, bytes([0x92, len(scalar)])) + codec.tlv(0x5F48, scalar)
                request(session, 0xDB, 0x3F, 0xFF, codec.tlv(0x4D, body))
            peer = ec.generate_private_key(ec.SECP256R1())
            point = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            body = codec.tlv(0xA6, codec.tlv(0x7F49, codec.tlv(0x86, point)))
            sdk.verify_pin(session.options.openpgp_pin, extended=True)
            for reference, key_slot in ((2, KEY_REF.DEC), (3, KEY_REF.AUT), (2, KEY_REF.DEC)):
                request(session, 0x22, 0x41, 0xB8, codec.tlv(0x83, bytes([reference])))
                session.check("MSE-selected key ECDH", request(session, 0x2A, 0x80, 0x86, body), peer.exchange(ec.ECDH(), keys[key_slot].public_key()))
            for invalid in (0, 1, 4, 255):
                reply = session.apdu(codec.apdu(0x22, 0x41, 0xB8, codec.tlv(0x83, bytes([invalid]))), "openpgp.MSE.invalid-reference")
                session.check("invalid MSE reference refused", reply.protocol, "applet_error")
                session.check("invalid MSE preserves previous assignment", request(session, 0x2A, 0x80, 0x86, body), peer.exchange(ec.ECDH(), keys[KEY_REF.DEC].public_key()))
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                sdk.verify_admin(session.options.openpgp_admin)
                for slot in keys:
                    sdk_supported(session, lambda: sdk.delete_key(slot))


def uif(session):
    from yubikit.openpgp import KEY_REF, UIF
    for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        for policy in (UIF.OFF, UIF.ON, UIF.FIXED):
            with session.case(f"openpgp.UIF.{slot.name}.{policy.name}", ("O19", "O11", "O12", "O13"),
                              effects=("replace_openpgp_keys", "config_change", "applet_reset") if policy == UIF.FIXED else ("replace_openpgp_keys", "config_change"), touch=True):
                sdk = pgp_session(session)
                original = sdk_supported(session, lambda: sdk.get_uif(slot))
                session.require(not original.is_fixed, "existing fixed UIF policy cannot be restored")
                key = fixture_key(session, "ECCP256")
                sdk.put_key(slot, key)
                try:
                    sdk_supported(session, lambda: sdk.set_uif(slot, policy))
                    session.check("UIF policy readback", sdk.get_uif(slot), policy)
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    private_operation(session, sdk, slot, key.public_key(), "ECCP256")
                    if policy == UIF.FIXED:
                        result = session.apdu(codec.apdu(0xDA, 0, slot.uif_do, bytes(UIF.OFF)), "openpgp.UIF.fixed-disable")
                        session.check("fixed UIF cannot be disabled", result.protocol, "applet_error")
                        session.check("fixed UIF survives refusal", sdk.get_uif(slot), policy)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        if policy == UIF.FIXED:
                            from .openpgp_lifecycle import request as pgp_request
                            pgp_request(session, 0xE6)
                            pgp_request(session, 0x44)
                            session.options.openpgp_pin, session.options.openpgp_admin = "123456", "12345678"
                        else:
                            sdk.set_uif(slot, original)
                            sdk_supported(session, lambda: sdk.delete_key(slot))


def run(session):
    piv(session)
    openpgp(session)
    mse(session)
    uif(session)
