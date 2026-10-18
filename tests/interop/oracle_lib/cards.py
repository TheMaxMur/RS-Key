# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV and OpenPGP fixtures; SDK calls pass through the raw APDU recorder."""
from contextlib import contextmanager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

from . import pgp_keys
from .fido import verified


@contextmanager
def selected_cleanup(session, applet, context):
    with context as value:
        try:
            yield value
        finally:
            if not session.broken:
                session.select(applet)


def connection(session):
    from yubikit.core import TRANSPORT
    from yubikit.core.smartcard import SmartCardConnection

    class RecordedConnection(SmartCardConnection):
        @property
        def transport(self):
            return TRANSPORT.USB

        def send_and_receive(self, apdu):
            reply = session.apdu(bytes(apdu), "sdk.apdu." + bytes(apdu[:4]).hex())
            return reply.data[:-2], reply.status

        def close(self):
            pass

    return RecordedConnection()


def fixture_key(session, algorithm):
    if algorithm.startswith("RSA"):
        return rsa.generate_private_key(65537, int(algorithm[3:]))
    if algorithm == "ED25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(session.fixture("cards.ed25519"))
    if algorithm == "X25519":
        return x25519.X25519PrivateKey.from_private_bytes(session.fixture("cards.x25519"))
    curve = {"ECCP256": ec.SECP256R1, "ECCP384": ec.SECP384R1,
             "SECP256R1": ec.SECP256R1, "SECP384R1": ec.SECP384R1, "SECP521R1": ec.SECP521R1,
             "SECP256K1": ec.SECP256K1, "BrainpoolP256R1": ec.BrainpoolP256R1,
             "BrainpoolP384R1": ec.BrainpoolP384R1, "BrainpoolP512R1": ec.BrainpoolP512R1}[algorithm]()
    return ec.derive_private_key(int.from_bytes(session.fixture("cards." + algorithm, 24), "big") + 1, curve)


def encoded_public(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sdk_supported(session, operation):
    from yubikit.core import NotSupportedError
    from .runner import SkipCase
    try:
        return operation()
    except NotSupportedError as error:
        session.trace.emit("host_rejected", library="yubikit", reason=str(error))
        raise SkipCase(f"SDK capability check: {error}", expected_cause=error) from error


def piv(session):
    from yubikit.piv import KEY_TYPE, SLOT, PivSession
    slot = SLOT(0x82)
    for algorithm in ("ECCP256", "ECCP384", "RSA2048", "ED25519", "X25519"):
        for origin in ("import", "generate"):
            label = f"piv.fixture.{algorithm}.{origin}"
            with session.case(label, ("P03", "P06", "P09", "P10", "P11", "P12", "P15"), effects=("replace_piv_slot_82",), touch=True):
                session.require(session.options.management_key is not None and session.options.piv_pin is not None,
                                "PIV fixtures require --management-key-env and --piv-pin-env")
                piv = PivSession(connection(session))
                piv.authenticate(session.options.management_key)
                piv.verify_pin(session.options.piv_pin)
                created = False
                try:
                    key_type = KEY_TYPE[algorithm]
                    if origin == "import":
                        private = fixture_key(session, algorithm)
                        sdk_supported(session, lambda: piv.put_key(slot, private))
                        public = private.public_key()
                    else:
                        public = sdk_supported(session, lambda: piv.generate_key(slot, key_type))
                    created = True
                    session.state("piv.slot82", origin + ":" + algorithm)
                    session.observe("algorithm", algorithm)
                    session.observe("origin", origin)
                    session.observe("public_key", encoded_public(public), "presence" if origin == "generate" or algorithm == "RSA2048" else "exact")
                    message = session.fixture("piv.message", 48)
                    if algorithm == "X25519":
                        peer = x25519.X25519PrivateKey.from_private_bytes(session.fixture("piv.x25519.peer"))
                        got = piv.calculate_secret(slot, peer.public_key())
                        session.check("X25519 shared secret", got, peer.exchange(public))
                    else:
                        signature = piv.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15() if algorithm == "RSA2048" else None)
                        cose_alg = {"ECCP256": -7, "ECCP384": -7, "RSA2048": -257, "ED25519": -8}[algorithm]
                        verified(session, "PIV signature", public, cose_alg, signature, message)
                        if algorithm.startswith("ECC"):
                            peer = ec.generate_private_key(public.curve)
                            session.check("ECDH shared secret", piv.calculate_secret(slot, peer.public_key()), peer.exchange(ec.ECDH(), public))
                        elif algorithm == "RSA2048":
                            plain = session.fixture("piv.rsa.plaintext", 32)
                            ciphertext = public.encrypt(plain, padding.PKCS1v15())
                            session.check("RSA decryption", piv.decrypt(slot, ciphertext, padding.PKCS1v15()), plain)
                finally:
                    if created and not session.broken:
                        session.trace.phase = "cleanup"
                        if piv.version >= (5, 7, 0):
                            piv.authenticate(session.options.management_key)
                            piv.delete_key(slot)
                            session.state("piv.slot82", "empty")
                            session.observe("cleanup", "key deleted")
                        else:
                            session.observe("cleanup", "profile has no DELETE KEY; fixture remains in slot 82")


def openpgp(session):
    from yubikit.openpgp import KEY_REF, OpenPgpSession
    for reference in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        for origin in ("import", "generate"):
            label = f"openpgp.fixture.{reference.name.lower()}.{origin}.p256"
            with session.case(label, ("O02", "O08", "O09", "O10", "O11", "O12", "O13", "O22"), effects=(f"replace_openpgp_{reference.name.lower()}_key",), touch=True):
                session.require(session.options.openpgp_pin is not None and session.options.openpgp_admin is not None,
                                "OpenPGP fixtures require --openpgp-pin-env and --openpgp-admin-env")
                pgp = OpenPgpSession(connection(session))
                pgp.verify_admin(session.options.openpgp_admin)
                created = False
                try:
                    if origin == "import":
                        private = fixture_key(session, "ECCP256")
                        sdk_supported(session, lambda: pgp_keys.put_key(session, pgp, reference, private))
                        public = private.public_key()
                    else:
                        public = sdk_supported(session, lambda: pgp_keys.generate(session, pgp, reference, "SECP256R1"))
                    created = True
                    session.state("openpgp." + reference.name, origin + ":p256")
                    session.check("public key readback", encoded_public(pgp.get_public_key(reference)), encoded_public(public))
                    session.observe("public_key", encoded_public(public), "presence" if origin == "generate" else "exact")
                    pgp.verify_pin(session.options.openpgp_pin, extended=reference != KEY_REF.SIG)
                    if reference == KEY_REF.DEC:
                        peer = ec.generate_private_key(ec.SECP256R1())
                        session.check("OpenPGP ECDH", pgp.decrypt(peer.public_key()), peer.exchange(ec.ECDH(), public))
                    else:
                        before = pgp.get_signature_counter()
                        message = session.fixture("openpgp.message", 48)
                        operation = pgp.sign if reference == KEY_REF.SIG else pgp.authenticate
                        signature = operation(message, hashes.SHA256())
                        verified(session, "OpenPGP signature", public, -7, signature, message)
                        after = pgp.get_signature_counter()
                        session.check("signature counter scope", after - before, 1 if reference == KEY_REF.SIG else 0)
                finally:
                    if created and not session.broken:
                        session.trace.phase = "cleanup"
                        pgp.verify_admin(session.options.openpgp_admin)
                        sdk_supported(session, lambda: pgp_keys.delete_key(session, pgp, reference))
                        session.state("openpgp." + reference.name, "empty")
                        session.observe("cleanup", "key deleted; algorithm attributes restored by SDK to RSA2048")
