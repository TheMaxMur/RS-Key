# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw private-operation widths are verified without imposing an SDK digest size."""
from contextlib import contextmanager
from itertools import product

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils

from . import codec, pgp_keys
from .card_keys import PGP_ALGORITHMS
from .cards import fixture_key
from .openpgp_lifecycle import fixture_session

SIGN_ALGORITHMS = tuple(value for value in PGP_ALGORITHMS if value != "X25519")
LENGTHS = (0, 1, 15, 16, 23, 24, 31, 32, 33, 47, 48, 49, 63, 64, 65, 66, 67, 127, 128, 255, 256)


class RawPrehash(hashes.HashAlgorithm):
    name, block_size = "sha512", 128

    def __init__(self, size):
        self.size = size

    @property
    def digest_size(self):
        return self.size


def verification_digest(public, data):
    if isinstance(public.curve, ec.SECP521R1) and len(data) >= 66:
        # ecdsa 0.17 bytes2scalar masks low 521 bits; OpenSSL truncates high bits.
        integer = int.from_bytes(data[:66], "big") & ((1 << 521) - 1)
        return (integer << 7).to_bytes(66, "big")
    return data or b"\x00"


def verify_signature(session, public, payload, signature):
    if isinstance(public, rsa.RSAPublicKey):
        numbers, width = public.public_numbers(), public.key_size // 8
        expected = b"\x00\x01" + b"\xff" * (width - len(payload) - 3) + b"\x00" + payload
        session.check("raw RSA signature has the modulus width", len(signature), width)
        session.check("raw RSA signature independently recovers exact PKCS1 bytes", pow(int.from_bytes(signature, "big"), numbers.e, numbers.n).to_bytes(width, "big"), expected)
    elif isinstance(public, ed25519.Ed25519PublicKey):
        public.verify(signature, payload)
        session.check("raw EdDSA signature covers the entire input message", True)
    else:
        width = (public.curve.key_size + 7) // 8
        session.check("raw EC signature contains both full scalar halves", len(signature), width * 2)
        der = utils.encode_dss_signature(int.from_bytes(signature[:width], "big"), int.from_bytes(signature[width:], "big"))
        digest = verification_digest(public, payload)
        public.verify(der, digest, ec.ECDSA(utils.Prehashed(RawPrehash(len(digest)))))
        session.check("raw ECDSA signature independently verifies the profiled prehash", True)
        if isinstance(public.curve, ec.SECP521R1) and len(payload) >= 66:
            session.observe("prehash_profile", "ecdsa 0.17: first 66 bytes, low 521 bits; not standard high-bit truncation")


def sign(session, slot, public, payload, expected=0x9000):
    reply = session.apdu(codec.apdu(0x2a, 0x9e, 0x9a, payload) if int(slot) == 1 else codec.apdu(0x88, data=payload))
    session.check("raw signature input has the exact width/policy outcome", reply.status, expected)
    if expected == 0x9000:
        verify_signature(session, public, payload, session.card_value(reply))
    else:
        session.check("refused signature produces no partial private output", reply.data[:-2], b"")


@contextmanager
def operation_key(session, slot, algorithm, mode=1):
    session.require(session.profile == "rsk", "raw private-operation profiles require RS-Key", "excluded_by_profile")
    session.select("piv")
    sdk = fixture_session(session)
    private = fixture_key(session, algorithm)
    uif_tag = 0xd5 + int(slot)
    old_mode, old_uif = sdk.get_data(0xc4)[0], sdk.get_data(uif_tag)
    session.require(old_uif[:1] != b"\x02", "input isolation requires a UIF policy that can be restored")
    installed = configured = False
    try:
        pgp_keys.put_key(session, sdk, slot, private)
        installed = True
        sdk.put_data(0xc4, bytes([mode]))
        configured = True
        sdk.put_data(uif_tag, b"\x00\x20")
        yield sdk, private
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            sdk.verify_admin(session.options.openpgp_admin)
            if configured:
                sdk.put_data(0xc4, bytes([old_mode]))
                sdk.put_data(uif_tag, old_uif)
            if installed:
                pgp_keys.delete_key(session, sdk, slot)


def signatures(session):
    from yubikit.openpgp import KEY_REF
    for algorithm, slot, mode in product(SIGN_ALGORITHMS, (KEY_REF.SIG, KEY_REF.AUT), (0, 1)):
        sizes = sorted(set(LENGTHS) | ({int(algorithm[3:]) // 8 + delta for delta in (-12, -11, -10, -1, 0, 1)} if algorithm.startswith("RSA") else set()))
        for size in sizes:
            with session.case(f"openpgp.raw-signature.{slot.name}.{algorithm}.PW1-mode-{mode}.length-{size}", ("O02", "O08", "O10", "O11", "O12", "O19", "O22", "G03", "G10", "G13", "G14"), effects=("replace_openpgp_keys", "config_change"), touch=True,
                    parameters={"slot": slot.name, "algorithm": algorithm, "PW1_mode": mode, "input_length": size}):
                with operation_key(session, slot, algorithm, mode) as (sdk, private):
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    before = sdk.get_signature_counter()
                    payload = session.fixture("OpenPGP.raw-signature", size)
                    expected = 0x6581 if algorithm.startswith("RSA") and size > private.key_size // 8 - 11 else 0x9000
                    sign(session, slot, private.public_key(), payload, expected)
                    session.check("only a successful SIG operation advances the signature counter", sdk.get_signature_counter(), before + (slot == KEY_REF.SIG and expected == 0x9000))
                    reference = 0x81 if slot == KEY_REF.SIG else 0x82
                    status = session.apdu(codec.apdu(0x20, p2=reference)).status
                    left = sdk.get_data(0xc4)[4]
                    session.check("one-shot SIG status is spent on success and refusal; AUT never spends it", status, 0x63c0 | min(left, 15) if slot == KEY_REF.SIG and mode == 0 else 0x9000)
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    sign(session, slot, private.public_key(), session.fixture("OpenPGP.raw-signature.control", 32))


def run(session):
    signatures(session)
