# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""AES PSO uses PW1.82 and DEC UIF independently of the asymmetric key and MSE."""
from contextlib import contextmanager
from itertools import product

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import codec, pgp_keys
from .lifecycle import Action, change
from .openpgp_lifecycle import fixture_session
from .openpgp_mse import cue


def crypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return cipher.update(data) + cipher.finalize()


@contextmanager
def fixture(session, width):
    session.require(session.profile == "rsk", "AES PSO routing requires RS-Key", "excluded_by_profile")
    session.select("piv")
    sdk = fixture_session(session)
    uif = sdk.get_data(0xd7)
    session.require(uif[:1] != b"\x02", "AES policy isolation needs reversible DEC UIF")
    key = session.fixture("OpenPGP.AES.key", width)
    try:
        sdk.put_data(0xd7, b"\x00\x20")
        sdk.put_data(0xd5, key)
        yield sdk, key
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            cue(session, "accept")
            sdk.verify_admin(session.options.openpgp_admin)
            sdk.put_data(0xd7, uif)
            session.observe("AES_fixture_cleanup", "write-only fixture key remains until explicit applet reset; no export or delete command")


def operation(session, key, decrypt=False, size=32, status=0x9000):
    plain = session.fixture("OpenPGP.AES.message", size)
    encrypted = crypt(key, plain) if size % 16 == 0 else bytes(size)
    reply = session.apdu(codec.apdu(0x2a, 0x80 if decrypt else 0x86, 0x86 if decrypt else 0x80, b"\x02" + encrypted if decrypt else plain))
    session.check("AES authorization, touch and block grammar have distinct outcomes", reply.status, status)
    if status == 0x9000:
        session.check("AES independently verifies the exact zero-IV CBC result", session.card_value(reply), plain if decrypt else b"\x02" + encrypted)
    else:
        session.check("AES refusal exposes no plaintext or ciphertext", reply.data[:-2], b"")


def run(session):
    for width, decrypt, reference, touch, outcome in product((16, 32), (False, True), (None, 0x81, 0x82, 0x83), (False, True), ("accept", "decline", "timeout")):
        with session.case(f"openpgp.AES.width-{width}.decrypt-{decrypt}.grant-{reference}.UIF-{touch}.{outcome}", ("O02", "O13", "O15", "O19", "O22", "G10", "G13", "G14"), effects=("replace_openpgp_aes_key", "config_change"), touch=True):
            session.require(not touch or session.options.operator, "controlled AES UIF outcome needs operator action")
            session.require(not touch or outcome != "decline" or "display" in session.options.features, "UIF decline needs a declared display")
            session.require(not touch or outcome != "timeout" or session.options.timeout > 130, "UIF timeout needs the complete device window")
            with fixture(session, width) as (sdk, key):
                sdk.put_data(0xd7, bytes([touch, 0x20]))
                for ref in (0x81, 0x82, 0x83):
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, ref)))
                if reference is not None:
                    sdk.verify_admin(session.options.openpgp_admin) if reference == 0x83 else sdk.verify_pin(session.options.openpgp_pin, extended=reference == 0x82)
                before = sdk.get_signature_counter()
                cue(session, outcome)
                operation(session, key, decrypt, status=0x6982 if reference != 0x82 else 0x6600 if touch and outcome != "accept" else 0x9000)
                session.check("AES success and failure preserve the signature counter", sdk.get_signature_counter(), before)
                cue(session, "accept")
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                operation(session, key, decrypt)
    for width, decrypt, size in product((16, 32), (False, True), (0, 1, 15, 16, 17, 31, 32, 255, 256)):
        with session.case(f"openpgp.AES.block-grammar.width-{width}.decrypt-{decrypt}.length-{size}", ("O15", "O22", "G01", "G03", "G14"), effects=("replace_openpgp_aes_key", "config_change")):
            with fixture(session, width) as (sdk, key):
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                operation(session, key, decrypt, size, 0x9000 if size and size % 16 == 0 else 0x6700)
                operation(session, key, decrypt)
    for authorized, size in product((False, True), (0, 1, 15, 16, 17, 23, 24, 25, 31, 32, 33, 127, 128, 255)):
        with session.case(f"openpgp.AES.PUT-D5.PW3-{authorized}.length-{size}", ("O07", "O15", "O22", "G01", "G03", "G10", "G13", "G14"), effects=("replace_openpgp_aes_key", "config_change")):
            with fixture(session, 32) as (sdk, key):
                candidate = session.fixture("OpenPGP.AES.replacement", size)
                if not authorized:
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                status = 0x6982 if not authorized else 0x9000 if size in (16, 32) else 0x6a80
                session.check("AES key width follows PW3; no deletion or 24-byte import", session.apdu(codec.apdu(0xda, 0, 0xd5, candidate)).status, status)
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                operation(session, candidate if status == 0x9000 else key)
    independence(session)


def independence(session):
    from yubikit.openpgp import KEY_REF
    for transition, action in product(("import", "replace", "delete", "generate", "MSE"), Action):
        with session.case(f"openpgp.AES.DEC-independent.{transition}.{action.value}", ("O08", "O09", "O10", "O13", "O14", "O15", "O22", "X11", "G09", "G14"), effects=("replace_openpgp_aes_key", "replace_openpgp_keys", "config_change", "reboot") if action == Action.POWER_CYCLE else ("replace_openpgp_aes_key", "replace_openpgp_keys", "config_change"), touch=True):
            with fixture(session, 32) as (sdk, key):
                installed = False
                try:
                    pgp_keys.put_key(session, sdk, KEY_REF.DEC, ec.derive_private_key(101, ec.SECP256R1()))
                    installed = True
                    if transition == "replace":
                        pgp_keys.put_key(session, sdk, KEY_REF.DEC, ec.derive_private_key(102, ec.SECP256R1()))
                    elif transition == "delete":
                        pgp_keys.delete_key(session, sdk, KEY_REF.DEC)
                    elif transition == "generate":
                        pgp_keys.generate(session, sdk, KEY_REF.DEC, "SECP256R1")
                    elif transition == "MSE":
                        session.card_value(session.apdu(codec.apdu(0x22, 0x41, 0xb8, b"\x83\x01\x03")))
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    operation(session, key)
                    operation(session, key, True)
                    change(session, action)
                    session.select("openpgp")
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    operation(session, key)
                    operation(session, key, True)
                finally:
                    if installed and not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        pgp_keys.delete_key(session, sdk, KEY_REF.DEC)
