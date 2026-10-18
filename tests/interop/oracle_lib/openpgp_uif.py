# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Touch refusal and attestation validation have different one-shot boundaries."""
from contextlib import contextmanager
from itertools import product

from cryptography import x509

from . import codec, pgp_keys
from .card_keys import certificate
from .openpgp_lifecycle import fixture_session
from .openpgp_mse import cue, operate
from .openpgp_operations import operation_key, sign


def uif_values():
    yield "empty-deletes", b"", 0x9000
    for flag, feature in product((0, 1, 3, 127, 255), (0, 1, 32, 255)):
        yield f"flag-{flag}-opaque-feature-{feature}", bytes([flag, feature]), 0x9000 if flag <= 1 else 0x6a80
    for size in (1, 3, 4, 127, 128, 255):
        yield f"length-{size}", b"\x01" * size, 0x6a80


def grammar(session):
    for tag, granted in product(range(0xd6, 0xda), (False, True)):
        for label, value, status in uif_values():
            with session.case(f"openpgp.UIF.DO-{tag:02x}.PW3-{granted}.{label}", ("O07", "O19", "O22", "G01", "G03", "G04", "G10", "G13", "G14"), effects=("config_change",)):
                session.require(session.profile == "rsk", "UIF data-object validation requires RS-Key", "excluded_by_profile")
                sdk = fixture_session(session)
                old = sdk.get_data(tag)
                session.require(old[:1] != b"\x02", "permanent UIF needs the separately gated reset fixture")
                try:
                    sdk.put_data(tag, b"\x01\x20")
                    if not granted:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                    reply = session.apdu(codec.apdu(0xda, 0, tag, value))
                    session.check("UIF owner precedes flag, opaque feature and body validation", reply.status, status if granted else 0x6982)
                    session.check("UIF write or refusal keeps the exact appropriate value", sdk.get_data(tag), value if granted and status == 0x9000 else b"\x01\x20")
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        sdk.put_data(tag, old)


@contextmanager
def generated(session, slot, mode):
    session.select("piv")
    sdk = fixture_session(session)
    old_mode, old_uif = sdk.get_data(0xc4)[0], sdk.get_data(0xd9)
    session.require(old_uif[:1] != b"\x02", "attestation UIF needs a reversible policy")
    occurrence = {1: 2, 2: 1, 3: 0}[int(slot)]
    session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, bytes.fromhex("60045c027f21"))))
    old_cert = sdk.get_data(0x7f21)
    installed = configured = False
    try:
        public = pgp_keys.generate(session, sdk, slot, "SECP256R1")
        installed = True
        sdk.put_data(0xc4, bytes([mode]))
        configured = True
        sdk.put_data(0xd9, b"\x00\x20")
        yield sdk, public, occurrence
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            cue(session, "accept")
            sdk.verify_admin(session.options.openpgp_admin)
            if configured:
                sdk.put_data(0xc4, bytes([old_mode]))
                sdk.put_data(0xd9, old_uif)
            session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, bytes.fromhex("60045c027f21"))))
            sdk.put_data(0x7f21, old_cert)
            if installed:
                pgp_keys.delete_key(session, sdk, slot)


def attest(session, sdk, slot, public, occurrence, expected=0x9000, wire=None):
    reply = session.apdu(wire if wire is not None else codec.apdu(0xfb, int(slot), cla=0x80))
    session.check("ATTEST applies authentication, grammar, UIF and origin in order", reply.status, expected)
    if expected == 0x9000:
        session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, bytes.fromhex("60045c027f21"))))
        leaf = x509.load_der_x509_certificate(sdk.get_data(0x7f21))
        root = x509.load_der_x509_certificate(sdk.get_data(0xfc))
        certificate(session, leaf, root, public)
    else:
        session.check("refused ATTEST returns no private bytes", reply.data[:-2], b"")


def policies(session):
    from yubikit.openpgp import KEY_REF
    for operation, mode, policy, outcome, reference in product(("SIG", "AUT", "DEC", "ATTEST"), (0, 1), (0, 1), ("accept", "decline", "timeout"), (None, 0x81, 0x82, 0x83)):
        with session.case(f"openpgp.UIF.operation-{operation}.mode-{mode}.UIF-{policy}.{outcome}.grant-{reference}", ("O02", "O11", "O12", "O13", "O19", "O20", "O22", "G10", "G13", "G14"), effects=("replace_openpgp_keys", "config_change", "write_openpgp_certificates"), touch=True):
            session.require(session.profile == "rsk", "one-shot UIF and attestation ordering require RS-Key", "excluded_by_profile")
            session.require(session.options.operator, "UIF outcomes require controlled operator action")
            session.require(outcome != "decline" or "display" in session.options.features, "explicit UIF decline requires a declared display")
            session.require(outcome != "timeout" or session.options.timeout > 130, "UIF timeout must cover the complete device window")
            slot = KEY_REF.SIG if operation in ("SIG", "ATTEST") else KEY_REF.AUT if operation == "AUT" else KEY_REF.DEC
            context = generated(session, slot, mode) if operation == "ATTEST" else operation_key(session, slot, "SECP256R1", mode)
            with context as held:
                sdk, public = held[0], held[1] if operation == "ATTEST" else held[1].public_key()
                occurrence = held[2] if operation == "ATTEST" else None
                sdk.put_data(0xd9 if operation == "ATTEST" else 0xd5 + int(slot), bytes([policy, 0x20]))
                for ref in (0x81, 0x82, 0x83):
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, ref)))
                if reference is not None:
                    sdk.verify_admin(session.options.openpgp_admin) if reference == 0x83 else sdk.verify_pin(session.options.openpgp_pin, extended=reference == 0x82)
                required = 0x81 if operation in ("SIG", "ATTEST") else 0x82
                before = sdk.get_signature_counter()
                cue(session, outcome)
                expected = 0x6982 if reference != required else 0x6600 if policy and outcome != "accept" else 0x9000
                if operation == "SIG":
                    sign(session, slot, public, session.fixture("OpenPGP.UIF.signature"), expected)
                elif operation == "ATTEST":
                    attest(session, sdk, slot, public, occurrence, expected)
                else:
                    operate(session, 0xa4 if operation == "AUT" else 0xb8, held[1], expected)
                spent = mode == 0 and reference == required and (operation == "SIG" or operation == "ATTEST" and expected == 0x9000)
                left = sdk.get_data(0xc4)[4]
                session.check("UIF decline spends one-shot SIG but preserves one-shot ATTEST", session.apdu(codec.apdu(0x20, p2=required)).status, 0x9000 if reference == required and not spent else 0x63c0 | min(left, 15))
                session.check("only a successful SIG increments the signature counter", sdk.get_signature_counter(), before + (operation == "SIG" and expected == 0x9000))
                cue(session, "accept")
                sdk.verify_pin(session.options.openpgp_pin, extended=required == 0x82)
                if operation == "SIG":
                    sign(session, slot, public, session.fixture("OpenPGP.UIF.control"))
                elif operation == "ATTEST":
                    attest(session, sdk, slot, public, occurrence)
                else:
                    operate(session, 0xa4 if operation == "AUT" else 0xb8, held[1])


def run(session):
    grammar(session)
    policies(session)


def permanent(session):
    from yubikit.openpgp import KEY_REF
    from .openpgp_reset_profile import activate
    for operation in ("SIG", "AUT", "DEC", "ATTEST"):
        with session.case("openpgp.UIF.permanent.operation-" + operation, ("O02", "O11", "O12", "O13", "O19", "O20", "O21", "O22", "G10", "G14"), effects=("replace_openpgp_keys", "config_change", "write_openpgp_certificates", "applet_reset"), touch=True):
            session.require(session.profile == "rsk", "permanent UIF profile requires RS-Key", "excluded_by_profile")
            session.require(session.options.operator and "display" in session.options.features and session.options.timeout > 130, "fixed UIF refusal/timeout needs a controlled display and full timeout")
            slot = KEY_REF.SIG if operation in ("SIG", "ATTEST") else KEY_REF.AUT if operation == "AUT" else KEY_REF.DEC
            context = generated(session, slot, 0) if operation == "ATTEST" else operation_key(session, slot, "SECP256R1", 0)
            with context as held:
                sdk, public = held[0], held[1] if operation == "ATTEST" else held[1].public_key()
                fixed = False
                try:
                    sdk.put_data(0xd9 if operation == "ATTEST" else 0xd5 + int(slot), b"\x02\x20")
                    fixed = True
                    for outcome in ("decline", "timeout", "accept"):
                        sdk.verify_pin(session.options.openpgp_pin, extended=operation in ("AUT", "DEC"))
                        before = sdk.get_signature_counter()
                        cue(session, outcome)
                        status = 0x9000 if outcome == "accept" else 0x6600
                        if operation == "SIG":
                            sign(session, slot, public, session.fixture("OpenPGP.fixed-UIF"), status)
                        elif operation == "ATTEST":
                            attest(session, sdk, slot, public, held[2], status)
                        else:
                            operate(session, 0xa4 if operation == "AUT" else 0xb8, held[1], status)
                        session.check("fixed UIF preserves signature counter on every refusal/non-SIG operation", sdk.get_signature_counter(), before + (operation == "SIG" and status == 0x9000))
                        required = 0x81 if operation in ("SIG", "ATTEST") else 0x82
                        spent = operation == "SIG" or operation == "ATTEST" and status == 0x9000
                        session.check("fixed UIF has the same one-shot consumption boundary", session.apdu(codec.apdu(0x20, p2=required)).status, 0x63c0 | min(sdk.get_data(0xc4)[4], 15) if spent else 0x9000)
                finally:
                    if fixed and not session.broken:
                        session.trace.phase = "cleanup"
                        cue(session, "accept")
                        sdk.verify_admin(session.options.openpgp_admin)
                        session.card_value(session.apdu(codec.apdu(0xe6)))
                        activate(session)
