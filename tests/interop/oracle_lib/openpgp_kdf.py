# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Fixed-layout KDF reseeding is allowed only while all owner slots are empty."""
from contextlib import contextmanager
from itertools import product

from . import codec, pgp_keys
from .cards import fixture_key
from .lifecycle import Action, change
from .openpgp_lifecycle import fixture_session, kdf_body
from .openpgp_mse import operate
from .openpgp_operations import operation_key, sign

OFF = b"\x81\x01\x00"


def inputs(body):
    yield "valid", body, True
    fields = list(codec.parse_tlv(body))
    for size in range(len(body)):
        yield f"truncated-{size}", body[:size], False
    for suffix in (b"\x00", codec.tlv(0x99, b"x"), body):
        yield "trailing-" + suffix.hex(), body + suffix, False
    for index, (tag, value) in enumerate(fields):
        for label, replacement in (("missing", b""), ("wrong-tag", codec.tlv(tag ^ 0x40, value)),
                ("short", codec.tlv(tag, value[:-1])), ("long", codec.tlv(tag, value + b"x")),
                ("duplicate", codec.tlv(tag, value) * 2), ("BER-length", bytes([tag, 0x81, len(value)]) + value)):
            encoded = [codec.tlv(t, v) for t, v in fields]
            encoded[index] = replacement
            yield f"field-{tag:02x}-{label}", b"".join(encoded), False
    yield "reordered", b"".join(codec.tlv(t, v) for t, v in reversed(fields)), False
    for tag in (0x81, 0x82, 0x83):
        for value in (0, 1, 255):
            # The firmware stores algorithm/hash/count bytes as host metadata.
            yield f"opaque-{tag:02x}-{value}", b"".join(codec.tlv(t, bytes([value]) * len(v) if t == tag else v) for t, v in fields), True


def raw_verify(session, reference, secret):
    return session.card_value(session.apdu(codec.apdu(0x20, p2=reference, data=secret)))


def populated(session):
    from yubikit.openpgp import KEY_REF
    for slot, single, action in product((KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT), (False, True), (None, Action.POWER_CYCLE)):
        for label in ("off", "on", "malformed", "missing-admin"):
            with session.case(f"openpgp.KDF.populated.{slot.name}.single-{single}.reboot-{bool(action)}.{label}", ("O03", "O11", "O12", "O13", "O18", "O22", "X11", "G05", "G10", "G13", "G14"),
                    effects=("replace_openpgp_keys", "config_change", "pin_change", "reboot") if action else ("replace_openpgp_keys", "config_change", "pin_change"), touch=True):
                with operation_key(session, slot, "SECP256R1") as (sdk, private):
                    original = sdk.get_data(0xf9)
                    original_status = sdk.get_data(0xc4)
                    body, _, _ = kdf_body(session, single)
                    data = OFF if label == "off" else body[:-1] if label == "malformed" else body
                    if label == "missing-admin":
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                    reply = session.apdu(codec.apdu(0xda, 0, 0xf9, data))
                    expected = 0x6982 if label == "missing-admin" else 0x6a80 if label == "malformed" else 0x6985
                    session.check("KDF cannot reseed references beside an existing private key", reply.status, expected)
                    session.check("KDF refusal leaves exact policy and retry counters", (sdk.get_data(0xf9), sdk.get_data(0xc4)), (original, original_status))
                    if action:
                        change(session, action)
                        session.select("openpgp")
                        session.check("refused KDF policy remains unchanged after power loss", sdk.get_data(0xf9), original)
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    if slot == KEY_REF.SIG:
                        sign(session, slot, private.public_key(), session.fixture("OpenPGP.KDF.retained-key"))
                    else:
                        operate(session, 0xb8 if slot == KEY_REF.DEC else 0xa4, private)


@contextmanager
def empty(session):
    from yubikit.openpgp import KEY_REF
    session.require(session.profile == "rsk", "fixed KDF layout semantics require RS-Key", "excluded_by_profile")
    sdk = fixture_session(session)
    session.require(sdk.get_data(0xf9) == OFF, "empty KDF fixture requires known disabled KDF")
    for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
        session.require(session.apdu(codec.apdu(0x47, 0x81, data=slot.crt)).status == 0x6a88, "KDF reseed requires every owner key slot to be confirmed empty")
    session.require(session.options.openpgp_reset_code is not None, "supply known reset code (empty means unset) for exact restoration")
    installed = False
    current_admin = session.options.openpgp_admin.encode()
    try:
        def landed(admin):
            nonlocal installed, current_admin
            installed, current_admin = True, admin
        yield sdk, landed
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            raw_verify(session, 0x83, current_admin)
            if installed:
                sdk.put_data(0xf9, OFF)
                session.card_value(session.apdu(codec.apdu(0x24, p2=0x81, data=b"123456" + session.options.openpgp_pin.encode())))
                session.card_value(session.apdu(codec.apdu(0x24, p2=0x83, data=b"12345678" + session.options.openpgp_admin.encode())))
            sdk.verify_admin(session.options.openpgp_admin)
            sdk.put_data(0xd3, session.options.openpgp_reset_code.encode())
            sdk.verify_pin(session.options.openpgp_pin)
            session.check("KDF cleanup restores the disabled policy", sdk.get_data(0xf9), OFF)


def run(session):
    for single in (False, True):
        # Expansion uses the same deterministic wire body as the executing case.
        base, _, _ = kdf_body(session, single)
        for label, body, accepted in inputs(base):
            for authorized in (False, True):
                with session.case(f"openpgp.KDF.empty.single-{single}.PW3-{authorized}.{label}", ("O02", "O04", "O07", "O18", "O22", "G01", "G03", "G04", "G05", "G07", "G10", "G13", "G14"),
                        effects=("pin_change", "pin_attempts")):
                    with empty(session) as (sdk, landed):
                        sdk.put_data(0xd3, "oracle-KDF-reset-code".encode())
                        if not authorized:
                            session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                        reply = session.apdu(codec.apdu(0xda, 0, 0xf9, body))
                        session.check("KDF fixed layout is judged after PW3 and before reseeding", reply.status, 0x6982 if not authorized else 0x9000 if accepted else 0x6a80)
                        if authorized and accepted:
                            fields = dict(codec.parse_tlv(body))
                            # Record landed state before any subsequent assertion can fail.
                            landed(fields[0x88])
                            session.check("accepted KDF stores even opaque host metadata verbatim", sdk.get_data(0xf9), body)
                            session.check("KDF reseed deactivates incompatible reset-code verifier", sdk.get_data(0xc4)[5], 0)
                            raw_verify(session, 0x81, fields[0x87])
                            raw_verify(session, 0x82, fields[0x87])
                            raw_verify(session, 0x83, fields[0x88])
                            domain = ("openpgp", 0x81)
                            with session.attempts(domain, 2):
                                try:
                                    wrong = session.apdu(codec.apdu(0x20, p2=0x81, data=b"123456"))
                                    session.check("raw factory PIN no longer matches the KDF-output verifier", wrong.status, 0x6982)
                                finally:
                                    if not session.broken:
                                        raw_verify(session, 0x81, fields[0x87])
                        else:
                            session.check("refused KDF retains old verifier policy", sdk.get_data(0xf9), OFF)
                            sdk.verify_admin(session.options.openpgp_admin)
                            sdk.verify_pin(session.options.openpgp_pin)
                        sdk.verify_admin(session.options.openpgp_admin) if not authorized or not accepted else raw_verify(session, 0x83, dict(codec.parse_tlv(body))[0x88])
                        sdk.put_data(0xd3, session.options.openpgp_reset_code.encode())
    persistence(session)


def persistence(session):
    from yubikit.openpgp import KEY_REF
    for single, action in product((False, True), Action):
        with session.case(f"openpgp.KDF.installed-before-key.single-{single}.{action.value}", ("O02", "O03", "O04", "O11", "O18", "O22", "X11", "G10", "G14"),
                effects=("pin_change", "replace_openpgp_keys", "reboot") if action == Action.POWER_CYCLE else ("pin_change", "replace_openpgp_keys"), touch=True):
            with empty(session) as (sdk, landed):
                body, user, admin = kdf_body(session, single)
                sdk.put_data(0xf9, body)
                landed(admin)
                private, installed = fixture_key(session, "SECP256R1"), False
                try:
                    pgp_keys.put_key(session, sdk, KEY_REF.SIG, private)
                    installed = True
                    raw_verify(session, 0x81, user)
                    before = sdk.get_signature_counter()
                    sign(session, KEY_REF.SIG, private.public_key(), session.fixture("OpenPGP.KDF.before-reconnect"))
                    change(session, action)
                    session.select("openpgp")
                    session.check("KDF DO remains exact across each connection lifetime", sdk.get_data(0xf9), body)
                    session.check("successful signature counter persists under KDF", sdk.get_signature_counter(), before + 1)
                    session.check("connection change retires KDF-derived PW1 access status", session.apdu(codec.apdu(0x20, p2=0x81)).status, 0x63c0 | min(sdk.get_data(0xc4)[4], 15))
                    raw_verify(session, 0x81, user)
                    sign(session, KEY_REF.SIG, private.public_key(), session.fixture("OpenPGP.KDF.after-reconnect"))
                    raw_verify(session, 0x83, admin)
                    session.check("even identical KDF cannot reseed references after key installation", session.apdu(codec.apdu(0xda, 0, 0xf9, body)).status, 0x6985)
                finally:
                    if installed and not session.broken:
                        session.trace.phase = "cleanup"
                        raw_verify(session, 0x83, admin)
                        pgp_keys.delete_key(session, sdk, KEY_REF.SIG)
