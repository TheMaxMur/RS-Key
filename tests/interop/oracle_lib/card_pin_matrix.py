# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reference syntax and PIN changes are witnessed with a populated signing key."""
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes

from . import pgp_keys
from . import codec
from .cards import fixture_key, sdk_supported
from .card_states import sdk_refused
from .fido import verified
from .lifecycle import Action, change
from .piv_lifecycle import wire_pin
from .piv_matrix import key_fixture
from .openpgp_lifecycle import fixture_session as pgp_session


def piv_sign(session, sdk, key):
    from yubikit.piv import KEY_TYPE, SLOT
    message = session.fixture("piv.PIN.matrix.message")
    signature = sdk.sign(SLOT(0x82), KEY_TYPE.ECCP256, message, hashes.SHA256())
    verified(session, "PIV retained key signature", key.public_key(), -7, signature, message)


def piv_verify(session):
    from yubikit.piv import PIN_POLICY
    for kind, values in (("length", (1, 2, 7, 9, 16, 24, 32)), ("reference", (0, 1, 0x81, 0x82, 0x9B, 255)), ("P1", (1, 2, 127, 254, 255))):
        for value in values:
            with session.case(f"piv.VERIFY.{kind}-{value}.grant-preservation", ("P01", "P03", "P17", "G03", "G04", "G10", "G14"),
                              effects=("replace_piv_keys",), touch=True):
                session.require(session.profile == "rsk", "VERIFY validation ordering requires RS-Key", "excluded_by_profile")
                with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)
                    before = sdk.get_pin_metadata()
                    raw = wire_pin(session.options.piv_pin)
                    p1, p2, body = 0, 0x80, raw
                    if kind == "length":
                        body = (raw * 4)[:value]
                    elif kind == "reference":
                        p2 = value
                    else:
                        p1 = value
                    response = session.apdu(codec.apdu(0x20, p1, p2, body))
                    session.check("VERIFY malformed syntax has no comparison cost", response.status, 0x6A80)
                    session.check("VERIFY malformed syntax preserves retries", sdk.get_pin_metadata().attempts_remaining, before.attempts_remaining)
                    if kind == "length" and value != 1:
                        sdk_refused(session, lambda: piv_sign(session, sdk, key), "malformed length revokes PIN grant", 0x6982)
                    else:
                        piv_sign(session, sdk, key)
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)
    with session.case("piv.VERIFY.wrong-PIN-revokes-standing-grant", ("P03", "P17", "G10", "G14"),
                      effects=("replace_piv_keys", "pin_attempts"), touch=True):
        with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
            sdk.verify_pin(session.options.piv_pin)
            initial = sdk.get_pin_metadata().attempts_remaining
            session.require(initial > 1, "one rejected comparison requires a recovery retry")
            wrong = "00000000" if session.options.piv_pin != "00000000" else "11111111"
            with session.attempts(("piv", 0x80), 3):
                try:
                    result = session.apdu(codec.apdu(0x20, p2=0x80, data=wire_pin(wrong)))
                    session.check("wrong PIN consumes one retry", result.status, 0x63C0 | (initial - 1))
                    sdk_refused(session, lambda: piv_sign(session, sdk, key), "wrong VERIFY revokes grant on populated key", 0x6982)
                finally:
                    if not session.broken:
                        sdk.verify_pin(session.options.piv_pin)
            piv_sign(session, sdk, key)


def piv_changes(session):
    for reference in (0x80, 0x81):
        for label, candidate in (("empty", ""), ("one-byte", "1"), ("below-minimum", "12345"), ("minimum", "123456"), ("minimum-plus-one", "1234567"), ("maximum", "12345678"),
                                 ("unicode-six-bytes", "ééé"), ("non-digits", "Or4!ab")):
            with session.case(f"piv.CHANGE.ref-{reference:02x}.{label}", ("P04", "P05", "P17", "G03", "G08", "G14"),
                              effects=("replace_piv_keys", "pin_change"), touch=True):
                session.require(session.profile == "rsk", "reference boundary catalog requires RS-Key", "excluded_by_profile")
                session.require(session.options.piv_puk is not None, "known PUK required for PUK boundary restore")
                with key_fixture(session) as (sdk, key):
                    original = session.options.piv_pin if reference == 0x80 else session.options.piv_puk
                    candidate_wire = candidate.encode().ljust(8, b"\xff")
                    changed = False
                    try:
                        result = session.apdu(codec.apdu(0x24, p2=reference, data=wire_pin(original) + candidate_wire))
                        changed = result.protocol == "success"
                        session.check("PIV new reference boundary", result.status, 0x9000 if 6 <= len(candidate.encode()) <= 8 else 0x6A80)
                        if changed:
                            if reference == 0x80:
                                sdk.verify_pin(candidate)
                            else:
                                session.card_value(session.apdu(codec.apdu(0x2C, p2=0x80, data=candidate_wire + wire_pin(session.options.piv_pin))))
                        sdk.verify_pin(candidate if changed and reference == 0x80 else session.options.piv_pin)
                        piv_sign(session, sdk, key)
                    finally:
                        if changed and not session.broken:
                            session.trace.phase = "cleanup"
                            session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=candidate_wire + wire_pin(original))))
                        if not session.broken:
                            sdk.verify_pin(session.options.piv_pin)
                            piv_sign(session, sdk, key)


@contextmanager
def pgp_key(session):
    from yubikit.openpgp import KEY_REF
    sdk = pgp_session(session)
    key = fixture_key(session, "ECCP256")
    created = False
    try:
        pgp_keys.put_key(session, sdk, KEY_REF.SIG, key)
        created = True
        yield sdk, key
    finally:
        if created and not session.broken:
            session.trace.phase = "cleanup"
            sdk.verify_admin(session.options.openpgp_admin)
            sdk_supported(session, lambda: pgp_keys.delete_key(session, sdk, KEY_REF.SIG))


def pgp_sign(session, sdk, key):
    message = session.fixture("PGP.PIN.matrix.message")
    sdk.verify_pin(session.options.openpgp_pin)
    before = sdk.get_signature_counter()
    verified(session, "OpenPGP retained key signature", key.public_key(), -7, sdk.sign(message, hashes.SHA256()), message)
    session.check("retained SIG key counter increments once", sdk.get_signature_counter(), before + 1)


def pgp_changes(session):
    for reference in (0x81, 0x83):
        minimum = 6 if reference == 0x81 else 8
        for label, candidate in (("empty", ""), ("one-byte", "a"), ("below-minimum", "a" * (minimum - 1)), ("minimum", "a" * minimum), ("minimum-plus-one", "a" * (minimum + 1)),
                                 ("maximum-minus-one", "a" * 126), ("maximum", "a" * 127), ("too-long", "a" * 128),
                                 ("unicode-minimum-bytes", "é" * (minimum // 2))):
            with session.case(f"openpgp.CHANGE.ref-{reference:02x}.{label}", ("O02", "O03", "O11", "O22", "G03", "G08", "G14"),
                              effects=("replace_openpgp_sig_key", "pin_change"), touch=True):
                session.require(session.profile == "rsk", "OpenPGP reference lengths require RS-Key", "excluded_by_profile")
                with pgp_key(session) as (sdk, key):
                    original = session.options.openpgp_pin if reference == 0x81 else session.options.openpgp_admin
                    changed = False
                    try:
                        result = session.apdu(codec.apdu(0x24, p2=reference, data=original.encode() + candidate.encode()))
                        changed = result.protocol == "success"
                        if changed:
                            if reference == 0x81:
                                session.options.openpgp_pin = candidate
                            else:
                                session.options.openpgp_admin = candidate
                        session.check("OpenPGP reference length policy", result.status, 0x9000 if minimum <= len(candidate.encode()) <= 127 else 0x6985)
                        if reference == 0x83:
                            sdk.verify_admin(session.options.openpgp_admin)
                        pgp_sign(session, sdk, key)
                    finally:
                        if changed and not session.broken:
                            session.trace.phase = "cleanup"
                            session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=candidate.encode() + original.encode())))
                            if reference == 0x81:
                                session.options.openpgp_pin = original
                            else:
                                session.options.openpgp_admin = original
                        if not session.broken:
                            pgp_sign(session, sdk, key)


def pgp_binary(session):
    for reference in (0x81, 0x83):
        minimum = 6 if reference == 0x81 else 8
        candidates = (bytes(minimum), b"a\x00" + b"b" * (minimum - 2), b"\xff" * minimum,
                      b"\xc3" * minimum, b" \t" + b"x" * (minimum - 2), b"x" * 126 + b"\xc3")
        for candidate in candidates:
            with session.case(f"openpgp.CHANGE.binary-{reference:02x}." + candidate.hex(), ("O02", "O03", "O11", "G03", "G08", "G14"),
                              effects=("replace_openpgp_sig_key", "pin_change"), touch=True):
                session.require(session.profile == "rsk", "opaque reference byte semantics require RS-Key", "excluded_by_profile")
                with pgp_key(session) as (sdk, key):
                    original = (session.options.openpgp_pin if reference == 0x81 else session.options.openpgp_admin).encode()
                    changed = False
                    try:
                        session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=original + candidate)))
                        changed = True
                        verified_reference = session.apdu(codec.apdu(0x20, p2=reference, data=candidate))
                        if verified_reference.status != 0x9000:
                            session.broken = True
                            session.values["halt_reason"] = "accepted opaque reference cannot authenticate; secret state needs explicit recovery"
                        session.check("exact opaque reference authenticates without UTF8 or NUL normalization", verified_reference.status, 0x9000)
                        if reference == 0x83:
                            sdk.verify_pin(session.options.openpgp_pin)
                        message = session.fixture("PGP.binary.PIN.message")
                        before = sdk.get_signature_counter()
                        verified(session, "opaque reference retains the original private SIG key", key.public_key(), -7,
                                 sdk.sign(message, hashes.SHA256()), message)
                        session.check("opaque reference operation increments SIG counter once", sdk.get_signature_counter(), before + 1)
                    finally:
                        if changed and not session.broken:
                            session.trace.phase = "cleanup"
                            session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=candidate + original)))
                        if not session.broken:
                            pgp_sign(session, sdk, key)


def connection_grants(session):
    from yubikit.piv import PIN_POLICY
    for action in ("same-SELECT", "other-SELECT", "idle", *Action):
        name = action.value if isinstance(action, Action) else action
        with session.case("piv.PIN-grant.connection." + name, ("P01", "P03", "P17", "T14", "X11", "G10", "G14"),
                          effects=("replace_piv_keys", "reboot") if action == Action.POWER_CYCLE else ("replace_piv_keys",), touch=True):
            session.require(session.profile == "rsk", "PIV grant lifetime is profiled for RS-Key", "excluded_by_profile")
            with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                sdk.verify_pin(session.options.piv_pin)
                piv_sign(session, sdk, key)
                if isinstance(action, Action):
                    change(session, action)
                    session.select("piv")
                elif action == "idle":
                    from .timers import wait
                    wait(session, 16.25)
                else:
                    if action == "other-SELECT":
                        session.select("openpgp")
                    session.select("piv")
                if action in ("idle", "same-SELECT"):
                    piv_sign(session, sdk, key)
                else:
                    sdk_refused(session, lambda: piv_sign(session, sdk, key), "connection change revokes PIV PIN grant", 0x6982)
                sdk.verify_pin(session.options.piv_pin)
                piv_sign(session, sdk, key)


def run(session):
    piv_verify(session)
    piv_changes(session)
    pgp_changes(session)
    pgp_binary(session)
    connection_grants(session)
