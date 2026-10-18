# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP references have independent access latches and shared PW1 retries."""
from contextlib import contextmanager
from itertools import product

from cryptography.hazmat.primitives import hashes

from . import codec
from .card_pin_matrix import pgp_key
from .card_states import sdk_refused
from .fido import verified

REFS = (0x81, 0x82, 0x83)
MARKER = b"oracle-PW-reference-control"


def authenticate(session, sdk, references=REFS):
    for reference in references:
        if reference == 0x83:
            sdk.verify_admin(session.options.openpgp_admin)
        else:
            sdk.verify_pin(session.options.openpgp_pin, extended=reference == 0x82)


@contextmanager
def fixture(session):
    session.require(session.profile == "rsk", "OpenPGP reference grammar requires RS-Key", "excluded_by_profile")
    with pgp_key(session) as (sdk, key):
        authenticate(session, sdk)
        mode, private, public = sdk.get_data(0xc4)[0], sdk.get_data(0x103), sdk.get_data(0x5e)
        try:
            sdk.put_data(0xc4, b"\x01")
            sdk.put_data(0x103, MARKER)
            sdk.put_data(0x5e, MARKER)
            yield sdk, key
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                authenticate(session, sdk)
                sdk.put_data(0xc4, bytes([mode]))
                sdk.put_data(0x103, private)
                sdk.put_data(0x5e, public)


def grants(session, sdk, key, live=REFS):
    before = sdk.get_data(0xc4)
    for reference in REFS:
        left = before[6 if reference == 0x83 else 4]
        session.check("reference status query reflects its own access latch", session.apdu(codec.apdu(0x20, p2=reference)).status, 0x9000 if reference in live else 0x63c0 | min(left, 15))
    message = session.fixture("OpenPGP.references.message")
    if 0x81 in live:
        verified(session, "reference state retains the actual private signing key", key.public_key(), -7, sdk.sign(message, hashes.SHA256()), message)
    else:
        sdk_refused(session, lambda: sdk.sign(message, hashes.SHA256()), "unverified PW1.81 cannot sign", 0x6982)
    private = session.apdu(codec.apdu(0xca, 1, 3))
    session.check("PW1.82 private-read gate has no foreign-reference override", private.status, 0x9000 if 0x82 in live else 0x6982)
    if 0x82 in live:
        session.check("private reference witness retains the complete value", session.card_value(private), MARKER)
    session.check("PW3 protected write has no foreign-reference override", session.apdu(codec.apdu(0xda, 0, 0x5e, MARKER)).status, 0x9000 if 0x83 in live else 0x6982)
    session.check("reference observations spend no retry", sdk.get_data(0xc4), before)


def grammar(session):
    for reference, p1 in product(REFS, (0, 1, 2, 127, 254, 255)):
        bodies = (b"", b"x") if p1 != 0 else (b"", *(b"x" * length for length in (1, 5 if reference != 0x83 else 7, 128, 255)))
        for body in bodies:
            with session.case(f"openpgp.VERIFY.grammar.ref-{reference:02x}.P1-{p1}.length-{len(body)}", ("O02", "O07", "O11", "O22", "G03", "G04", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "write_and_restore_openpgp_DO"), touch=True):
                with fixture(session) as (sdk, key):
                    before = sdk.get_data(0xc4)
                    expected = 0x9000 if not body and p1 in (0, 255) else 0x6a80 if p1 in (0, 255) else 0x6b00
                    session.check("VERIFY mode and impossible length have distinct refusals", session.apdu(codec.apdu(0x20, p1, reference, body)).status, expected)
                    session.check("VERIFY grammar cannot consume the shared retry state", sdk.get_data(0xc4), before)
                    live = tuple(value for value in REFS if value != reference) if p1 == 255 and not body else REFS
                    grants(session, sdk, key, live)
    for reference in range(256):
        if reference in REFS:
            continue
        for p1 in (0, 255):
            with session.case(f"openpgp.VERIFY.unknown-reference-{reference:02x}.P1-{p1}", ("O02", "G04", "G09", "G10", "G14"), effects=("replace_openpgp_sig_key", "config_change", "write_and_restore_openpgp_DO"), touch=True):
                with fixture(session) as (sdk, key):
                    session.check("VERIFY cannot name a private internal reference", session.apdu(codec.apdu(0x20, p1, reference)).status, 0x6b00)
                    grants(session, sdk, key)


def wrong_password(session):
    for reference in REFS:
        with session.case(f"openpgp.VERIFY.wrong-reference-{reference:02x}", ("O02", "O11", "O22", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "write_and_restore_openpgp_DO", "pin_attempts"), touch=True):
            with fixture(session) as (sdk, key):
                before = sdk.get_data(0xc4)
                domain = 0x83 if reference == 0x83 else 0x81
                index = 6 if domain == 0x83 else 4
                session.require(before[index] > 1, "wrong-PW probe needs one recovery attempt")
                secret = session.options.openpgp_admin if domain == 0x83 else session.options.openpgp_pin
                wrong = bytes([secret.encode()[0] ^ 1]) + secret.encode()[1:]
                with session.attempts(("openpgp", domain), 2):
                    session.check("wrong password has a real comparison refusal", session.apdu(codec.apdu(0x20, p2=reference, data=wrong)).status, 0x6982)
                    expected = bytearray(before)
                    expected[index] -= 1
                    session.check("PW1 modes share one counter while PW3 is independent", sdk.get_data(0xc4), bytes(expected))
                    grants(session, sdk, key, tuple(value for value in REFS if value != reference))
                    authenticate(session, sdk, (reference,))
                grants(session, sdk, key)
                session.check("correct reference restores its configured retry maximum", sdk.get_data(0xc4), before)


def changes(session):
    for reference, standing, defect in product((0x81, 0x83), (False, True), ("wrong-P1", "wrong-reference", "short-old-body", "empty-new", "short-new", "long-new", "wrong-old-and-short-new")):
        with session.case(f"openpgp.CHANGE.reference-{reference:02x}.standing-{standing}.{defect}", ("O02", "O03", "O07", "O11", "O22", "G03", "G04", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "pin_attempts", "write_and_restore_openpgp_DO"), touch=True):
            with fixture(session) as (sdk, key):
                if not standing:
                    for value in REFS:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, value)))
                before = sdk.get_data(0xc4)
                secret = (session.options.openpgp_pin if reference == 0x81 else session.options.openpgp_admin).encode()
                minimum = 6 if reference == 0x81 else 8
                p1, p2, body, expected = 0, reference, secret + b"x" * (minimum - 1), 0x6985
                if defect == "wrong-P1":
                    p1, expected = 1, 0x6b00
                elif defect == "wrong-reference":
                    p2, expected = 0x82, 0x6b00
                elif defect == "short-old-body":
                    body, expected = secret[:-1], 0x6700
                elif defect == "empty-new":
                    body = secret
                elif defect == "long-new":
                    body = secret + b"x" * 128
                elif defect == "wrong-old-and-short-new":
                    session.require(before[4 if reference == 0x81 else 6] > 1, "wrong-old probe requires a known recovery attempt")
                    body, expected = bytes([secret[0] ^ 1]) + body[1:], 0x6982
                with session.attempts(("openpgp", reference), 2):
                    result = session.apdu(codec.apdu(0x24, p1, p2, body))
                    session.check("CHANGE distinguishes framing, old-secret comparison and new policy", result.status, expected)
                    wanted = bytearray(before)
                    if expected == 0x6982:
                        wanted[4 if reference == 0x81 else 6] -= 1
                    session.check("only a plausible wrong old reference spends a retry", sdk.get_data(0xc4), bytes(wanted))
                    live = set(REFS if standing else ())
                    if expected == 0x6982:
                        live.discard(reference)
                    elif expected == 0x6985:
                        live.add(reference)
                    grants(session, sdk, key, live)
                    authenticate(session, sdk, (reference,))
                authenticate(session, sdk)
                grants(session, sdk, key)


def run(session):
    grammar(session)
    wrong_password(session)
    changes(session)
