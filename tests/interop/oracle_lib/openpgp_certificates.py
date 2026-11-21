# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""SELECT DATA grammar never changes the selected occurrence on refusal."""
from contextlib import contextmanager
from itertools import product

from . import codec
from .lifecycle import Action, change
from .openpgp_lifecycle import fixture_session

SELECTOR = bytes.fromhex("60045c027f21")


def select(session, occurrence):
    session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, SELECTOR)))


@contextmanager
def certificates(session):
    session.require(session.profile == "rsk", "certificate selector/cursor grammar requires RS-Key", "excluded_by_profile")
    sdk, originals = fixture_session(session), {}
    try:
        for occurrence in range(3):
            select(session, occurrence)
            originals[occurrence] = sdk.get_data(0x7f21)
            sdk.put_data(0x7f21, b"oracle-certificate-" + bytes([occurrence]))
        yield sdk
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            sdk.verify_admin(session.options.openpgp_admin)
            for occurrence, value in originals.items():
                select(session, occurrence)
                sdk.put_data(0x7f21, value)


def selector_inputs(occurrence):
    yield "valid", occurrence, 4, SELECTOR, 0x9000
    for p1 in (3, 4, 127, 128, 255):
        yield f"P1-{p1}", p1, 4, SELECTOR, 0x6b00
    for p2 in (0, 1, 2, 3, 5, 127, 128, 255):
        yield f"P2-{p2}", occurrence, p2, SELECTOR, 0x6b00
    for size in range(len(SELECTOR)):
        yield f"truncated-{size}", occurrence, 4, SELECTOR[:size], 0x6a80
    for label, body in (("outer-tag", b"\x61" + SELECTOR[1:]), ("outer-length", b"\x60\x03" + SELECTOR[2:]),
            ("inner-tag", SELECTOR[:2] + b"\x5d" + SELECTOR[3:]), ("inner-length", SELECTOR[:3] + b"\x03" + SELECTOR[4:]),
            ("wrong-DO", SELECTOR[:-1] + b"\x22"), ("BER-outer-length", b"\x60\x81\x04" + SELECTOR[2:]),
            ("trailing", SELECTOR + b"\x00"), ("duplicate", SELECTOR * 2), ("unknown-before", b"\x99\x00" + SELECTOR)):
        yield label, occurrence, 4, body, 0x6a80
    yield "P1-before-body", 255, 4, b"", 0x6b00
    yield "P2-before-body", occurrence, 255, b"", 0x6b00


def run(session):
    for occurrence, granted in product(range(3), (False, True)):
        for label, p1, p2, body, status in selector_inputs(occurrence):
            with session.case(f"openpgp.certificate.SELECT-DATA.occurrence-{occurrence}.PW3-{granted}.{label}", ("O16", "O22", "G01", "G03", "G04", "G07", "G10", "G13", "G14"), effects=("write_and_restore_openpgp_certificates",)):
                with certificates(session) as sdk:
                    before = sdk.get_signature_counter()
                    select(session, 1)
                    if not granted:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                    session.check("SELECT DATA reference/P2 precedes exact body without PW3 gate", session.apdu(codec.apdu(0xa5, p1, p2, body)).status, status)
                    actual = occurrence if status == 0x9000 else 1
                    session.check("refused SELECT DATA preserves the exact selected certificate", sdk.get_data(0x7f21), b"oracle-certificate-" + bytes([actual]))
                    result = session.apdu(codec.apdu(0xcc, 0x7f, 0x21))
                    session.check("refused SELECT DATA preserves the walk anchor", result.status, 0x9000 if actual < 2 else 0x6a80)
                    if actual < 2:
                        session.check("certificate walk advances only after successful GET NEXT", session.card_value(result), b"oracle-certificate-" + bytes([actual + 1]))
                    session.check("certificate parsing never advances the SIG counter", sdk.get_signature_counter(), before)
    for label, p1, p2, body in (("body", 0x7f, 0x21, b"x"), ("wrong-P1", 0x7e, 0x21, b""), ("wrong-P2", 0x7f, 0x22, b""), ("both", 0, 0, b"x")):
        with session.case("openpgp.certificate.GET-NEXT." + label, ("O16", "O22", "G01", "G03", "G04", "G14"), effects=("write_and_restore_openpgp_certificates",)):
            with certificates(session) as sdk:
                select(session, 0)
                session.check("malformed GET NEXT is refused before advancing", session.apdu(codec.apdu(0xcc, p1, p2, body)).status, 0x6a80)
                session.check("refused GET NEXT leaves certificate occurrence unchanged", sdk.get_data(0x7f21), b"oracle-certificate-\x00")
                session.check("valid GET NEXT after malformed command still advances once", session.card_value(session.apdu(codec.apdu(0xcc, 0x7f, 0x21))), b"oracle-certificate-\x01")
    for action in ("same-SELECT", "refused-SELECT", "other-SELECT", *Action):
        label = action.value if isinstance(action, Action) else action
        with session.case("openpgp.certificate.lifetime." + label, ("O01", "O16", "O22", "X11", "G10", "G14"), effects=("write_and_restore_openpgp_certificates", "reboot") if action == Action.POWER_CYCLE else ("write_and_restore_openpgp_certificates",)):
            with certificates(session) as sdk:
                select(session, 1)
                if isinstance(action, Action):
                    change(session, action)
                elif action == "other-SELECT":
                    session.select("piv")
                elif action == "refused-SELECT":
                    session.check("unrecognized AID selection refused", session.apdu(codec.apdu(0xa4, 4, data=b"\xf0\xff\xff\xff\xff")).status, 0x6a82)
                session.select("openpgp")
                retained = action in ("same-SELECT", "refused-SELECT")
                reply = session.apdu(codec.apdu(0xcc, 0x7f, 0x21))
                session.check("certificate walk survives same/refused SELECT only", reply.status, 0x9000 if retained else 0x6a80)
                for occurrence in range(3):
                    select(session, occurrence)
                    session.check("connection change preserves each certificate body", sdk.get_data(0x7f21), b"oracle-certificate-" + bytes([occurrence]))
