# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Recovery commands retain known references and independently verified private keys."""
from contextlib import contextmanager
from itertools import product

from . import codec
from .lifecycle import Action, change
from .openpgp_references import authenticate, fixture, grants

CODE = b"oracle-reset-reference"
REPLACEMENT = "oracle-recovered-PW1"


def recovered(session, domain, mechanism):
    session.failed_auth.discard(("openpgp", domain))
    session.trace.emit("authorization_recovered", domain=str(("openpgp", domain)), mechanism=mechanism, evidence=session.evidence())


@contextmanager
def store(session):
    session.require(session.options.openpgp_reset_code is not None, "supply the known reset code; an empty value declares it unset")
    original_pin, original_code = session.options.openpgp_pin, session.options.openpgp_reset_code.encode()
    with fixture(session) as (sdk, key):
        sdk.put_data(0xd3, CODE)
        maxima = sdk.get_data(0xc4)[4:7]
        try:
            yield sdk, key, maxima
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                authenticate(session, sdk, (0x83,))
                session.card_value(session.apdu(codec.apdu(0xf2, data=maxima)))
                recovered(session, 0x81, "PW3-authenticated retry-policy restoration")
                recovered(session, "reset_code", "PW3-authenticated retry-policy restoration")
                if session.options.openpgp_pin != original_pin:
                    session.card_value(session.apdu(codec.apdu(0x24, p2=0x81, data=session.options.openpgp_pin.encode() + original_pin.encode())))
                    session.options.openpgp_pin = original_pin
                sdk.put_data(0xd3, original_code)
                authenticate(session, sdk)
            else:
                session.trace.emit("fixture_cleanup_pending", applet="openpgp", reason="transport outcome unknown; reference/policy writes were not replayed")


def retries(session):
    bodies = (b"", b"x", b"xx", b"xxxx", bytes(255), bytes(3), b"\x01\x02\x03", b"\xff\xff\xff", b"\x00\x02\x00")
    for authorized, parameters, body in product((False, True), ((0, 0), (1, 255)), bodies):
        with session.case(f"openpgp.SET-RETRIES.PW3-{authorized}.parameters-{parameters[0]}-{parameters[1]}.body-{body.hex()}", ("O02", "O04", "O06", "O11", "O22", "G03", "G04", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "write_and_restore_openpgp_DO"), touch=True):
            with store(session) as (sdk, key, maxima):
                before = sdk.get_data(0xc4)
                if not authorized:
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                result = session.apdu(codec.apdu(0xf2, *parameters, data=body))
                expected = 0x6982 if not authorized else 0x6a80 if len(body) != 3 else 0x9000
                session.check("SET RETRIES checks PW3 before body and ignores P1/P2", result.status, expected)
                wanted = bytearray(before)
                if expected == 0x9000:
                    for index, value in enumerate(body, 4):
                        if value:
                            wanted[index] = value
                session.check("zero policy bytes preserve each reference while nonzero resets its budget", sdk.get_data(0xc4), bytes(wanted))
                grants(session, sdk, key, (0x81, 0x82, 0x83) if authorized else (0x81, 0x82))


def persistence(session):
    for body in (b"\x01\x02\x03", b"\xff\xff\xff", b"\x03\x01\x02"):
        with session.case("openpgp.SET-RETRIES.power." + body.hex(), ("O02", "O04", "O06", "O11", "O22", "X11", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "reboot", "write_and_restore_openpgp_DO"), touch=True):
            with store(session) as (sdk, key, maxima):
                session.card_value(session.apdu(codec.apdu(0xf2, data=body)))
                change(session, Action.POWER_CYCLE)
                session.select("openpgp")
                session.check("all three retry budgets persist after cold power", sdk.get_data(0xc4)[4:7], body)
                authenticate(session, sdk)
                grants(session, sdk, key)
                session.card_value(session.apdu(codec.apdu(0x2c, p2=0x81, data=CODE + REPLACEMENT.encode())))
                session.options.openpgp_pin = REPLACEMENT
                authenticate(session, sdk)
                grants(session, sdk, key)


def code_lengths(session):
    for authorized, size in product((False, True), (0, 1, 7, 8, 126, 127, 128, 255)):
        with session.case(f"openpgp.reset-code.length-{size}.PW3-{authorized}", ("O02", "O04", "O05", "O11", "O22", "G03", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "write_and_restore_openpgp_DO"), touch=True):
            with store(session) as (sdk, key, maxima):
                candidate = b"r" * size
                if not authorized:
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                result = session.apdu(codec.apdu(0xda, 0, 0xd3, candidate))
                expected = 0x6982 if not authorized else 0x9000 if size == 0 or 8 <= size <= 127 else 0x6a80
                session.check("reset-code write has its own authorization and byte-length rule", result.status, expected)
                live = candidate if expected == 0x9000 else CODE
                session.check("reset-code counter is zero exactly when no code is installed", sdk.get_data(0xc4)[5], maxima[1] if live else 0)
                response = session.apdu(codec.apdu(0x2c, p2=0x81, data=live + REPLACEMENT.encode()))
                session.check("installed code opens recovery and removed code has no verifier", response.status, 0x9000 if live else 0x6a88)
                if live:
                    session.options.openpgp_pin = REPLACEMENT
                authenticate(session, sdk)
                grants(session, sdk, key)


def reset_grammar(session):
    for mode, reference, defect in product((0, 2), (0x81, 0x82, 0x83, 0, 255), ("valid", "missing-PW3", "short-new", "long-new", "empty-body", "invalid-mode")):
        with session.case(f"openpgp.RESET-RETRY.mode-{mode}.reference-{reference:02x}.{defect}", ("O02", "O03", "O04", "O05", "O11", "O22", "G01", "G03", "G04", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "write_and_restore_openpgp_DO"), touch=True):
            with store(session) as (sdk, key, maxima):
                new = b"n" * (5 if defect == "short-new" else 128 if defect == "long-new" else 10)
                body = (CODE if mode == 0 else b"") + new
                if defect == "empty-body":
                    body = b""
                if defect == "missing-PW3":
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x83)))
                p1 = 1 if defect == "invalid-mode" else mode
                expected = 0x6a88 if reference != 0x81 else 0x6a86 if p1 == 1 else 0x6985 if mode == 2 and defect == "missing-PW3" else 0x6700 if mode == 0 and defect == "empty-body" else 0x6985 if defect in ("empty-body", "short-new", "long-new") else 0x9000
                session.check("RESET RETRY isolates reference/mode/authorization/new-value order", session.apdu(codec.apdu(0x2c, p1, reference, body)).status, expected)
                if expected == 0x9000:
                    session.options.openpgp_pin = new.decode()
                authenticate(session, sdk)
                grants(session, sdk, key)


def blocked_user_and_code(session):
    for reference in ("PW1", "reset-code"):
        with session.case("openpgp.blocked-reference." + reference, ("O02", "O04", "O05", "O06", "O11", "O22", "G10", "G13", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "pin_attempts", "write_and_restore_openpgp_DO"), touch=True):
            with store(session) as (sdk, key, maxima):
                session.card_value(session.apdu(codec.apdu(0xf2, data=b"\x02\x02\x03")))
                domain = 0x81 if reference == "PW1" else "reset_code"
                wrong = (session.options.openpgp_pin[:-1] + "!").encode() if reference == "PW1" else b"x" * len(CODE)
                with session.attempts(("openpgp", domain), 3):
                    for left in (1, 0):
                        wire = codec.apdu(0x20, p2=0x81, data=wrong) if reference == "PW1" else codec.apdu(0x2c, p2=0x81, data=wrong + REPLACEMENT.encode())
                        session.check("wrong reference charges a bounded attempt", session.apdu(wire).status, 0x6982 if left else 0x6983)
                        session.check("shared/private retry counter reaches the exact blocked floor", sdk.get_data(0xc4)[4 if reference == "PW1" else 5], left)
                    correct = codec.apdu(0x20, p2=0x81, data=session.options.openpgp_pin.encode()) if reference == "PW1" else codec.apdu(0x2c, p2=0x81, data=CODE + REPLACEMENT.encode())
                    session.check("blocked reference refuses even its correct known value", session.apdu(correct).status, 0x6983)
                grants(session, sdk, key, (0x82, 0x83) if reference == "PW1" else (0x81, 0x82, 0x83))
                if reference == "PW1":
                    session.card_value(session.apdu(codec.apdu(0x2c, 2, 0x81, REPLACEMENT.encode())))
                    session.options.openpgp_pin = REPLACEMENT
                else:
                    sdk.put_data(0xd3, CODE)
                    recovered(session, domain, "PW3-authorized reset-code replacement")
                    session.card_value(session.apdu(codec.apdu(0x2c, p2=0x81, data=CODE + REPLACEMENT.encode())))
                    session.options.openpgp_pin = REPLACEMENT
                recovered(session, domain, "PW3 authorized known-reference recovery")
                authenticate(session, sdk)
                grants(session, sdk, key)


def run(session):
    retries(session)
    persistence(session)
    code_lengths(session)
    reset_grammar(session)
    blocked_user_and_code(session)
    blocked_persistence(session)


def blocked_persistence(session):
    for reference, action in product(("PW1", "reset-code"), Action):
        with session.case(f"openpgp.blocked-reference.persistence.{reference}.{action.value}", ("O02", "O04", "O05", "O06", "O11", "O22", "X11", "G10", "G14"), effects=("replace_openpgp_sig_key", "config_change", "pin_change", "pin_attempts", "write_and_restore_openpgp_DO", "reboot") if action == Action.POWER_CYCLE else ("replace_openpgp_sig_key", "config_change", "pin_change", "pin_attempts", "write_and_restore_openpgp_DO"), touch=True):
            with store(session) as (sdk, key, maxima):
                session.card_value(session.apdu(codec.apdu(0xf2, data=b"\x02\x02\x03")))
                domain = 0x81 if reference == "PW1" else "reset_code"
                wrong = (session.options.openpgp_pin[:-1] + "!").encode() if reference == "PW1" else b"x" * len(CODE)
                with session.attempts(("openpgp", domain), 2):
                    for left in (1, 0):
                        wire = codec.apdu(0x20, p2=0x81, data=wrong) if reference == "PW1" else codec.apdu(0x2c, p2=0x81, data=wrong + REPLACEMENT.encode())
                        session.check("bounded wrong comparisons establish a blocked persistent reference", session.apdu(wire).status, 0x6982 if left else 0x6983)
                change(session, action)
                session.select("openpgp")
                session.check("connection change cannot replenish the blocked reference", sdk.get_data(0xc4)[4 if reference == "PW1" else 5], 0)
                session.check("connection change clears standing PW3 without changing its budget", session.apdu(codec.apdu(0x20, p2=0x83)).status, 0x63c3)
                sdk.verify_admin(session.options.openpgp_admin)
                if reference == "PW1":
                    session.card_value(session.apdu(codec.apdu(0x2c, 2, 0x81, REPLACEMENT.encode())))
                    session.options.openpgp_pin = REPLACEMENT
                else:
                    sdk.put_data(0xd3, CODE)
                recovered(session, domain, "PW3-authorized reference replacement after observed persistent block")
                authenticate(session, sdk)
                grants(session, sdk, key)
