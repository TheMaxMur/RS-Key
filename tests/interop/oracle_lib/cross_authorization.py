# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Actual foreign grants cannot replace the populated target's own authorization."""
from contextlib import contextmanager
from enum import Enum

from . import codec
from .binding import require_pair
from .cards import connection, selected_cleanup
from .fido import cm, info, pin_token
from .fido_fixtures import credential
from .management_cases import read as config_read, write as config_write
from .oath_access import known_record, lock, unlock
from .oath_gates import reset
from .oath_pin_matrix import NAME, PIN, private_record, setup
from .otp_commands import Mode, Route, configure, fixture as otp_fixture, address, mutate, witness


class Grant(Enum):
    PIV_PIN = ("PIV-PIN", "piv")
    PIV_MANAGEMENT = ("PIV-management", "piv")
    PGP_81 = ("OpenPGP-PW1.81", "openpgp")
    PGP_82 = ("OpenPGP-PW1.82", "openpgp")
    PGP_83 = ("OpenPGP-PW3", "openpgp")
    OATH_CODE = ("OATH-code", "oath")
    OATH_PIN = ("OATH-PIN", "oath")
    OATH_BOTH = ("OATH-code-and-PIN", "oath")
    FIDO_CONFIG = ("FIDO-ACFG", "fido")
    FIDO_RO = ("FIDO-readonly", "fido")
    OTP_CODE = ("OTP-access-code", "otp")
    MANAGEMENT = ("management-lock-code", "management")


@contextmanager
def source(session, grant):
    from yubikit.piv import PivSession
    from yubikit.openpgp import OpenPgpSession
    phase = session.trace.phase
    try:
        applet = grant.value[1]
        if applet not in ("fido", "oath"):
            session.select("openpgp" if applet == "piv" else "piv")
            session.select(applet)
        if grant in (Grant.PIV_PIN, Grant.PIV_MANAGEMENT):
            sdk = PivSession(connection(session))
            if grant == Grant.PIV_PIN:
                sdk.verify_pin(session.options.piv_pin)
                session.check("source PIV PIN is actually verified", session.apdu(codec.apdu(0x20, p2=0x80)).status, 0x9000)
            else:
                sdk.authenticate(session.options.management_key)
                session.observe("source_management_proof", "SDK verified mutual challenge response with the supplied PIV key")
            yield
        elif grant in (Grant.PGP_81, Grant.PGP_82, Grant.PGP_83):
            sdk = OpenPgpSession(connection(session))
            reference = {Grant.PGP_81: 0x81, Grant.PGP_82: 0x82, Grant.PGP_83: 0x83}[grant]
            if reference == 0x83:
                sdk.verify_admin(session.options.openpgp_admin)
            else:
                sdk.verify_pin(session.options.openpgp_pin, extended=reference == 0x82)
            session.check("source OpenPGP reference is actually verified", session.apdu(codec.apdu(0x20, p2=reference)).status, 0x9000)
            yield
        elif grant in (Grant.OATH_CODE, Grant.OATH_PIN, Grant.OATH_BOTH):
            secret = setup(session)
            try:
                selected = lock(session)
                if grant != Grant.OATH_PIN:
                    unlock(session, 2, secret, selected)
                if grant != Grant.OATH_CODE:
                    session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                session.check("source OATH code and PIN grants are distinct", session.apdu(codec.apdu(0xa1)).status, 0x6982 if grant == Grant.OATH_PIN else 0x9000)
                yield
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)
        elif grant in (Grant.FIDO_CONFIG, Grant.FIDO_RO):
            token = pin_token(session, 32 if grant == Grant.FIDO_CONFIG else 64)
            if grant == Grant.FIDO_RO:
                session.ctap_value(cm(session, *token, 1))
            else:
                from .audit_access import authorized
                session.ctap_value(session.ctap(0x41, authorized(session, token, 7)))
            yield
        elif grant == Grant.OTP_CODE:
            slot = session.options.otp_slot
            config = configure(session.fixture("cross.auth.OTP.key", 20), Mode.HMAC, session.fixture("cross.auth.OTP.access", 6))
            with otp_fixture(session, Route.CARD, slot, config):
                command, offset = address(slot)
                mutate(session, Route.CARD, command, config + config[38:44], offset)
                witness(session, Route.CARD, slot, config)
                try:
                    yield
                finally:
                    if not session.broken:
                        session.select("otp")
        else:
            original = config_read(session, "card")
            session.require(original.get(10) == b"\x00", "foreign management fixture cannot replace an existing lock")
            code = session.fixture("cross.auth.management", 16)
            try:
                config_write(session, "card", codec.tlv(10, code))
                session.check("source management lock is actually armed", config_read(session, "card")[10], b"\x01")
                session.card_value(config_write(session, "card", codec.tlv(11, code) + codec.tlv(3, original[3])))
                yield
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    config_write(session, "card", codec.tlv(11, code) + codec.tlv(10, bytes(16)))
                    session.check("foreign management fixture removes its known lock", config_read(session, "card"), original)
    finally:
        session.trace.phase = phase


def target(session, applet, grant):
    if applet == "piv":
        from yubikit.piv import PIN_POLICY
        from .piv_matrix import key_fixture
        from .card_pin_matrix import piv_sign
        from .card_states import sdk_refused
        from .piv_objects import read, write
        with selected_cleanup(session, "piv", key_fixture(session, policy=PIN_POLICY.ONCE)) as (sdk, key):
            original = read(session, 0x5f0077)
            try:
                session.select("openpgp")
                with source(session, grant):
                    session.select("piv")
                    sdk_refused(session, lambda: piv_sign(session, sdk, key), "foreign applet cannot authorize a populated PIV key", 0x6982)
                    session.check("foreign applet cannot authorize a real PIV object write", write(session, 0x5f0077, b"foreign-must-not-write").status, 0x6982)
                    session.check("foreign authorization refusal preserves full PIV object", read(session, 0x5f0077), original)
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)
                    sdk.authenticate(session.options.management_key)
                    session.card_value(write(session, 0x5f0077, b"target-authorized"))
                    session.check("PIV's own management authority performs a real write", read(session, 0x5f0077), b"target-authorized")
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    session.select("piv")
                    sdk.authenticate(session.options.management_key)
                    session.card_value(write(session, 0x5f0077, original))
    elif applet == "openpgp":
        from .openpgp_references import fixture, grants, authenticate
        with selected_cleanup(session, "openpgp", fixture(session)) as (sdk, key):
            session.select("piv")
            with source(session, grant):
                session.select("openpgp")
                grants(session, sdk, key, ())
                authenticate(session, sdk)
                grants(session, sdk, key)
    elif applet == "oath":
        secret = setup(session)
        try:
            lock(session)
            session.select("piv")
            with source(session, grant):
                selected = dict(codec.parse_tlv(session.select("oath")))
                session.check("foreign applet cannot grant OATH access-code authorization", session.apdu(codec.apdu(0xa1)).status, 0x6982)
                session.check("foreign applet cannot expose a populated OATH private record", session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x6982)
                unlock(session, 2, secret, selected)
                session.check("the target's code alone still cannot grant its independent PIN", session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x6982)
                session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                private_record(session)
                known_record(session, NAME, 0)
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                reset(session)
    elif applet == "fido":
        with credential(session, session.current.name, resident=True) as fixture:
            token = pin_token(session, 64)
            before = session.ctap_value(cm(session, *token, 1))
            session.select("piv")
            with source(session, grant):
                session.check("foreign applet cannot grant missing CTAP authorization", session.ctap(10, {1: 1}).status, 0x36)
                session.check("foreign card authentication does not revoke a valid persistent device-wide token", session.ctap_value(cm(session, *token, 1)), before)
                fixture.assertion(session)
    elif applet == "otp":
        slot = session.options.otp_slot
        config = configure(session.fixture("cross.auth.target.OTP.key", 20), Mode.HMAC, session.fixture("cross.auth.target.OTP.access", 6))
        with otp_fixture(session, Route.CARD, slot, config):
            try:
                session.select("piv")
                with source(session, grant):
                    session.select("otp")
                    command, offset = address(slot)
                    session.check("foreign authority cannot replace a populated OTP slot", session.apdu(codec.apdu(1, command, offset, config + bytes(6))).status, 0x6982)
                    witness(session, Route.CARD, slot, config)
                    mutate(session, Route.CARD, command, config + config[38:44], offset)
                    witness(session, Route.CARD, slot, config)
            finally:
                if not session.broken:
                    session.select("otp")
    else:
        original = config_read(session, "card")
        session.require(original.get(10) == b"\x00", "target management fixture cannot replace an existing lock")
        code = session.fixture("cross.auth.target.management", 16)
        try:
            config_write(session, "card", codec.tlv(10, code))
            before = config_read(session, "card")
            session.check("target management lock is actually armed", before[10], b"\x01")
            session.select("piv")
            with source(session, grant):
                value = bytes([before[8][0] ^ 0x40])
                reply = config_write(session, "card", codec.tlv(8, value))
                session.check("foreign applet cannot authorize the target's configuration lock", reply.is_rejection)
                session.check("foreign management refusal preserves the whole record", config_read(session, "card"), before)
                session.card_value(config_write(session, "card", codec.tlv(11, code) + codec.tlv(8, value)))
                session.check("target's own lock code authorizes the same real write", config_read(session, "card")[8], value)
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                config_write(session, "card", codec.tlv(11, code) + codec.tlv(8, original[8]) + codec.tlv(10, bytes(16)))
                session.check("cross-authorization management fixture restored", config_read(session, "card"), original)


def run(session):
    for applet in ("piv", "openpgp", "oath", "fido", "otp", "management"):
        for grant in Grant:
            if grant.value[1] == applet:
                continue
            with session.case(f"cross.authorization.{grant.value[0]}.to-{applet}", ("X01", "X02", "X12", "G09", "G10", "G13", "G14"),
                    effects=("replace_piv_slot_82", "replace_openpgp_sig_key", "create_fido_credential", "create_oath_record", "config_change", "pin_change", "applet_reset", "replace_otp_slot_" + str(session.options.otp_slot)), touch=True):
                session.require(session.profile == "rsk", "complete foreign grant contracts require RS-Key", "excluded_by_profile")
                require_pair(session)
                session.require(all((session.options.pin, session.options.piv_pin, session.options.management_key, session.options.openpgp_pin, session.options.openpgp_admin)), "all source and target fixture credentials are required")
                session.require(info(session).get(4, {}).get("clientPin"), "FIDO grant controls need a configured host PIN")
                target(session, applet, grant)
