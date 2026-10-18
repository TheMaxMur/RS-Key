# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Stored LED bytes, live normalized values and configuration gates are distinct."""
from contextlib import contextmanager
from itertools import product
import sys

from . import codec
from .fido import info
from .lifecycle import Action, change, require_action
from .management_cases import read as management_read, write as management_write
from .rescue_cases import active, request as rescue
from .rescue_presence import private_control
from .vendor_cases import vendor
from .vendor_matrix import authenticated

LED_LENGTH = 17
DEFAULTS = ((1, 2, 16, 0), (3, 2, 16, 0), (2, 4, 16, 0), (4, 1, 16, 0))


def normalize(raw):
    statuses = [list(raw[at:at + 4]) for at in range(1, LED_LENGTH, 4)]
    for status in statuses:
        status[1] &= 7
    touch = statuses[2]
    touch[1] = touch[1] or 4
    touch[2] = max(8, touch[2])
    touch[3] = max(2, touch[3]) if touch[3] else 0
    if any(index != 2 and value[1] == touch[1] == DEFAULTS[index][1] for index, value in enumerate(statuses)):
        statuses[2] = list(DEFAULTS[2])
    for index, value in enumerate(statuses):
        if index != 2 and value[1] == statuses[2][1]:
            statuses[index] = list(DEFAULTS[index])
    return bytes([bool(raw[0])]) + b"".join(bytes(value) for value in statuses)


def cue(session, mode):
    session.trace.emit("interaction", action="vendor-config-consent-" + mode, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: selected test key LED/config confirmation: " + mode, file=sys.stderr)


def stored(session):
    return session.ctap_value(vendor(session, 13, {1: 2}))[1]


def live(session):
    session.select("vendor", required=True)
    result = session.apdu(codec.apdu(0x11))
    session.require(result.status != 0x6d00, "this build has no live LED backend", "unsupported_confirmed")
    return session.card_value(result)


@contextmanager
def fixture(session):
    session.require(session.profile == "rsk", "vendor record rules require RS-Key", "excluded_by_profile")
    original, effective = stored(session), live(session)
    session.require(len(original) == LED_LENGTH and len(effective) == LED_LENGTH, "known stored/current LED block required; an absent record cannot be deleted for restoration")
    session.require(effective == normalize(original), "exact live restoration requires the current values to match the stored block")
    session.require(management_read(session, "card").get(10) == b"\x00", "known unlocked configuration is required")
    active(session)
    public = rescue(session, 0x10, 2)
    try:
        yield original, effective
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            cue(session, "accept")
            if stored(session) != original or live(session) != effective:
                session.ctap_value(vendor(session, 12, {1: 2, 2: original}, authenticated=True))
            session.check("LED fixture restores exact stored bytes", stored(session), original)
            session.check("LED fixture restores normalized live values", live(session), effective)
            active(session)
            private_control(session, public)


def raw_blocks(session):
    for index, value in product(range(LED_LENGTH), (0, 1, 2, 7, 8, 16, 31, 127, 128, 254, 255)):
        with session.case(f"rsk.LED.raw-normalization.byte-{index}.value-{value}", ("V09", "V12", "G03", "G04", "G11", "G14"), effects=("config_change",), touch=True):
            with fixture(session) as (original, _):
                raw = bytearray(original)
                raw[index] = value
                raw = bytes(raw)
                session.ctap_value(vendor(session, 12, {1: 2, 2: raw}, authenticated=True))
                session.check("FIDO LED write retains raw input bytes independently of live normalization", stored(session), raw)
                session.check("live LED block follows the complete normalization rule", live(session), normalize(raw))
                session.ctap_value(vendor(session, 12, {1: 2, 2: raw}, authenticated=True))
                session.check("raw LED replay leaves the same stored record", stored(session), raw)
                session.check("identical write still applies the live normalized block", live(session), normalize(raw))


def body_lengths(session):
    for size in (0, 1, 2, 3, 7, 12, 13, 16, 17, 18, 32, 255, 256, 1024):
        with session.case(f"rsk.LED.FIDO-body.length-{size}", ("V09", "V12", "G01", "G03", "G13", "G14"), effects=("config_change",), touch=True):
            with fixture(session) as (original, effective):
                raw = bytes([1]) + b"".join(bytes(value) for value in DEFAULTS)
                data = (raw + session.fixture("LED.extra-body", max(0, size - LED_LENGTH)))[:size]
                result = vendor(session, 12, {1: 2, 2: data}, authenticated=True)
                session.check("FIDO LED needs a complete current block and ignores its tail", result.status, 3 if size < LED_LENGTH else 0)
                session.check("LED width outcome preserves or stores precisely seventeen bytes", stored(session), original if size < LED_LENGTH else raw)
                session.check("short LED refusal cannot change live state", live(session), effective if size < LED_LENGTH else normalize(raw))


def card_parameters(session):
    for p2, size in product(range(256), (0, 1, 2, 3)):
        with session.case(f"rsk.LED.CCID.P2-{p2}.length-{size}", ("V09", "V12", "G01", "G03", "G04", "G14"), effects=("config_change",), touch=True,
                parameters={"P2": p2, "brightness": p2, "body_length": size, "ignored_P2_bits": p2 & 0xc0}):
            with fixture(session) as (_, effective):
                raw = bytearray(effective)
                raw[0] = bool(p2 & 8)
                at = 1 + 4 * ((p2 >> 4) & 3)
                raw[at + 1], raw[at + 2] = p2 & 7, p2
                raw = bytearray(normalize(bytes(raw)))
                if size:
                    raw[at] = 255
                    raw = bytearray(normalize(bytes(raw)))
                if size >= 2:
                    raw[at + 3] = 1
                data = b"\xff\x01\x99"[:size]
                cue(session, "accept")
                session.select("vendor", required=True)
                session.card_value(session.apdu(codec.apdu(0x10, p2, p2, data)))
                expected = normalize(bytes(raw))
                session.check("CCID LED optional effect/speed and ignored tail/reserved bits match the selected status", live(session), expected)
                session.check("CCID LED stores its normalized complete block", stored(session), expected)


def gates(session):
    for target, locked, size, mode in product((1, 2, 3), (False, True), (0, 16, 17), ("accept", "decline", "panel-cancel", "timeout")):
        with session.case(f"rsk.config.gate.target-{target}.locked-{locked}.length-{size}.{mode}",
                ("V09", "V12", "M04", "G01", "G03", "G10", "G13", "G14"), effects=("config_change",), touch=True):
            session.require(session.options.operator, "config consent ordering needs a controlled operator action")
            session.require(mode not in ("decline", "panel-cancel") or "display" in session.options.features, "explicit decline requires display profile", "excluded_by_profile")
            session.require(mode != "timeout" or session.options.timeout > 130, "config timeout requires the full window")
            strict = "strict-config" in session.options.features
            session.require(target != 1 or bool(session.ctap_value(vendor(session, 13, {1: 1}))[1]), "PHY no-op controls need an existing record; creating one could queue a reboot")
            with fixture(session) as (original, effective):
                code = session.fixture("LED.config-lock", 16)
                try:
                    if locked:
                        cue(session, "accept")
                        management_write(session, "card", codec.tlv(10, code))
                        session.check("shared lock is armed before vendor-config test", management_read(session, "card")[10], b"\x01")
                    cue(session, mode)
                    data = original[:size] if target == 2 else b"\x99" * size
                    result = vendor(session, 12, {1: target, 2: data}, authenticated=True)
                    expected = (0x27 if strict and mode != "accept" else 2 if target == 3 else
                        3 if target == 2 and size < LED_LENGTH else 0x30 if locked else 0)
                    session.check("strict consent, selector, LED width and lock have their defined precedence", result.status, expected)
                    cue(session, "accept")
                    session.check("refusal or incomplete PHY no-op preserves the exact LED record", stored(session), original)
                    session.check("refusal or replay preserves live LED state", live(session), effective)
                finally:
                    if not session.broken:
                        cue(session, "accept")
                        if management_read(session, "card").get(10) == b"\x01":
                            management_write(session, "card", codec.tlv(11, code) + codec.tlv(10, bytes(16)))


def persistence(session):
    for action in Action:
        with session.case("rsk.LED.raw-and-live.persistence." + action.value, ("V09", "V12", "X11", "G11", "G14"), effects=("config_change", "reboot"), touch=True):
            session.require(session.card is not None and hasattr(session.card, "control"), "LED persistence needs an explicit connection backend", "excluded_by_mode")
            require_action(session, action)
            with fixture(session) as (original, _):
                raw = bytes([original[0] ^ 1]) + original[1:]
                session.ctap_value(vendor(session, 12, {1: 2, 2: raw}, authenticated=True))
                change(session, action)
                session.check("LED raw record survives the connection action", stored(session), raw)
                session.check("LED live state is restored from its normalized stored record", live(session), normalize(raw))


def authorization(session):
    defects = ("missing-auth", "missing-protocol", "empty-auth", "short-auth", "long-auth", "bad-MAC", "wrong-permission", "readonly", "unknown-protocol", "unsupported-protocol")
    for version, target, defect in product((1, 2), (0, 1, 2, 3), defects):
        with session.case(f"rsk.config.authorization.protocol-{version}.target-{target}.{defect}",
                ("V09", "V12", "M05", "G01", "G03", "G04", "G10", "G13", "G14"), effects=("config_change",), touch=True):
            session.require(session.profile == "rsk", "config build gates require RS-Key", "excluded_by_profile")
            session.require(info(session).get(4, {}).get("clientPin"), "host config auth failures need a known configured PIN")
            session.require(defect != "readonly" or info(session).get(4, {}).get("perCredMgmtRO"), "read-only token not advertised", "unknown")
            with fixture(session) as (original, effective):
                management = management_read(session, "card")
                phy = session.ctap_value(vendor(session, 13, {1: 1}))[1]
                session.require(target != 1 or bool(phy), "identical PHY auth control requires an existing record")
                data = codec.tlv(8, management[8]) if target == 0 else phy if target == 1 else original if target == 2 else b""
                cue(session, "withhold")
                result = authenticated(session, 0x41, 12, {1: target, 2: data}, defect, version=version)
                strict = "strict-config" in session.options.features
                expected = (0x36 if defect == "missing-auth" else 0x14 if defect == "missing-protocol" else
                    2 if defect in ("unknown-protocol", "unsupported-protocol") else 0x33) if strict else 2 if target == 3 else 0
                session.check("CONFIG_WRITE PIN failures precede strict touch and selector; default profile ignores supplied host auth", result.status, expected)
                cue(session, "accept")
                session.check("config authorization probe preserves exact management fields", management_read(session, "card"), management)
                session.check("config authorization probe preserves raw PHY record", session.ctap_value(vendor(session, 13, {1: 1}))[1], phy)
                session.check("config authorization probe preserves raw LED record", stored(session), original)
                session.check("config authorization probe preserves live LED values", live(session), effective)


def run(session):
    raw_blocks(session)
    body_lengths(session)
    card_parameters(session)
    gates(session)
    authorization(session)
    persistence(session)
