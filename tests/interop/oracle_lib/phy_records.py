# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PHY uses a one-byte-length overlay, not a strict BER-TLV transaction."""
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import codec
from .lifecycle import Action, change, require_action
from .rescue_cases import active, request

WIDTHS = {0: 4, 4: 1, 5: 1, 6: 2, 8: 1, 10: 4, 11: 1, 12: 1, 13: 1, 14: 1}
STRINGS = (9, 15)


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


def overlay(current, data):
    result, at = dict(current), 0
    while at + 2 <= len(data):
        tag, size = data[at:at + 2]
        end = at + 2 + size
        if end > len(data):
            break
        value = data[at + 2:end]
        if tag in WIDTHS and size == WIDTHS[tag]:
            result[tag] = value
        elif tag in STRINGS and 1 <= size <= 33:
            text = value.split(b"\x00", 1)[0]
            if not text:
                result.pop(tag, None)
            elif len(text) <= 32:
                result[tag] = text + b"\x00"
        at = end
    return result


def defaults(value):
    if not isinstance(value, dict):
        raise ValueError("PHY defaults must be an object of two-digit hexadecimal tags and hexadecimal wire values")
    result = {}
    for key, encoded in value.items():
        if not isinstance(key, str) or len(key) != 2 or not isinstance(encoded, str):
            raise ValueError("PHY default tag/value must be hexadecimal strings")
        tag, data = int(key, 16), bytes.fromhex(encoded)
        if tag not in WIDTHS or len(data) != WIDTHS[tag]:
            raise ValueError("PHY numeric default has an unknown tag or wrong width")
        result[tag] = data
    return result


def read(session):
    active(session)
    return dict(codec.parse_tlv(request(session, 0x1e, 1)))


@contextmanager
def fixture(session, before, expected):
    introduced = set(expected) - set(before)
    supplied = session.options.phy_defaults or {}
    session.require(all(tag in supplied for tag in introduced if tag not in STRINGS),
        "a newly introduced numeric PHY field needs its known boot-default wire value via --phy-defaults; no guessed hardware default")
    restore = {**before, **{tag: supplied[tag] for tag in introduced if tag not in STRINGS}}
    try:
        yield
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            active(session)
            fields = {**restore, **{tag: b"\x00" for tag in introduced if tag in STRINGS}}
            request(session, 0x1c, 1, data=b"".join(tlv(tag, value) for tag, value in fields.items()))
            session.check("PHY fixture restores every original field and declared effective default", read(session), restore)
            if introduced - set(STRINGS):
                session.observe("cleanup_limit", {"default_overrides_retained": sorted(introduced - set(STRINGS)),
                    "reason": "numeric PHY fields have no delete operation; explicit known boot defaults preserve effective hardware behavior"})


def vectors():
    for tag in (*WIDTHS, *STRINGS):
        width = WIDTHS.get(tag, 33)
        sizes = sorted({0, 1, max(0, width - 1), width, width + 1, 32, 33, 34, 127, 128, 255})
        for size in sizes:
            yield f"tag-{tag:02x}.length-{size}", tlv(tag, b"x" * size)
        for value in (0, 1, 2, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 254, 255):
            yield f"tag-{tag:02x}.byte-{value}", tlv(tag, bytes([value]) * (1 if tag in STRINGS else width))
        value = b"oracle" if tag in STRINGS else bytes(width)
        other = b"replacement" if tag in STRINGS else b"\xff" * width
        first, second = tlv(tag, value), tlv(tag, other)
        for label, wire in (("duplicate-last-wins", first + second), ("duplicate-reversed", second + first),
                ("unknown-before", tlv(0x99, b"ignored") + first), ("unknown-after", first + tlv(0x99, b"ignored")),
                ("nested-unknown", tlv(0x53, first)), ("trailing-header", first + b"\xff"),
                ("trailing-truncated", first + b"\x05\x02x"), ("truncated-before", b"\x99\xff" + first),
                ("BER-length-is-not-PHY-length", bytes([tag, 0x81, len(value)]) + value)):
            yield f"tag-{tag:02x}.{label}", wire
    for tag in STRINGS:
        for label, value in (("NUL-clear", b"\x00"), ("embedded-NUL", b"oracle\x00ignored"), ("ASCII-32", b"a" * 32),
                ("NUL-terminated-32", b"a" * 32 + b"\x00"), ("multibyte-32", "é".encode() * 16),
                ("four-byte-codepoint", "😀".encode() * 8), ("invalid-UTF8", b"\xff\xc0\x80"),
                ("split-UTF8", "é".encode() * 16 + b"\xc3"), ("overlong-no-NUL", b"a" * 33)):
            yield f"string-{tag:02x}.{label}", tlv(tag, value)


def run(session):
    for label, wire in vectors():
        with session.case("rescue.PHY.overlay." + label, ("R03", "V09", "G01", "G03", "G04", "G05", "G07", "G08", "G13", "G14"),
                effects=("config_change",), touch=True, parameters={"PHY_overlay": label, "reboot": False}):
            before = read(session)
            expected = overlay(before, wire)
            with fixture(session, before, expected):
                public = request(session, 0x10, 2)
                # Rescue writes stage the record; no boot applies these deliberately invalid pins/IDs.
                request(session, 0x1c, 1, data=wire)
                session.check("PHY applies complete known-width fields up to its first truncated TLV", read(session), expected)
                request(session, 0x1c, 1, data=tlv(6, expected[6]))
                session.check("valid partial control preserves every unrelated PHY field", read(session), expected)
                digest = session.fixture("PHY.retained-device-key")
                raw = request(session, 0x10, 1, data=digest)
                session.check("PHY control has a complete device-key signature", len(raw), 64)
                signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public).verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                session.check("PHY grammar preserves the actual device private key", request(session, 0x10, 2), public)


def persistence(session):
    from .rescue_presence import private_control
    for action in Action:
        with session.case("rescue.PHY.persistent-record-and-key." + action.value, ("R03", "V09", "X11", "G11", "G14"), effects=("config_change", "reboot"), touch=True):
            before = read(session)
            session.require(session.card is not None and hasattr(session.card, "control"), "PHY persistence needs a defined connection backend", "excluded_by_mode")
            require_action(session, action)
            expected = {**before, 6: (int.from_bytes(before[6], "big") ^ 8).to_bytes(2, "big")}
            with fixture(session, before, expected):
                public = request(session, 0x10, 2)
                request(session, 0x1c, 1, data=tlv(6, expected[6]))
                change(session, action)
                session.check("each complete PHY field survives the explicit connection action", read(session), expected)
                private_control(session, public)
