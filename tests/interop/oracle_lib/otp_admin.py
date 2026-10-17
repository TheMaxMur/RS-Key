# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Profiled OTP admin commands distinguish acknowledgments from witnessed effects."""
import hmac

from . import codec
from .keyboard import receive, US
from .otp import slot_config, slot_request, slot_select

CHARSET = "cbdefghijklnrtuvCBDEFGHIJKLNRTUV0123456789!\t\r"


def run(session):
    slot = session.options.otp_slot
    for command, minimum, maximum in ((8, 64, 64), (9, 64, 64), (0x11, 3, 4), (0x12, 45, 45)):
        for length in sorted({0, 1, minimum - 1, minimum, minimum + 1, maximum - 1, maximum, maximum + 1}):
            with session.case(f"otp.admin.command-{command:02x}.length-{length}", ("Y13", "Y01", "G03", "G14"),
                              effects=("config_change", f"replace_otp_slot_{slot}")):
                session.require(session.profile in ("rsk", "yubikey"), "admin slots need a confirmed command catalog", "unknown")
                slot_select(session)
                key = session.fixture("otp.admin.control", 20)
                write, calculate = (1, 0x30) if slot == 1 else (3, 0x38)
                slot_request(session, write, slot_config(key) + bytes(6))
                try:
                    data = bytes([4]) * length if command == 0x12 else bytes(length)
                    if session.otp_hid:
                        reply = session.otp_call(command, data)
                    else:
                        reply = session.apdu(codec.apdu(1, command, data=data), "otp.admin")
                    session.observe("admin_response", (reply.protocol, reply.status))
                    challenge = session.fixture("otp.admin.challenge", 64)
                    session.check("admin command does not replace slot key", slot_request(session, calculate, challenge, 20), hmac.digest(key, challenge, "sha1"))
                    session.observe("write_visibility", "acknowledgment and independent slot control; opaque admin record has no read API")
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        slot_request(session, write, bytes(58))
                        if command == 0x12:
                            defaults = bytes(next(code for code, text in US.items() if text == char.lower()) | (0x80 if char.isupper() else 0) if char != "!" else 0x9E for char in CHARSET)
                            slot_request(session, 0x12, defaults + bytes(6))
                            session.observe("cleanup_limit", "default US map installed; previous write-only map cannot be restored")
    with session.case("otp.admin.scan-map.actual-keyboard-effect", ("Y13", "Y11", "Y12"), effects=("config_change", "keyboard_output", f"replace_otp_slot_{slot}")):
        session.require(session.profile == "rsk", "scan-map behavior is profiled for RS-Key", "excluded_by_profile")
        session.require(session.keyboard is not None and session.options.operator, "scan-map effect requires explicit keyboard receiver and operator")
        from yubikit.yubiotp import HotpSlotConfiguration
        slot_select(session)
        write = 1 if slot == 1 else 3
        key = session.fixture("scan-map.HOTP", 20)
        config = HotpSlotConfiguration(key).append_cr(False).get_config()
        default = bytes(next(code for code, value in US.items() if value == char.lower()) | (0x80 if char.isupper() else 0) if char != "!" else 0x9E for char in CHARSET)
        try:
            slot_request(session, write, config + bytes(6))
            slot_request(session, 0x12, bytes([4]) * 45 + bytes(6))
            text = receive(session, "short press" if slot == 1 else "long press")
            session.check("scan map changes actual HID output", text, "aaaaaa")
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                slot_request(session, 0x12, default + bytes(6))
                slot_request(session, write, bytes(58))
                session.observe("cleanup_limit", "default US scan map installed; previous write-only scan map cannot be exported")
