# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw CCID messages and PC/SC Part 10 pinpad requests retain their own layers."""
from . import codec
from .trace import Reply


def ccid(session, command, body=b"", slot=0, sequence=0, declared=None):
    session.require(session.card is not None and hasattr(session.card, "raw"), "raw CCID unavailable through selected PC/SC backend", "excluded_by_mode")
    request = bytes([command]) + (len(body) if declared is None else declared).to_bytes(4, "little") + bytes([slot, sequence, 0, 0, 0]) + body
    response = session._exchange("ccid", "ccid_message", f"ccid.{command:02x}.slot-{slot}.seq-{sequence}", request, session.options.timeout,
                                 lambda deadline, observe: Reply(session.card.raw(request, deadline, observe)))
    session.check("CCID response header present", len(response.data) >= 10)
    return response.data


def messages(session):
    for sequence in (0, 1, 127, 255):
        with session.case(f"transport.CCID.power-status-transfer.{sequence}", ("T10", "G04", "G14")):
            powered = ccid(session, 0x62, sequence=sequence)
            session.check("CCID power-on ATR present", len(powered) > 10)
            session.check("CCID power-on sequence", powered[6], sequence)
            status = ccid(session, 0x65, sequence=sequence)
            session.check("CCID status response type", status[0], 0x81)
            session.check("CCID card active", status[7] & 3, 0)
            for slot in (1, 255):
                rejected = ccid(session, 0x65, slot=slot, sequence=sequence)
                session.check("CCID invalid slot fails at transport", rejected[7] & 0xC0, 0x40)
                session.check("CCID slot refusal cause", rejected[8], 5)
            off = ccid(session, 0x63, sequence=sequence)
            session.check("CCID power-off response", off[7] & 3, 1)
            ccid(session, 0x62, sequence=sequence)
            from .runner import AIDS
            result = ccid(session, 0x6F, codec.apdu(0xA4, 4, data=AIDS["piv"]), sequence=sequence)
            session.check("XfrBlock usable after invalid slot and power off", result[-2:], b"\x90\x00")


def ioctl(session, code, body, label):
    session.require(session.card is not None and hasattr(session.card, "pipe"), "PC/SC control backend unavailable", "excluded_by_mode")
    request = code.to_bytes(4, "big") + body
    reply = session._exchange("card", "pcsc_control", label, request, session.options.timeout,
                              lambda deadline, observe: session.card.transfer({"control": "ioctl", "code": code, "data": body}, deadline, observe))
    return reply.data


def verify_structure(reference):
    template = bytes([0, 0x20, 0, reference])
    return bytes.fromhex("0000820000067f0201000000000000") + len(template).to_bytes(4, "little") + template


def pinpad(session):
    from smartcard.pcsc.PCSCPart10 import CM_IOCTL_GET_FEATURE_REQUEST
    for applet, reference in (("piv", 0x80), ("openpgp", 0x81), ("openpgp", 0x82), ("openpgp", 0x83)):
        for action in ("correct-PIN", "operator-cancel", "timeout", "truncated-structure"):
            with session.case(f"transport.pinpad.{applet}.{reference:02x}.{action}", ("T16", "P03" if applet == "piv" else "O02", "G14"), touch=action == "correct-PIN"):
                session.require(session.profile != "trezor", "wallet profile excludes PC/SC pinpad", "excluded_by_profile")
                session.require(session.options.operator, "secure PIN-entry scenarios require --operator")
                session.select(applet)
                features = ioctl(session, CM_IOCTL_GET_FEATURE_REQUEST, b"", "pcsc.features")
                session.check("PC/SC feature TLV width", len(features) % 6, 0)
                controls = {features[offset]: int.from_bytes(features[offset + 2:offset + 6], "big") for offset in range(0, len(features), 6)}
                session.require(6 in controls, "driver does not expose FEATURE_VERIFY_PIN_DIRECT", "unknown")
                body = verify_structure(reference)
                session.trace.emit("interaction", action=action, source="runner", stage="requested", observed_touch_ns=None)
                import sys
                print(f"oracle: pinpad {applet} {reference:02x}: {action}", file=sys.stderr)
                result = ioctl(session, controls[6], body[:-1] if action == "truncated-structure" else body, "pcsc.verify-pin-direct")
                session.check("pinpad response has status", len(result) >= 2)
                sw = int.from_bytes(result[-2:], "big")
                session.observe("secure_entry_status", sw)
                if action == "correct-PIN":
                    session.check("on-device PIN accepted", sw, 0x9000)
                else:
                    session.check("cancel/timeout/malformed cannot authenticate", sw != 0x9000)


def run(session):
    messages(session)
    pinpad(session)
