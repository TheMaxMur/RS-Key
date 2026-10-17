# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Configuration lock enforcement through each explicitly selected writer."""
from . import codec
from .vendor_cases import vendor

WRITERS = ("card", "hid", "otp", "fido")
APPLICATIONS = ((1, "otp"), (2, "u2f"), (8, "openpgp"), (16, "piv"), (32, "oath"), (512, "fido"))


def require_writer(session, writer):
    session.require(session.profile in ("rsk", "yubikey"), "management catalog requires a confirmed profile", "unknown")
    if writer in ("hid", "fido"):
        session.require(session.hid is not None, "no selected HID", "excluded_by_mode")
    elif writer == "otp":
        session.require(session.otp_hid is not None, "no selected OTP HID", "excluded_by_mode")
    else:
        session.require(session.card is not None, "no selected PC/SC reader", "excluded_by_mode")
    session.require(writer != "fido" or session.profile == "rsk", "0x41 management writer is RS-Key-specific", "excluded_by_profile")


def read(session, writer, required=False):
    require_writer(session, writer)
    if writer == "card":
        session.select("management", required=required)
        body = session.card_value(session.apdu(codec.apdu(0x1D)))
    elif writer == "hid":
        reply = session.hid_call(0x42, name="management.read-config")
        session.check("HID config read success", reply.protocol, "success")
        body = reply.data
    elif writer == "otp":
        reply = session.otp_call(0x13)
        session.check("OTP config read success", reply.protocol, "success")
        body = reply.data
    else:
        reply = session.hid_call(0x42, name="management.read-config-for-vendor-writer")
        session.check("HID config read success", reply.protocol, "success")
        body = reply.data
    session.check("DeviceInfo length prefix", len(body) > 0 and body[0] == len(body) - 1)
    entries = codec.parse_tlv(body[1:])
    session.check("DeviceInfo tags unique", len({tag for tag, _ in entries}), len(entries))
    return dict(entries)


def write(session, writer, fields):
    require_writer(session, writer)
    body = bytes([len(fields)]) + fields
    if writer == "card":
        session.select("management")
        return session.apdu(codec.apdu(0x1C, data=body))
    if writer == "hid":
        return session.hid_call(0x43, body, "management.write-config")
    if writer == "otp":
        return session.otp_call(0x15, body)
    return vendor(session, 12, {1: 0, 2: fields}, authenticated=True)


def locks(session):
    for writer in WRITERS:
        with session.case("management.transition.lock." + writer, ("M01", "M02", "M04", "M05", "X08", "G10", "G14"),
                          effects=("config_change",), touch=True):
            original = read(session, writer)
            session.require(original.get(0x0A) == b"\x00", "existing config lock is not replaced")
            code = session.fixture("management.lock", 16)
            set_reply = write(session, writer, codec.tlv(0x0A, code))
            session.observe("set.status", set_reply.status)
            # A strict-config writer can acknowledge while refusing to apply a change.
            current = read(session, writer)
            if current.get(0x0A) != b"\x01":
                session.require(False, "writer did not arm the lock; not an enforcement observation")
            locked = True
            try:
                selected = {"card": session.card is not None, "hid": session.hid is not None,
                            "otp": session.otp_hid is not None, "fido": session.hid is not None and session.profile == "rsk"}
                for other in (item for item in WRITERS if selected[item]):
                    session.check(other + " observes shared config lock", read(session, other).get(0x0A), b"\x01")
                    for defect, fields in (("missing", b""), ("wrong", codec.tlv(0x0B, code[:-1] + bytes([code[-1] ^ 1]))),
                                           ("short", codec.tlv(0x0B, code[:-1]))):
                        reply = write(session, other, fields + codec.tlv(0x0A, bytes(16)))
                        trigger = session.evidence()
                        label = other + "." + defect
                        session.observe(label + ".status", reply.status)
                        after = read(session, writer)
                        session.check(label + " unlock cannot clear lock", after.get(0x0A), b"\x01")
                        session.check(label + " unlock cannot change config", {k: v for k, v in after.items() if k != 0x0A},
                                      {k: v for k, v in original.items() if k != 0x0A})
                        session.transition("management.lock", "locked", "locked_after_" + label, trigger, [trigger, session.evidence()])
                replacement = session.fixture("management.replacement-lock", 16)
                write(session, writer, codec.tlv(0x0B, code) + codec.tlv(0x0A, replacement))
                code = replacement
                session.check("replacement lock remains set", read(session, writer).get(0x0A), b"\x01")
            finally:
                if locked and not session.broken:
                    session.trace.phase = "cleanup"
                    write(session, writer, codec.tlv(0x0B, code) + codec.tlv(0x0A, bytes(16)))
                    session.check("original unlocked configuration restored", read(session, writer), original)


def rejected_writes(session):
    for writer in WRITERS:
        for tag, value in ((1, b"\x00\x00"), (2, b"\x00" * 4), (4, b"\x01"), (5, b"\x01"), (3, b"\x00")):
            with session.case(f"management.negative.{writer}.tag-{tag}", ("M02", "M05", "G03", "G14"), effects=("config_change",), touch=True):
                original = read(session, writer)
                session.require(original.get(0x0A) == b"\x00", "malformed-write case requires unlocked config")
                reply = write(session, writer, codec.tlv(tag, value))
                session.observe("status", reply.status)
                trigger = session.evidence()
                session.check("malformed or device-owned tag does not change config", read(session, writer), original)
                session.transition("management.config", "original", "unchanged_after_invalid_write", trigger, [trigger, session.evidence()])


def run(session):
    rejected_writes(session)
    locks(session)


def extended(session):
    applications(session)
    service(session)
    persistence(session)


def applications(session):
    for writer in WRITERS:
        for subset in range(1 << len(APPLICATIONS)):
            mask = sum(bit for index, (bit, _) in enumerate(APPLICATIONS) if subset & (1 << index))
            with session.case(f"management.enforcement.{writer}.{mask:04x}", ("M03", "M05", "X08", "G14"), effects=("config_change",), touch=True):
                session.require(session.profile == "rsk", "live enforcement requires the confirmed RS-Key profile", "excluded_by_profile")
                session.require(session.card is not None, "explicit management-card restoration path is required")
                original = read(session, writer)
                session.require(original.get(10) == b"\x00", "requires unlocked configuration")
                before = original.get(3, original[1])
                try:
                    write(session, writer, codec.tlv(3, mask.to_bytes(2, "big")))
                    session.check("application mask readback", read(session, "card", required=True)[3], mask.to_bytes(2, "big"))
                    for bit, applet in APPLICATIONS:
                        if applet in ("fido", "u2f"):
                            if session.hid is None:
                                continue
                            reply = session.ctap(4) if applet == "fido" else session.hid_call(3, codec.apdu(3), "u2f.version.enforcement")
                        else:
                            from .runner import AIDS
                            reply = session.apdu(codec.apdu(0xA4, 4, data=AIDS[applet]), "select.enforcement." + applet)
                        session.check(applet + " actual dispatch enforcement", reply.protocol == "success", bool(mask & bit))
                        if not mask & bit:
                            session.check(applet + " disabled dispatch is a rejection", reply.is_rejection)
                    session.check("management remains reachable with all masks", bool(read(session, "card", required=True)))
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        write(session, "card", codec.tlv(3, before))
                        session.check("original application mask restored", read(session, "card")[3], before)


def service(session):
    for ins in (0x1E, 0x1F, 0, 0x7F, 255):
        with session.case(f"management.service-ins.{ins:02x}", ("M07", "G14"), effects=("config_change",)):
            session.require(session.profile == "rsk", "service INS catalog requires confirmed RS-Key", "excluded_by_profile")
            original = read(session, "card")
            session.select("management")
            reply = session.apdu(codec.apdu(ins), "management.service")
            session.check("profiled management service result", reply.status, 0x9000 if ins == 0x1E else 0x6D00)
            session.check("service command leaves configuration unchanged", read(session, "card"), original)


def persistence(session):
    from .lifecycle import Action, change
    for action in Action:
        with session.case("management.persistence." + action.value, ("M06", "M04", "X11"), effects=("config_change", "reboot") if action == Action.POWER_CYCLE else ("config_change",), touch=True):
            original = read(session, "card")
            session.require(original.get(10) == b"\x00", "requires initially unlocked configuration")
            code = session.fixture("management.persistence-lock", 16)
            changed = False
            try:
                write(session, "card", codec.tlv(10, code))
                session.check("persistent lock armed", read(session, "card")[10], b"\x01")
                changed = True
                change(session, action)
                session.check("lock survives connection action", read(session, "card")[10], b"\x01")
                write(session, "card", codec.tlv(3, b"\x00\x00"))
                session.check("persistent lock enforces rejection", read(session, "card")[10], b"\x01")
                session.check("configuration preserved through locked write", {k: v for k, v in read(session, "card").items() if k != 10},
                              {k: v for k, v in original.items() if k != 10})
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    write(session, "card", codec.tlv(11, code) + codec.tlv(10, bytes(16)))
                    session.check("persistence fixture lock cleared", read(session, "card"), original)
