# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rescue selectors and calendar inputs, including the profile's normalization."""
from datetime import datetime, timedelta, timezone

from . import codec
from .lifecycle import Action, change
from .rescue_cases import RTC_MAX, active, request


def civil_bytes(year, month, day, hour=0, minute=0, second=0, weekday=0):
    return year.to_bytes(2, "big") + bytes((month, day, weekday, hour, minute, second))


def epoch(session):
    value = request(session, 0x1E, 4, 2)
    session.check("Unix RTC response length", len(value), 4)
    return int.from_bytes(value, "big")


def unchanged_clock(session, seconds, started):
    got = epoch(session)
    elapsed = (session.trace.now() - started) // 1000000000 + 2
    session.check("refusal preserves advancing RTC", (got - seconds) & RTC_MAX <= elapsed)


def calendars(session):
    dates = ((1970, 0, 1, 0, 0, 0), (1999, 11, 31, 23, 59, 59), (2000, 1, 29, 12, 34, 56),
             (2000, 1, 30, 0, 0, 0), (2001, 1, 29, 0, 0, 0), (2000, 3, 31, 0, 0, 0),
             (2038, 0, 19, 3, 14, 8), (2106, 1, 7, 6, 28, 15), (2000, 11, 31, 23, 59, 60))
    for fields in dates:
        for weekday in (0, 6, 255):
            with session.case("rescue.RTC.civil." + ".".join(map(str, (*fields, weekday))), ("R04", "G04", "G14"),
                              effects=("set_rtc",), parameters={"calendar": fields, "weekday": weekday}):
                active(session)
                year, month, day, hour, minute, second = fields
                expected = datetime(year, month + 1, 1, tzinfo=timezone.utc) + timedelta(days=day - 1, hours=hour, minutes=minute, seconds=second)
                request(session, 0x1C, 2, 1, civil_bytes(*fields, weekday=weekday))
                started = session.trace.now()
                unchanged_clock(session, int(expected.timestamp()), started)
                wire = request(session, 0x1E, 4, 1)
                session.check("calendar readback width", len(wire), 8)
                observed = datetime(int.from_bytes(wire[:2], "big"), wire[2] + 1, wire[3], wire[5], wire[6], wire[7], tzinfo=timezone.utc)
                elapsed = (session.trace.now() - started) // 1000000000 + 2
                session.check("calendar normalized date", (int(observed.timestamp()) - int(expected.timestamp())) & RTC_MAX <= elapsed)
                session.check("weekday recomputed from calendar", wire[4], (observed.weekday() + 1) % 7)
                session.observe("calendar_profile", "RS-Key normalizes short-month overflow and leap second; weekday on write is ignored")


def invalid_clock(session):
    base = civil_bytes(2000, 1, 29, 12, 34, 56)
    invalid = [("civil-length-" + str(size), 1, base[:size] if size < 8 else base + bytes(size - 8), 0x6700)
               for size in (0, 1, 7, 9, 16)]
    for index, value, label in ((2, 12, "month"), (2, 255, "month-overflow"), (3, 0, "day-zero"),
                                (3, 32, "day"), (5, 24, "hour"), (6, 60, "minute"), (7, 61, "second")):
        body = bytearray(base)
        body[index] = value
        invalid.append((label, 1, bytes(body), 0x6A80))
    invalid.extend((("pre-epoch", 1, civil_bytes(1969, 11, 31, 23, 59, 59), 0x6A80),
                    ("epoch-overflow", 1, civil_bytes(2106, 1, 7, 6, 28, 16), 0x6A80),
                    ("year-overflow", 1, civil_bytes(65535, 0, 1), 0x6A80)))
    invalid.extend(("unix-length-" + str(size), 2, bytes(size), 0x6700) for size in (0, 1, 3, 5, 8))
    invalid.extend(("selector-" + str(p2), p2, base, 0x6A86) for p2 in (0, 3, 255))
    for name, selector, data, status in invalid:
        with session.case("rescue.RTC.refuse." + name, ("R04", "G03", "G04", "G13", "G14"), effects=("set_rtc",)):
            active(session)
            request(session, 0x1C, 2, 2, (951782400).to_bytes(4, "big"))
            before, started = epoch(session), session.trace.now()
            request(session, 0x1C, 2, selector, data, expected=status)
            trigger = session.evidence()
            unchanged_clock(session, before, started)
            session.transition("rtc", "set", "preserved_after_refusal", trigger, [trigger, session.evidence()])


def selectors(session):
    sizes = {2: 20, 3: 3, 6: 3, 7: 2, 8: 2}
    for selector in (1, 2, 3, 5, 6, 7, 8, 0, 9, 255):
        with session.case(f"rescue.READ.selector-{selector}", ("R01", "G01", "G03", "G04", "G14")):
            active(session)
            expected = 0x9000 if selector in (1, *sizes) else 0x6A86
            if selector == 6 and getattr(session.card, "emulated", False):
                reply = session.apdu(codec.apdu(0x1E, selector, cla=0x80), "rescue.READ.rollback")
                session.require(reply.status != 0x6400, "selected emulator exposes no rollback fuse observation", "excluded_by_mode")
                value = session.card_value(reply)
            else:
                value = request(session, 0x1E, selector, expected=expected)
            if selector in sizes:
                session.check("rescue selector response width", len(value), sizes[selector])
            elif selector == 1:
                session.check("PHY read is parseable TLV", bool(codec.parse_tlv(value)))
            if selector == 2:
                free, used, total, _, flash = (int.from_bytes(value[offset:offset + 4], "big") for offset in range(0, 20, 4))
                session.check("flash usage accounting", total > 0 and used <= total and free + used == total and flash >= total)
            elif selector == 3:
                session.check("secure-boot state flags are Boolean", value[0] in (0, 1) and value[1] in (0, 1))
            elif selector == 6:
                session.check("rollback state within reported capacity", value[0] in (0, 1) and 0 <= value[1] <= value[2] and value[2] > 0)
            request(session, 0x1E, selector, data=b"x", expected=0x6700)
            session.check("invalid read leaves storage active", request(session, 0x1E, 8), b"\x02\x01")
    for ins, p1, p2, data, status in ((0x1E, 8, 1, b"", 0x6A86), (0x1E, 4, 0, b"", 0x6A86),
                                     (0x1E, 4, 3, b"", 0x6A86), (0x1C, 0, 0, b"", 0x6A86),
                                     (0x1C, 255, 0, b"x", 0x6A86), (0x1F, 2, 0, b"", 0x6A86),
                                     (0x1F, 255, 0, b"", 0x6A86), (0x1F, 0, 0, b"x", 0x6700),
                                     (0x20, 2, 0, b"INITV2", 0x6A86), (0x20, 0, 1, b"INITV2", 0x6A86)):
        with session.case(f"rescue.refuse.{ins:02x}.{p1}.{p2}.{data.hex()}", ("R01", "R05", "R06", "G13", "G14")):
            active(session)
            request(session, ins, p1, p2, data, expected=status)
            session.check("selector refusal leaves active store", request(session, 0x1E, 8), b"\x02\x01")


def unset_clock(session):
    with session.case("rescue.RTC.power-cycle-unsets", ("R04", "X11"), effects=("reboot",)):
        active(session)
        request(session, 0x1C, 2, 2, (951782400).to_bytes(4, "big"))
        change(session, Action.POWER_CYCLE)
        active(session)
        for selector in (1, 2):
            request(session, 0x1E, 4, selector, expected=0x6985)
        request(session, 0x1C, 2, 2, (951782400).to_bytes(4, "big"))
        unchanged_clock(session, 951782400, session.trace.now())


def run(session):
    selectors(session)
    calendars(session)
    invalid_clock(session)
    unset_clock(session)
