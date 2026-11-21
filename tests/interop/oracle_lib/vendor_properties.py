# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Counter, LED normalization, audit wrap and measurement-build command properties."""
import hashlib

from . import codec
from .vendor_cases import rsk, vendor
from .vectors import pairwise


def counter(session):
    with session.case("rsk.counter.increment-read-and-reselect", ("V11", "X08", "G11"), effects=("increment_vendor_counter",), touch=True):
        rsk(session)
        session.select("vendor")
        before = int.from_bytes(session.card_value(session.apdu(codec.apdu(2))), "big")
        after = int.from_bytes(session.card_value(session.apdu(codec.apdu(1))), "big")
        session.check("vendor counter increment", after, (before + 1) & 0xFFFFFFFF)
        session.select("vendor")
        session.check("counter survives reselect", int.from_bytes(session.card_value(session.apdu(codec.apdu(2))), "big"), after)
        session.observe("cleanup_limit", "monotonic fixture counter increment retained")


def leds(session):
    dimensions = {"status": range(4), "effect": range(5), "color": range(8),
                  "brightness": (0, 1, 7, 8, 254, 255), "speed": (0, 1, 2, 254, 255), "steady": (False, True)}
    for parameters in pairwise(dimensions, session.options.seed + ":LED"):
        label = ".".join(f"{key}-{value}" for key, value in parameters.items())
        with session.case("rsk.LED." + label, ("V12", "V09", "G03", "G04", "G14"), effects=("config_change",), touch=True,
                          parameters=parameters, method="seeded pairwise; every pair of declared levels; candidate product bounded at 65536"):
            rsk(session)
            session.select("vendor")
            original = session.card_value(session.apdu(codec.apdu(0x11)))
            session.require(len(original) == 17, "LED property cases require the 17-byte profile")
            try:
                p2 = parameters["status"] << 4 | parameters["color"] | (8 if parameters["steady"] else 0)
                session.card_value(session.apdu(codec.apdu(0x10, parameters["brightness"], p2, bytes([parameters["effect"], parameters["speed"]]))))
                block = session.card_value(session.apdu(codec.apdu(0x11)))
                session.check("LED block width", len(block), 17)
                session.check("global steady flag applied", block[0], int(parameters["steady"]))
                touch = block[9:13]
                session.check("touch color cannot be off", touch[1] != 0)
                session.check("touch brightness has floor", touch[2] >= 8)
                session.check("touch speed has floor", touch[3] == 0 or touch[3] >= 2)
                others = [block[2 + index * 4] for index in (0, 1, 3)]
                session.check("touch color remains unique", touch[1] not in others)
                session.check("LED effective read stable", session.card_value(session.apdu(codec.apdu(0x11))), block)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    session.ctap_value(vendor(session, 12, {1: 2, 2: original}, authenticated=True))
                    session.select("vendor")
                    session.check("LED fixture restored", session.card_value(session.apdu(codec.apdu(0x11))), original)


def audit_wrap(session):
    with session.case("rsk.audit.ring-wrap-chain", ("V07", "V08", "G11", "G14"), effects=("capacity", "config_change"), touch=True):
        rsk(session)
        original = session.ctap_value(vendor(session, 14, {1: 2}))[1]
        try:
            session.ctap_value(vendor(session, 14, {1: 1}, authenticated=True))
            before = session.ctap_value(vendor(session, 7, authenticated=True))
            for index in range(130):
                session.ctap_value(vendor(session, 14, {1: index & 1}, authenticated=True))
                session.ctap_value(vendor(session, 14, {1: 1}, authenticated=True))
            after = session.ctap_value(vendor(session, 7, authenticated=True))
            session.check("audit sequence advances beyond ring", after[2] - before[2] > 128)
            session.check("audit ring retains bounded window", after[2] - after[1], 128)
            session.check("wrapped audit entry byte count", len(after[4]), 128 * 20)
            session.check("ring wrap advances prefix commitment", after[1] > before[1])
            head = after[3]
            for offset in range(0, len(after[4]), 20):
                head = hashlib.sha256(head + after[4][offset:offset + 20]).digest()
            checkpoint = session.ctap_value(vendor(session, 8, {1: b"wrap"}, authenticated=True))
            if checkpoint[2] == after[2]:
                session.check("wrapped ring chain reaches checkpoint", head, checkpoint[1])
            else:
                session.observe("checkpoint_continuity", "explicit intervening journal entries; prefix cannot be asserted")
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                session.ctap_value(vendor(session, 14, {1: int(original)}, authenticated=True))


def measurements(session):
    for selector in (0, 1, 2, 3, 255):
        with session.case(f"rsk.measurement.bench.selector-{selector}", ("V13", "G04")):
            rsk(session)
            session.require("bench" in session.options.features, "positive benches need a confirmed measurement build", "excluded_by_profile")
            session.select("vendor")
            result = session.apdu(codec.apdu(0x14, selector, 1), "vendor.bench")
            if selector == 255:
                session.check("unknown bench selector refused", result.protocol, "applet_error")
            else:
                data = session.card_value(result)
                session.check("bench summary shape", len(data) in (20, 24))
                words = [int.from_bytes(data[index:index + 4], "little") for index in range(0, 20, 4)]
                session.check("bench has samples and ordered minimum/median", words[0] > 0 and words[2] <= words[3])
                session.observe("device_timer_summary_us", words, "presence")


def run(session):
    counter(session)
    leds(session)
    audit_wrap(session)
    measurements(session)
