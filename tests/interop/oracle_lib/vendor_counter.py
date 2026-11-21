# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The vendor counter is shared, persistent and increments only after consent."""
from enum import Enum
from itertools import product
import sys

from . import codec
from .binding import require_pair
from .lifecycle import Action, change, require_action
from .runner import AIDS
from .trace import Outcome, TransferError

COUNTER_MASK = 0xffffffff


class Route(Enum):
    CARD = "CCID"
    HID = "CTAPHID-MSG"


def cue(session, mode):
    session.trace.emit("interaction", action="vendor-counter-consent-" + mode, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: selected test key vendor counter confirmation: " + mode, file=sys.stderr)


def ready(session):
    session.require(session.profile == "rsk", "vendor counter profile requires RS-Key", "excluded_by_profile")
    session.require(session.hid is not None and session.card is not None, "counter sharing needs both explicitly selected transports", "excluded_by_mode")
    require_pair(session)


def select(session, route):
    if route == Route.CARD:
        session.select("vendor", required=True)
    else:
        session.card_value(session.hid_call(3, codec.apdu(0xa4, 4, data=AIDS["vendor"]), "vendor.HID.SELECT"))


def call(session, route, ins=2, p1=0, p2=0, body=b""):
    wire = codec.apdu(ins, p1, p2, body)
    return session.apdu(wire) if route == Route.CARD else session.hid_call(3, wire, "vendor.HID.counter")


def read(session, route):
    select(session, route)
    body = session.card_value(call(session, route))
    session.check("vendor counter response is exactly one unsigned word", len(body), 4)
    return int.from_bytes(body, "big")


def shared(session, value):
    for route in Route:
        session.check("both transports expose the same persistent counter", read(session, route), value)


def consent(session):
    for route, mode in product(Route, ("accept", "decline", "panel-cancel", "timeout")):
        with session.case(f"rsk.counter.consent.{route.value}.{mode}", ("V11", "X08", "G10", "G11", "G14"), effects=("increment_vendor_counter",), touch=True):
            ready(session)
            session.require(session.options.operator, "counter consent/refusal needs a controlled operator action")
            session.require(mode not in ("decline", "panel-cancel") or "display" in session.options.features, "explicit counter refusal requires the display profile", "excluded_by_profile")
            session.require(mode != "timeout" or session.options.timeout > 130, "counter timeout needs the complete presence window")
            before = read(session, route)
            cue(session, mode)
            result = call(session, route, 1)
            expected = (before + 1) & COUNTER_MASK if mode == "accept" else before
            session.check("counter mutation has a distinct consent refusal", result.status, 0x9000 if mode == "accept" else 0x6985)
            if mode == "accept":
                session.check("increment response contains the committed counter value", session.card_value(result), expected.to_bytes(4, "big"))
            else:
                session.check("refused counter mutation returns no value", result.data[:-2], b"")
            shared(session, expected)
            if mode != "accept":
                select(session, route)
                cue(session, "accept")
                session.check("valid increment recovers immediately after refusal", session.card_value(call(session, route, 1)), ((before + 1) & COUNTER_MASK).to_bytes(4, "big"))
                shared(session, (before + 1) & COUNTER_MASK)


def parameters(session):
    for route, ins, p1, p2, size in product(Route, (1, 2), (0, 1, 127, 255), (0, 255), (0, 1, 255)):
        with session.case(f"rsk.counter.parameters.{route.value}.INS-{ins}.P1-{p1}.P2-{p2}.length-{size}", ("V11", "G01", "G03", "G04", "G11", "G14"), effects=("increment_vendor_counter",) if ins == 1 else (), touch=ins == 1):
            ready(session)
            before = read(session, route)
            cue(session, "accept")
            result = call(session, route, ins, p1, p2, session.fixture("vendor.counter.ignored-body", size))
            expected = (before + (ins == 1)) & COUNTER_MASK
            session.check("counter ignores its unused parameters and body without extra mutations", session.card_value(result), expected.to_bytes(4, "big"))
            shared(session, expected)


def persistence(session):
    for route, action in product(Route, Action):
        with session.case(f"rsk.counter.persistence.{route.value}.{action.value}", ("V11", "X08", "X11", "G11", "G14"), effects=("increment_vendor_counter", "reboot"), touch=True):
            ready(session)
            session.require(hasattr(session.card, "control"), "counter persistence needs a defined connection backend", "excluded_by_mode")
            require_action(session, action)
            before = read(session, route)
            cue(session, "accept")
            value = (before + 1) & COUNTER_MASK
            session.check("fixture increment commits before the connection action", session.card_value(call(session, route, 1)), value.to_bytes(4, "big"))
            change(session, action)
            shared(session, value)


def lost_response(session):
    with session.case("rsk.counter.lost-increment-response.no-replay", ("V11", "X10", "G11", "G12", "G14"), effects=("increment_vendor_counter", "session_recovery"), touch=True):
        ready(session)
        session.require(hasattr(session.card, "drop_response"), "counter response-loss injection requires an explicit backend boundary", "excluded_by_mode")
        before, wire = read(session, Route.CARD), codec.apdu(1)
        cue(session, "accept")
        try:
            session._exchange("card", session.card.layer, "vendor.counter.increment-lost-response", wire, session.options.timeout,
                lambda deadline, observe: session.card.drop_response(wire, deadline, observe))
        except TransferError as error:
            session.check("counter injection reports an unknown delivered response", (error.outcome, error.protocol), (Outcome.CANCELLED, "injected_response_loss"))
        else:
            session.check("response-loss injection cannot return a known counter acknowledgment", False)
        change(session, Action.RECONNECT)
        value = read(session, Route.CARD)
        session.check("uncertain increment commits at most once and is never replayed", value in (before, (before + 1) & COUNTER_MASK))
        shared(session, value)
        session.observe("uncertain_counter_readback", {"before": before, "after": value, "mutation_replayed": False})


def run(session):
    consent(session)
    parameters(session)
    persistence(session)
    lost_response(session)
