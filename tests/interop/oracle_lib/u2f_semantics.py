# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""U2F references, counters, cancellation and transport lifetimes use owned handles."""
from cryptography.hazmat.primitives.asymmetric import ec

from .fido import u2f_apdu, u2f_registration, verified
from .fido_fixtures import credential
from .hid_sequences import allocate, hooks, send
from .lifecycle import Action, change


def available(session):
    reply = session.hid_call(3, u2f_apdu(3), "u2f.VERSION.precondition")
    session.require(reply.status == 0x9000, "valid U2F VERSION refused by current applet/policy", "unsupported_confirmed")


def payload(fixture, handle=None, application=None):
    handle = fixture["handle"] if handle is None else handle
    return fixture["challenge"] + (fixture["application"] if application is None else application) + bytes([len(handle) & 255]) + handle


def assertion(session, fixture, mode=3, route="hid"):
    wire = u2f_apdu(2, mode, payload(fixture))
    if route == "card":
        session.select("fido")
        response = session.apdu(wire, "u2f.AUTH.card")
    else:
        response = session.hid_call(3, wire, "u2f.AUTH.hid")
    value = session.card_value(response)
    session.check("U2F signature response has flags and counter", len(value) > 5)
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), fixture["public_key"])
    verified(session, "retained U2F credential signature", public, -7, value[5:], fixture["application"] + value[:5] + fixture["challenge"])
    session.check("U2F UP flag follows control", value[0] & 1, int(mode == 3))
    return int.from_bytes(value[1:5], "big")


def bounds(session):
    for size in (0, 1, 31, 32, 63, 65, 96, 128):
        with session.case(f"u2f.REGISTER.body-length-{size}", ("U02", "U06", "G03", "G14"), effects=("create_u2f_credential",), touch=True):
            available(session)
            fixture = u2f_registration(session, session.current.name)
            before = assertion(session, fixture)
            reply = session.hid_call(3, u2f_apdu(1, data=session.fixture("U2F.invalid-register", size)))
            session.check("REGISTER fixed concatenation must contain two 32-byte fields", reply.status, 0x6700)
            session.observe("REGISTER_length_basis", "no field length markers: only the concatenated 64-byte width is observable")
            session.check("refused REGISTER does not advance authentication counter", assertion(session, fixture), before + 1)
    for mode in range(256):
        if mode in (3, 7, 8):
            continue
        with session.case(f"u2f.AUTH.reserved-control-{mode:02x}", ("U03", "U04", "U05", "U06", "G04", "G14"), effects=("create_u2f_credential",), touch=True):
            available(session)
            fixture = u2f_registration(session, session.current.name)
            before = assertion(session, fixture)
            response = session.hid_call(3, u2f_apdu(2, mode, payload(fixture)))
            session.check("reserved U2F control is an applet refusal", response.protocol, "applet_error")
            session.check("reserved U2F control has no counter effect", assertion(session, fixture), before + 1)
    for size in (0, 1, 31, 32, 63, 64, 65, 255, 256):
        with session.case(f"u2f.AUTH.handle-length-{size}", ("U03", "U04", "G03", "G09", "G14"), effects=("create_u2f_credential",), touch=True):
            available(session)
            fixture = u2f_registration(session, session.current.name)
            before = assertion(session, fixture)
            reply = session.hid_call(3, u2f_apdu(2, 7, payload(fixture, handle=session.fixture("U2F.foreign-handle", size))))
            session.check("foreign or malformed handle refused before presence", reply.protocol, "applet_error")
            session.check("handle refusal does not advance counter", assertion(session, fixture), before + 1)


def lifetime(session):
    for action in ("mixed-FIDO", "vendor-SELECT", "card-transport", Action.USB_RECONNECT, Action.POWER_CYCLE):
        label = action.value if isinstance(action, Action) else action
        with session.case("u2f.lifetime." + label, ("U02", "U03", "U04", "U05", "U06", "FE13", "X02", "X03", "X11", "G14"),
                          effects=("create_u2f_credential", "create_fido_credential", "reboot") if action == Action.POWER_CYCLE else ("create_u2f_credential", "create_fido_credential"), touch=True):
            if isinstance(action, Action):
                session.require(session.profile == "rsk" and session.card is not None and hasattr(session.card, "control"), "explicit paired RS-Key reconnect backend required", "excluded_by_mode")
            elif action in ("vendor-SELECT", "card-transport"):
                session.require(session.card is not None, "selected smartcard transport required", "excluded_by_mode")
            available(session)
            first, second = [u2f_registration(session, session.current.name + f".{index}") for index in (0, 1)]
            counts = [assertion(session, first), assertion(session, second), assertion(session, first)]
            session.check("U2F counter is global across handles", [counts[1] - counts[0], counts[2] - counts[1]], [1, 1])
            session.check("check-only recognizes owned handle without presence", session.hid_call(3, u2f_apdu(2, 7, payload(first))).status, 0x6985)
            if action == "mixed-FIDO":
                with credential(session, session.current.name) as fido:
                    fido.assertion(session)
            elif action == "vendor-SELECT":
                session.select("vendor" if session.profile == "rsk" else "management")
            elif isinstance(action, Action):
                change(session, action)
            current = assertion(session, first, route="card" if action == "card-transport" else "hid")
            session.check("U2F key and counter survive selected transition", current, counts[-1] + 1)
            response = session.hid_call(3, u2f_apdu(2, 8, payload(first)))
            session.observe("no-UP_profile_outcome", (response.protocol, response.status))
            if response.protocol == "success":
                # Verify this response rather than sending a second authentication.
                data = session.card_value(response)
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), first["public_key"])
                verified(session, "U2F no-UP signature", key, -7, data[5:], first["application"] + data[:5] + first["challenge"])
                session.check("no-UP response has UP clear", data[0] & 1, 0)
                session.check("no-UP signature advances global counter once", int.from_bytes(data[1:5], "big"), current + 1)
            else:
                session.check("no-UP request was refused by applet policy", response.protocol, "applet_error")
                session.check("no-UP refusal has no counter effect", assertion(session, first), current + 1)


def presence(session):
    for operation in (1, 2):
        for outcome in ("cancel", "foreign-cancel", "no-touch"):
            with session.case(f"u2f.presence.command-{operation}.{outcome}", ("U02", "U03", "U04", "T07", "G12", "G14"), effects=("create_u2f_credential",), touch=True,
                    parameters={"u2f_operation": operation, "presence_action": outcome}):
                available(session)
                session.require(outcome != "no-touch" or session.options.operator and session.options.timeout > 35, "no-touch U2F case requires --operator and timeout above 35 seconds")
                if outcome in ("cancel", "foreign-cancel"):
                    session.require(session.hid is not None and hasattr(session.hid, "send_only"), "raw cancellation backend required", "excluded_by_mode")
                other = allocate(session) if outcome == "foreign-cancel" else None
                fixture = u2f_registration(session, session.current.name)
                before = assertion(session, fixture)
                request = u2f_apdu(operation, 0 if operation == 1 else 3, fixture["challenge"] + fixture["application"] if operation == 1 else payload(fixture))
                if outcome in ("cancel", "foreign-cancel"):
                    timeline = []
                    def cancel(status, timestamp):
                        timeline.append((status, timestamp))
                        if status == 2:
                            send(session, 0x11, other if other is not None and len(timeline) == 1 else session.hid.cid)
                    with hooks(session, keepalive=cancel):
                        reply = session.hid_call(3, request)
                    session.check("U2F cancellation followed an actual UP request", any(status == 2 for status, _ in timeline))
                    if other is not None:
                        session.check("foreign CANCEL cannot finish the U2F owner's presence wait", sum(status == 2 for status, _ in timeline) >= 2)
                else:
                    import sys
                    print("oracle: do not touch until the U2F request has been refused", file=sys.stderr)
                    session.trace.emit("interaction", action="withhold_U2F_presence", stage="requested", source="runner", observed_touch_ns=None)
                    reply = session.hid_call(3, request)
                session.check("U2F absent or cancelled presence refused", reply.status, 0x6985)
                session.check("presence refusal leaves key and counter intact", assertion(session, fixture), before + 1)


def run(session):
    bounds(session)
    lifetime(session)
    presence(session)
