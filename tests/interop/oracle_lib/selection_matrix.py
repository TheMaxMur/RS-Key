# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Selection presence and competition do not authorize any credential operation."""
import sys

from .fido import cm, pin_token
from .fido_fixtures import credential
from .hid_sequences import allocate, hooks, send
from .transport import HID_CBOR, HID_ERROR, HID_PING


def run(session):
    for mode in ("confirm", "decline", "no-touch", "cancel", "competing-selection"):
        with session.case("fido.selection.matrix." + mode, ("F22", "T06", "T07", "T08", "X05", "G14"),
                effects=("create_fido_credential",), touch=True, parameters={"selection_action": mode}):
            session.require(session.profile == "rsk", "selection status/ownership contract requires RS-Key", "excluded_by_profile")
            session.require(mode not in ("confirm", "decline", "no-touch") or session.options.operator, "selection needs the declared operator action")
            session.require(mode != "decline" or "display" in session.options.features, "explicit decline requires a display")
            session.require(mode != "no-touch" or session.options.timeout > 130, "withheld selection presence needs the complete device timeout")
            other = allocate(session) if mode == "competing-selection" else None
            with credential(session, session.current.name) as fixture:
                version, token = pin_token(session, 64)
                before = session.ctap_value(cm(session, version, token, 1))
                retries = session.ctap_value(session.ctap(6, {1: version, 2: 1}))
                print("oracle: selection: " + mode + "; do not confirm the owner when cancellation/competition is requested", file=sys.stderr)
                session.trace.emit("interaction", action="selection-" + mode, stage="requested", source="runner", observed_touch_ns=None)
                if mode in ("cancel", "competing-selection"):
                    timeline, foreign = [], []
                    def report(frame, timestamp):
                        if other is not None and frame[:4] == other:
                            foreign.append(frame)
                    def keepalive(status, timestamp):
                        timeline.append((status, timestamp))
                        if status == 2:
                            if other is not None and len(timeline) == 1:
                                send(session, HID_CBOR, other, b"\x0b", "ctaphid.competing-selection")
                            elif other is None or len(timeline) >= 3:
                                send(session, 0x11, session.hid.cid)
                    with hooks(session, keepalive=keepalive, report=report):
                        result = session.ctap(11)
                    session.check("selection cancellation follows actual UP-needed", any(status == 2 for status, _ in timeline))
                    session.check("selection is cancelled by its owner", result.status, 0x2d)
                    for frame in foreign:
                        session.check("competing selection receives CHANNEL_BUSY if answered", frame[4:8], bytes([HID_ERROR | 128, 0, 1, 6]))
                    if other is not None:
                        owner = session.hid.cid
                        try:
                            session.hid.cid = other
                            session.check("competing CID recovers after selection cancellation", session.hid_call(HID_PING, b"selection-owner-ended").data, b"selection-owner-ended")
                        finally:
                            session.hid.cid = owner
                else:
                    result = session.ctap(11)
                    session.check("selection follows the declared presence outcome", result.status, {"confirm": 0, "decline": 0x27, "no-touch": 0x2f}[mode])
                session.check("selection never consumes a PIN retry", session.ctap_value(session.ctap(6, {1: version, 2: 1})), retries)
                session.check("selection preserves the persistent listing grant", session.ctap_value(cm(session, version, token, 1)), before)
                fixture.assertion(session)
