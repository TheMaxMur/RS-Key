# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A reboot acknowledgment precedes an independently observed USB disconnect."""
from . import codec
from .lifecycle import Action, change
from .rescue_cases import active, request
from .rescue_presence import cue, private_control
from .trace import Outcome, TransferError


def run(session):
    for applet in ("rescue", "vendor"):
        for bootsel in (False, True):
            with session.case(f"rescue.reboot.observed-response-before-disconnect.{applet}.BOOTSEL-{bootsel}",
                    ("R05", "X11", "T01", "G12", "G14"), effects=("reboot", "session_recovery"), touch=True):
                session.require(session.profile == "rsk", "reboot availability/profile requires RS-Key", "excluded_by_profile")
                session.require(session.card is not None and hasattr(session.card, "wait_disconnect"),
                    "reboot ordering requires a native USB disconnect observation, not a PC/SC APDU or operator report", "excluded_by_mode")
                session.require(session.options.operator, "BOOTSEL exit and exact normal-mode rebinding require an operator")
                active(session)
                public, acknowledged = request(session, 0x10, 2), False
                session.select(applet, required=True)
                cue(session, "accept")
                try:
                    reply = session.apdu(codec.apdu(0x1f, int(bootsel), cla=0x80 if applet == "rescue" else 0))
                    session.check("reboot returns its complete acknowledgment before observation continues", (reply.protocol, reply.status, reply.data), ("success", 0x9000, b"\x90\x00"))
                    acknowledged = True
                    answer = session.trace.exchanges[-1]
                    try:
                        session._exchange("card", "usb_disconnect_observation", "reboot.await-USB-disconnect", b"", session.options.timeout,
                            lambda deadline, observe: session.card.wait_disconnect(deadline, observe))
                    except TransferError as error:
                        session.check("reboot produces an actual USB disconnect rather than a host timeout", error.outcome, Outcome.DISCONNECTED)
                    else:
                        session.check("disconnect observation cannot fabricate an APDU response", False)
                    disconnected = session.trace.exchanges[-1]
                    session.check("host observed the entire answer before its disconnect observation", answer["timing"]["call_end_ns"] <= disconnected["timing"]["call_end_ns"])
                    session.observe("reboot_order_scope", {"acknowledgment_exchange": answer["exchange_id"], "disconnect_exchange": disconnected["exchange_id"],
                        "device_reset_instant_ns": None, "ordering": "host observations; no exact device-side reset timestamp"})
                finally:
                    if acknowledged:
                        session.trace.emit("interaction", action="return-selected-key-to-normal-mode", stage="requested", source="runner", bootsel=bootsel)
                        input("oracle: return ONLY the selected test key to normal USB mode, then press Enter: ")
                        change(session, Action.USB_RECONNECT)
                active(session)
                private_control(session, public)
