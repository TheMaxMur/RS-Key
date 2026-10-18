# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Explicit warm boot and connection lifetimes never equate reconnect with power loss."""
from enum import Enum

from . import codec
from .binding import require_pair
from .lifecycle import Action, change, require_action
from .rescue_presence import cue
from .trace import Outcome, TransferError


class Boundary(Enum):
    SELF = "select-self"
    OTHER = "select-other"
    INVALID = "invalid-select"
    RECONNECT = "reconnect"
    CARD_RESET = "card_reset"
    USB_RECONNECT = "usb_reconnect"
    USB_RESET = "usb-reset"
    POWER = "power_cycle"
    WARM = "warm-reboot"


def preflight(session, boundary):
    session.require(session.card is not None, "vendor lifetime controls require the selected card interface")
    require_pair(session)
    if boundary in (Boundary.RECONNECT, Boundary.CARD_RESET, Boundary.USB_RECONNECT, Boundary.POWER):
        require_action(session, Action(boundary.value))
    elif boundary == Boundary.WARM:
        require_action(session, Action.USB_RECONNECT)
        session.require(hasattr(session.card, "wait_disconnect"), "warm boot needs an actual USB disconnect observation", "excluded_by_mode")
    elif boundary == Boundary.USB_RESET:
        require_action(session, Action.USB_RECONNECT)
        session.require(hasattr(session.card, "usb_reset"), "USB bus reset requires its explicit native backend; handle reconnect is insufficient", "excluded_by_mode")


def cross(session, boundary):
    if boundary in (Boundary.SELF, Boundary.OTHER, Boundary.INVALID):
        session.select("fido")
        if boundary == Boundary.SELF:
            session.select("fido")
        elif boundary == Boundary.OTHER:
            session.select("piv", required=True)
            session.card_value(session.apdu(codec.apdu(0xfd)))
        else:
            session.check("unknown AID has the profiled rejection", session.apdu(codec.apdu(0xa4, 4, data=b"oracle-no-such-applet")).status, 0x6a82)
        session.select("fido")
    elif boundary == Boundary.USB_RESET:
        session._exchange("card", "usb_control", "vendor-lifetime.USB-bus-reset", b"", session.options.timeout,
            lambda deadline, observe: session.card.usb_reset(deadline, observe))
        change(session, Action.USB_RECONNECT)
    elif boundary != Boundary.WARM:
        change(session, Action(boundary.value))
    else:
        session.select("rescue", required=True)
        cue(session, "accept")
        result = session.apdu(codec.apdu(0x1f, cla=0x80))
        session.check("warm reboot acknowledges before disconnect observation", (result.status, result.data), (0x9000, b"\x90\x00"))
        try:
            session._exchange("card", "usb_disconnect_observation", "vendor-lifetime.warm-disconnect", b"", session.options.timeout,
                lambda deadline, observe: session.card.wait_disconnect(deadline, observe))
        except TransferError as error:
            session.check("warm boot is an observed disconnect", error.outcome, Outcome.DISCONNECTED)
        else:
            session.check("warm boot cannot substitute a host answer for disconnect", False)
        change(session, Action.USB_RECONNECT)


def loses_ram(boundary):
    return boundary in (Boundary.POWER, Boundary.WARM)
