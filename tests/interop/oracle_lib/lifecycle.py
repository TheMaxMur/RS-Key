# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Explicit connection changes; operator reports never become device timestamps."""
from enum import Enum

from .trace import Reply


class Action(Enum):
    RECONNECT = "reconnect"
    CARD_RESET = "card_reset"
    POWER_CYCLE = "power_cycle"
    USB_RECONNECT = "usb_reconnect"


def change(session, action, transport="card"):
    if session.broken and action == Action.RECONNECT and session.current and "session_recovery" in session.current.effects:
        session.recovering = True
        try:
            return _change(session, action, transport)
        finally:
            session.recovering = False
    return _change(session, action, transport)


def _change(session, action, transport):
    session._gate()
    if not isinstance(action, Action):
        raise ValueError("connection action must be typed")
    backend = getattr(session, transport)
    session.require(backend is not None and hasattr(backend, "control"), "selected backend cannot perform this connection action", "excluded_by_mode")
    session.require(action != Action.POWER_CYCLE or session.options.operator or getattr(backend, "emulated", False),
                    "physical power cycle requires --operator; availability is not an observed gesture")
    rebind_usb = action in (Action.POWER_CYCLE, Action.USB_RECONNECT)
    session.require(not rebind_usb or session.hid is None or hasattr(session.hid, "reopen"),
                    "USB connection action needs a defined HID rebinding backend")
    if rebind_usb:
        for name, interface in (("otp", session.otp_hid), ("keyboard", session.keyboard)):
            session.require(interface is None or hasattr(interface, "reopen"), name + " interface has no defined rebinding operation")
    session.values.pop("same_instance_confirmed", None)
    started = session.trace.now()
    session.trace.emit("interaction", action=action.value, stage="requested", source="runner", transport=transport)
    if action == Action.POWER_CYCLE and not getattr(backend, "emulated", False):
        input("oracle: unplug and replug ONLY the selected test key, then press Enter: ")
        completed = session.trace.now()
        session.trace.emit("interaction", action=action.value, stage="reported_complete", source="operator_report",
                           uncertainty_ns=completed - started, interval_start_ns=started, interval_end_ns=completed)
    reply = session._exchange(transport, "backend_control", action.value, b"", session.options.timeout,
                              lambda deadline, observe: backend.control("reconnect" if action == Action.USB_RECONNECT else action.value, deadline, observe))
    session.check("connection control completed", reply.protocol, "success")
    session.broken = False
    session.values.pop("halt_reason", None)
    session.applet = None
    session.values.pop("fido.info", None)
    session.trace.emit("session_changed", session_id=transport, cause=action.value, evidence=session.evidence(),
                       binding="same exact reader/path; no neighboring-device fallback")
    if rebind_usb and session.hid is not None:
        descriptor = session.hid.reopen(session.options.operator)
        session.trace.emit("device_bound", session_id="hid", device=descriptor,
                           binding_evidence="same unique serial, VID/PID, interface and family; or explicit operator-selected serial-less interface")
        session.hid.initialize(session.trace, session.options.timeout)
    if rebind_usb:
        for name, interface in (("otp", session.otp_hid), ("keyboard", session.keyboard)):
            if interface is not None:
                session.require(hasattr(interface, "reopen"), name + " interface has no defined rebinding operation")
                descriptor = interface.reopen(session.options.operator)
                session.trace.emit("device_bound", session_id=name, device=descriptor, binding_evidence="explicit replug binding")
    if session.hid is not None and session.card is not None:
        from .binding import check_pair
        try:
            check_pair(session)
        except BaseException:
            session.broken = True
            raise


def run(session):
    from . import codec
    for action in Action:
        for applet in ("piv", "openpgp", "oath"):
            with session.case(f"connection.{action.value}.{applet}", ("T01", "T14", "X11"),
                              effects=("reboot",) if action == Action.POWER_CYCLE else ()):
                selected = session.select(applet)
                change(session, action)
                after = session.select(applet)
                if applet == "piv":
                    session.check("PIV version after session change", len(session.card_value(session.apdu(codec.apdu(0xFD)))), 3)
                elif applet == "openpgp":
                    session.check("OpenPGP challenge after session change", len(session.card_value(session.apdu(codec.apdu(0x84, le=8)))), 8)
                else:
                    session.check("OATH identity survives connection change", dict(codec.parse_tlv(after)).get(0x71), dict(codec.parse_tlv(selected)).get(0x71))
