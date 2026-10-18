# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rebind a measured native boundary without an intervening card applet SELECT."""
from . import codec
from .binding import require_pair, prove_credential
from .fido import info
from .lifecycle import Action, require_action
from .runner import AIDS, CtapRoute
from .trace import Outcome, TransferError
from .vendor_boot import Boundary


def preflight(session, boundary):
    session.require(session.profile == "rsk", "native lifetime contracts require RS-Key", "excluded_by_profile")
    session.require(boundary in (Boundary.WARM, Boundary.USB_RESET), "native boundary must be warm CPU reboot or USB bus reset")
    require_pair(session)
    require_action(session, Action.USB_RECONNECT)
    session.require(session.otp_hid is None and session.keyboard is None,
        "card-grant lifetime measurement requires only the selected FIDO and native CCID handles", "excluded_by_mode")
    card, hid = getattr(session.card, "descriptor", {}), getattr(session.hid, "descriptor", {})
    session.require(card.get("serial_number") and card.get("serial_number") == hid.get("serial_number"),
        "native lifetime requires matching unique backend serial bindings before fixture writes", "excluded_by_mode")
    session.require(hasattr(session.card, "usb_reset") if boundary == Boundary.USB_RESET else hasattr(session.card, "wait_disconnect"),
        "native bus reset or actual disconnect backend is unavailable", "excluded_by_mode")
    session.require(not info(session).get(4, {}).get("alwaysUv"), "post-boundary identity proof needs a silent UV-optional credential")


def cross(session, boundary, retained):
    card = session.card
    session.values.pop("same_instance_confirmed", None)
    try:
        if boundary == Boundary.WARM:
            session.card_value(session.hid_call(3, codec.apdu(0xa4, 4, data=AIDS["vendor"]), "native-lifetime.HID-MSG.SELECT-vendor"))
            session.card_value(session.hid_call(3, codec.apdu(0x1f), "native-lifetime.HID-MSG.warm-reboot"))
            try:
                session._exchange("card", "usb_disconnect_observation", "native-lifetime.warm-disconnect", b"", session.options.timeout,
                    lambda deadline, observe: card.wait_disconnect(deadline, observe))
            except TransferError as error:
                session.check("native warm reboot has an observed USB disconnect", error.outcome, Outcome.DISCONNECTED)
            else:
                session.check("native warm reboot must not fabricate a disconnect", False)
        else:
            session._exchange("card", "usb_control", "native-lifetime.USB-bus-reset", b"", session.options.timeout,
                lambda deadline, observe: card.usb_reset(deadline, observe))
        session.recovering = True
        result = session._exchange("card", "backend_control", "native-lifetime.exact-CCID-reopen", b"", session.options.timeout,
            lambda deadline, observe: card.control("reconnect", deadline, observe))
        session.check("exact native reader was reopened", result.protocol, "success")
        descriptor = session.hid.reopen(session.options.operator)
        session.trace.emit("device_bound", session_id="hid", device=descriptor, binding_evidence="same unique serial and unchanged exact native selectors")
        session.hid.initialize(session.trace, session.options.timeout)
        session.applet = None
        session.values.pop("fido.info", None)
        with session.route(CtapRoute.HID):
            prove_credential(session, retained)
        session.broken = False
        session.values.pop("halt_reason", None)
        session.values["same_instance_confirmed"] = True
        session.trace.emit("session_changed", session_id="native-pair", cause=boundary.value,
            binding="exact same serial-bound interfaces plus fresh private credential proof; no card SELECT between the boundary and the grant observation")
        session.observe("native_boundary_scope", "USB reset/reopen includes ICC power-on; grant observations concern that whole boundary. Warm reboot was sent through independent HID MSG selection. No CPU-parallelism or exact device reset timestamp is inferred.")
    except BaseException:
        session.broken = True
        session.values["halt_reason"] = "native boundary or fresh key-continuity proof failed; no following mutation is permitted"
        raise
    finally:
        session.recovering = False
