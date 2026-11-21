# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Lost boot/setup acknowledgments retain the limits of public readback evidence."""
from itertools import product

from . import codec
from .binding import prove_credential, require_pair
from .fido import info
from .fido_fixtures import credential
from .lifecycle import Action, change, require_action
from .rescue_cases import active, request
from .rescue_presence import cue, private_control
from .rescue_recovery import ready
from .runner import AIDS
from .uncertain_writes import lose, require_loss


def setup(session):
    for layout, selector, magic in (("empty", 0, b"INITV2"), ("legacy", 1, b"IMPORTV2")):
        with session.case("cross.unknown-write.rescue.storage-setup." + layout, ("X10", "R01", "R02", "R06", "G11", "G12", "G14"),
                effects=("session_recovery", "storage_setup", "reboot"), touch=True):
            require_loss(session)
            require_action(session, Action.USB_RECONNECT)
            session.require(session.hid is None and session.otp_hid is None and session.keyboard is None,
                "recovery setup uses only the exact rescue card; ordinary applets cannot provide a pre-setup cross-interface identity proof", "excluded_by_mode")
            ready(session, layout)
            cue(session, "accept")
            lose(session, 0x20, lambda: session.apdu(codec.apdu(0x20, selector, data=magic, cla=0x80)), recovery=Action.USB_RECONNECT)
            session.select("rescue")
            status = request(session, 0x1e, 8)
            session.check("unknown setup readback is complete active or recovery state", status in (b"\x02\x00", b"\x02\x01"))
            session.observe("unknown_setup_readback", {"layout": layout, "ready": status == b"\x02\x01",
                "commit": "active transition observed" if status == b"\x02\x01" else "unknown; recovery remains",
                "full_media_before_after": "unobservable through public recovery commands", "initialization_retried": False})
            if status == b"\x02\x01":
                public = request(session, 0x10, 2)
                private_control(session, public)
                for applet in ("fido", "piv", "openpgp", "oath", "otp", "management", "vendor"):
                    reply = session.apdu(codec.apdu(0xa4, 4, data=AIDS[applet]))
                    session.check("active setup exposes factory applets or preserves declared legacy applet policy", reply.status in ((0x9000,) if layout == "empty" else (0x9000, 0x6285, 0x6a82)))
                    session.observe("setup_applet." + applet, reply.status)
            session.require(False, "public readiness/dispatch cannot prove a complete media image or exclude every partial legacy migration; explicit unknown retained without reinitializing", "unknown")


def reboots(session):
    for applet, bootsel in product(("rescue", "vendor"), (False, True)):
        with session.case(f"cross.unknown-write.reboot.{applet}.BOOTSEL-{bootsel}", ("X10", "X11", "R02", "R05", "T01", "G11", "G12", "G14"),
                effects=("session_recovery", "reboot", "create_fido_credential"), touch=True):
            require_loss(session)
            require_pair(session)
            require_action(session, Action.USB_RECONNECT)
            session.require(session.options.operator, "lost reboot needs an operator to return only the selected BOOTSEL test key to normal mode")
            hid, card = getattr(session.hid, "descriptor", {}), getattr(session.card, "descriptor", {})
            session.require(hid.get("serial_number") and hid.get("serial_number") == card.get("serial_number"),
                "lost boot recovery needs exact serial-matched native interfaces", "excluded_by_mode")
            session.require(not info(session).get(4, {}).get("alwaysUv"), "fresh post-rebind proof must precede any PIN entry on the unproved peer")
            active(session)
            public = request(session, 0x10, 2)
            with credential(session, session.current.name, extensions={"credProtect": 1}) as retained:
                session.select(applet)
                cue(session, "accept")
                lose(session, 0x1f, lambda: session.apdu(codec.apdu(0x1f, int(bootsel), cla=0x80 if applet == "rescue" else 0)), recovery=None)
                session.trace.emit("interaction", action="return-only-selected-test-key-to-normal-mode", stage="requested", source="runner", bootsel_requested=bootsel)
                input("oracle: if the selected test key entered BOOTSEL, return it to normal mode; otherwise leave its state as found, then press Enter: ")
                session.trace.emit("interaction", action="return-only-selected-test-key-to-normal-mode", stage="reported_complete", source="operator_report", observed_disconnect_ns=None)
                change(session, Action.USB_RECONNECT)
                prove_credential(session, retained)
                active(session)
                private_control(session, public)
                session.observe("unknown_reboot_readback", {"request_applet": applet, "bootsel_requested": bootsel, "acknowledgment": "unobserved",
                    "device_reset_instant_ns": None, "CPU_reboot_committed": "unknown", "original_private_keys_retained": True,
                    "reason": "injected handle close abandons the native response/disconnect path; a normal-mode rebind/operator report cannot prove the requested CPU/BOOTSEL transition", "reboot_retried": False})
                session.require(False, "lost reboot ACK has no decisive CPU/BOOTSEL commit witness after handle close; do not manufacture a reset or resend it", "unknown")


def run(session):
    setup(session)
    reboots(session)
