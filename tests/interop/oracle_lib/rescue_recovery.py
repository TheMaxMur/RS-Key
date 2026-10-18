# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Prepared recovery media expose only the defined rescue command whitelist."""
from itertools import product

from . import codec
from .rescue_cases import request
from .rescue_presence import cue, require
from .runner import AIDS

LAYOUTS = ("empty", "legacy", "occupied", "incompatible")


def ready(session, layout):
    session.require(session.profile == "rsk", "storage recovery command policy requires RS-Key", "excluded_by_profile")
    session.require(session.options.recovery_layout == layout, "an independently prepared matching recovery fixture must be explicitly declared")
    session.select("rescue", required=True)
    session.require(request(session, 0x1e, 8) == b"\x02\x00", "prepared storage fixture is not in recovery mode")
    session.observe("prepared_layout_basis", "operator-declared layout; the public ready bit does not identify its bytes or prove a complete storage-image hash")


def whitelist(session):
    forbidden = [(0x10, selector, 0, bytes(32) if selector == 1 else b"x" if selector == 3 else b"") for selector in (0, 1, 2, 3, 255)]
    forbidden += [(0x1b, 0, 0, b"invalid"), (0x1c, 1, 0, b"\x06\x02\x00\x00"), (0x1c, 2, 2, bytes(4))]
    forbidden += [(0x1e, selector, 0, b"") for selector in (0, 1, 2, 5, 9, 255)]
    forbidden += [(0x7e, 0, 0, b"")]
    for layout in LAYOUTS:
        with session.case("rescue.recovery.full-command-whitelist." + layout, ("R01", "R04", "R06", "R07", "G10", "G13", "G14")):
            ready(session, layout)
            for applet in ("fido", "piv", "openpgp", "oath", "otp", "management", "vendor"):
                session.check("only rescue remains selectable in recovery mode", session.apdu(codec.apdu(0xa4, 4, data=AIDS[applet])).status, 0x6a82)
            session.select("rescue", required=True)
            for ins, p1, p2, body in forbidden:
                request(session, ins, p1, p2, body, expected=0x6581)
                session.check("forbidden recovery command cannot initialize or alter readiness", request(session, 0x1e, 8), b"\x02\x00")
            for selector, width in ((3, 3), (7, 2), (8, 2)):
                session.check("allowed recovery status has its declared width", len(request(session, 0x1e, selector)), width)
            result = session.apdu(codec.apdu(0x1e, 6, cla=0x80))
            session.check("rollback status is served or reports the platform's unavailable fuse reader", result.status in (0x9000, 0x6400))
            if result.status == 0x9000:
                session.check("available recovery rollback status is complete", len(session.card_value(result)), 3)
            for civil in (False, True):
                result = session.apdu(codec.apdu(0x1e, 4, 1 if civil else 2, cla=0x80))
                session.check("recovery permits RTC reads with the explicit unset-clock refusal", result.status in (0x9000, 0x6985))
                if result.status == 0x9000:
                    session.check("set RTC read has the selected complete representation", len(session.card_value(result)), 8 if civil else 4)
            for p1, p2, data, expected in ((2, 0, b"INITV2", 0x6a86), (0, 1, b"INITV2", 0x6a86),
                    (0, 0, b"", 0x6a80), (0, 0, b"IMPORTV2", 0x6a80), (1, 0, b"INITV2", 0x6a80)):
                request(session, 0x20, p1, p2, data, expected=expected)
            request(session, 0x1f, 255, expected=0x6a86)
            request(session, 0x1f, 1, data=b"x", expected=0x6700)
            session.check("whitelist probes leave the recovery fixture unconsumed", request(session, 0x1e, 8), b"\x02\x00")


def administration(session):
    for layout, selector, mode in product(LAYOUTS, (0, 1), ("decline", "panel-cancel", "timeout", "accept")):
        if layout in ("empty", "legacy") and mode == "accept":
            continue
        with session.case(f"rescue.recovery.administration.{layout}.action-{selector}.{mode}", ("R06", "G10", "G12", "G13", "G14"), effects=("storage_setup",), touch=True):
            ready(session, layout)
            require(session, mode)
            cue(session, mode)
            expected = 0x6581 if layout == "incompatible" and mode == "accept" else 0x6985
            result = session.apdu(codec.apdu(0x20, selector, data=b"INITV2" if selector == 0 else b"IMPORTV2", cla=0x80))
            if result.status != expected:
                session.broken = True
                session.values["halt_reason"] = "unexpected storage-administration result; prepared recovery fixture needs explicit inspection"
            session.check("prepared occupied/incompatible or refused administration has its distinct cause", result.status, expected)
            session.check("refused administration neither activates storage nor consumes its fixture", request(session, 0x1e, 8), b"\x02\x00")
            session.check("ordinary applets remain unreachable after refused setup", session.apdu(codec.apdu(0xa4, 4, data=AIDS["piv"])).status, 0x6a82)
            session.select("rescue", required=True)
            session.observe("storage_preservation_limit", "readiness and command availability are observed; private flash-image preservation is verified by the storage backend's host tests, not by exporting secrets")


def run(session):
    whitelist(session)
    administration(session)
