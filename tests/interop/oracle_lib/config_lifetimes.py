# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A populated shared lock, flags and disabled applet survive each native lifetime."""
from itertools import product

from . import codec
from .fido import info
from .fido_fixtures import credential
from .management_cases import WRITERS, read, require_writer, write
from .management_state import usable
from .runner import AIDS
from .vendor_boot import Boundary, cross, preflight

OATH_CAPABILITY = 32


def run(session):
    for writer, boundary in product(WRITERS, Boundary):
        with session.case(f"management.shared-lifetime.writer-{writer}.{boundary.value}", ("X08", "X11", "M02", "M03", "M04", "M05", "M06", "G10", "G11", "G14"),
                effects=("config_change", "create_fido_credential", "reboot", "session_recovery"), touch=True,
                parameters={"writer": writer, "boundary": boundary.value, "stored_fields": [3, 8, 10]}):
            session.require(session.profile == "rsk", "shared configuration lifetime contracts require RS-Key", "excluded_by_profile")
            preflight(session, boundary)
            require_writer(session, writer)
            session.require(usable(session, writer), "strict-config disables this writer's changes", "excluded_by_profile")
            session.require(info(session).get(4, {}).get("clientPin") and session.options.pin, "known configured FIDO PIN required for private continuity witness")
            original = read(session, "card")
            session.require(original.get(10) == b"\x00" and int.from_bytes(original[3], "big") & OATH_CAPABILITY,
                "lifetime fixture requires an initially unlocked configuration with OATH enabled")
            mask = (int.from_bytes(original[3], "big") & ~OATH_CAPABILITY).to_bytes(2, "big")
            code, changed = session.fixture("config.lifetime.lock", 16), False
            with credential(session, session.current.name) as retained:
                try:
                    write(session, writer, codec.tlv(3, mask) + codec.tlv(8, bytes([original[8][0] ^ 0x40])) + codec.tlv(10, code))
                    expected = {**original, 3: mask, 8: bytes([original[8][0] ^ 0x40]), 10: b"\x01"}
                    session.check("writer atomically installs the owned mask, flags and lock", read(session, "card"), expected)
                    changed = True
                    session.check("disabled OATH is actually refused before the boundary", session.apdu(codec.apdu(0xa4, 4, data=AIDS["oath"])).is_rejection)
                    cross(session, boundary)
                    readers = ["card", "hid", "fido"] + (["otp"] if session.otp_hid is not None else [])
                    for reader in readers:
                        session.check("every selected interface sees the same complete persistent configuration", read(session, reader), expected)
                    session.check("disabled OATH dispatch stays refused after the boundary", session.apdu(codec.apdu(0xa4, 4, data=AIDS["oath"])).is_rejection)
                    denied = write(session, "card", codec.tlv(3, original[3]))
                    session.check("persistent lock rejects an unauthenticated real mask change", denied.is_rejection)
                    session.check("refused mask cannot partially enable OATH", read(session, "card"), expected)
                    retained.assertion(session)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        write(session, "card", codec.tlv(11, code) + codec.tlv(10, bytes(16)) + codec.tlv(3, original[3]) + codec.tlv(8, original[8]))
                        session.check("known lock code restores every original shared field", read(session, "card"), original)
                        session.check("restored OATH applet is actually reachable", bool(session.select("oath")))
                        retained.assertion(session)
