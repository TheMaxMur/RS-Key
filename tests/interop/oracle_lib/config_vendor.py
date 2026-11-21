# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Vendor CONFIG integer IDs stage truncated PHY values without applying a boot."""
from itertools import product

from . import codec, phy_records
from .config_matrix import request
from .enterprise import EA_RPIDS
from .fido import info, pin_token
from .management_cases import read as management_read, write as management_write
from .rescue_cases import request as rescue
from .rescue_presence import private_control
from .vendor_cases import vendor
from .vendor_lifecycle import AUT_ENABLE, AUT_DISABLE

PHY_IDS = {0x6fcb19b0cbe3acfa: (0, 4), 0x7b392a394de9f948: (4, 1),
           0x76a85945985d02fd: (5, 1), 0x269f3b09eceb805f: (6, 2)}
DEFINED_IDS = {*PHY_IDS, AUT_ENABLE, AUT_DISABLE, EA_RPIDS}


def catalog(session):
    with session.case("rsk.CONFIG-COMMANDS.complete-profile-catalog", ("V09", "V10", "F01", "F21", "G14")):
        session.require(session.profile == "rsk", "vendor CONFIG IDs require RS-Key", "excluded_by_profile")
        advertised = session.ctap_value(vendor(session, 15))[1]
        session.check("vendor catalog lists every defined ID exactly once", isinstance(advertised, list) and len(advertised) == len(DEFINED_IDS) and set(advertised) == DEFINED_IDS)
        session.check("standard getInfo does not invent a second vendor catalog", info(session).get(21, []), [])


def integers(session):
    values = (None, 0, 1, 23, 24, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1)
    for version, (identifier, (tag, width)), value in product((1, 2), PHY_IDS.items(), values):
        with session.case(f"rsk.CONFIG.vendor-PHY.protocol-{version}.tag-{tag:02x}.value-{value}",
                ("F21", "V09", "R03", "G01", "G03", "G04", "G10", "G11", "G14"), effects=("config_change",), touch=True,
                parameters={"vendor_id": identifier, "integer": value, "wire_width": width, "apply_at_boot": False}):
            session.require(session.profile == "rsk", "vendor PHY integer rules require RS-Key", "excluded_by_profile")
            before = phy_records.read(session)
            expected = {**before, tag: ((value or 0) & ((1 << (width * 8)) - 1)).to_bytes(width, "big")}
            with phy_records.fixture(session, before, expected):
                public = rescue(session, 0x10, 2)
                effective = session.ctap_value(vendor(session, 13, {1: 1})).get(2, {})
                fields = {1: identifier, **({3: value} if value is not None else {})}
                version, token = pin_token(session, 32, version=version)
                command = request(session, version, token, 255, fields)
                session.ctap_value(session.ctap(13, command))
                session.check("CONFIG integer is truncated to its defined PHY width", phy_records.read(session), expected)
                session.check("staged CONFIG integer does not change boot-effective GPIO/driver/timeout", session.ctap_value(vendor(session, 13, {1: 1})).get(2, {}), effective)
                session.ctap_value(session.ctap(13, command))
                session.check("authenticated replay keeps the same complete PHY record", phy_records.read(session), expected)
                rejected = {**command, 4: bytes([command[4][0] ^ 1]) + command[4][1:]}
                session.check("same numeric change with an invalid MAC is refused", session.ctap(13, rejected).status, 0x33)
                session.check("refused replay preserves all staged PHY fields", phy_records.read(session), expected)
                private_control(session, public)


def locked(session):
    for version, (identifier, (tag, width)), identical in product((1, 2), PHY_IDS.items(), (False, True)):
        with session.case(f"rsk.CONFIG.vendor-PHY.locked.protocol-{version}.tag-{tag:02x}.identical-{identical}",
                ("F21", "V09", "M04", "G10", "G13", "G14"), effects=("config_change",), touch=True):
            session.require(session.profile == "rsk", "shared PHY lock requires RS-Key", "excluded_by_profile")
            original = management_read(session, "card")
            session.require(original.get(10) == b"\x00", "known unlocked management fixture required")
            before = phy_records.read(session)
            session.require(tag in before, "locked identical case needs a stored field before setup")
            code = session.fixture("CONFIG.vendor.PHY.lock", 16)
            try:
                management_write(session, "card", codec.tlv(10, code))
                session.check("shared lock was actually armed", management_read(session, "card")[10], b"\x01")
                number = int.from_bytes(before[tag], "big") ^ (0 if identical else 1)
                version, token = pin_token(session, 32, version=version)
                fields = request(session, version, token, 255, {1: identifier, 3: number})
                session.check("PHY config lock precedes identical or changed integer writes", session.ctap(13, fields).status, 0x30)
                session.check("locked CONFIG integer preserves the complete record", phy_records.read(session), before)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    current = management_read(session, "card")
                    if current.get(10) == b"\x01":
                        management_write(session, "card", codec.tlv(11, code) + codec.tlv(10, bytes(16)))
                    session.check("numeric CONFIG fixture restores management configuration", management_read(session, "card"), original)


def run(session):
    catalog(session)
    integers(session)
    locked(session)
