# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Opaque records stay unknown; observable PHY, RTC and scan maps get readback."""
from contextlib import ExitStack

from . import codec, keyboard, phy_records
from .keyboard_counters import configuration, expected_hotp, ready
from .otp_admin_matrix import default_map
from .otp_commands import Mode, Route, configure, fixture, request as otp_request, witness
from .rescue_cases import active, device_certificate_fixture, request as rescue
from .rescue_presence import private_control
from .uncertain_writes import classify, lose, require_loss


def rescue_records(session):
    from cryptography.hazmat.primitives.asymmetric import ec
    for kind in ("PHY", "RTC", "certificate"):
        with session.case("cross.unknown-write.rescue." + kind, ("X10", "R02", "R03", "R04", "G11", "G12", "G14"),
                effects=("session_recovery", "config_change", "set_rtc", "replace_identity"), touch=True):
            require_loss(session)
            active(session)
            public = rescue(session, 0x10, 2)
            if kind == "PHY":
                original = phy_records.read(session)
                expected = {**original, 9: b"Oracle uncertain\x00", 15: b"Oracle writer\x00"}
                with phy_records.fixture(session, original, expected):
                    active(session)
                    payload = phy_records.tlv(9, expected[9]) + phy_records.tlv(15, expected[15])
                    lose(session, 0x1c, lambda: session.apdu(codec.apdu(0x1c, 1, data=payload, cla=0x80)))
                    classify(session, "whole staged PHY record", phy_records.read(session), original, expected)
                    private_control(session, public)
            elif kind == "RTC":
                original = rescue(session, 0x1e, 4, 2)
                session.check("RTC readback has the complete epoch width", len(original), 4)
                old, started = int.from_bytes(original, "big"), session.trace.now()
                new = old ^ 0x40000000
                lose(session, 0x1c, lambda: session.apdu(codec.apdu(0x1c, 2, 2, new.to_bytes(4, "big"), cla=0x80)))
                active(session)
                actual = int.from_bytes(rescue(session, 0x1e, 4, 2), "big")
                elapsed = (session.trace.now() - started) // 1_000_000_000 + 2
                old_window, new_window = (actual - old) & 0xffffffff <= elapsed, (actual - new) & 0xffffffff <= elapsed
                session.check("RTC lost write reads one complete old or new running clock", old_window != new_window)
                session.observe("RTC_unknown_write_readback", {"outcome": "unchanged" if old_window else "committed",
                    "host_elapsed_tolerance_seconds": elapsed, "device_commit_instant": None, "mutation_replayed": False})
                private_control(session, public)
                restore = (old + (session.trace.now() - started) // 1_000_000_000) & 0xffffffff
                rescue(session, 0x1c, 2, 2, restore.to_bytes(4, "big"))
                session.check("RTC explicit recovery restores the advancing original epoch", (int.from_bytes(rescue(session, 0x1e, 4, 2), "big") - restore) & 0xffffffff <= 2)
            else:
                certificate = device_certificate_fixture(session, ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public))
                lose(session, 0x10, lambda: session.apdu(codec.apdu(0x10, 3, data=certificate, cla=0x80)))
                active(session)
                private_control(session, public)
                session.observe("unknown_write_readback", {"record": "rescue device certificate", "commit": "unknown", "partial": "unobservable",
                    "reason": "profile has no certificate export/read command; unchanged signing key cannot prove certificate contents", "mutator_replayed": False})
                session.require(False, "certificate commit/partial state has no decisive public observation; unknown retained", "unknown")


def opaque_otp(session):
    for command in (8, 9, 0x11):
        with session.case(f"cross.unknown-write.OTP.opaque-admin-{command:02x}", ("X10", "Y01", "Y06", "Y13", "G11", "G12", "G14"),
                effects=("session_recovery", "config_change", "otp_both_slots", "otp_extra_slots")):
            require_loss(session)
            session.require("strict-config" not in session.options.features, "strict-config deliberately swallows these admin writes", "excluded_by_profile")
            with ExitStack() as stack:
                configs = {slot: configure(session.fixture(f"unknown.admin.slot-{slot}", 20), Mode.HMAC) for slot in range(1, 5)}
                for slot, config in configs.items():
                    stack.enter_context(fixture(session, Route.CARD, slot, config))
                body = b"\x01\x00\x00\x00" if command == 0x11 else b"oracle-owned-opaque-record".ljust(64, b"\x00") + bytes(6)
                lose(session, 1, lambda: otp_request(session, Route.CARD, command, body))
                session.select("otp")
                for slot, config in configs.items():
                    witness(session, Route.CARD, slot, config)
                session.observe("unknown_write_readback", {"record": f"OTP admin {command:02x}", "commit": "unknown", "partial": "unobservable",
                    "reason": "no export or active NDEF/legacy-mode effect in this USB profile; SELECT resets program sequence, so it is not durable commit evidence", "mutator_replayed": False})
                session.require(False, "opaque admin write remains unknown after its independent private-slot controls", "unknown")


def scan_map(session):
    with session.case("cross.unknown-write.OTP.scan-map.actual-keyboard-readback", ("X10", "Y09", "Y11", "Y12", "Y13", "Y14", "G11", "G12", "G14"),
            effects=("session_recovery", "config_change", "otp_both_slots", "otp_extra_slots", "keyboard_output")):
        require_loss(session)
        ready(session, Mode.HOTP6)
        session.require("strict-config" not in session.options.features, "strict-config intentionally swallows scan-map writes", "excluded_by_profile")
        configs = {slot: configuration(session, slot, Mode.HOTP6, access=bytes(6)) for slot in range(1, 5)}
        try:
            with ExitStack() as stack:
                for slot, config in configs.items():
                    stack.enter_context(fixture(session, Route.CARD, slot, config))
                session.card_value(otp_request(session, Route.CARD, 0x12, default_map()))
                session.check("known pre-loss US map is established through actual keyboard output", keyboard.receive(session, keyboard.gesture(session, 1)), expected_hotp(configs[1], 0))
                lose(session, 1, lambda: otp_request(session, Route.CARD, 0x12, bytes([4]) * 45))
                session.select("otp")
                actual = keyboard.receive(session, keyboard.gesture(session, 1))
                classify(session, "whole effective OTP scan map", actual, expected_hotp(configs[1], 1), "aaaaaa")
                session.observe("scan_map_readback_scope", "actual mapped HOTP digits distinguish old/new effective mappings; opaque unused map entries remain unobservable through this output, and no claim is made about those bytes")
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                session.select("otp")
                session.card_value(otp_request(session, Route.CARD, 0x12, default_map()))
                session.observe("cleanup_limit", "known default US map retained; prior custom map is write-only and cannot be restored")


def run(session):
    rescue_records(session)
    opaque_otp(session)
    scan_map(session)
