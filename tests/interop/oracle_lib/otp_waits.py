# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw feature commands cancel only completed owner waits and preserve slot keys."""
from .otp import crc16
from .otp_challenges import cue
from .otp_commands import Mode, Route, checksum, configure, fixture, witness
from .otp_transport import DUMMY_ABORT, RESET, feature, frames, serial, status
from .timers import wait

POLL_INTERVAL_SECONDS, POLL_LIMIT = 0.02, 256


def poll(session, predicate, label):
    for _ in range(POLL_LIMIT):
        reply = feature(session).data
        session.check("waiting OTP report retains its exact width", len(reply), 8)
        if predicate(reply):
            return reply
        wait(session, POLL_INTERVAL_SECONDS)
    session.check(label, False)


def send(session, command, body):
    for report in frames(command, body.ljust(64, b"\x00")):
        feature(session, report)


def run(session):
    for slot in (1, 2):
        for mode in ("reset", "dummy-abort", "new-command", "partial-then-reset", "bad-CRC-then-reset"):
            with session.case(f"otp.raw-wait.slot-{slot}.{mode}", ("T15", "Y01", "Y07", "Y12", "X05", "G05", "G12", "G14"), effects=(f"replace_otp_slot_{slot}",), touch=True):
                session.require(session.options.operator, "raw OTP wait must be allowed to start without an accidental confirmation")
                session.require(session.otp_hid is not None and hasattr(session.otp_hid, "raw_feature"), "raw feature backend required", "excluded_by_mode")
                config = bytearray(configure(session.fixture("OTP.raw-wait.key", 20), Mode.HMAC))
                config[47] |= 8
                config = checksum(config)
                with fixture(session, Route.HID, slot, config):
                    expected = serial(session)
                    before = status(session)
                    cue(session, "withhold touch until the runner requests confirmation")
                    send(session, 0x30 if slot == 1 else 0x38, session.fixture("OTP.raw-wait.challenge", 64))
                    poll(session, lambda value: bool(value[-1] & 0x20), "challenge never entered observed UP-needed")
                    if mode in ("partial-then-reset", "bad-CRC-then-reset"):
                        packets = frames(0x10, session.fixture("OTP.queued.frame", 64))
                        if mode == "partial-then-reset":
                            packets = packets[:5]
                        else:
                            damaged = bytearray(packets[-1])
                            damaged[2] ^= 1
                            packets[-1] = bytes(damaged)
                        for packet in packets:
                            feature(session, packet)
                        for _ in range(3):
                            session.check("partial or bad-CRC incoming frame cannot cancel OTP presence", feature(session).data[-1] & 0x20, 0x20)
                    if mode == "new-command":
                        send(session, 0x10, bytes(64))
                        first = poll(session, lambda value: bool(value[-1] & 0x40) or value[-1] == 0, "replacement command never completed")
                        session.check("complete replacement supersedes the waiting challenge", first[-1], 0x40)
                        session.check("replacement returns exact serial rather than stale HMAC", first[:4], expected)
                        session.check("replacement serial has a valid response CRC", crc16(first[:6]), 0xf0b8)
                        session.check("replacement serial stream terminates without extra private reports", feature(session).data, bytes(7) + b"\x40")
                    else:
                        feature(session, DUMMY_ABORT if mode == "dummy-abort" else RESET)
                        first = poll(session, lambda value: value[-1] == 0 or bool(value[-1] & 0x40), "OTP abort never returned idle")
                        session.check("owner abort returns idle without private result data", first[-1], 0)
                    after = status(session)
                    session.check("OTP cancellation preserves program sequence and slot flags", after[4:7], before[4:7])
                    cue(session, "confirm")
                    witness(session, Route.HID, slot, config)
