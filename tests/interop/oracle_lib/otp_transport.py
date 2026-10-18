# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Feature-report framing faults are independent of OTP applet command faults."""
from .otp import crc16

REPORT_BYTES, REPORT_DATA, PAYLOAD_BYTES = 8, 7, 64
RESET = bytes(7) + b"\xff"
DUMMY_ABORT = bytes(7) + b"\x8f"


def frames(command, payload):
    if len(payload) != PAYLOAD_BYTES:
        raise ValueError("OTP framing payload must contain 64 bytes")
    wire = payload + bytes([command]) + crc16(payload).to_bytes(2, "little") + bytes(3)
    return [wire[offset:offset + REPORT_DATA] + bytes([0x80 | index]) for index, offset in enumerate(range(0, len(wire), REPORT_DATA))]


def feature(session, report=None):
    session.require(session.profile != "trezor", "raw OTP excluded on wallet profile", "excluded_by_profile")
    session.require(session.otp_hid is not None and hasattr(session.otp_hid, "raw_feature"), "raw OTP feature backend unavailable", "excluded_by_mode")
    return session._exchange("otp", "otp_hid_feature", "otp.GET_REPORT" if report is None else "otp.SET_REPORT",
        b"" if report is None else report, session.options.timeout,
        lambda deadline, observe: session.otp_hid.raw_feature(report, deadline, observe))


def status(session):
    feature(session, RESET)
    value = feature(session).data
    session.check("OTP status report width", len(value), REPORT_BYTES)
    session.check("OTP status not a pending response", value[-1], 0)
    return value


def serial(session):
    expected = session.otp_call(0x10, expected_len=4).data
    session.check("serial control width", len(expected), 4)
    return expected


def run(session):
    for defect in ("bad-CRC", "missing-nonzero-report", "missing-final", "out-of-range-sequence", "dummy-abort", "reset-abort",
                   "reordered-complete", "duplicate-middle", "restart-first", "duplicate-final", "response-abort"):
        with session.case("transport.OTP-feature." + defect, ("T15", "Y01", "G05", "G12", "G14"), effects=("malformed_known_command",)):
            session.require(session.profile == "rsk", "sequence acceptance rules are profiled for RS-Key", "excluded_by_profile")
            expected = serial(session)
            before = status(session)
            packets = frames(0x10, session.fixture("OTP.frame.payload", PAYLOAD_BYTES))
            valid = defect in ("reordered-complete", "duplicate-middle", "restart-first", "duplicate-final", "response-abort")
            if defect == "bad-CRC":
                packets[-1] = packets[-1][:2] + bytes([packets[-1][2] ^ 1]) + packets[-1][3:]
            elif defect == "missing-nonzero-report":
                packets.pop(4)
            elif defect == "missing-final":
                packets.pop()
            elif defect == "out-of-range-sequence":
                packets[-1] = packets[-1][:-1] + b"\x8a"
            elif defect in ("dummy-abort", "reset-abort"):
                packets = [*packets[:5], DUMMY_ABORT if defect == "dummy-abort" else RESET]
            elif defect == "reordered-complete":
                packets = [packets[0], *reversed(packets[1:9]), packets[9]]
            elif defect == "duplicate-middle":
                packets.insert(5, packets[4])
            elif defect == "restart-first":
                packets = [*packets[:5], *packets]
            elif defect == "duplicate-final":
                packets.append(packets[-1])
            for packet in packets:
                feature(session, packet)
            reports = []
            for _ in range(16):
                report = feature(session).data
                session.check("raw OTP response report width", len(report), REPORT_BYTES)
                reports.append(report)
                if report[-1] & 0x40 or report[-1] == 0:
                    break
            first = reports[-1]
            if valid:
                session.check("complete CRC-valid report sequence produces serial data", first[-1], 0x40)
                session.check("raw serial exact with independent command control", first[:4], expected)
                if defect == "response-abort":
                    feature(session, DUMMY_ABORT)
                    session.check("abort retires pending OTP output", feature(session).data[-1], 0)
                else:
                    end = feature(session).data
                    session.check("serial response has terminal pending marker", end[-1], 0x40)
                    session.check("serial response CRC", crc16(first[:6]), 0xF0B8)
            else:
                session.check("incomplete or corrupt OTP frame produces no data", first[-1], 0)
            after = status(session)
            session.check("raw framing does not change program sequence or slot flags", after[4:7], before[4:7])
            session.check("OTP protocol recovers after raw framing fault", serial(session), expected)
