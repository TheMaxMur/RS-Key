# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw OTP frames run through the capture dispatcher and real worker branch."""
import sys
from types import SimpleNamespace

import pytest

import oracle
from oracle_lib import otp_hid
from yubikit.core.otp import calculate_crc
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


class Features:
    layer = "otp_hid_feature"
    broken = False

    def __init__(self, defect=None):
        self.buffer, self.output, self.defect = bytearray(70), [], defect
        self.serial = b"\x00\x00\x00\x17"
        self.status = b"\x00\x05\x08\x00\x01\x00\x00\x00"

    def transfer(self, slot, data, expected_len, deadline, observe):
        assert slot == 0x10
        observe("tx", data)
        observe("rx", self.serial)
        return Reply(self.serial)

    def raw_feature(self, packet, deadline, observe):
        if packet is None:
            output = self.output.pop(0) if self.output else self.status
            observe("rx", output)
            return Reply(output)
        observe("tx", packet)
        marker = packet[7]
        if marker == 0xFF or marker & 0x80 and marker & 31 > 9:
            self.buffer = bytearray(70)
            if self.defect != "abort-keeps-output":
                self.output = []
        elif marker & 0x80:
            sequence = marker & 31
            if sequence == 0:
                self.buffer = bytearray(70)
            self.buffer[sequence * 7:sequence * 7 + 7] = packet[:7]
            if sequence == 9:
                correct = calculate_crc(self.buffer[:64]) == int.from_bytes(self.buffer[65:67], "little")
                if correct or self.defect == "bad-CRC-runs-command":
                    payload = self.serial + ((~calculate_crc(self.serial)) & 65535).to_bytes(2, "little")
                    self.output = [payload.ljust(7, b"\x00") + b"\x40", bytes(7) + b"\x40"]
                self.buffer = bytearray(70)
        return Reply(b"", "no_response_expected")


@pytest.mark.parametrize("defect,expected", [(None, None), ("bad-CRC-runs-command", "produces no data"),
                                           ("abort-keeps-output", "abort retires pending OTP output")])
def test_raw_feature_matrix_has_report_timings_and_fault_controls(tmp_path, defect, expected):
    trace = Trace(tmp_path / "OTP-frames", {})
    peer = Features(defect)
    session = Session(trace, otp_hid=peer, profile="rsk", options=Options(exercise=True))
    oracle.execute(session, ["otp-transport"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    writes = [row for row in trace.exchanges if row["command"] == "otp.SET_REPORT"]
    reads = [row for row in trace.exchanges if row["command"] == "otp.GET_REPORT"]
    assert writes and reads and all(row["timing"]["response_latency_ns"] is None for row in writes)
    assert all(row["timing"]["response_latency_ns"] is not None for row in reads)


def test_worker_raw_feature_branch_calls_endpoint_without_sdk_framing(monkeypatch):
    writes, output = [], []
    class Endpoint:
        def open_path(self, path):
            assert path == b"\x01"
        def send_feature_report(self, report):
            writes.append(report)
            return len(report)
        def get_feature_report(self, report_id, size):
            return bytes(9)
        def close(self):
            pass
    messages = iter([{"raw_feature": bytes(7) + b"\x8f"}, {"raw_feature": None}, None])
    class Pipe:
        def recv(self):
            return next(messages)
        def send(self, value):
            output.append(value)
        def close(self):
            pass
    monkeypatch.setitem(sys.modules, "hid", SimpleNamespace(device=Endpoint))
    monkeypatch.setattr(otp_hid.sys, "platform", "linux")
    otp_hid._otp_worker(Pipe(), "01")
    assert writes == [bytes(8) + b"\x8f"]
    replies = [row for row in output if row[0] == "raw_reply"]
    assert len(replies) == 2 and replies[0][2] is False and replies[1][1:3] == (bytes(8), True)
    assert not [row for row in output if row[0] == "error"]
