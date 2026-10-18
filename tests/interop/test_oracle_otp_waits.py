# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw reports distinguish partial frames from valid superseding commands."""
import hmac

import pytest

import oracle
from oracle_lib import otp_waits
from oracle_lib.otp import crc16
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_otp_commands import Features as CommandFeatures, Peer


class Features(CommandFeatures):
    def __init__(self, peer):
        super().__init__(peer)
        self.pending, self.output, self.buffer = None, [], bytearray(70)

    def transfer(self, *args):
        self.pending, self.output = None, []
        return super().transfer(*args)

    def status_report(self):
        return b"\x00" + self.peer.status() + b"\x00"

    def stream(self, data):
        data += (~crc16(data) & 65535).to_bytes(2, "little")
        self.output = [data[offset:offset + 7].ljust(7, b"\x00") + bytes([0x40 | index]) for index, offset in enumerate(range(0, len(data), 7))]
        self.output.append(bytes(7) + b"\x40")

    def raw_feature(self, report, deadline, observe):
        if report is None:
            value = self.output.pop(0) if self.output else bytes(7) + b"\x20" if self.pending else self.status_report()
            observe("rx", value)
            return Reply(value)
        observe("tx", report)
        marker = report[-1]
        if marker == 255 or marker & 128 and marker & 31 > 9:
            if self.pending and self.peer.defect == "abort-emits-old-HMAC":
                slot, challenge = self.pending
                config = self.peer.slots[slot]
                self.stream(hmac.digest(config[22:38] + config[16:22], challenge, "sha1"))
            else:
                self.output = []
            self.pending, self.buffer = None, bytearray(70)
        elif marker & 128:
            sequence = marker & 31
            if sequence == 0:
                self.buffer = bytearray(70)
            self.buffer[sequence * 7:sequence * 7 + 7] = report[:7]
            if sequence == 9:
                correct = crc16(self.buffer[:64]) == int.from_bytes(self.buffer[65:67], "little")
                if correct or self.peer.defect == "bad-CRC-supersedes-wait":
                    command, payload = self.buffer[64], bytes(self.buffer[:64])
                    if command in (0x30, 0x38):
                        self.pending = (1 if command == 0x30 else 2, payload)
                    elif self.peer.defect != "new-command-keeps-old-wait":
                        self.pending = None
                        sw, output = self.peer.execute(command, 0, payload)
                        if sw == 0x9000 and output:
                            self.stream(output)
            elif self.pending and self.peer.defect == "partial-frame-cancels-wait":
                self.pending = None
        return Reply(b"", "no_response_expected")


@pytest.mark.parametrize("defect,needle", [(None, None), ("abort-emits-old-HMAC", "owner abort returns idle"),
    ("bad-CRC-supersedes-wait", "cannot cancel OTP presence"), ("partial-frame-cancels-wait", "cannot cancel OTP presence"),
    ("new-command-keeps-old-wait", "replacement command never completed")])
def test_raw_feature_presence_abort_and_command_supersession(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-raw-waits", {})
    session = Session(trace, otp_hid=Features(peer), profile="rsk", options=Options(exercise=True, touch=True, operator=True))
    monkeypatch.setattr(otp_waits, "cue", lambda session, action: setattr(peer, "presence", action == "confirm"))
    monkeypatch.setattr(otp_waits, "wait", lambda session, seconds: None)
    oracle.execute(session, ["otp-waits"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.slots
