# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Processing/UP/final-response cancellation runs through the real HID assembler."""
from collections import deque
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import mldsa

from oracle_lib import codec, hid_operations
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from oracle_lib.transport import Hid
from oracle_lib.transport_cases import reports
from test_oracle_registration_matrix import RegistrationPeer


class Reports:
    def __init__(self, defect=None):
        self.peer, self.queue, self.pending, self.defect = RegistrationPeer(), deque(), bytearray(), defect
        self.active, self.stage = False, None

    def write(self, value):
        frame = value[1:]
        cid = frame[:4]
        if frame[4] & 128:
            command, self.length = frame[4] & 127, int.from_bytes(frame[5:7], "big")
            if command == 0x11:
                if self.active and self.stage == 2:
                    self.queue.clear()
                    self.queue.extend(reports(cid, 0x10, b"\x2d"))
                elif self.defect == "late-CANCEL-reply" and not self.active:
                    self.queue.extend(reports(cid, 0x10, b"\x2d"))
                return len(value)
            self.command = command
            self.pending = bytearray(frame[7:7 + min(57, self.length)])
        else:
            self.pending.extend(frame[5:5 + min(59, self.length - len(self.pending))])
        if len(self.pending) == self.length:
            if self.command == 1:
                response = bytes(self.pending)
            elif self.pending[:1] == b"\x04":
                response = b"\x00" + codec.encode({4: {}, 10: [{"type": "public-key", "alg": -7}]})
            else:
                response = self.peer.transfer(self.command, bytes(self.pending), 0, lambda *args: None).data
                if self.pending[:1] == b"\x01":
                    self.active = True
                    self.queue.extend(reports(cid, 0x3b, b"\x01"))
                    self.queue.extend(reports(cid, 0x3b, b"\x02"))
                    if self.defect == "completed-race-loses-key":
                        for record in self.peer.records.values():
                            record["key"] = ec.generate_private_key(ec.SECP256R1())
            self.queue.extend(reports(cid, self.command, response))
        return len(value)

    def read(self, size, milliseconds):
        if not self.queue:
            return b""
        frame = self.queue.popleft()
        if frame[4] == 0xbb:
            self.stage = frame[7]
        elif frame[4] == 0x90:
            self.active = False
        return frame

    def close(self):
        pass


@pytest.mark.parametrize("defect,needle", [(None, None), ("completed-race-loses-key", "InvalidSignature"),
    ("late-CANCEL-reply", "applet_error', 45")])
def test_processing_cancel_and_completion_races_keep_a_usable_private_key(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(hid_operations, "ALGORITHMS", (-7,))
    trace = Trace(tmp_path / "processing", {})
    hid = Hid({}, trace.now, Reports(defect))
    hid.cid = b"\x01\x02\x03\x04"
    session = Session(trace, hid=hid, profile="rsk", options=Options(exercise=True, touch=True))
    hid_operations.processing(session)
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures, failures
        assert sum(row["verdict"] == "pass" for row in trace.cases) == 3


class QuantumPeer(RegistrationPeer):
    def make(self, fields):
        algorithm = fields[4][0]["alg"]
        private = {-48: mldsa.MLDSA44PrivateKey, -49: mldsa.MLDSA65PrivateKey, -50: mldsa.MLDSA87PrivateKey}[algorithm].generate()
        self.serial += 1
        identifier = b"quantum-owned-" + self.serial.to_bytes(4, "big")
        self.records[identifier] = {"key": private, "rp": fields[2]["id"], "alg": algorithm}
        cose = {1: 7, 3: algorithm, -1: private.public_key().public_bytes_raw()}
        signed = hashlib.sha256(fields[2]["id"].encode()).digest() + b"\x41" + bytes(4) + bytes(16)
        signed += len(identifier).to_bytes(2, "big") + identifier + codec.encode(cose)
        return 0, {1: "none", 2: signed, 3: {}}

    def assertion(self, fields):
        identifier = fields[3][0]["id"]
        record = self.records[identifier]
        assert fields[1] == record["rp"]
        signed = hashlib.sha256(fields[1].encode()).digest() + b"\x01" + bytes(4)
        return 0, {1: {"type": "public-key", "id": identifier}, 2: signed, 3: record["key"].sign(signed + fields[2])}


def test_unadvertised_profiled_PQC_processing_races_verify_real_MLDSA(tmp_path, monkeypatch):
    monkeypatch.setattr(hid_operations, "ALGORITHMS", (-48, -49, -50))
    trace = Trace(tmp_path / "PQC-processing", {})
    backend = Reports()
    backend.peer = QuantumPeer()
    hid = Hid({}, trace.now, backend)
    hid.cid = b"\x01\x02\x03\x04"
    session = Session(trace, hid=hid, profile="rsk", options=Options(exercise=True, touch=True))
    hid_operations.processing(session)
    trace.finish()
    assert len(trace.cases) == 9 and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases]
