# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""U2F presence refusal runs through raw HID with real attestation and counter witnesses."""
from collections import deque

import pytest

from oracle_lib import u2f_semantics
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from oracle_lib.transport import Hid
from oracle_lib.transport_cases import reports
from test_oracle_u2f_semantics import Peer


class Reports:
    def __init__(self, defect=None):
        self.peer, self.queue, self.defect = Peer(), deque(), defect
        self.active, self.current = False, None

    def write(self, report):
        frame = report[1:]
        cid = frame[:4]
        if self.current is not self.session.current:
            self.current, self.registrations, self.authentications = self.session.current, 0, 0
        if frame[4] & 128:
            command, size = frame[4] & 127, int.from_bytes(frame[5:7], "big")
            if command == 6:
                self.queue.extend(reports(cid, command, frame[7:15] + b"\x10\x20\x30\x40" + bytes([2, 5, 8, 0, 5])))
                return len(report)
            if command == 0x11:
                if self.active and (cid == self.owner or self.defect == "foreign-cancel-bypass"):
                    self.queue.clear()
                    self.queue.extend(reports(self.owner, 3, b"\x69\x85"))
                return len(report)
            assert command == 3
            self.length = size
            self.pending = bytearray(frame[7:7 + min(size, 57)])
        else:
            self.pending.extend(frame[5:5 + min(59, self.length - len(self.pending))])
        if len(self.pending) == self.length:
            wire, refused = bytes(self.pending), False
            if wire[1] == 1:
                self.registrations += 1
                refused = self.current.parameters["u2f_operation"] == 1 and self.registrations == 2
            elif wire[1] == 2 and wire[2] == 3:
                self.authentications += 1
                refused = self.current.parameters["u2f_operation"] == 2 and self.authentications == 2
            if refused:
                self.active, self.owner = True, cid
                if self.defect == "refusal-advances-counter":
                    self.peer.u2f_counter += 1
                self.queue.extend(reports(cid, 0x3b, b"\x02"))
                self.queue.extend(reports(cid, 0x3b, b"\x02"))
                response = b"\x69\x85"
            else:
                response = self.peer.u2f(wire, lambda *args: None).data
            self.queue.extend(reports(cid, 3, response))
        return len(report)

    def read(self, size, milliseconds):
        if not self.queue:
            return b""
        frame = self.queue.popleft()
        if frame[4] == 0x83:
            self.active = False
        return frame

    def close(self):
        pass


@pytest.mark.parametrize("defect,needle", [(None, None), ("foreign-cancel-bypass", "foreign CANCEL cannot finish"),
    ("refusal-advances-counter", "presence refusal leaves key and counter intact")])
def test_U2F_REGISTER_AUTH_cancellation_and_no_touch_preserve_private_state(tmp_path, defect, needle):
    trace = Trace(tmp_path / "U2F-presence", {})
    backend = Reports(defect)
    hid = Hid({}, trace.now, backend)
    hid.cid = b"\x01\x02\x03\x04"
    session = Session(trace, hid=hid, profile="rsk", options=Options(exercise=True, touch=True, operator=True, timeout=131))
    backend.session = session
    u2f_semantics.presence(session)
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
