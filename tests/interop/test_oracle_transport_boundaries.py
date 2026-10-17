# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""An offline report assembler exposes timeout and foreign-channel defects."""
from collections import deque

import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from oracle_lib.transport import Hid
from oracle_lib.transport_cases import reports


class Assembler:
    def __init__(self, defect=None):
        self.now, self.queue, self.pending = 0, deque(), None
        self.defect, self.next_cid = defect, 10

    def write(self, data):
        frame = data[1:]
        cid, kind = frame[:4], frame[4]
        if self.pending and self.now - self.pending[3] >= 500000000 and self.defect != "no-assembly-deadline":
            self.queue.extend(reports(self.pending[0], 0x3F, b"\x05"))
            self.pending = None
        if kind & 128:
            length, body = int.from_bytes(frame[5:7], "big"), frame[7:]
            if kind == 0x86:
                self.next_cid += 1
                target = self.next_cid.to_bytes(4, "big") if cid == b"\xff" * 4 else cid
                self.queue.extend(reports(cid, 6, body[:8] + target + bytes([2, 5, 8, 0, 5])))
            elif length <= 57:
                self.queue.extend(reports(cid, kind & 127, body[:length]))
                if self.defect == "post-completion-keepalive" and body[:length] == b"idle-witness":
                    self.queue.extend(reports(cid, 0x3B, b"\x01"))
            else:
                self.pending = [cid, length, bytearray(body), self.now]
        elif self.pending:
            if cid != self.pending[0]:
                self.queue.extend(reports(cid, 0x3F, b"\x06"))
                if self.defect == "foreign-corrupts-owner":
                    self.pending[2][0] ^= 1
            else:
                self.pending[2].extend(frame[5:])
                if len(self.pending[2]) >= self.pending[1]:
                    self.queue.extend(reports(cid, 1, bytes(self.pending[2][:self.pending[1]])))
                    self.pending = None
        return len(data)

    def read(self, size, milliseconds):
        if self.queue:
            return self.queue.popleft()
        self.now += milliseconds * 1000000
        return b""


@pytest.mark.parametrize("defect,expected", [(None, None), ("no-assembly-deadline", "after assembly deadline times out"),
                                           ("foreign-corrupts-owner", "does not corrupt owning CID"),
                                           ("post-completion-keepalive", "no KEEPALIVE or final reply after request completion")])
def test_actual_report_writer_runs_scheduled_and_foreign_cases(tmp_path, monkeypatch, defect, expected):
    from oracle_lib import transport
    peer = Assembler(defect)
    monkeypatch.setattr(transport.time, "sleep", lambda seconds: setattr(peer, "now", peer.now + max(1, int(seconds * 1e9))))
    trace = Trace(tmp_path / "boundaries", {}, clock=lambda: peer.now)
    hid = Hid({}, trace.now, peer)
    hid.cid = b"\x01\x02\x03\x04"
    session = Session(trace, hid=hid, profile="rsk", options=Options(exercise=True))
    oracle.execute(session, ["transport-boundaries"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert peer.now >= 1550000000


def test_scheduled_report_invalid_delays_are_host_rejected_before_write():
    from oracle_lib.trace import TransferError
    peer = Assembler()
    hid = Hid({}, lambda: peer.now, peer)
    for delays in ([], [-1], [float("nan")], [float("inf")]):
        with pytest.raises(TransferError, match="report delays"):
            hid.transfer_reports(1, reports(hid.cid, 1, b""), 1000000000, lambda *a, **kw: None, delays=delays)
    assert not peer.queue
