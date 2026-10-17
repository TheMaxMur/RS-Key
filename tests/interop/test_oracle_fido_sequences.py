# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Assertion cursor tests bind every continuation to the initiating signed hash."""
import pytest

import oracle
from oracle_lib import codec, fido_sequences
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_extensions import ExtensionPeer


class Peer(ExtensionPeer):
    def __init__(self, clock, defect):
        super().__init__(defect)
        self.clock, self.assertions, self.query, self.last = clock, [], None, 0

    def transfer(self, command, request, deadline, observe):
        operation = request[0]
        fields = codec.decode(request[1:]) if len(request) > 1 else {}
        if operation == 4 and self.defect != "getInfo-keeps-walk":
            self.assertions.clear()
        if operation == 2 and 3 not in fields:
            self.assertions = [key for key, row in self.records.items() if row["resident"] and row["rp"] == fields[1]]
            self.query = fields
        elif operation not in (8,):
            return super().transfer(command, request, deadline, observe)
        observe("tx", request)
        if operation == 8 and self.clock[0] - self.last > 30:
            self.assertions.clear()
        if not self.assertions:
            status, result = 0x30, {}
        else:
            total = len(self.assertions)
            identifier = self.assertions.pop(0)
            if self.defect == "duplicate-credential" and operation == 8:
                identifier = next(key for key, row in self.records.items() if row["rp"] == self.query[1])
            status, result = super().assertion({**self.query, 3: [{"id": identifier}]})
            if operation == 2:
                result[5] = total
            self.last = self.clock[0]
        encoded = bytes([status]) + (codec.encode(result) if status == 0 else b"")
        observe("rx", encoded)
        return Reply(encoded, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("getInfo-keeps-walk", "getInfo retires assertion walk"),
                                           ("duplicate-credential", "no duplicate credential")])
def test_discovery_cursor_dispatch(tmp_path, monkeypatch, defect, expected):
    clock = [0]
    peer = Peer(clock, defect)
    trace = Trace(tmp_path / "assertions", {"clock_fixture": "synthetic peer only"})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", timeout=32))
    monkeypatch.setattr(fido_sequences, "wait", lambda session, seconds: clock.__setitem__(0, clock[0] + seconds))
    oracle.execute(session, ["fido-sequences"])
    trace.finish()
    failed = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failed and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    else:
        assert any(expected in row["reason"] for row in failed), failed
    assert not any(row["resident"] for row in peer.records.values())
