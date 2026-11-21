# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Selection outcomes are checked against independent retry, grant and key state."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from oracle_lib.transport_cases import reports
from test_oracle_token_matrix import Peer as TokenPeer


class Peer(TokenPeer):
    on_report = on_keepalive = None
    cid = b"\x01\x02\x03\x04"
    cancel_sent = False

    def send_only(self, frames, deadline, observe):
        for frame in frames:
            observe("tx", frame)
            if frame[4] == 0x91:
                self.cancel_sent = True
            else:
                assert frame[4] == 0x90 and frame[7] == 11
                code = 1 if self.defect == "wrong-competition-status" else 6
                self.on_report(reports(frame[:4], 0x3f, bytes([code]))[0], self.session.trace.now())
        return Reply(b"", "no_response_expected")

    def transfer(self, command, wire, deadline, observe):
        if command == 6:
            return Reply(wire + b"\x10\x20\x30\x40" + bytes([2, 5, 8, 0, 5]))
        if command == 1:
            return Reply(wire)
        if wire[:1] == b"\x0b":
            self.cancel_sent = False
            mode = self.session.current.parameters["selection_action"]
            if mode in ("cancel", "competing-selection"):
                for _ in range(3):
                    self.on_keepalive(2, self.session.trace.now())
                assert self.cancel_sent
                status = 0x2d
            else:
                status = {"confirm": 0, "decline": 0x27, "no-touch": 0x2f}[mode]
            if self.defect == "selection-spends-PIN":
                self.remaining -= 1
            if self.defect == "selection-deletes-key":
                self.records.clear()
            observe("tx", wire)
            observe("rx", bytes([status]))
            return Reply(bytes([status]), "success" if not status else "applet_error", status)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("selection-spends-PIN", "selection never consumes"),
    ("selection-deletes-key", "CTAP success"), ("wrong-competition-status", "competing selection receives CHANNEL_BUSY")])
def test_selection_presence_and_competing_owner_state(tmp_path, defect, needle):
    trace = Trace(tmp_path / "selection", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, features=("display",), pin="fixture-PIN", timeout=131))
    peer.session = session
    oracle.execute(session, ["selection-matrix"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
