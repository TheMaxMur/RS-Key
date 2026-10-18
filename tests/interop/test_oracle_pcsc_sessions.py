# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise PC/SC control dispatch without connecting a system reader."""
import pytest

import oracle
from oracle_lib.runner import Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from oracle_lib.transport import _pcsc_worker


def test_native_worker_encodes_transactions_and_dispositions(monkeypatch):
    from smartcard import scard
    from smartcard import System
    calls, output = [], []
    class Connection:
        hcard = 17
        def connect(self):
            calls.append("connect")
        def reconnect(self, disposition):
            calls.append(("reconnect", disposition))
        def getATR(self):
            calls.append("ATR")
            return [0x3B, 0]
        def disconnect(self):
            calls.append("disconnect")
    class Reader:
        def __str__(self):
            return "synthetic-reader"
        def createConnection(self):
            return Connection()
    requests = iter([{"control": "transaction", "begin": True},
                     *[{"control": "transaction", "begin": False, "disposition": name} for name in ("leave", "reset", "unpower")],
                     *[{"control": "reset", "disposition": name} for name in ("leave", "reset", "unpower")], None])
    class Pipe:
        def send(self, value):
            output.append(value)
        def recv(self):
            return next(requests)
        def close(self):
            pass
    monkeypatch.setattr(System, "readers", lambda: [Reader()])
    monkeypatch.setattr(scard, "SCardBeginTransaction", lambda handle: calls.append(("begin", handle)) or scard.SCARD_S_SUCCESS)
    monkeypatch.setattr(scard, "SCardEndTransaction", lambda handle, disposition: calls.append(("end", handle, disposition)) or scard.SCARD_S_SUCCESS)
    _pcsc_worker(Pipe(), "synthetic-reader")
    assert not [row for row in output if row[0] == "error"], output
    assert len([row for row in output if row[0] == "control_reply"]) == 7
    assert calls.count("ATR") == 4
    assert ("begin", 17) in calls
    for disposition in (scard.SCARD_LEAVE_CARD, scard.SCARD_RESET_CARD, scard.SCARD_UNPOWER_CARD):
        assert ("end", 17, disposition) in calls and ("reconnect", disposition) in calls


@pytest.mark.parametrize("mode", ["exclusive", "direct"])
def test_native_worker_passes_explicit_sharing_to_reader(monkeypatch, mode):
    from smartcard import scard, System
    calls = []
    class Connection:
        def connect(self, **fields):
            calls.append(fields)
        def getATR(self):
            return [0x3B, 0]
        def disconnect(self):
            pass
    class Reader:
        def __str__(self):
            return "reader"
        def createConnection(self):
            return Connection()
    class Pipe:
        def send(self, value):
            assert value[0] == "ready"
        def recv(self):
            return None
        def close(self):
            pass
    monkeypatch.setattr(System, "readers", lambda: [Reader()])
    _pcsc_worker(Pipe(), ("reader", mode))
    assert calls == [{"mode": scard.SCARD_SHARE_EXCLUSIVE if mode == "exclusive" else scard.SCARD_SHARE_DIRECT}]


@pytest.mark.parametrize("busy", [False, True])
def test_sharing_scenarios_recover_owner_after_driver_outcomes(tmp_path, busy):
    from oracle_lib.trace import Outcome
    class Card:
        layer, pipe = "pcsc_apdu", True
        active = False
        seen = []
        def transfer(self, request, deadline, observe):
            if isinstance(request, dict):
                if request["control"] == "transaction":
                    self.active = request["begin"]
                return Reply(b"")
            observe("tx", request)
            data = (b"\x05\x08\x00" if request[1] == 0xFD else b"") + b"\x90\x00"
            observe("rx", data)
            return Reply(data, status=0x9000)
        def probe_client(self, request, deadline, observe, sharing="shared"):
            self.seen.append((sharing, self.active))
            if busy:
                raise TransferError("driver sharing refusal", Outcome.HOST_REJECTED, code=0x8010000B)
            return self.transfer(request, deadline, observe)
    trace = Trace(tmp_path / "sharing", {})
    card = Card()
    oracle.execute(Session(trace, card=card), ["pcsc-sharing"])
    trace.finish()
    assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert len(card.seen) == 6 and not card.active


@pytest.mark.parametrize("busy", [False, True])
def test_second_client_and_owner_recovery_through_dispatch(tmp_path, busy):
    class Card:
        layer = "pcsc_apdu"
        pipe = True
        active = False
        dispositions = []
        def transfer(self, request, deadline, observe):
            if isinstance(request, dict):
                if request["control"] == "transaction":
                    self.active = request["begin"]
                self.dispositions.append(request)
                return Reply(b"\x3b\x00")
            observe("tx", request)
            body = b"\x05\x08\x00" if request[1] == 0xFD else b""
            observe("rx", body + b"\x90\x00")
            return Reply(body + b"\x90\x00", status=0x9000)
        def probe_client(self, request, deadline, observe):
            assert self.active
            if busy:
                raise TransferError("synthetic PC/SC transaction wait", Outcome.DEADLINE)
            return self.transfer(request, deadline, observe)
    trace = Trace(tmp_path / "pcsc", {})
    card = Card()
    session = Session(trace, card=card)
    oracle.execute(session, ["pcsc-sessions"])
    trace.finish()
    assert not card.active and not session.broken
    assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert all(row["observation_layer"] == "pcsc_control" for row in trace.exchanges if row["command"] in ("pcsc.transaction", "pcsc.reset"))
