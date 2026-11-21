# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Persistent read-only grants survive a changed USB session and a power cycle."""
import pytest

import oracle
from oracle_lib import binding, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_binding import Identity
from test_oracle_lifetimes import Peer as LifetimePeer


class Peer(LifetimePeer):
    def reopen(self, operator):
        if self.defect:
            self.token = b"rotated persistent token".ljust(32, b"\x00")
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")

    def transfer(self, command, request, deadline, observe):
        if command == 0x42:
            body, status = Identity(17).identity(), None
        elif request[:1] == b"\x04":
            body = b"\x00" + codec.encode({1: ["FIDO_2_3"], 4: {"clientPin": True, "pinUvAuthToken": True, "credMgmt": True, "perCredMgmtRO": True}, 6: [1, 2]})
            status = 0
        else:
            return super().transfer(command, request, deadline, observe)
        observe("tx", request)
        observe("rx", body)
        return Reply(body, status=status)


@pytest.mark.parametrize("defect", [None, "persistent-key-is-volatile"])
def test_readonly_reconnect_through_dispatch(tmp_path, defect):
    trace = Trace(tmp_path / "reconnect", {})
    peer, card = Peer([0], defect), Identity(17)
    card.emulated = True
    session = Session(trace, hid=peer, card=card, profile="rsk", options=Options(exercise=True, pin="fixture-PIN", allow_effects=("reboot",)))
    binding.confirm(session)
    oracle.execute(session, ["fido-reconnect"])
    trace.finish()
    rows = trace.cases[1:]
    if defect is None:
        assert all(row["verdict"] == "pass" for row in rows), rows
    else:
        assert any(row["verdict"] == "fail" and "CTAP success" in row["reason"] for row in rows), rows
    assert card.controls == 2
