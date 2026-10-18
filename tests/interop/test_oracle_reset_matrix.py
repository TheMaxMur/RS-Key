# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reset refusal is falsified with retained keys and grants, including late display consent."""
import pytest

import oracle
from oracle_lib import binding, reset_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as TokenPeer


class Peer(TokenPeer):
    on_keepalive = on_report = None
    cid = b"\x01\x02\x03\x04"

    def send_only(self, frames, deadline, observe):
        for frame in frames:
            assert frame[4] == 0x91
            observe("tx", frame)
        return Reply(b"", "no_response_expected")

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 7:
            mode = self.session.current.parameters["reset_action"]
            if mode == "outside-window" and "display" in self.session.options.features:
                return super().transfer(command, wire, deadline, observe)
            status = {"outside-window": 0x30, "decline": 0x27, "cancel": 0x2d, "timeout": 0x2f}[mode]
            if mode == "cancel":
                self.on_keepalive(2, self.session.trace.now())
            if self.defect == "refused-reset-deletes-key":
                self.records.clear()
            if self.defect == "refused-reset-revokes-grant":
                self.token, self.permissions = bytes(32), 0
            observe("tx", wire)
            observe("rx", bytes([status]))
            return Reply(bytes([status]), "applet_error", status)
        return super().transfer(command, wire, deadline, observe)


class Card:
    emulated = True

    def control(self, action, deadline, observe):
        return Reply(b"offline ATR")


@pytest.mark.parametrize("display", [False, True])
@pytest.mark.parametrize("defect,needle", [(None, None), ("refused-reset-deletes-key", "scoped assertion"),
    ("refused-reset-revokes-grant", "refused reset preserves ordinary grant")])
def test_refused_reset_preserves_private_and_authorized_state(tmp_path, monkeypatch, display, defect, needle):
    monkeypatch.setattr(binding, "check_pair", lambda session: None)
    monkeypatch.setattr(reset_matrix, "snapshot", lambda *args: None)
    monkeypatch.setattr(reset_matrix, "wait", lambda *args: None)
    trace = Trace(tmp_path / "reset-refusals", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, card=Card(), profile="rsk", options=Options(exercise=True, touch=True, operator=True, pin="fixture-PIN", timeout=131,
        features=("display",) if display else (), allow_effects=("applet_reset", "pin_change", "reboot")))
    peer.session = session
    oracle.execute(session, ["reset-matrix"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        if defect == "refused-reset-deletes-key":
            needle = "refused reset preserves ordinary grant"
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" or not display and row["scenario_id"].endswith("decline") for row in trace.cases), trace.cases
        assert peer.pin_value == "fixture-PIN"
