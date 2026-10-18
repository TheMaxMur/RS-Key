# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A panel peer shares its persistent retry counter with encrypted host PIN requests."""
import pytest

import oracle
from oracle_lib import binding, uv_block
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_uv_matrix import Peer as UVPeer


class Peer(UVPeer):
    soft, mismatches, choice = False, 0, None

    def client_pin(self, fields):
        if fields[2] == 7:
            return 0, {5: self.remaining, **({4: True} if self.soft else {})}
        if fields[2] in (6, 9) and self.remaining == 0:
            if fields[2] == 9:
                return 0x32, {}
            if self.defect != "permanent-block-bypass":
                return 0x3c, {}
        if fields[2] == 6:
            if self.soft:
                if self.defect == "blocked-entry-spends":
                    self.remaining -= 1
                return 0x3c, {}
            if self.choice == "submit exactly one WRONG PIN; do not retry inside the panel":
                self.failed_pin()
                self.mismatches += 1
                self.soft = self.mismatches == 3 or self.remaining == 0
                return 0x3c if self.soft else 0x3f, {}
        return super().client_pin(fields)

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 7:
            self.soft, self.mismatches = False, 0
        return super().transfer(command, wire, deadline, observe)


class Card:
    emulated = True

    def __init__(self, peer):
        self.peer = peer

    def control(self, action, deadline, observe):
        self.peer.soft, self.peer.mismatches = False, 0
        if self.peer.defect == "power-replenishes-budget":
            self.peer.remaining = 8
        return Reply(b"synthetic ATR")


@pytest.mark.parametrize("defect,needle", [(None, None), ("blocked-entry-spends", "blocked entry does not spend"),
    ("power-replenishes-budget", "power cycle preserves the remaining"), ("permanent-block-bypass", "permanent local block survives")])
def test_local_UV_blocking_and_cold_power_recovery(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    monkeypatch.setattr(binding, "check_pair", lambda *args: None)
    monkeypatch.setattr(uv_block, "snapshot", lambda *args: None)
    original_cue = uv_block.cue
    def operator(session, choice):
        peer.choice = choice
        original_cue(session, choice)
    monkeypatch.setattr(uv_block, "cue", operator)
    trace = Trace(tmp_path / "UV-block", {})
    session = Session(trace, hid=peer, card=Card(peer), profile="rsk", options=Options(exercise=True, touch=True, operator=True, pin="fixture-PIN", allow_effects=("pin_attempts", "pin_change", "applet_reset", "reboot")))
    peer.session = session
    oracle.execute(session, ["uv-block"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert peer.pin_value == "fixture-PIN" and peer.remaining == 8
