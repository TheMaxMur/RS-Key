# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Refused OATH presence cannot compute, change a moving factor or install a PIN."""
import pytest

import oracle
from oracle_lib import oath_presence
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_pin_matrix import Peer as PinPeer
from test_oracle_oath_semantics import fields


class Peer(PinPeer):
    present = True

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        gated = ins == 0xb4 and self.code is None
        record = None
        if ins in (0xa2, 0xb1):
            name = fields(body)[0x71]
            record = self.records[name]
            gated = bool(record["flags"] & 2)
        if gated and not self.present and self.defect != "ignored-presence":
            if record is not None and record["hotp"] and self.defect == "denied-touch-spends-HOTP":
                record["counter"] += 1
            if record is not None and record["flags"] & 1 and self.defect == "denied-touch-raises-mark":
                record["mark"] = 1
            observe("tx", wire)
            observe("rx", b"\x69\x82")
            return Reply(b"\x69\x82", "applet_error", 0x6982)
        return super().transfer(wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("ignored-presence", "CALCULATE requires the requested confirmed"),
    ("denied-touch-spends-HOTP", "OATH response matches independent HMAC"),
    ("denied-touch-raises-mark", "APDU success")])
def test_OATH_touch_outcomes_preserve_counter_mark_and_PIN_install_state(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    original_cue = oath_presence.cue
    def operator(session, mode):
        peer.present = mode == "confirm"
        original_cue(session, mode)
    monkeypatch.setattr(oath_presence, "cue", operator)
    trace = Trace(tmp_path / "OATH-presence", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, features=("display",), timeout=131,
        allow_effects=("applet_reset", "pin_change")))
    oracle.execute(session, ["oath-presence"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason and (defect != "denied-touch-raises-mark" or "increasing-TOTP" in name) for name, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert not peer.records and peer.pin is None
