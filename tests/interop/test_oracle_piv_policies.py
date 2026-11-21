# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Policy state is independent from the SDK and signs with retained real keys."""
import pytest

import oracle
from oracle_lib import codec, piv_policies
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_piv_matrix import KeyCard


class Peer(KeyCard):
    emulated = True
    fresh, presence = False, True

    def control(self, action, deadline, observe):
        self.has_pin, self.has_management, self.fresh = False, False, False
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xfe and dict(codec.parse_tlv(data)).get(0xaa) in (b"\x04", b"\x05"):
            observe("tx", wire)
            observe("rx", b"\x6a\x80")
            return Reply(b"\x6a\x80", "applet_error", 0x6a80)
        if ins == 0xA4 and not (self.selected == "piv" and data and AIDS["piv"].startswith(data)):
            self.fresh = False
        if ins == 0x87 and p2 in self.keys:
            pin, touch = self.policies[p2]
            allowed = pin == 1 or self.has_pin and (pin != 3 or self.fresh or self.defect == "ALWAYS-reusable")
            if not allowed or touch != 1 and not self.presence and self.defect != "touch-ignored":
                if allowed and self.defect == "declined-touch-spends-PIN":
                    self.fresh = False
                observe("tx", wire)
                observe("rx", b"\x69\x82")
                return Reply(b"\x69\x82", "applet_error", 0x6982)
            if p1 == 0x11 and pin != 1:
                self.fresh = False
        result = super().transfer(wire, deadline, observe)
        if ins == 0x20 and data and result.status == 0x9000:
            self.fresh = True
        if ins == 0xFE and result.status == 0x9000:
            fields = dict(codec.parse_tlv(data))
            self.policies[p2] = (fields.get(0xaa, bytes([3 if p2 == 0x9c else 1 if p2 == 0x9e else 2]))[0], fields.get(0xab, b"\x01")[0])
        return result


@pytest.mark.parametrize("defect,interruption", [(None, None), ("ALWAYS-reusable", "repeat"),
    ("touch-ignored", "decline"), ("declined-touch-spends-PIN", "decline")])
def test_PIV_policy_product_with_touch_refusals_and_freshness(tmp_path, monkeypatch, defect, interruption):
    monkeypatch.setattr(piv_policies, "PIV_SLOTS", (0x82, 0x9c, 0x9e))
    monkeypatch.setattr(piv_policies, "wait", lambda *args: None)
    trace = Trace(tmp_path / "PIV-policies", {})
    peer = Peer(defect)
    original_cue = piv_policies.cue
    def operator(session, action):
        peer.presence = action == "accept"
        original_cue(session, action)
    monkeypatch.setattr(piv_policies, "cue", operator)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, piv_pin="123456", management_key=DEFAULT_KEY, timeout=131, allow_effects=("reboot",)))
    oracle.execute(session, ["piv-policies"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any(row["parameters"]["interruption"] == interruption and "PIV policy controls the private operation" in row["reason"] for row in failures), [(row["scenario_id"], row["reason"]) for row in failures]
    else:
        assert not failures, [(row["scenario_id"], row["reason"]) for row in failures]
        assert all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_mode" for row in trace.cases), trace.cases
        assert not peer.keys
