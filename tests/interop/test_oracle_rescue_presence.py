# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rescue refusal and shared-lock faults are detected by real device-key signatures."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import rescue_presence
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_phy_records import Card as PhyCard
from test_oracle_management_state import Peer as Management


class Card(PhyCard):
    def __init__(self, defect):
        super().__init__()
        self.fault, self.selected, self.confirmed = defect, "rescue", True
        self.management = Management(False, None)

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        status = None
        if ins == 0xa4:
            self.selected = next(name for name, aid in AIDS.items() if data == aid)
        elif self.selected == "management":
            self.management.confirmed = self.confirmed
            return self.management.reply("card", "read" if ins == 0x1d else "write", b"" if ins == 0x1d else data[1:1 + data[0]], observe)
        elif ins == 0x1c and p1 == 1:
            if len(data) < 2:
                status = 0x6700
            elif self.management.lock is not None and self.fault != "locked-PHY-bypass":
                status = 0x6986
            elif not self.confirmed and self.fault != "confirmation-ignored":
                status = 0x6985
        elif ins == 0x10 and p1 in (1, 3):
            if p1 == 1 and len(data) != 32 or p1 == 3 and not data:
                status = 0x6700
            elif not self.confirmed and self.fault != "confirmation-ignored":
                status = 0x6985
        elif ins == 0x1f and p1 == 1:
            status = 0x6700 if data else 0x6985
        if status is None:
            return super().transfer(wire, deadline, observe)
        if status == 0x6700 and not self.confirmed and self.fault == "grammar-after-consent":
            status = 0x6985
        if status == 0x6985 and self.fault == "refusal-replaces-key":
            self.key = ec.derive_private_key(43, ec.SECP256K1())
        output = status.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,needle", [(None, None), ("confirmation-ignored", "rescue response cause"),
    ("grammar-after-consent", "rescue response cause"), ("refusal-replaces-key", "InvalidSignature"),
    ("locked-PHY-bypass", "rescue response cause")])
def test_rescue_consent_and_validation_order_preserve_the_actual_private_key(tmp_path, monkeypatch, defect, needle):
    card = Card(defect)
    original = dict(card.fields)
    trace = Trace(tmp_path / "rescue-presence", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True, timeout=131,
        features=("display",), allow_effects=("config_change", "replace_identity")))
    original_cue = rescue_presence.cue
    def operator(session, mode):
        card.confirmed = mode == "accept"
        original_cue(session, mode)
    monkeypatch.setattr(rescue_presence, "cue", operator)
    oracle.execute(session, ["rescue-presence"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert card.fields == original and card.management.lock is None
