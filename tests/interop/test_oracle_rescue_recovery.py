# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Prepared recovery layouts enforce selection, command and administration policy."""
import pytest

import oracle
from oracle_lib import rescue_recovery
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts


class Card:
    layer = "offline_recovery_card"

    def __init__(self, layout, defect):
        self.layout, self.defect, self.confirmed, self.active = layout, defect, False, False
        self.calls = []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        self.calls.append((ins, p1, p2, data))
        status, body = 0x9000, b""
        if ins == 0xa4:
            if data != AIDS["rescue"] and self.defect != "ordinary-app-reachable":
                status = 0x6a82
            else:
                body = bytes(12)
        elif ins == 0x20:
            if p1 not in (0, 1) or p2:
                status = 0x6a86
            elif data != (b"INITV2" if p1 == 0 else b"IMPORTV2"):
                status = 0x6a80
            elif not self.confirmed:
                status = 0x6985
            elif self.defect == "occupied-setup-succeeds":
                self.active = True
            else:
                status = 0x6581 if self.layout == "incompatible" else 0x6985
        elif ins == 0x1f:
            status = 0x6700 if data else 0x6a86
        elif ins == 0x1e and p1 in (3, 4, 6, 7, 8):
            if p1 == 8:
                body = bytes([2, int(self.active)])
            elif p1 == 4:
                status = 0x6581 if self.defect == "RTC-not-whitelisted" else 0x6985
            elif p1 == 6:
                status = 0x6400
            else:
                body = bytes(3 if p1 == 3 else 2)
        else:
            status = 0x9000 if self.defect == "forbidden-command-served" else 0x6581
        output = body + status.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("layout", rescue_recovery.LAYOUTS)
@pytest.mark.parametrize("defect,needle", [(None, None), ("ordinary-app-reachable", "only rescue remains selectable"),
    ("forbidden-command-served", "rescue response cause"), ("RTC-not-whitelisted", "recovery permits RTC"),
    ("occupied-setup-succeeds", "distinct cause")])
def test_full_recovery_whitelist_and_prepared_negative_layouts(tmp_path, monkeypatch, layout, defect, needle):
    if defect == "occupied-setup-succeeds" and layout not in ("occupied", "incompatible"):
        return
    card = Card(layout, defect)
    trace = Trace(tmp_path / "rescue-recovery", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True, timeout=131,
        features=("display",), recovery_layout=layout, allow_effects=("storage_setup",)))
    monkeypatch.setattr(rescue_recovery, "cue", lambda session, mode: setattr(card, "confirmed", mode == "accept"))
    oracle.execute(session, ["rescue-recovery"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
        if defect == "occupied-setup-succeeds":
            assert session.broken
    else:
        assert not failures, failures
        assert any(row["verdict"] == "pass" for row in trace.cases)
        assert all(row["verdict"] == "pass" or row["applicability"] == "blocked_by_precondition" for row in trace.cases), trace.cases
        assert not card.active
        assert all(data == b"invalid" and p1 == 0 for ins, p1, p2, data in card.calls if ins == 0x1b)


def test_default_catalog_runs_recovery_refusals_before_consuming_a_prepared_fixture():
    assert oracle.SUITES.index("rescue-recovery") < oracle.SUITES.index("rescue")
