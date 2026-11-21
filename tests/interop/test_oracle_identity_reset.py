# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Actual applet reset peers must retain a separately provisioned signing identity."""
import pytest

import oracle
from oracle_lib import binding
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_cross_reset import Card, DEFAULT_KEY
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_matrix import sdk_type
from test_oracle_seed_lifetimes import Peer


@pytest.mark.parametrize("target", [None, "piv", "openpgp", "oath", "fido"])
def test_batch_identity_private_key_survives_each_actual_applet_reset(tmp_path, monkeypatch, target):
    from yubikit import openpgp
    hid = Peer("reset-deletes-batch-identity" if target == "fido" else None)
    class ResetCard(Card):
        def control(self, action, deadline, observe):
            hid.control(action, deadline, observe)
            return super().control(action, deadline, observe)
        def transfer(self, wire, deadline, observe):
            ins, p1, p2, data = apdu_parts(wire)
            result = super().transfer(wire, deadline, observe)
            if result.protocol == "success" and target == self.applet and ins == {"piv": 0xfb, "openpgp": 0x44, "oath": 4}.get(target):
                hid.org = hid.chain = None
            return result
    card = ResetCard(hid, None)
    trace = Trace(tmp_path / "identity-reset", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", piv_puk="12345678", management_key=DEFAULT_KEY,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("replace_identity", "applet_reset", "pin_change", "pin_attempts", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    monkeypatch.setattr(binding, "check_pair", lambda s: s.values.update(same_instance_confirmed=True))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["identity-reset"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if target:
        assert any(name == "rsk.identity.reset." + target + ".private-witness" and "packed-chain commitment" in reason for name, reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert sum(row["scenario_id"].endswith(".private-witness") for row in trace.cases) == 4
        assert hid.org is None
