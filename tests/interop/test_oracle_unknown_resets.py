# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unknown lifecycle writes resolve active/terminated/blocked/factory states first."""
import pytest

import oracle
from oracle_lib import binding, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_cross_reset import Card as Applets, Hid
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_matrix import sdk_type
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Card(Applets):
    def __init__(self, hid, commit, fault):
        super().__init__(hid, fault)
        self.commit, self.fault, self.losses = commit, fault, []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0x10 and self.applet == "fido":
            reply = self.hid.transfer(0x10, body, deadline, lambda *_: None)
            output = reply.data + b"\x90\x00"
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0x9000)
        return super().transfer(wire, deadline, observe)

    def drop_response(self, wire, deadline, observe):
        self.losses.append(wire)
        observe("tx", wire)
        if self.commit:
            old_piv = self.piv.keys.copy()
            old_policies = self.piv.policies.copy()
            result = self.transfer(wire, deadline, lambda *_: None)
            assert result.status == 0x9000
            if self.fault == "partial-PIV-reset" and self.applet == "piv" and wire[1] == 0xfb:
                self.piv.keys = old_piv
                self.piv.policies = old_policies
        raise TransferError("offline lifecycle answer abandoned", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit,fault,needle", [(False, None, None), (True, None, None),
    (True, "partial-PIV-reset", "complete blocked old state or complete factory deletion"),
    (True, "neighbor-key-lost", "ApduError"),
    (True, "reset-retains-RO", "cannot revive the old persistent grant")])
def test_lost_reset_terminate_activate_states_and_populated_neighbors(tmp_path, monkeypatch, commit, fault, needle):
    from yubikit import openpgp
    hid = Hid(fault)
    card = Card(hid, commit, fault)
    trace = Trace(tmp_path / "unknown-lifecycles", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", piv_puk="12345678", management_key=DEFAULT_KEY,
        openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("session_recovery", "config_change", "applet_reset", "pin_change", "pin_attempts", "reboot")))
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    oracle.execute(session, ["unknown-resets"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
        assert session.broken
    else:
        assert len(trace.cases) == 5 and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert len(card.losses) == 5 and not card.piv.keys and not card.pgp.keys and not card.oath.records
        assert card.otp_key is None and card.management.lock is None and hid.pin_value == "fixture-PIN"
