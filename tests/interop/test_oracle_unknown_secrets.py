# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Lost secret changes are recovered by bounded comparisons, never blind retries."""
import pytest

import oracle
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_card_pin_matrix import PinCard
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import Peer as Pgp, sdk_with_errors
from test_oracle_oath_pin_matrix import Peer as Oath
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Card:
    layer = "pcsc_apdu"

    def __init__(self, commit, defect):
        self.commit, self.defect, self.applet = commit, defect, None
        self.piv, self.openpgp, self.oath, self.losses = PinCard(), Pgp(), Oath(), []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4 and p1 == 4:
            self.applet = next(name for name, aid in AIDS.items() if aid.startswith(body) or body.startswith(aid))
        return getattr(self, self.applet).transfer(wire, deadline, observe)

    def control(self, action, deadline, observe):
        self.piv.has_pin = self.piv.has_management = False
        self.openpgp.grants.clear()
        self.oath.pin_verified, self.oath.validated = False, self.oath.code is None
        return Reply(b"offline ATR")

    def drop_response(self, wire, deadline, observe):
        self.losses.append(wire)
        observe("tx", wire)
        if self.commit:
            reply = self.transfer(wire, deadline, lambda *_: None)
            assert reply.status == 0x9000
            if self.defect == "unknown-PIV-verifier" and self.applet == "piv":
                self.piv.pin = b"corrupt!"
            if self.defect == "unknown-OATH-verifier" and self.applet == "oath":
                self.oath.pin = b"corrupt!"
            if self.defect == "PGP-loses-key" and self.applet == "openpgp":
                self.openpgp.keys.clear()
        raise TransferError("offline secret write answer abandoned", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit,defect,needle", [(False, None, None), (True, None, None),
    (True, "unknown-PIV-verifier", "complete known old or new verifier"),
    (True, "unknown-OATH-verifier", "complete known old or new verifier"),
    (True, "PGP-loses-key", "ApduError")])
def test_secret_readback_and_private_recovery_controls(tmp_path, monkeypatch, commit, defect, needle):
    from yubikit import openpgp
    trace = Trace(tmp_path / "unknown-secrets", {})
    card = Card(commit, defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        piv_pin="123456", piv_puk="12345678", management_key=DEFAULT_KEY, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("session_recovery", "pin_change", "pin_attempts", "applet_reset", "config_change")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["unknown-secrets"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert len(trace.cases) == 7 and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert len(card.losses) == 7 and card.piv.pin == b"123456" and card.piv.puk == b"12345678"
        assert card.openpgp.pins == {0x81: b"123456", 0x83: b"12345678"}
        assert not card.piv.keys and not card.openpgp.keys and not card.oath.records
