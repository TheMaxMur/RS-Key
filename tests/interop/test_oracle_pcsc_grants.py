# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Disposition defects fail on protected operations with independently held keys."""
import pytest

import oracle
from oracle_lib import pcsc_grants
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_oath_gates import Peer as OathPeer
from test_oracle_openpgp_references import Peer as PgpPeer, sdk_with_errors
from test_oracle_piv_references import Peer as PivPeer
from test_oracle_piv_lifecycle import DEFAULT_KEY


def native_peer(base, applet, defect):
    class Peer(base):
        pipe = True

        def __init__(self):
            super().__init__()
            self.transaction = False
            self.controls = []

        def transfer(self, request, deadline, observe):
            if not isinstance(request, dict):
                return super().transfer(request, deadline, observe)
            self.controls.append(request.copy())
            if request["control"] == "transaction":
                self.transaction = request["begin"]
            disposition = request.get("disposition", "leave")
            resets = disposition != "leave"
            if defect == "leave-resets":
                resets = not request.get("begin", False)
            if defect == "reset-retains":
                resets = False
            if resets:
                if applet == "piv":
                    self.has_pin, self.has_management, self.witness = False, False, None
                    if defect == "reset-replaces-key":
                        self.keys.clear()
                elif applet == "openpgp":
                    self.grants.clear()
                    if defect == "reset-replaces-key":
                        self.keys.clear()
                else:
                    self.pin_verified, self.validated = False, self.code is None
                    if defect == "reset-replaces-key":
                        for record in self.records.values():
                            record["secret"] = b"wrong secret"
            observe("control", b"", disposition=disposition)
            return Reply(b"\x3b\x00")
    return Peer()


@pytest.mark.parametrize("applet,base", [("piv", PivPeer), ("openpgp", PgpPeer), ("oath", OathPeer)])
@pytest.mark.parametrize("defect", [None, "leave-resets", "reset-retains", "reset-replaces-key"])
def test_every_disposition_and_grant_subset_uses_private_witnesses(tmp_path, monkeypatch, applet, base, defect):
    from yubikit import openpgp
    peer = native_peer(base, applet, defect)
    trace = Trace(tmp_path / "pcsc-grants", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        piv_pin="123456", management_key=DEFAULT_KEY, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("config_change", "pin_change", "applet_reset")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    for other in ("piv", "openpgp", "oath"):
        if other != applet:
            monkeypatch.setattr(pcsc_grants, other, lambda session, operation, disposition: None)
    oracle.execute(session, ["pcsc-grants"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert failures
        if defect == "leave-resets":
            assert any(".leave." in name and ("latch" in reason or "APDU" in reason or "own access latch" in reason) for name, reason in failures), failures
        elif defect == "reset-retains":
            assert any(".reset." in name and ("latch" in reason or "must be refused" in reason) for name, reason in failures), failures
        else:
            assert any(".reset." in name and ("signature" in reason or "APDU" in reason or "HOTP secret" in reason) for name, reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert not peer.transaction
        assert {row.get("disposition") for row in peer.controls} >= {"leave", "reset", "unpower"}


def test_pcsc_grants_excludes_other_backends_before_fixture_writes(tmp_path):
    class Card:
        def transfer(self, *args):
            pytest.fail("an inapplicable PC/SC grant case must not write its fixture")
    trace = Trace(tmp_path / "no-native-pcsc", {})
    oracle.execute(Session(trace, card=Card(), profile="rsk", options=Options(exercise=True, touch=True,
        allow_effects=("config_change", "pin_change", "applet_reset"))), ["pcsc-grants"])
    trace.finish()
    assert trace.cases and all(row["applicability"] == "excluded_by_mode" for row in trace.cases)
