# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A lost ACK cannot become proof of reboot or complete legacy migration."""
import builtins

import pytest

import oracle
from oracle_lib import binding
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_rescue import Card as Rescue
from test_oracle_token_matrix import Peer as Tokens


class Hid(Tokens):
    descriptor = {"serial_number": "offline-unknown-boot"}
    rebound = False

    def __init__(self):
        super().__init__()
        self.after_rebind = []

    def transfer(self, command, wire, deadline, observe):
        if self.rebound:
            self.after_rebind.append(wire)
        return super().transfer(command, wire, deadline, observe)

    def reopen(self, operator):
        self.rebound = True
        return self.descriptor

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="offline")


class Card(Rescue):
    descriptor = Hid.descriptor

    def __init__(self, commit, hid=None, layout=None, fault=None):
        super().__init__(None)
        self.commit, self.hid, self.layout, self.fault = commit, hid, layout, fault
        self.active, self.losses = layout is None, []

    def control(self, action, deadline, observe):
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0x1f:
            output = b"\x90\x00"
        elif ins == 0x20:
            assert body == (b"INITV2" if self.layout == "empty" else b"IMPORTV2")
            self.active = True
            output = b"\x90\x00"
        elif ins == 0x1e and p1 == 8:
            output = (b"\x02\x03" if self.fault == "invalid-ready" and self.losses else bytes([2, int(self.active)])) + b"\x90\x00"
        else:
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0x9000)

    def drop_response(self, wire, deadline, observe):
        self.losses.append(wire)
        observe("tx", wire)
        if self.commit:
            self.transfer(wire, deadline, lambda *_: None)
            if self.fault == "lost-private-key":
                self.hid.records.clear()
        raise TransferError("offline boot/setup ACK abandoned", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit", [False, True])
@pytest.mark.parametrize("layout", ["empty", "legacy"])
def test_prepared_setup_reports_only_observed_readiness_and_retains_unknown_media(tmp_path, commit, layout):
    trace = Trace(tmp_path / "unknown-setup", {})
    card = Card(commit, layout=layout)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        recovery_layout=layout, allow_effects=("session_recovery", "storage_setup", "reboot")))
    oracle.execute(session, ["unknown-boot"])
    trace.finish()
    selected = next(row for row in trace.cases if row["scenario_id"].endswith("storage-setup." + layout))
    assert selected["applicability"] == "unknown" and selected["verdict"] == "inconclusive", selected
    assert len(card.losses) == 1 and card.active == commit
    assert not any(row["verdict"] == "fail" for row in trace.cases)


@pytest.mark.parametrize("commit", [False, True])
def test_lost_reboot_stays_unknown_even_after_real_key_continuity_proofs(tmp_path, monkeypatch, commit):
    hid = Hid()
    card = Card(commit, hid)
    trace = Trace(tmp_path / "unknown-reboot", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        pin="fixture-PIN", allow_effects=("session_recovery", "reboot")))
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    monkeypatch.setattr(builtins, "input", lambda *args: "")
    oracle.execute(session, ["unknown-boot"])
    trace.finish()
    rows = [row for row in trace.cases if ".reboot." in row["scenario_id"]]
    assert len(rows) == 4 and all(row["applicability"] == "unknown" for row in rows), rows
    assert len(card.losses) == 4 and not any(row["verdict"] == "fail" for row in trace.cases)


def test_failed_post_rebind_identity_stops_before_PIN_or_another_boot_write(tmp_path, monkeypatch):
    hid = Hid()
    card = Card(True, hid, fault="lost-private-key")
    trace = Trace(tmp_path / "unknown-reboot-wrong-key", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        pin="fixture-PIN", allow_effects=("session_recovery", "reboot")))
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    monkeypatch.setattr(builtins, "input", lambda *args: "")
    oracle.execute(session, ["unknown-boot"])
    trace.finish()
    assert any(row["verdict"] == "fail" and "CTAP success" in row["reason"] for row in trace.cases), trace.cases
    assert session.broken and len(card.losses) == 1
    assert hid.after_rebind and not any(wire[:1] == b"\x06" for wire in hid.after_rebind)
