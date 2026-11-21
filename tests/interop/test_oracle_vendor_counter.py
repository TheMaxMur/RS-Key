# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Counter witnesses distinguish consent, sharing, persistence and uncertain delivery."""
import builtins

import pytest

import oracle
from oracle_lib import binding, vendor_counter
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts


class Peer:
    def __init__(self, fault, delivered):
        self.fault, self.delivered, self.confirmed = fault, delivered, True
        self.values = {"card": 0xfffffffe, "hid": 0xfffffffe}
        self.lost_mutations = 0
        self.increments = 0

    def transfer(self, route, wire, observe):
        ins, p1, p2, body = apdu_parts(wire)
        status, data = 0x9000, b""
        if ins == 0xa4:
            pass
        elif ins in (1, 2):
            if ins == 1:
                if not self.confirmed and self.fault != "ignores-consent":
                    status = 0x6985
                else:
                    self.increments += 1
                    targets = (route,) if self.fault == "separate-transports" else tuple(self.values)
                    for target in targets:
                        self.values[target] = (self.values[target] + (2 if self.fault == "double-increment" else 1)) & 0xffffffff
            if status == 0x9000:
                data = self.values[route].to_bytes(4, "big")
        else:
            raise AssertionError("unprofiled counter request")
        output = data + status.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0x9000 else "applet_error", status)


class Card:
    layer, emulated = "offline_counter_card", True

    def __init__(self, peer):
        self.peer = peer

    def transfer(self, wire, deadline, observe):
        return self.peer.transfer("card", wire, observe)

    def control(self, action, deadline, observe):
        if self.peer.fault == "reset-loses-counter":
            self.peer.values = {"card": 0, "hid": 0}
        return Reply(b"")

    def drop_response(self, wire, deadline, observe):
        self.peer.lost_mutations += 1
        if self.peer.delivered:
            self.peer.transfer("card", wire, lambda *args: None)
            if self.peer.fault == "lost-double-increment":
                self.peer.transfer("card", wire, lambda *args: None)
        observe("tx", wire, evidence="offline delivery is intentionally not disclosed")
        raise TransferError("injected offline response loss", Outcome.CANCELLED, protocol="injected_response_loss")


class Hid:
    layer = "offline_counter_hid"

    def __init__(self, peer):
        self.peer = peer

    def transfer(self, command, wire, deadline, observe):
        assert command == 3
        return self.peer.transfer("hid", wire, observe)

    def reopen(self, operator):
        return {"profile": "rsk", "serial_number": "offline-counter"}

    def initialize(self, trace, timeout):
        pass


@pytest.mark.parametrize("fault,delivered,needle", [(None, False, None), (None, True, None),
    ("ignores-consent", True, "distinct consent refusal"), ("separate-transports", True, "same persistent counter"),
    ("double-increment", True, "committed counter value"), ("reset-loses-counter", True, "same persistent counter"),
    ("lost-double-increment", True, "commits at most once")])
def test_counter_consent_all_parameters_wrap_routes_and_connection_lifetimes(tmp_path, monkeypatch, fault, delivered, needle):
    peer = Peer(fault, delivered)
    trace = Trace(tmp_path / "counter", {})
    session = Session(trace, card=Card(peer), hid=Hid(peer), profile="rsk", options=Options(exercise=True, touch=True,
        operator=True, timeout=131, features=("display",), allow_effects=("reboot",)))
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    monkeypatch.setattr(builtins, "input", lambda prompt: "")
    original = vendor_counter.cue
    def cue(session, mode):
        peer.confirmed = mode == "accept"
        original(session, mode)
    monkeypatch.setattr(vendor_counter, "cue", cue)
    oracle.execute(session, ["vendor-counter"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert peer.values["hid"] == peer.values["card"] and peer.lost_mutations == 1
        assert any(row["observations"].get("uncertain_counter_readback", {}).get("value", {}).get("mutation_replayed") is False for row in trace.cases)


def test_unavailable_power_action_is_excluded_before_the_irreversible_fixture_increment(tmp_path, monkeypatch):
    peer = Peer(None, True)
    card = Card(peer)
    card.emulated = False
    trace = Trace(tmp_path / "counter-preflight", {})
    session = Session(trace, card=card, hid=Hid(peer), profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("reboot",)))
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    vendor_counter.persistence(session)
    trace.finish()
    assert peer.increments == 6
    assert all(row["applicability"] == "blocked_by_precondition" for row in trace.cases if row["scenario_id"].endswith("power_cycle"))
    assert all(row["verdict"] == "pass" for row in trace.cases if not row["scenario_id"].endswith("power_cycle"))
