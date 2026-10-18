# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Vendor readback resolves unknown flash changes without repeating the mutator."""
import pytest

import oracle
from oracle_lib import binding, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_seed_lifetimes import Peer as SeedPeer


class Peer(SeedPeer):
    def __init__(self):
        super().__init__()
        self.led, self.audit = bytes(range(17)), False

    def transfer(self, *args):
        if len(args) == 4 and args[1][:1] == b"\x41":
            command, wire, deadline, observe = args
            fields = codec.decode(wire[1:])
            sub, params = fields[1], fields.get(2, {})
            if sub == 13 and params[1] == 2:
                return self.reply(wire, 0, {1: self.led}, observe)
            if sub == 12:
                status = self.mac_valid(wire[0], fields)
                if not status:
                    self.led = params[2]
                return self.reply(wire, status, {}, observe)
            if sub == 14:
                if params[1] != 2:
                    status = self.mac_valid(wire[0], fields)
                    if status:
                        return self.reply(wire, status, {}, observe)
                    self.audit = bool(params[1])
                return self.reply(wire, 0, {1: self.audit}, observe)
        return super().transfer(*args)


class Card:
    layer, emulated = "pcsc_apdu", True

    def __init__(self, peer, commit, fault):
        self.peer, self.commit, self.fault = peer, commit, fault
        self.losses = []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins != 0x10:
            return Reply(b"\x90\x00", status=0x9000)
        reply = self.peer.transfer(0x10, body, deadline, lambda *_: None)
        output = reply.data + b"\x90\x00"
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0x9000)

    def control(self, action, deadline, observe):
        return self.peer.control(action, deadline, observe)

    def drop_response(self, wire, deadline, observe):
        self.losses.append(bytes(wire))
        observe("tx", wire)
        if self.commit:
            reply = self.transfer(wire, deadline, lambda *_: None)
            assert reply.data[0] == 0
            body = apdu_parts(wire)[3]
            fields = codec.decode(body[1:])
            if body[0] == 0x41 and fields[1] == 12 and self.fault == "partial-LED":
                self.peer.led = self.peer.led[:8]
            elif body[0] == 0x41 and fields[1] == 3 and self.fault == "wrong-seed":
                self.peer.vendor.seed = b"\x01" * 32
            elif body[0] == 13 and self.peer.lock_key is not None and self.fault == "wrong-lock-RAM":
                self.peer.unlocked = True
        raise TransferError("synthetic vendor answer abandoned", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit,fault,needle", [(False, None, None), (True, None, None),
    (True, "partial-LED", "complete old or new"), (True, "wrong-seed", "complete old or new"),
    (True, "wrong-lock-RAM", "complete old or new")])
def test_vendor_unknown_mutations_have_exact_private_and_record_readback(tmp_path, monkeypatch, commit, fault, needle):
    trace = Trace(tmp_path / "vendor-uncertain", {})
    peer = Peer()
    card = Card(peer, commit, fault)
    session = Session(trace, hid=peer, card=card, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("seed_change", "config_change", "replace_identity", "applet_reset", "pin_change", "reboot")))
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["vendor-uncertain"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert len(trace.cases) == 8 and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert len(card.losses) == 8 and peer.vendor.seed == bytes(range(32))
        assert peer.led == bytes(range(17)) and not peer.audit and peer.lock_key is None and not peer.sealed and peer.org is None
