# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Owned cursor state has independent channel, kind and clock enforcement."""
import hmac

import pytest

import oracle
from oracle_lib import binding, codec, cursor_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_credential_matrix import StorePeer
from test_oracle_expanded import apdu_parts


class Peer(StorePeer):
    cid = b"\x01\x02\x03\x04"
    now, cm_time, ga_time = 0, 0, 0

    def __init__(self, defect=None):
        super().__init__(defect)
        self.cm_owner, self.ga_owner, self.kind, self.ga = None, None, None, []
        self.readonly = None
        self.next_channel = 99

    def pin(self, fields):
        before = self.token, self.permissions, self.protocol
        result = super().pin(fields)
        if fields[2] == 9 and fields[9] == 64:
            self.readonly = self.token
            self.token, self.permissions, self.protocol = before
        return result

    def credential_management(self, fields):
        sub = fields[1]
        if sub in (3, 5):
            if self.kind not in (2, 4) or self.cm_owner != self.cid and self.defect != "foreign-CID-continues" or sub != (3 if self.kind == 2 else 5) or self.now - self.cm_time > 30 and self.defect != "cursor-never-expires":
                return 0x30, {}
        else:
            self.kind, self.cm_owner = sub, self.cid
        self.cm_time = self.now
        if self.readonly is not None and sub not in (3, 5):
            message = bytes([sub]) + (codec.encode(fields[2]) if 2 in fields else b"")
            if fields.get(4) == hmac.digest(self.readonly, message, "sha256")[:16 if fields[3] == 1 else 32]:
                old = self.token, self.permissions
                try:
                    self.token, self.permissions = self.readonly, 64
                    return super().credential_management(fields)
                finally:
                    self.token, self.permissions = old
        return super().credential_management(fields)

    def transfer(self, command, wire, deadline, observe):
        if command == 6:
            self.next_channel += 1
            result = wire + self.next_channel.to_bytes(4, "big") + bytes([2, 5, 8, 0, 5])
            return Reply(result)
        cmd = wire[0]
        if cmd != 10:
            self.kind = None
        if cmd not in (2, 8):
            self.ga = []
        if cmd == 2:
            fields = codec.decode(wire[1:])
            if 3 not in fields:
                descriptors = [{"type": "public-key", "id": key} for key, record in self.records.items() if record["rp"] == fields[1] and record["resident"]]
                self.ga = [{**fields, 3: [row]} for row in descriptors]
                self.ga_owner, self.ga_time = self.cid, self.now
                value = super().assertion(self.ga.pop(0))[1]
                value[5] = len(descriptors)
                output = b"\x00" + codec.encode(value)
            else:
                return super().transfer(command, wire, deadline, observe)
        elif cmd == 8:
            if not self.ga or self.ga_owner != self.cid and self.defect != "foreign-CID-continues" or self.now - self.ga_time > 30 and self.defect != "cursor-never-expires":
                output = b"\x30"
            else:
                value = super().assertion(self.ga.pop(0))[1]
                self.ga_time = self.now
                output = b"\x00" + codec.encode(value)
        elif cmd == 0xff:
            output = b"\x01"
        else:
            return super().transfer(command, wire, deadline, observe)
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if output[0] == 0 else "applet_error", output[0])

    def reopen(self, operator):
        self.cid = (int.from_bytes(self.cid, "big") + 1).to_bytes(4, "big")
        return {"synthetic": True}

    def initialize(self, trace, timeout):
        return None


class Card:
    layer, emulated = "pcsc_apdu", True

    def __init__(self, peer):
        self.peer = peer

    def control(self, action, deadline, observe):
        if action == "power_cycle":
            self.peer.ga, self.peer.kind = [], None
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, _, _, body = apdu_parts(wire)
        if ins == 0x10:
            owner, self.peer.cid = self.peer.cid, bytes(4)
            try:
                result = self.peer.transfer(0x10, body, deadline, lambda *_: None)
            finally:
                self.peer.cid = owner
            response = result.data + b"\x90\x00"
        else:
            response = (b"\x05\x08\x00" if ins == 0xfd else b"") + b"\x90\x00"
        observe("tx", wire)
        observe("rx", response)
        return Reply(response, status=0x9000)


@pytest.mark.parametrize("defect,needle", [(None, None), ("foreign-CID-continues", "foreign channel cannot continue"),
    ("cursor-never-expires", "interruption retires the initialized walk")])
def test_owned_RP_credential_and_assertion_cursors(tmp_path, monkeypatch, defect, needle):
    trace = Trace(tmp_path / "owned-cursors", {})
    peer = Peer(defect)
    monkeypatch.setattr(cursor_matrix, "wait", lambda session, seconds: setattr(peer, "now", peer.now + seconds))
    def paired(session):
        session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(binding, "check_pair", paired)
    session = Session(trace, hid=peer, card=Card(peer), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", timeout=32, allow_effects=("reboot",)))
    paired(session)
    oracle.execute(session, ["cursor-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert not peer.records
