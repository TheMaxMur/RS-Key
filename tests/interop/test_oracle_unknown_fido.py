# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Lost CTAP answers need old/new private and persistent-state observations."""
import hashlib

import pytest

import oracle
from oracle_lib import binding, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_blob_matrix import Peer as Blob
from test_oracle_credential_matrix import StorePeer
from test_oracle_expanded import apdu_parts
from test_oracle_token_matrix import Peer as Tokens


class Peer(Tokens):
    def __init__(self, defect):
        super().__init__()
        self.fault, self.cursor, self.limit, self.rp_scope = defect, [], 256, None
        body = codec.encode([])
        self.blob = body + hashlib.sha256(body).digest()[:16]
        self.staging, self.total, self.blob_defect, self.always = b"", 0, None, False

    def make(self, fields):
        old = [key for key, row in self.records.items() if row["resident"] and row["rp"] == fields[2]["id"] and row["user"]["id"] == fields[3]["id"]]
        status, value = super().make(fields)
        if not status and fields.get(7, {}).get("rk"):
            for key in old:
                del self.records[key]
        return status, value

    def credential_management(self, fields):
        if fields[1] in (3, 5) and not self.cursor:
            return 0x30, {}
        status, value = StorePeer.credential_management(self, fields)
        if not status and fields[1] in (4, 5):
            key = self.records[value[7]["id"]]["key"].public_key().public_numbers()
            value[8] = {1: 2, 3: -7, -1: 1, -2: key.x.to_bytes(32, "big"), -3: key.y.to_bytes(32, "big")}
        return status, value

    def transfer(self, command, wire, deadline, observe):
        if wire[0] not in (10,):
            self.cursor = []
        if wire[0] != 12:
            self.staging, self.total = b"", 0
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 4: {"rk": True, "clientPin": True, "pinUvAuthToken": True, "credMgmt": True,
                "perCredMgmtRO": True, "authnrCfg": True, "alwaysUv": self.always, "largeBlobs": True},
                5: 576, 6: [1, 2], 11: 1024, 13: 4}
            status = 0
        elif wire[0] == 12:
            status, value = Blob.blobs(self, codec.decode(wire[1:]))
        elif wire[0] == 13:
            fields = codec.decode(wire[1:])
            assert fields[1] == 2 and fields[4] == self.mac(b"\xff" * 32 + b"\x0d\x02") and self.permissions & 32
            self.always = not self.always
            status, value = 0, {}
        else:
            return super().transfer(command, wire, deadline, observe)
        output = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)


class Card:
    layer = "pcsc_apdu"

    def __init__(self, peer, commit):
        self.peer, self.commit, self.losses = peer, commit, []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        output = self.peer.transfer(0x10, body, deadline, lambda *_: None).data if ins == 0x10 else b""
        output += b"\x90\x00"
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0x9000)

    def control(self, action, deadline, observe):
        self.peer.cursor, self.peer.staging, self.peer.total = [], b"", 0
        return Reply(b"offline ATR")

    def drop_response(self, wire, deadline, observe):
        self.losses.append(wire)
        observe("tx", wire)
        if self.commit:
            result = self.transfer(wire, deadline, lambda *_: None)
            assert result.data[0] == 0
            ins, p1, p2, body = apdu_parts(wire)
            fields = codec.decode(body[1:])
            if self.peer.fault == "corrupt-user" and body[0] == 10 and fields[1] == 7:
                self.peer.records[fields[2][2]["id"]]["user"]["id"] = b"wrong"
            if self.peer.fault == "partial-blob" and body[0] == 12:
                self.peer.blob = b"partial"
            if self.peer.fault == "unknown-PIN" and body[0] == 6:
                self.peer.pin_value = "corrupt-verifier"
        raise TransferError("offline CTAP response abandoned", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit,defect,needle", [(False, None, None), (True, None, None),
    (True, "corrupt-user", "complete old or updated user fields"),
    (True, "partial-blob", "complete old or new value"),
    (True, "unknown-PIN", "complete known old or new verifier")])
def test_FIDO_lost_secret_resident_blob_and_policy_mutations(tmp_path, monkeypatch, commit, defect, needle):
    trace = Trace(tmp_path / "unknown-FIDO", {})
    peer = Peer(defect)
    card = Card(peer, commit)
    session = Session(trace, hid=peer, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", allow_effects=("session_recovery", "pin_change", "pin_attempts", "config_change")))
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["unknown-fido"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert len(trace.cases) == 16 and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert len(card.losses) == 16 and peer.pin_value == "fixture-PIN" and not peer.always
        assert not any(row["resident"] for row in peer.records.values())
