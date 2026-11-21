# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Encrypted discovery members are independently keyed over identity and storage state."""
import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import oracle
from oracle_lib import binding, codec, store_state
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as TokenPeer


class Peer(TokenPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.ro_exists, self.seed, self.tag = False, b"initial identity", bytes(16)

    def advance(self):
        self.tag = hashlib.sha256(self.tag + b"mutation").digest()[:16]

    def client_pin(self, fields):
        status, value = super().client_pin(fields)
        if not status and fields[2] == 9 and fields[9] == 64:
            self.ro_exists = True
        return status, value

    def credential_management(self, fields):
        sub, parameters = fields[1], fields.get(2, {})
        if sub not in (6, 7):
            return super().credential_management(fields)
        payload = bytes([sub]) + codec.encode(parameters)
        if fields[4] != self.mac(payload) or not self.permissions & 4:
            return 0x33, {}
        record = self.records.get(parameters[2]["id"])
        if record is None:
            return 0x2e, {}
        if sub == 7 and parameters[3]["id"] != record["user"]["id"]:
            if self.defect == "refused-update-advances-tag":
                self.advance()
            return 2, {}
        if sub == 6:
            del self.records[parameters[2]["id"]]
        else:
            record["user"] = parameters[3]
        if sub != 7 or self.defect != "update-keeps-tag":
            self.advance()
        return 0, {}

    def make(self, fields):
        status, value = super().make(fields)
        if not status and fields.get(7, {}).get("rk"):
            self.advance()
        return status, value

    def encrypted(self, label, plain):
        iv = bytes(16) if self.defect == "fixed-IV" else os.urandom(16)
        key = HKDF(hashes.SHA256(), 16, bytes(32), label).derive(self.ro)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv + cipher.update(plain) + cipher.finalize()

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 7:
            self.ro_exists = False
            if self.defect != "reset-keeps-identifier":
                self.seed = hashlib.sha256(self.seed + b"reset").digest()
            self.advance()
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 2: ["largeBlobKey"], 4: {"rk": True, "clientPin": self.pin_value is not None, "pinUvAuthToken": True, "credMgmt": True, "perCredMgmtRO": True}, 6: [1, 2]}
            if self.ro_exists:
                value[25] = self.encrypted(b"encIdentifier", hashlib.sha256(self.seed).digest()[:16])
                value[30] = self.encrypted(b"encCredStoreState", self.tag)
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


class Card:
    emulated = True

    def control(self, action, deadline, observe):
        return Reply(b"synthetic ATR")


@pytest.mark.parametrize("defect,needle", [(None, None), ("fixed-IV", "fresh IV for each anonymous"),
    ("update-keeps-tag", "user update changes"), ("refused-update-advances-tag", "refused update cannot advance"),
    ("reset-keeps-identifier", "reset starts a different platform identifier")])
def test_encrypted_store_state_create_update_delete_and_reset(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(binding, "check_pair", lambda *args: None)
    monkeypatch.setattr(store_state, "snapshot", lambda *args: None)
    trace = Trace(tmp_path / "encrypted-store", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, card=Card(), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("applet_reset", "pin_change", "reboot")))
    oracle.execute(session, ["store-state"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert peer.pin_value == "fixture-PIN" and not peer.records
