# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""UV issuance uses real ECDH and checks internal versus external grant provenance."""
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec, uv_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as TokenPeer


class Peer(TokenPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.internal = False

    def client_pin(self, fields):
        if fields[2] == 7:
            return 0, {5: self.remaining}
        if fields[2] != 6:
            result = super().client_pin(fields)
            if fields[2] in (5, 9) and not result[0] and fields.get(9) != 64:
                self.internal = False
            return result
        bits = fields[9]
        low = bits & 255
        if bits == 0:
            return 2, {}
        if low & (8 | 32) or low & 64 and low != 64:
            if self.defect != "UV-allows-config":
                return 0x40, {}
        mode = self.session.current.parameters.get("operator_action")
        if mode:
            if mode == "wrong-PIN-once":
                self.failed_pin()
                return 0x3f, {}
            if self.defect == "cancel-spends-retry":
                self.remaining -= 1
            return {"decline-consent": 0x27, "decline-pad": 0x27, "cancel": 0x2d, "timeout": 0x2f}[mode], {}
        aes, mac = self.keys(fields)
        cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
        encrypted = (bytes(16) if fields[1] == 2 else b"") + cipher.update(hashlib.sha256(self.pin_value.encode()).digest()[:16]) + cipher.finalize()
        result = super().client_pin({**fields, 2: 9, 6: encrypted})
        self.internal = True
        return result

    def assertion(self, fields):
        status, value = super().assertion(fields)
        if not status and fields.get(4, {}).get("uvm"):
            factor = 4 if self.internal and self.defect != "internal-is-external" else 0x800
            data = value[2][:32] + bytes([value[2][32] | 128]) + value[2][33:37] + codec.encode({"uvm": [[1, 2, 4], [factor, 2, 4]]})
            value[2] = data
            record = self.records[value[1]["id"]]
            value[3] = record["key"].sign(data + fields[2], ec.ECDSA(hashes.SHA256()))
        return status, value

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 4:
            output = b"\x00" + codec.encode({1: ["FIDO_2_3"], 2: ["uvm"], 4: {"uv": self.pin_value is not None, "clientPin": self.pin_value is not None, "pinUvAuthToken": True, "credMgmt": True, "perCredMgmtRO": True}, 6: [1, 2]})
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("internal-is-external", "UV token provenance"),
    ("cancel-spends-retry", "only a submitted mismatch consumes"), ("UV-allows-config", "local-UV permissions follow")])
def test_local_UV_permissions_refusal_budget_and_signed_provenance(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(uv_matrix, "PERMISSIONS", (0, 1, 2, 3, 4, 8, 32, 64, 65, 128, 255, 256, 257))
    monkeypatch.setattr(uv_matrix, "options", lambda session: None)
    monkeypatch.setattr(uv_matrix, "assertion_options", lambda session: None)
    monkeypatch.setattr(uv_matrix, "extension_outputs", lambda session: None)
    monkeypatch.setattr(uv_matrix, "local_change", lambda session: None)
    trace = Trace(tmp_path / "UV", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, pin="fixture-PIN", timeout=131, allow_effects=("pin_attempts",)))
    peer.session = session
    oracle.execute(session, ["uv-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
