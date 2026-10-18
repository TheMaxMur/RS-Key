# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Configuration policy peers enforce MACs, code-point rules and owned RP lists."""
import hashlib
import hmac

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as TokenPeer


class Peer(TokenPeer):
    emulated = True

    def __init__(self, defect=None):
        super().__init__(defect)
        self.factory_policy()

    def factory_policy(self):
        self.floor, self.complexity, self.force, self.always, self.ep, self.allowed = 4, False, False, False, False, []

    def control(self, action, deadline, observe):
        return Reply(b"offline ATR")

    def reopen(self, operator):
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")

    @staticmethod
    def trivial(value):
        return (len(set(value)) <= 2 or any(all(value[i] == value[i % period] for i in range(len(value))) for period in range(1, len(value) // 2 + 1))
                or all(ord(b) - ord(a) == 1 for a, b in zip(value, value[1:])) or all(ord(b) - ord(a) == -1 for a, b in zip(value, value[1:])) or value == "password")

    def client_pin(self, fields):
        if fields[2] in (5, 9) and self.force:
            aes, mac = self.keys(fields)
            assert self.decrypt(fields[1], aes, fields[6]) == hashlib.sha256(self.pin_value.encode()).digest()[:16]
            return (0x31 if fields[2] == 5 else 0x37), {}
        if fields[2] == 4:
            aes, mac = self.keys(fields)
            assert fields[4] == hmac.digest(mac, fields[5] + fields[6], "sha256")[:16 if fields[1] == 1 else 32]
            candidate = self.decrypt(fields[1], aes, fields[5]).split(b"\x00", 1)[0].decode()
            assert self.decrypt(fields[1], aes, fields[6]) == hashlib.sha256(self.pin_value.encode()).digest()[:16]
            if self.force and candidate == self.pin_value:
                return 0x37, {}
            if len(candidate) < self.floor or self.complexity and self.trivial(candidate) and self.defect != "complexity-ignored":
                self.ro = hashlib.sha256(self.ro).digest()
                return 0x37, {}
            result = super().client_pin(fields)
            if result[0] == 0:
                self.force = False
            return result
        return super().client_pin(fields)

    def configuration(self, fields):
        protocol, sub = fields.get(3), fields[1]
        if protocol is not None and protocol not in (1, 2):
            return 2
        if sub not in (1, 2, 3, 255):
            return 0x14 if sub == 0 else 2
        if 4 not in fields:
            return 0x36
        if protocol is None:
            return 0x14
        message = b"\xff" * 32 + bytes([13, sub]) + (codec.encode(fields[2]) if 2 in fields else b"")
        if (fields[4] != self.mac(message) or not self.permissions & 32) and self.defect != "config-auth-bypass":
            return 0x33
        parameters = fields.get(2, {})
        if sub == 1:
            self.ep = True
        elif sub == 2:
            self.always = not self.always
        elif sub == 3:
            if len(parameters.get(2, [])) > 8 and self.defect != "truncate-RP-list":
                return 0x28
            minimum = parameters.get(1) or self.floor
            if not self.floor <= minimum <= 63:
                return 0x37
            self.floor = minimum
            self.complexity |= parameters.get(4, False)
            if parameters.get(2):
                self.allowed = parameters[2][:8]
            self.force |= parameters.get(3, False) or len(self.pin_value) < self.floor
            if self.force:
                self.token, self.permissions = bytes(32), 0
                self.ro = hashlib.sha256(self.ro).digest()
        else:
            return 0x3E
        return 0

    def make(self, fields):
        status, result = super().make(fields)
        if not status:
            requested = fields.get(6, {})
            visible = fields[2]["id"] in self.allowed or self.defect == "RP-policy-leak"
            extensions = {}
            if visible:
                if requested.get("minPinLength"):
                    extensions["minPinLength"] = self.floor
                if requested.get("pinComplexityPolicy"):
                    extensions["pinComplexityPolicy"] = self.complexity
            if extensions:
                result[2] = result[2][:32] + bytes([result[2][32] | 128]) + result[2][33:] + codec.encode(extensions)
        return status, result

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 7:
            self.factory_policy()
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 2: ["minPinLength", "pinComplexityPolicy"],
                4: {"clientPin": self.pin_value is not None, "rk": True, "credMgmt": True, "pinUvAuthToken": True, "perCredMgmtRO": True,
                    "authnrCfg": True, "setMinPINLength": True, "alwaysUv": self.always, "ep": self.ep},
                6: [1, 2], 12: self.force, 13: self.floor, 16: 8, 27: self.complexity, 29: 63}
            output = b"\x00" + codec.encode(value)
        elif wire[0] == 13:
            output = bytes([self.configuration(codec.decode(wire[1:]))])
        else:
            return super().transfer(command, wire, deadline, observe)
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if output[0] == 0 else "applet_error", output[0])


@pytest.mark.parametrize("defect,needle", [(None, None), ("config-auth-bypass", "CONFIG isolates the authorization failure cause"),
    ("truncate-RP-list", "RP-list overflow is not silently truncated"), ("complexity-ignored", "complexity rejects a length-valid trivial PIN"),
    ("RP-policy-leak", "PIN policy is visible only to its permitted RP")])
def test_configuration_authorization_and_policy_edges(tmp_path, monkeypatch, defect, needle):
    from oracle_lib import binding
    monkeypatch.setattr(binding, "check_pair", lambda session: None)
    peer = Peer(defect)
    trace = Trace(tmp_path / "CONFIG-matrix", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("config_change", "pin_change", "pin_attempts", "applet_reset", "reboot")))
    oracle.execute(session, ["config-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert peer.pin_value == "fixture-PIN" and peer.floor == 4 and not peer.complexity
