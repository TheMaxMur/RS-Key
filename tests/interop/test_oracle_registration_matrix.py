# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Registration products verify real keys after each accepted or refused request."""
import copy
import hashlib

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_credential_matrix import StorePeer


class RegistrationPeer(StorePeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.always_uv = False

    def make(self, fields):
        if not all(key in fields for key in (1, 2, 3)) or "id" not in fields.get(2, {}) or "id" not in fields.get(3, {}):
            return 0x14, {}
        if not fields.get(4):
            return 0x26, {}
        if any("type" not in row or "alg" not in row for row in fields[4]):
            return 0x12, {}
        if len(fields[1]) != 32 or not 1 <= len(fields[2]["id"].encode()) <= 253:
            return 3, {}
        if any(byte in b" \t\n\r\v\f" for byte in fields[2]["id"].encode()) or not 1 <= len(fields[3]["id"]) <= 64:
            return 2, {}
        options = fields.get(7, {})
        if any(type(value) is not bool for name, value in options.items() if name in ("rk", "up", "uv")):
            return 0x11, {}
        authenticated = 8 in fields
        if options.get("up") is False or options.get("uv") is True and not authenticated:
            return 0x2C, {}
        if not authenticated and (self.always_uv or options.get("rk")):
            if self.defect != "resident-without-UV":
                return 0x36, {}
        extensions = fields.get(6, {})
        if "largeBlobKey" in extensions and (not extensions["largeBlobKey"] or not options.get("rk")):
            return 0x2C, {}
        if "hmac-secret-mc" in extensions and not extensions.get("hmac-secret"):
            return 0x14, {}
        for descriptor in fields.get(5, []):
            record = self.records.get(descriptor["id"])
            if record and record["rp"] == fields[2]["id"] and (authenticated or record["ext"].get("credProtect") != 3 or self.defect == "credProtect-existence-leak"):
                return 0x19, {}
        fields = copy.deepcopy(fields)
        for name in ("name", "displayName"):
            if name in fields[3]:
                fields[3][name] = fields[3][name].encode()[:64].decode("utf-8", errors="ignore")
        self.hmac_seed = hashlib.sha256(b"extension-credential-" + (self.serial + 1).to_bytes(4, "big") + b"hmac secret").digest()
        status, value = super().make(fields)
        if status == 0:
            value[2] = value[2][:32] + bytes([(value[2][32] | 4) if authenticated else (value[2][32] & ~4)]) + value[2][33:]
        return status, value

    def transfer(self, command, wire, deadline, observe):
        status, value = 0, None
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 2: ["credProtect", "hmac-secret", "hmac-secret-mc", "largeBlobKey"],
                4: {"rk": True, "clientPin": True, "credMgmt": True, "pinUvAuthToken": True, "alwaysUv": self.always_uv, "authnrCfg": True, "makeCredUvNotRqd": True}, 6: [1, 2]}
        elif wire[0] == 13:
            assert codec.decode(wire[1:])[1] == 2
            self.always_uv = not self.always_uv
            value = {}
        elif wire[0] == 1:
            try:
                if self.defect == "accept-trailing-item":
                    fields, consumed = codec.decode(wire[1:], prefix=True)
                else:
                    fields = codec.decode(wire[1:])
                if list(fields) != sorted(fields):
                    status, value = 0x12, {}
                else:
                    status, value = self.make(fields)
            except ValueError:
                status, value = 0x12, {}
        else:
            return super().transfer(command, wire, deadline, observe)
        output = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("resident-without-UV", "registration matrix exact outcome"),
    ("credProtect-existence-leak", "credProtect excludeList visibility"), ("accept-trailing-item", "registration matrix exact outcome")])
def test_registration_matrix_expands_options_bounds_encoding_and_visibility(tmp_path, defect, expected):
    peer = RegistrationPeer(defect)
    trace = Trace(tmp_path / "registration", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("config_change",)))
    oracle.execute(session, ["registration-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not any(record["resident"] for record in peer.records.values())
        assert not peer.always_uv
