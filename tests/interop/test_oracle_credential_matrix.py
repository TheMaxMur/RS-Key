# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CM state and authorization defects are tested through the suite dispatcher."""
import hashlib

import pytest

import oracle
from oracle_lib import codec, fido
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_fido_properties import PropertyPeer


class StorePeer(PropertyPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.limit, self.cursor = 4, []
        self.rp_scope = None

    def pin(self, fields):
        result = super().pin(fields)
        if fields[2] == 9:
            self.rp_scope = fields.get(10)
        return result

    def make(self, fields):
        resident = fields.get(7, {}).get("rk", False)
        previous = [key for key, record in self.records.items() if record["resident"] and record["rp"] == fields[2]["id"] and record["user"]["id"] == fields[3]["id"]]
        if resident and not previous and sum(record["resident"] for record in self.records.values()) == self.limit:
            return 0x28, {}
        status, value = super().make(fields)
        if resident and self.defect != "retain-replaced-key":
            for key in previous:
                del self.records[key]
        return status, value

    def credential_management(self, fields):
        sub, parameters = fields[1], fields.get(2, {})
        if sub not in (3, 5):
            self.cursor = []
            payload = bytes([sub]) + (codec.encode(parameters) if 2 in fields else b"")
            if fields.get(4) != self.mac(payload):
                return 0x33, {}
            if sub in (6, 7) and not self.permissions & 4 and self.defect != "readonly-writes":
                return 0x40, {}
            if sub not in (6, 7) and not self.permissions & (4 | 64):
                return 0x40, {}
        live = {key: record for key, record in self.records.items() if record["resident"]}
        if sub == 1:
            return 0, {1: len(live), 2: self.limit - len(live)}
        if sub == 2:
            self.cursor = [{3: {"id": rp}, 4: hashlib.sha256(rp.encode()).digest()} for rp in sorted({record["rp"] for record in live.values()})]
        if sub == 4:
            self.cursor = [{6: record["user"], 7: {"type": "public-key", "id": key}} for key, record in live.items() if hashlib.sha256(record["rp"].encode()).digest() == parameters[1]]
        if sub in (2, 3, 4, 5):
            if not self.cursor:
                return (0x2E if sub in (2, 4) else 0x30), {}
            count = len(self.cursor)
            value = dict(self.cursor.pop(0))
            if sub in (2, 4):
                value[5 if sub == 2 else 9] = count
            return 0, value
        if sub in (6, 7):
            try:
                key = parameters[2]["id"]
                user = parameters[3]["id"] if sub == 7 else None
            except KeyError:
                return 0x14, {}
            record = live.get(key)
            if self.rp_scope is not None and (record is None or self.rp_scope != record["rp"]):
                return 0x40, {}
            if record is None:
                return 0x2E, {}
            if sub == 7 and user != record["user"]["id"] and self.defect != "change-user-ID":
                return 0x02, {}
            if sub == 6:
                del self.records[key]
            else:
                record["user"] = parameters[3]
            return 0, {}
        return 0x02, {}

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 10:
            self.cursor = []
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 4: {"rk": True, "credMgmt": True, "clientPin": True, "pinUvAuthToken": True, "perCredMgmtRO": True}, 6: [1, 2]}
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,expected", [(None, None), ("readonly-writes", "CM invalid mutation refused"),
    ("change-user-ID", "CM invalid mutation refused"), ("retain-replaced-key", "replaced credential ID cannot authenticate")])
def test_owned_cm_matrix_checks_full_store_and_invalid_mutations(tmp_path, defect, expected):
    peer = StorePeer(defect)
    trace = Trace(tmp_path / "credential-matrix", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("capacity",)))
    oracle.execute(session, ["credential-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_mode" for row in trace.cases), trace.cases
        assert not any(row["resident"] for row in peer.records.values())
        full = next(row for row in trace.cases if row["scenario_id"].endswith("fill-delete-recreate"))
        assert full["verdict"] == "pass"
