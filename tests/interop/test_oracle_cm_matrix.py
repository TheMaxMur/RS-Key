# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CM parser/auth/walk ordering is independent from the generated case expectations."""
import hashlib
import hmac

import pytest

import oracle
from oracle_lib import cm_matrix, codec
from oracle_lib.runner import Options, Session
from test_oracle_unknown_fido import Peer as Base


class Peer(Base):
    def __init__(self, defect):
        super().__init__(None)
        self.fault, self.now, self.issued, self.walk_time, self.cm_kind = defect, 0, 0, 0, None

    def client_pin(self, fields):
        status, value = super().client_pin(fields)
        if not status and fields[2] in (5, 9) and fields.get(9) != 64:
            self.issued = self.now
        return status, value

    def credential_management(self, fields):
        if 1 not in fields:
            return 0x14, {}
        if fields.get(3, 0) > 0xffffffff:
            return 0x12, {}
        sub, params = fields[1], fields.get(2, {})
        if sub in (3, 5):
            if self.fault == "Next-validates-ignored-protocol" and fields.get(3) == 0:
                return 2, {}
            if not self.cursor or self.cm_kind != (2 if sub == 3 else 4) or self.now - self.walk_time > 30:
                return 0x30, {}
            self.walk_time = self.now
            return 0, self.cursor.pop(0)
        self.cursor, self.cm_kind = [], None
        protocol = fields.get(3)
        if protocol not in (None, 1, 2):
            return 2, {}
        if 4 not in fields:
            return 0x36, {}
        if protocol is None:
            return 0x14, {}
        if sub == 4 and len(params.get(1, b"")) != 32 or sub in (6, 7) and "id" not in params.get(2, {}) or sub == 7 and "id" not in params.get(3, {}):
            return 0x14, {}
        if sub in (4, 6, 7) and len(codec.encode(params)) > 384:
            return 0x39, {}
        message = bytes([sub]) + (codec.encode(params) if sub in (4, 6, 7) and 2 in fields else b"")
        width = 16 if protocol == 1 else 32
        persistent = sub in (1, 2, 4) and fields[4] == hmac.digest(self.ro, message, "sha256")[:width]
        ordinary = fields[4] == hmac.digest(self.token, message, "sha256")[:width] and self.permissions & 4 and self.now - self.issued <= 30
        if not persistent and not ordinary and self.fault != "bad-MAC-accepted":
            if self.fault == "refusal-deletes-neighbor":
                for key, row in list(self.records.items()):
                    if row["resident"]:
                        del self.records[key]
                        break
            return 0x33, {}
        live = {key: row for key, row in self.records.items() if row["resident"]}
        if sub == 1:
            return 0, {1: len(live), 2: self.limit - len(live)}
        if sub == 2:
            self.cursor = [{3: {"id": rp}, 4: hashlib.sha256(rp.encode()).digest()} for rp in sorted({row["rp"] for row in live.values()})]
        elif sub == 4:
            self.cursor = [{6: row["user"], 7: {"type": "public-key", "id": key}} for key, row in live.items() if hashlib.sha256(row["rp"].encode()).digest() == params[1]]
        elif sub in (6, 7):
            identifier = params[2]["id"]
            record = live.get(identifier)
            if record is None:
                return 0x2e, {}
            if sub == 6:
                del self.records[identifier]
            else:
                user = params[3]
                if record["user"]["id"] != user["id"]:
                    return 2, {}
                record["user"] = {key: value if key == "id" else value.encode()[:64].decode("utf-8", errors="ignore") for key, value in user.items() if value}
            return 0, {}
        else:
            return 2, {}
        if not self.cursor:
            return 0x2e, {}
        self.cm_kind, self.walk_time = sub, self.now
        value = {**self.cursor.pop(0), 5 if sub == 2 else 9: len(self.cursor) + 1}
        return 0, value

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 10:
            self.cm_kind = None
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("bad-MAC-accepted", "isolated exact result"),
    ("Next-validates-ignored-protocol", "isolated exact result"), ("refusal-deletes-neighbor", "CTAP success")])
def test_each_CM_field_authority_and_initialized_continuation(tmp_path, monkeypatch, defect, needle):
    from oracle_lib.trace import Trace
    peer = Peer(defect)
    trace = Trace(tmp_path / "CM-fields", {})
    monkeypatch.setattr(cm_matrix, "wait", lambda session, seconds: setattr(peer, "now", peer.now + seconds))
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", timeout=32))
    oracle.execute(session, ["cm-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason and (defect != "Next-validates-ignored-protocol" or ".sub-3.zero-protocol" in name) for name, reason in failures), failures[:30]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:30]
        assert not any(row["resident"] for row in peer.records.values())
        assert {(row["parameters"]["subcommand"], name) for row in trace.cases for name in (row["parameters"]["defect"],)} >= {(sub, name) for sub in range(1, 8) for name in ("missing-auth", "empty-auth", "zero-protocol", "valid", "revoked", "expired")}
