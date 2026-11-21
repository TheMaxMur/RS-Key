# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Offline OATH state and page peer with deliberate counter/cursor defects."""
import hmac

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_apdu_matrix import decode_apdu


class Card:
    layer, emulated = "pcsc_apdu", True

    def __init__(self, defect=None):
        self.defect, self.records, self.pending = defect, {}, b""

    def control(self, action, deadline, observe):
        if self.defect == "power-clears-counter":
            for row in self.records.values():
                row["counter"] = 0
        return Reply(b"offline ATR")

    def code(self, record, challenge):
        if record["hotp"]:
            challenge = record["counter"].to_bytes(8, "big")
            record["counter"] += 1
        digest = hmac.digest(record["secret"], challenge, "sha1")
        offset = digest[-1] & 15
        value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1000000
        return codec.tlv(0x76, b"\x06" + value.to_bytes(4, "big"))

    def transfer(self, wire, deadline, observe):
        ins, p1, p2 = wire[1:4]
        data, le = decode_apdu(wire)
        status, result = 0x9000, b""
        if ins != 0xA5 and not (self.defect == "stale-cursor" and ins == 0xA2 and not data):
            self.pending = b""
        if ins == 0xA4 and p1 == 4:
            result = codec.tlv(0x71, b"offline-id")
        elif ins == 1:
            increasing = data.endswith(b"\x78\x01")
            fields = dict(codec.parse_tlv(data[:-2] if increasing else data))
            key = fields[0x73]
            self.records[fields[0x71]] = {"hotp": key[0] == 0x11, "counter": int.from_bytes(fields.get(0x7A, bytes(4)), "big"),
                                        "secret": key[2:], "increasing": increasing, "mark": 0}
        elif ins == 2:
            del self.records[dict(codec.parse_tlv(data))[0x71]]
        elif ins == 0xA1:
            result = b"".join(codec.tlv(0x72, bytes([0x11 if row["hotp"] else 0x21]) + name) for name, row in self.records.items())
        elif ins in (0xA2, 0xA4):
            fields = dict(codec.parse_tlv(data))
            challenge = fields.get(0x74)
            if challenge is None or len(challenge) > 64:
                status = 0x6A80
            elif ins == 0xA2:
                record = self.records[fields[0x71]]
                number = int.from_bytes(challenge, "big")
                if record["increasing"] and (number < record["mark"] or number == record["mark"] and self.defect != "accept-equal-mark"):
                    status = 0x6A80
                else:
                    result = self.code(record, challenge)
                    record["mark"] = max(record["mark"], number)
            else:
                for name, row in self.records.items():
                    result += codec.tlv(0x71, name)
                    if row["hotp"]:
                        result += codec.tlv(0x77, b"\x06")
                        if self.defect == "bulk-burns-HOTP":
                            row["counter"] += 1
                    else:
                        result += self.code(row, challenge)
                        if row["increasing"]:
                            row["mark"] = int.from_bytes(challenge, "big")
        elif ins == 0xA5:
            if not self.pending:
                status = 0x6D00
            else:
                result, self.pending = self.pending, b""
        else:
            raise AssertionError("unexpected OATH operation")
        if len(result) > le:
            self.pending, result = result[le:], result[:le]
            status = 0x6100 | min(255, len(self.pending))
        observe("tx", wire)
        response = result + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("bulk-burns-HOTP", "HOTP counter survives refusal"),
    ("accept-equal-mark", "equal and lower increasing challenges refused"), ("stale-cursor", "retired OATH page cannot be continued"),
    ("power-clears-counter", "HOTP counter survives refusal")])
def test_oath_state_boundaries_through_dispatch(tmp_path, defect, expected):
    trace = Trace(tmp_path / "oath", {})
    card = Card(defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, allow_effects=("reboot",)))
    oracle.execute(session, ["oath-matrix", "oath-reconnect"])
    trace.finish()
    failed = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failed), failed
    else:
        assert not failed and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert not card.records
