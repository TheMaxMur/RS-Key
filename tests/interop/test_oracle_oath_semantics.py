# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH semantic peers keep independent hash, digit and moving-factor state."""
import hmac

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_apdu_matrix import decode_apdu


def fields(data):
    result = {}
    while data:
        if data[0] == 0x78:
            result[0x78], data = data[1:2], data[2:]
            continue
        tag, length = data[:2]
        if length & 128:
            count = length & 127
            width, length = 2 + count, int.from_bytes(data[2:2 + count], "big")
        else:
            width = 2
        result[tag], data = data[width:width + length], data[width + length:]
    return result


class Peer:
    layer = "pcsc_apdu"

    def __init__(self, defect=None, committed=True):
        self.records, self.defect, self.committed = {}, defect, committed

    def control(self, action, deadline, observe):
        return Reply(b"offline ATR")

    def drop_response(self, request, deadline, observe):
        if self.committed:
            self.transfer(request, deadline, lambda direction, data: observe(direction, data) if direction == "tx" else None)
        else:
            observe("tx", request, evidence="API invoked; peer did not commit")
        raise TransferError("synthetic response lost", Outcome.CANCELLED)

    def calculate(self, record, challenge, full):
        if record["hotp"]:
            challenge = record["counter"].to_bytes(8, "big")
            record["counter"] += 1
        digest = hmac.digest(record["secret"], challenge, record["hash"])
        offset = digest[-1] & 15
        number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** record["digits"])
        payload = digest if full else number.to_bytes(4, "big")
        return codec.tlv(0x75 if full else 0x76, bytes([record["digits"]]) + payload)

    def transfer(self, wire, deadline, observe):
        ins, p1, p2 = wire[1:4]
        data, le = decode_apdu(wire)
        sw, output = 0x9000, b""
        if ins == 0xA4 and p1 == 4:
            output = codec.tlv(0x71, b"offline-id")
        elif ins == 1:
            parsed = fields(data)
            material = parsed[0x73]
            kind, algorithm, digits = material[0] & 0xF0, material[0] & 15, material[1]
            valid = (14 <= len(material[2:]) <= 64 and 6 <= digits <= 8 and kind in (0x10, 0x20) and algorithm in (1, 2, 3)
                     and (0x7A not in parsed or kind == 0x10 and len(parsed[0x7A]) == 4))
            if not valid and self.defect != "accept-invalid-secret":
                sw = 0x6A80
            else:
                self.records[parsed[0x71]] = {"hotp": kind == 0x10, "hash": {1: "sha1", 2: "sha256", 3: "sha512"}.get(algorithm, "sha1"),
                    "digits": digits, "secret": material[2:], "flags": parsed.get(0x78, b"\x00")[0],
                    "counter": int.from_bytes(parsed.get(0x7A, bytes(4)), "big"), "mark": 0}
        elif ins == 2:
            self.records.pop(fields(data)[0x71])
        elif ins == 0xA1:
            output = b"".join(codec.tlv(0x72, bytes([0x11 if item["hotp"] else 0x21]) + name) for name, item in self.records.items())
        elif ins in (0xA2, 0xA4):
            parsed = fields(data)
            challenge = parsed[0x74]
            if len(challenge) > 64:
                sw = 0x6A80
            elif ins == 0xA2:
                record = self.records[parsed[0x71]]
                if not record["hotp"] and record["flags"] & 1 and int.from_bytes(challenge, "big") <= record["mark"]:
                    sw = 0x6A80
                else:
                    output = self.calculate(record, challenge, p2 == 0)
                    record["mark"] = int.from_bytes(challenge, "big")
            else:
                for name, record in self.records.items():
                    output += codec.tlv(0x71, name)
                    if record["hotp"]:
                        output += codec.tlv(0x77, bytes([record["digits"]]))
                    elif record["flags"] & 2:
                        output += codec.tlv(0x7C, bytes([record["digits"]]))
                        if self.defect == "bulk-burns-touch":
                            output = output[:-3] + self.calculate(record, challenge, p2 == 0)
                    else:
                        output += self.calculate(record, challenge, p2 == 0)
                        record["mark"] = int.from_bytes(challenge, "big")
        else:
            raise AssertionError(f"unexpected OATH command {ins}")
        response = output + sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", response)
        return Reply(response, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,expected", [(None, None), ("accept-invalid-secret", "single OATH PUT defect refused"),
                                           ("bulk-burns-touch", "bulk touch record is marked")])
@pytest.mark.parametrize("committed", [False, True])
def test_oath_semantics_and_uncertain_hotp_response_through_dispatch(tmp_path, defect, expected, committed):
    peer = Peer(defect, committed)
    trace = Trace(tmp_path / "OATH-semantics", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True))
    oracle.execute(session, ["oath-semantics"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and not session.broken
        assert any(row["command"] == "oath.injected-response-loss" and row["execution_outcome"] == "cancelled" for row in trace.exchanges)
