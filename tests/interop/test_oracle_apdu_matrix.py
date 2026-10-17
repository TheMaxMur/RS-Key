# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Offline card frames pending responses independently of the scenario helper."""
import os

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


def decode_apdu(wire):
    if len(wire) == 4:
        return b"", 256
    if len(wire) == 5:
        return b"", wire[4] or 256
    extended = wire[4] == 0
    if extended and len(wire) == 7:
        return b"", int.from_bytes(wire[5:7], "big") or 65536
    offset = 7 if extended else 5
    length = int.from_bytes(wire[5:7], "big") if extended else wire[4]
    body, tail = wire[offset:offset + length], wire[offset + length:]
    assert len(body) == length
    return body, (int.from_bytes(tail, "big") or (65536 if extended else 256)) if tail else 256


class Card:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.value, self.pending, self.defect = b"original", b"", defect
        self.authenticated = False

    def transfer(self, wire, deadline, observe):
        ins, p1, p2 = wire[1:4]
        data, le = decode_apdu(wire)
        status, result = 0x9000, b""
        stale_final = False
        if ins == 0xC0:
            if not self.pending:
                status = 0x6D00
            else:
                result = self.pending
                stale_final = len(result) <= le and self.defect == "replay-tail"
                self.pending = result if stale_final else b""
        else:
            if self.defect != "stale-tail-after-reject" or ins != 0xCA or (p1, p2) != (255, 255):
                self.pending = b""
            if ins == 0xA4:
                self.authenticated = False
            elif ins == 0x20:
                self.authenticated = data == b"admin"
                status = 0x9000 if self.authenticated else 0x6982
            elif ins == 0xFD:
                result = b"\x05\x08\x00"
            elif ins == 0xCA:
                if (p1, p2) == (0, 0x5E):
                    result = self.value
                else:
                    status = 0x6B00
            elif ins == 0xDA:
                assert self.authenticated and (p1, p2) == (0, 0x5E)
                self.value = data[:-1] if self.defect == "truncated-Lc" else data
            elif ins == 0x84:
                if le > 3060:
                    status = 0x6700
                else:
                    result = os.urandom(le - 1 if self.defect == "short-challenge" else le)
            else:
                raise AssertionError("unexpected APDU")
        if len(result) > le:
            self.pending, result = result[le:], result[:le]
        if self.pending and result and not stale_final:
            status = 0x6100 | min(255, len(self.pending))
        observe("tx", wire)
        response = result + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("replay-tail", "cannot be replayed"),
    ("stale-tail-after-reject", "retires response tail"), ("truncated-Lc", "writes full declared body"),
    ("short-challenge", "challenge exact requested length")])
def test_iso_cases_and_response_lifetimes_through_dispatch(tmp_path, monkeypatch, defect, expected):
    from yubikit import openpgp
    trace = Trace(tmp_path / "apdu", {})
    card = Card(defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, openpgp_pin="user", openpgp_admin="admin"))
    class Sdk:
        def __init__(self, connection):
            session.select("openpgp")
        def verify_admin(self, value):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=value.encode())))
        def get_data(self, tag):
            reply = session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255))
            value = reply.data[:-2]
            while reply.status >> 8 == 0x61:
                reply = session.apdu(codec.apdu(0xC0, le=256))
                value += reply.data[:-2]
            session.card_value(reply)
            return value
        def put_data(self, tag, value):
            session.card_value(session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, value)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    oracle.execute(session, ["apdu-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert card.value == b"original"
