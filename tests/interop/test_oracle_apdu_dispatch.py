# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A separate dispatcher model exposes empty blocks, malformed cases and ceilings."""
import pytest

import oracle
from oracle_lib import apdu_dispatch, codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_apdu_matrix import decode_apdu


class Card:
    layer = "ccid_message"

    def __init__(self, defect=None):
        self.sequence, self.selected, self.chain, self.header = 0, None, b"", None
        self.value, self.auth, self.defect = b"original owned DO", False, defect

    def dispatch(self, wire):
        if len(wire) < 4:
            return b"\x67\x00"
        cla, ins, p1, p2 = wire[:4]
        try:
            data, le = decode_apdu(wire)
            if len(wire) > 5:
                extended = wire[4] == 0
                offset = 7 if extended else 5
                size = int.from_bytes(wire[5:7], "big") if extended else wire[4]
                assert len(wire) - offset - size in ((0, 2) if extended else (0, 1))
        except (AssertionError, IndexError):
            return b"\x67\x00"
        if not cla & 0x10 and cla not in (0, 4, 0x80, 0x84):
            if self.defect == "fabricated-class-status":
                return b"\x6e\x00"
            if self.defect == "silent-class-abandons-chain":
                self.chain, self.header = b"", None
            return b""
        if cla in (4, 0x84) and not (ins == 0xa4 and p1 == 4):
            return b"\x6e\x00"
        header = (cla & ~0x10, ins, p1, p2)
        if cla & 0x10:
            if self.header is not None and self.header != header:
                self.chain, self.header = b"", None
                return b"\x68\x83"
            self.header = header
            self.chain += data
            if len(self.chain) >= 3072:
                self.chain, self.header = b"", None
                return b"\x67\x00" if self.defect != "chain-overflow-object-error" else b"\x6a\x80"
            return b"\x90\x00"
        if ins == 0xa4 and p1 == 4:
            self.chain, self.header = b"", None
            for name, aid in AIDS.items():
                if data and aid.startswith(data):
                    self.selected = name
                    return b"\x90\x00"
            return b"\x6a\x82"
        if self.header is not None:
            if self.header != header:
                self.chain, self.header = b"", None
                return b"\x68\x83"
            data, self.chain, self.header = self.chain + data, b"", None
            if len(data) > 3072:
                return b"\x67\x00"
        if self.selected == "rescue" and cla != 0x80:
            return b"\x6e\x00"
        if ins in (0x7e, 0x7f):
            return b"\x6d\x00"
        if self.selected == "openpgp":
            if ins == 0x20:
                self.auth = data == b"12345678"
            elif ins == 0xda:
                if not self.auth:
                    return b"\x69\x82"
                if len(data) > 2048:
                    return b"\x6a\x80" if self.defect != "object-overflow-chain-error" else b"\x67\x00"
                self.value = data
            elif ins == 0xca and (p1, p2) == (0, 0x5e):
                return self.value + b"\x90\x00"
            elif ins == 0x84:
                return b"x" * le + b"\x90\x00"
        if (ins, p1, p2, data) == apdu_dispatch.READS[self.selected]:
            return self.selected.encode() + b"\x90\x00"
        return b"\x90\x00"

    def transfer(self, wire, deadline, observe):
        observe("tx", wire)
        output = self.dispatch(wire)
        observe("rx", output)
        status = int.from_bytes(output[-2:], "big")
        return Reply(output, "success" if status == 0x9000 else "applet_error", status)

    def raw(self, wire, deadline, observe):
        observe("tx", wire)
        data = self.dispatch(wire[10:])
        kind, status, error = (0x81, 0x40, 1) if len(wire[10:]) < 4 else (0x80, 0, 0)
        if error:
            data = b""
        output = bytes([kind]) + len(data).to_bytes(4, "little") + bytes([0, wire[6], status, error, 0]) + data
        observe("rx", output)
        return output


@pytest.mark.parametrize("defect,needle", [(None, None), ("fabricated-class-status", "actual empty DataBlock"),
    ("silent-class-abandons-chain", "own accumulated prefix"), ("chain-overflow-object-error", "chain ceiling"),
    ("object-overflow-chain-error", "chain ceiling")])
def test_each_applet_class_and_encoding_and_distinct_chain_object_bounds(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    card = Card(defect)
    trace = Trace(tmp_path / "APDU-dispatch", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, openpgp_admin="12345678", openpgp_pin="123456"))
    class Sdk:
        def __init__(self, connection):
            session.select("openpgp")
        def verify_admin(self, pin):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=pin.encode())))
        def get_data(self, tag):
            return session.card_value(session.apdu(codec.apdu(0xca, tag >> 8, tag & 255)))
        def put_data(self, tag, value):
            return session.card_value(session.apdu(codec.apdu(0xda, tag >> 8, tag & 255, value)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    monkeypatch.setattr(apdu_dispatch, "wait", lambda session, seconds: None)
    if defect:
        if defect == "fabricated-class-status":
            monkeypatch.setattr(apdu_dispatch, "READS", {"piv": apdu_dispatch.READS["piv"]})
            monkeypatch.setattr(apdu_dispatch, "chains", lambda session: None)
        else:
            monkeypatch.setattr(apdu_dispatch, "classes", lambda session: None)
            monkeypatch.setattr(apdu_dispatch, "grammar", lambda session: None)
    oracle.execute(session, ["apdu-dispatch"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert card.value == b"original owned DO" and card.header is None
