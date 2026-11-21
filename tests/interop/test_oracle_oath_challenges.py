# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The two challenge readers are distinguished by independently parsed wire bytes."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_pin_matrix import Peer as PinPeer


def first(data):
    if len(data) < 2:
        raise ValueError("short TLV")
    tag, length = data[:2]
    offset = 2
    if length & 128:
        width = length & 127
        if width not in (1, 2) or len(data) < 2 + width:
            raise ValueError("bad length")
        length = int.from_bytes(data[2:2 + width], "big")
        offset += width
    if offset + length > len(data):
        raise ValueError("short value")
    return tag, data[offset:offset + length], data[offset + length:]


class Peer(PinPeer):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins not in (0xa2, 0xa4) or ins == 0xa4 and p1 == 4:
            return super().transfer(wire, deadline, observe)
        sw, canonical = 0x9000, b""
        if not self.validated:
            sw = 0x6982
        else:
            try:
                if ins == 0xa2:
                    tag, name, data = first(data)
                    if tag != 0x71:
                        raise ValueError("name first")
                    canonical += codec.tlv(tag, name)
                tag, challenge, tail = first(data)
                if tag != 0x74 or len(challenge) > 64 or ins == 0xa2 and tail and self.defect != "individual-ignores-tail":
                    raise ValueError("challenge grammar")
                if ins == 0xa4 and tail and self.defect == "bulk-rejects-tail":
                    raise ValueError("over-strict bulk grammar")
                canonical += codec.tlv(tag, challenge)
            except ValueError:
                sw = 0x6a80
        if sw != 0x9000:
            observe("tx", wire)
            observe("rx", sw.to_bytes(2, "big"))
            return Reply(sw.to_bytes(2, "big"), "applet_error", sw)
        reply = super().transfer(codec.apdu(ins, p1=p1, p2=p2, data=canonical), deadline,
            lambda direction, value: observe(direction, wire if direction == "tx" else value))
        if self.defect == "challenge-revokes-PIN":
            self.pin_verified = False
        return reply


@pytest.mark.parametrize("defect,needle", [(None, None), ("individual-ignores-tail", "enforces code authorization before its own grammar"),
    ("bulk-rejects-tail", "enforces code authorization before its own grammar"), ("challenge-revokes-PIN", "cannot invent or revoke private-record grants")])
def test_individual_and_bulk_challenge_grammar_and_authorization(tmp_path, defect, needle):
    trace = Trace(tmp_path / "OATH-challenges", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        allow_effects=("pin_change", "applet_reset", "config_change")))
    oracle.execute(session, ["oath-challenges"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and peer.pin is None
