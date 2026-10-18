# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Both route directions need populated continuations and usable original grants."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_cursor_matrix import Card as BaseCard, Peer as CursorPeer
from test_oracle_expanded import apdu_parts


class Card(BaseCard):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4 and body == b"\xf0\xff\xff\xff\xff":
            from oracle_lib.trace import Reply
            observe("tx", wire)
            observe("rx", b"\x6a\x82")
            return Reply(b"\x6a\x82", "applet_error", 0x6a82)
        if ins == 0xa4 and self.peer.defect == "SELECT-drops-walk":
            self.peer.ga, self.peer.kind = [], None
        return super().transfer(wire, deadline, observe)


class Peer(CursorPeer):
    def credential_management(self, fields):
        previous = self.protocol
        try:
            self.protocol = fields.get(3, previous)
            return super().credential_management(fields)
        finally:
            self.protocol = previous

    def transfer(self, command, wire, deadline, observe):
        foreign = self.cid == bytes(4)
        if self.defect == "card-token-isolated" and foreign and wire[0] == 10:
            fields = codec.decode(wire[1:])
            if fields[1] == 1:
                from oracle_lib.trace import Reply
                return Reply(b"\x33", "applet_error", 0x33)
        result = super().transfer(command, wire, deadline, observe)
        if self.defect == "foreign-refusal-drops-walk" and result.status == 0x30:
            self.ga, self.kind = [], None
        return result


@pytest.mark.parametrize("defect,needle", [(None, None), ("foreign-CID-continues", "cannot inherit a populated"),
    ("foreign-refusal-drops-walk", "CTAP success"), ("card-token-isolated", "CTAP success"), ("SELECT-drops-walk", "CTAP success")])
def test_bidirectional_token_scope_and_each_populated_walk(tmp_path, defect, needle):
    trace = Trace(tmp_path / "cross-walks", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, card=Card(peer), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["cross-walks"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert len(trace.cases) == 96 and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert not peer.records
