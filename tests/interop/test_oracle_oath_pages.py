# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent page buffering detects stale continuations and cross-grant effects."""
import pytest

import oracle
from oracle_lib.trace import Reply, Trace
from oracle_lib.runner import Options, Session
from test_oracle_apdu_matrix import decode_apdu
from test_oracle_expanded import apdu_parts
from test_oracle_oath_commands import Peer as CommandPeer


class Peer(CommandPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.pending = b""

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        _, le = decode_apdu(wire)
        if ins == 0xa4 and p1 == 4 and body == b"\xf0\xff\xff\xff\xff":
            if self.defect == "invalid-SELECT-retires-page":
                self.pending = b""
            observe("tx", wire)
            observe("rx", b"\x6a\x82")
            return Reply(b"\x6a\x82", "applet_error", 0x6a82)
        if wire[0] == 0 and ins != 0xa5 and self.defect != "stale-page":
            self.pending = b""
        if wire[0] != 0 and self.defect == "class-retires-page":
            self.pending = b""
        if ins == 0xa5:
            sw = 0x9000 if self.pending else 0x6d00
            output, self.pending = self.pending[:le or 256], self.pending[le or 256:]
            if self.pending:
                sw = 0x6100 | min(len(self.pending), 255)
            observe("tx", wire)
            observe("rx", output + sw.to_bytes(2, "big"))
            return Reply(output + sw.to_bytes(2, "big"), "success" if sw == 0x9000 else "continuation" if sw >> 8 == 0x61 else "applet_error", sw)
        if ins == 0xff and wire[0] == 0:
            observe("tx", wire)
            observe("rx", b"\x6d\x00")
            return Reply(b"\x6d\x00", "applet_error", 0x6d00)
        emissions = []
        reply = super().transfer(wire, deadline, lambda direction, data: emissions.append((direction, data)))
        output, sw = reply.data[:-2], reply.status
        if ins in (0xa1, 0xa4) and p1 != 4 and sw == 0x9000 and le is not None and len(output) > le:
            output, self.pending = output[:le], output[le:]
            sw = 0x6100 | min(len(self.pending), 255)
        if ins == 0xa3 and reply.status == 0x6a80 and self.defect == "bad-proof-clears-PIN":
            self.pin_verified = False
        observe("tx", wire)
        observe("rx", output + sw.to_bytes(2, "big"))
        return Reply(output + sw.to_bytes(2, "big"), "success" if sw == 0x9000 else "continuation" if sw >> 8 == 0x61 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("stale-page", "retired or exhausted page cannot be resumed"),
    ("class-retires-page", "APDU success"), ("invalid-SELECT-retires-page", "APDU success"), ("bad-proof-clears-PIN", "independent private-record grant")])
def test_page_authorization_retirement_and_exact_reconstruction(tmp_path, defect, needle):
    trace = Trace(tmp_path / "OATH-pages", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        allow_effects=("pin_change", "applet_reset", "config_change")))
    oracle.execute(session, ["oath-pages"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and peer.pin is None
