# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Command-level OATH guards are checked with populated private records and counters."""
import pytest

import oracle
from oracle_lib import oath_commands
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_pin_matrix import Peer as PinPeer


class Peer(PinPeer):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4 and p1 == 4:
            return super().transfer(wire, deadline, observe)
        sw = None
        if wire[0] != 0 and self.defect != "class-bypass":
            sw = 0x6e00
        elif self.defect != "parameter-bypass":
            permitted = ((p1, p2) == (0xde, 0xad)) if ins == 4 else (p1 == 0 and p2 in (0, 1)) if ins in (0xa2, 0xa4) else p1 == 0 or p2 == 0 if ins == 0xa3 else True if ins == 0xa5 else (p1, p2) == (0, 0)
            if not permitted:
                sw = 0x6b00
        if sw is None and ins == 0xa5:
            sw = 0x6d00
        if sw is None and ins not in (4, 0xa3, 0xb2, 0xb3) and not self.validated:
            sw = 0x6982
        if sw is not None:
            result = sw.to_bytes(2, "big")
            observe("tx", wire)
            observe("rx", result)
            return Reply(result, "applet_error", sw)
        result = super().transfer(wire, deadline, observe)
        if ins == 0xb2 and result.status == 0x9000 and self.defect == "PIN-opens-code":
            self.validated = True
        return result


@pytest.mark.parametrize("defect,needle", [(None, None), ("class-bypass", "known OATH command validates class"),
    ("parameter-bypass", "known OATH command validates class"), ("PIN-opens-code", "OTP-PIN cannot open the access-code gate")])
def test_OATH_command_parameter_and_authorization_matrix(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(oath_commands, "PARAMETERS", (0, 1, 2))
    trace = Trace(tmp_path / "OATH-commands", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("pin_change", "applet_reset", "config_change")))
    oracle.execute(session, ["oath-commands"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and not peer.extras and peer.pin is None
