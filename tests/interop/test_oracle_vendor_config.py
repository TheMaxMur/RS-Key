# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""An incomplete PHY field is a no-op; an incomplete LED block is refused."""
import pytest

from oracle_lib import codec, vendor_cases
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


class Peer:
    layer = "offline_vendor_config"

    def __init__(self, defect):
        self.defect = defect
        self.records = {1: bytes.fromhex("060200000b011f"), 2: bytes(range(17))}

    def transfer(self, command, wire, deadline, observe):
        fields = codec.decode(wire[1:])
        sub, parameters = fields[1], fields[2]
        target = parameters[1]
        status, result = 0, {}
        if sub == 13:
            result = {1: self.records[target]}
        else:
            assert sub == 12
            data = parameters[2]
            if target == 2 and len(data) < 17:
                status = 0 if self.defect == "short-LED-accepted" else 3
            elif target == 1 and data == bytes.fromhex("0482ff"):
                if self.defect == "truncated-PHY-drops-record":
                    self.records[target] = b"\x06\x02\x00\x00"
            else:
                assert data == self.records[target]
        output = bytes([status]) + (codec.encode(result) if not status else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,needle", [(None, None), ("short-LED-accepted", "configuration grammar"),
    ("truncated-PHY-drops-record", "preserved stored config")])
def test_vendor_config_applies_each_record_grammar_without_inventing_PHY_refusal(tmp_path, defect, needle):
    trace = Trace(tmp_path / "vendor-config", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("config_change",)))
    session.values["fido.info"] = {4: {"clientPin": False}}
    vendor_cases.configuration(session)
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
