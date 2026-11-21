# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A typed peer rejects wire widths before authentication or state mutation."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as PinPeer


class Peer(PinPeer):
    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 4: {"clientPin": True, "credMgmt": True, "pinUvAuthToken": True, "largeBlobs": True, "authnrCfg": True}, 6: [1, 2]}
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        fields = codec.decode(wire[1:])
        op = wire[0]
        unsigned = [fields[key] for key in ({1: (9, 10), 2: (7,), 6: (1, 2, 9), 10: (1, 3), 13: (1, 3), 0x41: (1, 3)}.get(op, ())) if key in fields]
        if op == 13 and isinstance(fields.get(2), dict) and fields.get(1) == 3:
            unsigned.append(fields[2][1])
        if op == 0x41 and fields.get(1) in (12, 13, 14):
            unsigned.append(fields[2][1])
        wide = [fields[key] for key in (1, 3, 4, 6) if key in fields] if op == 12 else []
        if op == 13 and fields.get(1) == 255:
            wide.extend(fields[2][key] for key in (1, 3))
        signed = [row["alg"] for row in fields.get(4, [])] if op == 1 else []
        status = 0x11 if any(value < 0 for value in (*unsigned, *wide)) else 0x12 if any(value > 0xffffffff for value in unsigned) or any(not -(1 << 63) <= value < 1 << 63 for value in signed) else 0
        if status:
            if self.defect == "accepts-negative" and status == 0x11 or self.defect == "truncates-u32" and status == 0x12:
                status = 0x33
            if self.defect == "numeric-refusal-deletes-key":
                self.records.clear()
            output = bytes([status])
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "applet_error", status)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("accepts-negative", "reject before semantic"),
    ("truncates-u32", "reject before semantic"), ("numeric-refusal-deletes-key", "CTAP success")])
def test_all_typed_integer_fields_have_width_signedness_and_private_recovery_controls(tmp_path, defect, needle):
    trace = Trace(tmp_path / "numeric", {})
    session = Session(trace, hid=Peer(defect), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["numeric-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:15]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:15]
