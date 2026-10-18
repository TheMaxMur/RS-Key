# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Synthetic biometric storage independently enforces grants, cursors and quota."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_fido_states import CtapPeer


class Peer(CtapPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.templates, self.pending, self.serial = {b"preexisting": "Owner"}, None, 0

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 4:
            status, result = 0, {1: ["FIDO_2_1"], 4: {"bioEnroll": True, "clientPin": True, "pinUvAuthToken": True}, 6: [1, 2]}
        elif wire[0] == 9:
            fields = codec.decode(wire[1:])
            sub, parameters = fields[2], fields.get(3, {})
            message = bytes([1, sub]) + (codec.encode(parameters) if 3 in fields else b"")
            status, result = 0, {}
            if sub not in (3, 7) and (fields.get(4) != self.protocol or fields.get(5) != self.mac(message) or not self.permissions & 8) and self.defect != "bio-auth-bypass":
                status = 0x33
            elif sub == 7:
                result = {2: 1, 3: 2, 8: 64}
            elif sub == 4:
                result = {7: [{1: key, 2: name} for key, name in self.templates.items()]}
            elif sub == 1:
                if self.session.current.parameters.get("biometric_action") == "duplicate-sample":
                    result = {5: 11}
                elif len(self.templates) >= 3:
                    status = 0x17
                elif parameters.get(3) == 1000:
                    result = {5: 13, 6: 2}
                else:
                    self.serial += 1
                    self.pending = self.serial.to_bytes(4, "big")
                    result = {4: self.pending, 5: 0, 6: 1}
            elif sub == 2:
                if self.pending is None or parameters.get(1) != self.pending:
                    status = 0x30
                else:
                    self.templates[self.pending] = ""
                    self.pending = None
                    result = {5: 0, 6: 0}
            elif sub == 3:
                if self.defect != "cancel-keeps-cursor":
                    self.pending = None
            elif sub in (5, 6):
                template = parameters[1]
                if template not in self.templates:
                    status = 0x2e
                elif sub == 6:
                    if self.defect == "delete-neighbor":
                        self.templates.pop(b"preexisting", None)
                    del self.templates[template]
                elif len(parameters[2].encode()) > 64 and self.defect != "name-truncated":
                    status = 3
                else:
                    self.templates[template] = parameters[2][:64]
            else:
                raise AssertionError("unknown synthetic biometric command")
        else:
            return super().transfer(command, wire, deadline, observe)
        output = bytes([status]) + (codec.encode(result) if not status else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,needle", [(None, None), ("bio-auth-bypass", "biometric authorization defect"),
    ("cancel-keeps-cursor", "cancel retires the incomplete"), ("delete-neighbor", "only fixture biometric templates"),
    ("name-truncated", "friendly name beyond advertised")])
def test_biometric_negative_sequences_and_full_store(tmp_path, defect, needle):
    trace = Trace(tmp_path / "biometric", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, profile="generic", options=Options(exercise=True, touch=True, operator=True, pin="fixture-PIN", allow_effects=("capacity",)))
    peer.session = session
    oracle.execute(session, ["bio-matrix"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert peer.templates == {b"preexisting": "Owner"}
