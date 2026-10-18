# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""MSE cases use genuine AEAD and independent PIN and channel state."""
import pytest

import oracle
from oracle_lib import codec, vendor_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_pin_matrix import PinPeer
from test_oracle_vendor import VendorPeer


class MatrixPeer(PinPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.mse_peer, self.channel_defect = VendorPeer(), defect
        self.initial_seed = self.mse_peer.seed

    def transfer(self, command, wire, deadline, observe):
        if wire[0] not in (0x41, 13):
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, parameters = fields[1], fields.get(2, {})
        status, result = 0, {}
        if wire[0] == 13:
            status = 0x3E
        elif sub == 15:
            from oracle_lib.vendor_lifecycle import AUT_ENABLE, AUT_DISABLE
            from oracle_lib.enterprise import EA_RPIDS
            result = {1: [AUT_ENABLE, AUT_DISABLE, EA_RPIDS]}
        elif sub == 11:
            result = {1: False}
        elif sub == 5:
            result = {1: False, 2: True, 3: False}
        elif sub == 1:
            if self.mse_peer.channel:
                return self.mse_peer.transfer(command, wire, deadline, observe)
            point = parameters.get(1, {})
            if not point.get(-2) or not point.get(-3):
                status = 0x14
            elif 2 in parameters and len(parameters[2]) == 1184 and any(
                (int.from_bytes(parameters[2][offset:offset + 3], "little") & 4095) >= 3329 or
                (int.from_bytes(parameters[2][offset:offset + 3], "little") >> 12) >= 3329 for offset in range(0, 1152, 3)):
                status = 0x02
            else:
                return self.mse_peer.transfer(command, wire, deadline, observe)
        elif sub in (2, 3, 6, 9, 10):
            channel = self.mse_peer.channel
            if self.channel_defect != "retain-after-refusal":
                self.mse_peer.channel = None
            if channel is None:
                status = 0x30
            elif sub != 6:
                payload = b"\xff" * 32 + b"\x41" + bytes([sub]) + (codec.encode(parameters) if 2 in fields else b"")
                if fields.get(3) not in (1, 2):
                    status = 0x14 if 3 not in fields else 0x02
                elif fields.get(4) != self.mac(payload) or not self.permissions & 32:
                    status = 0x33
            if not status:
                if sub == 2:
                    self.mse_peer.channel = channel
                    return self.mse_peer.transfer(command, wire, deadline, observe)
                if sub in (3, 6, 9):
                    status = 0x3D
                else:
                    result = {}
            if status and self.channel_defect == "failure-mutates-seed":
                self.mse_peer.seed = bytes(32)
        else:
            raise AssertionError(f"unexpected vendor command {sub}")
        output = bytes([status]) + (codec.encode(result) if not status else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("retain-after-refusal", "refusal spends"),
                                           ("failure-mutates-seed", "preserves")])
def test_mse_failures_are_checked_with_fresh_channel_and_exact_seed(tmp_path, defect, expected):
    peer = MatrixPeer(defect)
    trace = Trace(tmp_path / "vendor-semantic", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("seed_change", "replace_identity")))
    oracle.execute(session, ["vendor-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_mode" for row in trace.cases), trace.cases
        assert peer.mse_peer.seed == peer.initial_seed
