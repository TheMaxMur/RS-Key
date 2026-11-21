# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The separate device-PIN gate has its own entries and persistent retry record."""
import pytest

import oracle
from oracle_lib import codec, vendor_local_pin
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_audit_access import Peer as AuditPeer
from test_oracle_expanded import apdu_parts
from test_oracle_vendor import VendorPeer


class Peer(AuditPeer):
    def __init__(self, headless, fault):
        super().__init__(False, None)
        self.headless, self.fault, self.mode = headless, fault, "correct-device-PIN"
        self.device_retries, self.mse = 8, VendorPeer()

    def handle(self, command, wire, deadline, observe):
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, params = fields[1], fields.get(2, {})
        if sub == 1:
            return self.mse.transfer(command, wire, deadline, observe)
        if sub == 5:
            output = b"\x00" + codec.encode({1: False, 2: True, 3: False, 4: False, 5: False})
        elif sub == 11:
            output = b"\x00" + codec.encode({1: False})
        elif sub == 13:
            output = b"\x00" + codec.encode({1: bytes(range(17))})
        elif sub == 14 and params.get(1) == 2:
            return super().transfer(command, wire, deadline, observe)
        else:
            channel = self.mse.channel
            if sub in (2, 3, 9, 10):
                self.mse.channel = None
            if sub in (2, 3, 9, 10) and channel is None:
                status = 0x30
            elif self.headless:
                status = 0x36
            elif self.mode != "correct-device-PIN" and self.fault != "local-gate-bypass":
                status = {"wrong-device-PIN-once": 0x31, "decline-pad": 0x27, "cancel-pad": 0x2d, "timeout-pad": 0x2f}[self.mode]
                if self.mode == "wrong-device-PIN-once":
                    self.device_retries -= 1
                    if self.fault == "spends-host-PIN":
                        self.remaining -= 1
            else:
                status, self.device_retries = 0, 8
            if status:
                if self.fault == "refusal-deletes-private-keys":
                    self.records.clear()
                output = bytes([status])
            elif sub in (7, 8, 14):
                return super().transfer(command, wire, deadline, observe)
            elif sub == 2:
                self.mse.channel = channel
                return self.mse.transfer(command, wire, deadline, observe)
            elif sub in (3, 9):
                output = bytes([0x3d if sub == 3 else 2])
            elif sub in (10, 12):
                output = b"\x00"
            else:
                raise AssertionError("unprofiled successful local-PIN mutation")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if output[0] == 0 else "applet_error", output[0])

    def transfer(self, *args):
        if len(args) == 4:
            return self.handle(*args)
        wire, deadline, observe = args
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4:
            return Reply(b"\x90\x00", status=0x9000)
        assert ins == 0x10
        result = self.handle(0x10, data, deadline, observe)
        return Reply(result.data + b"\x90\x00", status=0x9000)


@pytest.mark.parametrize("headless,fault,needle", [(False, None, None), (True, None, None),
    (False, "local-gate-bypass", "exact refusal/continuation"), (False, "spends-host-PIN", "host PIN retry record"),
    (False, "refusal-deletes-private-keys", "CTAP success")])
def test_vendor_local_PIN_is_independent_of_getInfo_UV_and_the_host_PIN_reference(tmp_path, monkeypatch, headless, fault, needle):
    peer = Peer(headless, fault)
    trace = Trace(tmp_path / "vendor-device-PIN", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        timeout=131, device_pin_state="set", features=("headless" if headless else "display", "strict-config"),
        allow_effects=("pin_attempts", "seed_change", "replace_identity", "config_change")))
    original = vendor_local_pin.cue
    def cue(session, mode):
        peer.mode = mode
        original(session, mode)
    monkeypatch.setattr(vendor_local_pin, "cue", cue)
    oracle.execute(session, ["vendor-local-pin"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert peer.device_retries == 8 and peer.remaining == 8
