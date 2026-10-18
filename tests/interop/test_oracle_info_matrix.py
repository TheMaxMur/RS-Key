# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Discovery consistency and connection lifetimes use independently held EC state."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import binding, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from oracle_lib.transport import HID_INIT
from test_oracle_pin_matrix import PinPeer


class Peer(PinPeer):
    cid = b"\x01\x02\x03\x04"

    def transfer(self, command, wire, deadline, observe):
        if command == HID_INIT:
            if self.defect == "INIT-rotates-agreement":
                self.private = ec.derive_private_key(self.generation + 1000, ec.SECP256R1())
            output = wire + self.cid + bytes([2, 5, 8, 0, 5])
        elif wire[0] == 4:
            value = {1: ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"], 2: ["largeBlobKey"], 3: bytes(16),
                4: {"clientPin": True, "rk": True, "credMgmt": True, "pinUvAuthToken": True}, 5: 7609, 6: [1, 2],
                9: ["usb"], 10: [{"type": "public-key", "alg": -7}], 13: 4, 29: 63}
            if self.defect == "invented-version":
                value[1].append("FIDO_2_2")
            output = b"\x00" + codec.encode(value)
        else:
            return super().transfer(command, wire, deadline, observe)
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0 if command != HID_INIT else None)


class Card:
    emulated, layer = True, "pcsc_apdu"

    def __init__(self, hid):
        self.hid = hid

    def transfer(self, request, deadline, observe):
        assert request[1] == 0xa4
        observe("tx", request)
        observe("rx", b"\x90\x00")
        return Reply(b"\x90\x00", status=0x9000)

    def control(self, action, deadline, observe):
        if action == "power_cycle" and self.hid.defect != "power-retains-agreement":
            self.hid.private = ec.generate_private_key(ec.SECP256R1())
        return Reply(b"synthetic ATR")


@pytest.mark.parametrize("defect,needle", [(None, None), ("invented-version", "RS-Key version strings"),
    ("INIT-rotates-agreement", "agreement lifetime follows power"), ("power-retains-agreement", "agreement lifetime follows power")])
def test_discovery_consistency_and_key_agreement_connection_state(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(binding, "check_pair", lambda session: None)
    peer = Peer(defect)
    trace = Trace(tmp_path / "info", {})
    session = Session(trace, hid=peer, card=Card(peer), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("reboot",)))
    oracle.execute(session, ["info-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
