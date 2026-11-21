# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""MSE peers share cryptographic state while keeping explicit route/CID ownership."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_token_matrix import Peer as PinPeer
from test_oracle_vendor import VendorPeer


class Peer(PinPeer):
    def __init__(self, defect):
        super().__init__()
        self.mse, self.owner, self.fault = VendorPeer(), None, defect
        self.cid = b"test"
        self.on_keepalive = self.on_report = None
        self.ephemeral = 42

    def send_only(self, *args):
        raise AssertionError("offline scope test never sends unobserved frames")

    def handle(self, route, wire, deadline, observe):
        if wire[0] not in (0x41, 13):
            return super().transfer(0x10, wire, deadline, observe)
        try:
            fields = codec.decode(wire[1:])
        except (ValueError, TypeError):
            if self.fault == "parse-refusal-spends-channel":
                self.mse.channel = None
            return Reply(b"\x12", "applet_error", 0x12)
        sub, params = fields.get(1), fields.get(2, {})
        if type(sub) is not int or not isinstance(params, dict) or 3 in fields and type(fields[3]) is not int or 4 in fields and not isinstance(fields[4], bytes):
            if self.fault == "parse-refusal-spends-channel":
                self.mse.channel = None
            return Reply(b"\x11", "applet_error", 0x11)
        if wire[0] == 13:
            channel = self.mse.channel
            self.mse.channel = None
            status = 2 if channel is not None and (self.owner == route or self.fault == "foreign-channel-owner") else 0x30
            result = {}
        elif sub in (1, 2):
            if sub == 1:
                self.owner = route
                if self.mse.channel is None and self.fault != "reuses-MSE-ephemeral":
                    self.ephemeral += 1
                    self.mse.device_key = ec.derive_private_key(self.ephemeral, ec.SECP256R1())
            if sub == 2 and self.owner != route and self.fault != "foreign-channel-owner":
                self.mse.channel = None
                status, result = 0x30, {}
            else:
                return self.mse.transfer(0x10, wire, deadline, observe)
        elif sub == 5:
            status, result = 0, {1: False, 2: True, 3: False, 4: False, 5: False}
        elif sub == 11:
            status, result = 0, {1: False}
        elif sub in (3, 6, 9, 10):
            channel = self.mse.channel
            if self.fault != "consumer-retains-channel":
                self.mse.channel = None
            valid_owner = self.owner == route or self.fault == "foreign-channel-owner"
            status = 0x30 if channel is None or not valid_owner else 0x3d if sub == 3 else 0 if sub == 10 else 2
            result = {}
        else:
            raise AssertionError("unprofiled MSE lifetime request")
        output = bytes([status]) + (codec.encode(result) if not status else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)

    def transfer(self, *args):
        if len(args) == 4:
            command, wire, deadline, observe = args
            if command == 6:
                return Reply(wire + b"more" + bytes(5))
            return self.handle(("hid", self.cid), wire, deadline, observe)
        wire, deadline, observe = args
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4:
            return Reply(b"\x90\x00", status=0x9000)
        assert ins == 0x10
        reply = self.handle(("card", b"\x00" * 4), data, deadline, observe)
        return Reply(reply.data + b"\x90\x00", status=0x9000)


@pytest.mark.parametrize("defect,needle", [(None, None), ("consumer-retains-channel", "spends MSE"),
    ("foreign-channel-owner", "owner/foreign-channel outcome"), ("parse-refusal-spends-channel", "CTAP success"),
    ("reuses-MSE-ephemeral", "reuse its device ephemeral")])
def test_every_MSE_consumer_route_CID_and_parser_boundary_uses_the_original_crypto_channel(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "MSE-lifetimes", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("seed_change", "replace_identity", "config_change")))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["mse-lifetimes"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
