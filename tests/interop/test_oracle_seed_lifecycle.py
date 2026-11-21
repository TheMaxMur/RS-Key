# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Seed migration is exercised over real ECDH/AEAD and signed credential wires."""
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_extensions import ExtensionPeer
from test_oracle_vendor import VendorPeer


class Peer(ExtensionPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.vendor, self.sealed = VendorPeer(), False

    def transfer(self, command, request, deadline, observe):
        if request[0] == 4:
            return self.vendor.transfer(command, request, deadline, observe)
        if request[0] in (1, 2):
            fields = codec.decode(request[1:])
            if request[0] == 2:
                record = self.records.get(fields[3][0]["id"])
                if record and record["seed"] != self.vendor.seed and self.defect != "old-credential-bypass":
                    observe("tx", request)
                    observe("rx", b"\x2e")
                    return Reply(b"\x2e", "applet_error", 0x2E)
            reply = super().transfer(command, request, deadline, observe)
            if request[0] == 1:
                for record in self.records.values():
                    record.setdefault("seed", self.vendor.seed)
            return reply
        fields = codec.decode(request[1:])
        sub, status, value = fields[1], 0, {}
        if sub == 3:
            if self.vendor.channel is None:
                status = 0x30
            else:
                key, aad = self.vendor.channel
                self.vendor.channel = None
                blob = fields[2][1]
                try:
                    seed = ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
                    if self.defect != "load-noop":
                        self.vendor.seed = seed
                except InvalidTag:
                    status = 0 if self.defect == "invalid-AEAD-accepted" else 0x3D
        elif sub == 5:
            value = {1: self.sealed, 2: True, 3: False, 4: False}
        elif sub == 4:
            self.sealed = True
        elif sub == 2 and self.sealed:
            status, self.vendor.channel = 0x30, None
        else:
            return self.vendor.transfer(command, request, deadline, observe)
        observe("tx", request)
        encoded = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("rx", encoded)
        return Reply(encoded, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("load-noop", "fixture seed exports exactly"),
    ("invalid-AEAD-accepted", "bad seed AEAD has integrity failure"), ("old-credential-bypass", "rejects old wrapped credential")])
def test_seed_lifecycle_dispatch_and_restoration(tmp_path, defect, expected):
    peer = Peer(defect)
    original = peer.vendor.seed
    trace = Trace(tmp_path / "seed", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("seed_change",)))
    oracle.execute(session, ["vendor-lifecycle"])
    trace.finish()
    rows = [row for row in trace.cases if row["scenario_id"].startswith("rsk.seed.")]
    failures = [row for row in rows if row["verdict"] == "fail"]
    if expected is None:
        assert not failures and all(row["verdict"] == "pass" for row in rows), rows
    else:
        assert any(expected in row["reason"] for row in failures), failures
    assert peer.vendor.seed == original
