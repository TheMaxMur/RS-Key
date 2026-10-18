# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Audit peers independently authenticate, journal and sign each checkpoint."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import audit_access, binding, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_config_matrix import Peer as PinPeer


class Peer(PinPeer):
    def __init__(self, configured, defect):
        super().__init__()
        if not configured:
            self.pin_value = None
        self.fault, self.enabled, self.confirmed = defect, False, True
        self.entries, self.anchor = [], hashlib.sha256(b"offline audit genesis").digest()
        self.key = ec.derive_private_key(89, ec.SECP256R1())

    def append(self, event, aux=0):
        if self.enabled:
            self.entries.append(len(self.entries).to_bytes(4, "little") + bytes(4) + bytes([event, aux]) + bytes(10))

    def control(self, action, deadline, observe):
        if self.fault == "connection-loses-audit":
            self.enabled, self.entries = False, []
        return Reply(b"offline ATR")

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, params = fields[1], fields.get(2, {})
        status, result = 0, {}
        ungated = sub == 14 and params.get(1) == 2
        if self.pin_value is not None and not ungated and self.fault != "audit-auth-bypass":
            if 3 in fields and fields[3] not in (1, 2):
                status = 2
            elif 4 not in fields:
                status = 0x36
            elif 3 not in fields:
                status = 0x14
            else:
                message = b"\xff" * 32 + bytes([0x41, sub]) + (codec.encode(params) if 2 in fields else b"")
                mac = hmac.digest(self.token, message, "sha256")[:16 if fields[3] == 1 else 32]
                if fields[4] != mac or not self.permissions & 32:
                    status = 0x33
        needs_touch = sub in (8, 14) or sub == 7 and self.pin_value is None
        if not status and not ungated and needs_touch and not self.confirmed and self.fault != "audit-ignores-decline":
            status = 0x27
        if not status:
            if sub == 7:
                result = {1: 0, 2: len(self.entries), 3: self.anchor, 4: b"".join(self.entries)}
            elif sub == 8:
                nonce = params.get(1, b"")
                if len(nonce) > 32:
                    status = 2
                else:
                    head = self.anchor
                    for entry in self.entries:
                        head = hashlib.sha256(head + entry).digest()
                    seq = len(self.entries)
                    message = b"RSK-AUDIT-CKPT-v1" + head + seq.to_bytes(4, "little") + (b"" if self.fault == "nonce-not-bound" else nonce)
                    result = {1: head, 2: seq, 3: self.key.sign(message, ec.ECDSA(hashes.SHA256())),
                        4: self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)}
                    self.append(0x11)
            elif sub == 14:
                target = params.get(1, 0)
                if target == 1:
                    self.enabled = True
                    self.append(0x16, 1)
                elif target == 0:
                    self.append(0x16, 0)
                    self.enabled = False
                result = {1: self.enabled}
            else:
                raise AssertionError("unprofiled audit request")
        if status and self.fault == "refused-ACL-appends":
            self.entries.append(len(self.entries).to_bytes(4, "little") + bytes(4) + b"\x16\x00" + bytes(10))
        output = bytes([status]) + (codec.encode(result) if status == 0 else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("configured,defect,needle", [(True, None, None), (False, None, None),
    (True, "audit-auth-bypass", "authorization is refused before presence"), (False, "audit-ignores-decline", "operation-denied"),
    (True, "nonce-not-bound", "InvalidSignature"), (True, "connection-loses-audit", "survives connection action"),
    (True, "refused-ACL-appends", "pre-request journal")])
def test_audit_ACL_consent_nonce_binding_refusal_and_persistent_history(tmp_path, monkeypatch, configured, defect, needle):
    peer = Peer(configured, defect)
    trace = Trace(tmp_path / "audit-access", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, touch=True, timeout=131,
        pin="fixture-PIN" if configured else None, device_pin_state="unset", operator=True, features=("display",), allow_effects=("config_change", "reboot")))
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    original = audit_access.cue
    def cue(session, mode):
        peer.confirmed = mode == "accept"
        original(session, mode)
    monkeypatch.setattr(audit_access, "cue", cue)
    oracle.execute(session, ["audit-access"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and not failures, failures[:20]
        assert all(row["verdict"] == "pass" or row["applicability"] in ("excluded_by_profile", "blocked_by_precondition") for row in trace.cases)
        assert not peer.enabled
