# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent seed peers decrypt real channels and bind old private references."""
import hmac

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import oracle
from oracle_lib import codec, fido, seed_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as PinPeer
from test_oracle_vendor import VendorPeer


class Peer(PinPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.fault, self.vendor = defect, VendorPeer()
        self.sealed, self.confirmed = False, True
        self.owners = {}
        self.target, self.confirmations = False, (True, True)

    def make(self, fields):
        status, value = super().make(fields)
        if not status:
            self.owners[fido.auth_data(value[2])["credential_id"]] = self.vendor.seed
        return status, value

    def assertion(self, fields):
        descriptor = fields.get(3, [{}])[0]
        if descriptor.get("id") in self.owners and self.owners[descriptor["id"]] != self.vendor.seed and self.fault != "old-credential-survives":
            return 0x2e, {}
        return super().assertion(fields)

    def reply(self, wire, status, value, observe):
        output = bytes([status]) + (codec.encode(value) if status == 0 else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0 else "applet_error", status)

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, params = fields[1], fields.get(2, {})
        if sub == 1:
            return self.vendor.transfer(command, wire, deadline, observe)
        if sub == 5:
            return self.reply(wire, 0, {1: self.sealed, 2: True, 3: False, 4: False, 5: False}, observe)
        if sub == 11:
            return self.reply(wire, 0, {1: False}, observe)
        channel = self.vendor.channel
        if sub in (2, 3, 6) and not (self.fault == "retains-consumer-channel" and self.target):
            self.vendor.channel = None
        if sub == 6:
            return self.reply(wire, 0x30 if channel is None else 2, {}, observe)
        status, value = 0, {}
        if sub == 3 and len(params.get(1, b"")) != 60:
            status = 0x14
        if not status and sub != 4 and channel is None:
            status = 0x30
        if not status and self.pin_value is not None and self.fault != "authorization-bypass":
            if 3 in fields and fields[3] not in (1, 2):
                status = 2
            elif 4 not in fields:
                status = 0x36
            elif 3 not in fields:
                status = 0x14
            else:
                message = b"\xff" * 32 + bytes([0x41, sub]) + (codec.encode(params) if 2 in fields else b"")
                expected = hmac.digest(self.token, message, "sha256")[:16 if fields[3] == 1 else 32]
                if fields[4] != expected or not self.permissions & 32:
                    status = 0x33
        if not status and not self.confirmed and self.fault != "ignores-decline":
            status = 0x27
        if not status and sub == 3 and self.pin_value is None:
            for index, accepted in enumerate(self.confirmations):
                if not accepted and self.fault != ("skips-replace-prompt" if index == 0 else "skips-load-prompt"):
                    status = 0x27
        if not status:
            if sub == 2:
                key, aad = channel
                nonce = bytes(12)
                value = {1: nonce + ChaCha20Poly1305(key).encrypt(nonce, self.vendor.seed, aad)}
            elif sub == 3:
                key, aad = channel
                blob = params[1]
                try:
                    scalar = ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
                except InvalidTag:
                    status = 0x3d
                else:
                    if not 0 < int.from_bytes(scalar, "big") < seed_matrix.ORDER and self.fault != "accepts-zero-scalar":
                        status = 2
                    else:
                        self.vendor.seed = scalar
            elif sub == 4:
                self.sealed = True
                if self.fault == "FINALIZE-spends-MSE":
                    self.vendor.channel = None
            else:
                raise AssertionError("unprofiled seed command")
        if status and self.fault == "refusal-rekeys-seed":
            self.vendor.seed = bytes(32)
        if status and sub == 4 and self.fault == "FINALIZE-spends-MSE":
            self.vendor.channel = None
        return self.reply(wire, status, value, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("authorization-bypass", "specific refusal"),
    ("retains-consumer-channel", "spends the channel"), ("FINALIZE-spends-MSE", "CTAP success"),
    ("accepts-zero-scalar", "length, integrity, scalar"), ("old-credential-survives", "old wrapped reference"),
    ("refusal-rekeys-seed", "exact seed"), ("ignores-decline", "operation-denied status")])
def test_seed_auth_crypto_refusal_and_populated_reference_controls(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "seed-matrix", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        operator=True, timeout=140, features=("display",), allow_effects=("seed_change",)))
    original = seed_matrix.cue
    def cue(session, mode):
        peer.confirmed = mode.startswith("accept")
        original(session, mode)
    monkeypatch.setattr(seed_matrix, "cue", cue)
    authenticated = seed_matrix.authenticated
    def target(*args, **kwargs):
        peer.target = True
        try:
            return authenticated(*args, **kwargs)
        finally:
            peer.target = False
    monkeypatch.setattr(seed_matrix, "authenticated", target)
    oracle.execute(session, ["seed-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:15]
    else:
        assert trace.cases and not failures, failures[:15]
        assert all(row["verdict"] == "pass" or row["scenario_id"].startswith(("rsk.seed.no-host-or-device-PIN.", "rsk.seed.no-PIN.")) or row["applicability"] == "excluded_by_profile" for row in trace.cases), trace.cases
        assert peer.vendor.seed == bytes(range(32)) and not peer.sealed


@pytest.mark.parametrize("defect", [None, "skips-replace-prompt", "skips-load-prompt"])
def test_seed_no_PIN_profile_requires_both_named_LOAD_confirmations(tmp_path, monkeypatch, defect):
    peer = Peer(defect)
    peer.pin_value = None
    trace = Trace(tmp_path / "seed-no-PIN", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True,
        operator=True, device_pin_state="unset", features=("display",), timeout=140, allow_effects=("seed_change",)))
    def cue(session, mode):
        peer.confirmations = (False, True) if "at Replace device seed" in mode else (True, False) if "at Load seed" in mode else (True, True)
    monkeypatch.setattr(seed_matrix, "cue", cue)
    seed_matrix.no_pin(session)
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("either named PIN-less LOAD refusal" in row["reason"] for row in failures), failures
    else:
        assert len(trace.cases) == 8 and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
