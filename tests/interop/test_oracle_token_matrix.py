# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Token scope is independently enforced before signing with retained EC keys."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_pin_matrix import PinPeer


class Peer(PinPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.ro, self.rp = hashlib.sha256(b"persistent RO").digest(), None
        self.older = []

    def client_pin(self, fields):
        sub = fields[2]
        if sub in (5, 9):
            bits = fields.get(9, 0)
            if sub == 5 and (bits or 10 in fields) or sub == 9 and bits == 0:
                return 2, {}
            low = bits & 255
            if sub == 9 and (low & 8 or low & 64 and low != 64):
                return 0x40, {}
            before = self.token, self.protocol, self.permissions, self.rp
            status, value = super().client_pin({**fields, 9: 3 if sub == 5 else low})
            if status:
                return status, value
            if sub == 9 and low == 64:
                aes, mac = self.keys(fields)
                cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
                encoded = cipher.update(self.ro) + cipher.finalize()
                value = {2: (bytes(16) if fields[1] == 2 else b"") + encoded}
                if self.defect != "RO-replaces-session":
                    self.token, self.protocol, self.permissions, self.rp = before
                else:
                    self.token = self.ro
            else:
                self.rp = fields.get(10)
                if self.defect == "replacement-retains-old":
                    self.older = [*self.older[-7:], before]
            return status, value
        status, value = super().client_pin(fields)
        if sub == 4 and status in (0, 0x37):
            if not status:
                self.token, self.permissions, self.rp = bytes(32), 0, None
            if self.defect != "PIN-retains-RO":
                self.ro = hashlib.sha256(self.ro).digest()
        return status, value

    def failed_pin(self):
        self.token, self.permissions, self.rp = bytes(32), 0, None
        return super().failed_pin()

    def credential_management(self, fields):
        payload = bytes([fields[1]]) + (codec.encode(fields[2]) if 2 in fields else b"")
        width = 16 if fields[3] == 1 else 32
        if self.pin_value is not None and fields.get(4) == hmac.digest(self.ro, payload, "sha256")[:width]:
            return 0, {1: 0, 2: 200}
        if fields.get(4) != self.mac(payload) or not self.permissions & 4 or self.rp is not None:
            return 0x33, {}
        return 0, {1: 0, 2: 200}

    def assertion(self, fields):
        if 6 in fields:
            if self.defect == "replacement-retains-old":
                for token, version, permissions, rp in self.older:
                    if permissions & 2 and fields[6] == hmac.digest(token, fields[2], "sha256")[:16 if version == 1 else 32] and rp in (None, fields[1]):
                        current = self.token, self.protocol, self.permissions, self.rp
                        try:
                            self.token, self.protocol, self.permissions, self.rp = token, version, permissions, rp
                            return super().assertion(fields)
                        finally:
                            self.token, self.protocol, self.permissions, self.rp = current
            if fields[6] != self.mac(fields[2]) or not self.permissions & 2 or self.rp is not None and self.rp != fields[1] and self.defect != "RP-ignored":
                return 0x33, {}
            if self.rp is None and self.defect != "unbound-reusable":
                self.rp = fields[1]
        return super().assertion(fields)

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 7 and self.defect != "reset-retains-RO":
            self.ro = hashlib.sha256(self.ro + b"reset").digest()
        if wire[0] == 7 and self.defect != "reset-retains-ordinary":
            self.token, self.permissions, self.rp = bytes(32), 0, None
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 4: {"clientPin": self.pin_value is not None, "rk": True, "credMgmt": True, "pinUvAuthToken": True, "perCredMgmtRO": True}, 6: [1, 2], 13: 4}
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("RO-replaces-session", "RO issuance does not replace ordinary"),
    ("PIN-retains-RO", "PIN change invalidates persistent RO"), ("RP-ignored", "GA checks both permission"),
    ("unbound-reusable", "first successful use binds")])
def test_legacy_scoped_and_persistent_grants(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "token-matrix", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("pin_change", "pin_attempts")))
    oracle.execute(session, ["token-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_mode" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]


@pytest.mark.parametrize("defect,needle", [(None, None), ("reset-retains-RO", "PIN reprovision cannot revive the reset persistent"),
    ("reset-retains-ordinary", "reset independently revokes a live ordinary/legacy")])
def test_reset_revokes_grants_that_were_live_after_reboot(tmp_path, monkeypatch, defect, needle):
    from oracle_lib import binding, reset_tokens
    class Hid(Peer):
        def reopen(self, operator):
            return {"serial_number": "17"}
        def initialize(self, trace, timeout):
            trace.emit("session_opened", session_id="hid", backend="synthetic")
    class Control:
        emulated = True
        def control(self, action, deadline, observe):
            return Reply(b"offline ATR")
    trace = Trace(tmp_path / "reset-grants", {})
    session = Session(trace, hid=Hid(defect), card=Control(), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("applet_reset", "pin_change", "reboot")))
    monkeypatch.setattr(binding, "check_pair", lambda session: None)
    monkeypatch.setattr(reset_tokens, "snapshot", lambda session, excluded: None)
    oracle.execute(session, ["reset-tokens"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert len(trace.cases) == 4 and all(row["verdict"] == "pass" for row in trace.cases), trace.cases


@pytest.mark.parametrize("defect", [None, "replacement-retains-old"])
def test_every_legacy_scoped_replacement_pair(tmp_path, monkeypatch, defect):
    from oracle_lib import token_matrix
    for name in ("admission", "rp_binding", "pin_invalidation", "readonly_isolation", "refused_change_grants"):
        monkeypatch.setattr(token_matrix, name, lambda session: None)
    trace = Trace(tmp_path / "token-replacement", {})
    session = Session(trace, hid=Peer(defect), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["token-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("each ordinary/legacy replacement invalidates" in reason for name, reason in failures), failures
    else:
        assert len(trace.cases) == 8 and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
