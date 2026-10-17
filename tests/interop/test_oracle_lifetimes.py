# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A synthetic clock distinguishes ordinary token expiry from persistent grants."""
import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec, fido_lifetimes
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_fido_states import CtapPeer


class Peer(CtapPeer):
    def __init__(self, clock, defect):
        super().__init__(defect)
        self.clock, self.last, self.walk_last, self.issued = clock, 0, 0, 0
        self.persistent = {}

    def pin(self, fields):
        response = super().pin(fields)
        if fields[2] == 9:
            self.last = self.clock[0]
            self.issued = self.clock[0]
            if fields[9] == 64:
                version = fields[1]
                peer = fields[3]
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                public = ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"), ec.SECP256R1()).public_key()
                shared = self.private.exchange(ec.ECDH(), public)
                aes = hashlib.sha256(shared).digest() if version == 1 else HKDF(hashes.SHA256(), 32, bytes(32), b"CTAP2 AES key").derive(shared)
                self.token = self.persistent.setdefault(version, hashlib.sha256(bytes([version])).digest())
                cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
                encrypted = cipher.update(self.token) + cipher.finalize()
                response = {2: (bytes(16) if version == 2 else b"") + encrypted}
        return response

    def credential_management(self, fields):
        expired = self.clock[0] - self.last >= 30 or self.clock[0] - self.issued >= 600
        if expired and (self.permissions != 64 or self.defect == "expires-readonly"):
            if self.defect != "expiry-bypass":
                return 0x33, {}
        if fields[1] in (3, 5) and self.clock[0] - self.walk_last >= 30:
            self.walk = []
        if fields[1] not in (3, 5) and fields.get(4) != self.mac(bytes([fields[1]]) + (codec.encode(fields[2]) if 2 in fields else b"")):
            return 0x33, {}
        permissions = self.permissions
        self.permissions = 4 if permissions == 64 else permissions
        result = super().credential_management(fields)
        self.permissions = permissions
        self.last = self.walk_last = self.clock[0]
        return result


@pytest.mark.parametrize("defect,expected", [(None, None), ("expiry-bypass", "ordinary token expires"),
                                           ("expires-readonly", "CTAP success")])
def test_token_idle_lifetimes_through_dispatch(tmp_path, monkeypatch, defect, expected):
    clock = [0]
    peer = Peer(clock, defect)
    trace = Trace(tmp_path / "lifetimes", {"clock_fixture": "synthetic peer only"})
    session = Session(trace, hid=peer, profile="rsk", options=Options(pin="fixture-PIN", timeout=602))
    session.values["fido.info"] = {4: {"credMgmt": True, "perCredMgmtRO": True, "clientPin": True, "pinUvAuthToken": True}, 6: [1, 2]}
    monkeypatch.setattr(fido_lifetimes, "wait", lambda session, seconds: clock.__setitem__(0, clock[0] + seconds))
    oracle.execute(session, ["fido-lifetimes"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    else:
        assert any(expected in row["reason"] for row in failures), failures
