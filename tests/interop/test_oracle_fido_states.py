# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A CTAP peer checks the actual PIN/token/MAC and blob wire path."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


class CtapPeer:
    layer = "hid_report"

    def __init__(self, defect=None):
        self.defect = defect
        self.private = ec.derive_private_key(42, ec.SECP256R1())
        self.token = bytes(32)
        self.protocol, self.permissions = 2, 0
        self.generation = 0
        self.walk = []
        self.rps = ["first.oracle.invalid", "second.oracle.invalid"]
        body = codec.encode([])
        self.original = body + hashlib.sha256(body).digest()[:16]
        self.blob = self.original
        self.staging, self.total = b"", 0

    def mac(self, data):
        return hmac.digest(self.token, data, "sha256")[:16 if self.protocol == 1 else 32]

    def pin(self, fields):
        version, sub = fields[1], fields[2]
        point = self.private.public_key().public_numbers()
        if sub == 2:
            return {1: {1: 2, 3: -25, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}}
        assert sub == 9
        peer = fields[3]
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"), ec.SECP256R1()).public_key()
        shared = self.private.exchange(ec.ECDH(), public)
        aes = hashlib.sha256(shared).digest() if version == 1 else HKDF(hashes.SHA256(), 32, bytes(32), b"CTAP2 AES key").derive(shared)
        encrypted = fields[6]
        iv, data = (bytes(16), encrypted) if version == 1 else (encrypted[:16], encrypted[16:])
        decryptor = Cipher(algorithms.AES(aes), modes.CBC(iv)).decryptor()
        assert decryptor.update(data) + decryptor.finalize() == hashlib.sha256(b"fixture-PIN").digest()[:16]
        self.generation += 1
        self.token = hashlib.sha256(self.generation.to_bytes(4, "big")).digest()
        self.protocol, self.permissions = version, fields[9]
        cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
        encoded = cipher.update(self.token) + cipher.finalize()
        return {2: (bytes(16) if version == 2 else b"") + encoded}

    def credential_management(self, fields):
        sub = fields[1]
        if sub not in (3, 5):
            message = bytes([sub]) + (codec.encode(fields[2]) if 2 in fields else b"")
            if self.defect != "bad-MAC-accepted" and fields.get(4) != self.mac(message):
                return 0x33, {}
            if self.defect != "permission-bypass" and not self.permissions & 4:
                return 0x40, {}
        if sub == 1:
            return 0, {1: 2, 2: 200}
        if sub == 2:
            self.walk = list(self.rps)
        if sub in (2, 3):
            if not self.walk:
                return 0x30, {}
            rp = self.walk.pop(0)
            value = {3: {"id": rp}, 4: hashlib.sha256(rp.encode()).digest()}
            if sub == 2:
                value[5] = len(self.rps)
            return 0, value
        return 0x30, {}

    def blobs(self, fields):
        if 1 in fields:
            return 0, {1: self.blob[fields[3]:fields[3] + fields[1]]}
        offset, fragment = fields[3], fields[2]
        message = b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + hashlib.sha256(fragment).digest()
        invalid = not self.permissions & 16 or fields.get(5) != self.mac(message)
        if offset == 0:
            total = fields.get(4, 0)
            invalid |= not 17 <= total <= 1024
        else:
            total = self.total
            invalid |= offset != len(self.staging)
        if invalid:
            if self.defect == "partial-commit-on-refusal":
                self.blob = b"damaged by rejected write"
            return 0x33, {}
        if offset == 0:
            self.staging, self.total = b"", total
        self.staging += fragment
        if len(self.staging) == total:
            if hashlib.sha256(self.staging[:-16]).digest()[:16] != self.staging[-16:]:
                return 0x3D, {}
            self.blob = self.staging
        return 0, {}

    def transfer(self, command, request, deadline, observe):
        observe("tx", request)
        assert command == 0x10
        operation, fields = request[0], codec.decode(request[1:]) if len(request) > 1 else {}
        status, value = 0, {}
        if operation == 4:
            self.walk = []
            value = {1: ["FIDO_2_1"], 4: {"clientPin": True, "pinUvAuthToken": True, "credMgmt": True, "largeBlobs": True}, 6: [1, 2], 11: 1024}
        elif operation == 6:
            value = self.pin(fields)
        elif operation == 10:
            status, value = self.credential_management(fields)
        elif operation == 12:
            status, value = self.blobs(fields)
        else:
            raise AssertionError(f"unexpected CTAP command {operation}")
        response = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("rx", response)
        return Reply(response, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,assertion", [(None, None), ("bad-MAC-accepted", "wrong-token-MAC refused"),
    ("permission-bypass", "wrong-token-permission refused"), ("partial-commit-on-refusal", "committed blob survives failed fragment")])
def test_real_token_and_blob_wire_cases_detect_each_defect(tmp_path, defect, assertion):
    peer = CtapPeer(defect)
    trace = Trace(tmp_path / "fido-states", {})
    session = Session(trace, hid=peer, options=Options(exercise=True, pin="fixture-PIN"))
    oracle.execute(session, ["fido-states"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if assertion is None:
        assert not failures, failures
        assert any(row["scenario_id"] == "fido.transition.token-scope.1" and row["verdict"] == "pass" for row in trace.cases)
        assert any(row["scenario_id"] == "fido.transition.token-scope.2" and row["verdict"] == "pass" for row in trace.cases)
    else:
        assert any(assertion in row["reason"] for row in failures), failures
    assert peer.blob == peer.original


def test_missing_advertisement_is_not_confirmed_device_rejection(tmp_path):
    from oracle_lib.fido import credential
    trace = Trace(tmp_path / "unadvertised", {})
    session = Session(trace, options=Options(exercise=True, touch=True))
    session.values["fido.info"] = {10: [{"alg": -7}]}
    credential(session, -8, False)
    trace.finish()
    assert trace.cases[0]["applicability"] == "unknown"
    assert not trace.exchanges


class CredentialPeer(CtapPeer):
    def __init__(self, wrong_refusal=False):
        super().__init__()
        self.wrong_refusal = wrong_refusal
        self.key = ec.derive_private_key(99, ec.SECP256R1())
        self.descriptor = {"id": b"oracle-credential", "type": "public-key"}
        self.rp = None
        self.counter = self.auth_rejections = 0

    def transfer(self, command, request, deadline, observe):
        if request[0] not in (1, 2):
            return super().transfer(command, request, deadline, observe)
        observe("tx", request)
        operation, fields = request[0], codec.decode(request[1:])
        challenge = fields[1] if operation == 1 else fields[2]
        auth_field = 8 if operation == 1 else 6
        status, value = 0, {}
        if fields.get(auth_field) != self.mac(challenge) or not self.permissions & operation:
            status = 0x36
            self.auth_rejections += 1
        elif operation == 1:
            self.rp = fields[2]["id"]
            point = self.key.public_key().public_numbers()
            cose = {1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}
            auth = hashlib.sha256(self.rp.encode()).digest() + b"\x45" + bytes(4) + bytes(16)
            identifier = self.descriptor["id"]
            auth += len(identifier).to_bytes(2, "big") + identifier + codec.encode(cose)
            value = {1: "none", 2: auth, 3: {}}
        elif fields[1] != self.rp or fields[3] != [self.descriptor]:
            status = 0x36 if self.wrong_refusal else 0x2E
        else:
            self.counter += 1
            auth = hashlib.sha256(self.rp.encode()).digest() + b"\x05" + self.counter.to_bytes(4, "big")
            value = {1: self.descriptor, 2: auth, 3: self.key.sign(auth + challenge, ec.ECDSA(hashes.SHA256()))}
        response = bytes([status]) + (codec.encode(value) if status == 0 else b"")
        observe("rx", response)
        return Reply(response, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("wrong_refusal", [False, True])
def test_credential_refusal_cases_have_valid_auth_and_exact_cause(tmp_path, wrong_refusal):
    from oracle_lib.fido import credential
    peer = CredentialPeer(wrong_refusal)
    trace = Trace(tmp_path / "credential-refusal", {})
    session = Session(trace, hid=peer, options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    credential(session, -7, False)
    trace.finish()
    assert peer.auth_rejections == 0
    case = trace.cases[0]
    if wrong_refusal:
        assert case["verdict"] == "fail" and "finds no credential" in case["reason"], case
    else:
        assert case["verdict"] == "pass", case
        assert peer.counter == 4
