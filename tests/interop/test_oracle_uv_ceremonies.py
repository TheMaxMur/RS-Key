# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Local ceremony flags and extension secrets are independently signed by a peer."""
import copy
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oracle_lib import codec, fido, uv_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_registration_matrix import RegistrationPeer


class Peer(RegistrationPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.internal = False

    def pin(self, fields):
        if fields[2] == 6:
            fields = copy.deepcopy(fields)
            point = fields[3]
            public = ec.EllipticCurvePublicNumbers(int.from_bytes(point[-2], "big"), int.from_bytes(point[-3], "big"), ec.SECP256R1()).public_key()
            shared = self.private.exchange(ec.ECDH(), public)
            aes = hashlib.sha256(shared).digest() if fields[1] == 1 else HKDF(hashes.SHA256(), 32, bytes(32), b"CTAP2 AES key").derive(shared)
            cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
            fields[6] = (bytes(16) if fields[1] == 2 else b"") + cipher.update(hashlib.sha256(b"fixture-PIN").digest()[:16]) + cipher.finalize()
            fields[2] = 9
            result = super().pin(fields)
            self.internal = True
            return result
        result = super().pin(fields)
        if fields[2] == 9:
            self.internal = False
        return result

    def make(self, fields):
        original = fields
        fields = copy.deepcopy(fields)
        options = fields.get(7, {})
        local = 8 not in fields and options.get("uv") and options.get("up") is not False
        if local:
            fields[8] = b"independently verified local PIN"
        status, value = super().make(fields)
        if not status and original.get(6, {}).get("uvm"):
            parsed = fido.auth_data(value[2])
            ext = {**parsed.get("extensions", {}), "uvm": [[1, 2, 4]] + ([[4 if local else 0x800, 2, 4]] if 8 in fields else [])}
            if self.defect == "MC-local-UV-cleared" and local:
                value[2] = value[2][:32] + bytes([value[2][32] & ~4]) + value[2][33:]
            prefix_size = 55 + len(parsed["credential_id"]) + len(codec.encode(parsed["cose"]))
            value[2] = value[2][:32] + bytes([value[2][32] | 128]) + value[2][33:prefix_size] + codec.encode(ext)
        return status, value

    def assertion(self, fields):
        fields = copy.deepcopy(fields)
        options = fields.get(5, {})
        local = 6 not in fields and options.get("uv") and options.get("up") is not False
        if local or self.defect == "silent-UV-ceremony" and options.get("uv"):
            fields[6] = self.mac(fields[2])
            fields[7] = self.protocol
        status, value = super().assertion(fields)
        if not status and fields.get(4, {}).get("uvm"):
            parsed = fido.auth_data(value[2])
            ext = parsed.get("extensions", {})
            if local or 6 in fields and self.internal:
                ext["uvm"] = [[4 if row[0] == 0x800 else row[0], row[1], row[2]] for row in ext["uvm"]]
            if self.defect == "local-HMAC-other-secret" and local and "hmac-secret" in ext:
                ext["hmac-secret"] = bytes(len(ext["hmac-secret"]))
            value[2] = value[2][:37] + codec.encode(ext)
            record = self.records[value[1]["id"]]
            value[3] = record["key"].sign(value[2] + fields[2], ec.ECDSA(hashes.SHA256()))
        return status, value

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 2: ["uvm", "credProtect", "hmac-secret", "hmac-secret-mc", "credBlob", "largeBlobKey"], 4: {
                "uv": True, "clientPin": True, "rk": True, "credMgmt": True, "pinUvAuthToken": True, "makeCredUvNotRqd": True}, 6: [1, 2]}
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("MC-local-UV-cleared", "registration UV reflects"),
    ("silent-UV-ceremony", "GA visibility uses actual UV"), ("local-HMAC-other-secret", "all UV verification methods use")])
def test_local_UV_option_products_and_extension_secrets(tmp_path, defect, needle):
    trace = Trace(tmp_path / "UV-ceremonies", {})
    session = Session(trace, hid=Peer(defect), profile="rsk", options=Options(exercise=True, touch=True, operator=True, pin="fixture-PIN"))
    uv_matrix.options(session)
    uv_matrix.assertion_options(session)
    uv_matrix.extension_outputs(session)
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
