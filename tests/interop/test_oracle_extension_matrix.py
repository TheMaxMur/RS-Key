# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Owned blobs, signed payment outputs and certificate selection have separate state."""
import copy
import datetime
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

import oracle
from oracle_lib import codec, extension_matrix, fido
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_credential_matrix import StorePeer
from test_oracle_info_matrix import Card


class Peer(StorePeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.attest = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline Oracle Attestation")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.attest.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)).sign(self.attest, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        self.local_token, self.orphan = False, None

    def reopen(self, operator):
        return {"offline": True}

    def initialize(self, trace, timeout):
        return None

    def pin(self, fields):
        if fields[2] == 6:
            fields = dict(fields)
            peer, version = fields[3], fields[1]
            remote = ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"), ec.SECP256R1()).public_key()
            shared = self.private.exchange(ec.ECDH(), remote)
            key = hashlib.sha256(shared).digest() if version == 1 else HKDF(hashes.SHA256(), 32, bytes(32), b"CTAP2 AES key").derive(shared)
            cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
            fields.update({2: 9, 6: (bytes(16) if version == 2 else b"") + cipher.update(hashlib.sha256(b"fixture-PIN").digest()[:16]) + cipher.finalize()})
            result = super().pin(fields)
            self.local_token = True
            return result
        if fields[2] == 9:
            self.local_token = False
        return super().pin(fields)

    def make(self, fields):
        preferences = fields.get(11)
        if preferences and any(type(value) is not str for value in preferences):
            return 0x11, {}
        status, value = super().make(fields)
        if status:
            return status, value
        identifier = fido.auth_data(value[2])["credential_id"]
        if self.defect == "reused-slot-discloses-blob" and self.orphan is not None:
            self.records[identifier]["large"] = self.orphan
        if preferences != ["none"] or self.defect == "ignores-none-format":
            value[1], value[3] = "packed", {"alg": -7, "x5c": [self.certificate], "sig": self.attest.sign(value[2] + fields[1], ec.ECDSA(hashes.SHA256()))}
        return status, value

    def credential_management(self, fields):
        if fields[1] == 6:
            self.orphan = self.records[fields[2][2]["id"]].get("large")
        return super().credential_management(fields)

    def assertion(self, fields):
        fields = copy.deepcopy(fields)
        ext = fields.get(4, {})
        blob = ext.get("largeBlob")
        overflow = False
        if blob is not None:
            read = blob == {"read": True} and type(blob.get("read")) is bool
            write = set(blob) == {"write", "originalSize"} and type(blob["write"]) is bytes and type(blob["originalSize"]) is int and blob["originalSize"] >= 0
            if not read and not write:
                return 0x12, {}
            if write and (len(blob["write"]) > 4046 or blob["originalSize"] > 0xffffffff) and self.defect != "accept-oversize-blob":
                overflow = True
                del ext["largeBlob"]
        for name in ("thirdPartyPayment", "uvm"):
            if ext.get(name) is False:
                del ext[name]
        status, value = super().assertion(fields)
        if status:
            return status, value
        if overflow:
            value.setdefault(8, {})["largeBlob"] = {"written": False}
        if self.local_token:
            parsed = fido.auth_data(value[2])
            if "uvm" in parsed.get("extensions", {}):
                parsed["extensions"]["uvm"] = [[4 if row[0] == 2048 else row[0], *row[1:]] for row in parsed["extensions"]["uvm"]]
                value[2] = value[2][:37] + codec.encode(parsed["extensions"])
                record = self.records[value[1]["id"]]
                value[3] = record["key"].sign(value[2] + fields[2], ec.ECDSA(hashes.SHA256()))
        return 0, value

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 2: ["largeBlob", "uvm", "credProtect", "thirdPartyPayment"],
                4: {"rk": True, "credMgmt": True, "clientPin": True, "pinUvAuthToken": True, "uv": True}, 6: [1, 2]}
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("ignores-none-format", "format preference follows"),
    ("reused-slot-discloses-blob", "blob lifetime follows"), ("accept-oversize-blob", "integer overflow return written false")])
def test_extension_output_products_format_lists_blob_bounds_and_lifetimes(tmp_path, monkeypatch, defect, needle):
    from oracle_lib import binding
    monkeypatch.setattr(binding, "check_pair", lambda session: None)
    trace = Trace(tmp_path / "extension-matrix", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, card=Card(peer), profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        pin="fixture-PIN", allow_effects=("reboot",)))
    oracle.execute(session, ["extension-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not any(row["resident"] for row in peer.records.values())
