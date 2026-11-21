# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Extension outputs are independently encrypted and signed by an offline peer."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import oracle
from oracle_lib import codec, fido
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_fido_states import CtapPeer


class ExtensionPeer(CtapPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.defect, self.records, self.serial, self.counter = defect, {}, 0, 0

    def hmac_value(self, fields, registration=False):
        point, version = fields[1], fields[4]
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(point[-2], "big"), int.from_bytes(point[-3], "big"), ec.SECP256R1()).public_key()
        shared = self.private.exchange(ec.ECDH(), public)
        if version == 1:
            aes = mac = hashlib.sha256(shared).digest()
        else:
            aes = HKDF(hashes.SHA256(), 32, bytes(32), b"CTAP2 AES key").derive(shared)
            mac = HKDF(hashes.SHA256(), 32, bytes(32), b"CTAP2 HMAC key").derive(shared)
        encrypted = fields[2]
        assert fields[3] == hmac.digest(mac, encrypted, "sha256")[:16 if version == 1 else 32]
        iv, body = (bytes(16), encrypted) if version == 1 else (encrypted[:16], encrypted[16:])
        decryptor = Cipher(algorithms.AES(aes), modes.CBC(iv)).decryptor()
        salts = decryptor.update(body) + decryptor.finalize()
        secret = b"different secret" if self.defect == "HMAC-unstable" and not registration else b"credential HMAC secret"
        result = b"".join(hmac.digest(secret, salts[index:index + 32], "sha256") for index in range(0, len(salts), 32))
        encryptor = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
        return (bytes(16) if version == 2 else b"") + encryptor.update(result) + encryptor.finalize()

    def credential_management(self, fields):
        sub = fields[1]
        if sub == 6:
            self.records.pop(fields[2][2]["id"])
        elif sub == 7:
            self.records[fields[2][2]["id"]]["user"] = fields[2][3]
        else:
            return super().credential_management(fields)
        return 0, {}

    def transfer(self, command, request, deadline, observe):
        operation, fields = request[0], codec.decode(request[1:]) if len(request) > 1 else {}
        if operation not in (1, 2, 4):
            return super().transfer(command, request, deadline, observe)
        observe("tx", request)
        status, value = 0, {}
        if operation == 4:
            value = {1: ["FIDO_2_3"], 2: ["credProtect", "credBlob", "hmac-secret", "hmac-secret-mc", "thirdPartyPayment", "uvm", "largeBlob"],
                     4: {"clientPin": True, "pinUvAuthToken": True, "rk": True, "credMgmt": True}, 6: [1, 2], 15: 128,
                     10: [{"alg": alg} for alg in (-7, -35, -36, -8, -9, -19, -51, -52)]}
        else:
            status, value = self.make(fields) if operation == 1 else self.assertion(fields)
        response = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("rx", response)
        return Reply(response, "success" if not status else "applet_error", status)

    def make(self, fields):
        ext, resident = fields.get(6, {}), fields.get(7, {}).get("rk", False)
        if ext.get("largeBlob", {}).get("support") == "required" and not resident:
            return 0x18, {}
        self.serial += 1
        algorithm = next(alg["alg"] for alg in fields[4] if alg["alg"] in fido.RSK_ALGORITHMS)
        curves = {-7: (1, ec.SECP256R1), -9: (1, ec.SECP256R1), -35: (2, ec.SECP384R1),
                  -51: (2, ec.SECP384R1), -36: (3, ec.SECP521R1), -52: (3, ec.SECP521R1)}
        if algorithm in (-8, -19):
            private = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(str(self.serial).encode()).digest())
            cose = {1: 1, 3: algorithm, -1: 6, -2: private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)}
        else:
            curve, factory = curves[algorithm]
            private = ec.derive_private_key(self.serial, factory())
            point = private.public_key().public_numbers()
            width = (private.curve.key_size + 7) // 8
            cose = {1: 2, 3: algorithm, -1: curve, -2: point.x.to_bytes(width, "big"), -3: point.y.to_bytes(width, "big")}
        identifier = b"extension-credential-" + self.serial.to_bytes(4, "big")
        record = {"key": private, "alg": algorithm, "rp": fields[2]["id"], "ext": ext, "resident": resident,
                  "blob": ext.get("credBlob", b"") if len(ext.get("credBlob", b"")) <= 128 else b"", "user": fields[3]}
        self.records[identifier] = record
        signed = {}
        if "credProtect" in ext:
            signed["credProtect"] = ext["credProtect"]
        if "credBlob" in ext:
            signed["credBlob"] = len(ext["credBlob"]) <= 128
        if "hmac-secret-mc" in ext:
            signed["hmac-secret-mc"] = self.hmac_value(ext["hmac-secret-mc"], registration=True)
        auth = hashlib.sha256(record["rp"].encode()).digest() + bytes([0x45 | (128 if signed else 0)]) + bytes(4)
        auth += bytes(16) + len(identifier).to_bytes(2, "big") + identifier + codec.encode(cose) + (codec.encode(signed) if signed else b"")
        value = {1: "none", 2: auth, 3: {}}
        if resident and "largeBlob" in ext:
            value[6] = {"largeBlob": {"supported": True}}
        return 0, value

    def assertion(self, fields):
        named = fields.get(3)
        identifier = (named[0]["id"] if named else None) if 3 in fields else next((key for key, record in self.records.items() if record["rp"] == fields[1]), None)
        record = self.records.get(identifier)
        if not record or record["rp"] != fields[1]:
            return 0x2E, {}
        uv, up = fields.get(6) == self.mac(fields[2]), fields.get(5, {}).get("up", True)
        level = record["ext"].get("credProtect", 1)
        if not uv and (level == 3 or level == 2 and not named) and self.defect != "credProtect-bypass":
            return 0x2E, {}
        extensions, unsigned = {}, {}
        for name, value in fields.get(4, {}).items():
            if name == "credBlob":
                extensions[name] = record["blob"]
            elif name == "thirdPartyPayment":
                if type(value) is not bool:
                    return 0x11, {}
                extensions[name] = record["ext"].get(name, False)
            elif name == "uvm":
                extensions[name] = ([[1, 2, 4]] if up else []) + ([[2048, 2, 4]] if uv else [] if up else [[512, 2, 4]])
            elif name == "hmac-secret":
                try:
                    extensions[name] = self.hmac_value(value)
                except (ValueError, AssertionError):
                    return 0x33, {}
            elif name == "largeBlob":
                if value == {"read": True}:
                    if "large" in record:
                        unsigned[name] = record["large"]
                elif set(value) == {"write", "originalSize"}:
                    written = record["resident"] and up and bool(named)
                    unsigned[name] = {"written": written}
                    if written and (self.defect != "blob-replacement-ignored" or "large" not in record):
                        record["large"] = {"blob": value["write"], "originalSize": value["originalSize"]}
                else:
                    return 0x12, {}
        self.counter += 1
        auth = hashlib.sha256(fields[1].encode()).digest() + bytes([int(up) | (4 if uv else 0) | (128 if extensions else 0)]) + self.counter.to_bytes(4, "big")
        if extensions:
            auth += codec.encode(extensions)
        key, algorithm = record["key"], record["alg"]
        signature = key.sign(auth + fields[2]) if algorithm in (-8, -19) else key.sign(auth + fields[2], ec.ECDSA(fido.HASH_ALGORITHMS[algorithm]()))
        value = {1: {"id": identifier, "type": "public-key"}, 2: auth, 3: signature}
        if unsigned:
            value[8] = unsigned
        return 0, value


@pytest.mark.parametrize("defect,expected", [(None, None), ("credProtect-bypass", "visibility without UV"),
    ("HMAC-unstable", "registration and assertion HMAC match"), ("blob-replacement-ignored", "largeBlob original size")])
def test_extensions_dispatch_checks_signed_outputs_and_real_crypto(tmp_path, defect, expected):
    trace = Trace(tmp_path / "extensions", {})
    peer = ExtensionPeer(defect)
    session = Session(trace, hid=peer, options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["fido-extensions"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    else:
        assert any(expected in " ".join([row["reason"], *row.get("causes", [])]) for row in failures), failures
    assert not any(record["resident"] for record in peer.records.values())
