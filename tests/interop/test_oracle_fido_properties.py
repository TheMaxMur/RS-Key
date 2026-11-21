# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Per-credential secrets and counters are produced by an independent CTAP peer."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec, fido
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_extensions import ExtensionPeer


class PropertyPeer(ExtensionPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.hmac_seed, self.credential_counts = b"initial", {}
        self.corrupted = set()

    def hmac_value(self, fields, registration=False):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
        iv, data = (bytes(16), encrypted) if version == 1 else (encrypted[:16], encrypted[16:])
        decryptor = Cipher(algorithms.AES(aes), modes.CBC(iv)).decryptor()
        salts = decryptor.update(data) + decryptor.finalize()
        key = b"shared" if self.defect == "shared-HMAC" else self.hmac_seed
        result = b"".join(hmac.digest(key, salts[i:i + 32], "sha256") for i in range(0, len(salts), 32))
        cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
        return (bytes(16) if version == 2 else b"") + cipher.update(result) + cipher.finalize()

    def invalid_extension(self, fields, operation):
        extensions = fields.get(6 if operation == 1 else 4, {})
        for name, value in extensions.items():
            expected = {"credProtect": (int,), "credBlob": (bytes,) if operation == 1 else (bool,),
                        "hmac-secret": (bool,) if operation == 1 else (dict, bool),
                        "minPinLength": (bool,), "pinComplexityPolicy": (bool,), "uvm": (bool,),
                        "thirdPartyPayment": (bool,), "largeBlobKey": (bool,)}.get(name)
            if expected and type(value) not in expected and self.defect != "accept-wrong-type":
                return 0x11
            if name == "largeBlobKey" and value is False:
                return 0x2C
            if name == "hmac-secret" and operation == 2 and isinstance(value, dict):
                try:
                    version = value.get(4, 1)
                    if version not in (1, 2) or len(value[1][-2]) != 32 or len(value[1][-3]) != 32:
                        return 0x12
                    ec.EllipticCurvePublicNumbers(int.from_bytes(value[1][-2], "big"), int.from_bytes(value[1][-3], "big"), ec.SECP256R1()).public_key()
                    if len(value[2]) not in ((32, 64) if version == 1 else (48, 80)) or len(value[3]) != (16 if version == 1 else 32):
                        return 0x03
                except (KeyError, TypeError, ValueError):
                    return 0x12
        return 0

    def make(self, fields):
        bad = self.invalid_extension(fields, 1)
        if bad:
            return bad, {}
        status, result = super().make(fields)
        if status == 0:
            identifier = fido.auth_data(result[2])["credential_id"]
            self.credential_counts[identifier] = 0
            if fields.get(6, {}).get("largeBlobKey"):
                result[5] = hashlib.sha256(identifier + b"large blob key").digest()
        return status, result

    def assertion(self, fields):
        bad = self.invalid_extension(fields, 2)
        if bad:
            if self.defect == "bad-field-mutates-secret" and "hmac-secret" in fields.get(4, {}):
                self.corrupted.add(fields[3][0]["id"])
            return bad, {}
        named = fields.get(3)
        record = self.records.get(named[0]["id"]) if named else None
        if record:
            self.hmac_seed = hashlib.sha256(named[0]["id"] + (b"corrupted" if named[0]["id"] in self.corrupted else b"hmac secret")).digest()
        if "hmac-secret" in fields.get(4, {}) and fields.get(5, {}).get("up") is False:
            return 0x3B, {}
        status, value = super().assertion(fields)
        if not status:
            identifier = value[1]["id"]
            record = self.records[identifier]
            count = self.counter if self.defect == "global-counter" else self.credential_counts[identifier] if record["resident"] else 0
            self.credential_counts[identifier] += 1
            value[2] = value[2][:33] + count.to_bytes(4, "big") + value[2][37:]
            value[3] = record["key"].sign(value[2] + fields[2], ec.ECDSA(fido.HASH_ALGORITHMS[record["alg"]]()))
            if (fields.get(4, {}).get("largeBlobKey") or self.defect == "unsolicited-key") and record["ext"].get("largeBlobKey"):
                value[7] = hashlib.sha256(identifier + b"large blob key").digest()
        return status, value

    def transfer(self, command, wire, deadline, observe):
        if wire[:1] == b"\x04":
            value = {1: ["FIDO_2_3"], 2: ["credProtect", "credBlob", "hmac-secret", "minPinLength", "pinComplexityPolicy", "uvm", "thirdPartyPayment", "largeBlobKey"],
                     4: {"rk": True, "credMgmt": True, "clientPin": True, "pinUvAuthToken": True}, 6: [1, 2], 15: 128}
            response = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", response)
            return Reply(response, "success", 0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,expected", [(None, None), ("shared-HMAC", "different credentials have different HMAC"),
    ("global-counter", "per-credential counter advances"), ("unsolicited-key", "no unsolicited assertion largeBlobKey"),
    ("accept-wrong-type", "known extension wrong type refused"),
    ("bad-field-mutates-secret", "HMAC valid control preserves secret after malformed field")])
def test_property_matrix_uses_real_requests_and_signed_witnesses(tmp_path, defect, expected):
    trace = Trace(tmp_path / "properties", {})
    peer = PropertyPeer(defect)
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["fido-properties"])
    trace.finish()
    failed = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failed), failed
    else:
        assert not failed, failed
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert not any(record["resident"] for record in peer.records.values())


class ReconnectedPeer(PropertyPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.reconnections = 0

    def reopen(self, operator):
        self.reconnections += 1
        if self.defect == "volatile-counter":
            self.credential_counts = {key: 0 for key in self.credential_counts}
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")

    def make(self, fields):
        status, value = super().make(fields)
        if not status:
            self.records[fido.auth_data(value[2])["credential_id"]]["born"] = self.reconnections
        return status, value

    def assertion(self, fields):
        status, value = super().assertion(fields)
        if not status and 7 in value and self.defect == "volatile-blob-key" and self.records[value[1]["id"]]["born"] < self.reconnections:
            value[7] = hashlib.sha256(value[7] + b"rotated after reconnect").digest()
        return status, value

    def transfer(self, command, wire, deadline, observe):
        if command == 0x42:
            from test_oracle_binding import Identity
            value = Identity(17).identity()
            observe("tx", wire)
            observe("rx", value)
            return Reply(value)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,expected", [(None, None), ("volatile-counter", "counter retained across"),
                                           ("volatile-blob-key", "largeBlobKey survives")])
def test_credential_properties_survive_actual_reconnect_dispatch(tmp_path, defect, expected):
    from oracle_lib import binding
    from test_oracle_binding import Identity
    trace = Trace(tmp_path / "properties-reconnected", {})
    card, peer = Identity(17), ReconnectedPeer(defect)
    card.emulated = True
    session = Session(trace, hid=peer, card=card, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("reboot",)))
    binding.confirm(session)
    oracle.execute(session, ["fido-property-reconnect"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert card.controls and not any(record["resident"] for record in peer.records.values())
