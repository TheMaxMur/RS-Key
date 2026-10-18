# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIN boundary checks decrypt host messages and preserve independently signed keys."""
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
from test_oracle_fido_properties import PropertyPeer
from test_oracle_binding import Identity


class PinPeer(PropertyPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.pin_value, self.remaining = "fixture-PIN", 8
        self.rotations = 42

    def keys(self, fields):
        point, version = fields[3], fields[1]
        if len(point[-2]) != 32 or len(point[-3]) != 32:
            raise ValueError("coordinates need exactly 32 bytes, independently of integer value")
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(point[-2], "big"), int.from_bytes(point[-3], "big"), ec.SECP256R1()).public_key()
        shared = self.private.exchange(ec.ECDH(), public)
        if version == 1:
            return hashlib.sha256(shared).digest(), hashlib.sha256(shared).digest()
        return tuple(HKDF(hashes.SHA256(), 32, bytes(32), name).derive(shared) for name in (b"CTAP2 AES key", b"CTAP2 HMAC key"))

    @staticmethod
    def decrypt(version, key, data):
        iv, body = (data[:16], data[16:]) if version == 2 else (bytes(16), data)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(body) + decryptor.finalize()

    def failed_pin(self):
        self.remaining -= 1
        self.rotations += 1
        if self.defect != "static-agreement":
            self.private = ec.derive_private_key(self.rotations, ec.SECP256R1())
        return 0x31, {}

    def client_pin(self, fields):
        version, sub = fields[1], fields[2]
        if sub == 1:
            return 0, {3: self.remaining}
        if sub == 2:
            point = self.private.public_key().public_numbers()
            return 0, {1: {1: 2, 3: -25, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}}
        if sub in (3, 4):
            if not all(key in fields for key in (3, 4, 5)) or sub == 4 and 6 not in fields:
                return 0x14, {}
            if not fields[3].get(-2) or not fields[3].get(-3):
                return 0x14, {}
            if not len(fields[5]) or len(fields[5]) % 16 or len(fields[5]) > 80:
                return 0x37, {}
            if sub == 3 and self.pin_value is not None:
                return 0x30, {}
            if sub == 4 and len(fields[6]) not in (16, 32):
                return 0x02, {}
        try:
            aes, mac = self.keys(fields)
        except (KeyError, ValueError):
            return 0x02, {}
        if sub in (3, 4):
            expected = hmac.digest(mac, fields[5] + fields.get(6, b""), "sha256")[:16 if version == 1 else 32]
            if fields[4] != expected and self.defect != "ignore-MAC":
                return 0x33, {}
            if sub == 4:
                previous = self.decrypt(version, aes, fields[6])
                if len(previous) != 16:
                    return 0x33, {}
                if previous != hashlib.sha256(self.pin_value.encode()).digest()[:16]:
                    return self.failed_pin()
                self.remaining = 8
            plain = self.decrypt(version, aes, fields[5])
            if len(plain) != 64:
                return 0x02, {}
            if plain[-1] != 0:
                return 0x37, {}
            raw = plain.split(b"\x00", 1)[0]
            try:
                candidate = raw.decode()
            except UnicodeDecodeError:
                return 0x37, {}
            if (len(raw) if self.defect == "count-bytes" else len(candidate)) < 4 or len(raw) > 63:
                return 0x37, {}
            self.pin_value = candidate
            if self.defect == "change-deletes-keys":
                self.records.clear()
            return 0, {}
        assert sub in (5, 9)
        previous = self.decrypt(version, aes, fields[6])
        if previous != hashlib.sha256(self.pin_value.encode()).digest()[:16]:
            return self.failed_pin()
        self.remaining = 8
        self.generation += 1
        self.protocol, self.permissions = version, fields.get(9, 3)
        self.token = hashlib.sha256(self.generation.to_bytes(4, "big")).digest()
        cipher = Cipher(algorithms.AES(aes), modes.CBC(bytes(16))).encryptor()
        encrypted = cipher.update(self.token) + cipher.finalize()
        return 0, {2: (bytes(16) if version == 2 else b"") + encrypted}

    def transfer(self, command, wire, deadline, observe):
        if command == 0x42:
            output = Identity(17).identity()
            observe("tx", wire)
            observe("rx", output)
            return Reply(output)
        if wire[0] not in (4, 6, 7):
            return super().transfer(command, wire, deadline, observe)
        observe("tx", wire)
        status, value = 0, {}
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 4: {"clientPin": self.pin_value is not None, "rk": True, "credMgmt": True, "pinUvAuthToken": True}, 6: [1, 2], 13: 4}
        elif wire[0] == 7:
            self.pin_value, self.remaining = None, 8
            self.records.clear()
        else:
            status, value = self.client_pin(codec.decode(wire[1:]))
        output = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("rx", output)
        return Reply(output, "success" if not status else "applet_error", status)

    def reopen(self, operator):
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")


@pytest.mark.parametrize("suite", ["pin-matrix", "pin-setup-matrix"])
@pytest.mark.parametrize("defect,expected", [(None, None), ("ignore-MAC", "PIN defect refused"),
    ("count-bytes", "PIN defect refused"), ("change-deletes-keys", "CTAP success"), ("static-agreement", "agreement key changes")])
def test_pin_matrix_decrypts_semantic_inputs_and_restores_fixture(tmp_path, suite, defect, expected):
    if suite == "pin-setup-matrix" and defect in ("change-deletes-keys", "static-agreement"):
        pytest.skip("change and agreement defects belong to configured-PIN scenarios")
    peer, card = PinPeer(defect), Identity(17)
    card.emulated = True
    trace = Trace(tmp_path / "pin-matrix", {})
    session = Session(trace, hid=peer, card=card, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("pin_change", "pin_attempts", "applet_reset", "reboot")))
    oracle.execute(session, [suite])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        expected = "invalid setPIN refused" if suite == "pin-setup-matrix" else expected
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert peer.pin_value == "fixture-PIN" and peer.remaining == 8
        assert len(trace.cases) > 40


def test_pin_suites_are_wallet_excluded_before_io(tmp_path):
    trace = Trace(tmp_path / "wallet", {})
    session = Session(trace, profile="trezor", options=Options(exercise=True, touch=True))
    oracle.execute(session, ["pin-matrix", "pin-setup-matrix"])
    trace.finish()
    assert len(trace.cases) == 2 and all(row["applicability"] == "excluded_by_profile" for row in trace.cases)
    assert not trace.exchanges
