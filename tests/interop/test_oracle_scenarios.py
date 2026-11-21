# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Known answers and deliberately wrong device replies exercise scenario verdicts."""
import hashlib
import hmac
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).parent))
import oracle
from oracle_lib import codec, fido, otp
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from oracle_lib import otp_hid
from oracle_lib.trace import Outcome, TransferError


class OathCard:
    layer = "synthetic_apdu"

    def __init__(self, defect=None):
        self.records, self.calls, self.defect = {}, [], defect

    def close(self):
        pass

    def transfer(self, request, deadline, observe):
        self.calls.append(request)
        observe("tx", request)
        ins, p2 = request[1], request[3]
        fields = codec.parse_tlv(request[5:5 + request[4]]) if len(request) > 5 and not (ins == 0xA4 and request[2] == 4) else []
        values = dict(fields)
        result = b""
        if ins == 0xA4 and request[2] == 4:
            pass
        elif ins == 1:
            self.records[values[0x71]] = [values[0x73], 0]
        elif ins == 2:
            del self.records[values[0x71]]
        elif ins == 5:
            self.records[fields[1][1]] = self.records.pop(fields[0][1])
        elif ins == 0xA1:
            result = b"".join(codec.tlv(0x72, key[:1] + name) for name, (key, _) in self.records.items())
        elif ins == 0xA2:
            record = self.records[values[0x71]]
            key, count = record
            challenge = count.to_bytes(8, "big") if key[0] & 0x10 else values[0x74]
            result = self.calculate(key, challenge, p2)
            if key[0] & 0x10 and self.defect != "stuck-counter":
                record[1] += 1
        elif ins == 0xA4:
            result = b"".join(codec.tlv(0x71, name) + self.calculate(key, values[0x74], p2) for name, (key, _) in self.records.items())
        elif ins != 0xA4:
            raise AssertionError(f"unexpected fixture request {ins:02x}")
        reply = result + b"\x90\x00"
        observe("rx", reply)
        return Reply(reply, "success", 0x9000)

    def calculate(self, key, challenge, truncated):
        digest = hmac.digest(key[2:], challenge, {1: "sha1", 2: "sha256", 3: "sha512"}[key[0] & 15])
        if not truncated:
            return codec.tlv(0x75, key[1:2] + digest)
        offset = digest[-1] & 15
        value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** key[1])
        if self.defect == "wrong-value":
            value ^= 1
        return codec.tlv(0x76, key[1:2] + value.to_bytes(4, "big"))


@pytest.mark.parametrize("defect", [None, "wrong-value", "stuck-counter"])
def test_oath_lifecycle_checks_the_result_and_cleans_up(tmp_path, defect):
    trace = Trace(tmp_path / "capture", {"backend": "synthetic"})
    card = OathCard(defect)
    session = Session(trace, card=card, options=Options(exercise=True))
    otp.oath(session)
    trace.finish()
    assert not card.records
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect is None:
        assert not failures
        assert all(row["verdict"] == "pass" for row in trace.cases)
    else:
        expected = "HOTP counter" if defect == "stuck-counter" else "TOTP value"
        assert any(expected in row["reason"] for row in failures)
        assert all(row["exchanges"] for row in failures)


def test_oath_fixture_does_not_run_without_exercise(tmp_path):
    trace = Trace(tmp_path / "capture", {})
    card = OathCard()
    otp.oath(Session(trace, card=card))
    trace.finish()
    assert not card.calls
    assert all(row["applicability"] == "excluded_by_mode" for row in trace.cases)


def test_oath_rfc6238_known_answers():
    assert [otp.otp_value(secret, (1).to_bytes(8, "big"), label, 8) for _, label, secret in otp.OATH_HASHES] == [94287082, 46119246, 90693936]


def test_otp_config_crc_and_full_length_mode():
    variable = otp.slot_config(bytes(range(20)))
    fixed = otp.slot_config(bytes(range(20)), variable=False)
    assert otp.crc16(variable) == otp.crc16(fixed) == 0xF0B8
    assert variable[47] == 0x26 and fixed[47] == 0x22
    assert fixed[16:22] == bytes(range(16, 20)) + bytes(2)


@pytest.mark.parametrize("version", [1, 2])
def test_pin_protocol_ecdh_and_authenticated_encryption(version):
    remote = ec.generate_private_key(ec.SECP256R1())
    point = remote.public_key().public_numbers()
    peer = {1: 2, 3: -25, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}
    protocol = fido.PinProtocol(version, peer)
    platform = ec.EllipticCurvePublicNumbers(int.from_bytes(protocol.cose[-2], "big"), int.from_bytes(protocol.cose[-3], "big"), ec.SECP256R1()).public_key()
    shared = remote.exchange(ec.ECDH(), platform)
    if version == 1:
        assert protocol.mac_key == protocol.aes_key == hashlib.sha256(shared).digest()
    else:
        import cryptography.hazmat.primitives.hmac as crypto_hmac
        prk = crypto_hmac.HMAC(bytes(32), hashes.SHA256())
        prk.update(shared)
        extracted = prk.finalize()
        assert protocol.mac_key == hmac.digest(extracted, b"CTAP2 HMAC key\x01", "sha256")
        assert protocol.aes_key == hmac.digest(extracted, b"CTAP2 AES key\x01", "sha256")
    plaintext = bytes(range(64))
    encrypted = protocol.encrypt(plaintext)
    assert len(encrypted) == 64 + (16 if version == 2 else 0)
    assert protocol.decrypt(encrypted) == plaintext
    assert protocol.authenticate(b"message") == hmac.digest(protocol.mac_key, b"message", "sha256")[:16 if version == 1 else 32]


def test_signature_verification_and_tamper_control(tmp_path):
    trace = Trace(tmp_path / "capture", {})
    session = Session(trace)
    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(b"message", ec.ECDSA(hashes.SHA256()))
    with session.case("signature"):
        fido.verified(session, "valid", key.public_key(), -7, signature, b"message")
    with session.case("wrong-message"):
        fido.verified(session, "invalid", key.public_key(), -7, signature, b"different")
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass"
    assert trace.cases[1]["verdict"] == "fail"
    assert "InvalidSignature" in trace.cases[1]["reason"]


def test_authenticator_data_boundaries_and_extensions():
    key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    cose = {1: 2, 3: -7, -1: 1, -2: key.x.to_bytes(32, "big"), -3: key.y.to_bytes(32, "big")}
    data = bytes(32) + b"\xc1" + bytes(4) + bytes(16) + b"\x00\x02id" + codec.encode(cose) + codec.encode({"credBlob": True})
    parsed = fido.auth_data(data)
    assert parsed["credential_id"] == b"id" and parsed["extensions"] == {"credBlob": True}
    assert encoded_point(fido.public_key(parsed["cose"])) == (key.x, key.y)
    for bad in (data[:36], data[:54], data[:-1], data + b"\x00"):
        with pytest.raises(ValueError):
            fido.auth_data(bad)


def encoded_point(key):
    point = key.public_numbers()
    return point.x, point.y


def test_trezor_cli_profile_cannot_be_overridden(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(oracle, "inventory", lambda: {"hid": [{"id": "wallet", "profile": "trezor", "serial_number": "wallet", "path_hex": "01"}], "readers": []})
    result = oracle.main(["capture", "--out", str(tmp_path / "capture"), "--hid", "wallet", "--profile", "generic", "--exercise"])
    assert result == 2
    assert "cannot be overridden" in capsys.readouterr().err
    from oracle_lib.trace import recover
    run = recover(tmp_path / "capture")
    assert run["execution_outcome"] == "runner_error"
    assert not any(row["command"].startswith("open.") for row in run["exchanges"])


def test_u2f_uses_extended_apdu_encoding():
    request = fido.u2f_apdu(1, data=bytes(64))
    assert request[:7] == bytes.fromhex("00010000000040")
    assert len(request) == 73 and request[-2:] == bytes(2)


def _hanging_otp_worker(pipe, path):
    pipe.send(("ready", b""))
    pipe.recv()
    pipe.send(("io", "tx", b"\x00" * 9, time.monotonic_ns(), {"api": "synthetic_feature"}))
    time.sleep(30)


def test_otp_feature_deadline_terminates_worker(monkeypatch):
    monkeypatch.setattr(otp_hid, "_otp_worker", _hanging_otp_worker)
    origin = time.monotonic_ns()
    clock = lambda: time.monotonic_ns() - origin
    feature = otp_hid.OtpFeature({"path_hex": "00"}, clock, origin)
    events = []
    try:
        with pytest.raises(TransferError) as failure:
            feature.transfer(0x38, bytes(64), 20, clock() + 100_000_000,
                             lambda *args, **kwargs: events.append((args, kwargs)))
        assert failure.value.outcome == Outcome.DEADLINE
        assert not feature.process.is_alive()
        assert events and events[0][0][0] == "tx"
    finally:
        feature.close()


def test_native_otp_never_falls_back_from_an_unknown_path():
    from oracle_lib.native_otp import MacFeature
    with pytest.raises(ValueError, match="exact registry ID"):
        MacFeature(b"unknown-path")
    with pytest.raises(ValueError, match="outside uint64"):
        MacFeature(b"DevSrvsID:18446744073709551616")


def _refused_otp_worker(pipe, path):
    pipe.send(("ready", b""))
    pipe.recv()
    pipe.send(("error", "OSError", "not permitted", 0xE00002E2, "host_rejected"))


def test_otp_os_refusal_is_not_a_device_disconnect(monkeypatch):
    monkeypatch.setattr(otp_hid, "_otp_worker", _refused_otp_worker)
    origin = time.monotonic_ns()
    clock = lambda: time.monotonic_ns() - origin
    feature = otp_hid.OtpFeature({"path_hex": "00"}, clock, origin)
    try:
        with pytest.raises(TransferError) as failure:
            feature.transfer(-1, b"", 0, clock() + 1_000_000_000, lambda *args, **kwargs: None)
        assert failure.value.outcome == Outcome.HOST_REJECTED
        assert failure.value.code == 0xE00002E2
    finally:
        feature.close()
