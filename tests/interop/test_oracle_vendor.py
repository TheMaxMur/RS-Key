# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Cryptographic peers exercise the ordinary vendor entry points without USB."""
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oracle_lib import codec, vendor_cases
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


class VendorPeer:
    layer = "hid_report"

    def __init__(self, defect=None):
        self.defect = defect
        self.channel = None
        self.seed = bytes(range(32))
        self.device_key = ec.derive_private_key(42, ec.SECP256R1())
        self.epoch = bytes(32)
        self.entries = bytes(20)

    def transfer(self, command, request, deadline, observe):
        observe("tx", request)
        assert command == 0x10
        status, result = 0, {}
        if request[0] == 4:
            result = {1: ["FIDO_2_1"], 4: {"clientPin": False}}
        else:
            assert request[0] == 0x41
            fields = codec.decode(request[1:])
            subcommand, params = fields[1], fields.get(2, {})
            if subcommand == 5:
                result = {1: False, 2: True}
            elif subcommand == 1:
                if self.channel:
                    status, self.channel = 0x30, None
                else:
                    try:
                        point = params[1]
                        assert len(point[-2]) == len(point[-3]) == 32
                        peer = ec.EllipticCurvePublicNumbers(int.from_bytes(point[-2], "big"), int.from_bytes(point[-3], "big"), ec.SECP256R1()).public_key()
                        shared = self.device_key.exchange(ec.ECDH(), peer)
                        own = self.device_key.public_key().public_numbers()
                        result = {1: {1: 2, 3: -25, -1: 1, -2: own.x.to_bytes(32, "big"), -3: own.y.to_bytes(32, "big")}}
                        aad = b"\x04" + result[1][-2] + result[1][-3]
                        salt, context = b"", aad
                        if params.get(2):
                            from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
                            secret, ciphertext = MLKEM768PublicKey.from_public_bytes(params[2]).encapsulate()
                            result[2], shared = ciphertext, shared + secret
                            salt, context = b"RSK-MSE-PQ-v1", aad + ciphertext
                        if self.defect == "wrong-KDF-domain":
                            context += b"wrong"
                        self.channel = HKDF(hashes.SHA256(), 32, salt, context).derive(shared), aad
                    except (KeyError, ValueError, AssertionError):
                        status = 2
            elif subcommand == 2:
                if self.channel is None:
                    status = 0x30
                else:
                    key, aad = self.channel
                    nonce = bytes(12)
                    result = {1: nonce + ChaCha20Poly1305(key).encrypt(nonce, self.seed, aad)}
                    if self.defect != "channel-reuse":
                        self.channel = None
            elif subcommand == 7:
                result = {1: 0, 2: 1, 3: self.epoch, 4: self.entries}
            elif subcommand == 8:
                nonce = params[1]
                if len(nonce) > 32:
                    status = 2
                else:
                    head = hashlib.sha256(self.epoch + self.entries).digest()
                    message = b"RSK-AUDIT-CKPT-v1" + head + (1).to_bytes(4, "little") + nonce
                    if self.defect == "unbound-nonce":
                        message = message[:-len(nonce)] if nonce else message + b"x"
                    signature = self.device_key.sign(message, ec.ECDSA(hashes.SHA256()))
                    result = {1: head, 2: 1, 3: signature,
                              4: self.device_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)}
            else:
                raise AssertionError(f"unexpected vendor subcommand {subcommand}")
        response = bytes([status]) + (codec.encode(result) if status == 0 else b"")
        observe("rx", response)
        return Reply(response, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("wrong-KDF-domain", "InvalidTag"),
                                          ("channel-reuse", "consumed channel cannot export again")])
def test_MSE_export_and_consumption_have_independent_crypto_controls(tmp_path, defect, expected):
    trace = Trace(tmp_path / "MSE", {})
    session = Session(trace, hid=VendorPeer(defect), profile="rsk", options=Options(exercise=True, touch=True))
    vendor_cases.mse(session)
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases)
    else:
        assert any(expected in row["reason"] for row in failures), failures


@pytest.mark.parametrize("defect", [None, "unbound-nonce"])
def test_audit_signature_covers_host_nonce_and_chain_head(tmp_path, defect):
    trace = Trace(tmp_path / "audit", {})
    session = Session(trace, hid=VendorPeer(defect), profile="rsk", options=Options(touch=True))
    vendor_cases.audit(session)
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect is None:
        assert not failures, failures
    else:
        assert failures and any("InvalidSignature" in row["reason"] for row in failures)
