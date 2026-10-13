#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Verify real RSA/ML-DSA operations and transport liveness on a TrustZone ELF.

Only explicit loopback image-emulator sockets are used. Start a fresh no-touch
image; the PIV test uses its default management key and PIN. No getInfo delay
is invoked. Run inside nix develop (cryptography, hidapi and dilithium-py).
"""

import argparse
import hashlib
import json
import socket
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_der_x509_certificate
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

from ctaphid import decode, enc

MAX_GAP_S = 0.5
DEADLINE_S = 1200
READ_TIMEOUT_S = 60
PROCESSING_GRACE_S = 0.15
WTX_GRACE_S = 0.3
CLIENT_DATA_HASH = hashlib.sha256(b"RS-Key TrustZone crypto keepalive").digest()
MLDSA_SETS = [
    ("ML-DSA-44", -48, ML_DSA_44, mldsa.MLDSA44PublicKey, 1312, 2420),
    ("ML-DSA-65", -49, ML_DSA_65, mldsa.MLDSA65PublicKey, 1952, 3309),
    ("ML-DSA-87", -50, ML_DSA_87, mldsa.MLDSA87PublicKey, 2592, 4627),
]


def receive(sock, size):
    body = bytearray()
    while len(body) < size:
        part = sock.recv(size - len(body))
        assert part, "emulator closed the transport socket"
        body.extend(part)
    return bytes(body)


def inspect(port, command):
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        sock.sendall(command.encode() + b"\n")
        with sock.makefile("rb") as stream:
            line = stream.readline(4096).decode().split()
        assert line and line[0] == "ok", line
        return dict(word.split("=", 1) for word in line[1:])


def wait_ready(port):
    deadline = time.monotonic() + READ_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            status = inspect(port, "status")
        except ConnectionRefusedError:
            time.sleep(0.01)
            continue
        assert status["dead"] == "false", "image faulted"
        if status["ready"] == "true":
            return status
        time.sleep(0.01)
    raise AssertionError("image USB did not become ready without a power cycle")


class Measurement:
    def __init__(self, port):
        self.port = port
        self.wall_start = time.monotonic()
        inspect(port, "transport-begin")
        self.keepalives = 0

    def keepalive(self):
        assert time.monotonic() - self.wall_start < DEADLINE_S, "operation deadline expired"
        self.keepalives += 1

    def finish(self):
        trace = inspect(self.port, "transport-end")
        assert int(trace["keepalives"]) == self.keepalives, "socket and USB keepalive counts differ"
        return {
            "image_elapsed_s": int(trace["elapsed_ns"]) / 1_000_000_000,
            "wall_elapsed_s": round(time.monotonic() - self.wall_start, 3),
            "keepalives": self.keepalives,
            "image_max_gap_s": int(trace["max_gap_ns"]) / 1_000_000_000,
        }


def record(operation, result, minimum=0):
    print(json.dumps({"operation": operation, **{k: round(v, 3) if isinstance(v, float) else v for k, v in result.items()}}), flush=True)
    assert result["keepalives"] >= minimum, f"{operation}: only {result['keepalives']} keepalives"
    assert result["image_max_gap_s"] <= MAX_GAP_S, f"{operation}: USB starved for {result['image_max_gap_s']}s"


class Hid:
    def __init__(self, port, inspect_port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=READ_TIMEOUT_S)
        self.inspect_port = inspect_port
        self.cid = b"\xff" * 4
        nonce = b"tzcrypto"
        self.send(0x86, nonce)
        report = receive(self.sock, 64)
        assert report[4:7] == b"\x86\x00\x11" and report[7:15] == nonce, "CTAPHID INIT failed"
        self.cid = report[15:19]

    def send(self, command, body):
        assert len(body) <= 7609
        first = self.cid + bytes([command]) + len(body).to_bytes(2, "big") + body[:57]
        self.sock.sendall(first.ljust(64, b"\0"))
        for seq, off in enumerate(range(57, len(body), 59)):
            self.sock.sendall((self.cid + bytes([seq]) + body[off:off + 59]).ljust(64, b"\0"))

    def ctap(self, command, fields):
        measured = Measurement(self.inspect_port)
        self.send(0x90, bytes([command]) + enc(fields))
        while True:
            report = receive(self.sock, 64)
            assert report[:4] == self.cid, "reply changed CTAPHID channel"
            if report[4] == 0xBB:
                assert report[5:8] == b"\x00\x01\x01", "expected PROCESSING keepalive"
                measured.keepalive()
                continue
            assert report[4] == 0x90, f"CTAPHID returned command {report[4]:#x}"
            result = measured.finish()
            size = int.from_bytes(report[5:7], "big")
            assert 1 <= size <= 7609
            body = bytearray(report[7:])
            seq = 0
            while len(body) < size:
                report = receive(self.sock, 64)
                assert report[:4] == self.cid and report[4] == seq, "response framing failed"
                body.extend(report[5:])
                seq += 1
            body = bytes(body[:size])
            assert body[0] == 0, f"CTAP {command:#x} status {body[0]:#x}"
            return decode(body[1:]), result


def tlv(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else (b"\x81" + bytes([size]) if size < 256 else b"\x82" + size.to_bytes(2, "big"))
    return tag.to_bytes((tag.bit_length() + 7) // 8, "big") + length + value


def parse_tlv(body):
    fields = {}
    while body:
        tag, off = body[0], 1
        if tag & 0x1F == 0x1F:
            tag, off = (tag << 8) | body[1], 2
        size = body[off]
        off += 1
        if size & 0x80:
            width = size & 0x7F
            assert 1 <= width <= 2
            size = int.from_bytes(body[off:off + width], "big")
            off += width
        assert off + size <= len(body) and tag not in fields, "invalid response TLV"
        fields[tag], body = body[off:off + size], body[off + size:]
    return fields


class Ccid:
    def __init__(self, port, inspect_port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=READ_TIMEOUT_S)
        self.inspect_port = inspect_port
        self.seq = 0
        atr, _ = self.call(0x62, b"")
        assert atr.startswith(b"\x3b"), "CCID power-on failed"

    def call(self, command, body):
        seq = self.seq
        self.seq = (seq + 1) % 256
        msg = bytes([command]) + len(body).to_bytes(4, "little") + bytes([0, seq, 0, 0, 0]) + body
        measured = Measurement(self.inspect_port)
        self.sock.sendall(b"\0" + len(msg).to_bytes(4, "big") + msg)
        while True:
            size = int.from_bytes(receive(self.sock, 4), "big")
            assert 10 <= size <= 3072, f"invalid CCID length {size}"
            reply = receive(self.sock, size)
            assert reply[0] == 0x80 and reply[5:7] == bytes([0, seq]), "CCID response changed type/slot/sequence"
            assert int.from_bytes(reply[1:5], "little") == size - 10
            if reply[7] == 0x80:
                assert size == 10 and reply[8:10] == b"\0\0", "invalid CCID time extension"
                measured.keepalive()
                continue
            assert reply[7:10] == b"\0\0\0", f"CCID failed: {reply[7:10].hex()}"
            return reply[10:], measured.finish()

    def apdu(self, ins, p1, p2, body=b""):
        header = bytes([0, ins, p1, p2])
        length = bytes([len(body)]) if len(body) < 256 else b"\0" + len(body).to_bytes(2, "big")
        reply, result = self.call(0x6F, header + (length + body if body else b""))
        data = reply[:-2]
        while reply[-2] == 0x61:
            reply, _ = self.call(0x6F, bytes([0, 0xC0, 0, 0, reply[-1]]))
            data += reply[:-2]
        assert reply[-2:] == b"\x90\0", f"PIV INS {ins:#x} status {reply[-2:].hex()}"
        return data, result


def check_rsa(args):
    piv = Ccid(args.ccid_port, args.inspect_port)
    try:
        piv.apdu(0xA4, 4, 0, bytes.fromhex("a000000308000010000100"))
        key = bytes(range(1, 9)) * 3
        body, _ = piv.apdu(0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, b"")))
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        witness = dec.update(parse_tlv(parse_tlv(body)[0x7C])[0x80]) + dec.finalize()
        challenge = bytes(range(16))
        body, _ = piv.apdu(0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, witness) + tlv(0x81, challenge)))
        encrypt = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        assert parse_tlv(parse_tlv(body)[0x7C])[0x82] == encrypt.update(challenge) + encrypt.finalize()
        print("RSA-2048: generating a key in Secure…", flush=True)
        body, result = piv.apdu(0x47, 0, 0x9C, tlv(0xAC, tlv(0x80, b"\x07")))
        fields = parse_tlv(parse_tlv(body)[0x7F49])
        modulus = int.from_bytes(fields[0x81], "big")
        exponent = int.from_bytes(fields[0x82], "big")
        assert modulus.bit_length() == 2048 and exponent == 65537
        public = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        record("RSA-2048 generate", result, minimum=int(result["image_elapsed_s"] >= WTX_GRACE_S))
        for run in range(args.runs):
            piv.apdu(0x20, 0, 0x80, b"123456\xff\xff")
            message = b"RS-Key TrustZone RSA signature " + bytes([run])
            digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
            encoded = b"\0\x01" + b"\xff" * (256 - 3 - len(digest_info)) + b"\0" + digest_info
            body, result = piv.apdu(0x87, 7, 0x9C, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, encoded)))
            signature = parse_tlv(parse_tlv(body)[0x7C])[0x82]
            assert len(signature) == 256
            public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            try:
                public.verify(signature, message + b"!", padding.PKCS1v15(), hashes.SHA256())
            except InvalidSignature:
                pass
            else:
                raise AssertionError("RSA verifier accepted a changed message")
            record(f"RSA-2048 sign {run + 1}", {**result, "signature_verified": True},
                   minimum=int(result["image_elapsed_s"] >= WTX_GRACE_S))
    finally:
        piv.sock.close()


def check_mldsa(args):
    hid = Hid(args.fido_port, args.inspect_port)
    try:
        for label, alg, dilithium, public_type, pk_size, sig_size in MLDSA_SETS:
            rp = f"tz-{label.lower()}.example"
            print(f"{label}: registering in Secure…", flush=True)
            response, result = hid.ctap(1, {
                1: CLIENT_DATA_HASH, 2: {"id": rp},
                3: {"id": b"tz-crypto", "name": "tz-crypto"},
                4: [{"alg": alg, "type": "public-key"}],
            })
            auth_data = response[2]
            assert auth_data[:32] == hashlib.sha256(rp.encode()).digest() and auth_data[32] & 0x41 == 0x41
            cred_size = int.from_bytes(auth_data[53:55], "big")
            cred_id = auth_data[55:55 + cred_size]
            cose = decode(auth_data[55 + cred_size:])
            assert cred_size > 0 and cose[1] == 7 and cose[3] == alg and len(cose[-1]) == pk_size
            assert response[1] == "packed" and response[3]["alg"] == -7
            attestation = load_der_x509_certificate(response[3]["x5c"][0]).public_key()
            attestation.verify(response[3]["sig"], auth_data + CLIENT_DATA_HASH, ec.ECDSA(hashes.SHA256()))
            record(f"{label} makeCredential", {**result, "attestation_verified": True})
            public = public_type.from_public_bytes(cose[-1])
            for run in range(args.runs):
                response, result = hid.ctap(2, {
                    1: rp, 2: CLIENT_DATA_HASH, 3: [{"id": cred_id, "type": "public-key"}],
                })
                auth_data, signature = response[2], response[3]
                assert len(auth_data) == 37 and auth_data[:32] == hashlib.sha256(rp.encode()).digest() and auth_data[32] & 1
                assert len(signature) == sig_size
                message = auth_data + CLIENT_DATA_HASH
                public.verify(signature, message)
                assert dilithium.verify(cose[-1], message, signature), f"{label}: dilithium-py rejected signature"
                tampered = bytes([signature[0] ^ 1]) + signature[1:]
                assert not dilithium.verify(cose[-1], message, tampered), f"{label}: dilithium-py accepted tamper"
                try:
                    public.verify(tampered, message)
                except InvalidSignature:
                    pass
                else:
                    raise AssertionError(f"{label}: OpenSSL accepted tamper")
                record(f"{label} getAssertion {run + 1}", {**result, "signature_verified": "OpenSSL + dilithium-py"},
                       minimum=int(result["image_elapsed_s"] >= PROCESSING_GRACE_S))
    finally:
        hid.sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fido-port", type=int, required=True)
    parser.add_argument("--ccid-port", type=int, required=True)
    parser.add_argument("--inspect-port", type=int, required=True)
    parser.add_argument("--runs", type=int, default=3, help="signatures per generated key")
    parser.add_argument("--suite", choices=["rsa", "mldsa", "all"], default="all")
    args = parser.parse_args()
    assert 1 <= args.runs <= 255
    wait_ready(args.inspect_port)
    if args.suite in ("rsa", "all"):
        check_rsa(args)
    if args.suite in ("mldsa", "all"):
        check_mldsa(args)
    print("PASS: real crypto verified and transport gaps bounded on the image clock", flush=True)
