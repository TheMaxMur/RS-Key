#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Shared CTAPHID + CTAP2 clientPIN helpers for the device test suite: raw
CTAPHID transport (INIT / CBOR with fragmentation), a canonical CBOR codec,
and PIN/UV-auth protocol two (`Protocol2`). Needs `hidapi` + `cryptography`.

Which device those helpers talk to is `_device.find`, re-exported here for the
suites that already import their transport from this module.
"""
import os
import sys
import time

try:
    import hid  # also re-exported: the suites open their device with `ctaphid.hid`
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

from cryptography.hazmat.primitives import hashes, hmac as chmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from _device import find, find_all  # noqa: F401  (re-exported for the suites)

REPORT_LEN = 64
CTAPHID_INIT = 0x86
CTAPHID_CBOR = 0x90
CTAPHID_KEEPALIVE = 0xBB  # device-still-processing status frame
CTAP_CLIENT_PIN = 0x06  # CTAP2 authenticatorClientPIN (naming mirrors tools/rsk/ctaphid.py)
# Bound the keepalive wait and CBOR recursion so a broken/hostile device cannot hang or
# crash the test runner (mirrors tools/rsk/ctaphid.py).
KEEPALIVE_DEADLINE_S = 120
CBOR_MAX_DEPTH = 32


def _hdr(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25, n >> 8, n & 0xFF])
    if n < 2**32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def enc(v):
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return _hdr(0, v) if v >= 0 else _hdr(1, -1 - v)
    if isinstance(v, bytes):
        return _hdr(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return _hdr(3, len(b)) + b
    if isinstance(v, list):
        return _hdr(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        return _hdr(5, len(v)) + b"".join(enc(k) + enc(val) for k, val in v.items())
    raise TypeError(type(v))


def _dec(b, i, depth=0):
    if depth > CBOR_MAX_DEPTH:
        raise ValueError("CBOR nesting too deep")
    ib = b[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        val = info
    elif info == 24:
        val, i = b[i], i + 1
    elif info == 25:
        val, i = (b[i] << 8) | b[i + 1], i + 2
    elif info == 26:
        val, i = int.from_bytes(b[i:i + 4], "big"), i + 4
    elif info == 27:
        val, i = int.from_bytes(b[i:i + 8], "big"), i + 8
    else:
        raise ValueError("unsupported")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major in (2, 3):
        s = b[i:i + val]
        return (s if major == 2 else s.decode("utf-8", "replace")), i + val
    if major == 4:
        out = []
        for _ in range(val):
            x, i = _dec(b, i, depth + 1)
            out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(val):
            k, i = _dec(b, i, depth + 1)
            x, i = _dec(b, i, depth + 1)
            out[k] = x
        return out, i
    if major == 7:
        return {20: False, 21: True}.get(info), i
    raise ValueError("major")


def decode(b):
    return _dec(b, 0)[0]


def write(dev, payload):
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev):
    # 20s: absorbs flash-GC stalls during long ops (reset / resident
    # makeCredential) — the device sends one upfront keepalive, not a stream.
    return bytes(dev.read(REPORT_LEN, 20000))


def ctaphid_init(dev):
    """CTAPHID INIT with a random nonce; returns the 4-byte channel id."""
    write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + os.urandom(8))
    r = read(dev)
    assert r[4] == CTAPHID_INIT
    return bytes(r[15:19])


def send_cbor(dev, cid, payload):
    n = len(payload)
    write(dev, cid + bytes([CTAPHID_CBOR, n >> 8, n & 0xFF]) + payload[:57])
    off, seq = 57, 0
    while off < n:
        write(dev, cid + bytes([seq]) + payload[off:off + 59])
        off, seq = off + 59, seq + 1
    r = read(dev)
    deadline = time.monotonic() + KEEPALIVE_DEADLINE_S
    while len(r) >= 5 and r[4] == CTAPHID_KEEPALIVE:  # still processing
        if time.monotonic() > deadline:
            raise IOError("device kept sending CTAPHID keepalives past the deadline")
        r = read(dev)
    assert len(r) >= 5, "empty HID read (device timed out / dropped report)"
    assert r[4] == CTAPHID_CBOR, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    while len(data) < bcnt:
        c = read(dev)
        if not c:
            raise IOError("device did not send the full CTAPHID response")
        if len(c) < 6:
            raise IOError("short CTAPHID continuation frame")
        data += c[5:5 + min(59, bcnt - len(data))]
    return bytes(data[:bcnt])


def client_pin(dev, cid, fields):
    return send_cbor(dev, cid, bytes([CTAP_CLIENT_PIN]) + enc(fields))


class Protocol2:
    """Platform side of CTAP2 PIN/UV-auth protocol two."""

    def __init__(self, auth_x, auth_y):
        auth_pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(auth_x, "big"), int.from_bytes(auth_y, "big"), ec.SECP256R1()
        ).public_key()
        self.priv = ec.generate_private_key(ec.SECP256R1())
        nums = self.priv.public_key().public_numbers()
        self.x = nums.x.to_bytes(32, "big")
        self.y = nums.y.to_bytes(32, "big")
        z = self.priv.exchange(ec.ECDH(), auth_pub)
        self.hmac_key = self._hkdf(z, b"CTAP2 HMAC key")
        self.aes_key = self._hkdf(z, b"CTAP2 AES key")

    @staticmethod
    def _hkdf(z, info):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info).derive(z)

    def cose(self):
        return {1: 2, 3: -25, -1: 1, -2: self.x, -3: self.y}

    def encrypt(self, pt):
        iv = os.urandom(16)
        c = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        return iv + c.update(pt) + c.finalize()

    def decrypt(self, ct):
        d = Cipher(algorithms.AES(self.aes_key), modes.CBC(ct[:16])).decryptor()
        return d.update(ct[16:]) + d.finalize()

    def authenticate(self, msg):
        h = chmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(msg)
        return h.finalize()


def get_retries(dev, cid):
    r = client_pin(dev, cid, {1: 2, 2: 1})
    assert r[0] == 0x00, f"getPINRetries status {r[0]:#x}"
    return decode(r[1:])[3]
