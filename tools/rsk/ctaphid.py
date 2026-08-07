#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Shared CTAPHID + CTAP2 clientPIN helpers (kept in sync with tests/ctaphid.py):
raw CTAPHID transport (INIT / CBOR with fragmentation), a canonical CBOR codec,
and PIN/UV-auth protocol two (`Protocol2`). Needs `hidapi` + `cryptography`.
"""
import os
import sys
import time

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

from cryptography.hazmat.primitives import hashes, hmac as chmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

REPORT_LEN = 64
CTAPHID_INIT = 0x86
CTAPHID_CBOR = 0x90
CTAPHID_KEEPALIVE = 0xBB  # CTAPHID_KEEPALIVE status frame (device still processing)
CTAP_GET_INFO = 0x04  # CTAP2 authenticatorGetInfo
FIDO_USAGE_PAGE = 0xF1D0  # FIDO HID usage page (CTAPHID spec)
# The Usage Page (0xF1D0) item as it appears in a HID report descriptor. Used to
# confirm a FIDO device when hidapi leaves `usage_page` unset (some Linux
# libusb/hidraw builds report 0), so detection stays VID/PID-agnostic.
FIDO_USAGE_PAGE_ITEM = b"\x06\xd0\xf1"
# Ceiling on the keepalive wait: a hostile device can stream keepalives forever, so bail
# past any legitimate ceremony (30s presence window + flash-GC slack) rather than hang.
KEEPALIVE_DEADLINE_S = 120
# Max CBOR nesting a well-formed device response uses; deeper is a hostile/broken device
# trying to overflow the recursive decoder.
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
    # A hostile device can nest arrays/maps to overflow this recursive decoder; bound it.
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
        # The text is device-controlled; a strict decode would crash on invalid UTF-8.
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


def find():
    """The single FIDO HID device, or None. Prefer `find_all` when it matters which
    device is acted on — this returns the first match and cannot tell you there were
    others."""
    found = find_all()
    return found[0] if found else None


def find_all():
    """Every attached FIDO HID device, in enumeration order.

    Destructive and identity-bearing commands must resolve exactly one: the CCID half
    of the tooling picks its device by *reader name*, so with two authenticators
    attached a bare first-match here silently pairs one device's applets with another
    device's FIDO identity (audit run-31)."""
    devices = hid.enumerate()
    found = [d for d in devices if d.get("usage_page") == FIDO_USAGE_PAGE]
    if found:
        return found
    # hidapi left usage_page unset (0/None) — read each such device's report
    # descriptor and match the FIDO usage-page item directly, rather than guessing
    # by VID/PID (RS-Key ships several presets, so no fixed pair to key off).
    return [d for d in devices if not d.get("usage_page") and _declares_fido(d.get("path"))]


def _declares_fido(path):
    """Open `path` and report whether its HID report descriptor names the FIDO
    usage page. Passive read; any hidapi error means "treat as non-FIDO, skip"."""
    if not path:
        return False
    dev = hid.device()
    try:
        dev.open_path(path)
        desc = bytes(dev.get_report_descriptor())
    except (OSError, ValueError, TypeError, AttributeError):
        return False
    finally:
        dev.close()
    return FIDO_USAGE_PAGE_ITEM in desc


def write(dev, payload):
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev):
    # 20s: absorbs flash-GC stalls during long ops (reset / resident
    # makeCredential) — the device sends one upfront keepalive, not a stream.
    return bytes(dev.read(REPORT_LEN, 20000))


def ctaphid_init(dev):
    """CTAPHID INIT with a random nonce; returns the 4-byte channel id."""
    return ctaphid_init_caps(dev)[0]


def ctaphid_init_caps(dev):
    """CTAPHID INIT; returns `(channel id, capability byte)`.

    The capability byte is the last of the 17 payload bytes. `rsk identify` reads
    it: bit 0 (WINK) is the device saying it has an indicator to flash, so a build
    without one is reported rather than sent a command it answers invisibly."""
    write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + os.urandom(8))
    r = read(dev)
    assert r[4] == CTAPHID_INIT
    return bytes(r[15:19]), r[23]


def send_cbor(dev, cid, payload):
    n = len(payload)
    write(dev, cid + bytes([CTAPHID_CBOR, n >> 8, n & 0xFF]) + payload[:57])
    off, seq = 57, 0
    while off < n:
        write(dev, cid + bytes([seq]) + payload[off:off + 59])
        off, seq = off + 59, seq + 1
    r = read(dev)
    # A hostile device can stream keepalives forever (each read() returns before the idle
    # timeout, so a per-frame timeout never fires); bound the total wait rather than spin.
    deadline = time.monotonic() + KEEPALIVE_DEADLINE_S
    while len(r) >= 5 and r[4] == CTAPHID_KEEPALIVE:
        if time.monotonic() > deadline:
            raise IOError("device kept sending CTAPHID keepalives past the deadline")
        r = read(dev)
    assert len(r) >= 5, "empty HID read (device timed out / dropped report)"
    assert r[4] == CTAPHID_CBOR, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    while len(data) < bcnt:
        # Bound the wall clock, not just the byte budget: a device trickling one 6-byte
        # frame per HID timeout makes progress every iteration, so the guards below never
        # fire — it would otherwise hold us for hours (audit run-30).
        if time.monotonic() > deadline:
            raise IOError("device stalled mid-response — CTAPHID reassembly deadline exceeded")
        c = read(dev)
        # A hostile/broken device can announce a large BCNT and then stop sending
        # continuation frames; read() returns b"" on the HID timeout, so bail rather
        # than spin forever.
        if not c:
            raise IOError("device did not send the full CTAPHID response")
        # A frame with no payload past the 5-byte header (cid+seq) makes no progress —
        # bail instead of looping forever on a stream of short frames.
        if len(c) < 6:
            raise IOError("short CTAPHID continuation frame")
        data += c[5:5 + min(59, bcnt - len(data))]
    return bytes(data[:bcnt])


def client_pin(dev, cid, fields):
    return send_cbor(dev, cid, bytes([0x06]) + enc(fields))


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
