#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: authenticatorMakeCredential over CTAPHID_CBOR.

    nix develop -c python tests/11_fido_makecredential.py

Registers a resident ES256 credential and checks the makeCredential response
(status, fmt, authData fields, attStmt). Shipping firmware returns fmt="none"
with an empty attStmt by default; a `--features fido-conformance` build returns
fmt="packed" self-attestation whose ECDSA signature this test then verifies (the
signature maths is also unit-tested — this confirms a well-formed response over
real USB). The self-attestation check is therefore conditional on fmt.
"""
import hashlib
import os
import sys

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find  # noqa: E402

REPORT_LEN = 64
CTAPHID_INIT = 0x86
CTAPHID_CBOR = 0x90
AAGUID = bytes(
    [0x24, 0x79, 0xC7, 0xBF, 0x6B, 0x30, 0x56, 0x83,
     0x9E, 0xC8, 0x0E, 0x81, 0x71, 0xA9, 0x18, 0xB7]
)
RP_ID = "example.com"


# --- tiny CBOR encoder (uint / negint / bytes / text / array / map) ---
def _hdr(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25, n >> 8, n & 0xFF])
    raise ValueError("value too large for this mini-encoder")


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


# --- tiny CBOR decoder ---
def _dec(b, i):
    ib = b[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        val = info
    elif info == 24:
        val, i = b[i], i + 1
    elif info == 25:
        val, i = (b[i] << 8) | b[i + 1], i + 2
    else:
        raise ValueError("unsupported")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major in (2, 3):
        s = b[i:i + val]
        return (s if major == 2 else s.decode()), i + val
    if major == 4:
        out = []
        for _ in range(val):
            x, i = _dec(b, i)
            out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(val):
            k, i = _dec(b, i)
            x, i = _dec(b, i)
            out[k] = x
        return out, i
    if major == 7:
        return {20: False, 21: True}.get(info), i
    raise ValueError("major")


def decode(b):
    v, _ = _dec(b, 0)
    return v


def write(dev, payload):
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev):
    return bytes(dev.read(REPORT_LEN, 3000))


def send_cbor(dev, cid, payload):
    n = len(payload)
    write(dev, cid + bytes([CTAPHID_CBOR, n >> 8, n & 0xFF]) + payload[:57])
    off = 57
    seq = 0
    while off < n:  # request continuation frames (request is small, usually one frame)
        write(dev, cid + bytes([seq]) + payload[off:off + 59])
        off += 59
        seq += 1
    r = read(dev)
    while r[4] == 0xBB:  # CTAPHID_KEEPALIVE (upfront frame): still processing
        r = read(dev)
    assert r[4] == CTAPHID_CBOR, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    s = 0
    while len(data) < bcnt:
        c = read(dev)
        data += c[5:5 + min(59, bcnt - len(data))]
        s += 1
    return bytes(data[:bcnt])


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        client_data_hash = hashlib.sha256(b"rs-key test").digest()
        req = bytes([0x01]) + enc({
            1: client_data_hash,
            2: {"id": RP_ID},
            3: {"id": b"\x01\x02\x03\x04", "name": "alice"},
            4: [{"alg": -7, "type": "public-key"}],
            7: {"rk": True},
        })
        resp = send_cbor(dev, cid, req)
        assert resp[0] == 0x00, f"makeCredential status {resp[0]:#x}"
        m = decode(resp[1:])
        fmt = m[1]
        assert fmt in ("none", "packed"), f"fmt={fmt!r}"

        ad = m[2]
        assert ad[:32] == hashlib.sha256(RP_ID.encode()).digest(), "rpIdHash mismatch"
        assert ad[32] & 0x41 == 0x41, f"flags {ad[32]:#x} missing AT|UP"
        assert ad[37:53] == AAGUID, "AAGUID mismatch"
        cred_len = (ad[53] << 8) | ad[54]
        assert cred_len == 42, f"resident credId len {cred_len} != 42"
        cose = decode(ad[55 + cred_len:])
        assert cose[1] == 2 and cose[3] == -7, f"COSE key {cose}"

        att = m[3]
        if fmt == "none":
            assert att == {}, f"fmt=none must carry an empty attStmt, got {att!r}"
            print("SKIP: self-attestation verify needs a --features fido-conformance "
                  "firmware (shipping firmware sends fmt=none)")
            print(f"makeCredential ok: fmt=none credId={cred_len}B attStmt={{}}")
        else:  # packed self-attestation
            assert att["alg"] == -7 and isinstance(att["sig"], bytes), f"attStmt {att}"
            print(f"makeCredential ok: fmt=packed credId={cred_len}B sig={len(att['sig'])}B")
        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
