#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: register (makeCredential) then log in (getAssertion) over CTAPHID_CBOR.

    nix develop -c python tests/12_fido_getassertion.py

Registers a non-resident ES256 credential, then runs getAssertion twice with it
in the allowList. Checks the assertion structure (credential id echoed, rpIdHash,
UP flag, signature present) and that the signature counter stays 0.

Zero is the answer here, not a placeholder: signature counters are per-credential
(`EF_CRED_CTR`) so that an RP cannot correlate one credential's use with another's,
and a non-resident credential keeps no on-device state to count in — `getassertion.rs`
reports 0 for it and advances nothing. This test asserted a strict increment until
2026-08-08, three weeks after the counters became per-credential; it was green
last on the global counter. The increment is covered where the state exists:
`getassertion_tests.rs` for resident credentials, `13_u2f.py` for U2F.
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
RP_ID = "example.com"


def _hdr(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    return bytes([(major << 5) | 25, n >> 8, n & 0xFF])


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
    return _dec(b, 0)[0]


def write(dev, payload):
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev):
    return bytes(dev.read(REPORT_LEN, 3000))


def send_cbor(dev, cid, payload):
    n = len(payload)
    write(dev, cid + bytes([CTAPHID_CBOR, n >> 8, n & 0xFF]) + payload[:57])
    off, seq = 57, 0
    while off < n:
        write(dev, cid + bytes([seq]) + payload[off:off + 59])
        off, seq = off + 59, seq + 1
    r = read(dev)
    while len(r) >= 5 and r[4] == 0xBB:  # CTAPHID_KEEPALIVE: still processing
        r = read(dev)
    assert r[4] == CTAPHID_CBOR, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    while len(data) < bcnt:
        c = read(dev)
        data += c[5:5 + min(59, bcnt - len(data))]
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
        cdh = hashlib.sha256(b"rs-key test").digest()
        rp_hash = hashlib.sha256(RP_ID.encode()).digest()

        # Register (non-resident).
        mc = send_cbor(dev, cid, bytes([0x01]) + enc({
            1: cdh,
            2: {"id": RP_ID},
            3: {"id": b"\x09\x08\x07\x06", "name": "bob"},
            4: [{"alg": -7, "type": "public-key"}],
        }))
        assert mc[0] == 0x00, f"makeCredential status {mc[0]:#x}"
        ad = decode(mc[1:])[2]
        cred_len = (ad[53] << 8) | ad[54]
        cred_id = ad[55:55 + cred_len]
        print(f"registered: credId={cred_len}B")

        def login():
            ga = send_cbor(dev, cid, bytes([0x02]) + enc({
                1: RP_ID,
                2: cdh,
                3: [{"type": "public-key", "id": cred_id}],
            }))
            assert ga[0] == 0x00, f"getAssertion status {ga[0]:#x}"
            m = decode(ga[1:])
            assert m[1]["id"] == cred_id, "credential id mismatch"
            a = m[2]
            assert a[:32] == rp_hash, "rpIdHash mismatch"
            assert a[32] & 0x01 == 0x01, f"UP flag missing ({a[32]:#x})"
            assert a[32] & 0x40 == 0x00, "assertion authData must not set AT"
            assert isinstance(m[3], bytes) and len(m[3]) >= 64, f"sig len {len(m[3])}"
            ctr = int.from_bytes(a[33:37], "big")
            return ctr, len(m[3])

        c1, siglen = login()
        c2, _ = login()
        print(f"login ok: sig={siglen}B counter {c1} -> {c2}")
        assert (c1, c2) == (0, 0), f"non-resident credential reported a counter ({c1} -> {c2})"

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
