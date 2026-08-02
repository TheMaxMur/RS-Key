#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: CTAPHID_CBOR authenticatorGetInfo over USB.

    nix develop -c python tests/10_fido_getinfo.py

Sends a CTAP2 getInfo (command 0x04) and decodes the response, checking
versions (U2F_V2 + FIDO_2_0), the AAGUID, options (rk/up), ES256 in
algorithms, and the firmware version. Carries its own tiny CBOR reader.
"""
import os
import sys

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find, fw_version  # noqa: E402

REPORT_LEN = 64
CTAPHID_INIT = 0x86
CTAPHID_CBOR = 0x90

AAGUID = bytes(
    [0x24, 0x79, 0xC7, 0xBF, 0x6B, 0x30, 0x56, 0x83,
     0x9E, 0xC8, 0x0E, 0x81, 0x71, 0xA9, 0x18, 0xB7]
)
# getInfo firmwareVersion (field 0x0E) packs the version the management applet also
# reports: the default 5.7.4 = (5<<16)|(7<<8)|4.
_MAJOR, _MINOR, _PATCH = fw_version()
FIRMWARE_VERSION = (_MAJOR << 16) | (_MINOR << 8) | _PATCH


def write(dev, payload):
    assert len(payload) <= REPORT_LEN
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev, timeout_ms=2000):
    return bytes(dev.read(REPORT_LEN, timeout_ms))


def send_cbor(dev, cid, payload):
    """Send a (small, single-frame) CTAPHID_CBOR request and reassemble the reply."""
    write(dev, cid + bytes([CTAPHID_CBOR, len(payload) >> 8, len(payload) & 0xFF]) + payload)
    r = read(dev)
    while len(r) >= 5 and r[4] == 0xBB:  # CTAPHID_KEEPALIVE: still processing
        r = read(dev)
    assert r[4] == CTAPHID_CBOR, f"CBOR cmd mismatch: {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7 : 7 + bcnt])
    seq = 0
    while len(data) < bcnt:
        c = read(dev)
        assert c[4] == seq, f"seq mismatch: {c[4]} != {seq}"
        data += c[5 : 5 + min(REPORT_LEN - 5, bcnt - len(data))]
        seq += 1
    return bytes(data[:bcnt])


# --- minimal CBOR decoder (uint/negint/bytes/text/array/map/bool) ---
def _decode(b, i):
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
        val, i = int.from_bytes(b[i : i + 4], "big"), i + 4
    else:
        raise ValueError(f"unsupported additional info {info}")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major == 2:
        return bytes(b[i : i + val]), i + val
    if major == 3:
        return b[i : i + val].decode(), i + val
    if major == 4:
        out = []
        for _ in range(val):
            v, i = _decode(b, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(val):
            k, i = _decode(b, i)
            v, i = _decode(b, i)
            out[k] = v
        return out, i
    if major == 7:
        return {20: False, 21: True}.get(info, None), i
    raise ValueError(f"unsupported major {major}")


def decode(b):
    val, i = _decode(b, 0)
    assert i == len(b), f"trailing CBOR bytes: {i} != {len(b)}"
    return val


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device (usage page 0xF1D0) found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        r = read(dev)
        cid = r[15:19]
        print(f"INIT ok: newcid={cid.hex()} caps={r[23]:#04x}")

        resp = send_cbor(dev, cid, b"\x04")  # authenticatorGetInfo
        assert resp[0] == 0x00, f"getInfo status {resp[0]:#x} != 0"
        m = decode(resp[1:])
        print(f"getInfo: {m}")

        assert "U2F_V2" in m[0x01] and "FIDO_2_0" in m[0x01], f"versions={m[0x01]}"
        assert m[0x03] == AAGUID, f"aaguid={m[0x03].hex()}"
        assert m[0x04].get("rk") is True and m[0x04].get("up") is True, f"options={m[0x04]}"
        algs = [e.get("alg") for e in m[0x0A]]
        assert -7 in algs, f"ES256 (-7) not in algorithms {algs}"
        assert m[0x0E] == FIRMWARE_VERSION, f"firmwareVersion={m[0x0E]:#x}"

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
