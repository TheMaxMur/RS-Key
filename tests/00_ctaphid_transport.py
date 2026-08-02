#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Smoke test: find the rs-key FIDO HID device and run CTAPHID INIT + PING.

    pip install hidapi      # or: uv pip install hidapi
    python tests/00_ctaphid_transport.py

Exercises channel allocation (INIT) and the PING echo.
"""
import os
import sys

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find  # noqa: E402

REPORT_LEN = 64


def write(dev, payload):
    assert len(payload) <= REPORT_LEN
    # hidapi wants a leading report-id byte (0x00) for report-id-less devices.
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev, timeout_ms=1000):
    return bytes(dev.read(REPORT_LEN, timeout_ms))


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device (usage page 0xF1D0) found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        # ---- CTAPHID_INIT on the broadcast channel ----
        nonce = bytes(range(8))
        write(dev, b"\xff\xff\xff\xff\x86\x00\x08" + nonce)
        r = read(dev)
        assert r[4] == 0x86, f"INIT cmd mismatch: {r[4]:#x}"
        assert r[7:15] == nonce, f"nonce mismatch: {r[7:15].hex()} != {nonce.hex()}"
        newcid = r[15:19]
        print(
            f"INIT ok: newcid={newcid.hex()} iface_ver={r[19]} "
            f"version={r[20]}.{r[21]}.{r[22]} caps={r[23]:#04x}"
        )

        # ---- CTAPHID_PING (single frame) ----
        payload = b"rs-key transport ping"
        write(dev, newcid + b"\x81" + bytes([len(payload) >> 8, len(payload) & 0xFF]) + payload)
        r = read(dev)
        bcnt = (r[5] << 8) | r[6]
        got = r[7 : 7 + bcnt]
        assert r[4] == 0x81, f"PING cmd mismatch: {r[4]:#x}"
        assert got == payload, f"PING echo mismatch: {got!r} != {payload!r}"
        print(f"PING ok: echoed {got!r}")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
