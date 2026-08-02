#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Flash-pipeline test: drive the vendor counter applet over CTAPHID_MSG.

    pip install hidapi      # or: uv pip install hidapi
    python tests/01_flash_persistence.py

Exercises CTAPHID_MSG -> APDU dispatch -> vendor applet -> flash: SELECT by
AID, increment the persisted u32 counter, read it back. To prove persistence,
power-cycle the board (hold BOOT, tap RESET — NOT re-flash) and run again: the
"before" value must have carried over, not reset to 0.
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
CTAPHID_MSG = 0x83
CTAPHID_ERROR = 0xBF

VENDOR_AID = bytes([0xF0, 0x00, 0x00, 0x00, 0x01])
APDU_SELECT = bytes([0x00, 0xA4, 0x04, 0x00, len(VENDOR_AID)]) + VENDOR_AID
APDU_INCREMENT = bytes([0x00, 0x01, 0x00, 0x00, 0x00])  # INS 0x01, Le=0
APDU_GET = bytes([0x00, 0x02, 0x00, 0x00, 0x00])  # INS 0x02, Le=0
SW_OK = b"\x90\x00"


def write_frame(dev, payload):
    assert len(payload) <= REPORT_LEN
    # hidapi wants a leading report-id byte (0x00) for report-id-less devices.
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read_frame(dev, timeout_ms=1000):
    return bytes(dev.read(REPORT_LEN, timeout_ms))


def ctaphid_init(dev):
    nonce = bytes(range(8))
    write_frame(dev, b"\xff\xff\xff\xff\x86\x00\x08" + nonce)
    r = read_frame(dev)
    assert r[4] == 0x86, f"INIT cmd mismatch: {r[4]:#x}"
    assert r[7:15] == nonce, "INIT nonce mismatch"
    return r[15:19]  # newcid


def msg(dev, cid, apdu):
    """Send one APDU as a CTAPHID_MSG and return (response_data, sw) bytes."""
    assert len(apdu) <= REPORT_LEN - 7, "this test only frames single-packet APDUs"
    write_frame(dev, cid + bytes([CTAPHID_MSG, len(apdu) >> 8, len(apdu) & 0xFF]) + apdu)

    r = read_frame(dev)
    if r[4] == CTAPHID_ERROR:
        sys.exit(f"device returned CTAPHID_ERROR code={r[7]:#04x}")
    assert r[4] == CTAPHID_MSG, f"unexpected response cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    payload = bytearray(r[7 : 7 + bcnt])
    while len(payload) < bcnt:  # reassemble continuation frames (not needed for tiny replies)
        c = read_frame(dev)
        payload += c[5 : 5 + (bcnt - len(payload))]
    if len(payload) < 2:
        sys.exit(f"response too short: {payload.hex()}")
    return bytes(payload[:-2]), bytes(payload[-2:])


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device (usage page 0xF1D0) found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        cid = ctaphid_init(dev)
        print(f"INIT ok: newcid={cid.hex()}")

        data, sw = msg(dev, cid, APDU_SELECT)
        if sw != SW_OK:
            sys.exit(f"SELECT failed: SW={sw.hex()} (is the vendor applet registered?)")
        print(f"SELECT {VENDOR_AID.hex()} ok: SW={sw.hex()}")

        data, sw = msg(dev, cid, APDU_GET)
        assert sw == SW_OK and len(data) == 4, f"GET failed: data={data.hex()} SW={sw.hex()}"
        before = int.from_bytes(data, "big")
        print(f"counter before = {before}")

        data, sw = msg(dev, cid, APDU_INCREMENT)
        assert sw == SW_OK and len(data) == 4, f"INCREMENT failed: data={data.hex()} SW={sw.hex()}"
        incremented = int.from_bytes(data, "big")
        print(f"increment returned = {incremented}")

        data, sw = msg(dev, cid, APDU_GET)
        after = int.from_bytes(data, "big")
        print(f"counter after  = {after}")

        assert incremented == before + 1, f"increment math wrong: {before} -> {incremented}"
        assert after == incremented, f"read-back mismatch: {after} != {incremented}"

        print("\nIn-boot read/write PASS")
        print(
            f"Persistence check: counter is now {after}. Power-cycle the board "
            f"(hold BOOT, tap RESET — do NOT re-flash) and run this again; "
            f"'counter before' must read {after}, not 0."
        )
    finally:
        dev.close()


if __name__ == "__main__":
    main()
