#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Nitrokey OTP slots 3 & 4 test — drive the OTP applet over PC/SC.

The classic YubiKey OTP application has two slots (short / long touch); this
firmware adds two more (Nitrokey layout), addressed over CCID by the P2 slot
offset:

    configure  P1=0x01 P2=<slot-1>     (P1=0x03 is slot 2 only, P2 must be 0)
    calculate  P1=0x30/0x20 P2=<slot-1>
    status-ext P1=0x14                  -> lists all four slots

Yubico Authenticator / ykman only know slots 1/2, so this is the only way to
exercise 3/4. This programs HMAC-SHA1 challenge-response on slots 3 and 4,
verifies the response against host HMAC, and checks the extended status lists
them. Idempotent: deletes slots 3/4 at start and end (no access code used).
Physically, slots 3/4 are typed by three / four BOOTSEL clicks.

    nix develop -c python tests/74_otp_slots_3_4.py
"""
import hashlib
import hmac as hmac_mod
import os
import struct
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OTP_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
CONFIG_SIZE = 52
TKT_CHAL_RESP, CFG_CHAL_HMAC = 0x40, 0x22
KEY20 = bytes(range(1, 21))


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            lsb = crc & 1
            crc >>= 1
            if lsb:
                crc ^= 0x8408
    return crc


def hmac_config(key20):
    c = bytearray(CONFIG_SIZE)
    c[16:22] = key20[16:20] + bytes(2)  # UID head holds the last 4 key bytes
    c[22:38] = key20[:16]               # AES field holds the first 16
    c[45], c[46], c[47] = 0, TKT_CHAL_RESP, CFG_CHAL_HMAC
    c[50:52] = struct.pack("<H", ~crc16(c[:50]) & 0xFFFF)
    return bytes(c)


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")
    conn = target.createConnection()
    conn.connect()

    def tx(cmd, what, expect=(0x90, 0x00)):
        data, sw1, sw2 = conn.transmit(cmd)
        print("%-32s -> %s %02X%02X" % (what, toHexString(data)[:30], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return bytes(data)

    # P2 = slot - 1 (slot 3 -> P2=2, slot 4 -> P2=3).
    def configure(slot, config):
        tx([0x00, 0x01, 0x01, slot - 1, len(config) + 6] + list(config) + [0] * 6,
           f"CONFIGURE slot {slot}")

    def delete(slot):
        conn.transmit([0x00, 0x01, 0x01, slot - 1, CONFIG_SIZE + 6] + [0] * (CONFIG_SIZE + 6))

    def calculate(slot, challenge):
        return tx([0x00, 0x01, 0x30, slot - 1, len(challenge)] + list(challenge),
                  f"CALCULATE slot {slot} (HMAC)")

    sw = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(OTP_AID)] + OTP_AID)[1:]
    if sw == (0x6A, 0x82):
        fail("OTP AID not found — device runs firmware without the OTP applet?")
    print("SELECT OTP AID -> %02X%02X" % sw)
    for s in (3, 4):
        delete(s)

    challenge = bytes(range(64))  # full 64-byte challenge (no LT64 trimming)
    for slot in (3, 4):
        configure(slot, hmac_config(KEY20))
        resp = calculate(slot, challenge)
        want = hmac_mod.new(KEY20, challenge, hashlib.sha1).digest()
        if resp != want:
            fail(f"slot {slot} HMAC {resp.hex()} != host {want.hex()}")
        print(f"  slot {slot} HMAC-SHA1 verified against host")

    # Extended status (P1=0x14) must list slots 3 and 4 (tags 0xB2, 0xB3).
    ext = tx([0x00, 0x01, 0x14, 0x00, 0x00], "STATUS-EXT (P1=0x14)")
    if 0xB2 not in ext or 0xB3 not in ext:
        fail(f"status-ext missing slot 3/4 tags: {ext.hex()}")
    print("  status-ext lists slots 3 and 4")

    for s in (3, 4):
        delete(s)
    print("  cleanup OK (slots 3/4 deleted)")

    print("\nPASS (OTP slots 3/4 over CCID)")
    print("Manual: program a Yubico-OTP/static slot 3, then 3 BOOTSEL clicks -> it types.")


if __name__ == "__main__":
    main()
