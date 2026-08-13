#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CCID transport test — drive the device over PC/SC (pyscard).

    nix develop -c python tests/30_ccid_transport.py
    # or from the validation venv (has pyscard):
    nix develop -c python tests/30_ccid_transport.py

Exercises the CCID slice end to end, HID-free: PC/SC -> OS CCID driver -> USB
bulk -> rsk_usb::ccid -> APDU dispatch -> vendor applet. Powers the card on
(FIDO ATR), SELECTs the vendor applet by AID, and increments/reads the
persisted counter — the same applet tests/01 drives over CTAPHID_MSG.

INCREMENT is user-presence-gated, so on a board with a button this waits for a
touch; the no-touch test image and `tools/emu` confirm on their own.

Needs pyscard and a running PC/SC daemon (built in on macOS).
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

# The FIDO ATR the firmware answers with (without its leading length byte).
ATR_FIDO = [
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0,
    0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
]

VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(VENDOR_AID)] + VENDOR_AID
INCREMENT = [0x00, 0x01, 0x00, 0x00]
GET = [0x00, 0x02, 0x00, 0x00, 0x00]  # Le = 0 (case 2)
# CORE1_STATS: core1's prime-search counters, a timing oracle over RSA keygen.
# Behind `--features core1-stats`, so a shipped image must not answer it.
CORE1_STATS = [0x00, 0x12, 0x00, 0x00, 0x00]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")

    conn = target.createConnection()
    conn.connect()

    atr = list(conn.getATR())
    print("ATR:", toHexString(atr))
    if atr != ATR_FIDO:
        fail(f"ATR mismatch\n  got      {toHexString(atr)}\n  expected {toHexString(ATR_FIDO)}")

    data, sw1, sw2 = conn.transmit(SELECT)
    print("SELECT vendor AID -> %02X%02X" % (sw1, sw2))
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"SELECT not 9000 (got {sw1:02X}{sw2:02X})")

    data, sw1, sw2 = conn.transmit(INCREMENT)
    print("INC -> %s %02X%02X" % (toHexString(data), sw1, sw2))
    if (sw1, sw2) != (0x90, 0x00) or len(data) != 4:
        fail("INCREMENT did not return a 4-byte counter + 9000")
    inc = int.from_bytes(bytes(data), "big")

    data, sw1, sw2 = conn.transmit(GET)
    print("GET -> %s %02X%02X" % (toHexString(data), sw1, sw2))
    if (sw1, sw2) != (0x90, 0x00) or len(data) != 4:
        fail("GET did not return a 4-byte counter + 9000")
    cur = int.from_bytes(bytes(data), "big")

    if cur != inc:
        fail(f"counter mismatch: INC returned {inc}, GET returned {cur}")

    print(f"counter = {cur} (consistent across INC/GET over CCID)")

    # A board assertion, not an emulator one: `tools/emu`'s `EmuVendorPlatform`
    # never implemented `core1_stats`, so the shim answers 6D00 either way. What
    # this catches is a firmware built with the debug feature reaching a key.
    data, sw1, sw2 = conn.transmit(CORE1_STATS)
    print("CORE1_STATS -> %s %02X%02X" % (toHexString(data), sw1, sw2))
    if (sw1, sw2) != (0x6D, 0x00) or data:
        fail("INS 12 (core1 stats) answered on a shipping image — a keygen timing oracle")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
