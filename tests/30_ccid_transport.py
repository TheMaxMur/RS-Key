#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CCID transport test — drive the device over PC/SC (pyscard).

    nix develop -c python tests/30_ccid_transport.py
    # or from the validation venv (has pyscard):
    nix develop -c python tests/30_ccid_transport.py

Exercises the CCID slice end to end, HID-free: PC/SC -> OS CCID driver -> USB
bulk -> rsk_usb::ccid -> APDU dispatch -> vendor applet. Powers the card on
(the ATR its USB identity calls for), SELECTs the vendor applet by AID, and
increments/reads the persisted counter — the same applet tests/01 drives over CTAPHID_MSG.

INCREMENT is user-presence-gated, so on a board with a button this waits for a
touch; the no-touch test image and `tools/emu` confirm on their own.

Needs pyscard and a running PC/SC daemon (built in on macOS).
"""
import os
import sys

try:
    from smartcard.Exceptions import CardConnectionException
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

# The two ATRs the firmware answers with (without the leading length byte): a
# YubiKey's under the Yubico USB identity, RS-Key's own label under any other VID
# (`firmware/src/main.rs`, `rsk_usb::ccid::ATR_YUBIKEY` / `ATR_RSKEY`).
ATR_YUBIKEY = [
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0,
    0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
]
ATR_RSKEY = [
    0x3B, 0xFC, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0,
    0x21, 0xC0, 0x56, 0x52, 0x53, 0x2D, 0x4B, 0x65, 0x79, 0x4B,
]
# The OpenPGP AID's manufacturer bytes follow the same VID gate as the ATR, so they
# name the ATR to expect without trusting the one under test.
OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
YUBICO_MANUFACTURER = [0x00, 0x06]

VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(VENDOR_AID)] + VENDOR_AID
INCREMENT = [0x00, 0x01, 0x00, 0x00]
GET = [0x00, 0x02, 0x00, 0x00, 0x00]  # Le = 0 (case 2)
# CORE1_STATS: core1's prime-search counters, a timing oracle over RSA keygen.
# Behind `--features core1-stats`, so a shipped image must not answer it.
CORE1_STATS = [0x00, 0x12, 0x00, 0x00, 0x00]
# pcsc-lite's answer to a transmit the reader reports failed.
SCARD_E_NOT_TRANSACTED = 0x80100016


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def expected_atr(conn):
    """The ATR this card's USB identity calls for, read off its OpenPGP AID."""
    _, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID)
    aid, s1, s2 = conn.transmit([0x00, 0xCA, 0x00, 0x4F, 0x00])
    if (sw1, sw2, s1, s2) != (0x90, 0x00, 0x90, 0x00) or len(aid) < 10:
        fail("cannot read the OpenPGP AID that names the card's identity")
    return ATR_YUBIKEY if aid[8:10] == YUBICO_MANUFACTURER else ATR_RSKEY


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")

    conn = target.createConnection()
    conn.connect()

    atr = list(conn.getATR())
    print("ATR:", toHexString(atr))
    want = expected_atr(conn)
    if atr != want:
        fail(f"ATR mismatch\n  got      {toHexString(atr)}\n  expected {toHexString(want)}")

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

    # A YubiKey 5.8.0 answers a class it does not serve (all but 00/04/80/84,
    # chaining aside) with an empty data block, no status word, which PC/SC
    # reports as an error. The card answers the next command as ever.
    try:
        data, sw1, sw2 = conn.transmit([0x40] + SELECT[1:])
    except CardConnectionException as e:
        # hresult 0: the transmit worked and brought back no status word. Any other
        # is the host refusing to send class 40, which proves nothing either way.
        if getattr(e, "hresult", 0):
            print(f"SELECT under class 40 -> not sent by this host ({e}); unchecked")
        else:
            print(f"SELECT under class 40 -> no answer ({e})")
    else:
        fail(f"SELECT under class 40 answered {sw1:02X}{sw2:02X}; a YubiKey answers nothing")
    data, sw1, sw2 = conn.transmit(SELECT)
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"SELECT after the empty answer not 9000 (got {sw1:02X}{sw2:02X})")

    # A block too short for CLA INS P1 P2 is refused by the reader, as a YubiKey
    # 5.8.0 refuses one: a failed slot status, which PC/SC makes a failed transmit.
    try:
        data, sw1, sw2 = conn.transmit([0x40])
    except CardConnectionException as e:
        hresult = getattr(e, "hresult", 0)
        if hresult == SCARD_E_NOT_TRANSACTED:
            print(f"1-byte block -> refused by the reader ({e})")
        elif hresult == 0:
            fail(f"a 1-byte block got an empty answer ({e}); a YubiKey's reader refuses it")
        else:
            print(f"1-byte block -> not sent by this host ({e}); unchecked")
    else:
        fail(f"a 1-byte block was answered {sw1:02X}{sw2:02X}; a YubiKey's reader refuses it")
    data, sw1, sw2 = conn.transmit(SELECT)
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"SELECT after the refused block not 9000 (got {sw1:02X}{sw2:02X})")

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
