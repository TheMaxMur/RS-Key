#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Management-applet test — drive the Yubico management applet over PC/SC.

SELECTs the management AID (A0 00 00 05 27 47 11 17) and reads its config, the
same path `ykman` / Yubico Authenticator / `nitropy` use to identify the key and
show its firmware version. Read-only and idempotent (no WRITE CONFIG — that's
covered by the rsk-mgmt and rsk-devconf host tests). Run from the venv that has pyscard:

    nix develop -c python tests/70_management.py
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID
READ_CONFIG = [0x00, 0x1D, 0x00, 0x00, 0x00]  # case 2 (Le = 0 → 256)

# Expected reported version (Yubico-encoded 5.7.4, matches getInfo 0x0E).
WANT_VERSION = [5, 7, 4]

# Management config tags / capability bits.
TAG_USB_SUPPORTED, TAG_SERIAL, TAG_FORM_FACTOR, TAG_VERSION = 0x01, 0x02, 0x04, 0x05
CAP_OTP, CAP_U2F, CAP_PIV, CAP_OPENPGP, CAP_OATH, CAP_FIDO2 = 0x01, 0x02, 0x10, 0x08, 0x20, 0x200


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def tlv_parse(blob):
    out, i = {}, 0
    while i + 2 <= len(blob):
        tag, ln = blob[i], blob[i + 1]
        if i + 2 + ln > len(blob):
            break
        out[tag] = blob[i + 2 : i + 2 + ln]
        i += 2 + ln
    return out


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")

    conn = target.createConnection()
    conn.connect()

    data, sw1, sw2 = conn.transmit(SELECT)
    ver_str = bytes(data).decode("ascii", "replace")
    print("SELECT mgmt AID -> %r %02X%02X" % (ver_str, sw1, sw2))
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"SELECT not 9000 (got {sw1:02X}{sw2:02X})")
    if ver_str != "5.7.4":
        fail(f"SELECT version string {ver_str!r} != '5.7.4'")

    data, sw1, sw2 = conn.transmit(READ_CONFIG)
    print("READ CONFIG -> %s %02X%02X" % (toHexString(data), sw1, sw2))
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"READ CONFIG not 9000 (got {sw1:02X}{sw2:02X})")
    if not data or data[0] != len(data) - 1:
        fail("READ CONFIG overall-length byte mismatch")

    tlv = tlv_parse(data[1:])
    ver = tlv.get(TAG_VERSION)
    print("  version:", ver)
    if ver != WANT_VERSION:
        fail(f"TAG_VERSION {ver} != {WANT_VERSION}")

    caps_b = tlv.get(TAG_USB_SUPPORTED)
    if not caps_b or len(caps_b) != 2:
        fail("TAG_USB_SUPPORTED missing / not 2 bytes")
    caps = (caps_b[0] << 8) | caps_b[1]
    want_caps = CAP_FIDO2 | CAP_U2F | CAP_OPENPGP | CAP_OATH | CAP_OTP | CAP_PIV
    print("  capabilities: 0x%03X (FIDO2|U2F|OpenPGP|OATH|OTP|PIV=0x%03X)" % (caps, want_caps))
    if caps != want_caps:
        # Older firmware reports fewer bits; newer firmware must match exactly.
        if caps | CAP_PIV == want_caps:
            fail("capabilities lack PIV — device runs older firmware?")
        if caps | CAP_OATH | CAP_OTP | CAP_PIV == want_caps:
            fail("capabilities lack OATH/OTP/PIV — device runs older firmware?")
        fail(f"capabilities 0x{caps:03X} != 0x{want_caps:03X}")

    serial = tlv.get(TAG_SERIAL)
    if not serial or len(serial) != 4:
        fail("TAG_SERIAL missing / not 4 bytes")
    print("  serial bytes:", toHexString(serial), "->", int.from_bytes(bytes(serial), "big"))
    if tlv.get(TAG_FORM_FACTOR) != [0x01]:
        fail("TAG_FORM_FACTOR != 0x01")

    print("\nPASS — management applet reports version 5.7.4 + FIDO2/U2F/OpenPGP/OATH/OTP/PIV caps.")


if __name__ == "__main__":
    main()
