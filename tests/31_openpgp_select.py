#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP applet test — drive the card over PC/SC (pyscard).

    nix develop -c python tests/31_openpgp_select.py
    # or from the validation venv (has pyscard):
    nix develop -c python tests/31_openpgp_select.py

Read-only card-status surface over CCID, HID-free: SELECT the OpenPGP AID,
then read the data objects `gpg --card-status` reads — full AID (4F),
historical bytes (5F52), PW status (C4), application related data (6E).
Needs pyscard + a running PC/SC daemon (built in on macOS).
"""
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader, fw_version  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID + [0x00]


def get_data(tag):
    """GET DATA APDU for a 16-bit tag, Le = 0 (case 2, short Le → 256 max)."""
    return [0x00, 0xCA, (tag >> 8) & 0xFF, tag & 0xFF, 0x00]


VERSION = [0x00, 0xF1, 0x00, 0x00, 0x00]

# Expected ROM values (rsk-openpgp::files).
HISTORICAL_BYTES = [0x00, 0x31, 0x84, 0x73, 0x80, 0x01, 0xC0, 0x05, 0x90, 0x00]
# PW status byte 0 ("PW1 valid for several PSO:CDS") is mutable runtime state
# (set via PUT DATA C4), so only the fixed tail is asserted: the three max PIN
# lengths (127) and the three retry counters.
#
# The middle counter is the resetting code's, and it ships **0**: the RC is
# deactivated until PUT DATA 0xD3 sets a real one, per OpenPGP Card 3.4 §4.3.4,
# so `RESET RETRY P1=0` cannot run against a default RC. That is the run-10 audit
# fix (`ca7e056`, 2026-07-08) — this expectation still read 3 until 2026-08-08,
# which is to say it asserted the backdoor the fix closed.
PW_STATUS_FIXED = [127, 127, 127, 3, 0, 3]
# The vendor VERSION command (INS 0xF1) answers with the device firmware version
# (`rsk_sdk::FIRMWARE_VERSION`), as a real YubiKey does — its OpenPGP "Application
# version" is its firmware version. Not the OpenPGP card version (3.4).
EXPECTED_FW_VERSION = list(fw_version())


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def transmit_full(conn, apdu):
    """Transmit, following ISO 7816-4 `61xx` response chaining via GET RESPONSE.

    A short-Le GET DATA caps a reply at 256 bytes; a larger DO (the 6E template
    runs ~259 B) comes back as 256 bytes + `61 LL`, the firmware signalling LL
    more via GET RESPONSE (`00 C0 00 00 LL`). scdaemon/gpg/ykman all chain here;
    this test must too (the chaining was added for them in commit 9cbec02)."""
    data, sw1, sw2 = conn.transmit(apdu)
    out = list(data)
    rounds = 0
    while sw1 == 0x61:
        rounds += 1
        if rounds > 16:  # a healthy 6E chains in 1 round; cap so a firmware
            fail("GET RESPONSE chaining did not terminate (>16 rounds)")
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        out += list(more)
    return out, sw1, sw2


def expect_ok(conn, apdu, what):
    data, sw1, sw2 = transmit_full(conn, apdu)
    print("%-28s -> %s %02X%02X" % (what, toHexString(data) or "(empty)", sw1, sw2))
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"{what} not 9000 (got {sw1:02X}{sw2:02X})")
    return data


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")

    conn = target.createConnection()
    conn.connect()
    print("ATR:", toHexString(list(conn.getATR())))

    fci = expect_ok(conn, SELECT, "SELECT OpenPGP AID")
    if not fci or fci[0] != 0x6F:
        fail(f"SELECT FCI should start with 6F, got {toHexString(fci)}")

    aid = expect_ok(conn, get_data(0x004F), "GET DATA 4F (full AID)")
    if aid[:6] != OPENPGP_AID:
        fail(f"full AID does not start with the OpenPGP AID: {toHexString(aid)}")
    if len(aid) != 16:
        fail(f"full AID should be 16 bytes, got {len(aid)}")
    print("  serial bytes:", toHexString(aid[10:14]))

    hist = expect_ok(conn, get_data(0x5F52), "GET DATA 5F52 (historical)")
    if hist != HISTORICAL_BYTES:
        fail(f"historical bytes mismatch: {toHexString(hist)}")

    pw = expect_ok(conn, get_data(0x00C4), "GET DATA C4 (PW status)")
    if len(pw) != 7 or pw[0] not in (0x00, 0x01) or pw[1:] != PW_STATUS_FIXED:
        fail(f"PW status mismatch: {toHexString(pw)} (byte0 ∈ {{00,01}}, "
             f"tail must be {toHexString(PW_STATUS_FIXED)})")

    app = expect_ok(conn, get_data(0x006E), "GET DATA 6E (app data)")
    if not app:
        fail("application related data (6E) is empty")
    # The constructed 6E template must keep its outer 6E tag — ykman/yubikit
    # parse it with `Tlv.unpack(0x6E, response)` and reject an unwrapped reply
    # (an unwrapped `4F …` here is exactly what broke `ykman openpgp info`).
    if app[0] != 0x6E:
        fail(f"6E composite must keep its 6E tag (got {app[0]:02X}); ykman Tlv.unpack(0x6E) requires it")
    # The 4F (full AID) DO must be nested somewhere inside the 6E composite.
    if bytes(OPENPGP_AID) not in bytes(app):
        fail("6E composite does not contain the AID")

    ver = expect_ok(conn, VERSION, "VERSION (F1)")
    if ver != EXPECTED_FW_VERSION:
        fail(f"version mismatch: {toHexString(ver)} != {toHexString(EXPECTED_FW_VERSION)} "
             f"(an image built FW_VERSION=X.Y.Z needs the same value in the environment)")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
