#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CCID secure PIN entry (pinpad) — the PIN is typed on the device screen.

    # display board, built `LED_KIND=none FLASH_SIZE=16M ... --features display`:
    nix develop -c python tests/53_ccid_pinpad.py            # OpenPGP PW1
    nix develop -c python tests/53_ccid_pinpad.py --applet piv

Interactive, and needs a *display* board (the standard build leaves
`bPINSupport = 0x00` and rejects `PC_to_RDR_Secure`). It drives a CCID secure
VERIFY via PC/SC `FEATURE_VERIFY_PIN_DIRECT`: the device must pop its on-screen
PIN pad, you type the PIN on the *device* (never on the host), and it returns the
card's status word — `90 00` for the right PIN, `63 Cx` for a wrong one (x tries
left), and a CCID cancel/timeout error if you tap Cancel or let it lapse.

The canonical, lowest-prerequisite trigger is GnuPG's internal CCID driver, which
keys solely off the descriptor's `bPINSupport` and works where the rsk Python CLI
is blocked (it is pure C):

    gpg-connect-agent "scd checkpin OPENPGP.1" /bye   # OpenPGP PW1, no host config

For PIV via OpenSC set `enable_pinpad = true` in `opensc.conf`, then
`opensc-tool -s 00:20:00:80` (or `pkcs11-tool --login`) drives the same pad.

This script is the PC/SC-direct cross-check; if your host's CCID driver doesn't
expose `FEATURE_VERIFY_PIN_DIRECT`, fall back to the gpg path above. See
`docs/protocol.md` §1.3.
"""
import argparse
import os
import sys

try:
    from smartcard.util import toHexString
    from smartcard.pcsc.PCSCPart10 import (
        getFeatureRequest,
        hasFeature,
        FEATURE_VERIFY_PIN_DIRECT,
    )
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
PIV_AID = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]


def select(aid):
    return [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]


def pin_verify_struct(apdu):
    """A PC/SC v2 Part 10 PIN_VERIFY structure for a variable-length pinpad VERIFY.

    The device collects the PIN and builds the body itself, so `bmPINBlockString`
    is 0 (adaptive) and `abData` is just the bare VERIFY template (no Lc/data).
    """
    return [
        0x00,  # bTimeOut (reader default)
        0x00,  # bTimeOut2
        0x82,  # bmFormatString: ASCII, byte units, pos 0, left
        0x00,  # bmPINBlockString: variable length
        0x00,  # bmPINLengthFormat
        0x06, 0x7F,  # wPINMaxExtraDigit (min 6 / max — device ignores, uses its own)
        0x02,  # bEntryValidationCondition: validation key pressed
        0x01,  # bNumberMessage
        0x00, 0x00,  # wLangId
        0x00,  # bMsgIndex
        0x00, 0x00, 0x00,  # bTeoPrologue
        len(apdu), 0x00, 0x00, 0x00,  # ulDataLength (LE)
    ] + apdu


def main():
    ap = argparse.ArgumentParser(description="CCID on-device PIN entry test")
    ap.add_argument("--applet", choices=["openpgp", "piv"], default="openpgp")
    args = ap.parse_args()

    if args.applet == "openpgp":
        aid, template = OPENPGP_AID, [0x00, 0x20, 0x00, 0x81]  # VERIFY PW1 (sign)
        label = "OpenPGP PW1"
    else:
        aid, template = PIV_AID, [0x00, 0x20, 0x00, 0x80]  # VERIFY PIV PIN
        label = "PIV PIN"

    target = find_reader()
    if not target:
        sys.exit("no PC/SC reader — is the device plugged in?")
    conn = target.createConnection()
    conn.connect()

    sw1, sw2 = conn.transmit(select(aid))[1:]
    if (sw1, sw2) != (0x90, 0x00):
        sys.exit(f"SELECT {label} failed: {sw1:02X}{sw2:02X}")

    features = getFeatureRequest(conn)
    verify_ioctl = hasFeature(features, FEATURE_VERIFY_PIN_DIRECT)
    if not verify_ioctl:
        sys.exit(
            "host CCID driver did not expose FEATURE_VERIFY_PIN_DIRECT.\n"
            "Either this is not a display build (bPINSupport=0), or your PC/SC\n"
            "stack doesn't drive pinpad. Use the gpg path:\n"
            '  gpg-connect-agent "scd checkpin OPENPGP.1" /bye'
        )

    struct = pin_verify_struct(template)
    print(f"Driving secure VERIFY for {label} — type the PIN ON THE DEVICE screen.")
    resp = conn.control(verify_ioctl, struct)
    if len(resp) < 2:
        sys.exit(f"short secure-verify response: {toHexString(resp)}")
    sw1, sw2 = resp[-2], resp[-1]
    sw = (sw1 << 8) | sw2
    if sw == 0x9000:
        print("OK — PIN verified on-device (90 00). The PIN never crossed USB.")
    elif sw1 == 0x63:
        print(f"wrong PIN — {sw2 & 0x0F} tries left (63 {sw2:02X}).")
    elif sw == 0x6983:
        print("PIN blocked (69 83).")
    else:
        print(f"status word {sw:04X} (see docs/protocol.md §2.1).")


if __name__ == "__main__":
    main()
