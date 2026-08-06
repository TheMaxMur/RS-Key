# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk openpgp — OpenPGP applet utilities.

reset: factory-reset the OpenPGP applet to its default PINs (123456 / 12345678).
The flash KV survives reflashing, so non-default PINs left by a prior gpg
session block the OpenPGP tests at VERIFY. This blocks PW1+PW3 (no admin PIN
needed) then drives the spec-compliant blocked-PIN TERMINATE (0xE6) + ACTIVATE
(0x44), which the firmware re-seeds to factory state. FIDO is untouched (the
OpenPGP TERMINATE is scoped to OpenPGP FIDs). DESTRUCTIVE for OpenPGP; idempotent.
"""
from . import ccid
from .common import confirm

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
INS_VERIFY, INS_ACTIVATE, INS_TERMINATE = 0x20, 0x44, 0xE6
MODE_PW1, MODE_PW3 = 0x81, 0x83
PW1_DEFAULT, PW3_DEFAULT = b"123456", b"12345678"


def _apdu(ins, p1, p2, data=b""):
    a = [0x00, ins, p1, p2]
    if data:
        a += [len(data)] + list(data)
    return a


def register(sub):
    p = sub.add_parser("openpgp", help="OpenPGP applet utilities")
    g = p.add_subparsers(dest="cmd", required=True)
    r = g.add_parser("reset", help="factory-reset OpenPGP to default PINs (DESTRUCTIVE)")
    r.set_defaults(func=reset)


def reset(args):
    conn = ccid.connect(exclusive=True)
    # The card must actually carry an OpenPGP application before we block its PINs and
    # TERMINATE it: find_reader can only pick an RS-Key now, but a wrong applet (or a
    # future caller) must fail closed rather than destroy an unrelated card (audit run-30).
    _, s1, s2 = ccid.select(conn, OPENPGP_AID)
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(
            f"no OpenPGP application on the selected card ({s1:02X}{s2:02X}) — refusing to reset"
        )
    # Typed confirmation on the interactive path (promised in docs/guides/cli.md).
    # offboard drives us with args=None mid-ceremony after its own OFFBOARD prompt;
    # prompting again there would raise EOFError on non-TTY stdin and lose its receipt.
    if args is not None:
        confirm("OPENPGP RESET")
    # Block both PINs (each VERIFY decrements the retry counter; at 0 it blocks).
    for mode in (MODE_PW3, MODE_PW1):
        for _ in range(5):
            ccid.transmit(conn, _apdu(INS_VERIFY, 0x00, mode, b"00000000"))
    _, s1, s2 = ccid.transmit(conn, _apdu(INS_TERMINATE, 0x00, 0x00))
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(f"TERMINATE not accepted ({s1:02X}{s2:02X}) — PINs may not both be blocked")
    ccid.transmit(conn, _apdu(INS_ACTIVATE, 0x00, 0x00))
    ccid.select(conn, OPENPGP_AID)
    _, p1, p2 = ccid.transmit(conn, _apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT))
    _, q1, q2 = ccid.transmit(conn, _apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT))
    if (p1, p2) == ccid.SW_OK and (q1, q2) == ccid.SW_OK:
        print("OpenPGP reset to factory defaults (PW1=123456, PW3=12345678).")
    else:
        raise SystemExit("reset finished but default PINs do not verify — try rsk-wipe")
