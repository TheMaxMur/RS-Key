# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Attended initialization and legacy import of authenticated storage."""
import sys

from . import ccid

RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")
FORMAT = 2
INS_STORAGE = 0x20
READ_STATE = bytes.fromhex("801E080000")


def register(sub):
    parser = sub.add_parser("storage", help="authenticated storage state and attended setup")
    parser.add_argument("action", choices=["status", "initialize", "import-legacy"])
    parser.set_defaults(func=run)


def _state(conn):
    body, sw1, sw2 = ccid.transmit(conn, READ_STATE)
    if (sw1, sw2) != ccid.SW_OK:
        raise SystemExit(f"storage state failed: {sw1:02X}{sw2:02X}")
    if len(body) != 2 or body[0] != FORMAT or body[1] not in (0, 1):
        raise SystemExit("unsupported storage state response")
    return body[1] == 1


def run(args):
    conn = ccid.connect(exclusive=args.action != "status")
    try:
        _, sw1, sw2 = ccid.select(conn, RESCUE_AID)
        if (sw1, sw2) != ccid.SW_OK:
            raise SystemExit(f"rescue SELECT failed: {sw1:02X}{sw2:02X}")
        ready = _state(conn)
        if args.action == "status":
            print(f"storage v{FORMAT}: {'ready' if ready else 'recovery required'}")
            return
        if ready:
            raise SystemExit("storage is already active")
        if args.action == "initialize":
            p1, magic = 0, b"INITV2"
            print("approve on the device to initialize wholly blank storage…", file=sys.stderr)
        else:
            p1, magic = 1, b"IMPORTV2"
            print("approve on the device to trust and import its legacy records…", file=sys.stderr)
        apdu = bytes([0x80, INS_STORAGE, p1, 0, len(magic)]) + magic
        _, sw1, sw2 = ccid.transmit(conn, apdu)
        if (sw1, sw2) == ccid.SW_COND_NOT_SATISFIED:
            raise SystemExit("storage operation declined or incompatible with the current medium")
        if (sw1, sw2) != ccid.SW_OK:
            raise SystemExit(f"storage operation failed: {sw1:02X}{sw2:02X}; keep the flash image for recovery")
        print("storage operation complete; the device is restarting")
    finally:
        conn.disconnect()
