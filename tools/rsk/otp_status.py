# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Read the boot-only OTP seal result, including Linux's driver-named readers."""
from enum import IntEnum

from . import ccid
from .common import die
from .status import RESCUE_AID, rescue_read, rescue_serial


class SealStatus(IntEnum):
    UNCHECKED = 0
    UNPROVISIONED = 1
    SEALED = 2
    MIGRATION_PENDING = 3
    SCRUB_PENDING = 4
    INCOMPLETE = 5
    READ_FAILED = 6
    FOREIGN_LOCK = 7
    WRITE_FAILED = 8
    TEST_KEYS = 9
    PARTIAL_LATCH = 10
    INCOMPLETE_LOCK = 11


LABELS = {
    SealStatus.UNCHECKED: "automatic sealing was not checked by this backend",
    SealStatus.UNPROVISIONED: "OTP keys are not provisioned",
    SealStatus.SEALED: "sealed: BOOTSEL/non-secure access closed, migration latch set",
    SealStatus.MIGRATION_PENDING: "migration pending; complete the actions below, then restart",
    SealStatus.SCRUB_PENDING: "flash scrub incomplete; restart to retry, preserve storage if it persists",
    SealStatus.INCOMPLETE: "OTP provisioning incomplete or invalid; automatic seal refused; do not repeat burn",
    SealStatus.READ_FAILED: "OTP read failed; automatic seal could not be verified",
    SealStatus.FOREIGN_LOCK: "unexpected OTP lock bits; automatic seal refused",
    SealStatus.WRITE_FAILED: "OTP seal write/readback failed; restart to retry",
    SealStatus.TEST_KEYS: "test-key firmware: real OTP sealing is disabled",
    SealStatus.PARTIAL_LATCH: "access sealed, latch redundancy incomplete; ROM refuses further writes; do not repeat burn",
    SealStatus.INCOMPLETE_LOCK: "torn access lock: Secure writes closed too early; recovery required, do not repeat burn",
}


def read_status(conn):
    data, hi, lo = rescue_read(conn, 0x09)
    if (hi, lo) == (0x6A, 0x86):
        die("firmware has no automatic OTP sealing status; upgrade it to complete sealing")
    if (hi, lo) != ccid.SW_OK:
        die(f"OTP seal status failed: {hi:02X}{lo:02X}")
    if len(data) != 4 or data[0] != 1:
        die("unsupported OTP seal status response")
    try:
        state = SealStatus(data[1])
    except ValueError:
        die("unknown OTP seal status")
    return state, int.from_bytes(data[2:], "big")


def connect():
    """Discover by read-only rescue SELECT; neither a label nor VID grants access."""
    ccid._require()
    found = []
    for reader in ccid.readers():
        conn, keep = None, False
        try:
            conn = reader.createConnection()
            conn.connect()
            data, hi, lo = ccid.select(conn, RESCUE_AID)
            if (hi, lo) == ccid.SW_OK and len(data) == 12 and data[:4] == b"\x01\x02\x08\x06":
                found.append((conn, rescue_serial(data, hi, lo)))
                keep = True
        except Exception:
            pass  # An unavailable reader is not a responder to this read-only probe.
        finally:
            if conn is not None and not keep:
                try:
                    conn.disconnect()
                except Exception:
                    pass  # A failed probe may never have established a connection.
    if len(found) != 1:
        for conn, _ in found:
            conn.disconnect()
        die("expected exactly one RS-Key rescue responder; disconnect other RS-Keys and retry")
    return found[0]


def run(_args):
    from .otp import pre_otp_actions

    conn, serial = connect()
    try:
        state, left = read_status(conn)
        print(f"device {serial}: {LABELS[state]}")
        if state == SealStatus.MIGRATION_PENDING:
            for action in pre_otp_actions(left):
                print(f"  - {action}")
        if state != SealStatus.SEALED:
            raise SystemExit(2)
    finally:
        conn.disconnect()
