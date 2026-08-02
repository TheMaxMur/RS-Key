#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Secure-reboot test — the vendor reboot command (`cmd_reboot_bootsel`).

The vendor applet's INS 0x1F requests a reboot that the worker performs only
after the SW_OK reaches the host, wiping the live RAM key material first (FIDO
auth state + the DRBG):

  * P1=0x00 — warm reboot (`SCB::sys_reset`): the device re-enumerates and comes
    back by itself. This test drives that path and confirms the device returns.
  * P1=0x01 — secure reboot to BOOTSEL (`reset_to_usb_boot`): the device drops to
    the USB bootloader for reflashing and does NOT come back on its own. Only run
    with `--bootsel`; afterwards re-drag a firmware UF2 to restore it.

Run from the venv with pyscard:

    nix develop -c python tests/51_secure_reboot.py
    …                                                            tests/51_secure_reboot.py --bootsel
"""
import os
import sys
import time

try:
    from smartcard.CardConnection import CardConnection
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]
MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
INS_REBOOT = 0x1F


def connect():
    # Marker required: the re-enumeration poll below asks "is the board back?", and
    # MGMT_AID is Yubico's own management AID — a real YubiKey answers it 9000.
    r = find_reader(require_marker=True)
    if r is None:
        return None
    conn = r.createConnection()
    try:
        conn.connect(CardConnection.T1_protocol)
    except Exception:
        try:
            conn.connect()
        except Exception:
            return None
    return conn


def select(conn, aid):
    return conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid)] + aid)


def main():
    bootsel = "--bootsel" in sys.argv
    conn = connect()
    if conn is None:
        sys.exit("no 'RSK' reader — flash the secure-reboot firmware and replug")

    _, sw1, sw2 = select(conn, VENDOR_AID)
    if (sw1, sw2) != (0x90, 0x00):
        sys.exit(f"SELECT vendor AID failed: {sw1:02X}{sw2:02X}")
    print("SELECT vendor AID -> 9000")

    p1 = 0x01 if bootsel else 0x00
    _, sw1, sw2 = conn.transmit([0x00, INS_REBOOT, p1, 0x00])
    if (sw1, sw2) != (0x90, 0x00):
        sys.exit(f"reboot command rejected: {sw1:02X}{sw2:02X} "
                 "(pre-secure-reboot firmware reports 6D00)")
    print(f"REBOOT (P1={p1:#04x}) -> 9000")
    try:
        conn.disconnect()
    except Exception:
        pass

    if bootsel:
        print("\nDevice is rebooting to BOOTSEL — the RP2350 mass-storage drive "
              "should appear.\nReflash a firmware UF2 to restore it.")
        print("secure-reboot PASS (BOOTSEL requested)")
        return

    # Warm reboot: the device disconnects, re-runs main(), and re-enumerates.
    print("waiting for the device to re-enumerate ...")
    deadline = time.time() + 15
    while time.time() < deadline:
        time.sleep(1.0)
        conn = connect()
        if conn is None:
            continue
        try:
            data, sw1, sw2 = select(conn, MGMT_AID)
        except Exception:
            continue
        if (sw1, sw2) == (0x90, 0x00):
            ver = bytes(data).decode("ascii", "replace")
            print(f"device back after warm reboot: mgmt SELECT -> {ver!r} 9000")
            print("secure-reboot PASS (warm reboot, device returned)")
            return
    sys.exit("device did not come back within 15s after the warm reboot")


if __name__ == "__main__":
    main()
