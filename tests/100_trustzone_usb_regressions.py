#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Physical TrustZone USB regressions; requires an explicitly selected no-touch key.

late-callback and usb-reset use a test-gateway-probes image. ccid uses the normal
image and replaces a scratch PIV object under the default management key.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import time

import hid
import usb.core
import usb.util
from smartcard.scard import SCARD_LEAVE_CARD, SCARD_SHARE_EXCLUSIVE
from smartcard.Exceptions import CardConnectionException

from _device import find, find_reader
from ctaphid import ctaphid_init, read, write

PROBE_COMMAND = 0xFE
RESCUE_AID = bytes.fromhex("a0583fc19b7e4f21")
RTC_BASE = 2_170_000_000


def selected_card(timeout=0, disposition=None):
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        reader = find_reader(require_marker=True)
        if reader is not None:
            connection = reader.createConnection()
            try:
                connection.connect(mode=SCARD_SHARE_EXCLUSIVE, disposition=disposition)
                return connection
            except CardConnectionException as error:
                last_error = error
        if time.monotonic() >= deadline:
            raise AssertionError(f"selected CCID reader did not become ready: {last_error}")
        time.sleep(0.05)


def transmit(connection, command, expected=0x9000):
    data, sw1, sw2 = connection.transmit(list(command))
    status = (sw1 << 8) | sw2
    assert status == expected, f"APDU {bytes(command[:4]).hex()}: {status:04x}, expected {expected:04x}"
    return bytes(data)


def rescue(connection):
    identity = transmit(connection, bytes([0, 0xA4, 4, 0, len(RESCUE_AID)]) + RESCUE_AID)
    assert len(identity) == 12 and identity[:2] == b"\x01\x02", "wrong applet identity"


def clock(connection):
    return int.from_bytes(transmit(connection, [0x80, 0x1E, 4, 2, 0]), "big")


def set_clock(connection):
    rescue(connection)
    transmit(connection, bytes([0x80, 0x1C, 2, 2, 4]) + RTC_BASE.to_bytes(4, "big"))
    assert RTC_BASE <= clock(connection) < RTC_BASE + 5


class Diagnostics:
    def __init__(self):
        self.device = hid.device()
        self.device.open_path(find()["path"])
        self.cid = ctaphid_init(self.device)

    def command(self, payload):
        write(self.device, self.cid + bytes([PROBE_COMMAND, 0, len(payload)]) + payload)
        response = read(self.device)
        assert response[:7] == self.cid + bytes([PROBE_COMMAND, 0, 4]), response.hex()
        return int.from_bytes(response[7:11], "little")

    def close(self):
        self.device.close()


def late_callback():
    connection = selected_card()
    diagnostics = Diagnostics()
    try:
        set_clock(connection)
        before = diagnostics.command(b"epoch")
        assert diagnostics.command(b"reset") == before, "the probe changed the physical USB epoch"
        after = clock(connection)
        assert RTC_BASE <= after < RTC_BASE + 5, "late NS callback rebooted the MCU"
        assert diagnostics.command(b"epoch") == before
        assert diagnostics.command(b"legacy-reset") == 0xFFFF_FFFF, "Secure still accepts an NS global reset"
        assert RTC_BASE <= clock(connection) < RTC_BASE + 5
        return {"late_NS_callback_preserves_new_session": True, "NS_global_reset_refused": True, "usb_epoch": before}
    finally:
        diagnostics.close()
        connection.disconnect()


def reset():
    connection = selected_card()
    diagnostics = Diagnostics()
    try:
        set_clock(connection)
        before = diagnostics.command(b"epoch")
        assert diagnostics.command(b"arm-abort") == 1
    finally:
        diagnostics.close()
        connection.disconnect()
    key = usb.core.find(idVendor=find()["vendor_id"], idProduct=find()["product_id"])
    assert usb.util.get_string(key, key.iSerialNumber) == os.environ["RSK_TEST_SERIAL"]
    try:
        key.reset()
    finally:
        usb.util.dispose_resources(key)
    connection = selected_card(timeout=30)
    diagnostics = Diagnostics()
    try:
        after = diagnostics.command(b"epoch")
        assert after > before, "Secure did not observe the physical USB reset"
        assert diagnostics.command(b"abort") == 0, "an old CCID ABORT survived the USB epoch"
        rescue(connection)
        observed = clock(connection)
        assert RTC_BASE <= observed < RTC_BASE + 30, "USB reset rebooted the MCU"
        return {"physical_USB_reset_recovered": True, "MCU_clock_preserved": True, "epochs": [before, after]}
    finally:
        diagnostics.close()
        connection.disconnect()


def piv_module():
    spec = importlib.util.spec_from_file_location("piv_frames", Path(__file__).with_name("80_piv.py"))
    piv_test = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(piv_test)
    cipher = piv_test.Cipher(piv_test.algorithms.AES(piv_test.DEFAULT_MGM), piv_test.modes.ECB())
    encryptor = cipher.encryptor()
    assert len(encryptor.update(bytes(16)) + encryptor.finalize()) == 16
    return piv_test


def ccid():
    piv_test = piv_module()
    connection = selected_card()
    try:
        set_clock(connection)
        piv = piv_test.Piv(connection)
        piv.select()
        piv.auth_mgm()
        piv_test.test_frame_sized_objects(piv)
        head = [0, piv_test.INS_GET_DATA, 0x3F, 0xFF, 0, 0, 5, 0x5C, 3, *piv_test.OBJ_POOL, 0, 0]
        for size in (50, 114, 177, 241, 304):
            value = bytes(i % 251 for i in range(size))
            body = piv_test.tlv(0x53, value)
            assert (10 + len(body) + 2) % 64 == 0
            piv.apdu(piv_test.INS_PUT_DATA, 0x3F, 0xFF,
                     piv_test.tlv(0x5C, piv_test.OBJ_POOL) + body)
            assert transmit(connection, head) == body
            piv.apdu(piv_test.INS_VERSION, 0, 0, le=True)
        piv.apdu(piv_test.INS_PUT_DATA, 0x3F, 0xFF,
                 piv_test.tlv(0x5C, piv_test.OBJ_POOL) + piv_test.tlv(0x53, b""))
        piv.apdu(piv_test.INS_VERSION, 0, 0, le=True)
        return {"CCID_3072_and_following_APDU": True, "shorter_ZLP_boundaries": [64, 128, 192, 256, 320]}
    finally:
        connection.disconnect()


def bus_reset():
    piv_test = piv_module()
    connection = selected_card(timeout=30, disposition=SCARD_LEAVE_CARD)
    try:
        set_clock(connection)
        piv = piv_test.Piv(connection)
        piv.select()
        piv.auth_mgm()
        piv.verify_pin(piv_test.DEFAULT_PIN)
        piv.verify_pin(b"")
    finally:
        connection.disconnect()
    connection = selected_card(timeout=30, disposition=SCARD_LEAVE_CARD)
    try:
        piv = piv_test.Piv(connection)
        piv.verify_pin(b"")
        piv.apdu(piv_test.INS_PUT_DATA, 0x3F, 0xFF,
                 piv_test.tlv(0x5C, piv_test.OBJ_POOL) + piv_test.tlv(0x53, b""))
        key = usb.core.find(idVendor=find()["vendor_id"], idProduct=find()["product_id"])
        assert usb.util.get_string(key, key.iSerialNumber) == os.environ["RSK_TEST_SERIAL"]
        try:
            key.reset()
        finally:
            usb.util.dispose_resources(key)
    finally:
        try:
            connection.disconnect()
        except CardConnectionException:
            pass  # The USB reset can invalidate the old PC/SC handle.
    # macOS tears down and recreates the CCID driver asynchronously after reset.
    time.sleep(2)
    connection = selected_card(timeout=30, disposition=SCARD_LEAVE_CARD)
    try:
        piv = piv_test.Piv(connection)
        piv.select()
        _, status = piv.verify_pin(b"", want=None)
        assert status & 0xFFF0 == 0x63C0 and status & 15, "PIN authority survived reset"
        _, status = piv.raw(piv_test.INS_GENERATE, 0, piv_test.SLOT_9C,
                            piv_test.tlv(0xAC, piv_test.tlv(0x80, [piv_test.ALGO_RSA2048])))
        assert status == 0x6982, f"management authority survived reset: {status:04x}"
        rescue(connection)
        assert RTC_BASE <= clock(connection) < RTC_BASE + 60, "the MCU rebooted"
        return {"physical_USB_reset_recovered": True, "PIN_revoked": True,
                "management_authority_revoked": True, "MCU_clock_preserved": True,
                "PCSC_disconnect_kept_authorization_control": True}
    finally:
        connection.disconnect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--case", choices=("late-callback", "usb-reset", "ccid", "bus-reset"), required=True)
    parser.add_argument("--runs", type=int, default=1)
    args = parser.parse_args()
    assert 1 <= args.runs <= 100
    os.environ["RSK_TEST_SERIAL"] = args.serial
    os.environ["RSK_TEST_READER"] = args.reader
    device = find()
    assert device and device["serial_number"] == args.serial
    print(json.dumps({"serial": args.serial, "bcdDevice": hex(device["release_number"])}), flush=True)
    operation = {"late-callback": late_callback, "usb-reset": reset, "ccid": ccid, "bus-reset": bus_reset}[args.case]
    for run in range(args.runs):
        started = time.monotonic()
        result = operation()
        print(json.dumps({"case": args.case, "run": run + 1, "seconds": round(time.monotonic() - started, 3), **result}), flush=True)


if __name__ == "__main__":
    main()
