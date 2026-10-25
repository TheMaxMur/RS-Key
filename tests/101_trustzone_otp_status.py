#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Compare Secure CCID / NS OTP status and exercise YubiKit on a selected test key.

Replaces OTP slot 2 with a scratch HMAC configuration and deletes it afterwards.
Uses HID feature requests on EP0 without capturing keyboard input.
"""

import argparse
import array
import hashlib
import hmac
import json
import os

import usb.core
import usb.util
from smartcard.scard import SCARD_SHARE_EXCLUSIVE
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import HmacSha1SlotConfiguration, SLOT, YubiOtpSession

from _device import find, find_reader

OTP_AID = bytes.fromhex("a0000005272001")
REPORT_SIZE = 8


class UsbOtp(OtpConnection):
    def __init__(self, identity):
        self.device = usb.core.find(idVendor=identity["vendor_id"], idProduct=identity["product_id"])
        assert self.device and usb.util.get_string(self.device, self.device.iSerialNumber) == identity["serial_number"]
        self.device._ctx.managed_open()

    def receive(self):
        data = array.array("B", [0] * REPORT_SIZE)
        count = self.device._ctx.backend.ctrl_transfer(
            self.device._ctx.handle, 0xA1, 1, 0x0300, 0, data, 2000)
        assert count == REPORT_SIZE, count
        return bytes(data)

    def send(self, data):
        assert len(data) == REPORT_SIZE
        count = self.device._ctx.backend.ctrl_transfer(
            self.device._ctx.handle, 0x21, 9, 0x0300, 0, array.array("B", data), 2000)
        assert count == REPORT_SIZE, count

    def close(self):
        usb.util.dispose_resources(self.device)


def select_otp(card, otp):
    data, sw1, sw2 = card.transmit([0, 0xA4, 4, 0, len(OTP_AID), *OTP_AID])
    assert (sw1, sw2) == (0x90, 0)
    report = otp.receive()
    assert report[1:7] == bytes(data), (
        f"NS OTP status {report[1:7].hex()} differs from Secure CCID status {bytes(data).hex()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    assert 1 <= args.runs <= 20
    os.environ["RSK_TEST_SERIAL"] = args.serial
    os.environ["RSK_TEST_READER"] = args.reader
    identity = find()
    assert identity and identity["serial_number"] == args.serial
    card = find_reader(require_marker=True).createConnection()
    card.connect(mode=SCARD_SHARE_EXCLUSIVE)
    try:
        with UsbOtp(identity) as otp:
            select_otp(card, otp)
            for run in range(args.runs):
                session = YubiOtpSession(otp)
                if session.get_config_state().is_configured(SLOT.TWO):
                    session.delete_slot(SLOT.TWO)
                key = bytes(range(1, 21))
                message = b"RS-Key TrustZone OTP status" + bytes([run])
                try:
                    session.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(key))
                    assert session.get_config_state().is_configured(SLOT.TWO)
                    assert session.calculate_hmac_sha1(SLOT.TWO, message) == hmac.new(key, message, hashlib.sha1).digest()
                    select_otp(card, otp)
                finally:
                    cleanup = YubiOtpSession(otp)
                    if cleanup.get_config_state().is_configured(SLOT.TWO):
                        cleanup.delete_slot(SLOT.TWO)
                assert not cleanup.get_config_state().is_configured(SLOT.TWO)
                select_otp(card, otp)
                print(json.dumps({"run": run + 1, "CCID_and_HID_status_match": True,
                                  "YubiKit_HMAC_SHA1_verified": True, "scratch_slot_removed": True}), flush=True)
    finally:
        card.disconnect()


if __name__ == "__main__":
    main()
