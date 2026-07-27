#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A touch-gated challenge must not wedge the OTP transport.

A slot programmed with `--touch` answers only after a button press, and reports
the wait in the status byte (`0x20`). A host that meets that wait and moves on
ends it one of two ways, both of which a YubiKey honours:

  * the dummy write `0x8f` — an out-of-range sequence, ykpers `yk_force_key_update`;
  * simply sending the next command, which supersedes the pending challenge.

RS-Key honoured neither before bcdDevice `0x085B`: it sat in the wait and answered
"would block" to everything for the whole touch timeout, which was enough to make
KeePassXC treat the key as broken. This test needs no press — it checks that the
device lets go, not that it computes the right HMAC (`73_otp_keyboard.py` covers
that).

    pip install pyusb
    python tests/77_otp_touch_wait.py [--slot 1|2]

**Linux only in practice**: libusb cannot claim a HID interface on macOS or
Windows. The slot must be programmed as a `--touch` challenge-response slot —
the test says so and skips if it sees no touch wait.
"""
import argparse
import contextlib
import sys
import time

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("missing dependency: pip install pyusb")

SLOT_CHAL_HMAC = {1: 0x30, 2: 0x38}
SLOT_DEVICE_SERIAL = 0x10
DUMMY_WRITE = 0x8F
WRITE_FLAG = 0x80
WAIT_FLAG, RESP_PENDING = 0x20, 0x40
RELEASE_BUDGET = 3.0  # seconds; the touch timeout it must NOT wait out is 15-30


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            lsb = crc & 1
            crc >>= 1
            if lsb:
                crc ^= 0x8408
    return crc


class Otp:
    def __init__(self, dev, itf=0):
        self.dev, self.itf = dev, itf

    def status(self):
        return bytes(self.dev.ctrl_transfer(0xA1, 0x01, 0x0300, self.itf, 8, 1000))

    def put(self, report):
        self.dev.ctrl_transfer(0x21, 0x09, 0x0300, self.itf, report, 1000)

    def send_frame(self, slot_id):
        frame = bytearray(70)
        frame[64] = slot_id
        frame[65:67] = crc16(bytes(64)).to_bytes(2, "little")
        for seq in range(10):
            self.put(bytes(frame[seq * 7 : seq * 7 + 7]) + bytes([WRITE_FLAG | seq]))

    def wait_until(self, done, budget):
        t0 = time.monotonic()
        while time.monotonic() - t0 < budget:
            st = self.status()
            if done(st):
                return time.monotonic() - t0, st
            time.sleep(0.05)
        return None, self.status()

    def drain(self, budget=8.0):
        """Read until the plain status frame settles (no response mid-stream)."""
        t0, stable = time.monotonic(), 0
        while time.monotonic() - t0 < budget:
            stable = stable + 1 if self.status()[7] == 0 else 0
            if stable >= 4:
                return True
            time.sleep(0.05)
        return False


def arm_and_confirm_wait(otp, slot_id):
    otp.send_frame(slot_id)
    took, st = otp.wait_until(lambda s: s[7] & WAIT_FLAG, 2.0)
    if took is None:
        sys.exit(
            f"SKIP: no touch wait after arming (status {st.hex(' ')}) — program the "
            "slot with `ykman otp chalresp --touch <slot>` and rerun"
        )
    return took


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slot", type=int, choices=(1, 2), default=1)
    args = ap.parse_args()

    dev = None
    for vid in (0x1050, 0x1209):
        for d in usb.core.find(find_all=True, idVendor=vid):
            if "RS" in (usb.util.get_string(d, d.iProduct) or "").upper():
                dev = d
    if dev is None:
        sys.exit("no RS-Key found")
    print(f"{usb.util.get_string(dev, dev.iProduct)}  bcdDevice=0x{dev.bcdDevice:04x}")

    otp = Otp(dev)
    if dev.is_kernel_driver_active(otp.itf):
        dev.detach_kernel_driver(otp.itf)
    usb.util.claim_interface(dev, otp.itf)
    try:
        if not otp.drain():
            sys.exit("FAIL: the transport never settled to an idle status frame")

        arm_and_confirm_wait(otp, SLOT_CHAL_HMAC[args.slot])
        print("  armed: the device reports a touch wait")
        otp.send_frame(SLOT_DEVICE_SERIAL)
        took, st = otp.wait_until(lambda s: s[7] & RESP_PENDING, RELEASE_BUDGET)
        if took is None:
            sys.exit(f"FAIL: a new frame did not supersede the wait ({st.hex(' ')})")
        print(f"  OK  a new frame superseded the wait in {took:.1f}s ({st[:4].hex()})")
        otp.drain()

        arm_and_confirm_wait(otp, SLOT_CHAL_HMAC[args.slot])
        otp.put(bytes(7) + bytes([DUMMY_WRITE]))
        took, st = otp.wait_until(lambda s: not s[7] & WAIT_FLAG, RELEASE_BUDGET)
        if took is None:
            sys.exit(f"FAIL: the 0x8f dummy write did not end the wait ({st.hex(' ')})")
        print(f"  OK  the 0x8f dummy write ended the wait in {took:.1f}s")
        otp.drain()
    finally:
        usb.util.release_interface(dev, otp.itf)
        with contextlib.suppress(usb.core.USBError):
            dev.attach_kernel_driver(otp.itf)

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
