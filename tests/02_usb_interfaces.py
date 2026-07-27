#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""USB layout test — the interface order and the OTP frame protocol's reach.

Two properties a host tool written for YubiKeys depends on, neither of which any
host test can see (they live in the USB descriptors and on the control pipe):

  * the interfaces enumerate in the stock YubiKey order — keyboard/OTP, FIDO,
    CCID. `ykpers`/`ykcore` (KeePassXC, ykchalresp, pam_yubico) claims interface
    0 and puts the OTP frame reports there without reading a descriptor first,
    so whichever interface sits at index 0 decides whether those tools work;
  * the OTP frame protocol answers a HID feature GET_REPORT on *both* HID
    interfaces, as a 5.7.4 YubiKey does, which keeps such a host working even if
    the order ever shifts (e.g. an interface disabled in the phy record).

    pip install pyusb        # plus libusb
    python tests/02_usb_interfaces.py

**Linux only in practice**: libusb cannot claim a HID interface on macOS (IOKit
holds it) or Windows. Run it on a Linux host with the Yubico udev rules
installed — the same environment the tools under test need.

The device is picked by its product string ("RS-Key" / "RSK"); pass --index to
choose among several, which is also how to point it at a real YubiKey as a
reference. A key with the OTP interface disabled
(`ykman config usb --disable OTP`) will fail here by design: the frame protocol
is gone from both interfaces then.
"""
import argparse
import contextlib
import sys

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("missing dependency: pip install pyusb")

RSKEY_VIDS = (0x1050, 0x1209)  # Yubico-interop build, then the RS-Key default
HID_CLASS, CCID_CLASS = 0x03, 0x0B
HID_GET_REPORT, FEATURE_REPORT = 0x01, 0x03 << 8
REPORT_DESC_TYPE = 0x22
# Usage Page (Generic Desktop) + Usage (Keyboard), and Usage Page (0xF1D0).
KEYBOARD_DESC_PREFIX = bytes([0x05, 0x01, 0x09, 0x06])
FIDO_DESC_PREFIX = bytes([0x06, 0xD0, 0xF1])
STATUS_FRAME_LEN = 8


def candidates():
    found = []
    for vid in RSKEY_VIDS:
        found += list(usb.core.find(find_all=True, idVendor=vid))
    return found


def pick(index):
    devs = candidates()
    if not devs:
        sys.exit("no RS-Key found (VID 0x1050 / 0x1209)")
    if index is not None:
        return devs[index]
    ours = [d for d in devs if "RS" in (usb.util.get_string(d, d.iProduct) or "").upper()]
    if len(ours) == 1:
        return ours[0]
    if len(devs) == 1:
        return devs[0]
    for i, d in enumerate(devs):
        print(f"  --index {i}: {usb.util.get_string(d, d.iProduct)} bcdDevice=0x{d.bcdDevice:04x}")
    sys.exit("several candidates — pass --index")


@contextlib.contextmanager
def claimed(dev, itf):
    """Take the interface off the kernel, as ykpers does, and hand it back after."""
    if dev.is_kernel_driver_active(itf):
        dev.detach_kernel_driver(itf)
    usb.util.claim_interface(dev, itf)
    try:
        yield
    finally:
        usb.util.release_interface(dev, itf)
        with contextlib.suppress(usb.core.USBError):
            dev.attach_kernel_driver(itf)


def probe(dev, itf):
    """(report descriptor, OTP status frame) — the frame is None if the device stalls."""
    with claimed(dev, itf):
        descriptor = bytes(
            dev.ctrl_transfer(0x81, 0x06, REPORT_DESC_TYPE << 8, itf, 256, 1000)
        )
        try:
            frame = bytes(
                dev.ctrl_transfer(
                    0xA1, HID_GET_REPORT, FEATURE_REPORT, itf, STATUS_FRAME_LEN, 1000
                )
            )
        except usb.core.USBError as e:
            frame = None
            print(f"  itf {itf}: feature GET_REPORT refused — {e}")
    return descriptor, frame


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", type=int, help="pick the nth candidate device")
    args = ap.parse_args()

    dev = pick(args.index)
    print(f"{usb.util.get_string(dev, dev.iProduct)}  bcdDevice=0x{dev.bcdDevice:04x}")

    interfaces = sorted(
        (i.bInterfaceNumber, i.bInterfaceClass) for i in dev.get_active_configuration()
    )
    print(f"  interfaces: {interfaces}")
    hid_itfs = [n for n, cls in interfaces if cls == HID_CLASS]
    ccid_itfs = [n for n, cls in interfaces if cls == CCID_CLASS]
    if len(hid_itfs) != 2:
        sys.exit(f"FAIL: expected two HID interfaces, got {hid_itfs}")

    kbd_itf, fido_itf = hid_itfs
    probes = {itf: probe(dev, itf) for itf in hid_itfs}

    if not probes[kbd_itf][0].startswith(KEYBOARD_DESC_PREFIX):
        sys.exit(f"FAIL: interface {kbd_itf} is not the keyboard/OTP interface")
    if not probes[fido_itf][0].startswith(FIDO_DESC_PREFIX):
        sys.exit(f"FAIL: interface {fido_itf} is not the FIDO interface")
    if kbd_itf != 0:
        sys.exit(f"FAIL: keyboard/OTP must be interface 0, found it at {kbd_itf} — ykpers breaks")
    if ccid_itfs and ccid_itfs[0] < fido_itf:
        sys.exit(f"FAIL: CCID at {ccid_itfs[0]} precedes FIDO at {fido_itf}")
    print(f"  OK  order: keyboard/OTP {kbd_itf}, FIDO {fido_itf}, CCID {ccid_itfs}")

    for itf, (_, frame) in probes.items():
        if frame is None or len(frame) != STATUS_FRAME_LEN:
            sys.exit(f"FAIL: interface {itf} served no OTP status frame")
        if not 1 <= frame[1] <= 9:
            sys.exit(f"FAIL: interface {itf} status frame looks wrong: {frame.hex(' ')}")
        print(
            f"  OK  itf {itf} status frame {frame.hex(' ')} "
            f"(version {frame[1]}.{frame[2]}.{frame[3]})"
        )

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
