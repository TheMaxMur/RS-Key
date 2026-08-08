#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run an on-device test against `tools/emu` instead of a board.

    cargo run --manifest-path tools/emu/Cargo.toml --target "$HOST"   # in one shell
    python tests/emu.py tests/10_fido_getinfo.py                      # in another

It installs a fake `hid` module whose one device is the emulator's CTAPHID
socket, then runs the target script unchanged — so the suites keep opening the
device exactly as they do against hardware, and no test file knows about any of
this. hidapi does not have to be installed.

What this cannot stand in for: anything that needs the USB stack itself
(interface order, enumeration, the replug and reboot helpers), the CCID suites
(they go through pyscard — the emulator serves APDUs, but this shim does not
fake `smartcard` yet), and every hardware property the emulator has none of
(secure boot, OTP, power cuts). A green run here is a protocol result, not a
device result.
"""
import os
import runpy
import socket
import sys
import types

REPORT_LEN = 64
DEFAULT_ADDR = "127.0.0.1:7799"
DEFAULT_CCID_ADDR = "127.0.0.1:7800"
ENV_ADDR = "RSK_EMU"
ENV_CCID_ADDR = "RSK_EMU_CCID"

# The emulator's card-socket opcode for "unplug and plug back in". The suites
# that reset need the CTAP 2.1 §6.6 power-up window, which only a real power
# cycle reopens; `replug.py` asks an operator for it and polls the enumeration,
# so the shim answers that poll — see `_enumerate`.
OP_REPLUG = 0x03

# What the fake enumeration reports. The product string carries an RSK marker so
# `_device`'s picker accepts it, and says "emulator" so a log never reads as a
# board that was never plugged in.
EMU_PATH = b"rsk-emu"
EMU_PRODUCT = "RS-Key Security Key (emulator)"
EMU_SERIAL = "rs-key-emu"
FIDO_USAGE_PAGE = 0xF1D0


def _addr(env=ENV_ADDR, default=DEFAULT_ADDR):
    host, _, port = os.environ.get(env, default).rpartition(":")
    return (host or "127.0.0.1", int(port))


def _replug():
    """Tell the emulator to power-cycle. Best effort: without the card socket
    (`--ccid-port 0`) there is nothing to ask, and the suite then fails on the
    reset window rather than on a connection error."""
    try:
        with socket.create_connection(_addr(ENV_CCID_ADDR, DEFAULT_CCID_ADDR), timeout=5) as s:
            s.sendall(bytes([OP_REPLUG]) + (0).to_bytes(4, "big"))
            s.recv(4)
    except OSError as e:
        print(f"emu: could not replug ({e}) — the reset window will stay shut")


class EmuHid:
    """The subset of a `hid.device()` the suites use, over a TCP socket."""

    def __init__(self):
        self.sock = None

    def open_path(self, path=None):
        self.sock = socket.create_connection(_addr(), timeout=5)

    # `hid.device().open()` by vid/pid, for callers that skip enumerate().
    def open(self, vid=None, pid=None, serial=None):
        self.open_path()

    def write(self, data):
        # hidapi takes a leading report-id byte for report-id-less devices; the
        # wire carries the 64-byte report alone.
        buf = bytes(data)
        if len(buf) == REPORT_LEN + 1:
            buf = buf[1:]
        self.sock.sendall(buf.ljust(REPORT_LEN, b"\x00")[:REPORT_LEN])
        return len(data)

    def read(self, length=REPORT_LEN, timeout_ms=1000):
        self.sock.settimeout(max(timeout_ms, 1) / 1000)
        chunks = b""
        try:
            while len(chunks) < REPORT_LEN:
                part = self.sock.recv(REPORT_LEN - len(chunks))
                if not part:
                    break
                chunks += part
        except socket.timeout:
            return []  # what hidapi returns when nothing arrived in time
        return list(chunks[:length])

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    # Present so a caller that sets these does not blow up; the emulator has no
    # blocking mode to switch.
    def set_nonblocking(self, _v):
        pass


def _enumerate(vid=0, pid=0):
    return [
        {
            "path": EMU_PATH,
            "vendor_id": 0x1209,
            "product_id": 0x000D,
            "serial_number": EMU_SERIAL,
            "product_string": EMU_PRODUCT,
            "manufacturer_string": "RS-Key",
            "usage_page": FIDO_USAGE_PAGE,
            "usage": 0x01,
            "interface_number": 0,
        }
    ]


def install():
    """Put the fake `hid` module in place of the real one, and make the
    power-cycle helper drive the emulator instead of an operator."""
    fake = types.ModuleType("hid")
    fake.device = EmuHid
    fake.enumerate = _enumerate
    sys.modules["hid"] = fake
    _patch_replug()
    return fake


def _patch_replug():
    """Replace `replug.wait_gone`/`wait_back` with the emulator's power cycle.

    Patching the two waits, rather than faking a gap in the enumeration, is what
    keeps this deterministic: the suites poll `find()` in several shapes (some
    prompt first, some close the handle first), and every one of them ends up in
    these two functions."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import replug
    except ImportError:
        return  # a suite that never power-cycles does not need it

    def wait_gone(timeout=None):
        _replug()

    def wait_back(timeout=None):
        import time

        from ctaphid import ctaphid_init

        dev = EmuHid()
        dev.open_path()
        return dev, ctaphid_init(dev), time.time()

    replug.wait_gone = wait_gone
    replug.wait_back = wait_back


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <test script> [args…]")
    install()
    target = sys.argv[1]
    sys.argv = sys.argv[1:]
    # The suites add their own directory to sys.path for `_device`; do it here
    # too, since the script is run by path.
    sys.path.insert(0, os.path.dirname(os.path.abspath(target)))
    runpy.run_path(target, run_name="__main__")


if __name__ == "__main__":
    main()
