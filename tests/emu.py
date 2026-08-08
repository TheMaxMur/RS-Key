#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run an on-device test against `tools/emu` instead of a board.

    cargo run --manifest-path tools/emu/Cargo.toml --target "$HOST"   # in one shell
    python tests/emu.py tests/10_fido_getinfo.py                      # in another

It installs a fake `hid` module whose one device is the emulator's CTAPHID socket
and a fake `smartcard` package whose one reader is its card socket, then runs the
target script unchanged — so the suites keep opening the device exactly as they
do against hardware, and no test file knows about any of this. Neither hidapi nor
pyscard has to be installed.

What this cannot stand in for: anything that needs the USB stack itself
(enumeration, interface order, the CCID block layer), the applets the emulator
does not carry (the firmware-local vendor AID: LED, bench, reboot-to-BOOTSEL),
and every hardware property it has none of (secure boot, OTP, power cuts). A
green run here is a protocol result, not a device result.

The suites in [`UNSUPPORTED`] are refused up front with their reason and exit 77,
rather than being allowed to fail somewhere in the middle. A harness that cannot
tell "does not apply here" from "broken" makes the second one invisible, and
these fourteen would otherwise be re-diagnosed by every person who runs a sweep.
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

# The emulator's card-socket opcodes.
OP_XFR = 0x00
OP_POWER_ON = 0x01
OP_POWER_OFF = 0x02
# "Unplug and plug back in": the suites that reset need the CTAP 2.1 §6.6
# power-up window, which only a real power cycle reopens; `replug.py` asks an
# operator for it, so the shim answers on their behalf — see `_patch_replug`.
OP_REPLUG = 0x03

# An on-card RSA-4096 keygen is the slowest thing the card socket ever answers.
CARD_TIMEOUT_S = 300

# Exit code for a suite the emulator cannot serve — the autotools convention, so
# a sweep can count skips apart from both passes and failures.
EXIT_SKIP = 77

# What the emulator has nothing to answer with, and why. Each of these fails on
# the emulator for a reason that is not a defect, so it is refused before it
# starts. Removing an entry is a claim that the emulator grew the capability.
UNSUPPORTED = {
    # The vendor AID (counter, LED, bench, reboot-to-BOOTSEL) is implemented in
    # `firmware/src/vendor.rs`, not in a crate, and drives hardware the emulator
    # does not have.
    "01_flash_persistence": "needs the firmware-local vendor AID",
    "14_up_only_after_reboot": "needs the firmware-local vendor AID (reboot)",
    "15_u2f_vendor_msg_isolation": "needs the firmware-local vendor AID",
    "30_ccid_transport": "needs the firmware-local vendor AID (counter)",
    "51_secure_reboot": "needs the firmware-local vendor AID (reboot)",
    "76_soft_lock": "needs the firmware-local vendor AID (reboot)",
    # Below the applet layer: the emulator serves reports and APDUs, not USB.
    "02_usb_interfaces": "reads the USB descriptors; the emulator has no USB",
    "73_otp_keyboard": "drives the OTP keyboard interface over raw USB",
    "77_otp_touch_wait": "drives the OTP keyboard interface over raw USB",
    "53_ccid_pinpad": "needs the PC/SC reader's FEATURE_VERIFY_PIN_DIRECT layer",
    # Faking python-fido2's own transport would leave the suite testing this
    # shim instead of a third-party client, which is the whole point of it.
    "61_pqc_thirdparty_client": "driven through python-fido2's HID transport",
    "65_pqc_thirdparty_client65": "driven through python-fido2's HID transport",
    # Hardware by definition.
    "54_sram_residue": "measures SRAM residue on a real chip",
    "90_otp_mkek_migration": "migrates the OTP MKEK; the emulator has no fuses",
}

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


def _card_request(sock, op, payload=b""):
    """One card-socket exchange: `op | len:u32be | payload` out, `len:u32be |
    payload` back."""
    sock.sendall(bytes([op]) + len(payload).to_bytes(4, "big") + bytes(payload))
    return _recv_exact(sock, int.from_bytes(_recv_exact(sock, 4), "big"))


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise OSError("the emulator closed the card socket")
        buf += part
    return buf


def _replug():
    """Tell the emulator to power-cycle. Best effort: without the card socket
    (`--ccid-port 0`) there is nothing to ask, and the suite then fails on the
    reset window rather than on a connection error."""
    try:
        with socket.create_connection(_addr(ENV_CCID_ADDR, DEFAULT_CCID_ADDR), timeout=5) as s:
            _card_request(s, OP_REPLUG)
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


class SmartcardException(Exception):
    pass


class CardConnectionException(SmartcardException):
    pass


class NoCardException(SmartcardException):
    def __init__(self, hresult=0, message="no card"):
        super().__init__(message)
        self.hresult = hresult


class CardConnection:
    """pyscard's protocol constants; the emulator serves APDUs and has no T=0/T=1
    layer to select between, so `connect` takes the argument and ignores it."""

    T0_protocol = 0x0001
    T1_protocol = 0x0002
    RAW_protocol = 0x0004
    T15_protocol = 0x0008


class EmuCard:
    """The subset of a pyscard `CardConnection` the suites use, over the card
    socket. Connecting powers the card on, which resets the selected applet's
    security status — the same thing a `SCardConnect` after a disconnect does, so
    a suite that verifies a PIN and reconnects loses it here too."""

    def __init__(self):
        self.sock = None
        self.atr = []

    def connect(self, protocol=None, mode=None, disposition=None):
        try:
            self.sock = socket.create_connection(
                _addr(ENV_CCID_ADDR, DEFAULT_CCID_ADDR), timeout=CARD_TIMEOUT_S
            )
        except OSError as e:
            raise NoCardException(message=f"emulator card socket: {e}") from e
        self.atr = list(_card_request(self.sock, OP_POWER_ON))

    def getATR(self):
        return self.atr

    def transmit(self, apdu, protocol=None):
        if self.sock is None:
            raise CardConnectionException("transmit on a card that is not connected")
        resp = _card_request(self.sock, OP_XFR, bytes(apdu))
        if len(resp) < 2:
            raise CardConnectionException(f"response shorter than a status word: {resp.hex()}")
        return list(resp[:-2]), resp[-2], resp[-1]

    def disconnect(self):
        if self.sock is None:
            return
        try:
            _card_request(self.sock, OP_POWER_OFF)
        except OSError:
            pass  # the emulator went away; the handle is being dropped anyway
        self.sock.close()
        self.sock = None


class EmuReader:
    """One reader, named so `_device.find_reader` sees the RSK marker it looks
    for and a log never reads as a board that was never plugged in."""

    name = f"{EMU_PRODUCT} 00 00"

    def __str__(self):
        return self.name

    __repr__ = __str__

    def createConnection(self):
        return EmuCard()


def _readers(groups=None):
    return [EmuReader()]


def _to_hex_string(data=None, format=0):
    return " ".join(f"{b:02X}" for b in (data or []))


def install():
    """Put the fake `hid` module and `smartcard` package in place of the real
    ones, and make the power-cycle helper drive the emulator instead of an
    operator."""
    fake = types.ModuleType("hid")
    fake.device = EmuHid
    fake.enumerate = _enumerate
    sys.modules["hid"] = fake
    _install_smartcard()
    _patch_replug()
    return fake


def _install_smartcard():
    """A `smartcard` package with the four modules the suites import.

    `smartcard.pcsc.PCSCPart10` is deliberately absent: it is the PC/SC feature
    layer (`FEATURE_VERIFY_PIN_DIRECT`), which the emulator has nothing behind,
    and `53_ccid_pinpad.py` already treats its ImportError as "no pinpad here"."""
    pkg = types.ModuleType("smartcard")
    pkg.__path__ = []  # a package with no submodules to find on disk

    system = types.ModuleType("smartcard.System")
    system.readers = _readers

    util = types.ModuleType("smartcard.util")
    util.toHexString = _to_hex_string

    conn = types.ModuleType("smartcard.CardConnection")
    conn.CardConnection = CardConnection

    exceptions = types.ModuleType("smartcard.Exceptions")
    exceptions.SmartcardException = SmartcardException
    exceptions.CardConnectionException = CardConnectionException
    exceptions.NoCardException = NoCardException

    sys.modules["smartcard"] = pkg
    for name, module in (
        ("System", system),
        ("util", util),
        ("CardConnection", conn),
        ("Exceptions", exceptions),
    ):
        sys.modules[f"smartcard.{name}"] = module
        setattr(pkg, name, module)


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
    target = sys.argv[1]
    name = os.path.basename(target).removesuffix(".py")
    if name in UNSUPPORTED:
        print(f"SKIP: {name} — {UNSUPPORTED[name]}. Run it against a board.")
        sys.exit(EXIT_SKIP)
    install()
    sys.argv = sys.argv[1:]
    # The suites add their own directory to sys.path for `_device`; do it here
    # too, since the script is run by path.
    sys.path.insert(0, os.path.dirname(os.path.abspath(target)))
    runpy.run_path(target, run_name="__main__")


if __name__ == "__main__":
    main()
