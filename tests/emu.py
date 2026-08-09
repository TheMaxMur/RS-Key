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
(enumeration, interface order, the CCID packetisation), the arms of the vendor
applet that drive hardware (the LED, the second core, the benches, the drop to
BOOTSEL), and every hardware property the emulator has none of (secure boot, OTP,
fuses). A green run here is a protocol result, not a device result.

The suites in [`UNSUPPORTED`] are refused up front with their reason and exit 77,
rather than being allowed to fail somewhere in the middle. A harness that cannot
tell "does not apply here" from "broken" makes the second one invisible, and each
of them would otherwise be re-diagnosed by every person who runs a sweep.
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

# The emulator's card-socket opcodes: a whole CCID message, or the power cycle
# CCID has no message for. The suites that reset need the CTAP 2.1 §6.6 power-up
# window, which only a real power cycle reopens; `replug.py` asks an operator for
# it, so the shim answers on their behalf — see `_patch_replug`.
OP_CCID = 0x00
OP_REPLUG = 0x03

# CCID message types and the header layout (CCID 1.1 §6). The shim builds the
# same messages a PC/SC driver puts on the bulk-OUT endpoint, so the emulator's
# framing is exercised rather than bypassed.
CCID_POWER_ON = 0x62
CCID_POWER_OFF = 0x63
CCID_XFR_BLOCK = 0x6F
CCID_DATA_BLOCK_RET = 0x80
CCID_SLOT_STATUS_RET = 0x81
CCID_HEADER = 10
# bmCommandStatus (bStatus bits 7:6) == 01 — "time extension requested": the card
# is still working, and the answer is the message after it.
CCID_STATUS_MASK = 0xC0
CCID_STATUS_TIMEEXT = 0x80

# An on-card RSA-4096 keygen is the slowest thing the card socket ever answers.
CARD_TIMEOUT_S = 300

# Exit code for a suite the emulator cannot serve — the autotools convention, so
# a sweep can count skips apart from both passes and failures.
EXIT_SKIP = 77

# Suites that need the Yubico card identity — the emulator has it, but only when
# started `--yubico`. Skipped by *asking the card* rather than by a fixed entry
# below: the identity is a runtime choice, and a hardcoded skip would go on
# refusing a run that would have passed.
NEEDS_YUBICO = {"30_ccid_transport": "asserts the Yubico ATR — start the emulator with --yubico"}
# The Yubico ATR's first two bytes (`rsk_usb::ccid::ATR_YUBIKEY`); the RS-Key one
# differs from byte 1 on.
ATR_YUBICO_PREFIX = bytes([0x3B, 0xFD])

# What the emulator has nothing to answer with, and why. Each of these fails on
# the emulator for a reason that is not a defect, so it is refused before it
# starts. Removing an entry is a claim that the emulator grew the capability.
UNSUPPORTED = {
    # The emulator carries the vendor applet (`crates/rsk-vendor`), so its
    # counter, its warm reboot and the U2F/SELECT routing all run — and `--yubico`
    # gives it the Yubico card identity `30` checks. What it has no hardware for is
    # the LED, the second core's counters and the drop to BOOTSEL.
    "51_secure_reboot": "reboots to BOOTSEL; there is no bootloader to fall into",
    # Below the applet layer: this shim serves reports and APDUs, not USB. The
    # emulator itself does have a USB stack now — `--usbip` attaches it to a Linux
    # host as a real device — but that path needs no shim, so these run there as
    # ordinary hardware suites rather than through here.
    "02_usb_interfaces": "reads the USB descriptors; this shim serves reports",
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


def _recv_frame(sock):
    """One `len:u32be | payload` response off the card socket."""
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
            s.sendall(bytes([OP_REPLUG]) + (0).to_bytes(4, "big"))
            _recv_frame(s)
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
            # The default build's identity (`VIDPID=RSKey`), which is also what
            # `--usbip` presents. It was 0x000D here and in the USB/IP device
            # info — a number neither the firmware nor its build script has ever
            # produced, written twice from the same guess.
            "product_id": 0x0001,
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
    """The subset of a pyscard `CardConnection` the suites use — and the CCID
    driver underneath it, since the socket carries whole CCID messages.

    Connecting powers the card on, which resets the selected applet's security
    status: the same thing a `SCardConnect` after a disconnect does, so a suite
    that verifies a PIN and reconnects loses it here too."""

    def __init__(self):
        self.sock = None
        self.atr = []
        self.seq = 0

    def connect(self, protocol=None, mode=None, disposition=None):
        try:
            self.sock = socket.create_connection(
                _addr(ENV_CCID_ADDR, DEFAULT_CCID_ADDR), timeout=CARD_TIMEOUT_S
            )
        except OSError as e:
            raise NoCardException(message=f"emulator card socket: {e}") from e
        self.atr = list(self._exchange(CCID_POWER_ON))

    def getATR(self):
        return self.atr

    def transmit(self, apdu, protocol=None):
        if self.sock is None:
            raise CardConnectionException("transmit on a card that is not connected")
        resp = self._exchange(CCID_XFR_BLOCK, bytes(apdu))
        if len(resp) < 2:
            raise CardConnectionException(f"response shorter than a status word: {resp.hex()}")
        return list(resp[:-2]), resp[-2], resp[-1]

    def disconnect(self):
        if self.sock is None:
            return
        try:
            self._exchange(CCID_POWER_OFF)
        except OSError:
            pass  # the emulator went away; the handle is being dropped anyway
        self.sock.close()
        self.sock = None

    def _exchange(self, msg_type, payload=b""):
        """Send one `PC_to_RDR` and return the answering message's body, stepping
        over the time extensions a slow command (on-card RSA keygen) streams
        first. Checks what a driver checks — the echoed sequence and the reply
        type — because a client that accepts any framing tests none of it."""
        self.seq = (self.seq + 1) & 0xFF
        header = bytes([msg_type]) + len(payload).to_bytes(4, "little") + bytes(
            [0x00, self.seq, 0x00, 0x00, 0x00]
        )
        self.sock.sendall(
            bytes([OP_CCID])
            + (CCID_HEADER + len(payload)).to_bytes(4, "big")
            + header
            + payload
        )
        while True:
            resp = _recv_frame(self.sock)
            if len(resp) < CCID_HEADER:
                raise CardConnectionException(f"short CCID response: {resp.hex()}")
            if resp[6] != self.seq:
                raise CardConnectionException(f"bSeq {resp[6]} answering {self.seq}")
            if resp[0] == CCID_DATA_BLOCK_RET and resp[7] & CCID_STATUS_MASK == CCID_STATUS_TIMEEXT:
                continue
            dw = int.from_bytes(resp[1:5], "little")
            if len(resp) < CCID_HEADER + dw:
                raise CardConnectionException(f"dwLength {dw} over {len(resp)} bytes")
            return resp[CCID_HEADER:CCID_HEADER + dw]


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


def _card_identity():
    """The ATR the emulator is serving, or `None` when the card socket is not
    there to ask."""
    try:
        card = EmuCard()
        card.connect()
        atr = bytes(card.getATR())
        card.disconnect()
        return atr
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <test script> [args…]")
    target = sys.argv[1]
    name = os.path.basename(target).removesuffix(".py")
    if name in UNSUPPORTED:
        print(f"SKIP: {name} — {UNSUPPORTED[name]}. Run it against a board.")
        sys.exit(EXIT_SKIP)
    if name in NEEDS_YUBICO:
        atr = _card_identity()
        if atr is None or not atr.startswith(ATR_YUBICO_PREFIX):
            print(f"SKIP: {name} — {NEEDS_YUBICO[name]}.")
            sys.exit(EXIT_SKIP)
    install()
    sys.argv = sys.argv[1:]
    # The suites add their own directory to sys.path for `_device`; do it here
    # too, since the script is run by path.
    sys.path.insert(0, os.path.dirname(os.path.abspath(target)))
    runpy.run_path(target, run_name="__main__")


if __name__ == "__main__":
    main()
