#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Which device the on-device tests talk to, and what version it should report.

    python tests/10_fido_getinfo.py                              # one key attached
    RSK_TEST_SERIAL=rs-key-0001 python tests/10_fido_getinfo.py  # …one of several
    RSK_TEST_PATH="$path" python tests/13_u2f.py                 # …by hidapi path
    RSK_TEST_READER=RSK python tests/31_openpgp_select.py        # …CCID, by reader name

A first match over `hid.enumerate()` takes whatever the OS lists first. Next to a
real YubiKey, a board built `VIDPID=Yubikey5` answers on the same 1050:0407, and
on 2026-08-02 tests 10 and 15 ran against the *YubiKey* — reporting its aaguid,
its `alwaysUv` and its `6700` as RS-Key failures. Audit run-31 fixed the same
class in the host CLI (`tools/rsk/ctaphid.find_all`, `common.connect_fido`).

The rule here is that one: a single attached device is the target; with several
the target is named, or the run stops instead of guessing. `RSK_MARKERS` breaks a
tie — it never picks blindly.

`find_reader` applies it on the PC/SC side, where the same first-match habit was
copy-pasted into every CCID script with an `rs[0]` fallback. That fallback is the
sharper edge of the two: several of these suites are destructive (`tests/80_piv.py`
blocks both PIN references and factory-RESETs, `tests/90_otp_mkek_migration.py`
migrates the OTP kbase), and a build whose `USB_PRODUCT` carries no marker left
them driving whatever reader the OS listed first.

`RSK_TEST_SERIAL` is the portable pin: hidapi and python-fido2 report the same
device under different path syntax, so a path copied from one will not match the
other. `RSK_TEST_READER` is a substring of the PC/SC reader name, since that name
is a display string with a host-assigned slot index, not a stable id.
"""
import os
import sys
from collections import namedtuple

try:
    import hid
except ImportError:  # the python-fido2 suites run in a venv without hidapi
    hid = None

try:
    from smartcard.System import readers
except ImportError:  # the HID-only suites run in a venv without pyscard
    readers = None

# The two enumerations (hidapi dicts, python-fido2 descriptors) narrowed to what
# picking a device needs.
Ident = namedtuple("Ident", "path serial product vid pid")

ENV_SERIAL = "RSK_TEST_SERIAL"
ENV_PATH = "RSK_TEST_PATH"
ENV_READER = "RSK_TEST_READER"

FIDO_USAGE_PAGE = 0xF1D0
# The Usage Page (0xF1D0) item as it appears in a HID report descriptor: matches a
# FIDO device when hidapi leaves `usage_page` unset (some Linux libusb/hidraw builds
# report 0), so detection stays VID/PID-agnostic (mirrors tools/rsk/ctaphid.py).
FIDO_USAGE_PAGE_ITEM = b"\x06\xd0\xf1"
# The product-string markers both RS-Key identities carry ("RS-Key Security Key",
# "YubiKey RSK OTP+FIDO+CCID"); a genuine YubiKey carries neither. The PC/SC reader
# name is that same product string, so find_reader matches on it too.
RSK_MARKERS = ("RSK", "RS-Key")
# The firmware version every applet reports, and the build var that changes it
# (crates/rsk-sdk/build.rs, docs/build.md).
FW_VERSION_DEFAULT = "5.7.4"
ENV_FW_VERSION = "FW_VERSION"

_announced = None  # last announced path: poll loops call find() every 50 ms
_announced_reader = None  # the reader twin: the warm-reboot helpers poll too
_warned_pin = False
_warned_reader_pin = False


def find_all():
    """Every attached FIDO HID device, in enumeration order. Unfiltered and silent."""
    if hid is None:
        sys.exit("missing dependency: pip install hidapi")
    devices = hid.enumerate()
    found = [d for d in devices if d.get("usage_page") == FIDO_USAGE_PAGE]
    if found:
        return found
    # hidapi left usage_page unset (0/None) — read each such device's report
    # descriptor and match the FIDO usage-page item directly, rather than guessing
    # by VID/PID (RS-Key ships several presets, so no fixed pair to key off).
    return [d for d in devices if not d.get("usage_page") and _declares_fido(d.get("path"))]


def find():
    """The device under test, or None when it is not attached — the replug helpers
    poll on that. Exits when the choice is ambiguous: guessing is what this replaces."""
    return _pick(find_all(), _hid_ident)


def find_fido2():
    """`find` for the suites driven through python-fido2 (their venv has no hidapi).

    Picks over descriptors, not `CtapHidDevice.list_devices()`, which opens a
    connection to every attached key on the way past — including the one this must
    not touch."""
    from fido2.hid import CtapHidDevice, list_descriptors, open_connection

    desc = _pick(list(list_descriptors()), _fido2_ident)
    return CtapHidDevice(desc, open_connection(desc)) if desc else None


def find_reader(require_marker=False):
    """The PC/SC reader of the device under test, or None when it is not attached.
    Exits when the choice is ambiguous: guessing is what this replaces.

    `require_marker` drops the lone-reader case, so an unpinned, unmarked reader reads
    as "not attached" rather than as the board. The reboot pollers (51, 14, 76) need
    that — "is the board back yet?" must not be answered by a stranger, and a real
    YubiKey answers the same mgmt AID 51 probes with. The destructive suites (80, 90)
    take it as a seatbelt. All five refused an unmarked reader before this helper; the
    pin is their way past it.

    Returns the reader, not a connection: 51 wants T1 with a T0 fallback and 80 has
    to step past a `NoCardException`, so the connect stays at the call site (as the
    HID callers do their own `open_path`)."""
    global _announced_reader, _warned_reader_pin
    if readers is None:
        sys.exit("missing dependency: pip install pyscard")
    cands = list(readers())
    if not cands:
        return None
    want = os.environ.get(ENV_READER)
    if want:
        pinned = [r for r in cands if want.lower() in str(r).lower()]
        if not pinned and not _warned_reader_pin:
            _warned_reader_pin = True
            print(f"note: {ENV_READER}={want} matches none of the {len(cands)} attached "
                  f"PC/SC reader(s) — unplugged, or a typo?")
        cands = pinned
    elif require_marker:
        cands = [r for r in cands if _is_rsk(str(r))]
    elif len(cands) > 1:
        cands = [r for r in cands if _is_rsk(str(r))] or cands
    if not cands:
        return None
    if len(cands) > 1:
        sys.exit(
            f"{len(cands)} PC/SC readers to choose from — refusing to guess which is the "
            f"board under test (several of these suites are destructive, and a first "
            f"match here would aim them at a real YubiKey):\n"
            + "\n".join(f"  {r}" for r in cands)
            + f"\nUnplug the others, or name one: {ENV_READER}=<part of the reader name>"
        )
    if _announced_reader != str(cands[0]):
        _announced_reader = str(cands[0])
        print(f"reader: {cands[0]}")
        if not _is_rsk(_announced_reader):
            print(f"   note: no {'/'.join(RSK_MARKERS)} marker in the reader name — is this "
                  f"the board under test? (name it with {ENV_READER})")
    return cands[0]


def fw_version():
    """The (major, minor, patch) the flashed image reports — FIDO getInfo 0x0E, OpenPGP
    INS 0xF1, the OATH/OTP/PIV version fields. Mirrors crates/rsk-sdk/build.rs: 5.7.4
    unless the image was built `FW_VERSION=X.Y.Z`, in which case run the tests with the
    same value (docs/build.md)."""
    raw = os.environ.get(ENV_FW_VERSION) or FW_VERSION_DEFAULT
    parts = raw.split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() and int(p) <= 255 for p in parts):
        sys.exit(f"{ENV_FW_VERSION}={raw!r} must be X, X.Y or X.Y.Z with components 0..=255")
    return tuple(int(p) for p in parts) + (0,) * (3 - len(parts))


def _pick(cands, ident):
    """Resolve `cands` to the one device under test: an explicit pin wins, else the
    RSK marker breaks a tie, else there had better be exactly one."""
    global _warned_pin
    if not cands:
        return None
    want_path, want_serial = os.environ.get(ENV_PATH), os.environ.get(ENV_SERIAL)
    if want_path:
        pinned = [c for c in cands if _text(ident(c).path) == want_path]
    elif want_serial:
        pinned = [c for c in cands if ident(c).serial == want_serial]
    else:
        pinned = None
    if pinned is not None:
        if not pinned and not _warned_pin:
            _warned_pin = True
            print(f"note: {ENV_PATH if want_path else ENV_SERIAL}={want_path or want_serial} "
                  f"matches none of the {len(cands)} attached FIDO HID device(s) — "
                  f"unplugged, or a typo?")
        cands = pinned
    elif len(cands) > 1:
        cands = [c for c in cands if _is_rsk(ident(c).product)] or cands
    if not cands:
        return None
    if len(cands) > 1:
        sys.exit(
            f"{len(cands)} FIDO HID devices to choose from — refusing to guess which is the "
            f"board under test (a first match here has silently tested a real YubiKey "
            f"before):\n"
            + "\n".join(f"  {_describe(ident(c))}" for c in cands)
            + f"\nUnplug the others, or name one: {ENV_SERIAL}=<serial>, or {ENV_PATH}=<path> "
            f"when two boards answer to the same serial"
        )
    _announce(ident(cands[0]))
    return cands[0]


def _announce(ident):
    global _announced
    if _announced == ident.path:
        return
    _announced = ident.path
    print(f"device: {_describe(ident)}")
    if not _is_rsk(ident.product):
        print(f"   note: no {'/'.join(RSK_MARKERS)} marker in the product string — is this "
              f"the board under test? (name it with {ENV_SERIAL})")


def _describe(ident):
    vidpid = f"{ident.vid:04x}:{ident.pid:04x}" if ident.vid is not None else "?"
    return (f"{ident.product or '?'}  {vidpid}  serial={ident.serial or '?'}  "
            f"path={_text(ident.path)}")


def _hid_ident(d):
    return Ident(d.get("path"), d.get("serial_number") or "", d.get("product_string") or "",
                 d.get("vendor_id"), d.get("product_id"))


def _fido2_ident(desc):
    return Ident(desc.path, desc.serial_number or "", desc.product_name or "",
                 desc.vid, desc.pid)


def _is_rsk(product):
    return any(m in product for m in RSK_MARKERS)


def _text(path):
    return path.decode(errors="replace") if isinstance(path, bytes) else str(path or "")


def _declares_fido(path):
    """Open `path` and report whether its HID report descriptor names the FIDO
    usage page. Passive read; any hidapi error means "treat as non-FIDO, skip"."""
    if not path:
        return False
    dev = hid.device()
    try:
        dev.open_path(path)
        desc = bytes(dev.get_report_descriptor())
    except (OSError, ValueError, TypeError, AttributeError):
        return False
    finally:
        dev.close()
    return FIDO_USAGE_PAGE_ITEM in desc
