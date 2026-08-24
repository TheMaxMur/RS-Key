# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk hw — device hardware wiring and USB-identity strings via the phy record.

The phy record (`EF_PHY`) is the device-config blob PicoForge also writes; it
survives every applet reset and is applied at boot. The rescue applet exposes it
as READ (INS 0x1E, P1=01) and WRITE (INS 0x1C, P1=01). This command does a
read-modify-write of ONLY the fields you pass, so anything set elsewhere
(PicoForge, another flag) is preserved.

  --led-pin       the WS2812/gpio data GPIO (overrides the firmware build LED_PIN)
  --led-driver    the backend: gpio / pimoroni / ws2812 (overrides build LED_KIND)
  --led-order     the WS2812 wire byte order: rgb / grb (overrides build LED_ORDER)
  --manufacturer  the USB iManufacturer string (overrides the build/VID default)
  --product       the USB iProduct string (overrides the build/VID default)

A non-`none` firmware build compiles all three backends, so these switch the LED
at runtime — no reflash. The change applies at the NEXT boot, so a warm reboot is
issued unless --no-reboot. (Per-status COLOURS are a separate, live setting that
persists in a different record — see `rsk led`.)
"""

import sys

from . import ccid
from .backup import (
    CONFIG_READ,
    CONFIG_TARGET_PHY,
    CONFIG_WRITE,
    _die_pin_required,
    _die_touch_denied,
    _gated,
    _vendor,
)
from .common import add_pin_arg, connect_fido, device_has_pin, die, resolve_pin, sanitize
from .status import RESCUE_AID, rescue_read

# phy TLV tags — must match crates/rsk-phy/src/lib.rs.
TAG_LED_GPIO = 0x04
TAG_LED_DRIVER = 0x0C
TAG_LED_ORDER = 0x0D  # RS-Key vendor tag (PicoForge skips it as unknown)
TAG_LED_NUM = 0x0E  # RS-Key vendor tag: addressable LED count
TAG_PRESENCE_TIMEOUT = 0x08  # touch-wait timeout (seconds); PicoForge compatible
# Firmware floor for the touch window (presence::MIN_TIMEOUT_SECS): anything lower
# is raised on the device, so writing it would misreport the real window.
MIN_TOUCH_TIMEOUT = 10
TAG_USB_PRODUCT = 0x09  # iProduct string (NUL-terminated); PicoForge compatible
TAG_USB_MANUFACTURER = 0x0F  # RS-Key vendor tag: iManufacturer string (NUL-terminated)

# The phy record stores up to 32 bytes, but a USB string descriptor is built into a
# 64-byte control buffer that admits only 30 UTF-16 code units — past that the device
# panics during enumeration. The firmware clamps, so an over-long string is truncated
# rather than fatal; reject it here so the truncation is never a surprise.
USB_STR_MAX = 30

# A product name containing "yubikey" without a "CCID" token gets " OTP+FIDO+CCID"
# appended by the firmware (it stops ykman crashing on Windows), which eats into the
# budget above — the firmware truncates the name to make room.
YK_TOKEN_SUFFIX_LEN = len(" OTP+FIDO+CCID")

# Driver numbering follows PicoForge's LedDriverType.
DRIVERS = {"gpio": 1, "pimoroni": 2, "ws2812": 3}
DRIVER_NAMES = {v: k for k, v in DRIVERS.items()}
ORDERS = {"rgb": 0, "grb": 1}
ORDER_NAMES = {v: k for k, v in ORDERS.items()}


def register(sub):
    p = sub.add_parser(
        "hw",
        help="device hardware + USB-identity config (LED wiring, touch timeout, "
        "manufacturer/product strings) via the phy record",
    )
    p.add_argument(
        "--led-pin",
        type=int,
        metavar="0-29",
        help="WS2812/gpio data GPIO (RP2350A 0..=29)",
    )
    p.add_argument(
        "--led-driver",
        choices=sorted(DRIVERS),
        help="LED backend: gpio (on/off), pimoroni (3-pin PWM RGB), ws2812 (addressable)",
    )
    p.add_argument(
        "--led-order",
        choices=sorted(ORDERS),
        help="WS2812 wire byte order: grb (standard WS2812B) or rgb (Waveshare RP2350-One)",
    )
    p.add_argument(
        "--led-num",
        type=int,
        metavar="1-255",
        help="number of addressable LEDs connected at runtime (firmware caps it at the build's MAX_LEDS)",
    )
    p.add_argument(
        "--touch-timeout",
        type=int,
        metavar="10-255",
        help="touch-wait timeout in seconds (PicoForge compatible; firmware default 30, floor 10)",
    )
    p.add_argument(
        "--manufacturer",
        metavar="STR",
        help="USB iManufacturer string (≤30 bytes), overriding the build/VID-derived "
        "default. A Yubico VID already fills in 'Yubico' on its own; set this to pick "
        "your own brand or opt out of the Yubico identity.",
    )
    p.add_argument(
        "--product",
        metavar="STR",
        help="USB iProduct string (≤30 bytes), overriding the build/VID-derived default. "
        "A name containing 'yubikey' without a 'CCID' token gains ' OTP+FIDO+CCID' on "
        "the device, and is truncated to fit — keep it ≤16 bytes to survive intact.",
    )
    p.add_argument(
        "--get", action="store_true", help="read the current phy config and exit"
    )
    p.add_argument(
        "--no-reboot",
        action="store_true",
        help="don't reboot after writing (the change applies on the next boot)",
    )
    p.add_argument(
        "--transport",
        choices=["ccid", "fido"],
        default="ccid",
        help="ccid (PC/SC, default) or fido (CTAPHID — when pcscd can't reach the "
        "card; read-modify-write via CONFIG_READ/WRITE, gated by PIN + touch)",
    )
    add_pin_arg(p)
    p.set_defaults(func=run)


def _parse_tlv(data):
    """Parse the phy record into an ordered list of (tag, value-bytes). A TLV
    running past the end ends the parse (mirrors the firmware parser)."""
    out, i = [], 0
    while i + 2 <= len(data):
        tag, ln = data[i], data[i + 1]
        i += 2
        if i + ln > len(data):
            break
        out.append((tag, data[i : i + ln]))
        i += ln
    return out


def _serialize_tlv(tlvs):
    out = bytearray()
    for tag, val in tlvs:
        out += bytes([tag, len(val)]) + bytes(val)
    return bytes(out)


def _upsert(tlvs, tag, value):
    """Set or replace a single-byte TLV in place; append if not present."""
    for idx, (t, _) in enumerate(tlvs):
        if t == tag:
            tlvs[idx] = (tag, bytes([value]))
            return
    tlvs.append((tag, bytes([value])))


def _upsert_str(tlvs, tag, s):
    """Set or replace a NUL-terminated string TLV (the firmware wire format:
    value = UTF-8 bytes + a trailing NUL). Rejects an over-cap string."""
    raw = s.encode("utf-8")
    if not 1 <= len(raw) <= USB_STR_MAX:
        raise SystemExit(f"string for tag {tag:#04x} must be 1–{USB_STR_MAX} UTF-8 bytes")
    val = raw + b"\x00"
    for idx, (t, _) in enumerate(tlvs):
        if t == tag:
            tlvs[idx] = (tag, val)
            return
    tlvs.append((tag, val))


def _read_phy(conn):
    d, s1, s2 = rescue_read(conn, 0x01)
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(f"READ phy failed: {s1:02X}{s2:02X} (firmware too old?)")
    return _parse_tlv(d)


def _show(tlvs):
    by = {t: v for t, v in tlvs}
    pin = by.get(TAG_LED_GPIO)
    drv = by.get(TAG_LED_DRIVER)
    order = by.get(TAG_LED_ORDER)
    print(
        "phy config ('(build default)' = field absent, firmware build value used):"
    )
    print(f"  pin     {pin[0] if pin else '(build default)'}")
    print(f"  driver  {DRIVER_NAMES.get(drv[0], drv[0]) if drv else '(build default)'}")
    print(
        f"  order   {ORDER_NAMES.get(order[0], order[0]) if order else '(build default)'}"
    )
    led_num = by.get(TAG_LED_NUM)
    print(f"  num     {led_num[0] if led_num else '(build default)'}")
    tmo = by.get(TAG_PRESENCE_TIMEOUT)
    print(f"  touch   {str(tmo[0]) + 's' if tmo else '(build default 30s)'}")

    def _str(v):
        # Device-controlled USB identity strings; sanitize INSIDE the guard so an
        # absent field stays None (sanitize(None) == "None" would print literally).
        return sanitize(v.rstrip(b"\x00").decode("utf-8", "replace")) if v else None

    mfr = _str(by.get(TAG_USB_MANUFACTURER))
    prod = _str(by.get(TAG_USB_PRODUCT))
    print(f"  mfr     {mfr if mfr else '(build/VID default)'}")
    print(f"  product {prod if prod else '(build/VID default)'}")


def _would_set(args):
    """Whether any config flag was passed (vs a bare read/--get)."""
    return (
        args.led_pin is not None
        or args.led_driver is not None
        or args.led_order is not None
        or args.led_num is not None
        or args.touch_timeout is not None
        or args.manufacturer is not None
        or args.product is not None
    )


def _apply_args(tlvs, args):
    """Upsert the phy TLVs the user set on the CLI (validating ranges) — the
    transport-agnostic read-modify-write shared by the CCID and FIDO paths."""
    if args.led_pin is not None:
        if not 0 <= args.led_pin <= 29:
            raise SystemExit("--led-pin must be 0–29 (RP2350A GPIOs)")
        _upsert(tlvs, TAG_LED_GPIO, args.led_pin)
    if args.led_driver is not None:
        _upsert(tlvs, TAG_LED_DRIVER, DRIVERS[args.led_driver])
    if args.led_order is not None:
        _upsert(tlvs, TAG_LED_ORDER, ORDERS[args.led_order])
    if args.led_num is not None:
        if not 1 <= args.led_num <= 255:
            raise SystemExit("--led-num must be 1–255")
        _upsert(tlvs, TAG_LED_NUM, args.led_num)
    if args.touch_timeout is not None:
        # The firmware raises anything below 10 s to 10 s (a window short enough to
        # expire mid-press turns one hold into two grants), so reject it here
        # instead of writing a record the device will not honour.
        if not MIN_TOUCH_TIMEOUT <= args.touch_timeout <= 255:
            raise SystemExit(f"--touch-timeout must be {MIN_TOUCH_TIMEOUT}–255 (seconds)")
        _upsert(tlvs, TAG_PRESENCE_TIMEOUT, args.touch_timeout)
    if args.manufacturer is not None:
        _upsert_str(tlvs, TAG_USB_MANUFACTURER, args.manufacturer)
    if args.product is not None:
        raw = args.product.encode("utf-8")
        if b"yubikey" in raw.lower() and b"CCID" not in raw:
            room = USB_STR_MAX - YK_TOKEN_SUFFIX_LEN
            if len(raw) > room:
                print(
                    f"note: the device appends ' OTP+FIDO+CCID' to a YubiKey-style "
                    f"name, so this will be truncated to {room} bytes "
                    f"({args.product[:room]!r})"
                )
        _upsert_str(tlvs, TAG_USB_PRODUCT, args.product)


def run(args):
    if args.transport == "fido":
        _run_fido(args)
    else:
        _run_ccid(args)


def _run_ccid(args):
    # Writes EF_PHY — the USB identity — so it must not guess a device either.
    conn = ccid.connect(exclusive=True)
    _, s1, s2 = ccid.select(conn, RESCUE_AID)
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(
            f"SELECT rescue AID failed: {s1:02X}{s2:02X} (firmware too old?)"
        )
    tlvs = _read_phy(conn)
    if args.get or not _would_set(args):
        _show(tlvs)
        return
    _apply_args(tlvs, args)

    blob = _serialize_tlv(tlvs)
    # The phy write is device identity, so the firmware gates it behind an
    # on-device confirmation — prompt for it, and explain a decline (6985).
    print(
        "approve on the device (touch / on-screen Approve) to write the config…",
        file=sys.stderr,
    )
    _, s1, s2 = ccid.transmit(
        conn, [0x80, 0x1C, 0x01, 0x00, len(blob)] + list(blob) + [0x00]
    )
    if (s1, s2) == ccid.SW_COND_NOT_SATISFIED:
        raise SystemExit(
            "phy write declined on the device (no confirmation). Approve on the "
            "device when prompted, then retry."
        )
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(f"WRITE phy failed: {s1:02X}{s2:02X}")
    print("phy LED config written ✓")
    _show(tlvs)
    if args.no_reboot:
        print("not rebooting — the change applies on the next boot.")
    else:
        print("rebooting to apply…")
        ccid.reboot(conn, bootsel=False)


def _read_phy_fido(dev, cid):
    """Read EF_PHY over CTAPHID (vendor CONFIG_READ, ungated) for read-modify-write."""
    st, m = _vendor(dev, cid, {1: CONFIG_READ, 2: {1: CONFIG_TARGET_PHY}})
    if st != 0:
        die(
            f"CONFIG_READ failed: {st:#x} — firmware too old for config-over-FIDO "
            "(needs bcdDevice ≥ 0x07EF)"
        )
    v = m[1] if m and 1 in m else b""
    # The device controls this value; a non-bytes CBOR value (e.g. an integer) would make
    # _parse_tlv's len(data) raise. Require the byte string the record is supposed to be
    # (matches led.py's CONFIG_READ guard).
    if not isinstance(v, (bytes, bytearray)):
        die("device returned a malformed PHY block (non-bytes CONFIG_READ value)")
    return _parse_tlv(bytes(v))


def _run_fido(args):
    """The pcscd-free path: read-modify-write EF_PHY over CTAPHID (CONFIG_READ +
    the PIN/touch-gated CONFIG_WRITE). Applies on the next boot — no reboot verb
    here, so the user re-plugs to apply."""
    dev, cid = connect_fido(exclusive=True)
    tlvs = _read_phy_fido(dev, cid)
    if args.get or not _would_set(args):
        _show(tlvs)
        return
    _apply_args(tlvs, args)

    blob = _serialize_tlv(tlvs)
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    print(
        "if the device prompts for a touch, approve it (only strict-config builds gate this FIDO write)…",
        file=sys.stderr,
    )
    fields = _gated(CONFIG_WRITE, {1: CONFIG_TARGET_PHY, 2: blob}, dev, cid, pin)
    st, _ = _vendor(dev, cid, fields)
    _die_pin_required(st)
    _die_touch_denied(st)
    if st != 0:
        die(f"CONFIG_WRITE failed: {st:#x}")
    print("phy config written over FIDO ✓")
    _show(tlvs)
    print("re-plug or reboot the device to apply (the FIDO path does not reboot).")
