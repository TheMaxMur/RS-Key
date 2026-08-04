# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk led — LED customisation over the vendor applet (CCID).

SET LED (INS 0x10, P1=brightness, P2 = color | steady 0x08 | status<<4,
optional data[0..1] = effect, speed) / GET LED (INS 0x11, returns
[steady, (effect, color, brightness, speed) x 4] — 17 bytes).
Per-status color + brightness + effect + speed; --steady is a solid color
(global). Persists in flash, applies live.
"""

import sys

from . import ccid
from .backup import (
    CONFIG_READ,
    CONFIG_TARGET_LED,
    CONFIG_WRITE,
    _die_pin_required,
    _die_touch_denied,
    _gated,
    _vendor,
)
from .common import add_pin_arg, connect_fido, device_has_pin, die, resolve_pin

COLORS = {
    "off": 0,
    "red": 1,
    "green": 2,
    "blue": 3,
    "yellow": 4,
    "magenta": 5,
    "cyan": 6,
    "white": 7,
}
COLOR_NAMES = {v: k for k, v in COLORS.items()}
EFFECTS = {"legacy": 0, "vapor": 1, "bounce": 2, "flow": 3, "sparkle": 4}
EFFECT_NAMES = {v: k for k, v in EFFECTS.items()}
STATUSES = {"idle": 0, "processing": 1, "touch": 2, "boot": 3}
STATUS_NAMES = {v: k for k, v in STATUSES.items()}
P2_STEADY = 0x08
# 17-byte block format: [steady, (effect, color, brightness, speed) x 4]
BLOCK_STRIDE = 4  # bytes per status
BLOCK_OFF_STEADY = 0
BLOCK_OFF_EFFECT = 1  # first status starts here
BLOCK_OFF_COLOR = 2
BLOCK_OFF_BRIGHTNESS = 3
BLOCK_OFF_SPEED = 4
CONF_LEN = 1 + BLOCK_STRIDE * len(STATUSES)  # 17


def register(sub):
    p = sub.add_parser("led", help="LED color/brightness/effect customisation")
    p.add_argument(
        "--status",
        choices=sorted(STATUSES),
        default="idle",
        help="which status to change (default idle)",
    )
    p.add_argument(
        "--brightness",
        type=int,
        metavar="0-255",
        help="per-channel brightness for --status (0 = off)",
    )
    p.add_argument("--color", choices=sorted(COLORS), help="color for --status")
    p.add_argument(
        "--effect", choices=sorted(EFFECTS), help="visual effect for --status"
    )
    p.add_argument(
        "--speed", type=int, metavar="0-255", help="effect speed (0 = built-in default)"
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--steady", action="store_true", help="solid color, no blinking")
    g.add_argument("--blink", action="store_true", help="restore status blinking")
    p.add_argument("--get", action="store_true", help="read the current config")
    p.add_argument(
        "--transport",
        choices=["ccid", "fido"],
        default="ccid",
        help="ccid (PC/SC, default) or fido (CTAPHID — when pcscd can't reach the "
        "card; read-modify-write via CONFIG_READ/WRITE, gated by PIN + touch, applied live)",
    )
    add_pin_arg(p)
    p.set_defaults(func=run)


def _get_block(conn):
    d, s1, s2 = ccid.transmit(conn, [0x00, 0x11, 0x00, 0x00, 0x00])
    # The readers index up to d[15] (steady + 4 statuses x 4 bytes); require the
    # full block so a short/hostile response fails cleanly instead of IndexError.
    if (s1, s2) != ccid.SW_OK or len(d) < 16:
        raise SystemExit(f"GET LED failed: {s1:02X}{s2:02X} (len {len(d)})")
    return d


def _status_offset(st):
    return BLOCK_OFF_EFFECT + st * BLOCK_STRIDE


def _changing(args):
    return (
        args.brightness is not None
        or args.color is not None
        or args.effect is not None
        or args.speed is not None
        or args.steady
        or args.blink
    )


def _apply_block(block, args):
    """Read-modify-write the 17-byte block for `--status` from the CLI overrides —
    the whole-block form the FIDO CONFIG_WRITE takes. Validates ranges in place."""
    st = STATUSES[args.status]
    off = _status_offset(st)
    if args.effect is not None:
        block[off] = EFFECTS[args.effect]
    if args.color is not None:
        block[off + 1] = COLORS[args.color]
    if args.brightness is not None:
        if not 0 <= args.brightness <= 255:
            raise SystemExit("--brightness must be 0–255")
        block[off + 2] = args.brightness
    if args.speed is not None:
        if not 0 <= args.speed <= 255:
            raise SystemExit("--speed must be 0–255")
        block[off + 3] = args.speed
    if args.steady:
        block[BLOCK_OFF_STEADY] = 1
    elif args.blink:
        block[BLOCK_OFF_STEADY] = 0


def _show_block(d):
    print(f"mode={'steady' if d[BLOCK_OFF_STEADY] else 'blink'}")
    for st, name in sorted(STATUS_NAMES.items()):
        off = _status_offset(st)
        effect = EFFECT_NAMES.get(d[off], d[off])
        color = COLOR_NAMES.get(d[off + 1], d[off + 1])
        brightness = d[off + 2]
        print(
            f"  {name:<10} color={color:<8} brightness={brightness:<3} effect={effect}"
        )


def run(args):
    if args.transport == "fido":
        _run_fido(args)
    else:
        _run_ccid(args)


def _writes(args):
    """Whether this invocation will persist a block, so it must not land on a
    guessed device. A read may still take the first match — `rsk status` and
    `rsk inventory` are the multi-device-aware views and deliberately do."""
    return _changing(args) and not args.get


def _run_ccid(args):
    conn = ccid.connect(exclusive=_writes(args))
    ccid.select(conn, ccid.VENDOR_AID)
    if _changing(args):
        block = _get_block(conn)
        st = STATUSES[args.status]
        off = _status_offset(st)
        # Read current values from block.
        effect = block[off]
        color = block[off + 1]
        brightness = block[off + 2]
        steady = bool(block[BLOCK_OFF_STEADY])

        # Apply user overrides.
        if args.brightness is not None:
            if not 0 <= args.brightness <= 255:
                raise SystemExit("--brightness must be 0–255")
            brightness = args.brightness
        if args.color is not None:
            color = COLORS[args.color]
        if args.effect is not None:
            effect = EFFECTS[args.effect]
        if args.speed is not None:
            if not 0 <= args.speed <= 255:
                raise SystemExit("--speed must be 0–255")
        steady = True if args.steady else False if args.blink else steady

        # Build APDU: P1 = brightness, P2 = color | steady | status<<4.
        p2 = (color & 0x7) | (P2_STEADY if steady else 0) | (st << 4)
        # Include optional data bytes for effect and speed.
        data = []
        if args.effect is not None or args.speed is not None:
            data.append(effect)
            if args.speed is not None:
                data.append(args.speed & 0xFF)
        _, s1, s2 = ccid.transmit(conn, [0x00, 0x10, brightness & 0xFF, p2] + data)
        if (s1, s2) != ccid.SW_OK:
            raise SystemExit(f"SET LED failed: {s1:02X}{s2:02X}")
        parts = [
            f"set {args.status}: color={COLOR_NAMES.get(color, color)}",
            f"brightness={brightness}",
            f"effect={EFFECT_NAMES.get(effect, effect)}",
            f"(mode={'steady' if steady else 'blink'})",
        ]
        print(" ".join(parts))
    if args.get or not _changing(args):
        _show_block(_get_block(conn))


def _read_block_fido(dev, cid):
    """Read EF_LED_CONF over CTAPHID (CONFIG_READ LED, ungated) as a mutable block.
    The firmware seeds the record with the defaults on first boot, so this is
    always a full block to read-modify-write."""
    st, m = _vendor(dev, cid, {1: CONFIG_READ, 2: {1: CONFIG_TARGET_LED}})
    if st != 0:
        die(
            f"CONFIG_READ LED failed: {st:#x} — firmware too old for LED-over-FIDO "
            "(needs bcdDevice ≥ 0x07F0)"
        )
    v = m[1] if m and 1 in m else b""
    # The device controls this value; a CBOR integer would make bytes(v) attempt a
    # huge allocation. Require the byte string the record is supposed to be.
    if not isinstance(v, (bytes, bytearray)):
        die("device returned a malformed LED block (non-bytes CONFIG_READ value)")
    b = bytes(v)
    if len(b) < CONF_LEN:
        die("device returned no LED block — update firmware, or set it once via CCID")
    return bytearray(b[:CONF_LEN])


def _run_fido(args):
    """The pcscd-free path: read-modify-write EF_LED_CONF over CTAPHID (CONFIG_READ
    + the PIN/touch-gated CONFIG_WRITE). The firmware applies it live."""
    dev, cid = connect_fido(exclusive=_writes(args))
    block = _read_block_fido(dev, cid)
    if args.get or not _changing(args):
        _show_block(block)
        return
    _apply_block(block, args)
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    print(
        "if the device prompts for a touch, approve it (only strict-config builds gate this FIDO write)…",
        file=sys.stderr,
    )
    fields = _gated(CONFIG_WRITE, {1: CONFIG_TARGET_LED, 2: bytes(block)}, dev, cid, pin)
    st, _ = _vendor(dev, cid, fields)
    _die_pin_required(st)
    _die_touch_denied(st)
    if st != 0:
        die(f"CONFIG_WRITE LED failed: {st:#x}")
    print("LED config written over FIDO ✓ (applied live)")
    _show_block(block)
