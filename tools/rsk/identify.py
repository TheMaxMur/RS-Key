# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk identify — make a key point at itself (CTAPHID_WINK).

The one command whose whole point is that *several* keys are attached, so unlike
the rest of the CLI it does not refuse to guess: it walks every attached
authenticator, winks each in turn and names it, and you watch which one blinks.

A device that does not advertise `CAPABILITY_WINK` is reported, not winked — the
bit means "implements CTAPHID_WINK" (CTAP §11.2.9.2.1), so an unset one is the
device saying it has no indicator, and sending the command anyway would print a
success nobody can see."""
import time

from . import ctaphid
from .common import die, sanitize

#: CTAPHID_WINK — `TYPE_INIT | 0x08`.
CTAPHID_WINK = 0x88
#: INIT capability bit 0: the device implements CTAPHID_WINK.
CAPFLAG_WINK = 0x01
#: Gap between winks, long enough to tell two bursts apart by eye.
GAP_S = 1.5


def register(sub):
    p = sub.add_parser("identify", help="blink a key's indicator so you can tell it apart")
    p.add_argument("--repeat", type=int, default=1, metavar="N",
                   help="wink each device N times (default 1)")
    p.set_defaults(func=run)


def label(info):
    """A human line for one enumerated device. Both strings come from the device,
    so they go through `sanitize` like every other printed device value."""
    product = sanitize(info.get("product_string") or "?")
    serial = sanitize(info.get("serial_number") or "")
    return f"{product}{f' [{serial}]' if serial else ''}"


def wink(dev, cid):
    """Send one CTAPHID_WINK and report whether the device answered it."""
    ctaphid.write(dev, cid + bytes([CTAPHID_WINK, 0, 0]))
    return ctaphid.read(dev)[4] == CTAPHID_WINK


def run(args):
    if args.repeat < 1:
        die("--repeat must be at least 1")
    found = ctaphid.find_all()
    if not found:
        die("no FIDO HID device found (usage page 0xF1D0)")
    winked = 0
    for i, info in enumerate(found):
        dev = ctaphid.hid.device()
        dev.open_path(info["path"])
        try:
            cid, caps = ctaphid.ctaphid_init_caps(dev)
            if not caps & CAPFLAG_WINK:
                print(f"{i + 1}. {label(info)} — no indicator (does not advertise wink)")
                continue
            for n in range(args.repeat):
                if not wink(dev, cid):
                    die(f"{label(info)} refused CTAPHID_WINK")
                if n + 1 < args.repeat:
                    time.sleep(GAP_S)
            winked += 1
            print(f"{i + 1}. {label(info)} — winking now 👀")
        finally:
            dev.close()
        if i + 1 < len(found):
            time.sleep(GAP_S)
    if not winked:
        die("no attached device can wink (a build with no indicator cannot identify itself)")
