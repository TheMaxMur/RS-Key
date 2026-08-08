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
    """Send one CTAPHID_WINK and report whether the device answered it.
    A device that answers nothing returns an empty read on the timeout, so the
    reply is bounds-checked rather than indexed."""
    ctaphid.write(dev, cid + bytes([CTAPHID_WINK, 0, 0]))
    r = ctaphid.read(dev)
    return len(r) > 4 and r[4] == CTAPHID_WINK


def _identify_one(tag, info, repeat):
    """Wink one enumerated device; report why not and return False if it cannot be.
    Every failure here is per-device — this command exists to walk *all* of them, so
    one key that is busy, silent or refuses must not end the walk for the rest."""
    dev = ctaphid.hid.device()
    try:
        dev.open_path(info["path"])
        cid, caps = ctaphid.ctaphid_init_caps(dev)
        if not caps & CAPFLAG_WINK:
            print(f"{tag} — no indicator (does not advertise wink)")
            return False
        for n in range(repeat):
            if not wink(dev, cid):
                print(f"{tag} — refused CTAPHID_WINK")
                return False
            if n + 1 < repeat:
                time.sleep(GAP_S)
    except (OSError, ValueError) as e:
        print(f"{tag} — unreachable ({e})")
        return False
    finally:
        dev.close()
    print(f"{tag} — winking now 👀")
    return True


def run(args):
    if args.repeat < 1:
        die("--repeat must be at least 1")
    found = ctaphid.find_all()
    if not found:
        die("no FIDO HID device found (usage page 0xF1D0)")
    winked = 0
    for i, info in enumerate(found):
        if not _identify_one(f"{i + 1}. {label(info)}", info, args.repeat):
            continue
        winked += 1
        if i + 1 < len(found):
            time.sleep(GAP_S)
    if not winked:
        die("no attached device can wink (a build with no indicator cannot identify itself)")
