# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk status — a one-shot device overview (FIDO getInfo + secure-boot + backup).

`gather()` returns a plain dict so the same data can drive `--json` and the TUI.
Every channel is probed softly: an absent or erroring channel is reported, not
fatal.
"""
import json

from . import ccid, ctaphid
from .backup import CTAP_VENDOR, STATE as VENDOR_STATE
from .common import sanitize, sanitize_join

RESCUE_AID = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]
INS_RESCUE_READ = 0x1E


def rescue_read(conn, p1):
    return ccid.transmit(conn, [0x80, INS_RESCUE_READ, p1, 0x00, 0x00])


def rescue_serial(d, s1, s2):
    """8-byte chip serial (hex) from a rescue SELECT response, or None (protocol.md §7)."""
    if (s1, s2) != ccid.SW_OK or len(d) < 12:
        return None
    return d[4:12].hex()


def _fw(v):
    return f"{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}" if isinstance(v, int) else None


def _fido():
    """getInfo + backup state over one HID session; {} if no FIDO device."""
    info = ctaphid.find()
    if not info:
        return {"present": False}
    out = {"present": True}
    dev = ctaphid.hid.device()
    dev.open_path(info["path"])
    try:
        cid = ctaphid.ctaphid_init(dev)
        r = ctaphid.send_cbor(dev, cid, bytes([ctaphid.CTAP_GET_INFO]))
        if r[0] == 0:
            gi = ctaphid.decode(r[1:])
            out["versions"] = gi.get(1)
            out["aaguid"] = gi.get(3).hex() if gi.get(3) else None
            out["fw"] = _fw(gi.get(14))
            opts = gi.get(4) or {}
            out["clientPin"] = bool(opts.get("clientPin"))
            out["options"] = sorted(k for k, v in opts.items() if v)
        rb = ctaphid.send_cbor(dev, cid, bytes([CTAP_VENDOR]) + ctaphid.enc({1: VENDOR_STATE}))
        if rb[0] == 0:
            m = ctaphid.decode(rb[1:])
            out["backup"] = {"sealed": bool(m.get(1)), "has_seed": bool(m.get(2))}
            if 3 in m:  # soft-lock state (bcdDevice >= 0x0742)
                out["lock"] = {"locked": bool(m.get(3)), "unlocked": bool(m.get(4))}
    except Exception as e:
        out["error"] = str(e)
    finally:
        dev.close()
    return out


def _secure_boot():
    """rescue READ P1=0x03 (+0x06 anti-rollback) over CCID; None if unavailable."""
    try:
        conn = ccid.connect()
    except (SystemExit, Exception):
        return None
    try:
        sel, s1, s2 = ccid.select(conn, RESCUE_AID)
        if (s1, s2) != ccid.SW_OK:
            return {"available": False}
        serial = rescue_serial(sel, s1, s2)
        d, s1, s2 = rescue_read(conn, 0x03)
        if (s1, s2) != ccid.SW_OK or len(d) < 3:
            return {"available": False}
        out = {"available": True, "enabled": bool(d[0]), "locked": bool(d[1]), "bootkey": d[2], "serial": serial}
        d, s1, s2 = rescue_read(conn, 0x06)
        if (s1, s2) == ccid.SW_OK and len(d) >= 3:  # bcdDevice >= 0x074A
            out["rollback"] = {"required": bool(d[0]), "version": d[1], "capacity": d[2]}
        return out
    except Exception as e:
        return {"available": False, "error": str(e)}


def gather():
    sb = _secure_boot()
    return {"fido": _fido(), "secure_boot": sb, "serial": (sb or {}).get("serial")}


def register(sub):
    p = sub.add_parser("status", help="device overview (FIDO + secure-boot + backup)")
    p.add_argument("--json", action="store_true", help="machine-readable (for the TUI)")
    p.set_defaults(func=run)


def run(args):
    s = gather()
    if args.json:
        print(json.dumps(s))
        return
    if s.get("serial"):
        print(f"serial     : {s['serial']}")
    f = s["fido"]
    if not f.get("present"):
        print("FIDO HID   : not found")
    else:
        print(f"FIDO HID   : present  fw {f.get('fw')}  aaguid {(f.get('aaguid') or '')[:16]}…")
        print(f"  versions : {sanitize_join(f.get('versions'))}")
        print(f"  clientPin: {f.get('clientPin')}")
        b = f.get("backup")
        if b:
            print(f"  backup   : sealed={b['sealed']}  has_seed={b['has_seed']}")
        lk = f.get("lock")
        if lk:
            state = "LOCKED" + (" (unlocked this session)" if lk["unlocked"] else " — FIDO ops disabled") if lk["locked"] else "off"
            print(f"  seed lock: {state}")
    sb = s["secure_boot"]
    if not sb or not sb.get("available"):
        print("secure boot: (CCID unavailable)")
    else:
        state = "LOCKED" if sb["locked"] else "ENABLED" if sb["enabled"] else "not enabled"
        print(f"secure boot: {state}  (enabled={sb['enabled']} locked={sb['locked']} bootkey={sb['bootkey']:#x})")
        rb = sb.get("rollback")
        if rb:
            state = "required" if rb["required"] else "not required (versionless images still boot)"
            print(f"  rollback : {state}  boot version {rb['version']}/{rb['capacity']}")
