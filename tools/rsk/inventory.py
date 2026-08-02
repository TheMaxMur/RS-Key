# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk inventory — fleet enumeration and device identity verification.

list:   one record per connected RS-Key: serial (the RP2350 OTP chip id, read
        from the rescue applet's SELECT response), secure-boot state, flash
        usage, firmware version, bcdDevice (the build counter), FIDO options,
        backup / soft-lock state, org-attestation state. Touch-free and
        PIN-free — safe against a whole hub of keys. `--json` emits one JSON
        object per line for scripting.

verify: challenge-response proof that the key in hand is the enrolled device:
        the device signs a fresh challenge with the DEVK-derived P-256
        attestation key (vendor AUDIT_CHECKPOINT — the same key `rsk audit
        verify` prints). Pin it against the fingerprint or full public key
        recorded at provisioning with --expect-key. Touch; --pin if a PIN is
        set. The checkpoint is itself journaled, so every verify leaves a
        trace in the audit log.
"""
import json
import os
import sys

from . import ccid, ctaphid
from .audit import AUDIT_CHECKPOINT, _fingerprint, verify_checkpoint
from .backup import ERR_NOT_ALLOWED, _die_pin_required, _die_touch_denied, _gated, _vendor
from .common import (add_pin_arg, connect_fido, device_has_pin, die,
                     resolve_pin, sanitize, sanitize_join)
from .fido import ATT_STATE  # vendor: org-attestation state (ungated)
from .status import RESCUE_AID, VENDOR_STATE, _fw, rescue_read, rescue_serial


def register(sub):
    p = sub.add_parser("inventory", help="fleet enumeration + device identity check")
    g = p.add_subparsers(dest="cmd", required=True)

    ls = g.add_parser("list", help="one record per connected key (touch-free)")
    ls.add_argument("--json", action="store_true", help="one JSON object per line")
    ls.set_defaults(func=cmd_list)

    v = g.add_parser("verify", help="challenge-response vs the enrolled attestation key")
    add_pin_arg(v)
    v.add_argument("--expect-key",
                   help="expected identity: 16-hex fingerprint or full hex SEC1 pubkey")
    v.set_defaults(func=cmd_verify)


# --- collection ---------------------------------------------------------------

def _ccid_records():
    """One record per PC/SC reader that answers the rescue SELECT."""
    try:
        from smartcard.System import readers
    except ImportError:
        return []
    try:
        rs = readers()
    except Exception:
        return []
    out = []
    for r in rs:
        rec = {"reader": str(r)}
        try:
            conn = r.createConnection()
            conn.connect()
            d, s1, s2 = ccid.select(conn, RESCUE_AID)
            serial = rescue_serial(d, s1, s2)
            if serial is None:
                continue  # not an RS-Key
            rec["serial"] = serial
            rec["sdk"] = f"{d[2]}.{d[3]}"
            d, s1, s2 = rescue_read(conn, 0x03)
            if (s1, s2) == ccid.SW_OK and len(d) >= 3:
                rec["secure_boot"] = {"enabled": bool(d[0]), "locked": bool(d[1]),
                                      "bootkey": d[2]}
            d, s1, s2 = rescue_read(conn, 0x02)
            if (s1, s2) == ccid.SW_OK and len(d) >= 20:
                rec["flash"] = {"free": int.from_bytes(d[0:4], "big"),
                                "used": int.from_bytes(d[4:8], "big"),
                                "kv_total": int.from_bytes(d[8:12], "big"),
                                "files": int.from_bytes(d[12:16], "big"),
                                "chip": int.from_bytes(d[16:20], "big")}
            conn.disconnect()
        except Exception as e:
            rec["error"] = str(e)
            if "serial" not in rec:
                continue  # never answered as an RS-Key — skip foreign readers
        out.append(rec)
    return out


def _hid_records():
    """One record per FIDO HID device (usage page 0xF1D0)."""
    out = []
    for info in ctaphid.hid.enumerate():
        if info.get("usage_page") != ctaphid.FIDO_USAGE_PAGE:
            continue
        rec = {"product": info.get("product_string"),
               "bcd_device": f"0x{info.get('release_number', 0):04x}"}
        dev = ctaphid.hid.device()
        try:
            dev.open_path(info["path"])
            cid = ctaphid.ctaphid_init(dev)
            r = ctaphid.send_cbor(dev, cid, bytes([ctaphid.CTAP_GET_INFO]))
            if r[0] == 0:
                gi = ctaphid.decode(r[1:])
                rec["fw"] = _fw(gi.get(14))
                rec["versions"] = gi.get(1)
                rec["aaguid"] = gi.get(3).hex() if gi.get(3) else None
                rec["client_pin"] = bool((gi.get(4) or {}).get("clientPin"))
            st, m = _vendor(dev, cid, {1: VENDOR_STATE})
            if st == 0:
                rec["backup"] = {"sealed": bool(m.get(1)), "has_seed": bool(m.get(2))}
                if 3 in m:
                    rec["lock"] = {"locked": bool(m.get(3)), "unlocked": bool(m.get(4))}
            st, m = _vendor(dev, cid, {1: ATT_STATE})
            if st == 0:
                rec["org_attestation"] = {"installed": bool(m.get(1))}
                if m.get(1) and m.get(2):
                    rec["org_attestation"]["chain_sha256"] = m[2].hex()
        except Exception as e:
            rec["error"] = str(e)
        finally:
            dev.close()
        out.append(rec)
    return out


def gather():
    """CCID + HID records; merged into one when exactly one of each is present
    (with several keys on the bus the two transports cannot be matched up, so
    the records stay separate, each tagged with its transport)."""
    ccid_recs, hid_recs = _ccid_records(), _hid_records()
    if len(ccid_recs) == 1 and len(hid_recs) == 1:
        return [{"transport": "ccid+hid", **ccid_recs[0], **hid_recs[0]}]
    return ([{"transport": "ccid", **r} for r in ccid_recs]
            + [{"transport": "hid", **r} for r in hid_recs])


# --- list ---------------------------------------------------------------------

def _print_record(rec):
    name = sanitize(rec.get("serial") or rec.get("product") or "?")
    print(f"device {name}  ({rec['transport']})")
    if rec.get("error"):
        print(f"  error      : {rec['error']}")
    fw = rec.get("fw")
    if fw or rec.get("bcd_device"):
        print(f"  firmware   : {fw or '?'}  bcdDevice {rec.get('bcd_device', '?')}"
              + (f"  sdk {rec['sdk']}" if rec.get("sdk") else ""))
    sb = rec.get("secure_boot")
    if sb:
        state = "LOCKED" if sb["locked"] else "ENABLED" if sb["enabled"] else "not enabled"
        print(f"  secure boot: {state}  (bootkey {sb['bootkey']:#x})")
    fl = rec.get("flash")
    if fl:
        print(f"  flash      : {fl['used']}/{fl['kv_total']} B used, {fl['files']} files")
    if rec.get("versions") is not None:
        print(f"  fido       : {sanitize_join(rec['versions'])}  clientPin={rec.get('client_pin')}")
    b, lk = rec.get("backup"), rec.get("lock")
    if b:
        lock = ("LOCKED" if lk["locked"] else "off") if lk else "n/a"
        print(f"  backup     : sealed={b['sealed']} has_seed={b['has_seed']}  seed lock: {lock}")
    att = rec.get("org_attestation")
    if att:
        chain = f"  chain sha256 {att['chain_sha256'][:16]}…" if att.get("chain_sha256") else ""
        print(f"  org attest : {'installed' + chain if att['installed'] else 'not installed'}")


def cmd_list(args):
    recs = gather()
    if args.json:
        for rec in recs:
            print(json.dumps(rec))
        return
    if not recs:
        die("no RS-Key found (neither FIDO HID nor CCID answered)")
    for i, rec in enumerate(recs):
        if i:
            print()
        _print_record(rec)
    if len(recs) > 1 and any(r["transport"] != "ccid+hid" for r in recs):
        print("\nnote: several keys connected — CCID and HID records cannot be "
              "matched to each other; plug keys in one at a time for merged records")


# --- verify -------------------------------------------------------------------

def cmd_verify(args):
    # The printed serial and the printed fingerprint must come from the same physical
    # device: `docs/guides/fleet.md` tells the operator to record them together as the
    # enrollment anchor, and `--expect-key` checks only the fingerprint afterwards. The
    # two halves are resolved by different transports, so refuse to guess.
    dev, cid = connect_fido(exclusive=True)
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    challenge = os.urandom(16)
    print("touch the device (BOOTSEL) to sign the challenge…", file=sys.stderr)
    st, m = _vendor(dev, cid,
                    _gated(AUDIT_CHECKPOINT, {1: challenge}, dev, cid, pin))
    _die_pin_required(st)
    if st == ERR_NOT_ALLOWED:
        die("refused — no OTP DEVK provisioned (see docs/production.md)")
    _die_touch_denied(st)
    if st != 0:
        die(f"challenge signing failed: {st:#x}")
    _, _, _, pubkey = verify_checkpoint(
        m, challenge, "do not trust this device",
        "SIGNATURE INVALID — this device cannot prove its identity")

    fp = _fingerprint(pubkey)
    serials = [r["serial"] for r in _ccid_records() if r.get("serial")]
    if len(serials) == 1:
        print(f"serial      : {serials[0]}")
    elif serials:
        # More than one card answered: nothing here proves which of them owns the
        # attestation key that just signed, so print no serial rather than a wrong one.
        print(f"serial      : (ambiguous — {len(serials)} cards attached)")
    print(f"fingerprint : {fp}")
    print(f"att key     : {pubkey.hex()}")

    if args.expect_key:
        want = args.expect_key.lower().strip()
        if want not in (fp, pubkey.hex()):
            die("attestation key MISMATCH — this is NOT the enrolled device")
        print("verdict     : identity verified ✓ (matches --expect-key)")
    else:
        print("verdict     : signature OK — record the fingerprint and pin "
              "future runs with --expect-key")
