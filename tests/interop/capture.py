#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Capture a structured snapshot of ONE security key for the differential.

The other half of the differential (`diff.py` compares two of these). Read-only
by design: every cell only *reads* device state — nothing here mutates keys (the
mutating crypto-parity controls live in `parity.py`).

Both keys can stay plugged: a genuine YubiKey and the RS-Key `VIDPID=Yubikey5`
build are told apart by the **`RSK` marker** the RS-Key build carries in its USB
product string, its FIDO HID descriptor, and its PC/SC reader name (a real key
never has it), while ykman cells target by `--device <serial>`. Capture each:

    python tests/interop/capture.py --label real --serial <yk-serial>  --out real.json
    python tests/interop/capture.py --label rsk  --serial <rsk-serial> --out rsk.json

An **identity guard** refuses to write a snapshot whose device doesn't match the
`--label`: the FIDO AAGUID must be RS-Key's own iff `--label rsk`. It vouches for
the *device*, not for each cell: a cell whose tool takes no device selector (`gpg`,
`pkcs11-tool`) has to pin and then verify its own target, or it quietly records
whichever card scdaemon and OpenSC happened to pick — the worst failure mode of a
two-device diff, because a differing row then reads as a match.

Environment (macOS 27): run under the nix dev-shell python for the `hid`/`pyscard`
transports, but shell out to **Homebrew** `ykman`/`fido2-token`/`gpg`/`pkcs11-tool`
— the nix-packaged ykman aborts under the macOS 27 libffi JIT. `_bin()` prefers
`/opt/homebrew/bin` on Darwin for exactly this reason.
"""
import argparse
import datetime
import json
import os
import platform
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)  # divergences / normalize / run (siblings)
sys.path.insert(0, os.path.dirname(_HERE))  # tests/  → ctaphid

import subprocess  # noqa: E402

import normalize as nz  # noqa: E402

# Env keys the nix dev-shell exports that would sabotage a Homebrew CLI child:
# PYTHONPATH points ykman's own python at the nix site-packages (a mismatched,
# libffi-broken ykman); the DYLD paths pull in nix dylibs. Scrub them for every
# child — native tools (fido2-token, system_profiler) don't care, and capture's
# own process keeps them so `import hid`/`pyscard` still resolve the nix packages.
_SCRUB = ("PYTHONPATH", "PYTHONHOME", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH")


def run(cmd, timeout=25, stdin=None):
    """Spawn a child tool with the nix python/dyld env scrubbed. Returns
    (rc, combined_output); rc<0 means the tool could not be spawned."""
    env = {k: v for k, v in os.environ.items() if k not in _SCRUB}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return -1, f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, f"timeout after {timeout}s (a touch cell with no press?)"


RSK_AAGUID_PREFIX = "2479c7bf"  # RS-Key's self-assigned AAGUID (crates/rsk-fido/src/consts.rs)
RSK_MARKER = "RSK"  # RS-Key's product/reader marker; a genuine YubiKey never carries it
FIDO_USAGE_PAGE = 0xF1D0
MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]


def _bin(name):
    """Prefer the Homebrew build on macOS — the nix ykman/fido2 abort under the
    macOS 27 libffi JIT (same trampoline assert that breaks `rsk`)."""
    if platform.system() == "Darwin":
        hb = f"/opt/homebrew/bin/{name}"
        if os.path.exists(hb):
            return hb
    return shutil.which(name)


def _is_rsk(text):
    return RSK_MARKER in (text or "")


def cell(parsed=None, raw="", status="ok", transport="", touch=False, mutating=False, detail=""):
    return {"raw": raw, "parsed": parsed or {}, "status": status,
            "transport": transport, "touch": touch, "mutating": mutating, "detail": detail}


# ── device discovery, per label ──────────────────────────────────────────────

def ykman_serials():
    yk = _bin("ykman")
    if not yk:
        return []
    rc, out = run([yk, "list", "--serials"])
    return [s.strip() for s in out.splitlines() if s.strip().isdigit()] if rc == 0 else []


def resolve_serial(want):
    serials = ykman_serials()
    if want:
        if want not in serials:
            sys.exit(f"device with serial {want} not found (plugged: {serials or 'none'})")
        return want
    if len(serials) == 1:
        return serials[0]
    if not serials:
        sys.exit("no ykman-visible device — flashed + plugged? (RS-Key needs the VIDPID=Yubikey5 build)")
    sys.exit(f"multiple devices plugged ({serials}); pass --serial to pick one")


def fido_dict(label):
    """The FIDO HID device matching `label` (RS-Key carries the RSK marker in its
    product string; a real key does not). Returns the hidapi dict or None."""
    try:
        import hid
    except Exception:
        return None
    fidos = [d for d in hid.enumerate() if d.get("usage_page") == FIDO_USAGE_PAGE]
    for d in fidos:
        tag = (d.get("product_string") or "") + (d.get("serial_number") or "")
        if _is_rsk(tag) == (label == "rsk"):
            return d
    return None


def raw_getinfo(label):
    """Raw CTAP2 authenticatorGetInfo from the labelled device → decoded map, or None."""
    d = fido_dict(label)
    if not d or not d.get("path"):
        return None
    try:
        import ctaphid as ch
        import hid
    except Exception:
        return None
    dev = hid.device()
    try:
        dev.open_path(d["path"])
        cid = ch.ctaphid_init(dev)
        resp = ch.send_cbor(dev, cid, b"\x04")
        if not resp or resp[0] != 0x00:
            return None
        return ch.decode(resp[1:])
    except Exception:
        return None
    finally:
        try:
            dev.close()
        except Exception:
            pass


def ccid_reader(label):
    try:
        from smartcard.System import readers
    except Exception:
        return None
    yk = [r for r in readers() if "YubiKey" in str(r) or _is_rsk(str(r))]
    for r in yk:
        if _is_rsk(str(r)) == (label == "rsk"):
            return r
    return None


def ccid_session(reader, apdus):
    """Open ONE connection, run every APDU in order (so applet SELECT persists
    across the sequence — a fresh connect resets selection), return
    (list of (data, sw1, sw2), atr). Retries once after killing scdaemon on a
    PC/SC sharing violation (0x8010000B)."""
    for attempt in (0, 1):
        conn = reader.createConnection()
        try:
            conn.connect()
            atr = bytes(conn.getATR())
            out = []
            for apdu in apdus:
                data, sw1, sw2 = conn.transmit(list(apdu))
                out.append((bytes(data), sw1, sw2))
            return out, atr
        except Exception as e:
            if attempt == 0 and "8010000B" in str(e).upper().replace("0X", ""):
                _kill_scdaemon()
                continue
            raise
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass


def identity_guard(label, serial, aaguid):
    if aaguid:
        is_rsk = aaguid.lower().startswith(RSK_AAGUID_PREFIX)
        if label == "rsk" and not is_rsk:
            sys.exit(f"identity guard: --label rsk but AAGUID {aaguid} is not RS-Key's — wrong device?")
        if label == "real" and is_rsk:
            sys.exit(f"identity guard: --label real but AAGUID {aaguid} IS RS-Key's — captured the emulator")
    print(f"  identity guard ok: label={label} serial={serial} aaguid={aaguid or 'n/a'}")


# ── cells ────────────────────────────────────────────────────────────────────

def _jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v


def c_usb_descriptors(label):
    """USB descriptor fields straight from hidapi's enumeration of the matched FIDO
    interface — portable and reliable where macOS `system_profiler` lists nothing
    for a hub-attached key. `release_number` is the bcdDevice."""
    d = fido_dict(label)
    if not d:
        return cell(status="skip", transport="usb", detail="no matching FIDO HID device")
    parsed = {
        "usb.idVendor": f"0x{d.get('vendor_id', 0):04x}",
        "usb.idProduct": f"0x{d.get('product_id', 0):04x}",
        "usb.serialNumber": d.get("serial_number") or "",
        "usb.bcdDevice": f"0x{d.get('release_number', 0):04x}",
        "usb.manufacturer": d.get("manufacturer_string") or "",
        "usb.product": d.get("product_string") or "",
    }
    raw = json.dumps({k: v for k, v in d.items() if k != "path"}, default=str)
    return cell(parsed=parsed, raw=raw, transport="usb")


def c_fido_getinfo(label, info):
    if info is None:
        return cell(status="skip", transport="hid", detail="raw getInfo unavailable (hid? device?)")
    return cell(parsed=nz.fido_getinfo(info), transport="hid",
                raw=json.dumps({str(k): _jsonable(v) for k, v in info.items()}))


def c_fido_token_info(label):
    ft = _bin("fido2-token")
    if not ft:
        return cell(status="skip", transport="hid", detail="fido2-token not on PATH")
    rc, out = run([ft, "-L"])
    if rc != 0:
        return cell(status="error", transport="hid", raw=out[:300])
    # -L lines: `ioreg://<n>: vendor=0x1050, product=0x0407 (<product string>)`.
    # The path itself contains `://`, so split on the `: ` separator, not `:`.
    want_rsk = label == "rsk"
    line = next((ln for ln in out.splitlines() if _is_rsk(ln) == want_rsk and "0x1050" in ln), None)
    if not line:
        return cell(status="skip", transport="hid", detail="no matching fido2-token device line")
    path = line.split(": ", 1)[0].strip()
    rc, info = run([ft, "-I", path])
    if rc != 0:
        return cell(status="error", transport="hid", raw=info[:400])
    return cell(parsed=nz.kv_lines(info, "fido.token"), raw=info, transport="hid")


def c_ccid_atr(label):
    reader = ccid_reader(label)
    if reader is None:
        return cell(status="skip", transport="ccid", detail="no matching PC/SC reader")
    try:
        _, atr = ccid_session(reader, [])  # ATR is available on connect, no APDU needed
    except Exception as e:
        return cell(status="error", transport="ccid", detail=str(e)[:160])
    return cell(parsed={"ccid.reader": str(reader), "ccid.atr": atr.hex()},
                raw=f"reader={reader}\natr={atr.hex()}", transport="ccid")


def c_mgmt_tlv(label):
    reader = ccid_reader(label)
    if reader is None:
        return cell(status="skip", transport="ccid", detail="no matching PC/SC reader")
    select = [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID
    read = [0x00, 0x1D, 0x00, 0x00, 0x00]
    try:
        (sel, cfg), _ = ccid_session(reader, [select, read])  # one session — SELECT persists
    except Exception as e:
        return cell(status="error", transport="ccid", detail=str(e)[:160])
    if sel[1:] != (0x90, 0x00):
        return cell(status="error", transport="ccid", detail=f"SELECT mgmt SW {sel[1]:02x}{sel[2]:02x}")
    data, sw1, sw2 = cfg
    if (sw1, sw2) != (0x90, 0x00):
        return cell(status="error", transport="ccid", detail=f"READ CONFIG SW {sw1:02x}{sw2:02x}")
    return cell(parsed=nz.mgmt_deviceinfo(data), raw=data.hex(), transport="ccid")


def _ykman_cell(serial, args, ns):
    yk = _bin("ykman")
    if not yk:
        return cell(status="skip", transport="ccid", detail="ykman not on PATH")
    rc, out = run([yk, "--device", serial] + args, timeout=30)
    if rc != 0:
        return cell(status="error", transport="ccid", raw=out[:400],
                    detail=out.strip().splitlines()[-1][:160] if out.strip() else "rc!=0")
    return cell(parsed=nz.kv_lines(out, ns), raw=out, transport="ccid")


def c_ykman_oath_list(serial):
    yk = _bin("ykman")
    if not yk:
        return cell(status="skip", transport="ccid", detail="ykman not on PATH")
    rc, out = run([yk, "--device", serial, "oath", "accounts", "list"], timeout=30)
    if rc != 0:
        return cell(status="error", transport="ccid", raw=out[:400])
    names = sorted(ln.strip() for ln in out.splitlines() if ln.strip())
    return cell(parsed={"oath.count": len(names), "oath.names": names}, raw=out, transport="ccid")


def _openpgp_aid(gpg_card, serial):
    """The AID of the inserted card whose Yubico serial is `serial`, or None.

    `gpg --card-status` has no device selector and scdaemon serves exactly one card,
    so with both keys plugged it answers for whichever it picked — for both labels.
    `gpg-card list --cards` enumerates all of them, and the AID
    `D276000124010000 | manufacturer(4) | serial(8, BCD) | 0000` names the one we want."""
    rc, out = run([gpg_card, "--", "list", "--cards"], timeout=30)
    if rc != 0:
        return None
    want = f"{int(serial):08d}"
    for line in out.splitlines():
        parts = line.split()
        aid = parts[-1] if parts else ""
        if len(aid) == 32 and aid[20:28] == want:
            return aid
    return None


def c_gpg_card(serial):
    gpg_card = _bin("gpg-card")
    if not gpg_card:
        return cell(status="skip", transport="ccid", detail="gpg-card not on PATH")
    _kill_scdaemon()  # release the reader from any prior holder
    aid = _openpgp_aid(gpg_card, serial)
    if not aid:
        return cell(status="error", transport="ccid",
                    detail=f"`gpg-card list --cards` lists no card with serial {serial}")
    rc, out = run([gpg_card, "--", "list", aid], timeout=30)
    if rc != 0:
        return cell(status="error", transport="ccid", raw=out[:400])
    parsed = nz.kv_lines(out, "openpgp.gpg")
    got = parsed.get("openpgp.gpg.serial_number", "")
    if got != aid:
        return cell(status="error", transport="ccid", raw=out[:400],
                    detail=f"gpg-card answered for {got or '?'}, asked for {aid}")
    return cell(parsed=parsed, raw=out, transport="ccid")


def _opensc_slot_block(text, description):
    """Just the `Slot N (…): <description>` stanza of a `pkcs11-tool -L` dump.

    `-L` ignores `--slot-description` and lists every reader, and `kv_lines` is
    last-write-wins — so an unsliced dump hands the other key's token metadata to
    both labels. Only `-O` honours the pin, so the slot list is sliced by hand."""
    out, keep = [], False
    for line in text.splitlines():
        if line.startswith("Slot "):
            keep = line.split(":", 1)[-1].strip() == description
            # `Slot 1 (0x4)` slugs to a key naming the host's enumeration order, so
            # the two snapshots would compare fields that don't exist on each other.
            line = f"Slot description: {description}"
        if keep:
            out.append(line)
    return "\n".join(out)


def c_opensc(label):
    pk = _bin("pkcs11-tool")
    if not pk:
        return cell(status="skip", transport="ccid", detail="pkcs11-tool (OpenSC) not on PATH")
    mod = next((p for p in ("/opt/homebrew/lib/opensc-pkcs11.so",
                            "/Library/OpenSC/lib/opensc-pkcs11.so",
                            "/usr/local/lib/opensc-pkcs11.so",
                            "/usr/lib/opensc-pkcs11.so") if os.path.exists(p)), None)
    if not mod:
        return cell(status="skip", transport="ccid", detail="opensc-pkcs11.so not found")
    reader = ccid_reader(label)
    if reader is None:
        return cell(status="skip", transport="ccid", detail="no matching PC/SC reader")
    _kill_scdaemon()
    rc, slots = run([pk, "--module", mod, "-L"], timeout=30)
    if rc != 0:
        return cell(status="error", transport="ccid", raw=slots[:400], detail="pkcs11-tool -L rc!=0")
    block = _opensc_slot_block(slots, str(reader))
    if not block:
        return cell(status="error", transport="ccid", raw=slots[:400],
                    detail=f"no PKCS#11 slot for reader {reader}")
    rc, objs = run([pk, "--module", mod, "--slot-description", str(reader), "-O"], timeout=30)
    if rc != 0:
        return cell(status="error", transport="ccid", raw=objs[:400], detail="pkcs11-tool -O rc!=0")
    # The object dump gets its own namespace: it is whatever PIV certificates each
    # key happens to carry, not a property of the firmware under test.
    parsed = nz.kv_lines(block, "pkcs11")
    parsed.update(nz.kv_lines(objs, "pkcs11.obj"))
    return cell(parsed=parsed, raw=f"{block}\n{objs}", transport="ccid")


def _kill_scdaemon():
    """Release the PC/SC reader from any gpg-agent/scdaemon holder before a raw
    pyscard connect — otherwise the CCID cells get a 0x8010000B sharing violation."""
    gpgconf = _bin("gpgconf")
    if gpgconf:
        run([gpgconf, "--kill", "scdaemon"])


def capture(label, serial):
    info = raw_getinfo(label)
    aaguid = nz.uuid_str(info[0x03]) if info and 0x03 in info else None
    identity_guard(label, serial, aaguid)

    cells = {}
    # HID / USB — independent of the CCID reader lock.
    cells["usb_descriptors"] = c_usb_descriptors(label)
    cells["fido_getinfo"] = c_fido_getinfo(label, info)
    cells["fido_token_info"] = c_fido_token_info(label)
    # CCID phase: free the reader, run the raw pyscard cells first, then ykman
    # (transactional — releases per call), and gpg/OpenSC last since gpg leaves
    # scdaemon holding the reader.
    _kill_scdaemon()
    cells["ccid_atr"] = c_ccid_atr(label)
    cells["mgmt_tlv"] = c_mgmt_tlv(label)
    cells["ykman_info"] = _ykman_cell(serial, ["info"], "ykman.info")  # own ns; mgmt.* is the raw TLV
    cells["ykman_piv"] = _ykman_cell(serial, ["piv", "info"], "piv")
    cells["ykman_openpgp"] = _ykman_cell(serial, ["openpgp", "info"], "openpgp")
    cells["ykman_oath_info"] = _ykman_cell(serial, ["oath", "info"], "oath")
    cells["ykman_oath_list"] = c_ykman_oath_list(serial)
    cells["ykman_otp"] = _ykman_cell(serial, ["otp", "info"], "otp")
    cells["gpg_card"] = c_gpg_card(serial)
    cells["opensc"] = c_opensc(label)
    meta = {
        "label": label,
        "host_os": platform.system().lower(),
        "date": datetime.date.today().isoformat(),
        "ykman_serial": serial,
        "fido_aaguid": aaguid,
        "fw": _fw_from(cells),
        "bcdDevice": cells["usb_descriptors"]["parsed"].get("usb.bcdDevice"),
        "tool_versions": _tool_versions(),
    }
    return {"meta": meta, "cells": cells}


def _fw_from(cells):
    p = cells.get("ykman_info", {}).get("parsed", {})
    return p.get("mgmt.firmware_version") or cells.get("mgmt_tlv", {}).get("parsed", {}).get("mgmt.version")


def _tool_versions():
    out = {}
    for tool, args in (("ykman", ["--version"]), ("fido2-token", ["-V"]), ("gpg", ["--version"])):
        b = _bin(tool)
        if b:
            rc, o = run([b] + args, timeout=10)
            if rc == 0 and o.strip():
                out[tool] = o.strip().splitlines()[0][:80]
    return out


def main():
    ap = argparse.ArgumentParser(description="Capture one device snapshot for the RS-Key ↔ YubiKey diff")
    ap.add_argument("--label", required=True, choices=["real", "rsk"])
    ap.add_argument("--serial", help="ykman serial to target (auto if a single device is plugged)")
    ap.add_argument("--out", help="write snapshot JSON here (default: stdout)")
    args = ap.parse_args()

    serial = resolve_serial(args.serial)
    print(f"capturing {args.label} (serial {serial})…")
    snap = capture(args.label, serial)

    n = {s: sum(1 for c in snap["cells"].values() if c["status"] == s) for s in ("ok", "skip", "error")}
    print(f"  cells: {n['ok']} ok, {n['skip']} skip, {n['error']} error")
    for name, c in snap["cells"].items():
        if c["status"] != "ok":
            print(f"    {c['status']:5s} {name}: {c['detail']}")

    text = json.dumps(snap, indent=2, default=_jsonable)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"  wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
