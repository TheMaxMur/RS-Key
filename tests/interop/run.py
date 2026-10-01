#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Real-world interop sweep — drive the tools a user actually runs.

Unlike `tests/*.py` (which speak APDU/CBOR to the device directly) and the
`third_party/` suites (upstream protocol conformance), this runner shells out
to the *real* consumer software — libfido2, gpg, ykman, OpenSC — and records
whether the device works end-to-end with each. It is the executable half of
[docs/interop.md](../../docs/interop.md).

    nix develop -c python tests/interop/run.py            # read-only CLI cells
    nix develop -c python tests/interop/run.py --touch    # also touch cells
    nix develop -c python tests/interop/run.py --json     # machine-readable

Read-only by design: every default probe only *reads* device state. Touch
cells (`--touch`) need a finger on the BOOTSEL button and the touch firmware
build. Nothing here mutates keys unless you pass `--destructive` (no probe
uses it yet — it is reserved for future enrol/keygen cells).

Exit status is non-zero if any probe that actually ran (not skipped) FAILED.
A missing tool or an absent transport is a SKIP, not a failure.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

MARK = {PASS: "✅", FAIL: "❌", SKIP: "⏭️"}


def run(cmd, timeout=25, stdin=None):
    """Run a command, return (rc, combined_output). rc=-1 means could not spawn."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return -1, f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, f"timeout after {timeout}s (a touch cell with no press?)"


# ---------------------------------------------------------------- discovery

def discover():
    """Probe which transports the device exposes. Returns a dict."""
    env = {"hid": False, "ccid": False, "fido_dev": None, "ykman": None}

    if shutil.which("fido2-token"):
        rc, out = run(["fido2-token", "-L"])
        if rc == 0 and out.strip():
            # `<path>: vendor (0xXXXX) product (0xXXXX) ...` — the default build
            # reports the RS-Key id 0x1209:0xF1D2 (the opt-in Yubico flavor reports
            # 0x1050:0x0407). The path is the first whitespace-free token (macOS
            # `ioreg://…:`, Linux `/dev/hidraw0`); the `: ` separator leaves a
            # trailing colon. ykman discovery below only finds the Yubico flavor.
            first = out.strip().splitlines()[0]
            env["fido_dev"] = (first.split()[0].rstrip(":") or None) if first.split() else None
            env["hid"] = env["fido_dev"] is not None

    if shutil.which("ykman"):
        rc, out = run(["ykman", "info"])
        if rc == 0 and ("Device type" in out or "Serial" in out):
            env["ccid"] = True
            env["ykman"] = out
    return env


# ----------------------------------------------------------------- probes
# Each probe: (id, protocol, consumer, transport, needs_touch, fn) where fn
# takes the env dict and returns (status, detail). transport in
# {"hid","ccid","either"} gates on discovery.

def p_fido_list(env):
    rc, out = run(["fido2-token", "-L"])
    if rc != 0:
        return FAIL, out.strip()[:120]
    return PASS, env["fido_dev"] or out.strip().splitlines()[0][:80]


def p_fido_info(env):
    if not env["fido_dev"]:
        return SKIP, "no fido2 device path"
    rc, out = run(["fido2-token", "-I", env["fido_dev"]])
    if rc != 0:
        return FAIL, out.strip()[:160]
    ok = "versions:" in out or "FIDO_2" in out or "extensions:" in out
    ver = next((ln.strip() for ln in out.splitlines() if "version" in ln.lower()), "")
    return (PASS if ok else FAIL), ver[:100] or out.strip()[:100]


def p_gpg_card(env):
    if not shutil.which("gpg"):
        return SKIP, "gpg not installed"
    # gpg-agent/scdaemon talk PC/SC; close other readers first if this SKIPs.
    rc, out = run(["gpg", "--card-status"], timeout=30)
    if rc != 0:
        return FAIL, out.strip().splitlines()[-1][:160] if out.strip() else "rc!=0"
    ok = "OpenPGP" in out or "Application ID" in out or "Reader" in out
    return (PASS if ok else FAIL), "card-status read"


def p_ykman_openpgp(env):
    # The 0x0759 regression probe: yubikit Tlv.unpack(0x6E, …) must not raise.
    rc, out = run(["ykman", "openpgp", "info"])
    if rc != 0:
        tail = out.strip().splitlines()[-1] if out.strip() else "rc!=0"
        return FAIL, tail[:160]
    ok = "OpenPGP" in out or "version" in out.lower()
    return (PASS if ok else FAIL), out.strip().splitlines()[0][:100]


def p_ykman_piv(env):
    rc, out = run(["ykman", "piv", "info"])
    if rc != 0:
        return FAIL, (out.strip().splitlines()[-1] if out.strip() else "rc!=0")[:160]
    return (PASS if "PIV" in out or "version" in out.lower() else FAIL), "piv info"


def p_ykman_oath(env):
    rc, out = run(["ykman", "oath", "accounts", "list"])
    if rc != 0:
        return FAIL, (out.strip().splitlines()[-1] if out.strip() else "rc!=0")[:160]
    return PASS, "oath list ok (may be empty)"


def p_ykman_otp(env):
    rc, out = run(["ykman", "otp", "info"])
    if rc != 0:
        return FAIL, (out.strip().splitlines()[-1] if out.strip() else "rc!=0")[:160]
    return (PASS if "Slot" in out else FAIL), "otp info"


def p_ssh_sk(env):
    # Touch cell: enrol an ed25519-sk key. Writes only to /tmp; needs a press
    # (and possibly the FIDO PIN). We do not delete the resident handle — this
    # creates a NON-resident key, so nothing persists on the device.
    if not shutil.which("ssh-keygen"):
        return SKIP, "ssh-keygen not installed"
    import os
    import tempfile

    d = tempfile.mkdtemp(prefix="rsk-sk-")
    key = os.path.join(d, "id_ed25519_sk")
    rc, out = run(
        ["ssh-keygen", "-t", "ed25519-sk", "-f", key, "-N", "", "-C", "rsk-interop"],
        timeout=40,
    )
    ok = rc == 0 and os.path.exists(key + ".pub")
    detail = "enrolled ed25519-sk" if ok else (out.strip().splitlines()[-1] if out.strip() else "rc!=0")
    return (PASS if ok else FAIL), detail[:160]


PROBES = [
    # id,                  protocol,  consumer,                transport, touch, fn
    ("fido2-token -L",     "FIDO2",   "libfido2",              "hid",   False, p_fido_list),
    ("fido2-token -I",     "FIDO2",   "libfido2",              "hid",   False, p_fido_info),
    ("gpg --card-status",  "OpenPGP", "gpg",                   "ccid",  False, p_gpg_card),
    ("ykman openpgp info", "OpenPGP", "ykman",                 "ccid",  False, p_ykman_openpgp),
    ("ykman piv info",     "PIV",     "ykman",                 "ccid",  False, p_ykman_piv),
    ("ykman oath list",    "OATH",    "ykman",                 "ccid",  False, p_ykman_oath),
    ("ykman otp info",     "OTP",     "ykman",                 "ccid",  False, p_ykman_otp),
    ("ssh-keygen -sk",     "FIDO2",   "openssh",               "hid",   True,  p_ssh_sk),
]


def have_transport(env, transport):
    if transport == "either":
        return env["hid"] or env["ccid"]
    return env[transport]


def main():
    ap = argparse.ArgumentParser(description="RS-Key real-world interop sweep")
    ap.add_argument("--touch", action="store_true", help="also run touch cells (need a button press)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--destructive", action="store_true", help="allow state-mutating cells (none yet)")
    args = ap.parse_args()

    env = discover()
    results = []
    for pid, proto, consumer, transport, touch, fn in PROBES:
        if touch and not args.touch:
            status, detail = SKIP, "touch cell (pass --touch)"
        elif not have_transport(env, transport):
            status, detail = SKIP, f"no {transport} transport (device flashed + plugged?)"
        else:
            status, detail = fn(env)
        results.append(
            {"id": pid, "protocol": proto, "consumer": consumer, "status": status, "detail": detail}
        )

    if args.json:
        print(json.dumps({"env": {k: env[k] for k in ("hid", "ccid")}, "results": results}, indent=2))
    else:
        print("RS-Key interop sweep  (HID=%s  CCID=%s)\n" % (env["hid"], env["ccid"]))
        print("  %-20s %-9s %-9s %s" % ("probe", "protocol", "consumer", "result"))
        print("  " + "-" * 74)
        for r in results:
            print(
                "  %-20s %-9s %-9s %s %-5s %s"
                % (r["id"], r["protocol"], r["consumer"], MARK[r["status"]], r["status"], r["detail"])
            )
        npass = sum(1 for r in results if r["status"] == PASS)
        nfail = sum(1 for r in results if r["status"] == FAIL)
        nskip = sum(1 for r in results if r["status"] == SKIP)
        print("\n  %d passed, %d failed, %d skipped" % (npass, nfail, nskip))
        if not env["hid"] and not env["ccid"]:
            print("  (no device found — flash the no-touch build and plug it in)")

    return 1 if any(r["status"] == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
