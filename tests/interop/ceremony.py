#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Stage-2 scriptable ceremonies + the manual checklist.

Stage 1 (`capture.py`/`diff.py`) diffs the wire surface. Stage 2 proves the key
works end-to-end with the software a user runs. Most of those ceremonies are
interactive (a PIN prompt, a browser, a touch) and are driven by hand — see the
checklist `--list` prints. This script covers the cells that ARE scriptable:

  * piv-sign   — `yubico-piv-tool test-signature`: signs test data with a PIV
                 slot and verifies it against that slot's own certificate.
  * opensc     — what OpenSC's PKCS#11 module binds (it emulates PKCS#15 and, on
                 a YubiKey, latches onto the OpenPGP app — a useful data point).

Run against ONE plugged key at a time (leave a single key in — libfido2 / PC-SC
cannot disambiguate two "Yubico YubiKey" tokens), once per key, then compare.

    python tests/interop/ceremony.py --piv-pin 123456          # PIV sign+verify (+ opensc)
    python tests/interop/ceremony.py --list                    # manual checklist

NOTE the PIV PIN is NOT the FIDO PIN. PIV defaults to 123456; 12345678 is the
FIDO PIN / the PIV PUK. A wrong PIV PIN burns a retry (3 total) — pass the right
one. A correct verify resets the counter.
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from capture import _bin, run  # scrubbed-env runner + Homebrew-aware tool resolver

OPENSC_MODULES = (
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/Library/OpenSC/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
)


def piv_sign(pin, slot):
    """`yubico-piv-tool test-signature`: sign + verify against the slot cert."""
    yp = _bin("yubico-piv-tool")
    if not yp:
        return False, "yubico-piv-tool not installed (brew install yubico-piv-tool)"
    rc, out = run([yp, "-a", "verify-pin", "-P", pin, "-a", "test-signature", "-s", slot], timeout=40)
    low = out.lower()
    if "pin verification failed" in low or "blocked" in low:
        # Surface the retry count and DO NOT retry with another guess.
        return False, next((ln.strip() for ln in out.splitlines() if "pin" in ln.lower()), "PIN failed")
    if "successfully verified" in low or "signature is valid" in low:
        return True, f"slot {slot}: signed + verified against the slot cert"
    # test-signature prompts for the hash on some builds; treat a clean rc with a
    # signature as success, else report the tail for triage.
    if rc == 0 and ("signature" in low or "verif" in low):
        return True, f"slot {slot}: {out.strip().splitlines()[-1][:100]}"
    return False, out.strip().splitlines()[-1][:140] if out.strip() else "rc!=0"


def opensc_bind():
    """Report which app OpenSC's PKCS#11 module latches onto, and its objects."""
    pk = _bin("pkcs11-tool")
    mod = next((m for m in OPENSC_MODULES if os.path.exists(m)), None)
    if not pk or not mod:
        return None, "pkcs11-tool / opensc-pkcs11.so not found"
    rc, out = run([pk, "--module", mod, "-L"])
    if rc != 0:
        return None, "pkcs11-tool -L failed"
    labels = [ln.split(":", 1)[1].strip() for ln in out.splitlines() if "token label" in ln.lower()]
    rc, objs = run([pk, "--module", mod, "-O"])
    nobj = sum(1 for ln in objs.splitlines() if "Object" in ln)
    return True, f"binds {labels or '?'}; {nobj} object(s) visible"


CHECKLIST = """Stage-2 differential checklist — run ONCE PER KEY (leave one plugged), then compare.

  SCRIPTABLE (this script runs them):
    [piv-sign]   yubico-piv-tool test-signature on a PIV slot (PIN 123456 by default).
    [opensc]     what OpenSC's PKCS#11 module binds + object count.

  INTERACTIVE — you run these (PIN + a touch when the LED blinks):
    [ssh-sk]     ssh-keygen -t ed25519-sk -f /tmp/rsk_sk -N "" -C rsk-ceremony
                 → enrols a FIDO2 sk-key; type the FIDO PIN (12345678) + touch.
                   Both keys must write /tmp/rsk_sk.pub. (ecdsa-sk if ed25519-sk is refused.)
    [age]        age-plugin-yubikey --identity   (lists PIV-backed age identities; -g to generate)

  GUI / manual — do on each key, note pass/fail:
    [webauthn]   https://webauthn.io — register + authenticate a passkey, in Chrome / Firefox / Safari.
    [yubico-auth] Yubico Authenticator app — detects the key + 6 apps, lists OATH, shows a live TOTP?
    [otp-type]   Focus a text field, short-tap the key — does it type a Yubico-OTP / static string?
    [macos-ctk]  sc_auth identities ; system_profiler SPSmartCardsDataType — CTK sees reader + ATR.

  Record each cell's real-vs-rsk result in assurance/reports/interop.md (the Stage-2 matrix rows).
"""


def main():
    ap = argparse.ArgumentParser(description="RS-Key Stage-2 ceremonies (PIV sign, OpenSC) + checklist")
    ap.add_argument("--piv-pin", default="123456", help="PIV PIN (NOT the FIDO PIN; default 123456)")
    ap.add_argument("--slot", default="9a", help="PIV slot to sign with (default 9a)")
    ap.add_argument("--list", action="store_true", help="print the manual ceremony checklist")
    args = ap.parse_args()
    if args.list:
        print(CHECKLIST)
        return 0

    ok, detail = piv_sign(args.piv_pin, args.slot)
    print(f"[piv-sign] {'PASS' if ok else 'FAIL'} — {detail}")
    bok, bdetail = opensc_bind()
    mark = "PASS" if bok else "SKIP"
    print(f"[opensc]   {mark} — {bdetail}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
