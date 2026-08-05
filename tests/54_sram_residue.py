#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""SRAM residue after the presence-gated BOOTSEL drop — with a device-side control.

`worker::reboot` scrubs the live RAM key material before dropping to the
bootloader, on the premise that the RP2350 bootrom leaves main SRAM intact, so a
reflash could otherwise recover secrets from it. That premise has never been
measured in this repo: audit run-34 #3 found that the run-33 "HW-VERIFIED" result
rests on a 520 KiB dump of **nothing but zeros**, whose positive control spliced a
host-generated prime into a copy of that same zero buffer and never touched the
device. An all-zero dump is equally consistent with the scrub working, with the
bootrom clearing SRAM anyway, and with `picotool save` being unable to read SRAM
on a secure-boot board — so "0 factors found" established nothing.

This script therefore refuses to reach a verdict without proving, from the same
dump, that it can see device SRAM at all:

  1. generate an RSA-2048 key on-card (OpenPGP, PW3), keeping its **public**
     modulus — the number a residual prime must divide;
  2. request the presence-gated reboot to BOOTSEL (vendor INS 0x1F, P1=1) — touch
     when the device asks;
  3. `picotool save -r` main SRAM, then judge:

       dump has one distinct byte value      -> INCONCLUSIVE (nothing was read)
       modulus absent from the dump          -> INCONCLUSIVE (no control)
       modulus present, a factor of N found  -> RESIDUE PRESENT
       modulus present, no factor            -> RESIDUE ABSENT

The control is the modulus itself, and it has to be: it is the **non-secret half
of the very computation whose secret half this is hunting**, produced seconds
earlier, in the same memory, and the reboot scrub has no reason to touch it. A
marker sent in some spare APDU field would not do — `rsk_usb::ccid` zeroizes the
request and response buffers after every transfer, so its absence would prove
nothing. If N is not in the dump, either SRAM did not survive the drop or
`picotool` cannot read it here, and "no factors found" is not a result.

To settle a fix, run it twice — once on the build without the scrub (expect
`present`) and once on the build with it (expect `absent`). A single `absent` run
proves nothing on its own; that is the mistake this script exists to stop
repeating.

    nix develop -c python tests/54_sram_residue.py
    nix develop -c python tests/54_sram_residue.py --expect present

The board is left in BOOTSEL — reflash it afterwards. Needs a no-touch board or a
finger on the button, PW3 at its default, and picotool on PATH.
"""
import argparse
import os
import subprocess
import sys
import time

try:
    from smartcard.CardConnection import CardConnection
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]
PW3_DEFAULT = b"12345678"

INS_VERIFY, INS_PUT_DATA, INS_KEYPAIR_GEN, INS_REBOOT = 0x20, 0xDA, 0x47, 0x1F
MODE_PW3, CRT_SIG = 0x83, 0xB6
ATTR_RSA2K = bytes([0x01, 0x08, 0x00, 0x00, 0x20, 0x00])

#: RP2350 main SRAM (SRAM0..SRAM9 + the two striped banks) — 520 KiB.
SRAM_START, SRAM_END = 0x2000_0000, 0x2008_2000
#: RSA-2048 primes are 128 bytes; the bignum limbs are u32, so windows step by 4.
FACTOR_LEN, WINDOW_STEP = 128, 4
#: Below this, the dump is degenerate and says nothing either way.
MIN_DISTINCT_BYTES = 2


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def inconclusive(msg):
    """Not a pass and not a failure — the measurement did not happen."""
    print(f"\nINCONCLUSIVE: {msg}")
    print("The residue question is unanswered by this run. Do NOT record it as a")
    print("clean result (audit run-34 #3 is exactly that mistake).")
    sys.exit(2)


def apdu(ins, p1, p2, data=b"", le=None):
    a = [0x00, ins, p1, p2, len(data)] + list(data)
    if le is not None:
        a.append(le)
    return a


def gen_apdu(p1, crt):
    """GENERATE in an extended-length APDU (an RSA public key exceeds 256 bytes)."""
    data = bytes([crt, 0x00])
    return [0x00, INS_KEYPAIR_GEN, p1, 0x00, 0x00, 0x00, len(data)] + list(data) + [0x00, 0x00]


def parse_modulus(do):
    """The N of a `7F49 82 LL { 81 82 <N> · 82 <E> }` RSA public-key DO."""
    do = bytes(do)
    if do[:3] != b"\x7f\x49\x82":
        fail(f"not a 7F49 82 DO: {do[:5].hex()}")
    i = 5
    if do[i] != 0x81 or do[i + 1] != 0x82:
        fail("expected modulus tag 81 82")
    nlen = int.from_bytes(do[i + 2:i + 4], "big")
    return int.from_bytes(do[i + 4:i + 4 + nlen], "big")


def connect():
    r = find_reader(require_marker=True)
    if r is None:
        fail("no RS-Key PC/SC reader")
    conn = r.createConnection()
    try:
        conn.connect(CardConnection.T1_protocol)
    except Exception:
        conn.connect()
    return conn


def tx(conn, cmd, what, expect=(0x90, 0x00)):
    data, s1, s2 = conn.transmit(list(cmd))
    if expect is not None and (s1, s2) != expect:
        fail(f"{what}: SW {s1:02X}{s2:02X}")
    print(f"  {what}: {s1:02X}{s2:02X}")
    return bytes(data)


def select(conn, aid, what):
    return tx(conn, [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00], what)


def dump_sram(path):
    """`picotool save -r` main SRAM off the board now sitting in BOOTSEL."""
    for attempt in range(30):
        r = subprocess.run(
            ["picotool", "save", "-r", hex(SRAM_START), hex(SRAM_END), path, "-t", "bin"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return
        if attempt == 0:
            print("  waiting for the board in BOOTSEL…")
        time.sleep(1)
    fail(f"picotool save failed after 30s: {r.stdout}{r.stderr}")


def modulus_probes(n):
    """Byte runs of `n` a dump should contain if it holds device SRAM.

    Both byte orders, and the ends rather than the whole 256 bytes: the firmware
    stores bignums as u32 limbs, and a 32-byte run is already far past coincidence.
    """
    return [
        n.to_bytes(256, "big")[:32], n.to_bytes(256, "big")[-32:],
        n.to_bytes(256, "little")[:32], n.to_bytes(256, "little")[-32:],
    ]


def factors_of(blob, n):
    """Every window of `blob` that divides `n`, as (offset, endianness).

    A prime is odd, so a window whose least-significant byte is even cannot be
    one — that halves the work in each direction and costs one comparison.
    """
    hits = []
    for off in range(0, len(blob) - FACTOR_LEN + 1, WINDOW_STEP):
        w = blob[off:off + FACTOR_LEN]
        for order, lsb in (("big", w[-1]), ("little", w[0])):
            if not lsb & 1:
                continue
            cand = int.from_bytes(w, order)
            if 1 < cand < n and n % cand == 0:
                hits.append((off, order))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--expect", choices=["present", "absent"], default="absent",
                    help="what this build should show; the exit code follows it")
    ap.add_argument("--dump", default="sram.bin", help="where to write the SRAM image")
    args = ap.parse_args()

    conn = connect()

    print("Generating an RSA-2048 key on-card (this is slow — tens of seconds)…")
    select(conn, OPENPGP_AID, "SELECT OpenPGP")
    tx(conn, apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3")
    tx(conn, apdu(INS_PUT_DATA, 0x00, 0xC1, ATTR_RSA2K), "PUT SIG algo-attr (rsa2048)")
    t0 = time.time()
    n = parse_modulus(tx(conn, gen_apdu(0x80, CRT_SIG), "GENERATE RSA-2048 SIG"))
    print(f"  modulus {n.bit_length()} bits, {time.time() - t0:.1f}s")
    if n.bit_length() != 2048:
        fail(f"expected a 2048-bit modulus, got {n.bit_length()}")

    print("\nRequesting the presence-gated reboot to BOOTSEL — touch the device…")
    select(conn, VENDOR_AID, "SELECT vendor")
    try:
        conn.transmit([0x00, INS_REBOOT, 0x01, 0x00, 0x00])
    except Exception:
        pass  # the device drops off the bus mid-reply on a confirmed reboot
    time.sleep(2)

    dump_sram(args.dump)
    blob = open(args.dump, "rb").read()
    print(f"\nDumped {len(blob)} bytes of SRAM to {args.dump}")

    distinct = len(set(blob))
    nonzero = sum(1 for b in blob if b)
    print(f"  {distinct} distinct byte values, {nonzero} non-zero ({nonzero / len(blob):.1%})")
    if distinct < MIN_DISTINCT_BYTES:
        inconclusive("the dump holds a single byte value — nothing was read back. "
                     "Either the bootrom cleared SRAM, or picotool cannot read it "
                     "on this board (a secure-boot image reports `ARM Secure`).")

    seen = [p for p in modulus_probes(n) if p in blob]
    if not seen:
        inconclusive("the public modulus is not in the dump, so this dump does not "
                     "hold memory the device demonstrably used seconds ago. Either "
                     "SRAM did not survive the drop or picotool did not read it — "
                     "a 'no factors' result here would mean nothing.")
    print(f"  control: {len(seen)}/4 modulus probes present ✓")

    print("\nScanning for a factor of the modulus…")
    hits = factors_of(blob, n)
    for off, order in hits:
        print(f"  FACTOR at 0x{off:06x} ({order}-endian)")

    verdict = "present" if hits else "absent"
    print(f"\nRESIDUE {verdict.upper()} — {len(hits)} factor window(s), control OK")
    if verdict != args.expect:
        print(f"FAIL: expected residue {args.expect}")
        sys.exit(1)
    print("PASS")
    print("\nThe board is in BOOTSEL — reflash it before using it again.")


if __name__ == "__main__":
    main()
