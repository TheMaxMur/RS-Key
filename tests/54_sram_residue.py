#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Does SRAM survive the presence-gated BOOTSEL drop, and does it hold secrets?

Two questions, two subcommands, and the first gates the second:

    nix develop -c python tests/54_sram_residue.py control
    nix develop -c python tests/54_sram_residue.py residue --expect present

`worker::reboot` scrubs the live RAM key material before dropping to the
bootloader, on the premise that the RP2350 bootrom leaves main SRAM intact — so a
reflash could otherwise recover secrets from it. Audit run-34 #3 found that
premise has never been measured: run-33's "HW-VERIFIED" result rests on a 520 KiB
dump of nothing but zeros, whose positive control spliced a host-generated prime
into a copy of that same zero buffer and never touched the device.

An all-zero dump has three explanations, and two of them close the finding class
outright rather than confirming the scrub:

    the bootrom cleared SRAM entering the bootloader  -> there is nothing to leak
    picoboot refuses to serve SRAM on this board      -> there is nothing to read
    the scrub worked                                  -> the fix holds

`control` separates them from the flashed ELF alone, with no key generated. It
reads a window of `.text` first, which both proves picoboot reads work at all and
authenticates the ELF against the image actually running. Then it reads `.data` —
RAM-resident asm (`bignum_*`, `IncrementalSieve::step`) plus the `SMALL_PRIMES`
table, moved to RAM by c9a74ef, immutable after boot and known byte-for-byte from
the file. If those come back, the dump is device SRAM, proven a priori and by the
same mechanism (a known byte string at a known address) the residue hunt uses. If
they come back zero, one probe still separates the last two explanations: write a
pattern through picoboot and read it back. It returns → picoboot serves SRAM, so
the zeros were the memory.

Exit codes: 0 as expected · 1 expectation or setup failed · 2 INCONCLUSIVE, the
measurement did not happen · 3 SETTLED without the scan, so `--expect` cannot apply.

`residue` then makes the measurement `control` licensed: generate an RSA-2048 key
on-card, drop to BOOTSEL, and hunt a factor of its public modulus — reported per
region, so a hit names what has to be fixed. The regions come from the ELF: the
main stack (`_stack_end`..`_stack_start`, whose frames audit run-34 #2 measured at
~20 KiB for signing against ~4.5 KiB for the reboot path), core1's stack, `.bss`,
`.data`. Each static `worker::reboot` claims to scrub is asserted zero by symbol,
which is a sharper question than "did the scan find anything".

Run on 2026-08-05, Waveshare RP2350 Zero (silicon A4, secure boot off, picotool
2.2.0-a4): 4 KiB of `.text` byte-exact, all 520 KiB of SRAM zero, and the written
pattern read straight back — the platform clears main SRAM on the drop, so there
is nothing left in it to recover. That is a property of this silicon and boot
configuration, not of the firmware; re-run it when either changes.

Should a configuration ever keep SRAM, `residue` is what measures the scrub, and
it takes two runs. No scrub reaches the stack today, so the shipping build is
already the "before": it must show `present` first, and only that licenses reading
a later `absent` as the fix working rather than as a dump that read nothing. A
single `absent` run proves nothing; that is the mistake this file exists to stop
repeating.

Both subcommands leave the board in BOOTSEL — reflash it afterwards. They need a
finger on the button (or a no-touch board) and picotool on PATH. `residue` also
needs PW3 at its default and is **destructive**: GENERATE replaces whatever key
the OpenPGP signature slot holds. The ELF must be the flashed one — `check.sh`
leaves its own no-touch image at the default path, and the `.text` check exists
to catch exactly that mix-up.
"""
import argparse
import os
import struct
import subprocess
import sys
import time
from collections import namedtuple

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
DEFAULT_ELF = "target/thumbv8m.main-none-eabihf/release/firmware"
#: How much `.text` to read back. Enough that a match cannot be coincidence,
#: small enough that the read is instant.
TEXT_PROBE = 4096
#: RSA-2048 primes are 128 bytes; the bignum limbs are u32, so windows step by 4.
FACTOR_LEN, WINDOW_STEP = 128, 4
#: Where the read-back probe writes: mid-SRAM, clear of the bootrom's own
#: workspace, and only ever after the dump has been taken.
WRITEBACK_ADDR, WRITEBACK_LEN = 0x2001_0000, 256

SHT_SYMTAB, SHT_NOBITS, STT_FUNC = 2, 8, 2

Sym = namedtuple("Sym", "name addr size kind")
Sec = namedtuple("Sec", "name addr size data")

#: Statics `worker::reboot` claims to leave zero, by symbol substring.
SCRUBBED = [
    ("core1", "MAILBOX", "core1's prime in transit and the keygen DRBG seed"),
    ("otp_kbd", "OTP_HID", "the keyboard transport's frame and ticket buffers"),
]
#: Statics it deliberately does not reach — reported, not asserted.
UNSCRUBBED = [
    ("core1", "CORE1_SIEVE", "core1 scrubs this on its own STOP edge; a faulted core1 does not"),
    ("core1", "CORE1_STACK", "core1's frames — no scrub reaches these (audit run-34 #2)"),
]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def inconclusive(msg):
    """Not a pass and not a failure — the measurement did not happen."""
    print(f"\nINCONCLUSIVE: {msg}")
    print("The residue question is unanswered by this run. Do NOT record it as a")
    print("clean result (audit run-34 #3 is exactly that mistake).")
    sys.exit(2)


def settled(msg):
    """A real answer the scan was not needed for, so `--expect` cannot apply."""
    print(f"\nSETTLED: {msg}")
    sys.exit(3)


# --- the flashed image, as the ELF describes it -------------------------------

def read_elf(path):
    """Allocated sections (with their file bytes) and symbols of a 32-bit LE ELF."""
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        fail(f"cannot read {path}: {e}")
    if raw[:4] != b"\x7fELF" or raw[4:6] != b"\x01\x01":
        fail(f"{path}: not a 32-bit little-endian ELF")
    (shoff,) = struct.unpack_from("<I", raw, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", raw, 0x2E)
    hdrs = [struct.unpack_from("<10I", raw, shoff + i * shentsize) for i in range(shnum)]

    def cstr(tab, idx):
        return raw[tab + idx:raw.index(b"\0", tab + idx)].decode()

    shstr = hdrs[shstrndx][4]
    secs, syms = {}, {}
    for h in hdrs:
        name, typ, addr, off, size = cstr(shstr, h[0]), h[1], h[3], h[4], h[5]
        # NOBITS (.bss) has no file image; keep its bounds, drop the bytes.
        secs[name] = Sec(name, addr, size, None if typ == SHT_NOBITS else raw[off:off + size])
        if typ != SHT_SYMTAB:
            continue
        stroff = hdrs[h[6]][4]
        for o in range(off, off + size, 16):
            n, val, sz, info = struct.unpack_from("<IIIB", raw, o)
            kind = info & 0xF
            # An ARM function symbol carries the Thumb bit in bit 0; left in, every
            # slice taken from one is a byte past where the code actually starts.
            addr = val & ~1 if kind == STT_FUNC else val
            syms[cstr(stroff, n)] = Sym(cstr(stroff, n), addr, sz, kind)
    return secs, syms


def expected(secs, addr, size):
    """What the ELF says lives at `addr`, or None if no loaded section covers it."""
    for s in secs.values():
        if s.data is not None and s.addr and s.addr <= addr and addr + size <= s.addr + s.size:
            return s.data[addr - s.addr:addr - s.addr + size]
    return None


def one_sym(syms, module, name):
    """The static `module::name`, matched on its length-prefixed mangled segments.

    Rust appends a hash, so the exact symbol name is not knowable here, and a bare
    substring is not unique: `OTP_HID` also matches `OTP_HID_HANDLER_KBD`. A miss
    (or a mangling scheme this does not know) skips the assertion out loud rather
    than measuring the wrong bytes.
    """
    seg = (f"{len(module)}{module}", f"{len(name)}{name}")
    hits = [s for n, s in syms.items() if all(x in n for x in seg) and s.size]
    return hits[0] if len(hits) == 1 else None


# --- the device ---------------------------------------------------------------

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


def drop_to_bootsel(conn):
    """Vendor INS 0x1F P1=1 — the warm drop whose residue is the subject.

    It has to be this path: holding the button through a replug is a power-on
    reset, which loses SRAM for reasons that have nothing to do with the scrub.
    """
    print("\nRequesting the presence-gated reboot to BOOTSEL — touch the device…")
    select(conn, VENDOR_AID, "SELECT vendor")
    try:
        conn.transmit([0x00, INS_REBOOT, 0x01, 0x00, 0x00])
    except Exception:
        pass  # the device drops off the bus mid-reply on a confirmed reboot
    time.sleep(2)


def writeback_reads_back(args):
    """Does picoboot serve SRAM contents, or does it only answer zeros?

    An all-zero read has two causes that look identical, and this separates them:
    write a pattern through picoboot and read it straight back. It comes back →
    reads work, so the zeros were the memory. Only ever called once the dump is
    taken and the board is on its way to a reflash regardless.
    """
    src = args.dump + ".pattern"
    pat = bytes((i * 7 + 0x5A) & 0xFF for i in range(WRITEBACK_LEN))
    open(src, "wb").write(pat)
    wrote = subprocess.run(["picotool", "load", src, "-t", "bin", "-o", hex(WRITEBACK_ADDR)],
                           capture_output=True, text=True)
    if wrote.returncode:
        print("  read-back probe: picoboot refused the write too")
        return False
    ok = save(WRITEBACK_ADDR, WRITEBACK_LEN, args.dump + ".back") == pat
    print(f"  read-back probe: a pattern written to {WRITEBACK_ADDR:#x} "
          f"{'reads straight back ✓' if ok else 'does NOT read back ✗'}")
    return ok


def save(start, size, path, wait=False):
    """`picotool save -r` a range off the board now sitting in BOOTSEL."""
    cmd = ["picotool", "save", "-r", hex(start), hex(start + size), path, "-t", "bin"]
    for attempt in range(30 if wait else 1):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            return open(path, "rb").read()
        if wait and attempt == 0:
            print("  waiting for the board in BOOTSEL…")
        if wait:
            time.sleep(1)
    return None


# --- judging ------------------------------------------------------------------

def describe(label, blob, note=""):
    print(f"  {label:<34} {len(blob):>7} B  {sum(1 for b in blob if b):>7} non-zero  "
          f"{len(set(blob)):>3} distinct  {note}")


def check_readable(secs, syms, args):
    """The `control` question, as a decision table. Returns the SRAM dump."""
    text = secs.get(".text")
    if text is None or text.data is None:
        fail(f"{args.elf}: no loaded .text")
    n = min(TEXT_PROBE, text.size)

    sram = save(SRAM_START, SRAM_END - SRAM_START, args.dump, wait=True)
    if sram is None:
        inconclusive("picotool could not read SRAM at all — the board never reached "
                     "BOOTSEL, or picoboot refused the read.")
    flash = save(text.addr, n, args.dump + ".text", wait=False)

    print(f"\nDumped {len(sram)} bytes of SRAM to {args.dump}")
    if flash is None or not any(flash):
        print("\nRESULT: picoboot returns nothing for flash either.")
        inconclusive("memory reads are refused on this board, so no dump taken here "
                     "can say anything about SRAM. On a secure-boot board that "
                     "refusal is itself the mitigation — an attacker with BOOTSEL "
                     "has no other interface — but say that, do not call it a scrub.")
    if flash != text.data[:n]:
        fail(f"the first {n} bytes of .text read back differently from {args.elf} — "
             "this ELF is not the image on the board (check.sh leaves its own "
             "no-touch build at the default path). Re-point --elf and re-run.")
    print(f"  control: {n} B of .text matches the ELF ✓ (picoboot reads work, "
          "and this ELF is the flashed image)")

    data = secs[".data"]
    got = sram[data.addr - SRAM_START:data.addr - SRAM_START + data.size]
    ro = [s for s in syms.values()
          if data.addr <= s.addr < data.addr + data.size
          and (s.kind == STT_FUNC or "SMALL_PRIMES" in s.name) and s.size]
    intact = [s for s in ro
              if got[s.addr - data.addr:s.addr - data.addr + s.size]
              == expected(secs, s.addr, s.size)]
    same = sum(1 for a, b in zip(got, data.data) if a == b)
    print(f"  control: {len(intact)}/{len(ro)} immutable .data symbols byte-exact, "
          f"{same}/{data.size} .data bytes match the ELF")

    if not any(got):
        print("\nRESULT: flash reads back, SRAM does not.")
        # Decide on the WHOLE dump, not on this window. `.data` sits at the RAM
        # origin, so any mechanism that clears only the low kilobytes — a loader
        # workspace, a staging buffer, a partial scrub — zeroes exactly what the
        # verdict is read from while leaving the stack and the 128 KiB keygen heap
        # untouched, which is where the secrets in question actually live. Those
        # regions are the whole point (audit run-35).
        nz = sum(1 for b in sram if b)
        print(f"  whole dump: {len(sram)} B, {nz} non-zero, {len(set(sram))} distinct")
        if len(sram) != SRAM_END - SRAM_START:
            inconclusive(f"short dump: {len(sram)} of {SRAM_END - SRAM_START} bytes, "
                         "so regions the verdict covers were never read.")
        if nz:
            inconclusive("the .data window is zero but the dump is not — a partial "
                         "clear cannot license a verdict about the stack or the heap. "
                         "Scan the live regions before concluding anything.")
        if writeback_reads_back(args):
            settled("main SRAM does not survive the drop to BOOTSEL — every byte of "
                    "the dump is zero, not just the control window. picoboot serves "
                    "SRAM faithfully, so those zeros are the memory itself and nothing "
                    "is recoverable from RAM this way. Note what it is NOT evidence "
                    "of: the platform cleared it, not worker::reboot's scrub, and the "
                    "result belongs to this silicon revision and boot configuration.")
        inconclusive("SRAM reads as zeros and a pattern written into it does not read "
                     "back either, so picoboot is not serving SRAM here. Nothing found "
                     "or not found in such a dump would mean anything.")
    if not intact:
        inconclusive("SRAM is non-zero but no RAM-resident code or table came back "
                     "intact, so the dump is not this firmware's memory. Nothing "
                     "found or not found in it would mean anything.")
    print("\nSRAM READABLE — the dump is device memory, so a residue result from it "
          "is worth having.")
    return sram


def scan_regions(secs, syms, sram, n):
    """Factor windows of `n`, per named region. Returns their distinct addresses.

    The regions nest — `CORE1_STACK` is inside `.bss` — so a hit is counted by
    address, not once per window it shows up in.
    """
    stack_end, stack_start = syms.get("_stack_end"), syms.get("_stack_start")
    windows = [(".data", secs[".data"].addr, secs[".data"].size, ""),
               (".bss (all statics)", secs[".bss"].addr, secs[".bss"].size, "")]
    for mod, name, why in UNSCRUBBED:
        if s := one_sym(syms, mod, name):
            windows.append((name, s.addr, s.size, why))
    if stack_end and stack_start:
        windows.append(("main stack", stack_end.addr, stack_start.addr - stack_end.addr,
                        "the frames audit run-34 #2 measured"))

    found = set()
    for label, addr, size, why in windows:
        blob = sram[addr - SRAM_START:addr - SRAM_START + size]
        describe(label, blob, why)
        for off, order in factors_of(blob, n):
            print(f"    !! FACTOR at 0x{addr + off:08x} ({order}-endian)")
            found.add(addr + off)
    return found


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


def modulus_probes(n):
    """Byte runs of `n` a dump holding the keygen's memory should contain.

    Both byte orders, and the ends rather than all 256 bytes: the firmware stores
    bignums as u32 limbs, and a 32-byte run is already far past coincidence. This
    is a secondary control — it says a bignum-shaped value is findable the way the
    factor scan assumes, which `.data` alone does not establish.
    """
    return [n.to_bytes(256, "big")[:32], n.to_bytes(256, "big")[-32:],
            n.to_bytes(256, "little")[:32], n.to_bytes(256, "little")[-32:]]


# --- subcommands --------------------------------------------------------------

def cmd_control(args):
    secs, syms = read_elf(args.elf)
    conn = connect()
    drop_to_bootsel(conn)
    sram = check_readable(secs, syms, args)
    print("\nRegions, as the ELF lays them out:")
    d = secs[".data"]
    describe(".data", sram[d.addr - SRAM_START:d.addr - SRAM_START + d.size])
    for mod, name, why in SCRUBBED + UNSCRUBBED:
        if s := one_sym(syms, mod, name):
            describe(name, sram[s.addr - SRAM_START:s.addr - SRAM_START + s.size], why)
    if (e := syms.get("_stack_end")) and (t := syms.get("_stack_start")):
        describe("main stack", sram[e.addr - SRAM_START:t.addr - SRAM_START],
                 "audit run-34 #2's window")
    print("\nPASS — run `residue --expect present` next, on a build without the scrub.")
    print("The board is in BOOTSEL — reflash it before using it again.")


def cmd_residue(args):
    secs, syms = read_elf(args.elf)
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

    drop_to_bootsel(conn)
    sram = check_readable(secs, syms, args)
    print(f"  modulus (keep this to re-judge the dump): {n:x}")

    seen = sum(1 for p in modulus_probes(n) if p in sram)
    print(f"  secondary control: {seen}/4 modulus probes present"
          f"{'' if seen else ' — the public half of the very computation is absent'}")

    print("\nScanning each region for a factor of the modulus…")
    hits = scan_regions(secs, syms, sram, n)
    print("\nStatics worker::reboot claims to leave zero:")
    for mod, name, why in SCRUBBED:
        s = one_sym(syms, mod, name)
        if s is None:
            print(f"  {name}: no unique sized symbol — ASSERTION SKIPPED, not passed")
            continue
        blob = sram[s.addr - SRAM_START:s.addr - SRAM_START + s.size]
        print(f"  {name} ({why}): {'ZERO ✓' if not any(blob) else 'NON-ZERO ✗'}")

    verdict = "present" if hits else "absent"
    print(f"\nRESIDUE {verdict.upper()} — {len(hits)} factor window(s), control OK")
    if verdict != args.expect:
        print(f"FAIL: expected residue {args.expect}")
        sys.exit(1)
    print("PASS")
    print("\nThe board is in BOOTSEL — reflash it before using it again.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # On a shared parent these would have to precede the subcommand, which reads
    # backwards for a one-shot test script; give both subparsers their own.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--elf", default=DEFAULT_ELF, help="the FLASHED firmware ELF")
    common.add_argument("--dump", default="sram.bin", help="where to write the SRAM image")
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("control", parents=[common],
                   help="can this board's SRAM be read back at all?")
    res = sub.add_parser("residue", parents=[common],
                         help="is a private factor left in it?")
    res.add_argument("--expect", choices=["present", "absent"], default="absent",
                     help="what this build should show; the exit code follows it")
    args = ap.parse_args()
    (cmd_control if args.mode == "control" else cmd_residue)(args)


if __name__ == "__main__":
    main()
