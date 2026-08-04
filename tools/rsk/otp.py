# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk otp — OTP-MKEK provisioning. IRREVERSIBLE; explicit go required.

burn:        write DEVK@0xE80 + MKEK@0xE90 + chaff into OTP page 58 from BOOTSEL
             (picotool ritual). The host generates, verifies, and forgets the keys.
lock-page58: apply the permanent BL/NS access lock from secure firmware (rescue
             INS 0x1B) — the half picotool cannot do (the lock row lives in OTP
             page 63, bootloader-read-only). After it lands, `picotool otp get`
             can no longer read the page-58 keys; the firmware still can.
rollback-require: fuse BOOT_FLAGS0.ROLLBACK_REQUIRED from secure firmware
             (rescue INS 0x1B, P1=0x48) — after `rsk secure-boot lock` the flag
             row is bootloader-read-only, so only the firmware can. From then
             on the bootrom refuses any image without a rollback version, which
             is what makes `picotool seal --rollback` actually enforce
             (docs/production.md, "Anti-rollback"). The firmware refuses unless
             secure boot is enabled — so by construction the image you run it
             from already carries a version and stays bootable.
"""
import os
import re
import secrets
import tempfile

from . import ccid
from .common import confirm, die, picotool
from .status import RESCUE_AID, rescue_read, rescue_serial

DEVK_ROW, MKEK_ROW, KEY_ROWS, CHAFF_OFFSET = 0xE80, 0xE90, 16, 0x20
LOCK1_ROW, LOCK_VALUE = 0xFF5, 0x3C3C3C
K256_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

LOCK_APDU = [0x80, 0x1B, 0x58, 0x00, 0x06] + list(b"LOCK58") + [0x00]
LOCK_SW = {
    ccid.SW_OK: "OK — page 58 is now locked (or was already)",
    ccid.SW_COND_NOT_SATISFIED: "CONDITIONS_NOT_SATISFIED — keys not provisioned, or the lock row "
                                "already holds a foreign value (firmware refused)",
    (0x69, 0x84): "DATA_INVALID — wrong magic payload",
    (0x6A, 0x86): "INCORRECT_P1P2",
    (0x64, 0x00): "EXEC_ERROR — OTP read/write failed or did not verify",
}
ROLLBACK_APDU = [0x80, 0x1B, 0x48, 0x00, 0x06] + list(b"ROLLBK") + [0x00]
ROLLBACK_SW = {
    ccid.SW_OK: "OK — ROLLBACK_REQUIRED is now fused (or was already)",
    ccid.SW_COND_NOT_SATISFIED: "CONDITIONS_NOT_SATISFIED — secure boot is not enabled; the flag "
                                "does nothing without enforcement, so the firmware refused",
    (0x69, 0x84): "DATA_INVALID — wrong magic payload",
    (0x6A, 0x86): "INCORRECT_P1P2 — firmware too old (no anti-rollback support)?",
    (0x64, 0x00): "EXEC_ERROR — OTP read/write failed or did not verify",
}


def register(sub):
    p = sub.add_parser("otp", help="OTP-MKEK provisioning (IRREVERSIBLE)")
    g = p.add_subparsers(dest="cmd", required=True)
    b = g.add_parser("burn", help="burn DEVK+MKEK+chaff into OTP page 58 (BOOTSEL)")
    b.add_argument("--dry-run", action="store_true", help="preflight only, no writes")
    b.set_defaults(func=burn)
    lk = g.add_parser("lock-page58", help="apply the page-58 hard-lock from firmware (CCID)")
    lk.add_argument("--dry-run", action="store_true", help="connect + SELECT only")
    lk.set_defaults(func=lock_page58)
    rb = g.add_parser("rollback-require",
                      help="fuse ROLLBACK_REQUIRED from firmware (CCID; anti-rollback)")
    rb.add_argument("--dry-run", action="store_true", help="connect + report state only")
    rb.set_defaults(func=rollback_require)


def _read_raw_row(row):
    r = picotool("otp", "get", "-r", "-n", f"{row:#x}", check=False)
    if r.returncode != 0:
        return None
    m = re.search(r"VALUE\s+(0x[0-9a-fA-F]+)", r.stdout)
    if not m:
        die(f"unparseable otp get output for row {row:#x}: {r.stdout!r}")
    return int(m.group(1), 16) & 0xFFFFFF


def burn(args):
    picotool("info")  # a board in BOOTSEL answers; anything else aborts
    rows = (list(range(DEVK_ROW, DEVK_ROW + KEY_ROWS))
            + list(range(MKEK_ROW, MKEK_ROW + KEY_ROWS))
            + list(range(DEVK_ROW + CHAFF_OFFSET, DEVK_ROW + CHAFF_OFFSET + KEY_ROWS))
            + list(range(MKEK_ROW + CHAFF_OFFSET, MKEK_ROW + CHAFF_OFFSET + KEY_ROWS))
            + [LOCK1_ROW - 1, LOCK1_ROW])
    for row in rows:
        v = _read_raw_row(row)
        if v is None:
            die(f"row {row:#x} unreadable — page already locked?")
        if v != 0:
            die(f"row {row:#x} = {v:#08x}, not blank — board already provisioned?")
    print(f"preflight: {len(rows)} rows blank ✓")

    mkek = secrets.token_bytes(32)
    while True:
        devk = secrets.token_bytes(32)
        if 0 < int.from_bytes(devk, "big") < K256_N:
            break
    if args.dry_run:
        print("dry-run: would write DEVK@0xE80 + MKEK@0xE90 (ECC) + chaff; no OTP touched")
        return

    print("This PERMANENTLY burns the MKEK + DEVK into OTP page 58. No undo.")
    confirm("BURN-OTP-PAGE58")
    with tempfile.TemporaryDirectory(dir=_scratch_dir()) as td:
        def write_scratch(name, data):
            """picotool takes a path, so the key has to touch a filesystem. Create it
            0600 and O_EXCL, overwrite before unlink, and prefer the RAM-backed dir —
            the docs promise the host keeps no copy (audit run-32)."""
            p = os.path.join(td, name + ".bin")  # picotool dispatches by extension
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return p

        def shred(p):
            with open(p, "r+b") as f:
                n = f.seek(0, os.SEEK_END)
                f.seek(0)
                f.write(b"\x00" * n)
                f.flush()
                os.fsync(f.fileno())
            os.unlink(p)

        def burn_key(row, key, name):
            p = write_scratch(name, key)
            try:
                picotool("otp", "load", "-e", "-s", f"{row:#x}", p)
            finally:
                shred(p)
            print(f"{name} @ {row:#x} written + verified ✓")

        burn_key(DEVK_ROW, devk, "devk")
        burn_key(MKEK_ROW, mkek, "mkek")
        for base, name in ((DEVK_ROW, "devk_chaff"), (MKEK_ROW, "mkek_chaff")):
            raw = [(_read_raw_row(base + i) or 0) ^ 0xFFFFFF for i in range(KEY_ROWS)]
            # The chaff is the per-row complement of the key just burned, so it is
            # key-equivalent and gets the same handling.
            blob = b"".join(v.to_bytes(3, "little") + b"\x00" for v in raw)
            p = write_scratch(name, blob)
            try:
                picotool("otp", "load", "-r", "-s", f"{base + CHAFF_OFFSET:#x}", p)
            finally:
                shred(p)
            print(f"{name} @ {base + CHAFF_OFFSET:#x} written ✓")
        lock = picotool("otp", "set", "-r", f"{LOCK1_ROW:#x}", f"{LOCK_VALUE:#x}", check=False)
    locked = lock.returncode == 0 and _read_raw_row(MKEK_ROW) is None
    print("\nkeys + chaff burned ✓" + ("" if locked else
          " — BL/NS hard-lock NOT applied (OTP page 63 is bootloader-read-only;\n"
          "run `rsk otp lock-page58` from the firmware). Page-58 keys stay readable\n"
          "via `picotool otp get` from BOOTSEL until then."))
    print(
        "\nNext boot migrates your secrets under the fused root, then runs a\n"
        "one-shot at-rest hardening pass that physically scrubs the old\n"
        "chip-serial-sealed copies from flash. That first boot stays dark a few\n"
        "seconds longer than usual (the scrub runs before USB attach) — do NOT\n"
        "cut power during it. It runs once and re-runs if interrupted."
    )


def _scratch_dir():
    """A RAM-backed parent for the key scratch files, or None for the default.

    Overwrite-then-unlink does not reliably erase on a copy-on-write filesystem
    (APFS, btrfs, ZFS) or behind an SSD's wear levelling, so never landing the
    plaintext on non-volatile storage is the step that actually closes the
    channel. Linux gives us `/dev/shm`; macOS has no tmpfs, so there the shred
    below is the whole mitigation.
    """
    shm = "/dev/shm"
    return shm if os.path.isdir(shm) and os.access(shm, os.W_OK) else None


def _select_rescue(conn):
    """SELECT the rescue applet and return the chip serial it answers with. The
    serial names the device an irreversible fuse burn is about to hit, so the
    operator confirms against it rather than against a static token (audit run-32)."""
    d, s1, s2 = ccid.select(conn, RESCUE_AID)
    if (s1, s2) != ccid.SW_OK:
        die(f"SELECT rescue AID failed: {s1:02X}{s2:02X} (firmware too old?)")
    serial = rescue_serial(d, s1, s2)
    print(f"rescue applet selected ✓  device {serial or 'serial unavailable'}")
    return serial


def lock_page58(args):
    conn = ccid.connect(exclusive=True)
    serial = _select_rescue(conn)
    if args.dry_run:
        print("dry-run: would send OTP_LOCK (80 1B 58 00 06 'LOCK58' 00)")
        return
    print("This PERMANENTLY locks OTP page 58 away from BOOTSEL / non-secure. No undo.")
    confirm(serial or "LOCK-PAGE58")
    _, s1, s2 = ccid.transmit(conn, LOCK_APDU)
    print(f"OTP_LOCK → SW {s1:02X}{s2:02X}: {LOCK_SW.get((s1, s2), 'unknown status')}")
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(2)
    print("done. From BOOTSEL `picotool otp get -r 0xe90` must now fail (permission).")


def rollback_require(args):
    conn = ccid.connect(exclusive=True)
    serial = _select_rescue(conn)
    d, s1, s2 = rescue_read(conn, 0x06)
    if (s1, s2) != ccid.SW_OK or len(d) < 3:
        die(f"anti-rollback state read failed: SW {s1:02X}{s2:02X} — firmware too old?")
    required, version, capacity = d[0], d[1], d[2]
    print(f"anti-rollback state: ROLLBACK_REQUIRED={bool(required)}, "
          f"boot version {version}/{capacity}")
    if required:
        print("already fused — nothing to do ✓")
        return
    if args.dry_run:
        print("dry-run: would send OTP_LOCK (80 1B 48 00 06 'ROLLBK' 00)")
        return
    print("This PERMANENTLY makes the bootrom refuse any image WITHOUT a rollback")
    print("version — including every UF2 sealed before this feature (the old")
    print("firmware-signed.uf2, an unsealed-era rsk-wipe). Re-seal those with")
    print("`--rollback` first. See docs/production.md, \"Anti-rollback\". No undo.")
    confirm(serial or "ROLLBACK-REQUIRED")
    _, s1, s2 = ccid.transmit(conn, ROLLBACK_APDU)
    print(f"OTP_LOCK → SW {s1:02X}{s2:02X}: {ROLLBACK_SW.get((s1, s2), 'unknown status')}")
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(2)
    print("done. Negative-test: a signed-but-versionless UF2 must now refuse to boot")
    print("(falls back to BOOTSEL); the current image keeps booting.")
