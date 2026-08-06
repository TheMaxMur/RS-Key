# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk secure-boot — secure-boot provisioning + key rotation (host picotool ritual).

Staged so every irreversible write is proven by a real boot before the next, and
the only bricking step is the single SECURE_BOOT_ENABLE bit:

  status    read the current secure-boot OTP state (always safe)
  load-key  A: bootkey fingerprint + KEY_VALID (slot 0 by default). non-enforcing
  harden    B: DEBUG_DISABLE + GLITCH_DETECTOR_ENABLE/SENS=3.   non-enforcing
  enable    C: SECURE_BOOT_ENABLE = 1.                          the brick bit
  lock      D: revoke every untrusted key slot + PAGE1/PAGE2 bootloader-read-only.

RP2350 has four boot-key slots (BOOTKEY0..3); the bootrom boots an image whose
public key matches ANY valid, non-revoked slot. That is what makes rotation
possible WITHOUT the old key — but only on a board that left a free slot (did
NOT run the full `lock`, so the key pages stay bootloader-writable):

  load-key --slot N   provision a fingerprint into boot-key slot N (0..3)
  revoke N            set KEY_INVALID for slot N (its key stops validating)
  rotate <new.json>   guided: provision a new key into a free slot, then tells
                      you to flash + PROVE it before revoking the old slot

Optional stage 3 (anti-rollback, docs/production.md) lives in `rsk otp
rollback-require` — it burns from the *firmware* side, so it works before and
after `lock`; `status` here shows ROLLBACK_REQUIRED + the boot-version
thermometer either way.

USB BOOTSEL stays enabled (the recovery path); the signing key lives outside the
repo and must be backed up. Run against a board in BOOTSEL. --dry-run prints the
exact picotool commands without touching anything.
"""
import json
import os
import re
import tempfile

from .common import confirm, die, picotool

CRIT1_ROW, BOOT_FLAGS1_ROW, BOOTKEY0_0_ROW = 0x40, 0x4B, 0x80
# Four boot-key slots: BOOTKEY{n}_0 = 0x80 + n*0x10 (0x80/0x90/0xa0/0xb0), each a
# 16-row ECC block holding the SHA-256 fingerprint of one signing public key.
N_KEY_SLOTS, BOOTKEY_STRIDE = 4, 0x10
PAGE1_LOCK1_ROW, PAGE2_LOCK1_ROW = 0xF83, 0xF85
# Anti-rollback: BOOT_FLAGS0 bit 11 + the 48-bit DEFAULT_BOOT_VERSION
# thermometer. All RBIT-3 (three consecutive row copies, bitwise majority).
BOOT_FLAGS0_ROW, BOOT_VERSION0_ROW, BOOT_VERSION1_ROW = 0x48, 0x4E, 0x51
ROLLBACK_REQUIRED_BIT = 1 << 11
# PAGEx_LOCK1 byte = LOCK_BL[5:4] | LOCK_NS[3:2] | LOCK_S[1:0], x3 majority.
# 0x14 = BL/NS read-only, S read-write — NOT 0x3C (inaccessible): pages 1 & 2
# hold the flags + boot-key the bootrom must READ at every boot.
PAGE_LOCK_BL_RO = 0x141414


def register(sub):
    p = sub.add_parser("secure-boot", help="secure-boot provisioning + key rotation (IRREVERSIBLE)")
    g = p.add_subparsers(dest="cmd", required=True)
    g.add_parser("status", help="read the current secure-boot OTP state").set_defaults(func=cmd_status)
    lk = g.add_parser("load-key", help="A: bootkey fingerprint + KEY_VALID (slot 0 by default)")
    lk.add_argument("otp_json", help="the otp.json that `picotool seal` produced")
    lk.add_argument("--slot", type=int, default=0, help=f"boot-key slot to provision (0..{N_KEY_SLOTS - 1}; default 0)")
    lk.add_argument("--dry-run", action="store_true")
    lk.set_defaults(func=cmd_load_key)
    rv = g.add_parser("revoke", help="revoke one boot-key slot (KEY_INVALID) — for rotation")
    rv.add_argument("slot", type=int, help=f"boot-key slot to revoke (0..{N_KEY_SLOTS - 1})")
    rv.add_argument("--dry-run", action="store_true")
    rv.set_defaults(func=cmd_revoke)
    ro = g.add_parser("rotate", help="guided key rotation: provision a new slot, then flash+prove+revoke")
    ro.add_argument("otp_json", help="the otp.json `picotool seal` produced for the NEW key")
    ro.add_argument("--slot", type=int, default=None, help="target free slot (default: next free)")
    ro.add_argument("--dry-run", action="store_true")
    ro.set_defaults(func=cmd_rotate)
    for name, fn in (("harden", cmd_harden), ("enable", cmd_enable), ("lock", cmd_lock)):
        sp = g.add_parser(name, help=f"{name} stage")
        sp.add_argument("--dry-run", action="store_true")
        sp.set_defaults(func=fn)


def require_bootsel():
    r = picotool("info", check=False)
    if r.returncode != 0 or "RP2350" not in r.stdout:
        die("no RP-series device in BOOTSEL mode (reboot first: `rsk reboot bootsel`)")
    # `picotool info` is the one command that iterates EVERY match and still
    # succeeds; every OTP command below is single-target and fails. Without this
    # the reads all failed, `_raw` reported blank, and a hardened, secure-boot
    # LOCKED board printed as virgin (audit run-36). Refuse to guess, the same
    # rule `connect_fido(exclusive=True)` applies to the CCID/HID side.
    if "Multiple RP-series devices" in r.stdout:
        die("more than one RP-series device in BOOTSEL mode — unplug the others; "
            "this tool will not guess which one to read or burn")


def _raw(row):
    # An unreadable row is NOT a blank row. Every caller coerced `None` with
    # `or 0`, so a failed read looked like an unprovisioned fuse: `status` printed
    # a fully hardened, LOCKED board as untouched, and `load-key` reached its typed
    # confirmation on state the tool had never read (audit run-36). Die on both
    # failure modes, as the sibling `otp.py:_read_raw_row` already does.
    r = picotool("otp", "get", "-r", "-n", f"{row:#x}", check=False)
    if r.returncode != 0:
        die(f"row {row:#x} unreadable — is exactly one RP2350 in BOOTSEL mode?")
    m = re.search(r"VALUE\s+(0x[0-9a-fA-F]+)", r.stdout)
    if m is None:
        die(f"row {row:#x} unparseable — picotool output format changed?")
    return int(m.group(1), 16) & 0xFFFFFF


def _majority3(row):
    """Bitwise 2-of-3 majority over an RBIT-3 row triple — the bootrom's view."""
    a, b, c = ((_raw(row + i) or 0) for i in range(3))
    return (a & b) | (a & c) | (b & c)


# --- pure helpers (no device; unit-tested in test_secureboot.py) --------------

def slot_key_row(n):
    """First OTP row of boot-key slot n (BOOTKEY{n}_0)."""
    return BOOTKEY0_0_ROW + n * BOOTKEY_STRIDE


def _valid_slot(n):
    if not (0 <= n < N_KEY_SLOTS):
        die(f"slot must be 0..{N_KEY_SLOTS - 1} (got {n})")
    return n


def _build_slot_json(seal_data, slot, new_key_valid):
    """Minimal `picotool otp load` json to write a fingerprint into `slot`.

    Re-targets the seal json's slot-0 `bootkey0` fingerprint onto BOOTKEY{slot}
    and sets KEY_VALID to `new_key_valid` (the *accumulated* mask, so OTP only
    ever gains bits — antifuses cannot clear one).
    """
    fp = seal_data.get("bootkey0")
    if fp is None:
        die("otp.json is missing bootkey0 — not a `picotool seal` otp.json?")
    return {f"bootkey{slot}": fp, "boot_flags1": {"key_valid": new_key_valid}}


def _next_free_slot(s):
    """First slot with no fingerprint and neither KEY_VALID nor KEY_INVALID set."""
    for n in range(N_KEY_SLOTS):
        bit = 1 << n
        if not s["slots_present"][n] and not (s["key_valid"] & bit) and not (s["key_invalid"] & bit):
            return n
    return None


def _revoke_leaves_valid(key_valid, key_invalid, slot):
    """Slots still valid AND not revoked after revoking `slot`; 0 ⇒ would brick."""
    return key_valid & ~(key_invalid | (1 << slot)) & 0xF


def _trusted_slots(key_valid, key_invalid):
    """The mask the bootrom trusts: KEY_VALID set AND KEY_INVALID clear."""
    return key_valid & ~key_invalid & 0xF


def _lock_invalid_mask(key_valid, key_invalid):
    """KEY_INVALID for `lock`: revoke every slot the bootrom does not already
    trust. A superset of the current KEY_INVALID, so the antifuse write never
    asks picotool to clear a bit. Hard-coding 0xE instead assumed the live key
    sits in slot 0 and, after a rotation, revoked the key the board was actually
    booting on (audit run-32)."""
    return ~_trusted_slots(key_valid, key_invalid) & 0xF


def pages_locked(s):
    """Key/flag pages bootloader-read-only (after `lock`) ⇒ BOOTSEL can't write keys.
    Only LOCK_BL (bits 4-5 of each RBIT-3 byte, mask 0x303030) blocks bootloader
    writes; a pre-existing LOCK_NS/LOCK_S in the row does not, so mask to LOCK_BL
    rather than testing the whole row (else a chip with LOCK_NS set false-positives)."""
    bl = 0x303030
    return bool((s["page1_lock"] or 0) & bl) or bool((s["page2_lock"] or 0) & bl)


# --- device state -------------------------------------------------------------

def slot_present(n):
    """True if slot n's fingerprint rows are written (first 2 ECC rows non-zero)."""
    base = slot_key_row(n)
    return any((_raw(base + i) or 0) for i in range(2))


def read_state():
    crit1, flags1 = _raw(CRIT1_ROW) or 0, _raw(BOOT_FLAGS1_ROW) or 0
    version = (bin(_majority3(BOOT_VERSION0_ROW)).count("1")
               + bin(_majority3(BOOT_VERSION1_ROW)).count("1"))
    slots = [slot_present(n) for n in range(N_KEY_SLOTS)]
    return {
        "secure_boot_enable": bool(crit1 & 1), "debug_disable": bool(crit1 & (1 << 2)),
        "glitch_enable": bool(crit1 & (1 << 4)), "glitch_sens": (crit1 >> 5) & 3,
        "key_valid": flags1 & 0xF, "key_invalid": (flags1 >> 8) & 0xF,
        "slots_present": slots, "bootkey0_present": slots[0],
        "page1_lock": _raw(PAGE1_LOCK1_ROW), "page2_lock": _raw(PAGE2_LOCK1_ROW),
        "rollback_required": bool(_majority3(BOOT_FLAGS0_ROW) & ROLLBACK_REQUIRED_BIT),
        "boot_version": version,
    }


def print_state(s):
    # The lock's own evidence is the fused key pages, not a particular KEY_INVALID
    # value — that depends on which slot the board boots from.
    locked = (s["secure_boot_enable"] and pages_locked(s)
              and s["debug_disable"] and s["glitch_enable"] and s["glitch_sens"] == 3)
    slotmap = "  ".join(
        f"[{n}]{'K' if s['slots_present'][n] else '.'}"
        f"{'V' if s['key_valid'] & (1 << n) else '.'}"
        f"{'X' if s['key_invalid'] & (1 << n) else '.'}"
        for n in range(N_KEY_SLOTS))
    print(f"  boot-key slots  : {slotmap}   (K=key V=valid X=revoked)")
    print(f"  KEY_VALID/INVALID : {s['key_valid']:#x} / {s['key_invalid']:#x}")
    print(f"  DEBUG_DISABLE   : {s['debug_disable']}")
    print(f"  GLITCH enable/sens: {s['glitch_enable']} / {s['glitch_sens']}")
    print(f"  SECURE_BOOT_ENABLE: {s['secure_boot_enable']}   <-- enforcement")
    print(f"  ROLLBACK_REQUIRED : {s['rollback_required']}   boot version {s['boot_version']}/48")
    print(f"  => secure boot {'LOCKED' if locked else 'ENABLED' if s['secure_boot_enable'] else 'NOT enabled'}")


def _set(args, dry):
    print("   picotool otp", *args)
    if not dry:
        picotool("otp", *args)


def cmd_status(args):
    require_bootsel()
    print("Secure-boot OTP state:")
    print_state(read_state())


def _provision_slot(otp_json, slot, dry, *, stage_label):
    """Write a seal-json fingerprint into boot-key `slot` + KEY_VALID; verify it took."""
    otp_json = os.path.expanduser(otp_json)
    if not os.path.exists(otp_json):
        die(f"{otp_json} not found (the otp.json `picotool seal` produced)")
    require_bootsel()
    s = read_state()
    if pages_locked(s):
        die("key pages are bootloader-locked (full `lock` was run) — BOOTSEL can no "
            "longer write boot keys. Rotation needs a board that reserved a free slot.")
    # KEY_INVALID too: it supersedes KEY_VALID in the bootrom, so burning here
    # spends one of four one-way slots on a key that will never be trusted, while
    # the tool prints "confirm it boots". `cmd_rotate` and `_next_free_slot` both
    # check all three; this site checked two (audit run-36).
    bit = 1 << slot
    if s["slots_present"][slot] or (s["key_valid"] & bit) or (s["key_invalid"] & bit):
        die(f"slot {slot} is not free (holds a key / is KEY_VALID / revoked) — pick another.")
    with open(otp_json) as f:
        data = json.load(f)
    new_valid = (s["key_valid"] | (1 << slot)) & 0xF
    out = _build_slot_json(data, slot, new_valid)
    print(f"{stage_label}: bootkey {bytes(out[f'bootkey{slot}']).hex()} -> slot {slot}, "
          f"KEY_VALID {s['key_valid']:#x} -> {new_valid:#x} (non-enforcing):")
    confirm("LOAD-BOOTKEY") if not dry else None
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, f"bootkey_slot{slot}.json")
        with open(p, "w") as f:
            json.dump(out, f)
        print("   picotool otp load", p)
        if not dry:
            picotool("otp", "load", p)
            s = read_state()
            if not s["slots_present"][slot] or not (s["key_valid"] & (1 << slot)):
                die(f"verify failed: slot {slot} fingerprint / KEY_VALID did not take")
            print_state(s)
    return s


def cmd_load_key(args):
    slot = _valid_slot(args.slot)
    _provision_slot(args.otp_json, slot, args.dry_run,
                    stage_label=f"Stage A — load-key slot {slot}")
    if slot == 0:
        print("\nNEXT: reflash the SIGNED UF2, confirm it boots, then `rsk secure-boot harden`")
    else:
        print(f"\nNEXT: reflash a UF2 signed by THIS key, confirm it boots, then revoke the "
              f"old slot (`rsk secure-boot revoke <old>`)")


def cmd_revoke(args):
    slot = _valid_slot(args.slot)
    require_bootsel()
    s = read_state()
    if pages_locked(s):
        die("the BOOT_FLAGS1 page is bootloader-locked (full `lock` was run) — KEY_INVALID "
            "can no longer be written from BOOTSEL.")
    bit = 1 << slot
    if s["key_invalid"] & bit:
        print(f"slot {slot} is already revoked (KEY_INVALID bit set). Nothing to do.")
        return
    if _revoke_leaves_valid(s["key_valid"], s["key_invalid"], slot) == 0:
        die(f"refusing: revoking slot {slot} would leave NO valid, non-revoked key — the "
            "board would boot nothing. Provision and PROVE a replacement first "
            "(`rsk secure-boot load-key --slot <free>`).")
    if not (s["key_valid"] & bit):
        print(f"note: slot {slot} is not currently KEY_VALID — revoking anyway (harmless).")
    new_invalid = (s["key_invalid"] | bit) & 0xF
    print(f"Revoke boot-key slot {slot}: KEY_INVALID {s['key_invalid']:#x} -> {new_invalid:#x}.")
    print("Images signed ONLY by that slot's key stop booting. Make sure the replacement key")
    print("is provisioned AND was proven to boot before you do this.")
    confirm("REVOKE-BOOTKEY") if not args.dry_run else None
    _set(["set", "OTP_DATA_BOOT_FLAGS1.KEY_INVALID", f"{new_invalid:#x}"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if not (s["key_invalid"] & bit):
            die("verify failed: KEY_INVALID bit did not take")
        print_state(s)
    print(f"\nDONE. Slot {slot} revoked.")


def cmd_rotate(args):
    require_bootsel()
    s = read_state()
    if pages_locked(s):
        die("key pages are bootloader-locked (full `lock` was run) — no rotation is possible "
            "on this board; a fresh board is the only path.")
    if args.slot is not None:
        target = _valid_slot(args.slot)
        bit = 1 << target
        if s["slots_present"][target] or (s["key_valid"] & bit) or (s["key_invalid"] & bit):
            die(f"slot {target} is not free (has a key / is valid / revoked) — pick another.")
    else:
        target = _next_free_slot(s)
        if target is None:
            die("no free boot-key slot — all four are used or revoked; rotation needs a fresh board.")
    old = [n for n in range(N_KEY_SLOTS) if (s["key_valid"] & (1 << n)) and not (s["key_invalid"] & (1 << n))]
    print(f"Key rotation — provisioning the NEW key into free slot {target}.")
    print(f"Currently-trusted (old) slot(s): {old or 'none'}")
    _provision_slot(args.otp_json, target, args.dry_run,
                    stage_label=f"Rotate — load-key slot {target}")
    print("\nNEXT (in order — do NOT skip the boot proof; both keys are trusted until step 3):")
    print("  1. Re-sign your firmware AND rsk-wipe with the NEW key.")
    print("  2. Flash the new signed image; CONFIRM the board boots and works.")
    print(f"  3. Only then revoke the old key:  rsk secure-boot revoke {('/'.join(map(str, old)) or '<old-slot>')}")


def cmd_harden(args):
    require_bootsel()
    if not read_state()["bootkey0_present"]:
        die("no bootkey present — run `load-key` first.")
    print("Stage B — DEBUG_DISABLE + GLITCH_DETECTOR (non-enforcing; kills SWD — fine, BOOTSEL-only):")
    confirm("HARDEN-SECURE-BOOT") if not args.dry_run else None
    _set(["set", "OTP_DATA_CRIT1.DEBUG_DISABLE", "1"], args.dry_run)
    _set(["set", "OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE", "1"], args.dry_run)
    _set(["set", "OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS", "3"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if not (s["debug_disable"] and s["glitch_enable"] and s["glitch_sens"] == 3):
            die("verify failed: hardening fuses did not take")
        print_state(s)
    print("\nNEXT: reboot, confirm the board still boots, then `rsk secure-boot enable`")


def cmd_enable(args):
    require_bootsel()
    s = read_state()
    if not s["bootkey0_present"]:
        die("no bootkey — run `load-key`/`harden` first.")
    # RP2350's own KEY_VALID doc: enabling enforcement without a valid key renders
    # the device unbootable. A fingerprint alone is not enough (audit run-32).
    if _trusted_slots(s["key_valid"], s["key_invalid"]) == 0:
        die("refusing: no slot is both KEY_VALID and non-revoked — enabling "
            "enforcement now would leave the board unable to validate any image.")
    if s["secure_boot_enable"]:
        die("SECURE_BOOT_ENABLE already set.")
    print("Stage C — SECURE_BOOT_ENABLE = 1. THE IRREVERSIBLE ENFORCEMENT BIT.")
    print("Make sure a SIGNED image is flashed and was proven to boot.")
    confirm("ENABLE-SECURE-BOOT") if not args.dry_run else None
    _set(["set", "OTP_DATA_CRIT1.SECURE_BOOT_ENABLE", "1"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if not s["secure_boot_enable"]:
            die("verify failed: SECURE_BOOT_ENABLE did not take")
        print_state(s)
    print("\nNEXT: prove signed boots; negative-test an UNSIGNED UF2 is rejected; then `lock`")


def cmd_lock(args):
    require_bootsel()
    s = read_state()
    if not s["secure_boot_enable"]:
        die("SECURE_BOOT_ENABLE not set — run `enable` and verify it first.")
    # Which slot the board actually boots on decides the mask; `lock` used to burn a
    # constant and silently revoke a rotated-to key (audit run-32).
    trusted = _trusted_slots(s["key_valid"], s["key_invalid"])
    if trusted == 0:
        die("refusing: no slot is both KEY_VALID and non-revoked — the board would "
            "not boot any image after the lock. Provision a key first.")
    if trusted & (trusted - 1):
        keep = [n for n in range(N_KEY_SLOTS) if trusted & (1 << n)]
        die(f"refusing: slots {keep} are both trusted, so `lock` cannot tell which one "
            "to keep. Run `revoke <old slot>` first (it carries the last-valid-key guard).")
    invalid = _lock_invalid_mask(s["key_valid"], s["key_invalid"])
    keep = trusted.bit_length() - 1
    print(f"Stage D — KEY_INVALID={invalid:#x} (revoke every slot but {keep}) "
          "+ PAGE1/PAGE2 read-only:")
    print("This forecloses key rotation (no free slot left). Skip it to keep a rotation slot.")
    confirm("LOCK-SECURE-BOOT") if not args.dry_run else None
    _set(["set", "OTP_DATA_BOOT_FLAGS1.KEY_INVALID", f"{invalid:#x}"], args.dry_run)
    _set(["set", "-r", "OTP_DATA_PAGE1_LOCK1", f"{PAGE_LOCK_BL_RO:#x}"], args.dry_run)
    _set(["set", "-r", "OTP_DATA_PAGE2_LOCK1", f"{PAGE_LOCK_BL_RO:#x}"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if s["key_invalid"] != invalid:
            die("verify failed: KEY_INVALID did not take")
        if _trusted_slots(s["key_valid"], s["key_invalid"]) == 0:
            die("verify failed: no trusted boot key survived the lock")
        print_state(s)
    print("\nDONE. Every future reflash must be a `picotool seal --sign`-ed UF2. Back up the key.")
    print("Optional next: anti-rollback — seal with `--rollback`, then `rsk otp rollback-require`")
    print("(docs/production.md, stage 3).")
