# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk audit — read and verify the device's tamper-evident audit journal.

The firmware keeps a 128-entry flash ring of security events (boots, FIDO
operations, PIN changes/lockouts, config changes, backup/lock activity),
hash-chained from an "epoch" accumulator that absorbs evicted history. The
device signs the chain head with an ECDSA P-256 key derived from the OTP DEVK
(vendor AUDIT_CHECKPOINT), so the log is verifiable end-to-end:

  log     export and pretty-print the journal      (--pin if a PIN is set,
                                                     else a touch)
  verify  log + signed checkpoint over a fresh
          challenge; checks the chain and the
          signature                                 (touch; --pin if a PIN is set)

`verify --expect-key` additionally pins the attestation identity (the 16-hex
fingerprint or the full 65-byte SEC1 public key, either form) — record it once
at provisioning time, then any later mismatch means you are talking to a
different (or cloned-without-OTP) device. Without a pin the verifying key comes
from the same response being checked, so an unpinned run establishes only that
the journal is internally consistent and self-signed.
"""
import hashlib
import os
import sys

from .backup import ERR_NOT_ALLOWED, _die_pin_required, _die_touch_denied, _gated, _vendor
from .common import add_pin_arg, connect_fido, device_has_pin, die, resolve_pin

AUDIT_READ, AUDIT_CHECKPOINT, AUDIT_CONFIG = 7, 8, 14
ENTRY_LEN = 20
CKPT_TAG = b"RSK-AUDIT-CKPT-v1"

EVT_RESET = 0x04  # firmware journal.rs EV_RESET
EVT_CONFIG_WRITE = 0x15  # firmware journal.rs EV_CONFIG_WRITE
CONFIG_TARGETS = {0: "dev-conf", 1: "phy", 2: "led"}

EVENTS = {
    0x01: "BOOT",
    0x02: "MAKE_CREDENTIAL",
    0x03: "GET_ASSERTION",
    0x04: "RESET",
    0x05: "PIN_SET",
    0x06: "PIN_CHANGE",
    0x07: "PIN_LOCKOUT",
    0x08: "CFG_MIN_PIN",
    0x09: "CFG_ENTERPRISE_ATT",
    0x0A: "LOCK_ENGAGE",
    0x0B: "LOCK_RELEASE",
    0x0C: "BACKUP_EXPORT",
    0x0D: "BACKUP_LOAD",
    0x0E: "BACKUP_FINALIZE",
    0x0F: "U2F_REGISTER",
    0x10: "U2F_AUTH",
    0x11: "CHECKPOINT",
    0x12: "ATT_IMPORT",
    0x13: "ATT_CLEAR",
    0x14: "CFG_ALWAYS_UV",
    0x15: "CONFIG_WRITE",
    0x16: "AUDIT_CFG",
}


def register(sub):
    p = sub.add_parser("audit", help="tamper-evident audit journal")
    g = p.add_subparsers(dest="cmd", required=True)

    lg = g.add_parser("log", help="export and print the journal")
    add_pin_arg(lg)
    lg.set_defaults(func=cmd_log)

    v = g.add_parser("verify", help="log + DEVK-signed chain checkpoint (touch)")
    add_pin_arg(v)
    v.add_argument("--expect-key",
                   help="expected identity: 16-hex fingerprint or full hex SEC1 pubkey")
    v.set_defaults(func=cmd_verify)

    st = g.add_parser("status", help="show whether journalling is on (no touch)")
    st.set_defaults(func=cmd_status)

    en = g.add_parser("enable", help="turn journalling ON (PIN + touch)")
    add_pin_arg(en)
    en.set_defaults(func=cmd_enable)

    dis = g.add_parser("disable", help="turn journalling OFF (PIN + touch)")
    add_pin_arg(dis)
    dis.set_defaults(func=cmd_disable)


def _fold(epoch, entries):
    h = epoch
    for off in range(0, len(entries), ENTRY_LEN):
        h = hashlib.sha256(h + entries[off:off + ENTRY_LEN]).digest()
    return h


def _fingerprint(pubkey):
    return hashlib.sha256(pubkey).hexdigest()[:16]


def verify_signature(head, seq, sig, pubkey, challenge, distrust, badsig):
    """ECDSA-verify a checkpoint signature over CKPT_TAG ‖ head ‖ seq ‖ challenge;
    die()s fail-closed. Split out so a saved receipt can be re-checked offline,
    with no device and no CBOR map (`rsk offboard --verify`)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
        msg = CKPT_TAG + head + int(seq).to_bytes(4, "little") + challenge
    except (ValueError, TypeError, OverflowError):
        die(f"malformed checkpoint fields — {distrust}")
    try:
        vk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        die(badsig)


def verify_checkpoint(m, challenge, distrust, badsig):
    """Validate the DEVK checkpoint map `m` over `challenge`; die()s fail-closed.
    Returns (head, seq, sig, pubkey)."""
    if not all(k in m for k in (1, 2, 3, 4)):
        die(f"malformed checkpoint response — {distrust}")
    head, seq, sig, pubkey = m[1], m[2], m[3], m[4]
    verify_signature(head, seq, sig, pubkey, challenge, distrust, badsig)
    return head, seq, sig, pubkey


def read_journal(dev, cid, pin):
    """AUDIT_READ → (start, seq_next, epoch, entries bytes)."""
    if pin is None:
        # No PIN backs the gate, so the firmware requires a touch instead.
        print("touch the device (BOOTSEL) to read the journal…", file=sys.stderr)
    st, m = _vendor(dev, cid, _gated(AUDIT_READ, None, dev, cid, pin))
    _die_pin_required(st)
    _die_touch_denied(st)
    if st != 0:
        die(f"audit read failed: {st:#x}")
    start, seq_next, epoch, entries = m[1], m[2], m[3], m[4]
    if len(entries) % ENTRY_LEN or len(entries) != (seq_next - start) * ENTRY_LEN:
        die("export length does not match the window — corrupt journal?")
    return start, seq_next, epoch, entries


def _detail(e):
    """The detail column of one entry. The device coalesces a run of config writes
    into a single ring slot (an ungated host must not be able to flush the ring), so
    a CONFIG_WRITE detail is `repeats(2 LE) ‖ targets(1)`: how many writes the entry
    stands for and which records they touched."""
    if e[8] != EVT_CONFIG_WRITE:
        return e[10:18].hex()
    n = int.from_bytes(e[10:12], "little") + 1
    hit = "+".join(t for bit, t in CONFIG_TARGETS.items() if e[12] & (1 << bit))
    return f"{n}× write ({hit or 'unknown'})"


def print_entries(entries):
    print(f"{'seq':>6}  {'uptime':>10}  {'event':<18} aux  detail")
    for off in range(0, len(entries), ENTRY_LEN):
        e = entries[off:off + ENTRY_LEN]
        seq = int.from_bytes(e[0:4], "little")
        t_ms = int.from_bytes(e[4:8], "little")
        name = EVENTS.get(e[8], f"0x{e[8]:02x}")
        print(f"{seq:>6}  {t_ms / 1000:>9.1f}s  {name:<18} {e[9]:>3}  {_detail(e)}")


def cmd_log(args):
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    start, seq_next, epoch, entries = read_journal(dev, cid, pin)
    print(f"window [{start}, {seq_next})  —  {seq_next - start} entries, "
          f"{start} folded into the epoch")
    print(f"epoch : {epoch.hex()}")
    print(f"head  : {_fold(epoch, entries).hex()}  (chain over the window — OK)\n")
    print_entries(entries)


def _audit_state(dev, cid):
    """AUDIT_CONFIG status query (target 2, ungated) → whether journalling is on."""
    st, m = _vendor(dev, cid, {1: AUDIT_CONFIG, 2: {1: 2}})
    if st != 0:
        die(f"audit status failed: {st:#x}")
    return bool(m.get(1))


def cmd_status(args):
    dev, cid = connect_fido()
    print(f"audit journalling: {'ON' if _audit_state(dev, cid) else 'OFF'}")


def _audit_set(args, target, verb):
    # OFF by default: journalling is opt-in, so nothing is written to the key's
    # flash until it is turned on here (and it stops the moment it is turned off).
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    print("touch the device (BOOTSEL) to confirm…", file=sys.stderr)
    st, m = _vendor(dev, cid, _gated(AUDIT_CONFIG, {1: target}, dev, cid, pin))
    _die_pin_required(st)
    _die_touch_denied(st)
    if st != 0:
        die(f"audit {verb} failed: {st:#x}")
    print(f"audit journalling: {'ON' if bool(m.get(1)) else 'OFF'} — {verb}d ✓")


def cmd_enable(args):
    _audit_set(args, 1, "enable")


def cmd_disable(args):
    _audit_set(args, 0, "disable")


def cmd_verify(args):
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    start, seq_next, epoch, entries = read_journal(dev, cid, pin)
    head_local = _fold(epoch, entries)

    challenge = os.urandom(16)
    print("touch the device (BOOTSEL) to sign the checkpoint…", file=sys.stderr)
    st, m = _vendor(dev, cid,
                    _gated(AUDIT_CHECKPOINT, {1: challenge}, dev, cid, pin))
    if st == ERR_NOT_ALLOWED:
        die("checkpoint refused — no OTP DEVK provisioned (see docs/production.md)")
    _die_touch_denied(st)
    if st != 0:
        die(f"checkpoint failed: {st:#x}")
    head_signed, seq_signed, sig, pubkey = verify_checkpoint(
        m, challenge, "do not trust this journal",
        "checkpoint SIGNATURE INVALID — do not trust this journal")

    if head_signed != head_local:
        die("signed head differs from the exported window — the journal changed "
            "between read and checkpoint; rerun, and if it persists: TAMPER")
    fp = _fingerprint(pubkey)
    if args.expect_key and args.expect_key.lower().strip() not in (fp, pubkey.hex()):
        die("attestation key MISMATCH — this is not the enrolled device")

    print_entries(entries)
    print(f"\nchain   : OK — head {head_local.hex()}")
    print(f"sig     : OK — checkpoint over seq_next={seq_signed}, fresh challenge")
    print(f"att key : {pubkey.hex()}")
    print(f"          fingerprint {fp} — record this; pin later runs with --expect-key")
    if args.expect_key:
        print("verdict : journal authentic ✓ (signed by the pinned key)")
    else:
        # The verifying key came out of the very response being checked, so an
        # unpinned run proves self-consistency, never identity. Same caveat as
        # `rsk inventory verify`.
        print("verdict : chain + signature OK — the key is NOT pinned, so this "
              "does not prove which device signed it")
