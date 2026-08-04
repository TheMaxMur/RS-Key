# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk lock — at-rest soft-lock of the FIDO seed (AUT_ENABLE / UNLOCK / AUT_DISABLE).

`enable` wraps the 32-byte seed under a host-held lock key (ChaCha20-Poly1305)
and erases the plaintext from flash; from then on EVERY power-cycle needs
`rsk lock unlock` before any FIDO operation works — including ssh-sk logins.
The lock key is shown once as a BIP-39 phrase (or SLIP-39 shares, or hex);
losing it means the only way out is a FIDO factory reset, which destroys the
identity. `disable` restores the plaintext seed (requires an unlock first).

  enable   wrap the seed, show the lock key   (touch + PIN; typed confirm)
  unlock   load the seed into RAM until power-off
  disable  restore the plaintext seed         (touch + PIN; unlock first)
  status   print {sealed, has_seed, locked, unlocked}
"""
import os
import sys

from . import ctaphid
from .backup import (PINUV_PREFIX, STATE as VENDOR_STATE, from_bip39,
                     from_slip39, mse_handshake, to_bip39, to_slip39,
                     _acfg_token, _vendor)
from .common import add_pin_arg, connect_fido, device_has_pin, die, resolve_pin

CTAP_CONFIG = 0x0D
CONFIG_VENDOR = 0xFF
AUT_ENABLE = 0x03E43F56B34285E2
AUT_DISABLE = 0x1831A40F04A25ED9
VENDOR_UNLOCK = 6
AUT_TOUCH_HINT = "touch the device (BOOTSEL) to authorise…"

from cryptography.hazmat.primitives import hashes, hmac as chmac  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402


def register(sub):
    p = sub.add_parser("lock", help="at-rest soft-lock of the FIDO seed")
    g = p.add_subparsers(dest="cmd", required=True)

    def key_args(sp):
        sp.add_argument("--scheme", choices=["bip39", "slip39", "hex"], default="bip39")
        add_pin_arg(sp, help="FIDO2 PIN (authenticatorConfig requires one; prompted if omitted)")

    e = g.add_parser("enable", help="engage the lock (shows the lock key ONCE)")
    key_args(e)
    e.add_argument("--threshold", type=int, default=2, help="SLIP-39 shares needed (default 2)")
    e.add_argument("--shares", type=int, default=3, help="SLIP-39 total shares (default 3)")
    e.add_argument("--key-out", help="also write the lock key hex to this file (for tests)")
    e.set_defaults(func=cmd_enable)

    u = g.add_parser("unlock", help="unlock for this power cycle")
    u.add_argument("--mnemonic", help="BIP-39 phrase (else prompted per --scheme)")
    u.add_argument("--key-hex", help="raw 64-hex lock key")
    u.add_argument("--scheme", choices=["bip39", "slip39", "hex"], default="bip39")
    u.set_defaults(func=cmd_unlock)

    d = g.add_parser("disable", help="restore the plaintext seed (unlock first)")
    key_args(d)
    d.add_argument("--mnemonic", help="unlock first with this BIP-39 phrase")
    d.add_argument("--key-hex", help="unlock first with this raw 64-hex key")
    d.set_defaults(func=cmd_disable)

    g.add_parser("status", help="print the lock state").set_defaults(func=cmd_status)


def _state(dev, cid):
    st, m = _vendor(dev, cid, {1: VENDOR_STATE})
    if st != 0:
        die(f"state read failed: {st:#x}")
    # A hostile/old device may answer with a non-map or without the soft-lock
    # fields; require the map and key 3 (the isinstance guard also stops a scalar
    # reply from raising on `3 not in m`), then coerce to bool so a spoofed
    # string value can't reach the terminal or a downstream check raw.
    if not isinstance(m, dict) or 3 not in m:
        die("firmware too old — no soft-lock support (need bcdDevice >= 0x0742)")
    return {"sealed": bool(m.get(1)), "has_seed": bool(m.get(2)),
            "locked": bool(m.get(3)), "unlocked": bool(m.get(4))}


def _wrap_for_channel(key, aad, secret):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, secret, aad)


def _config_vendor(dev, cid, pin, vendor_id, param=None):
    """authenticatorConfig {1: 0xFF, 2: {1: id, 2: param?}, 3, 4} with the acfg MAC.
    `pin` is resolved by the caller (resolve_pin, required=True), so it is set."""
    subpara = {1: vendor_id}
    if param is not None:
        subpara[2] = param
    token = _acfg_token(dev, cid, pin)
    vp = PINUV_PREFIX + bytes([CTAP_CONFIG, CONFIG_VENDOR]) + ctaphid.enc(subpara)
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(vp)
    req = {1: CONFIG_VENDOR, 2: subpara, 3: 2, 4: h.finalize()}
    r = ctaphid.send_cbor(dev, cid, bytes([CTAP_CONFIG]) + ctaphid.enc(req))
    return r[0]


def _read_lock_key(args):
    if getattr(args, "key_hex", None):
        key = bytes.fromhex(args.key_hex)
    elif args.scheme == "hex":
        key = bytes.fromhex(input("lock key (64 hex chars): ").strip())
    elif args.scheme == "slip39":
        print("Enter SLIP-39 shares, one per line, blank line to finish:")
        lines = []
        while (ln := input()).strip():
            lines.append(ln)
        key = from_slip39(lines)
    else:
        key = from_bip39(getattr(args, "mnemonic", None) or input("BIP-39 phrase: "))
    if len(key) != 32:
        die(f"lock key is {len(key)} bytes, expected 32")
    return key


def _unlock(dev, cid, key):
    chan_key, aad = mse_handshake(dev, cid)
    blob = _wrap_for_channel(chan_key, aad, key)
    st, _ = _vendor(dev, cid, {1: VENDOR_UNLOCK, 2: {1: blob}})
    if st == 0x3D:
        die("device is not locked")
    if st != 0:
        die(f"unlock failed: {st:#x} (wrong key?)")


def cmd_status(args):
    dev, cid = connect_fido()
    for k, v in _state(dev, cid).items():
        print(f"{k:9}: {v}")


def cmd_enable(args):
    dev, cid = connect_fido(exclusive=True)
    s = _state(dev, cid)
    if s["locked"]:
        die("already locked")
    if not s["has_seed"]:
        die("no seed on the device")
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid), required=True)

    key = os.urandom(32)
    if args.scheme == "bip39":
        rendered = [("phrase", to_bip39(key)[0])]
    elif args.scheme == "slip39":
        shares = to_slip39(key, args.threshold, args.shares)
        rendered = [(f"share {i}/{len(shares)}", mn) for i, mn in enumerate(shares, 1)]
    else:
        rendered = [("key hex", key.hex())]

    print("\n=== LOCK KEY — WRITE THIS DOWN, IT IS SHOWN ONLY NOW ===")
    for label, text in rendered:
        print(f"\n[{label}]\n{text}")
    if args.scheme == "slip39":
        print(f"\n(any {args.threshold} of {args.shares} shares reconstruct the key)")
    if args.key_out:
        # Create the file 0600 up front: chmod-after-close left a window where the
        # lock key sat at the umask default (world-readable), and os.chmod follows
        # a swapped-in symlink. O_EXCL refuses a pre-existing file or symlink.
        try:
            fd = os.open(args.key_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as e:
            die(f"cannot write --key-out {args.key_out}: {e}")
        with os.fdopen(fd, "w") as f:
            f.write(key.hex() + "\n")
        print(f"\n(key hex also written to {args.key_out})")

    print("""
After enabling:
  * EVERY power-cycle needs `rsk lock unlock` before ANY FIDO operation —
    ssh-sk login stops being plug-and-touch until you unlock.
  * Losing the lock key means the ONLY recovery is a FIDO factory reset,
    which permanently destroys this identity (ssh keys, U2F registrations).""")
    if input("\nType LOCK-SEED to engage the lock: ").strip() != "LOCK-SEED":
        die("aborted")

    chan_key, aad = mse_handshake(dev, cid)
    blob = _wrap_for_channel(chan_key, aad, key)
    print(AUT_TOUCH_HINT, file=sys.stderr)
    st = _config_vendor(dev, cid, pin, AUT_ENABLE, blob)
    if st != 0:
        die(f"AUT_ENABLE failed: {st:#x}")
    s = _state(dev, cid)
    if not s["locked"] or s["has_seed"]:
        die(f"post-enable state unexpected: {s}")
    print("locked ✓ — plaintext seed erased; unlock with `rsk lock unlock`")


def cmd_unlock(args):
    dev, cid = connect_fido(exclusive=True)
    key = _read_lock_key(args)
    _unlock(dev, cid, key)
    print("unlocked ✓ — FIDO operations work until power-off")


def cmd_disable(args):
    dev, cid = connect_fido(exclusive=True)
    s = _state(dev, cid)
    if not s["locked"]:
        die("not locked")
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid), required=True)
    if not s["unlocked"]:
        _unlock(dev, cid, _read_lock_key(args))
    print(AUT_TOUCH_HINT, file=sys.stderr)
    st = _config_vendor(dev, cid, pin, AUT_DISABLE)
    if st != 0:
        die(f"AUT_DISABLE failed: {st:#x}")
    s = _state(dev, cid)
    if s["locked"] or not s["has_seed"]:
        die(f"post-disable state unexpected: {s}")
    print("unlocked permanently ✓ — plaintext seed restored")
