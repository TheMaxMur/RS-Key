# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk backup — wallet-style FIDO seed backup/restore over the vendor (0x41) MSE channel.

The device exports its 32-byte master seed once, at setup, encrypted over an
ephemeral ECDH channel; rendered here as a BIP-39 24-word phrase or SLIP-39
Shamir T-of-N shares. Restore reconstructs the 32 bytes and writes them back,
re-sealed under the new device's own key. Recovers the deterministic non-resident
FIDO identity (ed25519-sk / U2F / non-rk); resident passkeys and OpenPGP/PIV keys
are not covered.

  export   read the seed and print a mnemonic   (touch; --pin if a PIN is set)
  restore  install a seed from a mnemonic        (touch; --pin if a PIN is set)
  finalize seal the one-time export window       (touch) — AFTER you have written
           the mnemonic down; export is then refused until a reset reopens it
  status   print {sealed, has_seed}
"""
import hashlib
import os
import sys

from . import ctaphid
from .common import add_pin_arg, connect_fido, device_has_pin, die, resolve_pin

CTAP_VENDOR = 0x41
VENDOR_MSE, EXPORT, LOAD, FINALIZE, STATE = 1, 2, 3, 4, 5
# Device-config subcommands (rsk hw --transport fido); targets match rsk-fido consts.rs.
CONFIG_WRITE, CONFIG_READ = 0x0C, 0x0D
CONFIG_TARGET_DEV_CONF, CONFIG_TARGET_PHY, CONFIG_TARGET_LED = 0, 1, 2
PERM_ACFG = 0x20
ERR_OPERATION_DENIED, ERR_NOT_ALLOWED, ERR_PIN_REQUIRED = 0x27, 0x30, 0x36
PINUV_PREFIX = b"\xff" * 32  # CTAP 2.1 pinUvAuthParam prefix; must match firmware (rsk-fido vendor.rs/config.rs)

from cryptography.hazmat.primitives import hashes, hmac as chmac  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

# ML-KEM-768 (FIPS 203) is optional: cryptography >= 46 exposes it. When present,
# the MSE handshake is hybrid P-256 + ML-KEM-768 — harvest-now-decrypt-later
# resistant, since recovering the channel key (and thus the exported seed) would
# need *both* P-256 and ML-KEM-768 broken. Older hosts, or older devices that do
# not understand the extra field, transparently fall back to classical P-256.
try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (  # noqa: E402
        MLKEM768PrivateKey,
    )

    _MLKEM_OK = True
except ImportError:
    _MLKEM_OK = False

MSE_PQ_SALT = b"RSK-MSE-PQ-v1"  # domain-separates the hybrid key; must match firmware


def register(sub):
    p = sub.add_parser("backup", help="wallet-style FIDO seed backup / restore")
    g = p.add_subparsers(dest="cmd", required=True)

    def scheme(sp):
        sp.add_argument("--scheme", choices=["bip39", "slip39"], default="bip39")
        add_pin_arg(sp)

    e = g.add_parser("export", help="read the seed and print a mnemonic")
    scheme(e)
    e.add_argument("--threshold", type=int, default=2, help="SLIP-39 shares needed (default 2)")
    e.add_argument("--shares", type=int, default=3, help="SLIP-39 total shares (default 3)")
    e.set_defaults(func=cmd_export)
    r = g.add_parser("restore", help="install a seed from a mnemonic")
    scheme(r)
    r.add_argument("--mnemonic", help="BIP-39 phrase (else read from stdin)")
    r.set_defaults(func=cmd_restore)
    f = g.add_parser("finalize", help="seal the one-time export window")
    f.add_argument("--pin", help="(accepted for symmetry; finalize needs only touch)")
    f.set_defaults(func=cmd_finalize)
    g.add_parser("status", help="print {sealed, has_seed}").set_defaults(func=cmd_status)


def _vendor(dev, cid, fields):
    r = ctaphid.send_cbor(dev, cid, bytes([CTAP_VENDOR]) + ctaphid.enc(fields))
    return r[0], (ctaphid.decode(r[1:]) if len(r) > 1 and r[0] == 0 else None)


def _die_pin_required(st):
    if st == ERR_PIN_REQUIRED:
        die("device requires a PIN — pass --pin or enter it when prompted")


def _die_touch_denied(st):
    if st == ERR_OPERATION_DENIED:
        die("denied — no touch within 30 s; press the button when the LED blinks")


def mse_handshake(dev, cid):
    """ECDH key agreement → a 32-byte ChaCha20-Poly1305 channel key + its AAD.

    Sends the host's P-256 ephemeral key and, when ML-KEM-768 is available, an
    encapsulation key (subCommandParams key 2). A device that supports it replies
    with a ciphertext (response key 2) and the channel becomes hybrid:
    ``HKDF(salt=MSE_PQ_SALT, ikm=z ‖ ss_mlkem, info=aad ‖ ct)``. Otherwise — old
    host or old firmware — the classical ``HKDF(salt="", ikm=z, info=aad)`` is
    used. The AAD (the device's P-256 public point) is identical either way, so
    every downstream subcommand is unaffected by which channel was negotiated.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    cose = {1: 2, 3: -25, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
    subpara = {1: cose}
    kem = MLKEM768PrivateKey.generate() if _MLKEM_OK else None
    if kem is not None:
        subpara[2] = kem.public_key().public_bytes_raw()  # 1184-byte ek

    st, m = _vendor(dev, cid, {1: VENDOR_MSE, 2: subpara})
    if st != 0:
        die(f"MSE failed: status {st:#x}")
    dx, dy = m[1][-2], m[1][-3]
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(dx, "big"), int.from_bytes(dy, "big"), ec.SECP256R1()).public_key()
    z = priv.exchange(ec.ECDH(), peer)
    aad = b"\x04" + dx + dy

    ct = m.get(2)  # present iff the device went hybrid
    if kem is not None and ct is not None:
        ss = kem.decapsulate(ct)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=MSE_PQ_SALT,
                   info=aad + ct).derive(z + ss)
        print("MSE channel: hybrid P-256 + ML-KEM-768", file=sys.stderr)
    else:
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=aad).derive(z)
        print("MSE channel: classical P-256", file=sys.stderr)
    return key, aad


def _acfg_token(dev, cid, pin):
    r = ctaphid.client_pin(dev, cid, {1: 2, 2: 2})
    if r[0] != 0:
        die(f"getKeyAgreement failed: {r[0]:#x}")
    proto = ctaphid.Protocol2(ctaphid.decode(r[1:])[1][-2], ctaphid.decode(r[1:])[1][-3])
    ph = hashlib.sha256(pin.encode()).digest()[:16]
    r = ctaphid.client_pin(dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: PERM_ACFG})
    if r[0] != 0:
        die(f"getPinUvAuthToken failed: {r[0]:#x} (wrong PIN? do not guess)")
    return proto.decrypt(ctaphid.decode(r[1:])[2])  # key 2 = pinUvAuthToken


def _gated(subcmd, subpara, dev, cid, pin):
    fields = {1: subcmd}
    if subpara is not None:
        fields[2] = subpara
    if pin is not None:
        token = _acfg_token(dev, cid, pin)
        raw = ctaphid.enc(subpara) if subpara is not None else b""
        vp = PINUV_PREFIX + bytes([CTAP_VENDOR, subcmd]) + raw
        h = chmac.HMAC(token, hashes.SHA256())
        h.update(vp)
        fields[3], fields[4] = 2, h.finalize()
    return fields


def read_seed(dev, cid, pin):
    """MSE handshake + EXPORT; returns the decrypted 32-byte seed."""
    key, aad = mse_handshake(dev, cid)
    st, m = _vendor(dev, cid, _gated(EXPORT, None, dev, cid, pin))
    _die_pin_required(st)
    if st == ERR_NOT_ALLOWED:
        die("export refused — already sealed (run after a reset)")
    if st != 0:
        die(f"export failed: {st:#x}")
    seed = ChaCha20Poly1305(key).decrypt(m[1][:12], m[1][12:], aad)
    if len(seed) != 32:
        die("unexpected seed length")
    return seed


def write_seed(dev, cid, pin, seed):
    """MSE handshake + LOAD of `seed` (re-sealed under the device's own key)."""
    key, aad = mse_handshake(dev, cid)
    nonce = os.urandom(12)
    blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, seed, aad)
    st, _ = _vendor(dev, cid, _gated(LOAD, {1: blob}, dev, cid, pin))
    _die_pin_required(st)
    if st != 0:
        die(f"restore failed: {st:#x}")


def to_bip39(seed):
    from mnemonic import Mnemonic
    return [Mnemonic("english").to_mnemonic(seed)]


def from_bip39(words):
    from mnemonic import Mnemonic
    m = Mnemonic("english")
    phrase = " ".join(words.split())
    if not m.check(phrase):
        die("invalid BIP-39 phrase (checksum failed)")
    return bytes(m.to_entropy(phrase))


def to_slip39(seed, threshold, shares):
    from shamir_mnemonic import generate_mnemonics
    return generate_mnemonics(1, [(threshold, shares)], seed, b"", 0)[0]


def from_slip39(lines):
    from shamir_mnemonic import combine_mnemonics
    return combine_mnemonics([ln.strip() for ln in lines if ln.strip()], b"")


def cmd_status(args):
    dev, cid = connect_fido()
    st, m = _vendor(dev, cid, {1: STATE})
    if st != 0:
        die(f"status failed: {st:#x}")
    if not isinstance(m, dict):
        die("malformed status response")
    # Coerce to bool so a spoofed string value can't reach the terminal raw — the
    # device is untrusted, and this output is what the operator reads to confirm the
    # anti-exfiltration seal engaged (audit run-30).
    print(f"sealed   : {bool(m.get(1))}")
    print(f"has_seed : {bool(m.get(2))}")


def cmd_export(args):
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    print("touch the device (BOOTSEL) to authorise the export…", file=sys.stderr)
    seed = read_seed(dev, cid, pin)
    mnemonics = to_bip39(seed) if args.scheme == "bip39" else to_slip39(seed, args.threshold, args.shares)
    print("\n=== WRITE THIS DOWN — the only backup of your FIDO seed ===")
    for i, mn in enumerate(mnemonics, 1):
        label = f"share {i}/{len(mnemonics)}" if len(mnemonics) > 1 else "phrase"
        print(f"\n[{label}]\n{mn}")
    if args.scheme == "slip39":
        print(f"\n(any {args.threshold} of {args.shares} shares reconstruct the seed)")
    print(f"\nAfter recording it, seal the window:  rsk backup finalize"
          + (f" --pin {args.pin}" if args.pin else ""))


def cmd_restore(args):
    if args.scheme == "bip39":
        seed = from_bip39(args.mnemonic or input("BIP-39 phrase: "))
    else:
        print("Enter SLIP-39 shares, one per line, blank line to finish:")
        lines = []
        while (ln := input()).strip():
            lines.append(ln)
        seed = from_slip39(lines)
    if len(seed) != 32:
        die(f"reconstructed secret is {len(seed)} bytes, expected 32")
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    print("touch the device (BOOTSEL) to authorise the restore…", file=sys.stderr)
    write_seed(dev, cid, pin, seed)
    print("seed restored ✓ — the FIDO identity now matches the backup")


def cmd_finalize(args):
    dev, cid = connect_fido()
    print("touch the device (BOOTSEL) to seal the export window…", file=sys.stderr)
    st, _ = _vendor(dev, cid, {1: FINALIZE})
    if st != 0:
        die(f"finalize failed: {st:#x}")
    print("export window sealed ✓ (a factory reset reopens it)")
