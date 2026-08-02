#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rescue applet test — drive the recovery/provisioning interface over PC/SC.

The rescue applet (AID A0 58 3F C1 9B 7E 4F 21) serves: SELECT identity
(MCU/product/SDK version/serial), READ 0x1E (phy record, flash stats,
secure-boot status, session time), WRITE 0x1C (phy record, time), KEYDEV_SIGN
0x10 (secp256k1 device attestation: sign / public key / certificate upload)
and REBOOT 0x1F. INS 0x1D (enable secure boot) is deliberately not implemented
(fuse-burning).

This checks all of the safe surface. The phy write uses only fields the firmware
does NOT apply at boot (LED brightness + opts) so the device's USB identity is
untouched; note it leaves that inert phy record behind (there is no delete
command). The reboot command is exercised only with --reboot (the device drops
off the bus).

    nix develop -c python tests/85_rescue.py
"""
import hashlib
import os
import sys
import time

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed, encode_dss_signature)
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

RESCUE_AID = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def parse_tlv(blob):
    out, i = {}, 0
    while i + 2 <= len(blob):
        tag, ln = blob[i], blob[i + 1]
        i += 2
        if i + ln > len(blob):
            break
        out[tag] = blob[i:i + ln]
        i += ln
    return out


def main():
    do_reboot = "--reboot" in sys.argv
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")
    conn = target.createConnection()
    conn.connect()

    def tx(cmd, what, expect=(0x90, 0x00)):
        data, sw1, sw2 = conn.transmit(cmd)
        print("%-34s -> %-32s %02X%02X" % (what, toHexString(data)[:30], sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return bytes(data)

    # ---- SELECT: identity blob ----
    data, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(RESCUE_AID)] + RESCUE_AID)
    if (sw1, sw2) == (0x6A, 0x82):
        fail("rescue AID not found — device runs firmware without the rescue applet?")
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"SELECT rescue: {sw1:02X}{sw2:02X}")
    info = bytes(data)
    print("SELECT rescue ->", toHexString(data))
    if len(info) != 12:
        fail(f"identity blob is {len(info)} bytes, want 12")
    mcu, product, vmaj, vmin = info[0], info[1], info[2], info[3]
    serial = info[4:12]
    if mcu != 1:
        fail(f"MCU {mcu}, want 1 (RP2350)")
    if product != 2:
        fail(f"product {product}, want 2 (FIDO)")
    print(f"  MCU=RP2350 product=FIDO SDK={vmaj}.{vmin} serial={serial.hex()}")

    # ---- READ secure-boot status ----
    st = tx([0x80, 0x1E, 0x03, 0x00, 0x00], "READ secure-boot status")
    if len(st) != 3 or st[0] not in (0, 1) or st[1] not in (0, 1):
        fail(f"bad status {st.hex()}")
    print(f"  enabled={st[0]} locked={st[1]} bootkey={st[2]:#04x}")

    # ---- READ flash info ----
    fi = tx([0x80, 0x1E, 0x02, 0x00, 0x00], "READ flash info")
    if len(fi) != 20:
        fail(f"flash info is {len(fi)} bytes, want 20")
    free, used, total, nfiles, size = (int.from_bytes(fi[i:i + 4], "big") for i in range(0, 20, 4))
    print(f"  free={free} used={used} total={total} nfiles={nfiles} flash={size}")
    if free + used != total or nfiles == 0 or size not in (4 * 1024 * 1024, 16 * 1024 * 1024):
        fail("flash info inconsistent")

    # ---- phy write/read (inert fields only: brightness + opts) ----
    orig = tx([0x80, 0x1E, 0x01, 0x00, 0x00], "READ phy (original)")
    blob = [0x05, 1, 0x42, 0x06, 2, 0x00, 0x08]  # brightness 0x42, opts LED_STEADY
    tx([0x80, 0x1C, 0x01, 0x00, len(blob)] + blob, "WRITE phy (brightness+opts)")
    back = tx([0x80, 0x1E, 0x01, 0x00, 0x00], "READ phy (back)")
    tlv = parse_tlv(back)
    if tlv.get(0x05) != b"\x42" or tlv.get(0x06) != b"\x00\x08":
        fail(f"phy round-trip mismatch: {back.hex()} (wrote {bytes(blob).hex()})")
    if tlv.get(0x0B) != b"\x1f":
        fail(f"expected the ITF_ALL default to materialize, got {tlv.get(0x0B)}")
    if 0x00 in parse_tlv(orig):
        # The original record carried a VIDPID — put the original back so the
        # boot-time USB identity override is preserved exactly.
        tx([0x80, 0x1C, 0x01, 0x00, len(orig)] + list(orig), "WRITE phy (restore original)")
    print(f"  phy round-trip OK (original was {orig.hex() or 'empty'})")

    # ---- time set/get ----
    now = int(time.time())
    tx([0x80, 0x1C, 0x02, 0x02, 4] + list(now.to_bytes(4, "big")), "WRITE time (unix)")
    got = tx([0x80, 0x1E, 0x04, 0x02, 0x00], "READ time (unix)")
    delta = int.from_bytes(got, "big") - now
    if not (0 <= delta <= 5):
        fail(f"unix time drift {delta}s")
    cal = tx([0x80, 0x1E, 0x04, 0x01, 0x00], "READ time (calendar)")
    t = time.gmtime(now)
    want = (t.tm_year, t.tm_mon - 1, t.tm_mday)  # wire month is 0-based (tm_mon)
    have = (int.from_bytes(cal[0:2], "big"), cal[2], cal[3])
    if len(cal) != 8 or have != want:
        fail(f"calendar {cal.hex()}: {have} != {want}")
    print(f"  time OK ({have[0]}-{have[1] + 1:02}-{have[2]:02}, wday={cal[4]})")

    # ---- keydev: pubkey, sign, verify, persistence, cert upload ----
    pub = tx([0x80, 0x10, 0x02, 0x00, 0x00], "KEYDEV public key")
    if len(pub) != 65 or pub[0] != 0x04:
        fail(f"pubkey {len(pub)} bytes, first {pub[:1].hex()}")
    digest = hashlib.sha256(b"rs-key rescue test").digest()
    sig = tx([0x80, 0x10, 0x01, 0x00, 32] + list(digest), "KEYDEV sign digest")
    if len(sig) != 64:
        fail(f"signature {len(sig)} bytes, want 64 (r||s)")
    pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pk.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    print("  secp256k1 signature verified against the device public key")
    pub2 = tx([0x80, 0x10, 0x02, 0x00, 0x00], "KEYDEV public key (again)")
    if pub2 != pub:
        fail("device key did not persist between commands")
    cert = bytes([0x30, 0x10]) + b"rescue-test-cert"
    tx([0x80, 0x10, 0x03, 0x00, len(cert)] + list(cert), "KEYDEV cert upload")

    # ---- error paths ----
    tx([0x00, 0x1E, 0x03, 0x00, 0x00], "wrong CLA", expect=(0x6E, 0x00))
    tx([0x80, 0x1D, 0x00, 0x00, 0x00], "SECURE (unimplemented)", expect=(0x6D, 0x00))
    tx([0x80, 0x10, 0x01, 0x00, 4, 1, 2, 3, 4], "sign with short digest", expect=(0x67, 0x00))
    tx([0x80, 0x1E, 0x07, 0x00, 0x00], "READ bad P1", expect=(0x6A, 0x86))

    if do_reboot:
        tx([0x80, 0x1F, 0x00, 0x00, 0x00], "REBOOT (normal)")
        print("  reboot requested — the device will re-enumerate")

    print("PASS")


if __name__ == "__main__":
    main()
