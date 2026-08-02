#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OTP-MKEK migration test — two-phase, over PC/SC (pyscard).

Validates the kbase migration end-to-end on real hardware WITHOUT touching a
fuse, using a FAKE_MKEK/FAKE_DEVK test build (firmware/build.rs knobs):

  phase 1 — on the CURRENT (no-OTP) firmware:
      ./tests/90_otp_mkek_migration.py pre
    Records the rescue keydev public key and the PIV 9A public key (generating
    the 9A key with the default management key if absent) into /tmp/otp_mkek_state.json.
    Running this against the current firmware also sanity-checks the harness.

  phase 2 — after flashing the FAKE-key build
      (nix develop -c env FAKE_MKEK=<64hex> [FAKE_DEVK=<64hex>] \
           cargo build --release -p firmware --no-default-features):
      ./tests/90_otp_mkek_migration.py post [--devk <64hex>] [--pw3 <pin>] [--piv-pin <pin>]
    Checks, in order:
      * rescue keydev: with --devk, the reported public key must be the one
        derived from that scalar (proves the otp_key_2 branch); without --devk,
        it must EQUAL the phase-1 key (proves the 32B→33B flash re-seal kept it).
      * PIV: the 9A public key must equal phase 1 (boot-pass GCM re-seal kept
        the slot), and with --piv-pin the slot signs (PIN verifier fallback).
      * OpenPGP: with --pw3, VERIFY must succeed twice (first = the lazy
        fallback migration, second = the re-stored OTP-arm verifier).

    PINs are NEVER tried unless explicitly passed — a wrong guess burns retries
    on a personalised board. The FIDO clientPIN fallback is covered by host
    tests + the existing FIDO suites against the fake build.

Run with the validation venv python (pyscard + cryptography):
    nix develop -c python tests/90_otp_mkek_migration.py pre
"""
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed, encode_dss_signature)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

RESCUE_AID = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]
PIV_AID = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]
OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
STATE = "/tmp/otp_mkek_state.json"
# PIV default management key: AES-192 (algo 0x0A), 0x0102…08 repeated three times.
DEFAULT_MGM = bytes([1, 2, 3, 4, 5, 6, 7, 8] * 3)
MGM_ALGO = 0x0A


def tlv(tag, value):
    if len(value) < 0x80:
        ln = bytes([len(value)])
    elif len(value) < 0x100:
        ln = bytes([0x81, len(value)])
    else:
        ln = bytes([0x82, len(value) >> 8, len(value) & 0xFF])
    return bytes([tag]) + ln + bytes(value)


def tlv_find(data, tag):
    """First value for `tag` in a flat BER-TLV blob (1-byte tags, short/long len)."""
    i = 0
    data = bytes(data)
    while i < len(data):
        t = data[i]
        i += 1
        ln = data[i]
        i += 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(data[i:i + nb], "big")
            i += nb
        if t == tag:
            return data[i:i + ln]
        i += ln
    return None


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def connect():
    # Marker required: this migrates the OTP kbase, so it must not run on a stranger.
    target = find_reader(require_marker=True)
    if not target:
        fail("no RSK reader (device plugged in? pcscd up? scdaemon holding it?)")
    conn = target.createConnection()
    conn.connect()
    return conn


def tx(conn, cmd, what, expect=(0x90, 0x00)):
    data, sw1, sw2 = conn.transmit(list(cmd))
    if expect is not None and (sw1, sw2) != expect:
        fail(f"{what}: SW {sw1:02X}{sw2:02X}")
    return bytes(data), (sw1, sw2)


def select_aid(conn, aid, what):
    return tx(conn, [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid), f"SELECT {what}")


def keydev_pubkey(conn):
    select_aid(conn, RESCUE_AID, "rescue")
    data, _ = tx(conn, [0x80, 0x10, 0x02, 0x00, 0x00], "KEYDEV pubkey")
    if len(data) != 65 or data[0] != 0x04:
        fail(f"keydev pubkey shape: {len(data)} bytes")
    return data


def keydev_sign_check(conn, pub_sec1):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"otp-mkek keydev migration probe")
    dgst = digest.finalize()
    data, _ = tx(conn, [0x80, 0x10, 0x01, 0x00, 32] + list(dgst), "KEYDEV sign")
    if len(data) != 64:
        fail(f"keydev sig shape: {len(data)}")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_sec1)
    sig = encode_dss_signature(int.from_bytes(data[:32], "big"),
                               int.from_bytes(data[32:], "big"))
    pub.verify(sig, dgst, ec.ECDSA(Prehashed(hashes.SHA256())))


def piv_mgm_auth(conn):
    # Mutual-auth witness dance with the default AES-192 management key (algo 0x0A).
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    req = tlv(0x7C, tlv(0x80, b""))
    data, _ = tx(conn, [0x00, 0x87, MGM_ALGO, 0x9B, len(req)] + list(req),
                 "PIV mgm witness")
    wit = tlv_find(tlv_find(data, 0x7C), 0x80)
    if not wit or len(wit) != 16:
        fail(f"PIV witness shape ({0 if not wit else len(wit)} bytes)")
    dec = Cipher(algorithms.AES(DEFAULT_MGM), modes.ECB()).decryptor()
    witness = dec.update(bytes(wit)) + dec.finalize()
    challenge = os.urandom(16)
    body = tlv(0x7C, tlv(0x80, witness) + tlv(0x81, challenge) + tlv(0x82, b""))
    data, _ = tx(conn, [0x00, 0x87, MGM_ALGO, 0x9B, len(body)] + list(body),
                 "PIV mgm response")
    enc_chal = tlv_find(tlv_find(data, 0x7C), 0x82)
    enc = Cipher(algorithms.AES(DEFAULT_MGM), modes.ECB()).encryptor()
    if not enc_chal or bytes(enc_chal) != enc.update(challenge) + enc.finalize():
        fail("PIV mutual auth mismatch")


def piv_pubkey_9a(conn, generate_if_absent):
    select_aid(conn, PIV_AID, "PIV")
    # GET METADATA 9A → tag 0x04 holds the public-key template (0x86 = EC point).
    data, sw = tx(conn, [0x00, 0xF7, 0x00, 0x9A, 0x00], "PIV metadata 9A",
                  expect=None)
    if sw == (0x6A, 0x88) or sw == (0x6A, 0x82):
        if not generate_if_absent:
            fail("PIV 9A empty — run phase `pre` first")
        piv_mgm_auth(conn)
        tmpl = [0xAC, 0x03, 0x80, 0x01, 0x11]  # ECCP256
        data, _ = tx(conn, [0x00, 0x47, 0x00, 0x9A, len(tmpl)] + tmpl,
                     "PIV generate 9A")
        # 7F49 … 86 41 <65-byte point>
        idx = bytes(data).find(b"\x86\x41")
        if idx < 0:
            fail("PIV generate response lacks the point")
        return bytes(data[idx + 2:idx + 2 + 65])
    if sw != (0x90, 0x00):
        fail(f"PIV metadata 9A: SW {sw[0]:02X}{sw[1]:02X}")
    idx = bytes(data).find(b"\x86\x41")
    if idx < 0:
        fail("PIV metadata lacks the point")
    return bytes(data[idx + 2:idx + 2 + 65])


def piv_sign_check(conn, pin, pub_sec1):
    padded = pin.encode().ljust(8, b"\xff")
    tx(conn, [0x00, 0x20, 0x00, 0x80, 8] + list(padded), "PIV VERIFY")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"otp-mkek piv migration probe")
    dgst = digest.finalize()
    body = tlv(0x7C, tlv(0x82, b"") + tlv(0x81, dgst))
    data, _ = tx(conn, [0x00, 0x87, 0x11, 0x9A, len(body)] + list(body),
                 "PIV sign 9A")
    der = tlv_find(tlv_find(data, 0x7C), 0x82)
    if not der:
        fail("PIV sign response shape")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(pub_sec1))
    pub.verify(bytes(der), dgst, ec.ECDSA(Prehashed(hashes.SHA256())))


def openpgp_verify_pw3(conn, pw3):
    select_aid(conn, OPENPGP_AID, "OpenPGP")
    pin = list(pw3.encode())
    tx(conn, [0x00, 0x20, 0x00, 0x83, len(pin)] + pin, "OpenPGP VERIFY PW3 (fallback)")
    # Again: must now hit the re-stored OTP-arm verifier directly.
    tx(conn, [0x00, 0x20, 0x00, 0x83, len(pin)] + pin, "OpenPGP VERIFY PW3 (direct)")


def arg_value(flag):
    if flag in sys.argv:
        return sys.argv[sys.argv.index(flag) + 1]
    return None


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("pre", "post"):
        sys.exit(__doc__)
    phase = sys.argv[1]
    conn = connect()

    if phase == "pre":
        kd = keydev_pubkey(conn)
        keydev_sign_check(conn, kd)
        piv = piv_pubkey_9a(conn, generate_if_absent=True)
        with open(STATE, "w") as f:
            json.dump({"keydev": kd.hex(), "piv9a": piv.hex()}, f)
        print(f"keydev pubkey: {kd.hex()[:24]}…")
        print(f"PIV 9A pubkey: {piv.hex()[:24]}…")
        print(f"state → {STATE}")
        print("PRE OK — flash the FAKE-key build, then run `post`")
        return

    try:
        with open(STATE) as f:
            state = json.load(f)
    except FileNotFoundError:
        fail("no phase-1 state — run `pre` on the no-OTP firmware first")

    # Rescue keydev: DEVK branch or flash re-seal continuity.
    kd = keydev_pubkey(conn)
    devk_hex = arg_value("--devk")
    if devk_hex:
        priv = ec.derive_private_key(int(devk_hex, 16), ec.SECP256K1())
        expect = priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        if kd != expect:
            fail("keydev pubkey != FAKE_DEVK pubkey — otp_key_2 branch not taken")
        print("keydev = FAKE_DEVK scalar ✓ (otp_key_2 branch)")
    else:
        if kd.hex() != state["keydev"]:
            fail("keydev pubkey changed — flash re-seal lost the key")
        print("keydev pubkey unchanged ✓ (32B→33B re-seal)")
    keydev_sign_check(conn, kd)
    print("keydev signs ✓")

    # PIV: slot survived the boot-pass GCM re-seal.
    piv = piv_pubkey_9a(conn, generate_if_absent=False)
    if piv.hex() != state["piv9a"]:
        fail("PIV 9A pubkey changed — sealed-slot migration lost the key")
    print("PIV 9A pubkey unchanged ✓ (sealed-slot re-seal)")
    piv_pin = arg_value("--piv-pin")
    if piv_pin:
        piv_sign_check(conn, piv_pin, piv)
        print("PIV 9A signs after PIN fallback ✓")

    pw3 = arg_value("--pw3")
    if pw3:
        openpgp_verify_pw3(conn, pw3)
        print("OpenPGP PW3 fallback + direct verify ✓")

    print("PASS")


if __name__ == "__main__":
    main()
