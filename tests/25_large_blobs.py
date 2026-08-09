#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: authenticatorLargeBlobs (0x0C) over CTAPHID_CBOR.

    nix develop -c python tests/25_large_blobs.py

Exercises the large-blob store on the device:
  1. reset + getInfo          -> options.largeBlobs True; maxSerializedLargeBlobArray
                                 (0x0B) == MAX_LARGE_BLOB_SIZE
  2. get(offset 0)            -> the 17-byte CTAP2.1 default array
  3. setPIN + getPinUvAuthTokenUsingPinWithPermissions(largeBlobWrite)
  4. set (single fragment)    -> commits; get reads the same bytes back
  5. set (two fragments)      -> the accumulator assembles + commits; get matches
  5b. set (re-commit at end)  -> CTAP1_ERR_INVALID_SEQ (0x04): a finished transfer
                                 disarms the accumulator
  6. set (bad MAC)            -> CTAP2_ERR_PIN_AUTH_INVALID (0x33)
  7. set (corrupt integrity)  -> CTAP2_ERR_INTEGRITY_FAILURE (0x3D)
  8. get (offset past end)    -> CTAP1_ERR_INVALID_PARAMETER (0x02)

Self-contained: resets at the start, asking for a replug first — CTAP 2.1 §6.6
accepts a reset only just after power-up (see replug.py). Needs `cryptography` (in
the devshell) for the PIN/UV-auth protocol-two key agreement + token HMAC.
"""
import hashlib
import os
import sys

from cryptography.hazmat.primitives import hashes, hmac as chmac

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import (  # noqa: E402
    CTAPHID_INIT,
    Protocol2,
    client_pin,
    decode,
    enc,
    find,
    read,
    send_cbor,
    write,
)

PIN = b"1234"
PERM_LBW = 0x10
LARGE_BLOBS = 0x0C
# `MAX_LARGE_BLOB_SIZE` = 2046 — crates/rsk-fido/src/consts.rs, which defines it as
# `rsk_fs::MAX_VALUE_BYTES` (the backend's per-record ceiling, KV_BUF - 2). It was a
# flat 2048 until 2026-08-04; the literal here went on asserting the old value for
# four days, and the interop allow-list rotted on the same move (scripts/check.sh).
MAX_LARGE_BLOB_SIZE = 2046
# The empty CBOR array 0x80 followed by left16(SHA-256(0x80)).
DEFAULT_BLOB = bytes.fromhex("80") + hashlib.sha256(bytes([0x80])).digest()[:16]


def token_mac(token, data):
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def lbw_param(token, offset, fragment):
    """pinUvAuthParam over 0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le ‖ sha256(fragment)."""
    vd = (
        b"\xff" * 32
        + bytes([LARGE_BLOBS, 0x00])
        + offset.to_bytes(4, "little")
        + hashlib.sha256(fragment).digest()
    )
    return token_mac(token, vd)


def valid_blob(body):
    """A serialized array: body followed by its truncated-SHA-256 integrity tag."""
    return body + hashlib.sha256(body).digest()[:16]


def lb_get(dev, cid, get, offset):
    r = send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc({1: get, 3: offset}))
    assert r[0] == 0x00, f"largeBlobs get status {r[0]:#x}"
    return decode(r[1:])[1]


def lb_set(dev, cid, token, offset, fragment, length=None):
    fields = {2: fragment, 3: offset}
    if length is not None:
        fields[4] = length
    fields[5] = lbw_param(token, offset, fragment)
    fields[6] = 2
    return send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc(fields))


def get_token(dev, cid, proto, perm):
    ph = hashlib.sha256(PIN).digest()[:16]
    tk = client_pin(dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: perm})
    assert tk[0] == 0x00, f"getPinUvAuthToken status {tk[0]:#x}"
    return proto.decrypt(decode(tk[1:])[2])


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. Clean slate, then confirm getInfo advertises large blobs.
        dev, cid = replug.reset(dev, "step 1's clean slate")
        gi = decode(send_cbor(dev, cid, bytes([0x04]))[1:])
        assert gi[4].get("largeBlobs") is True, "options.largeBlobs not advertised"
        assert gi.get(0x0B) == MAX_LARGE_BLOB_SIZE, (
            f"maxSerializedLargeBlobArray = {gi.get(0x0B)}, want {MAX_LARGE_BLOB_SIZE}"
        )
        print(f"getInfo: largeBlobs=True, maxSerializedLargeBlobArray={gi[0x0B]}")

        # 2. A fresh device returns the 17-byte default array.
        blob0 = lb_get(dev, cid, 1024, 0)
        assert blob0 == DEFAULT_BLOB, f"default blob {blob0.hex()}"
        print(f"get(default): {len(blob0)}B = {blob0.hex()}")

        # 3. PIN + a largeBlobWrite-permission token.
        ka = client_pin(dev, cid, {1: 2, 2: 2})
        proto = Protocol2(decode(ka[1:])[1][-2], decode(ka[1:])[1][-3])
        padded = PIN + b"\x00" * (64 - len(PIN))
        npe = proto.encrypt(padded)
        sp = client_pin(dev, cid, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe})
        assert sp[0] == 0x00, f"setPIN status {sp[0]:#x}"
        token = get_token(dev, cid, proto, PERM_LBW)
        print("clientPIN: token with largeBlobWrite permission")

        # 4. Single-fragment write, then read it back.
        blob = valid_blob(bytes(range(40)))
        r = lb_set(dev, cid, token, 0, blob, length=len(blob))
        assert r[0] == 0x00, f"set status {r[0]:#x}"
        got = lb_get(dev, cid, 1024, 0)
        assert got == blob, f"readback {got.hex()} != {blob.hex()}"
        print(f"set/get (single, {len(blob)}B): roundtrip OK")

        # 5. Two-fragment write (exercises the cross-message accumulator).
        big = valid_blob(bytes((i * 7) & 0xFF for i in range(200)))
        split = 120
        assert lb_set(dev, cid, token, 0, big[:split], length=len(big))[0] == 0x00, "frag1"
        # Not yet committed: the store still holds the single-fragment blob.
        assert lb_get(dev, cid, 1024, 0) == blob, "committed before completion"
        assert lb_set(dev, cid, token, split, big[split:])[0] == 0x00, "frag2"
        got = lb_get(dev, cid, 1024, 0)
        assert got == big, f"multi-fragment readback len {len(got)}"
        print(f"set/get (two fragments, {len(big)}B): assembled OK")

        # 5b. A completed transfer is terminal (audit run-28). The accumulator used to
        # stay armed at the finished total, so a zero-length fragment at that offset
        # re-entered the commit and re-ran the flash write — seven bytes on the wire,
        # and ungated on a key with no PIN.
        replay = lb_set(dev, cid, token, len(big), b"")
        assert replay[0] == 0x04, f"re-commit status {replay[0]:#x}, want 0x04"
        assert lb_get(dev, cid, 1024, 0) == big, "array changed on a rejected re-commit"
        print("set (re-commit at end offset) -> INVALID_SEQ (0x04)")

        # 6. A bad MAC is rejected.
        bad = send_cbor(
            dev,
            cid,
            bytes([LARGE_BLOBS])
            + enc({2: blob, 3: 0, 4: len(blob), 5: b"\x00" * 32, 6: 2}),
        )
        assert bad[0] == 0x33, f"bad-MAC status {bad[0]:#x}, want 0x33"
        print("set (bad MAC) -> PIN_AUTH_INVALID (0x33)")

        # 7. A corrupted integrity tag is rejected.
        corrupt = bytearray(valid_blob(bytes([0x5A] * 40)))
        corrupt[-1] ^= 0xFF
        ci = lb_set(dev, cid, token, 0, bytes(corrupt), length=len(corrupt))
        assert ci[0] == 0x3D, f"integrity status {ci[0]:#x}, want 0x3D"
        print("set (corrupt tag) -> INTEGRITY_FAILURE (0x3D)")

        # 8. Reading past the end is rejected (current array is `big`).
        past = send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc({1: 10, 3: len(big) + 1}))
        assert past[0] == 0x02, f"offset-past-end status {past[0]:#x}, want 0x02"
        print("get (offset past end) -> INVALID_PARAMETER (0x02)")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
