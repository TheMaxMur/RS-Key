#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: U2F register + authenticate over CTAPHID_MSG (CTAP1).

    nix develop -c python tests/13_u2f.py

Runs a U2F registration (INS 0x01) then two authentications (INS 0x02) with the
returned key handle, checking response structure and counter increment. The
registration signature is verified under the attestation cert's public key.
"""
import hashlib
import os
import sys

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find  # noqa: E402

REPORT_LEN = 64
CTAPHID_INIT = 0x86
CTAPHID_MSG = 0x83

APP_ID = hashlib.sha256(b"https://example.com").digest()
CHAL = hashlib.sha256(b"rs-key u2f challenge").digest()


def write(dev, payload):
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev):
    return bytes(dev.read(REPORT_LEN, 3000))


def send_msg(dev, cid, apdu):
    """Send an APDU as a CTAPHID_MSG and reassemble the response."""
    n = len(apdu)
    write(dev, cid + bytes([CTAPHID_MSG, n >> 8, n & 0xFF]) + apdu[:57])
    off, seq = 57, 0
    while off < n:
        write(dev, cid + bytes([seq]) + apdu[off:off + 59])
        off, seq = off + 59, seq + 1
    r = read(dev)
    while len(r) >= 5 and r[4] == 0xBB:  # CTAPHID_KEEPALIVE: still processing
        r = read(dev)
    assert r[4] == CTAPHID_MSG, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    while len(data) < bcnt:
        c = read(dev)
        data += c[5:5 + min(59, bcnt - len(data))]
    return bytes(data[:bcnt])


def ext_apdu(ins, p1, data):
    return bytes([0x00, ins, p1, 0x00, 0x00, len(data) >> 8, len(data) & 0xFF]) + data + b"\x00\x00"


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # --- U2F version ---
        ver = send_msg(dev, cid, ext_apdu(0x03, 0x00, b""))
        assert ver[-2:] == b"\x90\x00" and ver[:-2] == b"U2F_V2", f"version: {ver!r}"

        # --- register --- (request is challenge ‖ application, per the U2F spec)
        reg = send_msg(dev, cid, ext_apdu(0x01, 0x00, CHAL + APP_ID))
        assert reg[-2:] == b"\x90\x00", f"register SW {reg[-2:].hex()}"
        body = reg[:-2]
        assert body[0] == 0x05, f"register id {body[0]:#x}"
        assert body[1] == 0x04, "public key must be uncompressed"
        pub_key = body[1:66]
        kh_len = body[66]
        assert kh_len == 64, f"key handle len {kh_len}"
        key_handle = body[67:67 + kh_len]
        rest = body[67 + kh_len:]
        assert rest[0] == 0x30, "attestation cert (SEQUENCE) missing"
        cert_len = 4 + ((rest[2] << 8) | rest[3]) if rest[1] == 0x82 else 2 + rest[1]
        cert_der, reg_sig = rest[:cert_len], rest[cert_len:]

        # Verify the attestation signature under the cert's key, over
        # 0x00 ‖ application ‖ challenge ‖ keyHandle ‖ pubKey (note: the sign base
        # puts application before challenge, the reverse of the request order).
        cert_key = load_der_x509_certificate(cert_der).public_key()
        sign_base = b"\x00" + APP_ID + CHAL + key_handle + pub_key
        cert_key.verify(reg_sig, sign_base, ec.ECDSA(hashes.SHA256()))
        print(f"registered: pubkey=65B keyHandle={kh_len}B (attestation sig verified)")

        # --- authenticate twice; counter must increment ---
        def authenticate():
            data = CHAL + APP_ID + bytes([len(key_handle)]) + key_handle
            a = send_msg(dev, cid, ext_apdu(0x02, 0x03, data))  # 0x03 = enforce-user-presence
            assert a[-2:] == b"\x90\x00", f"auth SW {a[-2:].hex()}"
            body = a[:-2]
            assert body[0] & 0x01 == 0x01, f"TUP flag missing ({body[0]:#x})"
            ctr = int.from_bytes(body[1:5], "big")
            return ctr, len(body) - 5

        c1, siglen = authenticate()
        c2, _ = authenticate()
        print(f"authenticated: sig={siglen}B counter {c1} -> {c2}")
        assert c2 > c1, f"counter did not increment ({c1} -> {c2})"

        # check-only on a valid handle → SW 0x6985 (conditions not satisfied).
        chk = send_msg(dev, cid, ext_apdu(0x02, 0x07, CHAL + APP_ID + bytes([len(key_handle)]) + key_handle))
        assert chk[-2:] == b"\x69\x85", f"check-only SW {chk[-2:].hex()} (want 6985)"

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
