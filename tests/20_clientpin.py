#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""clientPIN over CTAPHID_CBOR (PIN/UV-auth protocol two).

Runs the platform side of CTAP2 clientPIN against the device:
  1. getKeyAgreement      -> the authenticator's ephemeral P-256 public key
  2. ECDH + HKDF          -> the protocol-two shared secret (HMAC + AES keys)
  3. setPIN("1234")       -> stores the PIN (idempotent: NotAllowed = already set)
  4. getPinToken("1234")  -> decrypts the 32-byte pinUvAuthToken
  5. getPINRetries        -> 8 after a correct PIN
  6. getPinToken(wrong)   -> CTAP2_ERR_PIN_INVALID (0x31); retries drop to 7

A clean device is assumed (flash rsk-wipe first); a second run reuses the PIN.
Needs `cryptography` (in the devshell) for P-256 ECDH / AES-CBC / HMAC.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaphid import (  # noqa: E402
    CTAPHID_INIT,
    Protocol2,
    client_pin,
    decode,
    find,
    get_retries,
    hid,
    read,
    write,
)

PIN = b"1234"


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. getKeyAgreement -> authenticator ephemeral public key.
        ka = client_pin(dev, cid, {1: 2, 2: 2})
        assert ka[0] == 0x00, f"getKeyAgreement status {ka[0]:#x}"
        cose = decode(ka[1:])[1]
        assert cose[1] == 2 and cose[3] == -25 and cose[-1] == 1, "unexpected COSE key"
        proto = Protocol2(cose[-2], cose[-3])
        print(f"keyAgreement: authenticator pubkey x={cose[-2][:4].hex()}…")

        # 2. setPIN (idempotent: a prior run leaves it set).
        padded = PIN + b"\x00" * (64 - len(PIN))
        new_pin_enc = proto.encrypt(padded)
        params = {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(new_pin_enc), 5: new_pin_enc}
        sp = client_pin(dev, cid, params)
        # 0x33 = PIN_AUTH_INVALID, what CTAP 2.1 §6.5.5.5 returns when a PIN is
        # already set (changePIN is the only way to replace one).
        if sp[0] == 0x33:
            print("setPIN: already set (reusing PIN '1234')")
        else:
            assert sp[0] == 0x00, f"setPIN status {sp[0]:#x}"
            print("setPIN: ok")

        # 3. getPinToken with the correct PIN -> 32-byte token.
        ph = hashlib.sha256(PIN).digest()[:16]
        tok = client_pin(dev, cid, {1: 2, 2: 5, 3: proto.cose(), 6: proto.encrypt(ph)})
        assert tok[0] == 0x00, f"getPinToken status {tok[0]:#x}"
        token = proto.decrypt(decode(tok[1:])[2])
        assert len(token) == 32, f"token len {len(token)}"
        print(f"getPinToken: token={token[:4].hex()}… ({len(token)}B)")

        # 4. A correct PIN resets the retry counter to the maximum (8).
        r_ok = get_retries(dev, cid)
        assert r_ok == 8, f"retries after correct PIN = {r_ok}, want 8"
        print(f"getPINRetries: {r_ok}")

        # 5. A wrong PIN is rejected and decrements the counter.
        bad = client_pin(dev, cid, {1: 2, 2: 5, 3: proto.cose(), 6: proto.encrypt(b"\x00" * 16)})
        assert bad[0] == 0x31, f"wrong PIN status {bad[0]:#x}, want 0x31 (PIN_INVALID)"
        r_bad = get_retries(dev, cid)
        assert r_bad == 7, f"retries after wrong PIN = {r_bad}, want 7"
        print(f"wrong PIN -> PIN_INVALID, retries {r_ok} -> {r_bad}")

        print("\nclientPIN PASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
