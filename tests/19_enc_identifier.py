#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: getInfo's encIdentifier (0x19) over CTAPHID_CBOR.

    nix develop -c python tests/19_enc_identifier.py

CTAP 2.2 0x19 lets a platform holding the *persistent* pinUvAuthToken recognise
the device again, while telling an unauthorised caller nothing. The host tests
cover the construction; only the stack can show that the value a platform
actually receives is the one it can actually open, so this drives the real
acquisition path — clientPIN **protocol two**, `getPinUvAuthTokenUsingPin-
WithPermissions` with the `pcmr` permission (0x40) — and then decrypts.

  1. reset + no token yet         -> 0x19 absent
  2. PIN, then a pcmr token       -> 0x19 present, exactly 32 bytes
  3. two getInfo calls in a row   -> different bytes AND different IVs
  4. decrypt both under the token -> the same identifier, twice
  5. that identifier              -> not zero, not the AAGUID, not the token

Step 3 and step 4 only mean something together: differing bytes alone are what a
random blob does, and a stable plaintext alone is what a fingerprint does.
Self-contained and idempotent: resets at the start. Needs `cryptography`.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import Protocol2, client_pin, decode, enc, send_cbor  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402

PIN = b"12345678"
PERM_PCMR = 0x40  # persistent credential management, read-only (CTAP 2.2)
ENC_IDENTIFIER = 0x19
ENC_IDENTIFIER_LEN = 32  # iv(16) ‖ one AES-128-CBC block(16)


def get_info(dev, cid):
    r = send_cbor(dev, cid, b"\x04")
    assert r[0] == 0x00, f"getInfo status {r[0]:#x}"
    info = decode(r[1:])
    assert isinstance(info, dict), f"getInfo must decode to a map, got {type(info)}"
    return info


def open_identifier(token, blob):
    """Recover the identifier exactly as the spec says a platform must."""
    key = HKDF(
        algorithm=hashes.SHA256(), length=16, salt=b"\x00" * 32, info=b"encIdentifier"
    ).derive(token)
    dec = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    return dec.update(blob[16:]) + dec.finalize()


def main():
    dev, cid = replug.reset(None, "a clean slate for encIdentifier")
    try:
        info = get_info(dev, cid)
        assert ENC_IDENTIFIER not in info, (
            "0x19 must be absent before any persistent token exists — it is keyed "
            "by that token, so there is nothing to encrypt under"
        )
        aaguid = info[0x03]
        print("1. no persistent token yet: 0x19 absent, as it must be")

        ka = client_pin(dev, cid, {1: 2, 2: 2})
        cose = decode(ka[1:])[1]
        proto = Protocol2(cose[-2], cose[-3])
        padded = PIN + b"\x00" * (64 - len(PIN))
        npe = proto.encrypt(padded)
        sp = client_pin(
            dev, cid, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe}
        )
        assert sp[0] in (0x00, 0x33), f"setPIN status {sp[0]:#x}"
        ph = hashlib.sha256(PIN).digest()[:16]
        tk = client_pin(
            dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: PERM_PCMR}
        )
        assert tk[0] == 0x00, f"getPinUvAuthToken(pcmr) status {tk[0]:#x}"
        token = proto.decrypt(decode(tk[1:])[2])
        print(f"2. pcmr token acquired over PIN protocol two ({len(token)} bytes)")

        first = get_info(dev, cid).get(ENC_IDENTIFIER)
        second = get_info(dev, cid).get(ENC_IDENTIFIER)
        assert first is not None, "0x19 must appear once a persistent token exists"
        assert len(first) == ENC_IDENTIFIER_LEN, f"0x19 is {len(first)} bytes, want 32"
        print(f"   0x19 present, {len(first)} bytes")

        assert first != second, "a repeated blob would be a device fingerprint"
        assert first[:16] != second[:16], "the IV must be regenerated per getInfo"
        print("3. two calls differ, and so do their IVs")

        one, two = open_identifier(token, first), open_identifier(token, second)
        assert one == two, "the same device must decrypt to the same identifier"
        print(f"4. both decrypt to one identifier: {one.hex()}")

        assert one != b"\x00" * 16, "an all-zero identifier identifies nothing"
        assert one != aaguid, "the AAGUID is public and identical across RS-Keys"
        assert one not in (token[:16], token[16:]), "must not expose the token"
        print("5. identifier is not zero, not the AAGUID, not the token")
    finally:
        dev.close()
    print("\nPASS")


if __name__ == "__main__":
    main()
