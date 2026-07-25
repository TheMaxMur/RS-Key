#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: authenticatorSelection / authenticatorConfig / authenticatorReset.

    nix develop -c python tests/22_config_reset.py

  1. selection                         -> CTAP2_OK
  2. clientPIN getPinUvAuthToken (0x09) with the acfg permission
  3. config setMinPINLength(8)         -> OK; lowering to 4 -> PIN_POLICY_VIOLATION;
                                          no pinUvAuthParam -> PUAT_REQUIRED
  4. reset                             -> wipes the PIN (getInfo clientPin -> false)

Self-contained: sets a PIN, then resets it, so it leaves the device clean and is
idempotent. Needs `cryptography` (in the devshell). Asks for a replug before each
reset — CTAP 2.1 §6.6 accepts one only just after power-up (see replug.py).
"""
import hashlib
import os
import sys

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
from cryptography.hazmat.primitives import hashes, hmac as chmac  # noqa: E402

# 8 chars: setMinPINLength(8) must not force a PIN change (which would reset the
# token), so the same token can drive the follow-up config calls.
PIN = b"12345678"
PERM_ACFG = 0x20


def token_mac(token, data):
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def config_request(subcmd, subpara, token):
    """authenticatorConfig params, MAC over 0xff×32 ‖ 0x0d ‖ subcmd ‖ subpara."""
    vp = b"\xff" * 32 + bytes([0x0D, subcmd]) + subpara
    mac = token_mac(token, vp)
    req = bytearray([0xA0 | (4 if subpara else 3)])
    req += bytes([0x01, subcmd])
    if subpara:
        req += bytes([0x02]) + subpara
    req += bytes([0x03, 0x02])  # pinUvAuthProtocol = 2
    req += bytes([0x04, 0x58, len(mac)]) + mac
    return bytes(req)


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. authenticatorSelection (0x0B).
        sel = send_cbor(dev, cid, bytes([0x0B]))
        assert sel[0] == 0x00, f"selection status {sel[0]:#x}"
        print("selection: OK")

        # Clean slate: a prior run may have left a PIN, so reset before setting ours.
        dev, cid = replug.reset(dev, "the clean-slate reset")

        # 2. clientPIN: key agreement, setPIN, getPinUvAuthToken with acfg permission.
        ka = client_pin(dev, cid, {1: 2, 2: 2})
        cose = decode(ka[1:])[1]
        proto = Protocol2(cose[-2], cose[-3])
        padded = PIN + b"\x00" * (64 - len(PIN))
        npe = proto.encrypt(padded)
        sp = client_pin(dev, cid, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe})
        assert sp[0] in (0x00, 0x30), f"setPIN status {sp[0]:#x}"
        ph = hashlib.sha256(PIN).digest()[:16]
        tk = client_pin(dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: PERM_ACFG})
        assert tk[0] == 0x00, f"getPinUvAuthToken status {tk[0]:#x}"
        token = proto.decrypt(decode(tk[1:])[2])
        print("clientPIN: token with acfg permission")

        # 3. authenticatorConfig setMinPINLength.
        ok = send_cbor(dev, cid, bytes([0x0D]) + config_request(0x03, enc({1: 8}), token))
        assert ok[0] == 0x00, f"setMinPINLength status {ok[0]:#x}"
        low = send_cbor(dev, cid, bytes([0x0D]) + config_request(0x03, enc({1: 4}), token))
        assert low[0] == 0x37, f"expected PIN_POLICY_VIOLATION (0x37), got {low[0]:#x}"
        nop = send_cbor(dev, cid, bytes([0x0D]) + bytes([0xA1, 0x01, 0x03]))  # {1:3}, no param
        assert nop[0] == 0x36, f"expected PUAT_REQUIRED (0x36), got {nop[0]:#x}"
        print("config: setMinPINLength(8) OK, lower->0x37, no-param->0x36")

        # 4. authenticatorReset wipes the PIN.
        dev, cid = replug.reset(dev, "step 4's reset")
        gi = send_cbor(dev, cid, bytes([0x04]))
        assert gi[0] == 0x00
        assert decode(gi[1:])[4]["clientPin"] is False, "PIN survived reset"
        print("reset: OK, clientPin -> False")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
