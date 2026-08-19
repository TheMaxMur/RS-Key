#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: the vendor-facilitated (type 1) enterprise-attestation RP list.

    nix develop -c python tests/18_enterprise_rpids.py
    python tests/emu.py tests/18_enterprise_rpids.py     # no board

  1. clean slate, PIN, acfg token, enableEnterpriseAttestation
  2. type-1 makeCredential with an EMPTY list       -> no `ep` (today's behaviour)
  3. write the list, type-1 for a listed RP         -> `ep` = true
  4. ...and for an unlisted one                     -> still no `ep`
  5. power cycle, repeat 3                          -> the list is in flash
  6. nine rp ids                                    -> 0x28, previous list intact
  7. clear the list, repeat 3                       -> back to no `ep`
  8. reset, leaving the device clean

Self-contained and idempotent: it resets at both ends. Needs `cryptography`.
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

PIN = b"12345678"
PERM_ACFG = 0x20
CTAP_CONFIG = 0x0D
CONFIG_ENABLE_EA = 0x01
CONFIG_VENDOR = 0xFF
# consts::CONFIG_EA_RPIDS / MAX_EA_RPIDS.
CONFIG_EA_RPIDS = 0x0E6841934E719BE7
MAX_EA_RPIDS = 8
KEY_STORE_FULL = 0x28
LISTED = "listed.example"
UNLISTED = "unlisted.example"


def config(dev, cid, subcmd, subpara, token):
    """authenticatorConfig, MAC over 0xff×32 ‖ 0x0d ‖ subcmd ‖ subpara. `subcmd`
    goes through `enc` because 0xFF is the CBOR break marker, not the integer."""
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(b"\xff" * 32 + bytes([CTAP_CONFIG, subcmd]) + subpara)
    req = bytearray([0xA0 | (4 if subpara else 3)])
    req += bytes([0x01]) + enc(subcmd)
    if subpara:
        req += bytes([0x02]) + subpara
    req += bytes([0x03, 0x02])  # pinUvAuthProtocol = 2
    req += bytes([0x04, 0x58, 32]) + h.finalize()
    return send_cbor(dev, cid, bytes([CTAP_CONFIG]) + bytes(req))[0]


def set_rpids(dev, cid, token, ids):
    return config(dev, cid, CONFIG_VENDOR,
                  enc({1: CONFIG_EA_RPIDS, 4: list(ids)}), token)


def has_ep(dev, cid, rp_id):
    """makeCredential with enterpriseAttestation 1 — did the device call it one?"""
    req = bytes([0x01]) + enc({
        1: hashlib.sha256(b"rs-key ea test").digest(),
        2: {"id": rp_id},
        3: {"id": b"\x01\x02\x03\x04", "name": "alice"},
        4: [{"alg": -7, "type": "public-key"}],
        10: 1,
    })
    r = send_cbor(dev, cid, req)
    assert r[0] == 0x00, f"makeCredential({rp_id}) status {r[0]:#x}"
    m = decode(r[1:])
    assert isinstance(m, dict), f"makeCredential answered {type(m).__name__}, not a map"
    return m.get(4) is True


def acfg_token(dev, cid, set_pin=False):
    """A fresh acfg token. Every config write needs one of its own: a makeCredential
    in between clears the token's permissions, and the next write answers 0x33."""
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    if set_pin:
        npe = proto.encrypt(PIN + b"\x00" * (64 - len(PIN)))
        sp = client_pin(dev, cid,
                        {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe})
        assert sp[0] == 0x00, f"setPIN status {sp[0]:#x}"
    ph = hashlib.sha256(PIN).digest()[:16]
    tk = client_pin(dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: PERM_ACFG})
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

        # 1. Clean slate: a prior run may have left a PIN and a list.
        dev, cid = replug.reset(dev, "the clean-slate reset")
        token = acfg_token(dev, cid, set_pin=True)
        assert config(dev, cid, CONFIG_ENABLE_EA, b"", token) == 0x00, "enableEA failed"
        print("setup: PIN, acfg token, enterprise attestation enabled")

        # 2. An empty list qualifies nobody — what an upgraded device reads.
        assert not has_ep(dev, cid, LISTED), "empty list must not grant type-1 EA"
        print("empty list: no `ep`")

        # 3./4. Write the list; only what is on it qualifies.
        token = acfg_token(dev, cid)
        st = set_rpids(dev, cid, token, [LISTED])
        assert st == 0x00, f"set-rpids status {st:#x}"
        assert has_ep(dev, cid, LISTED), "a listed RP must get `ep`"
        assert not has_ep(dev, cid, UNLISTED), "an unlisted RP must not get `ep`"
        print(f"list [{LISTED}]: `ep` for it, none for {UNLISTED}")

        # 5. Real power, and the token dies with it — the list must not.
        dev, cid, _ = replug.power_cycle(dev, "the persistence check")
        assert has_ep(dev, cid, LISTED), "the list must survive a power cycle"
        print("power cycle: the list is still there")

        # 6. One past the bound is refused, and refusing leaves the list alone.
        too_many = [f"rp{i}.example" for i in range(MAX_EA_RPIDS + 1)]
        st = set_rpids(dev, cid, acfg_token(dev, cid), too_many)
        assert st == KEY_STORE_FULL, f"expected KEY_STORE_FULL ({KEY_STORE_FULL:#x}), got {st:#x}"
        assert has_ep(dev, cid, LISTED), "a refused write must not disturb the stored list"
        assert not has_ep(dev, cid, too_many[0]), "a refused write must store nothing"
        print(f"{len(too_many)} rp ids: refused 0x28, previous list intact")

        # 7. The clear.
        st = set_rpids(dev, cid, acfg_token(dev, cid), [])
        assert st == 0x00, f"clear status {st:#x}"
        assert not has_ep(dev, cid, LISTED), "a cleared list must qualify nobody"
        print("cleared: no `ep`")

        # 8. Leave the device as we found it.
        replug.reset(dev, "the cleanup reset")
        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
