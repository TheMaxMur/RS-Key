#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: the alwaysUv arm of §6.1.2's token-less makeCredential gate.

    nix develop -c python tests/16_always_uv_gate.py --pin <PIN>

With `alwaysUv` on and no built-in UV pad, a makeCredential carrying no
pinUvAuthParam is refused PUAT_REQUIRED **whatever `rk` says** (§6.1.2 steps
6.2/6.4, `crates/rsk-fido/src/makecredential.rs:537-538`). That is the half of the
gate `makeCredUvNotRqd` does not reach: step 10 turns on `rk`, step 6 does not.

`28_ctap_spec_alignment.py` asserts the `rk` = false case at the protocol level
already. This suite exists because 28 cannot go in the phase-4 recording — it
walks credentialManagement and takes a downstream refusal the trace mapper
deliberately refuses to map — and without a recording of this arm the model's
gate rule was `pin.set /\\ rk`, which predicts *served* here. It was refuted by
the first session that recorded it (formal/README.md, phase 4).

Needs a PIN already set and leaves alwaysUv off again; nothing else changes.
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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

GET_INFO, MAKE_CRED, AUTH_CONFIG = 0x04, 0x01, 0x0D
TOGGLE_ALWAYS_UV = 0x02
PERM_ACFG = 0x20
PUAT_REQUIRED = 0x36
RP_ID = "always-uv.example"


def ordered(d):
    """CTAP request maps need strictly ascending integer keys."""
    return {k: d[k] for k in sorted(d)}


def token_mac(token, data):
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def acfg_token(dev, cid, pin):
    """A fresh pinUvAuthToken carrying only `acfg`. One per config op: a spent
    token answers PIN_AUTH_INVALID on the next one (§6.5.5.7)."""
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    ph = hashlib.sha256(pin).digest()[:16]
    tk = client_pin(dev, cid, ordered(
        {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: PERM_ACFG}
    ))
    assert tk[0] == 0x00, f"getPinUvAuthToken status {tk[0]:#x}"
    return proto.decrypt(decode(tk[1:])[2])


def toggle_always_uv(dev, cid, pin):
    token = acfg_token(dev, cid, pin)
    body = b"\xff" * 32 + bytes([AUTH_CONFIG, TOGGLE_ALWAYS_UV])
    req = {1: TOGGLE_ALWAYS_UV, 3: 2, 4: token_mac(token, body)}
    r = send_cbor(dev, cid, bytes([AUTH_CONFIG]) + enc(ordered(req)))
    assert r[0] == 0x00, f"toggleAlwaysUv status {r[0]:#x}"


def always_uv(dev, cid):
    gi = send_cbor(dev, cid, bytes([GET_INFO]))
    assert gi[0] == 0x00, f"getInfo status {gi[0]:#x}"
    return decode(gi[1:])[4].get("alwaysUv")


def tokenless_make_credential(dev, cid, rk, user_id):
    req = {
        1: os.urandom(32),
        2: {"id": RP_ID},
        3: {"id": user_id, "name": "u"},
        4: [{"alg": -7, "type": "public-key"}],
    }
    if rk:
        req[7] = {"rk": True}
    return send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(ordered(req)))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", required=True, help="the device's FIDO2 PIN")
    args = ap.parse_args()
    pin = args.pin.encode()

    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        assert always_uv(dev, cid) is False, "start with alwaysUv off"
        # Inside the `try`, and the restore below wrapped: leaving the key with
        # alwaysUv on is not a failed test, it is the next three suites of the
        # phase-4 recording silently running under a different policy.
        try:
            toggle_always_uv(dev, cid, pin)
            assert always_uv(dev, cid) is True, "alwaysUv did not engage"
            print("alwaysUv on")

            # `rk=False` is the diagnostic row: with a PIN set, step 10 already
            # refuses `rk=True` whether alwaysUv is on or not, so only this one
            # tells step 6.4 from step 10. `rk=True` is the control beside it.
            for rk in (False, True):
                sw = tokenless_make_credential(dev, cid, rk, b"\xA0" + bytes([rk]) * 3)
                assert sw == PUAT_REQUIRED, \
                    f"token-less makeCredential rk={rk} status {sw:#x}, want 0x36"
                print(f"token-less makeCredential rk={rk} -> PUAT_REQUIRED (0x36)")
        finally:
            try:
                toggle_always_uv(dev, cid, pin)
            except AssertionError as error:
                print(f"restore attempt failed: {error}")
            if always_uv(dev, cid) is not False:
                sys.exit("FAIL: could not restore alwaysUv — turn it off by hand")
            print("alwaysUv restored to off")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
