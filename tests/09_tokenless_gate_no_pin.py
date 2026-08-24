#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: §6.1.2's token-less makeCredential gate while NO PIN is set.

    nix develop -c python tests/09_tokenless_gate_no_pin.py

Both cells here are served — `makeCredUvNotRqd` means a token-less
makeCredential needs no token while the device has no PIN, whatever `rk` says.
The suite exists for the phase-4 recording, where a gate boundary is a command
that moves no raw state: a *served* registration only becomes one when it writes
nothing. `crates/rsk-fido/src/credential.rs:810-825` reuses the slot when
`(rpIdHash, userId)` already match, so the second `rk: true` of the same user is
one row, and a non-discoverable create is the other. Without them `pin.set` is
TRUE at every gate boundary the model replays, and that conjunct is true rather
than falsifiable (formal/README.md, phase 4).

Held to getInfo `0x14 remainingDiscoverableCredentials` and not to the status
alone: `0x00` says only that the gate served the request, and the free-slot count
is what says the two later ones stored nothing — which is what makes them gate
rows at all.

The low number is the precondition: it has to run before anything sets a PIN.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaphid import (  # noqa: E402
    CTAPHID_INIT,
    decode,
    enc,
    find,
    read,
    send_cbor,
    write,
)

GET_INFO, MAKE_CRED = 0x04, 0x01
REMAINING_RK = 0x14
RP_ID = "no-pin-gate.example"
USER_ID = b"\x09" * 16


def ordered(d):
    """CTAP request maps need strictly ascending integer keys."""
    return {k: d[k] for k in sorted(d)}


def get_info(dev, cid):
    r = send_cbor(dev, cid, bytes([GET_INFO]))
    assert r[0] == 0x00, f"getInfo status {r[0]:#x}"
    return decode(r[1:])


def free_slots(dev, cid):
    """getInfo 0x14 — the live free discoverable-credential count."""
    info = get_info(dev, cid)
    assert REMAINING_RK in info, "getInfo carries no remainingDiscoverableCredentials"
    return info[REMAINING_RK]


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
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # The premise, not a formality: with a PIN set, step 10 refuses `rk` and
        # both rows below turn into the two cells the recording already holds.
        assert get_info(dev, cid)[4].get("clientPin") is False, \
            "this suite needs a device with no PIN — it runs before 21 sets one"

        before = free_slots(dev, cid)
        status = tokenless_make_credential(dev, cid, True, USER_ID)
        assert status == 0x00, f"token-less rk:true status {status:#x}, want 0x00"
        first = free_slots(dev, cid)
        assert first == before - 1, \
            f"the first registration took no slot ({before} -> {first})"
        print(f"rk:true served with no token, one slot spent ({before} -> {first})")

        status = tokenless_make_credential(dev, cid, True, USER_ID)
        assert status == 0x00, f"token-less rk:true (again) status {status:#x}, want 0x00"
        second = free_slots(dev, cid)
        assert second == first, \
            f"the same user's re-registration took a second slot ({first} -> {second})"
        print(f"rk:true re-registration served and stored nothing ({second} free)")

        status = tokenless_make_credential(dev, cid, False, b"\x0A" * 16)
        assert status == 0x00, f"token-less rk:false status {status:#x}, want 0x00"
        third = free_slots(dev, cid)
        assert third == second, \
            f"a non-discoverable create took a slot ({second} -> {third})"
        print(f"rk:false served on presence alone, stored nothing ({third} free)")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
