#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Device test: soft-lock (AUT_ENABLE / vendor UNLOCK / AUT_DISABLE).

Full cycle on the live board, identity-preserving (the seed VALUE never
changes; lock wraps and unwraps the same 32 bytes):

  baseline ops work -> enable (key saved to a file FIRST) -> ops fail ->
  warm reboot -> ops still fail, getInfo alive -> unlock -> ops work ->
  warm reboot -> ops fail again (per-boot lock) -> unlock -> disable ->
  warm reboot -> ops work with NO unlock (plaintext restored)

The lock key is written to --key-file (default /tmp/m10g_lock_key.hex) BEFORE
the lock is engaged; if a previous run died mid-cycle, the next run recovers
(unlock + disable with the saved key) and starts clean.

Needs the NO-TOUCH signed firmware build (enable/disable/makeCredential gates
auto-confirm) and the device PIN:

  nix develop -c python tests/76_soft_lock.py --pin <PIN>
"""
import argparse
import hashlib
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from _device import find_reader  # noqa: E402
from ctaphid import Protocol2, client_pin, ctaphid_init, decode, enc, find, send_cbor  # noqa: E402
from rsk import lock as lk  # noqa: E402

import hid  # noqa: E402

RP_ID = "m10g.test"
PERM_MC = 0x01


def open_fido(timeout=25.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = find()
        if info:
            dev = hid.device()
            try:
                dev.open_path(info["path"])
                return dev, ctaphid_init(dev)
            except (OSError, AssertionError, IndexError):
                # enumerated but the CTAPHID endpoint is not serving yet
                try:
                    dev.close()
                except Exception:
                    pass
        time.sleep(0.5)
    sys.exit("FAIL: FIDO HID device did not (re)appear")


def warm_reboot():
    target = find_reader(require_marker=True)
    if target is None:
        sys.exit("FAIL: no RSK CCID reader for the reboot step")
    conn = target.createConnection()
    conn.connect()
    _, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0, 0, 0, 1])
    if (sw1, sw2) != (0x90, 0x00):
        sys.exit(f"FAIL: vendor SELECT {sw1:02X}{sw2:02X}")
    try:
        conn.transmit([0x00, 0x1F, 0x00, 0x00, 0x00])  # warm reboot; reply may be cut
    except Exception:
        pass
    try:
        conn.disconnect()
    except Exception:
        pass


def reboot_and_reconnect():
    warm_reboot()
    time.sleep(2.0)
    return open_fido()


def pin_token(dev, cid, pin, perms):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    assert ka[0] == 0, f"getKeyAgreement {ka[0]:#x}"
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    ph = hashlib.sha256(pin.encode()).digest()[:16]
    tk = client_pin(dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: perms})
    if tk[0] != 0:
        sys.exit(f"FAIL: getPinUvAuthToken {tk[0]:#x} — wrong PIN? (NOT retrying)")
    return proto.decrypt(decode(tk[1:])[2])  # key 2 = pinUvAuthToken


def make_credential(dev, cid, pin):
    """Create a non-resident ES256 credential; returns its handle (credential id)."""
    cdh = b"\x11" * 32
    fields = {
        1: cdh,
        2: {"id": RP_ID, "name": "m10g"},
        3: {"id": b"u", "name": "u"},
        4: [{"alg": -7, "type": "public-key"}],
    }
    if pin is not None:
        token = pin_token(dev, cid, pin, PERM_MC)
        import hmac as pyhmac
        fields[8] = pyhmac.new(token, cdh, hashlib.sha256).digest()
        fields[9] = 2
    r = send_cbor(dev, cid, bytes([0x01]) + enc(fields))
    assert r[0] == 0, f"makeCredential {r[0]:#x}"
    auth_data = decode(r[1:])[2]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    return auth_data[55:55 + cred_len]


def silent_assertion(dev, cid, handle):
    req = bytes([0x02]) + enc({
        1: RP_ID, 2: b"\x00" * 32,
        3: [{"type": "public-key", "id": handle}],
        5: {"up": False},
    })
    return send_cbor(dev, cid, req)[0]


def state(dev, cid):
    return lk._state(dev, cid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", required=True, help="FIDO2 PIN (the config gate needs it)")
    ap.add_argument("--key-file", default="/tmp/m10g_lock_key.hex")
    args = ap.parse_args()

    dev, cid = open_fido()
    s = state(dev, cid)
    print(f"[0] state: {s}")
    if s["locked"]:
        print("    recovering from a previous run: unlock + disable with the saved key…")
        if not os.path.exists(args.key_file):
            sys.exit(f"FAIL: device locked and {args.key_file} is gone — "
                     f"recover manually: rsk lock unlock/disable (worst case: FIDO reset)")
        key = bytes.fromhex(open(args.key_file).read().strip())
        lk._unlock(dev, cid, key)
        st = lk._config_vendor(dev, cid, args.pin, lk.AUT_DISABLE)
        assert st == 0, f"recovery AUT_DISABLE {st:#x}"
        s = state(dev, cid)
        assert not s["locked"], s
        print("    recovered ✓")
    assert s["has_seed"], "device has no seed?!"

    handle = make_credential(dev, cid, args.pin)
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x00, f"[1] baseline silent assertion {rc:#x} (need the no-touch build)"
    print("[1] baseline: silent assertion 0x00 ✓")

    # The key goes to disk BEFORE the device is locked.
    key = secrets.token_bytes(32)
    with open(args.key_file, "w") as f:
        f.write(key.hex() + "\n")
    os.chmod(args.key_file, 0o600)
    print(f"[2] lock key saved to {args.key_file} (fp={hashlib.sha256(key).hexdigest()[:8]})")

    chan_key, aad = lk.mse_handshake(dev, cid)
    blob = lk._wrap_for_channel(chan_key, aad, key)
    st = lk._config_vendor(dev, cid, args.pin, lk.AUT_ENABLE, blob)
    assert st == 0, f"AUT_ENABLE {st:#x}"
    s = state(dev, cid)
    assert s["locked"] and not s["has_seed"] and not s["unlocked"], s
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x7F, f"[2] expected 0x7f right after enable, got {rc:#x}"
    print("[2] enabled: locked=True has_seed=False, assertion 0x7f ✓")

    dev, cid = reboot_and_reconnect()
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x7F, f"[3] expected 0x7f after reboot, got {rc:#x}"
    r = send_cbor(dev, cid, bytes([0x04]))
    assert r[0] == 0, f"getInfo while locked {r[0]:#x}"
    print("[3] rebooted: still locked (0x7f), getInfo alive ✓")

    lk._unlock(dev, cid, key)
    s = state(dev, cid)
    assert s["locked"] and s["unlocked"], s
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x00, f"[4] expected 0x00 after unlock, got {rc:#x}"
    print("[4] unlocked: assertion 0x00 ✓")

    dev, cid = reboot_and_reconnect()
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x7F, f"[5] expected 0x7f after 2nd reboot, got {rc:#x}"
    lk._unlock(dev, cid, key)
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x00, f"[5] expected 0x00 after 2nd unlock, got {rc:#x}"
    print("[5] per-boot lock proven (0x7f -> unlock -> 0x00) ✓")

    st = lk._config_vendor(dev, cid, args.pin, lk.AUT_DISABLE)
    assert st == 0, f"AUT_DISABLE {st:#x}"
    s = state(dev, cid)
    assert not s["locked"] and s["has_seed"], s
    dev, cid = reboot_and_reconnect()
    rc = silent_assertion(dev, cid, handle)
    assert rc == 0x00, f"[6] expected 0x00 plain after disable+reboot, got {rc:#x}"
    print("[6] disabled: plaintext restored, assertion 0x00 with no unlock ✓")

    os.unlink(args.key_file)
    print("PASS — soft-lock full cycle clean, identity preserved")


if __name__ == "__main__":
    main()
