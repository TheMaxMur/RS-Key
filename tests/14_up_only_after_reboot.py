#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""UP-only seed load after a reboot (needs firmware bcdDevice 0x073D+).

Proves that a silent (up=false, no PIN) getAssertion can load the device seed
in a FRESH boot session — what an SSH `ed25519-sk` login needs after a replug.

Sequence (hands-free; uses the enrolled ssh sk key as the credential):
  1. silent assertion        — informational; 0x7F here = blob still legacy
  2. (--pin) getPinToken     — one-time migration of a legacy 0x03/0x13 blob
  3. CCID vendor warm reboot — a real new boot session, no replug needed
  4. silent assertion        — MUST NOT be 0x7F:
       0x00  full assertion (no-touch build)
       0x27  presence timeout (touch build: up=false still polls the button)

PINs are never guessed: step 2 runs only with an explicit --pin. Run from the
.venv-fido python (hidapi + pyscard).
"""
import argparse
import base64
import hashlib
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402
from ctaphid import (  # noqa: E402
    Protocol2,
    client_pin,
    ctaphid_init,
    decode,
    enc,
    find,
    hid,
    send_cbor,
)

STATUS = {0x00: "OK", 0x27: "OPERATION_DENIED (presence timeout — seed loaded)",
          0x2E: "NO_CREDENTIALS", 0x31: "PIN_INVALID", 0x7F: "ERR_OTHER (seed unreadable)"}


def parse_sk_key(path):
    """Extract (application, key_handle) from an unencrypted OpenSSH sk key."""
    with open(path) as f:
        lines = [ln.strip() for ln in f.readlines()]
    assert lines[0] == "-----BEGIN OPENSSH PRIVATE KEY-----", "not an openssh key"
    blob = base64.b64decode("".join(lines[1:-1]))
    magic = b"openssh-key-v1\x00"
    assert blob.startswith(magic), "bad magic"
    off = len(magic)

    def rd_str(b, o):
        n = struct.unpack(">I", b[o:o + 4])[0]
        return b[o + 4:o + 4 + n], o + 4 + n

    cipher, off = rd_str(blob, off)
    kdf, off = rd_str(blob, off)
    _kdfopts, off = rd_str(blob, off)
    assert cipher == b"none" and kdf == b"none", "key file is passphrase-protected"
    nkeys = struct.unpack(">I", blob[off:off + 4])[0]
    off += 4
    assert nkeys == 1
    _pub, off = rd_str(blob, off)
    priv, _ = rd_str(blob, off)
    o = 8  # private section: check1(4) check2(4) then the key
    ktype, o = rd_str(priv, o)
    assert ktype == b"sk-ssh-ed25519@openssh.com", ktype
    _pk, o = rd_str(priv, o)
    app, o = rd_str(priv, o)
    _flags = priv[o]
    o += 1
    handle, o = rd_str(priv, o)
    return app.decode(), handle


def open_fido(timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = find()
        if info:
            try:
                dev = hid.device()
                dev.open_path(info["path"])
                return dev, ctaphid_init(dev)
            except OSError:
                pass  # enumerated but not ready yet
        time.sleep(0.5)
    sys.exit("FAIL: FIDO HID device did not (re)appear")


def silent_assertion(dev, cid, app, handle):
    req = bytes([0x02]) + enc({
        1: app, 2: b"\x00" * 32,
        3: [{"type": "public-key", "id": handle}],
        5: {"up": False},
    })
    return send_cbor(dev, cid, req)[0]


def get_pin_token(dev, cid, pin):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    if ka[0] != 0x00:
        sys.exit(f"FAIL: getKeyAgreement 0x{ka[0]:02X}")
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    ph = hashlib.sha256(pin).digest()[:16]
    tk = client_pin(dev, cid, {1: 2, 2: 5, 3: proto.cose(), 6: proto.encrypt(ph)})
    if tk[0] != 0x00:
        sys.exit(f"FAIL: getPinToken 0x{tk[0]:02X} — wrong PIN? (NOT retrying)")


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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ssh-key", default=os.path.expanduser("~/.ssh/id_ed25519_sk"),
                    help="enrolled OpenSSH sk key file (handle source)")
    ap.add_argument("--pin", help="FIDO2 PIN — runs getPinToken before the reboot "
                                  "to migrate a legacy PIN-wrapped seed once")
    args = ap.parse_args()

    app, handle = parse_sk_key(args.ssh_key)
    print(f"credential: app={app!r}, handle {len(handle)}B")

    dev, cid = open_fido()
    s0 = silent_assertion(dev, cid, app, handle)
    print(f"[1] silent assertion (this boot):  0x{s0:02X} {STATUS.get(s0, '?')}")
    if s0 == 0x7F and not args.pin:
        sys.exit("legacy PIN-wrapped seed still on flash — run once with --pin "
                 "to migrate it (one getPinToken), then this test is PIN-free")
    if args.pin:
        get_pin_token(dev, cid, args.pin.encode())
        print("[2] getPinToken OK (legacy blob, if any, migrated to plain)")
    dev.close()

    print("[3] vendor warm reboot over CCID …")
    warm_reboot()
    time.sleep(2.0)
    dev, cid = open_fido()
    s1 = silent_assertion(dev, cid, app, handle)
    print(f"[4] silent assertion (fresh boot): 0x{s1:02X} {STATUS.get(s1, '?')}")
    dev.close()

    if s1 == 0x7F:
        sys.exit("UP-ONLY FAIL: seed unreadable in a fresh boot session (0x7F)")
    print("UP-ONLY PASS: seed loads with no PIN op after a power cycle")


if __name__ == "__main__":
    main()
