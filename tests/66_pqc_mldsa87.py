#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: ML-DSA-87 (FIPS 204, COSE -50) credentials over CTAPHID.

    nix develop -c python tests/65_pqc_mldsa87.py

Needs `hidapi` + `dilithium-py`. Flash the **no-touch** image built WITHOUT
`advertise-pqc` — this test's whole point is the unadvertised-but-negotiable
path: a platform that never sees -50 in getInfo can still ask for it by name.

  1. reset                        -> clean slate (asks for a replug, §6.6)
  2. getInfo                      -> -50 ABSENT from `algorithms`; maxMsgSize 7609
  3. makeCredential [-50, -7]     -> -50 selected anyway: AKP COSE key
                                     {1:7, 3:-50, -1:pub(2592)}
  4. makeCredential [-50, -49]    -> list order decides between the ML-DSA sets
  5. getAssertion (allowList)     -> 4627-byte signature verifies under
                                     dilithium-py ML_DSA_87 (twice; the
                                     non-resident counter stays 0)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import decode, enc, find, read, send_cbor, write  # noqa: E402

try:
    from dilithium_py.ml_dsa import ML_DSA_87
except ImportError:
    sys.exit("missing dependency: pip install dilithium-py")

import hid  # noqa: E402

CTAPHID_INIT = 0x86
CDH = bytes(range(32))
RP = "pqc87.example.com"
PK_LEN, SIG_LEN = 2592, 4627


def ctap(dev, cid, cmd, fields=None):
    payload = bytes([cmd]) + (enc(fields) if fields is not None else b"")
    r = send_cbor(dev, cid, payload)
    return r[0], (decode(r[1:]) if len(r) > 1 else None)


def parse_make_credential(resp):
    auth_data = resp[2]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_len]
    cose = decode(auth_data[55 + cred_len:])
    return cred_id, cose[3], cose.get(-1), auth_data, resp[3]


def make_credential(dev, cid, algs, uid=b"\x01\x02\x03\x04"):
    req = {
        1: CDH,
        2: {"id": RP},
        3: {"id": uid, "name": "pqc87-user"},
        4: [{"alg": a, "type": "public-key"} for a in algs],
    }
    t = time.time()
    status, resp = ctap(dev, cid, 0x01, req)
    dt = time.time() - t
    assert status == 0x00, f"makeCredential status {status:#x}"
    return parse_make_credential(resp), dt


def get_assertion(dev, cid, cred_id):
    req = {1: RP, 2: CDH, 3: [{"id": cred_id, "type": "public-key"}]}
    t = time.time()
    status, resp = ctap(dev, cid, 0x02, req)
    dt = time.time() - t
    assert status == 0x00, f"getAssertion status {status:#x}"
    return resp[2], resp[3], dt


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        dev, cid = replug.reset(dev, "step 1's reset")

        # 2. The default build advertises no ML-DSA at all. Assert that -50 is
        # absent — if it appears, the image was built with `advertise-pqc` and
        # this test is measuring the wrong thing.
        status, gi = ctap(dev, cid, 0x04)
        assert status == 0x00
        algs = [e["alg"] for e in gi[10]]
        assert -50 not in algs, f"-50 advertised; want the default build: {algs}"
        assert gi[5] == 7609, f"maxMsgSize {gi[5]}, want 7609"
        print(f"getInfo: -50 unadvertised as expected; algorithms {algs}")

        # 3. Unadvertised does not mean unsupported: ask for it by name.
        (cred_id, alg, pk, _, att), dt_mc = make_credential(dev, cid, [-50, -7])
        assert alg == -50, f"selected alg {alg}, want -50 (first supported)"
        assert len(pk) == PK_LEN, f"pk len {len(pk)}, want {PK_LEN}"
        assert att["alg"] == -7 and att["x5c"], f"attStmt {att}"
        print(f"makeCredential -50: pk {len(pk)} B, credId {len(cred_id)} B, {dt_mc:.2f}s")

        # 4. List order decides between the ML-DSA sets, as for -49 vs -48.
        (_, alg2, _, _, _), _ = make_credential(dev, cid, [-50, -49], uid=b"\x05\x06\x07\x08")
        assert alg2 == -50, f"-50 listed first must win, got {alg2}"

        # 5. The signature is the real test: 4627 bytes that an independent
        # ML-DSA-87 implementation accepts over authData ‖ clientDataHash.
        ad1, sig1, dt_ga = get_assertion(dev, cid, cred_id)
        assert len(sig1) == SIG_LEN, f"sig len {len(sig1)}, want {SIG_LEN}"
        assert ML_DSA_87.verify(pk, ad1 + CDH, sig1), "assertion signature"
        print(f"getAssertion -50: sig {len(sig1)} B verified, {dt_ga:.2f}s")

        ad2, sig2, _ = get_assertion(dev, cid, cred_id)
        c1 = int.from_bytes(ad1[33:37], "big")
        c2 = int.from_bytes(ad2[33:37], "big")
        # Per-credential counters, non-resident credential — same expectation as
        # 60_pqc_mldsa and 63_pqc_mldsa65: it stays 0, it does not grow.
        assert (c1, c2) == (0, 0), f"non-resident credential reported a counter ({c1} -> {c2})"
        assert ML_DSA_87.verify(pk, ad2 + CDH, sig2), "second assertion signature"

        print("PASS: ML-DSA-87 negotiable while unadvertised")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
