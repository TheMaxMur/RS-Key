#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: ML-DSA-65 (FIPS 204, COSE -49) credentials over CTAPHID.

    nix develop -c python tests/63_pqc_mldsa65.py

Needs `hidapi` + `dilithium-py` (the nix devshell python has hidapi but not
dilithium-py; use the .venv-fido python or `pip install dilithium-py`). Flash the
no-touch build (this tool cannot press the button) built `--features
advertise-pqc` so getInfo advertises -49.

  1. reset                        -> clean slate (idempotent; asks for a replug,
                                     CTAP 2.1 §6.6 — see replug.py)
  2. getInfo                      -> advertise-pqc build: -49 leads, then -48;
                                     maxMsgSize 7609
  3. makeCredential [-49, -7]     -> the first supported entry is selected:
                                     AKP COSE key {1:7, 3:-49, -1:pub(1952)}; the
                                     packed self-attestation (3309-byte sig)
                                     verifies under dilithium-py ML_DSA_65
  4. makeCredential [-49, -48]    -> list order decides between the ML-DSA sets
  5. getAssertion (allowList)     -> assertion verifies; sign counter grows
  6. rk -7 then rk [-7,-49], same rp/user -> the resident slot upgrades to
                                     ML-DSA-65; discovery asserts with it
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import decode, enc, find, read, send_cbor, write  # noqa: E402

try:
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError:
    sys.exit("missing dependency: pip install dilithium-py")

import hid  # noqa: E402

CTAPHID_INIT = 0x86
CDH = bytes(range(32))
RP = "pqc65.example.com"
PK_LEN, SIG_LEN = 1952, 3309


def ctap(dev, cid, cmd, fields=None):
    payload = bytes([cmd]) + (enc(fields) if fields is not None else b"")
    r = send_cbor(dev, cid, payload)
    return r[0], (decode(r[1:]) if len(r) > 1 else None)


def parse_make_credential(resp):
    """-> (credId, alg, pk, authData, attStmt) from a packed mc response."""
    auth_data = resp[2]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_len]
    cose = decode(auth_data[55 + cred_len:])
    return cred_id, cose[3], cose.get(-1), auth_data, resp[3]


def make_credential(dev, cid, algs, uid=b"\x01\x02\x03\x04", rk=False):
    req = {
        1: CDH,
        2: {"id": RP},
        3: {"id": uid, "name": "pqc-user"},
        4: [{"alg": a, "type": "public-key"} for a in algs],
    }
    if rk:
        req[7] = {"rk": True}
    t = time.time()
    status, resp = ctap(dev, cid, 0x01, req)
    dt = time.time() - t
    assert status == 0x00, f"makeCredential status {status:#x}"
    return parse_make_credential(resp), dt


def get_assertion(dev, cid, cred_id=None):
    req = {1: RP, 2: CDH}
    if cred_id is not None:
        req[3] = [{"id": cred_id, "type": "public-key"}]
    t = time.time()
    status, resp = ctap(dev, cid, 0x02, req)
    dt = time.time() - t
    assert status == 0x00, f"getAssertion status {status:#x}"
    return resp[2], resp[3], dt  # authData, sig


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. reset for idempotency (needs a replug: CTAP 2.1 §6.6).
        dev, cid = replug.reset(dev, "step 1's reset")

        # 2. getInfo: the advertise-pqc build advertises both ML-DSA sets, -49
        # (ML-DSA-65) before -48. The classic default build advertises neither;
        # -49 is still negotiable there (proven in step 3), so accept both shapes.
        status, gi = ctap(dev, cid, 0x04)
        assert status == 0x00
        algs = [e["alg"] for e in gi[10]]
        if -49 in algs:
            assert algs == [-50, -49, -48, -7, -35, -36, -8], (
                f"algorithms list changed: {algs}"
            )
            print("getInfo: all three ML-DSA sets advertised (advertise-pqc)")
        else:
            assert -48 not in algs, f"-48 without -49?: {algs}"
            print("getInfo: classic algorithms only (default build); -49 still negotiable")
        assert gi[5] == 7609, f"maxMsgSize {gi[5]}, want 7609"

        # 3. ML-DSA-65 registration. CTAP 2.1 §6.1.2 step 4 picks the FIRST
        # supported entry, so -49 must lead the list to be selected.
        (cred_id, alg, pk, auth_data, att), dt_mc = make_credential(dev, cid, [-49, -7])
        assert alg == -49, f"selected alg {alg}, want -49 (first supported)"
        assert len(pk) == PK_LEN, f"pk len {len(pk)}, want {PK_LEN}"
        # Basic attestation is ES256 by the device key whatever the credential
        # algorithm is (`makecredential.rs` writes ALG_ES256 unconditionally), so a
        # PQC credential leaves the statement unchanged — same expectation as
        # 60_pqc_mldsa. This asserted an ML-DSA-65 SELF-attestation until
        # 2026-08-08, which no build has ever produced.
        assert att["alg"] == -7 and att["x5c"], f"attStmt {att}"

        # 4. The same rule decides between the two ML-DSA sets.
        (_, alg2, _, _, _), _ = make_credential(dev, cid, [-49, -48])
        assert alg2 == -49, f"-49 listed first must win, got {alg2}"

        # 5. Assertion under the step-3 credential; counter must grow.
        ad1, sig1, dt_ga = get_assertion(dev, cid, cred_id)
        assert len(sig1) == SIG_LEN
        assert ML_DSA_65.verify(pk, ad1 + CDH, sig1), "assertion sig"
        ad2, sig2, _ = get_assertion(dev, cid, cred_id)
        c1 = int.from_bytes(ad1[33:37], "big")
        c2 = int.from_bytes(ad2[33:37], "big")
        # Per-credential counters, non-resident credential — see 60_pqc_mldsa.
        assert (c1, c2) == (0, 0), f"non-resident credential reported a counter ({c1} -> {c2})"
        assert ML_DSA_65.verify(pk, ad2 + CDH, sig2)

        # 6. Classic -> PQC resident upgrade for one rp/user.
        uid = b"\x65\x65"
        make_credential(dev, cid, [-7], uid=uid, rk=True)
        (_, alg, pk2, _, _), _ = make_credential(dev, cid, [-49, -7], uid=uid, rk=True)
        assert alg == -49
        ad3, sig3, _ = get_assertion(dev, cid)  # discovery, no allowList
        assert len(sig3) == SIG_LEN, "upgraded resident credential signs ML-DSA-65"
        assert ML_DSA_65.verify(pk2, ad3 + CDH, sig3), "post-upgrade assertion sig"

        print(f"makeCredential(-49): {dt_mc:.2f}s, getAssertion: {dt_ga:.2f}s")
        print("PASS (ML-DSA-65 register+login verified, first-supported selection, resident upgrade)")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
