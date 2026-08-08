#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: ML-DSA-44 (FIPS 204, COSE -48) credentials over CTAPHID.

    nix develop -c python tests/60_pqc_mldsa.py

Needs `hidapi` + `dilithium-py` (both in the .venv-fido python; the nix devshell
python has neither dilithium-py nor a recent-enough cryptography ML-DSA backend).
Flash the no-touch build (firmware-test.uf2) — this tool cannot press the button.

  1. reset                        -> clean slate (idempotent; asks for a replug,
                                     CTAP 2.1 §6.6 — see replug.py)
  2. getInfo                      -> default build: -48 NOT advertised (Firefox
                                     strict-parser compat); advertise-pqc build:
                                     -48 leads; maxMsgSize 7609 either way
  3. makeCredential [-48, -7]     -> the first supported entry is selected:
                                     AKP COSE key {1:7, 3:-48, -1:pub(1312)}; the
                                     attestation stays packed/ES256 by the device
                                     key whatever the credential algorithm is
  4. getAssertion (allowList)     -> assertion verifies; sign counter grows
  5. rk -7 then rk [-7,-48], same rp/user -> the resident slot upgrades to
                                     ML-DSA-44; discovery asserts with it
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import decode, enc, find, read, send_cbor, write  # noqa: E402

try:
    from dilithium_py.ml_dsa import ML_DSA_44
except ImportError:
    sys.exit("missing dependency: pip install dilithium-py")

import hid  # noqa: E402

CTAPHID_INIT = 0x86
CDH = bytes(range(32))
RP = "pqc.example.com"
PK_LEN, SIG_LEN = 1312, 2420


def ctap(dev, cid, cmd, fields=None):
    payload = bytes([cmd]) + (enc(fields) if fields is not None else b"")
    r = send_cbor(dev, cid, payload)
    return r[0], (decode(r[1:]) if len(r) > 1 else None)


def parse_make_credential(resp):
    """-> (credId, alg, pk, authData, fmt, attStmt) from an mc response."""
    auth_data = resp[2]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_len]
    cose = decode(auth_data[55 + cred_len:])
    return cred_id, cose[3], cose.get(-1), auth_data, resp[1], resp[3]


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

        # 2. getInfo: the default build must NOT advertise -48 (shipped Firefoxes
        # hard-fail the whole getInfo on an unknown COSE id); the advertise-pqc
        # build prepends it. Both shapes accepted here — the PQC capability is
        # proven in step 3.
        status, gi = ctap(dev, cid, 0x04)
        assert status == 0x00
        algs = [e["alg"] for e in gi[10]]
        # Advertised set/order: ES256, ES384, ES512, then EdDSA (-8); advertise-pqc
        # prepends ML-DSA-65 (-49) then ML-DSA-44 (-48). ES256K (-47) is
        # implemented but never advertised.
        if -48 in algs:
            assert algs == [-49, -48, -7, -35, -36, -8], f"algorithms list changed: {algs}"
            print("getInfo: ML-DSA-65 (-49) + ML-DSA-44 (-48) advertised (advertise-pqc build)")
        else:
            assert algs == [-7, -35, -36, -8], f"classic algorithms list changed: {algs}"
            print("getInfo: classic algorithms only (Firefox-safe default build)")
        assert gi[5] == 7609, f"maxMsgSize {gi[5]}, want 7609"

        # 3. ML-DSA-44 registration. CTAP 2.1 §6.1.2 step 4 picks the FIRST
        # supported entry, so -48 must lead the list to be selected.
        (cred_id, alg, pk, auth_data, fmt, att), dt_mc = make_credential(dev, cid, [-48, -7])
        assert alg == -48, f"selected alg {alg}, want -48 (first supported)"
        assert len(pk) == PK_LEN
        # Basic attestation is ES256 by the device key whatever the credential
        # algorithm is, so a PQC credential leaves the statement unchanged.
        assert fmt == "packed", f"fmt={fmt!r}"
        assert att["alg"] == -7 and att["x5c"], f"attStmt {att}"

        # 4. Assertion under the same credential; counter must grow.
        ad1, sig1, dt_ga = get_assertion(dev, cid, cred_id)
        assert len(sig1) == SIG_LEN
        assert ML_DSA_44.verify(pk, ad1 + CDH, sig1), "assertion sig"
        ad2, sig2, _ = get_assertion(dev, cid, cred_id)
        c1 = int.from_bytes(ad1[33:37], "big")
        c2 = int.from_bytes(ad2[33:37], "big")
        # Zero, and staying zero: signature counters are per-credential and this
        # credential is not resident, so there is no on-device state to count in
        # (same rule as 12_fido_getassertion, which explains it).
        assert (c1, c2) == (0, 0), f"non-resident credential reported a counter ({c1} -> {c2})"
        assert ML_DSA_44.verify(pk, ad2 + CDH, sig2)

        # 5. Classic -> PQC resident upgrade for one rp/user.
        uid = b"\x42\x42"
        make_credential(dev, cid, [-7], uid=uid, rk=True)
        (_, alg, pk2, _, _, _), _ = make_credential(dev, cid, [-48, -7], uid=uid, rk=True)
        assert alg == -48
        ad3, sig3, _ = get_assertion(dev, cid)  # discovery, no allowList
        assert len(sig3) == SIG_LEN, "upgraded resident credential signs ML-DSA"
        assert ML_DSA_44.verify(pk2, ad3 + CDH, sig3), "post-upgrade assertion sig"

        print(f"makeCredential(-48): {dt_mc:.2f}s, getAssertion: {dt_ga:.2f}s")
        print("PASS (ML-DSA-44 register+login verified, resident upgrade)")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
