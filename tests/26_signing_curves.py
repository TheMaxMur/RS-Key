#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: the additional FIDO2 signing curves over CTAPHID_CBOR.

    nix develop -c python tests/26_signing_curves.py

For each of EdDSA (Ed25519), ES256K (secp256k1), ES384 (P-384) and ES512 (P-521),
in roughly fastest-to-slowest order:
  1. makeCredential(alg)      -> a credential with the matching COSE public key
  2. getAssertion(credId)     -> sign authData ‖ clientDataHash
  3. verify the signature under the credential public key (host `cryptography`)

getInfo's advertised set (0x0A) is checked once up front: ES256/ES384/ES512 and
EdDSA (-8) are advertised (EdDSA so the Windows WebAuthn API offers `ed25519-sk`);
ES256K (-47) is implemented but intentionally NOT advertised (the FIDO conformance
tool cannot verify a secp256k1 self-attestation). makeCredential still negotiates
ES256K from a request, so the per-curve loop exercises it all the same.

A no-PIN device is assumed (resets at the start, after a replug — CTAP 2.1 §6.6
accepts a reset only just after power-up, see replug.py). Needs `cryptography`.
Uses a generous response timeout because the pure-Rust P-384/P-521 arithmetic is
slow on the RP2350.
"""
import os
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import (  # noqa: E402
    CTAPHID_CBOR,
    CTAPHID_INIT,
    decode,
    enc,
    find,
    read,
    write,
)

RP_ID = "curve.example"
CDH = b"\xAB" * 32
CTAPHID_KEEPALIVE = 0xBB


def send_cbor_t(dev, cid, payload, first_ms=20000):
    """send_cbor with a long first-frame timeout + keepalive skipping."""
    n = len(payload)
    write(dev, cid + bytes([CTAPHID_CBOR, n >> 8, n & 0xFF]) + payload[:57])
    off, seq = 57, 0
    while off < n:
        write(dev, cid + bytes([seq]) + payload[off : off + 59])
        off, seq = off + 59, seq + 1
    r = bytes(dev.read(64, first_ms))
    while len(r) >= 5 and r[4] == CTAPHID_KEEPALIVE:
        r = bytes(dev.read(64, first_ms))
    if len(r) < 7:
        raise TimeoutError("no response within timeout (device busy or crashed)")
    assert r[4] == CTAPHID_CBOR, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7 : 7 + bcnt])
    while len(data) < bcnt:
        c = bytes(dev.read(64, 5000))
        data += c[5 : 5 + min(59, bcnt - len(data))]
    return bytes(data[:bcnt])


def make_credential(dev, cid, alg):
    req = {
        1: CDH,
        2: {"id": RP_ID},
        3: {"id": b"\x01\x02\x03\x04", "name": "u"},
        4: [{"alg": alg, "type": "public-key"}],
    }
    r = send_cbor_t(dev, cid, bytes([0x01]) + enc(req))
    assert r[0] == 0x00, f"makeCredential(alg={alg}) status {r[0]:#x}"
    resp = decode(r[1:])
    ad = resp[2]
    cred_len = (ad[53] << 8) | ad[54]
    cred_id = ad[55 : 55 + cred_len]
    cose = decode(ad[55 + cred_len :])
    return cred_id, cose


def get_assertion(dev, cid, cred_id):
    req = {1: RP_ID, 2: CDH, 3: [{"type": "public-key", "id": cred_id}]}
    r = send_cbor_t(dev, cid, bytes([0x02]) + enc(req))
    assert r[0] == 0x00, f"getAssertion status {r[0]:#x}"
    resp = decode(r[1:])
    return resp[2], resp[3]  # authData, signature


def verify_ec(curve, hashalg, cose, signed, sig):
    x = int.from_bytes(cose[-2], "big")
    y = int.from_bytes(cose[-3], "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    pub.verify(sig, signed, ec.ECDSA(hashalg))


def verify_ed(cose, signed, sig):
    ed25519.Ed25519PublicKey.from_public_bytes(cose[-2]).verify(sig, signed)


# (name, COSE alg, expected COSE kty, verifier) — fastest curve first.
CURVES = [
    ("EdDSA", -8, 1, verify_ed),
    ("ES256K", -47, 2, lambda c, s, g: verify_ec(ec.SECP256K1(), hashes.SHA256(), c, s, g)),
    ("ES384", -35, 2, lambda c, s, g: verify_ec(ec.SECP384R1(), hashes.SHA384(), c, s, g)),
    ("ES512", -36, 2, lambda c, s, g: verify_ec(ec.SECP521R1(), hashes.SHA512(), c, s, g)),
]


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        dev, cid = replug.reset(dev, "the clean-slate reset")
        gi = decode(send_cbor_t(dev, cid, bytes([0x04]))[1:])
        algs = {a["alg"] for a in gi[0x0A]}
        # ES256/384/512 and EdDSA (-8) are advertised; ES256K (-47) is implemented
        # but intentionally unadvertised (FIDO conformance MakeCred-Resp P-06) —
        # makeCredential still negotiates it, so the loop below still tests it.
        assert {-7, -8, -35, -36} <= algs, f"getInfo algorithms = {sorted(algs)}"
        assert -47 not in algs, f"ES256K (-47) must not be advertised: {sorted(algs)}"
        print(f"getInfo: algorithms {sorted(algs, reverse=True)}")

        passed = []
        for name, alg, kty, verify in CURVES:
            try:
                t0 = time.time()
                cred_id, cose = make_credential(dev, cid, alg)
                t_mc = time.time() - t0
                assert cose[1] == kty, f"{name}: COSE kty {cose[1]}, want {kty}"
                assert cose[3] == alg, f"{name}: COSE alg {cose[3]}, want {alg}"
                t0 = time.time()
                authdata, sig = get_assertion(dev, cid, cred_id)
                t_ga = time.time() - t0
                verify(cose, authdata + CDH, sig)
                print(
                    f"{name}: OK  (makeCred {t_mc:.2f}s, getAssertion {t_ga:.2f}s, "
                    f"{len(sig)}B sig)"
                )
                passed.append(name)
            except (TimeoutError, AssertionError, InvalidSignature) as e:
                print(f"{name}: FAIL — {e}")

        # Liveness: a working getInfo afterwards means the device did not crash.
        try:
            send_cbor_t(dev, cid, bytes([0x04]), first_ms=5000)
            print("device still responsive after the run")
        except Exception:
            print("device UNRESPONSIVE after the run (a curve crashed the firmware)")

        if len(passed) == len(CURVES):
            print("\nPASS")
        else:
            sys.exit(f"\nINCOMPLETE — passed {passed}")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
