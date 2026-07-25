#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Device test: the CTAP 2.1 spec-alignment surface (bcdDevice 0x0855+).

Covers the protocol-visible behaviour of the spec-alignment pass, which the
per-command suites do not reach — CTAPHID channel allocation and locking, the
`uv`/`pinUvAuthParam` precedence rule, `makeCredUvNotRqd`, the largeBlobs
parameter validation, `setMinPINLength` overflow, the rpId-scoped
`credentialManagement` token, and the U2F gate under `alwaysUv`:

   1. CTAPHID_INIT             -> a unique CID per broadcast INIT; an INIT on an
                                  allocated CID echoes it (§11.2.9.1.3)
   2. CTAPHID_LOCK             -> other channels get ERR_CHANNEL_BUSY, the owner
                                  passes, release frees; 0..10s bounds (§11.2.9.2.2)
   3. makeCredential options   -> uv:true alongside a pinUvAuthParam is accepted,
                                  not CTAP2_ERR_INVALID_OPTION (§6.1.2 step 5)
   4. pubKeyCredParams         -> the platform's FIRST supported algorithm wins,
                                  even with ML-DSA listed after it (§6.1.2 step 4)
   5. credBlob                 -> a blob of exactly maxCredBlobLength is accepted
   6. makeCredUvNotRqd         -> a NON-discoverable credential is created on
                                  presence alone with a PIN set, uv clear, and it
                                  asserts and excludes like any other; rk:true still
                                  needs a token (§6.1.2 steps 7/10, issue #51)
   7. setPIN (already set)     -> CTAP2_ERR_PIN_AUTH_INVALID (§6.5.5.5)
   8. largeBlobs get           -> `length` / pinUvAuthParam / over-long reads are
                                  refused; the 17-byte array is hash-checked (§6.10.2)
   9. setMinPINLength          -> more RP ids than fit is CTAP2_ERR_KEY_STORE_FULL,
                                  not a silent truncation (§6.11)
  10. credentialManagement     -> an rpId-scoped token may delete its own rp's
                                  credential; a foreign id and an rp-less subcommand
                                  both answer PIN_AUTH_INVALID (§6.8.5/6.8.6)
  11. alwaysUv                -> it overrides makeCredUvNotRqd in BOTH the
                                  advertisement and the enforcement (§6.1.2 step 6,
                                  §6.4), and U2F drops U2F_V2 and answers
                                  SW_COMMAND_NOT_ALLOWED 6986 (§7.2.4)

Non-destructive: no reset and no replug. `alwaysUv` is toggled on for step 11 and
restored in a `finally`; the one resident credential step 10 creates is removed by
the deleteCredential under test. Needs a NO-TOUCH build (the presence gates
auto-confirm) and the device PIN:

  nix develop -c python tests/28_ctap_spec_alignment.py --pin <PIN>
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
    ctaphid_init,
    decode,
    enc,
    find,
    read,
    send_cbor,
    write,
)

import hid  # noqa: E402

GET_INFO, MAKE_CRED, GET_ASSERTION = 0x04, 0x01, 0x02
CRED_MGMT, LARGE_BLOBS, AUTH_CONFIG = 0x0A, 0x0C, 0x0D
CTAPHID_PING, CTAPHID_LOCK, CTAPHID_MSG, CTAPHID_ERROR = 0x81, 0x84, 0x83, 0xBF
ERR_INVALID_PAR, ERR_INVALID_LEN, ERR_CHANNEL_BUSY = 0x02, 0x03, 0x06
PERM_MC, PERM_CM, PERM_LBW, PERM_ACFG = 0x01, 0x04, 0x10, 0x20
RP = "spec-align.example"

fails = []


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{' — ' + detail if detail else ''}")
    if not ok:
        fails.append(name)


def ordered(d):
    """CTAP request maps need strictly ascending integer keys; the parser enforces it."""
    return {k: d[k] for k in sorted(d)}


def raw(dev, cid, cmd, payload=b""):
    """One CTAPHID command: fragment the request, reassemble the reply."""
    n = len(payload)
    write(dev, cid + bytes([cmd, n >> 8, n & 0xFF]) + payload[:57])
    off, seq = 57, 0
    while off < n:
        write(dev, cid + bytes([seq]) + payload[off:off + 59])
        off, seq = off + 59, seq + 1
    r = read(dev)
    while r[4] == 0xBB:  # CTAPHID_KEEPALIVE
        r = read(dev)
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    while len(data) < bcnt:
        data += read(dev)[5:5 + min(59, bcnt - len(data))]
    return r[4], bytes(data[:bcnt])


def init_channel(dev):
    nonce = os.urandom(8)
    write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + nonce)
    r = read(dev)
    assert r[7:15] == nonce, "INIT nonce mismatch"
    return bytes(r[15:19])


def token_for(dev, cid, pin, perm, rp=None):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    ph = hashlib.sha256(pin).digest()[:16]
    req = {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: perm}
    if rp is not None:
        req[0x0A] = rp
    tk = client_pin(dev, cid, ordered(req))
    assert tk[0] == 0x00, f"getPinUvAuthToken status {tk[0]:#x}"
    return proto, proto.decrypt(decode(tk[1:])[2])


def hmac(token, data):
    from cryptography.hazmat.primitives import hashes, hmac as chmac

    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def lb_set(dev, cid, token, offset, frag, length=None):
    vd = b"\xff" * 32 + bytes([LARGE_BLOBS, 0x00]) + offset.to_bytes(4, "little")
    vd += hashlib.sha256(frag).digest()
    f = {2: frag, 3: offset, 5: hmac(token, vd), 6: 2}
    if length is not None:
        f[4] = length
    return send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc(ordered(f)))


def cm(dev, cid, token, sub, subpara=None):
    payload = bytes([sub]) + (enc(subpara) if subpara else b"")
    req = {1: sub, 3: 2, 4: hmac(token, payload)}
    if subpara:
        req[2] = subpara
    return send_cbor(dev, cid, bytes([CRED_MGMT]) + enc(ordered(req)))


def cfg(dev, cid, token, sub, subpara=None):
    body = enc(subpara) if subpara else b""
    req = {1: sub, 3: 2, 4: hmac(token, b"\xff" * 32 + bytes([AUTH_CONFIG, sub]) + body)}
    if subpara:
        req[2] = subpara
    return send_cbor(dev, cid, bytes([AUTH_CONFIG]) + enc(ordered(req)))


def channels_and_lock(dev):
    print("\n1/2. CTAPHID channels + lock (§11.2.9.1.3, §11.2.9.2.2)")
    cids = [init_channel(dev) for _ in range(3)]
    check("a unique CID per broadcast INIT", len(set(cids)) == 3,
          " ".join(c.hex() for c in cids))
    a, b = cids[0], cids[1]
    write(dev, a + bytes([CTAPHID_INIT, 0, 8]) + os.urandom(8))
    check("INIT on an allocated CID echoes it", bytes(read(dev)[15:19]) == a)

    c, _ = raw(dev, a, CTAPHID_LOCK, bytes([2]))
    check("the owner takes a 2s lock", c == CTAPHID_LOCK, f"cmd {c:#04x}")
    c, p = raw(dev, b, CTAPHID_PING, b"hi")
    check("another channel gets ERR_CHANNEL_BUSY",
          c == CTAPHID_ERROR and p[:1] == bytes([ERR_CHANNEL_BUSY]))
    c, p = raw(dev, a, CTAPHID_PING, b"hi")
    check("the owner still passes", c == CTAPHID_PING and p[:2] == b"hi")
    raw(dev, a, CTAPHID_LOCK, bytes([0]))
    c, _ = raw(dev, b, CTAPHID_PING, b"hi")
    check("release frees the other channel", c == CTAPHID_PING)
    c, p = raw(dev, a, CTAPHID_LOCK, bytes([11]))
    check("a lock time over 10s is ERR_INVALID_PAR",
          c == CTAPHID_ERROR and p[:1] == bytes([ERR_INVALID_PAR]))
    c, p = raw(dev, a, CTAPHID_LOCK, b"")
    check("a lock with BCNT 0 is ERR_INVALID_LEN",
          c == CTAPHID_ERROR and p[:1] == bytes([ERR_INVALID_LEN]))


def make_credential_surface(dev, cid, pin, cdh, base, gi):
    print("\n3/4/5. makeCredential options, algorithms, credBlob (§6.1.2, §12.2)")
    _, token = token_for(dev, cid, pin, PERM_MC)
    req = ordered({**base, 7: {"uv": True}, 8: hmac(token, cdh), 9: 2})
    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(req))
    check("uv:true alongside a pinUvAuthParam is accepted (was 0x2C)",
          r[0] == 0x00, f"status {r[0]:#04x}")

    _, token = token_for(dev, cid, pin, PERM_MC)
    req = ordered({**base,
                   4: [{"alg": -7, "type": "public-key"},
                       {"alg": -48, "type": "public-key"}],
                   8: hmac(token, cdh), 9: 2})
    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(req))
    alg = None
    if r[0] == 0x00:
        ad = decode(r[1:])[2]
        alg = decode(ad[55 + int.from_bytes(ad[53:55], "big"):])[3]
    check("the first supported algorithm wins over a later ML-DSA",
          r[0] == 0x00 and alg == -7, f"alg {alg}")

    maxblob = gi[15]
    _, token = token_for(dev, cid, pin, PERM_MC)
    req = ordered({**base, 6: {"credBlob": bytes(maxblob)},
                   8: hmac(token, cdh), 9: 2})
    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(req))
    check(f"a credBlob of exactly maxCredBlobLength ({maxblob}) is accepted",
          r[0] == 0x00, f"status {r[0]:#04x}")


def make_cred_uv_not_rqd(dev, cid, cdh, base):
    """The whole makeCredUvNotRqd contract: what it permits, what it still refuses,
    and that the credential it mints on presence alone is a usable one."""
    print("\n6. makeCredUvNotRqd (§6.1.2 steps 7/10, issue #51)")
    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(base))
    ad = decode(r[1:])[2] if r[0] == 0x00 else b""
    check("a non-discoverable credential is created with a PIN set and no token",
          r[0] == 0x00, f"status {r[0]:#04x}")
    check("…and the response leaves the uv flag clear",
          bool(ad[32] & 0x04) is False if ad else False, f"flags {ad[32]:#04x}" if ad else "")
    check("…and sets up, since presence is what authorised it",
          bool(ad[32] & 0x01) is True if ad else False)
    if not ad:
        return
    cred_id = ad[55:55 + int.from_bytes(ad[53:55], "big")]

    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(ordered({**base, 7: {"rk": True}})))
    check("a discoverable credential still needs a token (PUAT_REQUIRED)",
          r[0] == 0x36, f"status {r[0]:#04x}")

    # The credential must actually work — a token-less create that yields an unusable
    # handle would be a regression dressed as a fix.
    ga = send_cbor(dev, cid, bytes([GET_ASSERTION]) + enc(ordered({
        1: RP, 2: cdh, 3: [{"id": cred_id, "type": "public-key"}]})))
    aad = decode(ga[1:])[2] if ga[0] == 0x00 else b""
    check("the credential it minted asserts without a token", ga[0] == 0x00,
          f"status {ga[0]:#04x}")
    check("…and that assertion is up-only, uv clear",
          bool(aad[32] & 0x01) and not (aad[32] & 0x04) if aad else False)

    # excludeList still recognises it — the UV-less path is not a blind spot.
    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(ordered({
        **base, 5: [{"id": cred_id, "type": "public-key"}]})))
    check("excludeList still matches a credential made this way (CREDENTIAL_EXCLUDED)",
          r[0] == 0x19, f"status {r[0]:#04x}")


def set_pin_already_set(dev, cid):
    print("\n7. clientPIN setPIN on a device that already has one (§6.5.5.5)")
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    npe = proto.encrypt(b"87654321" + b"\x00" * 56)
    sp = client_pin(dev, cid, ordered(
        {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe}))
    check("setPIN answers PIN_AUTH_INVALID (was NOT_ALLOWED)", sp[0] == 0x33,
          f"status {sp[0]:#04x}")


def large_blobs_surface(dev, cid, pin, gi):
    print("\n8. largeBlobs parameter validation (§6.10.2)")
    r = send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc({1: 10, 3: 0, 4: 32}))
    check("a get carrying `length` is INVALID_PARAMETER", r[0] == 0x02, f"{r[0]:#04x}")
    r = send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc(
        ordered({1: 10, 3: 0, 5: b"\x00" * 32, 6: 2})))
    check("a get carrying a pinUvAuthParam is INVALID_PARAMETER", r[0] == 0x02)
    frag = gi[5] - 64  # maxFragmentLength = maxMsgSize - 64; not a getInfo key
    r = send_cbor(dev, cid, bytes([LARGE_BLOBS]) + enc({1: frag + 1, 3: 0}))
    check(f"a get over maxFragmentLength ({frag}) is INVALID_LENGTH", r[0] == 0x03)

    _, token = token_for(dev, cid, pin, PERM_LBW)
    good = b"\x80" + hashlib.sha256(b"\x80").digest()[:16]  # the 17-byte empty array
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    r = lb_set(dev, cid, token, 0, bytes(bad), length=len(good))
    check("the 17-byte minimum array is hash-checked too (was exempt)", r[0] == 0x3D,
          f"status {r[0]:#04x}")
    r = lb_set(dev, cid, token, 0, good, length=len(good))
    check("…and an honest one still writes", r[0] == 0x00)
    # A completed transfer is terminal (audit run-28): the accumulator is disarmed.
    r = lb_set(dev, cid, token, len(good), b"")
    check("a re-commit at the end offset is INVALID_SEQ", r[0] == 0x04, f"{r[0]:#04x}")


def min_pin_length_overflow(dev, cid, pin):
    print("\n9. setMinPINLength with more RP ids than fit (§6.11)")
    _, token = token_for(dev, cid, pin, PERM_ACFG)
    rpids = [f"rp{i}.example" for i in range(9)]  # maxRPIDsForSetMinPINLength is 8
    r = cfg(dev, cid, token, 0x03, {0x02: rpids})
    check("KEY_STORE_FULL instead of a silent truncation", r[0] == 0x28,
          f"status {r[0]:#04x}")


def scoped_cm_token(dev, cid, pin, cdh, base):
    print("\n10. credentialManagement with an rpId-scoped token (§6.8.5/6.8.6)")
    _, token = token_for(dev, cid, pin, PERM_MC)
    req = ordered({**base, 7: {"rk": True}, 8: hmac(token, cdh), 9: 2})
    r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(req))
    assert r[0] == 0x00, f"resident makeCredential {r[0]:#x}"

    _, token = token_for(dev, cid, pin, PERM_CM, rp=RP)
    r = cm(dev, cid, token, 0x04, {1: hashlib.sha256(RP.encode()).digest()})
    assert r[0] == 0x00, f"enumerateCredentialsBegin {r[0]:#x}"
    cred_id = decode(r[1:])[7]["id"]

    r = cm(dev, cid, token, 0x01)
    check("a scoped token is still refused for a subcommand that names no rp",
          r[0] == 0x33, f"status {r[0]:#04x}")
    foreign = bytearray(cred_id)
    foreign[0] ^= 0xFF
    r = cm(dev, cid, token, 0x06, {2: {"id": bytes(foreign), "type": "public-key"}})
    check("an id it does not own is PIN_AUTH_INVALID, not NO_CREDENTIALS", r[0] == 0x33,
          f"status {r[0]:#04x}")
    r = cm(dev, cid, token, 0x06, {2: {"id": cred_id, "type": "public-key"}})
    check("it CAN delete its own rp's credential (was refused outright)", r[0] == 0x00,
          f"status {r[0]:#04x}")


def under_always_uv(dev, cid, pin, base):
    print("\n11. alwaysUv overrides makeCredUvNotRqd (§6.1.2 step 6) + U2F (§7.2.4)")
    _, token = token_for(dev, cid, pin, PERM_ACFG)
    assert cfg(dev, cid, token, 0x02)[0] == 0x00, "toggleAlwaysUv on failed"
    try:
        gi = decode(send_cbor(dev, cid, bytes([GET_INFO]))[1:])
        # §6.4: with alwaysUv on the authenticator MUST advertise it false — and the
        # enforcement has to agree, or a platform is told one thing and refused another.
        check("getInfo advertises makeCredUvNotRqd false",
              gi[4].get("makeCredUvNotRqd") is False, str(gi[4].get("makeCredUvNotRqd")))
        r = send_cbor(dev, cid, bytes([MAKE_CRED]) + enc(base))
        check("…and a token-less non-discoverable create is refused, matching it",
              r[0] == 0x36, f"status {r[0]:#04x}")
        check("getInfo drops U2F_V2", "U2F_V2" not in gi[1], str(gi[1]))
        apdu = bytes([0, 1, 0, 0, 0, 0, 0x40]) + os.urandom(64) + b"\x00\x00"
        _, p = raw(dev, cid, CTAPHID_MSG, apdu)
        check("REGISTER answers SW_COMMAND_NOT_ALLOWED 6986 (was 6985)",
              p[-2:] == b"\x69\x86", f"sw {p[-2:].hex()}")
    finally:
        _, token = token_for(dev, cid, pin, PERM_ACFG)
        cfg(dev, cid, token, 0x02)
        gi = decode(send_cbor(dev, cid, bytes([GET_INFO]))[1:])
        if gi[4].get("alwaysUv") is not False:
            sys.exit("FAIL: could not restore alwaysUv — turn it off by hand")
        print("  ok   alwaysUv restored to off")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", required=True, help="the device's FIDO2 PIN")
    args = ap.parse_args()
    pin = args.pin.encode()

    info = find()
    if not info:
        sys.exit("FAIL: no FIDO HID device")
    dev = hid.device()
    dev.open_path(info["path"])
    cid = ctaphid_init(dev)
    try:
        gi = decode(send_cbor(dev, cid, bytes([GET_INFO]))[1:])
        if gi[4].get("clientPin") is not True:
            sys.exit("FAIL: this suite needs a PIN set on the device")
        if gi[4].get("alwaysUv") is not False:
            sys.exit("FAIL: start with alwaysUv off (step 11 toggles it)")
        cdh = hashlib.sha256(b"spec-alignment").digest()
        base = ordered({
            1: cdh,
            2: {"id": RP},
            3: {"id": b"\x28\x28\x28\x28", "name": "spec"},
            4: [{"alg": -7, "type": "public-key"}],
        })

        channels_and_lock(dev)
        make_credential_surface(dev, cid, pin, cdh, base, gi)
        make_cred_uv_not_rqd(dev, cid, cdh, base)
        set_pin_already_set(dev, cid)
        large_blobs_surface(dev, cid, pin, gi)
        min_pin_length_overflow(dev, cid, pin)
        scoped_cm_token(dev, cid, pin, cdh, base)
        under_always_uv(dev, cid, pin, base)

        if fails:
            sys.exit(f"\n{len(fails)} failure(s): " + "; ".join(fails))
        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
