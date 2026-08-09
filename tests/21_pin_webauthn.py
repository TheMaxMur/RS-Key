#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: PIN-gated WebAuthn over CTAPHID_CBOR.

    nix develop -c python tests/21_pin_webauthn.py

Proves CTAP2.1 PIN/UV enforcement end-to-end on the device:
  1. getInfo            -> advertises options.clientPin + pinUvAuthProtocols
  2. clientPIN          -> setPIN + getPinToken (reuses the clientPIN platform side)
  3. makeCredential     -> with a pinUvAuthParam; authData carries the UV flag
  4. getAssertion       -> with a pinUvAuthParam; authData carries the UV flag
  5. makeCredential     -> no pinUvAuthParam: refused for rk, allowed without it
                           (makeCredUvNotRqd), and then the UV flag stays clear

The pinUvAuthParam is HMAC-SHA256(pinUvAuthToken, clientDataHash) (protocol two).

**One token per UP-gated operation.** A successful makeCredential/getAssertion
spends its token: CTAP 2.1 §6.5.5.7 has the authenticator clear the UP/UV flags
and every permission but largeBlobWrite once the user-presence test passes, so the
next command sees no permissions and answers PIN_AUTH_INVALID (0x33). That is what
a real platform does too, and it is the GHSA-wqjm-653g-hgw3 fix — a token that
survived the touch let a follow-on authenticatorConfig ride it. This test reused
one token across two makeCredentials until 2026-08-08 and had been failing since
that fix shipped in 0.4.1.

A clean device is assumed (flash rsk-wipe first); a second run reuses the PIN.
"""
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

PIN = b"1234"
RP_ID = "example.com"
UV_FLAG = 0x04
AT_FLAG = 0x40


def token_mac(token, data):
    """pinUvAuthParam for protocol two: HMAC-SHA256(token, data)."""
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. getInfo advertises clientPIN.
        gi = send_cbor(dev, cid, bytes([0x04]))
        assert gi[0] == 0x00, f"getInfo status {gi[0]:#x}"
        m = decode(gi[1:])
        assert "clientPin" in m[4] and m[4]["pinUvAuthToken"] is True, "clientPin not advertised"
        assert set(m[6]) == {1, 2}, f"pinUvAuthProtocols {m[6]}"
        print(f"getInfo: clientPin={m[4]['clientPin']}, pinUvAuthProtocols={m[6]}")

        # 2. clientPIN: key agreement, setPIN (idempotent), getPinToken.
        ka = client_pin(dev, cid, {1: 2, 2: 2})
        cose = decode(ka[1:])[1]
        proto = Protocol2(cose[-2], cose[-3])
        padded = PIN + b"\x00" * (64 - len(PIN))
        npe = proto.encrypt(padded)
        sp = client_pin(dev, cid, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe})
        # 0x33 = PIN_AUTH_INVALID, what CTAP 2.1 §6.5.5.5 returns when a PIN is
        # already set (changePIN is the only way to replace one).
        assert sp[0] in (0x00, 0x33), f"setPIN status {sp[0]:#x}"
        ph = hashlib.sha256(PIN).digest()[:16]

        def new_token():
            """A freshly minted pinUvAuthToken. One per UP-gated command — the
            previous one was spent by the touch (see the module docstring). The
            ECDH shared secret outlives the token, so only getPinToken repeats."""
            tk = client_pin(dev, cid, {1: 2, 2: 5, 3: proto.cose(), 6: proto.encrypt(ph)})
            assert tk[0] == 0x00, f"getPinToken status {tk[0]:#x}"
            return proto.decrypt(decode(tk[1:])[2])

        print("clientPIN: pinUvAuthToken obtained")

        cdh = hashlib.sha256(b"rs-key test").digest()

        def make_cred(user):
            r = send_cbor(dev, cid, bytes([0x01]) + enc({
                1: cdh,
                2: {"id": RP_ID},
                3: {"id": user, "name": "u"},
                4: [{"alg": -7, "type": "public-key"}],
                7: {"rk": True},  # resident, so getAssertion can discover it
                8: token_mac(new_token(), cdh),
                9: 2,
            }))
            assert r[0] == 0x00, f"makeCredential status {r[0]:#x}"
            ad = decode(r[1:])[2]
            assert ad[32] & AT_FLAG and ad[32] & UV_FLAG, f"flags {ad[32]:#x}"
            return ad

        # 3. Two resident credentials for the same RP (distinct users) -> UV set.
        make_cred(b"\xAA\xAA\xAA\xAA")
        make_cred(b"\xBB\xBB\xBB\xBB")
        print("makeCredential x2: resident, UV set")

        # 4. getAssertion with no allowList -> resident discovery + numberOfCredentials.
        ga = send_cbor(dev, cid, bytes([0x02]) + enc({
            1: RP_ID,
            2: cdh,
            6: token_mac(new_token(), cdh),
            7: 2,
        }))
        assert ga[0] == 0x00, f"getAssertion status {ga[0]:#x}"
        m = decode(ga[1:])
        assert m[2][32] & UV_FLAG, f"UV flag missing (flags {m[2][32]:#x})"
        count = m.get(5)
        assert count is not None and count >= 2, f"numberOfCredentials {count}"
        print(f"getAssertion (discovery): UV set, numberOfCredentials={count}")

        # 5. getNextAssertion -> the next credential, UV set, no count field.
        gn = send_cbor(dev, cid, bytes([0x08]))
        assert gn[0] == 0x00, f"getNextAssertion status {gn[0]:#x}"
        mn = decode(gn[1:])
        assert mn[2][32] & UV_FLAG, f"UV flag missing (flags {mn[2][32]:#x})"
        assert 5 not in mn, "getNextAssertion must omit numberOfCredentials"
        print("getNextAssertion: next credential, UV set")

        # 6. A DISCOVERABLE makeCredential without a pinUvAuthParam is refused
        # (PUAT_REQUIRED): makeCredUvNotRqd (§6.1.2 step 7) does not cover rk.
        mc2 = send_cbor(dev, cid, bytes([0x01]) + enc({
            1: cdh,
            2: {"id": RP_ID},
            3: {"id": b"\xCC\xCC\xCC\xCC", "name": "u"},
            4: [{"alg": -7, "type": "public-key"}],
            7: {"rk": True},
        }))
        assert mc2[0] == 0x36, f"expected PUAT_REQUIRED (0x36), got {mc2[0]:#x}"
        print("resident makeCredential without PIN -> PUAT_REQUIRED (0x36)")

        # 7. The same request WITHOUT rk succeeds on presence alone, UV clear
        # (§6.1.2 step 10, makeCredUvNotRqd — issue #51).
        mc3 = send_cbor(dev, cid, bytes([0x01]) + enc({
            1: cdh,
            2: {"id": RP_ID},
            3: {"id": b"\xDD\xDD\xDD\xDD", "name": "u"},
            4: [{"alg": -7, "type": "public-key"}],
        }))
        assert mc3[0] == 0x00, f"makeCredential (non-resident) status {mc3[0]:#x}"
        ad3 = decode(mc3[1:])[2]
        assert ad3[32] & AT_FLAG and not ad3[32] & UV_FLAG, f"flags {ad3[32]:#x}"
        print("non-resident makeCredential without PIN -> OK, UV clear")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
