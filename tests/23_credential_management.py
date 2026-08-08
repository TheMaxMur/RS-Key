#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: authenticatorCredentialManagement over CTAPHID_CBOR.

    nix develop -c python tests/23_credential_management.py

Exercises every credentialManagement subcommand on the device:
  1. getInfo                       -> options.credMgmt advertised
  2. reset + clientPIN             -> token with the cm permission (0x04)
  3. makeCredential x3             -> 2 residents for example.com, 1 for other.com
  4. getCredsMetadata (0x01)       -> existing == 3
  5. enumerateRPs Begin/Next       -> 2 RPs, then getNextRP -> NOT_ALLOWED
  6. enumerateCredentials Begin/Next (example.com) -> 2 creds, then -> NOT_ALLOWED
  7. deleteCredential (0x06)       -> metadata drops to 2
  8. updateUserInformation (0x07)  -> the remaining cred's name changes
  9. pcmr token (CTAP 2.2)         -> reads OK, writers refuse it, survives a replug

The credMgmt pinUvAuthParam is HMAC-SHA256(token, subcommand ‖ rawSubCommandParams)
for 0x04/0x06/0x07 and HMAC-SHA256(token, subcommand) for 0x01/0x02 (protocol two).
Self-contained and idempotent: resets at start and end. Needs `cryptography`.
Each reset asks for a replug — CTAP 2.1 §6.6 accepts one only just after power-up
(see replug.py).
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
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

PIN = b"12345678"
PERM_MC = 0x01  # makeCredential
PERM_CM = 0x04  # credentialManagement
PERM_PCMR = 0x40  # persistent credential management, read-only (CTAP 2.2)
CM = 0x0A  # CTAP_CREDENTIAL_MGMT
RP1, RP2 = "example.com", "other.com"


def token_mac(token, data):
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def cm_request(subcmd, subpara, token):
    """credentialManagement params, MAC over `subcmd ‖ subpara`."""
    mac = token_mac(token, bytes([subcmd]) + (subpara or b""))
    req = bytearray([0xA0 | (4 if subpara else 3)])
    req += bytes([0x01, subcmd])
    if subpara:
        req += bytes([0x02]) + subpara
    req += bytes([0x03, 0x02])  # pinUvAuthProtocol = 2
    req += bytes([0x04, 0x58, len(mac)]) + mac
    return bytes(req)


def cm_next(subcmd):
    return bytes([0xA1, 0x01, subcmd])  # {1: subcommand}


def cred_desc(cred_id):
    return {"id": cred_id, "type": "public-key"}


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. getInfo advertises credMgmt.
        gi = send_cbor(dev, cid, bytes([0x04]))
        assert gi[0] == 0x00, f"getInfo status {gi[0]:#x}"
        assert decode(gi[1:])[4].get("credMgmt") is True, "options.credMgmt not advertised"
        print("getInfo: options.credMgmt = True")

        # 2. Clean slate, then a PIN. The key agreement is reused for every token
        # fetch below.
        dev, cid = replug.reset(dev, "step 2's clean slate")
        ka = client_pin(dev, cid, {1: 2, 2: 2})
        cose = decode(ka[1:])[1]
        proto = Protocol2(cose[-2], cose[-3])
        padded = PIN + b"\x00" * (64 - len(PIN))
        npe = proto.encrypt(padded)
        sp = client_pin(dev, cid, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe})
        # 0x33 = PIN_AUTH_INVALID, what CTAP 2.1 §6.5.5.5 returns when a PIN is
        # already set (a second run against the same device).
        assert sp[0] in (0x00, 0x33), f"setPIN status {sp[0]:#x}"
        ph = hashlib.sha256(PIN).digest()[:16]

        def get_token(perm):
            """A fresh pinUvAuthToken with permissions `perm`. Each fetch resets the
            token value and clears its rpId binding (getPinUvAuthTokenUsingPin-
            WithPermissions, subcommand 0x09)."""
            tk = client_pin(dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: perm})
            assert tk[0] == 0x00, f"getPinUvAuthToken status {tk[0]:#x}"
            return proto.decrypt(decode(tk[1:])[2])

        print("clientPIN: PIN set, key agreement established")

        # 3. Register three resident credentials. makeCredential binds the token to
        # the rpId on first use, so a fresh mc-token is fetched per credential
        # (one token can't span two RPs).
        cdh = hashlib.sha256(b"rs-key test").digest()

        def make_cred(rp, user, name):
            mc_token = get_token(PERM_MC)
            r = send_cbor(dev, cid, bytes([0x01]) + enc({
                1: cdh,
                2: {"id": rp},
                3: {"id": user, "name": name},
                4: [{"alg": -7, "type": "public-key"}],
                7: {"rk": True},
                8: token_mac(mc_token, cdh),
                9: 2,
            }))
            assert r[0] == 0x00, f"makeCredential status {r[0]:#x}"
            ad = decode(r[1:])[2]
            clen = int.from_bytes(ad[53:55], "big")
            return ad[55:55 + clen]  # 42-byte resident id

        make_cred(RP1, b"\xAA\xAA\xAA\xAA", "alice")
        make_cred(RP1, b"\xBB\xBB\xBB\xBB", "bob")
        make_cred(RP2, b"\xCC\xCC\xCC\xCC", "carol")
        print("makeCredential x3: 2 for example.com, 1 for other.com")

        # A fresh, unbound token with the cm permission drives all of credMgmt.
        token = get_token(PERM_CM)
        print("clientPIN: token with cm permission")

        def metadata(tok=None):
            r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x01, None, tok or token))
            assert r[0] == 0x00, f"getCredsMetadata status {r[0]:#x}"
            return decode(r[1:])[1]

        # 4. getCredsMetadata.
        assert metadata() == 3, "expected 3 existing residents"
        print("getCredsMetadata: existing = 3")

        # 5. enumerateRPs Begin/Next.
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x02, None, token))
        assert r[0] == 0x00, f"enumerateRPsBegin status {r[0]:#x}"
        m = decode(r[1:])
        assert m[5] == 2, f"rpTotal {m[5]}"
        rps = {m[3]["id"]}
        r = send_cbor(dev, cid, bytes([CM]) + cm_next(0x03))
        assert r[0] == 0x00, f"getNextRP status {r[0]:#x}"
        rps.add(decode(r[1:])[3]["id"])
        assert rps == {RP1, RP2}, f"RPs {rps}"
        r = send_cbor(dev, cid, bytes([CM]) + cm_next(0x03))
        assert r[0] == 0x30, f"exhausted getNextRP expected NOT_ALLOWED, got {r[0]:#x}"
        print(f"enumerateRPs: {sorted(rps)}, then getNextRP -> NOT_ALLOWED")

        # 6. enumerateCredentials Begin/Next for example.com — collect (user, credId).
        rp1_hash = hashlib.sha256(RP1.encode()).digest()
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x04, enc({1: rp1_hash}), token))
        assert r[0] == 0x00, f"enumerateCredentialsBegin status {r[0]:#x}"
        m = decode(r[1:])
        assert m[9] == 2, f"credTotal {m[9]}"
        creds = [(bytes(m[6]["id"]), bytes(m[7]["id"]))]
        r = send_cbor(dev, cid, bytes([CM]) + cm_next(0x05))
        assert r[0] == 0x00, f"getNextCredential status {r[0]:#x}"
        m = decode(r[1:])
        creds.append((bytes(m[6]["id"]), bytes(m[7]["id"])))
        assert {u for u, _ in creds} == {b"\xAA\xAA\xAA\xAA", b"\xBB\xBB\xBB\xBB"}, f"users {creds}"
        r = send_cbor(dev, cid, bytes([CM]) + cm_next(0x05))
        assert r[0] == 0x30, f"exhausted getNextCredential expected NOT_ALLOWED, got {r[0]:#x}"
        print("enumerateCredentials: 2 creds for example.com, then -> NOT_ALLOWED")

        # 7. deleteCredential -> metadata drops to 2.
        del_user, del_id = creds[0]
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x06, enc({2: cred_desc(del_id)}), token))
        assert r[0] == 0x00, f"deleteCredential status {r[0]:#x}"
        assert metadata() == 2, "metadata did not drop after delete"
        print("deleteCredential: existing 3 -> 2")

        # 8. updateUserInformation: rename the surviving example.com credential.
        keep_user, keep_id = creds[1]
        sub = enc({2: cred_desc(keep_id), 3: {"id": keep_user, "name": "bob2", "displayName": "Bob Two"}})
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x07, sub, token))
        assert r[0] == 0x00, f"updateUserInformation status {r[0]:#x}"
        # Re-enumerate example.com: one credential, new name.
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x04, enc({1: rp1_hash}), token))
        assert r[0] == 0x00, f"re-enumerate status {r[0]:#x}"
        m = decode(r[1:])
        assert m[9] == 1 and m[6]["name"] == "bob2", f"update not reflected: {m[6]}"
        print("updateUserInformation: name -> 'bob2'")

        # 9. pcmr (CTAP 2.2 §6.8.2/.3/.4): the persistent token is a read-only
        # credential-management grant — it drives the three readers, both writers
        # refuse it, and it outlives the power cycle. The last leg is the whole
        # point of "persistent" and only real hardware can show it.
        assert decode(gi[1:])[4].get("perCredMgmtRO") is True, "options.perCredMgmtRO absent"
        pcmr = get_token(PERM_PCMR)
        assert pcmr != token, "pcmr must not hand back a session token"
        assert metadata(pcmr) == 2, "getCredsMetadata under pcmr"
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x02, None, pcmr))
        assert r[0] == 0x00, f"enumerateRPsBegin under pcmr: {r[0]:#x}"
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x04, enc({1: rp1_hash}), pcmr))
        assert r[0] == 0x00, f"enumerateCredentialsBegin under pcmr: {r[0]:#x}"
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x06, enc({2: cred_desc(keep_id)}), pcmr))
        assert r[0] == 0x33, f"deleteCredential under pcmr wanted PIN_AUTH_INVALID, got {r[0]:#x}"
        print("pcmr: 3 reads OK, deleteCredential -> PIN_AUTH_INVALID")

        # The clean-up power cycle does double duty: it proves the grant survives a
        # replug (no clientPIN exchange in between — the key agreement died with the
        # power), and it opens the §6.6 window the clean-up reset needs.
        dev.close()
        print("\n👉 UNPLUG the key, then plug it straight back in — the pcmr token must "
              "survive the power cycle, and the clean-up reset needs the §6.6 window.")
        replug.wait_gone()
        dev, cid, seen = replug.wait_back()
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x02, None, pcmr))
        assert r[0] == 0x00, f"the pcmr token died on the power cycle: {r[0]:#x}"
        print("pcmr: still enumerates after a real power cycle")

        # Clean up — and authenticatorReset resets the persistent PUAT state (§6.6),
        # so the same token must stop verifying. An un-revoked one would reach the
        # empty store and answer NO_CREDENTIALS (0x2e) instead.
        r = send_cbor(dev, cid, bytes([0x07]))
        assert r[0] == 0x00, (f"clean-up reset {time.time() - seen:.1f}s after attach: {r[0]:#x} "
                              "(0x30 = past the window, just rerun)")
        r = send_cbor(dev, cid, bytes([CM]) + cm_request(0x02, None, pcmr))
        assert r[0] == 0x33, f"reset must revoke the pcmr grant, got {r[0]:#x}"
        print("reset: the pcmr grant is revoked")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
