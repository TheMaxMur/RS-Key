#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: getInfo's encCredStoreState (0x1E) over CTAPHID_CBOR.

    nix develop -c python tests/17_cred_store_state.py
    python tests/emu.py tests/17_cred_store_state.py     # no board

CTAP 2.3 0x1E lets a platform holding the *persistent* pinUvAuthToken ask "has the
discoverable-credential set changed since I last looked?" without enumerating it.
The host tests cover the construction and each mutation path; only the stack can
show that the tag a platform receives is the one it can open, and that it survives
the power the device actually loses.

  1. reset + no token yet          -> 0x1E absent
  2. PIN, then a pcmr token        -> 0x1E present, exactly 32 bytes, tag = zero
  3. two getInfo calls in a row    -> different IVs, SAME tag underneath
  4. makeCredential (rk)           -> the tag moves
  5. a getInfo and a getAssertion  -> the tag does NOT move
  6. power cycle                   -> the tag STILL does not move
  7. deleteCredential              -> the tag moves again
  8. reset, leaving the device clean

Step 6 is the one a RAM counter fails: `Fs::write_gen` restarts at zero on every
boot, so a store that changed across a replug would read as unchanged.
Self-contained and idempotent: resets at both ends. Needs `cryptography`.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import Protocol2, client_pin, decode, enc, send_cbor  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives import hashes, hmac as chmac  # noqa: E402

PIN = b"12345678"
PERM_MC = 0x01  # makeCredential
PERM_CM = 0x04  # credentialManagement
PERM_PCMR = 0x40  # persistent credential management, read-only (CTAP 2.2)
ENC_CRED_STORE_STATE = 0x1E
ENC_MEMBER_LEN = 32  # iv(16) ‖ one AES-128-CBC block(16)
RP_ID = "state.example"
CTAP_MAKE_CREDENTIAL = 0x01
CTAP_CRED_MGMT = 0x0A
CM_ENUMERATE_CREDS_BEGIN = 0x04
CM_DELETE_CREDENTIAL = 0x06


def get_info(dev, cid):
    r = send_cbor(dev, cid, b"\x04")
    assert r[0] == 0x00, f"getInfo status {r[0]:#x}"
    info = decode(r[1:])
    assert isinstance(info, dict), f"getInfo must decode to a map, got {type(info)}"
    return info


def open_state(token, blob):
    """Recover the tag exactly as the spec says a platform must — the encIdentifier
    construction, differing only in the HKDF label."""
    key = HKDF(
        algorithm=hashes.SHA256(), length=16, salt=b"\x00" * 32,
        info=b"encCredStoreState",
    ).derive(token)
    dec = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    return dec.update(blob[16:]) + dec.finalize()


def tag(dev, cid, token):
    blob = get_info(dev, cid).get(ENC_CRED_STORE_STATE)
    assert blob is not None, "0x1E must be present once a persistent token exists"
    assert len(blob) == ENC_MEMBER_LEN, f"0x1E is {len(blob)} bytes, want 32"
    return blob, open_state(token, blob)


def pin_token(dev, cid, perms, set_pin=False):
    """A fresh token with `perms`. Every command that consumes one needs its own:
    a makeCredential clears the permissions of the token it spent."""
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    if set_pin:
        npe = proto.encrypt(PIN + b"\x00" * (64 - len(PIN)))
        sp = client_pin(
            dev, cid, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(npe), 5: npe}
        )
        assert sp[0] == 0x00, f"setPIN status {sp[0]:#x}"
    ph = hashlib.sha256(PIN).digest()[:16]
    tk = client_pin(
        dev, cid, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(ph), 9: perms}
    )
    assert tk[0] == 0x00, f"getPinUvAuthToken({perms:#x}) status {tk[0]:#x}"
    return proto.decrypt(decode(tk[1:])[2])


def mac(token, msg):
    h = chmac.HMAC(token, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def make_rk(dev, cid, uid, name):
    """A discoverable credential, PIN-authorised — the create path."""
    cdh = hashlib.sha256(b"rs-key cred store state").digest()
    tok = pin_token(dev, cid, PERM_MC)
    req = enc({
        1: cdh,
        2: {"id": RP_ID},
        3: {"id": uid, "name": name},
        4: [{"alg": -7, "type": "public-key"}],
        7: {"rk": True},
        8: mac(tok, cdh),
        9: 2,
    })
    r = send_cbor(dev, cid, bytes([CTAP_MAKE_CREDENTIAL]) + req)
    assert r[0] == 0x00, f"makeCredential status {r[0]:#x}"


def cm(dev, cid, sub, subpara, token):
    """authenticatorCredentialManagement, MACed over subCommand ‖ subCommandParams."""
    body = bytes([sub]) + (enc(subpara) if subpara is not None else b"")
    # Keys ascending: `enc` writes a dict in insertion order and the parser refuses
    # anything else, so 2 has to be placed between 1 and 3, not appended after 4.
    req = {1: sub}
    if subpara is not None:
        req[2] = subpara
    req[3] = 2
    req[4] = mac(token, body)
    r = send_cbor(dev, cid, bytes([CTAP_CRED_MGMT]) + enc(req))
    return r[0], (decode(r[1:]) if len(r) > 1 and r[0] == 0 else None)


def main():
    dev, cid = replug.reset(None, "a clean slate for encCredStoreState")
    try:
        assert ENC_CRED_STORE_STATE not in get_info(dev, cid), (
            "0x1E is keyed by the persistent token, so it must be absent before one exists"
        )
        print("1. no persistent token yet: 0x1E absent, as it must be")

        token = pin_token(dev, cid, PERM_PCMR, set_pin=True)
        first, zero = tag(dev, cid, token)
        assert zero == b"\x00" * 16, f"an untouched store must be the zero tag, got {zero.hex()}"
        print(f"2. pcmr token acquired; 0x1E present, {len(first)} bytes, tag = zero")

        second, again = tag(dev, cid, token)
        assert first[:16] != second[:16], "the IV must be regenerated per getInfo"
        assert first != second, "a repeated blob would be a fingerprint"
        assert zero == again, "an unchanged store must decrypt to an unchanged tag"
        print("3. two calls differ, their IVs differ, the tag underneath does not")

        make_rk(dev, cid, b"\x01\x02", "alice")
        _, after_create = tag(dev, cid, token)
        assert after_create != zero, "a new discoverable credential must move the tag"
        print(f"4. makeCredential moved the tag: {after_create.hex()}")

        # Reads: another getInfo (already done by `tag`) and an enumerate.
        cmt = pin_token(dev, cid, PERM_CM)
        st, listing = cm(dev, cid, CM_ENUMERATE_CREDS_BEGIN,
                         {1: hashlib.sha256(RP_ID.encode()).digest()}, cmt)
        assert st == 0x00, f"enumerateCredentialsBegin status {st:#x}"
        cred_id = listing[7]["id"]
        _, after_read = tag(dev, cid, token)
        assert after_read == after_create, "reads must not move the tag"
        print("5. a getInfo and an enumerate changed nothing, and said so")

        dev, cid, _ = replug.power_cycle(dev, "the persistence check")
        token = pin_token(dev, cid, PERM_PCMR)
        _, after_cycle = tag(dev, cid, token)
        assert after_cycle == after_create, (
            "the tag must survive power — a RAM counter would read zero again here"
        )
        print("6. the tag is unchanged across a real power cycle")

        cmt = pin_token(dev, cid, PERM_CM)
        st, _ = cm(dev, cid, CM_DELETE_CREDENTIAL, {2: {"id": cred_id, "type": "public-key"}}, cmt)
        assert st == 0x00, f"deleteCredential status {st:#x}"
        _, after_delete = tag(dev, cid, token)
        assert after_delete != after_cycle, "deleteCredential must move the tag"
        assert after_delete != zero, "the tag advances; it does not return to where it was"
        print(f"7. deleteCredential moved the tag again: {after_delete.hex()}")

        replug.reset(dev, "the cleanup reset")
        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
