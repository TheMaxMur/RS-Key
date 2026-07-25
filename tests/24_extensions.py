#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: FIDO2 extensions over CTAPHID_CBOR.

    nix develop -c python tests/24_extensions.py

Exercises the credProtect / credBlob / hmac-secret / largeBlobKey extensions and
the getInfo advertisement on the device:
  1. getInfo                 -> extensions (0x02) + maxCredBlobLength (0x0F)
  2. reset
  3. makeCredential (rk)      -> ext {credProtect: 2, credBlob}; authData has the
                                ED flag + the credProtect/credBlob extension map
  4. getAssertion (allowList) -> credBlob echoed back in the authData extensions
  5. getAssertion (discovery) -> NO_CREDENTIALS (credProtect=2 hidden without UV)
  6. reset + makeCredential   -> ext {hmac-secret: true, largeBlobKey: true}
  7. getKeyAgreement          -> the platform ECDH key (protocol two)
  8. getAssertion (hmac)      -> hmac-secret output in authData (decrypts to a
                                32-byte value, deterministic per salt) + the
                                largeBlobKey response field (0x07)

The minPinLength extension and the PIN-gated config path are covered by the host
tests. Self-contained; resets at the start and before step 6, and asks for a
replug at each one — CTAP 2.1 §6.6 accepts a reset only just after power-up (see
replug.py).
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402
from ctaphid import (  # noqa: E402
    CTAPHID_INIT,
    Protocol2,
    _dec,
    client_pin,
    decode,
    enc,
    find,
    read,
    send_cbor,
    write,
)

RP_ID = "example.com"
ED_FLAG = 0x80
CRED_BLOB = b"\x01\x02\x03\x04\x05"


def auth_data_ext(ad, attested):
    """The authData extension map (or {}). `attested` marks makeCredential
    authData (which carries attestedCredentialData before the extensions)."""
    if attested:
        cred_len = (ad[53] << 8) | ad[54]
        _, idx = _dec(ad, 55 + cred_len)  # skip the COSE public key
    else:
        idx = 37
    return _dec(ad, idx)[0] if idx < len(ad) else {}


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        # 1. getInfo advertises the extensions + maxCredBlobLength.
        gi = send_cbor(dev, cid, bytes([0x04]))
        assert gi[0] == 0x00, f"getInfo status {gi[0]:#x}"
        m = decode(gi[1:])
        exts = m.get(2, [])
        for want in ("credBlob", "credProtect", "minPinLength", "thirdPartyPayment"):
            assert want in exts, f"extension {want!r} not advertised: {exts}"
        assert m.get(0x0F) == 128, f"maxCredBlobLength {m.get(0x0F)}"
        print(f"getInfo: extensions={exts}, maxCredBlobLength={m[0x0F]}")

        # 2. reset.
        dev, cid = replug.reset(dev, "step 2's reset")

        cdh = hashlib.sha256(b"rs-key test").digest()

        # 3. makeCredential (resident) with credProtect + credBlob.
        mc = send_cbor(dev, cid, bytes([0x01]) + enc({
            1: cdh,
            2: {"id": RP_ID},
            3: {"id": b"\xAA\xAA\xAA\xAA", "name": "u"},
            4: [{"alg": -7, "type": "public-key"}],
            6: {"credProtect": 2, "credBlob": CRED_BLOB},
            7: {"rk": True},
        }))
        assert mc[0] == 0x00, f"makeCredential status {mc[0]:#x}"
        ad = decode(mc[1:])[2]
        assert ad[32] & ED_FLAG, f"ED flag missing (flags {ad[32]:#x})"
        ext = auth_data_ext(ad, attested=True)
        assert ext.get("credProtect") == 2, f"authData credProtect {ext}"
        assert ext.get("credBlob") is True, f"authData credBlob {ext}"
        cred_len = (ad[53] << 8) | ad[54]
        cred_id = ad[55:55 + cred_len]
        print(f"makeCredential: ED set, ext={ext}, credId={len(cred_id)}B")

        # 4. getAssertion via allowList -> credBlob echoed (credProtect=2 visible).
        ga = send_cbor(dev, cid, bytes([0x02]) + enc({
            1: RP_ID,
            2: cdh,
            3: [{"id": cred_id, "type": "public-key"}],
            4: {"credBlob": True},
        }))
        assert ga[0] == 0x00, f"getAssertion status {ga[0]:#x}"
        gad = decode(ga[1:])[2]
        assert gad[32] & ED_FLAG, f"ED flag missing (flags {gad[32]:#x})"
        gext = auth_data_ext(gad, attested=False)
        assert gext.get("credBlob") == CRED_BLOB, f"credBlob echo {gext}"
        print(f"getAssertion (allowList): ED set, credBlob echoed ({len(gext['credBlob'])}B)")

        # 5. getAssertion discovery (no allowList, no UV) -> hidden (credProtect=2).
        gd = send_cbor(dev, cid, bytes([0x02]) + enc({1: RP_ID, 2: cdh}))
        assert gd[0] == 0x2E, f"expected NO_CREDENTIALS (0x2e), got {gd[0]:#x}"
        print("getAssertion (discovery): NO_CREDENTIALS — credProtect=2 hidden without UV")

        # 6. Fresh credential opting into hmac-secret + largeBlobKey.
        dev, cid = replug.reset(dev, "step 6's reset")
        mc = send_cbor(dev, cid, bytes([0x01]) + enc({
            1: cdh,
            2: {"id": RP_ID},
            3: {"id": b"\xBB\xBB\xBB\xBB", "name": "u"},
            4: [{"alg": -7, "type": "public-key"}],
            6: {"hmac-secret": True, "largeBlobKey": True},
            7: {"rk": True},
        }))
        assert mc[0] == 0x00, f"makeCredential status {mc[0]:#x}"
        ad = decode(mc[1:])[2]
        cred_len = (ad[53] << 8) | ad[54]
        cred_id = ad[55:55 + cred_len]

        # 7. getKeyAgreement -> the platform ECDH helper (protocol two).
        ka = client_pin(dev, cid, {1: 2, 2: 2})
        assert ka[0] == 0x00, f"getKeyAgreement status {ka[0]:#x}"
        cose = decode(ka[1:])[1]
        proto = Protocol2(cose[-2], cose[-3])

        # 8. getAssertion with hmac-secret + largeBlobKey.
        salt = bytes(range(32))
        salt_enc = proto.encrypt(salt)
        salt_auth = proto.authenticate(salt_enc)
        hmac_ext = {1: proto.cose(), 2: salt_enc, 3: salt_auth, 4: 2}

        def hmac_assertion():
            ga = send_cbor(dev, cid, bytes([0x02]) + enc({
                1: RP_ID,
                2: cdh,
                3: [{"id": cred_id, "type": "public-key"}],
                4: {"hmac-secret": hmac_ext, "largeBlobKey": True},
            }))
            assert ga[0] == 0x00, f"getAssertion status {ga[0]:#x}"
            return decode(ga[1:])

        m = hmac_assertion()
        gad = m[2]
        assert gad[32] & ED_FLAG, f"ED flag missing (flags {gad[32]:#x})"
        ext = auth_data_ext(gad, attested=False)
        enc_out = ext.get("hmac-secret")
        assert enc_out is not None and len(enc_out) == 48, f"hmac-secret output {ext}"
        out1 = proto.decrypt(enc_out)
        assert len(out1) == 32, f"decrypted hmac-secret len {len(out1)}"
        lbk = m.get(7)
        assert lbk is not None and len(lbk) == 32, f"largeBlobKey field {lbk}"
        print(f"getAssertion (hmac-secret): output decrypts to {len(out1)}B, largeBlobKey {len(lbk)}B")

        # The hmac-secret output is deterministic per (credential, salt).
        ext2 = auth_data_ext(hmac_assertion()[2], attested=False)
        out2 = proto.decrypt(ext2["hmac-secret"])
        assert out1 == out2, "hmac-secret must be deterministic for the same salt"
        print("getAssertion (hmac-secret): deterministic across calls")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
