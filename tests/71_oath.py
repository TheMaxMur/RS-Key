#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""YKOATH applet test — drive the OATH applet over PC/SC.

Exercises the full protocol the way ykman / Yubico Authenticator do: PUT
credentials (TOTP SHA1/SHA256/SHA512 + HOTP), CALCULATE against the RFC
4226/6238 reference vectors, LIST, CALCULATE ALL, RENAME, GET CREDENTIAL
(password-safe fields), VERIFY CODE, and the access-code lifecycle
(SET CODE → SELECT challenge → VALIDATE mutual auth → remove).

Idempotent: starts and ends with RESET (P1P2=0xDEAD), which touches only the
OATH slots — FIDO and OpenPGP state is unaffected. Run from the venv that has
pyscard:

    nix develop -c python tests/71_oath.py
"""
import hashlib
import hmac as hmac_mod
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]

INS_PUT, INS_DELETE, INS_SET_CODE, INS_RESET, INS_RENAME = 0x01, 0x02, 0x03, 0x04, 0x05
INS_LIST, INS_CALCULATE, INS_VALIDATE, INS_CALC_ALL = 0xA1, 0xA2, 0xA3, 0xA4
INS_VERIFY_CODE, INS_GET_CREDENTIAL = 0xB1, 0xB5

TAG_NAME, TAG_NAME_LIST, TAG_KEY, TAG_CHALLENGE = 0x71, 0x72, 0x73, 0x74
TAG_RESPONSE, TAG_T_RESPONSE, TAG_NO_RESPONSE = 0x75, 0x76, 0x77
TAG_PROPERTY, TAG_T_VERSION, TAG_ALGO = 0x78, 0x79, 0x7B
TAG_PWS_LOGIN, TAG_PWS_PASSWORD = 0x83, 0x84

ALG_SHA1, ALG_SHA256, ALG_SHA512 = 0x01, 0x02, 0x03
TYPE_HOTP, TYPE_TOTP = 0x10, 0x20

# RFC 6238 appendix B reference secrets; time 59 s → T = 1 (8-digit codes).
SECRET_SHA1 = b"12345678901234567890"
SECRET_SHA256 = b"12345678901234567890123456789012"
SECRET_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"
T1 = struct.pack(">Q", 1)


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def tlv(tag, val):
    assert len(val) < 128
    return bytes([tag, len(val)]) + bytes(val)


def tlv_parse(blob):
    """Walk short-form TLVs into an ordered (tag, value) list."""
    out, i = [], 0
    while i + 2 <= len(blob):
        tag, ln = blob[i], blob[i + 1]
        if i + 2 + ln > len(blob):
            break
        out.append((tag, bytes(blob[i + 2 : i + 2 + ln])))
        i += 2 + ln
    return out


def tlv_get(blob, tag):
    return next((v for t, v in tlv_parse(blob) if t == tag), None)


class Oath:
    def __init__(self, conn):
        self.conn = conn

    def apdu(self, ins, p1, p2, data=b"", want=0x9000):
        cmd = [0x00, ins, p1, p2]
        if data:
            cmd += [len(data)] + list(data)
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) | sw2
        if want is not None and sw != want:
            fail(f"INS {ins:02X}: SW {sw:04X} != {want:04X}")
        return bytes(resp), sw

    def select(self):
        resp, sw1, sw2 = self.conn.transmit([0x00, 0xA4, 0x04, 0x00, len(OATH_AID)] + OATH_AID)
        sw = (sw1 << 8) | sw2
        if sw == 0x6A82:
            fail("OATH AID not found — device runs firmware without the OATH applet?")
        if sw != 0x9000:
            fail(f"SELECT OATH: SW {sw:04X}")
        return bytes(resp)

    def put(self, name, ty_alg, digits, secret, touch=False, imf=None, extra=b""):
        data = tlv(TAG_NAME, name) + tlv(TAG_KEY, bytes([ty_alg, digits]) + secret)
        if touch:
            data += bytes([TAG_PROPERTY, 0x02])  # bare pair, like ykman
        data += extra
        if imf is not None:
            data += tlv(0x7A, struct.pack(">I", imf))
        self.apdu(INS_PUT, 0, 0, data)

    def calculate(self, name, challenge, truncated=True):
        data = tlv(TAG_NAME, name) + tlv(TAG_CHALLENGE, challenge)
        resp, _ = self.apdu(INS_CALCULATE, 0, 0x01 if truncated else 0x00, data)
        want_tag = TAG_T_RESPONSE if truncated else TAG_RESPONSE
        if resp[0] != want_tag:
            fail(f"CALCULATE: response tag {resp[0]:02X} != {want_tag:02X}")
        body = resp[2:]
        digits = body[0]
        if truncated:
            code = struct.unpack(">I", body[1:5])[0]
            # The four bytes are the truncation already reduced to `digits`
            # decimals, the way a YubiKey sends it. Reducing again here would
            # hide a device that did not (E65).
            if code >= 10 ** digits:
                fail(f"CALCULATE {name!r}: {code} is wider than {digits} digits")
            return code
        return body[1:]


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")
    conn = target.createConnection()
    conn.connect()
    oath = Oath(conn)

    # SELECT + RESET so any leftover state (creds, access code) is cleared.
    body = oath.select()
    ver = tlv_get(body, TAG_T_VERSION)
    name8 = tlv_get(body, TAG_NAME)
    print(f"SELECT -> version {list(ver)}, id {name8!r}")
    if list(ver) != [5, 7, 4]:
        fail(f"version TLV {list(ver)} != [5, 7, 4]")
    if len(name8) != 8:
        fail("device-id TLV not 8 bytes")
    oath.apdu(INS_RESET, 0xDE, 0xAD)
    body = oath.select()
    if tlv_get(body, TAG_CHALLENGE) is not None:
        fail("challenge TLV present after RESET — access code not cleared?")

    # Parameter bytes, as a YubiKey judges them: `00 00` everywhere, the `01`
    # that truncates on CALCULATE and CALCULATE ALL alone, `DE AD` on RESET, and
    # `6B00` for the rest (E60). A RESET the card would refuse must not reach the
    # wipe, and a PUT it would refuse must not reach the store.
    for ins, p1, p2 in [
        (INS_LIST, 1, 0), (INS_LIST, 0, 1), (INS_CALCULATE, 1, 0),
        (INS_CALC_ALL, 0, 2), (INS_VALIDATE, 0x0A, 0x0A),
        (INS_RESET, 0, 0), (INS_RESET, 0xDE, 0),
    ]:
        _, sw = oath.apdu(ins, p1, p2, want=None)
        if sw != 0x6B00:
            fail(f"INS {ins:02X} P1={p1:02X} P2={p2:02X}: SW {sw:04X} != 6B00")
    _, sw = oath.apdu(
        INS_PUT, 0, 1,
        tlv(TAG_NAME, b"ghost") + tlv(TAG_KEY, bytes([TYPE_TOTP | ALG_SHA1, 6]) + SECRET_SHA1),
        want=None,
    )
    if sw != 0x6B00:
        fail(f"PUT with P2=01: SW {sw:04X} != 6B00")
    if oath.apdu(INS_LIST, 0, 0)[0]:
        fail("PUT with P2=01 reached the store")

    # HOTP first so it lands in slot 0 (VERIFY CODE always targets slot 0).
    oath.put(b"hotp6", TYPE_HOTP | ALG_SHA1, 6, SECRET_SHA1)
    oath.put(b"rfc-sha1", TYPE_TOTP | ALG_SHA1, 8, SECRET_SHA1)
    oath.put(b"rfc-sha256", TYPE_TOTP | ALG_SHA256, 8, SECRET_SHA256)
    oath.put(b"rfc-sha512", TYPE_TOTP | ALG_SHA512, 8, SECRET_SHA512)
    oath.put(
        b"pws", TYPE_TOTP | ALG_SHA1, 6, SECRET_SHA1, touch=True,
        extra=tlv(TAG_PWS_LOGIN, b"user") + tlv(TAG_PWS_PASSWORD, b"hunter2"),
    )

    # TOTP against the RFC 6238 vectors (T = 1).
    for name, want in [(b"rfc-sha1", 94287082), (b"rfc-sha256", 46119246), (b"rfc-sha512", 90693936)]:
        got = oath.calculate(name, T1)
        print(f"TOTP {name.decode():10s} -> {got:08d} (want {want})")
        if got != want:
            fail(f"{name.decode()}: {got} != {want}")
    full = oath.calculate(b"rfc-sha1", T1, truncated=False)
    if full != hmac_mod.new(SECRET_SHA1, T1, hashlib.sha1).digest():
        fail("full (untruncated) TOTP response != local HMAC-SHA1")

    # HOTP sequence from counter 0 (RFC 4226), persisted on the card.
    for want in (755224, 287082, 359152):
        got = oath.calculate(b"hotp6", T1)  # challenge ignored for HOTP
        print(f"HOTP -> {got:06d} (want {want})")
        if got != want:
            fail(f"HOTP {got} != {want}")

    # VERIFY CODE checks slot 0 at its current counter (3) without advancing it.
    code3 = struct.pack(">I", 969429)
    oath.apdu(INS_VERIFY_CODE, 0, 0, tlv(TAG_NAME, b"hotp6") + tlv(TAG_RESPONSE, code3))
    oath.apdu(INS_VERIFY_CODE, 0, 0, tlv(TAG_NAME, b"hotp6") + tlv(TAG_RESPONSE, code3))
    _, sw = oath.apdu(
        INS_VERIFY_CODE, 0, 0,
        tlv(TAG_NAME, b"hotp6") + tlv(TAG_RESPONSE, struct.pack(">I", 111111)),
        want=None,
    )
    if sw != 0x6700:
        fail(f"VERIFY CODE with wrong code: SW {sw:04X} != 6700")
    print("VERIFY CODE: ok (slot-0 HOTP, counter not advanced)")

    # LIST: 5 entries with the right type|alg bytes.
    body, _ = oath.apdu(INS_LIST, 0, 0)
    entries = {v[1:].decode(): v[0] for t, v in tlv_parse(body) if t == TAG_NAME_LIST}
    print("LIST ->", entries)
    want_entries = {
        "hotp6": TYPE_HOTP | ALG_SHA1, "rfc-sha1": TYPE_TOTP | ALG_SHA1,
        "rfc-sha256": TYPE_TOTP | ALG_SHA256, "rfc-sha512": TYPE_TOTP | ALG_SHA512,
        "pws": TYPE_TOTP | ALG_SHA1,
    }
    if entries != want_entries:
        fail(f"LIST {entries} != {want_entries}")

    # CALCULATE ALL: HOTP yields no response, touch cred defers, TOTPs compute.
    body, _ = oath.apdu(INS_CALC_ALL, 0, 0x01, tlv(TAG_CHALLENGE, T1))
    kinds = {}
    items = tlv_parse(body)
    for (t, v), (t2, v2) in zip(items[::2], items[1::2]):
        if t == TAG_NAME:
            kinds[v.decode()] = t2
    print("CALC ALL ->", {k: f"{v:02X}" for k, v in kinds.items()})
    if kinds.get("hotp6") != TAG_NO_RESPONSE:
        fail("CALC ALL: HOTP entry not NO_RESPONSE")
    if kinds.get("pws") != 0x7C:
        fail("CALC ALL: touch entry not TOUCH_RESPONSE")
    if kinds.get("rfc-sha1") != TAG_T_RESPONSE:
        fail("CALC ALL: TOTP entry not truncated RESPONSE")

    # Single CALCULATE on the touch credential. The no-touch test build
    # auto-confirms presence, so this returns the code; the prod/touch build
    # (fw >= 0x0730) blocks on a real BOOTSEL press instead — verify that one
    # manually via `ykman oath accounts code` on a --touch account.
    got = oath.calculate(b"pws", T1)
    if got != 94287082 % 10**6:
        fail(f"touch cred CALCULATE: {got}")
    print("touch cred single CALCULATE (auto-confirm build): ok")

    # RENAME and calculate under the new name.
    oath.apdu(INS_RENAME, 0, 0, tlv(TAG_NAME, b"rfc-sha1") + tlv(TAG_NAME, b"renamed"))
    if oath.calculate(b"renamed", T1) != 94287082:
        fail("RENAME: calculate under new name broken")
    _, sw = oath.apdu(
        INS_CALCULATE, 0, 1, tlv(TAG_NAME, b"rfc-sha1") + tlv(TAG_CHALLENGE, T1), want=None
    )
    if sw != 0x6984:
        fail(f"old name still resolves after RENAME (SW {sw:04X})")
    print("RENAME: ok")

    # GET CREDENTIAL returns the password-safe fields.
    body, _ = oath.apdu(INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"pws"))
    if tlv_get(body, TAG_PWS_LOGIN) != b"user" or tlv_get(body, TAG_PWS_PASSWORD) != b"hunter2":
        fail("GET CREDENTIAL: PWS fields wrong")
    print("GET CREDENTIAL: ok (login/password fields)")

    # DELETE one credential.
    oath.apdu(INS_DELETE, 0, 0, tlv(TAG_NAME, b"rfc-sha256"))
    body, _ = oath.apdu(INS_LIST, 0, 0)
    if any(v[1:] == b"rfc-sha256" for t, v in tlv_parse(body) if t == TAG_NAME_LIST):
        fail("DELETE: credential still listed")

    # Access-code lifecycle. Key = 16 raw bytes (ykman derives via PBKDF2; the
    # protocol only sees the raw key).
    code_key = bytes(range(16))
    chal = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    proof = hmac_mod.new(code_key, chal, hashlib.sha1).digest()
    # The proof is carried over exactly 8 bytes, as on a YubiKey — a narrower
    # challenge would install a code on a proof with that much less margin (E63).
    short = chal[:7]
    _, sw = oath.apdu(
        INS_SET_CODE, 0, 0,
        tlv(TAG_KEY, bytes([ALG_SHA1]) + code_key) + tlv(TAG_CHALLENGE, short)
        + tlv(TAG_RESPONSE, hmac_mod.new(code_key, short, hashlib.sha1).digest()), want=None,
    )
    if sw != 0x6A80:
        fail(f"SET CODE over a 7-byte challenge: SW {sw:04X} != 6A80")
    if tlv_get(oath.select(), TAG_CHALLENGE) is not None:
        fail("SET CODE over a 7-byte challenge installed a code anyway")
    oath.apdu(
        INS_SET_CODE, 0, 0,
        tlv(TAG_KEY, bytes([ALG_SHA1]) + code_key) + tlv(TAG_CHALLENGE, chal) + tlv(TAG_RESPONSE, proof),
    )
    body = oath.select()
    card_chal = tlv_get(body, TAG_CHALLENGE)
    if card_chal is None or tlv_get(body, TAG_ALGO) != bytes([ALG_SHA1]):
        fail("SET CODE: SELECT lacks challenge/algo TLVs")
    _, sw = oath.apdu(INS_LIST, 0, 0, want=None)
    if sw != 0x6982:
        fail(f"LIST while locked: SW {sw:04X} != 6982 (validated should reset on SELECT)")
    # Wrong response must not unlock.
    host_chal = bytes([9] * 8)
    _, sw = oath.apdu(
        INS_VALIDATE, 0, 0,
        tlv(TAG_RESPONSE, bytes(20)) + tlv(TAG_CHALLENGE, host_chal), want=None,
    )
    # 6A80, as a YubiKey answers it: 6984 is that card's word for "no code is
    # installed", and the two states have to stay tellable apart (E62).
    if sw != 0x6A80:
        fail(f"VALIDATE with wrong response: SW {sw:04X} != 6A80")
    # Correct response unlocks; card answers our challenge (mutual auth).
    resp = hmac_mod.new(code_key, bytes(card_chal), hashlib.sha1).digest()
    body, _ = oath.apdu(
        INS_VALIDATE, 0, 0, tlv(TAG_RESPONSE, resp) + tlv(TAG_CHALLENGE, host_chal)
    )
    # The card reads VALIDATE by position — response first, as ykman sends it —
    # so the other order is 6A80 whatever the proof says (E61).
    _, sw = oath.apdu(
        INS_VALIDATE, 0, 0,
        tlv(TAG_CHALLENGE, host_chal) + tlv(TAG_RESPONSE, resp), want=None,
    )
    if sw != 0x6A80:
        fail(f"VALIDATE with the TLVs reordered: SW {sw:04X} != 6A80")
    if tlv_get(body, TAG_RESPONSE) != hmac_mod.new(code_key, host_chal, hashlib.sha1).digest():
        fail("VALIDATE: mutual-auth response wrong")
    oath.apdu(INS_LIST, 0, 0)
    # Remove the code (empty key) and verify SELECT goes challenge-less.
    oath.apdu(INS_SET_CODE, 0, 0, tlv(TAG_KEY, b""))
    if tlv_get(oath.select(), TAG_CHALLENGE) is not None:
        fail("SET CODE removal: challenge still present")
    print("ACCESS CODE: ok (set -> locked -> validate -> removed)")

    # Leave the applet empty.
    oath.apdu(INS_RESET, 0xDE, 0xAD)
    body, _ = oath.apdu(INS_LIST, 0, 0)
    if body:
        fail("RESET: credentials remain")

    print("\nPASS — YKOATH: RFC 6238 TOTP (SHA1/256/512), RFC 4226 HOTP + persistence,")
    print("LIST/CALC-ALL/RENAME/DELETE/GET-CREDENTIAL/VERIFY-CODE, access-code lifecycle.")


if __name__ == "__main__":
    main()
