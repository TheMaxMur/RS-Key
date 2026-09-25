#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP KDF-DO (`kdf-setup`) test — drive the card over PC/SC (pyscard).

    nix develop -c python tests/43_openpgp_kdf.py
    python tests/emu.py tests/43_openpgp_kdf.py       # no board

Reproduces what `gpg --card-edit` → `kdf-setup` puts on the wire: a single
`PUT DATA 00F9` carrying the DO that `g10/card-util.c::gen_kdf_data` builds, and
**no** CHANGE REFERENCE DATA after it. The card is the only party that can move
PW1/PW3 to the KDF output, and the DO's tags `87`/`88` are what it moves them to;
a card that stores the DO and nothing else answers `63Cx` to both references
until they block, which is issue #104.

Both of `gpg`'s layouts are exercised (110-byte three-salt, 90-byte single-salt),
plus `kdf-setup off`. The S2K here is RFC 4880 §3.7.1.3 iterated-and-salted over
SHA-256 — the same bytes gcrypt produces — so the DO this sends is byte-shaped
like a real `gpg` one rather than merely well-formed.

Every status word below was measured on a **YubiKey 5.7.4** first: sixteen
questions over this DO, and the two cards answer all sixteen the same.

**Self-restoring**: it ends with `kdf-setup off`, which puts the card back on the
default PINs (`123456` / `12345678`) with full retry counters. A card that
already holds a key cannot change the setting at all — the suite asserts that
refusal and stops, rather than reporting a card it must not touch as broken.

Needs pyscard + a PC/SC daemon (built in on macOS).
"""
import hashlib
import os
import sys

try:
    from smartcard.util import toHexString
except ImportError:
    sys.exit("missing dependency: pip install pyscard")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
SELECT = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID + [0x00]

PW1_DEFAULT = b"123456"
PW3_DEFAULT = b"12345678"

INS_VERIFY = 0x20
INS_CHANGE = 0x24
INS_GET_DATA = 0xCA
INS_PUT_DATA = 0xDA
MODE_PW1 = 0x81
MODE_PW3 = 0x83

DO_KDF = 0x00F9
DO_KEY_INFO = 0x00DE
DO_APP_DATA = 0x006E
DO_DISCRETE = 0x0073
DO_EXT_CAP = 0x00C0

# `gpg`'s KDF_DATA_LENGTH_MIN / _MAX, and the KDF-off body it sends verbatim.
KDF_LEN_SINGLE = 90
KDF_LEN_THREE = 110
KDF_OFF = bytes([0x81, 0x01, 0x00])

# An iteration count in the encodable range; the card never runs the KDF, so this
# only has to be a value `gpg` could have written and a host could reproduce.
ITERATIONS = 0x00300000
SALT_PW1 = bytes(range(0x10, 0x18))
SALT_RC = bytes(range(0x20, 0x28))
SALT_PW3 = bytes(range(0x30, 0x38))


def s2k(passphrase, salt, count):
    """RFC 4880 §3.7.1.3 iterated-and-salted S2K over SHA-256.

    The count is a byte budget, not a repeat count: hashing stops mid-way through
    `salt ‖ passphrase` if it runs out, and the whole thing is hashed at least
    once however small the count is."""
    data = salt + passphrase
    n = max(count, len(data))
    buf = (data * (n // len(data) + 1))[:n]
    return hashlib.sha256(buf).digest()


def kdf_do(single_salt):
    """The DO `gen_kdf_data` builds: `kdf-setup single` (one salt shared by both
    references) or a bare `kdf-setup` (a salt each for PW1, the RC and PW3)."""
    salt_admin = SALT_PW1 if single_salt else SALT_PW3
    body = bytes([0x81, 0x01, 0x03, 0x82, 0x01, 0x08, 0x83, 0x04])
    body += ITERATIONS.to_bytes(4, "big")
    body += bytes([0x84, 0x08]) + SALT_PW1
    if not single_salt:
        body += bytes([0x85, 0x08]) + SALT_RC
        body += bytes([0x86, 0x08]) + SALT_PW3
    body += bytes([0x87, 0x20]) + s2k(PW1_DEFAULT, SALT_PW1, ITERATIONS)
    body += bytes([0x88, 0x20]) + s2k(PW3_DEFAULT, salt_admin, ITERATIONS)
    want = KDF_LEN_SINGLE if single_salt else KDF_LEN_THREE
    assert len(body) == want, f"built {len(body)} bytes, gpg sends {want}"
    return body


def hashes_for(single_salt):
    """The two values `gpg` sends as passwords once that DO is in place."""
    return (
        s2k(PW1_DEFAULT, SALT_PW1, ITERATIONS),
        s2k(PW3_DEFAULT, SALT_PW1 if single_salt else SALT_PW3, ITERATIONS),
    )


def apdu(ins, p1, p2, data=b""):
    return [0x00, ins, p1, p2, len(data)] + list(data)


def get_data(tag):
    return [0x00, INS_GET_DATA, (tag >> 8) & 0xFF, tag & 0xFF, 0x00]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def tlvs(b):
    """Each `tag: value` of a BER-TLV run."""
    out, i = {}, 0
    while i < len(b):
        tag = b[i]
        i += 1
        if tag & 0x1F == 0x1F:
            tag = (tag << 8) | b[i]
            i += 1
        n = b[i]
        i += 1
        if n > 0x80:
            k = n & 0x7F
            n = int.from_bytes(bytes(b[i:i + k]), "big")
            i += k
        out[tag] = b[i:i + n]
        i += n
    return out


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")

    conn = target.createConnection()
    conn.connect()

    def tx(cmd, what, expect=(0x90, 0x00)):
        data, sw1, sw2 = conn.transmit(cmd)
        shown = toHexString(data)
        if len(shown) > 60:
            shown = shown[:57] + "..."
        print("%-42s -> %s %02X%02X" % (what, shown, sw1, sw2))
        if expect is not None and (sw1, sw2) != expect:
            fail(f"{what}: expected {expect[0]:02X}{expect[1]:02X}, got {sw1:02X}{sw2:02X}")
        return data, sw1, sw2

    tx(SELECT, "SELECT OpenPGP AID")

    # The DO is only offered because C0 byte 1 bit 1 says the card has it; if that
    # bit is ever cleared, `gpg` prints "not supported by this card" and every
    # assertion below is about a command no host would send. C0 is read where gpg
    # reads it, inside 6E's 73: GET DATA C0 alone is 6B00, as on a YubiKey 5.8.0.
    app, sw1, sw2 = tx(get_data(DO_APP_DATA), "GET application related data (6E)", None)
    while sw1 == 0x61:
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        app += more
    if (sw1, sw2) != (0x90, 0x00):
        fail(f"6E: {sw1:02X}{sw2:02X}")
    cap = tlvs(tlvs(tlvs(app)[DO_APP_DATA])[DO_DISCRETE])[DO_EXT_CAP]
    if not cap or not cap[0] & 0x01:
        fail(f"C0 byte 1 does not announce KDF-DO support: {toHexString(cap)}")

    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (default)")

    # Gnuk's `rw_kdf` guard and a YubiKey's. On a card that holds keys this is the
    # whole of the observable behaviour, so assert it and stop — the alternative is
    # a suite that resets a provisioned owner's PINs to `123456`.
    info, _, _ = tx(get_data(DO_KEY_INFO), "GET key information (DE)")
    # The attestation key's pair (`81`) is the card's own and always there; only the
    # three slots an owner fills are keys a KDF change could strand.
    owner = [info[i + 1] for i in range(0, len(info) - 1, 2) if info[i] in (0x01, 0x02, 0x03)]
    if any(status != 0x00 for status in owner):
        tx(
            apdu(INS_PUT_DATA, 0x00, 0xF9, kdf_do(single_salt=False)),
            "PUT KDF on a card holding a key (refused)",
            expect=(0x69, 0x85),
        )
        print("PASS (card holds keys: only the refusal is exercised)")
        return 0

    for single in (False, True):
        label = "single-salt" if single else "three-salt"
        body = kdf_do(single_salt=single)
        pw1_hash, pw3_hash = hashes_for(single)

        tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), f"VERIFY PW3 (before {label})")
        tx(apdu(INS_PUT_DATA, 0x00, 0xF9, body), f"PUT KDF DO ({label}, {len(body)}B)")

        # The access status stands across the write. Measured on a YubiKey 5.7.4:
        # `PUT DATA 5E` straight after `PUT DATA F9`, with no re-VERIFY, is `9000`.
        tx(apdu(INS_PUT_DATA, 0x00, 0x5E, b"kdf@example"), f"PUT login, no re-VERIFY ({label})")

        # `gpg` re-reads the DO to learn the salt and count it must feed the KDF.
        back, _, _ = tx(get_data(DO_KDF), f"GET KDF DO ({label})")
        if bytes(back) != body:
            fail(f"KDF DO round-trip mismatch ({label})")

        # …and from here it sends the KDF output, never the passphrase. This is
        # the assertion #104 failed: both of these answered 63Cx.
        tx(apdu(INS_VERIFY, 0x00, MODE_PW3, pw3_hash), f"VERIFY PW3 with the 88 hash ({label})")
        tx(apdu(INS_VERIFY, 0x00, MODE_PW1, pw1_hash), f"VERIFY PW1 with the 87 hash ({label})")

        _, sw1, sw2 = tx(
            apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT),
            f"VERIFY PW3 with the raw passphrase ({label})",
            expect=None,
        )
        if sw1 != 0x63 or (sw2 & 0xF0) != 0xC0:
            fail(f"the raw passphrase should no longer verify, got {sw1:02X}{sw2:02X}")

        # gpg's `passwd` under KDF sends hash(old) ‖ hash(new), split at the stored
        # length — 32 bytes now, which is the split the old code got wrong.
        new = hashlib.sha256(b"rs-key kdf test").digest()
        tx(apdu(INS_VERIFY, 0x00, MODE_PW3, pw3_hash), f"VERIFY PW3 (before CHANGE, {label})")
        tx(apdu(INS_CHANGE, 0x00, MODE_PW3, pw3_hash + new), f"CHANGE PW3 under KDF ({label})")
        tx(apdu(INS_VERIFY, 0x00, MODE_PW3, new), f"VERIFY PW3 (changed, {label})")

        # `kdf-setup off` — the card goes back to the raw passphrases, because that
        # is what gpg starts sending again the moment the DO reads 81 01 00.
        tx(apdu(INS_PUT_DATA, 0x00, 0xF9, KDF_OFF), f"PUT KDF off (after {label})")
        off, _, _ = tx(get_data(DO_KDF), "GET KDF DO (off)")
        if bytes(off) != KDF_OFF:
            fail(f"KDF-off DO reads back as {toHexString(off)}")
        tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), f"VERIFY PW3 (default again, {label})")
        tx(apdu(INS_VERIFY, 0x00, MODE_PW1, PW1_DEFAULT), f"VERIFY PW1 (default again, {label})")

    # A body that only resembles the DO must not re-seed anything.
    good = kdf_do(single_salt=False)
    for name, bad in (
        ("empty body", b""),
        ("one byte short", good[:-1]),
        ("one byte long", good + b"\x00"),
        ("tag 87 corrupted", good[:42] + bytes([good[42] ^ 0xFF]) + good[43:]),
        ("length of 88 corrupted", good[:77] + bytes([good[77] ^ 0xFF]) + good[78:]),
    ):
        tx(apdu(INS_PUT_DATA, 0x00, 0xF9, bad), f"PUT malformed KDF DO ({name})", expect=(0x6A, 0x80))
    tx(apdu(INS_VERIFY, 0x00, MODE_PW3, PW3_DEFAULT), "VERIFY PW3 (refusals changed nothing)")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
