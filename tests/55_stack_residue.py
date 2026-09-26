#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Does the dead-stack sweep remove what a request's crypto leaves below it?

    nix develop -c python tests/55_stack_residue.py

`firmware/src/sweep.rs` zeroes core0's dead stack after every request. What it is
for is the residue no `Secret` reaches: the `hmac` crate, for one, builds the key
XORed with its pads in a block of its own frame and returns without wiping it.
This drives exactly that path. It stores an OATH TOTP credential whose HMAC-SHA1
key is a fixed pattern, and counts three 16-byte patterns in core0's dead stack
after a CALCULATE, through the measurement build's vendor probe (INS 0x15): the
key, and the key XORed with the inner and the outer pad. `hmac_sha1` XORs one
block in place, key to inner pad to outer pad, so the outer-pad form is the one
expected; the other two are there to say so if that changes.

Two runs, and the first licenses the second. With the sweep stopped, the probe
has to find at least one pattern: that is the control, and it is what makes an
empty count mean the sweep removed something rather than that the probe cannot
see this residue. With the sweep running, it has to find none.

Exit codes: 0 PASS · 1 FAIL, a pattern survived the sweep · 2 INCONCLUSIVE, the
measurement did not happen: the control found nothing, the image has no probe,
OATH is behind an access code, or the harness itself failed. Only a finished run
exits 1, because the board record reads it as a refutation.

Needs a `--features bench` image (the probe never ships) and an OATH applet with
no access code. The credential is deleted afterwards and the sweep restarted,
whatever the run did. The expectation is on record before the board is read:
assurance/board/PLAT-UNSAFE-014.toml.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]

INS_PUT, INS_DELETE, INS_CALCULATE = 0x01, 0x02, 0xA2
TAG_NAME, TAG_KEY, TAG_CHALLENGE = 0x71, 0x73, 0x74
TOTP_SHA1, DIGITS = 0x21, 6

INS_STACK_RESIDUE = 0x15
RESIDUE_SCAN, RESIDUE_STOP, RESIDUE_RESTART = 0, 1, 2

NAME = b"rsk-stack-residue"
# Fixed, and unlike anything else the device holds, so a match names its source.
KEY = bytes.fromhex("5a3c96e1d27b48f0a5c3691e2db7840f5e3ca197")
IPAD, OPAD = 0x36, 0x5C
PATTERNS = {
    "key": KEY[:16],
    "key ^ ipad": bytes(b ^ IPAD for b in KEY[:16]),
    "key ^ opad": bytes(b ^ OPAD for b in KEY[:16]),
}

SW_OK = (0x90, 0x00)
SW_INS_NOT_SUPPORTED = (0x6D, 0x00)
PASS, FAIL, INCONCLUSIVE = 0, 1, 2


def tlv(tag, value):
    assert len(value) < 128
    return [tag, len(value), *value]


def tags(body):
    """The tags of a flat TLV response, in order."""
    out, i = [], 0
    while i + 2 <= len(body):
        out.append(body[i])
        i += 2 + body[i + 1]
    return out


def send(conn, apdu):
    data, sw1, sw2 = conn.transmit(list(apdu))
    return bytes(data), (sw1, sw2)


def select(conn, aid):
    return send(conn, [0x00, 0xA4, 0x04, 0x00, len(aid), *aid])


class HarnessError(Exception):
    """The run could not be made, which is not a verdict on the sweep."""


def expect_ok(what, sw):
    if sw != SW_OK:
        raise HarnessError(f"{what} answered {sw[0]:02X}{sw[1]:02X}")


def calculate(conn):
    """One CALCULATE over the credential: the path whose residue is counted."""
    select(conn, OATH_AID)
    body = tlv(TAG_NAME, NAME) + tlv(TAG_CHALLENGE, struct.pack(">Q", 1))
    _, sw = send(conn, [0x00, INS_CALCULATE, 0x00, 0x01, len(body), *body])
    expect_ok("CALCULATE", sw)


def residue(conn, sel, pattern=b""):
    select(conn, VENDOR_AID)
    data = list(pattern)
    apdu = [0x00, INS_STACK_RESIDUE, sel, 0x00] + ([len(data), *data] if data else [])
    return send(conn, apdu)


def counts(conn):
    """{pattern name: matches}, plus the dead stack's non-zero and scanned bytes."""
    found, nonzero, scanned = {}, 0, 0
    for name, pattern in PATTERNS.items():
        body, sw = residue(conn, RESIDUE_SCAN, pattern)
        expect_ok(f"the residue probe ({name})", sw)
        found[name], nonzero, scanned = struct.unpack("<III", body)
    return found, nonzero, scanned


def show(label, found, nonzero, scanned):
    hits = ", ".join(f"{name} {n}" for name, n in found.items())
    print(f"{label}: {hits}; {nonzero} of {scanned} dead-stack bytes not zero")


def run(conn):
    body, sw = select(conn, OATH_AID)
    expect_ok("SELECT OATH", sw)
    if TAG_CHALLENGE in tags(body):
        # A SELECT that carries a challenge is an applet behind an access code.
        print("INCONCLUSIVE: OATH has an access code; run this on one without")
        return INCONCLUSIVE
    key = tlv(TAG_KEY, [TOTP_SHA1, DIGITS, *KEY])
    put = tlv(TAG_NAME, NAME) + key
    _, sw = send(conn, [0x00, INS_PUT, 0x00, 0x00, len(put), *put])
    expect_ok("PUT", sw)

    _, sw = residue(conn, RESIDUE_STOP)
    if sw == SW_INS_NOT_SUPPORTED:
        print("INCONCLUSIVE: no residue probe — flash a `--features bench` image")
        return INCONCLUSIVE
    expect_ok("stopping the sweep", sw)
    calculate(conn)
    control = counts(conn)
    show("sweep stopped", *control)

    _, sw = residue(conn, RESIDUE_RESTART)
    expect_ok("restarting the sweep", sw)
    calculate(conn)
    swept = counts(conn)
    show("sweep running", *swept)

    if not any(control[0].values()):
        print("INCONCLUSIVE: the control found nothing, so an empty count proves nothing")
        return INCONCLUSIVE
    if any(swept[0].values()):
        print("FAIL: a pattern survived the sweep")
        return FAIL
    print("PASS: the control found the key's residue, and the sweep removed all of it")
    return PASS


def clean_up(conn):
    """The sweep back on and the credential gone, whatever the run did. A failure
    here is reported, and never replaces the verdict already reached."""
    try:
        _, sw = residue(conn, RESIDUE_RESTART)
        if sw not in (SW_OK, SW_INS_NOT_SUPPORTED):
            print(f"warning: restarting the sweep answered {sw[0]:02X}{sw[1]:02X}")
        select(conn, OATH_AID)
        name = tlv(TAG_NAME, NAME)
        send(conn, [0x00, INS_DELETE, 0x00, 0x00, len(name), *name])
    except Exception as err:  # noqa: BLE001 — any failure here is only a warning
        print(f"warning: clean-up failed ({err}); the sweep may still be stopped")


def main():
    target = find_reader()
    if not target:
        print("INCONCLUSIVE: no PC/SC reader — is the device flashed and the CCID driver bound?")
        sys.exit(INCONCLUSIVE)
    conn = target.createConnection()
    conn.connect()
    try:
        verdict = run(conn)
    except Exception as err:  # noqa: BLE001 — a broken harness is not a FAIL
        print(f"INCONCLUSIVE: {err}")
        verdict = INCONCLUSIVE
    finally:
        clean_up(conn)
    sys.exit(verdict)


if __name__ == "__main__":
    main()
