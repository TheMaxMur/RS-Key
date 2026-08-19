#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CTAP over CCID — the FIDO applet reached as ISO 7816 APDUs over PC/SC.

    nix develop -c python tests/42_fido_ccid.py
    python tests/emu.py tests/42_fido_ccid.py     # no board

The framing is CTAP 2.1 §11.2.1 and the client is `python-fido2`'s
`CtapPcscDevice`, spelled out here rather than imported: pyscard aborts under nix
on macOS 27 (libffi), and hand-writing the exchange is also what makes the
chaining visible.

  1. SELECT A0000006472F0001            -> 9000 with body "U2F_V2"
  2. 80 10 .. getInfo                   -> 61xx chained, CTAP2_OK, a CBOR map
  3. the AAGUID over CCID               -> the same one CTAPHID reports
  4. U2F VERSION on the same AID        -> 9000 with "U2F_V2"
  5. two clientPIN getKeyAgreement calls, one per transport
                                        -> the SAME ephemeral key

Step 5 is the one worth the suite: the transports share one `FidoState`, so a
power cycle has exactly one key agreement. Two states would answer two — and
would also carry two per-boot PIN-mismatch budgets, which is why they do not.

⚠️ On the default `0x1209:0x0001` identity the `ccid` driver does not bind the
interface at all, so a REAL board must be built `VIDPID=Yubikey5` (or the host
must carry the `ccid-rs-key` overlay) for this to find a reader.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaphid import CTAPHID_INIT, decode, find, read, send_cbor, write  # noqa: E402
from _device import find_reader  # noqa: E402

FIDO_AID = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
SELECT_FIDO = [0x00, 0xA4, 0x04, 0x00, len(FIDO_AID)] + FIDO_AID + [0x00]
U2F_VERSION = [0x00, 0x03, 0x00, 0x00, 0x00]
CTAP_GET_INFO = 0x04
CTAP_CLIENT_PIN = 0x06
# clientPIN {1: pinUvAuthProtocol 2, 2: subCommand getKeyAgreement}
GET_KEY_AGREEMENT = bytes([CTAP_CLIENT_PIN, 0xA2, 0x01, 0x02, 0x02, 0x02])


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def chain(conn, command):
    """Send one APDU and follow 61xx with GET RESPONSE, as `_chain_apdus` does."""
    body = bytearray()
    resp, sw1, sw2 = conn.transmit(list(command))
    while True:
        body += bytes(resp)
        if sw1 != 0x61:
            return bytes(body), (sw1, sw2)
        resp, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])


def ctap2(conn, payload):
    """NFCCTAP_MSG: one CTAP2 command in the data field, Le appended."""
    apdu = [0x80, 0x10, 0x00, 0x00, len(payload)] + list(payload) + [0x00]
    return chain(conn, apdu)


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the CCID interface bound? (see the docstring)")
    conn = target.createConnection()
    conn.connect()

    body, sw = chain(conn, SELECT_FIDO)
    if sw != (0x90, 0x00):
        fail(f"SELECT of the FIDO AID answered {sw[0]:02x}{sw[1]:02x}")
    if body != b"U2F_V2":
        fail(f"SELECT body is {body!r}, want b'U2F_V2' (a host reads it as CTAP1 support)")
    print("1. SELECT A0000006472F0001 -> 9000 U2F_V2")

    body, sw = ctap2(conn, bytes([CTAP_GET_INFO]))
    if sw != (0x90, 0x00):
        fail(f"getInfo over CCID answered {sw[0]:02x}{sw[1]:02x}")
    if not body or body[0] != 0x00:
        fail(f"getInfo status byte {body[:1].hex()}, want 00")
    info = decode(body[1:])
    if not isinstance(info, dict):
        fail(f"getInfo body decoded to {type(info).__name__}, not a map")
    print(f"2. getInfo over CCID -> CTAP2_OK, {len(body)} bytes, {len(info)} members")

    over_ccid_aaguid = info[0x03]

    # The same applet, reached the other way.
    hid = find()
    if not hid:
        fail("no FIDO HID device found")
    dev = __import__("hid").device()
    dev.open_path(hid["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]
        r = send_cbor(dev, cid, bytes([CTAP_GET_INFO]))
        if r[0] != 0x00:
            fail(f"getInfo over CTAPHID answered {r[0]:#x}")
        if decode(r[1:])[0x03] != over_ccid_aaguid:
            fail("the two transports report different AAGUIDs — not the same applet")
        print("3. the AAGUID matches CTAPHID's: one applet, two transports")

        body, sw = chain(conn, U2F_VERSION)
        if sw != (0x90, 0x00) or body != b"U2F_V2":
            fail(f"U2F VERSION over CCID: {body!r} {sw[0]:02x}{sw[1]:02x}")
        print("4. U2F VERSION on the same AID -> 9000 U2F_V2")

        over_hid = send_cbor(dev, cid, GET_KEY_AGREEMENT)
        over_ccid, sw = ctap2(conn, GET_KEY_AGREEMENT)
        if sw != (0x90, 0x00):
            fail(f"clientPIN over CCID answered {sw[0]:02x}{sw[1]:02x}")
        if over_hid != over_ccid:
            fail("the transports returned different key agreements — the session "
                 "state is forked, which also forks the per-boot PIN retry budget")
        print("5. one clientPIN key agreement for both transports: state is shared")
    finally:
        dev.close()
        conn.disconnect()
    print("\nPASS")


if __name__ == "__main__":
    main()
