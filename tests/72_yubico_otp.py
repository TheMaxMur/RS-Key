#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Yubico-OTP applet test — drive the OTP applet over PC/SC.

Exercises the CCID side of the YubiKey OTP application the way `ykman otp`
does: program / update / swap / delete slots (CRC-checked configs, access-code
protection) and challenge-response calculation in HMAC-SHA1 and Yubico-AES
modes, verified against host-side crypto. The typed-ticket keyboard interface
is covered separately by tests/73_otp_keyboard.py.

Idempotent: deletes both slots at start (trying the test access code as a
fallback for a crashed prior run) and at the end. OTP slots are their own
files — FIDO / OpenPGP / OATH state is untouched. Run from the venv that has
pyscard + cryptography:

    nix develop -c python tests/72_yubico_otp.py
"""
import hashlib
import hmac as hmac_mod
import os
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402

OTP_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]

CONFIG_SIZE, ACC_SIZE = 52, 6
TKT_CHAL_RESP = 0x40
CFG_HMAC_LT64, CFG_CHAL_HMAC, CFG_CHAL_YUBICO = 0x04, 0x22, 0x20

ACC0 = bytes(6)
ACC_TEST = bytes([1, 2, 3, 4, 5, 6])
KEY20 = bytes(range(20))
AESKEY = bytes(range(0x10, 0x20))


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            lsb = crc & 1
            crc >>= 1
            if lsb:
                crc ^= 0x8408
    return crc


def build_config(fixed=b"", uid=bytes(6), key=bytes(16), acc=ACC0, ext=0, tkt=0, cfg=0):
    c = bytearray(CONFIG_SIZE)
    c[: len(fixed)] = fixed
    c[16:22] = uid
    c[22:38] = key
    c[38:44] = acc
    c[44] = len(fixed)
    c[45], c[46], c[47] = ext, tkt, cfg
    c[50:52] = struct.pack("<H", ~crc16(c[:50]) & 0xFFFF)
    return bytes(c)


def chalresp_hmac_config(key20, acc=ACC0, cfg_extra=0):
    return build_config(
        uid=key20[16:20] + bytes(2), key=key20[:16], acc=acc,
        tkt=TKT_CHAL_RESP, cfg=CFG_CHAL_HMAC | cfg_extra,
    )


class Otp:
    def __init__(self, conn):
        self.conn = conn

    def apdu(self, p1, p2, data=b"", want=0x9000):
        cmd = [0x00, 0x01, p1, p2]
        if data:
            cmd += [len(data)] + list(data)
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) | sw2
        if want is not None and sw != want:
            fail(f"OTP P1={p1:02X}: SW {sw:04X} != {want:04X}")
        return bytes(resp), sw

    def select(self):
        resp, sw1, sw2 = self.conn.transmit([0x00, 0xA4, 0x04, 0x00, len(OTP_AID)] + OTP_AID)
        sw = (sw1 << 8) | sw2
        if sw == 0x6A82:
            fail("OTP AID not found — device runs firmware without the OTP applet?")
        if sw != 0x9000:
            fail(f"SELECT OTP: SW {sw:04X}")
        return bytes(resp)

    def configure(self, p1, config, acc=ACC0, want=0x9000):
        return self.apdu(p1, 0, config + acc, want=want)

    def delete_slot(self, p1):
        # An all-zero config deletes; recover from a leftover access code.
        _, sw = self.configure(p1, bytes(CONFIG_SIZE), ACC0, want=None)
        if sw == 0x6982:
            _, sw = self.configure(p1, bytes(CONFIG_SIZE), ACC_TEST, want=None)
        if sw != 0x9000:
            fail(f"delete slot (P1={p1:02X}): SW {sw:04X}")


def main():
    target = find_reader()
    if not target:
        fail("no PC/SC readers — is the device flashed and the CCID driver bound?")
    conn = target.createConnection()
    conn.connect()
    otp = Otp(conn)

    status = otp.select()
    print(f"SELECT -> status {list(status)}")
    # Six bytes over CCID: version(3), programming sequence, slot valid/touch
    # bits, pad. The seventh — the touch-wait status byte — belongs to the
    # keyboard frame protocol, and dropping it here is what makes SELECT answer
    # byte-for-byte like a real YubiKey's (`00c7232`, issue #44). This asserted
    # seven until 2026-08-08, three weeks after that landed.
    if len(status) != 6 or list(status[:3]) != [5, 7, 4]:
        fail(f"status record {list(status)} not a 5.7.4 6-byte record")
    otp.delete_slot(0x01)
    otp.delete_slot(0x03)
    status = otp.select()
    if status[4] != 0:
        fail("slots still valid after cleanup")

    # Program slot 1: HMAC-SHA1 challenge-response (variable-length mode).
    body, _ = otp.configure(0x01, chalresp_hmac_config(KEY20, cfg_extra=CFG_HMAC_LT64))
    if body[4] & 0x01 == 0:
        fail("CONFIG1_VALID not set after programming")
    if body[4] & 0x04:
        fail("chalresp slot must not report TOUCH")
    print("slot 1 programmed: HMAC chalresp,", f"opts={body[4]:#04x}")

    # HMAC chalresp against host-side HMAC (KeePassXC-style padding).
    challenge = b"rs-key chalresp"
    pad = bytes([0x7F]) * (64 - len(challenge))
    resp, _ = otp.apdu(0x30, 0, challenge + pad)
    want = hmac_mod.new(KEY20, challenge, hashlib.sha1).digest()
    print(f"HMAC chalresp -> {resp.hex()}")
    if resp != want:
        fail(f"HMAC response != host HMAC-SHA1 ({want.hex()})")

    # Program slot 2: Yubico-mode chalresp; response = AES-ECB(chal6 + serial10).
    otp.configure(0x03, build_config(key=AESKEY, tkt=TKT_CHAL_RESP, cfg=CFG_CHAL_YUBICO))
    serial4, _ = otp.apdu(0x10, 0)
    if len(serial4) != 4:
        fail("GET SERIAL: not 4 bytes")
    chal6 = bytes([9, 8, 7, 6, 5, 4])
    resp, _ = otp.apdu(0x28, 0, chal6)
    if len(resp) != 16:
        fail(f"Yubico chalresp: {len(resp)} bytes != 16")
    # The serial string in the block is the chip-id hex, which GET SERIAL only
    # partially exposes — verify by decrypting and checking the challenge half.
    dec = Cipher(algorithms.AES(AESKEY), modes.ECB()).decryptor()
    block = dec.update(resp) + dec.finalize()
    if block[:6] != chal6:
        fail("Yubico chalresp: decrypted block does not start with the challenge")
    print(f"Yubico chalresp -> ok (serial-str half: {block[6:].decode('ascii', 'replace')!r})")

    # Status-ext lists both slots with their flag TLVs.
    body, _ = otp.apdu(0x14, 0)
    if body[0] != 0xB0 or 0xB1 not in body:
        fail(f"status-ext missing slot TLVs: {body.hex()}")
    print("status-ext: ok")

    # GET CONFIG mirrors the management READ CONFIG TLV.
    otp_cfg, _ = otp.apdu(0x13, 0)
    resp, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID)
    if (sw1, sw2) != (0x90, 0x00):
        fail("SELECT mgmt failed")
    mgmt_cfg, sw1, sw2 = conn.transmit([0x00, 0x1D, 0x00, 0x00, 0x00])
    if (sw1, sw2) != (0x90, 0x00) or bytes(mgmt_cfg) != otp_cfg:
        fail("OTP GET CONFIG != management READ CONFIG")
    print("GET CONFIG matches management applet")
    otp.select()

    # Swap: the HMAC slot moves to slot 2 (and answers the slot-2 variant).
    body, _ = otp.apdu(0x06, 0)
    resp, _ = otp.apdu(0x38, 0, challenge + pad)
    if resp != want:
        fail("HMAC response after swap (slot 2) wrong")
    print("swap: ok (HMAC slot now answers as slot 2)")

    # Access-code protection on reprogramming.
    otp.delete_slot(0x01)
    otp.configure(0x01, chalresp_hmac_config(KEY20, acc=ACC_TEST), ACC0)
    _, sw = otp.configure(0x01, chalresp_hmac_config(KEY20), ACC0, want=None)
    if sw != 0x6982:
        fail(f"reprogram without access code: SW {sw:04X} != 6982")
    otp.configure(0x01, chalresp_hmac_config(KEY20), ACC_TEST)
    print("access code: ok (wrong code rejected, right code accepted)")

    # Leave both slots empty.
    otp.delete_slot(0x01)
    otp.delete_slot(0x03)
    status = otp.select()
    if status[4] != 0:
        fail("slots remain after final cleanup")

    print("\nPASS — OTP applet: program/update/swap/delete with CRC + access code,")
    print("HMAC-SHA1 chalresp (host-verified), Yubico-AES chalresp, status/serial/config.")


if __name__ == "__main__":
    main()
