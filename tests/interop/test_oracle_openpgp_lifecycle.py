# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP lifecycle peer checks raw verifier changes, AES vectors and DO isolation."""
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts


class Card:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.defect = defect
        self.factory()

    def factory(self):
        self.pins = {0x81: b"123456", 0x83: b"12345678"}
        self.grants, self.code, self.retries, self.certificate = set(), b"", 3, 0
        self.anchor = False
        self.values = {0x5E: b"", 0xDE: b"\x01\x00\x02\x00\x03\x00", 0xF9: b"\x81\x01\x00"}
        self.certs, self.aes, self.terminated = {i: b"original-" + bytes([i]) for i in range(3)}, None, False
        self.selection = None

    def transfer(self, request, deadline, observe):
        ins, p1, p2, data = apdu_parts(request)
        tag, status, output = p1 * 256 + p2, 0x9000, b""
        if self.terminated and ins not in (0x44, 0xA4):
            status = 0x6285
        elif ins == 0xA4:
            selected = next((name for name, aid in AIDS.items() if data and aid.startswith(data)), None)
            if selected is None:
                status = 0x6a82
            else:
                if selected != self.selection:
                    self.grants.clear()
                    self.anchor = False
                self.selection = selected
                if self.terminated and selected == "openpgp":
                    status = 0x6285
        elif ins == 0x20:
            if p1 == 0xFF:
                self.grants.discard(p2)
            elif self.pins[0x81 if p2 == 0x82 else p2] == data:
                self.grants.add(p2)
            else:
                self.grants.discard(p2)
                status = 0x6982
        elif ins == 0x24:
            old = self.pins[p2]
            if not data.startswith(old):
                status = 0x6982
            else:
                self.pins[p2] = data[len(old):]
        elif ins == 0x2C:
            if p1 == 2 and 0x83 not in self.grants:
                status = 0x6985
            elif p1 == 0 and not data.startswith(self.code):
                status = 0x6982
            else:
                self.pins[0x81] = data[len(self.code):] if p1 == 0 else data
        elif ins == 0xCA:
            self.anchor = tag == 0x7F21 or self.defect == "stale-certificate-cursor"
            if tag == 0xFFFF:
                status = 0x6B00
            else:
                output = bytes([0, 127, 127, 127, self.retries, self.retries if self.code else 0, self.retries]) if tag == 0xC4 else self.certs[self.certificate] if tag == 0x7F21 else self.values[tag]
        elif ins == 0xCC:
            if tag != 0x7F21 or not self.anchor or self.certificate >= 2:
                status = 0x6A80
            else:
                self.certificate += 1
                output = self.certs[self.certificate]
        elif ins == 0xDA:
            if 0x83 not in self.grants:
                status = 0x6982
            elif tag == 0xD3:
                self.code = data
            elif tag == 0x7F21:
                self.certs[0 if self.defect == "certificate-alias" else self.certificate] = data
            elif tag == 0xD5:
                self.aes = data
            elif tag == 0xF9:
                try:
                    values = dict(codec.parse_tlv(data))
                    assert data == b"\x81\x01\x00" or values[0x81] == b"\x03" and values[0x82] == b"\x08" and len(values[0x87]) == len(values[0x88]) == 32
                    self.values[tag] = data
                    self.pins = {0x81: b"123456", 0x83: b"12345678"} if data == b"\x81\x01\x00" else {0x81: values[0x87], 0x83: values[0x88]}
                except (ValueError, KeyError, AssertionError):
                    status = 0x6A80
            else:
                self.values[tag] = data
        elif ins == 0xF2:
            assert 0x83 in self.grants
            self.retries = data[0]
        elif ins == 0xA5:
            if p1 > 2:
                status = 0x6B00
            elif data != bytes.fromhex("60045c027f21"):
                status = 0x6A80
            else:
                self.certificate = p1
                self.anchor = True
        elif ins == 0x2A:
            if 0x82 not in self.grants:
                status = 0x6982
            elif p1 == 0x86:
                if len(data) % 16:
                    status = 0x6700
                else:
                    key = bytes(len(self.aes)) if self.defect == "wrong-AES-key" else self.aes
                    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
                    output = b"\x02" + encryptor.update(data) + encryptor.finalize()
            else:
                decryptor = Cipher(algorithms.AES(self.aes), modes.CBC(bytes(16))).decryptor()
                output = decryptor.update(data[1:]) + decryptor.finalize()
        elif ins == 0xE6:
            assert 0x83 in self.grants
            self.terminated = True
        elif ins == 0x44:
            if self.terminated:
                self.factory()
        else:
            raise AssertionError(f"unimplemented peer INS {ins:02x}")
        observe("tx", request)
        response = output + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("wrong-AES-key", "known-answer encryption"),
                                           ("certificate-alias", "certificate occurrence isolation"),
                                           ("stale-certificate-cursor", "OpenPGP response cause")])
def test_OpenPGP_lifecycle_normal_dispatch(tmp_path, monkeypatch, defect, expected):
    from yubikit import openpgp
    trace = Trace(tmp_path / "pgp", {})
    card = Card(defect)
    session = Session(trace, card=card, options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678",
                      openpgp_reset_code="", allow_effects=("pin_change", "applet_reset")))
    class Sdk:
        def __init__(self, connection):
            session.select("openpgp")
        def get_data(self, tag):
            return session.card_value(session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255)))
        def put_data(self, tag, data):
            return session.card_value(session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, data)))
        def verify_admin(self, secret):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=secret.encode())))
        def verify_pin(self, secret, extended=False):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x82 if extended else 0x81, data=secret.encode())))
        def set_reset_code(self, secret):
            self.put_data(0xD3, secret.encode())
        def reset_pin(self, new_pin, reset_code=None):
            data = (reset_code or "").encode() + new_pin.encode()
            session.card_value(session.apdu(codec.apdu(0x2C, 0 if reset_code is not None else 2, 0x81, data)))
        def change_pin(self, old, new):
            session.card_value(session.apdu(codec.apdu(0x24, p2=0x81, data=(old + new).encode())))
        def set_pin_attempts(self, user, reset, admin):
            session.card_value(session.apdu(codec.apdu(0xF2, data=bytes([user, reset, admin]))))
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    oracle.execute(session, ["openpgp-lifecycle"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    else:
        assert any(expected in " ".join([row["reason"], *row.get("causes", [])]) for row in failures), failures
    assert card.pins == {0x81: b"123456", 0x83: b"12345678"} and not card.terminated
