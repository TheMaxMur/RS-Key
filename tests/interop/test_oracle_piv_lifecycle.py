# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Real yubikit PIV wire encoding against independent symmetric/PIN state."""
import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts

DEFAULT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")


class PivCard:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.defect = defect
        self.factory()

    def factory(self):
        self.pin, self.puk = b"123456", b"12345678"
        self.totals, self.left = [3, 3], [3, 3]
        self.key, self.algorithm, self.touch = DEFAULT_KEY, 3, 1
        self.has_pin, self.has_management, self.witness = False, False, None
        self.objects = {}
        self.selected = None

    def encrypted(self, value):
        cipher = TripleDES(self.key) if self.algorithm == 3 else algorithms.AES(self.key)
        ctx = Cipher(cipher, modes.ECB()).encryptor()
        return ctx.update(value) + ctx.finalize()

    def compare(self, reference, value):
        if self.left[reference] == 0:
            return 0x6983
        current = self.pin if reference == 0 else self.puk
        if value.rstrip(b"\xff") != current:
            self.left[reference] -= 1
            return 0x6983 if self.left[reference] == 0 else 0x63C0 | min(self.left[reference], 15)
        self.left[reference] = self.totals[reference]
        return 0x9000

    def transfer(self, request, deadline, observe):
        ins, p1, p2, data = apdu_parts(request)
        status, body = 0x9000, b""
        if ins == 0xA4:
            selected = next((name for name, aid in AIDS.items() if data and aid.startswith(data)), None)
            if selected is None:
                status = 0x6a82
            elif self.selected != selected:
                self.has_pin, self.has_management, self.witness = False, False, None
                self.selected = selected
        elif ins == 0xFD:
            body = b"\x05\x08\x00"
        elif ins == 0xF7:
            if p2 in (0x80, 0x81):
                index = p2 - 0x80
                body = codec.tlv(5, b"\x01") + codec.tlv(6, bytes([self.totals[index], self.left[index]]))
            elif p2 == 0x9B:
                body = codec.tlv(1, bytes([self.algorithm])) + codec.tlv(2, bytes([0, self.touch])) + codec.tlv(5, b"\x01")
            else:
                status = 0x6A88
        elif ins == 0x20:
            if p1 == 0xFF:
                self.has_pin = False
            elif not data:
                status = 0x9000 if self.has_pin else 0x63C0 | min(self.left[0], 15) if self.left[0] else 0x6983
            else:
                status = self.compare(0, data)
                self.has_pin = status == 0x9000
        elif ins == 0x24:
            index = p2 - 0x80
            status = self.compare(index, data[:8])
            if status == 0x9000:
                if index:
                    self.puk = data[8:].rstrip(b"\xff")
                else:
                    self.pin = data[8:].rstrip(b"\xff")
        elif ins == 0x2C:
            status = self.compare(1, data[:8])
            if status == 0x9000 and self.defect != "unblock-noop":
                self.pin = data[8:].rstrip(b"\xff")
                self.left[0] = self.totals[0]
        elif ins == 0x87:
            fields = dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0x7C]))
            if fields == {0x80: b""}:
                self.witness = bytes(range(8 if self.algorithm == 3 else 16))
                body = codec.tlv(0x7C, codec.tlv(0x80, self.encrypted(self.witness)))
            elif fields.get(0x80) != self.witness:
                self.has_management = False
                status = 0x6982
            else:
                self.has_management = True
                body = codec.tlv(0x7C, codec.tlv(0x82, self.encrypted(fields[0x81])))
                self.witness = None
        elif ins == 0xFF:
            if not self.has_management and self.defect != "management-ACL-bypass":
                status = 0x6982
            else:
                fields = dict(codec.parse_tlv(data[1:]))
                width = {3: 24, 8: 16, 10: 24, 12: 32}[data[0]]
                if len(fields[0x9B]) != width:
                    status = 0x6A80
                else:
                    self.algorithm, self.key, self.touch = data[0], fields[0x9B], 2 if p2 == 0xFE else 1
        elif ins == 0xFA:
            if not self.has_management or not self.has_pin:
                status = 0x6982
            else:
                self.totals = [p1, p2]
                self.left = [p1, p2]
                self.pin, self.puk, self.has_pin = b"123456", b"12345678", False
        elif ins in (0xCB, 0xDB):
            fields = dict(codec.parse_tlv(data))
            tag = int.from_bytes(fields[0x5C], "big")
            if ins == 0xCB:
                if tag not in self.objects:
                    status = 0x6A82
                else:
                    body = codec.tlv(0x53, self.objects[tag])
            elif not self.has_management:
                status = 0x6982
            else:
                self.objects[tag] = fields[0x53]
        elif ins == 0xFB:
            if any(self.left):
                status = 0x6A80
            elif self.defect != "reset-keeps-objects":
                self.factory()
        else:
            raise AssertionError(f"unimplemented PIV instruction {ins:02x}")
        observe("tx", request)
        response = body + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("unblock-noop", "InvalidPinError"),
    ("management-ACL-bypass", "PIV response cause"), ("reset-keeps-objects", "APDU")])
def test_PIV_lifecycle_with_real_SDK_and_functional_peer(tmp_path, defect, expected):
    card = PivCard(defect)
    trace = Trace(tmp_path / "piv", {})
    session = Session(trace, card=card, options=Options(exercise=True, touch=True, piv_pin="123456", piv_puk="12345678",
                      management_key=DEFAULT_KEY, allow_effects=("pin_change", "pin_attempts", "config_change", "applet_reset")))
    oracle.execute(session, ["piv-lifecycle"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert card.pin == b"123456" and card.puk == b"12345678" and card.key == DEFAULT_KEY
    else:
        assert any(expected in " ".join([row["reason"], *row.get("causes", [])]) for row in failures), failures


@pytest.mark.parametrize("blocked_puk", [False, True])
def test_unblock_preflights_recovery_and_restores_after_assertion(tmp_path, monkeypatch, blocked_puk):
    from oracle_lib import piv_lifecycle
    class CounterFault(PivCard):
        def compare(self, reference, value):
            result = super().compare(reference, value)
            return 0x63C1 if reference == 0 and result == 0x63C2 else result
    card = CounterFault()
    if blocked_puk:
        card.left[1] = 0
    trace = Trace(tmp_path / "unblock-control", {})
    session = Session(trace, card=card, options=Options(exercise=True, piv_pin="123456", piv_puk="12345678",
                      management_key=DEFAULT_KEY, allow_effects=("pin_change", "pin_attempts")))
    for name in ("management_keys", "retries", "reset"):
        monkeypatch.setattr(piv_lifecycle, name, lambda session: None)
    oracle.execute(session, ["piv-lifecycle"])
    trace.finish()
    assert len(trace.cases) == 1 and trace.cases[0]["scenario_id"] == "piv.puk.block-unblock"
    assert card.pin == b"123456" and card.puk == b"12345678" and card.left[0] == 3
    if blocked_puk:
        assert trace.cases[0]["applicability"] == "blocked_by_precondition"
        assert card.left[1] == 0
    else:
        assert trace.cases[0]["verdict"] == "fail" and "PIV response cause" in trace.cases[0]["reason"]
        assert card.left == [3, 3]
