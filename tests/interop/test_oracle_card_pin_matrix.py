# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIN syntax and boundary changes are checked against retained real EC keys."""
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

import oracle
from oracle_lib import card_pin_matrix, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_piv_matrix import KeyCard


class PinCard(KeyCard):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        sw = None
        if ins == 0x20 and (p1 not in (0, 255) or p2 != 0x80 or p1 == 255 and data):
            sw = 0x6A80
        elif ins == 0x20 and data and len(data) != 8:
            if len(data) != 1 and self.defect != "malformed-keeps-grant":
                self.has_pin = False
            sw = 0x6A80
        elif ins == 0x24:
            index = p2 - 0x80
            sw = self.compare(index, data[:8])
            if sw == 0x9000:
                candidate = data[8:].rstrip(b"\xff")
                if not 6 <= len(candidate) <= 8:
                    sw = 0x6A80
                elif index:
                    self.puk = candidate
                else:
                    self.pin = candidate
        elif ins == 0x87 and p2 == 0x82 and self.policies[p2][0] != 1 and not self.has_pin:
            sw = 0x6982
        if sw is None:
            return super().transfer(wire, deadline, observe)
        output = sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect", [None, "malformed-keeps-grant"])
def test_PIV_reference_semantics_are_witnessed_by_private_operations(tmp_path, monkeypatch, defect):
    monkeypatch.setattr(card_pin_matrix, "pgp_changes", lambda session: None)
    monkeypatch.setattr(card_pin_matrix, "pgp_binary", lambda session: None)
    monkeypatch.setattr(card_pin_matrix, "connection_grants", lambda session: None)
    card = PinCard(defect)
    trace = Trace(tmp_path / "PIV-references", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, piv_pin="123456", piv_puk="12345678",
        management_key=DEFAULT_KEY, allow_effects=("pin_change", "pin_attempts")))
    oracle.execute(session, ["card-pin-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("malformed length revokes PIN grant must be refused" in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert card.pin == b"123456" and card.puk == b"12345678" and not card.keys


class PgpCard:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.pins = {0x81: b"123456", 0x83: b"12345678"}
        self.key, self.counter, self.grants, self.defect = None, 0, set(), defect

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        sw, body = 0x9000, b""
        if ins == 0xA4:
            self.grants.clear()
        elif ins == 0x20:
            if data == self.pins[p2]:
                self.grants.add(p2)
            else:
                sw = 0x6982
        elif ins == 0x24:
            previous = self.pins[p2]
            if not data.startswith(previous):
                sw = 0x6982
            elif not (6 if p2 == 0x81 else 8) <= len(data[len(previous):]) <= 127:
                sw = 0x6985
            else:
                self.pins[p2] = data[len(previous):]
                if self.defect == "NUL-trims-reference":
                    self.pins[p2] = self.pins[p2].split(b"\x00", 1)[0]
                if self.defect == "PIN-change-loses-key":
                    self.key = ec.generate_private_key(ec.SECP256R1())
        elif ins == 0xDB:
            packed = dict(codec.parse_tlv(data))[0x4D]
            private = dict(codec.parse_tlv(packed[2:]))[0x5F48]
            self.key = ec.derive_private_key(int.from_bytes(private, "big"), ec.SECP256R1())
        elif ins == 0xDA:
            assert p2 == 0xC1
            self.key = None
        elif ins == 0xCA:
            assert p2 in (0x7A, 0xFA)
            body = codec.tlv(0xFA, codec.tlv(0xC1, bytes.fromhex("132a8648ce3d030107"))) if p2 == 0xFA else codec.tlv(0x93, self.counter.to_bytes(3, "big"))
        elif ins == 0x2A:
            if 0x81 not in self.grants:
                sw = 0x6982
            else:
                body = self.key.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                self.counter += 1
                self.grants.discard(0x81)
        else:
            raise AssertionError(f"unexpected OpenPGP request {ins}")
        output = body + sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect", [None, "PIN-change-loses-key", "NUL-trims-reference"])
def test_OpenPGP_reference_boundaries_keep_the_same_private_key(tmp_path, monkeypatch, defect):
    from yubikit import openpgp
    monkeypatch.setattr(card_pin_matrix, "piv_verify", lambda session: None)
    monkeypatch.setattr(card_pin_matrix, "piv_changes", lambda session: None)
    monkeypatch.setattr(card_pin_matrix, "connection_grants", lambda session: None)
    card = PgpCard(defect)
    trace = Trace(tmp_path / "PGP-references", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("pin_change",)))
    class Sdk:
        def __init__(self, connection):
            session.select("openpgp")
        def verify_pin(self, value):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x81, data=value.encode())))
        def verify_admin(self, value):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=value.encode())))
        def put_key(self, slot, private):
            body = b"\xb6\x00" + codec.tlv(0x7F48, b"\x92\x20") + codec.tlv(0x5F48, private.private_numbers().private_value.to_bytes(32, "big"))
            session.card_value(session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, codec.tlv(0x4D, body))))
        def delete_key(self, slot):
            session.card_value(session.apdu(codec.apdu(0xDA, p2=0xC1, data=b"\x01\x08\x00\x00\x20\x00")))
        def get_signature_counter(self):
            data = session.card_value(session.apdu(codec.apdu(0xCA, p2=0x7A)))
            return int.from_bytes(dict(codec.parse_tlv(data))[0x93], "big")
        def sign(self, message, algorithm):
            digest = hashes.Hash(algorithm)
            digest.update(message)
            return session.card_value(session.apdu(codec.apdu(0x2A, 0x9E, 0x9A, digest.finalize())))
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    oracle.execute(session, ["card-pin-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        needle = "NUL normalization" if defect == "NUL-trims-reference" else "InvalidSignature"
        assert any(needle in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert card.pins == {0x81: b"123456", 0x83: b"12345678"} and card.key is None
