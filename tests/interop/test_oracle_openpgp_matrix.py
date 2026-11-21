# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Key-import and KDF defects are detected using independently retained EC keys."""
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import oracle
from oracle_lib import codec, openpgp_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_lifecycle import Card

CRTS = {b"\xb6\x00": 1, b"\xb8\x00": 2, b"\xa4\x00": 3}
P256 = bytes.fromhex("132a8648ce3d030107")
RSA2048 = bytes.fromhex("010800002000")


class Peer(Card):
    emulated = True

    def factory(self):
        super().factory()
        self.keys, self.attrs, self.count = {}, {slot: RSA2048 for slot in (1, 2, 3)}, 0
        self.values.update({tag: b"\x00\x20" for tag in range(0xd6, 0xda)})

    def control(self, action, deadline, observe):
        self.grants.clear()
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        sw, body = 0x9000, b""
        if ins == 0xda and p2 == 0xf9 and self.keys and 0x83 in self.grants:
            valid = data == b"\x81\x01\x00"
            layouts = {90: ((0, 0x81, 1), (3, 0x82, 1), (6, 0x83, 4), (12, 0x84, 8), (22, 0x87, 32), (56, 0x88, 32)),
                       110: ((0, 0x81, 1), (3, 0x82, 1), (6, 0x83, 4), (12, 0x84, 8), (22, 0x85, 8), (32, 0x86, 8), (42, 0x87, 32), (76, 0x88, 32))}
            valid |= len(data) in layouts and all(data[offset:offset + 2] == bytes([tag, width]) for offset, tag, width in layouts[len(data)])
            output = (0x6985 if valid else 0x6a80).to_bytes(2, "big")
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "applet_error", int.from_bytes(output, "big"))
        if ins == 0xCA and p2 == 0xFA:
            packed = b"".join(codec.tlv(0xC0 + slot, value) for slot in (1, 2, 3)
                              for value in (bytes([0x12 if slot == 2 else 0x13]) + P256[1:], *(bytes([1]) + bits.to_bytes(2, "big") + b"\x00\x20\x00" for bits in (1024, 2048, 3072, 4096))))
            output = codec.tlv(0xFA, packed) + b"\x90\x00"
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "success", 0x9000)
        if self.terminated or ins not in (0xDB, 0x47, 0x88) and not (ins == 0x2A and (p1, p2) in ((0x9E, 0x9A), (0x80, 0x86))) and not (ins == 0xDA and p2 in (0xC1, 0xC2, 0xC3)) and not (ins == 0xCA and p2 in (0x7A, 0xC1, 0xC2, 0xC3)):
            return super().transfer(wire, deadline, observe)
        if ins == 0xCA:
            body = codec.tlv(0x93, self.count.to_bytes(3, "big")) if p2 == 0x7A else self.attrs[p2 - 0xC0]
        elif ins == 0xDA:
            if 0x83 not in self.grants:
                sw = 0x6982
            elif data not in (P256, bytes([0x12]) + P256[1:], RSA2048, bytes.fromhex("010800001100"), bytes.fromhex("011000002000"), b""):
                sw = 0x6A80
            else:
                slot = p2 - 0xC0
                if self.attrs[slot] != data:
                    self.keys.pop(slot, None)
                self.attrs[slot] = data or RSA2048
        elif ins == 0xDB:
            if 0x83 not in self.grants:
                sw = 0x6982
            else:
                try:
                    packed = dict(codec.parse_tlv(data))[0x4D]
                    slot = CRTS[packed[:2]]
                    parts = dict(codec.parse_tlv(packed[2:]))
                    assert parts[0x7F48] == b"\x92\x20" and len(parts[0x5F48]) == 32
                    key = ec.derive_private_key(int.from_bytes(parts[0x5F48], "big"), ec.SECP256R1())
                except (AssertionError, ValueError, KeyError):
                    sw = 0x6A80
                    if self.defect == "refused-import-replaces-key":
                        self.keys[CRTS.get(packed[:2], 1)] = ec.generate_private_key(ec.SECP256R1())
                else:
                    self.keys[slot] = key
                    if slot == 1:
                        self.count = 0
        elif ins == 0x47:
            if p2 != 0 or p1 not in (0x80, 0x81) or data not in CRTS:
                sw = 0x6A80
            elif p1 == 0x80 and 0x83 not in self.grants:
                sw = 0x6982
            elif CRTS[data] not in self.keys:
                sw = 0x6A88
            else:
                point = self.keys[CRTS[data]].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                body = codec.tlv(0x7F49, codec.tlv(0x86, point))
        else:
            slot = 3 if ins == 0x88 else 1 if p1 == 0x9E else 2
            needed = 0x81 if slot == 1 else 0x82
            if needed not in self.grants:
                sw = 0x6982
            elif slot not in self.keys:
                sw = 0x6A88
            elif slot == 2:
                peer = dict(codec.parse_tlv(dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0xA6]))[0x7F49]))[0x86]
                body = self.keys[slot].exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer))
            else:
                der = self.keys[slot].sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                r, s = utils.decode_dss_signature(der)
                body = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                self.count += slot == 1
        observe("tx", wire)
        output = body + sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


def sdk_type(session):
    class Sdk:
        def __init__(self, connection):
            session.select("openpgp")
        def get_data(self, tag):
            return session.card_value(session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255)))
        def put_data(self, tag, body):
            session.card_value(session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, bytes(body))))
        def verify_admin(self, value):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=value.encode())))
        def verify_pin(self, value, extended=False):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x82 if extended else 0x81, data=value.encode())))
        def get_signature_counter(self):
            return int.from_bytes(dict(codec.parse_tlv(self.get_data(0x7A)))[0x93], "big")
        def get_algorithm_attributes(self, slot):
            return self.get_data(slot.algorithm_attributes_do)
        def set_algorithm_attributes(self, slot, value):
            self.put_data(slot.algorithm_attributes_do, bytes(value))
        def put_key(self, slot, private):
            self.set_algorithm_attributes(slot, bytes([0x12]) + P256[1:] if int(slot) == 2 else P256)
            session.card_value(session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, openpgp_matrix.import_body(slot, private, "SECP256R1", "valid"))))
        def delete_key(self, slot):
            self.set_algorithm_attributes(slot, RSA2048)
        def get_public_key(self, slot):
            data = session.card_value(session.apdu(codec.apdu(0x47, 0x81, data=slot.crt)))
            point = dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0x7F49]))[0x86]
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        def signature(self, ins, p1, p2, message, algorithm):
            digest = hashes.Hash(algorithm)
            digest.update(message)
            raw = session.card_value(session.apdu(codec.apdu(ins, p1, p2, digest.finalize())))
            return utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        def sign(self, message, algorithm):
            return self.signature(0x2A, 0x9E, 0x9A, message, algorithm)
        def authenticate(self, message, algorithm):
            return self.signature(0x88, 0, 0, message, algorithm)
        def decrypt(self, peer):
            point = peer.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            return session.card_value(session.apdu(codec.apdu(0x2A, 0x80, 0x86, codec.tlv(0xA6, codec.tlv(0x7F49, codec.tlv(0x86, point))))))
    return Sdk


@pytest.mark.parametrize("defect", [None, "refused-import-replaces-key"])
def test_OpenPGP_malformed_import_attribute_and_KDF_matrix(tmp_path, monkeypatch, defect):
    from yubikit import openpgp
    monkeypatch.setattr(openpgp_matrix, "PGP_ALGORITHMS", ("SECP256R1",))
    card = Peer(defect)
    trace = Trace(tmp_path / "PGP-matrix", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("pin_change", "reboot", "applet_reset", "config_change")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    oracle.execute(session, ["openpgp-matrix", "openpgp-terminated"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("import refusal preserves public identity" in row["reason"] for row in failures), failures
    else:
        assert not failures, [(row["scenario_id"], row["reason"]) for row in failures]
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not card.keys and not card.terminated


@pytest.mark.parametrize("curve", [ec.SECP256R1, ec.SECP384R1, ec.SECP521R1, ec.BrainpoolP384R1, ec.BrainpoolP512R1])
def test_OpenPGP_private_control_uses_a_digest_the_curve_accepts(tmp_path, curve):
    from oracle_lib.card_keys import private_operation
    from yubikit.openpgp import KEY_REF
    private = ec.generate_private_key(curve())
    trace = Trace(tmp_path / "curve-digest", {})
    session = Session(trace)
    class Sdk:
        def sign(self, message, digest):
            hasher = hashes.Hash(digest)
            hasher.update(message)
            prehash = hasher.finalize()
            return private.sign(prehash, ec.ECDSA(utils.Prehashed(digest)))
    with session.case("OpenPGP.curve-digest", ("O11",)):
        private_operation(session, Sdk(), KEY_REF.SIG, private.public_key(), private.curve.name)
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass", trace.cases
