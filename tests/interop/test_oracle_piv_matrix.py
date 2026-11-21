# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV failures use actual SDK APDUs and an independent EC private operation."""
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import oracle
from oracle_lib import codec, piv_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_lifecycle import DEFAULT_KEY, PivCard


class KeyCard(PivCard):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.keys, self.policies = {}, {}
        self.handshake_kind = None
        self.challenge_counter = 0

    def transfer(self, request, deadline, observe):
        ins, p1, p2, data = apdu_parts(request)
        if ins not in (0x87, 0xa4) and not (ins == 0xf7 and p2 == 0x9b):
            self.handshake_kind, self.witness = None, None
        if ins == 0xee:
            observe("tx", request)
            observe("rx", b"\x6d\x00")
            return Reply(b"\x6d\x00", "applet_error", 0x6d00)
        if not (ins in (0x47, 0xFE, 0xF6) or ins == 0xF7 and p2 == 0x82 or ins == 0x87):
            result = super().transfer(request, deadline, observe)
            if ins == 0xa4 and self.witness is None:
                self.handshake_kind = None
            return result
        sw, body = 0x9000, b""
        if ins in (0x47, 0xFE):
            if not self.has_management:
                sw = 0x6982
            elif ins == 0x47:
                try:
                    fields = dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0xAC]))
                    assert fields[0x80] == b"\x11" and all(fields.get(tag, b"\x01") in (b"\x01", b"\x02", b"\x03") for tag in (0xAA, 0xAB))
                except (KeyError, ValueError, AssertionError):
                    sw = 0x6A80
                else:
                    self.keys[p2] = ec.generate_private_key(ec.SECP256R1())
            else:
                try:
                    fields = dict(codec.parse_tlv(data))
                    assert p1 == 0x11 and len(fields[6]) == 32
                    private = ec.derive_private_key(int.from_bytes(fields[6], "big"), ec.SECP256R1())
                except (KeyError, ValueError, AssertionError):
                    sw = 0x6A80
                    if self.defect == "refusal-replaces-key":
                        self.keys[p2] = ec.generate_private_key(ec.SECP256R1())
                else:
                    self.keys[p2] = private
                    self.policies[p2] = (fields.get(0xAA, b"\x02")[0], fields.get(0xAB, b"\x01")[0])
        elif ins == 0xF6:
            self.keys.pop(p2, None)
        elif ins == 0xF7:
            if p2 not in self.keys:
                sw = 0x6A88
            else:
                point = self.keys[p2].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                body = codec.tlv(1, b"\x11") + codec.tlv(2, bytes(self.policies[p2])) + codec.tlv(3, b"\x02") + codec.tlv(4, codec.tlv(0x86, point))
        elif p2 == 0x9B:
            try:
                assert p1 == self.algorithm
                fields = dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0x7C]))
            except (ValueError, KeyError, AssertionError):
                sw = 0x6A80
            else:
                if fields in ({0x80: b""}, {0x81: b""}):
                    self.has_management = False
                    self.challenge_counter += 1
                    self.witness = hashlib.sha256(self.challenge_counter.to_bytes(4, "big")).digest()[:8 if self.algorithm == 3 else 16]
                    self.handshake_kind = 0x80 if 0x80 in fields else 0x81
                    body = codec.tlv(0x7C, codec.tlv(self.handshake_kind, self.encrypted(self.witness) if self.handshake_kind == 0x80 else self.witness))
                elif self.handshake_kind == 0x80 and 0x80 in fields and fields.get(0x81):
                    if fields[0x80] != self.witness:
                        sw = 0x6982
                    else:
                        self.has_management = True
                        if len(fields[0x81]) != len(self.witness):
                            sw = 0x6984
                        else:
                            body = codec.tlv(0x7C, codec.tlv(0x82, self.encrypted(fields[0x81])))
                    self.handshake_kind = None
                elif self.handshake_kind == 0x81 and 0x82 in fields:
                    self.has_management = fields[0x82] == self.encrypted(self.witness)
                    sw = 0x9000 if self.has_management else 0x6982
                    self.handshake_kind = None
                elif self.defect == "replay-authenticates":
                    sw, self.has_management = 0x9000, True
                else:
                    sw = 0x6A80
        else:
            try:
                assert p1 == 0x11 and p2 in self.keys
                fields = dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0x7C]))
                if 0x81 in fields:
                    digest = fields[0x81]
                    assert len(digest) <= 32
                    result = self.keys[p2].sign(digest.rjust(32, b"\x00"), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                else:
                    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), fields[0x85])
                    result = self.keys[p2].exchange(ec.ECDH(), point)
                body = codec.tlv(0x7C, codec.tlv(0x82, result))
            except (ValueError, KeyError, AssertionError):
                sw = 0x6A80
        observe("tx", request)
        output = body + sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,expected", [(None, None), ("refusal-replaces-key", "refused operation preserves key identity"),
                                           ("replay-authenticates", "management challenge outcome")])
def test_piv_semantic_rejections_keep_actual_private_key_usable(tmp_path, monkeypatch, defect, expected):
    monkeypatch.setattr(piv_matrix, "PIV_ALGORITHMS", ("ECCP256",))
    monkeypatch.setattr(piv_matrix, "private_lengths", lambda session: None)
    card = KeyCard(defect)
    trace = Trace(tmp_path / "piv-semantic", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, piv_pin="123456", management_key=DEFAULT_KEY, allow_effects=("config_change",)))
    oracle.execute(session, ["piv-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not card.keys


def test_each_PIV_slot_algorithm_origin_has_every_PIN_touch_pair():
    from oracle_lib import card_keys
    from oracle_lib.catalog import PlanTrace
    from yubikit.piv import PIN_POLICY, TOUCH_POLICY
    from itertools import product
    trace = PlanTrace()
    session = Session(trace, profile="rsk")
    session.planning = True
    card_keys.piv(session)
    scopes = {}
    for case in trace.cases:
        p = case["parameters"]
        scopes.setdefault((p["slot"], p["algorithm"], p["origin"]), set()).add((p["pin_policy"], p["touch_policy"]))
    expected = set(product((p.name for p in PIN_POLICY), (p.name for p in TOUCH_POLICY)))
    assert set(scopes) == set(product(card_keys.PIV_SLOTS, card_keys.PIV_ALGORITHMS, ("generate", "import")))
    assert all(pairs == expected for pairs in scopes.values())
    assert len({row["scenario_id"] for row in trace.cases}) == len(trace.cases)
    assert not trace.exchanges
