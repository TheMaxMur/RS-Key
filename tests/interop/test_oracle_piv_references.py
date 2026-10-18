# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reference syntax never bypasses independent retry and private-key state."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec, piv_references
from oracle_lib.runner import Options, Session
from oracle_lib.runner import AIDS
from oracle_lib.trace import Reply, Trace
from test_oracle_card_pin_matrix import PinCard
from test_oracle_expanded import apdu_parts
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Peer(PinCard):
    emulated = True
    presence = True

    def __init__(self, defect=None):
        super().__init__(defect)
        self.factory_attestation = ec.generate_private_key(ec.SECP384R1())

    def control(self, action, deadline, observe):
        self.has_pin, self.has_management, self.witness = False, False, None
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw = None
        if ins == 0xf7 and p2 == 0xf9 and p1 == 0:
            point = self.factory_attestation.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            output = codec.tlv(1, b"\x14") + codec.tlv(2, b"\x01\x01") + codec.tlv(3, b"\x01") + codec.tlv(4, codec.tlv(0x86, point)) + b"\x90\x00"
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0x9000)
        if ins in (0x47, 0xfe) and p2 == 0xf9:
            sw = 0x6982 if not self.has_management else 0x6a86 if ins == 0x47 else 0x6a80
        elif ins == 0xf6 and (p1 == 0xf9 or p2 == 0xf9):
            sw = 0x6982 if not self.has_management else 0x6a80 if p1 == 0xf9 else 0x6a88
        elif ins == 0x87 and p2 == 0x9b and self.touch != 1 and not self.presence:
            sw = 0x6982
        elif ins == 0xf7 and p1:
            sw = 0x6a86
        elif ins == 0xf9:
            sw = 0x6a80 if p1 in self.keys else 0x6a88
        elif ins == 0xdb and not body:
            sw = 0x6a80 if self.has_management else 0x6982
        elif ins == 0xff:
            if p1 != 0xff or p2 not in (0xfe, 0xff):
                sw = 0x6a86
            elif not self.has_management:
                sw = 0x6982
            elif len(body) == 1:
                sw = 0x6a80
            elif len(body) < 5:
                sw = 0x6700
            elif body[0] not in (3, 8, 10, 12) or body[1] != 0x9b or body[2] != {3: 24, 8: 16, 10: 24, 12: 32}[body[0]]:
                sw = 0x6a80
            elif len(body) != body[2] + 3:
                sw = 0x6700
        elif ins == 0xa4 and self.selected == "piv" and body and AIDS["piv"].startswith(body) and self.defect == "reselect-clears-grants":
            self.has_pin, self.has_management = False, False
        elif ins in (0x24, 0x2c):
            if p1 or p2 not in ((0x80, 0x81) if ins == 0x24 else (0x80,)):
                sw = 0x6a88
            elif len(body) != 16:
                sw = 0x6a80
            else:
                which = 1 if ins == 0x2c else p2 - 0x80
                sw = self.compare(which, body[:8])
                if sw == 0x9000:
                    candidate = body[8:].rstrip(b"\xff")
                    if not 6 <= len(candidate) <= 8:
                        sw = 0x6a80
                    elif ins == 0x2c or p2 == 0x80:
                        self.pin, self.left[0] = candidate, self.totals[0]
                    else:
                        self.puk = candidate
                elif self.defect == "failed-change-revokes-PIN":
                    self.has_pin = False
        elif ins == 0xfa:
            if len(body) == 1:
                sw = 0x6a80
            elif self.has_pin and self.has_management and (p1 == 0 or p2 == 0):
                sw = 0x6a80
            elif self.has_pin and self.has_management and self.defect == "policy-deletes-private-key":
                self.keys.clear()
        if sw is None:
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        observe("rx", sw.to_bytes(2, "big"))
        return Reply(sw.to_bytes(2, "big"), "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("failed-change-revokes-PIN", "APDU error"),
    ("policy-deletes-private-key", "APDU error"), ("reselect-clears-grants", "APDU error")])
def test_reference_catalog_binary_padding_precedence_policy_and_blocked_PUK(tmp_path, monkeypatch, defect, needle):
    trace = Trace(tmp_path / "PIV-references", {})
    peer = Peer(defect)
    original_cue = piv_references.cue
    def operator(session, mode):
        peer.presence = mode == "accept"
        original_cue(session, mode)
    monkeypatch.setattr(piv_references, "cue", operator)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, features=("display",), timeout=131, piv_pin="123456", piv_puk="12345678",
        management_key=DEFAULT_KEY, allow_effects=("pin_change", "pin_attempts", "reboot", "config_change")))
    oracle.execute(session, ["piv-references"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and peer.pin == b"123456" and peer.puk == b"12345678" and peer.totals == [3, 3]
