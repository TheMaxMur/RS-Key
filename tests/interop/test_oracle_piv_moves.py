# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""MOVE keeps certificate references and carries the key's authorization policy."""
import pytest
from cryptography.hazmat.primitives import serialization

import oracle
from oracle_lib import codec, piv_moves
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_matrix import KeyCard
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Peer(KeyCard):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xF6:
            if not self.has_management:
                sw = 0x6982
            elif p1 not in (0x82, 0x83, 0xFF):
                sw = 0x6A80
            elif p2 not in self.keys:
                sw = 0x6A88
            elif p1 == p2 or p1 in self.keys:
                sw = 0x6A80
            else:
                if p1 != 0xFF:
                    self.keys[p1], self.policies[p1] = self.keys[p2], self.policies[p2]
                    if self.defect == "remap-destination-policy":
                        self.policies[p1] = (2, 1)
                    if self.defect == "move-certificate":
                        from yubikit.piv import OBJECT_ID, SLOT
                        old, new = int(OBJECT_ID.from_slot(SLOT(p2))), int(OBJECT_ID.from_slot(SLOT(p1)))
                        self.objects[new] = self.objects.pop(old)
                del self.keys[p2]
                del self.policies[p2]
        elif ins == 0xF7 and p2 in (0x82, 0x83):
            if p2 not in self.keys:
                sw = 0x6A88
            else:
                point = self.keys[p2].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                output = codec.tlv(1, b"\x11") + codec.tlv(2, bytes(self.policies[p2])) + codec.tlv(3, b"\x01") + codec.tlv(4, codec.tlv(0x86, point))
        elif ins == 0xDB and dict(codec.parse_tlv(data)).get(0x53) == b"":
            self.objects.pop(int.from_bytes(dict(codec.parse_tlv(data))[0x5C], "big"), None)
        else:
            events = []
            observer = (lambda direction, body: events.append((direction, body))) if ins == 0x47 else observe
            result = super().transfer(wire, deadline, observer)
            if ins == 0x47 and result.status == 0x9000:
                fields = dict(codec.parse_tlv(dict(codec.parse_tlv(data))[0xAC]))
                self.policies[p2] = (fields.get(0xAA, b"\x02")[0], fields.get(0xAB, b"\x01")[0])
                point = self.keys[p2].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                result = Reply(codec.tlv(0x7F49, codec.tlv(0x86, point)) + b"\x90\x00", "success", 0x9000)
            for direction, body in events:
                observe(direction, result.data if direction == "rx" else body)
            return result
        observe("tx", wire)
        output += sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("remap-destination-policy", "MOVE carries algorithm, PIN, touch and origin"),
    ("move-certificate", "MOVE leaves certificate objects")])
def test_MOVE_metadata_private_controls_and_stationary_certificates(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(piv_moves, "PIV_SLOTS", (0x82, 0x83))
    peer = Peer(defect)
    trace = Trace(tmp_path / "PIV-MOVE", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, piv_pin="123456", management_key=DEFAULT_KEY, allow_effects=("replace_identity",)))
    oracle.execute(session, ["piv-moves"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.keys and not peer.objects
