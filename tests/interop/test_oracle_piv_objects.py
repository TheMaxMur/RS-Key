# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV object peers distinguish a command buffer, byte quota and record quota."""
import pytest

import oracle
from oracle_lib import codec, piv_objects, reset_witness
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_matrix import KeyCard
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Peer(KeyCard):
    emulated = True

    def factory(self):
        super().factory()
        self.keys, self.policies, self.pending = {}, {}, b""

    def control(self, action, deadline, observe):
        self.has_pin, self.has_management, self.pending = False, False, b""
        if self.defect == "volatile-object":
            self.objects.clear()
        return Reply(b"offline ATR")

    @staticmethod
    def pooled(identifier):
        return not (0x5FC100 <= identifier < 0x5FC1F0 or identifier in (0x5FFF00, 0x5FFF01))

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xA4:
            self.pending = b""
        if ins not in (0xCB, 0xDB):
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        output, sw = b"", 0x9000
        if ins == 0xDB:
            data = self.pending + data
            self.pending = data if wire[0] & 0x10 else b""
            if len(data) > 3072:
                self.pending, sw = b"", 0x6700
            elif not wire[0] & 0x10:
                fields = dict(codec.parse_tlv(data))
                identifier, value = int.from_bytes(fields[0x5C], "big"), fields[0x53]
                if not self.has_management and self.defect != "no-management-ACL":
                    sw = 0x6982
                elif not value:
                    self.objects.pop(identifier, None)
                elif self.pooled(identifier):
                    pool = {tag: body for tag, body in self.objects.items() if self.pooled(tag)}
                    used = sum(map(len, pool.values())) - len(pool.get(identifier, b"")) + len(value)
                    if (identifier not in pool and len(pool) >= 256 or used > 32768) and self.defect != "quota-ignored":
                        sw = 0x6A84
                    else:
                        self.objects[identifier] = value
                else:
                    self.objects[identifier] = value
        else:
            identifier = int.from_bytes(dict(codec.parse_tlv(data))[0x5C], "big")
            if identifier in (0x5FC103, 0x5FC108, 0x5FC109, 0x5FC121) and not self.has_pin and self.defect != "management-reads-biometric":
                sw = 0x6982
            else:
                defaults = {0x5FC102: b"default-chuid"}
                if self.defect != "missing-ccc-default":
                    defaults[0x5FC107] = bytes.fromhex("f000f100f200f50110")
                value = self.objects.get(identifier, defaults.get(identifier))
                if value is None:
                    sw = 0x6A82
                else:
                    output = codec.tlv(0x53, value)
        output += sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("no-management-ACL", "identical PIV PUT still requires"),
    ("management-reads-biometric", "PIV read ACL cannot be replaced"), ("volatile-object", "PIV object survives connection change"),
    ("quota-ignored", "pool reaches the independently bounded quota"),
    ("missing-ccc-default", "deleted CCC falls back to synthesized default")])
def test_PIV_object_owners_lifetimes_and_independent_quotas(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(piv_objects, "OBJECTS", (0x5FC102, 0x5FC103, 0x5FC107, 0x5FC1F0, 0x5FFF00, 0x5FFF10))
    monkeypatch.setattr(reset_witness, "snapshot", lambda session, excluded: None)
    peer = Peer(defect)
    trace = Trace(tmp_path / "PIV-objects", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, piv_pin="123456", piv_puk="12345678",
        management_key=DEFAULT_KEY, allow_effects=("capacity", "applet_reset", "pin_attempts", "pin_change", "reboot")))
    oracle.execute(session, ["piv-objects", "piv-pool-capacity"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.objects
