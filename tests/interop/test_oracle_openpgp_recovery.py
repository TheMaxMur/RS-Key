# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PW3 and resetting-code recovery maintain independent counters and retained keys."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import Peer as ReferencePeer, sdk_with_errors


class Peer(ReferencePeer):
    def factory(self):
        super().factory()
        self.code, self.code_maximum, self.code_left = b"", 3, 0

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xca and (p1, p2) == (0, 0xc4):
            output = bytes([self.mode, 127, 127, 127, self.left[0x81], self.code_left, self.left[0x83]])
        elif ins == 0xda and (p1, p2) == (0, 0xd3):
            if 0x83 not in self.grants:
                sw = 0x6982
            elif body and not 8 <= len(body) <= 127:
                sw = 0x6a80
            else:
                self.code, self.code_left = body, self.code_maximum if body else 0
        elif ins == 0xf2:
            if 0x83 not in self.grants:
                sw = 0x6982
            elif len(body) != 3:
                sw = 0x6a80
            else:
                for reference, value in zip((0x81, None, 0x83), body):
                    if value:
                        if reference is None:
                            self.code_maximum = value
                            self.code_left = value if self.code else 0
                        else:
                            self.maximum[reference] = self.left[reference] = value
                if body == bytes(3) and self.defect == "zero-policy-changes-code":
                    self.code_left = 1
        elif ins == 0x24:
            if p1 or p2 not in (0x81, 0x83):
                sw = 0x6b00
            elif len(body) < len(self.pins[p2]):
                sw = 0x6700
            elif not body.startswith(self.pins[p2]):
                sw = 0x6982
            else:
                new = body[len(self.pins[p2]):]
                self.left[p2] = self.maximum[p2]
                self.grants.add(p2)
                if not (6 if p2 == 0x81 else 8) <= len(new) <= 127:
                    sw = 0x6985
                else:
                    self.pins[p2] = new
        elif ins == 0x2c:
            if p2 != 0x81:
                sw = 0x6a88
            elif p1 not in (0, 2):
                sw = 0x6a86
            elif p1 == 2 and 0x83 not in self.grants:
                sw = 0x6985
            elif p1 == 0 and not self.code:
                sw = 0x6a88
            elif p1 == 0 and len(body) <= len(self.code):
                sw = 0x6700
            elif p1 == 0 and self.code_left == 0:
                sw = 0x6983
            elif p1 == 0 and not body.startswith(self.code):
                self.code_left -= 1
                sw = 0x6982 if self.code_left else 0x6983
                if self.defect == "wrong-RC-revokes-grants":
                    self.grants.clear()
            else:
                new = body[len(self.code):] if p1 == 0 else body
                if p1 == 0:
                    self.code_left = self.code_maximum
                    self.grants.clear()
                if not 6 <= len(new) <= 127:
                    sw = 0x6985
                else:
                    self.pins[0x81], self.left[0x81] = new, self.maximum[0x81]
                    if self.defect == "recovery-replaces-key":
                        self.keys[1] = ec.generate_private_key(ec.SECP256R1())
        else:
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("wrong-RC-revokes-grants", "own access latch"),
    ("zero-policy-changes-code", "zero policy bytes"), ("recovery-replaces-key", "InvalidSignature")])
def test_OpenPGP_recovery_grammar_policy_persistence_and_blocking(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-recovery", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678", openpgp_reset_code="",
        allow_effects=("config_change", "pin_attempts", "pin_change", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-recovery"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and peer.pins == {0x81: b"123456", 0x83: b"12345678"} and peer.code == b""
