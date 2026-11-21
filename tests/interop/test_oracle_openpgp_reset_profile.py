# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Routed reset state is populated with real private keys and permanent UIF."""
import pytest

import oracle
from oracle_lib import codec, openpgp_reset_profile
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_aes import Peer as AesPeer
from test_oracle_openpgp_kdf import Peer as KdfPeer
from test_oracle_openpgp_references import sdk_with_errors


class Peer(KdfPeer, AesPeer):
    def factory(self):
        super().factory()
        self.certs = {value: b"" for value in range(3)}
        self.rc_left = 0

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if self.terminated and ins not in (0x44, 0xa4):
            sw = 0x6285
        elif ins == 0xe6:
            if p1 or p2:
                sw = 0x6a86
            elif 0x83 not in self.grants and self.left[0x83]:
                sw = 0x6982
            elif body:
                sw = 0x6700
            else:
                self.factory()
                self.terminated = True
        elif ins == 0x44:
            if self.terminated:
                saved = self.data[0xd6]
                self.factory()
                if self.defect == "permanent-UIF-survives-reset":
                    self.data[0xd6] = b"\x02\xff" if saved == b"\x00\x20" else saved
        elif ins == 0xf2:
            if 0x83 not in self.grants:
                sw = 0x6982
            elif len(body) != 3:
                sw = 0x6a80
            else:
                for index, ref in ((0, 0x81), (2, 0x83)):
                    if body[index]:
                        self.maximum[ref] = self.left[ref] = body[index]
                if body[1]:
                    self.rc_left = body[1] if self.code else 0
        elif ins == 0xca and p2 == 0xc4:
            output = bytes([self.mode, 127, 127, 127, self.left[0x81], self.rc_left, self.left[0x83]])
        elif ins == 0x2c and not self.code:
            sw = 0x6a88
        else:
            result = super().transfer(wire, deadline, observe)
            if ins == 0xda and p2 == 0xd3 and result.status == 0x9000:
                self.rc_left = 3 if self.code else 0
            return result
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("permanent-UIF-survives-reset", "activation clears permanent UIF")])
def test_blocked_admin_reset_escape_terminated_command_gates_and_all_routed_defaults(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    from oracle_lib import reset_witness
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-reset-profile", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678", openpgp_reset_code="",
        allow_effects=("applet_reset", "config_change", "pin_change", "pin_attempts", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    monkeypatch.setattr(reset_witness, "snapshot", lambda session, excluded: None)
    monkeypatch.setattr(openpgp_reset_profile, "cue", lambda session, mode: setattr(peer, "presence", mode == "accept"))
    oracle.execute(session, ["openpgp-reset-profile"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and not peer.terminated and peer.aes is None
