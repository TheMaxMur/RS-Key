# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent CBC calculations expose ACL, length, DEC coupling and UIF defects."""
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec, openpgp_aes
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_openpgp_uif import Peer as UifPeer


class Peer(UifPeer):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xda and p2 == 0xd5:
            if 0x83 not in self.grants:
                sw = 0x6982
            elif len(body) not in (16, 32):
                sw = 0x6a80
                if self.defect == "refused-key-write-replaces-AES":
                    self.aes = bytes(32)
            else:
                self.aes = body
        elif ins == 0x22:
            pass
        elif ins == 0x2a and ((p1, p2) == (0x86, 0x80) or (p1, p2) == (0x80, 0x86) and body[:1] == b"\x02"):
            data = body[1:] if p1 == 0x80 else body
            if 0x82 not in self.grants and not (self.defect == "PW3-overrides-AES" and 0x83 in self.grants):
                sw = 0x6982
            elif self.data[0xd7] and self.data[0xd7][0] and not self.presence:
                sw = 0x6600
            elif self.aes is None:
                sw = 0x6a88
            elif not data or len(data) % 16:
                sw = 0x6700
            else:
                cipher = Cipher(algorithms.AES(self.aes), modes.CBC(bytes(16)))
                worker = cipher.decryptor() if p1 == 0x80 else cipher.encryptor()
                output = worker.update(data) + worker.finalize()
                if p1 != 0x80:
                    output = b"\x02" + output
        else:
            result = super().transfer(wire, deadline, observe)
            if ins == 0xda and p2 == 0xc2 and self.defect == "DEC-attributes-drop-AES":
                self.aes = None
            return result
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("refused-key-write-replaces-AES", "independently verifies the exact"),
    ("PW3-overrides-AES", "distinct outcomes"), ("DEC-attributes-drop-AES", "distinct outcomes")])
def test_AES_authentication_touch_blocks_key_writes_and_DEC_independence(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-AES", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        timeout=131, features=("display",), openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    def operator(session, mode):
        peer.presence = mode == "accept"
    monkeypatch.setattr(openpgp_aes, "cue", operator)
    oracle.execute(session, ["openpgp-aes"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys
