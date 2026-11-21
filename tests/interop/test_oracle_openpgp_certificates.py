# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Certificate occurrence and walk state are independent of selector parsing."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_openpgp_uif import Peer as UifPeer


class Peer(UifPeer):
    def control(self, action, deadline, observe):
        result = super().control(action, deadline, observe)
        self.anchor, self.certificate = False, 0
        return result

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xa5:
            if p1 >= 3 or p2 != 4:
                sw = 0x6b00
            elif body != bytes.fromhex("60045c027f21"):
                sw = 0x6a80
            else:
                self.certificate, self.anchor = p1, True
            if sw != 0x9000 and self.defect == "refused-selector-moves":
                self.certificate = 0
        elif ins == 0xcc:
            if body or p1 * 256 + p2 != 0x7f21 or not self.anchor or self.certificate >= 2:
                sw = 0x6a80
                if self.defect == "refused-NEXT-moves":
                    self.certificate = min(self.certificate + 1, 2)
            else:
                self.certificate += 1
                output = self.certs[self.certificate]
        else:
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("refused-selector-moves", "preserves the exact selected"),
    ("refused-NEXT-moves", "leaves certificate occurrence unchanged")])
def test_certificate_selector_precedence_refusals_cursor_and_lifetimes(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-certificates", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("reboot",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    original = dict(peer.certs)
    oracle.execute(session, ["openpgp-certificates"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert peer.certs == original
