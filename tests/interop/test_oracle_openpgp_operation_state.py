# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Operation syntax, missing keys and resettable counters have independent state."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_openpgp_uif import Peer as UifPeer


class Peer(UifPeer):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        slot = 3 if ins == 0x88 else 1 if (p1, p2) == (0x9e, 0x9a) else 2
        reference = 0x81 if slot == 1 else 0x82
        if ins == 0x88 and (p1, p2) != (0, 0):
            sw = 0x6b00
        elif ins == 0x2a and (p1, p2) not in ((0x9e, 0x9a), (0x80, 0x86), (0x86, 0x80)):
            sw = 0x6a86
        elif ins in (0x88, 0x2a) and slot not in self.keys:
            sw = 0x6985 if reference in self.grants else 0x6982
            if slot == 1 and reference in self.grants and self.mode == 0 and self.defect != "empty-SIG-preserves-one-shot":
                self.grants.discard(0x81)
        else:
            result = super().transfer(wire, deadline, observe)
            if self.defect == "any-key-import-resets-counter" and ins == 0xdb:
                self.count = 0
            return result
        output = sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("empty-SIG-preserves-one-shot", "consumes one-shot state"),
    ("any-key-import-resets-counter", "only replacing SIG resets")])
def test_private_modes_missing_keys_and_counter_scope_across_reconnect_and_replacement(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-operation-state", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-operation-state"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys
