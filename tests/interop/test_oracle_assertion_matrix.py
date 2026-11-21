# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Assertion validation precedes independent credential lookup and signature counters."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_credential_matrix import StorePeer


class Peer(StorePeer):
    def pin(self, fields):
        if fields[2] == 1:
            return {3: 8}
        return super().pin(fields)

    def assertion(self, fields):
        error = None
        if not all(key in fields for key in (1, 2)):
            error = 0x14
        elif not fields[1] or len(fields[2]) != 32:
            error = 3
        elif any(byte in b" \t\n\r\v\f" for byte in fields[1].encode()):
            error = 2
        elif fields.get(7, 1) > 0xffffffff:
            error = 0x12
        elif fields.get(7, 1) not in (1, 2):
            error = 2
        elif fields.get(5, {}).get("rk"):
            error = 0x2b
        elif fields.get(3) == []:
            error = 0x2e
        elif 6 in fields:
            if not fields[6]:
                error = 0x31
            elif 7 not in fields:
                error = 0x14
            elif fields[6] != self.mac(fields[2]) or not self.permissions & 2:
                error = 0x33
        if error is not None and (self.defect != "ignore-field-error" or error == 0x14):
            if self.defect == "refusal-consumes-counter":
                for key, record in self.records.items():
                    if record["resident"]:
                        self.credential_counts[key] += 1
            return error, {}
        if 3 not in fields and not any(row["resident"] and row["rp"] == fields[1] for row in self.records.values()):
            return 0x2e, {}
        return super().assertion(fields)


@pytest.mark.parametrize("defect,needle", [(None, None), ("ignore-field-error", "single-field boundary"),
    ("refusal-consumes-counter", "cannot consume a credential counter")])
def test_assertion_presence_lengths_RP_grammar_auth_and_private_counter(tmp_path, defect, needle):
    trace = Trace(tmp_path / "assertion-fields", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["assertion-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not any(row["resident"] for row in peer.records.values())
