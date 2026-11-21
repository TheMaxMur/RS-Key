# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Generated, imported and empty subjects require distinct attestation outcomes."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_openpgp_uif import Peer


@pytest.mark.parametrize("defect,needle", [(None, None), ("imported-origin-attests", "origin in order"),
    ("ATTEST-increments-signature-counter", "leave SIG counter untouched")])
def test_attestation_subject_origin_grammar_one_shot_and_retained_keys(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-attestation", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-attestation"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys
