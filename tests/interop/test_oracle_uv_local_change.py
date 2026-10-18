# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Operator reports need new-PIN confirmation without replacing the token under test."""
import hashlib

import pytest

from oracle_lib import uv_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_uv_matrix import Peer


@pytest.mark.parametrize("defect,needle", [(None, None), ("local-keeps-ordinary", "local PIN change revokes the standing"),
    ("local-keeps-RO", "local PIN change revokes persistent"), ("local-deletes-key", "CTAP success")])
def test_local_PIN_change_revocation_with_independent_new_PIN_confirmation(tmp_path, monkeypatch, defect, needle):
    peer = Peer()
    def change_on_panel(prompt):
        peer.pin_value = "7391846250"
        if defect != "local-keeps-ordinary":
            peer.token, peer.permissions, peer.rp = bytes(32), 0, None
        if defect != "local-keeps-RO":
            peer.ro = hashlib.sha256(peer.ro).digest()
        if defect == "local-deletes-key":
            peer.records.clear()
        return ""
    monkeypatch.setattr("builtins.input", change_on_panel)
    trace = Trace(tmp_path / "local-PIN-change", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, pin="fixture-PIN", allow_effects=("pin_change",)))
    peer.session = session
    uv_matrix.local_change(session)
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert peer.pin_value == "fixture-PIN" and not session.broken
