# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Known old/new access codes and real HMACs witness every connection lifetime."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_otp_commands import Features, Peer


@pytest.mark.parametrize("defect,needle", [(None, None), ("connection-forgets-access-code", "program sequence advances exactly"),
    ("unknown-command-changes-secret", "stored HMAC secret survives")])
def test_access_code_lifetimes_slot_references_and_unknown_command_controls(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-lifetimes", {})
    session = Session(trace, card=peer, otp_hid=Features(peer), profile="rsk", options=Options(exercise=True,
        allow_effects=("otp_extra_slots", "reboot")))
    oracle.execute(session, ["otp-lifetime"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"], row.get("causes", [])) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in " ".join([reason, *causes]) for _, reason, causes in failures), failures
    else:
        applicable = [row for row in trace.cases if row["applicability"] != "excluded_by_mode"]
        assert not failures and all(row["verdict"] == "pass" for row in applicable), [(row["scenario_id"], row["reason"]) for row in applicable if row["verdict"] != "pass"]
        assert not peer.slots
