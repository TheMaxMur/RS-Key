# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exact wire bytes and stored secrets witness challenge grammar and consent."""
import pytest

import oracle
from oracle_lib import otp_challenges
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_otp_commands import Features, Peer


@pytest.mark.parametrize("defect,needle", [(None, None), ("touch-bypass", "exact applet cause"),
    ("HMAC-includes-trailing-data", "exact fixed or trimmed challenge"),
    ("trim-only-one-padding-byte", "exact fixed or trimmed challenge"),
    ("connection-forgets-access-code", "exact applet status")])
def test_challenge_widths_padding_touch_and_access_code_persistence(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-challenges", {})
    session = Session(trace, card=peer, otp_hid=Features(peer), profile="rsk", options=Options(exercise=True, touch=True,
        operator=True, timeout=131, features=("display",), allow_effects=("otp_extra_slots", "reboot")))
    monkeypatch.setattr(otp_challenges, "cue", lambda session, action: setattr(peer, "presence", action == "confirm"))
    oracle.execute(session, ["otp-challenges"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"], row.get("causes", [])) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in " ".join([reason, *causes]) for _, reason, causes in failures), failures
    else:
        applicable = [row for row in trace.cases if row["applicability"] != "excluded_by_mode"]
        assert not failures and all(row["verdict"] == "pass" for row in applicable), [(row["scenario_id"], row["reason"]) for row in applicable if row["verdict"] != "pass"]
        assert not peer.slots
