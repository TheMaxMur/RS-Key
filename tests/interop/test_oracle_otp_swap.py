# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Both protected slots and all offset/length layouts survive refused swaps."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_otp_commands import Features, Peer


@pytest.mark.parametrize("defect,needle", [(None, None), ("SWAP-code-bypass", "program sequence advances exactly"),
    ("SWAP-noop", "deleted/absent slot")])
def test_swap_pairs_codes_layouts_and_feature_transport_refusal(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-swap", {})
    session = Session(trace, card=peer, otp_hid=Features(peer), profile="rsk", options=Options(exercise=True,
        allow_effects=("otp_both_slots", "otp_extra_slots")))
    oracle.execute(session, ["otp-swap"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        applicable = [row for row in trace.cases if row["applicability"] != "excluded_by_mode"]
        assert not failures and all(row["verdict"] == "pass" for row in applicable), [(row["scenario_id"], row["reason"]) for row in applicable if row["verdict"] != "pass"]
        assert not peer.slots
