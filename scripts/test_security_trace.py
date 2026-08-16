# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import copy
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import security_trace

TRACE = pathlib.Path(__file__).parents[1] / "formal" / "traces" / "security-phase4.jsonl"


def events():
    return security_trace.load_events([TRACE])


def test_recorded_trace_meets_all_three_coverage_floors(tmp_path):
    report = security_trace.generate(events(), tmp_path / "TraceSecurityData.tla")
    assert report["commands"] == 12
    assert report["steps"] == 30
    assert len(report["reached"]) == 13
    assert "WrongPin" in report["unreached"]


def test_mapper_infers_set_pin_without_using_the_hint():
    event = events()[2]
    assert [name for name, _ in security_trace.infer(event)] == [
        "SetPinStart",
        "SetPinClearPpuat",
        "SetPinWrite",
    ]


def test_an_unknown_raw_state_change_is_never_a_stutter():
    event = copy.deepcopy(events()[1])
    event["post"]["backup_sealed_record"] = True
    with pytest.raises(SystemExit, match="no independent B mapping"):
        security_trace.infer(event)


def test_a_discontinuous_raw_trace_is_refused(tmp_path):
    broken = copy.deepcopy(events()[:2])
    broken[1]["pre"]["pin_mismatches_raw"] = 1
    path = tmp_path / "broken.jsonl"
    path.write_text("".join(f"{json.dumps(e)}\n" for e in broken))
    with pytest.raises(SystemExit, match="raw discontinuity"):
        security_trace.load_events([path])


def test_a_shifted_action_hint_cannot_select_another_transition():
    event = copy.deepcopy(events()[3])
    event["action_hint"] = "makeCredential"
    with pytest.raises(SystemExit, match="action_hint disagrees"):
        security_trace.infer(event)
