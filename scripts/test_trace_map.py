# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `trace_map.py` is verified against.

The mapper's whole value is strictness — an event it cannot map is a hard
error, never a silent stutter — so every refusal direction is broken here once
on a fixture, and the sync check (the committed data module against the
committed trace) is shown able to fail in both directions.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import trace_map

GOOD = [
    {"ev": "select", "app": "piv", "sw": "9000"},
    {"ev": "verify", "app": "piv", "ref": "pivPin", "sw": "63C2"},
    {"ev": "select", "app": "piv", "sw": "9000"},
    {"ev": "card_reset"},
    {"ev": "select", "app": "piv", "sw": "9000"},
]


def build(root: pathlib.Path, events=None) -> pathlib.Path:
    traces = root / "formal" / "traces"
    traces.mkdir(parents=True)
    with open(traces / "seams-session.jsonl", "w") as fh:
        for e in GOOD if events is None else events:
            fh.write(json.dumps(e) + "\n")
    records, problems = trace_map.map_events(
        trace_map.load_events(traces / "seams-session.jsonl")
    )
    if not problems:
        (root / "formal" / "TraceSeamsData.tla").write_text(trace_map.render(records))
    return root


@pytest.fixture
def tree(tmp_path):
    return build(tmp_path)


def red(tree, needle: str) -> None:
    problems, _ = trace_map.audit(tree)
    assert any(needle in p for p in problems), problems


def test_green_fixture_passes(tree):
    problems, summary = trace_map.audit(tree)
    assert problems == []
    assert "5 actions" in summary


def test_double_select_maps_reselect_and_reset_clears_the_tracker():
    records, problems = trace_map.map_events(GOOD)
    assert problems == []
    # select, verify, RE-select, reset, then select again — which must be
    # SelectOther, because the reset dropped the selection.
    assert '"SelectOther"' in records[0]
    assert '"Reselect"' in records[2]
    assert records[3] == '[act |-> "CardReset"]'
    assert '"SelectOther"' in records[4]


def test_unknown_event_kind_is_refused(tmp_path):
    build(tmp_path, GOOD + [{"ev": "wink"}])
    red(tmp_path, "unknown event kind")


def test_unknown_applet_is_refused(tmp_path):
    build(tmp_path, [{"ev": "select", "app": "mgmt", "sw": "9000"}])
    red(tmp_path, "unknown applet")


def test_a_refused_select_is_refused(tmp_path):
    build(tmp_path, [{"ev": "select", "app": "piv", "sw": "6A82"}])
    red(tmp_path, "refused SELECT")


def test_a_strange_status_word_is_refused(tmp_path):
    build(
        tmp_path,
        [
            {"ev": "select", "app": "piv", "sw": "9000"},
            {"ev": "verify", "app": "piv", "ref": "pivPin", "sw": "6983"},
        ],
    )
    red(tmp_path, "neither success nor a retry count")


def test_a_verify_off_the_selected_applet_is_refused(tmp_path):
    build(
        tmp_path,
        [
            {"ev": "select", "app": "pgp", "sw": "9000"},
            {"ev": "verify", "app": "piv", "ref": "pivPin", "sw": "9000"},
        ],
    )
    red(tmp_path, "while the tracker says")


def test_an_unmapped_reference_is_refused(tmp_path):
    build(
        tmp_path,
        [
            {"ev": "select", "app": "oath", "sw": "9000"},
            {"ev": "verify", "app": "oath", "ref": "oathOtpPin", "sw": "9000"},
        ],
    )
    red(tmp_path, "no mapping for")


def test_an_empty_trace_is_refused(tmp_path):
    build(tmp_path, [])
    red(tmp_path, "zero actions")


def test_a_drifted_data_module_is_refused(tree):
    data = tree / "formal" / "TraceSeamsData.tla"
    data.write_text(data.read_text().replace('"Reselect"', '"SelectOther"'))
    red(tree, "does not match the mapping")


def test_a_missing_data_module_is_refused(tree):
    (tree / "formal" / "TraceSeamsData.tla").unlink()
    red(tree, "missing")


def test_a_missing_trace_is_refused(tmp_path):
    (tmp_path / "formal").mkdir()
    red(tmp_path, "missing")
