# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Family membership cannot discharge the matrix's unresolved requirements."""
import json

import oracle
from oracle_lib.catalog import catalog
from oracle_lib.trace import Reply


def test_full_catalog_exposes_variant_gaps_even_with_no_missing_families(monkeypatch, tmp_path, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline catalog attempted device access")
    monkeypatch.setattr(oracle, "inventory", forbidden)
    monkeypatch.setattr(oracle, "Hid", forbidden)
    monkeypatch.setattr(oracle, "Pcsc", forbidden)
    destination = tmp_path / "catalog.json"
    assert oracle.main(["plan", "--out", str(destination)]) == 0
    summary = json.loads(capsys.readouterr().out)
    report = json.loads(destination.read_text())["coverage"]
    assert not summary["unimplemented_families"]
    assert summary["matrix_completion"] == report["matrix_completion"] == "incomplete"
    assert summary["unresolved_requirements"] == report["unresolved_requirements"]
    assert any("F04" in item["families"] and "padding" in item["requirement"] for item in report["unresolved_requirements"])
    assert all(row["variant_coverage"] != "complete" for row in report["families"])
    assert not destination.with_name("events.jsonl").exists()


def test_a_small_selected_suite_cannot_certify_an_entire_family():
    report = catalog("rsk", ["transport-boundaries"], oracle.execute)["coverage"]
    hid = next(row for row in report["families"] if row["family"] == "T06")
    assert hid["scenarios"] and hid["variant_coverage"] == "incomplete"
    assert hid["unresolved_requirements"]


def test_continuation_status_is_not_a_rejection_for_any_apdu_adapter():
    assert Reply(b"x\x61\xff", "applet_error", 0x61FF).protocol == "response_continuation"
    assert Reply(b"x\x61\xff", status=0x61FF).protocol == "response_continuation"
    assert not Reply(b"x\x61\xff", status=0x61FF).is_rejection
    assert Reply(b"\x69\x82", "applet_error", 0x6982).protocol == "applet_error"
    assert Reply(b"\x3d", "applet_error", 0x3D).protocol == "applet_error"
