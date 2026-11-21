# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Family membership cannot discharge the matrix's unresolved requirements."""
import json
import re
from pathlib import Path

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
    pending = re.findall(r"^- \[ \] `([^`]+)`: (.+)$", Path(oracle.__file__).with_name("oracle-plan.md").read_text(), re.MULTILINE)
    assert summary["matrix_completion"] == report["matrix_completion"] == ("incomplete" if pending else "not_certified")
    assert summary["unresolved_requirements"] == report["unresolved_requirements"]
    assert report["unresolved_requirements"] == [{"families": re.findall(r"[A-Z]+\d{2}", families), "requirement": clause} for families, clause in pending]
    assert all(row["variant_coverage"] != "complete" for row in report["families"])
    assert not destination.with_name("events.jsonl").exists()


def test_a_small_selected_suite_cannot_certify_an_entire_family():
    report = catalog("rsk", ["ccid-matrix"], oracle.execute)["coverage"]
    ccid = next(row for row in report["families"] if row["family"] == "T10")
    assert ccid["scenarios"] and ccid["variant_coverage"] != "complete"
    assert ccid["coverage"] == "implemented_not_run" and not ccid["executed"]


def test_a_pending_clause_is_reported_even_when_its_family_has_a_scenario(tmp_path, monkeypatch):
    from oracle_lib import coverage
    monkeypatch.setattr(coverage, "__file__", str(tmp_path / "oracle_lib" / "coverage.py"))
    (tmp_path / "oracle-plan.md").write_text("| T10 | CCID | Power and framing | ABORT |\n\n- [ ] `T10`: Native control ABORT is still unimplemented.\n")
    case = {"families": ["T10"], "exchanges": [], "applicability": "not_run", "scenario_id": "one-family-member", "verdict": "inconclusive", "reason": "offline"}
    report = coverage.coverage([case])
    assert report["matrix_completion"] == "incomplete"
    assert report["families"][0]["variant_coverage"] == "incomplete"
    assert report["families"][0]["unresolved_requirements"] == ["Native control ABORT is still unimplemented."]


def test_continuation_status_is_not_a_rejection_for_any_apdu_adapter():
    assert Reply(b"x\x61\xff", "applet_error", 0x61FF).protocol == "response_continuation"
    assert Reply(b"x\x61\xff", status=0x61FF).protocol == "response_continuation"
    assert not Reply(b"x\x61\xff", status=0x61FF).is_rejection
    assert Reply(b"\x69\x82", "applet_error", 0x6982).protocol == "applet_error"
    assert Reply(b"\x3d", "applet_error", 0x3D).protocol == "applet_error"
