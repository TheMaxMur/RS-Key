# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Exercise the coverage command's missing-evidence exits through its shell entry."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
CARGO = r'''
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
mode = os.environ["METRICS_FIXTURE"]
if args[0] == "metadata":
    features = ["always-uv"] if "firmware/always-uv" in args else []
    print(json.dumps({"packages": [{"id": "fido", "name": "rsk-fido"}],
                      "resolve": {"nodes": [{"id": "fido", "features": features}]}}))
    print("metadata diagnostics belong on stderr", file=sys.stderr)
elif args[:2] == ["llvm-cov", "report"]:
    if "--lcov" in args:
        Path(args[args.index("--output-path") + 1]).write_text("TN:\nend_of_record\n")
    else:
        Path(args[args.index("--output-dir") + 1]).mkdir()
elif args[0] == "llvm-cov":
    if mode == "command-failure":
        print("fixture test execution failed")
        sys.exit(101)
    print(f"test result: ok. {0 if mode == 'no-tests' else 1} passed; 0 failed;")
    count = 0 if mode == "empty-report" else 1
    report = {"data": [{"files": [] if count == 0 else [{"filename": "fixture.rs"}],
                        "totals": {"lines": {"count": count, "covered": count}}}]}
    Path(args[args.index("--output-path") + 1]).write_text(json.dumps(report))
else:
    raise SystemExit(f"unexpected cargo command: {args}")
'''


def run(tmp_path, mode, profile="always-uv"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text(f"#!{sys.executable}\n" + CARGO)
    cargo.chmod(0o755)
    out = tmp_path / "report"
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
               COVERAGE_PROFILE=profile, COVERAGE_OUT=str(out), METRICS_FIXTURE=mode)
    result = subprocess.run(["bash", str(ROOT / "scripts/metrics.sh"), "--coverage"],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    return result, out


def test_profile_features_and_diagnostics_survive_the_actual_command(tmp_path):
    result, out = run(tmp_path, "present")
    assert result.returncode == 0, result.stderr
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["status"] == "complete"
    assert manifest["host_feature_args"] == ["rsk-fido/always-uv"]
    assert manifest["commands"][2]["argv"].count("rsk-fido/always-uv") == 1
    assert "stderr" in (out / "firmware.metadata.json.stderr").read_text()


@pytest.mark.parametrize("mode,message,status", [
    ("no-tests", "no executed tests", "incomplete"),
    ("empty-report", "missing coverage evidence", "incomplete"),
    ("command-failure", "coverage command failed (101)", "failed"),
])
def test_missing_evidence_is_not_a_completed_measurement(tmp_path, mode, message, status):
    result, out = run(tmp_path, mode)
    assert result.returncode != 0
    assert message in result.stderr
    assert json.loads((out / "manifest.json").read_text())["status"] == status
    assert not (out / "coverage.lcov").exists()


def test_unknown_shipping_feature_cannot_measure_default_silently(tmp_path):
    result, out = run(tmp_path, "present", "unknown-profile")
    assert result.returncode != 0
    assert "unknown firmware feature" in result.stderr
    assert not out.exists()
