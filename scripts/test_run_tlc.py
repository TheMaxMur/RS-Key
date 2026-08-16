# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Mutation table for the formal runner's verdict boundary.

TLC itself is the slow system under test in the weekly job. These cases replace
only its output stream, then drive the real runner, floors and configurations so
each silent-pass shape is permanently reproducible in the merge gate.
"""

import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNNER = ROOT / "formal" / "run-tlc.sh"

GREEN = """\
100 states generated
100 distinct states found
The depth of the complete state graph search is 3.
Model checking completed. No error has been found.
"""

VACUOUS = """\
1 states generated
1 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
"""

RED = """\
10 states generated
10 distinct states found
The depth of the complete state graph search is 2.
Invariant NoAuthorizationBypass is violated.
"""


@pytest.fixture
def fake_tlc(tmp_path):
    jar = tmp_path / "tla2tools.jar"
    jar.touch()
    java = tmp_path / "java"
    java.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "print(os.environ['FAKE_TLC_OUTPUT'])\n"
    )
    java.chmod(0o755)
    return jar, java


def run(fake_tlc, cfg: str, output: str, jar: pathlib.Path | None = None):
    real_jar, java = fake_tlc
    env = {
        **os.environ,
        "JAVA": str(java),
        "TLA2TOOLS_JAR": str(jar or real_jar),
        "FAKE_TLC_OUTPUT": output,
    }
    return subprocess.run(
        [str(RUNNER), cfg],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def test_broken_jar_path_fails_before_tlc(fake_tlc, tmp_path):
    result = run(fake_tlc, "Shipped.cfg", GREEN, tmp_path / "missing.jar")
    assert result.returncode == 2
    assert "not readable" in result.stderr


def test_broken_shipped_invariant_is_red(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", RED)
    assert result.returncode == 1
    assert "RED: NoAuthorizationBypass" in result.stdout
    assert "expected GREEN" in result.stdout


def test_one_state_model_is_vacuous_not_green(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", VACUOUS)
    assert result.returncode == 1
    assert "VACUOUS: nothing was enabled" in result.stdout
    assert "expected GREEN" in result.stdout


def test_floor_regression_is_not_green(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", GREEN)
    assert result.returncode == 1
    assert "FLOOR: 100 < 20000000" in result.stdout
    assert "expected GREEN" in result.stdout


def test_invariant_that_stops_catching_its_solo_mutant_is_rejected(fake_tlc):
    result = run(fake_tlc, "Solo_BugResetGatesFirst.cfg", GREEN)
    assert result.returncode == 1
    assert "GREEN" in result.stdout
    assert "expected RED" in result.stdout


def test_mutant_that_stops_firing_is_rejected(fake_tlc):
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", GREEN)
    assert result.returncode == 1
    assert "GREEN" in result.stdout
    assert "expected RED" in result.stdout
