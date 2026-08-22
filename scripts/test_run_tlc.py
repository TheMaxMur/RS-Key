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

#: What an INDUCTIVE probe looks like: every successor is already an initial
#: state, so the search ends at depth 1 with more states generated than found.
INDUCTIVE = """\
22920 states generated
1000 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
"""

#: And what it looks like when a step LEFT the predicate: a second level, which
#: is the refutation of `IndInv /\ Next => IndInv'` whatever the invariants say.
NOT_INDUCTIVE = """\
10748 states generated
788 distinct states found
The depth of the complete state graph search is 2.
Model checking completed. No error has been found.
"""


@pytest.fixture
def fake_tlc(tmp_path):
    jar = tmp_path / "tla2tools.jar"
    jar.touch()
    java = tmp_path / "java"
    java.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        # A real JVM dies on `-Xmx-`, and the heap column can now hold `-` as a
        # placeholder because a column follows it. Every row with one came back
        # "Could not create the Java Virtual Machine" — a RED for no reason at
        # all — so the stand-in refuses it too.
        "if '-Xmx-' in sys.argv:\n"
        "    sys.stderr.write('Error: Could not create the Java Virtual Machine.')\n"
        "    raise SystemExit(1)\n"
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


def test_an_induction_probe_at_depth_one_is_green_and_not_vacuous(fake_tlc):
    """Depth 1 is what INDUCTIVE looks like, not what vacuity looks like.

    Every successor of an `INIT IndInv` run is already an initial state, so the
    search terminates immediately. The generic rule reads that as nothing having
    been enabled and would refuse every such row.
    """
    result = run(fake_tlc, "StoreInduction.cfg", INDUCTIVE)
    assert result.returncode == 0
    assert "GREEN" in result.stdout


def test_an_induction_probe_whose_step_left_the_predicate_is_refused(fake_tlc):
    """Depth 2 means a successor was NOT an initial state, which is the whole
    claim failing — and the INVARIANTS block need not have noticed, because a
    conjunct of `IndInv` is not necessarily one of them."""
    result = run(fake_tlc, "StoreInduction.cfg", NOT_INDUCTIVE)
    assert result.returncode == 1
    assert "NOT INDUCTIVE" in result.stdout


def test_the_exemption_does_not_reach_an_ordinary_specification(fake_tlc):
    """`Shipped.cfg` has no `INIT` line, so the depth floor still binds it."""
    result = run(fake_tlc, "Shipped.cfg", INDUCTIVE)
    assert result.returncode == 1
    assert "VACUOUS: nothing was enabled" in result.stdout


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


#: A RED naming an invariant whose name carries a DIGIT. `[A-Za-z]+` matched none
#: of the nine trace rows for the whole life of the runner, so their verdict
#: column printed the raw error line and read RED coarsely — invisible until the
#: name started being compared.
RED_R4C = """\
37 states generated
37 distinct states found
The depth of the complete state graph search is 37.
Error: Invariant R4cGateAnswers is violated.
"""

RED_R4A = RED_R4C.replace("R4cGateAnswers", "R4aRawRefinesB")


def test_an_invariant_name_with_a_digit_is_read(fake_tlc):
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4C)
    assert result.returncode == 0
    assert "RED: R4cGateAnswers" in result.stdout


def test_a_red_for_the_wrong_invariant_is_rejected(fake_tlc):
    """The colour is right and the reason is not — 2 of 24 co-refutation patches
    in this tree scored a kill that way. Measured on this very row: flipping the
    alwaysUv mutant to the INVERSE defect kept it red at a different boundary."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4A)
    assert result.returncode == 1
    assert "expected RED: R4cGateAnswers" in result.stdout


def test_a_row_that_names_no_invariant_is_not_held_to_one(fake_tlc):
    """`TraceSeamsBad.cfg` is refused by a DEADLOCK, which names nothing, and the
    `Mut_*` families name theirs in their own INVARIANTS block."""
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", RED)
    assert result.returncode == 0
    assert "RED: NoAuthorizationBypass" in result.stdout


def test_a_placeholder_heap_does_not_reach_the_jvm(fake_tlc):
    """The row that exposed it: `RED - - <invariant>` gives `heap` the string
    `-`, and `-Xmx-` is not a heap."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4C)
    assert "Could not create the Java Virtual Machine" not in result.stdout
    assert result.returncode == 0
