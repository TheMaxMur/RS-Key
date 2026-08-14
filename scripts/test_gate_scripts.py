# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The rule the guards cannot state about themselves: every one is wired in.

Each `scripts/*_gate.py` asserts that `check.sh` runs *it* and that its own test
file is named after it. Neither direction covers the case that actually happens:
a new guard lands with no tests, or with tests nothing collects, and every
existing assertion stays green because none of them has heard of it. Found by
review, in the same pass that found four holes in the guards themselves.

Deliberately not inside one of the guards: it is a fact about the set of them,
and putting it in whichever one happened to be written last is how it comes to be
deleted with that one.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent

#: A gate script: run by `check.sh`, owed a mutation table. `gate_lines.py` is a
#: shared helper with no rule of its own, and the two `gate_*.py` spellings that
#: predate the convention are named here rather than pattern-matched, so the
#: pattern stays exact.
GATES = sorted(p.name for p in HERE.glob("*_gate.py") if not p.name.startswith("test_"))
#: Guards the `*_gate.py` pattern cannot reach, so they are owed a table by name
#: rather than by glob: `impact.py` is run by the pre-commit hook and not by
#: `check.sh`, and `kani.sh` is a shell script. Both once had no table at all,
#: which is the same blind spot one file over.
NAMED = {"impact.py": "test_impact.py", "kani.sh": "test_kani_sh.py"}
#: The pytest invocation that has to reach the tests, wherever it is spelled.
COLLECTS = re.compile(r"pytest\s+([^\n|;&]*)")


def check_sh():
    return (ROOT / "scripts/check.sh").read_text()


def test_there_are_gates_to_check():
    """A glob that matches nothing loops over nothing and passes every case below."""
    assert len(GATES) >= 4, GATES


def test_every_gate_is_run_by_check_sh():
    missing = [g for g in GATES if f"scripts/{g}" not in check_sh()]
    assert not missing, f"check.sh runs none of {missing}"


def test_every_gate_has_a_mutation_table():
    missing = [g for g in GATES if not (HERE / f"test_{g}").is_file()]
    missing += [g for g, table in NAMED.items() if not (HERE / table).is_file()]
    assert not missing, f"no scripts/test_<name>.py for {missing}"


def test_the_named_guards_still_exist():
    """A table kept for a guard that went away is one nobody will notice go stale."""
    missing = [g for g in NAMED if not (HERE / g).is_file()]
    assert not missing, f"{missing} are named here but not in scripts/"


def test_the_mutation_tables_are_collected():
    """`check.sh` collects the directory, so a new table is registered by name."""
    runs = [m.group(1) for m in COLLECTS.finditer(check_sh())]
    assert any("scripts" in words for words in runs), runs


def test_every_gate_reports_a_summary_when_it_is_happy():
    """A guard that prints nothing on success is one nobody notices going quiet."""
    for name in GATES:
        text = (HERE / name).read_text()
        assert "def audit(" in text, f"{name} has no audit() the tests can drive"
        assert "def main(" in text, f"{name} has no main() check.sh can run"
