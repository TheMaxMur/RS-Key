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
#: rather than by glob. Each value is **(mutation table, the file that runs it)**:
#: these guards are not wired in the same place, and "it has a table" says nothing
#: about whether anything invokes it — which is the half that goes missing. Each
#: once had no table at all, the same blind spot one file over; `run-tlc.sh` and
#: `kani.sh` are additionally not `check.sh` rows at all, so a rule that assumed
#: they were would be satisfied by the comments that name them.
NAMED = {
    "../formal/run-tlc.sh": ("test_run_tlc.py", "../.github/workflows/deep-checks.yml"),
    # The config generator: `config_gen_gate.py` is only as good as the script it
    # re-runs, and nothing else in `scripts/` names it — that guard IS its runner.
    "../formal/gen-configs.sh": ("test_config_gen_gate.py", "config_gen_gate.py"),
    "impact.py": ("test_impact.py", "hooks/pre-commit"),
    "kani.sh": ("test_kani_sh.py", "../.github/workflows/ci.yml"),
    "comutate.py": ("test_comutate.py", "check.sh"),
    "crate_graph.py": ("test_crate_graph.py", "check.sh"),
    # The font generator, the second of that shape: `check.sh` runs its `--check`
    # as a row, the name does not end in `_gate.py`, and it landed with no table.
    "generate_ui_fonts.py": ("test_generate_ui_fonts.py", "check.sh"),
    # The two `formal/` mappers: both are `check.sh` rows, neither ends in
    # `_gate.py`, so their tables could have been deleted with this file green.
    "security_trace.py": ("test_security_trace.py", "check.sh"),
    "trace_map.py": ("test_trace_map.py", "check.sh"),
}
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
    missing += [g for g, (table, _) in NAMED.items() if not (HERE / table).is_file()]
    assert not missing, f"no scripts/test_<name>.py for {missing}"


def test_the_named_guards_still_exist():
    """A table kept for a guard that went away is one nobody will notice go stale."""
    missing = [g for g in NAMED if not (HERE / g).is_file()]
    assert not missing, f"{missing} are named here but not in scripts/"


def code(text):
    """`text`'s lines with their comment tails cut off.

    A guard named only in a comment is run by nothing, and counting one is a hole
    this repo has already shipped: `kani_gate.py` read a commented-out invocation
    as live, and the prefix-only repair still passed `true # cargo …`. Cutting at
    the first `#` refuses both. Deliberately the conservative direction — a real
    invocation carrying a trailing `#` would be missed and go red, which is loud,
    where a comment counted as an invocation is silent.
    """
    return [
        stripped
        for line in text.splitlines()
        if (stripped := line.split("#", 1)[0]).strip()
    ]


def wired_in(guard, runner_text):
    """Whether the runner's code — not its prose — names `guard`."""
    name = pathlib.PurePath(guard).name
    return any(name in line for line in code(runner_text))


def test_every_named_guard_is_run_by_its_stated_runner():
    """The property the glob half already has, for the half that lacked it.

    `test_every_gate_is_run_by_check_sh` covers `GATES` and nothing covered
    `NAMED`, so an entry could arrive with a table, a file, and nothing invoking
    it. Three tables do assert it (`crate_graph`, `security_trace`,
    `generate_ui_fonts`) — by convention, one guard at a time, which is how the
    fourth arrives without one. Those stay: they pin the exact row including its
    flags, which a name match cannot.
    """
    missing = [
        (guard, runner)
        for guard, (_, runner) in NAMED.items()
        # A runner that is not there is one cause, and the test below owns it —
        # reading it here would report the same cause a second time, as a
        # traceback rather than a sentence.
        if (HERE / runner).is_file()
        and not wired_in(guard, (HERE / runner).read_text())
    ]
    assert not missing, f"named but invoked nowhere in their runner: {missing}"


def test_the_named_runners_still_exist():
    """A runner that moved makes the rule above vacuous rather than red."""
    missing = [r for _, r in NAMED.values() if not (HERE / r).is_file()]
    assert not missing, f"{missing} are named as runners but do not exist"


def test_a_comment_is_not_an_invocation():
    """The rule above is only worth having if prose cannot satisfy it."""
    assert wired_in("kani.sh", "        run: ./scripts/kani.sh pr")
    assert not wired_in("kani.sh", "# the weekly row runs scripts/kani.sh")
    assert not wired_in("kani.sh", "true # scripts/kani.sh all")
    assert not wired_in("kani.sh", "   \n\n")


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
