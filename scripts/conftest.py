# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""A skipped case is not a passed one, and only the exit code reaches the gate.

`check.sh`'s `pytest (gate scripts)` row reads that exit code and nothing else,
and so does `check-assurance.sh`'s `pytest (assurance scripts)` — the same
directory under the `assurance` marker registered below — so a table that stops
RUNNING is indistinguishable from one that passes: pytest
prints `s` in grey and exits 0. Measured on `test_elf_gate.py` before this file
existed — 7 of its 13 cases were `skipif`'d on a built firmware, so a checkout
with no `target/` ran the row at **6 passed, 7 skipped, exit 0**, and the seven
carrying the mutation table for `elf_gate.py` asserted nothing whatsoever.

It is the family `test_gate_scripts.py` already records twice: a rule that asks
whether a table EXISTS is bypassed by emptying it, and the rule that replaced it
counts cases as WRITTEN (`^def test_`, deliberately — re-entering pytest to find
out what it collects costs more than that rule is worth), which cannot tell a
case that ran from one that was skipped. Neutralising a whole table to skips
therefore left every rule in the tree green.

It belongs in a conftest and not in a case: a case counting the session's own
skips would be counting them while the session is still deciding them.
"""

from __future__ import annotations

#: How many skipped cases `pytest scripts` may report. ZERO — a case that cannot
#: run in a bare checkout is the thing to fix, not the budget: nearly every table
#: under `scripts/` drives its subject over handed-in text or a `tmp_path`
#: fixture. The exception is `test_ct_gate.py`'s image arms, which disassemble
#: the built firmware because the defect they inject is machine code; they ERROR
#: without one rather than skipping, which is the point. It is a PARAMETER of
#: `verdict()` rather than a global a case reads, so both arms are drivable
#: without patching the number the session it runs in is judged by.
SKIP_BUDGET = 0

_SKIPPED: set[str] = set()


def verdict(skipped: int, budget: int) -> str | None:
    """The message, or None when the session is inside its budget."""
    if skipped <= budget:
        return None
    return (
        f"pytest scripts: {skipped} skipped case(s) against a budget of"
        f" {budget} — a skipped case asserts nothing and still exits 0, which is"
        " the whole of what the row reads; hand it its subject or delete it"
    )


def pytest_configure(config):
    # The split between the two runners' pytest rows; unregistered, it is a
    # PytestUnknownMarkWarning in every file that carries it.
    config.addinivalue_line(
        "markers",
        "assurance: a table of the TLA+ plumbing or of a registry held against"
        " prose; scripts/check-assurance.sh runs these, scripts/check.sh the rest",
    )


def pytest_runtest_logreport(report):
    # `wasxfail` marks an xfail: a recorded expectation, not a case that quietly
    # did not run. Keyed by nodeid so a phase reported twice counts once.
    if report.skipped and not hasattr(report, "wasxfail"):
        _SKIPPED.add(report.nodeid)


def pytest_terminal_summary(terminalreporter):
    message = verdict(len(_SKIPPED), SKIP_BUDGET)
    if message:
        terminalreporter.write_line(message)
        for nodeid in sorted(_SKIPPED):
            terminalreporter.write_line(f"  {nodeid}")


def pytest_sessionfinish(session, exitstatus):
    # The exit code is what `check.sh` reads, so the budget has to move it —
    # `-rs` output reaches no `run` row's verdict. A session that already failed
    # keeps its own status.
    if verdict(len(_SKIPPED), SKIP_BUDGET) and exitstatus == 0:
        session.exitstatus = 1
