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

Both of its rules then shipped with a hole of that same family, found by the next
review and measured on the whole set rather than on the guard that prompted it. A
row can be COMMENTED OUT: the roster compared `check.sh`'s raw text while the
comment-cut written here for exactly that was applied only to `NAMED`, and all
eleven `*_gate.py` rows commented out at once left `pytest scripts -q` identical
to its baseline. And a table can be EMPTIED: the roster asked `is_file()` and
nothing else, so truncating one to its SPDX line took 241 cases out of the suite
with zero new failures. Deleting either — the line, the file — was caught, which
is what made the pair look covered.

The second fact about the set is what each script does with a temp. `check.sh`
was the only one of the nine that make one with no cleanup at all — five sites,
~10 GB of build trees per run, until a full volume stopped a session dead — and
nothing could say so, because every rule in the tree is about a guard's ROWS. One
of those five could not be cleaned even by hand: `out=$(mktemp -d)/pt.elf` keeps
the file and throws the directory away, so no name in the script reached it.

And the temp a script does NOT make. Those four rules are spelled over `mktemp`,
so the three `pytest` rows were invisible to every one of them while leaking
harder than any site they cover: pytest puts `tmp_path` under $TMPDIR, `nix
develop` hands each invocation a fresh one it never removes, and the retention
that would have swept it is counted per base directory — so it never met a
previous run. 361 orphaned bases, 8.9 GB, inside one day.
"""

import ast
import importlib
import inspect
import os
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap
import time
import types

import pytest

import conftest
import gate_lines

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
    # The four that sat in `UNROSTERED` below under the plainest reason there is
    # — "a `run` row with no mutation table" — until each got one. Two of them
    # are `.sh`, which the `_gate.py` glob cannot see even when the name ends in
    # `_gate`: `complexity_gate.sh` is that blind spot wearing a third suffix.
    "docs_constants.py": ("test_docs_constants.py", "check.sh"),
    "gate_union.py": ("test_gate_union.py", "check.sh"),
    "complexity_gate.sh": ("test_complexity_gate.py", "check.sh"),
    "token_refinement.sh": ("test_token_refinement.py", "check.sh"),
    # The reproduction runner: a `--self-test` row like the two in
    # `UNROSTERED`, and the one of that shape with a table of its own, so it
    # belongs here rather than in the carve-out that forbids one.
    "reproduce.sh": ("test_reproduce.py", "check.sh"),
}
#: The board-only scripts under `tests/` that have a host table here, as
#: **(script, its table)**. They are not guards and no `check.sh` row runs them —
#: that is exactly why they need naming: neither rule above can see a table whose
#: subject is not a row, so both members of this family could have been emptied
#: with `pytest scripts` green. Measured on the newer one: truncated to its SPDX
#: line, `python -m pytest scripts -q` was rc 0 until this dict existed.
BOARD_TABLES = {
    "../tests/54_sram_residue.py": "test_sram_residue_dump.py",
    "../tests/29_reset_power_cut.py": "test_reset_power_cut.py",
}

#: The pytest invocation that has to reach the tests, wherever it is spelled.
COLLECTS = re.compile(r"pytest\s+([^\n|;&]*)")

#: A case of a mutation table. Counted as written rather than as pytest collects
#: it: a parametrized table counts higher either way, and re-entering pytest to
#: find that out costs more than the rule is worth.
CASE = re.compile(r"^def test_", re.M)

#: What a mutation table must carry. The smallest in the tree has 8 cases, so
#: this catches the COLLAPSE and not a slide — and the collapse is what was
#: measured: `test_verdict_gate.py` truncated to its SPDX line took 241 cases out
#: of `pytest scripts -q` with ZERO new failures, because the rule below asked
#: only whether the file exists.
TABLE_FLOOR = 5

#: Every `def test_` under `scripts/`, and it is an EQUALITY rather than a floor.
#:
#: What it closes is the hole `TABLE_FLOOR` names and cannot reach: a single case
#: deleted from a 176-case table. Driven WITHOUT this rule —
#: `test_a_label_a_sentence_merely_WRITES_is_not_an_arm` deleted outright left
#: this file at exit 0, `test_platform_gate.py` at exit 0 with one fewer case
#: collected, and `scripts/platform_gate.py` at exit 0. Every case in this tree
#: could be deleted the same way, and `platform_gate.py`'s hollow-arm floor and
#: its misplaced-label diagnostic trip on no record in the checkout, so pytest is
#: the whole of their protection. With this rule the same deletion is exit 1 here
#: and still exit 0 in the file it was deleted from, which is the point: the
#: roster is what notices, not the table that lost the case.
#:
#: A FLOOR cannot do this and that is why this is not one: set at today's count it
#: decays to blind on the first case anyone adds, because 2500 - 1 still clears
#: 2499. The price of the equality is that ADDING a case is also a red, with one
#: number to move — the same shape as `platform_gate.py --write`, and the message
#: below prints the value to write. One number and not fifty-seven per-table ones:
#: this tree has a commit of its own removing three hard-coded twins of a count
#: that moved, and a twin per table is that defect fifty-seven times over.
#:
#: What it still does not cover: a case gutted rather than deleted. `assert True`
#: counts here exactly as the case it replaced did, and nothing in this file reads
#: a case's body.
SUITE_CASES = 2651


def check_sh():
    return (ROOT / "scripts/check.sh").read_text()


def suite_cases():
    """`def test_` over every table under `scripts/`, this file included."""
    return sum(len(CASE.findall(p.read_text()))
               for p in sorted(HERE.glob("test_*.py")))


def test_there_are_gates_to_check():
    """A glob that matches nothing loops over nothing and passes every case below."""
    assert len(GATES) >= 4, GATES


def test_every_gate_is_run_by_check_sh():
    """The row's CODE, because a `#` in front of it is not a row.

    This compared the file's raw text and `code()` — written in this file for
    exactly that, citing the `kani_gate.py` precedent — was applied only to
    `NAMED`. Measured: all eleven `*_gate.py` rows commented out at once left
    `pytest scripts -q` identical to its baseline, while deleting one line
    outright was caught.
    """
    missing = [g for g in GATES if not gate_lines.runs(check_sh(), f"scripts/{g}")]
    assert not missing, f"check.sh runs none of {missing}"


def tables():
    """(subject, its mutation table) for every half of the roster."""
    return ([(g, f"test_{g}") for g in GATES]
            + [(g, t) for g, (t, _) in NAMED.items()]
            + sorted(BOARD_TABLES.items()))


def test_every_gate_has_a_mutation_table():
    missing = [g for g, table in tables() if not (HERE / table).is_file()]
    assert not missing, f"no scripts/test_<name>.py for {missing}"


def test_every_mutation_table_has_cases_in_it():
    """A file, not an empty one: the rule above asked `is_file()` and nothing
    else, so truncating `test_verdict_gate.py` to its SPDX line took 241 cases
    out of the suite with zero new failures. Deleting it outright was caught —
    which is the pair that says the hole is the emptying, not the removal."""
    empty = {table: len(CASE.findall((HERE / table).read_text()))
             for _, table in tables()
             if (HERE / table).is_file()
             and len(CASE.findall((HERE / table).read_text())) < TABLE_FLOOR}
    assert not empty, f"mutation tables under the floor of {TABLE_FLOOR}: {empty}"


def test_the_board_scripts_with_a_table_still_exist():
    """A table kept for a script that moved is one nobody will notice go stale,
    and these are the entries no other rule here can reach."""
    missing = [g for g in BOARD_TABLES if not (HERE / g).is_file()]
    assert not missing, f"{missing} are named here but not in tests/"


def test_no_board_table_is_owed_a_check_sh_row():
    """The reason they are a separate roster: `check.sh` must NOT run them.

    They need a board and a real supply cut. A row appearing for one is a
    different mistake from a table going missing, and this says which."""
    row = check_sh()
    running = [g for g in BOARD_TABLES if gate_lines.runs(row, pathlib.PurePath(g).name)]
    assert not running, f"check.sh runs {running}, which need hardware"


def test_no_case_has_been_deleted_from_the_suite():
    """One case out of a 176-case table was a green tree. See [`SUITE_CASES`].

    The count is over `def test_` and not over what pytest collects, for the same
    reason [`CASE`] is: re-entering pytest to find out costs more than the rule is
    worth, and a parametrized case counts as one either way — which is enough,
    because a DELETED case takes its `def` with it.
    """
    now = suite_cases()
    assert now == SUITE_CASES, (
        f"scripts/ holds {now} `def test_` and SUITE_CASES says {SUITE_CASES}."
        f" If you added cases, write {now}. If you did not, one has been deleted"
    )


def test_the_named_guards_still_exist():
    """A table kept for a guard that went away is one nobody will notice go stale."""
    missing = [g for g in NAMED if not (HERE / g).is_file()]
    assert not missing, f"{missing} are named here but not in scripts/"


def wired_in(guard, runner_text):
    """Whether the runner's code — not its prose — names `guard`.

    `gate_lines.runs` rather than a comment-cut written here: this file had one,
    and having it in the file that needed it did not stop the rule above from
    comparing raw text instead. The eight guards that assert their own row in
    their own table read it from there too now.
    """
    return gate_lines.runs(runner_text, pathlib.PurePath(guard).name)


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
    """`check.sh` collects the directory, so a new table is registered by name.

    Over each row's CODE, like every other rule here: reading the raw text left a
    `#` in front of the `pytest scripts` row switching off every mutation table in
    the tree with this suite green. That is the third place the comment-cut was
    owed and the second time it was missed.
    """
    code = [gate_lines.split_at_comment(body)[0] for _indent, body in gate_lines.logical_lines(check_sh())]
    runs = [m.group(1) for line in code for m in COLLECTS.finditer(line)]
    assert any("scripts" in words for words in runs), runs


def test_every_gate_reports_a_summary_when_it_is_happy():
    """A guard that prints nothing on success is one nobody notices going quiet."""
    for name in GATES:
        text = (HERE / name).read_text()
        assert "def audit(" in text, f"{name} has no audit() the tests can drive"
        assert "def main(" in text, f"{name} has no main() check.sh can run"


#: A `check.sh` row that runs a script under `scripts/` and is owed no mutation
#: table by any rule above, with the reason. Held BOTH ways, the way
#: `release_gate.HISTORICAL` is: a name here that has since gained a table is
#: deleted from here, so a carve-out cannot outlive its need.
#:
#: Which is what happened to the four that used to sit here under the plainest
#: reason of all — "a `run` row with no mutation table" — and are on [`NAMED`]
#: now. What is left is the two shapes a table here is not the answer to: a
#: script that is not a guard, and a guard whose table is INSIDE it, driven by
#: the row itself. Three rows, and `pt.sh` is the only one that is not a guard.
UNROSTERED = {
    "pt.sh": "not a guard and not a `run` row: the elf and store rows invoke it"
             " to apply a partition table, and it asserts nothing",
    "ci-scope.sh": "a `run` row, and the one shape that does not need a table"
                   " here — `check.sh` runs its `--self-test`, so the table is"
                   " inside the script and the row IS the drive",
    "ci-knobs.sh": "the same: a `--self-test` row",
}

#: A `scripts/…` path as a `check.sh` row spells it, with or without `python`.
INVOKED = re.compile(r"(?:^|\s)(?:python3?\s+)?(?P<path>(?:\./)?scripts/[\w./-]+\.(?:py|sh))")


def invoked_scripts():
    """Every script under `scripts/` that a live `check.sh` row runs.

    `unquoted` as well as the comment cut, for this file's own reason one rule
    over: `check.sh` names itself inside an `echo` that tells a contributor which
    file to edit, and a rule reading that as an invocation reports the runner as
    a guard nothing tests.
    """
    code = [unquoted(gate_lines.split_at_comment(body)[0])
            for _indent, body in gate_lines.logical_lines(check_sh())]
    return sorted({pathlib.PurePath(found["path"]).name
                   for line in code for found in INVOKED.finditer(line)})


def test_every_script_check_sh_runs_is_on_a_roster():
    """The direction the two rules above cannot see, and the one that has failed.

    `test_every_gate_is_run_by_check_sh` walks the roster and asks whether the row
    exists. Nothing walked the ROWS and asked whether the roster has heard of
    them, so a guard whose name does not end `_gate.py` arrived with a table
    nothing was a roster for — measured on `crate_graph.py`, whose whole mutation
    table could have been deleted with this file green.
    """
    known = set(GATES) | {pathlib.PurePath(g).name for g in NAMED} | set(UNROSTERED)
    missing = [name for name in invoked_scripts() if name not in known]
    assert not missing, f"check.sh runs {missing}, which no roster here names"


def test_the_unrostered_carve_out_cannot_outlive_its_reason():
    """Both ways, so a script that has since gained a table leaves this list."""
    runs = set(invoked_scripts())
    stale = [name for name in UNROSTERED if name not in runs]
    assert not stale, f"{stale} are carved out here and no check.sh row runs them"
    covered = [name for name in UNROSTERED if (HERE / f"test_{pathlib.PurePath(name).stem}.py").is_file()]
    assert not covered, f"{covered} now have a mutation table — move them onto a roster"


def audit_arity(name):
    """How many values `name`'s `audit()` returns, so the stub can fill them.

    Read off the source rather than pinned in a table: the shapes run from one
    value to four, and a stub of the wrong arity raises in the REPORTING path,
    which reads as the exit-code case failing when it is the harness that is
    wrong.
    """
    found = 1
    for node in ast.parse((HERE / name).read_text()).body:
        if isinstance(node, ast.FunctionDef) and node.name == "audit":
            for inner in ast.walk(node):
                if isinstance(inner, ast.Return) and isinstance(inner.value, ast.Tuple):
                    found = max(found, len(inner.value.elts))
    return found


#: What the stub returns beside the findings. An empty LIST and not `None` in the
#: second slot: `assurance_gate` and `threat_gate` print that value's lines
#: before they look at the findings at all, so a stub that cannot be iterated
#: raises there and reads as this case failing.
FILLER = (None, [], "", [])

#: The operands a gate takes beside its root. One entry, named rather than
#: guessed from the signature: `run_count_gate.run(root, argv)` dispatches on it.
ENTRY_ARGS = {"run_count_gate.py": (ROOT, [])}


def exit_code(name, module):
    """What the row would read, whichever of three roads the gate takes to it.

    Most gates `return` an int out of `run` or `main`; `scope_gate` raises
    `SystemExit(1)` instead, which is that number by another road — so this reads
    it as one, or the one gate that never returns reads as the one that fails.

    Only `*_gate.py` is driven through here. The `NAMED` half does NOT share this
    contract and was measured not to: `crate_graph.py` and `generate_ui_fonts.py`
    dispatch on a subcommand and answer 0 and 2 to no arguments, `impact.py` and
    `security_trace.py` raise, and `comutate.py`'s `run` APPLIES the mutants
    rather than reporting on them.
    """
    if hasattr(module, "run"):
        args = ENTRY_ARGS.get(name, (ROOT,))
        try:
            return module.run(*args)
        except SystemExit as raised:
            return raised.code
    try:
        return module.main([]) if inspect.signature(module.main).parameters else module.main()
    except SystemExit as raised:
        return raised.code


@pytest.mark.parametrize("name", GATES)
def test_a_finding_reaches_the_row_as_a_non_zero_exit(name, monkeypatch, capsys):
    """The fact about the SET that no gate's own table stated about itself.

    Every mutation table under `scripts/` drives `audit()` and reads the findings
    it returns. `check.sh` reads neither: it reads the process's EXIT CODE, and
    nothing joined the two. Measured by flipping each entry function's non-zero
    return to zero and re-running that gate's own table: **14 of the 30 did not
    notice** — eleven stayed wholly green, and three had an unrelated red whose
    failure set the mutation did not change. Those rows printed their finding to
    the terminal and passed. `scope_gate` is the fourteenth in a shape the flip
    does not even reach: it `raise SystemExit(1)`s, mutated to `(0)` by hand, same
    result.

    One direction, deliberately. The clean direction needs a stub that also fills
    the summary line, which is built out of values only that gate's own `audit()`
    produces, and `check.sh` re-measures it on every run by being green.

    The finding must also be PRINTED, on either stream: six of these gates report
    on stdout and the rest on stderr, and which one is not this rule's business —
    a row that exits non-zero and says nothing is.
    """
    module = importlib.import_module(name[: -len(".py")])
    arity = audit_arity(name)
    finding = f"SYNTHETIC-EXIT-PROBE for {name}"
    answer = ([finding], *FILLER[1:arity]) if arity > 1 else [finding]
    monkeypatch.setattr(module, "audit", lambda *a, **k: answer)
    assert exit_code(name, module) != 0, f"{name} prints a finding and exits 0"
    printed = capsys.readouterr()
    assert finding in printed.out + printed.err, f"{name} exits non-zero without saying why"


def test_the_shared_exit_case_can_go_red():
    """The arm for the case above, in both of its directions.

    A rule that cannot fail is the thing this file exists to refuse, so the two
    shapes it is about are driven here over a stand-in: a gate that PRINTS the
    finding and exits 0 — which is exactly the mutation the sweep applied, and
    what fourteen rows would have survived — and one that exits non-zero in silence.
    """
    loud_but_green = types.SimpleNamespace(run=lambda root: (print("a finding"), 0)[1])
    assert exit_code("loud_but_green.py", loud_but_green) == 0

    silent_and_red = types.SimpleNamespace(run=lambda root: 1)
    assert exit_code("silent_and_red.py", silent_and_red) == 1

    # And the third shape, so `scope_gate`'s road is not read as an absence.
    def raiser(root):
        raise SystemExit(1)

    assert exit_code("raiser.py", types.SimpleNamespace(run=raiser)) == 1


#: `VAR=$(mktemp …)` — the whole right-hand side, deliberately. A trailing path
#: (`out=$(mktemp -d)/pt.elf`) keeps the file and drops the directory, so nothing
#: in the script can name the temp to remove it; that is a leak by construction
#: rather than by oversight, and it is what check.sh shipped for the store row.
MKTEMP_ASSIGN = re.compile(
    r'^(?:local\s+|declare\s+(?:-\w+\s+)*)?(?P<var>[A-Za-z_]\w*)='
    r'(?P<q>"?)\$\(\s*mktemp[^()]*\)(?P=q)$'
)

#: How a script may put a temp on a cleanup path. Two idioms, because there are
#: two: eight scripts hold one temp and remove it from their own EXIT trap, and
#: `check.sh` holds seven — bash keeps ONE EXIT trap, so a per-site one there
#: replaces the previous rather than joining it — and accumulates instead.
REMOVES = "rm "
ACCUMULATOR = "GATE_TMP"


def shell_scripts():
    """Every `*.sh` of the checkout, git's answer to what the tree is."""
    return sorted(p for p in gate_lines.tree_files(ROOT) if p.suffix == ".sh")


def code_lines(text):
    """Each logical line's CODE, stripped — what the shell runs, not what it quotes."""
    for _indent, body in gate_lines.logical_lines(text):
        yield gate_lines.split_at_comment(body)[0].strip()


def mktemp_sites(text):
    """(line, variable) per live `mktemp`; the variable is "" when none is bound."""
    for code in code_lines(text):
        if "mktemp" in code:
            found = MKTEMP_ASSIGN.match(code)
            yield code, (found["var"] if found else "")


#: A top-level shell function. Its body is the scope a temp shares with its
#: cleanup — see [`regions`].
FUNCTION = re.compile(r"^[A-Za-z_]\w*\(\)\s*\{\s*$")


def regions(text):
    """The script split into the scopes a cleanup may live in: each top-level
    function body, and everything outside them as one more.

    File scope was the first spelling, and it is too coarse in exactly the way
    that matters: `dir` names the temp of three different `check.sh` rows, so one
    row's registration satisfied the rule for all three. Measured — deleting the
    assurance row's `GATE_TMP+=("$dir")`, and again with it merely commented out,
    left `python -m pytest scripts -q` at rc 0 with 1789 passed both times, while
    the other four mutations below were caught. The two spellings the class is
    actually written in are the two that survived.
    """
    top, held, out = [], None, []
    for line in text.splitlines():
        if held is None and FUNCTION.match(line):
            held = []
        elif held is None:
            top.append(line)
        elif line == "}":
            out.append("\n".join(held))
            held = None
        else:
            held.append(line)
    # An unbalanced body is kept rather than dropped: losing it would take its
    # sites with it and read as a script with nothing to check.
    return out + ([] if held is None else ["\n".join(held)]) + ["\n".join(top)]


def registered(text, var):
    """Whether this SCOPE's code puts `$var` on a removal path.

    The two idioms differ in where the `rm` is: the trap carries it on the same
    line, the accumulator carries it once in the handler that drains the list —
    so requiring one on both reads every `GATE_TMP+=` line as a non-registration.
    Measured: that spelling reported all seven of check.sh's registered sites as
    loose, which is the rule failing in the loud direction and how it was found.
    """
    return any(
        f'"${var}"' in code
        and ((code.startswith("trap ") and REMOVES in code) or f"{ACCUMULATOR}+=(" in code)
        for code in code_lines(text)
    )


def drains_accumulator(text):
    """Whether anything in the script removes what the accumulator holds.

    The half `registered` gives up when it stops asking for an `rm` on the line:
    a list every temp is appended to and nothing reads leaks exactly as loudly as
    no list at all, and reads as covered.
    """
    lines = list(code_lines(text))
    return not any(ACCUMULATOR in code for code in lines) or any(
        ACCUMULATOR in code and REMOVES in code for code in lines
    )


def traps_exit(text):
    """Whether the script installs an EXIT trap at all.

    The registration rule cannot see this: deleting `trap gate_cleanup EXIT` from
    `check.sh` leaves every `GATE_TMP+=` line exactly where it was, and seven
    temps with a list nothing reads. Same hole one layer out as an unwired guard.
    """
    return any(code.startswith("trap ") and code.endswith(" EXIT") for code in code_lines(text))


def temp_makers():
    """(path, whole text, scope, sites in that scope) per scope that makes a temp."""
    out = []
    for rel in shell_scripts():
        text = (ROOT / rel).read_text()
        for scope in regions(text):
            sites = list(mktemp_sites(scope))
            if sites:
                out.append((rel, text, scope, sites))
    return out


def test_there_are_temp_making_scripts():
    """A glob that matches nothing loops over nothing and passes every case below."""
    found = {str(rel) for rel, _, _, _ in temp_makers()}
    assert len(found) >= 8, sorted(found)


def test_every_mktemp_names_the_path_it_makes():
    """A temp the script cannot name is one nothing can remove."""
    unnamed = [(str(rel), line) for rel, _, _, sites in temp_makers() for line, var in sites if not var]
    assert not unnamed, f"mktemp with no variable bound to it: {unnamed}"


def test_every_mktemp_is_registered_for_removal():
    """…and one it names but never removes is the same leak, spelled longer."""
    loose = [
        (str(rel), var)
        for rel, _text, scope, sites in temp_makers()
        for _line, var in sites
        if var and not registered(scope, var)
    ]
    assert not loose, f"temps on no cleanup path: {loose}"


def test_every_temp_making_script_traps_exit():
    """The rule above says a name is listed; this says something reads the list."""
    untrapped = [str(rel) for rel, text, _, _ in temp_makers() if not traps_exit(text)]
    assert not untrapped, f"makes a temp and traps no EXIT: {untrapped}"


def test_the_accumulator_is_drained():
    """…and this says what reads it removes something."""
    inert = [str(rel) for rel, text, _, _ in temp_makers() if not drains_accumulator(text)]
    assert not inert, f"accumulates temps and removes none: {inert}"


def test_a_quoted_mktemp_is_not_one():
    """The rules above are only worth having if a comment cannot trip or satisfy them.

    Both directions: prose about a leak must not be read as one, and prose about a
    trap must not be read as the cleanup. The comment-cut is `gate_lines`', so this
    pins the two shapes that reach these rules rather than re-testing the cut.
    """
    assert not list(mktemp_sites("# dir=$(mktemp -d) used to leak here\n"))
    assert not list(mktemp_sites("true # log=$(mktemp)\n"))
    assert list(mktemp_sites("log=$(mktemp)\n")) == [("log=$(mktemp)", "log")]
    assert not registered('# trap \'rm -rf "$d"\' EXIT\n', "d")
    assert not traps_exit("# trap cleanup EXIT\n")


def test_the_temp_rules_can_go_red():
    """The mutation table: one line per way the class has actually been spelled.

    Each was applied to `scripts/check.sh` and driven through `python -m pytest
    scripts -q` — the `pytest (gate scripts)` row verbatim, exit code taken with
    no pipe, and the failure read rather than the return code trusted. Unmutated:
    rc 0, 1789 passed. Then rc 1 each, at the rule named beside it — the last one
    at three of them, since the pre-fix file breaks three ways at once:

    * registration deleted / commented out → `..._is_registered_for_removal`
    * `out=$(mktemp -d)/pt.elf` → `..._names_the_path_it_makes`
    * `trap gate_cleanup EXIT` deleted → `..._traps_exit`
    * the handler's `rm` replaced by an `echo` → `..._accumulator_is_drained`
    * the whole pre-fix `check.sh` → the first three together

    The first two of those are the reason [`regions`] exists: with the rule
    file-scoped they were rc 0, 1789 passed, indistinguishable from the control.
    """
    trapped = 'd=$(mktemp -d)\ntrap \'rm -rf "$d"\' EXIT\n'
    assert list(mktemp_sites(trapped)) == [("d=$(mktemp -d)", "d")]
    assert registered(trapped, "d") and traps_exit(trapped)

    # 1. the site is not registered at all — check.sh, every row, before this fix
    assert not registered('d=$(mktemp -d)\ntrap \'rm -rf "$other"\' EXIT\n', "d")
    # 1b/1c. …and the two spellings that survived a file-scoped version of it: a
    # sibling scope registering the SAME variable name must not answer for this
    # one, whether the registration was deleted or only commented out.
    two_rows = (
        'a() {\n  dir=$(mktemp -d)\n}\n'
        'b() {\n  dir=$(mktemp -d)\n  GATE_TMP+=("$dir")\n}\n'
    )
    covered = [registered(scope, "dir") for scope in regions(two_rows) if list(mktemp_sites(scope))]
    assert covered == [False, True], covered
    commented = two_rows.replace('GATE_TMP+=', '# GATE_TMP+=')
    assert not any(registered(scope, "dir") for scope in regions(commented))
    # 2. the directory is never bound, so no name reaches it — the store row
    assert list(mktemp_sites("out=$(mktemp -d)/pt.elf\n")) == [("out=$(mktemp -d)/pt.elf", "")]
    # 3. registered on a line that removes nothing — a list nothing acts on
    assert not registered('d=$(mktemp -d)\ntrap \'echo "$d"\' EXIT\n', "d")
    # 4. accumulated, but the EXIT trap that drains the accumulator is gone
    assert not traps_exit('d=$(mktemp -d)\nGATE_TMP+=("$d")\n')
    # 5. a trap on a signal is not the one that runs when the script simply ends
    assert not traps_exit('trap \'rm -rf "$d"\' INT\n')
    # 6. accumulated and trapped, but the handler removes nothing
    assert registered('GATE_TMP+=("$d")\n', "d")
    assert not drains_accumulator('GATE_TMP+=("$d")\ntrap \'echo "${GATE_TMP[@]}"\' EXIT\n')
    assert drains_accumulator('GATE_TMP+=("$d")\nrm -rf -- "${GATE_TMP[@]}"\n')


#: A quoted span, single or double. Blanked before a call is looked for, because
#: `echo "third_party (fido): pytest exit $tp"` is prose the shell prints and
#: reading it as an invocation would demand a `--basetemp` on an `echo`. It is
#: also what stops `run "pytest (gate scripts)" …` matching on its own label, and
#: `GATE_PYTEST_TMP=".../rs-key/pytest"` on the name of its own directory.
QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'")

#: A live pytest invocation, at a command position rather than anywhere in the
#: line. Spelled to cover the bare `pytest foo -q` as well as the `python -m`
#: form the tree uses: a rule that only knew the long one would be satisfied by
#: writing the short one, which is the hole this file exists to catch.
PYTEST_CALL = re.compile(r"(?:^|[\s;|&(])pytest(?:\s|$)")

#: The pin that bounds it, `=` form only. `--basetemp <path>` leaves a bare path
#: in the row, and `roster_gate.collects` reads every word of a pytest row as
#: something it collects — a basetemp named `scripts` would answer for the row
#: that collects `scripts/`.
BASETEMP = re.compile(r"--basetemp=(?P<path>\S+)")


def unquoted(code):
    """`code` with quoted spans blanked — what it runs, not what it says."""
    return QUOTED.sub('""', code)


def pytest_calls():
    """(path, code line) per live pytest invocation in a tracked `*.sh`."""
    for rel in shell_scripts():
        for code in code_lines((ROOT / rel).read_text()):
            if PYTEST_CALL.search(unquoted(code)):
                yield str(rel), code


def pinned_at(code):
    """The `--basetemp` this line pins, quotes stripped, or "" if it pins none."""
    found = BASETEMP.search(code)
    return found["path"].strip("\"'") if found else ""


def test_there_are_pytest_rows():
    """A pattern that matches nothing loops over nothing and passes both rules."""
    found = list(pytest_calls())
    assert len(found) >= 3, found


def test_every_pytest_row_pins_a_basetemp():
    """An unpinned row leaks its whole `tmp_path` tree, once per run, for good.

    `--basetemp` is not the retention the docs describe — pytest removes the
    directory and recreates it at startup, so the row holds one run instead of
    every run. What this cannot say is WHERE: the path is a variable by the time
    it reaches here. That half is covered where it bites — a base inside the
    checkout lets `git rev-parse` answer from RS-Key's own .git, and
    `test_verdict_gate.py`'s "git cannot answer here" case fails on it (measured:
    `--basetemp=target/pytest/scripts` → 1788 of 1789, at that assertion).
    """
    loose = [(rel, code) for rel, code in pytest_calls() if not pinned_at(code)]
    assert not loose, f"pytest rows with no --basetemp: {loose}"


def test_no_two_pytest_rows_share_a_basetemp():
    """…and two rows pinned to one directory are a race, not a saving.

    The startup wipe is `rm -rf` over the whole path, so the second row through
    a shared base destroys the first row's output — silently, since it then runs
    green on an empty directory. Copying a row and forgetting its leaf is the way
    that arrives, and the copy is the half nobody re-reads. Compared as written,
    quotes off: two spellings of one path read as two, which errs toward letting
    a collision through rather than inventing one.
    """
    pinned = [pinned_at(code) for _rel, code in pytest_calls()]
    shared = sorted({p for p in pinned if p and pinned.count(p) > 1})
    assert not shared, f"pytest rows sharing one --basetemp: {shared}"


def test_a_quoted_pytest_is_not_a_call():
    """Both directions, the way the `mktemp` rules pin theirs.

    Prose about pytest must not be read as a row that owes a pin, and a row must
    not be excused by prose. One line in the tree needs the quote-cut and only
    one: `usbip-guest.sh` prints `pytest exit $tp`, where the word follows a
    space *inside* a string and matched. `emu-suites.sh`'s `tp_note="pytest exit
    $tp"` and `check.sh`'s own `…/rs-key/pytest` never did — [`PYTEST_CALL`] asks
    for a command position, so a `"` and a `/` in front of the word already
    answered for those two. Measured, both ways, before writing this down.
    """
    assert not PYTEST_CALL.search(unquoted('echo "third_party (fido): pytest exit $tp"'))
    assert not PYTEST_CALL.search(unquoted('GATE_PYTEST_TMP="${X:-$HOME/.cache}/rs-key/pytest"'))
    assert PYTEST_CALL.search(unquoted('run "pytest (x)" python -m pytest scripts -q'))
    assert PYTEST_CALL.search(unquoted("pytest scripts -q"))
    # The comment-cut is `code_lines`', so this pins that a commented-out row
    # neither owes a pin nor answers for one — the way `NAMED` learned to.
    assert not [c for c in code_lines("# python -m pytest scripts -q\n") if PYTEST_CALL.search(unquoted(c))]
    assert not [c for c in code_lines("true # pytest tools/rsk -q\n") if PYTEST_CALL.search(unquoted(c))]


def test_the_pytest_temp_rules_can_go_red():
    """The mutation table: one line per way the pin has been got wrong.

    Each was applied to `scripts/check.sh` and driven through the `pytest (gate
    scripts)` row, exit code taken with no pipe and the failing assertion read
    rather than the return code trusted. Unmutated: rc 0, 1794 passed.

    * the gate row's `--basetemp` deleted → `..._pins_a_basetemp`, rc 1
    * the `tools/rsk` row's deleted instead → the same rule, rc 1, other row
    * `tools/rsk` re-pinned onto the `gate` leaf → `..._share_a_basetemp`, rc 1
    * all three deleted → `..._pins_a_basetemp` names all three, rc 1
    * …and rewritten as a bare `pytest foo -q` → the same rule again, rc 1
    * every row's `pytest` renamed away → `..._there_are_pytest_rows`, rc 1
    * [`PYTEST_CALL`] narrowed to `python -m` while the rows say `pytest` → rc 1,
      but at `..._there_are_pytest_rows` and at this table, NOT at the pin rule

    The last one is the interesting reading and it corrected what was written
    here first. Narrowing the pattern does not leave the pin rule reporting a
    green tree — it leaves it with nothing to report on, and the sentinel above
    is what says so. That the three cases land at three different assertions is
    the point: with exactly three rows and a floor of three, one row going
    invisible is still a red, and it stops being one the moment a fourth row is
    added. Which is the argument for the pattern covering both spellings rather
    than for the floor being load-bearing.
    """
    pinned = 'run "x" python -m pytest scripts -q --basetemp="$T/scripts"'
    assert PYTEST_CALL.search(unquoted(pinned)) and pinned_at(pinned) == "$T/scripts"
    # 1. no pin at all — every row, before this fix
    assert not pinned_at('run "x" python -m pytest scripts -q')
    # 2. the bare spelling, which a `python -m`-only pattern would not see
    assert PYTEST_CALL.search(unquoted("pytest tools/rsk -q"))
    # 3. two rows on one leaf: the second wipes the first at startup
    rows = ['python -m pytest scripts -q --basetemp="$T/a"', "pytest tools/rsk -q --basetemp=$T/a"]
    seen = [pinned_at(r) for r in rows]
    assert len(set(seen)) == 1, seen
    # 4. …and the quoting must not be what makes two paths look different
    assert pinned_at('x --basetemp="$T/a"') == pinned_at("x --basetemp=$T/a")


# --- the third fact about the set: a case that is collected and does not RUN ---

#: `pytest -q` prints a grey `s` for a skipped case and exits 0, `check.sh` reads
#: that exit code and nothing else, and [`CASE`] above counts cases as WRITTEN by
#: design. So a table neutralised to skips satisfies every rule in this file —
#: the same shape as emptying one, which is measured two rules up. Measured on
#: `test_elf_gate.py`, 7 of whose 13 cases were `skipif`'d on a built firmware —
#: a checkout with no `target/` ran the row at `6 passed, 7 skipped`, rc 0.
#:
#: `scripts/conftest.py` is the budget, and it is driven here through a real
#: pytest rather than by calling its function: the hook has to move the EXIT CODE
#: to reach a `run` row, and a guard whose wiring nothing exercises is one that
#: can be deleted with the suite still green.
BUDGET = pathlib.Path("scripts/conftest.py")
SKIPPING = "import pytest\n\n\ndef test_x():\n    pytest.skip('no subject here')\n"
PASSING = "def test_x():\n    assert True\n"


def suite(tmp_path, body):
    """One case under the gate suite's own conftest, run the way `check.sh` runs
    it. Returns (exit code, output) — the code taken from the process, not from
    a parsed line of its output."""
    room = tmp_path / "suite"
    room.mkdir()
    shutil.copy(HERE / "conftest.py", room / "conftest.py")
    (room / "test_one.py").write_text(body)
    done = subprocess.run(
        [sys.executable, "-m", "pytest", str(room), "-q", "--basetemp", str(tmp_path / "bt")],
        capture_output=True,
        text=True,
    )
    return done.returncode, done.stdout + done.stderr


def test_the_gate_suite_carries_a_skip_budget():
    """A roster of one, for the same reason as `NAMED`: nothing else in the tree
    names this file, so without this case deleting it is a green edit."""
    assert (ROOT / BUDGET).is_file(), BUDGET
    for hook in ("pytest_runtest_logreport", "pytest_sessionfinish", "verdict"):
        assert hasattr(conftest, hook), hook


def test_a_skipped_case_reddens_the_row(tmp_path):
    """The direction that matters: the row must not read green over a case that
    asserted nothing."""
    code, output = suite(tmp_path, SKIPPING)
    assert code != 0, output
    assert "1 skipped case(s) against a budget of 0" in output, output


def test_the_same_suite_without_the_skip_stays_green(tmp_path):
    """The CONTROL. Without it the case above is satisfied by a budget that
    reddens every run, which is a gate nobody keeps."""
    code, output = suite(tmp_path, PASSING)
    assert code == 0, output
    assert "skipped case(s)" not in output, output


def test_the_budget_is_a_parameter_and_not_a_global():
    """Both numbers are arguments, so a case drives both arms without patching
    down the value the session it is running in is judged by — and the shipped
    value is asserted here rather than read from wherever the caller passes it."""
    assert conftest.SKIP_BUDGET == 0
    assert conftest.verdict(0, 0) is None
    assert conftest.verdict(1, 1) is None
    assert "1 skipped case(s) against a budget of 0" in conftest.verdict(1, 0)


def test_the_skip_budget_can_go_red():
    """The mutation table: one edit per arm to a copy of `scripts/conftest.py`,
    driven over the one-case suites above through a real pytest, exit code taken
    from the process. Unmutated: rc 0 on `PASSING`, rc 1 on `SKIPPING`, rc 0 on
    an `xfail`ing one.

    * `pytest_sessionfinish` deleted → `SKIPPING` back to **rc 0**, and the
      terminal line still printed: the message is not the guard, the exit code is
    * `pytest_runtest_logreport` deleted → nothing counts, `SKIPPING` **rc 0**
    * `verdict`'s `<=` to `<` → the CONTROL falls, `PASSING` **rc 1** at 0 skips,
      which is the arm that says the budget is not simply "always red"
    * `SKIP_BUDGET` 0 → 1 → `SKIPPING` **rc 0**: the number is load-bearing, so
      it is not a place to absorb a case that stopped running
    * the `wasxfail` cut removed → an `xfail` case counts as a skip, **rc 1** on
      a suite with nothing wrong with it (the over-reporting direction, which is
      why the cut is there)

    The third arm is the one worth reading: a guard that cannot go green is
    indistinguishable from one nobody trusts, and it is the arm the first draft
    of this table did not have.
    """
    assert conftest.verdict(1, 0)
    assert conftest.verdict(0, 0) is None


# --- and the leak neither of those rules can reach: the dev shell's own TMPDIR --

#: The dev shell. `nix develop` hands every invocation a fresh
#: `/tmp/nix-shell.XXXXXX` and never removes it — 159 had accumulated here, each
#: holding whatever a hand run left behind. A `trap … EXIT` in the `shellHook`
#: does NOT fix it, which is measured rather than argued: `nix develop -c` runs
#: the command in a child, `trap -p EXIT` inside it prints nothing, and the
#: directory survives with its contents. Moving TMPDIR is the mechanism that
#: works, and it is invisible to every rule above because no `.sh` file carries it.
DEVSHELL = pathlib.Path("nix/devshells.nix")
#: The cache root, read out of `check.sh` rather than written here a second time:
#: the gate's pytest bases already live under it, and a pin that drifted away
#: from them would leave two temp roots where the file claims one.
CACHE_ROOT = re.compile(r"\$\{XDG_CACHE_HOME:-\$HOME/\.cache\}/rs-key")
#: `export TMPDIR=` to somewhere. The value is captured so the rule can ask WHERE,
#: which is the half the pytest rules explicitly cannot ask.
TMPDIR_EXPORT = re.compile(r'^\s*export TMPDIR="(?P<path>[^"]+)"', re.M)
#: An age-bounded sweep of it. A relocated leak is still a leak; 7 days is longer
#: than any run here by orders of magnitude, so the bound cannot reach a live
#: invocation even with two shells open at once.
TMPDIR_SWEEP = re.compile(r'find "\$TMPDIR".*-mtime \+(?P<days>\d+).*rm -rf')


def devshell_text():
    return (ROOT / DEVSHELL).read_text()


def test_the_cache_root_is_one_root():
    """`check.sh` names it and the dev shell must name the same one."""
    assert CACHE_ROOT.search((ROOT / "scripts/check.sh").read_text())
    assert CACHE_ROOT.search(devshell_text())


def test_the_dev_shell_moves_tmpdir_off_the_directory_nothing_deletes():
    """Without this, a bare `nix develop -c …` leaks into a dir nix never removes.

    `check.sh` traps its seven `mktemp` sites and its pytest rows pin
    `--basetemp`, so the gate is clean; a hand run is not, and that is the whole
    residue of the class that filled this machine's disk to zero bytes.
    """
    found = TMPDIR_EXPORT.search(devshell_text())
    assert found, f"{DEVSHELL} exports no TMPDIR"
    assert CACHE_ROOT.search(found["path"]), (
        f"{DEVSHELL} points TMPDIR at {found['path']!r}, not under the cache root"
        " check.sh already owns")


def test_the_relocated_tmpdir_is_bounded():
    """A leak that moved is not a leak that stopped."""
    swept = TMPDIR_SWEEP.search(devshell_text())
    assert swept, f"{DEVSHELL} moves TMPDIR and never bounds it"
    assert int(swept["days"]) >= 1, "a same-day sweep can reach a live invocation"


def test_the_tmpdir_rules_can_go_red():
    """The mutation table, each arm applied to `nix/devshells.nix` and driven
    through the `pytest (gate scripts)` row with the exit code taken unpiped.

    * the `export TMPDIR=` line deleted → `..._moves_tmpdir_off_…`, rc 1
    * repointed at `/tmp/rs-key` → the same rule, on the path rather than absence
    * the `find … -mtime` sweep deleted → `..._is_bounded`, rc 1
    * the sweep left at `-mtime +0` → `..._is_bounded`, at the days assertion
    * the cache-root spelling changed on ONE side → `..._is_one_root`, rc 1
    """
    assert not TMPDIR_EXPORT.search('export TMP="$X"\n')
    moved = TMPDIR_EXPORT.search('  export TMPDIR="/tmp/rs-key"\n')
    assert moved and not CACHE_ROOT.search(moved["path"])
    assert not TMPDIR_SWEEP.search('find "$TMPDIR" -mindepth 1 -exec rm -rf {} +\n')
    zero = TMPDIR_SWEEP.search('find "$TMPDIR" -mindepth 1 -mtime +0 -exec rm -rf {} +\n')
    assert zero and int(zero["days"]) == 0


# --- the pytest base is per checkout, not per user ------------------------------

#: `check.sh`'s own assignment of the pytest base, and the `set` line it runs
#: under. The cases below EVALUATE both in a stand-in checkout.
PYTEST_BASE = re.compile(r"^GATE_PYTEST_TMP=.*$", re.M)
SHELL_OPTIONS = re.compile(r"^set -.*$", re.M)

#: A session that holds a file in its `tmp_path` until told to let go. Indented
#: here and dedented at use, so [`CASE`] does not count its `def test_` as a case.
HOLDER = textwrap.dedent("""\
    import os, pathlib, time

    def test_hold(tmp_path):
        held = tmp_path / "held"
        held.write_text("x")
        pathlib.Path(os.environ["HOLD_READY"]).write_text(str(held))
        go = pathlib.Path(os.environ["HOLD_GO"])
        for _ in range(1200):
            if go.exists():
                break
            time.sleep(0.05)
        assert held.exists(), "the base was wiped under a running session"
    """)
#: …and one that only starts, which is when pytest wipes a pinned base.
STARTER = "def test_start(tmp_path):\n    (tmp_path / 'x').write_text('x')\n"


def no_git_env(**extra):
    """The environment with git's own variables dropped, so no caller's repository leaks in."""
    return {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")}, **extra}


def two_checkouts(tmp_path):
    """A repository and a worktree of it, with one basename between them: the shape
    of the collision, which was two checkouts of ONE repository."""
    one, two = tmp_path.resolve() / "one" / "RS-Key", tmp_path.resolve() / "two" / "RS-Key"
    one.mkdir(parents=True)
    two.parent.mkdir(parents=True)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
           "-c", "core.hooksPath=/dev/null", "-C", str(one)]
    for args in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "t"],
                 ["worktree", "add", "-q", "--detach", str(two)]):
        subprocess.run(git + args, check=True, env=no_git_env(), capture_output=True)
    return one, two


def a_bin_without_git(tmp_path):
    """A PATH with the one tool the assignment needs besides git."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if not (bin_dir / "cut").exists():
        (bin_dir / "cut").symlink_to(shutil.which("cut"))
    return str(bin_dir)


def gate_pytest_base(checkout, cache, line=None, options=None, path=None):
    """Evaluate `check.sh`'s assignment, under its `set` line, standing in `checkout`."""
    text = check_sh()
    if line is None:
        # Exactly one: bash keeps the LAST of two, so a stale line below the fixed
        # one would put the gate back on a shared base with the first still read here.
        found = PYTEST_BASE.findall(text)
        assert len(found) == 1, f"check.sh assigns GATE_PYTEST_TMP {len(found)} times: {found}"
        line = found[0]
    options = SHELL_OPTIONS.search(text)[0] if options is None else options
    env = no_git_env(XDG_CACHE_HOME=str(cache), **({"PATH": path} if path else {}))
    return subprocess.run(
        [shutil.which("bash"), "-c", f'{options}\n{line}\nprintf %s "$GATE_PYTEST_TMP"'],
        cwd=checkout, env=env, capture_output=True, text=True,
    )


def base_of(checkout, cache, line=None):
    done = gate_pytest_base(checkout, cache, line)
    assert done.returncode == 0, done.stderr
    return pathlib.Path(done.stdout)


def test_two_checkouts_get_two_pytest_bases(tmp_path):
    """The base was `…/rs-key/pytest` for every checkout of this user, and pytest
    removes a pinned base when a session starts. Each base must still sit under the
    cache root, which is what keeps it out of the checkout it was moved out of."""
    cache = tmp_path.resolve() / "cache"
    bases = [base_of(c, cache) for c in two_checkouts(tmp_path)]
    assert bases[0] != bases[1], bases
    for base in bases:
        assert base.is_relative_to(cache / "rs-key" / "pytest"), base


def test_every_gate_pytest_row_pins_under_the_checkout_s_base():
    """The assignment is half of it: a row that spells its own path pins wherever
    that says, per user again, and the cases around this one never see it."""
    pinned = [pinned_at(code) for rel, code in pytest_calls() if rel == "scripts/check.sh"]
    assert pinned, "no pytest row in scripts/check.sh"
    stray = [p for p in pinned if not p.startswith("$GATE_PYTEST_TMP/")]
    assert not stray, f"check.sh pytest rows pinned outside $GATE_PYTEST_TMP: {stray}"


def test_a_gate_in_one_checkout_does_not_wipe_another_s_pytest_base(tmp_path):
    """On 2026-09-16 two sessions ran the full gate in two checkouts of this
    repository at once, both gate rows pinned to `~/.cache/rs-key/pytest/gate`,
    where the later start removes the earlier run's tree. Here each session is
    pinned where `check.sh` pins its checkout's gate row, and the first holds a file
    while the second starts."""
    cache = tmp_path.resolve() / "cache"
    first, second = (base_of(c, cache) / "gate" for c in two_checkouts(tmp_path))
    for leaf in (first, second):
        # A line that ignored XDG_CACHE_HOME would aim these at a live gate's base.
        assert leaf.is_relative_to(tmp_path.resolve()), f"refusing to pin {leaf}"
        # `check.sh`'s own `mkdir -p` after the assignment: pytest makes only the leaf.
        leaf.parent.mkdir(parents=True, exist_ok=True)
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "pytest.ini").write_text("[pytest]\n")
    (probe / "test_hold.py").write_text(HOLDER)
    (probe / "test_start.py").write_text(STARTER)
    ready, go = tmp_path / "ready", tmp_path / "go"
    session = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    env = no_git_env(HOLD_READY=str(ready), HOLD_GO=str(go))
    holder = subprocess.Popen(session + [f"--basetemp={first}", "test_hold.py"],
                              cwd=probe, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(1200):
            if ready.exists() or holder.poll() is not None:
                break
            time.sleep(0.05)
        assert ready.exists(), holder.communicate()[0]
        started = subprocess.run(session + [f"--basetemp={second}", "test_start.py"],
                                 cwd=probe, env=env, capture_output=True, text=True)
        assert started.returncode == 0, started.stdout + started.stderr
    finally:
        go.write_text("go")
        out = holder.communicate(timeout=120)[0]
    assert holder.returncode == 0, out


def test_a_base_that_cannot_be_keyed_stops_the_gate(tmp_path):
    """With no git to key it the assignment must stop the gate, not hand back
    `…/rs-key/pytest/`, which is the shared base again, silently. `pipefail` in
    `check.sh`'s `set` line is what makes the failing git the assignment's status."""
    checkout = two_checkouts(tmp_path)[0]
    done = gate_pytest_base(checkout, tmp_path.resolve() / "cache", path=a_bin_without_git(tmp_path))
    assert done.returncode != 0 and not done.stdout, (done.returncode, done.stdout)


def test_the_per_checkout_base_can_go_red(tmp_path):
    """The mutation table, each arm run through the same helpers the cases above
    use. Driven through the `pytest (gate scripts)` row as well, exit code taken
    with no pipe, for the first arm.

    * per user again, the line as it stood → both behavioural cases
    * keyed by basename → the repository and its worktree share a base
    * keyed by the common git dir → the same, the way a per-repository fix would
    * under the checkout's own `target/` → outside the cache root
    * a row spelling its own per-user path → the row rule
    * a second assignment below the first → every case that reads the line
    * `pipefail` dropped from the `set` line → the keyless fallback, at rc 0
    """
    cache = tmp_path.resolve() / "cache"
    checkouts = two_checkouts(tmp_path)
    root = cache / "rs-key" / "pytest"
    arms = (
        ('GATE_PYTEST_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest"', True, True),
        ('GATE_PYTEST_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest/$(basename "$PWD")"', True, True),
        ('GATE_PYTEST_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest/'
         '$(cd "$(git rev-parse --git-common-dir)" && pwd -P | git hash-object --stdin | cut -c1-12)"', True, True),
        ('GATE_PYTEST_TMP="$PWD/target/pytest"', False, False),
    )
    for line, shared, under_root in arms:
        bases = [base_of(c, cache, line) for c in checkouts]
        assert (bases[0] == bases[1]) is shared, (line, bases)
        assert bases[0].is_relative_to(root) is under_root, (line, bases)
    row = 'run "x" python -m pytest scripts -q --basetemp="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest/gate"'
    assert not pinned_at(row).startswith("$GATE_PYTEST_TMP/")
    assert len(PYTEST_BASE.findall('GATE_PYTEST_TMP="$A/x"\nrun x\nGATE_PYTEST_TMP="$HOME/x"\n')) == 2
    # The keyed spelling itself, not the live line: an arm about `set` must not
    # also fall whenever the assignment is the thing a mutation changed.
    keyed = ('GATE_PYTEST_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest/'
             '$(git rev-parse --show-toplevel | git hash-object --stdin | cut -c1-12)"')
    keyless = gate_pytest_base(checkouts[0], cache, keyed, "set -eu", a_bin_without_git(tmp_path))
    assert keyless.returncode == 0 and keyless.stdout.endswith("/rs-key/pytest/"), keyless
