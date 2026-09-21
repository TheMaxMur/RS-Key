# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `model_exception_gate.py` was verified against, kept.

Six guards this repo shipped before this one had a hole of the same family, so
the table below breaks the real defect shape in a fixture checkout, one at a
time, and asserts the MESSAGE rather than a count — a red for the wrong reason
proves as little as a green.

Two of the cases are not fixtures. `test_the_criterion_defect_reddens_the_row`
deletes `\\/ a = Oath` from a COPY of this checkout's own `RSKeyAppletSeams.tla`
— the exact clause stage 6's exit criterion is about, the one whose deletion
changed the input of no gate before this row existed — and drives the gate as a
PROCESS, because `check.sh` reads an exit code and not a list of findings.
`test_a_narrowing_over_a_state_variable_reddens_the_row` is the hole this table
found in the guard while it was being written: with the subject rule scoped to
bound names, a constructed `(sel = Piv \\/ sel = Pgp)` passed at rc 0. Closing it
turned up two real narrowings in `RSKeyAppletPolicies` that nothing had a row for.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own registry
passes, and the last three cases are about the derivation rather than the ledger
— a control that moves the model without changing a narrowing, and the two
shapes an empty derivation takes.
"""

import pathlib
import shutil
import subprocess
import sys

import pytest

import gate_lines
import model_exception_gate as gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A fixture module with one of each shape: a narrowing operand joined by `\\/`, a
#: total dispatch that must NOT be collected, a set literal that omits what its
#: sibling has, and a `CASE` that answers for part of its domain.
MODEL = '''\
--------------------------- MODULE RSKeyFixture ---------------------------
EXTENDS Naturals

CONSTANTS BugFixtureSwitch

Piv  == "piv"
Oath == "oath"
Refs == {"a", "b", "c"}
Small == {"a", "b"}

Dispatch(x) == IF x = Piv THEN 1 ELSE 2

Narrow(x) == IF BugFixtureSwitch \\/ x = Oath THEN 1 ELSE 2

Recover(r) ==
    CASE r = "a" -> {"b"}
      [] OTHER   -> {}
=============================================================================
'''

CFG = """\
SPECIFICATION Spec
CONSTANTS
    BugFixtureSwitch = TRUE
"""

#: The registry that disposes of every narrowing the fixture has, and of nothing
#: else. Written out rather than derived so a case can break one field at a time.
LEDGER = """\
[[exception]]
id = "MX-FIX-001"
module = "RSKeyFixture.tla"
line = 13
shape = "clause"
site = "Narrow"
clause = "x = Oath"
kind = "narrowing"
production = "OATH re-locks where the other applets keep."
why = "the recorded asymmetry."
mutant = "FixMut_BugFixtureSwitch.cfg"

[[exception]]
id = "MX-FIX-002"
module = "RSKeyFixture.tla"
line = 9
shape = "set"
site = "Small"
clause = "Small"
against = "Refs"
omits = ["c"]
kind = "narrowing"
production = "the third reference has no counter."
why = "out of scope for this module."
mutant = "owes"
owed = "FixSolo_BugThirdRefCounts.cfg"

[[exception]]
id = "MX-FIX-003"
module = "RSKeyFixture.tla"
line = 15
shape = "case"
site = "Recover"
clause = "Recover"
against = "Refs"
omits = ["b", "c"]
kind = "narrowing"
production = "blocked is terminal for the other two."
why = "the reset models cover them."
mutant = "owes"
owed = "FixSolo_BugTerminalRefRecovers.cfg"

[[exception]]
id = "MX-FIX-004"
module = "RSKeyFixture.tla"
line = 15
shape = "case"
site = "Recover"
clause = "Recover"
against = "Small"
omits = ["b"]
kind = "narrowing"
production = "the second reference is not a recovery target."
why = "measured against every containing set, not the smallest."
mutant = "owes"
owed = "FixSolo_BugSecondRefRecovers.cfg"
"""


TERMINATOR = "=============================================================================\n"


def plus(*bodies):
    """`MODEL` with definitions APPENDED, so no existing line moves.

    Inserting in the middle shifts every citation below it, and a case about one
    rule then fails on every other row's line number — a red for the wrong
    reason, which is what this file exists to refuse.
    """
    return MODEL.replace(TERMINATOR, "\n\n".join(bodies) + "\n" + TERMINATOR)


def build(tmp_path, model=MODEL, ledger=LEDGER):
    """A checkout with `formal/`, `assurance/` and nothing else the gate reads."""
    (tmp_path / "formal").mkdir(parents=True, exist_ok=True)
    (tmp_path / "assurance").mkdir(parents=True, exist_ok=True)
    (tmp_path / "formal" / "RSKeyFixture.tla").write_text(model)
    (tmp_path / "formal" / "FixMut_BugFixtureSwitch.cfg").write_text(CFG)
    (tmp_path / "assurance" / "model_exceptions.toml").write_text(ledger)
    (tmp_path / "assurance" / "abstractions.toml").write_text(
        '[[abstraction]]\nid = "NAR-FIXTURE"\n'
    )
    return tmp_path


def problems(tmp_path, model=MODEL, ledger=LEDGER, floor=4):
    """The findings, with the roster floor lowered to the fixture's own size."""
    build(tmp_path, model, ledger)
    was = gate.FLOOR_SITES
    gate.FLOOR_SITES = floor
    try:
        return gate.audit(tmp_path)
    finally:
        gate.FLOOR_SITES = was


def says(found, needle):
    return [p for p in found if needle in p]


# ---- the clean arm, both ways ------------------------------------------------


def test_the_fixture_is_green(tmp_path):
    """A table whose baseline is red reports its own fixture, not the defect."""
    assert problems(tmp_path) == []


def test_this_checkout_is_green():
    """And the real registry, which is what the row actually runs over."""
    assert gate.audit(ROOT) == []


def test_the_derivation_finds_every_shape(tmp_path):
    """The dispatch is NOT collected, and each of the three shapes is."""
    build(tmp_path)
    found = gate.exceptions(tmp_path)
    assert {(s["site"], s["shape"]) for s in found} == {
        ("Narrow", "clause"),
        ("Small", "set"),
        ("Recover", "case"),
    }, found


# ---- the criterion's own defect ----------------------------------------------


def test_the_criterion_defect_reddens_the_row(tmp_path):
    """`\\/ a = Oath` deleted from a copy of THIS tree, driven as `check.sh` drives it.

    Not the fixture: the clause stage 6 names, in the module it lives in, run
    through `main()` so the assertion is on the PROCESS exit code. Fourteen of
    thirty guards here could not go red because their tables drove `audit()` and
    nothing joined that to what the row reads.
    """
    scratch = tmp_path / "tree"
    (scratch / "scripts").mkdir(parents=True)
    shutil.copytree(ROOT / "formal", scratch / "formal")
    (scratch / "assurance").mkdir()
    for name in ("model_exceptions.toml", "abstractions.toml"):
        shutil.copy(ROOT / "assurance" / name, scratch / "assurance" / name)
    shutil.copy(ROOT / "scripts" / "model_exception_gate.py", scratch / "scripts")

    guard = scratch / "scripts" / "model_exception_gate.py"
    clean = subprocess.run([sys.executable, str(guard)], capture_output=True, text=True)
    assert clean.returncode == 0, clean.stderr

    seams = scratch / "formal" / "RSKeyAppletSeams.tla"
    text = seams.read_text()
    assert "IF BugReselectResetsStatus \\/ a = Oath" in text
    seams.write_text(text.replace("IF BugReselectResetsStatus \\/ a = Oath", "IF BugReselectResetsStatus"))

    red = subprocess.run([sys.executable, str(guard)], capture_output=True, text=True)
    assert red.returncode == 1, red.stdout
    assert "RSKeyAppletSeams.tla:237 `a = Oath`" in red.stderr, red.stderr
    assert "no longer narrows" in red.stderr


def test_a_narrowing_over_a_state_variable_reddens_the_row(tmp_path):
    """The hole this table found in the guard, kept as the case that closes it.

    With the subject rule scoped to bound names, a guard enumerating part of a
    domain over a state VARIABLE was invisible: a constructed
    `(sel = Piv \\/ sel = Pgp)` in an action that had neither passed at rc 0.
    """
    found = problems(
        tmp_path, model=plus("Widened == /\\ (sel = Piv \\/ sel = Oath)\n           /\\ z' = 1")
    )
    assert says(found, "narrows `sel = Piv`"), found
    assert says(found, "does not dispose of it"), found


# ---- the two directions of the ledger rule -----------------------------------


def test_an_unregistered_narrowing_reddens_the_row(tmp_path):
    """A new exception arrives and nobody decided it."""
    found = problems(
        tmp_path, model=plus("Second(y) == IF y = Piv \\/ BugFixtureSwitch THEN 1 ELSE 2")
    )
    assert says(found, "narrows `y = Piv`"), found
    assert says(found, "does not dispose of it"), found


def test_a_row_whose_clause_is_gone_reddens_the_row(tmp_path):
    found = problems(
        tmp_path,
        model=MODEL.replace("BugFixtureSwitch \\/ x = Oath", "BugFixtureSwitch"),
        floor=3,
    )
    assert says(found, "which the model no longer narrows"), found


def test_a_clause_that_only_moved_says_where_it_went(tmp_path):
    """A shifted citation and a deleted clause are different findings.

    Reporting the second for the first sends the reader to re-decide a narrowing
    that has not changed — `citation_gate.py` and `deleter_gate.py` both learned
    to say where a line went, and a message that cannot is why.
    """
    found = problems(tmp_path, model=MODEL.replace("EXTENDS Naturals", "EXTENDS Naturals\n"))
    assert says(found, "it is at :14 now"), found


def test_an_edited_clause_is_not_an_unrelated_diff(tmp_path):
    """`a = Oath` quietly becoming `a = Piv` must not pass as movement."""
    found = problems(tmp_path, model=MODEL.replace("\\/ x = Oath", "\\/ x = Piv"))
    assert says(found, "narrows `x = Piv`"), found
    assert says(found, "`x = Oath`, which the model no longer narrows"), found


def test_a_set_that_gains_a_member_reddens_its_row(tmp_path):
    """The derived half of a `set` row is compared, not trusted."""
    found = problems(
        tmp_path, model=MODEL.replace('Refs == {"a", "b", "c"}', 'Refs == {"a", "b", "c", "d"}')
    )
    assert says(found, "omits derives as"), found
    assert len(gate.exceptions(tmp_path)) == 4, "the mutation must not shrink the roster"


def test_a_case_is_measured_against_every_superset(tmp_path):
    """Dropping either `against` row is a finding, so no heuristic picks one."""
    found = problems(
        tmp_path,
        ledger=LEDGER[: LEDGER.index('[[exception]]\nid = "MX-FIX-004"')],
    )
    assert says(found, "`RecoveryOf`") == [], found
    assert says(found, "narrows `Recover` against `Small`"), found


# ---- the debt half -----------------------------------------------------------


def test_a_claimed_mutant_that_is_not_a_file_reddens_the_row(tmp_path):
    found = problems(
        tmp_path, ledger=LEDGER.replace("FixMut_BugFixtureSwitch.cfg", "FixMut_Absent.cfg")
    )
    assert says(found, "which is not a file in formal"), found


def test_a_mutant_from_another_clause_cannot_be_claimed(tmp_path):
    """The pairing that makes a claim falsifiable rather than decorative.

    The configuration exists and switches a real constant; what it does not do is
    switch one the claiming definition reads. Without this rule any row could
    have named any `.cfg` in the tree and read as carried.
    """
    build(tmp_path)
    (tmp_path / "formal" / "FixMut_BugElsewhere.cfg").write_text(
        "CONSTANTS\n    BugElsewhere = TRUE\n"
    )
    was = gate.FLOOR_SITES
    gate.FLOOR_SITES = 4
    try:
        (tmp_path / "assurance" / "model_exceptions.toml").write_text(
            LEDGER.replace("FixMut_BugFixtureSwitch.cfg", "FixMut_BugElsewhere.cfg")
        )
        found = gate.audit(tmp_path)
    finally:
        gate.FLOOR_SITES = was
    assert says(found, "is not this row's"), found


def test_a_paid_debt_still_recorded_as_owed_reddens_the_row(tmp_path):
    """The second direction of the ledger, and the one a debt column never has.

    `owed` names a configuration that must NOT exist. Someone writes it, the
    narrowing gains the mutant it was owed — and the row still says it is owed,
    which is a ledger describing a tree it has stopped being about.
    """
    build(tmp_path)
    (tmp_path / "formal" / "FixSolo_BugThirdRefCounts.cfg").write_text(CFG)
    was = gate.FLOOR_SITES
    gate.FLOOR_SITES = 4
    try:
        found = gate.audit(tmp_path)
    finally:
        gate.FLOOR_SITES = was
    assert says(found, "the debt is paid"), found


def test_a_debt_with_no_creditor_reddens_the_row(tmp_path):
    found = problems(
        tmp_path, ledger=LEDGER.replace('owed = "FixSolo_BugThirdRefCounts.cfg"\n', "")
    )
    assert says(found, "a debt with no creditor"), found


def test_a_claim_and_a_debt_at_once_is_refused(tmp_path):
    """A row cannot both name the mutant that drives it and record a debt for one.

    Found by ablation rather than by design: deleting this clause left all fifty
    cases green, which is the definition of decorative. The contradiction is real
    — `owed` names a file that must NOT exist, so a claimed row carrying one is a
    row asserting its own mutant is missing.
    """
    found = problems(
        tmp_path,
        ledger=LEDGER.replace(
            'mutant = "FixMut_BugFixtureSwitch.cfg"',
            'mutant = "FixMut_BugFixtureSwitch.cfg"\nowed = "FixSolo_BugNever.cfg"',
        ),
    )
    assert says(found, "and still names `owed`"), found


def test_a_row_with_no_mutant_field_at_all_is_refused(tmp_path):
    """The other clause the ablation found decorative. `mutant` is not optional:
    a row that says nothing about its debt reads as carried by anyone skimming."""
    found = problems(tmp_path, ledger=LEDGER.replace('mutant = "owes"\n', "", 1))
    assert says(found, "no mutant and no `owes`"), found


def test_a_mutant_arm_may_not_owe(tmp_path):
    found = problems(
        tmp_path,
        ledger=LEDGER.replace(
            'kind = "narrowing"\nproduction = "the third reference has no counter."',
            'kind = "mutant-arm"\nproduction = "the third reference has no counter."',
        ),
    )
    assert says(found, "a clause nothing drives"), found


# ---- the schema half ---------------------------------------------------------


def test_a_row_with_no_reason_is_not_a_decision(tmp_path):
    for field in ("why", "production"):
        found = problems(
            tmp_path, ledger=LEDGER.replace(f'{field} = "the recorded asymmetry."', f'{field} = ""')
            if field == "why"
            else LEDGER.replace(
                'production = "OATH re-locks where the other applets keep."', 'production = "  "'
            ),
        )
        assert says(found, f"with no {field} is not a decision"), (field, found)


def test_an_invented_key_is_refused(tmp_path):
    """Measured on `deleter_gate.py` before its own rule went in: a key nothing
    reads and nothing prints left that row at EXIT=0."""
    found = problems(tmp_path, ledger=LEDGER.replace('kind = "narrowing"', 'kind = "narrowing"\nseverity = "low"', 1))
    assert says(found, "which nothing reads"), found


def test_a_table_beside_the_rows_is_refused(tmp_path):
    found = problems(tmp_path, ledger=LEDGER + '\n[hardware]\nboard = "rp2350"\n')
    assert says(found, "held by no rule"), found


def test_a_bad_kind_shape_or_id_is_refused(tmp_path):
    assert says(problems(tmp_path, ledger=LEDGER.replace('kind = "narrowing"', 'kind = "fine"', 1)),
                "is not one of"), "kind"
    assert says(problems(tmp_path, ledger=LEDGER.replace('shape = "clause"', 'shape = "clauses"', 1)),
                "is not one of"), "shape"
    assert says(problems(tmp_path, ledger=LEDGER.replace('id = "MX-FIX-001"', 'id = "fix-1"', 1)),
                "is not MX-"), "id"


def test_two_rows_cannot_address_the_same_narrowing(tmp_path):
    """Found by ablation. A duplicate key is SILENT otherwise: the losing row is
    still schema-checked and reads as a decision, while the narrowing it was
    written for is disposed of by the other one."""
    found = problems(
        tmp_path,
        ledger=LEDGER.replace('id = "MX-FIX-004"\nmodule = "RSKeyFixture.tla"\nline = 15',
                              'id = "MX-FIX-004"\nmodule = "RSKeyFixture.tla"\nline = 15')
        + LEDGER[LEDGER.index('[[exception]]\nid = "MX-FIX-004"'):].replace(
            'id = "MX-FIX-004"', 'id = "MX-FIX-005"'),
    )
    assert says(found, "addresses nothing"), found


def test_a_row_that_addresses_nothing_is_a_finding_not_a_traceback(tmp_path):
    """The `line` a row is keyed on is not optional."""
    found = problems(tmp_path, ledger=LEDGER.replace("line = 13\n", "", 1))
    assert says(found, "an entry has no"), found


def test_the_string_vocabulary_is_the_QUOTED_members_only(tmp_path):
    """Found by ablation: merging the two halves left every case green.

    A set of bare NAMES (`{Piv, Oath}`) contributes no strings, so a comparison
    against the quoted spelling of one of those names resolves through neither
    half. Merge them and it resolves through the string half over an enumeration
    that holds no such string — a widening nothing else here would notice.
    """
    model = plus('Applets == {Piv, Oath}', 'Fake(f) == IF TRUE \\/ f = "Piv" THEN 1 ELSE 2')
    assert problems(tmp_path, model=model) == []
    build(tmp_path, model=model)
    assert not [s for s in gate.exceptions(tmp_path) if s["site"] == "Fake"]


def test_two_rows_cannot_share_an_id(tmp_path):
    found = problems(tmp_path, ledger=LEDGER.replace('id = "MX-FIX-002"', 'id = "MX-FIX-001"'))
    assert says(found, "carry the id"), found


def test_carried_by_must_resolve(tmp_path):
    assert problems(
        tmp_path, ledger=LEDGER.replace('why = "the recorded asymmetry."',
                                        'why = "x."\ncarried_by = "NAR-FIXTURE"')
    ) == []
    found = problems(
        tmp_path, ledger=LEDGER.replace('why = "the recorded asymmetry."',
                                        'why = "x."\ncarried_by = "NAR-ABSENT"')
    )
    assert says(found, "is not an id in"), found


def test_an_unreadable_registry_is_a_finding_not_a_traceback(tmp_path):
    build(tmp_path)
    (tmp_path / "assurance" / "model_exceptions.toml").write_text("[[exception]\n")
    assert gate.run(tmp_path) == 1


# ---- the derivation itself ---------------------------------------------------


def test_an_empty_derivation_cannot_pass_over_an_empty_roster(tmp_path):
    """The failure a verdict column cannot show, in both of its shapes.

    A model directory that has stopped matching, and a floor set below what the
    tree actually holds — one is the guard going quiet, the other is the floor
    being useless. Only the first can be constructed, so the second is asserted
    on this checkout's own count.
    """
    build(tmp_path)
    (tmp_path / "formal" / "RSKeyFixture.tla").unlink()
    assert says(gate.audit(tmp_path), "under the floor of"), "empty formal/"
    assert len(gate.exceptions(ROOT)) > gate.FLOOR_SITES, "the floor is at the roster"


def test_a_comment_is_not_a_narrowing(tmp_path):
    """Both TLA+ comment forms, because the module headers are one long block
    comment apiece and every one of them discusses the clauses below it."""
    for wrapper in ("    \\* {}", "    (* {} *)"):
        model = plus("Host(h) ==\n" + wrapper.format("IF TRUE \\/ h = Oath THEN 1 ELSE 2")
                     + "\n    /\\ h = 1")
        assert problems(tmp_path, model=model) == [], wrapper
    # And the arm that says the case above is not passing for another reason: the
    # SAME text outside a comment is collected.
    live = plus("Host(h) ==\n    /\\ (TRUE \\/ h = Oath)\n    /\\ h = 1")
    assert says(problems(tmp_path, model=live), "narrows `h = Oath`"), live


def test_the_vocabulary_reaches_through_extends(tmp_path):
    """The hole the first version shipped with, kept as a case.

    Scoped to a module's own text the string vocabulary of `RSKeyTokenGate` was
    empty, so its only narrowing — of an operation named in the module it extends
    — was derived by nothing.
    """
    build(tmp_path)
    (tmp_path / "formal" / "RSKeyChild.tla").write_text(
        "--------------------------- MODULE RSKeyChild ---------------------------\n"
        "EXTENDS RSKeyFixture\n\n"
        'Reach(z) == IF TRUE \\/ z = "c" THEN 1 ELSE 2\n'
        "=============================================================================\n"
    )
    found = [s for s in gate.exceptions(tmp_path) if s["module"] == "RSKeyChild.tla"]
    assert [s["clause"] for s in found] == ['z = "c"'], found


# ---- the control, and the row ------------------------------------------------


def test_a_model_edit_that_touches_no_narrowing_stays_green(tmp_path):
    """The control, and it is not a no-op: it adds a whole action, a `CASE` that
    covers its domain, and a comparison against a literal no enumeration holds —
    each of which an over-eager shape would collect."""
    model = plus(
        'Total(r) == CASE r = "a" -> 1 [] r = "b" -> 2 [] r = "c" -> 3 [] OTHER -> 0',
        'Unrelated(q) == IF q = "zz" \\/ TRUE THEN 1 ELSE 2',
        "Selected == /\\ sel = Piv\n            /\\ z' = 1",
    )
    assert problems(tmp_path, model=model) == []
    build(tmp_path, model=model)
    assert len(gate.exceptions(tmp_path)) == 4


def test_check_sh_runs_this_row():
    """The row, not the helper. `test_gate_scripts.py` asserts this over the
    `*_gate.py` glob as well; pinned here too, because that file is another
    agent's and a guard that asserts its own row is the convention eight of these
    already follow."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/model_exception_gate.py"), "no check.sh row"


def test_a_finding_reaches_the_row_as_a_non_zero_exit(monkeypatch, capsys):
    """`check.sh` reads an exit code, and nothing else. Driven here as well as in
    `test_gate_scripts.py`, because fourteen of thirty guards printed a finding
    and exited 0 with their own tables green."""
    monkeypatch.setattr(gate, "audit", lambda root: ["SYNTHETIC-PROBE"])
    assert gate.run(ROOT) == 1
    assert "SYNTHETIC-PROBE" in capsys.readouterr().err


def test_arguments_are_refused():
    saved = sys.argv
    sys.argv = ["model_exception_gate.py", "--relock"]
    try:
        assert gate.main() == 2
    finally:
        sys.argv = saved


@pytest.mark.parametrize("name", sorted(p.name for p in (ROOT / "formal").glob("*.tla")))
def test_every_model_is_scanned(name):
    """A model added to `formal/` is in the derivation's reach by the directory
    glob, not by a roster — the shape `citation_gate.py`'s `PAGES` had to grow a
    derived half for after its ninth module went unchecked."""
    assert name in gate.modules(ROOT)
