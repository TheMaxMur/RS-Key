# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `scope_gate.py` is verified against.

Same discipline as its siblings, and the same reason: every new guard in this
tree has shipped with a hole of one family -- a loop over nothing that exits 0,
a check that only fires on what already exists. So the cases that must NOT fire
are here in the same number as the ones that must, and they carry the weight:
a scope gate that reddened the liveness tier for running one relying party on
purpose would be deleted within a week, and rightly.

The fixture is a two-module `formal/` with a scope constant, a switch and a
mutant, small enough that every case says one thing.
"""

import pathlib

import pytest

import scope_gate

BASE = """---- MODULE Base ----
EXTENDS Naturals

CONSTANTS
    Slots,   \\* the scope constant under test
    BugOne

CONSTANT FixLate

VARIABLES x
vars == << x >>
Spec == x = 0
TypeOK == x \\in 0..1
NoDrift == TRUE
====
"""

CHILD = """---- MODULE Child ----
EXTENDS Base

Refines == TRUE
====
"""

BASE_CFG = """SPECIFICATION Spec
CONSTANTS
    Slots = {"a", "b"}
    BugOne = FALSE
    FixLate = TRUE
INVARIANTS
    TypeOK
    NoDrift
"""

MUT_CFG = BASE_CFG.replace("BugOne = FALSE", "BugOne = TRUE")

CHILD_CFG = """SPECIFICATION Spec
CONSTANTS
    Slots = {"a"}
    BugOne = FALSE
    FixLate = TRUE
INVARIANTS
    TypeOK
    Refines
"""

SCOPES = """\\* the record
Base   Slots   2   NoDrift
"""


class Tree:
    """A `formal/` small enough that a failure names one rule."""

    def __init__(self, root):
        self.formal = root / "formal"
        self.formal.mkdir(parents=True)
        self.write("Base.tla", BASE)
        self.write("Child.tla", CHILD)
        self.write("Base.cfg", BASE_CFG)
        self.write("Mut_BugOne.cfg", MUT_CFG)
        self.scopes = self.formal / "scopes.txt"
        self.scopes.write_text(SCOPES)

    def write(self, name, text):
        (self.formal / name).write_text(text)

    def edit(self, name, old, new):
        path = self.formal / name
        text = path.read_text()
        assert text.count(old) == 1, f"{name} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def problems(self, safety=("Base.cfg", "Mut_BugOne.cfg")):
        """Audited with the tier passed in: the fixture has no run-tlc.sh, and
        shelling out to the real one would make every case depend on the tree."""
        return scope_gate.audit(self.formal, self.scopes, set(safety))[0]


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    return [p for p in problems if needle in p]


# --- the clean fixture, and the real tree ------------------------------------


def test_clean_fixture_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    """The control the fixture cannot be: the model these rules were written for."""
    assert scope_gate.audit()[0] == []


# --- what must fire ----------------------------------------------------------


def test_a_scope_constant_with_no_row(tree):
    tree.edit("Base.tla", "    Slots,   \\* the scope constant under test",
              "    Slots,\n    Rounds,")
    tree.edit("Base.cfg", '    Slots = {"a", "b"}',
              '    Slots = {"a", "b"}\n    Rounds = 4')
    tree.edit("Mut_BugOne.cfg", '    Slots = {"a", "b"}',
              '    Slots = {"a", "b"}\n    Rounds = 4')
    assert only(tree.problems(), "Rounds is a scope constant with no row")


def test_a_row_that_names_nothing(tree):
    tree.scopes.write_text(SCOPES + "Base   Ghost   1   NoDrift\n")
    assert only(tree.problems(), "records Base Ghost")


def test_a_safety_config_below_the_minimum(tree):
    tree.edit("Base.cfg", '    Slots = {"a", "b"}', '    Slots = {"a"}')
    assert only(tree.problems(), "below the 2 that NoDrift was measured to need")


def test_a_numeric_scope_below_the_minimum(tree):
    tree.edit("Base.cfg", '    Slots = {"a", "b"}', "    Slots = 1")
    tree.edit("Mut_BugOne.cfg", '    Slots = {"a", "b"}', "    Slots = 3")
    assert only(tree.problems(), "below the 2 that NoDrift was measured to need")


def test_a_row_recorded_twice(tree):
    tree.scopes.write_text(SCOPES + "Base   Slots   1   NoDrift\n")
    assert only(tree.problems(), "recorded twice")


def test_a_minimum_that_is_not_a_number(tree):
    tree.scopes.write_text("Base   Slots   two   NoDrift\n")
    assert only(tree.problems(), "must be a number or `-`")


def test_a_short_row(tree):
    tree.scopes.write_text("Base   Slots   2\n")
    assert only(tree.problems(), "expected `<module> <constant> <min> <invariant>`")


def test_a_missing_record(tree):
    tree.scopes.unlink()
    assert only(tree.problems(), "is missing")


def test_a_config_that_belongs_to_no_module(tree):
    tree.edit("Base.cfg", "    FixLate = TRUE", "    FixLate = TRUE\n    Stray = 1")
    assert only(tree.problems(), "no single module assigns exactly its constants")


# --- what must NOT fire, which is the half these guards keep shipping without -


def test_a_non_safety_config_may_run_smaller(tree):
    """The liveness tier runs one relying party deliberately. A gate that
    reddened it would be measuring the wrong thing, and would be removed."""
    tree.edit("Base.cfg", '    Slots = {"a", "b"}', '    Slots = {"a"}')
    assert tree.problems(safety=("Mut_BugOne.cfg",)) == []


def test_a_dash_row_holds_nothing_to_a_number(tree):
    tree.scopes.write_text("Base   Slots   -   -\n")
    tree.edit("Base.cfg", '    Slots = {"a", "b"}', '    Slots = {"a"}')
    assert tree.problems() == []


def test_a_boolean_is_not_a_size(tree):
    """`PowerOnClearsScratch2` is an ASSUME, not a cardinality. Recording it
    keeps the pinned assumption visible; comparing it would be nonsense."""
    tree.edit("Base.cfg", '    Slots = {"a", "b"}', "    Slots = TRUE")
    assert only(tree.problems(), "was measured to need") == []


def test_a_scope_above_the_minimum_passes(tree):
    tree.edit("Base.cfg", '    Slots = {"a", "b"}', '    Slots = {"a", "b", "c"}')
    assert tree.problems() == []


def test_a_new_mutation_switch_is_not_a_scope(tree):
    tree.edit("Base.tla", "    BugOne", "    BugOne,\n    BugTwo")
    for cfg in ("Base.cfg", "Mut_BugOne.cfg"):
        tree.edit(cfg, "    FixLate = TRUE", "    BugTwo = FALSE\n    FixLate = TRUE")
    assert tree.problems() == []


def test_a_child_module_does_not_steal_its_parents_configs(tree):
    """`RSKeyTokenRefinement` over `RSKeySecurityState` is this shape: the child
    inherits every definition, so both match on names alone."""
    assert tree.problems() == []
    owner = scope_gate.owner_of(
        tree.formal / "Base.cfg",
        ["Base", "Child"],
        {m: scope_gate.transitive_constants(m, tree.formal) for m in ("Base", "Child")},
        {m: scope_gate.defined_in(m, tree.formal) for m in ("Base", "Child")},
        tree.formal,
    )
    assert owner == "Base"


def test_a_config_that_does_not_check_the_invariant_is_not_held(tree):
    """The fairness row: safety tier, one channel on purpose, and it checks a
    property the minimum was never measured against."""
    tree.write("Fair.cfg", BASE_CFG.replace('{"a", "b"}', '{"a"}')
               .replace("    NoDrift\n", ""))
    assert tree.problems(safety=("Base.cfg", "Mut_BugOne.cfg", "Fair.cfg")) == []


def test_a_minimum_without_its_invariant(tree):
    tree.scopes.write_text("Base   Slots   2   -\n")
    assert only(tree.problems(), "recorded together or not at all")


def test_an_invariant_the_module_does_not_define(tree):
    tree.scopes.write_text("Base   Slots   2   NoSuchThing\n")
    assert only(tree.problems(), "which Base does not define")


def test_the_one_line_constant_form_is_read(tree):
    """`CONSTANT FixLate` on its own line: reading only the block form loses it,
    and a parser that sees fewer constants than TLC does is the blind green."""
    assert "FixLate" in scope_gate.constants_of("Base", tree.formal)
