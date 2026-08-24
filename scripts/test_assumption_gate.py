# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import assumption_gate

MODULE = """------------------------- MODULE Probe -------------------------
EXTENDS Naturals

CONSTANTS
    PowerOnClearsScratch2,
    BugSomething

VARIABLES recorded

TypeOK == recorded \\in {"clear", "batch"}

ColdReset ==
    /\\ recorded' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded

Next == ColdReset

Spec == [][Next]_recorded
=============================================================================
"""

CFG = """SPECIFICATION Spec
CONSTANTS
    PowerOnClearsScratch2 = {clears}
    BugSomething = FALSE
INVARIANTS
    TypeOK
"""

ENTRY = """[[assumption]]
constant = "PowerOnClearsScratch2"
statement = "s"
discharged_by = "d"
risk = "usability"
"""


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A minimal formal/ + registry the gate is pointed at."""
    formal = tmp_path / "formal"
    formal.mkdir()
    (formal / "Probe.tla").write_text(MODULE, encoding="utf-8")
    (formal / "Probe.cfg").write_text(CFG.format(clears="TRUE"), encoding="utf-8")
    (formal / "ProbeCarry.cfg").write_text(CFG.format(clears="FALSE"), encoding="utf-8")
    registry = tmp_path / "assumptions.toml"
    registry.write_text(ENTRY, encoding="utf-8")
    monkeypatch.setattr(assumption_gate, "FORMAL", formal)
    monkeypatch.setattr(assumption_gate, "REGISTRY", registry)
    return formal, registry


def problems(_tree=None):
    return assumption_gate.audit()[0]


def test_a_two_armed_assumption_an_action_reads_is_clean(tree):
    assert problems() == []


def test_the_shipped_registry_matches_the_shipped_model():
    # No fixture: this one runs against the real tree, which is the row CI runs.
    assert assumption_gate.audit()[0] == []


def test_every_boot_mutant_runs_on_the_arm_that_carries_too():
    """The rows exist to say the mutants still fall there, so pin the arm.

    `run-tlc.sh` lists the family with `ls`, and `floors.txt` records only a
    verdict — flipping all three back to the TRUE arm by hand leaves both silent,
    and `BootCarry.cfg` alone would keep the two-armed rule satisfied.
    """
    arms = assumption_gate.assignments()["PowerOnClearsScratch2"]
    carries = {cfg for cfg, value in arms.items() if value == "FALSE"}
    mutants = {p.name for p in assumption_gate.FORMAL.glob("BootCarryMut_*.cfg")}
    assert mutants, "the carry-arm mutants have gone"
    assert carries == {"BootCarry.cfg"} | mutants
    assert len(mutants) == len({p.name for p in assumption_gate.FORMAL.glob("BootMut_*.cfg")})


def test_an_assumption_every_configuration_pins_the_same_way_is_an_axiom(tree):
    formal, _ = tree
    (formal / "ProbeCarry.cfg").unlink()
    assert any("is an axiom" in p for p in problems())


def test_an_assumption_no_action_reads_is_a_comment_with_a_type(tree):
    # The pre-D4 shape exactly: declared, ASSUMEd, and branched on nowhere.
    formal, _ = tree
    (formal / "Probe.tla").write_text(
        MODULE.replace(
            '/\\ recorded\' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded',
            '/\\ recorded\' = "clear"',
        ).replace("Next == ColdReset", "ASSUME PowerOnClearsScratch2\n\nNext == ColdReset"),
        encoding="utf-8")
    assert any("reaches a definition that reads it" in p for p in problems())


def test_a_constant_only_a_block_comment_names_is_still_a_comment(tree):
    """`(* … *)` prose sits below the first definition in every real module."""
    formal, _ = tree
    (formal / "Probe.tla").write_text(
        MODULE.replace(
            '/\\ recorded\' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded',
            '/\\ recorded\' = "clear"',
        ).replace("Next == ColdReset",
                  "(* PowerOnClearsScratch2 is what a cold reset does. *)\n\nNext == ColdReset"),
        encoding="utf-8")
    assert any("reaches a definition that reads it" in p for p in problems())


def test_a_constant_named_below_the_module_terminator_is_not_read(tree):
    formal, _ = tree
    (formal / "Probe.tla").write_text(
        MODULE.replace(
            '/\\ recorded\' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded',
            '/\\ recorded\' = "clear"',
        ) + "\nPowerOnClearsScratch2\n",
        encoding="utf-8")
    assert any("reaches a definition that reads it" in p for p in problems())


def test_a_constant_reached_only_through_a_symmetry_root_is_read(tree):
    """`SYMMETRY`, `CONSTRAINT`, `VIEW` and `ALIAS` name definitions TLC runs."""
    formal, _ = tree
    (formal / "Probe.tla").write_text(
        MODULE.replace(
            '/\\ recorded\' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded',
            '/\\ recorded\' = "clear"',
        ).replace("Next == ColdReset", "Symm == PowerOnClearsScratch2\n\nNext == ColdReset"),
        encoding="utf-8")
    for name in ("Probe.cfg", "ProbeCarry.cfg"):
        cfg = formal / name
        cfg.write_text(cfg.read_text(encoding="utf-8") + "SYMMETRY Symm\n", encoding="utf-8")
    assert problems() == []


def test_a_constant_only_an_orphan_definition_reads_is_still_a_comment(tree):
    """The rule's own failure family, one level in.

    `Orphan == PowerOnClearsScratch2` with nothing mentioning `Orphan` is as
    inert as the `ASSUME` above, and the rule read it as satisfied for as long
    as it only asked whether the module mentions the name anywhere.
    """
    formal, _ = tree
    (formal / "Probe.tla").write_text(
        MODULE.replace(
            '/\\ recorded\' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded',
            '/\\ recorded\' = "clear"',
        ).replace("Next == ColdReset", "Orphan == PowerOnClearsScratch2\n\nNext == ColdReset"),
        encoding="utf-8")
    assert any("reaches a definition that reads it" in p for p in problems())


def test_a_constant_a_root_reaches_through_a_helper_is_clean(tree):
    """And the other direction: two hops from a checked name is still read."""
    formal, _ = tree
    (formal / "Probe.tla").write_text(
        MODULE.replace(
            '/\\ recorded\' = IF PowerOnClearsScratch2 THEN "clear" ELSE recorded',
            "/\\ recorded' = Cleared",
        ).replace("Next == ColdReset",
                  'Cleared == IF PowerOnClearsScratch2 THEN "clear" ELSE recorded\n\nNext == ColdReset'),
        encoding="utf-8")
    assert problems() == []


def test_an_assumption_with_no_registry_entry_is_refused(tree):
    _, registry = tree
    registry.write_text("", encoding="utf-8")
    assert any("not in the registry" in p for p in problems())


def test_a_registry_entry_no_configuration_assigns_is_refused(tree):
    _, registry = tree
    registry.write_text(ENTRY.replace("PowerOnClearsScratch2", "NeverAssigned"), encoding="utf-8")
    assert any("no configuration assigns it" in p for p in problems())


@pytest.mark.parametrize("field", sorted(assumption_gate.HAND_FIELDS - {"constant"}))
def test_every_hand_written_field_is_required(tree, field):
    _, registry = tree
    registry.write_text(
        "\n".join(l for l in ENTRY.splitlines() if not l.startswith(field)), encoding="utf-8")
    assert any("missing" in p for p in problems())


def test_a_risk_outside_the_vocabulary_is_refused(tree):
    _, registry = tree
    registry.write_text(ENTRY.replace('risk = "usability"', 'risk = "medium"'), encoding="utf-8")
    assert any("is not one of" in p for p in problems())


def test_a_defect_switch_is_not_mistaken_for_an_assumption(tree):
    # `BugSomething` is Boolean and pinned FALSE everywhere, which is exactly the
    # shape rule three refuses — for an assumption. A switch is meant to be pinned.
    assert not any("BugSomething" in p for p in problems())
