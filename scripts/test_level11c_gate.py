#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `level11c_gate.py`, in the diff that adds the guard.

A guard that only sees a mistyped number is half a guard, and this tree has
shipped that half five times over. So the table has three families:

* **defect** — the page states a value the tree does not say;
* **removal** — the sentence carrying the value is deleted or reworded away.
  `scripts/docs_constants.py` leaves this open by construction, and it is the
  cheapest way to make a stale decision record green: stop saying the thing that
  went stale;
* **drift** — the page stands still and the TREE moves under it. This is the one
  the guard exists for, and the only family a fixture cannot fake: it is driven
  by patching the derivation's own reader, not the page.

Every case asserts WHICH finding fell and in which direction, not merely that the
audit came back non-empty. A red run is not evidence until you know why it went
red, and a table that only counts findings cannot tell a guard from its inverse.
"""
import pathlib
import re

import pytest

import level11c_gate as g

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / g.PAGE


@pytest.fixture
def page():
    return PAGE.read_text()


@pytest.fixture
def audit(monkeypatch):
    """Run the real audit with the page text (and optionally `lines`) replaced.

    The tree is never written: `Path.read_text` is intercepted for the one page,
    so a failing case leaves nothing behind to explain.
    """
    real_read = pathlib.Path.read_text

    def run(text=None, lines=None):
        if text is not None:
            monkeypatch.setattr(
                pathlib.Path,
                "read_text",
                lambda self, *a, **k: text if self == PAGE else real_read(self, *a, **k),
            )
        if lines is not None:
            monkeypatch.setattr(g, "lines", lines)
        return g.audit(ROOT)[0]

    return run


def test_the_page_as_written_is_green(audit):
    assert audit() == []


def test_every_rule_ran(audit):
    """The floor, and the reason it is a rule COUNT.

    A derivation that stops finding passes whatever it is shown, and the summary
    would still read `ok`. Asserted here rather than trusted from the green run
    above, which is the shape audit run-34 #9 is about.
    """
    assert len(g.derived()) >= g.RULE_FLOOR


@pytest.mark.parametrize(
    "before, after, expect",
    [
        ("73% of the foreign half", "70% of the foreign half",
         r"the assembly's share reads '70', the tree says 73"),
        ("five of the ten `[[boundary]]`", "five of the nine `[[boundary]]`",
         r"`\[\[boundary\]\]` rows reads 'nine', the tree says 10"),
        ("five of the ten `[[boundary]]`", "four of the ten `[[boundary]]`",
         r"linker-symbol boundaries reads 'four', the tree says 5"),
        ("168 of those carry", "169 of those carry",
         r"`<S: Storage` sites reads '169', the tree says 168"),
        ("13 registered tools", "12 registered tools",
         r"registered tools reads '12', the tree says 13"),
        ("and 1 is\nunpinned", "and 0 is\nunpinned",
         r"unpinned tools reads '0', the tree says 1"),
    ],
)
def test_a_value_the_tree_does_not_say_is_refused(audit, page, before, after, expect):
    findings = audit(page.replace(before, after))
    assert any(re.search(expect, f) for f in findings), findings


@pytest.mark.parametrize(
    "before, after, expect",
    [
        ("**Structurally blind, all nine:**", "**Structurally blind:**",
         "the sentence stating blind rows is gone"),
        ("% of the foreign half by line", "% of it by line",
         "the sentence stating the assembly's share is gone"),
        ("the registry reaches 4 and says", "the registry reaches most of them and says",
         "the sentence stating TCB categories reached is gone"),
    ],
)
def test_a_sentence_reworded_away_is_refused(audit, page, before, after, expect):
    """Deleting the claim must not be the cheap repair."""
    findings = audit(page.replace(before, after))
    assert any(expect in f for f in findings), findings


def test_a_value_stated_twice_is_refused(audit, page):
    findings = audit(page + "\n\nThe gate runs 116 rows.\n")
    assert any("stated 2 times" in f for f in findings), findings


def test_the_page_standing_still_while_the_tree_moves_is_refused(audit):
    """The family the guard exists for, driven through the derivation's reader."""
    real = g.lines
    findings = audit(
        lines=lambda rel: real(rel) + 200 if rel.endswith("bignum_asm.S") else real(rel)
    )
    assert any("the assembly's share reads '73', the tree says" in f for f in findings), findings


def test_the_named_row_still_runs_this_guard():
    """The wiring, not the function.

    A guard whose `check.sh` row nobody added is a guard the tree can delete with
    the suite green — measured five times in this repo, once per new guard.
    """
    check = (ROOT / "scripts/check.sh").read_text()
    assert "python scripts/level11c_gate.py" in check
