# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""docs/testing.md's prose Kani counts, held to `scripts/kani.sh`'s ratchets.

`kani_gate.py` derives that page's tier TABLE from the tree and refuses a cell
that drifted, in both directions. The prose around the table was held by nothing,
and it rotted the way an unheld number does: "the same 89 harness names" and
"against today's 89" were still on the page over a tree of 94, three paragraphs
under a table printing 94. Both were TRUE when they were written — `FLOOR_all`
was 89 on 2026-08-26 — which is why review passed them twice: nothing on the page
distinguished a dated measurement from a claim about the tree, and neither
sentence said which roster its 89 belonged to, so a reader could attach it to
`all`, to a weekly shard, or to the workspace.

So a present-tense count is written in one shape and one shape only — ``today's
`FLOOR_all` of 94`` — and this holds it to `scripts/kani.sh`, which
`kani_gate.py` already holds to the tree. Two hops, and no third place that
counts `#[kani::proof]`.

The page is flattened before matching, `*` dropped and whitespace collapsed:
re-wrapping a paragraph or bolding a phrase must not take the guard off it. That
is the hole this repo keeps shipping — a guard whose subject moved one column and
went unread while the row stayed green.

`UNNAMED` is the third clause and the shape that actually rotted: a count
attributed to *now* with no ratchet named. Refused outright, because the repair
for `today's 89` is not a fresher digit.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = pathlib.Path("docs/testing.md")
RUNNER = pathlib.Path("scripts/kani.sh")

#: `FLOOR_all=94`, `COVERS_light2=12`. Read here rather than imported from
#: `kani_gate.py`: that module is the other end of the chain this compares, and
#: one shared parser would let a mis-read agree with itself.
RATCHET = re.compile(r"^(FLOOR|COVERS)_(\w+)=\"?(\d+)\"?\s*(?:#.*)?$", re.M)

#: The one shape a present-tense count may take on the page.
PRESENT = re.compile(r"today's `((?:FLOOR|COVERS)_\w+)` of (\d+)\b")

#: A count attributed to now with no ratchet named — `today's 89`, the sentence
#: this file exists for.
UNNAMED = re.compile(r"today's `?\d")

#: The count the page's whole roster argument turns on, and the one that rotted
#: in two places. A page that stops stating it has deleted the claim, not fixed
#: it, so the clauses above would then be holding nothing.
ANCHOR = "FLOOR_all"


def flat(text):
    """`text` with emphasis dropped and whitespace collapsed, for matching."""
    return re.sub(r"\s+", " ", text.replace("*", ""))


def ratchets(runner):
    """name → value, as `scripts/kani.sh` writes its floors."""
    return {f"{kind}_{tier}": int(value) for kind, tier, value in RATCHET.findall(runner)}


def problems(page, runner):
    """Every prose count that no longer matches the runner, and why."""
    kept = ratchets(runner)
    out = []
    if not kept:
        # A roster that selects nothing exits 0: with no ratchets parsed, every
        # loop below runs zero times and the page passes unread.
        return [f"{RUNNER} carries no FLOOR_*/COVERS_* this could check the page against"]
    stated = {}
    for name, value in PRESENT.findall(flat(page)):
        stated[name] = int(value)
        if name not in kept:
            out.append(f"{PAGE} states today's `{name}`, which {RUNNER} does not define")
        elif int(value) != kept[name]:
            out.append(
                f"{PAGE} states today's `{name}` of {value}; {RUNNER} floors that"
                f" tier at {kept[name]}"
            )
    if ANCHOR not in stated:
        out.append(
            f"{PAGE} no longer states today's `{ANCHOR}` of {kept[ANCHOR]}; the prose"
            " counts it compares against are then held by nothing"
        )
    if UNNAMED.search(flat(page)):
        out.append(
            f"{PAGE} attributes a bare count to \"today's\"; name the ratchet"
            f" — today's `{ANCHOR}` of {kept[ANCHOR]} — so it cannot be read off"
            " the wrong roster"
        )
    return out


def page():
    return (ROOT / PAGE).read_text()


def runner():
    return (ROOT / RUNNER).read_text()


def test_the_shipped_page_matches_the_shipped_runner():
    assert problems(page(), runner()) == []


def test_a_floor_the_runner_raised_leaves_the_page_behind():
    """The rot itself: a harness lands, `kani.sh` moves, the prose does not."""
    floor = ratchets(runner())[ANCHOR]
    moved = runner().replace(f"{ANCHOR}={floor}", f"{ANCHOR}={floor + 1}")
    assert moved != runner(), "fixture no longer matches the runner"
    found = problems(page(), moved)
    assert any(f"`{ANCHOR}` of {floor}" in p and f"at {floor + 1}" in p for p in found), found


def test_a_number_the_page_mistypes_is_caught():
    floor = ratchets(runner())[ANCHOR]
    stale = flat(page()).replace(f"`{ANCHOR}` of {floor}", f"`{ANCHOR}` of {floor - 1}")
    assert stale != flat(page()), "fixture no longer matches the page"
    found = problems(stale, runner())
    assert any(f"`{ANCHOR}` of {floor - 1}" in p and f"at {floor}" in p for p in found), found


def test_deleting_the_clause_does_not_leave_it_green():
    """The deletion arm: the sentence removed, not re-typed."""
    floor = ratchets(runner())[ANCHOR]
    gone = flat(page()).replace(f"today's `{ANCHOR}` of {floor}", "today's roster")
    assert gone != flat(page()), "fixture no longer matches the page"
    found = problems(gone, runner())
    assert any("no longer states" in p and "FLOOR_all" in p for p in found), found


def test_the_shape_that_rotted_is_refused_outright():
    floor = ratchets(runner())["FLOOR_light1"]
    loose = flat(page()).replace(f"today's `FLOOR_light1` of {floor}", f"today's {floor}")
    assert loose != flat(page()), "fixture no longer matches the page"
    found = problems(loose, runner())
    assert any("bare count" in p for p in found), found


def test_a_ratchet_the_runner_does_not_define_is_a_finding_not_a_skip():
    """A mistyped tier would otherwise match no floor and be checked against none."""
    floor = ratchets(runner())["FLOOR_light1"]
    typo = flat(page()).replace(f"`FLOOR_light1` of {floor}", f"`FLOOR_lite1` of {floor}")
    assert typo != flat(page()), "fixture no longer matches the page"
    found = problems(typo, runner())
    assert any("does not define" in p and "FLOOR_lite1" in p for p in found), found


def test_a_runner_with_no_ratchets_left_is_refused():
    stripped = re.sub(r"^(FLOOR|COVERS)_\w+=.*$", "", runner(), flags=re.M)
    assert problems(page(), stripped) == [
        f"{RUNNER} carries no FLOOR_*/COVERS_* this could check the page against"
    ]


def test_a_rewrap_does_not_take_the_guard_off_the_sentence():
    """The phrase is wrapped across lines on the page today, and bolded in one of

    the two places — both were live holes before `flat` existed.
    """
    floor = ratchets(runner())["FLOOR_light1"]
    wrapped = flat(page()).replace(f"today's `FLOOR_light1` of {floor}", f"today's\n**`FLOOR_light1`**\nof {floor}")
    assert wrapped != flat(page()), "fixture no longer matches the page"
    assert problems(wrapped, runner()) == []
    assert problems(wrapped.replace(f"of {floor}", f"of {floor - 1}"), runner())
