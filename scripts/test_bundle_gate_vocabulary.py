# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""`METHODS` against the page it says it is a copy of.

`bundle_gate.METHODS` carried "in `docs/authorization-slice.md` item 3's order" as a
comment, and nothing compared the two. Both were extended by hand when
`KAT/differential` arrived — the same day, in the same commit, which is exactly
the pair that survives a green gate when only one of them moves.

Driven through `bundle_gate.audit` for the page side, so what the arms falsify is
the `slice evidence bundle` ROW and not a helper nothing calls. Measured by hand
on the shipped tree, `python scripts/bundle_gate.py` without a pipe: a word added
to `METHODS` alone, a word added to item 3 alone, the item's heading renamed and the
two lists reordered are exit 1 each, and removing the call from `audit` puts the
first two back to exit 0.

The roster side is a PARAMETER of `vocabulary_problems`, not a global a case
patches down — `bounds_gate`'s shape, for its reason: a default read at import
cannot be reached by `monkeypatch.setattr`, so a case that patched the name would
be asserting over a rule the shipped run never uses.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bundle_gate
import test_bundle_gate as T

pytestmark = pytest.mark.assurance

PAGE = bundle_gate.SLICE


def page_text(root):
    return (root / PAGE).read_text(encoding="utf-8")


def edit_page(root, old, new):
    text = page_text(root)
    assert text.count(old) == 1, f"fixture drift: {old!r}"
    (root / PAGE).write_text(text.replace(old, new))


def only_vocabulary(root):
    return [p for p in T.findings(root) if str(PAGE) in p]


def test_the_shipped_page_and_the_shipped_roster_agree():
    """The control. Read off the real tree, because the fixture copies this page
    and a fixture agreeing with itself would say nothing about the tree."""
    assert bundle_gate.vocabulary_problems(page_text(bundle_gate.ROOT)) == []


def test_a_word_on_the_page_and_not_in_the_roster(tmp_path):
    root = T.tree(tmp_path)
    edit_page(
        root,
        "accepted risk / KAT/differential)",
        "accepted risk / KAT/differential / fuzzing)",
    )
    assert any("was extended by hand" in p for p in only_vocabulary(root)), T.findings(root)


def test_a_word_in_the_roster_and_not_on_the_page():
    """The other direction, through the parameter — see this file's header for
    why it is not a `monkeypatch` of `METHODS`."""
    text = page_text(bundle_gate.ROOT)
    problems = bundle_gate.vocabulary_problems(text, bundle_gate.METHODS + ("fuzzing",))
    assert any("was extended by hand" in p for p in problems), problems


def test_the_same_words_in_a_different_order(tmp_path):
    """`METHODS` claims item 3's ORDER in as many words. A set equality leaves that
    half of the sentence a promise: with one, this case is green."""
    root = T.tree(tmp_path)
    edit_page(
        root,
        "measurement / accepted risk / KAT/differential)",
        "accepted risk / measurement / KAT/differential)",
    )
    assert any("in the same order" in p for p in only_vocabulary(root)), T.findings(root)


def test_the_anchor_is_the_heading_and_a_rename_is_loud(tmp_path):
    """A page that stopped publishing the list is a page that stopped being the
    source, and the rule says so instead of comparing against nothing. The anchor
    is this heading and never a line number — `citation_gate` reads `.rs`, `.sh`
    and `.txt`, so a line number in a `.md` is held by nothing at all."""
    root = T.tree(tmp_path)
    edit_page(root, bundle_gate.SLICE_ITEM, "3. **Method, scope and bounds**")
    assert any("stopped having a source" in p for p in only_vocabulary(root)), T.findings(root)


def test_the_page_going_away_is_not_an_empty_roster(tmp_path):
    root = T.tree(tmp_path)
    (root / PAGE).unlink()
    assert any("is missing" in p for p in only_vocabulary(root)), T.findings(root)


def test_the_separator_keeps_a_slash_inside_a_word_and_rejoins_a_wrap():
    """Whitespace on BOTH sides is what lets item 3 spell `KAT/differential` at all,
    and the page wraps mid-list — `bounded proof` arrives split across a newline
    and three spaces of indent."""
    text = (
        "3. **Method and scope/bounds** — the method per §4.1 (review / bounded\n"
        "   proof / KAT/differential), and for each obligation its bound\n"
    )
    assert bundle_gate.slice_methods(text) == ("review", "bounded proof", "KAT/differential")


def test_a_page_without_the_list_reads_as_no_source_at_all():
    assert bundle_gate.slice_methods("3. **Method and scope/bounds** — see §4.1.\n") is None
    assert bundle_gate.slice_methods("nothing of the sort\n") is None
