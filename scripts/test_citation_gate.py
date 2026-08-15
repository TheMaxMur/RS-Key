# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `citation_gate.py` is verified against.

Same discipline as its siblings, and for the same reason: the guards written in
this tree keep shipping with a hole of one family — a loop over nothing that
exits 0, a list that only checks what already exists. So the cases that must
*not* fire are here in the same number as the ones that must, including the one
that decides whether this row survives contact with the model: an ordinary edit
elsewhere in a cited file has to leave it green.
"""

import pathlib
import subprocess

import pytest

import citation_gate

CODE = """// SPDX-License-Identifier: AGPL-3.0-only
pub const RETRIES: u8 = 8;

pub fn judge(byte: u8) -> bool {
    byte < 0x80
}

pub fn spend() {}
"""

MODEL = """---- MODULE Probe ----
VARIABLES
    pin,   \\* EF_PIN (clientpin.rs:2)
    tok    \\* the grant (state.rs:4-6)

\\* the spend latch (clientpin.rs:8), the firmware half (firmware/src/main.rs:2)
\\* and a list, clientpin.rs:2,4-6
====
"""

#: Every page `PAGES` names that a case does not drive. It has to clear the
#: citation FLOOR, because a page that cites nothing is itself a problem.
STUB = """\\* a page this case does not drive (clientpin.rs:2, clientpin.rs:4-6)
"""

PAGE = """# The model

| invariant | where |
|---|---|
| `NoDrift` | `crates/rsk-fido/src/`: `clientpin.rs:4-6` · `:8` |
"""


#: The two pages the cases below drive: the `.tla` one carries the citations a
#: case edits, the `.md` one the continuation forms. Resolved by SUFFIX rather
#: than by position — `PAGES` grew a third entry when the applet-seams module
#: landed, and `PAGES[1]` silently became a different page, which failed six
#: cases at once. Every other page in the tuple is written out as a stub so a
#: run over the fixture is not complaining about a page that is simply absent.
def _page(name):
    hits = [p for p in citation_gate.PAGES if p.name == name]
    assert len(hits) == 1, f"{name} is not one of {citation_gate.PAGES}"
    return hits[0]


MODEL_PAGE = _page("RSKeySecurityState.tla")
PROSE_PAGE = _page("README.md")


class Tree:
    """A checkout the model can cite: two applet files, a firmware, two pages."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-fido/src/clientpin.rs", CODE)
        self.write("crates/rsk-fido/src/state.rs", CODE)
        self.write("crates/rsk-device/src/ctap.rs", CODE)
        self.write("crates/rsk-usb/src/ctaphid.rs", CODE)
        self.write("crates/rsk-fs/src/lib.rs", CODE)
        self.write("firmware/src/main.rs", CODE)
        for page in citation_gate.PAGES:
            self.write(page, STUB)
        self.write(MODEL_PAGE, MODEL)
        self.write(PROSE_PAGE, PAGE)
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def problems(self, floor=2, pending=None):
        """Audited with the floor lowered and no landing debt: the fixture is
        smaller than the tree and carries none of its history. A case that wants
        a debt passes one.
        """
        was, debts, per = (
            citation_gate.FLOOR,
            citation_gate.PENDING,
            citation_gate.FLOOR_BY_PAGE,
        )
        # The per-page overrides are cleared too: the fixture writes a 2-citation
        # stub to every page, so a page with a real-tree floor of its own would
        # fail the fixture for a reason that has nothing to do with the case.
        citation_gate.FLOOR, citation_gate.PENDING, citation_gate.FLOOR_BY_PAGE = (
            floor,
            pending or {},
            {},
        )
        try:
            return citation_gate.audit(self.root)[0]
        finally:
            citation_gate.FLOOR, citation_gate.PENDING, citation_gate.FLOOR_BY_PAGE = (
                was,
                debts,
                per,
            )


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    """The problems mentioning `needle`, so a message is asserted, not a count."""
    return [p for p in problems if needle in p]


# --- the clean tree, and the real one ----------------------------------------


def test_clean_tree_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    """The control the fixture cannot be: the model these rules were written for."""
    assert citation_gate.audit(citation_gate.ROOT)[0] == []


# --- citations that no longer resolve -----------------------------------------


def test_a_cited_file_that_is_gone(tree):
    (tree.root / "crates/rsk-fido/src/state.rs").unlink()
    assert only(tree.problems(), "no such file is in the tree")


def test_a_line_past_the_end_of_the_file(tree):
    tree.edit(MODEL_PAGE, "state.rs:4-6", "state.rs:4-600")
    assert only(tree.problems(), "which has 8 lines")


def test_a_range_that_runs_backwards(tree):
    tree.edit(MODEL_PAGE, "state.rs:4-6", "state.rs:6-4")
    assert only(tree.problems(), "runs backwards")


def test_a_cited_line_that_drifted_onto_a_blank(tree):
    """The one drift signal that costs nothing: the code cited has moved away."""
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub const RETRIES", "\npub const RETRIES")
    assert only(tree.problems(), "whose cited line is blank")


def test_a_continuation_that_binds_to_a_gone_file(tree):
    """`:8` inherits the file named before it, so it rots with that file."""
    tree.edit(PROSE_PAGE, "clientpin.rs:4-6", "clientpin.rs:400-600")
    assert only(tree.problems(), "which has 8 lines")


def test_a_bare_continuation_with_no_file_before_it(tree):
    tree.edit(PROSE_PAGE, "`clientpin.rs:4-6` · `:8`", "`:8`")
    assert only(tree.problems(), "with no file named before it")


def test_a_comma_list_is_read_through(tree):
    tree.edit(MODEL_PAGE, "clientpin.rs:2,4-6", "clientpin.rs:2,400")
    assert only(tree.problems(), "which has 8 lines")


def test_an_explicit_path_is_taken_literally(tree):
    tree.edit(MODEL_PAGE, "firmware/src/main.rs:2", "firmware/src/other.rs:2")
    assert only(tree.problems(), "no such file is in the tree")


def test_an_en_dash_does_not_swallow_the_upper_bound(tree):
    """A smart-dash substitution used to leave a single-line citation that passed."""
    tree.edit(MODEL_PAGE, "state.rs:4-6", "state.rs:4\u20136000")
    assert only(tree.problems(), "which has 8 lines")


def test_a_space_after_the_colon_still_counts(tree):
    tree.edit(MODEL_PAGE, "state.rs:4-6", "state.rs: 6000")
    assert only(tree.problems(), "which has 8 lines")


def test_line_zero_is_not_a_line(tree):
    """It passed both bounds checks and then asserted about `body[-1]`."""
    tree.edit(MODEL_PAGE, "state.rs:4-6", "state.rs:0")
    assert only(tree.problems(), "names line 0")


def test_a_continuation_does_not_bind_across_lines(tree):
    """`seen` used to live for a whole page, so a bare `:1` bound to a file named
    hundreds of lines earlier and was silently checked against it."""
    tree.write(
        PROSE_PAGE,
        (tree.root / PROSE_PAGE).read_text() + "\nA later sentence: `:1`.\n",
    )
    assert only(tree.problems(), "with no file named before it")


def test_an_unregistered_ambiguous_basename(tree):
    """First-hit-wins re-points every citation of a name, silently and page-wide."""
    tree.write("crates/rsk-device/src/state.rs", "one line\n")
    assert only(tree.problems(), "search directories")


def test_a_registered_ambiguous_basename_is_allowed(tree):
    """The one the model means, with the measurement, so the pick is reviewable."""
    tree.write("crates/rsk-device/src/clientpin.rs", "one line\n")
    was = dict(citation_gate.AMBIGUOUS)
    citation_gate.AMBIGUOUS["clientpin.rs"] = ("crates/rsk-fido/src/clientpin.rs", "measured")
    try:
        assert tree.problems() == []
    finally:
        citation_gate.AMBIGUOUS.clear()
        citation_gate.AMBIGUOUS.update(was)


def test_a_page_that_is_gone(tree):
    (tree.root / PROSE_PAGE).unlink()
    assert only(tree.problems(), "is gone; the model")


# --- the cases that must stay green -------------------------------------------


def test_an_edit_below_every_cited_line(tree):
    """The false alarm that would get this row switched off inside a week."""
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub fn spend() {}", "pub fn spend() {\n    // work\n}")
    assert tree.problems() == []


def test_an_edit_inside_a_cited_line(tree):
    """Content is a review question; this row asks about bounds, not meaning."""
    tree.edit("crates/rsk-fido/src/clientpin.rs", "RETRIES: u8 = 8", "RETRIES: u8 = 3")
    assert tree.problems() == []


def test_a_same_named_file_outside_the_search_path_is_not_picked(tree):
    """`crates/rsk-openpgp/src/state.rs` is not what a FIDO model means."""
    tree.write("crates/rsk-openpgp/src/state.rs", "one line\n")
    assert tree.problems() == []


def test_a_same_named_file_in_a_second_search_directory_is_reported(tree):
    """Not silently resolved by order: the pick has to be written down."""
    tree.write("firmware/src/state.rs", "one line\n")
    assert only(tree.problems(), "search directories")


# --- the debt this row landed with --------------------------------------------


def test_a_pending_entry_carries_its_citation(tree):
    debt = {"state.rs:4-600": "someone else's to re-point"}
    tree.edit(MODEL_PAGE, "state.rs:4-6", "state.rs:4-600")
    assert tree.problems(pending=debt) == []


def test_a_pending_entry_that_no_longer_rots(tree):
    """It ends when the citation is fixed, rather than living on as a carve-out."""
    debt = {"state.rs:4-600": "someone else's to re-point"}
    assert only(tree.problems(pending=debt), "no longer rots; delete the entry")


# --- the guard's own blind spots ----------------------------------------------


def test_a_page_that_stopped_citing(tree):
    """A regex that matches nothing loops over nothing and exits 0."""
    tree.write(MODEL_PAGE, "---- MODULE Probe ----\n====\n")
    assert only(tree.problems(), "under the floor")


def test_a_search_directory_that_moved(tree):
    """The list is hand-written, so a renamed crate has to be loud."""
    (tree.root / "crates/rsk-usb/src/ctaphid.rs").unlink()
    (tree.root / "crates/rsk-usb/src").rmdir()
    (tree.root / "crates/rsk-usb").rmdir()
    assert only(tree.problems(), "is in SEARCH but is not a directory")


def test_the_real_floor_is_met_by_the_real_pages():
    """The fixture lowers it; nothing else may. Each page clears its OWN floor —
    the default, or its `FLOOR_BY_PAGE` override where it has one."""
    for page in citation_gate.PAGES:
        text = (citation_gate.ROOT / page).read_text()
        assert len(list(citation_gate.citations(text))) >= citation_gate.floor_for(page)


def test_a_per_page_floor_is_honoured_and_is_lower_than_the_default():
    """The override exists because the flash-layer model is a tight one; a page
    with an override takes it, and it is strictly under the default so it can only
    ever RELAX the floor, never tighten one silently."""
    store = _page("RSKeyStore.tla")
    default_page = _page("RSKeySecurityState.tla")
    assert citation_gate.floor_for(store) == citation_gate.FLOOR_BY_PAGE["RSKeyStore.tla"]
    assert citation_gate.floor_for(store) < citation_gate.FLOOR
    assert citation_gate.floor_for(default_page) == citation_gate.FLOOR


# --- the guard's own wiring ---------------------------------------------------


def test_check_sh_still_runs_the_guard():
    check = (citation_gate.ROOT / "scripts/check.sh").read_text()
    assert "scripts/citation_gate.py" in check


def test_the_tests_are_named_after_the_guard():
    """`check.sh` collects `scripts` wholesale, so the name is the registration."""
    here = pathlib.Path(__file__).name
    assert here == f"test_{pathlib.Path(citation_gate.__file__).stem}.py"
