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
import gate_lines

CODE = """// SPDX-License-Identifier: AGPL-3.0-only
pub const RETRIES: u8 = 8;

pub fn judge(byte: u8) -> bool {
    byte < 0x80
}
/// Refines `RSKeySecurityState!NoDrift` — SEC-T-001.
pub fn spend() {}
"""

UNTAGGED_CODE = CODE.replace(
    "/// Refines `RSKeySecurityState!NoDrift` — SEC-T-001.",
    "// no property owner in this fixture file",
)

MODEL = """---- MODULE Probe ----
VARIABLES
    pin,   \\* EF_PIN (clientpin.rs:2)
    tok    \\* the grant (state.rs:4-6)

\\* the spend latch (clientpin.rs:8), the firmware half (firmware/src/main.rs:2)
\\* and a list, clientpin.rs:2,4-6
NoDrift == TRUE
====
"""

PROPERTIES = """\
[[property]]
id = "SEC-T-001"
name = "NoDrift"
status = "MODELLED-ONLY"
statement = "The fixture does not drift."
source = ["fixture"]
"""

#: Every page `PAGES` names that a case does not drive. It has to clear the
#: citation FLOOR, because a page that cites nothing is itself a problem.
STUB = """\\* a page this case does not drive (clientpin.rs:2, clientpin.rs:4-6)
"""

#: The same stub for a `PATHS_ONLY` page, which may not write a bare name.
PATH_STUB = """\\* a page this case does not drive
\\* (crates/rsk-fido/src/clientpin.rs:2, crates/rsk-fido/src/clientpin.rs:4-6)
"""

#: A CODE page: a proof header citing the code it drives. It is in the page set
#: because it CITES, not because a tuple names it — which is what makes the
#: silent source file below not a page at all. `lib.rs` is written into two
#: SEARCH roots deliberately: the bare name is ambiguous tree-wide, and the
#: sibling rule is what decides it for a page that is itself code.
PROOF = """// SPDX-License-Identifier: AGPL-3.0-only
//! The gate this proof drives (`clientpin.rs:4-6`), reproduced against the
//! crate root's own dispatch (`lib.rs:4-6`).
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


#: A `scripts/` page: host tooling making the same model→code claim a proof
#: header does. `security_trace.py` names the two predicates its recorder stands
#: in for, and both of them were wrong the day this half was added.
SCRIPT = """# SPDX-License-Identifier: AGPL-3.0-only
# The gate this recorder stands in for (`clientpin.rs:4-6`).
"""

#: A KEYED table: rows with names, under comment lines that move. Both anchors a
#: bundle can write — a line and a row key — point into this one file, which is
#: what lets the two be measured against the same edit.
FLOORS = """\\* WHAT EACH CONFIGURATION MUST PRODUCE, so a run nobody watched cannot
\\* pass by getting smaller.
\\* Columns: <config or glob>  <GREEN|RED>  <min distinct, or - >
Shipped.cfg                          GREEN   25854624
Solo_*.cfg                           RED     -
"""

#: The second KEYED table, and the harder one: its rows are named with SPACES in
#: them and they move whenever a row lands above them — three did in one session.
#: Both helpers that print a row are here, because both name it with `$1`.
CHECK = """#!/usr/bin/env bash
run() { echo; echo "== $1 =="; shift; "$@"; }
# a comment line, which is where a relock once parked a citation
run "formal citations"         python scripts/citation_gate.py
run "comutants lint"           python scripts/comutate.py --lint
run_tests "test (host)"        cargo test --workspace
"""

#: An evidence bundle: it cites code by line and the verdict table by ROW, which
#: is the pair the six repaired citations are about. In the corpus because the
#: directory holds it, not because a tuple names it. The second block writes the
#: SAME row two ways — by key and by line — so one insertion measures both, and
#: it writes the key TOML-escaped, which is how a basic string carries a quote.
BUNDLE = """\
[[method]]
artifact = "Solo_Probe.cfg"
reading = "the gate this row drives (`clientpin.rs:4-6`), and the verdict the runner holds\
 it to: formal/floors.txt:Solo_*.cfg gives the family `RED -` with no invariant column"

[[method]]
artifact = "comutants"
reading = "the row that lints the roster, by NAME because rows move: \
scripts/check.sh:\\"comutants lint\\" runs on every gate, and the same row written \
as a line is scripts/check.sh:5"
"""

#: An assurance REGISTRY, and the fourth derived half. It makes a bundle's kind
#: of claim one directory up, which is the whole of the roster rule: the bundles
#: are read by a half of their own, so a page read twice would report every rot
#: in them twice and orphan nothing when one half stopped finding it.
REGISTRY = """\
[[record]]
id = "PLAT-T-001"
statement = "the platform half the model leans on"
discharge = "the gate this row stands on (`clientpin.rs:4-6`), and the retry \
budget it is priced against at clientpin.rs:2"
"""

#: The derived page every code-half case drives.
PROOF_PAGE = "crates/rsk-fido/src/probe_kani.rs"

#: The derived page every scripts-half case drives, and one the exemption covers.
SCRIPT_PAGE = "scripts/probe_trace.py"
EXEMPT_PAGE = "scripts/citation_gate.py"

#: The derived page every bundle-half case drives, and the table it cites.
BUNDLE_PAGE = "assurance/bundle/SEC-T-001.toml"
FLOORS_PAGE = "formal/floors.txt"
CHECK_PAGE = "scripts/check.sh"

#: The derived page every registry-half case drives, and the registry that cites
#: NOTHING — the control that separates this half's rule from the bundles'.
REGISTRY_PAGE = "assurance/platform.toml"
SILENT_REGISTRY = "assurance/properties.toml"

MODEL_PAGE = _page("RSKeySecurityState.tla")
PROSE_PAGE = _page("README.md")


class Tree:
    """A checkout the model can cite: two applet files, a firmware, two pages."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-fido/src/clientpin.rs", CODE)
        self.write("crates/rsk-fido/src/state.rs", UNTAGGED_CODE)
        self.write("crates/rsk-fido/src/lib.rs", UNTAGGED_CODE)
        self.write(PROOF_PAGE, PROOF)
        self.write(SCRIPT_PAGE, SCRIPT)
        self.write(EXEMPT_PAGE, SCRIPT)
        self.write(FLOORS_PAGE, FLOORS)
        self.write(CHECK_PAGE, CHECK)
        self.write(BUNDLE_PAGE, BUNDLE)
        self.write(REGISTRY_PAGE, REGISTRY)
        self.write("crates/rsk-device/src/ctap.rs", UNTAGGED_CODE)
        self.write("crates/rsk-usb/src/ctaphid.rs", UNTAGGED_CODE)
        self.write("crates/rsk-fs/src/lib.rs", UNTAGGED_CODE)
        self.write("firmware/src/main.rs", UNTAGGED_CODE)
        for page in citation_gate.PAGES:
            self.write(page, PATH_STUB if page.name in citation_gate.PATHS_ONLY else STUB)
        self.write(MODEL_PAGE, MODEL)
        self.write(PROSE_PAGE, PAGE)
        self.write("assurance/properties.toml", PROPERTIES)
        self.write(
            "formal/Shipped.cfg",
            "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    NoDrift\n",
        )
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

    def lock(self):
        """Lock the citations as they stand — the state a case then perturbs."""
        self.problems(relock=True)

    def run(self, monkeypatch):
        """The exit code `check.sh`'s row takes, not `audit`'s list.

        A guard is falsified through the row that runs it: `main()` is what
        `python scripts/citation_gate.py` calls, and a clause whose finding never
        reaches an exit code is one the gate cannot go red on.
        """
        monkeypatch.setattr(citation_gate, "ROOT", self.root)
        monkeypatch.setattr(citation_gate.sys, "argv", ["citation_gate.py"])
        monkeypatch.setattr(citation_gate, "FLOOR", 2)
        monkeypatch.setattr(citation_gate, "PENDING", {})
        monkeypatch.setattr(citation_gate, "FLOOR_BY_PAGE", {})
        return citation_gate.main()

    def problems(self, floor=2, pending=None, relock=False, buried=False):
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
            if buried:
                return citation_gate.relock_report(self.root)
            return citation_gate.audit(self.root, relock=relock)[0]
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


# --- phase-1 property tags, both directions ---------------------------------


def test_a_tag_that_points_to_no_registry_row_fails(tree):
    tree.edit(
        "crates/rsk-fido/src/clientpin.rs",
        "SEC-T-001",
        "SEC-T-666",
    )
    assert only(tree.problems(), "id not in the registry")


def test_an_owner_invariant_without_a_production_tag_fails(tree):
    tree.edit(
        "crates/rsk-fido/src/clientpin.rs",
        "/// Refines `RSKeySecurityState!NoDrift` — SEC-T-001.",
        "// property tag removed",
    )
    assert only(tree.problems(), "checked by Shipped.cfg but has no Refines tag")


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
    assert gate_lines.runs(check, "scripts/citation_gate.py")


def test_the_tests_are_named_after_the_guard():
    """`check.sh` collects `scripts` wholesale, so the name is the registration."""
    here = pathlib.Path(__file__).name
    assert here == f"test_{pathlib.Path(citation_gate.__file__).stem}.py"


# --- the lock: drift is decidable, an edit in place is not --------------------


def test_a_citation_that_drifted_onto_another_line(tree):
    """The failure this row shipped without: 75 citations rotted while it said ok."""
    tree.lock()
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub const RETRIES", "// pushed down\npub const RETRIES")
    found = only(tree.problems(), "drifted")
    assert found, tree.problems()
    assert "is now at :3" in found[0], found[0]


def test_an_edit_inside_a_cited_line_still_passes_under_the_lock(tree):
    """The false alarm that would get this row switched off: nothing moved."""
    tree.lock()
    tree.edit("crates/rsk-fido/src/clientpin.rs", "RETRIES: u8 = 8", "RETRIES: u8 = 3")
    assert tree.problems() == []


def test_an_edit_below_every_cited_line_still_passes_under_the_lock(tree):
    tree.lock()
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub fn spend() {}", "pub fn spend() {\n    // work\n}")
    assert tree.problems() == []


def test_a_citation_the_lock_does_not_carry(tree):
    tree.lock()
    tree.write(PROSE_PAGE, PAGE + "\nand also `clientpin.rs:2`\n")
    assert only(tree.problems(), "is not in")


def test_a_lock_entry_nothing_cites_any_more(tree):
    tree.lock()
    tree.write(PROSE_PAGE, "# The model\n\n`clientpin.rs:2` · `clientpin.rs:4-6`\n")
    assert only(tree.problems(), "still locks")


def test_no_lock_file_means_no_lock_rules(tree):
    """A tree that was never locked is not lying; the real-tree case below is
    what keeps the file from being deleted to silence this."""
    assert not (tree.root / citation_gate.LOCK).exists()
    assert tree.problems() == []


def test_relock_writes_a_line_per_citation(tree):
    tree.lock()
    body = [
        l for l in (tree.root / citation_gate.LOCK).read_text().splitlines()
        if l and not l.startswith("#")
    ]
    assert body and all(len(l.split("\t")) == 5 for l in body)


# --- the pages that must write a path ----------------------------------------


#: Every `PATHS_ONLY` page, not the first one `PAGES` happens to hold. `next()`
#: is positional selection wearing a filter: `RSKeyAppletPolicies.tla` landing
#: ahead of `comutants.toml` re-pointed both cases below at a different page and
#: neither said so — the same silent move the `_page` helper above exists for.
def _paths_only_pages():
    pages = [p for p in citation_gate.PAGES if p.name in citation_gate.PATHS_ONLY]
    assert pages, "no PATHS_ONLY page is in PAGES, so neither case below asserts"
    return pages


def test_a_bare_name_on_a_paths_only_page(tree):
    for page in _paths_only_pages():
        tree.write(page, "note = \"a bare one: clientpin.rs:2, clientpin.rs:4-6\"\n")
        assert only(tree.problems(), "must write a repo path"), page
        tree.write(page, PATH_STUB)


def test_a_path_on_a_paths_only_page_is_fine(tree):
    for page in _paths_only_pages():
        tree.write(page, PATH_STUB)
    assert tree.problems() == []


# --- the real checkout --------------------------------------------------------


def test_the_real_lock_covers_every_real_citation():
    """Deleting the lock would switch the drift rule off silently; this is what
    stops that, since `audit` cannot tell a deleted lock from a fresh tree."""
    problems, _ = citation_gate.audit(citation_gate.ROOT)
    assert (citation_gate.ROOT / citation_gate.LOCK).is_file()
    assert not [p for p in problems if "is not in" in p or "still locks" in p]


# --- the two defects the row's own falsification run exposed ------------------

#: A file whose cited line is NOT unique: `pub fn spend() {}` reads the same at
#: :2 and :8, which is the shape that made the first report name the wrong one.
DUPE_CODE = """// SPDX-License-Identifier: AGPL-3.0-only
pub fn spend() {}
pub const RETRIES: u8 = 8;
pub fn judge(byte: u8) -> bool {
    byte < 0x80
}
/// Refines `RSKeySecurityState!NoDrift` — SEC-T-001.
pub fn spend() {}
"""


def test_drift_names_the_nearest_line_not_the_first(tree):
    """`pub fn reset(&mut self) {` is in the real state.rs three times, and
    first-match sent a reader to :98 for a citation that had moved to :428."""
    tree.write("crates/rsk-fido/src/clientpin.rs", DUPE_CODE)
    tree.lock()
    tree.edit("crates/rsk-fido/src/clientpin.rs", "// SPDX-License-Identifier: AGPL-3.0-only", "// SPDX-License-Identifier: AGPL-3.0-only\n// pushed everything down")
    drift = [p for p in tree.problems() if "drifted" in p and "`clientpin.rs:8`" in p]
    assert drift, tree.problems()
    assert "is now at :9" in drift[0], drift[0]
    assert "other line(s) read the same" in drift[0], drift[0]


def test_a_citation_that_trips_another_rule_is_not_also_an_orphaned_lock(tree):
    """One cause must not wear two messages: the blank-line rule fires, and the
    lock reconciliation used to report the same citation as uncited as well."""
    tree.lock()
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub const RETRIES: u8 = 8;", "   ")
    problems = tree.problems()
    assert only(problems, "cited line is blank"), problems
    assert only(problems, "still locks") == [], problems


# --- the code half: derived from the tree, not transcribed --------------------


def code_pages_of(tree):
    """`audit`'s own `tracked` set, widened suffixes and all.

    It filtered `.rs` here for a while, which is the set `code_pages` is supposed
    to narrow — so the helper was doing the rule's job and hiding it. Measured:
    deleting the suffix test inside `code_pages` left every case in this file
    green.
    """
    tracked = {
        str(rel)
        for rel in gate_lines.tree_files(tree.root)
        if rel.suffix.lstrip(".") in citation_gate.EXTS.split("|")
    }
    return [str(page) for page in citation_gate.code_pages(tree.root, tracked)]


def script_pages_of(tree):
    return [str(page) for page in citation_gate.script_pages(tree.root)]


def test_the_derivation_finds_a_proof_header_and_only_a_citing_file(tree):
    """A `.rs` file that cites nothing cannot fail this row — which is what keeps
    it off the back of every contributor who never writes a citation."""
    tree.write("crates/rsk-fido/src/quiet.rs", "// nothing is cited here\n")
    found = code_pages_of(tree)
    assert PROOF_PAGE in found, found
    assert "crates/rsk-fido/src/quiet.rs" not in found, found
    assert tree.problems() == []


def test_a_rotted_citation_in_a_proof_header_is_found(tree):
    """The measured hole: 19 of the tree's 42 code citations named something the
    surrounding prose was never about, while this row printed `ok`."""
    tree.edit(PROOF_PAGE, "clientpin.rs:4-6", "clientpin.rs:3-6")
    assert only(tree.problems(), "cited line is blank")


def test_relock_names_the_drift_it_is_about_to_bury(tree):
    """`--relock` is the laundering step, and it used to print one line.

    That is not a hypothetical: eight `RSKeyTransport.tla` citations were re-locked
    at their new lines with the page left saying the old thing, and this row read
    `ok` over it. The relock still succeeds — it is a record, not a judge — but it
    now names what it buried. Drive both halves: the rewrite is silent, the report
    is not.
    """
    tree.lock()
    tree.edit(
        "crates/rsk-fido/src/clientpin.rs",
        "// SPDX-License-Identifier: AGPL-3.0-only\n",
        "// SPDX-License-Identifier: AGPL-3.0-only\n// inserted\n// inserted\n",
    )
    assert only(tree.problems(), "has drifted"), "the fixture did not drift"
    buried = tree.problems(buried=True)
    assert only(buried, "has drifted"), buried
    assert any(str(MODEL_PAGE) in problem for problem in buried), buried
    # And the rewrite itself stays quiet, which is why the report has to exist.
    assert tree.problems(relock=True) == []


def test_relock_names_a_citation_the_lock_has_never_seen(tree):
    """The second family `LAUNDERED` covers: a NEW citation is locked unread."""
    tree.lock()
    tree.edit(MODEL_PAGE, "NoDrift == TRUE", "\\* and one more (state.rs:2)\nNoDrift == TRUE")
    buried = tree.problems(buried=True)
    assert only(buried, "is not in"), buried


# --- the evidence bundles: the third derived half ----------------------------


def bundle_pages_of(tree):
    return [str(page) for page in citation_gate.bundle_pages(tree.root)]


def test_the_bundle_roster_is_the_directory(tree):
    """A bundle is a page because the directory holds it. Named rosters are how
    the twelfth bundle would arrive with every citation in it unread."""
    tree.write("assurance/bundle/SEC-T-002.toml", BUNDLE)
    found = bundle_pages_of(tree)
    assert BUNDLE_PAGE in found and "assurance/bundle/SEC-T-002.toml" in found, found
    # And a bundle that cites NOTHING is still a page: `bundle_gate.py` holds this
    # directory to an evidence contract, so citing nothing is a finding, not an
    # opt-out — unlike the `.rs` and `.py` halves, which are in the set BECAUSE
    # they cite.
    tree.write("assurance/bundle/SEC-T-003.toml", 'note = "no citation here"\n')
    assert "assurance/bundle/SEC-T-003.toml" in bundle_pages_of(tree)


def test_a_bundle_citation_past_the_end_of_the_file(tree):
    """The whole class, before the widening: 517 citations over the eleven bundles
    of that day, and not one of them reachable from any gate."""
    tree.edit(BUNDLE_PAGE, "clientpin.rs:4-6", "clientpin.rs:4-600")
    assert only(tree.problems(), "which has 8 lines")


def test_a_bundle_row_citation_that_names_a_comment(tree):
    """The live defect, in its own shape: all six named a `\\*` COMMENT where the
    sentence was about a data row. A key is looked up in the row column, and
    comments are not in it."""
    tree.edit(BUNDLE_PAGE, "formal/floors.txt:Solo_*.cfg", "formal/floors.txt:Columns")
    assert only(tree.problems(), "names no row of formal/floors.txt")


def test_a_keyed_tables_comment_lines_are_not_rows():
    """`rows_of` reads the column `run-tlc.sh`'s own `expect_for` matches on, and
    that reader skips `\\*` and `#`. Without the skip a comment's first word is a
    row key, and a citation that names one reads as resolved."""
    rows = citation_gate.rows_of(FLOORS, citation_gate.KEYED[FLOORS_PAGE])
    assert rows == {"Shipped.cfg", "Solo_*.cfg"}, rows


def test_a_bundle_row_citation_whose_row_was_renamed(tree):
    tree.edit(FLOORS_PAGE, "Solo_*.cfg  ", "SoloWide_*.cfg  ")
    assert only(tree.problems(), "names no row of formal/floors.txt")


def test_a_row_citation_into_a_file_the_tree_does_not_have(tree):
    (tree.root / FLOORS_PAGE).unlink()
    assert only(tree.problems(), "no such file is in the tree")


def test_the_line_form_cannot_tell_a_comment_from_a_data_row(tree):
    """WHY the anchor is the key, measured rather than argued: the same wrong
    target written as a LINE resolves, is in range and is not blank, so every rule
    this guard has passes it. This is the arm that decided the repair."""
    tree.edit(BUNDLE_PAGE, "formal/floors.txt:Solo_*.cfg", "formal/floors.txt:2")
    assert tree.problems() == []


def test_deleting_the_bundle_half_is_caught_by_its_own_floor(tree, monkeypatch):
    """The derivation pointed somewhere the tree has nothing: a loop over an empty
    set exits 0, which is the shape four guards in this tree shipped with."""
    monkeypatch.setattr(citation_gate, "BUNDLE_ROOT", "assurance/no-bundles-here/")
    assert only(tree.problems(), "under the floor of 1")


def test_the_bundle_half_is_what_reads_a_bundles_citations(tree, monkeypatch):
    """The guard-deletion arm: take the pages out AND the floor that notices, the
    way a deletion actually happens, and the bad citation above is green again.
    That is what says the widening is load-bearing rather than decorative."""
    tree.edit(BUNDLE_PAGE, "clientpin.rs:4-6", "clientpin.rs:4-600")
    assert only(tree.problems(), "which has 8 lines")
    monkeypatch.setattr(citation_gate, "bundle_pages", lambda root: ())
    monkeypatch.setattr(citation_gate, "BUNDLE_PAGES_FLOOR", 0)
    assert tree.problems() == []


# --- the assurance registries: the fourth derived half ------------------------


def registry_pages_of(tree):
    return [str(page) for page in citation_gate.assurance_pages(tree.root)]


def test_the_registry_roster_is_the_directory_less_the_bundles(tree):
    """A registry is a page because it CITES and the directory holds it, and the
    bundles are excluded because a half of their own already reads them."""
    tree.write("assurance/board/PLAT-T-002.toml", REGISTRY)
    found = registry_pages_of(tree)
    assert REGISTRY_PAGE in found, found
    assert "assurance/board/PLAT-T-002.toml" in found, found
    assert BUNDLE_PAGE not in found, found


def test_a_registry_that_cites_nothing_is_not_a_page(tree):
    """The rule the bundles one directory over do NOT have, and the reason the two
    halves are separate. `bundle_gate.py` holds every bundle to a per-row evidence
    contract, so a bundle citing nothing is a finding; a registry of property tags
    names no line of Rust at all, and a floor over it would demand one."""
    assert (tree.root / SILENT_REGISTRY).is_file()
    assert SILENT_REGISTRY not in registry_pages_of(tree)


def test_a_rotted_registry_citation_past_the_end_of_the_file(tree):
    """The DEFECT arm, in the shape the widening actually found: three of the four
    live findings were a span running off the end of the file it named."""
    tree.edit(REGISTRY_PAGE, "clientpin.rs:4-6", "clientpin.rs:4-600")
    assert only(tree.problems(), "which has 8 lines")


def test_a_registry_citation_landing_on_a_blank_line(tree):
    """The fourth live finding: `scripts/kani_gate.py:524-553` for a reader that
    had moved, whose span now opens on a blank line. It is the drift signal that
    costs nothing, and it is what a bounds check alone cannot see."""
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub const RETRIES", "\npub const RETRIES")
    assert only(tree.problems(), "whose cited line is blank")


def test_a_bare_continuation_in_a_registry_binds_within_its_paragraph(tree):
    """The rot this half found three times over, and the reason it is worth
    gating: a bare `:824` written for a `.tla` module resolves against the last
    `.rs` file its paragraph named, because the reader cannot see a `.tla` at all.
    Nothing distinguishes a mis-bound continuation from a correct one except the
    line it lands on, so the bound is the whole check."""
    tree.edit(REGISTRY_PAGE, "at clientpin.rs:2", "at clientpin.rs:2 and `:900`")
    assert only(tree.problems(), "which has 8 lines")


def test_deleting_the_registry_half_is_caught_by_its_own_floor(tree, monkeypatch):
    """The derivation pointed somewhere the tree has nothing: a loop over an empty
    set exits 0, which is the shape four guards in this tree shipped with."""
    monkeypatch.setattr(citation_gate, "ASSURANCE_ROOT", "assurance-no-registries/")
    assert only(tree.problems(), "under the floor of 1")


def test_the_registry_half_is_what_reads_a_registrys_citations(tree, monkeypatch):
    """The REMOVAL arm: take the pages out AND the floor that notices, the way a
    deletion actually happens, and the bad citation above is green again. That is
    what says the widening is load-bearing rather than decorative."""
    tree.edit(REGISTRY_PAGE, "clientpin.rs:4-6", "clientpin.rs:4-600")
    assert only(tree.problems(), "which has 8 lines")
    monkeypatch.setattr(citation_gate, "assurance_pages", lambda root: ())
    monkeypatch.setattr(citation_gate, "ASSURANCE_PAGES_FLOOR", 0)
    assert tree.problems() == []


def test_the_registry_half_reaches_the_rows_exit_code(tree, monkeypatch):
    """A guard is falsified through the row that runs it. `main()` is what
    `python scripts/citation_gate.py` calls, and a half whose findings never reach
    an exit code is one the gate cannot go red on."""
    assert tree.run(monkeypatch) == 0
    tree.edit(REGISTRY_PAGE, "clientpin.rs:4-6", "clientpin.rs:4-600")
    assert tree.run(monkeypatch) == 1


def test_a_drifted_registry_citation_is_named_at_its_new_line(tree):
    """The failure the bounds rules cannot see, on the new half: a cited line that
    MOVED is still in the file, in range and not blank, so every other rule passes
    it. Only [`LOCK`] finds it, and 75 citations rotted exactly this way across
    three commits while the row printed `ok`."""
    tree.lock()
    tree.edit("crates/rsk-fido/src/clientpin.rs", "pub fn judge", "// one line above\npub fn judge")
    drifted = only(tree.problems(), "the citation has drifted")
    assert [p for p in drifted if p.startswith(REGISTRY_PAGE)], drifted


def test_the_summary_counts_the_registries_apart_from_the_bundles(tree):
    """Two halves reported as one number cannot say which stopped finding — the
    argument each derived floor is kept separate for, one line up."""
    summary = citation_gate.audit(tree.root)[1]
    assert "1 evidence bundles and 1 assurance registries resolve" in summary, summary


# --- the control: the exact motion that rotted the six ------------------------


def test_a_comment_inserted_above_a_cited_ROW_stays_green(tree):
    """Two of the six were re-anchored by hand one morning and rotted again the
    same day, because `floors.txt` gained three comment lines. A key does not
    move, so this edit is a non-event — which is the point of the row form."""
    tree.lock()
    tree.edit(FLOORS_PAGE, "Shipped.cfg", "\\* one more comment line\nShipped.cfg")
    assert tree.problems() == []


def test_the_same_insertion_moves_a_LINE_citation(tree):
    """The control's twin, and the measurement behind [`KEYED`]: written as a
    line, that same comment turns the row red and buys a hand re-anchor. Both are
    recorded because the choice between them is what this pair decides."""
    tree.edit(BUNDLE_PAGE, "formal/floors.txt:Solo_*.cfg", "formal/floors.txt:5")
    tree.lock()
    tree.edit(FLOORS_PAGE, "Shipped.cfg", "\\* one more comment line\nShipped.cfg")
    drift = only(tree.problems(), "has drifted")
    assert drift, tree.problems()
    assert "is now at :6" in drift[0], drift[0]


# --- the second keyed table: rows whose names have spaces ---------------------


def test_a_check_row_citation_resolves_by_its_name(tree):
    """The control. A row is named by the first argument of either helper that
    prints one, which is the string the runner puts in the log; the bundle writes
    it TOML-escaped, because that is how a basic string carries a quote."""
    rows = citation_gate.rows_of(CHECK, citation_gate.KEYED[CHECK_PAGE])
    assert rows == {"formal citations", "comutants lint", "test (host)"}, rows
    assert tree.problems() == []


def test_a_check_row_citation_that_names_no_row(tree, monkeypatch):
    """The first rule, driven through the ROW that runs it and not just the
    function: a key nothing in the file answers to has to reach an exit code."""
    tree.edit(BUNDLE_PAGE, 'check.sh:\\"comutants lint\\"', 'check.sh:\\"comutants lynt\\"')
    assert only(tree.problems(), "names no row of scripts/check.sh")
    assert tree.run(monkeypatch) == 1


def test_two_rows_answering_to_the_same_name(tree, monkeypatch):
    """The second rule, and it is asked of the TABLE rather than of the citations:
    a key two rows answer to anchors nothing, the way a basename in two SEARCH
    directories does. So it is a finding in a commit that cites neither."""
    tree.edit(CHECK_PAGE, 'run "formal citations"', 'run "comutants lint"')
    assert only(tree.problems(), "has 2 rows named `comutants lint`")
    assert tree.run(monkeypatch) == 1


def test_a_row_landing_above_a_cited_one_moves_only_the_LINE_form(tree):
    """The measurement that bought this entry, in the motion that produced it: one
    bundle's three citations of the `comutants lint` row went 725 → 772 → 785 over
    two commits in a day, and the relock in between recorded a neighbouring
    COMMENT for two of them. The same row is cited both ways here, so one
    insertion measures both anchors against the same edit."""
    tree.lock()
    tree.edit(
        CHECK_PAGE,
        'run "comutants lint"',
        'run "new row"                  true\nrun "comutants lint"',
    )
    drift = only(tree.problems(), "has drifted")
    assert len(drift) == 1, tree.problems()
    assert CHECK_PAGE in drift[0] and "is now at :6" in drift[0], drift[0]


def test_the_line_form_into_a_keyed_file_is_not_weakened(tree):
    """Adding a file to [`KEYED`] may not retire the line form into it, and the
    tree has a citation that needs it: `assurance/platform.toml`'s
    `scripts/check.sh:174-223` is a FUNCTION BODY, which is no row and has no key
    to name."""
    tree.edit(BUNDLE_PAGE, "scripts/check.sh:5", "scripts/check.sh:500")
    assert only(tree.problems(), "which has 6 lines")


def test_a_keyed_file_the_tree_no_longer_carries(tree, monkeypatch):
    """The rule [`SEARCH`] already has, one table over. An entry pointing at
    nothing checks nothing, and no citation has to exist for that to be true."""
    (tree.root / CHECK_PAGE).unlink()
    assert only(tree.problems(), "is in KEYED but the tree does not carry it")
    assert tree.run(monkeypatch) == 1


def test_deleting_the_entry_takes_both_of_its_findings_with_it(tree, monkeypatch):
    """The guard-deletion arm, done the way a deletion actually happens: the entry
    AND the pattern built from it. Both findings above go green, which is what
    says the entry is load-bearing rather than decorative — and it is why [`ROW`]
    is built by a function instead of written out beside the table."""
    tree.edit(BUNDLE_PAGE, 'check.sh:\\"comutants lint\\"', 'check.sh:\\"comutants lynt\\"')
    tree.edit(CHECK_PAGE, 'run "formal citations"', 'run "comutants lint"')
    assert len(tree.problems()) == 2, tree.problems()
    monkeypatch.setattr(
        citation_gate, "KEYED", {FLOORS_PAGE: citation_gate.KEYED[FLOORS_PAGE]}
    )
    monkeypatch.setattr(citation_gate, "ROW", citation_gate.row_pattern(citation_gate.KEYED))
    assert tree.problems() == []


# --- the widened extension set ------------------------------------------------


def test_a_shell_citation_is_read(tree):
    """`.sh` beside `.rs`: the bundles cite the RUNNER as finely as the firmware,
    and `formal/run-tlc.sh:231-234` is the derivation a reason-comparison argument
    rests on. The `.rs`-only group saw none of them."""
    tree.write("formal/run-tlc.sh", "#!/usr/bin/env bash\nderived_inv() { :; }\n")
    tree.edit(BUNDLE_PAGE, "clientpin.rs:4-6", "formal/run-tlc.sh:2")
    assert tree.problems() == []
    tree.edit(BUNDLE_PAGE, "formal/run-tlc.sh:2", "formal/run-tlc.sh:20")
    assert only(tree.problems(), "which has 2 lines")


def test_a_shell_page_is_not_a_code_page(tree):
    """`code_pages` asserts the `.rs` suffix itself rather than inheriting it from
    `tracked`, which now carries every suffix `CITE` can NAME. Without that a
    `tools/*.sh` that cites becomes a proof header by side effect."""
    tree.write("tools/probe.sh", "# cites (`clientpin.rs:4-6`)\n")
    assert "tools/probe.sh" not in code_pages_of(tree)


def test_relock_on_an_unmoved_tree_buries_nothing(tree):
    """The CONTROL. A report that fires on a quiet tree is one nobody reads."""
    tree.lock()
    assert tree.problems(buried=True) == []
    assert tree.problems() == []


def test_a_moved_citation_in_a_proof_header_is_found(tree):
    """The lock reaches the code half too, which is what ratchets it: a page that
    stops being read turns every entry it had into an orphan."""
    tree.lock()
    tree.edit(
        "crates/rsk-fido/src/clientpin.rs",
        "// SPDX-License-Identifier: AGPL-3.0-only\n",
        "// SPDX-License-Identifier: AGPL-3.0-only\n// inserted\n// inserted\n",
    )
    drifted = only(tree.problems(), "has drifted")
    assert any(PROOF_PAGE in problem for problem in drifted), drifted


def test_the_derivation_reads_a_citing_script_and_only_a_citing_one(tree):
    """`scripts/` was the last substantive citing surface no gate read, and the
    round that added it found three more rotted citations across three files."""
    tree.write("scripts/quiet.py", "# nothing is cited here\n")
    found = script_pages_of(tree)
    assert SCRIPT_PAGE in found, found
    assert "scripts/quiet.py" not in found, found
    assert tree.problems() == []


def test_a_rotted_citation_in_a_script_is_found(tree):
    """The measured hole: `security_trace.py` named `reset.rs:187` for a predicate
    on `:211`, twice, while this row printed `ok`."""
    tree.edit(SCRIPT_PAGE, "clientpin.rs:4-6", "clientpin.rs:3-6")
    assert only(tree.problems(), "cited line is blank")


def test_the_guards_own_fixtures_stay_exempt(tree):
    """`SCRIPT_EXEMPT` is what keeps this row off the files whose citations are
    deliberately broken — this guard's own prose and its mutation table. Without
    it the row cannot be green on any checkout that contains itself."""
    assert EXEMPT_PAGE in citation_gate.SCRIPT_EXEMPT
    assert EXEMPT_PAGE not in script_pages_of(tree)
    tree.edit(EXEMPT_PAGE, "clientpin.rs:4-6", "clientpin.rs:3-6")
    assert tree.problems() == []


def test_a_bare_name_on_a_code_page_resolves_to_its_sibling(tree):
    """`lib.rs` is in two SEARCH roots here. On a page that is itself code the
    author meant the one next to them, and a complaint would be noise."""
    assert (tree.root / "crates/rsk-fido/src/lib.rs").is_file()
    assert (tree.root / "crates/rsk-fs/src/lib.rs").is_file()
    assert tree.problems() == []


def test_the_sibling_never_outranks_the_registry(tree):
    """It used to be taken FIRST, before `hits` was even computed, so on a code
    page a bare name could not raise the ambiguity complaint and could not
    consult [`AMBIGUOUS`] — reintroducing the silent first-hit-wins that registry
    exists to stop, one layer down. As a tie-break it decides only what nothing
    else can."""
    tree.write("crates/rsk-device/src/clientpin.rs", "one line\n")
    tracked = {str(rel) for rel in gate_lines.tree_files(tree.root) if rel.suffix == ".rs"}
    was = dict(citation_gate.AMBIGUOUS)
    citation_gate.AMBIGUOUS["clientpin.rs"] = ("crates/rsk-device/src/clientpin.rs", "measured")
    try:
        # The proof page's OWN directory holds a `clientpin.rs`; the registry says
        # the other one is meant, and the registry wins.
        picked, complaint = citation_gate.resolve("clientpin.rs", tracked, PROOF_PAGE)
        assert picked == "crates/rsk-device/src/clientpin.rs", picked
        assert complaint is None
    finally:
        citation_gate.AMBIGUOUS.clear()
        citation_gate.AMBIGUOUS.update(was)


def test_an_unambiguous_name_needs_no_sibling(tree):
    """One hit in SEARCH is decided before the sibling is even looked at, so the
    rule cannot re-point a name that was never in doubt."""
    tracked = {str(rel) for rel in gate_lines.tree_files(tree.root) if rel.suffix == ".rs"}
    assert citation_gate.resolve("clientpin.rs", tracked, PROOF_PAGE) == (
        "crates/rsk-fido/src/clientpin.rs",
        None,
    )


def test_a_bare_name_on_a_model_page_is_still_reported(tree):
    """`formal/` holds no `.rs`, which is what makes the sibling rule unable to
    reach a model page. Asserted, rather than left as a property of the tree."""
    assert not [p for p in (tree.root / "formal").glob("*.rs")]
    tree.edit(MODEL_PAGE, "clientpin.rs:8", "lib.rs:8")
    assert only(tree.problems(), "search directories")


def test_a_citing_file_under_tools_is_read(tree):
    """`tools/` holds two detached Rust workspaces — 44 first-party `.rs` files
    the first version of this list left out, where a nonsense citation was green."""
    tree.write(
        "tools/emu/src/main.rs",
        "//! Mirrors the dispatch prologue (`clientpin.rs:99999`).\n",
    )
    assert only(tree.problems(), "which has")


def test_an_ordinary_sentence_with_a_backticked_term_is_not_a_citation(tree):
    """Over 13 curated pages "a backtick before it" was enough. Over 450 source
    files `` `LED_PERIOD_MS`: 250 ms `` is English, and the row went red naming a
    citation nobody wrote. Every real continuation is closed by a backtick."""
    tree.write(
        "crates/rsk-fido/src/quiet.rs",
        "//! The blink budget is set by `LED_PERIOD_MS`: 250 ms per phase.\n",
    )
    assert tree.problems() == []


def test_an_upstream_url_with_a_line_anchor_is_not_a_citation(tree):
    """`https://host/a/b/pio.rs:120` used to read as a citation to
    `//host/a/b/pio.rs` — realistic in a crate that references upstream HAL."""
    tree.write(
        "crates/rsk-fido/src/quiet.rs",
        "//! Upstream: https://github.com/e/e/blob/main/src/pio.rs:120\n",
    )
    assert tree.problems() == []


def test_a_source_file_that_is_not_utf8_does_not_end_the_row_in_a_traceback(tree):
    (tree.root / "crates/rsk-fido/src/binary.rs").write_bytes(b"// \xff\xfe not utf-8\n")
    assert tree.problems() == []


def test_a_derivation_that_finds_nothing_trips_the_floor_and_the_lock(tree, monkeypatch):
    """Both signals, because either alone can be argued away: the floor says the
    finder stopped finding, the orphans say what stopped being checked."""
    tree.lock()
    monkeypatch.setattr(citation_gate, "CODE_ROOTS", ("no-such-root/",))
    problems = tree.problems()
    # The derived-set message, not the per-page one — both say "under the floor
    # of", and a case that cannot tell them apart is one fixture edit from noise.
    assert only(problems, "the derivation stopped finding them"), problems
    assert only(problems, "which no longer cites it"), problems


def test_a_scripts_derivation_that_finds_nothing_trips_its_own_floor(tree, monkeypatch):
    """The scripts half gets its own floor for the reason the case above states:
    one number over the union cannot say WHICH finder stopped finding."""
    tree.lock()
    monkeypatch.setattr(citation_gate, "SCRIPT_ROOT", "no-such-root/")
    problems = tree.problems()
    assert only(problems, "the derivation stopped finding them"), problems
    assert only(problems, "which no longer cites it"), problems


def test_a_citing_file_outside_the_code_roots_is_not_read(tree):
    """A named limit, asserted so it stays a decision. `third_party/` is the one
    `.rs` directory left out — a vendored fork's citations are its author's — and
    `CHANGELOG.md`, which cites the tree as it stood at each entry and MUST be
    allowed to rot, is not Rust at all."""
    tree.write(
        "third_party/fork/src/probe.rs",
        "// a citation nothing checks (`clientpin.rs:9999`)\n",
    )
    assert "third_party/fork/src/probe.rs" not in code_pages_of(tree)
    assert tree.problems() == []


# --- the fourth extension: the bundles cite the GATES, and by line ------------


#: A `.py` citation target in the shape the rot actually took: a span that
#: started inside the function it names and ran past its end onto the blank
#: below. Six of the eight rotted `.py` citations in the tree were this.
PY_TARGET = """# SPDX-License-Identifier: AGPL-3.0-only
def check_rows(rows):
    return sorted(rows)

"""


def test_a_rotted_py_citation_in_a_bundle_is_found(tree, monkeypatch):
    """`EXTS` was `rs|sh|txt`, so the 32 `.py:NNN` occurrences the bundles carry
    — 23 distinct, 17 of them naming code their sentence was not about — were not
    parsed, not resolved, not locked and not drift-detectable. Driven through
    `main()`: a finding that never reaches an exit code is one the row cannot go
    red on. Only 6 of the 17 were catchable this mechanically; the rest took a
    reading."""
    tree.write("scripts/probe_gate.py", PY_TARGET)
    tree.edit(BUNDLE_PAGE, "clientpin.rs:4-6", "scripts/probe_gate.py:2-4")
    assert only(tree.problems(), "whose cited line is blank"), tree.problems()
    assert tree.run(monkeypatch) == 1


def test_taking_py_back_out_of_EXTS_stops_catching_it(tree, monkeypatch):
    """The deletion arm, and what says the widening is load-bearing rather than
    decorative: the same rotted citation over the same tree, with `py` out of
    [`EXTS`] and the reader re-derived from it, is not parsed at all. Green, at
    exit 0, over a bundle sending its reader to a blank line."""
    tree.write("scripts/probe_gate.py", PY_TARGET)
    tree.edit(BUNDLE_PAGE, "clientpin.rs:4-6", "scripts/probe_gate.py:2-4")
    monkeypatch.setattr(citation_gate, "EXTS", "rs|sh|txt")
    monkeypatch.setattr(
        citation_gate, "CITE", citation_gate.cite_pattern(citation_gate.EXTS)
    )
    assert tree.problems() == []
    assert tree.run(monkeypatch) == 0


def test_every_extension_in_EXTS_is_read(tree):
    """The non-weakening arm, derived from `EXTS` rather than transcribed: the
    widening ADDS. An edit that swapped an extension out instead would leave
    every citation of it unparsed, and this row green over all of them."""
    for ext in citation_gate.EXTS.split("|"):
        found = list(citation_gate.citations(f"the gate (`probe.{ext}:4-6`)"))
        assert [(c[1], c[2], c[3]) for c in found] == [(f"probe.{ext}", 4, 6)], (
            ext,
            found,
        )
