#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `bounds_gate.py` is verified against.

Every rule is broken once and the break must be the finding it claims to be,
then the real checkout closes the other direction: a guard that cannot go green
is deleted as fast as one that cannot go red.

The fixture is a COPY OF THE REAL BUNDLES rather than a mini-tree, and that is
the point rather than laziness. Every floor here is at this tree's measured count
— 17 bundles, 107 method rows, 541 bounds — so a synthetic tree would be under all
three before a case touched it, and the only way to test a rule would have been
to hand `audit` a smaller floor. That is the shape this tree has already
measured: a ceiling a case patches down is a ceiling whose SHIPPED value is never
exercised. Copying the real bundles means the numbers under test are the numbers
`check.sh` runs with, and a floor is reached by REMOVING evidence, which is the
direction the floor exists for.

The six mutations that motivated the row are all here, each in both spellings —
the bundle moved while the page stood still, and the page moved while the bundle
stood still — because before this row every one of the six was exit 0 on all
eight gates.
"""

import pathlib
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import bounds_gate
import gate_lines

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Tree:
    """The real bundles and the two pages, in a throwaway git checkout."""

    def __init__(self, root):
        self.root = root
        (root / "assurance/bundle").mkdir(parents=True)
        (root / "docs").mkdir(parents=True)
        shutil.copy(ROOT / "assurance/configurations.toml", root / "assurance")
        for src in sorted((ROOT / "assurance/bundle").glob("*.toml")):
            shutil.copy(src, root / "assurance/bundle" / src.name)
        for rel in ("docs/authorization-slice.md", "docs/assurance-bounds.md"):
            shutil.copy(ROOT / rel, root / rel)
        self.git("init", "-q")
        self.git("add", "-A")

    def git(self, *args):
        subprocess.run(
            ["git", "-C", str(self.root), *args], check=True, capture_output=True
        )

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git("add", "-A")

    def edit(self, rel, old, new, count=1):
        """Replace `old` exactly `count` times, failing loudly if the tree moved."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == count, (
            f"{rel} says {old!r} {text.count(old)} times, not {count}"
        )
        path.write_text(text.replace(old, new))
        self.git("add", "-A")

    def edit_first(self, rel, old, new):
        """Replace the FIRST occurrence. For a value the page prints many times —
        `bound_channels = 2` is 24 rows — where one moved row is the mutation and
        pinning the other 23 would be pinning the bundles instead."""
        path = self.root / rel
        text = path.read_text()
        assert old in text, f"{rel} does not say {old!r}"
        path.write_text(text.replace(old, new, 1))
        self.git("add", "-A")

    def set_bound(self, rel, ordinal, key, value):
        """Rewrite one `bound_*` line of one `[[method]]` row.

        Anchored by ORDINAL rather than by neighbouring text: `bound_channels =
        2` is four rows of this bundle with four different consequences, which is
        the reason the consequence is per-row in the first place, and the line
        after it is no longer the next bound.
        """
        path = self.root / rel
        out, index, in_method, hits = [], 0, False, 0
        for line in path.read_text().splitlines(keepends=True):
            if line.startswith("["):
                in_method = line.startswith("[[method]]")
                index += in_method
            if index == ordinal and in_method and line.startswith(f"{key} = "):
                line, hits = f"{key} = {value}\n", hits + 1
            out.append(line)
        assert hits == 1, f"{rel} method #{ordinal}: {key} begins {hits} lines, not 1"
        path.write_text("".join(out))
        self.git("add", "-A")

    def strip_bounds(self, rel, ordinal):
        """Every `bound_*` and `stops_*` line of one `[[method]]` row, removed.

        Written as a walk rather than as a literal because the two now alternate:
        pasting the four lines of a row would paste two consequences with them.
        """
        path = self.root / rel
        out, index, in_method = [], 0, False
        for line in path.read_text().splitlines(keepends=True):
            if line.startswith("["):
                in_method = line.startswith("[[method]]")
                index += in_method
            if index == ordinal and in_method and line.startswith(("bound_", "stops_")):
                continue
            out.append(line)
        path.write_text("".join(out))
        self.git("add", "-A")

    def regenerate(self):
        self.write("docs/assurance-bounds.md", bounds_gate.render(self.root))

    def problems(self, **floors):
        return bounds_gate.audit(self.root, **floors)[0]

    def records(self):
        return bounds_gate.table(bounds_gate.bundles(self.root, []))


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def row_for(tree, bound):
    """The page's rendered line for one bound, DERIVED rather than retyped.

    Since every bound carries a consequence the rendered row is a sentence long,
    and a case that pastes one is a case that rots the next time the sentence is
    edited. Asserted unique, so a mutation still names exactly one row.
    """
    page = (tree.root / "docs/assurance-bounds.md").read_text().splitlines()
    hits = [line for line in page if line.startswith(f"| `{bound}` |")]
    assert len(hits) == 1, f"{bound} is on {len(hits)} rows of the page, not 1"
    return hits[0]


def drop_line(tree, rel, prefix):
    """Delete the one line beginning `prefix`, failing loudly if it is not one."""
    path = tree.root / rel
    lines = path.read_text().splitlines(keepends=True)
    hits = [line for line in lines if line.startswith(prefix)]
    assert len(hits) == 1, f"{rel}: {prefix!r} begins {len(hits)} lines, not 1"
    path.write_text("".join(line for line in lines if line is not hits[0]))
    tree.git("add", "-A")


def set_line(tree, rel, prefix, replacement):
    """Rewrite the one line beginning `prefix`. Same assertion, same reason."""
    path = tree.root / rel
    lines = path.read_text().splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.startswith(prefix)]
    assert len(hits) == 1, f"{rel}: {prefix!r} begins {len(hits)} lines, not 1"
    lines[hits[0]] = replacement + "\n"
    path.write_text("".join(lines))
    tree.git("add", "-A")


def only(problems, needle):
    """The problems mentioning `needle`, so a message is asserted, not a count.

    On a failure this prints `assert []` and the UNFILTERED list is on the
    `+ where …` line under it. Read that line: a neutered rule reported as "the
    gate stayed silent" is usually a NEIGHBOUR's rule having fired instead.
    """
    return [p for p in problems if needle in p]


# --- both directions of green -------------------------------------------------


def test_the_fixture_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    findings, summary = bounds_gate.audit(ROOT)
    assert findings == [], findings
    assert summary.startswith("bounds-gate: ok")


def test_the_fixture_carries_the_evidence_it_is_built_for(tree):
    """A fixture under every floor would pass each rule below vacuously."""
    records = tree.records()
    assert len({r["property"] for r in records}) == bounds_gate.BUNDLE_FLOOR
    assert len({(r["bundle"], r["index"]) for r in records}) == bounds_gate.ROW_FLOOR
    assert len(records) == bounds_gate.BOUNDS_FLOOR


def test_a_change_with_no_consequence_stays_green(tree):
    """The control. A comment in a bundle and a non-bound key in a method row
    move no bound, so the page is unchanged and every rule stays quiet."""
    path = tree.root / "assurance/bundle/SEC-FIDO-001.toml"
    path.write_text(path.read_text() + '\n# a note that bounds nothing\n')
    tree.edit(
        "assurance/bundle/SEC-FIDO-003.toml",
        "bound_sequence = 5",
        'note_for_the_reader = "not a bound"\nbound_sequence = 5',
    )
    assert tree.problems() == []


# --- the six mutations that were exit 0 on all eight gates --------------------


def test_a_bundle_bound_that_moves_while_the_page_stands_still(tree):
    """Mutation 3: `bound_sequence` 5 -> 9999 in the bundle."""
    tree.edit("assurance/bundle/SEC-FIDO-001.toml", "bound_sequence = 5", "bound_sequence = 9999")
    assert only(tree.problems(), "is not what the generator writes")


def test_a_page_bound_that_moves_while_the_bundle_stands_still(tree):
    """Mutation 1: the same number, edited on the page instead."""
    tree.edit_first("docs/assurance-bounds.md", "| `bound_sequence` | `5` |", "| `bound_sequence` | `9999` |")
    assert only(tree.problems(), "is not what the generator writes")


def test_a_bundle_channel_bound_that_moves(tree):
    """Mutation 4: `bound_channels` 2 -> 77, in the bundle."""
    tree.set_bound("assurance/bundle/SEC-FIDO-001.toml", 5, "bound_channels", 77)
    assert only(tree.problems(), "is not what the generator writes")


def test_a_page_channel_bound_that_moves(tree):
    """Mutation 2: `model Channels 2` -> 77, on the page."""
    tree.edit_first(
        "docs/assurance-bounds.md",
        "| `bound_channels` | `2` |",
        "| `bound_channels` | `77` |",
    )
    assert only(tree.problems(), "is not what the generator writes")


def test_a_page_row_renamed_after_a_constant_that_does_not_exist(tree):
    """Mutation 5: the row keeps its number and names something the tree has not."""
    tree.edit(
        "docs/assurance-bounds.md",
        "| `bound_relation_tuples` | `63888` |",
        "| `bound_no_such_constant` | `63888` |",
    )
    assert only(tree.problems(), "is not what the generator writes")


def test_a_page_row_deleted(tree):
    """Mutation 6, and the one rule the byte diff alone would not have named.

    Two findings and both are wanted: the page no longer regenerates, AND it
    prints one bound fewer than the bundles carry — which is the rule that reads
    the FILE, so a filter inside `render` would be caught by it and not by the
    diff.
    """
    tree.edit("docs/assurance-bounds.md", row_for(tree, "bound_outcomes") + "\n", "")
    problems = tree.problems()
    assert only(problems, "is not what the generator writes")
    total = bounds_gate.BOUNDS_FLOOR
    assert only(problems, f"prints {total - 1} bound row(s) against the {total}")


def test_a_page_row_invented(tree):
    """The other direction of the same count: a row nothing derives."""
    row = row_for(tree, "bound_outcomes")
    tree.edit("docs/assurance-bounds.md", row, row + "\n| `bound_invented` | `1` | — |")
    total = bounds_gate.BOUNDS_FLOOR
    assert only(tree.problems(), f"prints {total + 1} bound row(s) against the {total}")


# --- the parallel table, both directions --------------------------------------


def test_a_hand_written_table_back_in_the_slice_section(tree):
    """The exact state this row was written to end."""
    tree.edit(
        "docs/authorization-slice.md",
        "## The bounds\n",
        "## The bounds\n\n| Bound | Value | What stops being proved |\n|---|---|---|\n"
        "| Kani sequence length | 5 operations | any defect needing a sixth |\n",
    )
    problems = tree.problems()
    assert only(problems, "carries 3 table line(s) of its own")
    assert only(problems, "carries this page's table header")


def test_the_slice_section_stops_naming_the_page(tree):
    """A section that lost its table owes the reader where the table went."""
    tree.edit("docs/authorization-slice.md", "(assurance-bounds.md)", "(scopes.txt)")
    assert only(tree.problems(), "does not name assurance-bounds.md")


def test_the_slice_section_deleted_outright(tree):
    tree.edit("docs/authorization-slice.md", "## The bounds", "## The former bounds")
    assert only(tree.problems(), "has no `## The bounds` section")


def test_the_table_header_copied_into_another_page(tree):
    """The completeness half: a rule naming one page cannot see the next copy."""
    tree.write(
        "docs/some-other-page.md",
        f"# Elsewhere\n\n{bounds_gate.TABLE_HEADER}\n|---|---|---|\n| a | 1 | b |\n",
    )
    assert only(tree.problems(), "docs/some-other-page.md carries this page's table header")


def test_a_table_header_in_the_generated_page_is_not_a_copy_of_itself(tree):
    """The rule skips its own artifact, or it reddens the page it writes."""
    assert bounds_gate.TABLE_HEADER in (tree.root / "docs/assurance-bounds.md").read_text()
    assert not only(tree.problems(), "carries this page's table header")


# --- the per-bound consequence column -----------------------------------------


def test_a_consequence_attached_to_no_bound(tree):
    """`stops_*` with no `bound_*` twin: prose in a field the table reads as evidence."""
    tree.edit(
        "assurance/bundle/SEC-FIDO-001.toml",
        "bound_sequence = 5",
        'bound_sequence = 5\nstops_seqence = "a typo is a consequence attached to nothing"',
    )
    assert only(tree.problems(), "`stops_seqence` names no `bound_seqence`")


def test_a_consequence_that_answers_nothing(tree):
    """The field occupied rather than filled — `bundle_gate.NON_ANSWERS`' spelling."""
    set_line(
        tree,
        "assurance/bundle/SEC-FIDO-001.toml",
        "stops_relation_tuples = ",
        'stops_relation_tuples = "n/a"',
    )
    assert only(tree.problems(), "which answers nothing")


def test_a_bundle_that_adopts_the_column_for_some_of_its_bounds(tree):
    """Half-adopted reads as complete while most of it is still the row note.

    Reached by REMOVING one consequence, because the tree carries the column for
    every bound now: the half-adopted state is a deletion away, not an addition.
    """
    drop_line(tree, "assurance/bundle/SEC-FIDO-007.toml", "stops_tagged_owners = ")
    assert only(tree.problems(), "25 bound(s) carry a `stops_*` consequence and 1 do not")


def test_the_column_is_adopted_for_every_bound_of_every_bundle(tree):
    """The other direction: full adoption is green, and the page prints it.

    This is the shipped state rather than a case's edit — the fixture is the real
    bundles, so what is asserted here is the tree's own count and not a mock's.
    """
    assert tree.problems() == []
    records = tree.records()
    assert [r for r in records if r["stops"] is None] == []
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    assert f"**{len(records)} of {len(records)}** bounds carry a per-bound consequence" in page
    assert "| `SEC-FIDO-007` | `RamNeverOutlivesFlashSeed` |" in page
    for record in records[:: len(records) // 8]:
        assert bounds_gate.prose(record["stops"]) in page


def test_the_consequence_column_can_go_backwards(tree):
    """The ratchet's direction, reached by RAISING the floor rather than by
    lowering a global: one over the count, the column is behind."""
    over = bounds_gate.PROSE_FLOOR + 1
    assert only(tree.problems(prose_floor=over), f"under the floor of {over}")


def test_one_consequence_removed_is_under_the_shipped_prose_floor(tree):
    """The arm the floor at the count buys, driven at the SHIPPED value.

    `PROSE_FLOOR` was 0 while the column was empty and could not fire; at the count it
    is a ratchet, and losing one consequence is red until an author moves it in
    the same diff. Reached by removing evidence — the direction a floor is for.
    """
    drop_line(tree, "assurance/bundle/SEC-FIDO-007.toml", "stops_tagged_owners = ")
    assert only(
        tree.problems(),
        f"{bounds_gate.PROSE_FLOOR - 1} bound(s) carry a `stops_*` consequence, under the floor of"
        f" {bounds_gate.PROSE_FLOOR}",
    )


# --- the floors ---------------------------------------------------------------


def test_a_bundle_that_stopped_being_rendered(tree):
    (tree.root / "assurance/bundle/SEC-FIDO-005.toml").unlink()
    tree.git("add", "-A")
    assert only(
        tree.problems(),
        f"{bounds_gate.BUNDLE_FLOOR - 1} bundle(s) reached this table, under the floor of"
        f" {bounds_gate.BUNDLE_FLOOR}",
    )


def test_a_method_row_whose_bounds_were_stripped(tree):
    """The row floor and the bounds floor are two questions, and this asks both."""
    tree.strip_bounds("assurance/bundle/SEC-FIDO-001.toml", 2)
    problems = tree.problems()
    assert only(
        problems,
        f"{bounds_gate.ROW_FLOOR - 1} method row(s) carry a bound, under the floor of"
        f" {bounds_gate.ROW_FLOOR}",
    )
    assert only(
        problems,
        f"{bounds_gate.BOUNDS_FLOOR - 2} `bound_*` key(s) rendered, under the floor of"
        f" {bounds_gate.BOUNDS_FLOOR}",
    )


def test_one_bound_removed_is_under_the_bounds_floor(tree):
    """At the count, losing ONE is red — which is what a floor at the measurement
    buys over a floor set comfortably below it."""
    drop_line(tree, "assurance/bundle/SEC-FIDO-001.toml", "bound_outcomes = ")
    drop_line(tree, "assurance/bundle/SEC-FIDO-001.toml", "stops_outcomes = ")
    assert only(
        tree.problems(),
        f"{bounds_gate.BOUNDS_FLOOR - 1} `bound_*` key(s) rendered, under the floor of"
        f" {bounds_gate.BOUNDS_FLOOR}",
    )


def test_a_checkout_with_no_bundle_directory_is_a_fact_not_a_finding(tmp_path):
    """The floors are scoped to "the source is there and the derivation found
    none of it", never to "the tree has none" — the pair `token_refinement_gate`
    shipped, one gate over."""
    (tmp_path / "docs").mkdir()
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True, capture_output=True)
    assert not [p for p in bounds_gate.audit(tmp_path)[0] if "under the floor" in p]


def test_the_shipped_floors_are_this_tree_s_counts():
    """A floor under the count catches a derivation that COLLAPSED and never one
    that slid. At the count, losing one is red until the floor moves in the same
    diff — and the floor cannot be moved by a case, only by an author."""
    records = bounds_gate.table(bounds_gate.bundles(ROOT, []))
    assert bounds_gate.BUNDLE_FLOOR == len({r["property"] for r in records})
    assert bounds_gate.ROW_FLOOR == len({(r["bundle"], r["index"]) for r in records})
    assert bounds_gate.BOUNDS_FLOOR == len(records)
    assert bounds_gate.PROSE_FLOOR == len([r for r in records if r["stops"] is not None])


def test_a_case_cannot_patch_a_floor_downward(monkeypatch):
    """The reason the floors are `audit` PARAMETERS and not globals it reads.

    A default is bound once, at import, so the name below is not what `main`
    consults — rebinding it changes nothing. That is the shape
    `claims_gate.DISCLAIMER_FLOOR` shipped after its mutation table reported a
    mutant SURVIVING because the only way to a global is to monkeypatch it.
    """
    monkeypatch.setattr(bounds_gate, "BOUNDS_FLOOR", 1)
    monkeypatch.setattr(bounds_gate, "BUNDLE_FLOOR", 1)
    assert bounds_gate.audit.__defaults__[1:3] == (107, 541)


# --- the derivation -----------------------------------------------------------


def test_a_bundle_with_no_property_id_names_nothing(tree):
    tree.edit("assurance/bundle/SEC-FIDO-005.toml", 'id = "SEC-FIDO-005"', 'name = "SEC-FIDO-005"')
    assert only(tree.problems(), "would be attributed to nothing")


def test_the_bare_prefix_is_not_a_bound(tree):
    """`bound_` IS the wildcard `bundle_gate.REQUIRED` spells, and a key that is
    the wildcard bounds nothing — the two files agree about that rather than
    each deciding."""
    tree.edit(
        "assurance/bundle/SEC-FIDO-001.toml",
        "bound_sequence = 5",
        "bound_ = 0\nbound_sequence = 5",
    )
    assert len(tree.records()) == bounds_gate.BOUNDS_FLOOR
    assert tree.problems() == []


def test_every_bound_of_every_bundle_reaches_the_page(tree):
    """The requirement in its own words, asserted against the file on disk."""
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    printed = len(bounds_gate.BOUND_ROW.findall(page))
    assert printed == len(tree.records()) == bounds_gate.BOUNDS_FLOOR
    for record in tree.records():
        assert f"`bound_{record['bound']}`" in page


def test_every_bundle_reaches_the_summary(tree):
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    for record in tree.records():
        assert f"| `{record['property']}` |" in page
        assert record["bundle"] in page


def test_a_row_note_travels_with_every_method_row(tree):
    """The fallback the `—` cells point at is rendered, or the page explains
    nothing at all while the column is empty."""
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    assert page.count("> **Row note (`shipped_relation`).**") == bounds_gate.ROW_FLOOR


def test_a_value_that_is_prose_rather_than_a_number_still_renders(tree):
    """`bound_totals` is `full symbolic u16 — not a shrink`, which is a bound
    saying it is not one. A renderer that assumed an int would drop it."""
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    assert "| `bound_totals` | full symbolic u16 — not a shrink," in page


def test_a_pipe_in_a_bundle_string_cannot_break_the_table(tree):
    tree.edit(
        "assurance/bundle/SEC-FIDO-001.toml",
        "bound_totals = \"full symbolic u16 — not a shrink, and saying so is the point\"",
        "bound_totals = \"a | b\"",
    )
    tree.regenerate()
    assert tree.problems() == []
    assert "| `bound_totals` | a \\| b |" in (tree.root / "docs/assurance-bounds.md").read_text()


# --- the page itself ----------------------------------------------------------


def test_a_missing_page_is_refused(tree):
    (tree.root / "docs/assurance-bounds.md").unlink()
    tree.git("add", "-A")
    assert only(tree.problems(), "is not what the generator writes")


def test_the_page_carries_the_disclaimer(tree):
    """It names eleven registered ids, so `claims_gate` owes it the sentence — and
    the sentence is imported rather than typed, so there is one copy to drop."""
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    assert "RS-Key is not formally verified" in page


def test_the_page_says_which_properties_it_renders_and_why(tree):
    """Requirement: the decision is on the page, not only in the commit."""
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    assert "**Every bundle the tree has — 17 of them.**" in page
    assert "**0 of its 17 rows** carry no bundle" in page


def test_the_rows_without_a_bundle_are_derived_from_the_ledger(tree):
    """The list on the page is the ledger's tranche minus the bundles, so a row
    gaining a bundle removes it from the sentence without anyone retyping it.

    `<=` and not `<`. The strict form was true the day this was written and was
    never the claim: it quietly asserted that SOME `p0-launch` row still had no
    bundle, which stopped being a fact when the six `SEC-STORE-*` bundles landed
    and the difference went empty. The derivation is what this case is about, and
    it holds at equality — the page then names no unbundled row instead of naming
    a wrong one, which is the direction it should fail in.
    """
    tranche = bounds_gate.launch_tranche(tree.root)
    bundled = {r["property"] for r in tree.records()}
    assert set(bundled) <= set(tranche)
    page = (tree.root / "docs/assurance-bounds.md").read_text()
    for pid in tranche:
        assert f"`{pid}`" in page, f"{pid} is in the tranche and on no line of the page"
    assert "`SEC-STORE-006`" in page


def test_a_tranche_row_that_lost_its_bundle_is_named_on_the_page(tree):
    """The same derivation, run over a tranche that is KNOWN to be uncovered.

    The case above holds at equality, and so does `unbundled = []` — the whole
    derivation hardcoded to "none are missing" passed all 46 cases of this table,
    because every `p0-launch` row carries a bundle today and the page's sentence
    reads `0 of its 17 rows` either way. Removing one bundle makes the difference
    exactly one row, which the page then has to NAME; the hardcoded empty answer
    still prints `0` and `none`, and that is this case going red.
    """
    orphan = "SEC-STORE-006"
    (tree.root / f"assurance/bundle/{orphan}.toml").unlink()
    tree.git("add", "-A")
    tranche = bounds_gate.launch_tranche(tree.root)
    page = bounds_gate.render(tree.root)
    assert f"**1 of its {len(tranche)} rows** carry no bundle" in page
    assert f"— `{orphan}`." in page


def test_a_tranche_that_resolves_to_nothing(tree):
    """A denominator of 0 reads as a complete tree; a source that is THERE and
    resolves to nothing is a reader that stopped, not a fact about the tree."""
    tree.edit("assurance/configurations.toml", 'p0-launch = [', "p0-launch-renamed = [")
    assert only(tree.problems(), "resolves no `p0-launch` row")


def test_write_regenerates_the_page(tree):
    (tree.root / "docs/assurance-bounds.md").write_text("stale\n")
    assert bounds_gate.run(tree.root, write=True) == 0
    tree.git("add", "-A")
    assert tree.problems() == []


def test_main_refuses_an_argument_it_does_not_have(capsys):
    assert bounds_gate.main(["--all"]) == 2
    assert "usage: bounds_gate.py" in capsys.readouterr().err


def test_run_reports_findings_on_stderr(tree, capsys):
    (tree.root / "docs/assurance-bounds.md").write_text("stale\n")
    assert bounds_gate.run(tree.root) == 1
    assert "bounds-gate:" in capsys.readouterr().err


# --- the wiring ---------------------------------------------------------------


def test_check_assurance_sh_runs_this_gate():
    """The row's CODE: a `#` in front of it is not a row."""
    text = (ROOT / "scripts/check-assurance.sh").read_text()
    assert gate_lines.runs(text, "scripts/bounds_gate.py")


def test_the_page_is_listed_in_the_docs_nav():
    """A generated page mdBook never renders is one no reader ever sees."""
    assert "assurance-bounds.md" in (ROOT / "docs/SUMMARY.md").read_text()


def test_the_page_declares_itself_generated_the_way_claims_gate_reads_it():
    """`claims_gate.generated_pages` pairs `ARTIFACT` with `GENERATED_BY`, and a
    page that does not declare itself that way is read as hand-written prose."""
    source = (ROOT / "scripts/bounds_gate.py").read_text()
    assert re.search(r'^ARTIFACT = pathlib\.Path\("docs/assurance-bounds.md"\)', source, re.M)
    assert re.search(r'^GENERATED_BY = "Generated by scripts/bounds_gate\.py --write"', source, re.M)
    assert bounds_gate.GENERATED_BY in (ROOT / bounds_gate.ARTIFACT).read_text()[:600]
