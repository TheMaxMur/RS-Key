# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `matrix_gate.check_citations`, kept.

Its own file rather than more cases in `test_matrix_gate.py`, because the rule
is about a different thing than the rest of that guard: every other refusal in
`matrix_gate.py` reads a DISPOSITION, and this one reads the prose beside it.

The rule earns its place on a measurement and the table is built around that
measurement. `assurance/configurations.toml` argues its dispositions in prose
that cites the tree — ten file paths and four `check.sh` row labels — and until
this rule none of the fourteen was read by anything. All fourteen resolve; two
of the CLAIMS around them did not survive being re-read by hand, and no rule
here catches that. What it catches is the step below: a citation that has gone
dead reads exactly like a live one. So the arms below are the two ways it dies
(the file goes, the row is renamed) and, just as important, the ways it must NOT
fire: `rsk-fido/bench` and `flash.size_mb=4` are vocabulary, and a guard that
reddens on vocabulary is one the next author deletes.

Both directions, and driven through `matrix_gate.run` rather than
`check_citations` — a rule the entry point never reaches can be deleted with
this file still green, which is the hole five of this repo's guards shipped
with. The MESSAGE is asserted, never the finding count: a red for a dead path
and a red for a stale artifact are the same exit code.
"""

import pathlib

import pytest

import matrix_gate
from test_matrix_gate import Tree, red, tree  # noqa: F401  (`tree` is the fixture)

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parent.parent


def regenerate(tree):
    """Re-seed the artifact so a green case is green for its own reason."""
    matrix_gate.run(tree.root, write=True)
    return tree.run()


# --- the rule is green where it should be ------------------------------------


def test_a_live_path_citation_passes(tree):
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on, per"
        " `firmware/src/presence.rs`.\"",
    )
    assert regenerate(tree) == 0


def test_a_live_row_citation_passes(tree):
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on; `test (core)` runs it.\"",
    )
    assert regenerate(tree) == 0


def test_a_glob_citation_passes_when_it_matches(tree):
    """`formal/*.cfg` is one claim about many files, and it has to stay sayable."""
    tree.write("formal/Shipped.cfg", "SPECIFICATION Spec\n")
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on; see `formal/*.cfg`.\"",
    )
    assert regenerate(tree) == 0


def test_vocabulary_is_not_a_citation(tree):
    """The false-positive floor: a rule that reddens on prose is not kept.

    None of these three names a file or a row — a cargo feature path, a board
    key, a FID — and all three are spellings the real ledger already uses.
    """
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on: `rsk-core/loud`,"
        " `flash.size_mb=4`, `EF_META`.\"",
    )
    assert regenerate(tree) == 0


# --- and red where it should be ----------------------------------------------


def test_a_cell_citing_a_file_that_is_not_there_is_refused(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on, per `firmware/src/gone.rs`.\"",
    )
    assert "cites `firmware/src/gone.rs`, which is not in the tree" in red(tree, capsys)


def test_a_question_citing_a_file_that_is_not_there_is_refused(tree, capsys):
    """The second record type, because `[[question]]` had no field list at all
    until recently and is where the longest arguments in the ledger live."""
    tree.edit(
        "assurance/configurations.toml",
        "text = \"does SEC-A-002 depend on the press indirectly?\"",
        "text = \"does SEC-A-002 depend on the press indirectly, see `docs/gone.md`?\"",
    )
    assert "cites `docs/gone.md`, which is not in the tree" in red(tree, capsys)


def test_a_cell_citing_a_row_that_is_not_there_is_refused(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on; `test (absent)` runs it.\"",
    )
    assert "cites `test (absent)`, which is no" in red(tree, capsys)


def test_a_renamed_check_sh_row_reddens_the_prose_that_names_it(tree, capsys):
    """The rot this rule is actually for, in the order it happens.

    The citation is live when it is written and the ledger is untouched
    afterwards; someone else renames the row. Before this rule that left the
    argument pointing at nothing with the grid unchanged and EXIT=0 — the same
    shape as a `formal/` citation drifting off its line, which is why the
    remedy is borrowed from `citation_gate.py` rather than invented.
    """
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the only column that compiles the ceremony, and the row that proves it.\"",
        "why = \"the only column that compiles the ceremony; `test (screen)` runs it.\"",
    )
    assert regenerate(tree) == 0
    tree.edit("scripts/check.sh", 'run_tests "test (screen)"', 'run_tests "test (panel)"')
    tree.edit(
        "assurance/configurations.toml", 'evidence = ["kani (screen)"]', 'evidence = ["test (panel)"]'
    )
    assert "cites `test (screen)`, which is no" in red(tree, capsys)


def test_a_glob_citation_that_matches_nothing_is_refused(tree, capsys):
    """A glob is the one citation shape that can go dead without a rename."""
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on; see `formal/*.cfg`.\"",
    )
    assert "cites `formal/*.cfg`, which is not in the tree" in red(tree, capsys)


# --- the half of the row namespace the shape rule cannot see ------------------


def test_a_shapeless_row_cited_with_the_prefix_passes(tree):
    """54 of the real tree's 113 rows carry no ` (…)` — `fmt`, `kani roster`,
    `published claims` — so the shape rule sees 52% of what a rename can break.
    The prefix is what makes the other half citable at all."""
    tree.edit("scripts/check.sh", 'run "clippy (loud)"', 'run "fmt" cargo fmt --check\nrun "clippy (loud)"')
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on, under `check.sh: fmt`.\"",
    )
    assert regenerate(tree) == 0


def test_a_shapeless_row_that_was_renamed_reddens_the_prose(tree, capsys):
    """The rot the whole rule exists for, on the 52% it could not reach.

    Same order as its `foo (bar)` sibling above: the citation is live when it is
    written, someone else renames the row, and before the prefix the argument
    pointed at nothing with the grid unchanged and EXIT=0 — indistinguishable
    from vocabulary, which is why no heuristic could have caught it.
    """
    tree.edit("scripts/check.sh", 'run "clippy (loud)"', 'run "fmt" cargo fmt --check\nrun "clippy (loud)"')
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on, under `check.sh: fmt`.\"",
    )
    assert regenerate(tree) == 0
    tree.edit("scripts/check.sh", 'run "fmt" cargo fmt', 'run "fmt (host)" cargo fmt')
    said = red(tree, capsys)
    assert "cites `check.sh: fmt`, and scripts/check.sh has no row 'fmt'" in said
    assert "makes a shapeless row label citable" in said


def test_a_citation_wrapped_across_two_lines_is_still_read(tree, capsys):
    """A `why` is a TOML block joined with `\\`, so a wrapped token arrives flat —
    but a block written WITHOUT the continuations keeps the newline, and the
    token then matches neither pattern and is checked by nothing. 0 of the real
    ledger's 208 tokens wrap today, which is a fact about the prose and not one
    about the rule; this is the arm that keeps it that way."""
    tree.edit(
        "assurance/configurations.toml",
        'why = "the image every measurement was taken on."',
        'why = """\nthe image every measurement was taken on, under `check.sh:\nfmt`."""',
    )
    assert "cites `check.sh: fmt`, and scripts/check.sh has no row 'fmt'" in red(tree, capsys)


def test_a_star_in_a_real_filename_is_still_found(tree):
    """Why the path check is one call and not two.

    It read `not (root / token).exists() and not list(root.glob(token))`, and no
    input could tell the halves apart — a mutation dropping the `exists` half
    was a survivor. The reason is the class `CITED_PATH` admits: no `[`, no `?`,
    so the only metacharacter that reaches the branch is `*`, and a file
    literally named `vec*.rs` matches the pattern `vec*.rs`. This is the arm
    that would have caught it if it were not.
    """
    tree.write("crates/rsk-core/src/vec*.rs", "// a star in the name, not a glob\n")
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on, per `crates/rsk-core/src/vec*.rs`.\"",
    )
    assert regenerate(tree) == 0


def test_a_token_carrying_a_bracket_is_vocabulary_and_not_a_path(tree):
    """The boundary the simplification above rests on, pinned rather than
    assumed: a token a glob would read as a character class never reaches the
    path branch at all, because `CITED_PATH`'s class stops it. Widen that class
    and the one call stops being enough — which is what this case is here to
    say to whoever widens it."""
    assert not matrix_gate.CITED_PATH.match("crates/rsk-core/src/vec[1].rs")
    assert not matrix_gate.CITED_PATH.match("crates/rsk-core/src/vec?1.rs")
    tree.edit(
        "assurance/configurations.toml",
        "why = \"the image every measurement was taken on.\"",
        "why = \"the image every measurement was taken on: `bytes[1..3]`, `EF_META[0]`.\"",
    )
    assert regenerate(tree) == 0


# --- and on the tree it ships in ---------------------------------------------


def test_the_shipped_ledger_cites_nothing_dead():
    """The guard has to be green on its own checkout, or it is not a row."""
    assert matrix_gate.check_citations(ROOT, matrix_gate.ledger(ROOT)) == []


def test_the_shipped_ledger_still_cites_something():
    """A rule over an empty set passes every case above it.

    Measured at 14 on the tree this landed in: ten paths and four row labels.
    The floor is 8 rather than 14 so a paragraph rewritten for length is an
    edit and not a red, and a ledger that stopped citing the tree is still one.
    """
    doc = matrix_gate.ledger(ROOT)
    cited = [
        token
        for kind, field in (("cell", "why"), ("question", "text"))
        for entry in doc.get(kind, [])
        for token in matrix_gate.CITED.findall(str(entry.get(field, "")))
        if matrix_gate.CITED_PATH.match(" ".join(token.split()))
        or matrix_gate.CITED_ROW.match(" ".join(token.split()))
    ]
    assert len(cited) >= 8, cited
