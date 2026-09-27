# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The registry shapes that came out of the `comutants lint` row as a traceback.

`anchor_shape_problems` validated the `[[site]]` array's own `file` and `find`
and left the FLAT form — the one 75 of the 79 entries use — with nothing at all,
so `patch_sites` read both by subscript and the row died on `KeyError: 'file'`.
A traceback is not a finding: it names a line of `comutate.py` and not the entry
a reader has to go fix, and the `run` verdict it protects never happens either.

Measured on the shipped registry, by driving `python scripts/comutate.py --lint`
over one hand-broken entry at a time (exit 1 taken without a pipe in both
directions): `KeyError: 'file'`, `KeyError: 'find'`, `TypeError: count()
argument 1 must be str, not list` and `AttributeError: 'str' object has no
attribute 'get'`. Each case below pairs the finding with the traceback the guard
is standing in front of, because a case asserting only the sentence would pass
over a guard that reports and then crashes anyway.

The fixture is `test_comutate.build`'s — one tree, so a drift in the registry
schema breaks one place rather than two.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import comutate
import test_comutate

pytestmark = pytest.mark.assurance


@pytest.fixture
def tree(tmp_path):
    return test_comutate.build(tmp_path)


def red(tree, needle: str) -> None:
    problems = comutate.lint(tree)
    assert any(needle in p for p in problems), problems


def test_the_green_fixture_still_passes(tree):
    """The control every arm below is read against: `== []` for any reason is a
    case that asserts the fixture, so the fixture is asserted once, here."""
    assert comutate.lint(tree) == []


def test_a_flat_entry_without_its_file_is_named_and_not_raised(tree):
    test_comutate.edit(
        tree / "formal" / "comutants.toml", 'file = "src/lib.rs"\n', ""
    )
    red(tree, "the flat form has no 'file'")
    with pytest.raises(KeyError):
        list(comutate.patch_sites({"find": "x"}))


def test_a_flat_entry_without_its_find_is_named_and_not_raised(tree):
    test_comutate.edit(
        tree / "formal" / "comutants.toml", 'find = "GUARD_LINE\\n"\n', ""
    )
    red(tree, "the flat form has no 'find'")
    with pytest.raises(KeyError):
        list(comutate.patch_sites({"file": "src/lib.rs"}))


def test_an_anchor_written_as_an_array_is_named_and_not_raised(tree):
    """The type half, and the reason the rule is not `if not entry.get(key)`: a
    TOML array is the shape an author reaches for when one anchor is not enough,
    it is TRUTHY, and `str.count` takes it no better than a missing key."""
    test_comutate.edit(
        tree / "formal" / "comutants.toml",
        'find = "GUARD_LINE\\n"',
        'find = ["GUARD_LINE\\n", "fn f"]',
    )
    red(tree, "the flat form has no 'find'")
    with pytest.raises(TypeError):
        "GUARD_LINE\n".count(["GUARD_LINE\n"])


def test_an_empty_anchor_is_named(tree):
    """`find = ""` resolves `len(text) + 1` times, so the anchor rule reports it
    as code that MOVED — the wrong cause, and the one the author cannot act on.
    The `[[site]]` half already refused an empty string; this is the parity."""
    test_comutate.edit(
        tree / "formal" / "comutants.toml", 'find = "GUARD_LINE\\n"', 'find = ""'
    )
    red(tree, "the flat form has no 'find'")


def test_a_site_table_written_with_one_bracket_pair_is_named(tree):
    """`[comutant.X.site]` is a table and `[[comutant.X.site]]` an array of them.
    With one pair the walk iterates the table's KEYS, and the rule written to
    report a site with no `file` was itself the traceback: `'str' object has no
    attribute 'get'`."""
    (tree / "formal" / "comutants.toml").write_text(
        (tree / "formal" / "comutants.toml").read_text()
        + '\n[comutant.BugAlpha.site]\nfile = "src/lib.rs"\nfind = "GUARD_LINE\\n"\n'
    )
    red(tree, "`site` is dict and not an array of tables")
    with pytest.raises(AttributeError):
        [site.get("file") for site in {"file": "src/lib.rs", "find": "x"}]


def test_a_site_array_of_things_that_are_not_tables_is_named():
    """The other half of the same shape rule: an array whose members are strings
    walks into the same `.get` as the single table does."""
    problems = comutate.anchor_shape_problems("BugX", {"site": ["src/lib.rs"]})
    assert any("not an array of tables" in p for p in problems), problems


def test_the_second_reader_of_the_loader_skips_instead_of_raising(tmp_path, monkeypatch):
    """`comutate.patch_sites` has a reader in another gate, and it invented half
    of this rule: `evidence_gate.comutant_patch_files` skipped on `"file" not in
    entry` and said nothing about `find`, so the entry below reached the loader
    from a row that does not own the registry. Measured on the shipped tree with
    `find` deleted from `BugTokenSurvivesPinChange`: `python
    scripts/evidence_gate.py` exited 1 on `KeyError: 'find'`. It is the shared
    rule now, so the malformed entry is the `comutants lint` row's to report and
    this one keeps deriving."""
    import assurance_gate
    import evidence_gate

    (tmp_path / "formal").mkdir()
    (tmp_path / "formal" / "comutants.toml").write_text(
        '[comutant.BugHalf]\nstatus = "patch"\nfile = "src/lib.rs"\n'
        '\n[comutant.BugWhole]\nstatus = "patch"\nfile = "src/lib.rs"\nfind = "x"\n'
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("x\n")
    monkeypatch.setattr(
        assurance_gate, "co_refuted", lambda root: {"Half": ["BugHalf"], "Whole": ["BugWhole"]}
    )
    assert evidence_gate.comutant_patch_files(tmp_path, "Half") == []
    assert evidence_gate.comutant_patch_files(tmp_path, "Whole") == ["src/lib.rs"]


def test_a_site_missing_its_file_still_says_so(tree):
    """The half that already worked, kept: one rule now serves both forms, and a
    shared rule is where a message quietly stops being the one a case matches."""
    test_comutate.edit(
        tree / "formal" / "comutants.toml",
        'status = "patch"\nfile = "src/lib.rs"\nfind = "GUARD_LINE\\n"\nreplace = ""',
        'status = "patch"\n\n[[comutant.BugAlpha.site]]\nfind = "GUARD_LINE\\n"',
    )
    red(tree, "site 1 has no 'file'")
