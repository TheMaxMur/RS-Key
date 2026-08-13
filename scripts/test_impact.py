# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `impact.py` never had.

It is the one guard in `scripts/` that `check.sh` does not run — the pre-commit
hook prints it, advisory and never fatal — and so it also had no table. Its three
known defects were all found by an audit rather than by a test: a `+++ b/` line
of *content* retargeting the parser, a `diff.noprefix` setting silencing every
diff, and a value-only edit to a multi-line definition seen by nothing. All three
have a row here, alongside the one this file lands with — a `const _: () =
assert!(…)` read as a constant named `_`, answering with 2381 sites.

The site lists are asserted, not just the names: a header over an empty list is
the shape a reporter fails in, and reading only the header cannot tell it from a
report that works.

⚠️ The fixture sources below are read by `impact.py` itself whenever *this* file
is edited — a `NAME = …` or `def name(` inside a string in a `.py` file is a
definition as far as the regexes are concerned. Hence the `fixture_` prefixes:
they are names `git grep -w` finds nowhere else, so this table cannot become the
flood it exists to close. (`def keep(…)` would have been 253 sites.)
"""

import pathlib
import re
import subprocess

import pytest

import impact

SCRIPT = pathlib.Path(impact.__file__).resolve()

#: A printed use site, `  path:line: text`. Matched rather than split on `:`, so
#: the report's own prose — the truncation line and the note beside it — cannot
#: be read back as a site.
SITE = re.compile(r"^ {2}(\S+:\d+): ")

#: A crate-shaped file: named constants of every shape the tool must still see —
#: single-line, multi-line, one-letter, underscore-prefixed — and the two shapes
#: that are spelled like one and are not, the anonymous constant and the const
#: generic parameter. `WIDTH` is the control: every case asserts it is still
#: reported, so a fix that silences the whole report fails here. New shapes go at
#: the end; the site lists below are line numbers.
RUST = """\
pub const WIDTH: usize = 32;
pub const N: usize = 4;
pub const TABLE: [u8; 3] = [
    1,
    2,
    3,
];
const _: () = assert!(WIDTH <= 64);
const _: () = {
    assert!(WIDTH > 0);
    assert!(TABLE[0] != 9);
};
const _KEEP: usize = WIDTH;

pub fn body() -> usize {
    WIDTH + _KEEP + N + TABLE[0] as usize
}

pub const WIDTH_MAX: usize = 64;
pub const WIDTH_MIN: usize = WIDTH_MAX / 2;

pub struct Wide<
    const N: usize,
> {
    pub data: [u8; N],
}

pub const SPANS: [&str; 3] = [
    "a ) b",
    "two",  // and one in a comment: )
    "three",
];
"""

PY = """\
FIXTURE_LIMIT = 7
_ = FIXTURE_LIMIT

FIXTURE_DOC = '''
placeholder
'''


def _(value):
    return value


def fixture_keep(value=FIXTURE_LIMIT):
    return value
"""

USER = """\
use crate::WIDTH;

pub fn other() -> usize {
    WIDTH * 2
}

pub fn spans() -> usize {
    crate::SPANS.len()
}
"""


#: Prose that says `N` more times than a report will print. `N` is a real
#: constant in `RUST` *and* an ordinary word here, and `git grep -w` cannot tell
#: the two apart — which is the whole of E132, and why order beats precision.
NOTES = "".join(f"Row {i}: the N in the table is the element count.\n" for i in range(1, 26))


class Tree:
    """A git checkout with the change staged, which is what the hook reports on."""

    def __init__(self, root, config=()):
        self.root = root
        self.write("src/lib.rs", RUST)
        self.write("src/other.rs", USER)
        self.write("tool.py", PY)
        self.write("docs/notes.md", NOTES)
        self.git("init", "-q")
        for key, value in config:
            self.git("config", key, value)
        self.git("add", "-A")
        self.git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args], capture_output=True, text=True, check=True
        ).stdout

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def run(self, unstaged=None):
        """The hook's own output over the change as staged.

        `unstaged` runs after `git add`, so the index and the worktree differ: the
        hunk line numbers belong to the staged side, and sizing the search by the
        other one measures lines nobody staged.
        """
        self.git("add", "-A")
        if unstaged:
            unstaged()
        self.text = subprocess.run(
            ["python3", str(SCRIPT)], cwd=self.root, capture_output=True, text=True, check=True
        ).stdout
        return self.text

    def report(self, unstaged=None):
        """`{name: [file:line, …]}` — what the hook prints, in the order it prints.

        The raw output stays on `self.text`, so a case can assert the report's
        prose — the order, the truncation note — off the same single run.
        """
        found, name = {}, None
        for line in self.run(unstaged).splitlines():
            if "(redefined in " in line:
                name = line.split()[0]
                found[name] = []
                announced = int(line.split("—")[1].split()[0])
            elif name and (site := SITE.match(line)):
                found[name].append(site.group(1))
                assert len(found[name]) <= announced, f"{name}: more sites than announced"
        return found

    def names(self):
        return sorted(self.report())


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def widen(tree):
    """Change the control's value, so every case has something to report."""
    tree.edit("src/lib.rs", "pub const WIDTH: usize = 32;", "pub const WIDTH: usize = 48;")


# --- the control, and the shape that drowned it --------------------------------


def test_a_changed_value_is_reported_with_the_sites_it_leaves_unread(tree):
    """The sites, not just the name — the list is the whole product.

    `WIDTH_MAX` and `WIDTH_MIN` are in the fixture for this list: they are the
    lines a `git grep` that lost `-w` would fold in.
    """
    widen(tree)
    report = tree.report()
    assert sorted(report) == ["WIDTH"]
    assert report["WIDTH"] == [
        "src/lib.rs:8",
        "src/lib.rs:10",
        "src/lib.rs:13",
        "src/lib.rs:16",
        "src/other.rs:1",
        "src/other.rs:4",
    ]


def test_a_change_that_touches_every_use_site_is_silent(tree):
    """"Prints nothing when every use site is inside the change" — the real quiet.

    An untouched tree returns before the parser runs, so it cannot show this.
    """
    widen(tree)
    tree.edit("src/lib.rs", "assert!(WIDTH <= 64);", "assert!(WIDTH <= 64); //")
    tree.edit("src/lib.rs", "assert!(WIDTH > 0);", "assert!(WIDTH > 0); //")
    tree.edit("src/lib.rs", "const _KEEP: usize = WIDTH;", "const _KEEP: usize = WIDTH; //")
    tree.edit("src/lib.rs", "WIDTH + _KEEP", "WIDTH  + _KEEP")
    tree.edit("src/other.rs", "use crate::WIDTH;", "use crate::WIDTH; //")
    tree.edit("src/other.rs", "WIDTH * 2", "WIDTH * 2 ")
    assert tree.report() == {}


def test_an_untouched_tree_reports_nothing(tree):
    assert tree.names() == []


def test_an_anonymous_constant_is_not_a_name(tree):
    """`const _` is Rust's hole. Reported, it answers with every `_` in the tree."""
    widen(tree)
    tree.edit("src/lib.rs", "assert!(WIDTH <= 64)", "assert!(WIDTH <= 96)")
    assert tree.names() == ["WIDTH"]


def test_a_line_inside_an_anonymous_constant_block_is_not_a_name(tree):
    """The multi-line form, which `enclosing_def` reaches rather than the regex."""
    widen(tree)
    tree.edit("src/lib.rs", "assert!(TABLE[0] != 9);", "assert!(TABLE[0] != 8);")
    assert tree.names() == ["WIDTH"]


def test_a_value_only_edit_to_a_multi_line_definition_is_reported(tree):
    """Run-34 #33, and the control for the case above.

    Both go through `enclosing_def`'s backward walk. Without this one, a walk that
    found nothing at all would satisfy every "not a name" case in the file.
    """
    tree.edit("src/lib.rs", "    2,\n", "    7,\n")
    report = tree.report()
    assert sorted(report) == ["TABLE"]
    # Not `src/lib.rs:3`: the definition's own line is not one of its users, and
    # here — unlike a single-line edit — the change does not touch it.
    assert report["TABLE"] == ["src/lib.rs:11", "src/lib.rs:16"]


def test_pythons_throwaway_binding_is_not_a_name(tree):
    """Same hole, same flood, other language — the family, not the instance."""
    tree.edit("tool.py", "FIXTURE_LIMIT = 7", "FIXTURE_LIMIT = 9")
    tree.edit("tool.py", "_ = FIXTURE_LIMIT", "_ = FIXTURE_LIMIT + 1")
    assert tree.names() == ["FIXTURE_LIMIT"]


def test_a_function_named_underscore_is_not_a_name(tree):
    tree.edit("tool.py", "FIXTURE_LIMIT = 7", "FIXTURE_LIMIT = 9")
    tree.edit("tool.py", "def _(value):", "def _(value, extra=None):")
    assert tree.names() == ["FIXTURE_LIMIT"]


# --- and the names that only look like it --------------------------------------


def test_an_underscore_prefixed_name_is_still_a_name(tree):
    """`_KEEP` is private, not anonymous. Excluding it would be the over-fix."""
    tree.edit("src/lib.rs", "const _KEEP: usize = WIDTH;", "const _KEEP: usize = WIDTH + 1;")
    assert tree.names() == ["_KEEP"]


def test_a_one_letter_name_is_still_a_name(tree):
    """The other over-fix: dropping short names to close the generic-parameter shape."""
    tree.edit("src/lib.rs", "pub const N: usize = 4;", "pub const N: usize = 5;")
    assert tree.names() == ["N"]


def test_a_const_generic_parameter_is_not_a_definition(tree):
    """A parameter list carries on with `,`; an item ends in `;`. E131.

    Giving the parameter a default is the diff shape a real edit makes, and the
    name it would report is the one a `git grep -w` floods on — 323 lines in this
    repo, where a proof harness's own `const N` makes `N` a real name too.
    """
    widen(tree)
    tree.edit("src/lib.rs", "    const N: usize,", "    const N: usize = 4,")
    assert tree.names() == ["WIDTH"]


def test_a_wide_name_does_not_bury_the_finding_beside_it(tree):
    """E132: some real names are too generic to grep, and that cannot be fixed.

    `N` is a constant here and a word in the prose; `git grep -w` answers with
    both. In name order the 28 lines printed above `WIDTH`'s six — the `_` flood
    again, with a name that is real. Narrowest first, and the count says what it
    is where the list is cut, which is where a reader of a flood is looking.
    """
    widen(tree)
    tree.edit("src/lib.rs", "pub const N: usize = 4;", "pub const N: usize = 5;")
    report = tree.report()
    assert list(report) == ["WIDTH", "N"]
    assert tree.text.index("WIDTH  (redefined") < tree.text.index("N  (redefined")
    # Announced in full, printed cut: a list nobody reaches the end of is the
    # shape this file exists to keep the report out of.
    assert "— 28 site(s) not in this change" in tree.text
    assert len(report["N"]) == impact.MAX_SITES
    assert "that count is `git grep -w N`" in tree.text


def test_a_bracket_in_a_string_or_a_comment_does_not_end_a_definition(tree):
    """A `//`-commented `)` used to close a span early, dropping the lines after it.

    Both decoys sit above the edited element, so a `code_only` blind to either one
    loses `SPANS` — and a lost definition is a use site nobody is told to read.
    """
    tree.edit("src/lib.rs", '    "three",', '    "four",')
    assert tree.names() == ["SPANS"]


def test_the_flood_does_not_hide_a_real_finding_beside_it(tree):
    """`4798668`'s shape: one real redefinition, one `const _`, one commit."""
    widen(tree)
    tree.edit(
        "src/lib.rs", "const _: () = assert!(WIDTH <= 64);", "const _: () = assert!(WIDTH <= 80);"
    )
    assert tree.names() == ["WIDTH"], "the anonymous constant is back in the report"


# --- the two defects the audit found and no test did ---------------------------


@pytest.mark.parametrize("setting", ["diff.mnemonicPrefix", "diff.noprefix"])
def test_a_personal_diff_prefix_setting_changes_nothing(tmp_path, setting):
    """Either one used to make every diff parse as empty — exit 0, silently.

    The sites are the assertion, not the name: `mnemonicPrefix` does not empty the
    report, it re-keys it under `w/src/lib.rs`, and every site in the change then
    reads as unread.
    """
    tree = Tree(tmp_path, config=[(setting, "true")])
    widen(tree)
    assert tree.report() == {
        "WIDTH": [
            "src/lib.rs:8",
            "src/lib.rs:10",
            "src/lib.rs:13",
            "src/lib.rs:16",
            "src/other.rs:1",
            "src/other.rs:4",
        ]
    }


def test_a_content_line_that_looks_like_a_header_does_not_retarget(tree):
    """Run-34 #34: `++ b/…` in a file's *body* becomes `+++ b/…` in its diff.

    Read as a header it moves `path`, so every later hunk of the same file lands
    under a name nobody has, and its use sites report as unread.
    """
    tree.edit("tool.py", "FIXTURE_LIMIT = 7", "FIXTURE_LIMIT = 9")
    tree.edit("tool.py", "placeholder", "++ b/decoy.py")
    tree.edit("tool.py", "def fixture_keep(value=FIXTURE_LIMIT):", "def fixture_keep(value=FIXTURE_LIMIT + 0):")
    report = tree.report()
    assert "tool.py:13" not in report.get("FIXTURE_LIMIT", []), report
