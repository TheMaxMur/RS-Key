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
    const N: usize,  // element count; one per lane
    const M: usize>
{
    pub data: [u8; N],
    pub more: [u8; M],
}

pub const SPANS: [&str; 3] = [
    "a ) b",
    "two",  // and one in a comment: )
    "three",
];

pub const SLOTS: usize = 8; /* was 4 before the bank split,
                               so this line ends on that comma */

pub static WORDS: [&str; 1] = ["w"];
pub(crate) const SERIAL_OFF: usize = 4;
pub static mut SCRATCH: u8 = 0;

pub const PAIR: [u8; 2] = [1,
    2];

pub const DELIMS: [u8; 2] = [
    b')',
    b'(',
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


class FixtureHolder:
    def fixture_method(self):
        return fixture_keep(FIXTURE_LIMIT)


def fixture_call(holder):
    return holder.fixture_method()


FIXTURE_SPANS = [
    'a ) b',
    "two",  # and one in a comment: )
    "say \\" ) done",
    'four',
]


def fixture_span_use():
    return len(FIXTURE_SPANS)
"""

#: A second file defining a name `src/lib.rs` also defines. Two modules each with
#: their own `SERIAL_OFF` is ordinary; what is not ordinary is dropping this line
#: from the report because it *looks* like the definition being changed.
DUP = """\
pub(crate) const SERIAL_OFF: usize = 9;
"""

USER = """\
use crate::WIDTH;

pub fn other() -> usize {
    WIDTH * 2
}

pub fn spans() -> usize {
    crate::SPANS.len()
}

pub fn sized() -> usize {
    crate::SLOTS + crate::SERIAL_OFF + crate::WORDS.len()
}

pub fn scratch() -> u8 {
    unsafe { crate::SCRATCH }
}

pub fn pair() -> u8 {
    crate::PAIR[0]
}

pub fn delims() -> u8 {
    crate::DELIMS[0]
}
"""


#: Prose that says `N` more times than a report will print. `N` is a real
#: constant in `RUST` *and* an ordinary word here, and `git grep -w` cannot tell
#: the two apart — which is the whole of E132, and why order beats precision.
#:
#: The first line names a constant the tree does not define yet: docs describing
#: a thing before the code lands is how a brand-new definition comes with a use
#: site already on it, which is what makes the `fresh` guard visible.
NOTES = "The FIXTURE_ROW column is reserved.\n" + "".join(
    f"Row {i}: the N in the table is the element count.\n" for i in range(1, 26)
)


class Tree:
    """A git checkout with the change staged, which is what the hook reports on."""

    def __init__(self, root, config=()):
        self.root = root
        self.write("src/lib.rs", RUST)
        self.write("src/other.rs", USER)
        self.write("src/dup.rs", DUP)
        self.write("tool.py", PY)
        self.write("docs/notes.md", NOTES)
        self.git("init", "-q")
        for key, value in config:
            self.git("config", key, value)
        self.git("add", "-A")
        self.land("base")

    def land(self, message="landed"):
        """Commit what is staged. A rev-range needs two sides to compare."""
        self.git("add", "-A")
        self.git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", message)

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

    def run(self, unstaged=None, *args):
        """The hook's own output over the change as staged.

        `unstaged` runs after `git add`, so the index and the worktree differ: the
        hunk line numbers belong to the staged side, and sizing the search by the
        other one measures lines nobody staged.

        `self.err` keeps stderr: the one thing this tool prints there is an alarm,
        and an alarm is judged by when it stays quiet as much as by when it fires.
        """
        self.git("add", "-A")
        if unstaged:
            unstaged()
        done = subprocess.run(
            ["python3", str(SCRIPT), *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        )
        self.text, self.err = done.stdout, done.stderr
        return self.text

    def report(self, unstaged=None, *args):
        """`{name: [file:line, …]}` — what the hook prints, in the order it prints.

        The raw output stays on `self.text`, so a case can assert the report's
        prose — the order, the truncation note — off the same single run.
        """
        found, name = {}, None
        for line in self.run(unstaged, *args).splitlines():
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


def test_a_method_signature_is_not_a_module_level_definition(tree):
    """E200. `\\s*def` matched an indented one, so every helper here was a flood.

    It fired on this branch's own anti-flood commit: `Tree.report`'s signature
    changed and the hook answered with 322 sites — as the *only* row, so E132's
    narrowest-first had nothing to sort. `run` is 2568 lines here, `write` 1232.
    The `NAME = …` half was anchored from the start; this is the same anchor.
    """
    tree.edit("tool.py", "FIXTURE_LIMIT = 7", "FIXTURE_LIMIT = 9")
    tree.edit(
        "tool.py", "    def fixture_method(self):", "    def fixture_method(self, extra=None):"
    )
    assert tree.names() == ["FIXTURE_LIMIT"]


def test_a_module_level_def_signature_is_still_a_definition(tree):
    """The over-fix: anchoring must not silence the shape this *is* scoped to."""
    tree.edit(
        "tool.py",
        "def fixture_keep(value=FIXTURE_LIMIT):",
        "def fixture_keep(value=FIXTURE_LIMIT, extra=None):",
    )
    report = tree.report()
    assert sorted(report) == ["fixture_keep"]
    assert report["fixture_keep"] == ["tool.py:19"]


# --- and the names that only look like it --------------------------------------


def test_an_underscore_prefixed_name_is_still_a_name(tree):
    """`_KEEP` is private, not anonymous. Excluding it would be the over-fix."""
    tree.edit("src/lib.rs", "const _KEEP: usize = WIDTH;", "const _KEEP: usize = WIDTH + 1;")
    assert tree.names() == ["_KEEP"]


def test_a_one_letter_name_is_still_a_name(tree):
    """The other over-fix: dropping short names to close the generic-parameter shape."""
    tree.edit("src/lib.rs", "pub const N: usize = 4;", "pub const N: usize = 5;")
    assert tree.names() == ["N"]


@pytest.mark.parametrize(
    "old, new",
    [
        (
            "    const N: usize,  // element count; one per lane",
            "    const N: u32,  // element count; one per lane",
        ),
        ("    const M: usize>", "    const M: u32>"),
    ],
)
def test_a_const_generic_parameter_is_not_a_definition(tree, old, new):
    """E131. A parameter has neither a value nor a `;`; an item has one or both.

    The name it would report is the one a `git grep -w` floods on — 323 lines in
    this repo, where a proof harness's own `const N` makes `N` a real name too.
    That trailing comment carries a `;` on purpose: read off the raw line rather
    than `code_only`'s, the semicolon alone makes the parameter look like an item.
    """
    widen(tree)
    tree.edit("src/lib.rs", old, new)
    assert tree.names() == ["WIDTH"]


def test_an_item_whose_line_ends_on_a_comma_is_still_an_item(tree):
    """The reason the discriminator is positive and not a list of endings.

    `PAIR`'s first line really does end on `,`, with no comment involved — so the
    blacklist spelling drops it while the scanner is working perfectly. Reading
    what an item *has* cannot fail that way.
    """
    tree.edit("src/lib.rs", "pub const PAIR: [u8; 2] = [1,", "pub const PAIR: [u8; 2] = [3,")
    assert tree.names() == ["PAIR"]


def test_a_block_comment_does_not_hide_a_definition(tree):
    """The regression E131's first spelling shipped, found by review.

    `SLOTS` is an ordinary item whose line ends on a comma inside an unterminated
    `/* … */`. Judged by what the line *ends with*, it vanishes from the report
    entirely — a use site nobody is told to read, which is the one direction this
    file must not fail in.
    """
    tree.edit("src/lib.rs", "pub const SLOTS: usize = 8;", "pub const SLOTS: usize = 9;")
    report = tree.report()
    assert sorted(report) == ["SLOTS"]
    assert report["SLOTS"] == ["src/other.rs:12"]


@pytest.mark.parametrize(
    "old, new, name",
    [
        ('pub static WORDS: [&str; 1] = ["w"];', 'pub static WORDS: [&str; 1] = ["z"];', "WORDS"),
        (
            "pub(crate) const SERIAL_OFF: usize = 4;",
            "pub(crate) const SERIAL_OFF: usize = 5;",
            "SERIAL_OFF",
        ),
        ("pub static mut SCRATCH: u8 = 0;", "pub static mut SCRATCH: u8 = 1;", "SCRATCH"),
    ],
)
def test_every_alternative_in_the_rust_pattern_is_reached(tree, old, new, name):
    """`static`, `pub(crate)` and `static mut` were in the regex and in no fixture.

    89 `static`, 101 restricted-visibility and 3 `static mut` definitions rest on
    alternatives no case had ever driven.
    """
    tree.edit("src/lib.rs", old, new)
    assert tree.names() == [name]


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


def test_the_python_half_of_the_scanner_reads_its_own_quotes_and_comments(tree):
    """E205. `'`, `#` and the escape step were Rust's fixture's job by accident.

    Three decoys above the edited element, one per half: a `'`-quoted bracket, a
    `#`-commented one, and one behind an escaped quote — where a scanner that
    steps over `\\` by one closes the string early and reads the rest as code.
    Any of the three loses `FIXTURE_SPANS`, which is the dropped-definition
    direction, in the language `defined()` reaches through `bracket_delta`.
    """
    tree.edit("tool.py", "    'four',", "    'five',")
    report = tree.report()
    assert sorted(report) == ["FIXTURE_SPANS"]
    assert report["FIXTURE_SPANS"] == ["tool.py:35"]


def test_a_char_literal_does_not_end_a_definition(tree):
    """E206. `b')'` is a bracket the source never had, and it cut the span short.

    The decoy is the *first* element, so a scanner that spends it closes `DELIMS`
    before reaching the edited one and the definition drops out of the report
    entirely — the false-negative direction, not the over-reading one the block
    comment gives. A lifetime has no closing quote, which is what keeps this from
    blanking `&'a str` and losing a definition the other way round.
    """
    tree.edit("src/lib.rs", "    b'(',", "    b'{',")
    report = tree.report()
    assert sorted(report) == ["DELIMS"]
    assert report["DELIMS"] == ["src/other.rs:24"]


def test_the_flood_does_not_hide_a_real_finding_beside_it(tree):
    """`4798668`'s shape: one real redefinition, one `const _`, one commit."""
    widen(tree)
    tree.edit(
        "src/lib.rs", "const _: () = assert!(WIDTH <= 64);", "const _: () = assert!(WIDTH <= 80);"
    )
    assert tree.names() == ["WIDTH"], "the anonymous constant is back in the report"


# --- the deletion anchor, and the side the line numbers belong to ---------------


def test_a_deletion_inside_a_multi_line_definition_is_reported(tree):
    """A pure deletion adds no post-side line, so it is anchored on the one above.

    Dropping an element from a constant is a value change like any other; with no
    anchor the hunk carries no line into `enclosing_def` and the edit is invisible.

    The *last* element on purpose: with a middle one, an anchor off by one still
    lands inside the statement and the row asserts nothing about where it points.
    """
    tree.edit("src/lib.rs", "    3,\n", "")
    report = tree.report()
    assert sorted(report) == ["TABLE"]
    assert report["TABLE"] == ["src/lib.rs:10", "src/lib.rs:15"]


def test_a_deletion_below_a_definition_is_not_attributed_to_it(tree):
    """The anchor sits on the line above, which may be the statement's *last* one.

    `below` is what asks whether the definition continues past the anchor. Without
    it, deleting the line after `];` reads as an edit to `TABLE`.
    """
    tree.edit("src/lib.rs", "const _: () = assert!(WIDTH <= 64);\n", "")
    assert tree.report() == {}


def test_the_search_is_sized_by_the_staged_side_not_the_worktree(tree):
    """The hunk line numbers belong to the index, so `post_lines` reads the index.

    Two wrong sides to read, and the staged padding separates them. Reading the
    *worktree* sizes the search by lines nobody staged; reading the diff's
    *pre-image* misses the twenty staged lines above `TABLE`. Both land the hunk's
    line number in padding that encloses no definition at all.
    """

    def decoy():
        path = tree.root / "src/lib.rs"
        path.write_text("// unstaged\n" * 9 + path.read_text())

    tree.edit(
        "src/lib.rs",
        "pub struct Wide<\n    const N: usize,  // element count; one per lane\n"
        "    const M: usize>\n{\n    pub data: [u8; N],\n    pub more: [u8; M],\n}\n\n",
        "",
    )
    tree.edit("src/lib.rs", "pub static mut SCRATCH: u8 = 0;", "pub static mut SCRATCH: u8 = 1;")
    report = tree.report(unstaged=decoy)
    assert sorted(report) == ["SCRATCH"]
    # Asserted, not just the name: a header over an empty list is the shape a
    # reporter fails in. The sites are worktree line numbers — `uses()` greps the
    # worktree while `touched` comes from the index, which is its own known limit.
    assert report["SCRATCH"] == ["src/other.rs:16"]


# --- what `redefinitions` refuses to call a redefinition ------------------------


def test_a_brand_new_definition_is_not_a_redefinition(tree):
    """E203. Added-only is new: nothing downstream can have gone unread yet.

    `FIXTURE_ROW` is named in the docs before the code lands — the ordinary way a
    fresh definition arrives with a `git grep` hit already on it, and the only way
    the guard's absence is visible at all.
    """
    tree.edit(
        "src/lib.rs",
        "pub const WIDTH: usize = 32;\n",
        "pub const WIDTH: usize = 32;\npub const FIXTURE_ROW: usize = 3;\n",
    )
    assert tree.report() == {}


def test_a_definition_line_re_emitted_unchanged_is_a_rewrite_around_it(tree):
    """E203. Moving a constant writes its line on both sides, identically.

    The value did not change, so the users do not need re-reading — and the first
    clause cannot see it, because a move puts the same text in `gone` and `born`
    and the touched line is the definition's own.
    """
    tree.edit("src/lib.rs", "pub(crate) const SERIAL_OFF: usize = 4;\n", "")
    tree.edit(
        "src/lib.rs",
        "pub const WIDTH: usize = 32;\n",
        "pub const WIDTH: usize = 32;\npub(crate) const SERIAL_OFF: usize = 4;\n",
    )
    assert tree.report() == {}


def test_another_files_definition_of_the_same_name_is_still_a_site(tree):
    """E203. `is_def` excuses the definition being changed, not every namesake.

    `src/dup.rs` defines its own `SERIAL_OFF`; dropping it from the list because
    it *looks* like a definition line hides the site most worth reading — a second
    owner of the same name, which is where a narrowed constant does its damage.
    """
    tree.edit(
        "src/lib.rs",
        "pub(crate) const SERIAL_OFF: usize = 4;",
        "pub(crate) const SERIAL_OFF: usize = 5;",
    )
    report = tree.report()
    assert sorted(report) == ["SERIAL_OFF"]
    assert report["SERIAL_OFF"] == ["src/dup.rs:1", "src/other.rs:12"]


# --- the rev-range path, which nothing drives ----------------------------------


def test_a_rev_range_is_sized_by_its_own_second_side(tree):
    """E202. `A..B`'s hunk numbers belong to B, so `post_lines` must read B.

    Nothing drives this path — the hook always reports on the index — so the whole
    expression that picks the side was asserted by nothing. The working tree is
    padded *after* the commit lands: read from there instead of from B, the hunk's
    line number falls in padding that encloses no definition at all.
    """
    tree.edit("src/lib.rs", "    2,\n", "    7,\n")
    tree.land()
    path = tree.root / "src/lib.rs"
    path.write_text("// landed after\n" * 9 + path.read_text())
    assert sorted(tree.report(None, "HEAD~1..HEAD")) == ["TABLE"]


def test_an_open_ended_rev_range_ends_at_HEAD(tree):
    """`A..` names HEAD, and `rsplit` hands back `''` for it.

    Without the fallback the side reads as `":"` — the index — which the same
    padding separates from HEAD, since the run stages it.
    """
    tree.edit("src/lib.rs", "    2,\n", "    7,\n")
    tree.land()
    path = tree.root / "src/lib.rs"
    path.write_text("// landed after\n" * 9 + path.read_text())
    assert sorted(tree.report(None, "HEAD~1..")) == ["TABLE"]


def test_a_bare_revision_compares_it_to_the_working_tree(tree):
    """No `..`, so the hunk numbers belong to the worktree and nothing else.

    The decoy renames a constant *after* the run stages it, so one line number
    carries two different names. Read from the worktree it is a brand-new one and
    nothing is owed; read from the index it is the old one, mid-rename, and the
    report gains a row the change never made. Padding proves nothing on this path
    — the padding is in the diff either way, so both readings answer `TABLE`.
    """

    def decoy():
        path = tree.root / "src/dup.rs"
        path.write_text(path.read_text().replace("SERIAL_OFF", "DUP_ONLY"))

    tree.edit("src/lib.rs", "    2,\n", "    7,\n")
    tree.land()
    assert sorted(tree.report(decoy, "HEAD~1")) == ["TABLE"]


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


# --- the alarm, and the commits it has nothing to say about --------------------

#: The alarm's own words, matched on stderr. It is judged by when it stays quiet
#: as much as by when it fires: a warning that greets `git mv` is one nobody reads
#: twice, and the signal it carries is gone by the time it is needed.
ALARM = "could not parse the diff"


@pytest.mark.parametrize("shape", ["a new binary asset", "chmod +x", "git mv"])
def test_a_contentless_change_is_not_a_diff_nobody_could_parse(tree, shape):
    """E204. All three carry no `+++` header and no hunk — by design, not by defeat.

    Read as a parse failure they spent the one alarm this tool has on the commit
    shapes it has least to say about, and this repo has both kinds: 23 tracked
    binary assets and 17 executable scripts.
    """
    if shape == "a new binary asset":
        (tree.root / "assets").mkdir()
        (tree.root / "assets/blob.bin").write_bytes(bytes(range(32)))
    elif shape == "chmod +x":
        (tree.root / "tool.py").chmod(0o755)
    else:
        tree.git("mv", "src/other.rs", "src/moved.rs")
    assert tree.report() == {}
    assert ALARM not in tree.err, tree.err


def test_a_diff_whose_hunks_name_no_file_is_still_an_alarm(tree, tmp_path_factory):
    """The direction that fix must not close: content nothing could file.

    `diff.external` hands git's whole output to another program — one of the very
    `git config diff.*` settings the message sends the reader to look at, and the
    only way a hunk reaches this parser with no file to its name.
    """
    driver = tmp_path_factory.mktemp("ext") / "diff.sh"
    driver.write_text('#!/bin/sh\nprintf "@@ -1 +1 @@\\n-x\\n+y\\n"\n')
    driver.chmod(0o755)
    tree.git("config", "diff.external", str(driver))
    widen(tree)
    assert tree.report() == {}
    assert ALARM in tree.err, tree.err
