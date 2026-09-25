# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `shrink_gate.py` is verified against.

Same discipline as its siblings: the cases that must NOT fire are here in the
same number as the ones that must, because a roster that reddens on an ordinary
`#[cfg(test)]` is one somebody switches off within a week.

The weight is on the spellings. Every guard defect found in this tree this week
was a rule closed in one spelling and walked around by the next, so each form a
kani condition can take gets a case: `not(…)`, `all(…)`, `any(…)`, `cfg_attr`,
`cfg!` in an expression, an inner `#![cfg]`, one inside a macro body, one
rustfmt has wrapped over four lines, one written in a comment, one written in a
string, and a `feature` whose NAME contains the word. On the page's side, a name
in prose is not a row and a row is not satisfied by a name in prose.

The fixture is a two-file crate with one shrink and one proof module, small
enough that a failure names one rule.
"""

import pathlib

import pytest

import gate_lines
import shrink_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

LIB = """\
pub mod thing;

#[cfg(kani)]
#[path = "thing_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "thing_tests.rs"]
mod tests;
"""

THING = """\
/// The shipped width: what the device allocates, and what the protocol document
/// publishes to third-party hosts that have to size their own buffer for it.
#[cfg(not(kani))]
const BUF: usize = 2048;
/// Sixteen under `cfg(kani)`, because CBMC bit-blasts the array whole and the
/// sequence harness wants gigabytes at the shipped width. What it stops proving
/// is that a body longer than two frames is copied through without splicing.
#[cfg(kani)]
const BUF: usize = 16;

pub fn size() -> usize {
    BUF
}
"""

PROOFS = """\
#[kani::proof]
fn size_is_the_buffer() {
    assert!(super::size() > 0);
}
"""

TESTS = """\
#[test]
fn size_is_the_buffer() {
    assert!(super::size() > 0);
}
"""

PAGE = """\
# Testing

| Crate | Source | Kani-only item |
|---|---|---|
| `rsk-x` | `thing.rs` | `BUF` |
"""

#: A rationale long enough to clear the floor, so a case that is not about the
#: floor does not trip it.
REASON = (
    "/// Shrunk under `cfg(kani)` because the solver cannot carry the shipped\n"
    "/// width, and what that stops proving is written out here at length so the\n"
    "/// floor is cleared by prose rather than by padding.\n"
)


class Tree:
    """A checkout with one crate and one page."""

    def __init__(self, root):
        self.root = root
        self.src = root / "crates/rsk-x/src"
        self.src.mkdir(parents=True)
        self.write("lib.rs", LIB)
        self.write("thing.rs", THING)
        self.write("thing_kani.rs", PROOFS)
        self.write("thing_tests.rs", TESTS)
        self.page = root / "docs/testing.md"
        self.page.parent.mkdir(parents=True)
        self.page.write_text(PAGE)

    def write(self, name, text):
        (self.src / name).write_text(text)

    def append(self, name, text):
        (self.src / name).write_text((self.src / name).read_text() + text)

    def edit(self, name, old, new):
        path = self.src / name
        text = path.read_text()
        assert text.count(old) == 1, f"{name} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def problems(self):
        return shrink_gate.audit(self.root)[0]

    def roster(self):
        return shrink_gate.audit(self.root)[1]


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    return [p for p in problems if needle in p]


# --- the clean fixture, the real tree, and the wiring -------------------------


def test_clean_fixture_is_green(tree):
    assert tree.problems() == []


def test_the_fixture_rosters_exactly_one_item(tree):
    """A guard that derives nothing passes every case below."""
    assert dict(tree.roster()) == {("rsk-x", "thing.rs", "BUF"): 1}


def test_this_checkout_is_green():
    """The control the fixture cannot be: the tree these rules were written for."""
    assert shrink_gate.audit()[0] == []


def test_this_checkout_rosters_the_seven_names_and_seven_assertions():
    """The measurement the page's hand-written 'four' was wrong about."""
    derived = shrink_gate.audit()[1]
    named = sorted(key[2] for key in derived if key[2] != shrink_gate.ANONYMOUS)
    assert named == [
        "CHAIN_BUF_SIZE",
        "CTAP_MAX_MESSAGE",
        "EF_META",
        "FID_PRESENT_BYTES",
        "FRAME_BODY",
        "RESP_BUILD",
        "RESP_CHAIN_CAP",
    ]
    assert sum(v for k, v in derived.items() if k[2] == shrink_gate.ANONYMOUS) == 7


def test_check_sh_runs_this_guard():
    """The row, not the file: a `#` in front of it is not a row, and every
    assertion that a guard is wired in has been satisfied by one before."""
    assert gate_lines.runs((ROOT / "scripts/check.sh").read_text(), "scripts/shrink_gate.py")


# --- what must fire ----------------------------------------------------------


def test_a_shrink_that_arrives_unrostered(tree):
    tree.append("thing.rs", REASON + "#[cfg(kani)]\nconst SECOND: usize = 4;\n")
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `SECOND`")


def test_a_row_whose_item_has_gone_away(tree):
    tree.page.write_text(PAGE + "| `rsk-x` | `thing.rs` | `GONE` |\n")
    assert only(tree.problems(), "rosters `rsk-x` `thing.rs` `GONE`")


def test_a_shrink_with_no_reason_above_it(tree):
    tree.edit("thing.rs", "/// Sixteen under `cfg(kani)`, because CBMC bit-blasts the array whole and the\n"
                          "/// sequence harness wants gigabytes at the shipped width. What it stops proving\n"
                          "/// is that a body longer than two frames is copied through without splicing.\n", "")
    assert only(tree.problems(), "with no reason written above it")


def test_a_reason_too_short_to_be_one(tree):
    tree.edit("thing.rs", "/// Sixteen under `cfg(kani)`, because CBMC bit-blasts the array whole and the\n"
                          "/// sequence harness wants gigabytes at the shipped width. What it stops proving\n"
                          "/// is that a body longer than two frames is copied through without splicing.\n",
              "// shrunk\n")
    assert only(tree.problems(), "with no reason written above it")


def test_a_kani_decision_inside_an_expression(tree):
    tree.edit("thing.rs", "    BUF\n", "    if cfg!(kani) { 16 } else { BUF }\n")
    assert only(tree.problems(), "inside an expression (`cfg!`)")


def test_a_whole_production_file_gated_by_an_inner_attribute(tree):
    tree.edit("thing.rs", "/// The shipped width", "#![cfg(kani)]\n/// The shipped width")
    assert only(tree.problems(), "gates the whole file on kani with an inner")


def test_an_item_this_roster_cannot_name(tree):
    tree.append("thing.rs", "\n#[cfg(kani)]\nimpl Thing {}\n")
    assert only(tree.problems(), "kani-conditioned `impl` this")


def test_a_file_no_module_declaration_reaches(tree):
    tree.write("orphan.rs", "#[cfg(kani)]\nconst HIDDEN: usize = 1;\n")
    assert only(tree.problems(), "no `mod` declaration reaches it")


def test_a_module_declared_over_a_file_that_is_not_there(tree):
    tree.edit("lib.rs", "pub mod thing;", "pub mod thing;\npub mod absent;")
    assert only(tree.problems(), "declared as a module but does not exist")


def test_all_kani_and_a_feature_is_still_a_shrink(tree):
    """`all(kani, …)` is false without kani, so it is a condition of its own —
    the fail-closed direction, since nobody has decided what it should mean."""
    tree.append("thing.rs", REASON + '#[cfg(all(kani, feature = "x"))]\nconst NARROW: usize = 4;\n')
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `NARROW`")


def test_any_kani_without_test_is_still_a_shrink(tree):
    tree.append("thing.rs", REASON + '#[cfg(any(kani, feature = "x"))]\nconst WIDE: usize = 4;\n')
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `WIDE`")


def test_cfg_attr_is_read_through_to_its_predicate(tree):
    """`cfg_attr(kani, …)` changes production source under Kani and nothing else."""
    tree.append("thing.rs", REASON + "#[cfg_attr(kani, repr(C))]\nstruct Narrowed;\n")
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `Narrowed`")


def test_an_arm_set_spelled_with_test_is_still_a_shrink(tree):
    """The way through the scaffolding exclusion, closed: two arms of one name,
    one of them mentioning kani, shrink production however they are spelled."""
    tree.edit("thing.rs", "#[cfg(not(kani))]\nconst BUF: usize = 2048;",
              "#[cfg(not(any(kani, test)))]\nconst BUF: usize = 2048;")
    tree.edit("thing.rs", "#[cfg(kani)]\nconst BUF: usize = 16;",
              "#[cfg(any(kani, test))]\nconst BUF: usize = 16;")
    tree.page.write_text(PAGE.replace("| `rsk-x` | `thing.rs` | `BUF` |\n", ""))
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `BUF`")


def test_a_cfg_inside_a_macro_body_is_read(tree):
    tree.append(
        "thing.rs",
        "\nmacro_rules! widths {\n    () => {\n" + REASON.replace("///", "        //")
        + "        #[cfg(kani)]\n        const INNER: usize = 2;\n    };\n}\n",
    )
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `INNER`")


def test_a_rustfmt_wrapped_attribute_is_read(tree):
    tree.append(
        "thing.rs",
        REASON + '#[cfg(all(\n    kani,\n    feature = "x"\n))]\nconst WRAPPED: usize = 4;\n',
    )
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `WRAPPED`")


def test_a_reason_above_a_wrapped_attribute_is_still_found(tree):
    """The half the case above cannot see. Scanning upward from the ITEM rather
    than from the attribute lands on `feature = "x"` and reports a reason that is
    sitting right there — measured: with the roster case alone, that mutation of
    this guard survived the whole table."""
    tree.append(
        "thing.rs",
        REASON + '#[cfg(all(\n    kani,\n    feature = "x"\n))]\nconst WRAPPED: usize = 4;\n',
    )
    tree.page.write_text(PAGE + "| `rsk-x` | `thing.rs` | `WRAPPED` |\n")
    assert tree.problems() == []


def test_a_feature_gated_module_still_ships(tree):
    """A `mod` behind a build feature is production; only `kani` and `test` take
    a file out of the walk."""
    tree.write("extra.rs", REASON + "#[cfg(kani)]\nconst EXTRA: usize = 1;\n")
    tree.edit("lib.rs", "pub mod thing;", 'pub mod thing;\n#[cfg(feature = "display")]\npub mod extra;')
    assert only(tree.problems(), "has no row for `rsk-x` `extra.rs` `EXTRA`")


def test_a_blank_line_breaks_the_run_and_the_reason_is_owed_again(tree):
    """The other direction of the same rule: an arm that is not the next item of
    the paragraph's run does not get to borrow it."""
    tree.edit("thing.rs", "#[cfg(kani)]\nconst BUF: usize = 16;",
              "#[cfg(kani)]\nconst BUF: usize = 16;\n\n#[cfg(kani)]\nconst PAIR: usize = 16;")
    tree.page.write_text(PAGE + "| `rsk-x` | `thing.rs` | `PAIR` |\n")
    assert only(tree.problems(), "`PAIR` under kani with no reason")


def test_a_name_in_prose_is_not_a_row(tree):
    """The page's own rot, reproduced: the sentence named three shrinks for
    months. A roster read out of prose is a roster that cannot lose an entry."""
    tree.page.write_text(
        PAGE.replace("| `rsk-x` | `thing.rs` | `BUF` |\n", "")
        + "\n`rsk-x` shrinks `BUF` under `cfg(kani)`, and that is all of them.\n"
    )
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `BUF`")


# --- what must NOT fire ------------------------------------------------------


def test_a_proof_module_hook_is_not_a_shrink(tree):
    """`#[cfg(kani)] #[path] mod proofs;` is the proof, not a narrowing of what
    it proves. Rostering the fifty of those would bury the eight that matter."""
    assert not only(tree.problems(), "proofs")


def test_verification_scaffolding_is_not_a_shrink(tree):
    """`any(test, kani)` is present in a `cargo test` build for the same reason
    it is present under Kani — it belongs to the test layer."""
    tree.append("thing.rs", "\n#[cfg(any(test, kani))]\nconst PROBE: usize = 7;\n")
    assert tree.problems() == []


def test_a_shrink_inside_a_verification_file_is_not_production(tree):
    """`rsk-fs`'s `store_assurance.rs` shrinks a FID limit; the file is reached
    only through `#[cfg(any(kani, test))] mod`, so it never ships."""
    tree.append("thing_kani.rs", "\n#[cfg(kani)]\nconst FID_LIMIT: usize = 3;\n")
    assert tree.problems() == []


def test_a_cfg_written_in_a_comment_is_not_an_item(tree):
    """The defect a guard two files over shipped with: four of twelve files
    entered an inventory because of a line saying those files have none."""
    tree.append("thing.rs", "\n// Never `#[cfg(kani)] const GHOST: usize = 1;` — see above.\n")
    assert tree.problems() == []


def test_a_cfg_written_in_a_string_is_not_an_item(tree):
    tree.append(
        "thing.rs",
        '\npub const SAMPLE: &str = "#[cfg(kani)] const GHOST: usize = 1;";\n',
    )
    assert tree.problems() == []


def test_a_feature_whose_name_contains_the_word_is_not_the_flag(tree):
    tree.append("thing.rs", '\n#[cfg(feature = "kani-bounds")]\nconst FEATURED: usize = 9;\n')
    assert tree.problems() == []


def test_a_quote_inside_a_byte_literal_does_not_blind_the_walk(tree):
    """`b'"'` in `rsk-usb`'s keyboard map opened a string that ran to the end of
    the file, and the walk then read that file as declaring no modules."""
    tree.edit("lib.rs", "pub mod thing;", "pub const QUOTE: u8 = b'\"';\npub mod thing;")
    assert tree.problems() == []


def test_a_second_arm_of_a_run_inherits_the_paragraph_above_it(tree):
    """`rsk-sdk` writes one paragraph over both of its constants and says so."""
    tree.edit("thing.rs", "#[cfg(kani)]\nconst BUF: usize = 16;",
              "#[cfg(kani)]\nconst BUF: usize = 16;\n#[cfg(kani)]\nconst PAIR: usize = 16;")
    tree.edit("thing.rs", "#[cfg(not(kani))]\nconst BUF: usize = 2048;",
              "#[cfg(not(kani))]\nconst BUF: usize = 2048;\n#[cfg(not(kani))]\nconst PAIR: usize = 2048;")
    tree.page.write_text(PAGE + "| `rsk-x` | `thing.rs` | `PAIR` |\n")
    assert tree.problems() == []


def test_a_padded_table_row_is_still_a_row(tree):
    tree.page.write_text(PAGE.replace("| `rsk-x` | `thing.rs` | `BUF` |",
                                      "|  `rsk-x`  |  `thing.rs`  |  `BUF`  |"))
    assert tree.problems() == []


def test_the_anonymous_assertions_are_rostered_one_by_one(tree):
    """They have no name to collapse on, so a second one in a file is a row the
    page still owes — which is what keeps the compensating half countable."""
    tree.append(
        "thing.rs",
        REASON + "#[cfg(not(kani))]\nconst _: () = assert!(BUF > 0);\n"
        + REASON + "#[cfg(not(kani))]\nconst _: () = assert!(BUF < 4096);\n",
    )
    tree.page.write_text(PAGE + "| `rsk-x` | `thing.rs` | `const _` |\n")
    assert only(tree.problems(), "has no row for `rsk-x` `thing.rs` `const _`")
