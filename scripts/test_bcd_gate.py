# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `bcd_gate.py` is verified against.

Four gate guards were written in one night and every one of them shipped with a
hole of the same family — a loop over an empty list, an exit code eaten by a
pipe, a rule that only looked at files that already existed. All four were found
by review, none by their author. So this arrives with the guard rather than
after it, and it asserts both directions: the cases that must fire, and the
cases that must **not**, which are the ones that decide whether a guard survives
its first false alarm.

The fixture is a real git history, because the rule is a question about one: the
base is a commit, the span reaches the working tree, and untracked files count.
A `#[cfg(test)]` hook, an inherited-gating sibling, a dev-dependency and an
integration target are all in it for the same reason — each is a shape the tree
produces weekly and none of them may fire.
"""

import pathlib
import subprocess

import pytest

import bcd_gate

MAIN = """#![no_std]

#[embassy_executor::main]
async fn main(_s: Spawner) {
    let device_release: u16 = 0x0100;
    config.device_release = device_release;
}
"""

LIB = """#![no_std]

pub const WIDTH: usize = 8;

pub fn judge(byte: u8) -> bool {
    byte < 0x80
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;
"""

TESTS = """use super::*;

#[path = "sub_tests.rs"]
mod sub_tests;

#[test]
fn judges() {
    assert!(judge(1));
}
"""

MANIFEST = """[package]
name = "rsk-a"
version = "0.1.0"

[dependencies]
minicbor = "2.2"

[dev-dependencies]
hex-literal = "1"
"""

CHANGELOG = """# Changelog

## [Unreleased]

- the first entry
"""


class Tree:
    """A checkout shaped like this one: a firmware, a crate, a cfg-gated sibling."""

    def __init__(self, root):
        self.root = root
        self.write("firmware/src/main.rs", MAIN)
        self.write("firmware/memory.x", "MEMORY { FLASH : ORIGIN = 0x10000000 }\n")
        self.write("crates/rsk-a/Cargo.toml", MANIFEST)
        self.write("crates/rsk-a/src/lib.rs", LIB)
        self.write("crates/rsk-a/src/tests.rs", TESTS)
        self.write("crates/rsk-a/src/sub_tests.rs", "use super::*;\n")
        self.write("crates/rsk-a/src/kani.rs", "use super::*;\n")
        self.write("crates/rsk-a/src/lib_tests.rs", "use super::*;\n")
        self.write("tools/host.py", "print('host only')\n")
        self.write("docs/protocol.md", "# Protocol\n")
        self.write("CHANGELOG.md", CHANGELOG)
        self.git("init", "-q")
        self.commit("the tree, and 0x0100")

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def append(self, rel, text):
        (self.root / rel).write_text((self.root / rel).read_text() + text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def commit(self, subject):
        self.git("add", "-A")
        self.git(
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            subject,
        )

    def bump(self, to="0x0101"):
        self.edit("firmware/src/main.rs", "0x0100", to)

    def note(self):
        self.append("CHANGELOG.md", "- a second entry\n")

    def problems(self):
        return bcd_gate.audit(self.root)[0]


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
    """The control the fixture cannot be: the tree these rules were written for."""
    assert bcd_gate.audit(bcd_gate.ROOT)[0] == []


# --- what reaches the image ---------------------------------------------------


def test_a_code_line_in_a_firmware_crate(tree):
    tree.append("crates/rsk-a/src/lib.rs", "\npub const EXTRA: u8 = 1;\n")
    assert only(tree.problems(), "pub const EXTRA")


def test_deleted_code_counts_too(tree):
    tree.edit("crates/rsk-a/src/lib.rs", "pub const WIDTH: usize = 8;\n", "")
    assert only(tree.problems(), "pub const WIDTH")


def test_a_brand_new_untracked_source_file(tree):
    """`git diff` cannot see it; a new module is exactly what this row is for."""
    tree.write("crates/rsk-a/src/extra.rs", "pub fn extra() -> u8 { 7 }\n")
    assert only(tree.problems(), "crates/rsk-a/src/extra.rs")


def test_a_non_rust_file_under_firmware(tree):
    tree.append("firmware/memory.x", "/* one more region */\n")
    assert only(tree.problems(), "firmware/memory.x")


def test_a_real_dependency(tree):
    tree.edit("crates/rsk-a/Cargo.toml", 'minicbor = "2.2"', 'minicbor = "2.3"')
    assert only(tree.problems(), "a table a lib build compiles from")


def test_a_plain_module_declaration_is_code(tree):
    """`mod x;` with no cfg pulls a file into the image, hook-shaped or not."""
    tree.write("crates/rsk-a/src/extra.rs", "pub fn extra() {}\n")
    tree.append("crates/rsk-a/src/lib.rs", "\nmod extra;\n")
    tree.commit("add the module and its file")
    assert only(tree.problems(), "mod extra;")


# --- what does not ------------------------------------------------------------


def test_a_doc_comment(tree):
    tree.append("crates/rsk-a/src/lib.rs", "\n/// A link fix that reaches no image.\n")
    assert tree.problems() == []


def test_an_ordinary_comment(tree):
    tree.append("crates/rsk-a/src/lib.rs", "\n// why, not what\n")
    assert tree.problems() == []


def test_a_cfg_gated_sibling(tree):
    tree.append("crates/rsk-a/src/tests.rs", "\n#[test]\nfn more() {}\n")
    assert tree.problems() == []


def test_gating_is_inherited_two_levels_down(tree):
    """`sub_tests.rs` carries no cfg of its own — `tests.rs` already did."""
    tree.append("crates/rsk-a/src/sub_tests.rs", "\n#[test]\nfn deeper() {}\n")
    assert tree.problems() == []


def test_a_kani_sibling(tree):
    tree.append("crates/rsk-a/src/kani.rs", "\n#[kani::proof]\nfn p() {}\n")
    assert tree.problems() == []


def test_a_newly_added_cfg_hook(tree):
    """The three lines that hook a sibling in, added at once."""
    tree.append(
        "crates/rsk-a/src/lib.rs",
        '\n#[cfg(test)]\n#[path = "lib_tests.rs"]\nmod more;\n',
    )
    assert tree.problems() == []


def test_a_dev_dependency(tree):
    tree.edit("crates/rsk-a/Cargo.toml", 'hex-literal = "1"', 'hex-literal = "2"')
    assert tree.problems() == []


def test_an_integration_target(tree):
    tree.write("crates/rsk-a/tests/it.rs", "#[test]\nfn it() {}\n")
    assert tree.problems() == []


def test_a_host_only_change(tree):
    tree.append("tools/host.py", "print('more')\n")
    assert tree.problems() == []


def test_a_docs_page(tree):
    tree.append("docs/protocol.md", "\nA clarification.\n")
    assert tree.problems() == []


def test_a_compile_time_assertion(tree):
    tree.append("crates/rsk-a/src/lib.rs", "\nconst _: () = assert!(WIDTH == 8);\n")
    assert tree.problems() == []


def test_a_reindent(tree):
    tree.edit("crates/rsk-a/src/lib.rs", "    byte < 0x80", "        byte < 0x80")
    assert tree.problems() == []


def test_a_cfg_attribute_over_shipped_code(tree):
    """`#[cfg(not(kani))]` emits nothing; what it gates is judged on its own lines."""
    tree.edit("crates/rsk-a/src/lib.rs", "pub fn judge", "#[cfg(not(kani))]\npub fn judge")
    assert tree.problems() == []


# --- the span, across commits -------------------------------------------------


def test_a_committed_change_with_no_bump(tree):
    tree.append("crates/rsk-a/src/lib.rs", "\npub const EXTRA: u8 = 1;\n")
    tree.commit("a firmware change that forgot the counter")
    assert only(tree.problems(), "pub const EXTRA")


def test_the_bump_may_arrive_later_in_the_working_tree(tree):
    tree.append("crates/rsk-a/src/lib.rs", "\npub const EXTRA: u8 = 1;\n")
    tree.commit("a firmware change that forgot the counter")
    tree.bump()
    tree.note()
    assert tree.problems() == []


def test_a_commit_that_only_moves_the_line_is_not_a_bump(tree):
    """`git log -G` matches a mover too; taking it would reset the base."""
    tree.edit("firmware/src/main.rs", "    let device_release", "\n    let device_release")
    tree.commit("reflow main.rs without touching the value")
    tree.append("crates/rsk-a/src/lib.rs", "\npub const EXTRA: u8 = 1;\n")
    tree.commit("a firmware change that forgot the counter")
    assert only(tree.problems(), "pub const EXTRA")


# --- the counter itself -------------------------------------------------------


def test_the_counter_may_not_go_down(tree):
    tree.bump("0x00FF")
    tree.note()
    assert only(tree.problems(), "it only goes up")


def test_the_counter_may_not_stand_still_across_a_bump_commit(tree):
    """A value re-used from a stale document reads as no bump at all."""
    tree.bump()
    tree.note()
    tree.commit("bump to 0x0101")
    tree.append("crates/rsk-a/src/lib.rs", "\npub const EXTRA: u8 = 1;\n")
    tree.edit("firmware/src/main.rs", "0x0101", "0x0100")
    assert only(tree.problems(), "it only goes up")


def test_the_binding_renamed_away(tree):
    tree.edit("firmware/src/main.rs", "let device_release: u16", "let rel: u16")
    assert only(tree.problems(), "no longer binds")


def test_a_history_that_never_bumped(tmp_path):
    """An empty history is not a green one: nothing pins what the counter was."""
    (tmp_path / "firmware/src").mkdir(parents=True)
    (tmp_path / "firmware/src/main.rs").write_text(MAIN)
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    problems, _ = bcd_gate.audit(tmp_path)
    assert only(problems, "no commit in this history ever changed the counter")


# --- CHANGELOG.md -------------------------------------------------------------


def test_a_bump_with_no_changelog_entry(tree):
    tree.bump()
    assert only(tree.problems(), "has not moved since HEAD")


def test_a_bump_with_a_changelog_entry(tree):
    tree.bump()
    tree.note()
    assert tree.problems() == []


def test_the_entry_may_arrive_in_the_next_commit(tree):
    """Requiring the same commit would leave the row red until the next bump."""
    tree.bump()
    tree.commit("bump to 0x0101, forgetting the entry")
    assert only(tree.problems(), "has not moved since")
    tree.note()
    assert tree.problems() == []


# --- the guard's own wiring ---------------------------------------------------


def test_check_sh_still_runs_the_guard():
    check = (bcd_gate.ROOT / "scripts/check.sh").read_text()
    assert "scripts/bcd_gate.py" in check


def test_the_tests_are_named_after_the_guard():
    """`check.sh` collects `scripts` wholesale, so the name is the registration."""
    here = pathlib.Path(__file__).name
    assert here == f"test_{pathlib.Path(bcd_gate.__file__).stem}.py"
