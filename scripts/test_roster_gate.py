# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `roster_gate.py` was verified by hand against, kept.

Each round of that guard was checked by editing the real tree, running it, and
reading the message — a battery that lives in a terminal scrollback and has to
be re-derived by whoever touches it next. Three of one review's top findings
were the previous round's fixes applied incompletely, which is what an untested
guard costs. So the table is a fixture instead: a four-crate workspace with one
copy of each file that carries a selection, mutated one thing at a time.

Both directions are asserted. A guard that cannot go green is deleted as fast
as one that cannot go red, and the false alarms are the reason this one shrank
— a one-crate example, a `--features` row, a source comment and a changelog
line each read as a broken roster once.
"""

import pathlib
import subprocess

import pytest

import roster_gate

CHECK = """#!/usr/bin/env bash
run "clippy (embedded)"   env BOARD=x cargo clippy --workspace -- -D warnings
run "clippy (host tests)" cargo clippy --workspace --exclude firmware --exclude rsk-wipe --target "$HOST" --all-targets -- -D warnings
run "rustdoc (host)"      cargo doc --workspace --exclude firmware --exclude rsk-wipe --no-deps --target "$HOST"
run "rustdoc (embedded)"  env BOARD=x cargo doc -p firmware -p rsk-wipe --no-deps
run "test (host)"         cargo test --workspace --exclude firmware --exclude rsk-wipe --target "$HOST"
run "test (strict-cfg)"   cargo test -p rsk-a -p rsk-b --features strict-config --target "$HOST"
run "crate roster"        python scripts/roster_gate.py
run "pytest (gate)"       python -m pytest scripts -q
"""

DOCS = """# Testing

```sh
nix develop -c cargo test --workspace --exclude firmware --exclude rsk-wipe \\
    --target aarch64-apple-darwin
```

One crate at a time: `cargo test -p rsk-a`.
"""

WORKFLOW = """# Local equivalents:
#   nix develop -c cargo llvm-cov --summary-only --fail-under-lines 80 --target <host> --workspace --exclude firmware --exclude rsk-wipe

name: deep-checks
jobs:
  coverage:
    steps:
      - name: llvm-cov
        run: |
          nix develop -c cargo llvm-cov --summary-only --fail-under-lines 80 \\
            --target x86_64-unknown-linux-gnu \\
            --workspace --exclude firmware --exclude rsk-wipe
"""

FLAKE = """{
  cargo-test = {
    buildPhase = ''
      cargo test --offline --frozen --target ${hostTarget} \\
        --workspace --exclude firmware --exclude rsk-wipe
    '';
  };
}
"""

MEMBERS = ("firmware", "rsk-wipe", "crates/rsk-a", "crates/rsk-b")


class Tree:
    """A checkout shaped like this one: four members, one copy of each file."""

    def __init__(self, root, members=MEMBERS):
        self.root = root
        self.write(
            "Cargo.toml",
            "[workspace]\nmembers = [%s]\n" % ", ".join(f'"{m}"' for m in members),
        )
        for rel in members:
            name = rel.rpartition("/")[2]
            self.write(f"{rel}/Cargo.toml", f'[package]\nname = "{name}"\n')
        self.write(roster_gate.CHECK, CHECK)
        self.write(roster_gate.DOCS, DOCS)
        self.write(roster_gate.WORKFLOW, WORKFLOW)
        self.write(roster_gate.FLAKE, FLAKE)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)

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

    def problems(self):
        return roster_gate.audit(self.root)[0]


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
    assert roster_gate.audit(roster_gate.ROOT)[0] == []


def test_summary_counts_every_selection(tree):
    assert "4 crates under crates/" not in roster_gate.audit(tree.root)[1]
    assert "2 crates under crates/" in roster_gate.audit(tree.root)[1]
    assert "firmware and rsk-wipe excluded" in roster_gate.audit(tree.root)[1]


# --- a row stops selecting the whole tree ------------------------------------


def test_row_reverted_to_a_hand_written_list(tree):
    tree.edit(
        roster_gate.CHECK,
        'cargo test --workspace --exclude firmware --exclude rsk-wipe --target "$HOST"',
        'cargo test -p rsk-a -p rsk-b --target "$HOST"',
    )
    assert only(tree.problems(), "`cargo test` picks rsk-a rsk-b by name")
    assert only(tree.problems(), "no `cargo test --workspace`")


def test_a_row_narrowed_to_one_crate(tree):
    """One crate is an example everywhere else; not for a verb the file promised."""
    tree.edit(
        roster_gate.CHECK,
        'cargo doc --workspace --exclude firmware --exclude rsk-wipe --no-deps --target "$HOST"',
        'cargo doc -p rsk-a --no-deps --target "$HOST"',
    )
    assert only(tree.problems(), "`cargo doc` picks rsk-a by name")


def test_a_narrowed_row_for_a_verb_the_file_never_promised(tree):
    """check.sh promises nothing about coverage, so its llvm-cov owes nothing."""
    tree.edit(
        roster_gate.CHECK,
        'run "crate roster"',
        'run "cov (one)" cargo llvm-cov -p rsk-a\nrun "crate roster"',
    )
    assert tree.problems() == []


def test_an_exclude_dropped(tree):
    tree.edit(
        roster_gate.WORKFLOW,
        "            --workspace --exclude firmware --exclude rsk-wipe\n",
        "            --workspace --exclude firmware\n",
    )
    assert only(tree.problems(), "excludes firmware from a cargo `--workspace`")


def test_a_third_exclude_added(tree):
    tree.edit(
        roster_gate.CHECK,
        'cargo test --workspace --exclude firmware --exclude rsk-wipe --target "$HOST"',
        'cargo test --workspace --exclude firmware --exclude rsk-wipe --exclude rsk-b --target "$HOST"',
    )
    assert only(tree.problems(), "excludes firmware rsk-b rsk-wipe")


def test_the_row_deleted(tree):
    tree.edit(
        roster_gate.CHECK,
        'run "test (host)"         cargo test --workspace --exclude firmware --exclude rsk-wipe --target "$HOST"\n',
        "",
    )
    assert only(tree.problems(), "no `cargo test --workspace`")


def test_the_row_commented_out(tree):
    tree.edit(roster_gate.CHECK, 'run "test (host)"', '# run "test (host)"')
    assert only(tree.problems(), "no `cargo test --workspace`")


def test_the_workflow_run_commented_out_while_the_header_agrees(tree):
    """The kani lesson: the copies agree over a job that measures nothing."""
    tree.edit(roster_gate.WORKFLOW, "        run: |", "        # run: |")
    assert only(tree.problems(), "no `cargo llvm-cov --workspace`")


def test_the_header_copy_deleted_while_the_row_runs(tree):
    tree.edit(
        roster_gate.WORKFLOW,
        "#   nix develop -c cargo llvm-cov --summary-only --fail-under-lines 80"
        " --target <host> --workspace --exclude firmware --exclude rsk-wipe\n",
        "#   see the coverage step below\n",
    )
    assert only(tree.problems(), "is quoted")


def test_the_embedded_row_cannot_answer_for_the_host_one(tree):
    """`cargo clippy --workspace` with no excludes is the embedded row, and it
    covers the two crates a host row cannot build — not the other way round."""
    tree.edit(
        roster_gate.CHECK,
        'run "clippy (host tests)" cargo clippy --workspace --exclude firmware --exclude rsk-wipe --target "$HOST" --all-targets -- -D warnings\n',
        "",
    )
    assert only(tree.problems(), "no `cargo clippy --workspace`")


def test_the_docs_copy_deleted(tree):
    tree.edit(roster_gate.DOCS, "cargo test --workspace", "cargo build --workspace")
    assert only(tree.problems(), "no `cargo test --workspace`")


def test_an_exclude_built_from_a_substitution(tree):
    tree.edit(roster_gate.FLAKE, "--exclude firmware --exclude rsk-wipe", "--exclude ${skip}")
    assert only(tree.problems(), "cannot read")


def test_a_stray_exclude_in_an_unregistered_file(tree):
    """The ninth-copy shape: a file nobody registered, selecting its own way."""
    tree.write("ci/nightly.sh", "cargo test --workspace --exclude rsk-a\n")
    assert only(tree.problems(), "ci/nightly.sh excludes rsk-a")


def test_two_commands_on_one_line_stay_two(tree):
    tree.edit(
        roster_gate.CHECK,
        'run "crate roster"',
        'run "extra" sh -c \'cargo build --workspace --exclude rsk-a && cargo test --workspace --exclude firmware --exclude rsk-wipe\'\nrun "crate roster"',
    )
    assert only(tree.problems(), "excludes rsk-a")


# --- what must stay green ----------------------------------------------------


def test_a_one_crate_example_in_the_docs(tree):
    tree.edit(roster_gate.DOCS, "`cargo test -p rsk-a`", "`cargo test -p rsk-a` or `cargo llvm-cov -p rsk-b`")
    assert tree.problems() == []


def test_a_parameterised_helper(tree):
    """Five rows DRY'd into one: the verb is a variable, the flags are not."""
    tree.edit(
        roster_gate.CHECK,
        'run "clippy (host tests)" cargo clippy --workspace --exclude firmware --exclude rsk-wipe --target "$HOST" --all-targets -- -D warnings\n'
        'run "rustdoc (host)"      cargo doc --workspace --exclude firmware --exclude rsk-wipe --no-deps --target "$HOST"\n',
        'host() { cargo "$1" --workspace --exclude firmware --exclude rsk-wipe --target "$HOST" "${@:2}"; }\n'
        'run "clippy (host tests)" host clippy --all-targets -- -D warnings\n'
        'run "rustdoc (host)"      host doc --no-deps\n',
    )
    assert tree.problems() == []


def test_a_features_filtered_multi_crate_row(tree):
    """`--features X` is about the crates that declare X, not about the tree."""
    assert only(tree.problems(), "strict-cfg") == []
    assert only(tree.problems(), "picks rsk-a rsk-b") == []


def test_a_features_filtered_one_crate_row(tree):
    tree.edit(
        roster_gate.CHECK,
        'run "crate roster"',
        'run "test (bench)" cargo test -p rsk-a --features bench --target "$HOST" bench\n'
        'run "crate roster"',
    )
    assert tree.problems() == []


def test_a_deliberate_list_says_so(tree):
    tree.edit(
        roster_gate.CHECK,
        'run "test (strict-cfg)"   cargo test -p rsk-a -p rsk-b --features strict-config --target "$HOST"',
        'run "test (two)"          cargo test -p rsk-a -p rsk-b --target "$HOST"  # roster: scoped — the two with fixtures',
    )
    assert tree.problems() == []


def test_a_source_comment_naming_two_crates(tree):
    tree.write("crates/rsk-a/src/lib.rs", "//! Run with `cargo test -p rsk-a -p rsk-b`.\n")
    assert tree.problems() == []


def test_a_changelog_line(tree):
    tree.write("CHANGELOG.md", "- the host rows ran `cargo test -p rsk-a -p rsk-b` until now\n")
    assert tree.problems() == []


def test_the_embedded_rows_owe_nothing(tree):
    """`cargo doc -p firmware -p rsk-wipe` names two crates and no `crates/` one."""
    assert only(tree.problems(), "rustdoc (embedded)") == []


# --- the tree `--workspace` is trusted to cover -------------------------------


def test_a_member_outside_crates_is_not_excluded(tree, tmp_path):
    tree = Tree(tmp_path / "b", (*MEMBERS, "xtask"))
    assert only(tree.problems(), "xtask is a workspace member outside crates/")


def test_an_excluded_name_that_left_the_workspace(tree, tmp_path):
    tree = Tree(tmp_path / "b", ("firmware", "crates/rsk-a", "crates/rsk-b"))
    assert only(tree.problems(), "rsk-wipe is excluded by every host row")


def test_a_crate_that_is_not_a_member(tree):
    tree.write("crates/rsk-c/Cargo.toml", '[package]\nname = "rsk-c"\n')
    assert only(tree.problems(), "crates/rsk-c is not in Cargo.toml's [workspace] members")


def test_a_member_with_no_manifest(tree, tmp_path):
    tree = Tree(tmp_path / "b", (*MEMBERS, "ghost"))
    (tmp_path / "b/ghost/Cargo.toml").unlink()
    assert only(tree.problems(), "ghost, which has no Cargo.toml")


def test_the_package_name_is_read_from_the_manifest(tree, tmp_path):
    """`--exclude` takes the package name; nothing makes it match the directory."""
    tree = Tree(tmp_path / "b", ("fw", "rsk-wipe", "crates/rsk-a", "crates/rsk-b"))
    tree.write("fw/Cargo.toml", '[package]\nname = "firmware"\n')
    assert tree.problems() == []


# --- the guard's own two self-checks ------------------------------------------


def test_check_sh_no_longer_runs_the_guard(tree):
    tree.edit(roster_gate.CHECK, "python scripts/roster_gate.py", "true")
    assert only(tree.problems(), f"no longer runs {roster_gate.SELF}")


def test_check_sh_no_longer_collects_the_tests(tree):
    tree.edit(roster_gate.CHECK, "python -m pytest scripts -q", "python -m pytest tools/rsk -q")
    assert only(tree.problems(), f"no longer runs {roster_gate.TESTS}")


def test_the_tests_are_named_after_the_guard():
    """`TESTS` is derived, so renaming the guard cannot orphan this file."""
    assert roster_gate.TESTS == pathlib.Path(__file__).resolve().relative_to(roster_gate.ROOT)
