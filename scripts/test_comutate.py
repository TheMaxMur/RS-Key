# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `comutate.py` is verified against.

The instrument injects defects and demands red, so the first question it must
answer about itself is the same one: can its own lint go red, and does its
verdict logic tell killed from gap? Every closed-world direction is broken
here once on a fixture; the verdict half runs against a real throwaway git
repo with `/usr/bin/false` and `/usr/bin/true` as the slice, so no cargo is
paid for what a process exit code proves.
"""

import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import comutate

SPEC = """\
pending_floor = 1

[comutant.BugAlpha]
status = "patch"
file = "src/lib.rs"
find = "GUARD_LINE\\n"
replace = ""
slice = ["true"]
expect = "gap"

[comutant.BugBeta]
status = "unreachable"
evidence = "measured in the fixture's own matrix"

[comutant.BugGamma]
status = "pending"
"""


def build(root: pathlib.Path) -> pathlib.Path:
    formal = root / "formal"
    formal.mkdir(parents=True)
    for bug in ("BugAlpha", "BugBeta", "BugGamma"):
        (formal / f"Mut_{bug}.cfg").write_text(
            "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooHolds\n"
        )
        (formal / f"Solo_{bug}.cfg").write_text(
            "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooHolds\n"
        )
    (formal / "comutants.toml").write_text(SPEC)
    src = root / "src"
    src.mkdir()
    (src / "lib.rs").write_text("GUARD_LINE\nfn f() {}\n")
    return root


@pytest.fixture
def tree(tmp_path):
    return build(tmp_path)


def edit(path: pathlib.Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, f"fixture drift: {old!r} not in {path.name}"
    path.write_text(text.replace(old, new))


def red(tree, needle: str) -> None:
    problems = comutate.lint(tree)
    assert any(needle in p for p in problems), problems


def test_green_fixture_passes(tree):
    assert comutate.lint(tree) == []


def test_cfg_without_entry_fails(tree):
    (tree / "formal" / "Mut_BugDelta.cfg").write_text("INVARIANTS\n    TypeOK\n")
    red(tree, "Mut_BugDelta.cfg has no comutant entry")


def test_stale_entry_fails(tree):
    (tree / "formal" / "Mut_BugAlpha.cfg").unlink()
    red(tree, "no Mut_BugAlpha.cfg — stale entry")


def test_vanished_anchor_fails(tree):
    edit(tree / "src" / "lib.rs", "GUARD_LINE\n", "")
    red(tree, "anchor 1 resolves 0 times")


def test_ambiguous_anchor_fails(tree):
    edit(tree / "src" / "lib.rs", "GUARD_LINE\n", "GUARD_LINE\nGUARD_LINE\n")
    red(tree, "anchor 1 resolves 2 times")


def test_pending_over_floor_fails(tree):
    edit(tree / "formal" / "comutants.toml", "pending_floor = 1", "pending_floor = 0")
    red(tree, "over the recorded floor")


def test_unreachable_without_evidence_fails(tree):
    edit(
        tree / "formal" / "comutants.toml",
        'evidence = "measured in the fixture\'s own matrix"',
        "",
    )
    red(tree, "unreachable without evidence")


def test_patch_without_expect_fails(tree):
    edit(tree / "formal" / "comutants.toml", 'expect = "gap"', "")
    red(tree, "expect must be")


# ---- the verdict half: a real worktree, no cargo -----------------------------


def git_tree(tmp_path) -> pathlib.Path:
    root = build(tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"],
        cwd=root,
        check=True,
    )
    return root


def test_failing_slice_is_killed(tmp_path):
    root = git_tree(tmp_path)
    entry = {"file": "src/lib.rs", "find": "GUARD_LINE\n", "slice": ["false"]}
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "killed"


def test_green_slice_is_gap(tmp_path):
    root = git_tree(tmp_path)
    entry = {"file": "src/lib.rs", "find": "GUARD_LINE\n", "slice": ["true"]}
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "gap"


def test_drifted_anchor_in_run_is_named(tmp_path):
    root = git_tree(tmp_path)
    entry = {"file": "src/lib.rs", "find": "NO_SUCH\n", "slice": ["true"]}
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "anchor-gone"


def test_run_flags_a_verdict_that_differs_from_the_record(tmp_path, capsys):
    # The fixture records BugAlpha as expect="gap" over a `true` slice, which is
    # a gap. Point its slice at `false` without touching `expect`: the run now
    # measures killed, and that MUST be a failure — a killed where the record
    # says gap (or the reverse) is the regression floors.txt gives that word.
    root = git_tree(tmp_path)
    edit(root / "formal" / "comutants.toml", 'slice = ["true"]', 'slice = ["false"]')
    assert comutate.run(root, "BugAlpha") == 1
    assert "differ from the record" in capsys.readouterr().err


def test_run_carries_uncommitted_work(tmp_path):
    # The point of `run` in the dev loop: a gap just closed by an uncommitted
    # edit must read as killed now, not after a commit. The worktree is HEAD, so
    # this only holds because run_one carries the tracked diff across.
    root = git_tree(tmp_path)
    (root / "src" / "lib.rs").write_text("GUARD_LINE\nfn f() { /* edited */ }\n")
    # sh -c so the `--target <host>` run_one appends to every slice (they are all
    # cargo commands in real use) lands in $0/$1 and is ignored here.
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", "grep -q edited src/lib.rs"],
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "gap", "the uncommitted edit was not carried into the worktree"
