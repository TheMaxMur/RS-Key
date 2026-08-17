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
phase2_count = 3

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

[comutant.BugStore]
status = "unreachable"
evidence = "fixture: the StoreMut_ prefix walks the same closed world"
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
    # The second roster prefix. Its Solo names a DIFFERENT invariant, so the
    # resolution test below can tell which file solo_invariant actually read.
    (formal / "StoreMut_BugStore.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    BarHolds\n"
    )
    (formal / "StoreSolo_BugStore.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    BarHolds\n"
    )
    (formal / "comutants.toml").write_text(SPEC)
    src = root / "src"
    src.mkdir()
    (src / "lib.rs").write_text("GUARD_LINE\nfn f() {}\n")
    _, _, entries = comutate.load(root)
    (formal / "README.md").write_text(
        "# Fixture\n\n" + comutate.phase2_block(root, entries) + "\n"
    )
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


def test_phase2_table_excludes_later_module_mutants(tree):
    text = (tree / "formal" / "README.md").read_text()
    assert "BugAlpha" in text
    assert "BugBeta" in text
    assert "BugGamma" in text
    assert "BugStore" not in text
    assert "0/3 code-level kills" in text
    assert "1 unreachable" in text
    assert "1 open gaps" in text
    assert "1 pending" in text


def test_stale_phase2_table_fails(tree):
    edit(tree / "formal" / "README.md", "`BugAlpha`", "`BugStale`")
    red(tree, "phase-2 fidelity table is stale")


def test_phase2_roster_wrong_count_fails(tree):
    edit(tree / "formal" / "comutants.toml", "phase2_count = 3", "phase2_count = 4")
    red(tree, "phase-2 roster has 3 mutants")


def test_phase2_table_maps_a_measured_kill_to_co_refuted(tree):
    _, _, entries = comutate.load(tree)
    block = comutate.phase2_block(tree, entries, {"BugAlpha": "killed"})
    assert "| `BugAlpha` | `FooHolds` | RED | **co-refuted** |" in block
    assert "1/3 code-level kills" in block


def test_write_readme_requires_every_patch_measurement(tree, capsys):
    _, _, entries = comutate.load(tree)
    assert comutate.write_readme(tree, entries, {}) == 1
    assert "refusing an unmeasured" in capsys.readouterr().err


def test_write_readme_publishes_a_complete_measurement(tree):
    edit(tree / "formal" / "README.md", "`BugAlpha`", "`BugStale`")
    _, _, entries = comutate.load(tree)
    assert comutate.write_readme(tree, entries, {"BugAlpha": "gap"}) == 0
    assert comutate.lint(tree) == []


def test_cfg_without_entry_fails(tree):
    (tree / "formal" / "Mut_BugDelta.cfg").write_text("INVARIANTS\n    TypeOK\n")
    red(tree, "Mut_BugDelta.cfg has no comutant entry")


def test_stale_entry_fails(tree):
    (tree / "formal" / "Mut_BugAlpha.cfg").unlink()
    red(tree, "comutant BugAlpha has no mutant configuration — stale entry")


def test_store_cfg_without_entry_fails(tree):
    # The second prefix is part of the closed world: a StoreMut_ configuration
    # with no entry must be named by its REAL filename, not a Mut_ guess.
    (tree / "formal" / "StoreMut_BugEpsilon.cfg").write_text(
        "INVARIANTS\n    TypeOK\n"
    )
    red(tree, "StoreMut_BugEpsilon.cfg has no comutant entry")


def test_a_stale_store_entry_fails(tree):
    (tree / "formal" / "StoreMut_BugStore.cfg").unlink()
    red(tree, "comutant BugStore has no mutant configuration — stale entry")


def test_store_solo_names_the_invariant(tree):
    # Resolution must go through StoreSolo_ for a store bug — the fixture's
    # StoreSolo names BarHolds where every Solo_ names FooHolds, so a wrong
    # lookup cannot pass by accident.
    assert comutate.solo_invariant(tree, "BugStore") == "BarHolds"
    assert comutate.solo_invariant(tree, "BugAlpha") == "FooHolds"


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


def test_compile_break_is_not_a_kill(tmp_path):
    # A slice that exits nonzero with a compiler-shaped error but no test line
    # is a broken patch, not a caught defect. Scoring it killed is how a patch
    # that does not compile passes as "the tests noticed" — the trap
    # BugPpuatIsAGate first fell into.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "error[E0308]: mismatched types" >&2; exit 1'],
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "build-broke", verdict


def test_test_failure_is_a_kill_even_with_error_word(tmp_path):
    # A real test failure line wins over a stray "error:" in the log — the tests
    # ran and caught it.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "test result: FAILED. 1 failed"; echo "error: x" >&2; exit 1'],
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "killed", verdict


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


def test_a_prefix_collision_is_named():
    # The guard's own falsification. Two families, one bug name: `roster` keys
    # on the stripped name, so the second silently overwrites the first and the
    # closed world stays green over a roster one mutant short.
    clashes = comutate.prefix_collisions(["Mut_BugX", "SeamMut_BugX", "Mut_BugY"])
    assert len(clashes) == 1, clashes
    assert "BugX" in clashes[0]


def test_the_shipped_families_share_no_bug_name():
    # The same guard over the real tree. NOT what the lint runs — the lint builds
    # its own glob inside `lint()`, and saying otherwise here is what would
    # convince a reviewer the wiring is covered; `test_a_collision_reddens_the_lint`
    # is the one that covers it. Green today because the eight families are
    # disjoint, not because the check is toothless: the case above proves it bites.
    stems = [p.stem for p in (comutate.ROOT / "formal").glob("*.cfg")]
    assert comutate.prefix_collisions(stems) == []
    assert comutate.orphan_solos(stems) == []


def test_a_collision_reddens_the_lint(tree):
    # The WIRING, not the function. Both guards passed their own falsification
    # while the lines that call them from `lint()` were covered by nothing: delete
    # those and the suite stayed green over a roster one mutant short, and the
    # weekly co-refutation job — which runs `run`, never pytest — would have
    # measured it and reported success. Driven through `lint()`, like every other
    # closed-world case in this file.
    (tree / "formal" / "SeamMut_BugAlpha.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooHolds\n"
    )
    red(tree, "are one roster key")


def test_an_unpaired_solo_reddens_the_lint(tree):
    # A Solo file whose family has no mutant of that name. `solo_invariant` keeps
    # the LAST family whose Solo exists, so this steals the invariant BugStore is
    # judged by — and `roster` cannot see it, because the stem matches no `Mut_`
    # prefix. Also driven through `lint()`.
    (tree / "formal" / "SeamSolo_BugStore.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    StolenHolds\n"
    )
    red(tree, "has no SeamMut_BugStore.cfg")


def test_a_gap_in_the_anchor_numbering_reddens_the_lint(tree):
    # The walk stops at the first missing number, so a `find3` written without a
    # `find2` never applies and the entry still reads as covering three sites.
    # Impossible while the cap was three-by-construction; in reach the moment it
    # was lifted, which is why the guard ships with the lift.
    edit(
        tree / "formal" / "comutants.toml",
        'find = "GUARD_LINE\\n"',
        'find = "GUARD_LINE\\n"\nfind3 = "fn f"',
    )
    red(tree, "not contiguous from 2")


def test_a_replacement_without_its_anchor_reddens_the_lint(tree):
    # `replace2` whose `find2` was renamed away: edits nothing, silently.
    edit(
        tree / "formal" / "comutants.toml",
        'find = "GUARD_LINE\\n"',
        'find = "GUARD_LINE\\n"\nreplace2 = "whatever"',
    )
    red(tree, "replace2 has no find2")


def test_carrying_both_anchor_forms_reddens_the_lint(tree):
    # A `[[site]]` array wins outright, so a flat `find` left beside it is dead
    # text that still reads like a patch.
    edit(
        tree / "formal" / "comutants.toml",
        'slice = ["true"]\nexpect = "gap"',
        'slice = ["true"]\nexpect = "gap"\n\n[[comutant.BugAlpha.site]]\n'
        'file = "src/lib.rs"\nfind = "GUARD_LINE\\n"',
    )
    red(tree, "carries both a [[site]] array")


def test_a_site_missing_its_file_reddens_the_lint(tree):
    edit(
        tree / "formal" / "comutants.toml",
        'status = "patch"\nfile = "src/lib.rs"\nfind = "GUARD_LINE\\n"\nreplace = ""',
        'status = "patch"\n\n[[comutant.BugAlpha.site]]\nfind = "GUARD_LINE\\n"',
    )
    red(tree, "site 1 has no 'file'")


def test_one_entry_patches_several_files(tmp_path):
    # The feature itself, and its falsification. The slice is green ONLY when
    # BOTH guards are gone, so a `gap` verdict means both files were patched and
    # a `killed` means one was not — which is exactly what the one-site variant
    # below measures. Before the `[[site]]` array a switch spanning two files had
    # to patch what fitted and name the rest in prose.
    root = git_tree(tmp_path)
    (root / "src" / "other.rs").write_text("GUARD_B\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "b"],
        cwd=root,
        check=True,
    )
    slice_ = ["sh", "-c", "! grep -q GUARD_LINE src/lib.rs && ! grep -q GUARD_B src/other.rs"]
    both = {
        "site": [
            {"file": "src/lib.rs", "find": "GUARD_LINE\n", "replace": ""},
            {"file": "src/other.rs", "find": "GUARD_B\n", "replace": ""},
        ],
        "slice": slice_,
    }
    verdict, detail = comutate.run_one(root, "BugAlpha", both, "any-host")
    assert verdict == "gap", f"one of the two files was not patched: {detail}"

    one = {"site": [both["site"][0]], "slice": slice_}
    verdict, _ = comutate.run_one(root, "BugAlpha", one, "any-host")
    assert verdict == "killed", "the slice cannot tell one patched file from two"
