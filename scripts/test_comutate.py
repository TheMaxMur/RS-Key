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

import os
import pathlib
import shutil
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


def test_an_invariant_named_solo_credits_the_bug_it_arms_alone(tree):
    """The evidence the filename-keyed lookup cannot see.

    `Solo_<Invariant>.cfg` arms a switch and checks one invariant, so its RED is
    the same proof as `Solo_<Bug>.cfg`'s under another name. Measured on the real
    tree before this: two bugs credited with one invariant each while five more
    stood proven, and four of the six P0-launch rows reading `co = 0` had a
    killed code twin in one of them.
    """
    (tree / "formal" / "Solo_BarHolds.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n"
        "INVARIANTS\n    TypeOK\n    BarHolds\n"
    )
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds", "BarHolds"]
    # …and the single-valued lookup, which the published table column takes, is
    # unchanged: the filename still decides which ONE name it answers with.
    assert comutate.solo_invariant(tree, "BugAlpha") == "FooHolds"


def test_a_solo_arming_a_second_switch_credits_neither_bug(tree):
    """Armed ALONE is the whole condition, and it is what the first measurement
    got wrong: five bugs looked under-credited until it was applied, two after.

    `Solo_BugSetPinKeepsPpuat.cfg` in the real tree arms a companion switch —
    the shipped seed-lead makes its own defect unreachable otherwise — so reading
    it as evidence for the companion credits `BugPpuatIsAGate` with an invariant
    it does not break.
    """
    (tree / "formal" / "Solo_BarHolds.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n    BugBeta = TRUE\n"
        "INVARIANTS\n    TypeOK\n    BarHolds\n"
    )
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds"]
    assert comutate.solo_invariants(tree, "BugBeta") == ["FooHolds"]


def test_a_multi_invariant_configuration_attributes_nothing(tree):
    """A configuration checking the whole set says which defect fired and not
    which property it broke — that is the difference `Solo_` carries, and the
    reason this reads solo-style rather than "arms the bug"."""
    # `BarHolds` FIRST: with `FooHolds` there, `targets[0]` collides with the name
    # the filename half already gives and the dedup erases the difference — the case
    # then passes with the solo-style condition deleted, which is measured and is
    # why the order is spelled out here.
    (tree / "formal" / "Mut_BugAlpha.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n"
        "INVARIANTS\n    TypeOK\n    BarHolds\n    FooHolds\n"
    )
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds"]


def test_a_bug_no_solo_names_credits_nothing(tree):
    """The floor: a name nothing solos for answers with an empty list, not with
    whatever the last file on disk happened to check.

    The indexed configuration is the point of the case, not scenery: without one
    the index is empty for every bug, and a "fall back to the last file" defect
    passes it — measured, 53 green with that defect installed.
    """
    (tree / "formal" / "Solo_BarHolds.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n"
        "INVARIANTS\n    TypeOK\n    BarHolds\n"
    )
    assert comutate.solo_invariants(tree, "BugNoSuchSwitch") == []


def test_the_same_invariant_is_credited_once(tree):
    """The dedup, which nothing covered and which is the highest-blast-radius line
    in the change: deleting `if inv != named` inflates 31 invariants on the real
    tree, mostly by doubling — `NoAuthorizationBypass` 11 to 22 — and every gate
    stays green. Here the filename solo is ALSO in the index, so both halves offer
    `FooHolds` and only one may survive."""
    (tree / "formal" / "Solo_BugAlpha.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n"
        "INVARIANTS\n    TypeOK\n    FooHolds\n"
    )
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds"]


def test_a_disarmed_observer_is_a_control_and_not_a_kill(tree):
    """A configuration that switches an observer OFF expects GREEN, so its RED is
    not evidence of anything. `TraceSecurityBadAlphaNoR4b.cfg` is that shape in the
    real tree and escapes only by checking three invariants."""
    (tree / "formal" / "Solo_BarHolds.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n    CheckBar = FALSE\n"
        "INVARIANTS\n    TypeOK\n    BarHolds\n"
    )
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds"]


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


def test_a_registration_that_outlived_its_directory_still_measures(tmp_path):
    # A swept /tmp or a reboot takes the directory and leaves `.git/worktrees`
    # naming it, so `wt.exists()` prunes nothing and the add dies "missing but
    # already registered". The dev loop's, not CI's: `comutants` checks out fresh.
    root = git_tree(tmp_path)
    wt = comutate.worktree_path("BugAlpha")
    shutil.rmtree(wt, ignore_errors=True)
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(wt), "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    shutil.rmtree(wt)
    assert not wt.exists(), "the reproduction needs the directory GONE"
    entry = {"file": "src/lib.rs", "find": "GUARD_LINE\n", "slice": ["false"]}
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "killed", verdict


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


# The five below are one guard — read the two words only where a TEST wrote them
# — and this is its mutation table, taken by deleting one clause of `run_one`'s
# classifier at a time and driving `pytest scripts` (the gate's own row, not the
# helper) over each. Unmutated: 82 passed.
#
#   clause deleted             the case that goes red
#   RUSTC_QUOTES in `ran`      a_rustc_echo_of_the_word_is_not_a_kill
#   RUSTC_QUOTES in `died`     a_rustc_echo_of_cargos_death_line_is_not_a_kill
#   the `died` clause          a_test_binary_that_died_is_a_kill
#   `"FAILED" in l`            a_terse_failure_line_is_a_kill
#   `"test result" in l`       a_passing_summary_beside_a_failure_is_a_kill
#   the `if not ran:` gate     those two, and test_failure_is_a_kill_even_with_…
#   the `^error:` search       both echo cases, and compile_break_is_not_a_kill
#
# No row is empty, so no clause is decorative. The same seven arms were driven
# over `cargo test -p rsk-fs` in a worktree, which is where the two verdicts
# this fixes were measured in the first place; `sh -c` reaches the classifier
# identically and costs no build, so that half is not repeated here.


def test_a_rustc_echo_of_the_word_is_not_a_kill(tmp_path):
    # THE defect this guard exists for. rustc quotes the file back, and three of
    # the 28 patched files carry the word in a comment — `meta_find`'s own doc
    # line reads `/// read that FAILED reads as "no record" here`. Measured
    # before the fix by deleting it: ('killed', '676 | |     /// read that …').
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": [
            "sh",
            "-c",
            'echo "error[E0433]: failed to resolve" >&2;'
            ' echo "676 | |     /// read that FAILED reads as no record here" >&2;'
            " exit 1",
        ],
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "build-broke", verdict


def test_a_rustc_echo_of_cargos_death_line_is_not_a_kill(tmp_path):
    # The same rule applied to the clause below it: a source line that happens to
    # quote `error: test failed` must not buy a kill either, or the fix would
    # have swapped one echo for another.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": [
            "sh",
            "-c",
            'echo "error[E0433]: failed to resolve" >&2;'
            ' echo "12 |     // error: test failed is quoted here" >&2; exit 1',
        ],
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "build-broke", verdict


def test_a_test_binary_that_died_is_a_kill(tmp_path):
    # The inverse, and the reason the `test result:`-only reading was refused: a
    # binary that ABORTS never prints a summary, so `^error:` sees only cargo's
    # `error: test failed` and calls a suite that caught the defect by crashing a
    # patch that will not build. Measured on a stack overflow in rsk-fs: 0
    # `test result:` lines, 0 `FAILED` lines, SIGABRT, and ('build-broke', …).
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": [
            "sh",
            "-c",
            'echo "fatal runtime error: stack overflow, aborting";'
            ' echo "error: test failed, to rerun pass \\`-p rsk-fs --lib\\`" >&2;'
            " exit 101",
        ],
    }
    verdict, detail = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "killed", verdict
    assert "test failed" in detail, detail


def test_a_terse_failure_line_is_a_kill(tmp_path):
    # Keeps "FAILED" load-bearing: libtest's per-test line carries it and the
    # summary line has not been printed yet.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "test mod::t ... FAILED"; echo "error: x" >&2; exit 1'],
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "killed", verdict


def test_a_passing_summary_beside_a_failure_is_a_kill(tmp_path):
    # And keeps "test result" load-bearing: one binary reported ok before the
    # slice went red elsewhere, which is still evidence that tests RAN.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "test result: ok. 5 passed"; echo "error: x" >&2; exit 1'],
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


def test_an_unregistered_boot_mutant_reddens_the_lint(tree):
    # The prefix TUPLE, not `roster()`. `BootMut_*` matched no entry of it for the
    # family's whole life, so three switches sat outside the closed world in BOTH
    # directions while this suite and the `check.sh` row printed ok — a mutant
    # configuration nothing could ever ask about. Driven through `lint()`, because
    # that is the half that was uncovered: take the tuple entry back out and the
    # three real entries read as stale instead, the same hole in the other colour.
    (tree / "formal" / "BootMut_BugBoot.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    MarkerHolds\n"
    )
    red(tree, "BootMut_BugBoot.cfg has no comutant entry")


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


# ---- the proof half ----------------------------------------------------------


def test_the_nix_library_path_is_dropped_for_a_kani_command_and_kept_otherwise(monkeypatch):
    # Measured on the weekly row: nix's libm reached CBMC's own binaries through
    # `LD_LIBRARY_PATH` and `goto-cc` died on a versioned symbol the system libc
    # does not carry — exit 1, no verdict, and the mutant scored a survivor. A
    # `cargo test` slice is nix-built and still needs that path.
    monkeypatch.setenv("LD_LIBRARY_PATH", "/nix/store/whatever/lib")
    root = pathlib.Path("/tmp/anywhere")
    kani = comutate.slice_env(["cargo", "kani", "-p", "x", "--harness", "y"], root)
    assert "LD_LIBRARY_PATH" not in kani
    test = comutate.slice_env(["cargo", "test", "-p", "x"], root)
    assert test["LD_LIBRARY_PATH"] == "/nix/store/whatever/lib"
    # And the two it sets for every command are still set for both.
    for env in (kani, test):
        assert env["CARGO_TARGET_DIR"] == str(root / "target")
        assert '--cfg sha2_backend="soft"' in env["RUSTFLAGS"]


def test_the_host_target_goes_on_a_cargo_test_and_nowhere_else():
    # `cargo kani` has no `--target`: it answers `error: unexpected argument
    # '--target' found`, which this file's own classifier reads as build-broke —
    # a mutant that never ran, recorded as a patch that does not compile.
    assert comutate.with_target(["cargo", "test", "-p", "x"], "h")[-2:] == ["--target", "h"]
    kani = ["cargo", "kani", "-p", "x", "--harness", "y"]
    assert comutate.with_target(kani, "h") == kani


@pytest.mark.parametrize(
    "out,code,verdict",
    [
        ("Checking harness y…\nVERIFICATION:- SUCCESSFUL\n", 0, "proof-survived"),
        ("Failed Checks: something else\nVERIFICATION:- FAILED\n", 1, "proof-wrong-reason"),
        ("CBMC timed out\nVERIFICATION:- FAILED\n", 1, "proof-broke"),
        (
            "Failed Checks: caller_location is not currently supported by Kani\n"
            "VERIFICATION:- FAILED\n",
            1,
            "proof-broke",
        ),
        # The one that made this guard's FIRST real run wrong: Kani prints a
        # codegen warning and the description of every check, reachable or not,
        # so `not currently supported` is in the output of a run that PASSED.
        (
            "warning: Found the following unsupported constructs:\n"
            '\t - Description: "caller_location is not currently supported by Kani"\n'
            "VERIFICATION:- SUCCESSFUL\n",
            0,
            "proof-survived",
        ),
        # And the same string in a check that did NOT fall, on a run that did.
        (
            '\t - Description: "caller_location is not currently supported by Kani"\n'
            "Failed Checks: NoAuthorizationBypass/B1: wrong set\n"
            "VERIFICATION:- FAILED\n",
            1,
            "killed-not-refused",
        ),
        # And the third direction, which the two above cannot see: a run that
        # answered NEITHER line. The weekly row met all three shapes wearing one
        # word, on a host where the same patch reddens B1 locally.
        ("Error: Failed to run cargo build\n", 101, "proof-broke"),
        (
            "cbmc: /nix/store/x/libstdc++.so.6: version `GLIBC_2.40' not found\n",
            127,
            "proof-broke",
        ),
        ("", 0, "proof-broke"),
    ],
)
def test_a_proof_that_did_not_redden_for_its_own_reason(out, code, verdict):
    # The two tool limits end in the SAME line a real refutation does, so a
    # harness that did not converge would score a kill wearing the right colour —
    # the direction failure AGENTS.md records two of twenty-four patches taking.
    # And the last two arms are the opposite error, measured on the first real
    # run: refusing a kill because a string appeared somewhere it means nothing.
    got = comutate.proof_verdict(out, code, "NoAuthorizationBypass/B1")
    if verdict == "killed-not-refused":
        assert got is None, got
    else:
        assert got[0] == verdict


def test_a_proof_that_reached_no_verdict_carries_the_tools_own_line():
    # The detail is the whole point of the arm: `proof-broke` with a fixed string
    # says a tool broke, and the next reader still has to reproduce the host to
    # learn which one. cargo and rustc cascade, so the FIRST error line wins.
    loader = "cbmc: /nix/store/x/libstdc++.so.6: version `GLIBC_2.40' not found"
    _, detail = comutate.proof_verdict(f"Checking harness y…\n{loader}\n", 127, "B1")
    assert loader in detail, detail
    # The child names itself first and the driver wraps it, so an anchored match
    # on the driver's own `Error:` would carry the wrapper and drop the cause.
    child = "cbmc: error while loading shared libraries: libstdc++.so.6"
    _, detail = comutate.proof_verdict(f"{child}\nError: Failed to run cbmc\n", 1, "B1")
    assert detail.endswith(child), detail
    cascade = "error: could not compile `rsk-fido`\nerror: aborting due to 1 error\n"
    _, detail = comutate.proof_verdict(cascade, 101, "B1")
    assert detail.endswith("could not compile `rsk-fido`"), detail


def test_a_proof_that_fell_on_its_named_check_is_not_refused():
    out = "Failed Checks: NoAuthorizationBypass/B1: wrong set\nVERIFICATION:- FAILED\n"
    assert comutate.proof_verdict(out, 1, "NoAuthorizationBypass/B1") is None


def test_a_killed_slice_with_a_surviving_proof_is_not_a_kill(tmp_path):
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "test result: FAILED"; exit 1'],
        "proof": ["sh", "-c", 'echo "VERIFICATION:- SUCCESSFUL"', "--harness"],
        "proof_names": "NoAuthorizationBypass/B1",
    }
    verdict, _ = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "proof-survived", verdict


def test_a_killed_slice_with_a_reddened_proof_names_the_check(tmp_path):
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "test result: FAILED"; exit 1'],
        "proof": [
            "sh",
            "-c",
            'echo "Failed Checks: NoAuthorizationBypass/B1: wrong set";'
            ' echo "VERIFICATION:- FAILED"; exit 1',
            "--harness",
        ],
        "proof_names": "NoAuthorizationBypass/B1",
    }
    verdict, detail = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "killed", (verdict, detail)
    assert "proof: Failed Checks: NoAuthorizationBypass/B1" in detail, detail


def test_a_killed_slice_whose_proof_never_ran_is_not_a_survivor(tmp_path, capsys):
    # The run-time half of `proof_problems`, driven through `run_one`: the three
    # static ways to name a harness that cannot redden are a gate row, and a tool
    # that does not run on the host is a fourth the lint cannot reach.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["sh", "-c", 'echo "test result: FAILED"; exit 1'],
        "proof": [
            "sh",
            "-c",
            'echo "goto-cc: it would not say why"; echo "error: goto-cc exited 1" >&2; exit 101',
            "--harness",
        ],
        "proof_names": "NoAuthorizationBypass/B1",
    }
    verdict, detail = comutate.run_one(root, "BugAlpha", entry, "any-host")
    assert verdict == "proof-broke", (verdict, detail)
    assert "goto-cc exited 1" in detail, detail
    # One line of detail named the tool and not its reason, measured: the runner
    # answered `goto-cc exited with status 1`, and what goto-cc said is gone by
    # the time the verdict is read — so the run prints its last words itself.
    assert "goto-cc: it would not say why" in capsys.readouterr().err


def test_a_green_slice_never_reaches_the_proof(tmp_path):
    # A slice that stayed green is a gap, and running the proof over it would
    # credit the mutant with a refutation the unit suite never made.
    root = git_tree(tmp_path)
    entry = {
        "file": "src/lib.rs",
        "find": "GUARD_LINE\n",
        "slice": ["true"],
        "proof": ["sh", "-c", "exit 1", "--harness"],
        "proof_names": "x",
    }
    assert comutate.run_one(root, "BugAlpha", entry, "any-host")[0] == "gap"


@pytest.mark.parametrize(
    "edit_to,text",
    [
        ('proof = ["cargo", "kani", "--harness", "h"]', "the check it must fell go together"),
        (
            'proof = ["cargo", "kani"]\nproof_names = "X"',
            "the proof must name --harness",
        ),
        ('proof_names = "X"', "the check it must fell go together"),
    ],
)
def test_a_proof_half_that_cannot_be_read_reddens_the_lint(tmp_path, edit_to, text):
    tree = build(tmp_path)
    edit(tree / "formal" / "comutants.toml", 'expect = "gap"', f'expect = "gap"\n{edit_to}')
    red(tree, text)


def test_a_proof_only_means_anything_under_a_kill(tmp_path):
    tree = build(tmp_path)
    edit(
        tree / "formal" / "comutants.toml",
        'expect = "gap"',
        'expect = "gap"\nproof = ["cargo", "kani", "--harness", "h"]\nproof_names = "X"',
    )
    red(tree, "only means anything under expect = 'killed'")


def test_the_shipped_proof_half_names_a_harness_that_exists():
    # The one entry that carries a proof today, and the trap it is against: a
    # `--harness` naming nothing runs every harness in the crate, and any of them
    # failing would be credited to this patch.
    entries = comutate.load(comutate.ROOT)[2]
    carried = {b: e for b, e in entries.items() if "proof" in e}
    assert carried, "no comutant reddens a proof — the finding this half closed is back"
    names = "\n".join(
        p.read_text() for p in (comutate.ROOT / "crates").glob("*/src/*kani*.rs")
    )
    for bug, entry in carried.items():
        harness = entry["proof"][entry["proof"].index("--harness") + 1]
        assert f"fn {harness}(" in names, (bug, harness)
        assert entry["proof_names"] in names, (bug, entry["proof_names"])


# ---- the proof half's closed world, driven through the row -------------------


#: A two-crate workspace for the proof half, because `-p` names a PACKAGE and
#: `--harness` a harness of that package: neither question can be asked of the
#: flat fixture above, which has no manifest at all. `beta` is not a dependency
#: of `alpha` unless an arm makes it one — that separation is what the patch
#: visibility clause is read against.
ALPHA_LIB = """\
GUARD_LINE
fn helper() {}

#[kani::proof]
fn alpha_holds() {}
"""
BETA_LIB = """\
/// Mentions `#[kani::proof]` and `fn ghost_holds()` in prose, which is what a
/// substring match reads as a harness and `bundle_gate.declarations` does not.
#[kani::proof]
fn beta_holds() {}

fn beta_guard() {}
"""


def build_proof_tree(tmp_path) -> pathlib.Path:
    root = build(tmp_path)
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ["alpha", "beta"]\n')
    for name, body in (("alpha", ALPHA_LIB), ("beta", BETA_LIB)):
        src = root / name / "src"
        src.mkdir(parents=True)
        (root / name / "Cargo.toml").write_text(f'[package]\nname = "crate-{name}"\n')
        (src / "lib.rs").write_text(body)
    edit(
        root / "formal" / "comutants.toml",
        'file = "src/lib.rs"',
        'file = "alpha/src/lib.rs"',
    )
    edit(
        root / "formal" / "comutants.toml",
        'expect = "gap"',
        'expect = "killed"\nproof = ["cargo", "kani", "-p", "crate-alpha",'
        ' "--harness", "alpha_holds"]\nproof_names = "AlphaHolds"',
    )
    # After the spec, never before: the table is generated FROM it, and BugAlpha
    # moving gap -> killed moves the row it publishes.
    _, _, entries = comutate.load(root)
    (root / "formal" / "README.md").write_text(
        "# Fixture\n\n" + comutate.phase2_block(root, entries) + "\n"
    )
    return root


@pytest.fixture
def proof_tree(tmp_path):
    return build_proof_tree(tmp_path)


def row(root: pathlib.Path) -> subprocess.CompletedProcess:
    """`python scripts/comutate.py --lint` over `root` — the `check.sh` row itself.

    The row keys on the PROCESS exit code of the entry point, and every other arm
    in this file drives `lint()`, one function below it. Fourteen of thirty gates
    in this tree could not go red because their tables stopped at that function.

    `comutate.py` is copied in because `ROOT` is `__file__`'s grandparent; what it
    imports lazily is reached over `PYTHONPATH` and answers about a path it is
    handed, so those modules are the shipped ones either way.
    """
    scripts = root / "scripts"
    scripts.mkdir(exist_ok=True)
    shutil.copy(comutate.__file__, scripts / "comutate.py")
    return subprocess.run(
        [sys.executable, str(scripts / "comutate.py"), "--lint"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(pathlib.Path(comutate.__file__).parent)},
    )


def red_row(root: pathlib.Path, needle: str) -> None:
    done = row(root)
    assert done.returncode == 1, (done.returncode, done.stdout, done.stderr)
    assert needle in done.stderr, done.stderr


def test_the_proof_fixture_is_green_through_the_row(proof_tree):
    """The control the arms below are read against — and not a vacuous one.

    A rule that resolved nothing would pass this too, so the roster it resolves
    against is asserted here: `crate-alpha` really does declare `alpha_holds` and
    really does not declare `beta_holds`, and `beta_guard`/`ghost_holds` are the
    two ways a name in that file is not a harness.
    """
    done = row(proof_tree)
    assert done.returncode == 0, (done.stdout, done.stderr)
    packages = comutate.workspace_packages(proof_tree)
    assert packages == {"crate-alpha": "alpha", "crate-beta": "beta"}
    harnesses = comutate.kani_harnesses(proof_tree, packages)
    assert harnesses == {"crate-alpha": {"alpha_holds"}, "crate-beta": {"beta_holds"}}


def test_a_harness_that_is_only_an_item_reddens_the_row(proof_tree):
    # The shape `bundle_gate` paid for one field over: `::STEPS` and `::StepRng`
    # are live items of the file the shipped harness lives in, and a name-exists
    # rule reads either as a discharged proof.
    edit(proof_tree / "formal" / "comutants.toml", '"alpha_holds"', '"helper"')
    red_row(proof_tree, "helper is alpha/src/lib.rs, which carries no #[kani::proof]")


def test_a_harness_named_only_in_prose_reddens_the_row(proof_tree):
    edit(proof_tree / "formal" / "comutants.toml", '"alpha_holds"', '"ghost_holds"')
    red_row(proof_tree, "ghost_holds names no #[kani::proof] in the workspace")


def test_a_harness_of_another_crate_reddens_the_row(proof_tree):
    # `cargo kani -p crate-alpha` does not run crate-beta's harnesses, so this
    # entry's RED cannot happen — and a tree-wide name search says it can.
    edit(proof_tree / "formal" / "comutants.toml", '"alpha_holds"', '"beta_holds"')
    red_row(proof_tree, "beta_holds is declared in crate-beta and not in crate-alpha")


def test_a_harness_flag_with_nothing_after_it_reddens_the_row(proof_tree):
    edit(proof_tree / "formal" / "comutants.toml", ', "--harness", "alpha_holds"]', ', "--harness"]')
    red_row(proof_tree, "--harness carries no value")


def test_a_package_that_is_no_workspace_member_reddens_the_row(proof_tree):
    edit(proof_tree / "formal" / "comutants.toml", '"crate-alpha"', '"crate-gamma"')
    red_row(proof_tree, "`-p crate-gamma`, which is no workspace member")


def test_a_patch_the_proofs_package_never_compiles_reddens_the_row(proof_tree):
    """The third way a recorded RED cannot happen, and the one no name resolves.

    Both halves are real — a live harness of `crate-alpha`, an anchor that
    resolves once in `crate-beta` — and `cargo kani -p crate-alpha` never
    compiles the patched crate, so the harness proves the code as shipped.
    """
    edit(proof_tree / "beta" / "src" / "lib.rs", "fn beta_guard", "GUARD_LINE\nfn beta_guard")
    edit(proof_tree / "formal" / "comutants.toml", '"alpha/src/lib.rs"', '"beta/src/lib.rs"')
    red_row(
        proof_tree,
        "the patch lands in crate-beta, which `cargo kani -p crate-alpha` never"
        " compiles",
    )


def test_a_patch_in_a_dependency_is_not_a_finding(proof_tree):
    """The same edit with the edge present. `-p` compiles the crate AND its
    workspace dependencies, so refusing every patch outside the package's own
    directory would refuse honest entries — the direction that makes a rule get
    switched off within a week."""
    edit(proof_tree / "beta" / "src" / "lib.rs", "fn beta_guard", "GUARD_LINE\nfn beta_guard")
    edit(proof_tree / "formal" / "comutants.toml", '"alpha/src/lib.rs"', '"beta/src/lib.rs"')
    (proof_tree / "alpha" / "Cargo.toml").write_text(
        '[package]\nname = "crate-alpha"\n\n[dependencies]\ncrate-beta = { path = "../beta" }\n'
    )
    done = row(proof_tree)
    assert done.returncode == 0, (done.stdout, done.stderr)


def test_the_shipped_proof_half_resolves_in_the_package_it_runs():
    """The registry as it stands, through the rule rather than a name search.

    `test_the_shipped_proof_half_names_a_harness_that_exists` above concatenates
    every `*kani*.rs` in `crates/` and asks whether the text holds `fn <name>(`.
    Measured against the four ways this half goes wrong, that catches two: a name
    nobody wrote and a `--harness` with nothing after it. It passes over a name
    that is an item but no harness, over a harness of ANOTHER crate, over a `-p`
    naming no member, and over a patch that package never compiles.
    """
    entries = comutate.load(comutate.ROOT)[2]
    carried = {b: e for b, e in entries.items() if "proof" in e}
    assert carried, "no comutant reddens a proof — the finding this half closed is back"
    packages, harnesses = comutate.proof_world(comutate.ROOT)
    for bug, entry in carried.items():
        assert comutate.proof_problems(comutate.ROOT, bug, entry, packages, harnesses) == []
        crate = comutate.flag_value(entry["proof"], "-p")
        assert comutate.flag_value(entry["proof"], "--harness") in harnesses[crate]


def test_a_companion_pair_credits_the_subject_and_not_the_companion(tree):
    """The pair `armed_subject` exists for, and the shape that cost `SEC-FIDO-006C`
    its evidence on the very commit that drove its code twin.

    A configuration named after the INVARIANT rather than the bug is invisible to
    the filename half, and the armed-alone condition refused it because the
    shipped tree makes the defect unreachable without its companion. So the
    clause read `co = 0` while its own mutant's code twin was killed.
    """
    (tree / "formal" / "gen-configs.sh").write_text(
        "companion_bug() {\n  case \"$1\" in\n"
        "    BugAlpha) echo BugGamma ;;\n    *) echo \"\" ;;\n  esac\n}\n"
    )
    (tree / "formal" / "SoloClause_BazHolds.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n    BugGamma = TRUE\n"
        "INVARIANTS\n    TypeOK\n    BazHolds\n"
    )
    comutate.companions.cache_clear()
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds", "BazHolds"]
    # And never the other way round: crediting the companion would give it an
    # invariant it does not break, which is what the armed-alone rule was for.
    # `FooHolds` is its own `Solo_BugGamma.cfg`, read by filename; `BazHolds` is
    # the clause config's and must not reach it.
    assert comutate.solo_invariants(tree, "BugGamma") == ["FooHolds"]


def test_two_real_defects_still_attribute_nothing(tree):
    """The rule is the COMPANION relation, not "two is fine". A configuration
    arming two unrelated defects says which one fired, not which property either
    breaks — and the generator is what decides which pairs are companions."""
    (tree / "formal" / "gen-configs.sh").write_text(
        "companion_bug() {\n  case \"$1\" in\n    *) echo \"\" ;;\n  esac\n}\n"
    )
    (tree / "formal" / "SoloClause_BazHolds.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugAlpha = TRUE\n    BugGamma = TRUE\n"
        "INVARIANTS\n    TypeOK\n    BazHolds\n"
    )
    comutate.companions.cache_clear()
    assert comutate.solo_invariants(tree, "BugAlpha") == ["FooHolds"]
    assert comutate.solo_invariants(tree, "BugGamma") == ["FooHolds"]


def test_the_companion_table_comes_from_the_generator(tree):
    """Derived, not restated: a third pair is added in `gen-configs.sh` and this
    reads it there. A copy in `scripts/` is the shape this tree keeps finding
    rotted, and the real table has exactly the two arms the generator carries."""
    comutate.companions.cache_clear()
    assert comutate.companions(comutate.ROOT) == {
        "BugBackupSealedNotAGate": "BugSeedDoesNotLead",
        "BugSetPinKeepsPpuat": "BugPpuatIsAGate",
    }
    comutate.companions.cache_clear()
