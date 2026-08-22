# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `config_gen_gate.py` was verified against, kept.

Every case drives the REAL generator over a copy of this checkout's `formal/`,
because the defect this row exists for is a file and its generator disagreeing —
a fixture generator writing fixture configurations would be two new things
agreeing with each other. One mutation per case, both directions: the clean copy
is green, this checkout is green, and an ordinary edit to a non-configuration
file in `formal/` stays green, which is the rule that decides whether a guard
survives contact with the tree.
"""

import pathlib
import shutil

import pytest

import config_gen_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A configuration from a family the measured hole was found on: deleting all
#: three left `assurance_gate.check_tiers` with nothing to say.
VICTIM = "BootCarryMut_BugMarkerBeforeScrub.cfg"


@pytest.fixture(scope="session")
def baseline(tmp_path_factory):
    """A checkout-shaped tree: the real generator, its output, and the one
    hand-written configuration beside it."""
    root = tmp_path_factory.mktemp("baseline")
    formal = root / "formal"
    formal.mkdir()
    shutil.copy2(ROOT / "formal/gen-configs.sh", formal / "gen-configs.sh")
    code, stderr = config_gen_gate.generate(root, formal)
    assert code == 0, stderr
    written = list(formal.glob("*.cfg"))
    assert len(written) > config_gen_gate.FLOOR, len(written)
    assert (formal / VICTIM).is_file(), "the fixture no longer holds the victim"
    shutil.copy2(ROOT / "formal/TokenExport.cfg", formal / "TokenExport.cfg")
    return root


@pytest.fixture
def tree(baseline, tmp_path):
    """A private copy of the baseline, so a mutation cannot outlive its test."""
    root = tmp_path / "tree"
    shutil.copytree(baseline, root)
    return root


def problems(root):
    found, _summary = config_gen_gate.audit(root)
    return found


def edit(path: pathlib.Path, old: str, new: str):
    """Replace `old` once, failing loudly if the fixture no longer says it."""
    text = path.read_text()
    assert text.count(old) == 1, f"{path.name} does not say {old!r} exactly once"
    path.write_text(text.replace(old, new))


# --- the two directions that decide whether the row is worth having ----------


def test_a_clean_copy_is_green(tree):
    assert problems(tree) == []


def test_this_checkout_is_green():
    """The row as `check.sh` runs it. A guard nobody can get green gets deleted."""
    found, summary = config_gen_gate.audit(ROOT)
    assert found == [], found
    assert "reproduce byte-for-byte" in summary


def test_an_unrelated_edit_in_formal_does_not_fire(tree):
    """A `.tla` module, a README, a trace: this row is about `.cfg` files only."""
    (tree / "formal/RSKeyProbe.tla").write_text("---- MODULE RSKeyProbe ----\n====\n")
    (tree / "formal/README.md").write_text("# notes\n")
    assert problems(tree) == []


# --- M1: a generated configuration deleted -----------------------------------


def test_a_deleted_generated_config_is_found(tree):
    (tree / "formal" / VICTIM).unlink()
    found = problems(tree)
    assert len(found) == 1, found
    assert VICTIM in found[0]
    assert "does not have it" in found[0]


def test_a_whole_deleted_family_is_found(tree):
    """The measured hole verbatim: all three, which shrank `tiered` and `present`
    together and so was invisible to `assurance_gate.check_tiers`."""
    for path in (tree / "formal").glob("BootCarryMut_*.cfg"):
        path.unlink()
    found = problems(tree)
    assert len(found) == 3, found
    assert all("does not have it" in problem for problem in found)


# --- M2: a generated configuration edited by hand ----------------------------


def test_a_hand_edited_config_is_found(tree):
    edit(tree / "formal" / VICTIM, "MaxWeak = 2", "MaxWeak = 1")
    found = problems(tree)
    assert len(found) == 1, found
    assert "differs from what" in found[0]
    assert "'    MaxWeak = 2'" in found[0] and "'    MaxWeak = 1'" in found[0]


def test_an_edit_that_only_shortens_a_config_is_found(tree):
    """The `zip` in `first_difference` stops at the shorter file, so a truncation
    has no differing line to report and needs the length branch."""
    path = tree / "formal" / VICTIM
    path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    found = problems(tree)
    assert len(found) == 1, found
    assert "lines, the generator writes" in found[0]


# --- M3: the generator changed and nothing regenerated -----------------------


def test_a_generator_edit_without_regenerating_is_found(tree):
    edit(tree / "formal/gen-configs.sh", 'echo "    MaxWeak = 2"', 'echo "    MaxWeak = 3"')
    found = problems(tree)
    assert len(found) == 13, found  # every Boot* configuration carries it
    assert all("differs from what" in problem for problem in found)


def test_a_new_family_the_tree_has_not_seen_is_found(tree):
    edit(
        tree / "formal/gen-configs.sh",
        "emit_boot Boot.cfg \"\"",
        "emit_boot Boot.cfg \"\"\nemit_boot BootProbe.cfg \"\"",
    )
    found = problems(tree)
    assert len(found) == 1, found
    assert "BootProbe.cfg" in found[0] and "runs nothing" in found[0]


# --- M4/M5/M6: the hand-written carve-out, both directions -------------------


def test_an_unregistered_hand_written_config_is_found(tree):
    (tree / "formal/Scratch.cfg").write_text("SPECIFICATION Spec\n")
    found = problems(tree)
    assert len(found) == 1, found
    assert "neither generated nor registered" in found[0]


def test_a_carve_out_whose_file_is_gone_is_found(tree):
    (tree / "formal/TokenExport.cfg").unlink()
    found = problems(tree)
    assert len(found) == 1, found
    assert "stale entry" in found[0]


def test_a_hand_written_config_may_not_claim_it_was_generated(tree):
    path = tree / "formal/TokenExport.cfg"
    path.write_text(f"\\* {config_gen_gate.HEADER} -- do not edit by hand.\n" + path.read_text())
    found = problems(tree)
    assert len(found) == 1, found
    assert "tells its next reader not to edit" in found[0]


# --- M7/M8: the generator itself failing, and failing quietly ----------------


def test_a_generator_that_dies_is_a_finding_not_a_pass(tree):
    """`set -euo pipefail` and a `[ … ] && echo` as the last command of a `{ }`
    group: measured, that wrote four of nineteen families and the caller saw 0."""
    edit(tree / "formal/gen-configs.sh", "emit Shipped.cfg", "false\nemit Shipped.cfg")
    found = problems(tree)
    assert any("exited 1" in problem for problem in found), found


def test_a_generator_that_writes_nothing_trips_the_floor(tree):
    """A loop over an empty set reports no differences, which reads as a pass."""
    edit(tree / "formal/gen-configs.sh", 'cd "$out_dir"', 'cd "$out_dir"\nexit 0')
    found = problems(tree)
    assert any("under the floor" in problem for problem in found), found


def test_the_floor_is_a_live_rule_not_a_dead_constant(tree, monkeypatch):
    """Raised above what the generator writes, it must be the ONLY complaint —
    which is what says the branch is reachable on a tree that is otherwise fine."""
    monkeypatch.setattr(config_gen_gate, "FLOOR", 10_000)
    found = problems(tree)
    assert len(found) == 1, found
    assert "under the floor of 10000" in found[0]


# --- the wiring, which no mutation above can assert --------------------------


def test_check_sh_runs_the_row():
    """`scripts/test_gate_scripts.py` asserts this for every `*_gate.py`; asserted
    here too, because that file finds guards by glob and a rename escapes it."""
    assert "scripts/config_gen_gate.py" in (ROOT / "scripts/check.sh").read_text()


def test_the_generator_still_takes_an_output_directory():
    """The whole row rests on it. Hardcode the destination again and every case
    above would compare `formal/` with itself and pass."""
    text = (ROOT / "formal/gen-configs.sh").read_text()
    assert 'out_dir=${1:-' in text and 'cd "$out_dir"' in text
