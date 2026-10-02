# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `scripts/reproduce.sh --self-test`.

The reproduction runner's whole value is that its phase list cannot silently
stop describing the tree, so the thing that needs a table is the self-test and
not the phases: a drift check nothing drives is the shape this repository has
found five times in its own guards, and each time the guard was green over the
hole it existed to catch.

Every case here drives the REAL script through its real entry point — `bash
scripts/reproduce.sh --self-test` over a fixture tree — rather than calling a
function inside it. That is deliberate and is the correction this programme
already paid for once: a guard whose wiring nothing exercises can be deleted
with the suite still green.

Five clauses, each with a removal arm and a defect arm:

* **rows** — every row's command shape is claimed, in both gate runners, and the
  extractor that reads them is held to finding any at all;
* **runners** — every shell runner under `scripts/` and `formal/` is claimed,
  and every claim names a file that is still there;
* **jobs** — every job of the three evidence workflows is claimed, and every
  claim names a job that still exists;
* **phases** — the tier table and the phase table agree in both directions, and
  a phase carries what it reproduces and the command that does it;
* **refusals** — the list of what cannot be reproduced is non-empty, every entry
  carries a reason, and the maintainer-only page it points at exists.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = "scripts/reproduce.sh"

#: The workflows the self-test reads. Named here so a fixture that forgets one
#: fails as a fixture rather than as a green case over a tree with no jobs in it.
WORKFLOWS = ("ci", "deep-checks", "emulator")


@pytest.fixture
def tree(tmp_path):
    """A copy of everything `--self-test` reads, and nothing else.

    A copy rather than the checkout: every case below mutates it, and a case
    that edits the tree it is run from is a case that can only be run once.
    """
    out = tmp_path / "tree"
    for sub in ("scripts/pages", "formal", "docs", ".github/workflows"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    for src in list(ROOT.glob("scripts/*.sh")) + list(ROOT.glob("scripts/pages/*.sh")):
        shutil.copy2(src, out / "scripts" / src.relative_to(ROOT / "scripts"))
    for src in ROOT.glob("formal/*.sh"):
        shutil.copy2(src, out / "formal" / src.name)
    for name in WORKFLOWS:
        shutil.copy2(ROOT / ".github/workflows" / f"{name}.yml",
                     out / ".github/workflows" / f"{name}.yml")
    shutil.copy2(ROOT / "docs/reproducing.md", out / "docs/reproducing.md")
    return out


def self_test(tree):
    """`--self-test` over `tree`, exit code taken with no pipe in the way."""
    done = subprocess.run(["bash", SCRIPT, "--self-test"], cwd=tree,
                          capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def edit(tree, old, new, path=SCRIPT):
    """One replacement in `tree`'s copy, refusing a mutation that changed nothing.

    The refusal is the point: a table whose edits silently miss their target
    reports every arm as a kill of the shipped code, which is the failure mode
    of a mutation table nobody drove.
    """
    target = tree / path
    text = target.read_text()
    assert old in text, f"mutation target not found in {path}: {old!r}"
    target.write_text(text.replace(old, new, 1))


# --- the control --------------------------------------------------------------


def test_the_shipped_tree_passes_its_own_self_test(tree):
    rc, out = self_test(tree)
    assert rc == 0, out
    assert "self-test ok" in out


# --- clause: rows -------------------------------------------------------------


def test_rows_removal_a_deleted_claim_leaves_the_gate_scripts_unrecognised(tree):
    edit(tree, '"^python3? scripts/|gate|"', "")
    rc, out = self_test(tree)
    assert rc == 1
    assert "a shape no claim here recognises" in out


def test_rows_defect_a_row_that_needs_a_board_is_unclaimed(tree):
    edit(tree, 'run "fmt"',
         'run "board smoke" python tests/10_fido_getinfo.py\nrun "fmt"',
         path="scripts/check.sh")
    rc, out = self_test(tree)
    assert rc == 1
    assert 'row "board smoke"' in out
    assert "whether a clean checkout can" in out


def test_rows_defect_the_second_runner_is_read_too(tree):
    """The same board row landing in `check-assurance.sh`: its rows are claimed
    the way `check.sh`'s are, or that runner could grow one unseen."""
    edit(tree, 'run "formal citations"',
         'run "board smoke" python tests/10_fido_getinfo.py\nrun "formal citations"',
         path="scripts/check-assurance.sh")
    rc, out = self_test(tree)
    assert rc == 1
    assert 'row "board smoke"' in out


def test_rows_defect_an_extractor_that_reads_nothing_is_a_finding(tree):
    (tree / "scripts/check.sh").write_text("#!/usr/bin/env bash\necho nothing\n")
    rc, out = self_test(tree)
    assert rc == 1
    assert "the extractor is broken" in out


# --- clause: runners ----------------------------------------------------------


def test_runners_removal_an_unclaimed_runner_is_a_finding(tree):
    edit(tree, '"scripts/miri-all.sh|miri|"', "")
    rc, out = self_test(tree)
    assert rc == 1
    assert "runners: 'scripts/miri-all.sh' is claimed by nothing here" in out


def test_runners_defect_a_new_evidence_runner_lands_unclaimed(tree):
    (tree / "scripts/hil-measure.sh").write_text("#!/usr/bin/env bash\n")
    rc, out = self_test(tree)
    assert rc == 1
    assert "runners: 'scripts/hil-measure.sh' is claimed by nothing here" in out


def test_runners_defect_a_claim_over_a_deleted_runner_is_a_finding(tree):
    (tree / "scripts/mutants-all.sh").unlink()
    rc, out = self_test(tree)
    assert rc == 1
    assert "'scripts/mutants-all.sh' is claimed here and is not in the tree" in out


# --- clause: jobs -------------------------------------------------------------


def test_jobs_removal_an_unclaimed_job_is_a_finding(tree):
    edit(tree, '"deep-checks:comutants|comutants|"', "")
    rc, out = self_test(tree)
    assert rc == 1
    assert "jobs: 'deep-checks:comutants' is claimed by nothing here" in out


def test_jobs_defect_a_new_weekly_job_lands_unclaimed(tree):
    workflow = tree / ".github/workflows/deep-checks.yml"
    workflow.write_text(workflow.read_text().replace(
        "\n  formal:\n", "\n  side-channel:\n    runs-on: ubuntu-latest\n"
                         "    steps:\n      - run: true\n\n  formal:\n", 1))
    rc, out = self_test(tree)
    assert rc == 1
    assert "jobs: 'deep-checks:side-channel' is claimed by nothing here" in out


def test_jobs_defect_a_claim_over_a_renamed_job_is_a_finding(tree):
    workflow = tree / ".github/workflows/deep-checks.yml"
    workflow.write_text(workflow.read_text().replace("\n  formal:\n", "\n  tlc:\n", 1))
    rc, out = self_test(tree)
    assert rc == 1
    assert "'deep-checks:formal' is claimed here and is no job of that workflow" in out


# --- clause: phases -----------------------------------------------------------


def test_phases_removal_a_phase_in_no_tier_is_a_finding(tree):
    edit(tree, '"deep|comutants emu image proofs-all coverage repro miri fuzz mutants"',
         '"deep|comutants emu image proofs-all coverage repro miri fuzz"')
    edit(tree, "mutants\"\n)", "\"\n)")
    rc, out = self_test(tree)
    assert rc == 1
    assert "'mutants' is declared and is in no tier" in out


def test_phases_defect_a_tier_naming_an_undeclared_phase_is_a_finding(tree):
    edit(tree, '"quick|pages docs"', '"quick|pages docs hardware"')
    rc, out = self_test(tree)
    assert rc == 1
    assert "names 'hardware', which is not a declared phase" in out


def test_phases_defect_a_phase_with_no_command_is_a_finding(tree):
    edit(tree, "|./scripts/docs.sh check\"", "|\"")
    rc, out = self_test(tree)
    assert rc == 1
    assert "'docs' has no command" in out


def test_phases_defect_a_claim_naming_an_undeclared_phase_is_a_finding(tree):
    edit(tree, '"scripts/check.sh|gate|"', '"scripts/check.sh|merge-gate|"')
    rc, out = self_test(tree)
    assert rc == 1
    assert "names phase 'merge-gate', which is not declared" in out


# --- clause: refusals ---------------------------------------------------------


def test_refusals_removal_an_empty_list_claims_everything_is_reproducible(tree):
    text = (tree / SCRIPT).read_text()
    head, _, tail = text.partition("REFUSED=(")
    (tree / SCRIPT).write_text(head + "REFUSED=(\n)\n" + tail.split("\n)\n", 1)[1])
    rc, out = self_test(tree)
    assert rc == 1
    assert "the list is empty" in out


def test_refusals_defect_a_refusal_with_no_reason_is_a_finding(tree):
    edit(tree, '"CodeQL|the buildless CodeQL pass runs on', '"CodeQL|" #')
    rc, out = self_test(tree)
    assert rc == 1
    assert "'CodeQL' is refused with no reason" in out


def test_refusals_defect_a_missing_maintainer_page_is_a_finding(tree):
    (tree / "docs/reproducing.md").unlink()
    rc, out = self_test(tree)
    assert rc == 1
    assert "does not exist, so the refusal points nowhere" in out


def test_refusals_defect_a_block_that_stops_naming_the_page_is_a_finding(tree):
    edit(tree, 'echo "  The board half is maintainer-only and written down in $HIL_PAGE."',
         'echo "  The board half is maintainer-only."')
    rc, out = self_test(tree)
    assert rc == 1
    assert "the refusal block does not name" in out


# --- the runner's own refusals ------------------------------------------------


@pytest.mark.parametrize("asked", ["flashing and fuses", "flashing", "board measurement"])
def test_a_hardware_class_asked_for_by_name_is_refused_by_name(tree, asked):
    """The refusal is a refusal and not an unknown-argument shrug."""
    done = subprocess.run(["bash", SCRIPT, asked], cwd=tree,
                          capture_output=True, text=True)
    out = done.stdout + done.stderr
    assert done.returncode == 3, out
    assert f"REFUSED: '{asked}' is not reproducible from a checkout" in out
    assert "docs/reproducing.md" in out


def test_an_argument_that_is_nothing_at_all_is_a_usage_error(tree):
    """The shrug still exists, for the case it is the right answer to."""
    done = subprocess.run(["bash", SCRIPT, "wibble"], cwd=tree,
                          capture_output=True, text=True)
    assert done.returncode == 2
    assert "no such tier or phase: wibble" in done.stdout + done.stderr


def test_the_refusal_block_is_printed_by_a_query_that_runs_nothing(tree):
    done = subprocess.run(["bash", SCRIPT, "--refusals"], cwd=tree,
                          capture_output=True, text=True)
    assert done.returncode == 0
    assert "NOT reproducible from this checkout" in done.stdout
    assert "docs/reproducing.md" in done.stdout


def test_every_phase_the_list_prints_carries_its_command(tree):
    """`--list` is what a reviewer copies from, so it may not print a bare name."""
    done = subprocess.run(["bash", SCRIPT, "--list"], cwd=tree,
                          capture_output=True, text=True)
    assert done.returncode == 0
    assert done.stdout.count("$ ") >= done.stdout.count("  tier ")
