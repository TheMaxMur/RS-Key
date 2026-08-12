# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `kani_gate.py` is verified against.

That guard was written after the daily row was found proving 29 of 49 harnesses,
and every round of it since has been checked by editing the real tree, running
it and reading the message — a battery living in a terminal scrollback, which is
exactly how the *previous* two gate scripts came to be the finding rather than
the instrument. `roster_gate.py` got a fixture for that reason; this is its
sibling, and it arrives with the tier split, when the guard stopped comparing
three strings and started reading a table.

Both directions are asserted. A guard that cannot go green is deleted as fast as
one that cannot go red, so the cases that must **not** fire are here too: a
`cargo kani setup` with no roster on it, and the per-crate `cargo kani -p rsk-x`
hints that live in source doc comments and say nothing about what CI proves.
"""

import pathlib
import subprocess

import pytest

import kani_gate

RUNNER = """#!/usr/bin/env bash
set -euo pipefail
FAST="rsk-a rsk-b"
SLOW="rsk-c"
STATEFUL="rsk-a"
crates_of() {
  case "$1" in
    pr) echo "$FAST" ;;
    state) echo "$STATEFUL" ;;
    all) echo "$FAST $SLOW" ;;
    *) return 1 ;;
  esac
}
TIERS="pr state all"
if [ "${1:-}" = "--tiers" ]; then
  for t in $TIERS; do echo "$t: $(crates_of "$t" | xargs)"; done
  exit 0
fi
"""

CI = """name: ci
jobs:
  proofs:
    steps:
      - name: prove the fast tier
        run: ./scripts/kani.sh pr
      - name: prove the security-state crates
        run: ./scripts/kani.sh state
"""

DEEP = """# Local equivalents:
#   ./scripts/kani.sh all

name: deep-checks
jobs:
  kani:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - name: prove every harness
        run: ./scripts/kani.sh all
"""

DOCS = """# Testing

```sh
cargo install --locked kani-verifier --version 0.67.0 && cargo kani setup
./scripts/kani.sh pr
./scripts/kani.sh state
./scripts/kani.sh all
```
"""

#: crate → the file in it that carries a harness. `rsk-bench` is here because the
#: guard checks its own exclusion list: one naming a crate with no proof is stale.
PROVEN = {
    "rsk-a": "src/lib.rs",
    "rsk-b": "src/tlv_kani.rs",
    "rsk-c": "src/lib.rs",
    "rsk-bench": "src/kani.rs",
}


class Tree:
    """A checkout shaped like this one: three proven crates, the excluded one."""

    def __init__(self, root):
        self.root = root
        self.write(kani_gate.RUNNER, RUNNER, executable=True)
        self.write(kani_gate.WORKFLOWS / "ci.yml", CI)
        self.write(kani_gate.PINNED_IN, DEEP)
        self.write(kani_gate.DOCS, DOCS)
        for crate, rel in PROVEN.items():
            self.write(f"crates/{crate}/{rel}", "#[kani::proof]\nfn p() {}\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)

    def write(self, rel, text, executable=False):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if executable:
            path.chmod(0o755)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def problems(self):
        return kani_gate.audit(self.root)[0]


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
    assert kani_gate.audit(kani_gate.ROOT)[0] == []


# --- coverage: the roster against the tree -----------------------------------


def test_a_crate_with_a_proof_on_no_tier(tree):
    tree.write("crates/rsk-d/src/lib.rs", "#[kani::proof]\nfn p() {}\n")
    assert only(tree.problems(), "rsk-d has a #[kani::proof] that no CI row runs")


def test_a_tier_crate_whose_proof_went_away(tree):
    (tree.root / "crates/rsk-c/src/lib.rs").write_text("fn p() {}\n")
    assert only(tree.problems(), "rsk-c is on the `all` tier but has no")


def test_a_proof_outside_crates(tree):
    tree.write("fuzz/fuzz_targets/x.rs", "#[kani::proof]\nfn p() {}\n")
    assert only(tree.problems(), "no tier can reach")


def test_a_stale_exclusion(tree):
    (tree.root / "crates/rsk-bench/src/kani.rs").write_text("fn p() {}\n")
    assert only(tree.problems(), "rsk-bench is excluded but has no")


def test_an_excluded_crate_put_back_on_a_tier(tree):
    tree.edit(kani_gate.RUNNER, 'SLOW="rsk-c"', 'SLOW="rsk-c rsk-bench"')
    assert only(tree.problems(), "rsk-bench is both excluded and on the `all` tier")


# --- the tiers against each other --------------------------------------------


def test_a_subtier_crate_missing_from_all(tree):
    tree.edit(kani_gate.RUNNER, 'STATEFUL="rsk-a"', 'STATEFUL="rsk-a rsk-z"')
    assert only(tree.problems(), "rsk-z is on the `state` tier but not on `all`")


def test_an_empty_tier(tree):
    tree.edit(kani_gate.RUNNER, 'STATEFUL="rsk-a"', 'STATEFUL=""')
    assert only(tree.problems(), "the `state` tier is empty")


def test_the_full_tier_renamed_away(tree):
    """Renamed out of the table entirely: nothing is left to ask about coverage."""
    tree.edit(kani_gate.RUNNER, "all) echo", "everything) echo")
    tree.edit(kani_gate.RUNNER, 'TIERS="pr state all"', 'TIERS="pr state everything"')
    assert only(tree.problems(), "no longer defines the `all` tier")


def test_the_full_tier_emptied(tree):
    """Still named, so every crate on it now reads as proven by nothing."""
    tree.edit(kani_gate.RUNNER, 'all) echo "$FAST $SLOW"', 'all) echo ""')
    problems = tree.problems()
    assert only(problems, "the `all` tier is empty")
    assert only(problems, "rsk-a has a #[kani::proof] that no CI row runs")


# --- the rows that have to run them ------------------------------------------


def test_a_tier_no_row_runs(tree):
    tree.edit(kani_gate.WORKFLOWS / "ci.yml", "run: ./scripts/kani.sh state", "run: true")
    assert only(tree.problems(), "no CI row runs the `state` tier")


def test_the_row_commented_out(tree):
    tree.edit(
        kani_gate.WORKFLOWS / "ci.yml",
        "run: ./scripts/kani.sh pr",
        "# run: ./scripts/kani.sh pr",
    )
    assert only(tree.problems(), "no CI row runs the `pr` tier")


def test_the_row_disabled_after_a_hash(tree):
    """`run: true # ./scripts/kani.sh all` runs the `true`. The hole it shipped with."""
    tree.edit(
        kani_gate.PINNED_IN,
        "run: ./scripts/kani.sh all",
        "run: true # ./scripts/kani.sh all",
    )
    assert only(tree.problems(), "no CI row runs the `all` tier")


def test_the_header_comment_alone_does_not_count(tree):
    """The kani lesson: the copies agree over a job that proves nothing."""
    tree.edit(kani_gate.PINNED_IN, "        run: ./scripts/kani.sh all", "        run: true")
    assert only(tree.problems(), "no CI row runs the `all` tier")


def test_a_row_naming_a_tier_that_does_not_exist(tree):
    tree.edit(
        kani_gate.WORKFLOWS / "ci.yml",
        "run: ./scripts/kani.sh pr",
        "run: ./scripts/kani.sh quick",
    )
    problems = tree.problems()
    assert only(problems, "which is not a tier")
    assert only(problems, "no CI row runs the `pr` tier")


def test_a_new_workflow_is_read_too(tree):
    """Every workflow, not a hard-coded pair — a fourth row is where the next one goes."""
    tree.write(
        kani_gate.WORKFLOWS / "nightly.yml",
        "jobs:\n  k:\n    steps:\n      - run: cargo kani -p rsk-a -p rsk-b\n",
    )
    assert only(tree.problems(), "writes its own `cargo kani")


# --- the page a reader copies ------------------------------------------------


def test_the_docs_copy_of_a_tier_deleted(tree):
    tree.edit(kani_gate.DOCS, "./scripts/kani.sh state\n", "")
    assert only(tree.problems(), "does not carry the `state` tier")


def test_the_docs_pin_drifted(tree):
    tree.edit(kani_gate.DOCS, "--version 0.67.0", "--version 0.66.0")
    assert only(tree.problems(), "installs kani 0.66.0, CI pins 0.67.0")


def test_the_workflow_pin_removed(tree):
    tree.edit(kani_gate.PINNED_IN, 'KANI_VERSION: "0.67.0"', "KANI_VERSION: latest")
    assert only(tree.problems(), "KANI_VERSION is not pinned")


def test_the_docs_install_unpinned(tree):
    tree.edit(kani_gate.DOCS, "kani-verifier --version 0.67.0", "kani-verifier")
    assert only(tree.problems(), "installs kani-verifier without --version")


# --- the rule that stops a second roster appearing ---------------------------


def test_a_hand_written_roster_in_the_workflow(tree):
    tree.edit(
        kani_gate.PINNED_IN,
        "run: ./scripts/kani.sh all",
        "run: cargo kani -p rsk-a -p rsk-b -p rsk-c",
    )
    problems = tree.problems()
    assert only(problems, "writes its own `cargo kani")
    assert only(problems, "no CI row runs the `all` tier")


def test_a_hand_written_roster_in_the_docs(tree):
    tree.edit(kani_gate.DOCS, "./scripts/kani.sh all", "cargo kani --package rsk-a")
    assert only(tree.problems(), "writes its own `cargo kani")


def test_cargo_kani_setup_is_not_a_roster(tree):
    """It names no package, so it is not a second copy of the list."""
    assert tree.problems() == []
    assert "cargo kani setup" in (tree.root / kani_gate.DOCS).read_text()


def test_a_per_crate_hint_in_a_source_comment_is_not_a_roster(tree):
    """`cargo kani -p rsk-a` in a doc comment tells a reader how to run one crate."""
    tree.write(
        "crates/rsk-a/src/lib.rs",
        "/// Kani proof harnesses (`cargo kani -p rsk-a`).\n#[kani::proof]\nfn p() {}\n",
    )
    assert tree.problems() == []


# --- the guard's own wiring ---------------------------------------------------


def test_check_sh_still_runs_the_guard():
    check = (kani_gate.ROOT / "scripts/check.sh").read_text()
    assert "scripts/kani_gate.py" in check


def test_the_tests_are_named_after_the_guard():
    """`check.sh` collects `scripts` wholesale, so the name is the registration."""
    here = pathlib.Path(__file__).name
    assert here == f"test_{pathlib.Path(kani_gate.__file__).stem}.py"
