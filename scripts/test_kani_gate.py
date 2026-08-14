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
FLOOR_pr=2
FLOOR_state=1
FLOOR_all=3
COVERS_pr=3
COVERS_state=2
COVERS_all=4
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

| Tier | Crates | Harnesses | Covers | Solve | Slowest harness |
|---|---|---|---|---|---|
| `pr` | 2 | 2 | 3 | 1 s | `rsk-a::p`, 1 s |
| `state` | 1 | 1 | 2 | 1 s | `rsk-a::p`, 1 s |
| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |
"""

#: crate → (the file in it that carries a harness, how many `kani::cover!` are in
#: it). `rsk-bench` is here because the guard checks its own exclusion list: one
#: naming a crate with no proof is stale. The counts are what the floors in
#: `RUNNER` and the table in `DOCS` are set to, so the clean tree is consistent
#: and every mutation below moves exactly one of the four copies.
PROVEN = {
    "rsk-a": ("src/lib.rs", 2),
    "rsk-b": ("src/tlv_kani.rs", 1),
    "rsk-c": ("src/lib.rs", 1),
    "rsk-bench": ("src/kani.rs", 0),
}


def fixture_harness(covers):
    """A file with one `#[kani::proof]` and `covers` `kani::cover!` inside it."""
    body = "".join(f"    kani::cover!(x == {i});\n" for i in range(covers))
    return f"#[kani::proof]\nfn p() {{\n{body}}}\n"


class Tree:
    """A checkout shaped like this one: three proven crates, the excluded one."""

    def __init__(self, root):
        self.root = root
        self.write(kani_gate.RUNNER, RUNNER, executable=True)
        self.write(kani_gate.WORKFLOWS / "ci.yml", CI)
        self.write(kani_gate.PINNED_IN, DEEP)
        self.write(kani_gate.DOCS, DOCS)
        for crate, (rel, covers) in PROVEN.items():
            self.write(f"crates/{crate}/{rel}", fixture_harness(covers))
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
    tree.edit(
        "crates/rsk-a/src/lib.rs",
        "#[kani::proof]",
        "/// Kani proof harnesses (`cargo kani -p rsk-a`).\n#[kani::proof]",
    )
    assert tree.problems() == []


# --- the floors, and the numbers the page prints beside them ------------------


def test_a_harness_named_in_prose_is_not_a_harness(tree):
    """The objection this derivation had to answer, and the reason it strips first.

    `presence_kani.rs` and `rsa-asm/src/kani.rs` each discuss `kani::cover!` in a
    doc comment; counted, they put `COVERS_pr` and `COVERS_all` one over anything
    a run can report, and the tier goes red for a parsing reason.
    """
    tree.edit(
        "crates/rsk-a/src/lib.rs",
        "#[kani::proof]",
        "//! An unsatisfiable `kani::cover!` does not fail the harness.\n"
        "/* nor does a #[kani::proof]\n   spelled across a block comment */\n"
        "#[kani::proof]",
    )
    assert tree.problems() == []


def test_a_harness_added_without_raising_the_floor(tree):
    """E130 itself: `FLOOR_all` sat at 64 while the tree carried 65."""
    tree.write("crates/rsk-c/src/more_kani.rs", fixture_harness(0))
    assert only(tree.problems(), "FLOOR_all=3, and the crates on that tier carry 4")


def test_a_floor_raised_past_the_tree(tree):
    """The other direction: a run cannot report more than the source has."""
    tree.edit(kani_gate.RUNNER, "FLOOR_pr=2", "FLOOR_pr=3")
    assert only(tree.problems(), "FLOOR_pr=3, and the crates on that tier carry 2")


def test_a_cover_added_without_raising_the_floor(tree):
    """One `kani::cover!` reaches two tiers here, and both floors are checked."""
    tree.edit("crates/rsk-a/src/lib.rs", "kani::cover!(x == 0);", fixture_harness(3).strip())
    problems = tree.problems()
    assert only(problems, "COVERS_pr=3, and the crates on that tier carry 5")
    assert only(problems, "COVERS_state=2, and the crates on that tier carry 4")
    assert only(problems, "COVERS_all=4, and the crates on that tier carry 6")


def test_a_floor_deleted_outright(tree):
    """A tier whose floor is gone reads as `None`, not as satisfied."""
    tree.edit(kani_gate.RUNNER, "COVERS_state=2\n", "")
    assert only(tree.problems(), "COVERS_state is not written there")


@pytest.mark.parametrize(
    "column, printed",
    [(1, "(3, 3, 4)"), (2, "(3, 3, 4)"), (3, "(3, 3, 4)")],
)
def test_the_page_s_own_copy_of_the_numbers_drifted(tree, column, printed):
    """docs/testing.md is the fourth copy: a reader learns the row's rule there."""
    cells = "| `all` | 3 | 3 | 4 |".split("|")
    cells[column + 1] = f" {int(cells[column + 1]) + 1} "
    tree.edit(kani_gate.DOCS, "| `all` | 3 | 3 | 4 |", "|".join(cells))
    assert only(tree.problems(), f"the tree has {printed}")


def test_the_page_s_tier_row_deleted(tree):
    tree.edit(kani_gate.DOCS, "| `state` | 1 | 1 | 2 | 1 s | `rsk-a::p`, 1 s |\n", "")
    assert only(tree.problems(), "tier table has no `state` row")


@pytest.mark.parametrize(
    "line",
    [
        "#[kani::proof_for_contract(f)]",
        "#[cfg_attr(kani, kani::proof)]",
        "use kani::cover;",
        "use kani::*;",
    ],
)
def test_a_spelling_neither_counter_can_see_is_refused(tree, line):
    """An uncounted harness is a floor set one too low, and it would be silent."""
    tree.edit("crates/rsk-a/src/lib.rs", "#[kani::proof]", f"{line}\n#[kani::proof]")
    assert only(tree.problems(), "neither counter can see that spelling")


def test_a_cover_in_a_crate_no_harness_reaches(tree):
    """A `kani::cover!` outside every harness is checked by nothing, quietly."""
    tree.write("crates/rsk-e/src/lib.rs", "fn f() { kani::cover!(true); }\n")
    assert only(tree.problems(), "rsk-e has a kani::cover! but no #[kani::proof]")


# --- the guard's own wiring ---------------------------------------------------


def test_check_sh_still_runs_the_guard():
    check = (kani_gate.ROOT / "scripts/check.sh").read_text()
    assert "scripts/kani_gate.py" in check


def test_the_tests_are_named_after_the_guard():
    """`check.sh` collects `scripts` wholesale, so the name is the registration."""
    here = pathlib.Path(__file__).name
    assert here == f"test_{pathlib.Path(kani_gate.__file__).stem}.py"


def test_a_spelling_is_refused_even_when_it_is_all_the_file_has(tree):
    """M2. The refusal was collected *after* the "nothing here" early return.

    A file whose only kani content is a spelling nothing counts has zero of both,
    so it took the early exit and said nothing — the silent under-count the
    refusal exists to make loud, in the one file where it is the whole story.
    """
    tree.write("crates/rsk-c/src/gen_kani.rs", "#[cfg_attr(kani, kani::proof)]\nfn q() {}\n")
    assert only(tree.problems(), "neither counter can see that spelling")


def test_a_slash_star_inside_a_string_does_not_swallow_the_file(tree):
    """Finding 3, and the shape is already in this tree (`rsk-wipe/build.rs`).

    Read before strings, a `/*` in a string literal opens a block comment that
    never closes: everything under it leaves both counters *and* the refusal. The
    mirror of that is what makes it the worst kind — the gate then reports a floor
    over the tree and coaches whoever reads it into lowering the number.
    """
    tree.write(
        "crates/rsk-c/src/glob_kani.rs",
        'const HELP: &str = "set BOARD=<boards/*.toml>";\n' + fixture_harness(1),
    )
    problems = tree.problems()
    assert only(problems, "FLOOR_all=3, and the crates on that tier carry 4")
    assert only(problems, "COVERS_all=4, and the crates on that tier carry 5")


def test_a_block_comment_left_open_is_refused(tree):
    """The tripwire under the stripper: Rust that compiles never ends inside one."""
    tree.write("crates/rsk-c/src/open_kani.rs", "/* never closed\n" + fixture_harness(0))
    assert only(tree.problems(), "still open at end of file")


def test_a_nested_block_comment_closes_once(tree):
    """M3. Rust nests them; a scanner that does not, ends the comment early."""
    tree.edit(
        "crates/rsk-a/src/lib.rs",
        "#[kani::proof]",
        "/* outer /* inner */ #[kani::proof] fn ghost() {} */\n#[kani::proof]",
    )
    assert tree.problems() == []


def test_two_harnesses_on_one_line_are_two(tree):
    """M10. `findall`, not `search` — the shape a tidying pass would introduce."""
    tree.edit(
        "crates/rsk-c/src/lib.rs",
        "#[kani::proof]\nfn p()",
        "#[kani::proof] fn q() {} #[kani::proof]\nfn p()",
    )
    assert only(tree.problems(), "FLOOR_all=3, and the crates on that tier carry 4")


def test_a_cover_outside_crates_is_an_orphan_too(tree):
    """M4. The widened message covers both, and only the harness half was driven."""
    tree.write("fuzz/fuzz_targets/c.rs", "fn f() { kani::cover!(true); }\n")
    assert only(tree.problems(), "no tier can reach")


def test_the_page_may_print_one_row_per_tier(tree):
    """Finding 6. `finditer` into a dict is last-match-wins, and it scans the page.

    A quick-reference table repeating a tier would decide the check instead of the
    real one, silently — so a duplicate is itself the finding.
    """
    tree.edit(
        kani_gate.DOCS,
        "| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |",
        "| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |\n\nrecap\n\n| `all` | 3 | 3 | 4 |",
    )
    assert only(tree.problems(), "prints 2 rows for `all`")


@pytest.mark.parametrize("spelling", ["FLOOR_all=3  # three crates", '  FLOOR_all="3"'])
def test_a_reformatted_floor_is_still_read(tree, spelling):
    """Finding 7. It tolerated no comment, no quotes, no indent — and then said
    the number was `None` over a file that plainly prints it."""
    tree.edit(kani_gate.RUNNER, "FLOOR_all=3", spelling)
    assert tree.problems() == []


def test_the_full_tier_may_be_split_across_two_rows(tree):
    """`all` is the anchor, not a row: two halves that partition it satisfy it.

    The daily run splits it because one half can exhaust a hosted runner's
    memory, and a job that dies should cost only its own crates.
    """
    tree.edit(
        kani_gate.RUNNER,
        '    all) echo "$FAST $SLOW" ;;',
        '    all) echo "$FAST $SLOW" ;;\n'
        '    light) echo "$FAST" ;;\n'
        '    heavy) echo "$SLOW" ;;',
    )
    tree.edit(kani_gate.RUNNER, 'TIERS="pr state all"', 'TIERS="pr state all light heavy"')
    tree.edit(
        kani_gate.RUNNER,
        "FLOOR_all=3\n",
        "FLOOR_all=3\nFLOOR_light=2\nFLOOR_heavy=1\n",
    )
    tree.edit(
        kani_gate.RUNNER,
        "COVERS_all=4\n",
        "COVERS_all=4\nCOVERS_light=3\nCOVERS_heavy=1\n",
    )
    tree.edit(
        kani_gate.PINNED_IN,
        "        run: ./scripts/kani.sh all",
        "        run: ./scripts/kani.sh light\n"
        "      - name: prove the heavy half\n"
        "        run: ./scripts/kani.sh heavy",
    )
    tree.edit(
        kani_gate.DOCS,
        "./scripts/kani.sh all\n",
        "./scripts/kani.sh all\n./scripts/kani.sh light\n./scripts/kani.sh heavy\n",
    )
    tree.edit(
        kani_gate.DOCS,
        "| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |\n",
        "| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |\n"
        "| `light` | 2 | 2 | 3 | 1 s | `rsk-a::p`, 1 s |\n"
        "| `heavy` | 1 | 1 | 1 | 2 s | `rsk-c::p`, 2 s |\n",
    )
    assert tree.problems() == []


def test_a_split_that_leaves_a_crate_behind_still_fails(tree):
    """The exemption is exact: halves that do not cover `all` are not a split."""
    tree.edit(
        kani_gate.RUNNER,
        '    all) echo "$FAST $SLOW" ;;',
        '    all) echo "$FAST $SLOW" ;;\n    light) echo "$FAST" ;;',
    )
    tree.edit(kani_gate.RUNNER, 'TIERS="pr state all"', 'TIERS="pr state all light"')
    tree.edit(kani_gate.RUNNER, "FLOOR_all=3\n", "FLOOR_all=3\nFLOOR_light=2\n")
    tree.edit(kani_gate.RUNNER, "COVERS_all=4\n", "COVERS_all=4\nCOVERS_light=3\n")
    tree.edit(
        kani_gate.PINNED_IN,
        "        run: ./scripts/kani.sh all",
        "        run: ./scripts/kani.sh light",
    )
    tree.edit(
        kani_gate.DOCS,
        "./scripts/kani.sh all\n",
        "./scripts/kani.sh all\n./scripts/kani.sh light\n",
    )
    tree.edit(
        kani_gate.DOCS,
        "| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |\n",
        "| `all` | 3 | 3 | 4 | 2 s | `rsk-c::p`, 2 s |\n"
        "| `light` | 2 | 2 | 3 | 1 s | `rsk-a::p`, 1 s |\n",
    )
    assert only(tree.problems(), "no CI row runs the `all` tier")
