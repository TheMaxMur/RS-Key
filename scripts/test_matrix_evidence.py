# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for the compile-only arm of `matrix_gate.check_evidence`.

`covered` is the strongest word in the matrix's vocabulary and every other thing
it used to rest on has been taken away from it in turn: a prose basis, then a row
that builds another image, then a row that builds this one and selects a crate
the property is not about. What was left is a row that builds THIS image, selects
the RIGHT crate, and runs none of it — `cargo build` and `cargo clippy` compile
and execute nothing. Measured on the real tree before the rule was written: 89
`gap` cells would pass the two older checks today and 9 of them name a build or a
lint row and nothing else, so the last route to a `covered` cell nobody measured
was open and the `why` was the only thing standing in it.

Both directions, and the third one that matters here — the rule must not SUPPRESS
its neighbour. A held-back list rather than an inline append, because the
owner-crate refusal fires only over an otherwise-clean row: appending inline
turned a row that was wrong twice into a row reported once, and the case that
caught it is `test_both_reasons_reach_the_reader` below. It was caught by an
existing case in `test_matrix_gate.py` going red, which is the only reason this
paragraph is not a hypothesis.
"""

import pathlib

import matrix_gate
from test_matrix_gate import Tree, red, tree  # noqa: F401  (`tree` is the fixture)

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A row that builds the `firmware-screen` column exactly — same feature, same
#: (absent) knobs — and selects the crate `SEC-B-001` is carried by. Everything
#: the two older rules ask for; it just never runs a line.
BUILD_ROW = 'run "build (screen)" cargo build -p rsk-screen -p firmware --features screen\n'
LINT_ROW = (
    'run "lint (screen)" cargo clippy -p rsk-screen -p firmware --features screen'
    " -- -D warnings\n"
)


def swap_evidence(tree, row, label):
    """Point the fixture's one `check-sh-rows` cell at `label`, and add the row."""
    tree.edit("scripts/check.sh", 'run "clippy (loud)"', row + 'run "clippy (loud)"')
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        f'evidence = ["{label}"]',
    )


# --- the green direction ------------------------------------------------------


def test_a_row_that_runs_the_crate_still_carries_a_covered_cell(tree):
    """`kani (screen)` builds the column, selects `rsk-screen`, and names the
    harness `assurance_gate` derives as `SEC-B-001`'s evidence. The fixture ships
    `covered` on it, so all four rules have a way to be satisfied at once."""
    assert tree.run() == 0


def test_a_row_that_is_not_cargo_at_all_is_not_refused_for_compiling(tree, capsys):
    """A `check.sh` row can be a shell function reading the built ELF, and those
    DO measure something. Which of them measures a given property is the `why`'s
    judgement — this rule reads a cargo subcommand and must say nothing here.

    The row is still refused, and the assertion names WHY so the pass is not
    read as an endorsement: it carries no `--features`, so it is the older
    another-image rule that fell, not this one.
    """
    swap_evidence(tree, 'run "image budget" firmware_size_budget\n', "image budget")
    said = red(tree, capsys)
    assert "executes none of it" not in said
    assert "`image budget` builds [] and this column is ['screen']" in said


# --- and the red one ----------------------------------------------------------


def test_a_covered_cell_resting_on_a_cargo_build_row_is_refused(tree, capsys):
    swap_evidence(tree, BUILD_ROW, "build (screen)")
    said = red(tree, capsys)
    assert "`build (screen)` runs `cargo build`" in said
    assert "executes none of it, so it cannot say SEC-B-001 holds here" in said


def test_a_covered_cell_resting_on_a_clippy_row_is_refused(tree, capsys):
    """The lint arm on its own, because `--all-targets` type-checks the tests and
    is the shape most likely to read as "the tests were involved"."""
    swap_evidence(tree, LINT_ROW, "lint (screen)")
    assert "`lint (screen)` runs `cargo clippy`" in red(tree, capsys)


def test_both_reasons_reach_the_reader(tree, capsys):
    """A row wrong twice — it compiles nothing AND names the wrong crate — owes
    both messages. The first draft appended inline and reported one of them."""
    swap_evidence(
        tree,
        'run "build (firmware only)" cargo build -p firmware --features screen\n',
        "build (firmware only)",
    )
    said = red(tree, capsys)
    assert "runs `cargo build`" in said
    assert "no row named here selects ['rsk-screen']" in said


# --- flags the row's program never reads -------------------------------------


def test_a_device_script_carrying_cargo_flags_is_not_read_as_cargo(tree, capsys):
    """`-p` and `--features` are cargo's flags and mean nothing to anything else.
    Measured on the real tree: `python tests/emu.py tests/29_reset_power_cut.py
    -p rsk-fido --features fips-profile` had BOTH inert, and the gate credited
    both — four `gap` cells took `covered` on `firmware-fips` at EXIT=0."""
    swap_evidence(
        tree,
        'run "emu (screen)" python tests/emu.py tests/01_screen.py'
        " -p rsk-screen --features screen\n",
        "emu (screen)",
    )
    said = red(tree, capsys)
    assert "`emu (screen)` builds [] and this column is ['screen']" in said


def test_a_device_scripts_package_flag_does_not_select_the_owner(tree, capsys):
    """The other half of the same rule, on the one column shape where the feature
    half is vacuous: a board preset enables nothing, so an inert `-p` was the
    whole of what made the row look like evidence about the property."""
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen"]',
        'properties = ["SEC-A-001"]\ncolumns = ["board-a"]',
    )
    swap_evidence(
        tree,
        'run "emu (board-a)" env BOARD=board-a python tests/emu.py tests/01_board.py'
        " -p firmware\n",
        "emu (board-a)",
    )
    said = red(tree, capsys)
    assert "no row named here selects ['firmware']" in said


# --- a name filter that selects nothing ---------------------------------------


def filtered_row(name):
    """The fixture's `cargo test` row, with a trailing name filter."""
    return (
        f'run_tests "test (screen filter)" cargo test -p rsk-screen -p firmware'
        f" --features screen {name}\n"
    )


def test_a_cargo_test_row_filtered_on_no_test_at_all_is_refused(tree, capsys):
    """A filter that selects zero tests prints `running 0 tests … filtered out`
    and exits 0 — this repo's own recorded trap, arriving inside the matrix. The
    real one filtered on `reset_keeps_the_pin_gate`, which is a `#[cfg(kani)]`
    harness no `cargo test` ever compiles."""
    swap_evidence(tree, filtered_row("no_such_test_name"), "test (screen filter)")
    said = red(tree, capsys)
    assert "filters `cargo test` on `no_such_test_name`" in said
    assert "the row runs 0 tests and exits 0" in said


def test_a_cargo_test_row_filtered_on_a_real_test_still_carries_covered(tree):
    """The green direction, and it is what keeps the rule off every filtered row:
    the same command with a filter a `#[test]` answers to passes, so what is
    refused is the empty selection and not the filtering."""
    tree.write(
        "crates/rsk-screen/src/lib_tests.rs",
        "#[test]\nfn shown_holds_on_every_build_smoke() {}\n",
    )
    swap_evidence(
        tree, filtered_row("shown_holds_on_every_build"), "test (screen filter)"
    )
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


# --- and on the tree it ships in ---------------------------------------------


def test_no_shipped_cell_rests_on_a_compile_only_row():
    """Green on its own checkout, and for a reason worth stating: the ledger has
    no `check-sh-rows` cell at all today, so the rule costs nothing to adopt and
    is in place before the first one is written."""
    doc = matrix_gate.ledger(ROOT)
    resting = [
        entry
        for entry in doc.get("cell", [])
        if entry.get("basis") == matrix_gate.CHECK_SH_ROWS
    ]
    assert resting == []
    assert matrix_gate.run(ROOT) == 0


def test_the_compile_only_list_still_has_the_subcommands_in_it():
    """A rule over an empty tuple passes every case above it.

    Every member individually, not a `>=` over two of four: `>= {"build",
    "clippy"}` left `check` and `doc` deletable with the suite green, which is
    the decorative half of a list that reads as complete. `doc` is driven below;
    `check` is asserted as an anticipatory member and the assertion SAYS so, with
    the measurement that makes it one.
    """
    assert set(matrix_gate.COMPILE_ONLY) == {"build", "check", "clippy", "doc"}
    rows = matrix_gate.check_sh_rows(ROOT)
    subcommands = [
        found.group(1)
        for _features, _env, command in rows.values()
        if (found := matrix_gate.CARGO_SUB.search(command))
    ]
    assert subcommands.count("check") == 0, "a `cargo check` row exists — drive it here"
    assert subcommands.count("doc") == 9, subcommands.count("doc")


def test_a_covered_cell_resting_on_a_rustdoc_row_is_refused(tree, capsys):
    """The member that was decorative only because no `rustdoc` row happens to
    pin a column's features. Nine of them exist in the real tree; pin one and
    the word `covered` rests on rustdoc having accepted the file."""
    swap_evidence(
        tree,
        'run "doc (screen)" cargo doc -p rsk-screen -p firmware --features screen\n',
        "doc (screen)",
    )
    assert "`doc (screen)` runs `cargo doc`" in red(tree, capsys)


# --- the fourth rule: the registry's evidence, not the crate's unit tests ------


def test_a_row_that_runs_no_registered_evidence_is_refused(tree, capsys):
    """The half of the ledger's definition the gate ran without.

    `covered` says THE REGISTRY'S evidence was produced on this configuration;
    the gate checked only that the named row builds this image and selects the
    right crate. Measured on the real tree: 80 `gap` cells passed every other
    rule here on an existing row, carried by eight `cargo test` rows, and not
    one of the eight produces registered evidence for any of the 40 rows —
    `test (fips: rsk-fido)` was one edit from `covered` on `SEC-FIDO-001`.
    """
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["test (screen)"]',
    )
    said = red(tree, capsys)
    assert "no row named here runs any of SEC-B-001's registered evidence" in said
    assert "['shown_holds_on_every_build']" in said
    assert "a crate's own unit tests are in none of its classes" in said


def test_a_row_that_runs_the_property_s_device_test_carries_the_cell(tree):
    """The third evidence class, driven through the gate and not asserted of the
    derivation. A statement sweep found it: with only the Kani arm above, the
    `tests/*.py` half of `registry_evidence` could be deleted with the suite
    green — the fixture had no `tests/` at all, so the class existed for no
    input. `assurance_gate` derives a script that names the invariant, and a row
    that runs one produces the registry's evidence as surely as a harness does.
    """
    tree.write("tests/10_shown.py", "# drives Shown end to end against the emulator\n")
    tree.edit(
        "scripts/check.sh",
        'run "clippy (loud)"',
        'run "device (screen)" cargo run -p rsk-screen --features screen'
        " -- tests/10_shown.py\n"
        'run "clippy (loud)"',
    )
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["device (screen)"]',
    )
    matrix_gate.registry_evidence.cache_clear()
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


def test_a_row_that_runs_the_property_s_fuzz_target_carries_the_cell(tree):
    """The second class, and the reason an artifact is matched on its STEM: a row
    says `cargo fuzz run shown`, never `shown.rs`, which is the file name
    `assurance_gate.grep_word` hands back."""
    tree.write("fuzz/fuzz_targets/shown.rs", "// fuzzes Shown across the wire\n")
    tree.edit(
        "scripts/check.sh",
        'run "clippy (loud)"',
        'run "fuzz (screen)" cargo fuzz run shown -p rsk-screen --features screen\n'
        'run "clippy (loud)"',
    )
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["fuzz (screen)"]',
    )
    matrix_gate.registry_evidence.cache_clear()
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


def test_an_artifact_a_row_merely_spells_is_not_one_it_ran(tree, capsys):
    """The boundary that makes the stem match safe, driven rather than argued.

    On the real tree the fuzz target `pqc` is a substring of the cargo feature
    `advertise-pqc`; under a plain `in` a row that merely ENABLES that feature
    would produce the property's evidence. The fixture's `screen` feature stands
    in for it: a target named `creen` is spelled by every row on this column.
    """
    (tree.root / "crates/rsk-screen/src/screen_kani.rs").unlink()
    tree.write("fuzz/fuzz_targets/creen.rs", "// names Shown, and nothing runs it\n")
    matrix_gate.registry_evidence.cache_clear()
    # `Tree.__init__` primes the cached list, and this row DELETES a file after
    # it: the stale entry is then read and the run dies on ENOENT before it can
    # reach the finding. Sibling rows in test_matrix_gate.py clear it for the
    # same reason. Only visible since `production_rust` stopped dropping the file
    # for having `kani` in its name — nothing declares it, so it is now a
    # production orphan.
    matrix_gate.production_rust.cache_clear()
    assert matrix_gate.registry_evidence(tree.root, "Shown") == ("creen",)
    said = red(tree, capsys)
    assert "no row named here runs any of SEC-B-001's registered evidence" in said
    assert "['creen']" in said


def test_the_message_says_so_when_the_registry_derives_nothing_runnable(tree, capsys):
    """A property whose only evidence is the formal invariant. The refusal must
    not read as "you named the wrong row" — there is no right one, and the route
    out is the model run at this column that `settled_by = "evidence"` asks for.
    """
    (tree.root / "crates/rsk-screen/src/screen_kani.rs").unlink()
    matrix_gate.production_rust.cache_clear()
    said = red(tree, capsys)
    assert "the registry derives none that a row can run" in said


def test_a_row_naming_the_harness_at_another_image_is_still_refused(tree, capsys):
    """The new rule must not SUBSUME the older ones: naming the property's own
    harness is not enough if the row builds a different image."""
    swap_evidence(
        tree,
        'run "kani (loud)" cargo kani -p rsk-screen -p firmware --features loud'
        " --harness shown_holds_on_every_build\n",
        "kani (loud)",
    )
    said = red(tree, capsys)
    assert "builds ['loud'] and this column is ['screen']" in said
    assert "runs any of SEC-B-001's registered evidence" not in said
