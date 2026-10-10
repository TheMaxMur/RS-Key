# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `matrix_gate.py` was verified against, kept.

The guard's whole claim is that a property proved on one image cannot silently
read as a claim about the other thirty. That claim is worth exactly as much as
the two refusals under it — a column the derivation misses, and an `equivalent`
cell whose sameness is a reviewer's impression — so both are broken here, one at
a time, in a fixture checkout, and the MESSAGE is asserted rather than a count.
A red for the inverse defect reads exactly like a red for the right one.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own matrix passes,
and `check.sh` is asserted to run the row. The last cases are about the
DERIVATION rather than the ledger — seven of the seven guards this repo shipped
before this one had a hole of that family, and an axis that quietly derives to
nothing satisfies every rule above it.

The cases added after an independent review all share one shape, and it is the
shape the six the author closed shared too: **the rule is walked past by writing
a stronger word.** `equivalent` was refused on a prose basis because it asserts
sameness, and `covered` — which asserts that the evidence was produced here —
took the same prose. So the arms below break each basis on what it now points
at: a row that builds another image, a row that only compiles this one, a `cfg`
site in a crate the property is not about, a chain that never reaches evidence.
"""

import pathlib

import pytest

import gate_lines
import matrix_gate
import platform_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Two images with no features, one with a feature that swaps a gate out, one
#: that pulls an optional crate in, and two that only pin a knob — the four
#: shapes the real flake has, in the smallest tree that has all of them. The
#: second pinned one is there so an `equivalent` CHAIN exists to follow.
FLAKE = """\
{
  packages = {
    default = mkFirmware { name = "firmware"; };
    firmware = mkFirmware { name = "firmware"; };
    firmware-no-touch = mkFirmware {
      name = "firmware-no-touch";
      cargoFlags = [
        "--features"
        "no-touch"
      ];
    };
    firmware-screen = mkFirmware {
      name = "firmware-screen";
      cargoFlags = [
        "--features"
        "screen"
      ];
    };
    firmware-pinned = mkFirmware {
      name = "firmware-pinned";
      vidpid = "Pico";
    };
    firmware-pinned-too = mkFirmware {
      name = "firmware-pinned-too";
      vidpid = "Nitro3";
    };
  };
}
"""

WORKSPACE = """\
[workspace]
members = ["firmware", "crates/rsk-core", "crates/rsk-screen"]
"""

MANIFEST = """\
[package]
name = "firmware"

[dependencies]
rsk-core = { path = "../crates/rsk-core" }
rsk-screen = { path = "../crates/rsk-screen", optional = true }

[features]
no-touch = []
screen = ["dep:rsk-screen"]
loud = []
"""

CORE = """\
[package]
name = "rsk-core"
"""

SCREEN = """\
[package]
name = "rsk-screen"
"""

#: The presence gate `no-touch` throws, so `gate-compiled-out` has a switch to
#: point at.
PRESENCE = """\
#[cfg(not(feature = "no-touch"))]
pub fn press() -> bool { sample() }
/// Refines `Fixture!Gated` — SEC-A-001.
pub fn gated() {}
/// Refines `Fixture!Held` — SEC-A-002.
pub fn held() {}
"""

CEREMONY = """\
/// Refines `Fixture!Shown` — SEC-B-001.
pub fn shown() {}
"""

#: A knob read where the real tree reads most of them: the root package's own
#: build script, at build time. Without one, no `env` prefix in this fixture
#: pins anything — which is the rule `inert_knobs` runs, and the reason this file
#: had to grow a build script to keep a green direction at all. Both spellings
#: of the read, as every one of the real tree's 38 declarations is written: the
#: `rerun-if-env-changed` line is what `unreadable_env_reads` holds the literal
#: read to, and dropping one of the two is a case below.
BUILD_RS = """\
fn main() {
    println!("cargo:rerun-if-env-changed=VIDPID");
    println!("cargo:rustc-env=PK_VIDPID={}", std::env::var("VIDPID").unwrap_or_default());
}
"""

#: And the other shape the real tree has, which is what `builds` is about: a knob
#: read by a DEPENDENCY the row never names — `rsk-fido`'s build script reads
#: `AAGUID` on every `-p firmware` — and read at COMPILE time rather than build
#: time, which is the `env!` half of `matrix_gate.ENV_READ`. One fixture line
#: carries both, and dropping either clause turns the green case below red.
CORE_RS = """\
pub fn core() {}
pub const BOARD: Option<&str> = option_env!("BOARD");
"""

#: `SEC-B-001`'s registered evidence, in the one class a `check.sh` row can run.
#: `assurance_gate` derives a property's Kani harnesses by looking for
#: `snake(name)` in the function names of `crates/*/src/*kani*.rs`, so the file
#: name matters as much as the function's — and the same filter keeps this file
#: out of the production set, which is why it cannot also become an owner.
SCREEN_KANI = """\
#[kani::proof]
pub fn shown_holds_on_every_build() {}
"""

REGISTRY = """\
[[property]]
id = "SEC-A-001"
name = "Gated"

[[property]]
id = "SEC-A-002"
name = "Held"

[[property]]
id = "SEC-B-001"
name = "Shown"

[[property]]
id = "SEC-C-001"
name = "Later"
"""

CHECK_SH = """\
run "clippy (loud)" cargo clippy -p firmware --features loud -- -D warnings
run_tests "test (screen)" cargo test -p rsk-screen -p firmware --features screen
run "kani (screen)" cargo kani -p rsk-screen -p firmware --features screen --harness shown_holds_on_every_build
run_tests "test (core)" cargo test -p firmware -p rsk-core
run "build-configuration matrix" python scripts/matrix_gate.py
"""

RELEASE = """\
jobs:
  build:
    steps:
      - name: build
        run: |
          for pkg in firmware firmware-screen; do
            nix build ".#$pkg"
          done
      - name: rebuild
        run: |
          for pkg in firmware firmware-screen; do
            nix build ".#$pkg" --rebuild
          done
"""

LEDGER = """\
[tranche]
p0-launch = ["SEC-A-001", "SEC-A-002"]
p0b = ["SEC-B-001"]
p1 = ["SEC-C-001"]
out-of-queue = []

[[cell]]
properties = ["SEC-A-001", "SEC-A-002"]
columns = ["firmware"]
disposition = "covered"
basis = "default-build"
why = "the image every measurement was taken on."

[[cell]]
properties = ["SEC-B-001"]
columns = ["firmware", "firmware-no-touch", "firmware-pinned", "firmware-pinned-too", "loud", "board-a"]
disposition = "out-of-scope"
basis = "crate-absent"
why = "rsk-screen is dep-gated behind the screen feature."

[[cell]]
properties = ["SEC-B-001"]
columns = ["firmware-screen"]
disposition = "covered"
basis = "check-sh-rows"
evidence = ["kani (screen)"]
why = "the only column that compiles the ceremony, and the row that proves it."

[[cell]]
properties = ["SEC-A-001", "SEC-A-002"]
columns = ["firmware-pinned"]
same_as = "firmware"
knob_delta = ["vidpid=Pico"]
disposition = "equivalent"
basis = "same-cargo-features"
why = "identical feature closure; the delta is a USB identity pair."

[[cell]]
properties = ["SEC-A-001", "SEC-A-002"]
columns = ["firmware-pinned-too"]
same_as = "firmware-pinned"
knob_delta = ["vidpid=Nitro3"]
disposition = "equivalent"
basis = "same-cargo-features"
why = "the same pinned identity as firmware-pinned, one step further out."

[[cell]]
properties = ["SEC-A-001"]
columns = ["firmware-no-touch"]
feature = "no-touch"
cfg = ["firmware/src/presence.rs"]
disposition = "out-of-scope"
basis = "gate-compiled-out"
why = "no-touch replaces the press with an auto-confirm."

[[question]]
column = "firmware-no-touch"
owner = "contributor"
settled_by = "absence"
text = "does SEC-A-002 depend on the press indirectly?"

[[question]]
column = "firmware-screen"
owner = "maintainer"
settled_by = "ruling"
text = "the screen build is not default plus screen."

[[question]]
column = "loud"
owner = "contributor"
settled_by = "evidence"
text = "is a never-shipped build in the supported set?"

[[question]]
column = "board-a"
owner = "contributor"
settled_by = "sameness"
text = "the board moves the presence pin."
"""

BOARD_A = """\
[usb]
vidpid = "RSKey"

[presence]
source = "gpio"
pin = 23
"""


class Tree:
    """A checkout with all three axes, in the smallest shape that has them."""

    def __init__(self, root):
        self.root = root
        self.write("Cargo.toml", WORKSPACE)
        self.write("firmware/Cargo.toml", MANIFEST)
        self.write("firmware/src/presence.rs", PRESENCE)
        self.write("firmware/build.rs", BUILD_RS)
        self.write("crates/rsk-core/Cargo.toml", CORE)
        self.write("crates/rsk-core/src/lib.rs", CORE_RS)
        self.write("crates/rsk-screen/Cargo.toml", SCREEN)
        self.write("crates/rsk-screen/src/lib.rs", CEREMONY)
        self.write("crates/rsk-screen/src/screen_kani.rs", SCREEN_KANI)
        self.write("nix/firmware.nix", FLAKE)
        self.write("firmware/boards/board-a.toml", BOARD_A)
        self.write(".github/workflows/release-build.yml", RELEASE)
        self.write("scripts/check.sh", CHECK_SH)
        self.write("assurance/properties.toml", REGISTRY)
        self.write("assurance/configurations.toml", LEDGER)
        (root / "docs").mkdir(parents=True, exist_ok=True)
        matrix_gate.run(root, write=True)

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

    def run(self):
        return matrix_gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # The shipped floors are about the real tree's 22 packages, 7 boards and 40
    # rows. Scaled to the fixture's so the collapse cases below still trip.
    monkeypatch.setattr(matrix_gate, "FLOOR_PACKAGES", 2)
    monkeypatch.setattr(matrix_gate, "FLOOR_BOARDS", 1)
    monkeypatch.setattr(matrix_gate, "FLOOR_ROWS", 2)
    matrix_gate.cfg_sites.cache_clear()
    matrix_gate.impl_gates.cache_clear()
    matrix_gate.crate_rust.cache_clear()
    return Tree(tmp_path)


def red(tree, capsys):
    """Run the guard, require it red, and hand back what it said."""
    assert tree.run() == 1
    return capsys.readouterr().err


# --- both directions, and the wiring -----------------------------------------


def test_the_clean_fixture_passes(tree):
    assert tree.run() == 0


def test_this_checkout_passes():
    """The guard has to be green on the tree it ships in, or it is not a row."""
    assert matrix_gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    assert gate_lines.runs((ROOT / "scripts/check.sh").read_text(), "scripts/matrix_gate.py")


def test_the_shipped_matrix_is_the_one_the_generator_writes():
    """The artifact half of the same rule, on the real tree rather than a fixture."""
    assert matrix_gate.render(ROOT) == (ROOT / matrix_gate.ARTIFACT).read_text()


# --- the axes: a configuration with no column --------------------------------


def test_a_new_flake_package_has_no_column_until_the_matrix_is_regenerated(tree, capsys):
    """The roadmap's exit predicate, first half: a new `firmware-*` reddens the row."""
    tree.edit(
        "nix/firmware.nix",
        "    firmware-pinned = mkFirmware {",
        '    firmware-fips = mkFirmware {\n      name = "firmware-fips";\n    };\n'
        "    firmware-pinned = mkFirmware {",
    )
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_new_board_preset_has_no_column_until_the_matrix_is_regenerated(tree, capsys):
    tree.write("firmware/boards/board-b.toml", BOARD_A)
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_new_cargo_feature_has_no_column_until_the_matrix_is_regenerated(tree, capsys):
    """The `largeblob-ext` shape: an orthogonal feature with no flake package."""
    tree.edit("firmware/Cargo.toml", "loud = []", 'loud = []\nquiet = []')
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_check_sh_row_for_a_feature_the_manifest_dropped_is_rejected(tree, capsys):
    """The other direction of the same rule: the row outlives its feature, so
    there is nothing for the derivation to make a column out of."""
    tree.edit("firmware/Cargo.toml", "loud = []\n", "")
    said = red(tree, capsys)
    assert "--features loud" in said
    assert "does not define" in said


def test_a_new_p0_family_property_has_no_row_until_it_is_classified(tree, capsys):
    """The row axis: a registry entry in no tranche is a row nobody would miss."""
    tree.edit(
        "assurance/properties.toml",
        '[[property]]\nid = "SEC-C-001"',
        '[[property]]\nid = "SEC-D-001"\nname = "Fresh"\n\n[[property]]\nid = "SEC-C-001"',
    )
    said = red(tree, capsys)
    assert "SEC-D-001" in said
    assert "in no tranche" in said


def test_classifying_a_new_property_still_needs_the_matrix_regenerated(tree, capsys):
    tree.edit(
        "assurance/properties.toml",
        '[[property]]\nid = "SEC-C-001"',
        '[[property]]\nid = "SEC-D-001"\nname = "Fresh"\n\n[[property]]\nid = "SEC-C-001"',
    )
    tree.edit("assurance/configurations.toml", 'p0b = ["SEC-B-001"]', 'p0b = ["SEC-B-001", "SEC-D-001"]')
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_tranche_naming_a_property_the_registry_lost_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'p1 = ["SEC-C-001"]', 'p1 = ["SEC-C-001", "SEC-Z-999"]')
    assert "no such property" in red(tree, capsys)


def test_a_property_in_two_tranches_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'p1 = ["SEC-C-001"]', 'p1 = ["SEC-C-001", "SEC-A-001"]')
    assert "in more than one tranche" in red(tree, capsys)


# --- the equivalences, which are what a reviewer will attack ------------------


def test_an_equivalence_the_feature_closure_refutes_is_rejected(tree, capsys):
    """The sharpest arm. `firmware-screen` compiles a crate `firmware` does not,
    so an `equivalent` between them is false however plausible it reads — and
    the refusal has to name the crate, not merely disagree."""
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-screen"')
    said = red(tree, capsys)
    assert "an equivalence the tree refutes" in said
    assert "rsk-screen" in said


def test_the_page_derives_what_each_column_compiles_unlike_the_default(tree):
    """The measured half of a `gap`. Three never-published measurement builds
    were parked on "is a build nobody ships in the supported set at all", and the
    answer that settled them was a derivation, not a ruling: what does this
    column compile that the default does not. So the page carries it per column,
    including the two ways it can be nothing — knobs only, and the default build
    itself."""
    page = (tree.root / matrix_gate.ARTIFACT).read_text()
    rows = {
        line.split("|")[2].strip(): line.split("|")[7].strip()
        for line in page.splitlines()
        if line.startswith("| 0") or line.startswith("| 1")
    }
    assert rows["`firmware`"] == "—"
    assert rows["`firmware-pinned`"] == "—", "a knob-only column compiles like the default"
    assert rows["`firmware-no-touch`"] == "`firmware` +`no-touch`"
    assert rows["`firmware-screen`"] == "`firmware` +`screen`, `rsk-screen` (added)"


def test_the_page_and_the_refusal_are_the_same_derivation(tree, capsys):
    """A second copy of it would rot beside this one: the page could go on
    printing an emptiness the rule had stopped agreeing with. So the crates an
    `equivalent` is refused on are asserted to be the crates the page names."""
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-screen"')
    said = red(tree, capsys)
    page = (tree.root / matrix_gate.ARTIFACT).read_text()
    cell = next(
        line.split("|")[7] for line in page.splitlines() if "| `firmware-screen` |" in line
    )
    for crate in ("firmware", "rsk-screen"):
        assert f"`{crate}`" in cell and crate in said


def open_gaps(tree):
    """The Open gaps table as {column: [cells]}, sliced by its own heading.

    By heading rather than by counting pipes: the first version keyed on a row
    having five of them, and gaining the owner and the route made every row
    invisible to it — which is a probe that stops probing without going red.
    """
    page = (tree.root / matrix_gate.ARTIFACT).read_text()
    body = page.split("## Open gaps", 1)[1].split("\n## ", 1)[0]
    return {
        line.split("|")[1].strip(): [cell.strip() for cell in line.split("|")[2:-1]]
        for line in body.splitlines()
        if line.startswith("| `")
    }


def test_the_open_gaps_table_counts_the_rows_whose_own_crate_moved(tree):
    """What a `gap` costs, per column. A board preset sets knobs and no cargo
    feature, so NOTHING the properties are about compiles differently there and
    the count is zero however many rows are open — which is the distinction three
    parked measurement builds turned on, and the one a `gap` count alone hides."""
    rows = open_gaps(tree)
    assert rows["`board-a`"][:2] == ["2", "0"], "knobs only: no owner crate moves"
    assert rows["`firmware-no-touch`"][:2] == ["1", "1"]
    assert rows["`firmware-screen`"][:2] == ["2", "2"]


def test_the_delta_column_says_so_when_no_column_derives_as_the_default_build(tree):
    """The origin is derived (no feature, no knob) rather than named, so a
    renamed `firmware` cannot leave the page silently measuring against nothing
    — every delta would read `—`, which is the strongest word the column has."""
    for attr in ("default", "firmware"):
        tree.edit(
            "nix/firmware.nix",
            f'    {attr} = mkFirmware {{ name = "firmware"; }};',
            f'    {attr} = mkFirmware {{ name = "firmware"; flashSize = "16M"; }};',
        )
    page = matrix_gate.render(tree.root)
    cells = [
        line.split("|")[7].strip()
        for line in page.splitlines()
        if line.startswith("| 0") or line.startswith("| 1")
    ]
    assert cells and set(cells) == {"n/a — no column derives as the default build"}


def test_an_equivalent_cell_with_the_basis_removed_is_rejected(tree, capsys):
    """The roadmap's exit predicate, second half: deleting the justification
    from an `equivalent` cell reddens the row."""
    tree.edit(
        "assurance/configurations.toml",
        'knob_delta = ["vidpid=Pico"]\ndisposition = "equivalent"\nbasis = "same-cargo-features"',
        'knob_delta = ["vidpid=Pico"]\ndisposition = "equivalent"',
    )
    assert "basis `None` is not one of" in red(tree, capsys)


def test_an_equivalent_cell_with_the_reason_removed_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'why = "identical feature closure; the delta is a USB identity pair."',
        'why = "  "',
    )
    assert "a disposition with no reason" in red(tree, capsys)


def test_an_equivalence_asserted_as_prose_is_rejected(tree, capsys):
    """There is no prose basis left in the vocabulary. `stated` was legal for
    every disposition except `equivalent` — and `covered` asserts MORE than an
    equivalence does, so writing the stronger word walked straight past the
    rule: all 955 `gap` cells of the real ledger, re-declared, EXIT=0."""
    tree.edit(
        "assurance/configurations.toml",
        'knob_delta = ["vidpid=Pico"]\ndisposition = "equivalent"\nbasis = "same-cargo-features"',
        'knob_delta = ["vidpid=Pico"]\ndisposition = "equivalent"\nbasis = "stated"',
    )
    assert "basis `stated` is not one of" in red(tree, capsys)


def test_an_equivalence_on_a_basis_that_is_not_a_sameness_is_rejected(tree, capsys):
    """The bases are real and still not interchangeable: only one of them says
    two columns compile alike."""
    tree.edit(
        "assurance/configurations.toml",
        'knob_delta = ["vidpid=Pico"]\ndisposition = "equivalent"\nbasis = "same-cargo-features"',
        'knob_delta = ["vidpid=Pico"]\ndisposition = "equivalent"\nbasis = "check-sh-rows"',
    )
    said = red(tree, capsys)
    assert "`equivalent` may rest on ['same-cargo-features']" in said
    assert "takes the strongest word in the vocabulary" in said


def test_out_of_scope_cannot_rest_on_a_basis_about_the_default_build(tree, capsys):
    """The same rule one word over, in the direction that WITHDRAWS a claim: an
    `out-of-scope` says the code or the gate is absent, and both of those are
    facts about the tree rather than a judgement about it."""
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "out-of-scope"\nbasis = "crate-absent"',
        'disposition = "out-of-scope"\nbasis = "default-build"',
    )
    assert "`out-of-scope` may rest on ['crate-absent', 'gate-compiled-out']" in red(tree, capsys)


def test_an_equivalence_naming_no_column_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-ghost"')
    assert "names no column in `same_as`" in red(tree, capsys)


def test_an_equivalence_with_itself_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-pinned"')
    assert "names its own column" in red(tree, capsys)


def test_an_equivalence_that_does_not_write_down_its_knob_delta_is_rejected(tree, capsys):
    """Without this half the rule was VACUOUS on every cell that used it: both
    sides carry an empty cargo-feature set — that is what "the delta is knobs"
    means — so the check compared the empty set with itself, 143 times."""
    tree.edit("assurance/configurations.toml", 'knob_delta = ["vidpid=Pico"]\n', "")
    said = red(tree, capsys)
    assert "owes a `knob_delta`" in said
    assert "the tree derives ['vidpid=Pico']" in said


def test_a_knob_the_column_gained_reddens_its_equivalence(tree, capsys):
    tree.edit("nix/firmware.nix", '      vidpid = "Pico";', '      vidpid = "Pico";\n      flashSize = "8M";')
    said = red(tree, capsys)
    assert "declares the knob delta ['vidpid=Pico']" in said
    assert "flashSize=8M" in said


def test_a_knob_whose_VALUE_moved_reddens_its_equivalence(tree, capsys):
    """The names alone cannot see this, and it is the edit that matters: a board
    earns its equivalence by setting knobs to the values `build.rs` defaults to,
    and one of them drifting leaves an identical name list."""
    tree.edit("nix/firmware.nix", 'vidpid = "Pico";', 'vidpid = "Dev";')
    said = red(tree, capsys)
    assert "declares the knob delta ['vidpid=Pico']" in said
    assert "vidpid=Dev" in said


def test_an_equivalence_chain_that_closes_on_itself_is_rejected(tree, capsys):
    """`firmware-2mb` = `firmware-16mb` = `firmware-2mb` was EXIT=0: the rule
    only ever looked one step, and a closed chain reaches nothing at all."""
    tree.edit(
        "assurance/configurations.toml",
        'same_as = "firmware"\nknob_delta = ["vidpid=Pico"]',
        'same_as = "firmware-pinned-too"\nknob_delta = ["vidpid=Pico"]',
    )
    said = red(tree, capsys)
    assert "chain closes on itself" in said
    assert "reaches no evidence" in said


def test_an_equivalence_to_a_column_that_is_itself_a_gap_is_rejected(tree, capsys):
    """The other half: `abrobot-4m` = `abrobot-16m`, where the target's own cells
    on those rows are undecided. An equivalence inherits a disposition, and
    nobody's judgement is not one."""
    tree.edit(
        "assurance/configurations.toml",
        '''[[cell]]
properties = ["SEC-A-001", "SEC-A-002"]
columns = ["firmware-pinned"]
same_as = "firmware"
knob_delta = ["vidpid=Pico"]
disposition = "equivalent"
basis = "same-cargo-features"
why = "identical feature closure; the delta is a USB identity pair."

''',
        "",
    )
    tree.edit(
        "assurance/configurations.toml",
        '[[question]]\ncolumn = "firmware-no-touch"',
        '[[question]]\ncolumn = "firmware-pinned"\nowner = "contributor"\n'
        'settled_by = "evidence"\ntext = "is a pinned USB identity a'
        ' security control at all?"\n\n[[question]]\ncolumn = "firmware-no-touch"',
    )
    said = red(tree, capsys)
    assert "`same_as` reaches SEC-A-001 × firmware-pinned, which is a `gap`" in said
    assert "an equivalence to a cell nobody decided is undecided too" in said


def test_an_equivalence_that_reaches_evidence_two_steps_out_is_accepted(tree):
    """The green direction: a chain is legal, it just has to END somewhere.
    `firmware-pinned-too` = `firmware-pinned` = `firmware`, which is `covered`."""
    assert tree.run() == 0


def test_an_equivalence_over_several_columns_at_once_is_rejected(tree, capsys):
    """One cell, one column: the knob delta differs per column, so a cell that
    swept several would carry a delta true of at most one of them."""
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware-pinned"]\nsame_as',
        'columns = ["firmware-pinned", "board-a"]\nsame_as',
    )
    assert "names 2 columns" in red(tree, capsys)


# --- the other bases, each held to the tree it claims about -------------------


def test_claiming_an_absent_crate_that_is_compiled_in_is_rejected(tree, capsys):
    """Direction matters: the message has to say the crate is PRESENT, not that
    a label is unrecognised."""
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware", "firmware-no-touch", "firmware-pinned",'
        ' "firmware-pinned-too", "loud", "board-a"]',
        'columns = ["firmware", "firmware-no-touch", "firmware-pinned",'
        ' "firmware-pinned-too", "loud", "board-a", "firmware-screen"]',
    )
    said = red(tree, capsys)
    assert "claims SEC-B-001's owners are absent" in said
    assert "rsk-screen" in said


def test_a_compiled_out_gate_a_column_does_not_enable_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'feature = "no-touch"',
        'feature = "screen"',
    )
    assert "which this column does not enable" in red(tree, capsys)


def test_a_compiled_out_gate_no_code_reads_is_rejected(tree, capsys):
    """A feature with no `cfg` site is a switch that throws nothing."""
    tree.edit("firmware/src/presence.rs", '#[cfg(not(feature = "no-touch"))]\n', "")
    assert "no production Rust gates on it" in red(tree, capsys)


def test_a_compiled_out_gate_that_does_not_say_which_site_is_rejected(tree, capsys):
    """That the feature exists is not the claim. Eight store and boot rows were
    declared out-of-scope on `firmware-fips` for `fips-profile` and passed on
    nothing more than some Rust somewhere gating on it."""
    tree.edit("assurance/configurations.toml", 'cfg = ["firmware/src/presence.rs"]\n', "")
    said = red(tree, capsys)
    assert "and no `cfg`" in said
    assert "is the whole claim" in said


def test_a_compiled_out_gate_naming_a_file_that_does_not_gate_on_it_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'cfg = ["firmware/src/presence.rs"]',
        'cfg = ["crates/rsk-core/src/lib.rs"]',
    )
    said = red(tree, capsys)
    assert "does not gate on `no-touch`" in said
    assert "firmware/src/presence.rs" in said


def test_a_compiled_out_gate_in_a_crate_the_property_is_not_about_is_rejected(tree, capsys):
    """The direction that matters: `rsk-core` really does gate on the feature and
    is still not where SEC-A-001 lives, so that switch is another property's."""
    tree.write(
        "crates/rsk-core/src/lib.rs",
        '#[cfg(feature = "no-touch")]\npub fn quiet() {}\n'
        "/// Refines `Fixture!Kept` — SEC-A-002.\npub fn kept() {}\n",
    )
    tree.edit(
        "assurance/configurations.toml",
        'cfg = ["firmware/src/presence.rs"]',
        'cfg = ["crates/rsk-core/src/lib.rs"]',
    )
    said = red(tree, capsys)
    assert "gates on `no-touch` in `rsk-core`" in said
    assert "another property's gate" in said


#: The glue route, in the shape the real tree has it: the switch is in
#: `firmware`, and the property it is claimed for lives in a crate. `firmware`
#: carries 1 of the real matrix's 40 rows, so the `carries | {"firmware"}` that
#: used to be the radius admitted every `firmware/` switch as every property's
#: gate — measured, `SEC-TRANS-001/002/003` took `out-of-scope` on the touch
#: button across nine columns, 27 cells, at EXIT=0.
GLUE_PRESENCE = """\
/// Refines `Fixture!Gated` — SEC-A-001.
pub fn gated() {}

impl fixture_sdk::UserPresence for Button {
    #[cfg(not(feature = "no-touch"))]
    fn press(&self) -> bool {
        sample()
    }
}
"""
#: The owner crate of `SEC-A-002`, and whether it names the hook is the whole
#: separation: the four properties the real `no-touch` cell is about all name
#: `UserPresence` and `rsk-usb` — which owns the reassembler — does not.
GLUE_CORE = """\
/// Refines `Fixture!Held` — SEC-A-002.
pub fn held(_p: &dyn UserPresence) {}
"""


def glue(tree, core=GLUE_CORE, hook='hook = "fixture_sdk::UserPresence"\n'):
    """Move `SEC-A-002` into `rsk-core` and claim the firmware switch for it."""
    tree.write("firmware/src/presence.rs", GLUE_PRESENCE)
    tree.write("crates/rsk-core/src/lib.rs", core)
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-A-001"]\ncolumns = ["firmware-no-touch"]',
        'properties = ["SEC-A-002"]\ncolumns = ["firmware-no-touch"]',
    )
    tree.edit(
        "assurance/configurations.toml",
        'feature = "no-touch"',
        hook + 'feature = "no-touch"',
    )


def test_a_firmware_switch_claimed_for_a_crates_property_owes_a_hook(tree, capsys):
    """The radius is the property's OWNERS. `firmware` is a route into it and not
    a member, so a glue site that names no hook is the blanket back again."""
    glue(tree, hook="")
    said = red(tree, capsys)
    assert "gate on `no-touch` in `firmware`, which does not carry SEC-A-002" in said
    assert "the glue crate is every property's gate" in said


def test_a_hook_the_owner_crate_never_names_is_rejected(tree, capsys):
    """The reassembler measurement, in miniature: the switch is real, the impl is
    real, and the property's own crate has never heard of the trait."""
    glue(tree, core="/// Refines `Fixture!Held` — SEC-A-002.\npub fn held() {}\n")
    said = red(tree, capsys)
    assert "never name `fixture_sdk::UserPresence`" in said
    assert "the gate behind it is that property's" in said


def test_a_hook_the_feature_does_not_gate_inside_is_rejected(tree, capsys):
    """A switch elsewhere in the file is not the hook's switch. This is the arm
    the owner half cannot raise: `rsk-usb` DOES name `MsgHandler`, and
    `strict-config`'s one site in `worker.rs` sits in an inherent `impl Worker`."""
    glue(tree)
    tree.edit(
        "firmware/src/presence.rs",
        '    #[cfg(not(feature = "no-touch"))]\n',
        "",
    )
    tree.edit(
        "firmware/src/presence.rs",
        "pub fn gated() {}",
        '#[cfg(not(feature = "no-touch"))]\npub fn gated() {}',
    )
    said = red(tree, capsys)
    assert "no `cfg` named here implements `fixture_sdk::UserPresence`" in said
    assert "a switch elsewhere in the file is not it" in said


def test_a_hook_the_owner_names_and_the_feature_gates_inside_is_accepted(tree):
    """Both directions: the rule has to let the real `no-touch` cell through, or
    it is a rule that refuses the 16 cells it was written to keep."""
    glue(tree)
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


def test_covered_on_a_configured_column_owes_the_rows_that_produced_it(tree, capsys):
    """`covered` is the strongest word in the vocabulary and it rested on
    nothing: the reviewer re-declared every `gap` cell of the real ledger
    `covered` and the row printed ok over 995 of them."""
    tree.edit("assurance/configurations.toml", 'evidence = ["kani (screen)"]\n', "")
    said = red(tree, capsys)
    assert "and no `evidence`" in said
    assert "the prose basis this vocabulary dropped" in said


def test_covered_naming_a_row_check_sh_does_not_have_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["test (the screen, surely)"]',
    )
    assert "which is no scripts/check.sh row" in red(tree, capsys)


def test_covered_naming_a_row_that_builds_another_image_is_rejected(tree, capsys):
    """The half that makes the basis worth having: a row is evidence for THIS
    column only if it builds this column's features."""
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["clippy (loud)"]',
    )
    said = red(tree, capsys)
    assert "builds ['loud'] and this column is ['screen']" in said
    assert "evidence from another image" in said


def test_covered_naming_a_row_that_does_not_pin_the_columns_knobs_is_rejected(tree, capsys):
    """And the other half, without which the basis is VACUOUS on every column
    whose whole delta is knobs — the six boards, and the geometry siblings."""
    tree.edit(
        "nix/firmware.nix",
        '      name = "firmware-screen";',
        '      name = "firmware-screen";\n      flashSize = "16M";',
    )
    said = red(tree, capsys)
    assert "does not pin ['FLASH_SIZE=16M']" in said
    assert "measured another image" in said


def test_covered_naming_a_row_that_only_compiles_the_image_is_rejected(tree, capsys):
    """The sharpest arm of this basis. A row that builds exactly this column
    still says nothing about THIS property — `build firmware (test, --features
    no-touch)` would otherwise have re-declared the four presence statements
    `covered` on the very image that removes the gate they are about."""
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["clippy (screen build)"]',
    )
    tree.edit(
        "scripts/check.sh",
        'run "clippy (loud)"',
        'run "clippy (screen build)" cargo build -p firmware --features screen\n'
        'run "clippy (loud)"',
    )
    said = red(tree, capsys)
    assert "no row named here selects ['rsk-screen']" in said
    assert "is not evidence about this property" in said


def test_covered_on_a_board_names_a_row_that_builds_that_board(tree, capsys):
    """A board preset's knobs are `build.rs`'s vocabulary and no row spells them
    out — a row reaches a board by its NAME, and that is what is checked."""
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen"]\ndisposition = "covered"',
        'properties = ["SEC-A-001"]\ncolumns = ["board-a"]\ndisposition = "covered"',
    )
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        'evidence = ["test (core)"]',
    )
    assert "does not pin ['BOARD=board-a']" in red(tree, capsys)


def test_two_check_sh_rows_under_one_label_are_rejected(tree, capsys):
    """The evidence lookup is by label, so two rows under one of them is a cell
    naming both and a gate reading one — the `mkFirmware` name collision, one
    file over."""
    tree.edit(
        "scripts/check.sh",
        'run "clippy (loud)"',
        'run "test (screen)" cargo test -p firmware --features loud\nrun "clippy (loud)"',
    )
    assert "has two rows named 'test (screen)'" in red(tree, capsys)


def test_the_default_build_basis_on_a_configured_column_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware"]\ndisposition = "covered"',
        'columns = ["firmware-no-touch"]\ndisposition = "covered"',
    )
    assert "basis `default-build` on a column that enables" in red(tree, capsys)


# --- the vocabulary and the shape of the ledger -------------------------------


def test_a_sixth_disposition_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "covered"\nbasis = "check-sh-rows"',
        'disposition = "probably-fine"\nbasis = "check-sh-rows"',
    )
    assert "disposition `probably-fine` is not one of" in red(tree, capsys)


def test_a_field_the_basis_does_not_read_is_rejected(tree, capsys):
    """`render` prints `same_as` whatever the disposition is, so a `covered` cell
    carrying one would show the reader a sameness the gate never derived."""
    tree.edit(
        "assurance/configurations.toml",
        'basis = "check-sh-rows"\nevidence = ["kani (screen)"]',
        'basis = "check-sh-rows"\nevidence = ["kani (screen)"]\nsame_as = "firmware"',
    )
    said = red(tree, capsys)
    assert "carries ['same_as'], which basis `check-sh-rows` does not read" in said
    assert "the page prints it beside the ones that are checked" in said


def test_an_invented_basis_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'basis = "crate-absent"', 'basis = "looks-the-same"')
    assert "basis `looks-the-same` is not one of" in red(tree, capsys)


def test_two_dispositions_for_one_cell_are_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen"]',
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen", "firmware"]',
    )
    assert "is disposed of twice" in red(tree, capsys)


def test_a_cell_for_a_column_that_does_not_exist_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", '"loud", "board-a"]', '"loud", "board-a", "board-z"]')
    assert "no such build configuration" in red(tree, capsys)


def test_a_cell_for_a_property_outside_the_p0_family_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen"]',
        'properties = ["SEC-B-001", "SEC-C-001"]\ncolumns = ["firmware-screen"]',
    )
    assert "is not a P0-family property" in red(tree, capsys)


# --- `gap` is a value, not a shrug -------------------------------------------


def test_a_declared_gap_cell_is_rejected(tree, capsys):
    """`gap` is the ABSENCE of a cell here. Declaring one put the cell in the
    placed set, which took the column out of the rule below while the grid still
    printed `gap` in every one of its cells — measured on the real ledger at 37
    cells and a deleted question, gate green."""
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "covered"\nbasis = "check-sh-rows"',
        'disposition = "gap"\nbasis = "check-sh-rows"',
    )
    said = red(tree, capsys)
    assert "disposition `gap` is not one of" in said
    assert "owe a settling question" in said


def test_a_column_with_gaps_and_no_question_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        '[[question]]\ncolumn = "firmware-no-touch"\nowner = "contributor"\n'
        'settled_by = "absence"\ntext = "does SEC-A-002 depend on the press indirectly?"\n\n',
        "",
    )
    said = red(tree, capsys)
    assert "`gap` cell(s) and no settling question" in said
    assert "a shrug" in said


def test_a_question_for_a_column_with_nothing_left_to_settle_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        '[[question]]\ncolumn = "loud"',
        '[[question]]\ncolumn = "firmware-pinned"\nowner = "contributor"\n'
        'settled_by = "evidence"\ntext = "nothing is open here."\n\n[[question]]\ncolumn = "loud"',
    )
    assert "no `gap` cell left to settle" in red(tree, capsys)


def test_a_settling_question_that_is_a_placeholder_is_rejected(tree, capsys):
    """`.strip()` alone let `"?"` and `"TODO"` stand as the question that would
    settle a whole column."""
    tree.edit(
        "assurance/configurations.toml",
        'text = "does SEC-A-002 depend on the press indirectly?"',
        'text = "TODO"',
    )
    said = red(tree, capsys)
    assert "no settling question" in said
    assert "is the same shrug" in said


# --- who owes the answer, and what would end the deferral --------------------


def test_the_owner_vocabulary_is_the_one_platform_gate_already_chose():
    """Borrowed, not re-picked — the identity is the assertion. A copy satisfies
    every rule below on the day it is written and is a second answer to one
    question the first time either register gains a role, which is the shape this
    repo has already been bitten by: a shared constant imported, then not used at
    the site it was imported for."""
    assert matrix_gate.OWNERS is platform_gate.OWNERS


def test_every_basis_a_cell_can_rest_on_has_a_route_that_reaches_it():
    """[`SETTLES`] is the disposition table read backwards, so it has to stay
    TOTAL over it — and until this case existed its values were read by nothing,
    which is the field-nothing-reads defect inside the diff that closed it. A
    sixth basis added to `ALLOWED` with no route would leave a question unable to
    name what settles its column, and `evidence` would silently become the answer
    for everything. `default-build` is the one basis deliberately unreachable: a
    column that IS the default build has no `gap` cell to settle."""
    reachable = {b for bases in matrix_gate.SETTLES.values() for b in bases}
    allowed = {b for bases in matrix_gate.ALLOWED.values() for b in bases}
    assert reachable <= set(matrix_gate.BASES)
    assert allowed - reachable == {matrix_gate.DEFAULT_BUILD}
    assert matrix_gate.SETTLES["ruling"] == (), "a ruling rests on no basis; it makes one"


def test_a_question_nobody_owns_is_rejected(tree, capsys):
    """Stage 0's last exit bullet. The vocabulary is `platform_gate`'s, borrowed
    rather than re-picked — a second one would be two answers to one question."""
    tree.edit("assurance/configurations.toml", 'owner = "contributor"\nsettled_by = "absence"', 'settled_by = "absence"')
    said = red(tree, capsys)
    assert "is owed by None" in said
    assert "a wish with a column number" in said


def test_a_question_owed_to_a_role_that_does_not_exist_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'owner = "maintainer"', 'owner = "someone"')
    assert "is owed by 'someone', which is not one of" in red(tree, capsys)


def test_a_question_that_cannot_say_what_would_end_it_is_rejected(tree, capsys):
    """A deferral with no route is not a deferral; it is the same shrug the word
    floor catches one field over."""
    tree.edit("assurance/configurations.toml", 'settled_by = "evidence"', "")
    said = red(tree, capsys)
    assert "settled_by = None" in said
    assert "is not deferred" in said


def test_a_question_waiting_on_a_ruling_that_nobody_can_rule_is_rejected(tree, capsys):
    """`ruling` means a decision no derivation can produce, and in this repo that
    is the maintainer's — AGENTS.md's maintainer-only list. Any other owner on it
    is a deferral pointed at somebody who cannot end it."""
    tree.edit("assurance/configurations.toml", 'owner = "maintainer"', 'owner = "contributor"')
    said = red(tree, capsys)
    assert "waits on a ruling and is owed by 'contributor'" in said
    assert "per AGENTS.md" in said


def test_a_question_waiting_on_an_equivalence_the_tree_refutes_is_rejected(tree, capsys):
    """The sharpest of the four, and the one this register was built out of:
    three columns sat parked on "maybe it is equivalent" while the derivation
    already said it is not. `loud` enables a cargo feature, so its closure is not
    the default build's and `same-cargo-features` can never be reached there."""
    tree.edit("assurance/configurations.toml", 'settled_by = "evidence"', 'settled_by = "sameness"')
    said = red(tree, capsys)
    assert "waits on an equivalence" in said
    assert "['firmware']" in said and "the tree already refuses it here" in said


def test_a_question_waiting_on_an_absence_that_cannot_happen_is_rejected(tree, capsys):
    """The other refusable route. A board preset sets knobs and no cargo feature,
    so nothing is compiled out and every open row's owner is compiled in —
    `out-of-scope` has neither of its bases to reach for."""
    tree.edit("assurance/configurations.toml", 'settled_by = "sameness"', 'settled_by = "absence"')
    said = red(tree, capsys)
    assert "waits on the code being absent" in said
    assert "neither basis `out-of-scope` takes can reach a cell here" in said


def test_a_field_a_question_does_not_read_is_rejected(tree, capsys):
    """`[[cell]]` has refused a stray field since it shipped and `[[question]]`
    had no list at all, so a key added here was read by nothing and printed by
    nothing — including a `review_by` somebody adds because the criterion says
    "date"."""
    tree.edit(
        "assurance/configurations.toml",
        'settled_by = "sameness"',
        'settled_by = "sameness"\nreview_by = "2027-01-01"',
    )
    said = red(tree, capsys)
    assert "carries ['review_by'], which nothing reads" in said
    assert "checked by nothing and printed by nothing" in said


def test_a_ledger_table_nothing_reads_is_rejected(tree, capsys):
    """The same question one level out, asked because the field one was. A
    mistyped `[[cell]]` is caught by the cells going missing; a table under a NEW
    name is a section of the file written for no reader, and nothing saw it."""
    tree.edit(
        "assurance/configurations.toml",
        '[[question]]\ncolumn = "board-a"',
        '[[review]]\nwhen = "2027-01-01"\n\n[[question]]\ncolumn = "board-a"',
    )
    said = red(tree, capsys)
    assert "carries a `review` table" in said
    assert "a section of this file no reader reads" in said


def test_the_page_prints_who_owes_each_question_and_what_would_end_it(tree):
    """A field the page does not show is the field-nothing-reads one step out:
    the gate would hold it and no reader would ever see it."""
    rows = open_gaps(tree)
    assert rows["`firmware-screen`"][2:4] == ["maintainer", "`ruling`"]
    assert rows["`board-a`"][2:4] == ["contributor", "`sameness`"]


def test_a_reason_that_is_a_placeholder_is_rejected(tree, capsys):
    """The same hole one field over: `why` was `.strip()`-checked too, so
    "believed fine." was a reason."""
    tree.edit(
        "assurance/configurations.toml",
        'why = "identical feature closure; the delta is a USB identity pair."',
        'why = "believed fine."',
    )
    assert "a disposition with no reason" in red(tree, capsys)


def test_a_question_for_a_column_that_does_not_exist_is_rejected(tree, capsys):
    tree.edit('assurance/configurations.toml', 'column = "board-a"', 'column = "board-z"')
    assert "which is no column" in red(tree, capsys)


# --- the derivation itself, which is the half a verdict column cannot show ----


def test_an_axis_that_derives_to_nothing_is_rejected(tree, capsys):
    """Every rule above passes over an empty matrix; five guards in this tree
    shipped with exactly that shape."""
    tree.write("nix/firmware.nix", "{ packages = { }; }\n")
    said = red(tree, capsys)
    assert "under the floors" in said
    assert "satisfies every rule below over an empty matrix" in said


def test_the_shipped_floors_are_this_tree_s_counts():
    """A floor of 12 against 19 packages catches a derivation that COLLAPSED and
    never one that slid: four boards can go one at a time under 4-vs-6. At the
    count, losing one is red until the floor is edited in the same diff."""
    cols = matrix_gate.columns(ROOT, matrix_gate.workspace(ROOT))
    assert matrix_gate.FLOOR_PACKAGES == len([c for c in cols if c.kind == "package"])
    assert matrix_gate.FLOOR_BOARDS == len([c for c in cols if c.kind == "board"])
    doc = matrix_gate.ledger(ROOT)
    tranche = {
        pid: name
        for name in matrix_gate.TRANCHES
        for pid in doc.get("tranche", {}).get(name, [])
    }
    rows = [pid for pid, _n in matrix_gate.registry(ROOT)
            if tranche.get(pid) in matrix_gate.ROW_TRANCHES]
    assert matrix_gate.FLOOR_ROWS == len(rows)


def test_a_row_axis_that_derives_to_nothing_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'p0-launch = ["SEC-A-001", "SEC-A-002"]', "p0-launch = []")
    assert "under the floor of" in red(tree, capsys)


def test_a_published_image_the_flake_does_not_build_is_rejected(tree, capsys):
    tree.edit(
        ".github/workflows/release-build.yml",
        "          for pkg in firmware firmware-screen; do\n            nix build \".#$pkg\"\n",
        "          for pkg in firmware firmware-screen firmware-ghost; do\n            nix build \".#$pkg\"\n",
    )
    said = red(tree, capsys)
    assert "publishes firmware-ghost" in said
    assert "flavor loops disagree" in said


def test_a_package_the_pattern_cannot_see_is_reported(tree, capsys):
    """The saw-everything invariant. Without it a package written in a spelling
    the block pattern misses is a column that never exists, and the only thing
    the gate would ever say is "regenerate and commit" — which launders it."""
    tree.edit(
        "nix/firmware.nix",
        "    firmware-pinned = mkFirmware {",
        '    inherit (x) y;\n    z = { a = mkFirmware { name = "ghost"; }; };\n'
        "    firmware-pinned = mkFirmware {",
    )
    said = red(tree, capsys)
    assert "calls mkFirmware" in said
    assert "a column that never exists" in said


def test_a_package_with_the_call_on_the_next_line_is_still_a_column(tree, capsys):
    """The green direction of the same rule: `attr =` / newline / `mkFirmware {`
    is how this very file already breaks two other bindings, and reading it as
    absent would report a package that is there as gone."""
    tree.edit(
        "nix/firmware.nix",
        "    firmware-pinned = mkFirmware {",
        "    firmware-pinned =\n      mkFirmware {",
    )
    assert tree.run() == 0


def test_a_cargo_flag_that_is_not_a_feature_is_a_knob(tree, capsys):
    """`--features` is not the only thing in a `cargoFlags` list, and the rest
    changes the image: a residual read as nothing left `--no-default-features`
    invisible to both halves of the equivalence rule AND to `default-build`."""
    tree.edit(
        "nix/firmware.nix",
        '      vidpid = "Pico";',
        '      vidpid = "Pico";\n      cargoFlags = [\n        "--no-default-features"\n      ];',
    )
    said = red(tree, capsys)
    assert "declares the knob delta ['vidpid=Pico']" in said
    assert "cargoFlags=--no-default-features" in said


def test_a_non_feature_cargo_flag_takes_the_default_build_basis_away(tree, capsys):
    """The other half of the same defect: a package built `--profile release-fast`
    reads as the image every measurement was taken on."""
    for attr in ("default", "firmware"):
        tree.edit(
            "nix/firmware.nix",
            f'    {attr} = mkFirmware {{ name = "firmware"; }};',
            f'    {attr} = mkFirmware {{ name = "firmware"; cargoFlags = ['
            ' "--profile" "release-fast" ]; };',
        )
    said = red(tree, capsys)
    assert "basis `default-build` on a column that enables" in said
    assert "cargoFlags" in said


@pytest.mark.parametrize("spelling", ["cargoFlags= [", "cargoFlags  = [", "cargoFlags =["])
def test_a_cargoflags_spelling_nixfmt_does_not_write_is_still_read(tree, spelling):
    """Nothing in this tree runs `nixfmt --check`, so the canonical shape cannot
    be assumed — and each of these read as NO features, which is a published
    flavor printing as the default build."""
    tree.edit(
        "nix/firmware.nix",
        '      name = "firmware-no-touch";\n      cargoFlags = [',
        f'      name = "firmware-no-touch";\n      {spelling}',
    )
    derived = matrix_gate.packages(tree.root)["firmware-no-touch"]
    assert derived == (frozenset({"no-touch"}), {}), derived
    assert tree.run() == 0


def test_a_cargoflags_the_gate_cannot_read_is_refused(tree, capsys):
    """A flag list that is not literal strings is a column derived wrong, and the
    conservative answer is to say so rather than to derive no flags."""
    tree.edit(
        "nix/firmware.nix",
        '      cargoFlags = [\n        "--features"\n        "screen"\n      ];',
        "      cargoFlags = extraFlags;",
    )
    assert "carries 'extraFlags', which is not a literal flag" in red(tree, capsys)


def test_a_cargoflags_list_with_flags_appended_to_it_is_refused(tree, capsys):
    """The same rule at the other end: reading only as far as the first `]`
    would take `[ … ] ++ extra` for the list and never see the rest."""
    tree.edit(
        "nix/firmware.nix",
        '        "screen"\n      ];',
        '        "screen"\n      ] ++ extraFlags;',
    )
    assert "which is not a literal flag" in red(tree, capsys)


def test_two_packages_under_one_name_that_derive_differently_are_rejected(tree, capsys):
    """`default` and `firmware` are one image under two attributes — but only
    while they derive the same. One of them gaining a knob replaced the other's
    column with NO message, and the saw-everything count cannot see it: both
    blocks are seen."""
    tree.edit(
        "nix/firmware.nix",
        '    default = mkFirmware { name = "firmware"; };',
        '    default = mkFirmware { name = "firmware"; flashSize = "16M"; };',
    )
    said = red(tree, capsys)
    assert "builds `firmware` from two mkFirmware blocks" in said
    assert "replaced the first with no message" in said


def test_a_features_flag_written_with_an_equals_sign_is_read(tree, capsys):
    """`--features=a` is a spelling cargo takes and a hand-rolled word scan does
    not — and a package whose features read as empty looks like the default
    build, which is a basis the gate ACCEPTS."""
    tree.edit(
        "nix/firmware.nix",
        '        "--features"\n        "screen"\n',
        '        "--features=screen"\n',
    )
    assert tree.run() == 0


def test_a_board_in_a_subdirectory_is_a_column(tree, capsys):
    """`build.rs` reads `boards/{BOARD}.toml` with no rule against a `/`, so a
    flat glob calls a real, buildable preset no board at all."""
    tree.write("firmware/boards/vendor/board-c.toml", BOARD_A)
    assert "is not what the generator writes" in red(tree, capsys)


def test_one_flavor_loop_is_under_the_floor(tree, capsys):
    """Without the floor, a reflow that hides one loop leaves the "the two lists
    must agree" comparison running over a single list, in silence."""
    tree.edit(
        ".github/workflows/release-build.yml",
        "      - name: rebuild\n        run: |\n          for pkg in firmware firmware-screen; do\n            nix build \".#$pkg\" --rebuild\n          done\n",
        "",
    )
    assert "under the floor of" in red(tree, capsys)


def test_a_malformed_input_is_a_finding_and_not_a_traceback(tree, capsys):
    """A traceback is a red too, and a much worse one: it names a line of the
    guard rather than the file whose shape changed."""
    tree.write("firmware/boards/board-a.toml", "loose = 1\n")
    assert "the axes cannot be derived from the tree" in red(tree, capsys)


def test_a_weak_feature_edge_fires_whatever_order_it_is_offered_in(tree, capsys):
    """`dep?/feat` fires only once the optional dependency is in, and a single
    pass drops the edge when it is walked first. `Column` passes the features
    SORTED, so a single-pass answer depended on the alphabet — and it
    under-approximated, which is the direction that makes a false `equivalent`
    pass."""
    tree.edit("firmware/Cargo.toml", "loud = []", 'loud = ["rsk-screen?/loud"]')
    tree.write("crates/rsk-screen/Cargo.toml", SCREEN + "\n[features]\nloud = []\n")
    manifests = matrix_gate.workspace(tree.root)
    both = [matrix_gate.resolve(manifests, order)[1].get("rsk-screen", frozenset())
            for order in (["loud", "screen"], ["screen", "loud"])]
    assert both[0] == both[1] == frozenset({"loud"}), both
    assert matrix_gate.resolve(manifests, ["loud"])[1].get("rsk-screen") is None


def test_a_hand_edited_matrix_is_rejected(tree, capsys):
    """The artifact says "do not edit by hand" and nothing made that true until
    this row; `config_gen_gate.py` shipped for the same reason one file over."""
    tree.edit("docs/assurance-matrix.md", "## Open gaps", "## Open holes")
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_matrix_rewritten_with_crlf_line_endings_is_rejected(tree, capsys):
    """`read_text` folds `\\r\\n` to `\\n`, so a CRLF copy compared as text is
    EQUAL to the LF one the generator writes — and the whole rewrite passed. The
    lesson is `config_gen_gate.py`'s, in the file this row names as its model."""
    path = tree.root / "docs/assurance-matrix.md"
    path.write_bytes(path.read_text().replace("\n", "\r\n").encode())
    assert "is not what the generator writes" in red(tree, capsys)


# --- what counts as production Rust ------------------------------------------


def test_a_cfg_site_no_buildable_image_compiles_is_not_a_gate(tree, capsys):
    """The filename filter this reader used to be, in the shape that survived it.

    `cfg_sites` refused a `kani`/`tests` NAME, which is what
    `assurance_gate.cfg_excluded` was written to replace; measured on the real
    tree, the two readers differed on 18 files. The sharpest of them is a
    DIRECTORY: `crates/rsk-fido/src/conformance/` is `#[cfg(test)] mod
    conformance;` and that function named only its `mod.rs`, so its eighteen
    siblings were still offered as gate sites — an `out-of-scope` cell citing
    `crates/rsk-fido/src/conformance/getinfo.rs` was EXIT=0, which is exactly
    what `cfg_sites`'s own docstring says it prevents. `ff0b277` moved that
    closure INTO `cfg_excluded`, so the case runs there now and this row pins
    the shape from the matrix end.
    """
    # Under `presence/`, because `presence.rs` is neither a crate root nor a
    # `mod.rs`: rustc 1.96 answers E0583 for `firmware/src/conformance/mod.rs`
    # and names these two paths itself. The fixture wrote a tree rustc rejects,
    # and the resolver agreed with it until `assurance_gate._child_home`.
    tree.write("firmware/src/presence/conformance/mod.rs", "mod wire;\n")
    tree.write(
        "firmware/src/presence/conformance/wire.rs",
        '#[cfg(feature = "no-touch")]\nfn only_here() {}\n',
    )
    tree.edit("firmware/src/presence.rs", "pub fn press()", "#[cfg(test)]\nmod conformance;\npub fn press()")
    tree.edit(
        "assurance/configurations.toml",
        'cfg = ["firmware/src/presence.rs"]',
        'cfg = ["firmware/src/presence/conformance/wire.rs"]',
    )
    matrix_gate.cfg_sites.cache_clear()
    matrix_gate.production_rust.cache_clear()
    said = red(tree, capsys)
    assert "names `firmware/src/presence/conformance/wire.rs`" in said
    assert "which does not gate on `no-touch`" in said


def test_a_cfg_site_a_buildable_image_does_compile_is_still_a_gate(tree):
    """The green direction, and the one that keeps the fix from being a blanket
    refusal on directories: the same two files under a `mod` no cfg withholds
    stay a gate site, and the cell citing one of them passes."""
    tree.write("firmware/src/presence/conformance/mod.rs", "mod wire;\n")
    tree.write(
        "firmware/src/presence/conformance/wire.rs",
        '#[cfg(feature = "no-touch")]\nfn only_here() {}\n',
    )
    tree.edit("firmware/src/presence.rs", "pub fn press()", "mod conformance;\npub fn press()")
    tree.edit(
        "assurance/configurations.toml",
        'cfg = ["firmware/src/presence.rs"]',
        'cfg = ["firmware/src/presence/conformance/wire.rs"]',
    )
    matrix_gate.cfg_sites.cache_clear()
    matrix_gate.production_rust.cache_clear()
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


# --- one column, one equivalence ---------------------------------------------


def test_a_second_equivalent_cell_on_one_column_is_rejected(tree, capsys):
    """`knob_delta` is a function of (column, `same_as`), so two `equivalent`
    cells on that pair derive the SAME delta and differ only in their row list
    and their prose — one cell written twice, with two `why` bodies free to
    argue opposite things. Measured on the real tree: appending a second
    `firmware-2mb` = `firmware` cell for three more rows was EXIT=0 beside a
    first one whose own `why` says every other row on that column stays `gap`.
    """
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-A-001", "SEC-A-002"]\ncolumns = ["firmware-pinned"]',
        'properties = ["SEC-A-001"]\ncolumns = ["firmware-pinned"]',
    )
    tree.edit(
        "assurance/configurations.toml",
        'why = "identical feature closure; the delta is a USB identity pair."',
        'why = "identical feature closure; the delta is a USB identity pair."\n\n'
        "[[cell]]\n"
        'properties = ["SEC-A-002"]\n'
        'columns = ["firmware-pinned"]\n'
        'same_as = "firmware"\n'
        'knob_delta = ["vidpid=Pico"]\n'
        'disposition = "equivalent"\n'
        'basis = "same-cargo-features"\n'
        'why = "the same pair again, for the row the cell above stopped naming."',
    )
    said = red(tree, capsys)
    assert "firmware-pinned: 2 `equivalent` cells claim this one column" in said
    assert "one cell split in two" in said


def test_a_second_equivalent_cell_escaping_by_another_same_as_is_rejected(tree, capsys):
    """The escape the `(column, same_as)` key left open, and the reason the key
    is now the column alone: sameness of the derived closure is an equivalence
    relation, so a second cell had only to name a DIFFERENT identical-closure
    column to mint a new key. Measured on the real ledger: a second
    `firmware-16mb` cell saying `same_as = "waveshare-one"` — which chains to the
    same `firmware` — added 5 cells at EXIT=0, its `why` free to contradict the
    first cell's."""
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-A-001", "SEC-A-002"]\ncolumns = ["firmware-pinned-too"]\n'
        'same_as = "firmware-pinned"',
        'properties = ["SEC-A-001"]\ncolumns = ["firmware-pinned-too"]\n'
        'same_as = "firmware-pinned"',
    )
    tree.edit(
        "assurance/configurations.toml",
        'why = "the same pinned identity as firmware-pinned, one step further out."',
        'why = "the same pinned identity as firmware-pinned, one step further out."\n\n'
        "[[cell]]\n"
        'properties = ["SEC-A-002"]\n'
        'columns = ["firmware-pinned-too"]\n'
        'same_as = "firmware"\n'
        'knob_delta = ["vidpid=Nitro3"]\n'
        'disposition = "equivalent"\n'
        'basis = "same-cargo-features"\n'
        'why = "measured against the default build rather than against its sibling."',
    )
    said = red(tree, capsys)
    assert "firmware-pinned-too: 2 `equivalent` cells claim this one column" in said
    assert "whatever each names in `same_as`" in said


def test_one_equivalent_cell_retargeted_at_the_default_build_is_accepted(tree):
    """The green direction, and it keeps the rule about the COLUMN rather than
    about the target: the same single cell, pointed at the default build instead
    of at its sibling, still passes."""
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware-pinned-too"]\nsame_as = "firmware-pinned"',
        'columns = ["firmware-pinned-too"]\nsame_as = "firmware"',
    )
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


# --- the derived caveat on the Open gaps table --------------------------------


def test_the_page_names_the_rows_that_carry_no_production_tag(tree):
    """The number was DERIVED for a reason the comment beside it got backwards.

    "Three P0-family rows carry no production tag" was exact when it was written
    at 41ddf88 (`SEC-FIDO-006A/B/C`) and went to zero at fc7491a, which tagged
    them — so it rotted rather than arriving wrong, which is the stronger case
    for deriving it. Nothing drove the non-empty branch, and replacing the whole
    derivation with a hard-coded `[]` left the suite green.
    """
    tree.edit("firmware/src/presence.rs", "/// Refines `Fixture!Held` — SEC-A-002.\n", "")
    page = matrix_gate.render(tree.root)
    assert "1 P0-family row(s) carry no production tag at all (`SEC-A-002`)" in page
    assert "which is the one direction this number can be wrong in" in page


def test_the_page_says_so_when_every_row_carries_a_tag(tree):
    """And the other arm, which is the one this checkout is in."""
    page = matrix_gate.render(tree.root)
    assert "Every P0-family row carries a production tag" in page
    assert "carry no production tag at all" not in page


# --- a knob the command the `env` prefix wraps never sees ----------------------


def a_covered_cell_on(tree, column, absent, row, label):
    """Move the fixture's one `check-sh-rows` cell onto `column`, resting on `row`.

    `absent` is how the column leaves the `crate-absent` list on the way, and it
    has to: one cell disposed of twice is a different refusal, and it would
    answer a different question from the one each case below asks.
    """
    tree.edit("assurance/configurations.toml", absent, "")
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware-screen"]',
        f'columns = ["{column}"]',
    )
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["kani (screen)"]',
        f'evidence = ["{label}"]',
    )
    tree.edit("scripts/check.sh", 'run "clippy (loud)"', row + 'run "clippy (loud)"')


def test_a_knob_no_crate_the_row_builds_reads_pins_nothing(tree, capsys):
    """The fifth hole of one family, and the twin of the `-p`/`--features` one.

    Measured on the real tree before the rule: `env FLASH_SIZE=16M cargo kani -p
    rsk-fido --harness reset_keeps_the_pin_gate` carried `SEC-FIDO-006A` ×
    `firmware-16mb` to `covered` at EXIT=0, on a package whose build script reads
    `AAGUID` and nothing else; one such row per column took 37 `covered` cells to
    102 over eight of the ten knob-bearing columns, still at EXIT=0. The row here
    is the same shape — `rsk-screen` has no build script and no dependency with
    one, so `BOARD` reaches nothing it compiles.
    """
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani -p rsk-screen'
        " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    said = red(tree, capsys)
    assert "`kani (board-a)` sets ['BOARD'] in an `env` prefix" in said
    assert "no package it builds reads it" in said


def test_a_knob_a_dependency_reads_at_compile_time_still_pins_it(tree):
    """The green direction, and the two admitting clauses it is the arm for.

    `rsk-core` is a dependency `-p firmware` never names and it reads `BOARD` —
    with `env!` rather than in a build script, so this one case falls if `builds`
    stops walking dependencies OR if `ENV_READ` stops reading the macro. The
    shape is the real tree's: `rsk-fido`'s build script reads `AAGUID` on every
    `-p firmware`, and a rule that looked only at the named packages would refuse
    an honest row.
    """
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani -p firmware -p rsk-screen'
        " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


def test_a_knob_the_named_package_reads_in_its_build_script_pins_it(tree):
    """And the other spelling, which is how this tree reads all five of its own:
    `firmware`'s build script and `env::var`, on the package the row names."""
    a_covered_cell_on(
        tree,
        "firmware-pinned",
        '"firmware-pinned", ',
        'run "kani (pinned)" env VIDPID=Pico cargo kani -p firmware -p rsk-screen'
        " --harness shown_holds_on_every_build\n",
        "kani (pinned)",
    )
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


# --- the other three spellings of "which packages does this row build" ---------


@pytest.mark.parametrize("flag", ["--manifest-path", "--manifest-path="])
def test_a_manifest_path_row_is_read_as_the_crate_it_names(tree, capsys, flag):
    """The same hole as above, one spelling over, and it survived the fix for it.

    Both operand forms, because `--package=x` selecting for one guard and not the
    other is the drift `gate_lines` was written for, and an `=` is how it started.

    Driven on the real tree with `-p` the only spelling read: `env
    FLASH_SIZE=16M cargo kani --manifest-path crates/rsk-fido/Cargo.toml
    --harness reset_keeps_the_pin_gate` walked past the knob rule — no `-p`, so
    `builds` took the whole workspace, in which `firmware` reads every knob — and
    the cell was then refused for naming no owner crate, which is a different
    sentence and only accidentally true. `scripts/check.sh` writes this flag
    twenty times, fifteen of them on a row.
    """
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani '
        f"{flag} crates/rsk-screen/Cargo.toml".replace("= ", "=")
        + " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    said = red(tree, capsys)
    assert "`kani (board-a)` sets ['BOARD'] in an `env` prefix" in said
    assert "no package it builds reads it" in said
    assert "no row named here selects" not in said, (
        "the knob rule is what this row breaks; the owner rule catching it instead"
        " is the accident that hid the hole"
    )


def test_a_manifest_path_names_the_owner_crate_too(tree):
    """The green direction of the same widening, and the reason it has to be one
    answer: this row selects `rsk-screen` by its manifest and `firmware` by name,
    so the knob is read and the property's owner is compiled. Read `-p` alone and
    the cell is refused for selecting no owner — a false alarm on an honest row.
    """
    a_covered_cell_on(
        tree,
        "firmware-pinned",
        '"firmware-pinned", ',
        'run "kani (pinned)" env VIDPID=Pico cargo kani -p firmware'
        " --manifest-path crates/rsk-screen/Cargo.toml"
        " --harness shown_holds_on_every_build\n",
        "kani (pinned)",
    )
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


def test_an_exclude_narrows_what_the_row_builds(tree, capsys):
    """`--workspace --exclude a --exclude b` is the host rows' own spelling, and
    it selects the tree LESS those names. Read as "no selection", it read as the
    whole workspace instead — the permissive direction, and the one the commit
    that closed the `-p` spelling recorded as standing looseness."""
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani --workspace'
        " --exclude firmware --exclude rsk-core"
        " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    said = red(tree, capsys)
    assert "`kani (board-a)` sets ['BOARD'] in an `env` prefix" in said
    assert "no package it builds reads it" in said


def test_an_exclude_that_keeps_the_reader_still_pins_the_knob(tree):
    """And its green arm, which is what stops the rule above from being a ban on
    the flag: `rsk-core` reads `BOARD` and this row still compiles it, because
    excluding a crate from `--workspace` does not remove it from the unit graph
    of one that depends on it."""
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani --workspace'
        " --exclude rsk-core"
        " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    matrix_gate.run(tree.root, write=True)
    assert tree.run() == 0


def test_a_generated_package_operand_is_refused_rather_than_guessed(tree, capsys):
    """`-p "$c"` names a crate no reader here can resolve. Both guesses are
    wrong: "selects nothing" makes it the whole workspace and every knob reads,
    "selects nothing at all" refuses an honest row for the wrong reason."""
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani -p "$crate"'
        " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    said = red(tree, capsys)
    assert "selects its packages with [\'-p \"$crate\"\']" in said
    assert "may not rest on a selection nobody can read" in said


def test_a_manifest_outside_the_workspace_is_refused(tree, capsys):
    """The other unresolvable spelling, and the one this checkout really writes:
    `tools/emu/Cargo.toml` is a workspace of its own, so which members it
    compiles is not a question this file's manifest map can answer."""
    a_covered_cell_on(
        tree,
        "board-a",
        ', "board-a"',
        'run "kani (board-a)" env BOARD=board-a cargo kani'
        " --manifest-path tools/emu/Cargo.toml"
        " --harness shown_holds_on_every_build\n",
        "kani (board-a)",
    )
    said = red(tree, capsys)
    assert "--manifest-path tools/emu/Cargo.toml" in said
    assert "names no `[workspace] member` this gate can resolve" in said


# --- the two spellings of a READ, held to each other ---------------------------


def test_a_read_this_gate_cannot_lex_is_named_rather_than_blamed_on_the_row(tree, capsys):
    """The false negative the union closes, driven on the real tree first.

    Rewrite `firmware/build.rs`'s `env::var("FLASH_SIZE")` as the equally valid
    `use std::env::var; var("FLASH_SIZE")` and `ENV_READ` loses the knob — so a
    row that really does build `firmware` at `FLASH_SIZE=16M` was told no package
    it builds reads it, which is false. A false negative on an honest row is
    worse than the hole it closes, so the repair is not a longer regex: the row
    stays green and the SPELLING is refused, at the site, by name.
    """
    tree.edit(
        "firmware/build.rs",
        'std::env::var("VIDPID")',
        'std::env::var_os("VIDPID").map(|v| v.into_string().unwrap())'.replace(
            "var_os", "vaross"
        ),
    )
    said = red(tree, capsys)
    assert "declares `cargo:rerun-if-env-changed=VIDPID`" in said
    assert "no `env::var(\"VIDPID\")` in `firmware` that this gate can read" in said


def test_a_knob_read_only_in_a_spelling_this_gate_cannot_lex_still_pins_it(tree):
    """The half that makes the case above a repair rather than a second alarm.

    The same rewrite, and the `covered` cell resting on a row that pins `VIDPID`
    keeps its knob: the union is what the row is judged against, and the one
    finding names the spelling instead of accusing the row.
    """
    a_covered_cell_on(
        tree,
        "firmware-pinned",
        '"firmware-pinned", ',
        'run "kani (pinned)" env VIDPID=Pico cargo kani -p firmware -p rsk-screen'
        " --harness shown_holds_on_every_build\n",
        "kani (pinned)",
    )
    matrix_gate.run(tree.root, write=True)
    tree.edit("firmware/build.rs", 'std::env::var("VIDPID")', 'vaross("VIDPID")')
    problems = matrix_gate.audit(tree.root)[0]
    assert [p for p in problems if "rerun-if-env-changed" in p]
    assert not [p for p in problems if "`kani (pinned)` sets" in p], (
        "the row pins VIDPID and the gate lost only the spelling of the read"
    )


def test_a_rerun_declared_for_a_knob_nothing_reads_is_refused(tree, capsys):
    """And the direction that stops the union being a way to claim a reader: a
    package could otherwise pin any knob with one dead `println!`."""
    tree.edit(
        "firmware/build.rs",
        'println!("cargo:rerun-if-env-changed=VIDPID");',
        'println!("cargo:rerun-if-env-changed=VIDPID");\n'
        '    println!("cargo:rerun-if-env-changed=KVMAIN");',
    )
    assert "declares `cargo:rerun-if-env-changed=KVMAIN`" in red(tree, capsys)
