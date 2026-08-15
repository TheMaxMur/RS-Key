# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `assurance_gate.py` is verified against.

The gate came back green on the real tree on its first run, which in this tree
is not a compliment — it is the opening of the question "can it go red at
all?". Every check the gate makes is broken here once, on a fixture, and the
break must be the finding it claims to be. The green fixture and the real tree
close the other direction: a guard that cannot go green is deleted as fast as
one that cannot go red.
"""

import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import assurance_gate

PROPERTIES = """\
[[property]]
id = "SEC-T-001"
name = "FooStaysClosed"
status = "BOUNDED"
statement = "Foo stays closed."
source = ["spec"]

[[property]]
id = "SEC-T-002"
name = "BarNeverOpens"
status = "MODELLED-ONLY"
statement = "Bar never opens."
source = ["spec"]

[[property]]
id = "SEC-R-001"
name = "RuledAwayRisk"
status = "ACCEPTED-RISK"
statement = "A ruled-away risk."
source = ["spec"]
ruling = "maintainer said so, dated"
"""

CRATES = """\
[crate.rsk-a]
class = "state-modelled"
model = "Mini"

[crate.rsk-b]
class = "pure"
evidence = ["crates/rsk-b/src/kani.rs"]
"""

TIERS = """\
#!/usr/bin/env bash
if [ "${1:-}" = "--tiers" ]; then
  echo "safety: Shipped.cfg Solo_BugFooOpens.cfg"
  echo "liveness:"
  exit 0
fi
exit 3
"""


def build(root: pathlib.Path) -> pathlib.Path:
    formal = root / "formal"
    formal.mkdir(parents=True)
    (formal / "Mini.tla").write_text(
        "FooStaysClosed == foo = FALSE\nBarNeverOpens == bar = FALSE\n"
    )
    (formal / "Shipped.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooStaysClosed\n    BarNeverOpens\n"
    )
    (formal / "Solo_BugFooOpens.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooStaysClosed\n"
    )
    # The gate's exemption list is global state, and its stale-exemption arm
    # fires on any tree without this file — which the first fixture proved by
    # going red on it. The file is deliberately in no tier: that is what the
    # exemption asserts.
    (formal / "Liveness_Full.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooStaysClosed\n"
    )
    runner = formal / "run-tlc.sh"
    runner.write_text(TIERS)
    runner.chmod(0o755)

    (root / "assurance").mkdir()
    (root / "assurance" / "properties.toml").write_text(PROPERTIES)
    (root / "assurance" / "crates.toml").write_text(CRATES)
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/rsk-a", "crates/rsk-b"]\n'
    )

    a = root / "crates" / "rsk-a" / "src"
    a.mkdir(parents=True)
    (a / "lib.rs").write_text("// FooStaysClosed is owned here\n")
    (a / "state_kani.rs").write_text("fn foo_stays_closed() {}\n")
    b = root / "crates" / "rsk-b" / "src"
    b.mkdir(parents=True)
    (b / "kani.rs").write_text("fn roundtrip() {}\n")
    (root / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (root / "fuzz" / "fuzz_targets" / "t.rs").write_text("// FooStaysClosed\n")
    (root / "tests").mkdir()
    (root / "tests" / "t.py").write_text("# nothing named here\n")
    return root


@pytest.fixture
def tree(tmp_path):
    return build(tmp_path)


def edit(path: pathlib.Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, f"fixture drift: {old!r} not in {path.name}"
    path.write_text(text.replace(old, new))


def red(tree, capsys, needle: str) -> None:
    assert assurance_gate.run(tree) == 1
    err = capsys.readouterr().err
    assert needle in err, f"expected {needle!r} in:\n{err}"


# ---- the direction that must stay open: green states pass -------------------


def test_green_fixture_passes(tree, capsys):
    assert assurance_gate.run(tree) == 0
    out = capsys.readouterr().out
    assert "assurance-gate: ok" in out
    assert "kani=1" in out  # the derivation saw foo_stays_closed


def test_real_tree_passes():
    r = subprocess.run(
        [sys.executable, str(pathlib.Path(assurance_gate.__file__))],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


# ---- the registry against the model, both ways ------------------------------


def test_checked_but_unregistered_fails(tree, capsys):
    edit(
        tree / "assurance" / "properties.toml",
        '[[property]]\nid = "SEC-T-002"',
        '[[property]]\nid = "SEC-T-002-GONE"',
    )
    # Removing the whole entry, not renaming: drop it by pointing the block at
    # a name nothing checks would trip a different finding. Rebuild the file.
    (tree / "assurance" / "properties.toml").write_text(
        PROPERTIES.replace(
            """[[property]]
id = "SEC-T-002"
name = "BarNeverOpens"
status = "MODELLED-ONLY"
statement = "Bar never opens."
source = ["spec"]

""",
            "",
        )
    )
    red(tree, capsys, "not in the registry: BarNeverOpens")


def test_registered_but_unchecked_fails(tree, capsys):
    with open(tree / "assurance" / "properties.toml", "a") as fh:
        fh.write(
            '\n[[property]]\nid = "SEC-T-009"\nname = "GhostInvariant"\n'
            'status = "MODELLED-ONLY"\nstatement = "x"\nsource = ["spec"]\n'
        )
    red(tree, capsys, "checked by no configuration: GhostInvariant")


def test_solo_cfg_at_unregistered_target_fails(tree, capsys):
    (tree / "formal" / "Solo_BugGhost.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    GhostInvariant\n"
    )
    edit(
        tree / "formal" / "run-tlc.sh",
        "Solo_BugFooOpens.cfg",
        "Solo_BugFooOpens.cfg Solo_BugGhost.cfg",
    )
    red(tree, capsys, "not in the registry: GhostInvariant")


# ---- the status must equal the evidence ceiling ------------------------------


def test_bounded_without_kani_fails(tree, capsys):
    (tree / "crates" / "rsk-a" / "src" / "state_kani.rs").write_text("\n")
    red(tree, capsys, "BOUNDED with no Kani harness")


def test_understated_status_fails(tree, capsys):
    edit(
        tree / "assurance" / "properties.toml",
        'name = "FooStaysClosed"\nstatus = "BOUNDED"',
        'name = "FooStaysClosed"\nstatus = "MODELLED-ONLY"',
    )
    red(tree, capsys, "status must be BOUNDED")


def test_proven_is_refused(tree, capsys):
    edit(
        tree / "assurance" / "properties.toml",
        'name = "BarNeverOpens"\nstatus = "MODELLED-ONLY"',
        'name = "BarNeverOpens"\nstatus = "PROVEN"',
    )
    red(tree, capsys, "refused until")


def test_risk_without_ruling_fails(tree, capsys):
    edit(tree / "assurance" / "properties.toml", 'ruling = "maintainer said so, dated"', "")
    red(tree, capsys, "ACCEPTED-RISK without a ruling")


def test_risk_that_is_actually_checked_fails(tree, capsys):
    edit(
        tree / "formal" / "Shipped.cfg",
        "    BarNeverOpens\n",
        "    BarNeverOpens\n    RuledAwayRisk\n",
    )
    red(tree, capsys, "a checked invariant is not a ruling")


def test_entry_without_tla_definition_fails(tree, capsys):
    edit(tree / "formal" / "Mini.tla", "BarNeverOpens == bar = FALSE\n", "")
    red(tree, capsys, "no definition in any formal/*.tla")


# ---- every cfg runs somewhere ------------------------------------------------


def test_cfg_outside_every_tier_fails(tree, capsys):
    (tree / "formal" / "Mut_BugNobodyRunsMe.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooStaysClosed\n"
    )
    red(tree, capsys, "in no tier of run-tlc.sh and not exempt")


def test_tier_naming_a_missing_file_fails(tree, capsys):
    edit(
        tree / "formal" / "run-tlc.sh",
        "Solo_BugFooOpens.cfg",
        "Solo_BugFooOpens.cfg Vanished.cfg",
    )
    red(tree, capsys, "in a tier but no such file")


# ---- the crate ledger, both ways ----------------------------------------------


def test_member_missing_from_ledger_fails(tree, capsys):
    edit(
        tree / "Cargo.toml",
        '"crates/rsk-a", "crates/rsk-b"',
        '"crates/rsk-a", "crates/rsk-b", "crates/rsk-new"',
    )
    red(tree, capsys, "workspace member not in the crate ledger: rsk-new")


def test_stale_ledger_entry_fails(tree, capsys):
    edit(tree / "Cargo.toml", ', "crates/rsk-b"', "")
    red(tree, capsys, "ledgered but not a workspace member: rsk-b")


def test_pure_evidence_must_exist(tree, capsys):
    (tree / "crates" / "rsk-b" / "src" / "kani.rs").unlink()
    red(tree, capsys, "evidence file missing")


def test_partial_needs_a_gap(tree, capsys):
    edit(
        tree / "assurance" / "crates.toml",
        'class = "state-modelled"\nmodel = "Mini"',
        'class = "state-partial"\nmodel = "Mini"',
    )
    red(tree, capsys, "state-partial without a named gap")


def test_unknown_class_fails(tree, capsys):
    edit(tree / "assurance" / "crates.toml", 'class = "pure"', 'class = "vibes"')
    red(tree, capsys, "unknown class")


def test_model_must_be_a_real_module(tree, capsys):
    edit(tree / "assurance" / "crates.toml", 'model = "Mini"', 'model = "Atlantis"')
    red(tree, capsys, "no formal/ module")
