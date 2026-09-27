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

pytestmark = pytest.mark.assurance

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
  echo "safety: Shipped.cfg Seams.cfg Solo_BugFooOpens.cfg"
  echo "liveness:"
  exit 0
fi
exit 3
"""

#: `comutate.armed_subject` reads the companion pair out of the GENERATOR, so a
#: fixture without one has no pair and the two-armed control below could not be
#: told from the two-armed mutant. `BugFooLatch` is a reachability aid for
#: `BugFooOpens`, not a second defect — the one shape that keeps its credit.
GENERATOR = """\
companion_bug() {
  case "$1" in
    BugFooOpens) echo BugFooLatch ;;
  esac
}
"""


def git(root: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def build(root: pathlib.Path) -> pathlib.Path:
    formal = root / "formal"
    formal.mkdir(parents=True)
    (formal / "Mini.tla").write_text(
        "FooStaysClosed == foo = FALSE\nBarNeverOpens == bar = FALSE\n"
    )
    (formal / "Shipped.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooStaysClosed\n"
    )
    (formal / "Seams.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    BarNeverOpens\n"
    )
    # ARMED, and that is the point: the `mut` column is credited off the switch
    # this block sets, not off the filename. A fixture whose only solo-style
    # configuration armed nothing scored `mut = 0` on every row, so every case
    # below would have measured the same zero before and after its mutation.
    (formal / "Solo_BugFooOpens.cfg").write_text(
        "SPECIFICATION Spec\nCONSTANTS\n    BugFooOpens = TRUE\n"
        "INVARIANTS\n    TypeOK\n    FooStaysClosed\n"
    )
    (formal / "gen-configs.sh").write_text(GENERATOR)
    # The gate's exemption list is global state, and its stale-exemption arm
    # fires on any tree without this file — which the first fixture proved by
    # going red on it. The file is deliberately in no tier: that is what the
    # exemption asserts.
    (formal / "Liveness_Full.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    FooStaysClosed\n"
    )
    (formal / "TokenExport.cfg").write_text("SPECIFICATION Spec\n")
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
    (a / "lib.rs").write_text(
        "/// Refines `Mini!FooStaysClosed` — SEC-T-001.\n"
        "fn foo() {}\n"
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
        "fn bar() {}\n"
    )
    (a / "state_kani.rs").write_text("fn foo_stays_closed() {}\n")
    b = root / "crates" / "rsk-b" / "src"
    b.mkdir(parents=True)
    (b / "kani.rs").write_text("fn roundtrip() {}\n")
    (root / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (root / "fuzz" / "fuzz_targets" / "t.rs").write_text("// FooStaysClosed\n")
    (root / "tests").mkdir()
    (root / "tests" / "t.py").write_text("# nothing named here\n")
    table_findings = []
    rows = assurance_gate.check_properties(root, table_findings)
    assert not table_findings
    (formal / "README.md").write_text(
        "# Fixture\n\n"
        + assurance_gate.readme_block(rows, assurance_gate.crate_ledger(root))
        + "\n"
    )
    # A checkout, because the evidence rule is git's listing and not a `stat`:
    # that is what closes the case-fold and the directory in one mechanism. `add`
    # as well as `init` so the paths are `--cached` and not merely `--others`,
    # which a stray `core.excludesfile` could filter.
    git(root, "init", "-q")
    git(root, "add", "-A")
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
        "    FooStaysClosed\n",
        "    FooStaysClosed\n    RuledAwayRisk\n",
    )
    red(tree, capsys, "a checked invariant is not a ruling")


def test_entry_without_tla_definition_fails(tree, capsys):
    edit(tree / "formal" / "Mini.tla", "BarNeverOpens == bar = FALSE\n", "")
    red(tree, capsys, "no definition in any formal/*.tla")


# ---- tags in production Rust ---------------------------------------------------


def test_tag_with_ghost_module_fails(tree, capsys):
    edit(tree / "crates" / "rsk-a" / "src" / "lib.rs", "`Mini!", "`Atlantis!")
    red(tree, capsys, "no such formal/ module")


def test_tag_with_unregistered_id_fails(tree, capsys):
    edit(tree / "crates" / "rsk-a" / "src" / "lib.rs", "SEC-T-001", "SEC-T-666")
    red(tree, capsys, "id not in the registry")


def test_tag_pairing_mismatch_fails(tree, capsys):
    edit(
        tree / "crates" / "rsk-a" / "src" / "lib.rs",
        "`Mini!FooStaysClosed` — SEC-T-001",
        "`Mini!FooStaysClosed` — SEC-T-002",
    )
    red(tree, capsys, "mismatched pairing")


def test_bare_unregistered_id_fails(tree, capsys):
    with open(tree / "crates" / "rsk-a" / "src" / "lib.rs", "a") as fh:
        fh.write("// see SEC-T-777 for the story\n")
    red(tree, capsys, "SEC-T-777 is not in the registry")


def test_owner_config_invariant_without_a_tag_fails(tree, capsys):
    edit(
        tree / "crates" / "rsk-a" / "src" / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        "",
    )
    red(tree, capsys, "checked by Seams.cfg but has no Refines tag")


def test_tag_must_name_the_module_that_defines_the_property(tree, capsys):
    (tree / "formal" / "Other.tla").write_text("OtherThing == TRUE\n")
    edit(
        tree / "crates" / "rsk-a" / "src" / "lib.rs",
        "`Mini!FooStaysClosed`",
        "`Other!FooStaysClosed`",
    )
    red(tree, capsys, "is defined by Mini, not Other")


def test_firmware_tag_counts_as_a_production_owner(tree, capsys):
    edit(
        tree / "crates" / "rsk-a" / "src" / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        "",
    )
    firmware = tree / "firmware" / "src"
    firmware.mkdir(parents=True)
    (firmware / "main.rs").write_text(
        "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_cross_model_support_is_generated_and_validated(tree):
    (tree / "formal" / "Helper.tla").write_text(
        "\\* Supports `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    findings = []
    rows = assurance_gate.check_properties(tree, findings)
    assert not findings
    row = next(row for row in rows if row["e"]["name"] == "BarNeverOpens")
    assert row["support"] == ["Helper"]


def test_cross_model_support_pairing_mismatch_fails(tree, capsys):
    (tree / "formal" / "Helper.tla").write_text(
        "\\* Supports `Mini!BarNeverOpens` — SEC-T-001.\n"
    )
    red(tree, capsys, "mismatched pairing")


# ---- the README table is generated, never hand-maintained ------------------


def test_stale_readme_table_fails(tree, capsys):
    edit(tree / "formal" / "README.md", "| `SEC-T-001`", "| `SEC-T-STALE`")
    red(tree, capsys, "traceability table is stale")


def test_write_readme_repairs_the_generated_block(tree, capsys):
    edit(tree / "formal" / "README.md", "| `SEC-T-001`", "| `SEC-T-STALE`")
    assert assurance_gate.write_readme(tree) == 0
    capsys.readouterr()
    assert assurance_gate.run(tree) == 0


def test_stale_generated_crate_ledger_fails(tree, capsys):
    edit(tree / "formal" / "README.md", "| `rsk-a` |", "| `rsk-stale` |")
    red(tree, capsys, "traceability table is stale")


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


# ---- what a `pure` row's evidence must BE, one arm per clause ----------------
#
# Measured on the real tree before the rule, following the message the gate
# itself prints when the ledger moves (`--write-readme`): `rsk-led` with
# `evidence = ["README.md"]` was EXIT 0, `["README.MD"]` was EXIT 0, and
# `["crates/rsk-led/src/kani.rs", "README.md"]` — the obvious move, appending a
# page to a row that already cites a real artifact — was EXIT 0. Only `["docs"]`
# reddened, because `.is_file()` is false for a directory: this gate was already
# stricter than `platform_gate` there, and not on case.
#
# Every case drives `assurance_gate.run` on the fixture, which is the gate row's
# own entry point, and none of them patches a floor.


def add(tree: pathlib.Path, rel: str, text: str) -> None:
    """Write a file INTO the fixture checkout — git's listing is what decides."""
    path = tree / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    git(tree, "add", "-A")


def pure_evidence(tree: pathlib.Path, value: str) -> None:
    """Point `rsk-b`'s evidence at `value` and republish the generated table.

    The republish is not a nicety: [`crate_ledger_table`] prints each row's
    evidence, so an edit left unpublished reddens as a STALE TABLE, which is
    exit 1 for the WRONG reason — the first reproduction of this hole measured
    exactly that and read it as the rule working. `write_readme` refuses an
    invalid tree, so a case with a real finding keeps the stale line as well;
    the assertions below name the evidence finding rather than counting them.
    """
    edit(
        tree / "assurance" / "crates.toml",
        'evidence = ["crates/rsk-b/src/kani.rs"]',
        f'evidence = [{value}]',
    )
    assurance_gate.write_readme(tree)


def test_a_hand_written_page_does_not_settle_a_pure_row(tree, capsys):
    """The headline: the file the rule exists to refuse, in the tree and named.

    NOT an arm, and the needle says so by naming the path rather than a clause —
    a root `README.md` trips the suffix and the home clause both, so deleting
    either one leaves it refused. The arms are the three cases below, each
    constructed to be accepted by every clause but its own."""
    add(tree, "README.md", "# Fixture\n\nProse about the crate.\n")
    pure_evidence(tree, '"README.md"')
    red(tree, capsys, "evidence 'README.md' is")


def test_appending_a_page_to_real_evidence_is_refused(tree, capsys):
    """EVERY path, not one of them. `platform_gate` records this as the
    reviewer's obvious move, and a rule reading "at least one artifact" is exit 0
    on it — the row keeps its proof and gains a paragraph that settles nothing.
    Like the case above it this is a shape, not an arm."""
    add(tree, "README.md", "# Fixture\n\nProse about the crate.\n")
    pure_evidence(tree, '"crates/rsk-b/src/kani.rs", "README.md"')
    red(tree, capsys, "evidence 'README.md' is")


def test_a_page_inside_the_crate_is_still_a_page(tree, capsys):
    """ARM for [`EVIDENCE_SUFFIX`], and it must be a path the OTHER two clauses
    accept or it proves nothing: this page is git's own spelling and sits in
    `rsk-b`'s own `src/`, so only the suffix refuses it. Deleting that clause
    alone puts this construction — a crate's notes filed as its proof — at exit
    0, which is `README.md` moved one directory in."""
    add(tree, "crates/rsk-b/src/notes.md", "# Notes\n\nThe roundtrip looks fine.\n")
    pure_evidence(tree, '"crates/rsk-b/src/notes.md"')
    red(tree, capsys, "'crates/rsk-b/src/notes.md' is not Rust source")


def test_a_miscased_evidence_path_is_not_in_the_tree(tree, capsys):
    """ARM for [`platform_gate.in_tree`], and the reason this gate borrows it
    rather than keeping `.is_file()`. The path is not created: APFS folds case,
    so `.is_file()` answers True for a file git lists as `kani.rs`, while the
    suffix clause folds too and the home clause matches the prefix — both accept
    it. Measured on this machine, `evidence = ["README.MD"]` on the real
    `rsk-led` row was exit 0 under `.is_file()`. git's listing is case-exact, so
    one message on both filesystems."""
    pure_evidence(tree, '"crates/rsk-b/src/KANI.RS"')
    red(tree, capsys, "evidence file missing: crates/rsk-b/src/KANI.RS")


def test_a_directory_is_not_an_evidence_file(tree, capsys):
    """Not a unique arm — `.is_file()` already refused this, which is where this
    gate was ahead of `platform_gate`. It is here so the git listing that
    replaced it did not give the directory back on the way past."""
    pure_evidence(tree, '"crates"')
    red(tree, capsys, "evidence file missing: crates")


def test_another_crates_source_settles_that_crate(tree, capsys):
    """ARM for [`evidence_homes`]. `crates/rsk-a/src/lib.rs` is git's own
    spelling and is Rust source, so both other clauses accept it — and it is
    `rsk-a`'s proof, not `rsk-b`'s. This is the relevance half `platform_gate`
    says outright it cannot check, reachable here only because a `pure` row's
    subject is a directory rather than a prose assumption."""
    pure_evidence(tree, '"crates/rsk-a/src/lib.rs"')
    red(tree, capsys, "'crates/rsk-a/src/lib.rs' is neither rsk-b's own source")


def test_a_fuzz_target_is_evidence_for_any_crate(tree, capsys):
    """CONTROL, and not a no-op: it is the only case that runs the SECOND arm of
    [`evidence_homes`], so deleting that arm turns this red. The allowance is
    deliberately loose — requiring the target to name the crate reddens
    `rsk-mldsa`'s two, which reach it through `rsk_crypto`'s re-export."""
    pure_evidence(tree, '"crates/rsk-b/src/kani.rs", "fuzz/fuzz_targets/t.rs"')
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_the_shipped_ledger_satisfies_the_rule():
    """CONTROL on the real tree — the direction this change must NOT fail in, and
    the answer to "which honest rows does it redden": none of the nine. The
    floors keep it from passing vacuously on an emptied ledger, and they are
    literals of this case rather than a knob the subject reads."""
    repo = pathlib.Path(__file__).resolve().parents[1]
    ledger = assurance_gate.crate_ledger(repo)
    pure = {n: e for n, e in ledger.items() if e.get("class") == "pure"}
    paths = [(n, p) for n, e in pure.items() for p in e.get("evidence", [])]
    for name, path in paths:
        assert str(path).lower().endswith(assurance_gate.EVIDENCE_SUFFIX), (name, path)
        assert str(path).startswith(assurance_gate.evidence_homes(name)), (name, path)
    assert len(pure) >= 9 and len(paths) >= 20


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


def test_a_driven_code_mutant_shows_as_evidence_the_status_ladder_cannot(tree):
    """The column exists because MODELLED-ONLY was reading as "nothing below the
    model" for the rows that carry a code twin driven against the real suite. How
    many that is belongs to `docs/assurance-vector.md`, which derives it."""
    root, _ = tree if isinstance(tree, tuple) else (tree, None)
    assurance_gate.co_refuted.cache_clear()
    assert assurance_gate.co_refuted(pathlib.Path(__file__).parents[1])["NoAuthWhenBlocked"] == [
        "BugUseWhenBlocked"
    ]


def test_a_comutant_that_is_not_a_driven_kill_is_not_evidence(tmp_path, monkeypatch):
    formal = tmp_path / "formal"
    formal.mkdir()
    (formal / "comutants.toml").write_text(
        '[comutant.BugX]\nstatus = "unreachable"\nexpect = "killed"\n', encoding="utf-8")
    assurance_gate.co_refuted.cache_clear()
    assert assurance_gate.co_refuted(tmp_path) == {}


def test_a_missing_comutants_file_is_no_evidence_rather_than_a_crash(tmp_path):
    assurance_gate.co_refuted.cache_clear()
    assert assurance_gate.co_refuted(tmp_path) == {}


def test_a_patch_the_suite_is_not_expected_to_catch_is_not_evidence(tmp_path):
    """Every entry in the tree today is `patch` + `killed`, so the second half of
    the filter is unfalsifiable against it — this poses the case that makes it
    bite. A patch nobody expects the suite to catch says nothing about the code."""
    formal = tmp_path / "formal"
    formal.mkdir()
    (formal / "comutants.toml").write_text(
        '[comutant.BugX]\nstatus = "patch"\nexpect = "survived"\n', encoding="utf-8")
    # …and a Solo configuration, so the invariant lookup resolves and the `expect`
    # filter is what decides. Without it the entry is dropped one step earlier and
    # the test passes for the wrong reason.
    (formal / "Solo_BugX.cfg").write_text(
        "SPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    SomeInvariant\n", encoding="utf-8")
    assurance_gate.co_refuted.cache_clear()
    assert assurance_gate.co_refuted(tmp_path) == {}


# ---- `mut` is credited by the CONSTANTS block, never by the filename ---------
#
# Measured before the rule, on a `git archive HEAD` copy of this tree:
# `StoreSolo_BugMetaWriteTearsBlob.cfg` stripped to `BugMetaWriteTearsBlob =
# FALSE` — a configuration arming NOTHING, so its run is the shipped model under
# another filename — left `SEC-STORE-003` at `mut=2`, the whole printed table
# byte-identical, and the `check.sh` "assurance registry" row at EXIT=0. After,
# the same strip reads `mut=1` and the row exits 1. Each case here mutates the
# fixture tree the audit is handed, so nothing is monkeypatched below the entry
# point, and `edit` refuses an anchor that did not resolve — a `str.replace`
# that matches nothing returns the string unchanged and the case then measures
# an unmutated fixture.


def solo_cfg(tree: pathlib.Path) -> pathlib.Path:
    return tree / "formal" / "Solo_BugFooOpens.cfg"


def test_a_configuration_that_arms_nothing_is_not_a_mutant(tree, capsys):
    edit(solo_cfg(tree), "BugFooOpens = TRUE", "BugFooOpens = FALSE")
    assert assurance_gate.solo_target_counts(tree / "formal") == {}
    red(tree, capsys, "traceability table is stale")


def test_a_configuration_arming_two_unrelated_defects_is_not_a_mutant(tree, capsys):
    """Two armed switches say which defect FIRED, not which property either
    breaks — the rule `armed_subject` carries, and the shape the control below
    holds it against."""
    edit(
        solo_cfg(tree),
        "    BugFooOpens = TRUE\n",
        "    BugFooOpens = TRUE\n    BugBarSlips = TRUE\n",
    )
    assert assurance_gate.solo_target_counts(tree / "formal") == {}
    red(tree, capsys, "traceability table is stale")


def test_a_companion_arm_keeps_the_credit(tree, capsys):
    """CONTROL — this one must stay GREEN, and it is the same SHAPE as the case
    above it: two armed switches, one credit or none. What separates them is the
    generator's companion pair, so the pair proves these cases measure the armed
    set and not the number of `= TRUE` lines."""
    edit(
        solo_cfg(tree),
        "    BugFooOpens = TRUE\n",
        "    BugFooOpens = TRUE\n    BugFooLatch = TRUE\n",
    )
    assert assurance_gate.solo_target_counts(tree / "formal") == {"FooStaysClosed": 1}
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_a_switch_spelled_neither_true_nor_false_credits_nothing(tree, capsys):
    """The direction an unreadable switch must fail in. `verdict_gate.Config`
    files the value under `unreadable` and leaves `armed` empty, so the count
    DROPS and the row reddens — the opposite reading would publish a mutant
    nothing arms, which is the defect one spelling mistake away."""
    edit(solo_cfg(tree), "BugFooOpens = TRUE", "BugFooOpens = TRUEISH")
    assert assurance_gate.solo_target_counts(tree / "formal") == {}
    red(tree, capsys, "traceability table is stale")


def test_the_shipped_tree_lost_no_credit_to_the_tightening():
    """CONTROL, on the real tree — the direction this change must NOT fail in.
    Reading the filename and reading the armed switch agree on every shipped
    configuration: 87 credits over 48 names, measured on both sides of the fix,
    so no published `mut` moved. The floor keeps the agreement from being
    vacuous, since an emptied prefix list would make both readings `{}`."""
    formal = pathlib.Path(__file__).resolve().parents[1] / "formal"
    by_name: dict[str, int] = {}
    for cfg in formal.glob("*.cfg"):
        if not cfg.name.startswith(assurance_gate.SOLO_CFG_PREFIXES):
            continue
        names = assurance_gate.cfg_checked(cfg)
        if len(names) == 1:
            by_name[names[0]] = by_name.get(names[0], 0) + 1
    assert assurance_gate.solo_target_counts(formal) == by_name
    assert sum(by_name.values()) >= 87 and len(by_name) >= 48


# --- the keys the property registry may carry ---------------------------------


def _properties(tree):
    return tree / "assurance" / "properties.toml"


def test_a_field_nobody_reads_is_refused(tree, capsys):
    """Measured before the rule: an invented key in the first `[[property]]` left
    this row at EXIT=0, so a field added to the property registry was held by
    nothing and shown to no reader."""
    path = _properties(tree)
    text = path.read_text()
    i = text.index("[[property]]\n") + len("[[property]]\n")
    path.write_text(text[:i] + 'nonsense_field_nobody_holds = "x"\n' + text[i:])
    red(tree, capsys, "which nothing reads")


def test_a_table_nobody_reads_is_refused(tree, capsys):
    """And a whole section, invisible in both directions before this."""
    path = _properties(tree)
    path.write_text(path.read_text() + '\n[[nonsense_table]]\nname = "x"\n')
    red(tree, capsys, "which nothing reads")


def test_the_allowlist_covers_every_key_the_shipped_registry_carries():
    """The direction an allowlist fails in, and the one the token-refinement gate
    was caught in: a list taken from the records that exist can be NARROWER than
    the contract, and then it refuses a legitimate field. Here the shipped file is
    the floor — if a record grows a key the gate reads, this says so before the
    row does."""
    import tomllib

    repo = pathlib.Path(__file__).resolve().parents[1]
    shipped = tomllib.loads(
        (repo / "assurance" / "properties.toml").read_text(encoding="utf-8")
    )
    assert set(shipped) <= set(assurance_gate.TABLES)
    for entry in shipped["property"]:
        assert set(entry) <= set(assurance_gate.PROPERTY_FIELDS), entry.get("id")


# ---- The production set is what SHIPS, not what is named `*_tests.rs` ---------
#
# The filename filter read a NAME. Six `*_assurance.rs` mirrors carry neither
# `kani` nor `tests` in theirs, and `store_assurance.rs` — `#[cfg(any(kani,
# test))]`, in no image anybody can build — stood as a production owner of four
# P0-launch store rows. Measured before the fix: `SEC-STORE-001` rust=3,
# `-002`/`-003`/`-004`/`-006` rust=2, `SEC-TRANS-003` rust=2; after, 1 each.

CFG_CASES = [
    # (cfg expression, is the module still production?)
    ("test", False),
    ("kani", False),
    ("any(kani, test)", False),
    ("all(test, feature = \"display\")", False),
    # A feature something outside `[dev-dependencies]` can turn on. The module
    # ships in that column of the matrix, so it is production there.
    ("feature = \"display\"", True),
    # The refutation that decides the free value: an optimistic TRUE for a free
    # feature makes `not(...)` FALSE, and `conformance/largeblobs.rs` — the
    # DEFAULT build's large-blob design — would have been dropped as unreachable.
    ("not(feature = \"largeblob-ext\")", True),
    # Asked for by thirteen crates and by every one of them under
    # `[dev-dependencies]`: on in `cargo test`, in no image.
    ("any(test, feature = \"test-util\", kani)", False),
    # One level out, and the reason the closure is ROOTED at firmware rather
    # than unioned over the workspace: `rsk-device`'s `security-trace` enables
    # `assurance-trace`, and only `tools/emu` enables `security-trace`.
    ("any(test, kani, feature = \"assurance-trace\")", False),
    # Unrecognised atoms stay free, because the direction that hides an owner
    # also reddens `check_property_tags` and the direction that keeps one does not.
    ("target_os = \"none\"", True),
    ("some_future_atom", True),
]


@pytest.mark.parametrize("expr,production", CFG_CASES)
def test_a_module_cfg_decides_whether_its_file_is_production(expr, production):
    repo = pathlib.Path(__file__).resolve().parents[1]
    held = assurance_gate._cfg_holds(expr, assurance_gate.shippable_features(repo))
    assert (held is not False) == production, (expr, held)


def test_the_dev_half_of_the_feature_graph_is_not_shippable():
    """`test-util` is a `[features]` KEY in three manifests, so a rule reading
    keys calls it shippable. What decides it is who turns it ON."""
    repo = pathlib.Path(__file__).resolve().parents[1]
    features = assurance_gate.shippable_features(repo)
    assert "test-util" not in features
    assert "assurance-trace" not in features
    assert "display" in features and "fips-profile" in features
    # The other direction: a feature no image can build with is not the same as
    # a feature nobody ships. `largeblob-ext` holds four `check.sh` rows and no
    # flake package, and it IS reachable from `firmware/Cargo.toml`.
    assert "largeblob-ext" in features and "no-touch" in features


def test_the_six_measured_mirrors_are_out_of_the_production_set():
    repo = pathlib.Path(__file__).resolve().parents[1]
    names = {f.name for f in assurance_gate.production_rust(repo)}
    for mirror in (
        "store_assurance.rs",
        "transport_assurance.rs",
        "powercut.rs",
        "reset_assurance.rs",
        "state_assurance.rs",
        "clientpin_assurance.rs",
    ):
        assert mirror not in names, mirror


def test_no_property_lost_its_last_production_owner():
    """The direction this change must NOT fail in. An owner column that drops to
    zero is an invariant with no code behind it, and `check_property_tags` says
    so — this asserts it on the shipped tree rather than waiting for the row."""
    import tomllib

    repo = pathlib.Path(__file__).resolve().parents[1]
    files = assurance_gate.production_rust(repo)
    registry = tomllib.loads(
        (repo / "assurance" / "properties.toml").read_text(encoding="utf-8")
    )
    owned = {
        entry["id"]
        for entry in registry["property"]
        if assurance_gate.grep_word(files, entry["name"])
    }
    for wanted in ("SEC-STORE-001", "SEC-STORE-006", "SEC-TRANS-003", "SEC-FIDO-007"):
        assert wanted in owned, wanted


def test_a_declaration_reached_through_a_path_attribute_is_found():
    """`#[path = "..."] mod x;` is how every `*_tests.rs` in this tree is hooked
    in, so a resolver reading only `<name>.rs` finds none of them."""
    repo = pathlib.Path(__file__).resolve().parents[1]
    excluded = assurance_gate.cfg_excluded(repo)
    names = {path.name for path in excluded}
    assert "store_assurance.rs" in names
    assert any(name.endswith("_kani.rs") for name in names)


def _mirror_tree(tree, gate: str) -> pathlib.Path:
    """Move `BarNeverOpens`'s only tag into a sub-tree declared under `gate`.

    The one variable between the two cases below is `gate`, so a red that came
    from a mis-parsed tag or a file the resolver never opened would take the
    green twin down with it. That twin is also the whole reason the red cannot
    be satisfied by the tag merely being GONE: nothing asserted here could say
    so, because `edit` proves the source line was there and the destination is
    written two lines above — this helper can only report on itself.
    """
    edit(
        tree / "crates" / "rsk-a" / "src" / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        f"{gate}mod conformance;\n",
    )
    home = tree / "crates" / "rsk-a" / "src" / "conformance"
    home.mkdir()
    (home / "mod.rs").write_text("mod wire;\n")
    (home / "wire.rs").write_text("// Refines `Mini!BarNeverOpens` — SEC-T-002.\n")
    return home / "wire.rs"


def _undeclared_leaf(tree, gate: str, decl: str, anchor: str, leaf: str) -> pathlib.Path:
    """The same move, onto a file NOTHING declares under the withheld module.

    Undeclared on purpose. A leaf its parent names is reached by the
    declaration closure as well, which then answers for both shapes below and
    the ancestor walk they aim at is never asked — the two mutants those cases
    exist to kill would both survive a fixture that declared its leaf.
    """
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        f"{gate}{decl}\n",
    )
    for rel in (anchor, leaf):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
    (src / anchor).write_text("// the withheld module itself; it declares nothing\n")
    (src / leaf).write_text("// Refines `Mini!BarNeverOpens` — SEC-T-002.\n")
    return src / leaf


def _declared_chain(tree, gate: str) -> pathlib.Path:
    """The same move onto a leaf a withheld file DECLARES, outside its sub-tree.

    `probe.rs` is what `gate` withholds, and it names `helpers/relay.rs` — a file
    no ancestor walk down from `probe/` can reach, because a `#[path]` leaf need
    not live under the module that declared it. Eleven files on the real tree
    have that shape, held out of the tag scan by the legacy `"tests" not in
    name` filter alone, which one leaf named `oracle.rs` walks straight past.

    Two links and not one, and `leaf.rs` sorts BEFORE `relay.rs`: a closure that
    propagates once rather than to a fixed point settles `relay.rs` and leaves
    the tag on `leaf.rs` in the production set. One link would score the same
    for both, and the pass order would be the filesystem's.
    """
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        f"{gate}mod probe;\n",
    )
    (src / "probe.rs").write_text('#[path = "helpers/relay.rs"]\nmod relay;\n')
    (src / "helpers").mkdir()
    (src / "helpers" / "relay.rs").write_text('#[path = "leaf.rs"]\nmod leaf;\n')
    (src / "helpers" / "leaf.rs").write_text(
        "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    return src / "helpers" / "leaf.rs"


#: Two directories under the withheld `mod.rs`, so a walk that reads only the
#: file's own parent stops one level short of the directory that is shut.
DEPTH2 = ("mod conformance;", "conformance/mod.rs", "conformance/deep/leaf.rs")

#: A `#[path]` re-point, so the sub-tree sits where the RESOLVED target is and
#: not where the declaring file plus the module's name would put it.
REPOINT = (
    '#[path = "elsewhere/entry.rs"]\nmod probe;',
    "elsewhere/entry.rs",
    "elsewhere/entry/leaf.rs",
)


def test_a_tag_under_a_withheld_mod_is_not_a_production_owner(tree, capsys):
    """The transitive half, and the shape it was measured in.

    `cfg_excluded` maps a withheld `mod` onto the ONE file it names, so a
    directory module shut by `#[cfg(test)] mod conformance;` kept every sibling
    below its `mod.rs` in the production set — eighteen of them on the real
    tree, under `crates/rsk-fido/src/conformance/`. Harmless only while none
    carries a tag, which is a condition a commit changes silently. Measured on a
    copy of the shipped tree: moving `SEC-FIDO-008`'s sole tag out of
    `clientpin.rs` and into `conformance/clientpin.rs` was EXIT=0, and the
    generated table went on publishing `Rust = 1` for an owner no image compiles.
    """
    _mirror_tree(tree, "#[cfg(test)]\n")
    red(tree, capsys, "checked by Seams.cfg but has no Refines tag")


def test_a_tag_under_a_shipped_mod_is_still_a_production_owner(tree, capsys):
    """The control the rule must be indifferent to: the same mirror, the same
    tag, one attribute fewer. A sub-tree no cfg withholds still owns its
    property, so the exclusion is not a blanket refusal of directories."""
    _mirror_tree(tree, "")
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_a_tag_two_directories_under_a_withheld_mod_is_not_an_owner(tree, capsys):
    """The ancestor walk is over every parent, not the immediate one. A rule
    reading `resolved.parent` shuts `conformance/` and keeps everything in
    `conformance/deep/`, which is the sub-tree it was pointed at."""
    _undeclared_leaf(tree, "#[cfg(test)]\n", *DEPTH2)
    red(tree, capsys, "checked by Seams.cfg but has no Refines tag")


def test_the_same_tag_two_directories_down_under_a_shipped_mod_owns(tree, capsys):
    """Its twin: depth is not what withholds a file, the `cfg` is."""
    _undeclared_leaf(tree, "", *DEPTH2)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_a_tag_under_a_repointed_withheld_mod_is_not_an_owner(tree, capsys):
    """The sub-tree follows the RESOLVED target. `#[path]` puts `mod probe;`'s
    children under `elsewhere/entry/`, and a home computed from the declaring
    file and the module's name names `probe/`, which holds nothing."""
    _undeclared_leaf(tree, "#[cfg(test)]\n", *REPOINT)
    red(tree, capsys, "checked by Seams.cfg but has no Refines tag")


def test_the_same_tag_under_a_repointed_shipped_mod_owns(tree, capsys):
    """Its twin: a `#[path]` re-point no cfg withholds still owns its property."""
    _undeclared_leaf(tree, "", *REPOINT)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_a_tag_a_withheld_file_declares_out_of_its_sub_tree_is_not_an_owner(
    tree, capsys
):
    """The residual the directory closure cannot see, driven on the real tree
    before it was closed: `#[path = "helpers/oracle.rs"] mod oracle;` inside
    `crates/rsk-led/src/tests.rs`, carrying `SEC-FIDO-008`'s only tag, was EXIT=0
    and the table went on publishing `Rust = 1` for a file no image compiles."""
    _declared_chain(tree, "#[cfg(test)]\n")
    red(tree, capsys, "checked by Seams.cfg but has no Refines tag")


def test_the_same_declared_leaf_under_a_shipped_mod_owns(tree, capsys):
    """Its twin: the leaf is not withheld by being named, but by every module
    that names it being withheld."""
    _declared_chain(tree, "")
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_a_leaf_one_shipped_module_still_declares_keeps_its_tag(tree, capsys):
    """The over-shut direction, which the census cannot show: a dropped owner
    and a correctly dropped mirror move the same column the same way.

    The same file can be `#[path]`-included from a shipped module and from a
    test — two modules, one file — so the rule is EVERY declarer withheld and
    not any. A closure asking whether some declarer is withheld drops this leaf
    and takes the shipped module's tag with it.
    """
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        "#[cfg(test)]\nmod probe;\nmod second;\n",
    )
    for name in ("probe", "second"):
        (src / f"{name}.rs").write_text('#[path = "helpers/oracle.rs"]\nmod oracle;\n')
    (src / "helpers").mkdir()
    (src / "helpers" / "oracle.rs").write_text(
        "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


# ---- what decides production is a cfg, never a spelling ---------------------


def only_owner_finding(tree, name: str) -> None:
    """The findings LIST, not a needle in stderr and not a line count.

    `red` above is satisfied by a run carrying any number of other findings, and
    every case below turns exactly one thing off. What the list has to tolerate
    is measured rather than guessed: an owner that loses its last production file
    takes the `rust` column from 1 to 0, so the generated table goes stale in the
    same breath and the honest count for these cases is TWO. An oracle demanding
    one finding would fail on the defect it is written for; an oracle reading
    only the needle would pass on a tree that was already red for other reasons.
    """
    findings, _, _ = assurance_gate.audit(tree)
    owner = f"{name}: checked by Seams.cfg but has no Refines tag in production Rust"
    stale = "formal/README.md traceability table is stale"
    assert owner in findings, findings
    assert [f for f in findings if not f.startswith(stale)] == [owner], findings


def _sub_directory_leaf(tree, gate: str) -> pathlib.Path:
    """Move the tag into `screen/helper.rs`, declared from `screen.rs`.

    The shape `crates/rsk-ui/src/render.rs` has and nothing else in the tree
    does: a declaring file that is neither a crate root nor a `mod.rs`, so a
    plain `mod helper;` inside it resolves under `screen/` and NOT beside it. A
    resolver missing that looks for `src/helper.rs`, finds nothing, and drops the
    declaration unrecorded — which leaves the leaf production whatever `gate`
    says, and left eleven real `crates/rsk-ui/src/render/` files with no recorded
    declarer at all.
    """
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        "mod screen;\n",
    )
    (src / "screen.rs").write_text(f"{gate}mod helper;\n")
    (src / "screen").mkdir()
    (src / "screen" / "helper.rs").write_text(
        "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    return src / "screen" / "helper.rs"


def test_a_tag_under_a_withheld_mod_of_a_sub_directory_module_is_not_an_owner(tree):
    """A test file classified as production, in the one shape the tree has.

    `helper.rs` is compiled by no image — `screen.rs` names it under
    `#[cfg(test)]` — and before [`_child_home`] the gate could not resolve the
    declaration at all, so the leaf stood as `BarNeverOpens`'s production owner
    at EXIT=0. Neither half of the deleted name filter reaches it: it is spelled
    `helper.rs`.
    """
    leaf = _sub_directory_leaf(tree, "#[cfg(test)]\n")
    assert leaf.resolve() in assurance_gate.cfg_excluded(tree)
    only_owner_finding(tree, "BarNeverOpens")


def test_the_same_sub_directory_leaf_under_a_shipped_mod_owns(tree, capsys):
    """Its twin, and the one variable is the attribute. A sub-directory module
    no cfg withholds is production, so the rule is not a refusal of `foo/`."""
    leaf = _sub_directory_leaf(tree, "")
    assert leaf.resolve() not in assurance_gate.cfg_excluded(tree)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def _self_gated_leaf(tree, prologue: str) -> pathlib.Path:
    """The same move onto a plainly-declared file that withholds ITSELF.

    Nothing about the declaration says `mirror.rs` is a mirror — `lib.rs` names
    it the way it names any module. The `#![cfg(test)]` in its own prologue is
    the whole difference, and it is the `*_assurance.rs` defect with the gate
    written on the other side of the file.
    """
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        "mod mirror;\n",
    )
    (src / "mirror.rs").write_text(
        f"{prologue}// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    return src / "mirror.rs"


def test_a_tag_in_a_file_its_own_prologue_withholds_is_not_an_owner(tree):
    """The last way in, and the only one no declaration can express."""
    leaf = _self_gated_leaf(tree, "#![cfg(test)]\n")
    assert leaf.resolve() in assurance_gate.cfg_excluded(tree)
    only_owner_finding(tree, "BarNeverOpens")


def test_a_prologue_cfg_a_shipped_image_can_set_keeps_the_file(tree, capsys):
    """Its twin, and it is deliberately not the empty one: an inner attribute of
    exactly the same shape over an expression that is satisfiable. A rule reading
    `#![cfg` and not the expression drops this file too."""
    leaf = _self_gated_leaf(tree, '#![cfg(target_os = "none")]\n')
    assert leaf.resolve() not in assurance_gate.cfg_excluded(tree)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_a_cfg_attribute_inside_the_file_body_does_not_withhold_it(tree, capsys):
    """The over-shut direction of the prologue rule. `mod inner { #![cfg(test)]
    … }` withholds that block and not the file, so the scan stops at the first
    item; a whole-text search reads this as a mirror and drops a shipped owner.
    """
    leaf = _self_gated_leaf(tree, "")
    leaf.write_text(
        "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
        "fn bar() {}\n"
        "mod inner {\n    #![cfg(test)]\n}\n"
    )
    assert leaf.resolve() not in assurance_gate.cfg_excluded(tree)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


#: Two production spellings the deleted `"kani" not in name and "tests" not in
#: name` filter withheld, and one is not hypothetical: `attests.rs` carries the
#: letters `tests` and is what an attestation module would plausibly be called.
SPELLED_LIKE_TESTS = ("attests", "kani_stubs")


@pytest.mark.parametrize("stem", SPELLED_LIKE_TESTS)
def test_a_production_file_spelled_like_a_test_still_owns_its_tag(tree, capsys, stem):
    """A production file classified as test, which is the direction a name
    filter fails in and the reason it is gone.

    Under the filter this was red — and red with the finding for a MISSING
    owner, printed over a file every image compiles, which is the worst message
    the gate has: it sends the reader to look for code that is already there.
    """
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        f"mod {stem};\n",
    )
    (src / f"{stem}.rs").write_text("// Refines `Mini!BarNeverOpens` — SEC-T-002.\n")
    assert (src / f"{stem}.rs").resolve() not in assurance_gate.cfg_excluded(tree)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


@pytest.mark.parametrize("stem", SPELLED_LIKE_TESTS)
def test_the_same_spelling_under_a_withheld_mod_is_not_an_owner(tree, stem):
    """Its twin, and the pair is what makes the green above an assertion rather
    than the absence of one: the SAME name goes both colours, so what moved is
    the attribute and nothing else."""
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        f"#[cfg(test)]\nmod {stem};\n",
    )
    (src / f"{stem}.rs").write_text("// Refines `Mini!BarNeverOpens` — SEC-T-002.\n")
    only_owner_finding(tree, "BarNeverOpens")


def test_the_shipped_tree_holds_no_file_the_name_filter_would_have_decided():
    """The census the deletion rests on, asserted rather than remembered.

    Every `.rs` whose name carries `kani` or `tests` is withheld by a cfg on the
    real tree, so the filter decided zero files: `production_rust` was 182 with
    it and 182 without, the same list both ways. Asserted as the PROPERTY and not
    as the count — a hard 182 goes red on the next file anyone adds, which is a
    reminder to edit a number rather than a statement about the classifier.
    """
    repo = pathlib.Path(__file__).resolve().parents[1]
    production = assurance_gate.production_rust(repo)
    assert production, "the classifier returned nothing at all"
    assert not [f for f in production if "kani" in f.name or "tests" in f.name]


# ---- the declaration is read by a scanner, so a spelling cannot hide it ------


#: Every spelling of "this module is test-only" that the line-oriented regex
#: standing here answered "production" to. Each is legal Rust `rustc 1.96` does
#: not compile into a non-test build, checked by putting a `compile_error!` in
#: the leaf rather than by reasoning about the grammar; and each pairs with a
#: twin below whose ONLY difference is one cfg ATOM, so the last attribute, the
#: comment, the block and the `pub(crate)` are identical across the pair and a
#: resolver that reads any of them instead of the cfg cannot tell them apart.
#: `target_os = "none"` and `some_future_atom` are the free atoms — satisfiable,
#: so they keep a file — and `test` is the one that withholds it.
WITHHELD, KEPT = "test", "some_future_atom"
SPELLINGS = {
    "a second cfg attribute stacked under the first": (
        '#[cfg({cfg})]\n#[cfg(target_os = "none")]\nmod helper;\n',
        "helper.rs",
    ),
    "the attribute on the mod line": ("#[cfg({cfg})] mod helper;\n", "helper.rs"),
    "an attribute broken over three lines": (
        "#[cfg(\n    {cfg}\n)]\nmod helper;\n",
        "helper.rs",
    ),
    "a comment after the closing bracket": (
        "#[cfg({cfg})] // why it is gated\nmod helper;\n",
        "helper.rs",
    ),
    "a doc comment between the attribute and the mod": (
        "#[cfg({cfg})]\n/// the helper\nmod helper;\n",
        "helper.rs",
    ),
    "a bracket inside the attribute beside it": (
        "#[cfg({cfg})]\n#[cfg_attr(test, deny[warnings])]\nmod helper;\n",
        "helper.rs",
    ),
    "a pub(crate) between the attribute and the mod": (
        "#[cfg({cfg})]\npub(crate) mod helper;\n",
        "helper.rs",
    ),
    "a cfg_attr that sets the cfg": (
        "#[cfg_attr(all(), cfg({cfg}))]\nmod helper;\n",
        "helper.rs",
    ),
    "an enclosing inline block": (
        "#[cfg({cfg})]\nmod inner {{\n    mod helper;\n}}\n",
        "inner/helper.rs",
    ),
    "a path attribute inside an inline block": (
        '#[cfg({cfg})]\nmod inner {{\n    #[path = "helper.rs"]\n    mod helper;\n}}\n',
        "inner/helper.rs",
    ),
    "a block comment above the prologue": (
        "mod helper;\n",
        "helper.rs//* the mirror */\n#![cfg({cfg})]\n",
    ),
    "a comment after the prologue": (
        "mod helper;\n",
        "helper.rs//#![cfg({cfg})] // mirror only\n",
    ),
    "a second prologue attribute stacked under the first": (
        "mod helper;\n",
        'helper.rs//#![cfg({cfg})]\n#![cfg(target_os = "none")]\n',
    ),
    # Both orders, because the two readings fail in opposite ones: a rule taking
    # the LAST attribute is wrong above, a rule taking the FIRST is wrong here,
    # and either pair alone leaves half the AND unfalsified.
    "a prologue attribute stacked above the cfg": (
        "mod helper;\n",
        'helper.rs//#![cfg(target_os = "none")]\n#![cfg({cfg})]\n',
    ),
}


def _spelled_leaf(tree, spelling: str, cfg: str) -> pathlib.Path:
    """Move `BarNeverOpens`'s only tag into a leaf declared as `spelling` says.

    `where` doubles as the prologue carrier: everything after the `//` is what
    the leaf says about ITSELF, which is the half no declaration can express.
    """
    declaration, where = SPELLINGS[spelling]
    src = tree / "crates" / "rsk-a" / "src"
    edit(
        src / "lib.rs",
        "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n",
        declaration.format(cfg=cfg),
    )
    leaf, _, prologue = where.partition("//")
    path = src / leaf
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        prologue.format(cfg=cfg) + "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
    )
    return path


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_legal_spelling_of_cfg_test_still_withholds_the_leaf(tree, spelling):
    """A test file classified as production, once per spelling.

    Measured on the shipped tree before this scanner: writing all 187
    cfg-carrying declarations on one line each — the shape a formatter rejoins
    and nothing else objects to — took `production_rust` from 182 to 394, every
    `.rs` in the tree, and the row printed no finding at all.
    """
    leaf = _spelled_leaf(tree, spelling, WITHHELD)
    assert leaf.resolve() in assurance_gate.cfg_excluded(tree), spelling
    only_owner_finding(tree, "BarNeverOpens")


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_the_same_spelling_over_a_satisfiable_cfg_keeps_the_leaf(tree, capsys, spelling):
    """Its twin. What moved is one cfg atom and nothing else, so a green here
    with a red above says the scanner read the CFG — not the punctuation."""
    leaf = _spelled_leaf(tree, spelling, KEPT)
    assert leaf.resolve() not in assurance_gate.cfg_excluded(tree), spelling
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


TAG_LINE = "/// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"
TAGGED = "// Refines `Mini!BarNeverOpens` — SEC-T-002.\n"


def _rewrite(tree, declaration: str) -> pathlib.Path:
    """Spend `BarNeverOpens`'s only tag on `declaration` and hand back `src`."""
    src = tree / "crates" / "rsk-a" / "src"
    edit(src / "lib.rs", TAG_LINE, declaration)
    return src


def test_a_string_holding_a_comment_opener_does_not_swallow_what_follows(tree):
    """The scan skips literals, and this is what it costs not to.

    A `"/*"` in a shipped constant opens a block comment that never closes, and
    everything after it — the `#[cfg(test)]`, the `mod`, the tag — is read as
    prose. The leaf then has no declarer at all and stands as the owner, which
    is the silent direction: no finding, and a mirror in the `rust` column.
    """
    src = _rewrite(tree, 'const PROBE: &str = "/*";\n#[cfg(test)]\nmod helper;\n')
    (src / "helper.rs").write_text(TAGGED)
    only_owner_finding(tree, "BarNeverOpens")


def test_a_brace_inside_a_string_does_not_extend_the_block_around_it(tree):
    """The structural half of the same clause: braces inside a literal.

    An unbalanced `{` in a shipped constant leaves the inline block above it
    open for the rest of the file, so the NEXT declaration is resolved under a
    directory that does not exist, resolves to nothing, and its leaf comes back
    an orphan — which [`production_rust`] keeps. A withheld file counted
    production, and the only tell is a declaration that quietly went missing.
    """
    src = _rewrite(
        tree,
        '#[cfg(test)]\nmod inner {\n    const BRACE: &str = "{";\n}\n'
        "#[cfg(test)]\nmod helper;\n",
    )
    (src / "helper.rs").write_text(TAGGED)
    only_owner_finding(tree, "BarNeverOpens")


def test_a_mod_declaration_under_a_root_directory_leaf_is_found(tree):
    """`mod screen;` resolves to `screen.rs` OR to `screen/mod.rs`, and the tree
    rests on the second: `crates/rsk-fido/src/lib.rs` withholds eighteen
    conformance files through a `conformance/mod.rs` that declares them."""
    src = _rewrite(tree, "#[cfg(test)]\nmod screen;\n")
    (src / "screen").mkdir()
    (src / "screen" / "mod.rs").write_text(TAGGED)
    only_owner_finding(tree, "BarNeverOpens")


def test_a_lifetime_between_two_declarations_is_not_a_char_literal(tree):
    """`'a` is one apostrophe, and a scanner pairing them off blanks the code in
    between. Two lifetimes around a `#[cfg(test)] mod` hide the whole
    declaration, and the leaf comes back as an owner nothing compiles."""
    src = _rewrite(
        tree,
        "fn head<'a>(x: &'a [u8]) -> &'a [u8] { x }\n"
        "#[cfg(test)]\nmod helper;\n"
        "fn tail<'b>(x: &'b [u8]) -> &'b [u8] { x }\n",
    )
    (src / "helper.rs").write_text(TAGGED)
    only_owner_finding(tree, "BarNeverOpens")


def test_a_path_leaf_a_shipped_module_also_names_survives_a_withheld_includer(
    tree, capsys
):
    """One live declarer keeps a file, and a PROLOGUE cannot overrule that.

    `mirror.rs` withholds itself and `#[path]`-includes `shared.rs`; `lib.rs`
    names the same file plainly, so an image compiles it. Folding a file's own
    `#![cfg]` into the declarations it writes withholds `shared.rs` outright and
    the fixed point never gets to say otherwise — a red over a compiled file.
    """
    src = _rewrite(tree, "mod shared;\nmod mirror;\n")
    (src / "shared.rs").write_text(TAGGED)
    (src / "mirror.rs").write_text(
        '#![cfg(test)]\n#[path = "shared.rs"]\nmod shared;\n'
    )
    assert (src / "shared.rs").resolve() not in assurance_gate.cfg_excluded(tree)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_an_orphan_under_a_self_withheld_module_is_shut_with_it(tree):
    """The one thing `shut` does that no declaration reaches.

    A declared child of a `#![cfg(test)]` file is already withheld twice over —
    by the directory and by the fixed point over its declarers — so the shape
    that isolates this clause is a file under `mirror/` that NO `mod` names.
    Compiled by nothing, and [`production_rust`] keeps orphans, so without the
    directory half it stands as `BarNeverOpens`'s owner at EXIT=0.
    """
    src = _rewrite(tree, "mod mirror;\n")
    (src / "mirror.rs").write_text("#![cfg(test)]\nfn m() {}\n")
    (src / "mirror").mkdir()
    (src / "mirror" / "stray.rs").write_text(TAGGED)
    only_owner_finding(tree, "BarNeverOpens")


def test_a_path_attribute_that_names_nothing_resolves_to_nothing(tree, capsys):
    """rustc has no fallback for a `#[path]`, so neither has this.

    Measured on rustc 1.96: `#[path = "gone.rs"] mod shared;` is `couldn't read
    src/gone.rs` with `shared/mod.rs` sitting right there, and `#[path = "y"]`
    over a directory is `Is a directory`. The `parent.parent / name / "mod.rs"`
    fallback that stood here answered a SECOND file for a declaration rustc
    resolves to none — and here that second file is `shared/mod.rs`, plainly
    declared, carrying the only tag: the fallback reddens the row over it.
    """
    src = _rewrite(tree, "mod screen;\nmod shared;\n")
    (src / "shared").mkdir()
    (src / "shared" / "mod.rs").write_text(TAGGED)
    (src / "screen.rs").write_text('#[cfg(test)]\n#[path = "gone.rs"]\nmod shared;\n')
    assert (src / "shared" / "mod.rs").resolve() not in assurance_gate.cfg_excluded(tree)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out


def test_an_orphan_owns_its_tag_and_the_shipped_tree_has_none(tree, capsys):
    """What keeping orphans costs, and the census that is the reason it is safe.

    The cost is not "a column one too high": 34 of the 59 rows sit at `rust = 1`,
    so for most of the table an over-counted owner is the whole difference
    between EXIT 1 naming the missing owner and EXIT 0 saying nothing — which is
    the first half here, asserted rather than argued. What makes the rule safe is
    the second half: the shipped tree has NO orphan, so the rule decides zero
    files today, and withholding one would instead buy a resolver gap the power
    to delete owners across the table in silence.
    """
    src = _rewrite(tree, "fn bar() {}\n")
    (src / "stray.rs").write_text(TAGGED)
    assert assurance_gate.run(tree) == 0
    assert "assurance-gate: ok" in capsys.readouterr().out

    repo = pathlib.Path(__file__).resolve().parents[1]
    reached = {target.resolve() for _, target, _ in assurance_gate.declared_targets(repo)}
    roots = {
        f.resolve()
        for f in assurance_gate.rust_sources(repo)
        if f.name in ("lib.rs", "main.rs")
    }
    orphans = [
        f
        for f in assurance_gate.rust_sources(repo)
        if f.resolve() not in reached and f.resolve() not in roots
    ]
    assert not orphans, [str(f) for f in orphans]
