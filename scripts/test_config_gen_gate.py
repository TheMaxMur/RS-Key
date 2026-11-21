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
import gate_lines

pytestmark = pytest.mark.assurance

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
    # The runner comes too: `check_carve_out_premise` asks `spec_for` whether an
    # exempt pair really is two experiments, and a tree without it would make
    # that arm report a missing runner in every case rather than run.
    shutil.copy2(ROOT / "formal/run-tlc.sh", formal / "run-tlc.sh")
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
    assert "line 13: generator writes b'    MarkerNeverLies', the tree has b''" \
        in found[0], found


# --- M3: the generator changed and nothing regenerated -----------------------


def test_a_generator_edit_without_regenerating_is_found(tree):
    edit(tree / "formal/gen-configs.sh", 'echo "    MaxWeak = 2"', 'echo "    MaxWeak = 3"')
    found = problems(tree)
    # Every configuration of the boot module carries it -- the two write/re-arm
    # order rows included, which is why this is 15 and not the 13 `Boot*` ones.
    assert len(found) == 15, found
    assert all("differs from what" in problem for problem in found)


def test_a_new_family_the_tree_has_not_seen_is_found(tree):
    # The appended line is not decoration: emitted with `Boot.cfg`'s arguments
    # the probe is its byte-for-byte twin, and the duplicate rule below would
    # answer first — a case proving a DIFFERENT finding than the one it is named
    # for. One comment line makes it a new family and nothing else.
    edit(
        tree / "formal/gen-configs.sh",
        "emit_boot Boot.cfg \"\"",
        "emit_boot Boot.cfg \"\"\nemit_boot BootProbe.cfg \"\""
        "\necho '\\* a family the tree has not seen' >> BootProbe.cfg",
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


def test_a_generator_that_dies_says_so_and_says_nothing_else(tree):
    """`set -euo pipefail` and a `[ … ] && echo` as the last command of a `{ }`
    group: measured, that wrote four of nineteen families and the caller saw 0.

    ONE finding, because everything downstream would also fire — a generator that
    wrote nothing leaves all 200 files reading as unregistered, and telling the
    reader their tree is wrong when the generator is is the report defect this
    tree has shipped before.
    """
    edit(
        tree / "formal/gen-configs.sh",
        "emit Shipped.cfg",
        'echo "gen-configs: the roster went missing" >&2\nfalse\nemit Shipped.cfg',
    )
    found = problems(tree)
    assert found == [
        "formal/gen-configs.sh exited 1: gen-configs: the roster went missing"
    ], found


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


def test_check_assurance_sh_runs_the_row():
    """`scripts/test_gate_scripts.py` asserts this for every `*_gate.py`; asserted
    here too, because that file finds guards by glob and a rename escapes it."""
    check = (ROOT / "scripts/check-assurance.sh").read_text()
    assert gate_lines.runs(check, "scripts/config_gen_gate.py")


def test_the_prose_still_counts_the_tree():
    """A count in a guard's own comment is held by NOTHING.

    `docs_constants.py` reads `docs/**`, `tests/*.py` and `metadata/*.json`, and
    `run_count_gate.py` reads the published trees; neither reads `scripts/`.
    Measured on this pair: rotting both back to `191 of the 192` leaves every row
    of the gate at exit 0. Asserted rather than generated because two sentences
    do not earn a generator — but a sentence that can be wrong silently is the
    one defect this row is named for, one directory over.
    """
    present = len(list((ROOT / "formal").glob("*.cfg")))
    said = f"{present - len(config_gen_gate.HAND_WRITTEN)} of the {present} configurations"
    for rel in ("scripts/config_gen_gate.py", "scripts/check-assurance.sh"):
        assert said in (ROOT / rel).read_text(), (rel, said)


def test_the_generator_still_takes_an_output_directory():
    """The whole row rests on it. Hardcode the destination again and every case
    above would compare `formal/` with itself and pass."""
    text = (ROOT / "formal/gen-configs.sh").read_text()
    assert 'out_dir=${1:-' in text and 'cd "$out_dir"' in text


# --- what the first review found: the rules the table did not have -----------


def test_a_generated_config_that_lost_its_header_is_found(tree):
    """The sentence the row is NAMED after, held on the side that has 200 files.

    It was checked only on the one hand-written file: rewrite the generator's
    header, regenerate so the tree agrees, and every configuration stopped
    telling its reader not to edit it while the row said ok.
    """
    script = tree / "formal/gen-configs.sh"
    text = script.read_text()
    assert text.count(config_gen_gate.HEADER) == 15, text.count(config_gen_gate.HEADER)
    script.write_text(text.replace(config_gen_gate.HEADER, "Auto-written; hands off"))
    code, stderr = config_gen_gate.generate(tree, tree / "formal")
    assert code == 0, stderr
    found = problems(tree)
    assert found, "the tree agrees with its generator, so only the header rule can fire"
    assert all("without the" in problem and "header" in problem for problem in found), found


def test_a_carve_out_the_generator_has_started_writing_is_found(tree):
    """The other direction the docstring promised and the first version omitted."""
    script = tree / "formal/gen-configs.sh"
    # A verbatim `cp` would ALSO be a duplicate finding, and this case is about
    # the carve-out and the header; one appended line keeps it about those two.
    tail = b"\\* the carve-out fixture\n"
    script.write_text(script.read_text() + "cp Shipped.cfg TokenExport.cfg\n"
                      "echo '\\* the carve-out fixture' >> TokenExport.cfg\n")
    (tree / "formal/TokenExport.cfg").write_bytes(
        (tree / "formal/Shipped.cfg").read_bytes() + tail
    )
    found = problems(tree)
    # Two, and the pair is the point: a carve-out the generator writes is both a
    # stale carve-out AND a file wearing a header the carve-out forbids. There is
    # no content that trips only one — the header rule owns both sides.
    assert len(found) == 2, found
    assert any("registered hand-written but formal/gen-configs.sh writes it" in p
               for p in found), found


def test_a_crlf_copy_is_not_byte_for_byte(tree):
    """`read_text` folds `\r\n` to `\n`, so a text comparison calls these equal —
    while the summary line claims byte-for-byte."""
    path = tree / "formal" / VICTIM
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    found = problems(tree)
    assert len(found) == 1, found
    assert "line 1:" in found[0], found


def test_a_missing_final_newline_names_the_right_difference(tree):
    """Every line equal and the files still different. `splitlines` counted these
    the same and offered "N lines and N lines" as the explanation."""
    path = tree / "formal" / VICTIM
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    found = problems(tree)
    assert len(found) == 1, found
    assert "every line they share is equal" in found[0], found
    assert "14 newline-separated part(s) and the tree has 13" in found[0], found


def test_a_cfg_that_is_not_a_regular_file_is_a_finding_not_a_traceback(tree):
    (tree / "formal/Directory.cfg").mkdir()
    found = problems(tree)
    assert any("not a regular file" in problem for problem in found), found


def test_the_baseline_row_quotes_this_gate_live_summary():
    """`formal/README.md`'s mutation table opens with a `the tree as it stands`
    row quoting this row's own summary line, and nothing compared the two.

    It has rotted twice — `eaf29a5` and `8cb0a74`, the second retyping fifteen
    lines at once and naming the staleness in its own subject. The number is
    live, so it can be held exactly rather than scoped: the run-count scan
    cannot see it (a markdown table row names no runner, and 200 is far under
    the value rule's floor), and the string is the whole claim.
    """
    body = config_gen_gate.audit(ROOT)[1].split("ok — ", 1)[1]
    assert body in (ROOT / "formal/README.md").read_text(), body


# --- the second finding: two names, one configuration ------------------------
#
# `Historical_E76.cfg` and `Mut_BugSeedDoesNotLead.cfg` were byte-identical from
# 301c53a, the commit that introduced them, until the emit line changed: the
# matrix ran ONE experiment under two names, paid wall clock for both, and every
# count derived by grepping `formal/*.cfg` counted it twice. Every check above
# holds a configuration against its GENERATOR, and two identical files both pass
# that — so the class was invisible to this row for its whole life.

#: The pair the historical defect was made of, named rather than described: this
#: file may be regenerated by a parallel edit, and a prose anchor would then
#: patch nothing and the case would prove nothing.
TWINS = ("Historical_E76.cfg", "Mut_BugSeedDoesNotLead.cfg")


def test_the_twins_are_distinct_in_this_checkout():
    """The premise of the two cases below. Without it, a tree that regressed to
    the duplicate would make `test_a_clean_copy_is_green` the failing case and
    these two the passing ones, which is the report backwards."""
    first, second = (ROOT / "formal" / name for name in TWINS)
    assert first.read_bytes() != second.read_bytes(), TWINS


def test_the_historical_duplicate_is_found(tree):
    """M-dup-1, the measured shape verbatim: one configuration under two names."""
    later, owner = tree / "formal" / TWINS[0], tree / "formal" / TWINS[1]
    assert later.read_bytes() != owner.read_bytes(), TWINS
    later.write_bytes(owner.read_bytes())
    found = problems(tree)
    # Sorted, so the ALPHABETICALLY FIRST name owns the bytes and the other is
    # the one reported — the same way the generator's own sweep says it.
    assert any(f"{TWINS[1]}: byte-identical to {TWINS[0]}" in problem
               for problem in found), found


def test_a_duplicate_of_a_hand_written_config_is_found(tree, monkeypatch):
    """M-dup-2, and the reason this side exists at all: the generator's own sweep
    covers what IT writes, and a hand-written configuration is the one thing no
    emitter can see and no regeneration would remove."""
    monkeypatch.setitem(config_gen_gate.HAND_WRITTEN, "Twin.cfg", "the M-dup-2 fixture")
    formal = tree / "formal"
    (formal / "Twin.cfg").write_bytes((formal / "TokenExport.cfg").read_bytes())
    found = problems(tree)
    assert found == ["Twin.cfg: byte-identical to TokenExport.cfg — two names, one"
                     " configuration, so the matrix runs one experiment twice and every"
                     " count derived from formal/*.cfg counts it twice"], found


def test_the_generator_refuses_to_write_the_duplicate_again(tree):
    """M-dup-3. The row above says the tree does not HOLD one; this says the
    generator cannot MAKE one — which is what stops the next edit to that emit
    line recreating a defect that survived fourteen commits.

    ONE finding, because a generator that exits non-zero is reported alone."""
    edit(
        tree / "formal/gen-configs.sh",
        "emit Historical_E76.cfg BugSeedDoesNotLead TRUE TRUE",
        "emit Historical_E76.cfg BugSeedDoesNotLead FALSE TRUE",
    )
    found = problems(tree)
    assert len(found) == 1, found
    # The generator's LAST stderr line, which is the pair itself: `audit` reports
    # a dead generator by its tail and nothing else.
    assert found[0].startswith("formal/gen-configs.sh exited 1:"), found
    assert f"{TWINS[1]} is the same configuration as {TWINS[0]}" in found[0], found


def test_a_stale_carve_out_is_found(tree):
    """M-dup-4, the other direction of the one exemption. The trace pair is two
    experiments because TLC takes the MODULE as an argument — edit either file
    and the carve-out stops describing anything, which reads like a rule."""
    edit(tree / "formal/TraceSeamsBad.cfg", "SPECIFICATION TraceSpec",
         "SPECIFICATION TraceSpec  \\* the M-dup-4 fixture")
    found = problems(tree)
    assert any("TraceSeamsBad.cfg:TraceSeams.cfg: named in formal/gen-configs.sh's"
               " DUP_OK" in problem for problem in found), found


def test_a_carve_out_this_row_cannot_read_is_a_finding(tree):
    """M-dup-5. The list lives in the generator and is READ here, so the two can
    never disagree — but a spelling change that the shell still accepts would
    leave this side reading NO exemptions and calling the trace pair a defect.
    Single quotes are exactly that: valid shell, invisible to the pattern."""
    edit(tree / "formal/gen-configs.sh",
         'DUP_OK="TraceSeamsBad.cfg:TraceSeams.cfg"',
         "DUP_OK='TraceSeamsBad.cfg:TraceSeams.cfg'")
    found = problems(tree)
    assert len(found) == 1, found
    assert 'no `DUP_OK="…"` line' in found[0], found


def test_the_carve_out_is_scoped_to_its_pair(tree):
    """M-dup-6 — THE SIXTH HOLE, and it is the family this row's own guards keep
    shipping with. The first edition exempted a NAME: `DUP_OK="TraceSeamsBad.cfg"`
    said that file may be anybody's twin, so a generator writing it as a copy of
    `Shipped.cfg` passed both guards at exit 0 while the pair the exemption was
    granted for had quietly gone. The exemption is a PAIR now, and both halves of
    that mutation are findings: the new twin, and the pair that is no longer one.
    """
    formal = tree / "formal"
    (formal / "TraceSeamsBad.cfg").write_bytes((formal / "Shipped.cfg").read_bytes())
    found = problems(tree)
    assert any("TraceSeamsBad.cfg: byte-identical to Shipped.cfg" in problem
               for problem in found), found
    assert any("TraceSeamsBad.cfg:TraceSeams.cfg: named in" in problem
               for problem in found), found


def test_a_carve_out_whose_premise_is_gone_is_found(tree):
    """M-dup-7, and it is what the generator's sweep cannot ask. The pair is two
    experiments only because `spec_for` routes the two names to two MODULES —
    keyed on the FILENAME, so an arm moved above another silently makes them one
    experiment while the exemption is still granted."""
    edit(tree / "formal/run-tlc.sh", "TraceSeamsBad*) echo TraceSeamsBad ;; ", "")
    found = problems(tree)
    assert any("sends both to TraceSeams" in problem for problem in found), found


def test_the_control_a_config_one_line_from_its_twin_is_not_one(tree):
    """THE CONTROL, and it is placed one line from the defect on purpose: an
    ordinary hand-edit must leave the duplicate rule silent, or the rule would be
    a second name for the byte-comparison that already exists. The mutation here
    changes the OTHER `Fix*` constant, so the file stays one line away from
    `Mut_BugSeedDoesNotLead.cfg` and never reaches it."""
    edit(tree / "formal" / TWINS[0], "FixPpuatRequiresPin = TRUE",
         "FixPpuatRequiresPin = FALSE")
    found = problems(tree)
    assert len(found) == 1, found
    assert "differs from what formal/gen-configs.sh writes" in found[0], found
    assert not any("byte-identical" in problem for problem in found), found
