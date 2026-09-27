# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `verdict_gate.py` is verified against.

Every case drives the REAL `formal/floors.txt` over the REAL `formal/*.cfg`,
because a fixture registry over fixture configurations would be two new things
agreeing with each other — and the measured hole was in the tree's own file, not
in a shape.

The families are DERIVED, never listed. That is the whole difference between
this table and `test_run_tlc.py`, which names five configurations and so happens
to cover `Mut_` and `Solo_` and nothing else: measured on this tree, 23 of the 25
wildcard families and 102 of the 192 configurations had no cheap merge-gate
witness at all, and a `SeamMut_*.cfg RED` turned `GREEN` was green everywhere.
Add a family to `floors.txt` and it arrives here parametrized, which is the only
way a roster of 25 stays a roster of 25.

The floor arms are parametrized over the rows that HAVE a floor rather than over
the families, and that is not a gap: every one of the 25 families is a RED row
carrying `-`, because "a counterexample search halts at the first violation, so
its state count is worker-scheduling dependent" is the file's own rule — and
this table asserts that rule too, in both directions.

Three kinds of case are not that, each for a stated reason. The four arms also
run on the ten EXACT rows that expect RED, which fell between the family arms and
the floor arms and had none of either. A handful write a `.cfg` or copy the set
into a tmp tree, because a mutation of what a CONFIGURATION says has to be made
in one — and because the spellings TLC accepts and this tree has never used
(`CONSTANT x = v`, `PROPERTY Name`) cannot be exercised by a file that does not
carry them. And the last four run the SCRIPT, over a throwaway git checkout:
everything else calls `audit()`, so the row's exit code — the only thing
the runner reads — was held by nothing, and `run()` returning 0 with every
finding printed passed all 182 cases of the first edition.
"""

import pathlib
import re
import shutil
import subprocess
import sys

import pytest

import verdict_gate

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent
FORMAL = ROOT / "formal"
REGISTRY = (FORMAL / "floors.txt").read_text(encoding="utf-8")
RUNNER = (FORMAL / "run-tlc.sh").read_text(encoding="utf-8")

#: The committed registry the floor arms compare against, resolved once through
#: the real git history — so the arms exercise the shipped comparison rather than
#: a fixture of one, and `previous_registry` itself is driven by a case below.
PREVIOUS = verdict_gate.previous_registry()

ROWS, RATCHETS, PARSE_PROBLEMS = verdict_gate.read_registry(REGISTRY)
#: The same, off the committed registry. `check_floors` reads a decrease's BEFORE
#: from here and its AFTER from the text handed in, so a floor arm that takes
#: both from the working tree agrees with the guard only while the two files
#: carry the same number — see `lowered` for the commit on which they did not.
WAS_ROWS, WAS_RATCHETS, _ = verdict_gate.read_registry(PREVIOUS or "")
FAMILIES = [row["pattern"] for row in ROWS if verdict_gate.GLOB.search(row["pattern"])]
FLOORED = [row["pattern"] for row in ROWS if row["floor"] is not None]
#: Subjects of a floor: the configurations a floored row decides, plus the
#: coverage ratchets, which are the same ratchet written `@Name value`.
#:
#: SCOPED TO ROWS THE PREVIOUS REGISTRY ALSO HAS, and the reason is measured
#: rather than tidy. `previous_registry` walks back to the newest COMMITTED
#: `floors.txt` whose bytes differ from the working tree's, so a row introduced
#: by that very commit has no earlier version — and "a floor may fall, but not
#: quietly" has nothing to compare for it. Asserting the rule there asserts a
#: check that cannot run: `AlwaysUv.cfg` failed both arms for exactly that
#: reason, one commit after it was added, while `TokenGate.cfg` (added one
#: commit earlier) passed them.
SUBJECTS = [
    subject
    for subject in FLOORED + sorted(RATCHETS)
    if any(
        line.split()[:1] == [subject.lstrip("@").split()[0]] or subject in line
        for line in (PREVIOUS or "").splitlines()
    )
]
assert SUBJECTS, "no floored row survives into the previous registry — the arms below run over nothing"
#: The rows that name ONE configuration and expect RED — ten of them, and the
#: four family arms ran over none, so a new exact RED did not "arrive here
#: parametrized" the way a new family does. Derived for the same reason.
EXACT_RED = [row["pattern"] for row in ROWS
             if not verdict_gate.GLOB.search(row["pattern"]) and row["want"] == "RED"]


def findings(text, previous=PREVIOUS, runner=RUNNER):
    problems, _ = verdict_gate.audit(
        FORMAL, registry_text=text, previous_text=previous, runner_text=runner)
    return problems


def rewrite(pattern, replacement):
    """`floors.txt` with `pattern`'s row replaced, or dropped when None."""
    kept, seen = [], False
    for line in REGISTRY.splitlines():
        parts = line.split()
        if parts and parts[0] == pattern:
            seen = True
            if replacement is not None:
                kept.append(replacement)
            continue
        kept.append(line)
    assert seen, f"{pattern} is no longer a row of floors.txt"
    return "\n".join(kept) + "\n"


def members(pattern):
    """The configurations a family decides, under first match."""
    rows, _, _ = verdict_gate.read_registry(REGISTRY)
    names = sorted(p.name for p in FORMAL.glob("*.cfg"))
    first, _ = verdict_gate.resolve(rows, names)
    return [n for n, hit in first.items() if hit and hit["pattern"] == pattern]


def about(problems, name):
    return [p for p in problems if p.startswith(f"{name}:")]


def row_for(pattern):
    return next(row for row in ROWS if row["pattern"] == pattern)


def broadened(pattern):
    """A glob one character wider, which masks `pattern` under first match."""
    return pattern.split("*", 1)[0][:-1] + "*"


def same_payload(pattern, row):
    """`pattern` carrying `row`'s payload verbatim, so a masking row disagrees
    with nothing: no verdict moves, and the row it masks simply stops being
    consulted — which is the silent half of the shape."""
    floor = "-" if row["floor"] is None else row["floor"]
    return f"{pattern} {row['want']} {floor} - {row['invariant'] or '-'}"


@pytest.fixture
def tree(tmp_path):
    """A copy of the real configurations a case may edit.

    The derivation reads a `.cfg`, so a mutation of what a configuration SAYS
    has to be made in one — and in a copy of the whole set, because a lone file
    would leave every other row orphaned and the report unreadable.
    """
    into = tmp_path / "formal"
    into.mkdir()
    for cfg in FORMAL.glob("*.cfg"):
        shutil.copy(cfg, into / cfg.name)
    return into


def tree_with(tree, was, now, name="Boot.cfg"):
    """`tree` with one configuration's text edited, and the tree back."""
    path = tree / name
    text = path.read_text(encoding="utf-8")
    assert was in text, (name, was)
    path.write_text(text.replace(was, now), encoding="utf-8")
    return tree


def findings_over(tree, text=REGISTRY):
    problems, _ = verdict_gate.audit(
        tree, registry_text=text, previous_text=PREVIOUS, runner_text=RUNNER)
    return problems


def test_the_registry_parses_and_the_tree_is_clean():
    """Both halves, because a parse that quietly dropped every row would make
    each case below loop over nothing and pass."""
    assert not PARSE_PROBLEMS, PARSE_PROBLEMS
    assert not findings(REGISTRY)


def test_there_are_families_and_floors_to_check():
    """A parametrization that matches nothing passes every case it generates.

    Both halves of `SUBJECTS` are floored, not their sum: deleting all six
    ratchets left the sum at exactly 20 and quietly dropped twelve cases.
    """
    assert len(FAMILIES) >= 25, FAMILIES
    assert len(FLOORED) >= 20, FLOORED
    assert len(RATCHETS) >= 6, RATCHETS
    assert len(EXACT_RED) >= 10, EXACT_RED
    assert all(members(pattern) for pattern in FAMILIES)


def test_the_previous_registry_is_read_from_git_and_differs():
    """The floor arms are worth nothing if the comparison is a file against
    itself, which is what `HEAD` would be on every CI checkout."""
    assert PREVIOUS is not None
    assert PREVIOUS != REGISTRY


# --- the four arms, on every wildcard family ------------------------------


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_family_flipped_to_green_is_rejected(pattern):
    """The measured miss, verbatim: `SeamMut_*.cfg RED` → `GREEN` was green in
    the targeted subset because the fixture names no configuration of that
    family. The verdict is read off the CONSTANTS here, so no family is named."""
    problems = findings(rewrite(pattern, f"{pattern} GREEN 999999"))
    for name in members(pattern):
        assert any("owes RED" in p for p in about(problems, name)), (name, problems[:3])


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_deleted_family_row_is_rejected(pattern):
    problems = findings(rewrite(pattern, None))
    for name in members(pattern):
        assert any("no verdict entry" in p for p in about(problems, name)), name


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_broad_row_above_a_family_is_rejected(pattern):
    """First match wins, so a broader glob laid on top decides everything the
    family used to. Its payload is IDENTICAL here on purpose: nothing disagrees,
    no verdict moves, and the family row simply stops being consulted — which is
    the silent half of the shape, and what makes it a masking rule rather than a
    duplicate one."""
    broad = pattern.split("*", 1)[0][:-1] + "*"
    problems = findings(f"{broad} RED -\n" + REGISTRY)
    assert any(f"`{pattern}` never decides anything" in p for p in problems), problems[:3]


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_wrong_reason_red_on_a_family_is_rejected(pattern):
    """A real invariant, of a module this family does not run: the colour is
    right and the reason is not, which is how 2 of 24 co-refutation patches in
    this tree scored a kill for the INVERSE defect."""
    mine = set().union(*(set(verdict_gate.Config(FORMAL / n).invariants)
                         for n in members(pattern)))
    every = set().union(*(set(verdict_gate.Config(p).invariants)
                          for p in FORMAL.glob("*.cfg")))
    stranger = sorted(every - mine)[0]
    problems = findings(rewrite(pattern, f"{pattern} RED - - {stranger}"))
    for name in members(pattern):
        assert any("does not check" in p for p in about(problems, name)), (name, stranger)


# --- the same four, on every exact RED row ---------------------------------
#
# The families cover 161 configurations and the floor arms cover the 20 floored
# rows and 6 ratchets; the ten EXACT rows that expect RED and carry no floor fell
# between them, so `TraceSeamsBad.cfg` and the nine trace/refinement rows had no
# RED->GREEN, no deleted-row and no wrong-reason arm at all. Derived here for the
# reason the families are: a roster of ten stays a roster of ten only if nobody
# has to remember to add to it.


@pytest.mark.parametrize("pattern", EXACT_RED)
def test_an_exact_red_flipped_to_green_is_rejected(pattern):
    """Two messages, because one row is the carve-out and it is the one whose
    RED could be turned GREEN if this arm asked only for a finding."""
    problems = about(findings(rewrite(pattern, f"{pattern} GREEN 999999")), pattern)
    expected = ("the carve-out exempts the derivation, not the verdict"
                if pattern in verdict_gate.UNSWITCHED_RED else "owes RED")
    assert any(expected in p for p in problems), (pattern, problems)


@pytest.mark.parametrize("pattern", EXACT_RED)
def test_a_deleted_exact_red_row_is_rejected(pattern):
    problems = about(findings(rewrite(pattern, None)), pattern)
    assert any("no verdict entry" in p for p in problems), (pattern, problems)


@pytest.mark.parametrize("pattern", EXACT_RED)
def test_a_broad_row_above_an_exact_red_is_rejected(pattern):
    """Its payload is copied off the row it masks, so nothing disagrees and the
    only thing that changed is which line decides — the silent shape."""
    row = row_for(pattern)
    masking = same_payload(broadened(pattern), row)
    problems = findings(f"{masking}\n" + REGISTRY)
    assert any(f"`{pattern}` never decides anything" in p for p in problems), problems[:3]


@pytest.mark.parametrize("pattern", EXACT_RED)
def test_a_wrong_reason_red_on_an_exact_row_is_rejected(pattern):
    """The colour right and the reason not — the shape that let 2 of 24
    co-refutation patches in this tree score a kill for the INVERSE defect."""
    mine = set(verdict_gate.Config(FORMAL / pattern).invariants)
    every = set().union(*(set(verdict_gate.Config(p).invariants)
                          for p in FORMAL.glob("*.cfg")))
    stranger = sorted(every - mine)[0]
    problems = about(findings(rewrite(pattern, f"{pattern} RED - - {stranger}")), pattern)
    assert any("does not check" in p for p in problems), (pattern, stranger, problems)


# --- the floor arm, on every row and ratchet that carries one --------------


def lowered(subject):
    """(the registry with `subject`'s floor weakened, the two numbers).

    `was` is the COMMITTED registry's value and not the working tree's, because
    that is the side `check_floors` compares a decrease against. The two are the
    same number on almost every checkout and differ for exactly one commit after
    a floor is RE-DERIVED — measured when `Shipped.cfg` and `Historical_E76.cfg`
    were re-derived from the first recorded run: five cases then asserted a
    movement the guard never reports, which is the sibling of the edge `SUBJECTS`
    above already records. `now` still rewrites the line that is actually in the
    file, but it is weakened off the SMALLER of the two numbers rather than off
    the working tree's alone: `Policies.cfg` grew 750 -> 110000 in this same
    tree, and half of a floor that grew by more than 2x is an INCREASE against
    the committed one — the guard reports nothing and the arm fails saying so.
    """
    if subject.startswith("@"):
        here, was = RATCHETS[subject], WAS_RATCHETS[subject]
        # A `Max` is the same ratchet upside down: it is weakened by RISING.
        now = (max(here, was) + 1 if subject.endswith("Max")
               else max(0, min(here, was) - 1))
        return REGISTRY.replace(f"{subject} {here}", f"{subject} {now}"), was, now
    row = next(r for r in ROWS if r["pattern"] == subject)
    was = next(r for r in WAS_ROWS if r["pattern"] == subject)["floor"]
    now = max(verdict_gate.MIN_FLOOR, min(row["floor"], was) // 2)
    return rewrite(subject, f"{subject} {row['want']} {now}"), was, now


@pytest.mark.parametrize("subject", SUBJECTS)
def test_an_unjustified_floor_decrease_is_rejected(subject):
    text, was, now = lowered(subject)
    assert was != now, subject
    problems = findings(text)
    assert any(f"floor {was} -> {now} with no justification" in p
               for p in about(problems, subject)), (subject, problems[:3])


@pytest.mark.parametrize("subject", SUBJECTS)
def test_a_justified_floor_decrease_is_accepted(subject):
    """The rule is "say so", not "never" — a guard that refuses a re-measurement
    outright gets deleted the first week a model legitimately shrinks."""
    text, was, now = lowered(subject)
    said = f"\\* floor-decrease: {subject} {was} -> {now} re-measured after the scope moved\n"
    assert not about(findings(said + text), subject)


def test_a_justification_without_a_reason_is_not_one():
    subject = SUBJECTS[0]
    text, was, now = lowered(subject)
    bare = f"\\* floor-decrease: {subject} {was} -> {now}\n"
    assert about(findings(bare + text), subject)


def test_a_marker_for_a_movement_that_did_not_happen_is_rejected():
    """A justification outliving its decrease is how the file fills with
    dispositions for movements nobody can find any more — and it is the same
    branch that refuses a marker invented for a floor that never fell."""
    subject = SUBJECTS[0]
    _, was, now = lowered(subject)
    said = f"\\* floor-decrease: {subject} {was} -> {now} re-measured\n"
    assert any("not the movement the committed registry shows" in p
               for p in about(findings(said + REGISTRY), subject))


def test_a_floor_that_is_deleted_outright_is_a_decrease():
    """A floor replaced by `-` weakens more than any number would."""
    row = next(r for r in WAS_ROWS if r["pattern"] == "Shipped.cfg")
    problems = findings(rewrite("Shipped.cfg", "Shipped.cfg GREEN -"))
    assert any(f"floor {row['floor']} -> 0" in p for p in about(problems, "Shipped.cfg"))


def test_no_previous_registry_is_a_finding_not_a_pass():
    """A guard that reads a git failure as "nothing moved" goes green the day the
    command's spelling breaks."""
    text, _, _ = lowered("Shipped.cfg")
    problems = findings(text, previous=None)
    assert any("no floor could be compared" in p for p in problems), problems


def test_a_previous_registry_that_parses_to_nothing_is_a_finding_too():
    """`previous is None` was the only shape reported, and it is not the only one
    a broken `git` produces: an answer of `""` parses to no rows, every `before`
    is None, and NO FLOOR IS COMPARED WITH ANYTHING while the row prints ok."""
    text, _, _ = lowered("Shipped.cfg")
    problems = findings(text, previous="")
    assert any("parses to no rows" in p for p in problems), problems


def test_git_answers_none_rather_than_nothing_when_it_cannot_answer(tmp_path):
    """The pin the rule above rests on. `git()` returning `""` on failure instead
    of `None` survived every case in this file, and it is what turns a broken
    `git show` into a clean comparison of nothing with nothing."""
    (tmp_path / "formal").mkdir()
    (tmp_path / "formal" / "floors.txt").write_text(REGISTRY)
    assert verdict_gate.git(tmp_path, "rev-parse", "HEAD") is None
    assert verdict_gate.previous_registry(tmp_path) is None


# --- the shape of a row ---------------------------------------------------


def test_a_green_row_with_no_floor_is_rejected():
    problems = findings(rewrite("Seams.cfg", "Seams.cfg GREEN -"))
    assert any("`Seams.cfg`: GREEN with no floor" in p for p in problems), problems[:3]


def test_a_green_row_floored_under_the_minimum_is_rejected():
    """It used to say the runner already refuses that as VACUOUS, and for the two
    induction probes that is FALSE: `run-tlc.sh` guards the `distinct < 2` test
    with an `elif` after `grep -qE '^INIT'`, so `StoreInduction.cfg` and
    `BootInduction.cfg` get no distinct floor from it at all and this is the only
    one they have."""
    problems = findings(rewrite("Seams.cfg", "Seams.cfg GREEN 1"))
    assert any("under the 2 below which a GREEN says only" in p for p in problems), problems[:3]
    # The corrected justification, held to the runner's own text: a claim about
    # another file that nothing reads rots exactly the way the wrong one did.
    # `.index` rather than `in`, so a runner that stopped saying either goes red.
    assert RUNNER.index("grep -qE '^INIT") < RUNNER.index('elif [ "${distinct:-0}" -lt 2 ]')


def test_a_red_row_given_a_floor_is_rejected():
    """One finding, not nineteen: `SeamMut_*.cfg` decides nineteen configurations
    and a mistyped column says the same thing about all of them.

    The `== problems` half alone was `[] == []` when the rule was removed — the
    one case of the 32-mutation sweep that killed nothing, which is the family
    this whole file exists for.
    """
    problems = findings(rewrite("SeamMut_*.cfg", "SeamMut_*.cfg RED 5000"))
    assert any("RED with a floor of 5000" in p for p in problems), problems[:3]
    assert [p for p in problems if "RED with a floor of 5000" in p] == [p for p in problems]


def test_a_green_row_naming_an_invariant_is_rejected():
    """Nothing compares an invariant on a pass, so a name there is a claim the
    runner never reads — and reads exactly like one it does."""
    text = rewrite("Shipped.cfg", "Shipped.cfg GREEN 36206318 - NoAuthorizationBypass")
    assert any("nothing compares" in p for p in findings(text))


def test_a_verdict_that_is_neither_colour_is_rejected():
    assert any("neither GREEN nor RED" in p for p in findings(rewrite("Seams.cfg", "Seams.cfg OK 200")))


# --- what the registry is measured against --------------------------------


def test_an_orphaned_row_is_rejected():
    assert any("matches no configuration" in p
               for p in findings("Gone_*.cfg RED -\n" + REGISTRY))


def test_conflicting_rows_are_refused_rather_than_ordered():
    """The rule the first-match resolution hides: two rows over one
    configuration, disagreeing, and the file decides by line number."""
    problems = findings("Shipped.cfg RED -\n" + REGISTRY)
    assert any("disagree" in p for p in about(problems, "Shipped.cfg")), problems[:3]


def test_the_no_verdict_exemption_is_checked_in_both_directions(monkeypatch):
    assert any("registered as having no verdict entry" in p
               for p in about(findings("TokenExport.cfg GREEN 2\n" + REGISTRY), "TokenExport.cfg"))
    monkeypatch.setitem(verdict_gate.NO_VERDICT, "NoSuch.cfg", "gone")
    assert any("stale entry" in p for p in about(findings(REGISTRY), "NoSuch.cfg"))


def test_the_unswitched_red_carve_out_is_checked_in_both_directions(monkeypatch):
    monkeypatch.setitem(verdict_gate.UNSWITCHED_RED, "Mut_BugCredBeforeRp.cfg", "not really")
    problems = about(findings(REGISTRY), "Mut_BugCredBeforeRp.cfg")
    assert any("drop the carve-out" in p for p in problems), problems
    monkeypatch.setitem(verdict_gate.UNSWITCHED_RED, "NoSuch.cfg", "gone")
    assert any("stale entry" in p for p in about(findings(REGISTRY), "NoSuch.cfg"))


def test_the_carve_out_exempts_the_derivation_and_not_the_verdict():
    """Both directions above are about MEMBERSHIP, and neither asked what the row
    says — so the one configuration singled out for attention was the only one
    whose RED could be turned GREEN with this row happy. Found by review."""
    victim = sorted(verdict_gate.UNSWITCHED_RED)[0]
    problems = findings(rewrite(victim, f"{victim} GREEN 999999"))
    assert any("the carve-out exempts the derivation, not the verdict" in p
               for p in about(problems, victim)), problems[:3]


def test_a_red_attributed_to_the_type_predicate_is_rejected():
    """`TypeOK` is checked by every configuration and targeted by no mutant, so
    naming it attributes the RED to nothing while satisfying "it checks it"."""
    text = rewrite("TraceSecurityBadPinSet.cfg", "TraceSecurityBadPinSet.cfg RED - - TypeOK")
    assert any("attributes the RED to nothing" in p
               for p in about(findings(text), "TraceSecurityBadPinSet.cfg"))


def test_a_red_attributed_to_a_property_is_rejected():
    """`run-tlc.sh` greps `Invariant … is violated` and nothing else, so a
    temporal refutation has no name it could ever compare."""
    text = rewrite("LiveMut_*.cfg", "LiveMut_*.cfg RED - - EveryWalkCloses")
    assert any("a temporal refutation cannot be named here" in p
               for p in about(findings(text), "LiveMut_BugWalkNeverExpires.cfg"))


def test_a_deleted_ratchet_is_the_largest_decrease_there_is():
    """Lowering `@TraceSecurityGatesMin` by one is caught above; deleting the line
    was free, and only the six `security_trace.py` names by constant had any
    backstop at all."""
    without = "\n".join(l for l in REGISTRY.splitlines() if not l.startswith("@")) + "\n"
    problems = findings(without)
    for ratchet in RATCHETS:
        assert any("a deleted ratchet is the largest decrease" in p
                   for p in about(problems, ratchet)), ratchet


def test_a_solo_row_flipped_to_green_leaves_its_multi_target_twin_unattributable():
    """The coupling that makes a multi-target RED mean anything: `SeamMut_*`
    checks six invariants and names none, so what says which defect its RED
    describes is the sibling running the same switches against ONE."""
    problems = findings(rewrite("SeamSolo_*.cfg", "SeamSolo_*.cfg GREEN 999999"))
    assert any("RED for no stated reason" in p
               for p in about(problems, "SeamMut_BugSigPinNotSpent.cfg")), problems[:3]


# --- the derivation reading a switch the way TLC reads it ------------------
#
# `v == "TRUE"` read a switch as OFF whenever its value was not the bare token,
# and two TLA+-legal spellings defeat that. Measured end to end against real TLC
# on `Boot.cfg`, in both: `run-tlc.sh` came back `RED: MarkerNeverLies … !!
# expected GREEN` while this row printed `ok — 191 configuration(s)` and exited
# 0. A defect switched on IN A BASELINE configuration — the green tree every
# mutant is measured against — passed the merge gate and died six days later.

SWITCHED_OFF = "BugMarkerBeforeScrub = FALSE"


@pytest.mark.parametrize("spelling", [
    "BugMarkerBeforeScrub = TRUE  \\* E-arm kept",
    "BugMarkerBeforeScrub =\n        TRUE",
])
def test_a_switch_on_in_a_baseline_configuration_is_read(tree, spelling):
    problems = about(findings_over(tree_with(tree, SWITCHED_OFF, spelling)), "Boot.cfg")
    assert any("switches BugMarkerBeforeScrub on and so owes RED" in p
               for p in problems), (spelling, problems)


def test_a_wrapped_switch_is_not_folded_into_the_line_above_it(tree):
    """The fold boundary, and it fails in the silent direction one line over.
    Reading `Name =` as a CONTINUATION folds two constants into one: with a
    switch above it the row went red naming the WRONG constant, and with a SIZE
    above it (`MaxWeak = 2`, which is this case) it went green with nothing to
    report — measured, `armed=[] unreadable=[]`."""
    problems = about(findings_over(tree_with(
        tree, "BugRekeyKeepsTheMarker = FALSE", "BugRekeyKeepsTheMarker =\n        TRUE")),
        "Boot.cfg")
    assert any("switches BugRekeyKeepsTheMarker on and so owes RED" in p
               for p in problems), problems


def test_a_comment_after_a_switch_that_is_off_leaves_it_off(tree):
    """The other direction: cutting the tail must not turn a remark into an arm.
    Without this the rule above is satisfied by reading every switch as ON."""
    assert not about(findings_over(tree_with(
        tree, SWITCHED_OFF, "BugMarkerBeforeScrub = FALSE  \\* still out")), "Boot.cfg")


def test_a_switch_value_that_is_neither_is_a_finding_not_a_shrug(tree):
    """What is left once both spellings are read, and the reason it is reported
    rather than skipped: "not TRUE" meaning "not armed" is what made the two
    above silent, so an unreadable value may not inherit that default."""
    problems = about(findings_over(tree_with(tree, SWITCHED_OFF, "BugMarkerBeforeScrub = 1")),
                     "Boot.cfg")
    assert any("neither TRUE nor FALSE" in p for p in problems), problems


def test_a_shipped_fix_taken_back_out_owes_red(tree):
    """`Fix*` is excluded from the defect switches so that a baseline is not read
    as a mutant, and that exclusion was an unlisted limit: a mutation expressed
    as one derived GREEN. Not hypothetical — `Historical_E77.cfg` already varies
    `FixPpuatRequiresPin`, and `gen-configs.sh`'s `emit <name> <bug> <fix>
    <fix2>` makes a Fix-only configuration a ONE-ARGUMENT change."""
    problems = about(findings_over(tree_with(
        tree, "FixPpuatRequiresPin = TRUE", "FixPpuatRequiresPin = FALSE",
        "TokenRefinement.cfg")), "TokenRefinement.cfg")
    assert any("takes FixPpuatRequiresPin off the arm Shipped.cfg ships it on" in p
               for p in problems), problems


# --- the OTHER direction of a `Fix*`, which had no reader at all -------------
#
# `FixSweepDropsCredsBeforeRpEntries` was assigned FALSE by 96 configurations and
# TRUE by NONE, so the conjunct it guards could be deleted with every recorded
# verdict unchanged — a model constant nothing branches on. `Historical_E76.cfg`
# arms it now, and the three cases below are what that cost this row: the fix
# comparison was symmetric and called an APPLIED repair a reverted one, and the
# verdict derivation calls anything arming a defect RED, which is the one thing
# a counterfactual repair cannot be assumed to be.

#: The counterfactual, named rather than described: `formal/` is regenerated by
#: edits that move line numbers, and a prose anchor would patch nothing.
REPAIR = "Historical_E76.cfg"
REPAIR_FIX = "FixSweepDropsCredsBeforeRpEntries"


def test_the_counterfactual_arms_the_fix_this_checkout_ships_off():
    """The premise of the three cases below, and the finding they came from: with
    the constant TRUE nowhere, every one of them would run over nothing."""
    baseline = verdict_gate.Config(FORMAL / verdict_gate.BASELINE)
    assert baseline.fixes[REPAIR_FIX] == "FALSE", baseline.fixes
    assert verdict_gate.Config(FORMAL / REPAIR).fixes[REPAIR_FIX] == "TRUE"


def test_a_repair_the_tree_never_took_is_not_a_fix_taken_back_out(tree):
    """THE CONTROL, and it is the mutation the old comparison got wrong. `v !=
    baseline.fixes[n]` is symmetric, so a fix the baseline leaves OFF and a
    configuration turns ON tripped `check_reverted_fixes` — a repair applied
    reported as the defect it closes. Applied where NO defect is armed it is not
    even a repair experiment: the verdict is still derived, and derived GREEN."""
    problems = about(findings_over(tree_with(
        tree, f"{REPAIR_FIX} = FALSE", f"{REPAIR_FIX} = TRUE", "Fairness.cfg")),
        "Fairness.cfg")
    assert problems == [], problems


def test_a_repair_armed_beside_a_defect_owes_an_exact_row():
    """A wildcard carrying a counterfactual's verdict is an accident waiting:
    `Mut_*.cfg RED -` would absorb a mutant somebody had disarmed with a `Fix*`,
    and the family's own RED would be the reason nobody looked. Driven by folding
    the two exact `Historical_*` rows back into the glob they replaced."""
    text = rewrite(REPAIR, None)
    lines = [
        "Historical_*.cfg                     RED     -"
        if line.split()[:1] == ["Historical_E77.cfg"] else line
        for line in text.splitlines()
    ]
    problems = about(findings("\n".join(lines) + "\n"), REPAIR)
    assert any("owes an exact row of its own" in p for p in problems), problems


def test_taking_the_repair_out_brings_the_derivation_straight_back(tree):
    """The exemption is narrow by construction, and this is what says so: the
    verdict stops being derived only while the repair is armed BESIDE the defect.
    Remove the repair and the file is `Mut_BugSeedDoesNotLead.cfg` again — a
    plain mutant, owed RED, held to a registry row that says GREEN."""
    problems = about(findings_over(tree_with(
        tree, f"{REPAIR_FIX} = TRUE", f"{REPAIR_FIX} = FALSE", REPAIR)), REPAIR)
    assert any("requires GREEN" in p and "owes RED" in p for p in problems), problems


def test_a_fix_value_that_is_neither_is_a_finding_not_a_shrug(tree):
    """`Config.unreadable` covers the defect and observer families and never the
    `Fix*` one, so an unreadable fix read here exactly like the shipped arm —
    the same silent direction, one family over."""
    problems = about(findings_over(tree_with(
        tree, "FixPpuatRequiresPin = TRUE", "FixPpuatRequiresPin = 1",
        "TokenRefinement.cfg")), "TokenRefinement.cfg")
    assert any("neither TRUE nor FALSE" in p and "applies one the tree never took" in p
               for p in problems), problems


def test_the_inline_block_spellings_are_read_the_way_tlc_reads_them(tmp_path):
    """`CONSTANT x = v`, `INVARIANT Name` and the SINGULAR `PROPERTY Name` are
    all TLC's, and no `.cfg` here uses any of them — so a parser blinder than TLC
    was invisible, which is how `PROPERTI?E?S?` came to be unable to match
    `PROPERTY` at all. Written rather than copied for that reason: the spelling
    under test is the one the tree does not carry."""
    cfg = tmp_path / "Inline.cfg"
    cfg.write_text("SPECIFICATION Spec\n"
                   "CONSTANT BugCommented = TRUE  \\* kept\n"
                   "CONSTANT BugSomethingOn = TRUE\n"
                   "INVARIANT OnlyTarget\n"
                   "PROPERTY EveryWalkCloses\n")
    config = verdict_gate.Config(cfg)
    assert config.armed == ["BugCommented", "BugSomethingOn"]
    assert config.invariants == ["OnlyTarget"]
    assert config.properties == ["EveryWalkCloses"]
    assert config.want == "RED"


def test_a_directory_named_like_a_configuration_is_reported_not_raised(tmp_path):
    """`config_gen_gate.audit` has the same rule over the same glob: a
    `IsADirectoryError` one line later is a report nobody can act on."""
    (tmp_path / "NotAFile.cfg").mkdir()
    problems, _ = verdict_gate.audit(tmp_path, registry_text=REGISTRY,
                                     previous_text=PREVIOUS, runner_text=RUNNER)
    assert any("NotAFile.cfg: a formal/*.cfg entry that is not a regular file" in p
               for p in problems), problems[:3]


# --- the runner and this row reading the same file ------------------------


def test_a_runner_that_cannot_read_a_digit_is_rejected():
    """`[A-Za-z]+` was the runner's extractor for its whole life and every `R4*`
    invariant has a DIGIT in its name, so nine rows printed a blank verdict
    column and compared nothing. It is a static disagreement between two files.

    Mutated by NAMING the extractor rather than by taking the file's first
    occurrence of that character class: the runner grew a second one when it
    learned to derive an expected invariant from a configuration's own
    INVARIANTS block, and a positional `replace(…, 1)` then narrowed *that*
    instead — leaving this case green over an extractor it had not touched."""
    narrowed = RUNNER.replace("'Invariant [A-Za-z][A-Za-z0-9_]* is violated'",
                              "'Invariant [A-Za-z]+ is violated'", 1)
    assert narrowed != RUNNER
    problems = findings(REGISTRY, runner=narrowed)
    assert any("cannot read" in p for p in problems), problems[:3]
    # Rows the narrowed reader still reads are no disagreement, and the tier-A
    # gate rows are the first of those -- `NoAuthorizationBypassA` is all
    # letters. Counting every invariant-naming row was exact only while every
    # one of them was an `R4*`.
    unreadable = [row for row in ROWS
                  if row["invariant"] and not re.fullmatch(r"[A-Za-z]+", row["invariant"])]
    assert len(problems) == len(unreadable), problems


def test_a_runner_with_no_reader_at_all_is_rejected():
    assert any("no longer extracts an invariant name" in p
               for p in findings(REGISTRY, runner="#!/usr/bin/env bash\n"))


def test_a_comment_is_a_comment_only_where_the_runner_says_so():
    """`run-tlc.sh` skips a line whose FIRST WORD is `\\*`; `\\*Shipped.cfg` is a
    glob to it. A parser more generous about comments than the runner is a
    parser reading a different registry."""
    assert not findings("\\* Shipped.cfg GREEN 1\n" + REGISTRY)
    assert findings("\\*Shipped.cfg GREEN 1\n" + REGISTRY)


def test_the_invariant_column_runs_to_the_end_of_the_line():
    """`read -r want floor heap inv` leaves everything past the fourth field in
    `inv`, so a remark after the name is part of the name the runner compares —
    and every run of that row prints `!! expected` forever."""
    text = rewrite("TraceSecurityBadPinSet.cfg",
                   "TraceSecurityBadPinSet.cfg RED - - R4cGateAnswers  and a remark")
    assert any("cannot read" in p for p in findings(text)), findings(text)[:3]


def test_trailing_whitespace_after_the_invariant_is_not_part_of_the_name():
    """The parity break in the other direction, and the same `read`: it strips
    trailing IFS whitespace off the last field where `split(None, 4)` keeps it,
    so three spaces produced TWO findings about a row the runner reads
    CORRECTLY. A red for the wrong reason is how a gate row gets deleted."""
    text = rewrite("TraceSecurityBadPinSet.cfg",
                   "TraceSecurityBadPinSet.cfg RED - - R4cGateAnswers   ")
    problems = findings(text)
    assert not [p for p in problems if "R4cGateAnswers" in p], problems


def test_a_carriage_return_is_a_finding_rather_than_a_fold():
    """`read` leaves the CR on the last field, `[ "$distinct" -lt "200\\r" ]` errors,
    bash reads the non-zero as false — and every floored row falls through to
    GREEN. `read_text` folds it away, which is why the audit asks the bytes."""
    problems = findings(REGISTRY.replace("\n", "\r\n"))
    assert any("carries a CR" in p for p in problems), problems[:3]


def test_a_pattern_the_two_would_expand_differently_is_refused():
    """A shell `case` expands `Boot[MS]*.cfg` and this row would read it as a
    literal, so the two would resolve different configurations from one file."""
    assert any("carries a character class" in p
               for p in findings("Boot[MS]*.cfg RED -\n" + REGISTRY))


def test_a_glob_does_not_fold_case():
    """`fnmatch` would, on this filesystem, and `case` never does."""
    assert verdict_gate.glob_to_regex("Solo_*.cfg").match("Solo_x.cfg")
    assert not verdict_gate.glob_to_regex("Solo_*.cfg").match("solo_x.cfg")


def test_a_single_character_glob_is_a_family_and_matches_one_character():
    """No row uses `?`, so both halves of it could be dropped in silence: the
    test that makes a row a FAMILY, and the translation `case` expands."""
    assert verdict_gate.GLOB.search("Solo_?.cfg")
    assert verdict_gate.glob_to_regex("Solo_?.cfg").match("Solo_x.cfg")
    assert not verdict_gate.glob_to_regex("Solo_?.cfg").match("Solo_xy.cfg")


def test_a_character_class_is_refused_by_its_opening_bracket():
    """`Boot[MS]*.cfg` carries both brackets, so a rule watching for the CLOSING
    one reads that row identically — and `[` is what makes `case` expand."""
    assert any("carries a character class" in p
               for p in findings("Boot[MS*.cfg RED -\n" + REGISTRY))


def test_an_indented_row_is_still_a_row():
    """`read` strips leading IFS whitespace, so the runner reads an indented row
    like any other; a parser that skipped one would be holding a different file.
    No row is indented today, which is what makes the rule droppable in silence."""
    assert any("matches no configuration" in p
               for p in findings("    Gone_*.cfg RED -\n" + REGISTRY))


def test_first_match_wins_is_unexercisable_on_this_tree():
    """Said out loud rather than given a faked case. "First match wins" is
    `floors.txt`'s own header line and NOTHING here can tell it from last-match:
    two rows over one configuration are refused as a conflict when they disagree
    and reported as a masked row when they do not, and the conflict message names
    `hits[0]` and `hits[1:]` rather than the resolution. Measured: no
    configuration is matched by more than one row. The assertion is the reason —
    if a pair ever overlaps, this goes red and the claim gets a case or goes."""
    _, every = verdict_gate.resolve(ROWS, sorted(p.name for p in FORMAL.glob("*.cfg")))
    overlapping = {name: [row["pattern"] for row in hits]
                   for name, hits in every.items() if len(hits) > 1}
    assert not overlapping, overlapping


def test_a_malformed_row_is_a_finding_rather_than_a_traceback():
    """Each of these reaches an `int()` or an index if its own branch goes."""
    assert any("expected `<config or glob>" in p for p in findings("Lonely.cfg\n" + REGISTRY))
    assert any("floor must be a count" in p
               for p in findings(rewrite("Seams.cfg", "Seams.cfg GREEN lots")))
    assert any("expected `@Name <integer>`" in p
               for p in findings("@TraceSecurityGatesMin seven\n" + REGISTRY))
    assert any("recorded twice" in p
               for p in findings("@TraceSecurityGatesMin 1\n" + REGISTRY))


def test_the_configuration_floor_catches_a_glob_that_found_nothing(tmp_path):
    """The shape five guards in this tree shipped with: every loop runs over an
    empty set and the row reads as a pass.

    And the same tree is the only one that reaches the missing-`BASELINE` branch,
    so it is asserted here rather than left driven-but-unread: every `Fix*` arm is
    compared against `Shipped.cfg`, and without it they are compared against
    nothing — the same shrug the derivation was refused for.
    """
    problems, _ = verdict_gate.audit(tmp_path, registry_text=REGISTRY,
                                     previous_text=PREVIOUS, runner_text=RUNNER)
    assert any(f"under the floor of {verdict_gate.CONFIG_FLOOR}" in p for p in problems)
    assert any("no such configuration, so a `Fix*` constant" in p for p in problems), problems[:3]


# --- the row as the gate runs it -------------------------------------------
#
# Everything above calls `audit()`, so the row's EXIT CODE — the only thing
# the runner reads — was held by nothing: `run()`'s `return 1` turned into
# `return 0` survived the whole table, printing all fourteen findings and passing
# the row. Nor was `decoded()` ever on the path, because a case that hands the
# registry over as TEXT cannot exercise the read that keeps its bytes.


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True)


@pytest.fixture
def checkout(tmp_path):
    """The smallest tree the real script resolves itself against.

    Two committed registries, because the floor comparison walks back to the
    newest one that DIFFERS: with a single commit it would compare the file with
    itself and report that instead. The older one is WEAKER, so the tree under
    test has risen rather than fallen and no floor-decrease marker is owed.
    """
    root = tmp_path / "checkout"
    (root / "scripts").mkdir(parents=True)
    (root / "formal").mkdir()
    shutil.copy(HERE / "verdict_gate.py", root / "scripts" / "verdict_gate.py")
    shutil.copy(FORMAL / "run-tlc.sh", root / "formal" / "run-tlc.sh")
    for cfg in FORMAL.glob("*.cfg"):
        shutil.copy(cfg, root / "formal" / cfg.name)
    registry = root / "formal" / "floors.txt"
    git(root, "init", "-q")
    for text in (rewrite("Shipped.cfg", "Shipped.cfg GREEN 10000000"), REGISTRY):
        registry.write_text(text, encoding="utf-8")
        git(root, "add", "formal/floors.txt")
        git(root, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
            "commit", "-q", "-m", "registry")
    return root


def gate(root, *args):
    return subprocess.run([sys.executable, str(root / "scripts" / "verdict_gate.py"), *args],
                          capture_output=True, text=True, check=False)


def test_the_script_passes_over_a_registry_that_holds(checkout):
    """The control. Without it every case below is satisfied by a row that can
    only fail."""
    done = gate(checkout)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "verdict-gate: ok —" in done.stdout


def test_the_script_exits_non_zero_and_names_the_weakening(checkout):
    """The measured miss, driven through `main()` this time — and the report is
    read, not just its length: `REPORT_LIMIT` at 0 prints `N finding(s)` naming
    none of them, which is a row whose output tells a reader nothing."""
    (checkout / "formal" / "floors.txt").write_text(
        rewrite("SeamMut_*.cfg", "SeamMut_*.cfg GREEN 999999"), encoding="utf-8")
    done = gate(checkout)
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert "SeamMut_BugSigPinNotSpent.cfg" in done.stderr, done.stderr
    assert "owes RED" in done.stderr, done.stderr


def test_the_script_reads_the_registry_bytes_rather_than_its_text(checkout):
    """`decoded()` is one of the six review fixes and the only one nothing held.
    On disk it is the difference between the runner comparing a floor of `200`
    and one of `200\\r` — which errors, and bash reads as "not below the floor"."""
    (checkout / "formal" / "floors.txt").write_bytes(REGISTRY.replace("\n", "\r\n").encode())
    done = gate(checkout)
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert "carries a CR" in done.stderr, done.stderr


def test_the_script_takes_no_argument(checkout):
    done = gate(checkout, "--all")
    assert done.returncode == 2, (done.stdout, done.stderr)
    assert "usage:" in done.stderr


#: The two files that quote the pre-fix reading above. It was transcribed into
#: both by the commit that fixed the defect, and nothing has ever compared them.
QUOTED_IN = ("formal/README.md", "scripts/test_verdict_gate.py")
QUOTE = re.compile(r"`ok — (\d+) configuration\(s\)`")


def test_the_pre_fix_reading_is_quoted_with_one_number_in_both_places():
    """A historical quotation's whole evidentiary value is that it is unchanged,
    and this one was changed — by a bulk retype of every `191` on the page when
    the roster grew to 196. Five of the six lines it moved were live claims about
    the tree and were right to move; the sixth was this, and it went to a number
    that was never true of anything: the derivation that printed it was fixed
    when `formal/` held 192 configurations, and 192 - 1 exempt is 191.

    The copy in this file survived only because no sweep reaches `scripts/`. So
    the guard is the pair, not either one: the same measurement, quoted twice,
    has to carry the same number.
    """
    said = {rel: set(QUOTE.findall((ROOT / rel).read_text())) for rel in QUOTED_IN}
    assert all(len(v) == 1 for v in said.values()), said
    assert len(set().union(*said.values())) == 1, said


def test_the_baseline_row_quotes_this_gate_live_summary():
    """The sibling of the case in `test_config_gen_gate.py`, for the other
    mutation table on the same page: `formal/README.md` opens it with a `the
    tree as it stands` row quoting this row's live summary, and only the gate
    moves it when the tree does. Both rotted; neither was compared to anything.
    """
    body = verdict_gate.audit()[1].split("ok — ", 1)[1]
    assert body in (ROOT / "formal/README.md").read_text(), body
