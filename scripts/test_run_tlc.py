# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Mutation table for the formal runner's verdict boundary.

TLC itself is the slow system under test in the weekly job. These cases replace
its output stream and the directories its log and its scratch land in — nothing
else — then drive
the real runner, floors and configurations so each silent-pass shape is
permanently reproducible in the merge gate. The directory is not a detail: this
file used to write into the real `formal/out/`, so it truncated the log of any
real run beside it and left a NUL hole where that run kept writing.

TWO DENOMINATORS COUNT `formal/floors.txt`, and `5fb1e9c`'s message mixed them.
NON-COMMENT NON-BLANK rows include the `@TraceSecurity*Min` ratchets; rows whose
SECOND FIELD is `RED`/`GREEN` do not. Re-measured, in that order: 77abdd3 61 and
55, aacd7ed 67 and 61, 95b850d 70 and 64 — with 7, 9 and 9 of them carrying an
invariant column. So "7 of 61" DID hold, at 77abdd3 under the first, and 7/55,
9/61, 9/64 hold under the second; the claim that the pair never held at any
revision is FALSE, and the queue item it came from was stale rather than made up.
Name the denominator before quoting either number.
"""

import os
import pathlib
import re
import subprocess
import tomllib

import pytest

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNNER = ROOT / "formal" / "run-tlc.sh"

GREEN = """\
100 states generated
100 distinct states found
The depth of the complete state graph search is 3.
Model checking completed. No error has been found.
"""

VACUOUS = """\
1 states generated
1 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
"""

RED = """\
10 states generated
10 distinct states found
The depth of the complete state graph search is 2.
Invariant NoAuthorizationBypass is violated.
"""

#: What an INDUCTIVE probe looks like: every successor is already an initial
#: state, so the search ends at depth 1 with more states generated than found.
INDUCTIVE = """\
22920 states generated
1000 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
"""

#: And what it looks like when a step LEFT the predicate: a second level, which
#: is the refutation of `IndInv /\ Next => IndInv'` whatever the invariants say.
NOT_INDUCTIVE = """\
10748 states generated
788 distinct states found
The depth of the complete state graph search is 2.
Model checking completed. No error has been found.
"""


#: Where the stand-in punches the NUL run. An environment variable cannot carry a
#: NUL byte, so the hole travels as a marker in the output plus a count beside it.
HOLE = "@@HOLE@@"


@pytest.fixture
def fake_tlc(tmp_path):
    jar = tmp_path / "tla2tools.jar"
    jar.touch()
    java = tmp_path / "java"
    java.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        # A real JVM dies on `-Xmx-`, and the heap column can now hold `-` as a
        # placeholder because a column follows it. Every row with one came back
        # "Could not create the Java Virtual Machine" — a RED for no reason at
        # all — so the stand-in refuses it too.
        "if '-Xmx-' in sys.argv:\n"
        "    sys.stderr.write('Error: Could not create the Java Virtual Machine.')\n"
        "    raise SystemExit(1)\n"
        # A java.io.tmpdir of the run's own, in the test's directory: SANY writes each
        # standard module there, and TLCs sharing the user's one parsed a half-written file.
        "tmp = [a.split('=', 1)[1] for a in sys.argv if a.startswith('-Djava.io.tmpdir=')]\n"
        "own = len(tmp) == 1 and os.path.isdir(tmp[0])\n"
        f"if not own or os.path.isabs(tmp[0]) and not tmp[0].startswith({str(tmp_path) + os.sep!r}):\n"
        "    print('stand-in refuses a TLC without a java.io.tmpdir of its own: ' + repr(tmp))\n"
        "    raise SystemExit(4)\n"
        # The metadir as the pinned jar (2.19) was measured to treat it: named after
        # the second under `states/` or `-metadir`, refused if that name exists, and
        # left behind by a run refuted in its initial state.
        "stamp = os.environ.get('FAKE_TLC_STAMP')\n"
        "if stamp:\n"
        "    root = sys.argv[sys.argv.index('-metadir') + 1] if '-metadir' in sys.argv else 'states'\n"
        # And never outside the test's own directory, whatever a cut runner hands it.
        f"    if os.path.isabs(root) and not root.startswith({str(tmp_path) + os.sep!r}):\n"
        "        print('stand-in refuses a metadir outside its test: ' + root)\n"
        "        raise SystemExit(3)\n"
        "    meta = os.path.join(root, stamp)\n"
        "    if os.path.exists(meta):\n"
        "        print('This directory should be ' + os.path.abspath(meta) + ', but that directory already exists.')\n"
        "        raise SystemExit(1)\n"
        "    os.makedirs(meta)\n"
        f"head, _, tail = os.environ['FAKE_TLC_OUTPUT'].partition({HOLE!r})\n"
        "out = sys.stdout.buffer\n"
        "out.write(head.encode())\n"
        "out.write(b'\\0' * int(os.environ['FAKE_TLC_HOLE']))\n"
        # The mechanism itself, in one line: a SECOND O_TRUNC open on the log
        # this process still holds. Its own next write then lands at the offset
        # it had before, and everything between is a hole — which is the NULs.
        "if os.environ['FAKE_TLC_TRUNCATE']:\n"
        "    out.flush()\n"
        "    open(os.environ['FAKE_TLC_TRUNCATE'], 'w').close()\n"
        "out.write(tail.encode() + b'\\n')\n"
        "if stamp and not os.environ.get('FAKE_TLC_LEAVES_METADIR'):\n"
        "    os.rmdir(meta)\n"
    )
    java.chmod(0o755)
    return jar, java, tmp_path / "out", tmp_path / "states"


def run(
    fake_tlc,
    cfg: str,
    output: str,
    jar: pathlib.Path | None = None,
    hole: int = 0,
    truncate: pathlib.Path | None = None,
    coverage: bool = False,
    runner: pathlib.Path | None = None,
    stamp: str = "",
    leaves: bool = False,
    shard: str = "",
):
    real_jar, java, out, states = fake_tlc
    env = {
        **os.environ,
        "COVERAGE": "1" if coverage else "0",
        "JAVA": str(java),
        "TLA2TOOLS_JAR": str(jar or real_jar),
        "FAKE_TLC_OUTPUT": output,
        "FAKE_TLC_HOLE": str(hole),
        "FAKE_TLC_TRUNCATE": str(truncate or ""),
        "FAKE_TLC_STAMP": stamp,
        # Unset unless a case asks for one, so every other row drives the runner
        # exactly as a local `./run-tlc.sh safety` does.
        **({"TLC_SHARD": shard} if shard else {}),
        "FAKE_TLC_LEAVES_METADIR": "1" if leaves else "",
        # Not `formal/out/`: these cases drive the REAL runner, so writing there
        # truncates the log of whatever real TLC run is in flight beside them —
        # which is the hole these cases are named for, and cost a standing rule.
        "TLC_OUT": str(out),
        # And for the same reason TLC's scratch: the runner makes a directory there.
        "TLC_STATES": str(states),
    }
    script = runner or RUNNER
    return subprocess.run(
        [str(script), cfg],
        cwd=script.parent,
        env=env,
        capture_output=True,
        text=True,
    )


def test_broken_jar_path_fails_before_tlc(fake_tlc, tmp_path):
    result = run(fake_tlc, "Shipped.cfg", GREEN, tmp_path / "missing.jar")
    assert result.returncode == 2
    assert "not readable" in result.stderr


def test_broken_shipped_invariant_is_red(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", RED)
    assert result.returncode == 1
    assert "RED: NoAuthorizationBypass" in result.stdout
    assert "expected GREEN" in result.stdout


def test_one_state_model_is_vacuous_not_green(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", VACUOUS)
    assert result.returncode == 1
    assert "VACUOUS: nothing was enabled" in result.stdout
    assert "expected GREEN" in result.stdout


def test_floor_regression_is_not_green(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", GREEN)
    assert result.returncode == 1
    assert "FLOOR: 100 < 36206318" in result.stdout
    assert "expected GREEN" in result.stdout


def test_an_induction_probe_at_depth_one_is_green_and_not_vacuous(fake_tlc):
    """Depth 1 is what INDUCTIVE looks like, not what vacuity looks like.

    Every successor of an `INIT IndInv` run is already an initial state, so the
    search terminates immediately. The generic rule reads that as nothing having
    been enabled and would refuse every such row.
    """
    result = run(fake_tlc, "StoreInduction.cfg", INDUCTIVE)
    assert result.returncode == 0
    assert "GREEN" in result.stdout


def test_an_induction_probe_whose_step_left_the_predicate_is_refused(fake_tlc):
    """Depth 2 means a successor was NOT an initial state, which is the whole
    claim failing — and the INVARIANTS block need not have noticed, because a
    conjunct of `IndInv` is not necessarily one of them."""
    result = run(fake_tlc, "StoreInduction.cfg", NOT_INDUCTIVE)
    assert result.returncode == 1
    assert "NOT INDUCTIVE" in result.stdout


def test_the_exemption_does_not_reach_an_ordinary_specification(fake_tlc):
    """`Shipped.cfg` has no `INIT` line, so the depth floor still binds it."""
    result = run(fake_tlc, "Shipped.cfg", INDUCTIVE)
    assert result.returncode == 1
    assert "VACUOUS: nothing was enabled" in result.stdout


def test_invariant_that_stops_catching_its_solo_mutant_is_rejected(fake_tlc):
    result = run(fake_tlc, "Solo_BugResetGatesFirst.cfg", GREEN)
    assert result.returncode == 1
    assert "GREEN" in result.stdout
    assert "expected RED" in result.stdout


def test_mutant_that_stops_firing_is_rejected(fake_tlc):
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", GREEN)
    assert result.returncode == 1
    assert "GREEN" in result.stdout
    assert "expected RED" in result.stdout


#: A RED naming an invariant whose name carries a DIGIT. `[A-Za-z]+` matched none
#: of the nine trace rows for the whole life of the runner, so their verdict
#: column printed the raw error line and read RED coarsely — invisible until the
#: name started being compared.
RED_R4C = """\
37 states generated
37 distinct states found
The depth of the complete state graph search is 37.
Error: Invariant R4cGateAnswers is violated.
"""

RED_R4A = RED_R4C.replace("R4cGateAnswers", "R4aRawRefinesB")


def test_an_invariant_name_with_a_digit_is_read(fake_tlc):
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4C)
    assert result.returncode == 0
    assert "RED: R4cGateAnswers" in result.stdout


def test_a_red_for_the_wrong_invariant_is_rejected(fake_tlc):
    """The colour is right and the reason is not — 2 of 24 co-refutation patches
    in this tree scored a kill that way. Measured on this very row: flipping the
    alwaysUv mutant to the INVERSE defect kept it red at a different boundary."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4A)
    assert result.returncode == 1
    assert "expected RED: R4cGateAnswers" in result.stdout


#: `Mut_BugResetGatesFirst.cfg` targets `ResetNeverWeakensSurvivingState` and
#: says so first under its own INVARIANTS. These three are the same run reddening
#: on that name, on a DIFFERENT invariant of the same block, and on `TypeOK`.
RED_TARGET = RED.replace("NoAuthorizationBypass", "ResetNeverWeakensSurvivingState")
RED_TYPEOK = RED.replace("NoAuthorizationBypass", "TypeOK")

#: A refusal that names no invariant at all: what `TraceSeamsBad.cfg` produces,
#: and what a mutant producing it instead of its invariant would produce too.
RED_DEADLOCK = """\
2 states generated
2 distinct states found
The depth of the complete state graph search is 2.
Error: Deadlock reached.
"""

#: A temporal refutation. TLC does not print `Invariant … is violated` for one,
#: so no name can be derived and none is demanded.
RED_PROPERTY = """\
1475 states generated
497 distinct states found
The depth of the complete state graph search is 6.
Error: Temporal properties were violated.
"""


def test_a_mutant_reddening_on_its_own_target_passes(fake_tlc):
    """The floors row names nothing; the configuration does."""
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", RED_TARGET)
    assert result.returncode == 0
    assert "RED: ResetNeverWeakensSurvivingState" in result.stdout


def test_a_mutant_reddening_on_another_invariant_is_rejected(fake_tlc):
    """The colour is right and the reason is not, on a row floors.txt leaves
    blank — 168 of the 177 RED rows are that row, so this was the shape the
    comparison skipped on 95% of them."""
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", RED)
    assert result.returncode == 1
    assert "expected RED: ResetNeverWeakensSurvivingState" in result.stdout


def test_a_mutant_reddening_on_typeok_is_rejected(fake_tlc):
    """`TypeOK` is checked by every configuration and targeted by no mutant, so
    a RED there attributes the failure to nothing at all."""
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", RED_TYPEOK)
    assert result.returncode == 1
    assert "expected RED: ResetNeverWeakensSurvivingState" in result.stdout


def test_a_mutant_refused_without_naming_an_invariant_is_rejected(fake_tlc):
    """A mutant that deadlocks instead of breaking what it models is the same
    wrong-reason RED wearing a different error line."""
    result = run(fake_tlc, "Solo_BugResetGatesFirst.cfg", RED_DEADLOCK)
    assert result.returncode == 1
    assert "expected RED: ResetNeverWeakensSurvivingState" in result.stdout


def test_a_deadlock_row_with_no_switch_armed_is_not_held_to_a_name(fake_tlc):
    """`TraceSeamsBad.cfg` lists six invariants and is refused by a DEADLOCK: no
    defect switch is armed in it, so the first name in its block describes
    nothing it does. Deriving there would demand a name no run of it can print,
    so it is held to the SHAPE of the refusal instead — and this is that shape."""
    result = run(fake_tlc, "TraceSeamsBad.cfg", RED_DEADLOCK)
    assert result.returncode == 0
    assert "RED: Error: Deadlock reached." in result.stdout


#: The rest of the shape rule, driven on the row it exists for. `TypeOK` is in
#: `TraceSeamsBad.cfg`'s own INVARIANTS block, so a "names some invariant it
#: checks" rule accepts this and only the shape refuses it.
NO_SWITCH_ARMED = "  !! expected RED on a deadlock or a property this configuration declares"


def test_a_zero_armed_row_reddening_on_typeok_is_rejected(fake_tlc):
    """Nothing compared these rows at all: a `TraceSeamsBad.cfg` whose harness
    broke instead of refusing the session reported RED and exited 0."""
    result = run(fake_tlc, "TraceSeamsBad.cfg", RED_TYPEOK)
    assert result.returncode == 1
    assert NO_SWITCH_ARMED in result.stdout


def test_a_zero_armed_row_reddening_on_an_invariant_it_checks_is_rejected(fake_tlc):
    """And not only on `TypeOK`. With no switch armed the configuration models no
    defect, so no name in its block attributes the RED to anything — which is why
    the rule here is a shape and not the two-armed rows' narrowed name set."""
    result = run(
        fake_tlc, "TraceSeamsBad.cfg",
        RED.replace("NoAuthorizationBypass", "NoStatusOutsideItsSelection"),
    )
    assert result.returncode == 1
    assert NO_SWITCH_ARMED in result.stdout


#: A configuration arming TWO defects: `Mut_BugSetPinKeepsPpuat.cfg` needs its
#: companion switch on, because the shipped seed-lead makes its own defect
#: unreachable alone. `NoAccessibleSecretWithoutGate` is the companion's target and
#: is what a real run of it reports — measured, at depth 13 against its own
#: invariant's 15, so TLC halts on the shallower one.
RED_COMPANION = RED.replace("NoAuthorizationBypass", "NoAccessibleSecretWithoutGate")


def test_a_two_armed_mutant_may_redden_on_either_switch(fake_tlc):
    """Its first-listed name is the generator's intent, not a prediction: with a
    second defect on, the state TLC finds first can violate the other one."""
    result = run(fake_tlc, "Mut_BugSetPinKeepsPpuat.cfg", RED_COMPANION)
    assert result.returncode == 0
    assert "RED: NoAccessibleSecretWithoutGate" in result.stdout


#: What the two-armed rows are held to now: a name one of their OWN switches
#: targets, read off that switch's solo twin. Both `Mut_` rows check six
#: invariants and their switches target two, so "an invariant this configuration
#: checks" was accepting four names nothing in the row is about.
NOT_A_TARGET = "  !! expected RED on an invariant one of its armed switches targets"


def test_a_two_armed_mutant_reddening_on_typeok_is_still_rejected(fake_tlc):
    """What it may NOT do. `TypeOK` is checked by every configuration and targeted
    by neither switch, so a RED there attributes the failure to nothing."""
    result = run(fake_tlc, "Mut_BugSetPinKeepsPpuat.cfg", RED_TYPEOK)
    assert result.returncode == 1
    assert NOT_A_TARGET in result.stdout


def test_a_two_armed_mutant_refused_without_an_invariant_is_rejected(fake_tlc):
    """…nor may it deadlock instead of breaking something it checks."""
    result = run(fake_tlc, "Mut_BugSetPinKeepsPpuat.cfg", RED_DEADLOCK)
    assert result.returncode == 1
    assert NOT_A_TARGET in result.stdout


#: The two names inside its own block that NEITHER armed switch is about.
#: `Mut_BugSetPinKeepsPpuat.cfg` arms `BugSetPinKeepsPpuat` (whose solo twin
#: checks `NoTokenAfterInvalidation`) and `BugPpuatIsAGate` (whose twin checks
#: `NoAccessibleSecretWithoutGate`); these are two of the other four.
RED_UNMANAGEABLE = RED.replace("NoAuthorizationBypass", "NoUnmanageableCredential")
RED_CROSS_TRANSPORT = RED.replace(
    "NoAuthorizationBypass", "NoCrossTransportTouchConsumption")


def test_a_two_armed_mutant_reddening_on_a_name_no_switch_targets_is_rejected(fake_tlc):
    """The gap the old rule left: `NoUnmanageableCredential` is one of the six
    this configuration checks, so it passed — while neither armed defect is about
    it, which makes the RED a kill for a reason the row does not model."""
    result = run(fake_tlc, "Mut_BugSetPinKeepsPpuat.cfg", RED_UNMANAGEABLE)
    assert result.returncode == 1
    assert NOT_A_TARGET in result.stdout


def test_the_same_gap_on_the_other_two_armed_mutant(fake_tlc):
    """A different configuration and a different name, so a rule that special-cases
    one of them does not pass here. `Mut_BugBackupSealedNotAGate.cfg` arms
    `BugBackupSealedNotAGate` and `BugSeedDoesNotLead`; touch consumption is
    neither one's target and is in the block all the same."""
    result = run(fake_tlc, "Mut_BugBackupSealedNotAGate.cfg", RED_CROSS_TRANSPORT)
    assert result.returncode == 1
    assert NOT_A_TARGET in result.stdout


def test_a_two_armed_mutant_may_redden_on_either_switch_s_own_target(fake_tlc):
    """THE CONTROL. Which of two armed defects TLC halts on is a property of the
    search, not of the tree: `NoAccessibleSecretWithoutGate` is the recorded one
    and `NoTokenAfterInvalidation` is this row's own first-listed name. Both are a
    switch's target, so the guard is indifferent between them — a rule pinned to
    the observed name would refuse this and call a scheduler a regression."""
    result = run(fake_tlc, "Mut_BugSetPinKeepsPpuat.cfg",
                 RED.replace("NoAuthorizationBypass", "NoTokenAfterInvalidation"))
    assert result.returncode == 0
    assert "RED: NoTokenAfterInvalidation" in result.stdout


def test_the_other_two_armed_mutant_reddening_on_its_own_target_passes(fake_tlc):
    """And the recorded verdict of the second row, so the narrowing is shown not
    to have reddened the run it was derived from."""
    result = run(fake_tlc, "Mut_BugBackupSealedNotAGate.cfg", RED_TARGET)
    assert result.returncode == 0
    assert "RED: ResetNeverWeakensSurvivingState" in result.stdout


def test_a_solo_row_arming_two_switches_keeps_its_one_name(fake_tlc):
    """`Solo_BugSetPinKeepsPpuat.cfg` arms the same pair and checks ONE invariant,
    so the intersection is narrower than the twins' set rather than equal to it —
    the third shape the narrowing has to get right, and its recorded verdict."""
    result = run(fake_tlc, "Solo_BugSetPinKeepsPpuat.cfg",
                 RED.replace("NoAuthorizationBypass", "NoTokenAfterInvalidation"))
    assert result.returncode == 0
    assert "RED: NoTokenAfterInvalidation" in result.stdout


def test_a_clause_row_falls_back_to_the_invariant_it_names(fake_tlc):
    """`SoloClause_ResetKeepsTheBackupSeal.cfg` checks ONE CLAUSE of an invariant,
    and no solo twin of either armed switch can name a clause — so the two sets
    do not meet and the fallback is what keeps the row satisfiable at all."""
    result = run(fake_tlc, "SoloClause_ResetKeepsTheBackupSeal.cfg",
                 RED.replace("NoAuthorizationBypass", "ResetKeepsTheBackupSeal"))
    assert result.returncode == 0
    assert "RED: ResetKeepsTheBackupSeal" in result.stdout


#: A run refuted by a temporal PROPERTY of a configuration that also checks an
#: invariant. `TokenRefinementDeadToken.cfg` is that shape: one invariant, one
#: property, and RED on the property by design — the state stutter it models is
#: legal and the outcome is not.
RED_ACTION_PROPERTY = """\
2 states generated
2 distinct states found
The depth of the complete state graph search is 2.
Error: Action property R1oTokenOutcomes is violated.
"""


def test_a_property_the_configuration_declares_is_a_right_reason(fake_tlc):
    """The false alarm this rule raised the first time it ran a whole tier: the
    derived name is an INVARIANT, the refutation names a PROPERTY, and the two
    are not alternatives — a configuration may declare both and be red on either."""
    result = run(fake_tlc, "TokenRefinementDeadToken.cfg", RED_ACTION_PROPERTY)
    assert result.returncode == 0
    assert "R1oTokenOutcomes" in result.stdout


def test_a_property_the_configuration_does_not_declare_is_still_wrong(fake_tlc):
    """…and the carve-out is about the names the configuration itself declares,
    not about the words `Action property` appearing in the line."""
    other = RED_ACTION_PROPERTY.replace("R1oTokenOutcomes", "SomethingElseEntirely")
    result = run(fake_tlc, "TokenRefinementDeadToken.cfg", other)
    assert result.returncode == 1
    assert "expected RED: R1oOutcomeCoverage" in result.stdout


def test_a_properties_only_row_is_not_held_to_an_invariant(fake_tlc):
    """`LiveMut_*` check temporal properties and no invariant beyond `TypeOK`;
    the runner reads `Invariant … is violated` and nothing else, so there is no
    name to compare and demanding one would refuse every such row."""
    result = run(fake_tlc, "LiveMut_BugWalkNeverExpires.cfg", RED_PROPERTY)
    assert result.returncode == 0
    assert "RED: Error: Temporal properties were violated." in result.stdout


def test_a_placeholder_heap_does_not_reach_the_jvm(fake_tlc):
    """The row that exposed it: `RED - - <invariant>` gives `heap` the string
    `-`, and `-Xmx-` is not a heap."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4C)
    assert "Could not create the Java Virtual Machine" not in result.stdout
    assert result.returncode == 0


#: What two writers leave on one path: the second's truncation resets the size,
#: the first writes on at its now-stale offset, and the gap between is NUL. The
#: shape is the measured one — the merge gate's own fixture above 1550 NULs at
#: offset 153, one straddled line, and the real run's own output from there on.
HOLED_GREEN = f"""\
22920 states generated
1000 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
{HOLE}states left on queue.
699350223 states generated
48679968 distinct states found
The depth of the complete state graph search is 55.
Model checking completed. No error has been found.
"""


def test_a_hole_in_the_log_does_not_turn_a_green_run_vacuous(fake_tlc):
    """One NUL byte makes grep call the whole log binary and match nothing, so
    every field comes back empty and the `< 2` rule fires over 48.7 M distinct
    states. Both implementations get it wrong and disagree on how: GNU sends
    `binary file matches` to stderr and the columns read `?`, BSD sends it to
    stdout and they read `Binary`. Fails safe, which is why it survived."""
    result = run(fake_tlc, "Shipped.cfg", HOLED_GREEN, hole=1550)
    assert result.returncode == 0
    assert "VACUOUS" not in result.stdout
    assert "states=699350223" in result.stdout
    assert "distinct=48679968" in result.stdout
    assert "depth=55" in result.stdout


#: The same hole under the other verdict branch, and under the one reader that
#: only `COVERAGE=1` reaches. Blinding either is a silent PASS, not a false red:
#: an unnamed RED still reads RED, and an unreported dead action reads GREEN.
HOLED_RED = f"""\
22920 states generated
1000 distinct states found
{HOLE}states left on queue.
37 states generated
37 distinct states found
The depth of the complete state graph search is 37.
Error: Invariant R4cGateAnswers is violated.
"""

HOLED_DEAD_ACTION = HOLED_GREEN.replace(
    "699350223 states generated",
    "<SetPin line 214, col 3 to line 219, col 41 of module RSKeySecurityState>: 0:0\n"
    "699350223 states generated",
)


def test_a_hole_does_not_cost_a_red_row_its_invariant_name(fake_tlc):
    """`-a` on the fields alone leaves this one blind, and the row still prints
    RED — the colour is right and the reason is gone, which is the shape that
    let nine trace rows compare nothing for their whole life."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", HOLED_RED, hole=1550)
    assert result.returncode == 0
    assert "RED: R4cGateAnswers" in result.stdout


def test_a_hole_does_not_hide_a_dead_action(fake_tlc):
    """The reader only `COVERAGE=1` reaches. An action that never fired makes
    every clause guarding it free, and a blinded grep reports none."""
    result = run(fake_tlc, "Shipped.cfg", HOLED_DEAD_ACTION, hole=1550, coverage=True)
    assert result.returncode == 1
    assert "DEAD ACTION in Shipped.cfg -- never fired: SetPin" in result.stderr


def test_a_second_writer_cannot_punch_a_hole_in_a_live_log(fake_tlc):
    """And the mechanism, not just its symptom, because `-a` is only a backstop:
    a hole that straddles a line takes that line with it whatever grep does. The
    log is truncated at open and APPENDED to, so a second writer's truncation
    leaves the first with no stale offset to write at."""
    log = fake_tlc[2] / "Shipped.log"
    result = run(fake_tlc, "Shipped.cfg", HOLED_GREEN, truncate=log)
    body = log.read_bytes()
    assert b"\0" not in body
    # Not decoration: the truncation above CREATES this path, so a runner writing
    # its log somewhere else entirely would leave an empty file here and satisfy
    # the line above. Measured — that mutant survived until this line was added.
    assert b"Model checking completed" in body
    assert result.returncode == 0


#: A RED naming an invariant no module defines. `TypeOK` is the wrong reason that
#: is real; this is the wrong reason that cannot even be spelled, and a rule that
#: catches one but not the other is reading the name rather than checking it.
RED_UNDEFINED = RED.replace("NoAuthorizationBypass", "ZzzNoModuleDefinesThis")

#: The inline action property TLC reports by SOURCE LOCATION instead of by name,
#: which is what `TokenRefinementBadMap.cfg` really produces — read off
#: `formal/out/TokenRefinementBadMap.log:22` of the recorded safety run.
RED_ACTION_AT_LINE = """\
1405 states generated
483 distinct states found
The depth of the complete state graph search is 6.
Error: Action property line 130, col 17 to line 130, col 30 of module RSKeyTokenAbstract is violated.
"""

#: And the third form: TLC naming the action property it refuted. Already seen on
#: `TokenRefinementDeadToken.cfg`, so a `LiveMut_*` whose property became an
#: action property would print this and must not be refused for it.
RED_NAMED_WALK = """\
619628 states generated
97271 distinct states found
The depth of the complete state graph search is 9.
Error: Action property EveryWalkCloses is violated.
"""

NO_PROPERTY = "  !! expected RED on a property this configuration declares"

#: The four rows that check NO invariant at all. They declare a temporal property
#: and nothing else, so `derived_inv` has no name to return, `armed_n` is 1, and
#: every rule above skipped them: measured, each one accepted a RED on `TypeOK`,
#: on a name no module defines, and on a deadlock. Three of them are the whole
#: mutation half of the liveness tier.
PROPERTIES_ONLY = [
    "LiveMut_BugAssertWedgesOnTimeout.cfg",
    "LiveMut_BugWaitScopeNotCleared.cfg",
    "LiveMut_BugWalkNeverExpires.cfg",
    "TokenRefinementBadMap.cfg",
]


@pytest.mark.parametrize("cfg", PROPERTIES_ONLY[:3])
def test_a_properties_only_mutant_refuted_by_its_property_passes(fake_tlc, cfg):
    """THE CONTROL. Their recorded verdict, which TLC writes without naming which
    property fell — so the shape is all there is to hold these rows to."""
    result = run(fake_tlc, cfg, RED_PROPERTY)
    assert result.returncode == 0
    assert "RED: Error: Temporal properties were violated." in result.stdout


def test_an_inline_action_property_is_a_right_reason(fake_tlc):
    """The other recorded shape: `TokenRefinementBadMap.cfg`'s property is inline,
    so TLC reports it by source location and there is no name to compare."""
    result = run(fake_tlc, "TokenRefinementBadMap.cfg", RED_ACTION_AT_LINE)
    assert result.returncode == 0
    assert "RED: Error: Action property line 130" in result.stdout


def test_a_named_property_of_a_properties_only_row_is_a_right_reason(fake_tlc):
    """And the third: TLC names an action property when it can. Refusing this
    would red a row for producing the most informative answer of the three."""
    result = run(fake_tlc, "LiveMut_BugWalkNeverExpires.cfg", RED_NAMED_WALK)
    assert result.returncode == 0
    assert NO_PROPERTY not in result.stdout


@pytest.mark.parametrize("cfg", PROPERTIES_ONLY)
@pytest.mark.parametrize(
    "output",
    [RED_TYPEOK, RED_UNDEFINED, RED_DEADLOCK],
    ids=["typeok", "undefined-invariant", "deadlock"],
)
def test_a_properties_only_mutant_reddening_on_anything_else_is_rejected(
    fake_tlc, cfg, output
):
    """Defect 1's shape in the rows its fix did not reach. The derived name came
    off the INVARIANTS block, and these four have none — so the colour was the
    only thing ever compared, and a mutant that broke the type system or wedged
    instead of refuting its property was a kill."""
    result = run(fake_tlc, cfg, output)
    assert result.returncode == 1
    assert NO_PROPERTY in result.stdout


def test_a_property_a_properties_only_row_does_not_declare_is_still_wrong(fake_tlc):
    """The shape is not `Action property` appearing in the line: the name, when
    TLC gives one, is compared against what this configuration declares."""
    result = run(
        fake_tlc,
        "LiveMut_BugWalkNeverExpires.cfg",
        RED_NAMED_WALK.replace("EveryWalkCloses", "EveryWaitReleases"),
    )
    assert result.returncode == 1
    assert NO_PROPERTY in result.stdout


def _recorded_rows() -> dict[str, str]:
    """Each configuration's row from `formal/runs.toml`'s `matrix` blocks, minus
    its name: the runner's own unedited output, which is the only place in the
    tree that records what TLC actually said on these four."""
    runs = tomllib.loads((ROOT / "formal" / "runs.toml").read_text())
    rows = {}
    for recorded in runs["run"]:
        for line in recorded["matrix"].splitlines():
            cfg, _, rest = line.partition(" ")
            if "states=" in rest:
                rows[cfg] = rest
    return rows


@pytest.mark.parametrize("cfg", PROPERTIES_ONLY)
def test_the_recorded_verdict_of_a_properties_only_row_is_accepted(fake_tlc, cfg):
    """THE ORACLE, FROM THE RECORDING AND NOT FROM A SECOND TRANSCRIPTION.

    The two shapes `refuted_by_a_property` accepts exist as two independent
    hand-typed copies — one in `run-tlc.sh`, one in the constants above — and
    NEITHER derives from `formal/runs.toml`. A TLC phrasing change moves both
    together, so every accepting case here keeps passing over a runner that would
    refuse the real thing: the oracle is one-sided against the tool. This drives
    each row's recorded verdict back through the shipped runner, which puts both
    sides on the recording.
    """
    verdict, _, counts = _recorded_rows()[cfg].partition("states=")
    verdict = verdict.strip()
    assert verdict.startswith("RED: "), f"{cfg}: recorded as {verdict!r}"
    states, distinct = re.match(r"(\d+)\s+distinct=(\d+)", counts).groups()
    result = run(fake_tlc, cfg, f"{states} states generated\n"
                               f"{distinct} distinct states found\n"
                               f"{verdict.removeprefix('RED: ')}\n")
    assert result.returncode == 0
    assert verdict in result.stdout
    assert f"states={states}" in result.stdout


#: THE DELETION ARMS. One row per clause of the rule above, each naming the case
#: that falsifies it and the DIRECTION the mutant moves in — a guard that goes red
#: for the wrong reason proves as little as one that cannot go red, and this table
#: is the rule's own instance of that. `real` is what the shipped runner answers
#: and `mutated` is what the clause-less one answers; they must differ.
#:
#:
#: DIRECTION, because a kill in the wrong one proves nothing: eight of the nine
#: rows here and in `SHAPE_ARMS` move 0 -> 1, which is the PERMISSIVE direction —
#: cut an exemption and a legitimate row is refused. Only "the refusal itself"
#: moves 1 -> 0, the silent pass. That skew is inherent to falsifying exemptions,
#: not a gap: a clause that GRANTS one can only be falsified by losing it.
#:
#: Two of the three clauses this table used to call inert are in `SHAPE_ARMS`
#: below, which was the wrong reading rather than a missing row: they are
#: falsified by shapes the ROSTER has no member of, not by no shape at all.
#: `[ -z "${inv:-}" ]` is the one that stays, and it is DECORATIVE — kept for
#: symmetry with the sibling branch below it, which carries the same guard for
#: the same reason. No coherent falsifier exists: reaching it with a name set
#: takes a `floors.txt` row naming something for a configuration that checks no
#: invariant, and `verdict_gate.check_reasons` (scripts/verdict_gate.py:619-634)
#: refuses every filling of that column: `TypeOK`, a property name, and a name the
#: configuration does not check. Named as well as numbered on purpose: `EXTS` in
#: `citation_gate.py` gained `py` in the repair pass, so the span above is locked
#: by content now — but a lock reports a span that MOVED, and only the name says
#: what to look for once it has. What the widening still does not reach, measured
#: over the pages that gate opens: 270 matches across 12 pages into `.toml` (115),
#: `.tla` (78), `.md` (56), `.cfg` (16), `.yml` (4) and `.log` (1) — one of them
#: this file's own `.log`. That is 188 citations as written, or 233 by the key its
#: lock uses, one row per span per page — one blind spot counted two ways, and
#: `citation_gate.py`'s own comment carries both so the copies cannot drift apart.
#: `.c`, `.h` and `.S` are ZERO — but 107 `.sh`, `.py` and `.txt` citations on
#: those pages DO resolve: what is blind here is prose, not this tree's source.
DELETION_ARMS = [
    (
        "names_a_property",
        '  names_a_property "$1" "$2" && return 0\n',
        "",
        "LiveMut_BugWalkNeverExpires.cfg",
        RED_NAMED_WALK,
        0,
        1,
    ),
    (
        "the plain temporal shape",
        '    "RED: Error: Temporal properties were violated."*) return 0 ;;\n',
        "",
        "LiveMut_BugWalkNeverExpires.cfg",
        RED_PROPERTY,
        0,
        1,
    ),
    (
        "the source-located action property",
        '    "RED: Error: Action property line "*) return 0 ;;\n',
        "",
        "TokenRefinementBadMap.cfg",
        RED_ACTION_AT_LINE,
        0,
        1,
    ),
    (
        "the refusal itself",
        "  esac\n  return 1\n}",
        "  esac\n  return 0\n}",
        "LiveMut_BugWalkNeverExpires.cfg",
        RED_TYPEOK,
        1,
        0,
    ),
    (
        "the call to the shape predicate",
        '&& [ -z "$checks" ] && ! refuted_by_a_property "$cfg" "$verdict"; then',
        '&& [ -z "$checks" ]; then',
        "LiveMut_BugWalkNeverExpires.cfg",
        RED_PROPERTY,
        0,
        1,
    ),
    (
        "the has-no-invariant test",
        '&& [ -z "$checks" ] && ! refuted_by_a_property',
        "&& ! refuted_by_a_property",
        "Mut_BugBackupSealedNotAGate.cfg",
        RED_TARGET,
        0,
        1,
    ),
    (
        "reading the derived name once",
        '  checks=$(derived_inv "$cfg")',
        '  checks=""',
        "Mut_BugResetGatesFirst.cfg",
        RED_TARGET,
        0,
        1,
    ),
]


@pytest.fixture
def arena(tmp_path):
    """A copy of the runner in a directory of symlinks to the real model, so a
    clause can be cut out of the script CI runs without touching the tree — and
    the configurations, floors and lint it reads are still the shipped ones.

    `extra` writes configurations the roster has no member of. They go HERE and
    not in `formal/`, where `scripts/config_gen_gate.py` holds every `.cfg` to
    `gen-configs.sh`, `run-tlc.sh --tiers` holds it to a tier, and `floors.txt`
    would owe it a verdict — three owners for a file whose only purpose is to
    make one clause of one rule falsifiable."""

    def build(old: str = "", new: str = "", extra: dict | None = None):
        d = tmp_path / f"arena{len(list(tmp_path.glob('arena*')))}"
        d.mkdir()
        for f in (ROOT / "formal").iterdir():
            if f.suffix in (".cfg", ".tla") or f.name in ("floors.txt", "tla-lint.py"):
                (d / f.name).symlink_to(f)
        for name, text in (extra or {}).items():
            (d / name).write_text(text)
        src = RUNNER.read_text()
        if old:
            assert src.count(old) == 1, f"anchor moved: {old!r}"
            src = src.replace(old, new)
        script = d / "run-tlc.sh"
        script.write_text(src)
        script.chmod(0o755)
        return script

    return build


@pytest.fixture
def mutant(arena):
    """The `arena` above with no configuration added: the shipped roster and one
    clause cut."""
    return lambda old, new: arena(old, new)


@pytest.mark.parametrize(
    "label,old,new,cfg,output,real_rc,mutated_rc",
    DELETION_ARMS,
    ids=[a[0] for a in DELETION_ARMS],
)
def test_every_clause_of_the_property_rule_has_a_row_that_falsifies_it(
    fake_tlc, mutant, label, old, new, cfg, output, real_rc, mutated_rc
):
    """Cut one clause; the named configuration must change answer. Both codes are
    asserted, not just the mutant's: a clause whose deletion leaves the row red
    for a different reason would otherwise read as a kill."""
    assert run(fake_tlc, cfg, output).returncode == real_rc
    assert run(fake_tlc, cfg, output, runner=mutant(old, new)).returncode == mutated_rc


#: A properties-only configuration in one of the two shapes the roster has no
#: member of. `EveryWalkCloses` is a real property of the module and
#: `BugWalkNeverExpires` a real switch, so the only invented thing is the pairing.
def _properties_only(armed: bool) -> str:
    return (
        "\\* Written by scripts/test_run_tlc.py -- not a member of any tier.\n"
        "SPECIFICATION FairSpec\n"
        "CONSTANTS\n"
        '    RPs = {"r1"}\n'
        f"    BugWalkNeverExpires = {'TRUE' if armed else 'FALSE'}\n"
        "PROPERTIES\n"
        "    EveryWalkCloses\n"
    )


#: Neither name matches a glob in `floors.txt`, which is half of what each shape
#: needs: with no row to state a verdict, `want` is empty and the colour rule
#: above cannot fire first and mask the clause under test.
ZERO_ARMED = "ZeroArmedProperty.cfg"
ARMED_NO_FLOOR = "ArmedPropertyNoFloor.cfg"

#: THE SHAPE ARMS: the two clauses `DELETION_ARMS` cannot reach, because each is
#: falsified by a configuration the tree does not contain rather than by an output
#: the tree's own rows cannot produce.
SHAPE_ARMS = [
    (
        "the armed-count floor",
        ZERO_ARMED,
        _properties_only(armed=False),
        ' && [ "$armed_n" -ge 1 ] \\\n',
        " \\\n",
        RED_DEADLOCK,
    ),
    (
        "the colour test",
        ARMED_NO_FLOOR,
        _properties_only(armed=True),
        '  elif [ "$got" = RED ] && [ -z "${inv:-}" ] &&',
        '  elif [ -z "${inv:-}" ] &&',
        GREEN,
    ),
]


@pytest.mark.parametrize(
    "label,name,text,old,new,output", SHAPE_ARMS, ids=[a[0] for a in SHAPE_ARMS]
)
def test_the_two_clauses_the_roster_cannot_falsify_have_an_arm_of_their_own(
    fake_tlc, arena, label, name, text, old, new, output
):
    """Both were called inert and neither is.

    `[ "$armed_n" -ge 1 ]` is what keeps a zero-armed properties-only row on
    `refused_by_shape`, which accepts a deadlock, instead of on
    `refuted_by_a_property`, which does not. `[ "$got" = RED ]` is what keeps an
    armed properties-only row with no floors verdict from being refused while
    GREEN. The mark is asserted and not just the code: a clause whose deletion
    reddens the row somewhere else is not this clause's kill.
    """
    shipped = run(fake_tlc, name, output, runner=arena(extra={name: text}))
    assert shipped.returncode == 0
    assert NO_PROPERTY not in shipped.stdout

    cut = run(fake_tlc, name, output, runner=arena(old, new, {name: text}))
    assert cut.returncode == 1
    assert NO_PROPERTY in cut.stdout


#: A row refuted in its INITIAL state, then one that is not, both RED on the same
#: invariant: the first pair the lost safety tier failed on, back to back.
LEAVER = "SeamSolo_BugCodelessOathIsAStatus.cfg"
VICTIM = "SeamSolo_BugDeselectKeepsOathUnlock.cfg"
RED_SEAM = RED.replace("NoAuthorizationBypass", "NoStatusOutsideItsSelection")

#: One TLC second for every start, which is what sub-second mutants make of them.
STAMP = "26-09-16-15-45-59"


def _same_second(fake_tlc, runner):
    """The leaver, then the victim, in one second. In an arena, because a runner cut
    of its `-metadir` sends the stand-in to `states/` beside itself."""
    first = run(fake_tlc, LEAVER, RED_SEAM, runner=runner, stamp=STAMP, leaves=True)
    assert first.returncode == 0, first.stdout + first.stderr
    return run(fake_tlc, VICTIM, RED_SEAM, runner=runner, stamp=STAMP)


def _refused_in_a_tier(fake_tlc, runner):
    """Every row of `liveness` leaving its metadir, all in one second: the measured
    failure happened INSIDE one tier run, where every row shares the runner's root."""
    run(fake_tlc, "liveness", RED_SEAM, runner=runner, stamp=STAMP, leaves=True)
    # The runner's own `--tiers` says which rows that is, so the size lives in one place.
    tiers = subprocess.run([str(runner), "--tiers"], cwd=runner.parent, capture_output=True, text=True)
    rows = next(line.split(":", 1)[1].split() for line in tiers.stdout.splitlines() if line.startswith("liveness:"))
    logs = sorted(fake_tlc[2].glob("*.log"))
    assert [log.stem for log in logs] == sorted(row.removesuffix(".cfg") for row in rows)
    return any("already exists" in log.read_text() for log in logs)


def test_a_row_refuted_in_its_initial_state_does_not_refuse_the_next_start(fake_tlc, arena):
    """Measured 2026-09-16: `./run-tlc.sh safety` lost five `SeamSolo_Bug*` rows,
    each `RED:` with no reason and a `!!`, because TLC names its metadir after the
    current second and a run refuted in its initial state leaves that directory
    behind. Every one of the five started in the second a leaver had."""
    victim = _same_second(fake_tlc, arena())
    log = (fake_tlc[2] / VICTIM.replace(".cfg", ".log")).read_text()
    assert "already exists" not in log
    assert victim.returncode == 0, victim.stdout
    assert "RED: NoStatusOutsideItsSelection" in victim.stdout


def test_the_rows_of_one_tier_do_not_share_a_metadir(fake_tlc, arena):
    """A root per runner is not enough on its own: TLC names its directory INSIDE
    whatever it is handed, so rows sharing one collide exactly as they did."""
    assert not _refused_in_a_tier(fake_tlc, arena())


def test_no_metadir_outlives_the_runner(fake_tlc, arena):
    """A directory per row would otherwise pile up a tier's worth, and the ones a
    refuted initial state leaves hold TLC's fingerprint and queue files."""
    _same_second(fake_tlc, arena())
    assert not any(fake_tlc[3].iterdir())


def test_a_metadir_that_cannot_be_made_stops_the_runner_before_tlc(fake_tlc, arena):
    """An environment that refuses TLC its scratch is the broken-jar case, not a
    row: exit 2 before anything is run or logged."""
    fake_tlc[3].write_text("not a directory\n")
    result = run(fake_tlc, VICTIM, RED_SEAM, runner=arena(), stamp=STAMP)
    assert result.returncode == 2
    assert "no metadir" in result.stderr
    assert not (fake_tlc[2] / VICTIM.replace(".cfg", ".log")).exists()


def _victim_refused(fake_tlc, runner):
    victim = _same_second(fake_tlc, runner)
    return victim.returncode == 1 and "!! expected RED: NoStatusOutsideItsSelection" in victim.stdout


def _metadir_left(fake_tlc, runner):
    _same_second(fake_tlc, runner)
    return any(fake_tlc[3].iterdir())


def _ran_with_no_metadir(fake_tlc, runner):
    fake_tlc[3].write_text("not a directory\n")
    return run(fake_tlc, VICTIM, RED_SEAM, runner=runner, stamp=STAMP).returncode != 2


#: THE METADIR ARMS: each part of the fix cut out of the runner, and the case that
#: then shows its defect -- the first two in the measured direction, a start
#: refused and its row RED with no reason.
METADIR_ARMS = [
    ("a metadir for the run", ' -metadir "$metaroot/${cfg%.cfg}"', "", _victim_refused),
    ("a directory per row", '"$metaroot/${cfg%.cfg}"', '"$metaroot"', _refused_in_a_tier),
    ("removing the root on exit", "  trap 'rm -rf \"$metaroot\"' EXIT\n", "", _metadir_left),
    (
        "stopping when none can be made",
        '  [ -n "$metaroot" ] || { echo "run-tlc: no metadir under $STATES" >&2; exit 2; }\n',
        "",
        _ran_with_no_metadir,
    ),
]


@pytest.mark.parametrize(
    "label,old,new,defect", METADIR_ARMS, ids=[a[0] for a in METADIR_ARMS]
)
def test_every_part_of_the_metadir_fix_has_a_row_that_falsifies_it(
    fake_tlc, arena, label, old, new, defect
):
    """Both sides asserted: the shipped runner shows no defect and the cut one
    does, so a cut that breaks the row somewhere else is not this part's kill."""
    assert not defect(fake_tlc, arena())
    assert defect(fake_tlc, arena(old, new))


# ---- the shard ---------------------------------------------------------------


def rows_of(result) -> list[str]:
    """The configurations a run reported, read off the rows it printed."""
    return [
        line.split()[0]
        for line in result.stdout.splitlines()
        if line.split() and line.split()[0].endswith(".cfg")
    ]


def test_the_shards_of_the_safety_tier_are_a_partition_of_it(fake_tlc):
    """The property sharding silently breaks: a configuration no shard runs is a
    row nobody watches, and a matrix of green shards says nothing about it.

    Three, because that is what `deep-checks.yml` runs, and over `safety` because
    that is the tier it shards. The roster comes from `--tiers`, so this cannot
    drift from the runner's own answer.
    """
    tiers = subprocess.run(
        [str(RUNNER), "--tiers"], cwd=RUNNER.parent, capture_output=True, text=True
    )
    whole = next(
        line.split(":", 1)[1].split()
        for line in tiers.stdout.splitlines()
        if line.startswith("safety:")
    )
    shards = [rows_of(run(fake_tlc, "safety", GREEN, shard=f"{i}/3")) for i in (1, 2, 3)]
    for i, mine in enumerate(shards, 1):
        assert mine, f"shard {i}/3 ran nothing"
        assert len(set(mine)) == len(mine), f"shard {i}/3 ran a configuration twice"
    ran = [cfg for mine in shards for cfg in mine]
    assert sorted(ran) == sorted(whole), "the shards are not the tier"
    assert all(len(mine) < len(whole) for mine in shards), "a shard took the whole tier"


def test_a_shard_keeps_the_tier_s_own_order(fake_tlc):
    # Weight decides MEMBERSHIP and nothing else: the rows are read against
    # `runs.toml`, and `--record` writes them in the order the lister names.
    tiers = subprocess.run(
        [str(RUNNER), "--tiers"], cwd=RUNNER.parent, capture_output=True, text=True
    )
    whole = next(
        line.split(":", 1)[1].split()
        for line in tiers.stdout.splitlines()
        if line.startswith("liveness:")
    )
    mine = rows_of(run(fake_tlc, "liveness", GREEN, shard="1/2"))
    assert mine == [cfg for cfg in whole if cfg in set(mine)]


def test_the_heaviest_configurations_do_not_share_a_shard(fake_tlc):
    """What round-robin got wrong, and the reason membership is cost-derived.

    `Shipped.cfg` and `Historical_E76.cfg` are the two 47-minute rows and sit 7
    apart in the lister, so `i mod 3` puts them in ONE shard — 220 minutes of a
    120-minute job, which is the shape that made this tier need splitting at all.
    """
    homes = {
        cfg: i
        for i in (1, 2, 3)
        for cfg in rows_of(run(fake_tlc, "safety", GREEN, shard=f"{i}/3"))
        if cfg in ("Shipped.cfg", "Historical_E76.cfg")
    }
    assert len(homes) == 2, homes
    assert len(set(homes.values())) == 2, f"both giants landed in one shard: {homes}"


@pytest.mark.parametrize("shard", ["4/3", "0/3", "1/0", "one/3", "3"])
def test_a_shard_that_is_not_i_of_k_is_refused(fake_tlc, shard):
    # `1/1` is the default and every other row runs under it, so the malformed
    # ones have to fail loudly rather than fall back to the whole tier.
    result = run(fake_tlc, "liveness", GREEN, shard=shard)
    assert result.returncode == 2, result.stdout
    assert "TLC_SHARD" in result.stderr, result.stderr


def test_a_shard_wider_than_its_tier_is_refused(fake_tlc):
    # A matrix with more jobs than the tier has rows would otherwise report a
    # green shard that ran nothing, which is the whole class this file is about.
    result = run(fake_tlc, "liveness", GREEN, shard="5/5")
    assert result.returncode == 2, result.stdout
    assert "selected no configuration" in result.stderr, result.stderr
