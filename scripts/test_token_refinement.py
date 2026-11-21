# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `token_refinement.sh` was carved out of a roster for lacking.

`test_gate_scripts.UNROSTERED` carved it out as "a `run` row with no mutation
table of its own; it dispatches to two `--check` scripts". Dispatch is exactly
where a row goes quiet: a `--check` that lost its flag REGENERATES the artefact
it was meant to compare, and a regenerating row cannot fail. The second call is
the same hole one line down — delete it and half the refinement stops being
checked with the row still green.

Driven as a subprocess against the real script, the way `test_kani_sh.py` drives
`kani.sh`: the two generators are stubs on the arena's own `scripts/`, so the
mutations move the DISPATCH and the script under test is the one `check.sh` runs.
The stubs distinguish the two modes the way the real pair does — with `--check`
they compare and exit a status, without it they write a file — so a lost flag is
visible as the artefact appearing, not just as an argv string.

What this table does NOT cover, kept from the carve-out it replaces so the
observation does not go with it: `export_token_relation.py` and
`generate_token_edges.py` have no mutation tables of their own. Neither is a
`check.sh` row — this runner is the only thing that invokes them — so
`test_gate_scripts.test_every_script_check_sh_runs_is_on_a_roster` cannot see
them either. The dispatch is held here; what the two of them compare is not.
"""

import os
import pathlib
import subprocess
import sys

import pytest

import gate_lines

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts/token_refinement.sh"

EXPORT = "export_token_relation.py"
EDGES = "generate_token_edges.py"

#: A stand-in for one of the two generators. `--check` compares and exits the
#: status the case asked for; without it the script GENERATES, which is the mode
#: that cannot fail and the reason a lost flag is worth a case.
STUB = """\
import os, pathlib, sys
name = pathlib.Path(__file__).stem
args = sys.argv[1:]
with open(os.environ["TOKEN_LOG"], "a") as log:
    log.write(f"{name} {' '.join(args)}\\n")
if "--check" not in args:
    pathlib.Path(f"generated-{name}.txt").write_text("regenerated\\n")
    raise SystemExit(0)
raise SystemExit(int(os.environ.get("RC_" + name.upper(), "0")))
"""


class Tree:
    """An arena holding the real runner and two stand-ins for what it dispatches to."""

    def __init__(self, root):
        self.root = root
        self.write(f"scripts/{EXPORT}", STUB)
        self.write(f"scripts/{EDGES}", STUB)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run(self, *args, cuts=(), export_rc=0, edges_rc=0):
        """The row, as `check.sh` runs it, with the runner optionally cut.

        Each cut is (anchor, replacement) applied to the runner's own source with
        the anchor asserted present, so a deletion arm whose anchor moved reads
        as a moved anchor rather than as a kill.
        """
        src = GUARD.read_text()
        for old, new in cuts:
            assert src.count(old) == 1, f"anchor moved: {old!r}"
            src = src.replace(old, new)
        script = self.root / "scripts/token_refinement.sh"
        self.write("scripts/token_refinement.sh", src)
        script.chmod(0o755)
        log = self.root / "ran.log"
        log.write_text("")
        return subprocess.run(
            [str(script), *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "TOKEN_LOG": str(log),
                "RC_EXPORT_TOKEN_RELATION": str(export_rc),
                "RC_GENERATE_TOKEN_EDGES": str(edges_rc),
            },
        )

    def ran(self):
        """What the runner actually dispatched to, in order, with its arguments."""
        return (self.root / "ran.log").read_text().split()  # flattened: name, args, …

    def generated(self):
        return sorted(p.name for p in self.root.glob("generated-*.txt"))


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


# --- both directions, and the wiring ------------------------------------------


def test_check_dispatches_to_both_scripts_with_the_flag(tree):
    """The row's own shape: two comparisons, neither of them a generation."""
    result = tree.run("--check")
    assert result.returncode == 0, result.stderr
    assert tree.ran() == [
        "export_token_relation", "--check", "generate_token_edges", "--check"
    ]
    assert tree.generated() == []


def test_generate_dispatches_to_both_scripts_without_it(tree):
    """The other half of the `case`, and what the flag is the difference between."""
    result = tree.run("--generate")
    assert result.returncode == 0, result.stderr
    assert tree.ran() == ["export_token_relation", "generate_token_edges"]
    assert tree.generated() == [
        "generated-export_token_relation.txt", "generated-generate_token_edges.txt"
    ]


def test_this_checkout_is_green():
    """The control the arena cannot be: the row over the tree it guards, with the
    real exporter and the real codegen behind it."""
    result = subprocess.run(
        [str(GUARD), "--check"], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "token-export: GREEN" in result.stdout
    assert "token-codegen: GREEN" in result.stdout


def test_the_exporter_keeps_a_java_io_tmpdir_of_its_own(tmp_path):
    """SANY writes each standard module into java.io.tmpdir, so TLCs sharing one
    parsed each other's half-written Naturals.tla (exit 150). A default nothing can
    be written to stands in for a shared one, without a race."""
    poisoned = {**os.environ, "JAVA_TOOL_OPTIONS": f"-Djava.io.tmpdir={tmp_path / 'no-such-tmp'}"}
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / EXPORT), "--check"],
        cwd=ROOT, capture_output=True, text=True, env=poisoned,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_check_assurance_sh_runs_the_row_as_a_check_and_not_a_generation():
    """The flag is part of the wiring: `--generate` rewrites the tree and exits 0
    whatever it finds, so a row spelled that way could never be red."""
    check = (ROOT / "scripts/check-assurance.sh").read_text()
    assert gate_lines.runs(check, "scripts/token_refinement.sh --check")
    assert not gate_lines.runs(check, "scripts/token_refinement.sh --generate")


# --- the row has to carry each half's failure ---------------------------------


def test_the_first_check_failing_fails_the_row_and_stops_it(tree):
    """`set -e`: the status is the failing script's own, not a flattened 1, and
    the second never runs — a comparison after a failed one reads a stale half."""
    result = tree.run("--check", export_rc=3)
    assert result.returncode == 3
    assert tree.ran() == ["export_token_relation", "--check"]


def test_the_second_check_failing_fails_the_row(tree):
    """The half a single-call runner would lose: both ran, the second refused."""
    result = tree.run("--check", edges_rc=4)
    assert result.returncode == 4
    assert tree.ran() == [
        "export_token_relation", "--check", "generate_token_edges", "--check"
    ]


def test_an_unknown_argument_is_refused_and_runs_nothing(tree):
    """A typo'd flag must not read as one of the two modes; exit 2 is the usage
    code, distinct from a check that ran and refused."""
    result = tree.run("--chek")
    assert result.returncode == 2
    assert "usage: scripts/token_refinement.sh --generate|--check" in result.stderr
    assert tree.ran() == []


def test_no_argument_at_all_is_refused_with_the_usage(tree):
    """`${1:-}` is what makes this the usage rather than `set -u`'s own death."""
    result = tree.run()
    assert result.returncode == 2
    assert "usage: scripts/token_refinement.sh" in result.stderr
    assert tree.ran() == []


# --- the control: what the runner is right to be indifferent to ----------------


def test_an_extra_argument_after_the_mode_is_ignored(tree):
    """`case "$1"` reads the first word only. Pinned as measured, with the
    neighbouring typo red in the same case so the green is indifference and not a
    dispatch that quietly stopped happening."""
    result = tree.run("--check", "--verbose")
    assert result.returncode == 0, result.stderr
    assert tree.ran() == [
        "export_token_relation", "--check", "generate_token_edges", "--check"
    ]
    assert tree.run("--verbose", "--check").returncode == 2


# --- the deletion arms: one clause at a time ----------------------------------


def test_deleting_the_errexit_masks_the_first_half_s_refusal(tree):
    """The clause with no other reader: without it the failing exporter is
    overwritten by the codegen's 0 and the row is green over a refused check."""
    assert tree.run("--check", export_rc=3).returncode == 3
    result = tree.run("--check", export_rc=3, cuts=[("set -euo pipefail\n", "")])
    assert result.returncode == 0
    assert tree.ran()[-2:] == ["generate_token_edges", "--check"]


def test_deleting_the_second_call_takes_its_refusal_with_it(tree):
    """Half the refinement stops being checked and the row cannot tell."""
    assert tree.run("--check", edges_rc=4).returncode == 4
    cut = [("    python scripts/generate_token_edges.py --check\n", "")]
    result = tree.run("--check", edges_rc=4, cuts=cut)
    assert result.returncode == 0
    assert tree.ran() == ["export_token_relation", "--check"]


def test_deleting_the_first_call_takes_its_refusal_with_it(tree):
    """The mirror of the case below it, and the half a reader assumes is safe
    because it is first: the export stops being compared and the row is green
    over a refinement relation nothing exported."""
    assert tree.run("--check", export_rc=3).returncode == 3
    cut = [("    python scripts/export_token_relation.py --check\n", "")]
    result = tree.run("--check", export_rc=3, cuts=cut)
    assert result.returncode == 0
    assert tree.ran() == ["generate_token_edges", "--check"]


def test_deleting_the_flag_turns_the_check_into_a_generation(tree):
    """The defect a `--check` row exists to avoid: the same command without the
    flag rewrites the artefact and exits 0 whatever it would have found."""
    assert tree.run("--check", export_rc=3).returncode == 3
    cut = [("    python scripts/export_token_relation.py --check\n",
            "    python scripts/export_token_relation.py\n")]
    result = tree.run("--check", export_rc=3, cuts=cut)
    assert result.returncode == 0
    assert tree.generated() == ["generated-export_token_relation.txt"]


def test_deleting_the_default_arm_lets_a_typo_pass_silently(tree):
    """Without it a mistyped mode matches nothing, the `case` falls through, and
    the row exits 0 having run neither script."""
    assert tree.run("--chek").returncode == 2
    cut = [('  *)\n    echo "usage: scripts/token_refinement.sh --generate|--check" >&2\n'
            "    exit 2\n    ;;\n", "")]
    result = tree.run("--chek", cuts=cut)
    assert result.returncode == 0
    assert tree.ran() == []


def test_deleting_the_default_expansion_costs_the_usage_message(tree):
    """The clause survives its own deletion as a different red: `set -u` kills the
    runner on `$1` with an unbound-variable message and rc 1, so the row is still
    not green — what goes is the sentence that says which flag to type."""
    assert tree.run().returncode == 2
    result = tree.run(cuts=[('case "${1:-}" in', 'case "$1" in')])
    assert result.returncode == 1
    assert "unbound variable" in result.stderr
    assert "usage:" not in result.stderr
