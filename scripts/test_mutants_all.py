# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `scripts/mutants-all.sh`: its accepted-survivors
baseline and its `--in-diff` mode.

Every case runs the REAL script over a fixture tree with a fake `cargo-mutants`
first on PATH, which prints a fixture roster for `--list` and, for a run, writes
fixture outcome files and the summary line the real tool prints. The script's
own verdict is what is read: its exit code, taken from the process, and the line
that says why — a sweep in CI is a few hours per shard, so a baseline rule that
cannot go red is found out only by the week it should have.

Each rule, the arm that falls when it is deleted, and in which direction:

* a survivor the file does not hold — `..._a_new_survivor_fails_the_shard`,
  "should have been refused"; duplicates are COUNTED, so one accepted copy of a
  mutation that survives twice is `..._counted_not_set_compared`;
* an accepted entry this shard now catches — `..._now_caught_is_stale`;
* an accepted entry the roster no longer produces, asked of shard 1 only —
  `..._no_longer_a_mutant_is_stale`, and its twin that says shard 2 stays quiet;
* an entry outside a `[class] reason` line — `..._an_entry_needs_a_class`;
* `:LINE:COL` is dropped before comparing — the control itself, whose survivors
  sit at other lines than the file's entries;
* `--in-diff` reads the working tree AND the files git has never seen, exits 2
  on a survivor and 0 on none, and a list that failed is not "none" — the
  `in_diff` cases.
"""

import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "mutants-all.sh"

#: The stand-in. It records what it was asked, answers `--list` from a fixture
#: roster (`diff-list` under `--in-diff`), and for a run copies the fixture
#: outcomes into `--output` and prints the fixture summary. Exits 2, as the real
#: one does when a mutant survives, so the script's `|| true` is exercised.
FAKE = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$FAKE/argv"
out="" list=0 diff=""
while [ $# -gt 0 ]; do
  case "$1" in
    --list) list=1 ;;
    --in-diff) diff=$2; cp "$2" "$FAKE/seen-diff"; shift ;;
    --output) out=$2; shift ;;
  esac
  shift
done
if [ "$list" = 1 ]; then
  [ -e "$FAKE/list-fails" ] && { echo "error: could not parse the diff" >&2; exit 1; }
  if [ -n "$diff" ]; then cat "$FAKE/diff-list"; else cat "$FAKE/list"; fi
  exit 0
fi
mkdir -p "$out/mutants.out"
cp "$FAKE"/out/*.txt "$out/mutants.out/"
cat "$FAKE/summary" 2>/dev/null
exit 2
"""

#: The fixture crate's one source file, and the mutants the fake reports in it,
#: each as `path:LINE:COL: mutation` the way cargo-mutants prints them.
LIB = "crates/rsk-a/src/lib.rs"
F = f"{LIB}:10:5: replace f -> bool with true"
G1 = f"{LIB}:12:9: replace + with - in g"
G2 = f"{LIB}:12:14: replace + with - in g"
H = f"{LIB}:20:5: replace h -> u8 with 0"
#: A mutant of the roster that this shard never runs: another shard's.
ELSEWHERE = f"{LIB}:30:5: replace k -> u8 with 1"


def name(mutant):
    """The name the baseline holds: the mutant less its `:LINE:COL`."""
    path, line, col, rest = mutant.split(":", 3)
    return f"{path}:{rest}"


ACCEPTED = f"""\
# SPDX-License-Identifier: AGPL-3.0-only
# A comment, and a blank line, which are neither class nor entry.

[masked] a guard a deeper guard repeats
{name(F)}
{name(G1)}
[unpinned] a value no test pins on purpose
{name(ELSEWHERE)}
"""


class Tree:
    """A checkout the script can run in: itself, a crate, a baseline, a git."""

    def __init__(self, root):
        self.root = root / "tree"
        self.fake = root / "fake"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "crates/rsk-a/src").mkdir(parents=True)
        (self.fake / "out").mkdir(parents=True)
        (self.fake / "bin").mkdir()
        shutil.copy(SCRIPT, self.root / "scripts" / SCRIPT.name)
        (self.root / "scripts/mutants-accepted.txt").write_text(ACCEPTED)
        (self.root / LIB).write_text("pub fn f() -> bool { false }\n")
        tool = self.fake / "bin" / "cargo-mutants"
        tool.write_text(FAKE)
        tool.chmod(0o755)
        # The roster floor is 10000, so the fixture roster clears it with filler.
        filler = [f"crates/rsk-a/src/fill.rs:{i}:1: replace fill{i} -> bool with true"
                  for i in range(10000)]
        self.roster([F, G1, G2, H, ELSEWHERE] + filler)
        (self.fake / "diff-list").write_text("")
        # The control: F and one copy of g survive, at lines the file never
        # names; the other copy of g and H are caught.
        self.outcomes(missed=[F.replace(":10:5:", ":11:5:"), G1], caught=[G2, H])
        self.summary("4 mutants tested in 1s: 2 missed, 2 caught")
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "the tree")

    def roster(self, lines):
        (self.fake / "list").write_text("".join(f"{line}\n" for line in lines))

    def outcomes(self, missed=(), caught=(), timeout=(), unviable=()):
        for kind, lines in (("missed", missed), ("caught", caught),
                            ("timeout", timeout), ("unviable", unviable)):
            (self.fake / "out" / f"{kind}.txt").write_text("".join(f"{m}\n" for m in lines))

    def summary(self, line):
        (self.fake / "summary").write_text(f"{line}\n")

    def accept(self, text):
        (self.root / "scripts/mutants-accepted.txt").write_text(text)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(PATH=f"{self.fake / 'bin'}:{env['PATH']}", FAKE=str(self.fake),
                   HOST_TARGET="x86_64-unknown-linux-gnu", GITHUB_STEP_SUMMARY="/dev/null")
        env.update(extra)
        return env

    def git(self, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                        "-C", str(self.root), *args],
                       check=True, capture_output=True, env=self.env())

    def run(self, *args, **env):
        """(exit code, output), the code taken from the process."""
        done = subprocess.run(["bash", f"scripts/{SCRIPT.name}", *args], cwd=self.root,
                              capture_output=True, text=True, env=self.env(**env))
        return done.returncode, done.stdout + done.stderr


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


# --- the sweep and its baseline -------------------------------------------------


def test_the_control_passes(tree):
    """Every survivor accepted at another line than the file names it, and an
    accepted mutant of another shard's slice: green, and it says why."""
    code, out = tree.run()
    assert code == 0, out
    assert "every survivor of shard 1/1 is accepted" in out


def test_a_new_survivor_fails_the_shard(tree):
    tree.outcomes(missed=[F, G1, H], caught=[G2])
    code, out = tree.run()
    assert code == 1, out
    assert f"survived, and not in scripts/mutants-accepted.txt: {name(H)}" in out
    assert (tree.root / "target/mutants/new-survivors.txt").read_text() == f"{name(H)}\n"


def test_a_survivor_twice_is_counted_not_set_compared(tree):
    """`g` carries the same mutation twice and the file accepts one copy."""
    tree.outcomes(missed=[F, G1, G2], caught=[H])
    code, out = tree.run()
    assert code == 1, out
    assert f"survived, and not in scripts/mutants-accepted.txt: {name(G1)}" in out


def test_an_accepted_mutant_now_caught_is_stale(tree):
    """The ratchet: a test that kills an accepted survivor owes the deletion, or
    a later regression of it would pass as accepted."""
    tree.outcomes(missed=[G1], caught=[F, G2, H])
    code, out = tree.run()
    assert code == 1, out
    assert f"now caught — delete the entry: {name(F)}" in out


def test_an_accepted_mutant_no_longer_a_mutant_is_stale(tree):
    tree.accept(ACCEPTED + f"{name(H).replace('h -> u8', 'gone -> u8')}\n")
    code, out = tree.run(MUTANTS_SHARD="1/2")
    assert code == 1, out
    assert "no longer a mutant of the tree — delete the entry" in out


def test_the_roster_question_is_asked_of_shard_one_only(tree):
    """Twelve shards reporting the same gone entry is one finding said twelve times."""
    tree.accept(ACCEPTED + f"{name(H).replace('h -> u8', 'gone -> u8')}\n")
    code, out = tree.run(MUTANTS_SHARD="2/2")
    assert code == 0, out


def test_an_entry_needs_a_class(tree):
    tree.accept(f"{name(F)}\n{name(G1)}\n")
    code, out = tree.run()
    assert code == 1, out
    assert "every entry sits under a `[class] reason` line" in out


def test_the_shipped_baseline_parses(tree):
    """The file triage edits in ordinary pull requests: an entry outside its class
    would otherwise first fail the weekly row, hours into the sweep."""
    tree.accept((ROOT / "scripts/mutants-accepted.txt").read_text())
    code, out = tree.run()
    assert "every entry sits under" not in out, out
    assert "class line with no reason" not in out, out
    assert "survived, and not in scripts/mutants-accepted.txt" in out, out


def test_a_class_needs_its_reason(tree):
    tree.accept(ACCEPTED.replace("[masked] a guard a deeper guard repeats", "[masked]"))
    code, out = tree.run()
    assert code == 1, out
    assert "class line with no reason" in out


def test_a_run_with_no_summary_is_not_a_pass(tree):
    (tree.fake / "summary").unlink()
    code, out = tree.run()
    assert code == 1, out
    assert "produced no summary line" in out


def test_a_shard_that_tested_nothing_is_not_a_pass(tree):
    tree.summary("0 mutants tested in 1s")
    code, out = tree.run()
    assert code == 1, out
    assert "tested 0 mutants" in out


# --- --in-diff -------------------------------------------------------------------


def test_in_diff_with_no_mutant_on_its_lines_exits_0_without_a_run(tree):
    code, out = tree.run("--in-diff", "HEAD")
    assert code == 0, out
    assert "in-diff: 0 mutants on the lines" in out
    assert "--list" in (tree.fake / "argv").read_text()


def test_in_diff_a_list_that_failed_is_not_zero_mutants(tree):
    """The real tool lists nothing at rc 0 over an empty diff or one with no Rust
    in it, so a list that FAILED is a failure — not a green "0 mutants"."""
    (tree.fake / "list-fails").write_text("")
    code, out = tree.run("--in-diff", "HEAD")
    assert code != 0, out
    assert "in-diff: 0 mutants" not in out


def test_in_diff_reads_the_working_tree_and_the_files_git_has_not_seen(tree):
    """A fix's new module is the code that most needs a test that notices it,
    and `git diff` alone does not show a file git has never seen."""
    (tree.root / LIB).write_text("pub fn f() -> bool { true }\n")
    (tree.root / "crates/rsk-a/src/new.rs").write_text("pub fn n() -> u8 { 7 }\n")
    (tree.fake / "diff-list").write_text(f"{F}\n")
    tree.outcomes(caught=[F])
    tree.summary("1 mutants tested in 1s: 1 caught")
    code, out = tree.run("--in-diff", "HEAD")
    assert code == 0, out
    seen = (tree.fake / "seen-diff").read_text()
    assert "+pub fn f() -> bool { true }" in seen
    assert "+pub fn n() -> u8 { 7 }" in seen


def test_in_diff_exits_2_on_a_survivor_and_names_it(tree):
    """No baseline here: every survivor on the lines the diff touches is read."""
    (tree.fake / "diff-list").write_text(f"{F}\n{H}\n")
    tree.outcomes(missed=[F], caught=[H])
    tree.summary("2 mutants tested in 1s: 1 missed, 1 caught")
    code, out = tree.run("--in-diff", "HEAD")
    assert code == 2, out
    assert f"  {name(F)}" in out
