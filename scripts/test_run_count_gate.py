# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `run_count_gate.py` is verified against.

Every rule is broken once on a fixture and the break has to be the finding it
claims to be, then the real checkout closes the other direction: a guard that
cannot go green is deleted as fast as one that cannot go red.

Two families get more than one case each, because both are where this class of
guard has failed before rather than where it is easiest to test.

The SPELLINGS, seven that must fire and three that must not. A run-count can be a
tally (`19 GREEN`), a count and a noun (`190 rows`), the same in words (`four
liveness rows`), a clause the tight tally cannot see (`20 that must come back
GREEN`), a wall clock, any of those inside a fenced code block, or the same in a
YAML comment run — because a rule closed in one spelling is this tree's most
expensive habit. Against them: a count with no run named at all, a table row
borrowing a runner from its neighbours, and the generated sentence itself, which
carries every spelling above and must not read as a typed one.

And the SCOPE registry, which is the half that turns a guard into a colander: an
entry matching nothing, an entry matching twice, and a literal that merely
resembles a registered one and must still be refused.
"""

import datetime
import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import gate_lines
import run_count_gate

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: A runner that answers only the pure query, which is all the gate asks of it.
RUN_TLC = """\
#!/usr/bin/env bash
[ "${1:-}" = "--tiers" ] || { echo "fixture runner: only --tiers" >&2; exit 2; }
echo "safety: Shipped.cfg Mut_BugFooOpens.cfg"
echo "liveness: Liveness.cfg"
"""

FLOORS = """\
\\* the fixture's verdict registry
Shipped.cfg     GREEN   100
Liveness.cfg    GREEN   10      12g
Mut_*.cfg       RED     -
"""

MINI = """\
---- MODULE Mini ----
CONSTANTS BugFooOpens, BugBarOpens
Init == TRUE
====
"""

COMUTANTS = """\
pending_floor = 0
phase2_count = 2

[comutant.BugFooOpens]
status = "patch"
expect = "killed"

[comutant.BugBarOpens]
status = "unreachable"
evidence = "no such door"
"""

#: `TypeOK` is in it on purpose: the published count is the security properties,
#: and a type invariant is not one of them.
SHIPPED_CFG = """\
SPECIFICATION Spec
INVARIANTS
    TypeOK
    FooStaysClosed
    BarNeverOpens
SYMMETRY Symm
"""

MATRIX_SAFETY = (
    "Shipped.cfg      GREEN                 states=4000  distinct=200 depth=6  600s\n"
    "Mut_BugFooOpens.cfg RED: FooStaysClosed states=90    distinct=40  depth=4  7s"
)
MATRIX_LIVENESS = "Liveness.cfg     GREEN                 states=900   distinct=44  depth=9  300s"

#: What TLC said about the same three rows, in TLC's words — the second account
#: `check_tlc` holds the matrix to. Each clock is a little under the runner's,
#: because the runner's brackets the JVM, and each line opens with the banner and
#: the start time: they are the only second source the provenance fields have.
def tlc_kept(when, workers=2, cores=1):
    head = f"with {workers} workers on {cores} cores (Some OS {os.uname().machine})"
    return {
        "safety": (
            f"Shipped.cfg {head} Starting... ({when}) 4000 states generated, 200 distinct"
            " states found, 0 states left on queue. The depth of the complete state graph"
            " search is 6. Finished in 09min 58s\n"
            f"Mut_BugFooOpens.cfg {head} Starting... ({when}) 90 states generated, 40"
            " distinct states found, 0 states left on queue. The depth of the complete"
            " state graph search is 4. Finished in 06s"
        ),
        "liveness": (
            f"Liveness.cfg {head} Starting... ({when}) 900 states generated, 44 distinct"
            " states found, 0 states left on queue. The depth of the complete state graph"
            " search is 9. Finished in 04min 59s"
        ),
    }

def a_minute_from_now():
    """The fixture's runs happen just AFTER its own commit, because `--record`
    refuses a run of a tree younger than itself. A hard-coded stamp made every
    `--record` case fail that check instead of the one it was written for."""
    later = datetime.datetime.now() + datetime.timedelta(minutes=1)
    return later.strftime("%Y-%m-%d %H:%M:%S")


#: One per configuration, the way `formal/out/` holds them. The banner and the
#: start line are what `provenance` reads, so they carry this machine's own arch:
#: a fixture that hard-coded one would pass on that machine and nowhere else.
def tlc_log(states, distinct, depth, finished, workers=2, cores=1, when=None):
    when = when or a_minute_from_now()
    return (
        "TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)\n"
        f"Running breadth-first search Model-Checking with fp 21 and seed 1 with {workers}"
        f" workers on {cores} cores with 3641MB heap and 64MB offheap memory (Some OS"
        f" {os.uname().machine}, Azul Systems, Inc. 1.8.0_492, MSBDiskFPSet, DiskStateQueue).\n"
        f"Starting... ({when})\n"
        "Model checking completed. No error has been found.\n"
        f"{states} states generated, {distinct} distinct states found, 0 states left on queue.\n"
        f"The depth of the complete state graph search is {depth}.\n"
        f"Finished in {finished} at ({when})\n"
    )


def logs(**kw):
    """The three logs of one fixture run, built per call so their start time is
    always after the fixture's own commit."""
    return {
        "Shipped": tlc_log(4000, 200, 6, "09min 58s", **kw),
        "Mut_BugFooOpens": tlc_log(90, 40, 4, "06s", **kw),
        "Liveness": tlc_log(900, 44, 9, "04min 59s", **kw),
    }

TESTING_MD = """\
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Testing

> The paragraph to quote, and the one whose state count had gone stale by sixty
> per cent, which is why a region has to be able to sit inside a blockquote.
> <!-- run-count-shipped-row:start -->
> <!-- run-count-shipped-row:end -->
> That is a result about the model.

<!-- run-count-tlc-roster:start -->
<!-- run-count-tlc-roster:end -->

Tier membership lives in `formal/run-tlc.sh`.

<!-- run-count-tlc-measured:start -->
<!-- run-count-tlc-measured:end -->

Counted out of `formal/runs.toml`.

<!-- run-count-comutate-roster:start -->
<!-- run-count-comutate-roster:end -->

The rest is in `formal/README.md`.
"""

FORMAL_MD = """\
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Formal

<!-- run-count-tlc-measured:start -->
<!-- run-count-tlc-measured:end -->

Nothing else on this page says how big a run was.
"""

README_MD = """\
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# formal/

<!-- run-count-tlc-measured:start -->
<!-- run-count-tlc-measured:end -->

Written from `formal/runs.toml`.

<!-- run-count-results-table:start -->
<!-- run-count-results-table:end -->

Every row of it came out of the record.

<!-- run-count-liveness-row:start -->
<!-- run-count-liveness-row:end -->

And that is the whole of it.
"""

WORKFLOW = """\
# The weekly row: TLC over formal/, every configuration `run-tlc.sh safety` lists.
name: deep-checks
on: workflow_dispatch
jobs:
  formal:
    runs-on: ubuntu-latest
    steps:
      - run: ./formal/run-tlc.sh safety
"""

CHECK_SH = """\
#!/usr/bin/env bash
run() { echo "== $1 =="; shift; "$@"; }
run "published run-counts"  python scripts/run_count_gate.py
"""

#: Carved out of the scan, and it has to say a run-count for the same reason the
#: page below does: a carve-out tested on a page with nothing in it passes for
#: free. Every line of the real one sits under a version heading, which is the
#: scope label a historical figure needs.
CHANGELOG_MD = """\
# Changelog

## [Unreleased]

- `run-tlc.sh safety` came back over 190 rows, 18 GREEN, in 2916 s.
"""

#: The carve-out has to be load-bearing: this page states a run-count, so a rule
#: that skipped it for any other reason would pass the case below for free.
VECTOR_MD = """\
<!-- Generated by scripts/evidence_gate.py --write — do not edit by hand -->

# Assurance vector

`run-tlc.sh safety` covers 190 rows, and 18 GREEN.
"""

#: The second carve-out's page, and the sentence kept apart from it so the same
#: bytes can be put somewhere ordinary: "states a run-count" is the property the
#: whole family rests on and asserting it of a page is not driving it. Shaped like
#: what `bounds_gate.py` renders, down to the two literals that brought the entry
#: about — both are the BUNDLE's prose, reflected onto a page no author may edit.
BOUNDS_NOTE = """\
> **Row note.** `comutate.solo_index` credits three switches, and 4 GREEN of the
> forty configurations naming the invariant.
"""

BOUNDS_MD = f"""\
<!-- Generated by scripts/bounds_gate.py --write — do not edit by hand -->

# Bounds

{BOUNDS_NOTE}"""

#: What a carve-out is now asked of, and the reason the fixture carries two of
#: them rather than a monkeypatched dict: `claims_gate.generated_pages` reads the
#: `ARTIFACT`/`GENERATED_BY` pair out of the generators, so a fixture with no
#: generator in it would redden both real entries in every case and measure the
#: registry against an empty tree.
GENERATOR_PY = """\
import pathlib

ARTIFACT = pathlib.Path("{page}")
GENERATED_BY = "Generated by scripts/{name}.py --write"
"""


class Tree:
    """A checkout shaped like this one, small enough to break one rule at a time."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.pending = set()
        #: One stamp for the whole fixture: the logs, the record's `date` and the
        #: kept lines are three copies of it, and the gate now holds them equal.
        self.when = a_minute_from_now()
        self.write("formal/run-tlc.sh", RUN_TLC)
        (self.root / "formal/run-tlc.sh").chmod(0o755)
        self.write("formal/floors.txt", FLOORS)
        self.write("formal/Mini.tla", MINI)
        self.write("formal/comutants.toml", COMUTANTS)
        for cfg in ("Shipped.cfg", "Mut_BugFooOpens.cfg", "Liveness.cfg"):
            self.write(f"formal/{cfg}", SHIPPED_CFG)
        # `stray`, because `/formal/out/*` is gitignored in the real tree: the
        # logs are the run's raw output, `--record` reads them where they lie and
        # the scan never sees them. Written with `write` they became tracked, and
        # every count in a log read as a second copy of itself.
        for name, text in logs(when=self.when).items():
            self.stray(f"formal/out/{name}.log", text)
        self.write("formal/README.md", README_MD)
        self.write("docs/testing.md", TESTING_MD)
        self.write("docs/formal.md", FORMAL_MD)
        self.write("docs/assurance-vector.md", VECTOR_MD)
        self.write("docs/assurance-bounds.md", BOUNDS_MD)
        for name, page in (
            ("evidence_gate", "docs/assurance-vector.md"),
            ("bounds_gate", "docs/assurance-bounds.md"),
        ):
            self.write(f"scripts/{name}.py", GENERATOR_PY.format(name=name, page=page))
        self.write(".github/workflows/deep-checks.yml", WORKFLOW)
        self.write("scripts/check.sh", CHECK_SH)
        self.write("CHANGELOG.md", CHANGELOG_MD)
        # A carve-out is checked to still EXIST, so the fixture has to carry every
        # file `NOT_TYPED_HERE` names. One tab-separated row, the shape
        # `citation_gate.py --relock` writes: a page, a cited file, a span and the
        # source line — which is where a count that nobody typed comes from.
        self.write(
            "formal/citations.lock",
            "# Generated by `scripts/citation_gate.py --relock`.\n"
            "formal/README.md\tsrc/probe.rs\t77-77\tcfg!(feature = \"always-uv\"),"
            "\tcfg!(feature = \"always-uv\"),\n",
        )
        # As the real tree ignores it. `commit()` is `git add -A`, so without
        # this the logs are tracked whatever `stray` does, and every count in
        # one reads as a second copy of itself.
        self.stray(".gitignore", "/formal/out/*\n")
        self.git("init", "-q")
        self.commit("the tree the runs are about")
        self.write("formal/runs.toml", self.record())
        self.regenerate()

    # --- the fixture's own mechanics -----------------------------------------

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        # The scan reads `git ls-files`, so a page a case writes has to be one
        # git knows about or the case measures an empty set and passes. Recorded
        # and flushed once per audit rather than added here, because that is one
        # `git` per assertion instead of one per file.
        self.pending.add(rel)

    def stray(self, rel, text):
        """A file git is NOT told about — which `write` would defeat, because it
        tells git about everything it writes."""
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def read(self, rel):
        return (self.root / rel).read_text()

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        text = self.read(rel)
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        self.write(rel, text.replace(old, new))

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def commit(self, subject):
        self.git("add", "-A")
        self.git(
            "-c", "user.name=t", "-c", "user.email=t@example.invalid",
            "commit", "-q", "-m", subject,
        )

    def head(self):
        done = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        )
        return done.stdout.strip()

    def record(self, safety=None, liveness=None, commit=None, drop="", tlc=None):
        out = run_count_gate.HEADER
        kept = tlc_kept(self.when)
        for tier, matrix, summary in (
            ("safety", safety or MATRIX_SAFETY, kept["safety"]),
            ("liveness", liveness or MATRIX_LIVENESS, kept["liveness"]),
        ):
            out += "\n[[run]]\n"
            for key, value in (
                ("tier", tier),
                ("command", f"./formal/run-tlc.sh {tier}"),
                ("date", self.when.split()[0]),
                ("commit", commit or self.head()),
                ("host", "a fixture (1 core)"),
                ("workers", 2),
            ):
                if key != drop:
                    out += f"{key} = {run_count_gate.quoted(value)}\n"
            out += f'matrix = """\n{matrix}\n"""\n'
            if drop != "tlc":
                out += f'tlc = """\n{summary if tlc is None else tlc}\n"""\n'
        return out

    def regenerate(self):
        for rel, text in run_count_gate.rendered(self.root, self.bodies()).items():
            self.write(rel, text)

    def bodies(self):
        runs = run_count_gate.load(self.root)
        return run_count_gate.region_bodies(
            run_count_gate.facts(self.root, runs, run_count_gate.tiers(self.root))
        )

    def track(self):
        """`--intent-to-add`, which is what puts a not-yet-committed page in
        `git ls-files` — the fixture is a working tree, not a release."""
        here = sorted(p for p in self.pending if (self.root / p).exists())
        self.pending.clear()
        if here:
            self.git("add", "-N", "--", *here)

    def problems(self):
        self.track()
        return run_count_gate.audit(self.root)[0]

    def summary(self):
        self.track()
        return run_count_gate.audit(self.root)[1]


@pytest.fixture
def tree(tmp_path, fixture_registries):
    return Tree(tmp_path)


def only(problems, needle):
    """The problems mentioning `needle`, so a message is asserted, not a count."""
    return [p for p in problems if needle in p]


#: The fixture's own Results grouping: three configurations, two lines, so the
#: closed world can be broken in one direction at a time.
GROUPS = (
    ("`Shipped.cfg` — the tree as it stands", ("Shipped.cfg",)),
    ("`Mut_*.cfg` — mutant against the whole invariant set", ("Mut_*.cfg",)),
    ("`Liveness.cfg` — the temporal half", ("Liveness.cfg",)),
)


@pytest.fixture
def fixture_registries(monkeypatch):
    """The real registries name real files; the fixture brings its own per case.

    `SCOPED` is left empty so every scan case says which entries it depends on,
    and so a real entry going stale cannot make a fixture case pass.

    Requested by `tree` rather than autouse, because autouse reached the one case
    that drives the REAL checkout — and that case then measured this tree against
    a three-line Results grouping and could never have passed.
    """
    monkeypatch.setattr(run_count_gate, "SCOPED", {})
    # Its ceiling with it: the ceiling EQUALS the registry now, which is what
    # makes raising it visible, and an empty registry has a ceiling of nothing.
    monkeypatch.setattr(run_count_gate, "SCOPE_CEILING", 0)
    monkeypatch.setattr(run_count_gate, "SCAN_FLOOR", 0)
    monkeypatch.setattr(run_count_gate, "RULE_FLOOR", 0)
    monkeypatch.setattr(run_count_gate, "TABLE_GROUPS", GROUPS)


# --- the clean tree --------------------------------------------------------


def test_the_fixture_is_green(tree):
    """Without this every case below could be passing on a tree that is broken
    for some other reason."""
    assert tree.problems() == []


def test_the_summary_counts_what_it_says(tree):
    assert "2 recorded tier run(s), 3 of 3 configuration(s) observed" in tree.summary()


def test_the_real_checkout_is_green():
    """The other direction, on the tree this actually guards."""
    assert run_count_gate.audit(ROOT)[0] == []


@pytest.mark.parametrize(
    "rule", ("TALLY", "COUNT", "CLOCK", "LOOSE_TALLY", "NAMES_A_RUN", "PAIR", "VERBATIM")
)
def test_a_scan_rule_that_has_stopped_matching_this_tree(monkeypatch, rule):
    """Each rule against the REAL checkout at the REAL floor, which is the half
    the fixture case below cannot reach: it monkeypatches `SCAN_FLOOR` down to 4
    and kills two rules at once, so the shipped 8 was never exercised against the
    shipped tree. Measured that way, the aggregate floor is blind — `COUNT` dead
    leaves 19 literals and `CLOCK` dead leaves 16, both over 8, and `TALLY` dead
    leaves all 28 because every tally is also a loose one.
    """
    monkeypatch.setattr(run_count_gate, rule, run_count_gate.re.compile("(?!x)x"))
    problems = run_count_gate.audit(ROOT)[0]
    assert only(problems, f"under the floor of {run_count_gate.RULE_FLOOR}"), problems


@pytest.mark.parametrize("ceiling", ("SCOPE_CEILING", "CARVE_OUT_CEILING", "SCOPE_SPAN_CAP"))
def test_a_ceiling_raised_without_the_entry_that_needs_it(monkeypatch, ceiling):
    """Three surviving mutants of one shape. `fb406e8` wrote of `SCAN_FLOOR` that
    monkeypatching it down on a fixture left the shipped value never exercised
    against the shipped tree -- and this file then shipped three ceilings with
    exactly that defect. The asymmetry is measured: lowering a FLOOR is caught,
    because the cases that drive it drive the real tree, and raising a CEILING was
    not, because nothing said where the ceiling should BE. Each sits on what the
    tree holds now, so a raise costs the diff line it is supposed to."""
    monkeypatch.setattr(run_count_gate, ceiling, getattr(run_count_gate, ceiling) + 62)
    assert run_count_gate.audit(ROOT)[0], ceiling


def test_a_published_sentence_that_stopped_being_generated(monkeypatch):
    """The region set had no floor at all: dropping one entry from
    `region_bodies`, deleting its two markers and retyping the sentence by hand
    left the row green over the exact state count this gate is named after. The
    table-DELETED family one layer out — the case below tests a region the
    generator does not own, and nothing tested a sentence it no longer does."""
    bodies = run_count_gate.region_bodies
    monkeypatch.setattr(
        run_count_gate, "region_bodies",
        lambda f, findings=None: dict(list(bodies(f, findings).items())[1:]),
    )
    assert only(run_count_gate.audit(ROOT)[0], "under the floor of"
                f" {run_count_gate.REGION_FLOOR}")


# --- the record: is it a run of THIS tier ----------------------------------


def test_a_configuration_the_tier_lists_and_no_run_covers(tree):
    tree.write("formal/runs.toml", tree.record(safety=MATRIX_SAFETY.splitlines()[0]))
    assert only(tree.problems(), "are in no recorded run"), tree.problems()


def test_a_recorded_row_the_tier_no_longer_lists(tree):
    tree.write(
        "formal/runs.toml",
        tree.record(safety=MATRIX_SAFETY + "\nGone.cfg  GREEN  states=1 distinct=1 depth=1 1s"),
    )
    assert only(tree.problems(), "Gone.cfg is recorded and the tier no longer lists it")


def test_the_model_moved_under_the_recorded_run(tree):
    """The gate reads model CONTENT for two things only -- the `Bug*` switch
    names and `Shipped.cfg`'s `INVARIANTS` -- so an edit that changes the state
    space without moving the roster or the floors left every published count
    stale and the row green. The record carries the commit, and this is the
    question that lets the row ask."""
    tree.write("formal/Mini.tla", MINI.replace("Init == TRUE", "Init == TRUE /\\ TRUE"))
    assert only(tree.problems(), "formal/Mini.tla has moved since")


def test_a_comment_in_the_model_is_not_the_model(tree):
    """These modules carry `file.rs:NNN` citations that `citation_gate.py`
    re-anchors every time the code under them moves. Driven against a real
    commit: a name-only diff called six modules changed over an edit that
    refreshed nothing but line numbers, and the row went red."""
    tree.write("formal/Mini.tla", MINI.replace(
        "Init == TRUE", "\\* the note above this line moved with the code\nInit == TRUE"))
    assert not only(tree.problems(), "has moved since"), tree.problems()


def test_a_page_beside_the_model_is_not_the_model(tree):
    """The other direction: `formal/README.md` carries generated regions that
    `--write` moves right after `--record`, so a rule over the whole directory
    would redden every honest run."""
    tree.write("formal/README.md", tree.read("formal/README.md") + "\nA later note.\n")
    assert not only(tree.problems(), "has moved since")


def test_a_row_recorded_twice(tree):
    tree.write("formal/runs.toml", tree.record(safety=MATRIX_SAFETY + "\n" + MATRIX_SAFETY.splitlines()[0]))
    assert only(tree.problems(), "Shipped.cfg recorded 2 times")


def test_a_verdict_the_floors_no_longer_allow(tree):
    tree.edit("formal/floors.txt", "Shipped.cfg     GREEN   100", "Shipped.cfg     RED     -")
    assert only(tree.problems(), "recorded GREEN and formal/floors.txt now requires RED")


def test_a_distinct_count_under_its_floor(tree):
    tree.edit("formal/floors.txt", "Shipped.cfg     GREEN   100", "Shipped.cfg     GREEN   9999")
    assert only(tree.problems(), "recorded 200 distinct, under the 9999")


def test_a_row_the_runner_itself_marked(tree):
    tree.write(
        "formal/runs.toml",
        tree.record(safety=MATRIX_SAFETY.replace(" 7s", " 7s  !! expected GREEN")),
    )
    assert only(tree.problems(), "!! expected GREEN` — a failed row is not a published result")


def test_a_run_with_no_provenance(tree):
    tree.write("formal/runs.toml", tree.record(drop="host"))
    assert only(tree.problems(), "no host — a result with no provenance")


def test_a_commit_that_is_not_an_object_name(tree):
    tree.write("formal/runs.toml", tree.record(commit="yesterday"))
    assert only(tree.problems(), "is not a full 40-character object name")


def test_a_commit_from_another_repository(tree):
    tree.write("formal/runs.toml", tree.record(commit="0" * 40))
    assert only(tree.problems(), "is in no history here")


# --- the matrix against TLC's own account of the same run -------------------
#
# The record was the hole under the whole row: `states`, `depth` and the wall
# clock were held against nothing at all and `distinct` only from below, so
# editing two fields and running `--write` restored six published sentences to
# the exact defect this gate is named after, green. One case per field, in the
# direction rot takes — a number made SMALLER, which is what a stale copy is.


def test_a_distinct_count_the_log_contradicts(tree):
    tree.edit("formal/runs.toml", "distinct=200", "distinct=48")
    assert only(tree.problems(), "recorded distinct=48 and TLC's own summary says 200")


def test_a_states_count_the_log_contradicts(tree):
    tree.edit("formal/runs.toml", "states=4000", "states=400")
    assert only(tree.problems(), "recorded states=400 and TLC's own summary says 4000")


def test_a_depth_the_log_contradicts(tree):
    tree.edit("formal/runs.toml", "depth=6 ", "depth=2 ")
    assert only(tree.problems(), "recorded depth=2 and TLC's own summary says 6")


def test_a_wall_clock_under_the_one_tlc_timed_itself_at(tree):
    """The measured attack: `1869s` retyped `539s` republished half an hour of
    exhaustive checking as nine minutes. The runner's clock brackets the JVM, so
    it can only ever be the larger of the two."""
    tree.edit("formal/runs.toml", "depth=6  600s", "depth=6  120s")
    assert only(tree.problems(), "and this one is -478s")


def test_a_wall_clock_further_over_it_than_a_jvm_starts_in(tree):
    tree.edit("formal/runs.toml", "depth=6  600s", "depth=6  9000s")
    assert only(tree.problems(), f"belongs in 0..{run_count_gate.CLOCK_SLACK}s")


@pytest.mark.parametrize("clock, over", (("628s", False), ("629s", True)))
def test_the_per_row_gap_is_bounded_where_it_says(tree, clock, over):
    """Written with the boundary spelled out rather than computed from the
    constant: `CLOCK_SLACK` at 3000 was a surviving mutant, because the case
    above uses a gap of 8402 and passes at either value. TLC timed this row at
    598 s, so 628 is exactly the bound and 629 is one over."""
    tree.edit("formal/runs.toml", "depth=6  600s", f"depth=6  {clock}")
    assert bool(only(tree.problems(), "belongs in 0..")) is over, tree.problems()


def test_one_configuration_with_two_kept_summaries(tree):
    """The finding existed and nothing drove it: a second line for one
    configuration silently replaced the first, so a row could be given a summary
    that is not its own with the real one left in the file above it."""
    tree.write("formal/runs.toml", tree.record(
        tlc=tlc_kept(tree.when)["safety"] + "\n"
        + tlc_kept(tree.when)["safety"].splitlines()[0].replace("4000 states", "40 states")))
    assert only(tree.problems(), "Shipped.cfg has two TLC summaries")


def test_a_row_with_no_tlc_summary_at_all(tree):
    tree.edit("formal/runs.toml", "Shipped.cfg with 2 workers", "Other.cfg with 2 workers")
    problems = tree.problems()
    assert only(problems, "Shipped.cfg is in the matrix and TLC's own summary of it is not")
    assert only(problems, "TLC's summary of Other.cfg is kept and the matrix has no such row")


def test_the_tlc_block_emptied_rather_than_deleted(tree):
    """The table-EMPTIED half. A block dropped whole is a missing key and reads
    as one; a block left in place with nothing in it is the same hole wearing the
    field's own name, and it is the form this tree has actually shipped."""
    tree.write("formal/runs.toml", tree.record(tlc=""))
    assert len(only(tree.problems(), "TLC's own summary of it is not")) == 3


def test_the_tlc_block_dropped_whole(tree):
    tree.write("formal/runs.toml", tree.record(drop="tlc"))
    assert only(tree.problems(), "no tlc — a result with no provenance")


def test_a_kept_line_that_is_not_a_tlc_summary(tree):
    tree.edit("formal/runs.toml", "Shipped.cfg with 2 workers", "Shipped.cfg went well with 2 workers")
    assert only(tree.problems(), "is not a TLC summary line")


def test_a_question_mark_must_mean_tlc_printed_nothing(tree):
    """`?` is the runner's spelling of "no such field", and TLC leaves both halves
    out on a run that died on an initial state — two rows of the recorded safety
    tier are exactly that. So the two accounts have to agree about ABSENCE, or the
    field with no number is the one field nothing checks."""
    tree.edit("formal/runs.toml", "states=4000", "states=?")
    assert only(tree.problems(), "recorded states=? and TLC's own summary says 4000")


def test_a_tier_whose_rows_all_sit_at_the_per_row_bound(tree):
    """The bound above is per row and the published sentence ADDS THEM UP: every
    row at its own TLC clock plus the slack put the legal safety total at
    [3064..8914] s against a recorded 3225, and `3225 s` was republished as
    `8914 s` with `--write` and the row both at exit 0."""
    tree.write("formal/runs.toml", tree.record(
        safety=MATRIX_SAFETY.replace("depth=6  600s", "depth=6  628s")
                            .replace("depth=4  7s", "depth=4  36s")))
    assert only(tree.problems(), "longer than TLC timed them, over the"), tree.problems()


def test_one_cold_row_in_a_tier_is_not_over_the_summed_bound(tree):
    """The other direction, and why `CLOCK_SLACK` is added on top of the per-row
    budget: a single cold page cache is what the per-row slack is FOR, and a
    two-row tier would otherwise have no room for it at all."""
    tree.write("formal/runs.toml", tree.record(
        safety=MATRIX_SAFETY.replace("depth=6  600s", "depth=6  620s")))
    assert not only(tree.problems(), "longer than TLC timed them")


@pytest.mark.parametrize("field, typed", (
    ("date", '"1999-01-01"'),
    ("workers", "97"),
    ("host", '"a Cray-1 (4096 cores)"'),
))
def test_a_provenance_field_the_banner_contradicts(tree, field, typed):
    """These three had no second source at all — each was driven to an absurd
    value with `--write` and the row both at exit 0 — and TLC printed all three,
    in the banner and the start line `--record` already parsed and threw away."""
    kept = tree.read("formal/runs.toml")
    tree.write("formal/runs.toml",
               run_count_gate.re.sub(rf"^{field} = .*$", f"{field} = {typed}", kept,
                                     count=1, flags=run_count_gate.re.M))
    assert only(tree.problems(), f"recorded {field}="), tree.problems()


@pytest.mark.parametrize("was, now", (
    ("2 workers", "9 workers"), ("1 cores", "8 cores"), (os.uname().machine, "vax"),
))
def test_kept_summaries_from_two_different_runs(tree, was, now):
    """One disagreement among the rows is a record assembled from two runs, and
    it is reported once rather than once per row. `arch` is in the tuple for the
    reason `queue` is read at all: it was captured and compared to nothing, and a
    JVM does not print the brand string `host` wears, so rows agreeing with each
    other is the only checkable claim left in it."""
    head = f"Mut_BugFooOpens.cfg with 2 workers on 1 cores (Some OS {os.uname().machine})"
    tree.edit("formal/runs.toml", head, head.replace(was, now))
    assert len(only(tree.problems(), "disagree about date/workers/cores")) == 1


def test_a_green_row_that_reports_no_state_count(tree):
    """`check_record` skips the distinct floor on a non-digit, so a GREEN row
    whose two halves politely agree there is nothing to compare escapes
    `floors.txt` entirely — and the published table loses the numbers to an em
    dash. TLC prints a summary on every run that reaches a verdict."""
    tree.write("formal/runs.toml", tree.record(
        safety=MATRIX_SAFETY.replace("states=4000  distinct=200 depth=6",
                                     "states=?     distinct=?   depth=?"),
        tlc=tlc_kept(tree.when)["safety"].replace(
            "4000 states generated, 200 distinct states found, 0 states left on queue."
            " The depth of the complete state graph search is 6. ", "")))
    assert only(tree.problems(), "came back GREEN and TLC printed no state count")


def test_a_green_row_with_states_left_on_its_queue(tree):
    """`queue` was captured by `TLC_ROW` and compared to nothing, so a record
    could claim an exhaustive GREEN while its own next words said a billion
    states were never explored."""
    tree.edit("formal/runs.toml", "200 distinct states found, 0 states left",
              "200 distinct states found, 999999999 states left")
    assert only(tree.problems(), "states on its queue — an exhaustive run leaves none")


def test_a_red_row_may_leave_states_on_its_queue(tree):
    """The other direction, and the reason the rule is about GREEN: TLC stops
    where it finds the error, so a queue is what a RED row IS. 148 of the 199
    recorded rows carry one."""
    tree.edit("formal/runs.toml", "40 distinct states found, 0 states left",
              "40 distinct states found, 12 states left")
    assert not only(tree.problems(), "states on its queue")


def test_more_distinct_states_than_were_generated(tree):
    """The other field of TLC's own sentence that nothing read. No run finds more
    distinct states than it made, so the pair is checkable without a second
    program — and `states` alone is held only to the matrix's copy of itself."""
    tree.write("formal/runs.toml", tree.record(
        safety=MATRIX_SAFETY.replace("states=4000 ", "states=1    "),
        tlc=tlc_kept(tree.when)["safety"].replace("4000 states generated", "1 states generated")))
    assert only(tree.problems(), "distinct among them — no run finds more")


def test_a_number_where_tlc_printed_nothing(tree):
    """The other direction of the same agreement, which nothing drove: the case
    above has the matrix say `?` where TLC printed a number, and this one has the
    matrix say a number where TLC printed none."""
    tree.write("formal/runs.toml", tree.record(
        tlc=tlc_kept(tree.when)["safety"].replace(
            "4000 states generated, 200 distinct states found, 0 states left on queue."
            " The depth of the complete state graph search is 6. ", "")))
    assert only(tree.problems(), "recorded states=4000 and TLC's own summary says nothing")


def test_write_will_not_publish_from_a_record_that_does_not_check_out(tree):
    """The laundering step, and the row's own message sends people to it: the
    gate says "run --write and commit the result", and `--write` used to rewrite
    every published sentence from whatever the record now said."""
    tree.edit("formal/runs.toml", "distinct=200", "distinct=48")
    assert run_count_gate.run(tree.root, ["--write"]) == 1
    assert "48 distinct states" not in tree.read("docs/testing.md")


def test_two_runs_for_one_tier(tree):
    tree.write("formal/runs.toml", tree.read("formal/runs.toml") + "\n[[run]]\ntier = \"safety\"\n")
    assert only(tree.problems(), "one run per tier")


def test_a_tier_the_record_has_never_seen(tree):
    """And it is ONE cause: without this rule the Results groups said the family
    had gone from the tree and the region generator raised `KeyError`, so a
    reader was told the tree is wrong when a run is simply missing."""
    kept = tree.read("formal/runs.toml")
    tree.write("formal/runs.toml", kept[: kept.index('\n[[run]]\ntier = "safety"')]
               + kept[kept.index('\n[[run]]\ntier = "safety"'):kept.index('\n[[run]]\ntier = "liveness"')])
    problems = tree.problems()
    assert problems == only(problems, "has no run of it"), problems


def test_a_tier_the_runner_does_not_list(tree):
    tree.edit("formal/runs.toml", 'tier = "liveness"', 'tier = "midnight"')
    assert only(tree.problems(), "has a run of midnight and formal/run-tlc.sh lists no tier")


def test_no_record_at_all(tree):
    (tree.root / "formal/runs.toml").unlink()
    assert only(tree.problems(), "no run has been recorded")


def test_a_record_with_no_runs_in_it(tree):
    tree.write("formal/runs.toml", "# nothing here\n")
    assert only(tree.problems(), "holds no [[run]]")


def test_the_runner_refusing_the_query(tree):
    """`--tiers` is the one thing this gate asks of the runner. If it stops
    answering, every comparison below loops over an empty roster and passes."""
    tree.write("formal/run-tlc.sh", "#!/usr/bin/env bash\nexit 3\n")
    (tree.root / "formal/run-tlc.sh").chmod(0o755)
    assert only(tree.problems(), "--tiers exited 3")


# --- the totals are counted, never stored ----------------------------------


def test_the_wall_clock_is_the_sum_of_the_rows(tree):
    """Not a field: a stored total is the second copy this row exists to remove."""
    assert "607 s" in tree.read("docs/testing.md"), tree.read("docs/testing.md")
    tree.write("formal/runs.toml", tree.record(safety=MATRIX_SAFETY.replace(" 600s", " 900s")))
    assert "907 s" in tree.bodies()[("docs/testing.md", "tlc-measured")]


def test_the_tally_is_counted_out_of_the_verdicts(tree):
    body = tree.bodies()[("docs/testing.md", "tlc-measured")]
    assert "1 GREEN, 1 RED" in body, body


# --- the generated regions -------------------------------------------------


def test_a_number_edited_by_hand_inside_a_region(tree):
    """The sentence this whole row is named after."""
    tree.edit("docs/testing.md", "1 GREEN, 1 RED", "191 GREEN, 1 RED")
    assert only(tree.problems(), "docs/testing.md: a generated region is not what the generator writes")


def test_a_region_inside_a_blockquote_keeps_its_prefix(tree):
    """Every emitted line carries whatever the start marker's line began with, or
    the region breaks the quote it sits in."""
    body = tree.read("docs/testing.md")
    assert "> <!-- Generated by scripts/run_count_gate.py --write" in body, body
    assert "> TLC checks 2 named invariants exhaustively over 200 distinct" in body, body
    assert body.count("\n> ") >= 4, body


def test_a_region_after_prose_is_refused(tree):
    """A marker owns its line: anything but `>` and whitespace in front of it is
    text the generator would swallow on the next write."""
    tree.edit(
        "docs/testing.md",
        "> <!-- run-count-shipped-row:start -->",
        "> and then <!-- run-count-shipped-row:start -->",
    )
    assert only(tree.problems(), "a marker owns its line")


def test_a_region_whose_markers_went_away(tree):
    tree.edit("formal/README.md", "<!-- run-count-liveness-row:end -->", "")
    assert only(tree.problems(), "needs exactly one 'liveness-row' marker pair")


def test_a_region_pasted_twice(tree):
    tree.write("docs/formal.md", tree.read("docs/formal.md") + FORMAL_MD)
    assert only(tree.problems(), "needs exactly one 'tlc-measured' marker pair")


def test_a_region_the_generator_does_not_own(tree):
    """The hole this guard shipped with, kept: `mask_regions` blanks a region out
    of the scan, so a marker pair nothing generates hides a typed number from
    both halves at once."""
    tree.write(
        "docs/typed.md",
        "<!-- run-count-invented:start -->\n`safety` came back over 190 rows.\n"
        "<!-- run-count-invented:end -->\n",
    )
    assert only(tree.problems(), "a run-count region named 'invented'")


def test_write_puts_the_tree_back(tree):
    tree.edit("docs/testing.md", "1 GREEN, 1 RED", "191 GREEN, 1 RED")
    assert tree.problems()
    run_count_gate.run(tree.root, ["--write"])
    assert tree.problems() == []


def test_the_roster_sentence_is_derived_from_the_tree(tree):
    """`switches` and `families` come out of `formal/`, not out of the record."""
    body = " ".join(tree.bodies()[("docs/testing.md", "tlc-roster")].split())
    assert "2 `Bug*` switches exist" in body and "`BugBarOpens` has none" in body, body


def test_a_recorded_configuration_in_no_results_group(tree, monkeypatch):
    """The table would silently not show it, under a sentence saying every row
    of it is from one run."""
    monkeypatch.setattr(run_count_gate, "TABLE_GROUPS", GROUPS[1:])
    assert only(tree.problems(), "Shipped.cfg is in no Results group")
    assert only(tree.problems(), "a generated region is not what the generator writes")


def test_a_results_group_that_matches_nothing(tree, monkeypatch):
    monkeypatch.setattr(
        run_count_gate, "TABLE_GROUPS", GROUPS + (("`Gone_*.cfg` — a family", ("Gone_*.cfg",)),)
    )
    assert only(tree.problems(), "matches no recorded configuration")


def test_the_results_table_counts_come_out_of_the_record(tree):
    body = tree.bodies()[("formal/README.md", "results-table")]
    assert "| 900 | 44 | 9 | 300 s |" in body, body
    assert "| 4 000 | 200 | 6 | 600 s |" in body, body
    assert "**GREEN**" in body and "`RED: FooStaysClosed`" in body, body


def test_the_comutant_roster_sentence_reads_its_registry(tree):
    tree.edit("formal/comutants.toml", "phase2_count = 2", "phase2_count = 1")
    assert only(tree.problems(), "a generated region is not what the generator writes")


# --- the scan: the spellings -----------------------------------------------


def typed(tree, text, name="docs/typed.md"):
    tree.write(name, text)
    return only(tree.problems(), "is a run-count outside every generated region")


def test_a_count_and_a_noun(tree):
    assert typed(tree, "The `safety` tier came back over 190 rows.\n")


def test_a_tally_needs_no_runner_beside_it(tree):
    """Nothing else in this tree is counted in GREEN and RED."""
    assert typed(tree, "It answered 18 GREEN and 172 RED.\n")


def test_a_count_with_no_run_named_is_not_one(tree):
    """The boundary, asserted: a guard that flags every number is deleted."""
    assert not typed(tree, "OTP is addressed in rows of 24 bits, in pages of 64 rows.\n")


def test_the_word_spelling(tree):
    assert typed(tree, "`liveness` took a while for its four liveness rows.\n")


def test_a_tally_the_tight_form_cannot_see(tree):
    assert typed(tree, "`run-tlc.sh safety` lists them: 20 that must come back GREEN.\n")


def test_a_wall_clock(tree):
    assert typed(tree, "`run-tlc.sh --tiers` says so; the tier took 2916 s.\n")


# Every one of these was a measured bypass at exit 0. They are the SAME claim in
# a spelling nobody had enumerated, which is what a shape rule always has one
# more of — the reason the value rule beside it is generated from the number.
@pytest.mark.parametrize("sentence", (
    "`run-tlc.sh safety` visited 195 states.",              # what a run PRODUCED
    "`run-tlc.sh safety` covered 195 mutants.",
    "`run-tlc.sh --tiers` lists 190+ rows.",                # a rounded-up count
    "`run-tlc.sh --tiers` lists _195 rows_.",               # `_` is a word char
    "`run-tlc.sh --tiers` lists 195 \u2014 rows.",           # an em dash is not `-`
    "The matrix came back GREEN: 20, RED: 174.",            # the tally, reversed
    "`run-tlc.sh --tiers` finished in 00:53:45.",           # a clock with no unit
    "`run-tlc.sh --tiers` took 3 hours.",
    "`run-tlc.sh --tiers` is a 54-minute run.",
    "`run-tlc.sh --tiers` is a 3225-second run.",
    "`run-tlc.sh --tiers` lists 77\u00a0563\u00a0872 rows.",  # NBSP grouping
    "`run-tlc.sh --tiers` lists 77\u2009563\u2009872 rows.",  # thin space
))
def test_a_spelling_the_shape_rules_walked_past(tree, sentence):
    assert typed(tree, sentence + "\n"), sentence


@pytest.mark.parametrize("sentence", (
    "`run-tlc.sh --tiers` took about an hour.",
    "The matrix came back 1 passed, 1 failed.",
))
def test_a_spelling_no_shape_rule_reaches(tree, sentence):
    """Kept as cases because they are OPEN, not because they are closed: "about
    an hour" carries no number for a numeric rule to find, and `passed/failed`
    is not this tree's vocabulary. Widening either costs more than it buys —
    measured over this tree, dropping the paragraph-local trigger takes the scan
    from 41 literals to 549, of which 505 want registering. The rules that do not
    play this game are the two generated ones below, and they only reach what the
    regions actually print.

    A third sentence stood here — "A run of the safety tier came back over 195
    configurations", the same claim with the trigger word left out — and it is
    the case below now. It was never a spelling: any paragraph restating every
    published number without saying `safety`, `liveness`, `run-tlc`, `comutate`
    or `--tiers` was five lines at exit 0.
    """
    assert not typed(tree, sentence + "\n"), sentence


# --- the THIRD rule: a value and the unit the regions print beside it ---------
#
# `VALUE_FLOOR` is floored by magnitude, so `8 named invariants`, `the nine
# shipped models` and `18 cores` were under no rule at all in ANY paragraph, and
# the shape rules above are armed by a word in the same paragraph, so leaving
# that word out bought silence for the rest. A value WITH ITS UNIT needs neither:
# it is generated from what the region says, like the value rule, and it reaches
# below the floor because `2 configurations` is not every other number.


def second_copy(tree, text, name="docs/typed.md"):
    tree.write(name, text)
    return only(tree.problems(), "is a second copy of")


@pytest.mark.parametrize("sentence", (
    "A run of the safety tier came back over 2 configurations.",   # no trigger
    "TLC checks 2 named invariants over the nine shipped models.",  # not a NOUN
    "It came back 1 green, at 607 s.",                             # and lower case
))
def test_a_published_value_and_its_unit_with_no_run_named(tree, sentence):
    """The paragraph the trigger let past, and the two claims no rule reached at
    all. Every number here is one the fixture's own regions publish."""
    assert second_copy(tree, sentence + "\n"), sentence


@pytest.mark.parametrize("sentence", (
    "The whole thing cost 607 seconds.",     # the generator writes `607 s`
    "The roster holds 2 switches.",          # it writes `2 configurations`
))
def test_a_published_value_under_another_word_of_the_same_kind(tree, sentence):
    """The generator's word is not the only one a page uses, and a correct copy
    under a synonym is a copy that rots: `71 entries` is the `71-entry` roster,
    the sentence a commit in this series had to hand-correct from 69. Widened
    only into the two vocabularies this file already enumerates for the shape
    scan — measured over the real tree, 4 more occurrences, 2 of them real."""
    assert second_copy(tree, sentence + "\n"), sentence


def test_a_published_value_under_a_word_of_another_kind(tree):
    """And the boundary: 607 is a wall clock, so a roster noun beside it is not
    the same claim. A rule that crossed the two kinds would be `COUNT` and
    `CLOCK` merged, which is every number with a word after it."""
    assert not second_copy(tree, "The roster holds 607 switches.\n")


def test_a_value_beside_a_word_the_regions_do_not_put_there(tree):
    """The boundary, asserted: the unit comes from the generated sentence, so a
    value under a different noun is not this claim and is not a finding. A rule
    that fired on `2 kittens` would be the aggregate scan without its floor."""
    assert not second_copy(tree, "There were 2 kittens and 607 kittens.\n")


def test_a_value_and_its_unit_are_one_finding_not_two(tree, big):
    """`200 distinct` is a value the regions print AND a phrase they print. Two
    findings would say the page holds two copies, and inside a registered
    fragment would spend `SCOPE_SPAN_CAP` twice for one literal."""
    tree.write("docs/typed.md", "# Typed\n\nIt reached 200 distinct states.\n")
    assert ("200", "distinct") in run_count_gate.phrased(tree.bodies())
    assert len(only(tree.problems(), "is a second copy of")) == 1, tree.problems()


def test_the_results_table_is_not_a_source_of_phrases(tree):
    """Its cells are `3` and `1 s` in units every other row shares, so a rule
    hunting them tree-wide would be a rule about every number there is."""
    pairs = run_count_gate.phrased(tree.bodies())
    assert ("600", "s") not in pairs and ("7", "s") not in pairs, sorted(pairs)


#: `"date"` rather than the date: the fixture stamps its record with TODAY
#: (`a_minute_from_now`), so the day this case speaks has to come from the fixture
#: too. Hard-coded, it asserted the gate over a date the fixture had stopped
#: publishing — green for one day, then red on the rollover with nothing changed.
@pytest.mark.parametrize("spoken", ("date", "WORKERS=2"))
def test_the_provenance_a_region_prints_verbatim(tree, spoken):
    """The date's three numbers are all under the value floor and `WORKERS=2`
    wears its unit on the left, so `PAIR` pairs it with the next word. Each is
    published on three pages and neither was held by anything."""
    if spoken == "date":
        spoken = tree.when.split()[0]
    assert second_copy(tree, f"Recorded on {spoken} on this box.\n"), spoken


#: Every separator [`GROUP`] holds. Each is asserted as the WHOLE literal,
#: because a case that asserts only that something fired passes with the
#: separator deleted: the rule then matches the truncated tail and the finding
#: names `'563 872 rows'`, which is `test_a_literal_is_reported_whole`'s own
#: defect wearing a lost separator. `340e515` added the three invisible
#: characters as the fix for a measured bypass and its two cases were exactly
#: that shape -- delete them again and the suite was green.
#:
#: This is also the only thing that sees a rule NARROWED. `RULE_FLOOR` counts
#: matches, and hollowing `GROUP` or `JOIN` moves none of the five tallies at all
#: (67/3/21/5/13 before and after), so the floor sees a rule killed and never one
#: that has quietly stopped holding a member.
@pytest.mark.parametrize("sep", (" ", "\u00a0", "\u2009", "\u202f", ",", "_"))
def test_every_grouping_the_count_rule_holds(tree, sep):
    number = sep.join(("77", "563", "872"))
    tree.write("docs/typed.md", f"`run-tlc.sh --tiers` lists {number} rows.\n")
    assert only(tree.problems(), repr(f"{number} rows")), tree.problems()


@pytest.mark.parametrize("join", (" ", "-", "\u2013", "\u2014"))
def test_every_join_the_count_rule_holds(tree, join):
    tree.write("docs/typed.md", f"`run-tlc.sh --tiers` lists 195{join}rows.\n")
    assert only(tree.problems(), repr(f"195{join}rows")), tree.problems()


def test_a_literal_is_reported_whole(tree):
    """`48.7 M-state GREEN` was reported as `'7 M-state GREEN'`: `NUM` stopped at
    the decimal point, so the finding named a number that is not in the page."""
    tree.write("docs/typed.md", "# Typed\n\n`run-tlc.sh safety` swept 48.7 M states.\n")
    assert only(tree.problems(), "'48.7 M states'")


def test_inside_a_fenced_code_block(tree):
    """Where the first of these was found: a shell comment in a ```sh fence."""
    assert typed(tree, "```sh\n./run-tlc.sh safety   # floors: 190 rows, 2916 s\n```\n")


def test_a_yaml_comment_run(tree):
    tree.edit(
        ".github/workflows/deep-checks.yml",
        "every configuration `run-tlc.sh safety` lists.",
        "the 194 configurations `run-tlc.sh safety` lists.",
    )
    assert only(tree.problems(), "'194 configurations' is a run-count")


#: The runner's own matrix line, verbatim. Its FIELD WIDTHS read as six
#: run-counts — `42s`, `38s`, `38s states`, `9s`, `8s`, `3s` — of a run that
#: never happened, and the line had not changed a byte: a comment twenty lines
#: below it began naming a tier, and a shell function has no blank line in it.
MATRIX_PRINTF = r"""printf '%-42s %-38s states=%-9s distinct=%-8s depth=%-3s %ss%s\n' \
"""


def test_a_field_width_is_not_a_measurement(tree):
    """The runner named on purpose: with no trigger in the block no rule is armed
    and this case would pass with the mask deleted."""
    assert not typed(tree, "`run-tlc.sh safety` prints one row per configuration:\n"
                     + MATRIX_PRINTF)


def test_a_real_count_on_the_line_of_a_field_width(tree):
    """The direction the mask could take with it — a measurement is still one
    when a conversion specification stands beside it."""
    assert typed(tree, "`run-tlc.sh safety` prints one row per configuration:\n"
                 + MATRIX_PRINTF.rstrip() + "   # over 1234 rows\n")


def test_a_real_count_on_the_line_after_a_field_width(tree):
    assert typed(tree, "`run-tlc.sh safety` prints one row per configuration:\n"
                 + MATRIX_PRINTF + "# and it swept 1234 states doing it\n")


def test_a_typed_count_in_the_runner_own_comment(tree):
    """The constructed defect, in the file the mask was written for and in the
    shape the seventh finding had: a figure typed into a `run-tlc.sh` comment,
    one line above the widths that must not be figures at all. `exit 0` keeps the
    appended lines out of the `--tiers` query and inside the same block, which is
    what arms them."""
    tree.write(
        "formal/run-tlc.sh",
        RUN_TLC + "exit 0\n"
        "# BugSetPinKeepsPpuat explored 1234 states without a counterexample.\n"
        + MATRIX_PRINTF + '  "$cfg" "$verdict"\n',
    )
    problems = tree.problems()
    assert only(problems, "'1234 states' is a run-count"), problems
    assert not [p for p in problems if "'42s'" in p or "'38s" in p], problems


def test_the_field_width_mask_is_what_keeps_the_runner_green(monkeypatch):
    """The mask's deletion arm, on the tree this actually guards rather than on a
    fixture: with `FORMAT` dead the runner's `printf` is six run-counts again,
    which is the red this was written for."""
    monkeypatch.setattr(run_count_gate, "FORMAT", run_count_gate.re.compile("(?!x)x"))
    problems = run_count_gate.audit(ROOT)[0]
    assert len(only(problems, "formal/run-tlc.sh:")) == 6, problems
    for literal in ("'42s'", "'38s'", "'38s states'", "'9s'", "'8s'", "'3s'"):
        assert only(problems, f"{literal} is a run-count"), literal


def test_the_runner_own_historical_measurement_is_registered(monkeypatch):
    """The other clause's deletion arm. The seventh finding was a REAL figure and
    is registered, not masked — so dropping its entry brings the measurement back
    and none of the widths with it."""
    key = ("formal/run-tlc.sh", "# 40 459 667 states without a counterexample")
    trimmed = {k: v for k, v in run_count_gate.SCOPED.items() if k != key}
    assert len(trimmed) == len(run_count_gate.SCOPED) - 1, "the entry has been renamed"
    monkeypatch.setattr(run_count_gate, "SCOPED", trimmed)
    monkeypatch.setattr(run_count_gate, "SCOPE_CEILING", len(trimmed))
    problems = run_count_gate.audit(ROOT)[0]
    assert only(problems, "'40 459 667 states' is a run-count"), problems
    assert len(only(problems, "formal/run-tlc.sh:")) == 1, problems


def test_a_table_row_borrows_no_runner_from_its_neighbours(tree):
    """A markdown table has no blank line in it, so the whole table was one
    block and one cell naming the runner turned the trigger on for the rest.
    The same table with both halves in ONE cell is the control: the rule is the
    row boundary, not the table."""
    assert not typed(
        tree,
        "| what | how many |\n|---|---|\n| `run-tlc.sh` rows | many |\n| other | 40 rows |\n",
    )
    assert typed(
        tree,
        "| what | how many |\n|---|---|\n| `run-tlc.sh safety` | 40 rows |\n",
    )


def test_inside_a_region_is_not_outside_one(tree, monkeypatch):
    """The mask, in the direction that matters: the generated sentence carries
    every spelling above and must not be reported as a typed one. With the mask
    taken away it is — which is what says the case is not passing for free."""
    assert not only(tree.problems(), "is a run-count outside every generated region")
    monkeypatch.setattr(run_count_gate, "mask_regions", lambda text: text)
    assert only(tree.problems(), "is a run-count outside every generated region")


# --- the scan: the scope registry ------------------------------------------


def test_a_scoped_literal_is_not_a_finding(tree, monkeypatch):
    monkeypatch.setattr(
        run_count_gate, "SCOPED", {("docs/typed.md", "over 190 rows"): "history"}
    )
    assert not typed(tree, "The `safety` tier came back over 190 rows.\n")


def test_a_scope_entry_that_matches_nothing(tree, monkeypatch):
    monkeypatch.setattr(run_count_gate, "SCOPED", {("docs/testing.md", "over 190 rows"): "history"})
    assert only(tree.problems(), "matches nothing — a stale exemption")


def test_a_scope_entry_that_matches_twice(tree, monkeypatch):
    """And the literals go on being findings while it does: a fragment that is not
    one occurrence protects nothing, which is the direction that must not invert."""
    monkeypatch.setattr(
        run_count_gate, "SCOPED", {("docs/typed.md", "over 190 rows"): "history"}
    )
    assert len(typed(tree, "`safety` came back over 190 rows, and again over 190 rows.\n")) == 2
    assert only(tree.problems(), "occurs 2 times — a figure worth a scope label")


def test_a_literal_outside_the_fragment_that_resembles_it(tree, monkeypatch):
    """The span rule. Registering one sentence must not exempt the next one that
    happens to say the same words."""
    monkeypatch.setattr(
        run_count_gate,
        "SCOPED",
        {("docs/typed.md", "was 190 rows in 2003 s"): "the tier before the widening"},
    )
    assert typed(
        tree,
        "`safety` was 190 rows in 2003 s before the widening.\n\n"
        "`safety` is 195 rows now.\n",
    )


# --- the registry itself, whose values nothing read --------------------------
#
# `SCOPED`'s labels were never looked at, so `""`, `None`, one word, six
# nonsense words and a description of an ENTIRELY DIFFERENT RUN each bought a
# brand-new stale literal an exemption. The last of those still passes and
# always will — no rule tells a right scope from a wrong one — so what is held
# here is that a label exists, was written for its own entry, and points at a
# page this gate reads, and that the silence one entry buys is bounded.

LONG = "a scope label with comfortably more than eight words in it"


@pytest.mark.parametrize("label", ("", None, "history", "the liveness tier in 2019"))
def test_a_scope_entry_whose_label_is_not_one(tree, monkeypatch, label):
    monkeypatch.setattr(run_count_gate, "SCOPED", {("docs/testing.md", "x"): label})
    assert only(tree.problems(), "word(s), under 8")


def test_a_scope_label_pasted_from_another_entry(tree, monkeypatch):
    monkeypatch.setattr(run_count_gate, "SCOPED", {
        ("docs/testing.md", "a"): LONG, ("docs/formal.md", "b"): LONG,
    })
    assert only(tree.problems(), "word for word")


def test_a_scope_entry_for_a_page_the_scan_does_not_read(tree, monkeypatch):
    monkeypatch.setattr(run_count_gate, "SCOPED", {("CHANGELOG.md", "a"): LONG})
    assert only(tree.problems(), "names a file the scan does not read")


def test_a_registry_over_its_ceiling(tree, monkeypatch):
    monkeypatch.setattr(run_count_gate, "SCOPE_CEILING", 1)
    monkeypatch.setattr(run_count_gate, "SCOPED", {
        ("docs/testing.md", "a"): LONG, ("docs/formal.md", "b"): LONG + " twice",
    })
    assert only(tree.problems(), "against a ceiling of 1")


def test_a_fragment_that_exempts_nothing(tree, monkeypatch):
    """Not the same as one that matches nothing: this string IS in the page, and
    covers no literal at all — the rules have moved past it."""
    monkeypatch.setattr(run_count_gate, "SCOPED",
                        {("docs/testing.md", "Tier membership lives in"): LONG})
    assert only(tree.problems(), "exempts no literal")


def test_a_fragment_that_exempts_more_than_its_cap(tree, monkeypatch):
    """One entry silenced seven literals in the real tree. A registry entry buys
    its own span, and a span can be a whole paragraph."""
    monkeypatch.setattr(run_count_gate, "SCOPE_SPAN_CAP", 1)
    tree.write("docs/typed.md",
               "# Typed\n\n`run-tlc.sh safety` covers 190 rows in 2916 s, 18 GREEN.\n")
    monkeypatch.setattr(run_count_gate, "SCOPED", {
        ("docs/typed.md", "covers 190 rows in 2916 s, 18 GREEN"): LONG,
    })
    assert only(tree.problems(), "over the cap of 1")


def test_the_published_pages_at_the_root_are_scanned(tree):
    """The obvious escape from a rule scoped to three directories."""
    tree.write("README.md", "# RS-Key\n\n`run-tlc.sh safety` covers 190 rows.\n")
    tree.commit("a published page at the root")
    assert only(tree.problems(), "README.md:3: '190 rows'")


def test_an_untracked_working_file_at_the_root_is_not(tree):
    """This tree keeps a large untracked planning document at the root on purpose,
    and a gate that reddens on a file nobody committed is one people switch off.

    The reason used to be TWO NAMES on a whitelist, while this docstring said
    untrackedness — so it claimed a property the code did not have, and every
    other page at the root (`SECURITY.md`, `COMPLIANCE.md`, `AGENTS.md`,
    `CODEX.md`) was out of the scan for a reason nobody had chosen. The set comes
    from `git ls-files` now, so the sentence is the mechanism.
    """
    tree.stray("PLANNING.md", "`run-tlc.sh safety` covers 190 rows.\n")
    assert not only(tree.problems(), "PLANNING.md")


@pytest.mark.parametrize("rel", (
    "formal/observed-runs.md",     # a new page in the tree the criterion NAMES
    "formal/floors.txt",           # the registry's own header prose
    "formal/Mini.tla",             # a `\\*` comment in a model
    "formal/run-tlc.sh",           # a `#` comment in the runner itself
    "formal/comutants.toml",       # and in a registry beside it
    ".github/summary.json",        # `.github/` was three suffixes, not a directory
    ".github/publish.sh",
    "SECURITY.md",                 # the root was two names, not the root
    "docs/observed.txt",           # `docs/` was `*.md`, not `docs/`
))
def test_a_count_typed_anywhere_under_the_trees_the_criterion_names(tree, rel):
    """All nine driven against the old rule at exit 0, with 13 more. The criterion
    names `docs/`, `formal/` and `.github/` BY DIRECTORY and the scan was a suffix
    whitelist under each, so `check.sh` stated a rule the code did not implement
    in all four of its parts. Widening it costs 0 literals over the real tree."""
    path = tree.root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    lead = "\\* " if rel.endswith(".tla") else "# " if rel.endswith((".sh", ".toml")) else ""
    path.write_text((path.read_text() if path.exists() else "")
                    + f"\n\n{lead}`run-tlc.sh safety` covers 190 rows.\n")
    tree.commit(f"a count typed in {rel}")
    assert only(tree.problems(), f"{rel}:"), rel


@pytest.mark.parametrize("line", (
    "  probe:\n    name: run-tlc --tiers over 190 rows",
    "  probe:\n    env:\n      NOTE: 'run-tlc --tiers, 190 rows'",
    "  probe:\n    steps:\n      - run: echo '19 GREEN, 171 RED' >> $GITHUB_STEP_SUMMARY",
))
def test_a_count_in_yaml_that_is_not_a_comment(tree, line):
    """Only `#` runs were read, so a count in a `name:`, an `env:` or the step
    summary a workflow PUBLISHES was invisible — driven, exit 0. Its own block and
    not part of a paragraph: a workflow has few blank lines and one step naming
    the runner would otherwise arm every other."""
    rel = ".github/workflows/deep-checks.yml"
    tree.write(rel, tree.read(rel) + "\n" + line + "\n")
    tree.commit("a count in a yaml value")
    assert only(tree.problems(), f"{rel}:")


# The carve-out list is the SECOND exemption registry on this row, and it landed
# with the defect the first was measured to have: reasons nothing read, and no
# ratchet on how many there are.


@pytest.mark.parametrize("why", ("", None, "history"))
def test_a_carve_out_whose_reason_is_not_one(tree, monkeypatch, why):
    monkeypatch.setattr(run_count_gate, "NOT_TYPED_HERE", {"CHANGELOG.md": why})
    assert only(tree.problems(), "the same rule its sibling registry has")


def test_a_carve_out_list_over_its_ceiling(tree, monkeypatch):
    monkeypatch.setattr(run_count_gate, "CARVE_OUT_CEILING", 1)
    assert only(tree.problems(), "against a ceiling of 1")


@pytest.mark.parametrize("rel", sorted(run_count_gate.NOT_TYPED_HERE))
def test_a_count_typed_in_a_file_carved_out_of_the_scan(tree, rel):
    tree.write(rel, "`run-tlc.sh safety` covers 190 rows.\n")
    assert not only(tree.problems(), f"{rel}:")


def test_a_carve_out_for_a_file_that_has_gone(tree):
    """`CHANGELOG.md` and not `formal/runs.toml`: the record going away is
    reported by `load()` before anything else runs, and one cause is one message
    — a reader told the carve-out is stale would go looking for the wrong thing."""
    (tree.root / "CHANGELOG.md").write_text("x\n")
    tree.git("add", "-N", "--", "CHANGELOG.md")
    tree.commit("a changelog to take away")
    (tree.root / "CHANGELOG.md").unlink()
    assert only(tree.problems(), "a carve-out nobody has is one nobody is reading")


# --- the OTHER rule: a value the generator prints, said a second time ---------
#
# The four rules above hunt for run-count-SHAPED text, and the shapes are
# unbounded — every case below was a measured bypass of them. This one is
# generated FROM the number instead, so it needs no noun, no trigger and no
# guess about phrasing, and its spellings are closed by construction. What it
# cannot see is a ROUNDED copy and a STALE one, which is why both rules are kept.


@pytest.fixture
def big(monkeypatch):
    """The fixture's own counts are three digits, so the rule is floored down to
    reach them. The REAL floor is exercised against the REAL tree below."""
    monkeypatch.setattr(run_count_gate, "VALUE_FLOOR", 100)


@pytest.mark.parametrize("spelled", ("4000", "4,000", "4 000", "4_000", "4\u00a0000",
                                    "4\u2009000", "4\u202f000"))
def test_a_second_copy_of_a_value_the_regions_print(tree, big, spelled):
    """No runner named, no roster noun, no tally: every one of the four shape
    rules is silent here and the number is still a second copy that will rot.

    Every grouping, including the NBSP and the two thin spaces `NUM`'s own class
    has never held — because these are generated FROM the value rather than
    parsed out of prose, which is the whole difference between the two rules."""
    tree.write("docs/typed.md", f"# Typed\n\nThe model reaches {spelled} of them.\n")
    assert only(tree.problems(), "docs/typed.md:3:"), spelled


def test_a_second_copy_re_wrapped_across_a_line(tree, big):
    """`77 563 872` re-wrapped by an editor is `77 563` at the end of one line and
    `872` at the start of the next. A list of whole spellings could not see that —
    the same enumerate-the-shapes mistake this rule exists in order not to make,
    one level down inside it."""
    tree.write("docs/typed.md", "# Typed\n\nThe model reaches 4\n000 of them.\n")
    assert only(tree.problems(), "is a second copy of 4000")


def test_a_value_the_generator_wrapped_mid_number_is_still_hunted_for():
    """The same wrap on the OTHER side of the rule, where it is silent. `emitted`
    carried its own retyped copy of the grouping class with the newline left out,
    so a value `fill` broke between groups came back as `563 872` and the real
    `77 563 872` was then hunted for by nothing at all. Read as the set, because
    nothing fails when this happens — a number simply stops being guarded."""
    body = run_count_gate.fill("wwww " * 12 + "the count was 77 563 872 distinct states")
    assert "77\n563" in body, body
    assert 77563872 in run_count_gate.emitted({("x", "y"): body})


@pytest.mark.parametrize("around", ("0x{}", "abc{}", "{}5", "1{}"))
def test_a_value_inside_something_that_is_not_a_number(tree, big, around):
    """A hex constant and an identifier are not this number. `0x4000` matched
    while the guard refused only a digit, a dot, a comma or an underscore."""
    tree.write("docs/typed.md", f"# Typed\n\nSee {around.format(4000)} for it.\n")
    assert not only(tree.problems(), "second copy of 4000"), around


def test_a_value_ending_a_sentence_is_still_one(tree, big):
    """The other direction of the same guard: a full stop after the number is a
    sentence, and refusing every trailing `.` would lose most of the prose."""
    tree.write("docs/typed.md", "# Typed\n\nThe model reaches 4000.\n")
    assert only(tree.problems(), "second copy of 4000")


def test_a_value_under_the_floor_is_nobody_second_copy(tree, big):
    """The other direction, and the reason the floor exists: `6` is `Shipped.cfg`'s
    depth in this fixture and every other small number in the tree. Measured over
    the real corpus, the rule finds 10 862 occurrences at no floor and 11 at ten
    thousand, of which none is a coincidence."""
    tree.write("docs/typed.md", "# Typed\n\nThe search went 6 deep.\n")
    assert not only(tree.problems(), "second copy of 6")


def test_a_second_copy_inside_a_registered_fragment(tree, big, monkeypatch):
    monkeypatch.setattr(
        run_count_gate, "SCOPED",
        {("docs/typed.md", "reached 200 of them back then"): "history"},
    )
    tree.write("docs/typed.md", "# Typed\n\nIt reached 200 of them back then.\n")
    assert not only(tree.problems(), "second copy of 200")


def test_the_value_rule_with_nothing_left_to_look_for(monkeypatch):
    """Against the real checkout: raise the floor past every number the regions
    print and the rule is inert, which is the shape audit run-34 #9 is about."""
    monkeypatch.setattr(run_count_gate, "VALUE_FLOOR", 10 ** 12)
    assert only(run_count_gate.audit(ROOT)[0], "the emitted-value rule matched 0")


def test_a_tracked_page_the_scan_cannot_decode(tree):
    """`scanned` swallowed a `UnicodeDecodeError` "rather than reported", so a
    page in any other encoding dropped out of the scan with nothing said. Costs
    nothing today -- all 21 files that do not decode in the real tree are images
    -- which is why it had to be driven rather than assumed."""
    tree.stray("docs/other.md", "")
    (tree.root / "docs/other.md").write_bytes(
        "# Cost\n\nCaf\xe9 ran `run-tlc.sh safety` in 2916 s.\n".encode("latin-1"))
    tree.pending.add("docs/other.md")
    assert only(tree.problems(), "does not decode as UTF-8")


def test_a_tracked_page_the_scan_cannot_open(tree):
    """The other silence in the same place: a page that is THERE and cannot be
    read left the scan with nothing said, the way one that does not decode did."""
    tree.write("docs/shut.md", "# Shut\n\n`run-tlc.sh safety` took 2916 s.\n")
    (tree.root / "docs/shut.md").chmod(0o000)
    try:
        assert only(tree.problems(), "cannot be read")
    finally:
        (tree.root / "docs/shut.md").chmod(0o644)


def test_a_tracked_page_that_is_only_gone_is_not_one(tree):
    """And the direction that must NOT redden: a tracked file deleted and not yet
    `git rm`ed is an ordinary working tree, not a page the scan cannot read."""
    tree.write("docs/going.md", "# Going\n\nNothing here.\n")
    tree.track()
    (tree.root / "docs/going.md").unlink()
    assert not only(tree.problems(), "cannot be read")


def test_a_binary_file_under_a_scanned_tree_is_not_a_page(tree):
    """The other direction, and the reason the two are told apart by a NUL byte
    the way git tells them apart: an image carries no prose and 21 of them are
    tracked under `docs/`."""
    tree.stray("docs/shot.png", "")
    (tree.root / "docs/shot.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe")
    tree.pending.add("docs/shot.png")
    assert not only(tree.problems(), "does not decode as UTF-8")


def test_a_page_another_gate_writes_whole(tree):
    assert not only(tree.problems(), "docs/assurance-vector.md")


def test_a_carve_out_whose_page_stopped_saying_so(tree):
    tree.edit("docs/assurance-vector.md", "<!-- Generated by scripts/evidence_gate.py --write — do not edit by hand -->\n", "")
    assert only(tree.problems(), "a stale carve-out is an unread page")


def test_the_bounds_page_another_gate_writes_whole(tree):
    assert not only(tree.problems(), "docs/assurance-bounds.md")


def test_the_carved_out_sentence_reddens_anywhere_else(tree):
    """Which is what makes the case above about the CARVE-OUT and not about a
    sentence no rule was ever going to match. The same bytes, off the page."""
    tree.write("docs/borrowed.md", f"# Borrowed\n\n{BOUNDS_NOTE}")
    assert only(tree.problems(), "docs/borrowed.md")


def test_the_bounds_carve_out_whose_page_stopped_saying_so(tree):
    tree.edit("docs/assurance-bounds.md", "<!-- Generated by scripts/bounds_gate.py --write — do not edit by hand -->\n", "")
    assert only(tree.problems(), "docs/assurance-bounds.md: carved out as written by")


def test_a_listed_page_cannot_grant_itself_the_carve_out(tree, monkeypatch):
    """The half the rule above is not: it asks the PAGE, and this drove what that
    lets through — a page nothing generates, listed, saying the phrase in ordinary
    prose, was exempt at exit 0. Asked of the generator it is a finding."""
    monkeypatch.setitem(
        run_count_gate.GENERATED_ELSEWHERE,
        "docs/borrowed.md",
        "Generated by scripts/bounds_gate.py --write",
    )
    tree.write(
        "docs/borrowed.md",
        "# Borrowed\n\nNobody writes this page; it merely says Generated by"
        f" scripts/bounds_gate.py --write in prose.\n\n{BOUNDS_NOTE}",
    )
    assert only(tree.problems(), "the carve-out is the generator's word")


def test_a_carve_out_whose_generator_stopped_writing_the_page(tree):
    """And the direction that reaches a real edit rather than a fabricated entry:
    the generator is still there and no longer names the page."""
    tree.edit("scripts/bounds_gate.py", 'pathlib.Path("docs/assurance-bounds.md")', 'pathlib.Path("docs/somewhere-else.md")')
    assert only(tree.problems(), "no generator in `scripts/` names it as the page it writes")


def test_what_a_whole_page_carve_out_does_not_catch(tree):
    """The price, as a case rather than a claim in a comment: a run-count typed
    onto the page by hand is silent HERE. `bounds_gate`'s byte diff is what sees
    it, one row over; one typed into the BUNDLE the page renders from is seen by
    neither, which this fixture holds no bundle to drive."""
    tree.edit("docs/assurance-bounds.md", "# Bounds\n", "# Bounds\n\n`run-tlc.sh safety` came back over 777 rows, 3 GREEN, in 4321 s.\n")
    assert tree.problems() == []


def test_the_scan_floor_catches_a_vocabulary_that_stopped_matching(tree, monkeypatch):
    """Audit run-34 #9: a checker that silently matches nothing passes whatever
    it is shown. Driven by taking the vocabulary away, not by emptying the tree."""
    monkeypatch.setattr(run_count_gate, "SCAN_FLOOR", 4)
    monkeypatch.setattr(run_count_gate, "NAMES_A_RUN", run_count_gate.re.compile("nothing at all"))
    monkeypatch.setattr(run_count_gate, "TALLY", run_count_gate.re.compile("nothing at all"))
    assert only(tree.problems(), "under the floor of 4")


# --- the recorder ----------------------------------------------------------


def test_a_partial_run_is_not_a_roster_run(tree, tmp_path):
    log = tmp_path / "partial.log"
    log.write_text(MATRIX_SAFETY.splitlines()[0] + "\n")
    with pytest.raises(RuntimeError, match="covers no tier whole"):
        run_count_gate.record(tree.root, log)


def test_a_log_with_no_rows_in_it(tree, tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("tla-lint: ok\n")
    with pytest.raises(RuntimeError, match="no `<cfg>"):
        run_count_gate.record(tree.root, log)


def test_a_log_carrying_a_row_of_no_tier(tree, tmp_path):
    log = tmp_path / "stray.log"
    log.write_text(
        MATRIX_SAFETY + "\n" + MATRIX_LIVENESS
        + "\nGone.cfg  GREEN  states=1 distinct=1 depth=1 1s\n"
    )
    with pytest.raises(RuntimeError, match="belong to no covered tier"):
        run_count_gate.record(tree.root, log)


def test_a_verdict_carrying_a_tla_operator_survives_the_record(tree, tmp_path):
    """`run-tlc.sh` falls through to TLC's own error line when no invariant name
    is on it, and TLA+ operators are `/\\` and `\\/` — which a TOML basic string
    reads as escapes and refuses to parse."""
    log = tmp_path / "backslash.log"
    log.write_text(
        MATRIX_SAFETY.replace("RED: FooStaysClosed", "RED: Error: x' = a /\\ b")
        + "\n" + MATRIX_LIVENESS + "\n"
    )
    run_count_gate.record(tree.root, log)
    assert "/\\ b" in run_count_gate.load(tree.root)["safety"]["rows"][1]["verdict"]


def test_recording_a_row_whose_log_has_gone(tree, tmp_path):
    """`formal/out/` is gitignored and the next run overwrites it, so the logs
    exist only at `--record` time. A row recorded without one has nothing behind
    it, and the record would carry a number with a single source again."""
    (tree.root / "formal/out/Shipped.log").unlink()
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    with pytest.raises(RuntimeError, match="is missing — record a run, do not type one"):
        run_count_gate.record(tree.root, log)


def test_recording_reads_the_workers_off_the_log_not_the_environment(tree, tmp_path, monkeypatch):
    """`WORKERS=9 … --record` over a log whose banner says two published *"at the
    default `WORKERS=9`"* on three pages. The field is about the run."""
    monkeypatch.setenv("WORKERS", "9")
    tree.write("formal/runs.toml", "# nothing here\n")
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    run_count_gate.record(tree.root, log)
    assert all(r["workers"] == 2 for r in run_count_gate.load(tree.root).values())


def test_recording_the_same_matrix_twice_moves_nothing(tree, tmp_path):
    """It used to stamp `date.today()` and HEAD on every call, so re-recording one
    capture republished it as a later run — of a tree it had never seen. The
    measured form: `commit` re-pointed at whatever had been committed since."""
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    run_count_gate.record(tree.root, log)
    first = tree.read("formal/runs.toml")
    tree.write("docs/formal.md", tree.read("docs/formal.md") + "\nsomething else\n")
    tree.commit("a commit after the run")
    run_count_gate.record(tree.root, log)
    assert tree.read("formal/runs.toml") == first


def test_recording_a_new_matrix_against_a_head_younger_than_the_run(tree, tmp_path):
    """A run of a tree that no longer exists is the defect one level up, and it is
    the one provenance field TLC cannot corroborate — so the check is on the only
    thing that is checkable, the order of the two clocks."""
    for name, text in logs(when="2019-01-01 00:00:00").items():
        tree.stray(f"formal/out/{name}.log", text)
    tree.write("formal/runs.toml", "# nothing here\n")
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    with pytest.raises(RuntimeError, match="record before committing, or re-run the tier"):
        run_count_gate.record(tree.root, log)


def test_a_run_tlc_timed_past_an_hour_records_and_checks_out(tree, tmp_path):
    """Past an hour TLC prints `Finished in 01h 12min` and drops the seconds. Read
    as seconds, a 72-minute Liveness.cfg could not be recorded at all, and a clock
    TLC truncated trails the runner's by up to 59 s more than the JVM bracket."""
    tree.stray("formal/out/Liveness.log", tlc_log(900, 44, 9, "01h 12min"))
    bound = 72 * 60 + 59 + run_count_gate.CLOCK_SLACK
    for seconds in (bound, bound + 1):
        log = tmp_path / f"{seconds}.log"
        log.write_text(
            MATRIX_SAFETY + "\n" + MATRIX_LIVENESS.replace(" 300s", f" {seconds}s") + "\n"
        )
        tree.write("formal/runs.toml", "# nothing here\n")
        run_count_gate.record(tree.root, log)
        tree.regenerate()
        if seconds == bound:
            assert tree.problems() == []
        else:
            assert only(tree.problems(), "Liveness.cfg recorded"), tree.problems()


def test_recording_logs_that_disagree_with_each_other(tree, tmp_path):
    """Within one tier, because that is where a run is one run. `liveness` is a
    single row here and a single row cannot disagree with itself — the first
    version of this case put the odd log there and never raised."""
    tree.stray("formal/out/Mut_BugFooOpens.log", tlc_log(90, 40, 4, "06s", workers=8))
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    with pytest.raises(RuntimeError, match="the logs disagree about date/workers/cores"):
        run_count_gate.record(tree.root, log)


def test_recording_a_log_from_another_machine(tree, tmp_path):
    """`host` is the log's core count wearing this machine's brand string, so the
    two have to be one box. Folded, not substring-matched: the JVM writes
    `aarch64` where `uname` writes `arm64`, and the plain comparison refused
    every honest record on this machine."""
    for name, text in logs().items():
        tree.stray(f"formal/out/{name}.log", text.replace(os.uname().machine, "s390x"))
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    with pytest.raises(RuntimeError, match="record where the run happened"):
        run_count_gate.record(tree.root, log)


def test_recording_a_whole_tier_leaves_a_green_tree(tree, tmp_path):
    log = tmp_path / "all.log"
    log.write_text(MATRIX_SAFETY + "\n" + MATRIX_LIVENESS + "\n")
    tree.write("formal/runs.toml", "# nothing here\n")
    assert tree.problems()
    run_count_gate.record(tree.root, log)
    run_count_gate.run(tree.root, ["--write"])
    assert tree.problems() == []


# --- the row itself --------------------------------------------------------


def test_check_assurance_sh_runs_this_gate():
    """The row as `check-assurance.sh` runs it, over its CODE — a `#` in front of
    the line is not a row, and that is how eleven guards were switched off at once."""
    assert gate_lines.runs((ROOT / "scripts/check-assurance.sh").read_text(), "scripts/run_count_gate.py")


def test_the_usage_line_refuses_what_it_does_not_take():
    assert run_count_gate.main(["--nonsense"]) == 2
    assert run_count_gate.main(["--record"]) == 2
    assert run_count_gate.main(["--write", "extra"]) == 2
