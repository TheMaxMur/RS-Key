# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `kani.sh`'s own verdict rows.

`kani.sh` is a gate script that had no table. Its harness floor was added on the
strength of a terminal scrollback, and the cover row below it reads a shape —
Kani's per-check listing — that no test pinned. Both are driven here against the
real script with a stub `cargo` on PATH, so the mutations move the *log* and the
script under test is the one CI runs.

The case that decides the cover row's design is
`test_one_dead_copy_of_a_live_cover_is_not_a_failure`. One `kani::cover!` becomes
several CBMC properties wherever the enclosing MIR branches on something the
condition re-tests, and the copies on the contradicting arms are dead by
construction: `rebuild_meta_any_blob` reports its `!with_new && …` cover twice,
UNSATISFIABLE once and SATISFIED once, and Kani's summary line says "2 of 3".
A row that read that summary would go red on a cover that is genuinely reached —
which is how a correct harness gets "repaired" and the instrument keeps the bug.
"""

import os
import re
import subprocess

import pytest

import kani_gate

RUNNER = kani_gate.ROOT / kani_gate.RUNNER

#: The stub the script calls instead of the verifier. Prints a fixture log and
#: exits with the code the test asked for, so `pipefail` is exercised too.
CARGO = """#!/usr/bin/env bash
cat "$KANI_FIXTURE"
exit "${KANI_RC:-0}"
"""


def floors():
    """The live floors, so a raise in `kani.sh` moves the fixtures with it."""
    found = dict(re.findall(r"^(FLOOR_\w+|COVERS_\w+)=(\d+)$", RUNNER.read_text(), re.M))
    assert {"FLOOR_pr", "COVERS_pr"} <= found.keys(), found
    return {k: int(v) for k, v in found.items()}


def check(kind, index, status, location, harness):
    return "\n".join(
        [
            f"Check {index}: {harness}.{kind}.{index}",
            f"\t - Status: {status}",
            '\t - Description: "a thing worth reaching"',
            f"\t - Location: {location} in function {harness}",
            "",
        ]
    )


def make_log(harnesses, *, summary=True, listing=True):
    """A Kani run, as `kani.sh` sees it.

    `harnesses` is [(name, [(location, [status, …]), …]), …] — one inner list per
    source-level `kani::cover!`, one status per CBMC property it became.

    Every cover is preceded by an ordinary assertion check, because that is what
    the real logs look like — 10 413 checks in the `pr` run, 25 of them covers —
    and a fixture of covers alone leaves the parser's `.cover.` discriminator and
    its per-check status reset asserting nothing.
    """
    out, index = [], 0
    for name, covers in harnesses:
        out.append(f"Checking harness {name}...\n")
        satisfied = 0
        total = 0
        for location, statuses in covers:
            for status in statuses:
                index += 1
                if listing:
                    out.append(check("assertion", index, "SUCCESS", location, name))
                index += 1
                total += 1
                satisfied += status == "SATISFIED"
                if listing:
                    out.append(check("cover", index, status, location, name))
        out.append("SUMMARY:")
        out.append(f" ** {satisfied} of {total} cover properties satisfied\n")
        out.append("VERIFICATION:- SUCCESSFUL")
    if summary:
        n = len(harnesses)
        out.append(f"Complete - {n} successfully verified harnesses, 0 failures, {n} total.")
    return "\n".join(out) + "\n"


def green(tier="pr"):
    """A run that meets both floors: every cover reached, nothing to report."""
    f = floors()
    harnesses = [(f"proofs::h{i}", []) for i in range(f[f"FLOOR_{tier}"])]
    for i in range(f[f"COVERS_{tier}"]):
        harnesses[-1 - (i % len(harnesses))][1].append(
            (f"crates/rsk-x/src/k.rs:{i + 10}:5", ["SATISFIED"])
        )
    return harnesses


def first_cover(harnesses):
    """(harness index, cover index) of a cover that is not the log's first check.

    Mutating check 1 would leave the parser's status reset (`s = ""`) untested:
    with nothing before it there is no status to leak in from.
    """
    index = next(i for i, (_, covers) in enumerate(harnesses) if covers)
    assert index > 0, "the mutated cover must have a check before it"
    return index


@pytest.fixture
def run(tmp_path):
    """Run the real `kani.sh` over a fixture log."""
    binroot = tmp_path / "bin"
    binroot.mkdir()
    (binroot / "cargo").write_text(CARGO)
    (binroot / "cargo").chmod(0o755)

    def go(harnesses, *, tier="pr", rc=0, raw=None, **kw):
        fixture = tmp_path / "kani.log"
        if raw is None:
            raw = make_log(harnesses, **kw) if harnesses is not None else ""
        fixture.write_text(raw)
        env = dict(os.environ)
        env["PATH"] = f"{binroot}:{env['PATH']}"
        env["KANI_FIXTURE"] = str(fixture)
        env["KANI_RC"] = str(rc)
        return subprocess.run(
            [str(RUNNER), tier], capture_output=True, text=True, env=env, cwd=tmp_path
        )

    return go


# --- the row has to go green, or it gets deleted as fast as one that can't fail -


@pytest.mark.parametrize("tier", ["pr", "state", "all"])
def test_a_clean_run_passes_and_says_what_it_read(run, tier):
    """Every tier, not just `pr` — `all` is the one no real run has ever reached."""
    r = run(green(tier), tier=tier)
    assert r.returncode == 0, r.stderr
    f = floors()
    assert f"{f[f'FLOOR_{tier}']} harnesses proved" in r.stdout
    assert f"{f[f'COVERS_{tier}']} covers reached" in r.stdout


def test_one_dead_copy_of_a_live_cover_is_not_a_failure(run):
    """The `rebuild_meta_any_blob` shape: same location, one arm dead, one live.

    Kani's own summary line calls this "2 of 3"; the tree's harness is correct.
    """
    harnesses = green()
    h = first_cover(harnesses)
    harnesses[h][1][0] = (harnesses[h][1][0][0], ["UNSATISFIABLE", "SATISFIED"])
    r = run(harnesses)
    assert r.returncode == 0, r.stderr


def test_the_same_location_in_two_harnesses_is_two_groups(run):
    """A cover in a shared helper is dead per harness, not tree-wide."""
    harnesses = green()
    shared = "crates/rsk-x/src/helper.rs:9:5"
    harnesses[0][1].append((shared, ["SATISFIED"]))
    harnesses[1][1].append((shared, ["UNSATISFIABLE"]))
    r = run(harnesses)
    assert r.returncode == 1
    assert harnesses[1][0] in r.stderr and shared in r.stderr


# --- and it has to go red ------------------------------------------------------


@pytest.mark.parametrize("status", ["UNSATISFIABLE", "UNREACHABLE", "UNDETERMINED"])
def test_a_cover_nothing_satisfies_fails_the_row(run, status):
    """Only SATISFIED counts. An undetermined cover is not evidence of one."""
    harnesses = green()
    h = first_cover(harnesses)
    location = harnesses[h][1][0][0]
    harnesses[h][1][0] = (location, [status])
    r = run(harnesses)
    assert r.returncode == 1
    assert "unreached" in r.stderr
    assert location in r.stderr


def test_every_copy_dead_fails_the_row(run):
    harnesses = green()
    h = first_cover(harnesses)
    location = harnesses[h][1][0][0]
    harnesses[h][1][0] = (location, ["UNSATISFIABLE", "UNREACHABLE"])
    r = run(harnesses)
    assert r.returncode == 1
    assert location in r.stderr


def test_a_second_dead_copy_is_over_the_ceiling(run):
    """Grouping forgives a dead copy; the ceiling is what keeps that bounded.

    Both groups here stay alive, so nothing above this fires — only the count of
    unsatisfied properties says a copy stopped being reachable.
    """
    harnesses = green()
    h = first_cover(harnesses)
    harnesses[h][1][0] = (harnesses[h][1][0][0], ["UNSATISFIABLE", "SATISFIED"])
    harnesses[h][1].append(("crates/rsk-x/src/k.rs:99:5", ["UNSATISFIABLE", "SATISFIED"]))
    r = run(harnesses)
    assert r.returncode == 1
    assert "over the" in r.stderr and "ceiling" in r.stderr


#: A harness whose second cover has no `- Status:` line, right after one that is
#: SATISFIED. Hand-written because no real log looks like this — which is exactly
#: why the parser's per-check status reset would otherwise be a line no case
#: reaches, and why the direction that matters (a dead cover inheriting the last
#: SATISFIED) cannot be built out of a faithful fixture.
MALFORMED_LOCATION = "crates/rsk-x/src/torn.rs:9:5"
MALFORMED = f"""Checking harness proofs::torn...

Check 900: proofs::torn.cover.1
\t - Status: SATISFIED
\t - Description: "reached"
\t - Location: crates/rsk-x/src/torn.rs:8:5 in function proofs::torn

Check 901: proofs::torn.cover.2
\t - Description: "the status line never arrived"
\t - Location: {MALFORMED_LOCATION} in function proofs::torn

VERIFICATION:- SUCCESSFUL
"""


def test_a_cover_with_no_status_line_is_not_inherited_from_the_last_one(run):
    log = make_log(green())
    n = floors()["FLOOR_pr"] + 1
    log = re.sub(
        r"^Complete - .*$",
        f"Complete - {n} successfully verified harnesses, 0 failures, {n} total.",
        log,
        flags=re.M,
    ).replace("Complete - ", MALFORMED + "Complete - ")
    r = run(None, raw=log)
    assert r.returncode == 1
    assert "unreached" in r.stderr
    assert MALFORMED_LOCATION in r.stderr


def test_a_cover_that_stopped_being_reported_fails_the_row(run):
    """One fewer than the floor: a `#[cfg(kani)]` hook or a cover that went away."""
    harnesses = green()
    harnesses[first_cover(harnesses)][1].pop()
    r = run(harnesses)
    assert r.returncode == 1
    assert "kani::cover!, under the" in r.stderr


def test_a_run_with_no_per_check_listing_fails_the_row(run):
    """`--output-format=terse` keeps the summary and drops the verdicts.

    Reading nothing is the failure four of this week's new guards shipped with,
    so it is named as its own case rather than folded into the floor.
    """
    r = run(green(), listing=False)
    assert r.returncode == 1
    assert "no per-check listing" in r.stderr


def test_an_empty_log_fails_the_row(run):
    r = run(None)
    assert r.returncode == 1
    assert "proved nothing" in r.stderr


# --- the harness floor, which had no table either ------------------------------


def test_too_few_harnesses_fails_the_row(run):
    """One harness short, every cover still reported: only the harness floor fires."""
    harnesses = green()
    dropped = next(i for i, (_, covers) in enumerate(harnesses) if not covers)
    harnesses.pop(dropped)
    r = run(harnesses)
    assert r.returncode == 1
    assert "harnesses, under the" in r.stderr


def test_the_verifier_s_own_failure_is_the_row_s(run):
    """`pipefail` first: a property violation must not be re-judged by the floors."""
    r = run(green(), rc=1)
    assert r.returncode != 0
    assert "covers reached" not in r.stdout


# --- the guard's own wiring ----------------------------------------------------


def test_every_tier_has_both_floors():
    """A tier added without a cover floor would run the row over an empty list."""
    text = RUNNER.read_text()
    tiers = re.search(r'^TIERS="([^"]*)"', text, re.M).group(1).split()
    f = floors()
    for tier in tiers:
        assert f.get(f"FLOOR_{tier}", 0) > 0, tier
        assert f.get(f"COVERS_{tier}", 0) > 0, tier
