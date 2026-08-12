#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the daily Kani row runs every harness the tree has.

`cargo kani` is invoked with a hand-written `-p` list, and a crate that is not on
it is not proven — but nothing says so. The row is named "prove every harness" and
it was running 29 of 49. Never added: `rsk-ui` (12 proofs, the trusted display's
touch-target geometry — the anti-phishing consent surface), `rsk-led` (5 over
`EF_LED_CONF`, a persisted record with a published wire format), `rsk-slip39` and
`rsk-bip39`. Green daily, asserting nothing about any of them. A harness in an
unlisted crate is worse than no harness, because the reviewer believes it runs.

Third time a gate script has been the finding rather than the instrument (after the
test filter that matched nothing and the fuzz row blind to `[[bin]]` targets), and
the first two were fixed at the site with no guard, which is why there is a third.
So: the roster is checked, not remembered.

Every `cargo kani … -p …` line in the workflow *and* in `docs/testing.md` must name
the same crates *and carry the same switches*, and that crate set must be exactly the
crates carrying a `#[kani::proof]`, less [`EXCLUDED`]. Both directions fail: an
unlisted crate with a proof, and a listed crate whose proof went away. The docs are in
scope because `docs/testing.md` states CI runs "the same `cargo kani` line" — a claim
that was false and is now checkable. Switches are compared because they are half of
what a reader copies: without `-Z unstable-options` the `--harness-timeout` beside it
is not even accepted, so a roster-only comparison lets the documented command drift
into one that does not run.

One of those lines has to be the one CI *runs*, so the workflow's copies are told
apart: a roster counts as executed only inside a step's `run:` scalar, uncommented.
Counting matching strings is not enough — the header's local-equivalent comment is a
second copy in the same file, so putting a `#` in front of the `run:` line left three
agreeing rosters and this guard green over a job that proved nothing. Deleting the
step was caught; disabling it was not, and disabling it is what a hurried "make the
nightly stop failing" does. "Uncommented" is judged per invocation and from the `#`,
not from the line's first character: `run: true # cargo kani …` runs the `true` and
reads as live to a `startswith` test — the hole this shipped with, and the one
`roster_gate.py` inherited from it. That rule, the `\\` continuation-joiner, the
`run:` walk itself, what a package flag is and which directories are the tree are
`gate_lines.py`'s now, one owner for both guards, because inheriting any of it a
second time is how it came to be wrong in two places at once — `-p` and
`--package` were the same flag to one guard and two to the other until they
shared this one.

Deliberately syntactic. It cannot say a harness proves anything worth proving — that
is the harness's own business — only that the solver is pointed at it.
"""

import collections
import pathlib
import re
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/deep-checks.yml"
DOCS = ROOT / "docs/testing.md"

#: Crates with a harness the daily row deliberately does not run, each with the
#: measured reason. An exclusion is a debt, so it is checked too: one naming a crate
#: that no longer has a proof is stale and fails, rather than quietly covering for a
#: harness someone deleted.
EXCLUDED = {
    "rsk-bench": "`summarize` sorts `samples[warmup..]`, a symbolic-length slice, so "
    "CBMC unwinds it without a bound: no verdict in 5 min, and none with "
    "--default-unwind 5 either (measured, kani 0.67.0, 2026-08-11).",
}

#: The version the workflow pins and the docs tell a reader to install. Kani's
#: verdicts are version-dependent, so an unpinned local install is a different tool.
PINNED = re.compile(r'KANI_VERSION:\s*"([\d.]+)"')
DOC_PIN = re.compile(r"kani-verifier --version ([\d.]+)")

INVOCATION = gate_lines.invocation(("kani",))

Roster = collections.namedtuple("Roster", "path named switches executed")


def switches(line):
    """The line's arguments with the package roster and any trailing hint gone.

    The workflow's comment copy ends in a `(cargo install …)` aside that the `run:`
    line and the docs do not carry, so the comparison starts after the first `(`.
    """
    args = INVOCATION.sub("", line.split("(", 1)[0], count=1)
    return tuple(gate_lines.strip_packages(args).split())


def commands(body):
    """Each `cargo kani …` on `body`, flagged live, its commented tail dropped.

    Live means left of the `#`. One that starts to the right of it is a quotation —
    the header's copy — and keeps its whole text, `#` and all being what it quotes.
    """
    live, quoted = gate_lines.split_at_comment(body)
    for segment, is_live in ((live, True), (quoted, False)):
        for found in INVOCATION.finditer(segment):
            yield segment[found.start() :], is_live


def workflow_rosters():
    """The workflow's `cargo kani … -p …` lines, each flagged executed or not.

    Executed = inside a step's `run:` scalar and left of any `#`; that is the only
    copy the job actually runs. Everything else in the file — the header's
    local-equivalent comment, a step name, a tail some edit commented out — is a
    quotation of it.
    """
    for body, executed in gate_lines.yaml_runs(WORKFLOW.read_text()):
        for line, live in commands(body):
            yield WORKFLOW, line, executed and live


def docs_rosters():
    """The docs' `cargo kani … -p …` line — a reader's copy, never run by CI."""
    for _indent, body in gate_lines.logical_lines(DOCS.read_text()):
        for line, _live in commands(body):
            yield DOCS, line, False


def invocations():
    """A [`Roster`] for every `cargo kani` line that names packages.

    A line with no `-p` is `cargo kani setup`, not a roster. Each source must still
    carry the copy it owns — the checks below say which — because a scanner that
    matches nothing reports nothing.
    """
    for path, line, executed in (*workflow_rosters(), *docs_rosters()):
        named = gate_lines.packages(line)
        if named:
            yield Roster(path.relative_to(ROOT), named, switches(line), executed)


def crates_with_proofs():
    """Crates carrying a `#[kani::proof]`, plus any proof that sits outside one.

    The whole tree is walked, not `crates/*/src`: the root `cargo kani` reaches only
    workspace members, so a harness under `fuzz/`, `tools/*` (detached workspaces) or
    `firmware/` (thumbv8m-only) is run by nothing and no `-p` can fix it. Scanning
    just the places a proof is *supposed* to live is how the blind spot gets rebuilt.
    """
    found, orphans = set(), []
    for rel in gate_lines.tree_files(ROOT):
        if rel.suffix != ".rs" or "#[kani::proof" not in (ROOT / rel).read_text():
            continue
        if rel.parts[0] == "crates":
            found.add(rel.parts[1])
        else:
            orphans.append(rel)
    return found, sorted(orphans)


def main():
    rosters = list(invocations())
    proven, orphans = crates_with_proofs()
    problems = []

    workflow, docs = WORKFLOW.relative_to(ROOT), DOCS.relative_to(ROOT)
    if not [r for r in rosters if r.executed]:
        problems.append(
            f"no `cargo kani … -p …` runs in {workflow}: the roster is in no step's"
            " `run:`, or that line is commented out — the copies left in the file"
            " agree with each other over a job that proves nothing."
        )
    if not [r for r in rosters if r.path == workflow and not r.executed]:
        problems.append(
            f"{workflow}'s local-equivalent comment no longer carries the"
            " `cargo kani … -p …` line the row runs."
        )
    if not [r for r in rosters if r.path == docs]:
        problems.append(
            f"{docs} no longer carries a `cargo kani … -p …` line; it is what a"
            " reader copies, and it says CI runs the same one."
        )
    if len({r.named for r in rosters}) > 1:
        problems.append("the `cargo kani` lines name different crates:")
        problems += [f"  {r.path}: {' '.join(sorted(r.named))}" for r in rosters]
    if len({r.switches for r in rosters}) > 1:
        problems.append("the `cargo kani` lines carry different switches:")
        problems += [f"  {r.path}: {' '.join(r.switches) or '(none)'}" for r in rosters]

    listed = set().union(*(r.named for r in rosters)) if rosters else set()
    for crate in sorted(proven - listed - set(EXCLUDED)):
        problems.append(f"{crate} has a #[kani::proof] that no CI row runs")
    for crate in sorted(listed - proven):
        problems.append(f"{crate} is on the `-p` list but has no #[kani::proof]")
    for crate in sorted(set(EXCLUDED) - proven):
        problems.append(f"{crate} is excluded but has no #[kani::proof] to exclude")
    for crate in sorted(set(EXCLUDED) & listed):
        problems.append(f"{crate} is both excluded and on the `-p` list")
    for rel in orphans:
        problems.append(f"{rel} has a #[kani::proof] no `-p` can reach")

    want = PINNED.search(WORKFLOW.read_text())
    got = DOC_PIN.search(DOCS.read_text())
    if not want:
        problems.append("KANI_VERSION is not pinned in the workflow")
    elif not got:
        problems.append("docs/testing.md installs kani-verifier without --version")
    elif got.group(1) != want.group(1):
        problems.append(
            f"docs/testing.md installs kani {got.group(1)}, CI pins {want.group(1)}"
        )

    if problems:
        print("kani-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA crate absent from the `-p` list is not proven, and the row that\n"
            "says it proves every harness stays green either way. Add it there and\n"
            "to docs/testing.md, or record it in EXCLUDED with the measured reason."
        )
        return 1

    print(
        f"kani-gate: ok — {len(listed)} crates on the `-p` list the row runs, "
        f"excluded: {', '.join(EXCLUDED)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
