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

Deliberately syntactic. It cannot say a harness proves anything worth proving — that
is the harness's own business — only that the solver is pointed at it.
"""

import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = (ROOT / ".github/workflows/deep-checks.yml", ROOT / "docs/testing.md")

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

INVOCATION = re.compile(r"cargo kani\b[^\n]*")
PKG = re.compile(r"-p ([\w-]+)")


def switches(line):
    """The line's arguments with the `-p <crate>` roster and any trailing hint gone.

    The workflow's comment copy ends in a `(cargo install …)` aside that the `run:`
    line and the docs do not carry, so the comparison starts after the first `(`.
    """
    args, tail, skip = line.split("(", 1)[0].split()[2:], [], False
    for word in args:
        if skip:
            skip = False
        elif word == "-p":
            skip = True
        else:
            tail.append(word)
    return tuple(tail)


def invocations():
    """(path, crate set, switches) for every `cargo kani` line that names packages.

    A line with no `-p` is `cargo kani setup`, not a roster. Zero rosters overall is
    a hard failure below: a scanner that matches nothing reports nothing.
    """
    for path in SOURCES:
        for line in INVOCATION.findall(path.read_text()):
            named = frozenset(PKG.findall(line))
            if named:
                yield path.relative_to(ROOT), named, switches(line)


def crates_with_proofs():
    """Crates carrying a `#[kani::proof]`, plus any proof that sits outside one.

    The whole tree is walked, not `crates/*/src`: the root `cargo kani` reaches only
    workspace members, so a harness under `fuzz/`, `tools/*` (detached workspaces) or
    `firmware/` (thumbv8m-only) is run by nothing and no `-p` can fix it. Scanning
    just the places a proof is *supposed* to live is how the blind spot gets rebuilt.
    """
    found, orphans = set(), []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        # A nested checkout (agent worktrees live under `.claude/worktrees/`) carries
        # a whole second copy of the tree, and none of its crates is a workspace
        # member, so every proof in it would read as an orphan no `-p` can reach.
        dirnames[:] = [
            d
            for d in dirnames
            if d not in ("target", ".git") and not (pathlib.Path(dirpath, d, ".git")).exists()
        ]
        for name in filenames:
            path = pathlib.Path(dirpath, name)
            if path.suffix != ".rs" or "#[kani::proof" not in path.read_text():
                continue
            rel = path.relative_to(ROOT)
            if rel.parts[0] == "crates":
                found.add(rel.parts[1])
            else:
                orphans.append(rel)
    return found, sorted(orphans)


def main():
    rosters = list(invocations())
    proven, orphans = crates_with_proofs()
    problems = []

    if len(rosters) < 3:
        problems.append(
            f"only {len(rosters)} `cargo kani -p …` line(s) found in "
            f"{[str(p.relative_to(ROOT)) for p in SOURCES]}; expected the workflow's"
            " run: line, its local-equivalent comment, and the docs command."
        )
    if len({named for _, named, _ in rosters}) > 1:
        problems.append("the `cargo kani` lines name different crates:")
        problems += [f"  {path}: {' '.join(sorted(named))}" for path, named, _ in rosters]
    if len({tail for _, _, tail in rosters}) > 1:
        problems.append("the `cargo kani` lines carry different switches:")
        problems += [f"  {path}: {' '.join(tail) or '(none)'}" for path, _, tail in rosters]

    listed = set().union(*(named for _, named, _ in rosters)) if rosters else set()
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

    want = PINNED.search(SOURCES[0].read_text())
    got = DOC_PIN.search(SOURCES[1].read_text())
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
        f"kani-gate: ok — {len(listed)} crates on the `-p` list, "
        f"excluded: {', '.join(EXCLUDED)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
