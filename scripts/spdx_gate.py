#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every source file says which licence it is under.

AGENTS.md has asked for the `AGPL-3.0-only` SPDX header on every new file since
the repo existed, and nothing checked it. RS-Key is AGPL-3.0-only *by inheritance*
— it reimplements a family licensed "version 3" with no "or later" (NOTICE), so
the version cannot drift — and a file with no header is a file whose terms a
downstream reader has to guess. Ported from Wasefire's `scripts/ci-copyright.sh`,
which asks the same question of its own tree with a hand-maintained skip list.

The header must be in the **first three lines**, which is where a shebang, a
`<!--` or a `/*` leaves room for it. That is not a style preference: it is where
every existing file in this tree puts it, so a wider window would accept a header
buried under code that a reader scanning the top would never see.

## Which files

By extension, and the set is the one the tree is *already* at 100 % on — measured
per extension, not chosen: `.rs` 436/436, `.py` 113/113, `.sh` 15/15, `.nix` 8/8,
`.svg` 18/18, and one each of `.x`, `.tla`, `.js`, `.html`. `.c`/`.h`/`.S` join
them because the only ones in the tree are vendored and exempt below, so a
*new* hand-written one is checked from the day it lands.

[`UNCHECKED`] is the other half, and it exists so the pair is exhaustive: an
extension in neither set is a failure that says "classify it". A hard-coded list
of what to check goes stale in silence — the tree grows a `.ts` and nobody ever
learns it is unchecked — and this is the cheapest thing that cannot.

A file with no extension is checked when it starts with `#!`: `scripts/hooks/
pre-commit` is a shell script and carries the header, and the next hook beside it
should not escape by having no suffix. One that is neither a script nor a name in
[`NOT_SOURCE`] is reported, so a `Makefile` or a `Dockerfile` cannot slip through
the gap between "no suffix" and "not classified".

A checked type may still be excused file by file — [`UNHEADERED`] — and only file
by file. The three `.github/ISSUE_TEMPLATE/*.yml` forms carry no header while the
eight workflow files and `dependabot.yml` all do, so excusing the *extension*
would have left every future workflow unchecked in order to excuse three forms.

## The exemptions, and their debt

Vendored code keeps its own notice; stamping AGPL on someone else's file would be
a false statement about it. So `third_party/` and the BSD-licensed bignum sources
under `crates/rsk-rsa/csrc/` are exempt — and the exemption is checked, the
way `kani_gate.py` checks its own: an exempt file must carry a `Copyright` line of
its own **or** sit under a directory holding a `LICENCE`/`LICENSE` file. An
exemption that covers a file with no notice at all is not an exemption, it is an
unlicensed file. A prefix that matches nothing is stale and fails too.

The directory half is a statement about the directory, so anything beside a
`LICENSE` inherits it — `crates/rsk-rsa/csrc/LICENSE.txt` covers the four
files there. That is the right reading for a vendored tree, and the reason the
repo's own top-level `LICENSE` is excluded from the walk: it would otherwise
cover the whole checkout.

## What this cannot say

That the header is *true*. A file may carry `AGPL-3.0-only` and be a copy of
something under other terms; that is a review question, not a grep's.
"""

import pathlib
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The line itself, and the window it has to be in.
HEADER = "SPDX-License-Identifier: AGPL-3.0-only"
WINDOW = 3

#: Extensions the whole tree already carries the header on, plus `.yml`, whose
#: three exceptions are listed by name below rather than excusing the extension.
#: Growing this set means stamping the files that do not — a bulk edit,
#: deliberately not this guard's to make on its own.
CHECKED = frozenset({".rs", ".py", ".sh", ".nix", ".svg", ".x", ".tla", ".js", ".html",
                     ".c", ".h", ".S", ".yml"})

#: Below this the guard is green over nothing. It has no roster to go empty, but
#: it does walk a tree, and a walk that returns nothing exits 0 — the shape four
#: guards in this repo shipped with. Today: 610.
FLOOR = 500

#: Files a suffix cannot classify, by name and with the reason. Named, not
#: pattern-matched, so a `Makefile` or a `Dockerfile` — neither of which has a
#: suffix either — is a failure that says "classify it" rather than a silent pass.
NOT_SOURCE = {
    "LICENSE": "the licence itself",
    "NOTICE": "the attribution file",
    ".gitignore": "git configuration",
}

#: The rest, each with the measured reason it is not checked. Present so that an
#: extension in neither set is a failure rather than a silent gap.
UNCHECKED = {
    ".md": "the tree is split — 21 of 57 carry it, the docs/ pages do not",
    ".toml": "12 of 44; a cargo manifest carries no header by convention",
    ".json": "data",
    ".jsonl": "data (recorded traces; strict JSON carries no comment to hold a header)",
    ".txt": "data",
    ".cfg": "data (kani/proptest knobs and board fragments)",
    ".lock": "generated",
    ".patch": "a diff of someone else's file, header and all",
    ".png": "binary",
    ".jpg": "binary",
    ".gif": "binary",
}

#: Where a file is under someone else's terms, with the reason. Checked below:
#: a prefix matching nothing is stale, and a file it covers still owes a notice.
EXEMPT = {
    "third_party/": "vendored upstream trees, each under its own licence",
    "crates/rsk-rsa/csrc/": "Emil Lenngren's BSD-2-Clause bignum C and asm",
}

#: Files of a checked type that carry no header for a stated reason. Listed one
#: by one, never by directory: `.yml` is checked because the eight workflow files
#: and `dependabot.yml` all carry the header, and blanket-excusing the extension
#: would have left every FUTURE workflow unchecked to excuse these three. Also
#: checked for staleness — one naming a file that is gone, or that has since
#: grown a header, fails.
UNHEADERED = {
    ".github/ISSUE_TEMPLATE/bug_report.yml": "a GitHub-rendered issue form",
    ".github/ISSUE_TEMPLATE/config.yml": "a GitHub-rendered issue form",
    ".github/ISSUE_TEMPLATE/feature_request.yml": "a GitHub-rendered issue form",
}


def kind(root, rel):
    """Whether `rel` is checked, unchecked-with-a-reason, or unclassified.

    Returns the suffix for an unclassified file, "" for one that is checked, and
    None for one nothing asks about.
    """
    suffix = rel.suffix
    if suffix in CHECKED:
        return ""
    if suffix in UNCHECKED:
        return None
    if suffix:
        return suffix
    # No extension: a script is still a source file, and a hook beside
    # `pre-commit` should not escape by having no suffix. A `Makefile` has no
    # suffix either, so anything that is neither a script nor a named licence is
    # reported rather than skipped.
    with (root / rel).open("rb") as handle:
        if handle.read(2) == b"#!":
            return ""
    return None if rel.name in NOT_SOURCE else f"file with no extension, {rel.name},"


def licensed(root, rel):
    """Whether an exempt file says whose it is, itself or by a neighbouring file.

    Two shapes because the tree has two: the vendored C carries a BSD block of
    its own, and the vendored test suites carry one `LICENSE` at the root of each
    tree. The repo's own top-level `LICENSE` is not one of them — it would excuse
    everything.
    """
    # `any(dir.glob(p) for p in …)` is always true: a generator is truthy. The
    # tests caught it; the guard had gone green over every exempt file.
    for parent in list(rel.parents)[:-1]:
        for pattern in ("LICEN[CS]E*", "COPYING*"):
            if any((root / parent).glob(pattern)):
                return True
    head = (root / rel).read_text(errors="replace").splitlines()[:25]
    return any("Copyright" in line for line in head)


def audit(root):
    """(problems, one-line summary) for how this checkout licenses its sources."""
    root = pathlib.Path(root)
    problems, checked, exempted, excused = [], 0, set(), set()
    for rel in sorted(gate_lines.tree_files(root)):
        unknown = kind(root, rel)
        if unknown is None:
            continue
        # Between "this type is asked about" and the header itself: a vendored
        # tree's own files are upstream's business, whatever type they are — the
        # licence texts beside them have no suffix to classify.
        prefix = next((p for p in EXEMPT if str(rel).startswith(p)), None)
        if prefix:
            exempted.add(prefix)
            if not licensed(root, rel):
                problems.append(
                    f"{rel} is exempt as {EXEMPT[prefix]} but carries no copyright"
                    " line and sits under no LICENCE — that is not an exemption"
                )
            continue
        if unknown:
            problems.append(
                f"{rel} is a `{unknown}` this guard has never been told about:"
                " add it to CHECKED, or to UNCHECKED/NOT_SOURCE with the reason"
            )
            continue
        if str(rel) in UNHEADERED:
            excused.add(str(rel))
            if HEADER in (root / rel).read_text(errors="replace"):
                problems.append(f"{rel} carries the header now; drop its UNHEADERED entry")
            continue
        checked += 1
        head = (root / rel).read_text(errors="replace").splitlines()[:WINDOW]
        if not any(HEADER in line for line in head):
            problems.append(f"{rel} has no `{HEADER}` in its first {WINDOW} lines")
    for prefix in sorted(set(EXEMPT) - exempted):
        problems.append(f"nothing under `{prefix}` is exempt any more; drop the entry")
    for rel in sorted(set(UNHEADERED) - excused):
        problems.append(f"{rel} is listed in UNHEADERED but is not in the tree")
    if checked < FLOOR:
        problems.append(
            f"only {checked} files were checked, under the floor of {FLOOR}:"
            " the walk found nothing, or the checked set stopped matching"
        )
    return problems, (
        f"spdx-gate: ok — {checked} source files carry the header,"
        f" {len(EXEMPT)} vendored trees exempt"
    )


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("spdx-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            f"\nEvery source file starts with `{HEADER}`\nand the copyright line"
            " under it — copy them from any neighbouring file. RS-Key is\n"
            "AGPL-3.0-only by inheritance (see NOTICE); a file with no header is"
            " one\nwhose terms a reader has to guess."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
