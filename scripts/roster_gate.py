#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every whole-tree `-p` roster names every crate the workspace has.

`scripts/check.sh` writes the same crate list out five times — the host clippy
row, three rustdoc rows, the host test row — `docs/testing.md` carries a sixth
for a reader to copy, and `.github/workflows/deep-checks.yml` a seventh on the
nightly `llvm-cov` row plus an eighth quoting it in the header. Nothing tied any
of them to `Cargo.toml`'s `[workspace] members`, so a crate that joins the tree
joins none of the rosters and every row stays green while covering less than its
name says. Not hypothetical, twice over, and the shape of it is worse than
neglect. The docs copy stood at 16 of 24 while having been amended four times,
each by the commit that added the one crate it names (`rsk-vendor`,
`rsk-device`, `rsk-store`, `rsk-display`); the eight it missed had all joined the
tree *before* those four. The coverage roster stood at 20 of 24, amended twice
the same way (`rsk-sha512`+`rsk-bench`, then `rsk-ec`+`rsk-mldsa`) and missing
exactly the four the docs copy had kept — so between them the two lists were
maintained by disjoint sets of commits and neither was ever reread. A list
somebody keeps amending is exactly the list nobody rereads.

Same shape as the Kani roster next door and the same fix: the roster is checked,
not remembered. It is a second script rather than more rules inside
`scripts/kani_gate.py` because that one answers a different question from a
different source of truth — which crates carry a `#[kani::proof]`, against a
workflow and the docs — and one script answering both would report "roster" for
two unrelated failures. What the two *do* share is how a command is read out of
a file, which is `gate_lines.py`'s now: the `#` rule had already gone wrong in
both at once, and this script's third reader would have been a third copy of the
`run:` walk.

The rules, and the mistake each one catches:

* a roster may only name real workspace members — a typo, or a crate that left;
* a gate row filtering no features must name every member under `crates/` — the
  new crate nobody added. A `--features X` row is about the crates that declare
  X and is exempt; `--all-features` filters nothing and is not. Every row in
  `check.sh` is a gate row, and so is the workflow's coverage row: what it
  measures a floor over is the host tree or the floor is over something else;
* a file that only *quotes* the list must carry one complete copy, not consist
  of complete copies. `docs/testing.md` is prose and prose grows examples:
  holding its every `cargo test -p …` to the whole tree reported 23 missing
  crates the moment a one-crate `cargo test -p rsk-fido` example was added
  beside the roster, and a guard that cries wolf on a docs edit is a guard
  someone deletes. The workflow's header block is the same kind of text and gets
  the same rule — it is the only `#` text scanned here, because in `check.sh`
  and the docs a `#` is a dead row or a heading while there it is the local
  equivalent a reader pastes, kept in step with the row beside it;
* each verb in [`WHOLE_TREE`] keeps at least one such roster in the file that
  owes it — deleting the row, or commenting it out, which is what "make the gate
  faster" reaches for first;
* every `crates/*/Cargo.toml` is a workspace member — the seam one level up,
  where a crate is invisible to `--workspace` and to all eight rosters at once;
* `check.sh` still runs this script.

`kani_gate.py` shipped with two holes worth not repeating. It counted a
commented-out invocation as a live one, so only what executes counts here — and
"executes" is judged from the `#`, not from the line's first character. This rule
first shipped as `startswith("#")`, under which `true # run "test (host)" …` left
a fully counted roster over a row that ran nothing; `kani_gate.py` had the same
hole in its own form and both were closed together. And it compared crate sets
while the rest of the command was free to drift; the analog here is the `crates/`
directory itself, which is why the filesystem is checked against `Cargo.toml`
instead of trusted through it.

Limits, so the row is not read as more than it is, each one measured rather than
assumed. It compares crate sets, not switches: a roster can stay complete while
the row stops doing what its name says — three rustdoc permutations becoming two
shows up only in the per-verb count this prints, and deleting the coverage row's
`--fail-under-lines` leaves it measuring 24 crates against no floor at all.
"Executes" here means "not commented out", so `if: false` or
`continue-on-error: true` on the coverage step is a complete roster over a job
that asserts nothing; closing that needs the shared reader to track step
structure, and it is open on the Kani row too, so it is a class of its own and
not this file's to fix alone. Run from `check.sh` it cannot catch its own row
being commented out; the self-check bites when the script is run by hand, the
one vantage point outside the thing being guarded.
"""

import collections
import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECK = pathlib.Path("scripts/check.sh")
DOCS = pathlib.Path("docs/testing.md")
WORKFLOW = pathlib.Path(".github/workflows/deep-checks.yml")
#: Derived, not spelled out, so renaming the script cannot silently disarm the
#: self-check below.
SELF = pathlib.Path(__file__).resolve().relative_to(ROOT)

#: Per file, the cargo verbs whose `-p` roster there is meant to be the whole
#: tree: what the gate lints, documents, tests and floors coverage over is every
#: crate, or the row's name is a lie. `cargo kani`'s roster is a different
#: question (`kani_gate.py` owns it), and `build`/`tree` name one crate on
#: purpose. Each entry is a presence check too — a verb whose last whole-tree
#: roster in its file is gone or commented out fails here.
WHOLE_TREE = {
    CHECK: ("clippy", "doc", "test"),
    WORKFLOW: ("llvm-cov",),
}
VERBS = sorted({verb for verbs in WHOLE_TREE.values() for verb in verbs})

#: Files that only *quote* the list, and what the copy in each is for. Each must
#: carry one complete roster; holding every line in them to the whole tree is
#: what failed a one-crate `cargo test -p rsk-fido` example with 23 complaints.
QUOTES = {
    WORKFLOW: "the local equivalent of its nightly rows",
    DOCS: "the `-p` roster a reader copies",
}

INVOCATION = re.compile(rf"\bcargo ({'|'.join(VERBS)})\b")
PKG = re.compile(r"(?:-p|--package)\s+([\w-]+)")
#: `-F` is `--features`' short form. `--all-features` deliberately does not
#: match — it selects no subset, so that row owes the whole roster too.
SELECTIVE = re.compile(r"(?:^|\s)(?:--features\b|-F)")

Roster = collections.namedtuple("Roster", "path verb named filtered executed")


def lines(path):
    """(logical line, executed) for `path`, read as what the file is.

    A workflow runs only what is inside a step's `run:`; every line of a shell
    script is the gate; nothing in the docs is ever run by anybody.
    """
    text = (ROOT / path).read_text()
    if path == WORKFLOW:
        yield from gate_lines.yaml_runs(text)
        return
    for _indent, body in gate_lines.logical_lines(text):
        yield body, path == CHECK


def rosters(path):
    """Every `cargo <verb> … -p …` line in `path`, flagged executed or not.

    A line with no `-p` names no roster (`cargo doc --manifest-path tools/tui/…`
    is the whole of its own workspace). Each invocation's arguments stop at the
    next one, so two chained on one line stay two rosters — merged, either could
    hide behind the other's crates. A commented tail runs nothing, and only in
    the workflow is it also read: there the header quotes the row it runs, and
    the pair drifting apart is the failure. In `check.sh` and in the docs a `#`
    is a dead row or a heading, and holding either to the whole tree is how a
    guard starts crying wolf.
    """
    for body, executed in lines(path):
        live, quoted = gate_lines.split_at_comment(body)
        segments = [(live, executed)]
        if path == WORKFLOW:
            segments.append((quoted, False))
        for segment, runs in segments:
            found = list(INVOCATION.finditer(segment))
            for this, after in zip(found, [*found[1:], None]):
                tail = segment[this.end() : after.start() if after else len(segment)]
                named = frozenset(PKG.findall(tail))
                if named:
                    yield Roster(
                        path, this.group(1), named, bool(SELECTIVE.search(tail)), runs
                    )


def members():
    """Package name -> member path, for every `[workspace] members` entry.

    The name comes out of each manifest rather than off its directory: `-p` takes
    the package name, and nothing in cargo makes the two agree.
    """
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    found = {}
    for rel in root["workspace"]["members"]:
        manifest = tomllib.loads((ROOT / rel / "Cargo.toml").read_text())
        found[manifest["package"]["name"]] = rel
    return found


def main():
    member = members()
    crates = {name for name, rel in member.items() if rel.startswith("crates/")}
    found = [*rosters(CHECK), *rosters(WORKFLOW), *rosters(DOCS)]
    problems = []

    listed = set(member.values())
    for path in sorted((ROOT / "crates").iterdir()):
        if (path / "Cargo.toml").is_file() and f"crates/{path.name}" not in listed:
            problems.append(
                f"crates/{path.name} is not in Cargo.toml's [workspace] members, so"
                " neither a `-p` list nor --workspace can reach it"
            )

    for roster in found:
        where = f"{roster.path}: `cargo {roster.verb}`"
        if roster.path == WORKFLOW and not roster.executed:
            where += " (the header's local equivalent)"
        for crate in sorted(roster.named - set(member)):
            problems.append(f"{where} names {crate}, not a workspace member")
        # Only a row that runs owes the whole tree line by line; a quoted one owes
        # its file one complete copy, checked below. A roster naming no `crates/`
        # member is about `firmware`/`rsk-wipe`, the thumbv8m-only pair, and owes
        # this list nothing.
        if (
            not roster.executed
            or roster.filtered
            or roster.verb not in WHOLE_TREE.get(roster.path, ())
            or not roster.named & crates
        ):
            continue
        for crate in sorted(crates - roster.named):
            problems.append(f"{where} does not name {crate}")

    covered = collections.Counter(
        (roster.path, roster.verb)
        for roster in found
        if roster.executed and not roster.filtered and roster.named & crates
    )
    for path, verbs in WHOLE_TREE.items():
        for verb in verbs:
            if not covered[path, verb]:
                problems.append(
                    f"no `cargo {verb} … -p …` over the whole tree runs in {path}:"
                    " the row is gone or commented out. If the verb moved to"
                    " --workspace, take it out of WHOLE_TREE and say so there."
                )
    for path, what in QUOTES.items():
        copies = [
            r
            for r in found
            if r.path == path
            and not r.executed
            and not r.filtered
            and r.named & crates
        ]
        if any(crates <= r.named for r in copies):
            continue
        # Which near-miss gets quoted only shapes the message; the verdict is
        # whether the whole list is in the file at all.
        near = max(copies, key=lambda r: len(r.named & crates), default=None)
        gap = f": {', '.join(sorted(crates - near.named))} missing" if near else ""
        problems.append(f"{path} no longer carries {what}{gap}")
    live = (gate_lines.split_at_comment(body)[0] for body, _ in lines(CHECK))
    if not [r for r in live if str(SELF) in r]:
        problems.append(f"{CHECK} does not run {SELF}: the rosters are unchecked again")

    if problems:
        print("crate-roster:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA crate absent from a `-p` list is not linted, documented, tested\n"
            "or measured by that row, and the row stays green either way. Add it\n"
            f"to every roster in {CHECK} and {WORKFLOW},\nand to the one in {DOCS}."
        )
        return 1

    rows = ", ".join(
        f"{n}× cargo {verb} in {path}" for (path, verb), n in sorted(covered.items())
    )
    print(
        f"crate-roster: ok — {len(crates)} crates under crates/, run by {rows}, and"
        f" quoted whole in {', '.join(str(p) for p in QUOTES)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
