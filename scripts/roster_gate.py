#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every whole-tree `-p` roster names every crate the workspace has.

`scripts/check.sh` writes the same crate list out five times — the host clippy
row, three rustdoc rows, the host test row — and `docs/testing.md` carries a
sixth for a reader to copy. Nothing tied any of them to `Cargo.toml`'s
`[workspace] members`, so a crate that joins the tree joins none of the rosters
and every row stays green while covering less than its name says. Not
hypothetical: the docs copy had already rotted to 16 of 24, missing every crate
added since it was written — `rsk-ec`, `rsk-mldsa` and `rsk-sha512` among them,
which is to say the crypto.

Same shape as the Kani roster next door and the same fix: the roster is checked,
not remembered. It is a second script rather than more rules inside
`scripts/kani_gate.py` because that one answers a different question from a
different source of truth — which crates carry a `#[kani::proof]`, against a
workflow and the docs — and one script answering both would report "roster" for
two unrelated failures.

The rules, and the mistake each one catches:

* a roster may only name real workspace members — a typo, or a crate that left;
* a roster filtering no features must name every member under `crates/` — the
  new crate nobody added. A `--features X` row is about the crates that declare
  X and is exempt; `--all-features` filters nothing and is not;
* each of [`WHOLE_TREE`]'s verbs keeps at least one such roster in `check.sh` —
  deleting the row, or commenting it out, which is what "make the gate faster"
  reaches for first;
* every `crates/*/Cargo.toml` is a workspace member — the seam one level up,
  where a crate is invisible to `--workspace` and to all six rosters at once;
* `check.sh` still runs this script.

`kani_gate.py` shipped with two holes worth not repeating. It counted a
commented-out invocation as a live one, so only lines that execute count here (a
`#` line is a shell comment in the script and a heading in the docs; neither
runs anything). And it compared crate sets while the rest of the command was
free to drift; the analog here is the `crates/` directory itself, which is why
the filesystem is checked against `Cargo.toml` instead of trusted through it.

Limits, so the row is not read as more than it is. It compares crate sets, not
switches: a roster can stay complete while the row stops doing what its name
says — three rustdoc permutations becoming two shows up only in the per-verb
count this prints. Run from `check.sh` it cannot catch its own row being
commented out; the self-check bites when the script is run by hand, the one
vantage point outside the thing being guarded. And `deep-checks.yml`'s
`llvm-cov` list is a further copy that is deliberately not checked here: its
coverage floor is measured over exactly the crates it names, so adding one is a
workflow change with a number attached, not bookkeeping.
"""

import collections
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECK = pathlib.Path("scripts/check.sh")
DOCS = pathlib.Path("docs/testing.md")
#: Derived, not spelled out, so renaming the script cannot silently disarm the
#: self-check below.
SELF = pathlib.Path(__file__).resolve().relative_to(ROOT)

#: The cargo verbs whose `-p` roster is meant to be the whole tree: what the gate
#: lints, documents and tests is every crate, or the row's name is a lie. `cargo
#: kani`'s roster is a different question (`kani_gate.py` owns it), and
#: `build`/`tree` name one crate on purpose.
WHOLE_TREE = ("clippy", "doc", "test")

INVOCATION = re.compile(rf"\bcargo ({'|'.join(WHOLE_TREE)})\b")
PKG = re.compile(r"(?:-p|--package)\s+([\w-]+)")
#: `-F` is `--features`' short form. `--all-features` deliberately does not
#: match — it selects no subset, so that row owes the whole roster too.
SELECTIVE = re.compile(r"(?:^|\s)(?:--features\b|-F)")

Roster = collections.namedtuple("Roster", "path verb named filtered")


def logical_lines(path):
    """The file's lines with `\\` continuations folded into one.

    `docs/testing.md` already writes its roster over four lines, and a long `run`
    row gets reflowed sooner or later. Half a roster read off half a line fails a
    comparison that nothing is wrong with, and a guard that cries wolf on a
    formatting edit is a guard someone deletes.
    """
    return re.sub(r"\\\n\s*", " ", (ROOT / path).read_text()).splitlines()


def rosters(path):
    """Every executed `cargo clippy|doc|test … -p …` line in `path`.

    A line with no `-p` names no roster (`cargo doc --manifest-path tools/tui/…`
    is the whole of its own workspace), and a commented one runs nothing. Each
    invocation's arguments stop at the next one, so two chained on one line stay
    two rosters — merged, either could hide behind the other's crates.
    """
    for line in logical_lines(path):
        body = line.strip()
        if body.startswith("#"):
            continue
        found = list(INVOCATION.finditer(body))
        for this, after in zip(found, [*found[1:], None]):
            tail = body[this.end() : after.start() if after else len(body)]
            named = frozenset(PKG.findall(tail))
            if named:
                yield Roster(path, this.group(1), named, bool(SELECTIVE.search(tail)))


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
    found = [*rosters(CHECK), *rosters(DOCS)]
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
        for crate in sorted(roster.named - set(member)):
            problems.append(f"{where} names {crate}, not a workspace member")
        # A roster naming no `crates/` member is about `firmware`/`rsk-wipe`, the
        # thumbv8m-only pair; it owes nothing to this list.
        if roster.filtered or not roster.named & crates:
            continue
        for crate in sorted(crates - roster.named):
            problems.append(f"{where} does not name {crate}")

    covered = collections.Counter(
        roster.verb
        for roster in found
        if roster.path == CHECK and not roster.filtered and roster.named & crates
    )
    for verb in WHOLE_TREE:
        if not covered[verb]:
            problems.append(
                f"no `cargo {verb} … -p …` over the whole tree is left in {CHECK}:"
                " the row is gone or commented out. If the verb moved to"
                " --workspace, take it out of WHOLE_TREE and say so there."
            )
    if not [r for r in found if r.path == DOCS]:
        problems.append(f"{DOCS} no longer carries the `-p` roster a reader copies")
    live = (r for r in logical_lines(CHECK) if not r.strip().startswith("#"))
    if not [r for r in live if str(SELF) in r]:
        problems.append(f"{CHECK} does not run {SELF}: the rosters are unchecked again")

    if problems:
        print("crate-roster:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA crate absent from a `-p` list is not linted, documented or tested by\n"
            "that row, and the row stays green either way. Add it to every roster in\n"
            f"{CHECK} and to the one in {DOCS}."
        )
        return 1

    print(
        f"crate-roster: ok — {len(crates)} crates under crates/, each named by "
        + ", ".join(f"{n}× cargo {verb}" for verb, n in sorted(covered.items()))
        + f" in {CHECK}, and by {DOCS}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
