#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every whole-tree `-p` roster names every crate the workspace has.

`scripts/check.sh` writes the same crate list out five times — the host clippy
row, three rustdoc rows, the host test row — `docs/testing.md` carries a sixth
for a reader to copy, `.github/workflows/deep-checks.yml` a seventh on the
nightly `llvm-cov` row plus an eighth quoting it in the header, and
`nix/checks.nix` a ninth that `nix flake check` runs. Nothing tied any of them
to `Cargo.toml`'s `[workspace] members`, so a crate that joins the tree joins
none of the rosters and every row stays green while covering less than its name
says. Not hypothetical, three times over, and the shape of it is worse than
neglect. The docs copy stood at 16 of 24 while having been amended four times,
each by the commit that added the one crate it names (`rsk-vendor`,
`rsk-device`, `rsk-store`, `rsk-display`); the eight it missed had all joined
the tree *before* those four. The coverage roster stood at 20 of 24, amended
twice the same way (`rsk-sha512`+`rsk-bench`, then `rsk-ec`+`rsk-mldsa`) and
missing exactly the four the docs copy had kept. The flake's stood at 12 of 24
and had never been amended at all — it was complete on the day de6f6d1 wrote it
and every crate since has passed it by, under a comment claiming it is "the same
host-testable crates scripts/check.sh runs". A list somebody keeps amending is
exactly the list nobody rereads, and a list nobody has ever amended is worse.

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
* a row that runs, filters no features and names a *list* of crates must name
  every member under `crates/` — the new crate nobody added. It holds whatever
  the verb: a roster is a claim about the tree before it is a claim about
  linting or testing it, and leaving verbs off the hook is how a row escapes by
  being new. A `--features X` row is about the crates that declare X and is
  exempt; `--all-features` filters nothing and is not;
* a row that names one crate is about that crate and owes nothing. Two is where
  a list starts, and that is the only boundary with a meaning: between "a list"
  and "a crate", not anywhere on the way to complete, since a 23-of-24 row is
  exactly the failure this exists for. Holding one-crate rows to the tree is not
  theoretical either — it is what a `cargo llvm-cov -p rsk-display` step, a
  `run:` echoing one, and a `cargo test -p rsk-crypto -- --ignored` row each did
  to this guard, 23 complaints apiece. A deliberate list that is *not* the tree
  says so on the line with [`SCOPED`]; the presence rule below is what stops
  that from being a way to switch the whole thing off;
* a file that only *quotes* the list must carry one complete copy, not consist
  of complete copies. `docs/testing.md` is prose and prose grows examples:
  holding its every `cargo test -p …` to the whole tree reported 23 missing
  crates the moment a one-crate `cargo test -p rsk-fido` example was added
  beside the roster, and a guard that cries wolf on a docs edit is a guard
  someone deletes. The workflow's header block is the same kind of text and gets
  the same rule — it is the only `#` text scanned here, because in `check.sh`
  and the docs a `#` is a dead row or a heading while there it is the local
  equivalent a reader pastes, kept in step with the row beside it;
* each verb in [`WHOLE_TREE`] keeps at least one whole-tree roster in the file
  that owes it — deleting the row, commenting it out, marking it scoped, or
  shrinking it to one crate, which is what "make the gate faster" reaches for;
* every `crates/*/Cargo.toml` is a workspace member — the seam one level up,
  where a crate is invisible to `--workspace` and to all nine rosters at once;
* **every file that selects cargo packages is one of [`SOURCES`]** — the seam
  this guard itself shipped with. A hand-written list of files to read is the
  same defect one level up, and it duly failed: the census that declared "eight
  rosters and no ninth" was `git grep -- '-p rsk-'`, and `nix/checks.nix`
  generates its flags (`concatMapStringsSep " " (c: "-p ${c}") hostCrates`), so
  no such string exists in it. So the owners are *found*: the tree is walked,
  every `cargo …` in it is read, and one that selects packages in a file this
  script does not know fails here. Registering a file is then a deliberate act
  with a name attached, and the next generated flag cannot be a tenth;
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
the row stops doing what its name says, and deleting the coverage row's
`--fail-under-lines` leaves it measuring 24 crates against no floor at all. The
`--features` exemption is per row, and presence is per verb: `cargo doc` has
three permutations here, so putting `--features` on one of them and gutting its
list leaves the other two answering for the verb — the per-verb count this
prints is where that shows, and it is printed rather than asserted because the
alternative is a number to maintain. "Executes" means "in a `run:`, not
commented out", so `if: false` or `continue-on-error: true` on the coverage step
is a complete roster over a job that asserts nothing; closing that needs the
shared reader to track step structure, and it is open on the Kani row too, so it
is a class of its own and not this file's to fix alone. Nothing here parses a
shell: a `run:` that only *echoes* a complete roster counts as a row, and one
that echoes an incomplete one is a false alarm (an echoed single crate is free,
which is the shape that was measured). The three guards are [`SOURCES`] entries
themselves, since their own text quotes `-p` lines by the dozen, so a roster
written *into* a gate script is one the census does not see. Run from `check.sh`
it cannot catch its own row being commented out; the self-check bites when the
script is run by hand, the one vantage point outside the thing being guarded.
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
FLAKE = pathlib.Path("nix/checks.nix")
KANI_GATE = pathlib.Path("scripts/kani_gate.py")
LINE_READER = pathlib.Path("scripts/gate_lines.py")
#: Derived, not spelled out, so renaming the script cannot silently disarm the
#: self-check below.
SELF = pathlib.Path(__file__).resolve().relative_to(ROOT)


def shell(text):
    """Every line of a shell script is the gate — a nix build phase included."""
    return ((body, True) for _indent, body in gate_lines.logical_lines(text))


def prose(text):
    """Nothing in the docs, or in a guard's own docstring, is run by anybody."""
    return ((body, False) for _indent, body in gate_lines.logical_lines(text))


#: How each file is read, which of its cargo verbs must keep a whole-tree row
#: there, and what its quoted copy is for. `read` is where a command is live: a
#: workflow runs only what is inside a step's `run:`. `owes` is the presence half
#: only — every executed list is held to the tree whatever its verb — and it is
#: what catches a row deleted, commented out or quietly narrowed to one crate.
#: The census below is what keeps this map from being the next stale list: a file
#: outside it that selects cargo packages fails.
Source = collections.namedtuple("Source", "read owes quotes")

SOURCES = {
    CHECK: Source(shell, ("clippy", "doc", "test"), None),
    WORKFLOW: Source(
        gate_lines.yaml_runs, ("llvm-cov",), "the local equivalent of its nightly rows"
    ),
    FLAKE: Source(shell, ("test",), None),
    DOCS: Source(prose, (), "the `-p` roster a reader copies"),
    # The three guards themselves, which own no roster but quote `-p` lines by
    # the dozen explaining them. Registered rather than carved out of the
    # census's regex: one place records every file that mentions a package
    # selection and what it is, and an exception written into a pattern is the
    # kind nobody reads again.
    SELF: Source(prose, (), None),
    KANI_GATE: Source(prose, (), None),
    LINE_READER: Source(prose, (), None),
}
WHOLE_TREE = {path: s.owes for path, s in SOURCES.items() if s.owes}
QUOTES = {path: s.quotes for path, s in SOURCES.items() if s.quotes}

#: Any cargo verb, not the handful `owes` names: a list of crates under a verb
#: this script has never heard of is still a list of crates, and reading only
#: the known verbs is how a row would escape by being new. `build`/`tree` name
#: one crate on purpose and the one-crate rule is what frees them, not this.
CARGO = gate_lines.invocation((r"[\w-]+",))
#: The one verb whose roster is not a claim about the tree: `cargo kani`'s list
#: is `kani_gate.py`'s, held against the crates that carry a `#[kani::proof]`
#: and its own measured exclusion. Holding it to `[workspace] members` would
#: demand harnesses from nine crates that have none.
OTHER_GUARDS = ("kani",)
#: `-F` is `--features`' short form. `--all-features` deliberately does not
#: match — it selects no subset, so that row owes the whole roster too.
SELECTIVE = re.compile(r"(?:^|\s)(?:--features\b|-F)")
#: What a row says when its list is deliberately not the tree. In the comment
#: half of the line, so it is a shell comment wherever it is written.
SCOPED = re.compile(r"#\s*roster: scoped\b")
#: A `name = [ "a" "b" ]` binding — the list a generated `-p` flag iterates.
BINDING = re.compile(r"(?<![\w-])(\w+)\s*=\s*\[([^]]*)\]", re.S)
STRING = re.compile(r'"([\w-]+)"')

Roster = collections.namedtuple("Roster", "path verb named filtered executed scoped")


def lines(path):
    """(logical line, executed) for `path`, read as what the file is."""
    return SOURCES[path].read((ROOT / path).read_text())


def commands(segment, matcher):
    """(verb, arguments) per invocation on `segment`, each stopping at the next.

    Two chained on one line stay two rosters — merged, either could hide behind
    the other's crates.
    """
    found = list(matcher.finditer(segment))
    for this, after in zip(found, [*found[1:], None]):
        yield this.group(1), segment[this.end() : after.start() if after else None]


def generated(tail, text):
    """The crates behind a `-p` flag some generator builds, or None.

    `nix/checks.nix` writes `concatMapStringsSep " " (c: "-p ${c}") hostCrates`,
    so the roster is the list, not the flag. Resolved by name against the same
    file, and only when exactly one name in the invocation is a list of strings
    there — two would be a guess.
    """
    if not gate_lines.PKG_GENERATED.search(tail):
        return None
    lists = {m[1]: frozenset(STRING.findall(m[2])) for m in BINDING.finditer(text)}
    hit = [w for w in dict.fromkeys(re.findall(r"[A-Za-z_]\w*", tail)) if w in lists]
    return lists[hit[0]] if len(hit) == 1 else frozenset()


def rosters(path):
    """Every `cargo <verb> … -p …` line in `path`, flagged executed or not.

    A line with no `-p` names no roster (`cargo doc --manifest-path tools/tui/…`
    is the whole of its own workspace). A commented tail runs nothing, and only
    in the workflow is it also read: there the header quotes the row it runs, and
    the pair drifting apart is the failure. In `check.sh` and in the docs a `#`
    is a dead row or a heading, and holding either to the whole tree is how a
    guard starts crying wolf.
    """
    text = (ROOT / path).read_text()
    for body, executed in lines(path):
        live, quoted = gate_lines.split_at_comment(body)
        segments = [(live, executed)]
        if path == WORKFLOW:
            segments.append((quoted, False))
        for segment, runs in segments:
            for verb, tail in commands(segment, CARGO):
                if verb in OTHER_GUARDS:
                    continue
                named = gate_lines.packages(tail) or generated(tail, text)
                if named is not None:
                    yield Roster(
                        path,
                        verb,
                        named,
                        bool(SELECTIVE.search(tail)),
                        runs,
                        bool(SCOPED.search(quoted)),
                    )


def census(crates):
    """Which files select cargo packages — found, not remembered.

    Every one of them must be a [`SOURCES`] entry, because a file this script
    does not open is a roster nothing checks, and that is how the ninth copy
    lived: its `-p` is generated, so the literal-string census that cleared the
    tree could not see it. Two shapes count as selecting: naming crates of this
    tree (one is an example, two is a list), and building the flag out of
    something no reader can resolve.
    """
    for rel in sorted(gate_lines.tree_files(ROOT)):
        if rel in SOURCES:
            continue
        try:
            text = (ROOT / rel).read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for _indent, body in gate_lines.logical_lines(text):
            for _verb, tail in commands(body, CARGO):
                named = gate_lines.packages(tail) & crates
                if gate_lines.PKG_GENERATED.search(tail):
                    yield (
                        f"{rel} builds a cargo `-p` flag from something this guard"
                        " cannot read, and is in no SOURCES entry"
                    )
                elif len(named) > 1:
                    yield (
                        f"{rel} names {len(named)} of the tree's crates on a cargo"
                        " command line, and is in no SOURCES entry"
                    )


def members():
    """(package name -> member path, entries with no manifest) for `[workspace]`.

    The name comes out of each manifest rather than off its directory: `-p` takes
    the package name, and nothing in cargo makes the two agree. A glob is a
    member spelling cargo accepts, so it is expanded rather than opened as a
    path — opening it raised a `FileNotFoundError` traceback, which fails loud
    but says nothing, and a guard that can crash is one more thing to disbelieve.
    A glob matching a directory with no manifest is just a glob; a literal entry
    without one is a broken workspace and is reported.
    """
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    found, broken = {}, []
    for entry in root["workspace"]["members"]:
        globbed = "*" in entry or "?" in entry or "[" in entry
        for path in sorted(ROOT.glob(entry)) if globbed else [ROOT / entry]:
            manifest = path / "Cargo.toml"
            if not manifest.is_file():
                if not globbed:
                    broken.append(entry)
                continue
            name = tomllib.loads(manifest.read_text())["package"]["name"]
            found[name] = str(path.relative_to(ROOT))
    return found, broken


def main():
    member, broken = members()
    crates = {name for name, rel in member.items() if rel.startswith("crates/")}
    found = [roster for path in SOURCES for roster in rosters(path)]
    # One file can carry the same unregistered shape a dozen times; the verdict
    # is the file, so say it once.
    problems = list(dict.fromkeys(census(crates)))
    problems += [
        f"Cargo.toml's [workspace] members names {rel}, which has no Cargo.toml"
        for rel in broken
    ]

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
        if not roster.named:
            problems.append(
                f"{where} builds its `-p` flags from a list this guard cannot"
                ' read: name it in that file as `<name> = [ "rsk-…" … ]`'
            )
        for crate in sorted(roster.named - set(member)):
            problems.append(f"{where} names {crate}, not a workspace member")
        # Only a row that runs, over a list rather than one crate, owes the whole
        # tree line by line; a quoted one owes its file one complete copy,
        # checked below. A roster naming no `crates/` member is about
        # `firmware`/`rsk-wipe`, the thumbv8m-only pair, and owes this nothing.
        if (
            not roster.executed
            or roster.filtered
            or roster.scoped
            or len(roster.named & crates) < 2
        ):
            continue
        for crate in sorted(crates - roster.named):
            problems.append(f"{where} does not name {crate}")

    covered = collections.Counter(
        (roster.path, roster.verb)
        for roster in found
        if roster.executed
        and not roster.filtered
        and not roster.scoped
        and len(roster.named & crates) > 1
    )
    for path, verbs in WHOLE_TREE.items():
        for verb in verbs:
            if not covered[path, verb]:
                problems.append(
                    f"no `cargo {verb} … -p …` over the whole tree runs in {path}:"
                    " the row is gone, commented out, marked scoped or down to one"
                    " crate. If the verb moved to --workspace, take it out of"
                    " SOURCES' `owes` and say so there."
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
            f"to every roster in {', '.join(str(p) for p in WHOLE_TREE)},\n"
            f"and to the quoted copy in {', '.join(str(p) for p in QUOTES)}.\n"
            "A row whose list is deliberately not the tree says so on the line\n"
            "with `# roster: scoped — why`; a file that names crates on a cargo\n"
            "line and is not one of the above joins SOURCES, saying which it is."
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
