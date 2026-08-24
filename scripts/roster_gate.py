#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every whole-tree row still selects the whole tree.

The host rows used to name their crates: one 24-crate `-p` roster written out
nine times across `scripts/check.sh` (five rows), `docs/testing.md`,
`.github/workflows/deep-checks.yml` (the nightly `llvm-cov` row and the header
quoting it) and `nix/checks.nix` (generated from a list, so invisible to a
`git grep`). Nothing tied any copy to `Cargo.toml`, and three had rotted in
disjoint ways — 16 of 24 in the docs, 20 on the coverage row, 12 in the flake —
each green while covering less than its name said. Five commits then built a
guard to hold the nine together, and it reached 800 lines of Python over 34
lines of text, misdiagnosing ordinary edits on the way. That is how a guard
comes to be deleted.

There is no roster now. Every one of those rows says
`--workspace --exclude firmware --exclude rsk-wipe`, which is the same set by
construction: those two are the only `[workspace] members` outside `crates/`,
and the only two that are thumbv8m-only. Measured equivalent to the roster it
replaces on all four verbs — identical `cargo test` binaries, byte-identical
`llvm-cov` totals (85.02 % line), rc 0 from clippy, and the same 24 `rsk_*`
directories out of rustdoc.

What is left to check is the seams that spelling has, each one a way for a row
to run less than it says while staying green:

* the exclusion is stale — a member joins outside `crates/` and every host row
  builds it, or a name here is no longer a member at all;
* a crate under `crates/` is not a member, so `--workspace` cannot see it. The
  same seam as before, and now the only place a crate hides from every row at
  once;
* an exclude is dropped, a third is added, or its operand is generated so no
  reader can resolve it. The third exclude is the rotted roster in modern
  spelling: nothing fails, the row just measures less. Held over the whole
  checkout rather than a list of files, because the ninth copy was invisible to
  a census that was told where to look;
* a row this tree owes is gone — deleted, commented out, or narrowed back to a
  hand-written list, which is what "make the gate faster" reaches for;
* a row comes back that picks crates by name. Only in the four files below,
  only on an executed line, only for the verb that file promises whole, and
  only when `--features` is not filtering it: a one-crate example, a source
  comment and a changelog line each named crates on a cargo line under the old
  rule, and all three were false alarms. One crate counts here, unlike under
  that rule, because a row is not free to be an example when its file has
  promised the verb — `cargo doc -p rsk-fido --all-features` in place of the
  all-features rustdoc permutation is measured green otherwise;
* `check.sh` still runs this script, and still collects its tests.

Limits, so the row is not read as more than it is. It compares flags, not what
a row does: deleting the coverage row's `--fail-under-lines` leaves it
selecting every crate under `crates/` against no floor. "Executes" means "in a
`run:`, not commented out", so `if: false` on that step is a correct selection
over a job that asserts nothing — open on the Kani row too, so it is a class of
its own and not this file's to close alone. A verb is owed one whole-tree row
per file rather than a count, so *deleting* one of the three rustdoc
permutations outright is caught by nothing here — narrowing it is the rule
above's catch, losing it is not. And a selection whose verb is a substitution
(`cargo "$1"`, five rows folded into one helper) counts for every verb its file
owes, because nothing here resolves a shell variable — after such a refactor,
deleting one of its callers is invisible too.
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
#: Derived, not spelled out, so renaming either file cannot silently disarm the
#: two self-checks below.
SELF = pathlib.Path(__file__).resolve().relative_to(ROOT)
TESTS = SELF.with_name(f"test_{SELF.stem}.py")

#: The whole of what a host row may skip, and why it is exactly two: they are
#: the only `[workspace] members` outside `crates/`, and both are thumbv8m-only.
#: Checked against the manifest below, so this cannot be the next stale list.
EXCLUDED = frozenset({"firmware", "rsk-wipe"})


def shell(text):
    """Every line of a shell script is the gate — a nix build phase included."""
    return ((body, True) for _indent, body in gate_lines.logical_lines(text))


def prose(text):
    """Nothing in the docs, or in a guard's own docstring, is run by anybody."""
    return ((body, False) for _indent, body in gate_lines.logical_lines(text))


#: How each file is read: a workflow runs only what is inside a step's `run:`,
#: a shell script runs every line, prose runs nothing.
READ = {CHECK: shell, FLAKE: shell, WORKFLOW: gate_lines.yaml_runs, DOCS: prose}

#: Where a whole-tree selection has to be, and whether that copy is run or only
#: read. The workflow owes both: the row inside a step's `run:`, and the header
#: comment a reader pastes locally, which had drifted from it once already.
OWED = (
    (CHECK, "clippy", True),
    (CHECK, "doc", True),
    (CHECK, "test", True),
    (FLAKE, "test", True),
    (WORKFLOW, "llvm-cov", True),
    (WORKFLOW, "llvm-cov", False),
    (DOCS, "test", False),
)
#: A file that promises the whole tree for a verb may not also run that verb
#: over a hand-picked list — three rustdoc permutations exist because each sees
#: what the others cannot, and narrowing one of them is what "make the gate
#: faster" reaches for. Per file, so a one-crate `cargo llvm-cov` in check.sh,
#: which promises nothing about coverage, stays what it is.
PROMISED = {path: {v for p, v, _e in OWED if p == path} for path, *_ in OWED}

#: This guard's own text, which quotes the selection by the paragraph explaining
#: it, and its tests, which mutate it on purpose. Registered rather than carved
#: out of the walk's pattern: an exception written into a regex is the kind
#: nobody reads again.
QUOTING = frozenset({SELF, TESTS})

#: `cargo <verb>`, and the same with the verb behind a substitution: rows folded
#: into one helper still select the whole tree, and reporting them as deleted is
#: the message guaranteed to be read as a false alarm.
CARGO = gate_lines.invocation((r"[\w-]+", r"""["']?[$@{%]\S*"""))
LITERAL = re.compile(r"[\w-]+")
WORKSPACE = re.compile(r"(?<![\w-])--workspace(?![\w-])")
EXCLUDE = re.compile(r"(?<![\w-])--exclude[=\s]+([\w-]+)(?![\w-])")
#: The same flag with an operand a substitution fills in, so no reader can
#: resolve it from the flag alone. A sigil, not "anything but a name", so that
#: prose writing `--exclude …` stays prose.
EXCLUDE_GENERATED = re.compile(r"""(?<![\w-])--exclude[=\s]+["']?[$@{%]""")
#: `cargo kani`'s list is `kani_gate.py`'s: it names the crates carrying a
#: `#[kani::proof]`, which is a claim about the harnesses, not about the tree.
OTHER_GUARDS = ("kani",)
#: What a row says when its list is deliberately not the tree. In the comment
#: half of the line, so it is a shell comment wherever it is written.
SCOPED = re.compile(r"#\s*roster: scoped\b")
#: `-F` is `--features`' short form. `--all-features` deliberately does not
#: match — it selects no subset, so that row is still a whole-tree row.
SELECTIVE = re.compile(r"(?:^|\s)(?:--features\b|-F)")


def commands(segment):
    """(verb, arguments) per invocation on `segment`, each stopping at the next.

    Two chained on one line stay two rows — merged, either could hide behind the
    other's flags.
    """
    found = list(CARGO.finditer(segment))
    for this, after in zip(found, [*found[1:], None]):
        yield this.group(1), segment[this.end() : after.start() if after else None]


def selects_tree(tail):
    """Whether these arguments are the documented whole-tree selection."""
    return bool(WORKSPACE.search(tail)) and frozenset(EXCLUDE.findall(tail)) == EXCLUDED


def rows(root, path):
    """(verb, arguments, executed, comment) per cargo invocation in `path`."""
    for body, runs in READ[path]((root / path).read_text()):
        live, quoted = gate_lines.split_at_comment(body)
        for segment, executed in ((live, runs), (quoted, False)):
            for verb, tail in commands(segment):
                if verb not in OTHER_GUARDS:
                    yield verb, tail, executed, quoted


def stray_excludes(root):
    """Every cargo `--exclude` in the checkout that is not the documented pair.

    Found, not remembered. The ninth copy of the old roster generated its flags,
    so the census that was told where to look could not see it; what a file
    contains decides whether it is read here.
    """
    for rel in sorted(gate_lines.tree_files(root)):
        if rel in QUOTING:
            continue
        try:
            text = (root / rel).read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for _indent, body in gate_lines.logical_lines(text):
            for _verb, tail in commands(body):
                got = frozenset(EXCLUDE.findall(tail))
                if EXCLUDE_GENERATED.search(tail):
                    yield (
                        f"{rel} builds a cargo `--exclude` from something this"
                        " guard cannot read: write the crate names out"
                    )
                elif got and got != EXCLUDED:
                    yield (
                        f"{rel} excludes {' '.join(sorted(got))} from a cargo"
                        f" `--workspace`, not {' '.join(sorted(EXCLUDED))}"
                    )


def members(root):
    """(package name -> member path, entries with no manifest) for `[workspace]`.

    The name comes out of each manifest rather than off its directory: `-p` and
    `--exclude` both take the package name, and nothing in cargo makes the two
    agree. A glob is a member spelling cargo accepts, so it is expanded rather
    than opened as a path — opening it raised a `FileNotFoundError` traceback,
    which fails loud but says nothing. A glob matching a directory with no
    manifest is just a glob; a literal entry without one is a broken workspace.
    """
    root_manifest = tomllib.loads((root / "Cargo.toml").read_text())
    found, broken = {}, []
    for entry in root_manifest["workspace"]["members"]:
        globbed = "*" in entry or "?" in entry or "[" in entry
        for path in sorted(root.glob(entry)) if globbed else [root / entry]:
            manifest = path / "Cargo.toml"
            if not manifest.is_file():
                if not globbed:
                    broken.append(entry)
                continue
            name = tomllib.loads(manifest.read_text())["package"]["name"]
            found[name] = str(path.relative_to(root))
    return found, broken


def tree_problems(root):
    """What `--workspace` itself cannot be trusted to cover, and what it skips."""
    member, broken = members(root)
    crates = {name for name, rel in member.items() if rel.startswith("crates/")}
    problems = [
        f"Cargo.toml's [workspace] members names {rel}, which has no Cargo.toml"
        for rel in broken
    ]
    for name in sorted(set(member) - crates - EXCLUDED):
        problems.append(
            f"{member[name]} is a workspace member outside crates/, so every host"
            f" row builds it — move it under crates/ if it is host-testable, or"
            f" exclude it in {SELF} and on every row"
        )
    for name in sorted(EXCLUDED - (set(member) - crates)):
        problems.append(
            f"{name} is excluded by every host row but is no longer a workspace"
            " member outside crates/"
        )
    listed = set(member.values())
    for path in sorted((root / "crates").iterdir()):
        if (path / "Cargo.toml").is_file() and f"crates/{path.name}" not in listed:
            problems.append(
                f"crates/{path.name} is not in Cargo.toml's [workspace] members,"
                " so --workspace cannot reach it"
            )
    return problems, crates


def collects(command, tests):
    """Whether a pytest invocation's path arguments reach `tests`."""
    return any(pathlib.Path(w) in (tests, *tests.parents) for w in command.split())


def audit(root):
    """(problems, one-line summary) for how this checkout selects its crates."""
    problems, crates = tree_problems(root)
    covered = collections.Counter()
    for path in READ:
        for verb, tail, executed, quoted in rows(root, path):
            if selects_tree(tail):
                covered[path, verb if LITERAL.fullmatch(verb) else None, executed] += 1
            elif (
                executed
                and verb in PROMISED[path]
                and not SELECTIVE.search(tail)
                and not SCOPED.search(quoted)
                and gate_lines.packages(tail) & crates
            ):
                picked = " ".join(sorted(gate_lines.packages(tail) & crates))
                problems.append(
                    f"{path}: `cargo {verb}` picks {picked} by name while this"
                    f" file's `cargo {verb}` is the whole tree. Say --workspace"
                    " with the excludes, or `# roster: scoped — why`"
                )
    problems += list(dict.fromkeys(stray_excludes(root)))
    for path, verb, executed in OWED:
        if not covered[path, verb, executed] + covered[path, None, executed]:
            problems.append(
                f"no `cargo {verb} --workspace` with the excludes"
                f"{'' if executed else ' is quoted'} in {path}: the row is gone,"
                " commented out, or back to a hand-written list"
            )
    check = READ[CHECK]((root / CHECK).read_text())
    live = [gate_lines.split_at_comment(body)[0] for body, _ in check]
    guard = [r for r in live if str(SELF) in r]
    tested = [r for r in live if "pytest" in r and collects(r, TESTS)]
    for what, hit in ((SELF, guard), (TESTS, tested)):
        if not hit:
            problems.append(f"{CHECK} no longer runs {what}")
    where = ", ".join(
        f"{n}× cargo {verb or '<var>'}{'' if executed else ' (quoted)'} in {path}"
        for (path, verb, executed), n in sorted(covered.items(), key=str)
    )
    return problems, (
        f"{len(crates)} crates under crates/, {' and '.join(sorted(EXCLUDED))}"
        f" excluded, selected whole by {where}"
    )


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("crate-roster:")
        for line in problems:
            print(f"  {line}")
        excludes = " ".join(f"--exclude {c}" for c in sorted(EXCLUDED))
        print(
            "\nA host row that skips a crate does not lint, document, test or\n"
            "measure it, and the row stays green either way. Every one of them\n"
            f"selects `--workspace {excludes}`; the files that\n"
            f"carry one are {', '.join(str(p) for p in READ)}."
        )
        return 1
    print(f"crate-roster: ok — {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
