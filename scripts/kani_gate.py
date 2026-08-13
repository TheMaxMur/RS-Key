#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the Kani rows, all of them, run every harness the tree has.

`cargo kani` is invoked with a hand-written `-p` list, and a crate that is not on
it is not proven — but nothing says so. The row was named "prove every harness"
and it was running 29 of 49. Never added: `rsk-ui` (12 proofs, the trusted
display's touch-target geometry — the anti-phishing consent surface), `rsk-led`
(5 over `EF_LED_CONF`, a persisted record with a published wire format),
`rsk-slip39` and `rsk-bip39`. Green daily, asserting nothing about any of them. A
harness in an unlisted crate is worse than no harness, because the reviewer
believes it runs.

Third time a gate script has been the finding rather than the instrument (after
the test filter that matched nothing and the fuzz row blind to `[[bin]]`
targets), and the first two were fixed at the site with no guard, which is why
there was a third. So: the roster is checked, not remembered.

Since the proofs split into tiers — a fast one on every pull request, the
security-state crates when a change reaches them, all of them daily — the roster
is no longer a string to compare. `scripts/kani.sh` owns tier → crates and prints
the table with `--tiers`; this reads that table and asks four things of it:

* the `all` tier is exactly the crates carrying a `#[kani::proof]`, less
  [`EXCLUDED`] — both directions, so a crate with an unrun proof fails and so
  does a listed crate whose proof went away;
* every other tier is a non-empty subset of it, because a tier that selects
  nothing is a row that exits 0 having proved nothing (`kani.sh` floors the
  harness count for the same reason, one layer down);
* every tier is invoked by a row CI actually **runs** — inside a step's `run:`
  scalar, left of any `#`. Counting matching strings is not enough: a workflow
  header's local-equivalent comment is a second copy in the same file, so putting
  a `#` in front of the `run:` line once left three agreeing rosters and this
  guard green over a job that proved nothing. "Uncommented" is judged from the
  `#`, not from the line's first character — `run: true # scripts/kani.sh all`
  runs the `true`;
* and every tier is in docs/testing.md, which is what a reader copies and which
  says CI runs the same commands.

The counts those tiers are floored at are read the same way. `kani.sh`'s
`FLOOR_*`/`COVERS_*` say how many harnesses and `kani::cover!`s a run must come
back with, docs/testing.md prints the same numbers in a table, and all four sets
were kept by the instruction "raise it in the commit that adds one". They drifted:
`FLOOR_all` sat at 64 against a tree of 65, so one harness could have gone missing
under a floor that still passed. Counted from the source here instead, both
directions — a floor under the tree is loose, one over it demands more than a run
can report — and the same for the page's table. The count is comment-stripped,
because two `*_kani.rs` files discuss `kani::cover!` in prose, and a spelling
neither counter can see is refused by name rather than skipped: an uncounted
harness is a floor set one too low, which is the drift, and it would be silent.

Nothing outside `scripts/kani.sh` may write a `-p` roster into a workflow or into
that page. That is the rule the old three-way string comparison was standing in
for, and it is the one that stops a fifth copy from appearing the day someone
wants a fifth tier. A `cargo kani -p <crate>` in a source file's doc comment is
not in scope: it tells a reader how to run one crate, it does not claim to say
what CI proves.

Deliberately syntactic. It cannot say a harness proves anything worth proving —
that is the harness's own business — only that the solver is pointed at it.
"""

import collections
import pathlib
import re
import subprocess
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = pathlib.Path(".github/workflows")
DOCS = pathlib.Path("docs/testing.md")
RUNNER = pathlib.Path("scripts/kani.sh")
#: Where the version CI installs is written down.
PINNED_IN = pathlib.Path(".github/workflows/deep-checks.yml")

#: Crates with a harness the daily row deliberately does not run, each with the
#: measured reason. An exclusion is a debt, so it is checked too: one naming a crate
#: that no longer has a proof is stale and fails, rather than quietly covering for a
#: harness someone deleted.
EXCLUDED = {
    "rsk-bench": "`summarize` sorts `samples[warmup..]`, a symbolic-length slice, so "
    "CBMC unwinds it without a bound: no verdict in 5 min, and none with "
    "--default-unwind 5 either (measured, kani 0.67.0, 2026-08-11).",
}

#: The tier that has to hold every crate. The others are subsets of it, so this is
#: the one the coverage question is asked of.
FULL = "all"

#: The version the workflow pins and the docs tell a reader to install. Kani's
#: verdicts are version-dependent, so an unpinned local install is a different tool.
PINNED = re.compile(r'KANI_VERSION:\s*"([\d.]+)"')
DOC_PIN = re.compile(r"kani-verifier --version ([\d.]+)")

#: An invocation of the tier runner, with or without a `./` and whatever drives it.
INVOKED = re.compile(r"(?<![\w/-])(?:\./)?scripts/kani\.sh\s+(\S+)")

#: The two shapes the floors are counts of. Every one in this tree is written
#: exactly like this, `#[kani::proof]` alone on its line.
HARNESS = re.compile(r"#\[kani::proof\]")
COVER = re.compile(r"\bkani::cover!")

#: Code that names one of them in a spelling neither counter sees: a contract
#: harness, a `cfg_attr` form, an import that could rename the macro. Refused, not
#: skipped — the miss would set a floor low, which is exactly the drift.
UNSEEN = re.compile(r"kani::(?:proof|cover)|^\s*use\s+kani::")

#: `kani.sh`'s ratchets, and the columns docs/testing.md prints beside them:
#: `| `pr` | 13 | 49 | 23 | …` is crates, harnesses, covers.
RATCHET = re.compile(r"^(FLOOR|COVERS)_(\w+)=(\d+)$", re.M)
DOC_ROW = re.compile(r"^\|\s*`(\w+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", re.M)

#: A hand-written roster: `cargo kani` with a package flag on it. `cargo kani
#: setup` carries none and is not one.
KANI = gate_lines.invocation(("kani",))

Use = collections.namedtuple("Use", "path tier executed")


def tiers(root):
    """tier → crates, as `scripts/kani.sh` itself reports them.

    Asked of the script rather than parsed out of it: `--tiers` and the run path
    go through the same `case`, so a tier this is shown is a tier that would
    actually run. Parsing the shell would be a second reading of the same table,
    which is the defect this guard exists to catch, one level up.
    """
    listing = subprocess.run(
        [str(root / RUNNER), "--tiers"], capture_output=True, check=True, text=True
    ).stdout
    out = {}
    for line in listing.splitlines():
        name, _, crates = line.partition(":")
        if name.strip():
            out[name.strip()] = frozenset(crates.split())
    return out


def statements(text, yaml):
    """(line, is inside a step's `run:`) over a workflow or a page of prose."""
    if yaml:
        yield from gate_lines.yaml_runs(text)
    else:
        for _indent, body in gate_lines.logical_lines(text):
            yield body, False


def uses(rel, text, yaml):
    """Every `scripts/kani.sh <tier>` on `text`, flagged executed or not.

    Executed means inside a step's `run:` scalar *and* left of the `#` — the only
    copy a job runs. A prose or comment copy is a quotation of it. Documentation
    is never executed, whatever it looks like.
    """
    for body, in_run in statements(text, yaml):
        live, quoted = gate_lines.split_at_comment(body)
        for segment, executed in ((live, in_run), (quoted, False)):
            for found in INVOKED.finditer(segment):
                yield Use(rel, found.group(1), executed)


def handwritten(rel, text, yaml):
    """Every hand-written `cargo kani … -p …` on `text` — there should be none."""
    for body, _in_run in statements(text, yaml):
        for found in KANI.finditer(body):
            if gate_lines.packages(body[found.start() :]):
                yield rel


def sources(root):
    """The files that claim to say what CI proves: every workflow, and the page."""
    for path in sorted((root / WORKFLOWS).glob("*.yml")):
        yield path.relative_to(root), path.read_text(), True
    yield DOCS, (root / DOCS).read_text(), False


def code_lines(text):
    """`text`'s lines with `//` and `/* … */` comments taken out.

    Prose is not a harness: `presence_kani.rs` and `rsa-asm/src/kani.rs` each
    discuss `kani::cover!` in a doc comment, and counting those two puts a floor
    above anything a run can report. A `//` inside a string ends the line early,
    which can only ever cut a macro's *arguments* — the token that opens the
    statement is left of any string on the line.
    """
    depth = 0
    for line in text.splitlines():
        out, i = [], 0
        while i < len(line):
            if depth:
                if line.startswith("*/", i):
                    depth -= 1
                    i += 2
                elif line.startswith("/*", i):
                    depth += 1
                    i += 2
                else:
                    i += 1
            elif line.startswith("/*", i):
                depth += 1
                i += 2
            elif line.startswith("//", i):
                break
            else:
                out.append(line[i])
                i += 1
        yield "".join(out)


def counted(text):
    """(harnesses, covers, the lines naming one that neither counter can see)."""
    harnesses = covers = 0
    unseen = []
    for line in code_lines(text):
        harnesses += len(HARNESS.findall(line))
        covers += len(COVER.findall(line))
        if UNSEEN.search(COVER.sub("", HARNESS.sub("", line))):
            unseen.append(line.strip())
    return harnesses, covers, unseen


def crates_with_proofs(root):
    """(harnesses per crate, covers per crate, orphans, uncountable lines).

    The whole tree is walked, not `crates/*/src`: the root `cargo kani` reaches only
    workspace members, so a harness under `fuzz/`, `tools/*` (detached workspaces) or
    `firmware/` (thumbv8m-only) is run by nothing and no `-p` can fix it. Scanning
    just the places a proof is *supposed* to live is how the blind spot gets rebuilt.
    """
    harnesses, covers = collections.Counter(), collections.Counter()
    orphans, unseen = [], []
    for rel in gate_lines.tree_files(root):
        if rel.suffix != ".rs":
            continue
        text = (root / rel).read_text()
        if "kani::" not in text:
            continue
        found, reached, odd = counted(text)
        unseen += [f"{rel}: {line}" for line in odd]
        if not found and not reached:
            continue
        if rel.parts[0] != "crates":
            orphans.append(rel)
            continue
        # Guarded, not `+= 0`: a `Counter` inserts the key either way, and the
        # membership of these two is what says which crates are proven and which
        # carry a cover no harness reaches.
        if found:
            harnesses[rel.parts[1]] += found
        if reached:
            covers[rel.parts[1]] += reached
    return harnesses, covers, sorted(orphans), unseen


def ratchets(root, table, harnesses, covers):
    """Problems where a floor, or a number the page prints, is not the tree's count.

    Both directions are wrong and they fail differently. A floor under the tree is
    loose — the harness that goes missing takes it with it, which is how
    `FLOOR_all` came to sit at 64 against 65 — and one over the tree asks for more
    than any run can report, which fails the row after it has done the work.
    """
    kept = {(k, t): int(v) for k, t, v in RATCHET.findall((root / RUNNER).read_text())}
    rows = {
        m[1]: (int(m[2]), int(m[3]), int(m[4]))
        for m in DOC_ROW.finditer((root / DOCS).read_text())
    }
    problems = []
    for tier, crates in sorted(table.items()):
        counts = (sum(harnesses[c] for c in crates), sum(covers[c] for c in crates))
        for kind, want, shape in (
            ("FLOOR", counts[0], "#[kani::proof]"),
            ("COVERS", counts[1], "kani::cover!"),
        ):
            if kept.get((kind, tier)) != want:
                problems.append(
                    f"scripts/kani.sh has {kind}_{tier}={kept.get((kind, tier))}, and the"
                    f" crates on that tier carry {want} {shape}"
                )
        if tier not in rows:
            problems.append(f"{DOCS}'s tier table has no `{tier}` row to check")
        elif rows[tier] != (len(crates), *counts):
            problems.append(
                f"{DOCS} prints {rows[tier]} for `{tier}`; the tree has"
                f" {(len(crates), *counts)} (crates, harnesses, covers)"
            )
    return problems


def audit(root):  # noqa: C901 — one clause per failure mode, each named
    """(problems, one-line summary) for how this checkout points Kani at its tree."""
    root = pathlib.Path(root)
    table = tiers(root)
    found = list(sources(root))
    seen = [u for rel, text, yaml in found for u in uses(rel, text, yaml)]
    loose = sorted({r for rel, text, yaml in found for r in handwritten(rel, text, yaml)})
    harnesses, covers, orphans, unseen = crates_with_proofs(root)
    proven = set(harnesses)
    problems = []

    for line in unseen:
        problems.append(
            f"{line} — neither counter can see that spelling, so every floor it"
            " belongs to would sit one too low; write it `#[kani::proof]` or"
            " `kani::cover!`"
        )
    for crate in sorted(set(covers) - proven):
        problems.append(f"{crate} has a kani::cover! but no #[kani::proof] to reach it")
    for rel in loose:
        problems.append(
            f"{rel} writes its own `cargo kani … -p …` roster; scripts/kani.sh"
            " owns the tiers, and a second copy is one nothing keeps in step"
        )
    for use in seen:
        if use.tier not in table and use.tier != "--tiers":
            problems.append(
                f"{use.path} runs `scripts/kani.sh {use.tier}`, which is not a tier"
            )
    for tier in sorted(table):
        if not [u for u in seen if u.tier == tier and u.executed]:
            problems.append(
                f"no CI row runs the `{tier}` tier: it is in no step's `run:`, or"
                " that line is commented out — a tier nobody runs proves nothing"
            )
        if not [u for u in seen if u.tier == tier and u.path == DOCS]:
            problems.append(
                f"{DOCS} does not carry the `{tier}` tier; it is what a reader"
                " copies, and it says CI runs the same commands"
            )

    if FULL not in table:
        problems.append(f"scripts/kani.sh no longer defines the `{FULL}` tier")
        table[FULL] = frozenset()
    listed = table[FULL]
    for crate in sorted(proven - listed - set(EXCLUDED)):
        problems.append(f"{crate} has a #[kani::proof] that no CI row runs")
    for crate in sorted(listed - proven):
        problems.append(f"{crate} is on the `{FULL}` tier but has no #[kani::proof]")
    for crate in sorted(set(EXCLUDED) - proven):
        problems.append(f"{crate} is excluded but has no #[kani::proof] to exclude")
    for crate in sorted(set(EXCLUDED) & listed):
        problems.append(f"{crate} is both excluded and on the `{FULL}` tier")
    for tier, crates in sorted(table.items()):
        if not crates:
            problems.append(f"the `{tier}` tier is empty; it would prove nothing")
        for crate in sorted(crates - listed):
            problems.append(f"{crate} is on the `{tier}` tier but not on `{FULL}`")
    for rel in orphans:
        problems.append(f"{rel} has a #[kani::proof] or kani::cover! no tier can reach")
    problems += ratchets(root, table, harnesses, covers)

    want = PINNED.search((root / PINNED_IN).read_text())
    got = DOC_PIN.search((root / DOCS).read_text())
    if not want:
        problems.append("KANI_VERSION is not pinned in the workflow")
    elif not got:
        problems.append(f"{DOCS} installs kani-verifier without --version")
    elif got.group(1) != want.group(1):
        problems.append(f"{DOCS} installs kani {got.group(1)}, CI pins {want.group(1)}")

    summary = (
        f"kani-gate: ok — {len(table)} tiers over {len(listed)} crates, "
        f"{sum(harnesses[c] for c in listed)} harnesses and "
        f"{sum(covers[c] for c in listed)} kani::cover! counted from source, "
        f"excluded: {', '.join(EXCLUDED)}"
    )
    return problems, summary


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("kani-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA crate absent from the `all` tier is not proven, and the row that\n"
            "says it proves every harness stays green either way. Add it to\n"
            "scripts/kani.sh and to docs/testing.md, or record it in EXCLUDED with\n"
            "the measured reason."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
