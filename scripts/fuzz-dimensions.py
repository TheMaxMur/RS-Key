#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""What a corpus actually explored, in log buckets. A diagnostic, not a check.

Ported from Wasefire's `crates/store/fuzz/src/{stats,histogram}.rs`, which bucket
the axes that make a store hard — how much of the storage was invalid before
init, how many pages were erased, how many times the power went — and are
explicitly *not* run during fuzzing, only when replaying a corpus.

Nothing in RS-Key gates on fuzz coverage. `scripts/fuzz-coverage.sh` has no
coverage floor at all; its only failures are the `.#fuzz` shell check and a
target-count floor. So this exits 0 on anything it can read, prints a table, and
gates nothing. A reporter that looks like a gate is worse than no reporter,
because someone eventually believes it.

Usage, from inside the fuzz shell (the target must be built):

    nix develop .#fuzz -c ./scripts/fuzz-dimensions.py fuzz/corpus/power_cut

The corpus is 45 814 files and stays out of git (`.gitignore:3`), so this depends
on nothing being present: no corpus, no rows, and it says so.

Buckets are powers of two, identified by their lower bound — 0, 1, 2-3, 4-7,
8-15 — which is Wasefire's shape and the right one here: every axis below is a
count whose interesting range spans orders of magnitude, and a linear histogram
of `bytes_written` would be one column.
"""

import collections
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: What the target prints per exec under `RSK_POWER_CUT_STATS`. Parsed rather
#: than agreed by convention: an axis the target stops printing simply stops
#: having a row, and an axis it adds appears without this file changing.
LINE = re.compile(r"^power-cut-stats((?: \w+=\d+)+)$", re.M)

#: The order rows are shown in, so the input dimensions come before what they
#: caused. An axis not named here is still shown, after these.
ORDER = ("dirty", "ops", "fids", "boots", "live", "erases", "writes", "bytes_written")


def bucket(value):
    """The power of two at or below `value`; 0 keeps its own bucket."""
    return 0 if value == 0 else 1 << (value.bit_length() - 1)


def measure(target, corpus):
    """Replay `corpus` through `target` and collect one dict per exec."""
    binary = next(
        (p for p in (ROOT / "fuzz/target").rglob(target) if p.is_file() and p.stat().st_mode & 0o111),
        None,
    )
    if binary is None:
        raise SystemExit(f"no built `{target}` under fuzz/target — cargo fuzz build {target}")
    done = subprocess.run(
        [str(binary), "-runs=0", "-shuffle=0", str(corpus)],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "RSK_POWER_CUT_STATS": "1"},
        check=False,
    )
    if done.returncode:
        print(f"note: {target} exited {done.returncode}; reporting what it printed", file=sys.stderr)
    return [
        {k: int(v) for k, v in (f.split("=") for f in found.group(1).split())}
        for found in LINE.finditer(done.stderr)
    ]


def histograms(runs):
    """axis -> {bucket: count}, over every exec that reported it."""
    out = collections.defaultdict(collections.Counter)
    for run in runs:
        for axis, value in run.items():
            out[axis][bucket(value)] += 1
    return out


def render(runs):
    """The table, columns sized to their contents."""
    found = histograms(runs)
    axes = [a for a in ORDER if a in found] + sorted(set(found) - set(ORDER))
    edges = sorted({b for counts in found.values() for b in counts})
    header = ["axis", *(str(b) for b in edges), "execs"]
    rows = [header]
    for axis in axes:
        counts = found[axis]
        rows.append(
            [axis, *(str(counts.get(b, "")) if counts.get(b) else "" for b in edges),
             str(sum(counts.values()))]
        )
    width = [max(len(r[i]) for r in rows) for i in range(len(header))]
    for row in rows:
        print("  ".join(cell.rjust(width[i]) for i, cell in enumerate(row)))


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <corpus-dir>   (for the power_cut target)")
    corpus = pathlib.Path(sys.argv[1])
    if not corpus.is_dir() or not any(corpus.iterdir()):
        print(f"{corpus}: no corpus to replay — nothing to report", file=sys.stderr)
        return 0
    runs = measure("power_cut", corpus)
    if not runs:
        print("the target printed no `power-cut-stats` line: it is an older build,", file=sys.stderr)
        print("or RSK_POWER_CUT_STATS is no longer the switch it reads", file=sys.stderr)
        return 0
    print(f"{len(runs)} execs over {sum(1 for _ in corpus.iterdir())} corpus inputs\n")
    render(runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
