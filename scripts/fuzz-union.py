#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Union the per-target fuzz LCOV reports into one repository-source number.

`scripts/fuzz-coverage.sh` writes `fuzz/coverage/<target>/coverage.lcov` per
target, each restricted to what that target's corpus reached. Neither the
per-target rows nor their average is the repository's fuzz coverage: a line any
one target reached is covered, and one no target reached is not. This unions
them the way `docs/testing.md` quotes the number.

The scope is deliberate. A `(file, line)` coordinate counts once and is covered
when ANY target's `DA:` record counts it above zero. Only sources under the
repository's `crates/`, `firmware/`, `third_party/` and `tools/` trees are in
scope. Excluded: the fuzz harnesses under `fuzz/`, dependency checkouts
(`.cargo/registry`, `.cargo/git`) and the rustc/library/rustlib sources — the
same omissions `fuzz-coverage.sh`'s `-ignore-filename-regex` makes, plus the
repository-root restriction that also drops a git dependency's checkout.
Vendored `third_party/` sources ARE counted, so this denominator is larger than
the host-unit scope's.

It gates nothing; `docs/testing.md` says why a fuzz reporter must not look like
a gate. It exits non-zero only when it has nothing it can read: no
`coverage.lcov` under the coverage directory, one it cannot read, or no
repository-source record at all.

    nix develop .#fuzz -c python scripts/fuzz-union.py
    python scripts/fuzz-union.py --coverage fuzz/coverage --root .
"""

import argparse
import pathlib
import sys

#: The repository trees this union reports. Everything else an LCOV may name — a
#: harness, a crates.io or git checkout, the std sources — is out of scope.
ROOTS = ("crates", "firmware", "third_party", "tools")

#: Where a checkout keeps the per-target reports and this run's own metadata.
COVERAGE = pathlib.Path("fuzz/coverage")

#: The checkout holding `fuzz/coverage/` when neither flag is given.
DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def repo_rel(path, root):
    """`path` relative to `root` when it is a repository source, else None.

    String prefixing rather than `Path.resolve`: the SF paths are absolute and
    name the checkout the instrumented build ran in, which need not be the one
    running this, so resolving them here is neither possible nor wanted.
    """
    prefix = str(root).rstrip("/") + "/"
    if not path.startswith(prefix):
        return None
    rel = path[len(prefix):]
    return rel if rel.split("/", 1)[0] in ROOTS else None


def parse_lcov(text):
    """Yield (source path, line, count) for every `DA:` record in `text`.

    A `DA:` line with fewer than two fields, or fields that are not integers, is
    skipped rather than fatal: the report is machine-written, and a malformed
    line is one coordinate's worth of noise, not a reason to drop the
    measurement. An optional third field (LLVM's checksum) is ignored.
    """
    source = None
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            source = raw[3:].strip()
        elif raw.startswith("DA:") and source is not None:
            fields = raw[3:].split(",")
            if len(fields) < 2:
                continue
            try:
                line, count = int(fields[0]), int(fields[1])
            except ValueError:
                continue
            yield source, line, count


def union(coverage, root):
    """{(repository-relative path, line): covered} over `coverage`'s reports.

    Keyed by coordinate so a `DA:` repeated inside one report and the same
    coordinate's repeat across targets both collapse to one entry; `covered` is
    True when any occurrence counted the line above zero. Unreadable reports
    raise `OSError` to the caller.
    """
    hits = {}
    for report in sorted(pathlib.Path(coverage).glob("*/coverage.lcov")):
        for source, line, count in parse_lcov(report.read_text(errors="replace")):
            rel = repo_rel(source, root)
            if rel is not None:
                key = (rel, line)
                hits[key] = hits.get(key, False) or count > 0
    return hits


def summarize(hits):
    """(covered, total, {root: (covered, total)}) for a union of `hits`."""
    covered, per = 0, {}
    for (rel, _line), hit in hits.items():
        seen, total = per.get(rel.split("/", 1)[0], (0, 0))
        per[rel.split("/", 1)[0]] = (seen + hit, total + 1)
        covered += hit
    return covered, len(hits), per


def metadata(coverage):
    """(config, source-commit) found beside the reports, each `None` if absent."""
    found = []
    for name in ("config.txt", "source-commit.txt"):
        try:
            text = (pathlib.Path(coverage) / name).read_text().strip()
        except OSError:
            found.append(None)
        else:
            found.append(text or None)
    return tuple(found)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--coverage", default=None,
        help=f"directory of <target>/coverage.lcov reports (default: {COVERAGE})",
    )
    parser.add_argument(
        "--root", default=None,
        help="repository root the SF paths are relative to (default: this checkout)",
    )
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root).resolve() if args.root else DEFAULT_ROOT
    coverage = pathlib.Path(args.coverage) if args.coverage else root / COVERAGE

    reports = sorted(coverage.glob("*/coverage.lcov"))
    if not reports:
        print(f"no coverage.lcov under {coverage} — nothing to union", file=sys.stderr)
        return 1
    try:
        hits = union(coverage, root)
    except OSError as err:
        print(f"cannot read {err.filename}: {err.strerror}", file=sys.stderr)
        return 1

    covered, total, per = summarize(hits)
    if not total:
        print(
            f"{coverage}: no repository-source record in {len(reports)} report(s)",
            file=sys.stderr,
        )
        return 1

    config, commit = metadata(coverage)
    print(f"{len(reports)} report(s) under {coverage}")
    if config:
        print(f"config: {config}")
    if commit:
        print(f"source commit: {commit}")
    print()
    print(f"{covered}/{total} = {100 * covered / total:.2f}%")
    for name in sorted(per):
        seen, lines = per[name]
        print(f"  {name}: {seen}/{lines} = {100 * seen / lines:.2f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
