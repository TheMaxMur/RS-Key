#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Co-refutation: inject each model mutant's defect into the Rust, expect red.

The security module's original 28 `Bug*` switches and the later store, admin,
display and transport modules each rebuild a real RS-Key defect, and the TLC
matrix proves the MODEL catches every one.
Nothing measured whether the code level — the unit tests, on the same defect —
catches them too. Three green checkers over three slightly different systems is
the failure mode this whole apparatus exists for, and the difference between
the two answers is a measured abstraction gap with a file and line attached.

The roster is `Mut_*`, `StoreMut_*`, `AdminMut_*`, `DispMut_*`, `TransMut_*` and —
since the applet batch — `SeamMut_*`, `LatMut_*` and `PolicyMut_*`. That batch was
the answer to a measured skew: 31 of the first 43 patches landed in `rsk-fido`,
`rsk-device` and `rsk-fs`, and the four applet crates that four of the nine
modules are written about held ZERO. "TLC is green over the applets" was
therefore fidelity nobody had measured, not fidelity measured and found good.

Three families remain DELIBERATELY out, because an exclusion stated here is a
plan and one implied by a glob is a hole:

* `BootMut_*` — two of its three defended sites live in `firmware/` (the
  marker-after-lap order in main.rs:621-622, the scratch-word carry in
  pin_lock.rs), which has no host tests by construction: `cargo test` cannot
  exercise them, and modelling exactly that gap is M7's stated point. The one
  host-testable site family — the lazy re-keys' `request_rescrub` re-arm —
  carries direct asserts in the migration tests instead
  (`pin_verifier_and_pinwrapped_seed_migrate_at_verify` and PIV's
  `kbase_migration_reseals_slots_and_pin_falls_back` pin EF_HARDENED cleared;
  each proved able to fail by removing its own site's re-arm in a worktree).
* `LiveMut_*` and `FairMut_*` — these are not defect switches. They break a
  LIVENESS property or the fairness shape under it, and the code-level question
  co-refutation asks ("does the same defect fail a host test?") has no meaning
  for a temporal property no unit test states. Named here rather than left to
  the glob, because the glob was how they were out before: `roster()` simply did
  not match them, which is the shape of hole this file exists to refuse.

`formal/comutants.toml` holds one entry per mutant: a `patch` (exact-snippet
find/replace — the defect, re-made in today's code), `unreachable` (the defect
became unreachable by construction after a shipped fix; the model measured it
and the evidence field says where), or `pending` (batch not yet derived,
floored so the count only goes down).

Three modes:

* `--lint` — the cheap closed-world half, a `check.sh` row. Every `Mut_*.cfg`
  has exactly one entry and vice versa; every patch anchor resolves exactly
  once in the current tree (drifted code fails loudly instead of patching the
  wrong place); every patch names a slice and an expected verdict; the pending
  count is at most the recorded floor. It also derives each mutant's target
  invariant from its own `Solo_*.cfg` — this file deliberately does not record
  it, so it cannot disagree with the matrix.
* `run [<Bug>]` — the measurement. A throwaway `git worktree` gets the
  patch, the slice runs there (sharing the main target dir — sequential, and a
  cold per-worktree build would cost more than the tests), the verdict is
  KILLED if any slice command fails, GAP if all stay green. The verdict must
  equal `expect`: a killed that came back green is a regression in exactly the
  sense floors.txt gives that word.
* `run --write-readme` — the same full measurement, followed by publication of
  the roadmap's original 28-row fidelity table. It refuses to publish from a
  partial run; ordinary lint then rejects table drift. The full roster runs in
  the weekly `deep-checks` workflow alongside `cargo-mutants`.

Deliberately NOT in `run`: fuzz targets (sampling is not a deterministic kill)
and full Kani tiers (minutes-per-harness belongs in the weekly row, and the
sequence proofs' own falsifiability is measured by their own table).
"""

import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = ROOT / "formal" / "comutants.toml"
README_START = "<!-- phase2-comutants:start -->"
README_END = "<!-- phase2-comutants:end -->"

STATUSES = {"patch", "unreachable", "pending"}


def load(root: pathlib.Path):
    with open(root / "formal" / "comutants.toml", "rb") as fh:
        data = tomllib.load(fh)
    return (
        data.get("pending_floor", 0),
        data.get("phase2_count", 28),
        data.get("comutant", {}),
    )


#: The mutant-config prefixes this file's closed world covers, and the Solo
#: prefix each pairs with. Boot, liveness and fairness prefixes are deliberately
#: absent — see the module docstring.
PREFIXES = (
    ("Mut_", "Solo_"),
    ("StoreMut_", "StoreSolo_"),
    ("AdminMut_", "AdminSolo_"),
    ("DispMut_", "DispSolo_"),
    ("TransMut_", "TransSolo_"),
    ("SeamMut_", "SeamSolo_"),
    ("LatMut_", "LatSolo_"),
    ("PolicyMut_", "PolicySolo_"),
)


def roster(root: pathlib.Path) -> dict[str, str]:
    """bug name -> its mutant configuration's filename, over every prefix.

    `startswith` is anchored, so `Mut_` does not swallow `StoreMut_*.cfg` or
    `SeamMut_*.cfg` (an 'S' is not an 'M'), and no prefix matches `BootMut_`,
    `LiveMut_` or `FairMut_`.

    The keys are bug names with the prefix stripped, so two families sharing a
    bug name would silently collapse to one entry — see `prefix_collisions`,
    which the lint runs before trusting anything this returns.
    """
    out: dict[str, str] = {}
    for p in sorted((root / "formal").glob("*.cfg")):
        for mut_pre, _ in PREFIXES:
            if p.name.startswith(mut_pre):
                out[p.stem.removeprefix(mut_pre)] = p.name
    return out


def orphan_solos(stems) -> list[str]:
    """`Bug*` Solo configurations with no mutant of their own family.

    The other half of the same closed world. `solo_invariant` resolves a bug by
    walking the families and keeping the LAST Solo file that exists, so a stray
    `<Family>Solo_<Bug>.cfg` — a leftover rename, or a Solo written ahead of its
    mutant — silently STEALS the invariant another family's mutant is judged by,
    and `roster` never sees it because the stem matches no `Mut_` prefix. Only
    `Bug*` stems are paired: `Solo_<Invariant>.cfg` and `SoloClause_*.cfg` are
    solo runs of an invariant or a clause, which have no mutant by design.
    """
    have = set(stems)
    out: list[str] = []
    for stem in sorted(have):
        for mut_pre, solo_pre in PREFIXES:
            if stem.startswith(solo_pre):
                bug = stem.removeprefix(solo_pre)
                if bug.startswith("Bug") and f"{mut_pre}{bug}" not in have:
                    out.append(
                        f"{stem}.cfg has no {mut_pre}{bug}.cfg — a Solo without "
                        "its own mutant steals the invariant that mutant is "
                        "judged by"
                    )
    return out


def prefix_collisions(stems) -> list[str]:
    """Problem lines for configuration stems two prefixes map onto ONE key.

    Eight families share one name space, and `roster` keys on the name with its
    prefix stripped: a second `BugX` under another prefix does not collide
    loudly, it OVERWRITES. Both closed-world directions then stay green over a
    roster holding one fewer mutant — the exact silent-shrink shape floors.txt
    exists for, one layer up. The families are disjoint today; this is what
    keeps them so when a tenth module reuses a good name.
    """
    seen: dict[str, str] = {}
    out: list[str] = []
    for stem in sorted(stems):
        for mut_pre, _ in PREFIXES:
            if stem.startswith(mut_pre):
                bug = stem.removeprefix(mut_pre)
                if bug in seen:
                    out.append(
                        f"{stem}.cfg and {seen[bug]}.cfg are one roster key "
                        f"({bug}) — rename one"
                    )
                seen[bug] = stem
    return out


def phase2_entries(root: pathlib.Path, entries: dict) -> list[tuple[str, dict]]:
    """The original 28 FIDO mutants, excluding later module extensions."""
    cfgs = roster(root)
    return sorted(
        (bug, entry)
        for bug, entry in entries.items()
        if cfgs.get(bug, "").startswith("Mut_")
    )


def solo_invariant(root: pathlib.Path, bug: str) -> str | None:
    solo = None
    for _, solo_pre in PREFIXES:
        candidate = root / "formal" / f"{solo_pre}{bug}.cfg"
        if candidate.is_file():
            solo = candidate
    if solo is None:
        return None
    names = [
        line.strip()
        for line in solo.read_text().splitlines()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.strip())
        and line.strip() not in ("TypeOK", "INVARIANTS", "SPECIFICATION", "CONSTANTS")
    ]
    return names[-1] if names else None


def patch_pairs(entry: dict):
    yield entry["find"], entry.get("replace", "")
    for n in ("2", "3"):
        if f"find{n}" in entry:
            yield entry[f"find{n}"], entry.get(f"replace{n}", "")


def code_status(entry: dict, measured: str | None = None) -> str:
    if entry.get("status") == "patch":
        verdict = measured or entry.get("expect", "?")
        return "co-refuted" if verdict == "killed" else verdict
    return entry.get("status", "?")


def phase2_block(
    root: pathlib.Path, entries: dict, measured: dict[str, str] | None = None
) -> str:
    rows = phase2_entries(root, entries)
    counts: dict[str, int] = {}
    lines = [
        README_START,
        "<!-- Generated by scripts/comutate.py run --write-readme; do not edit. -->",
        "| # | Mutant | Target invariant | Model | Code level |",
        "|---:|---|---|---|---|",
    ]
    for number, (bug, entry) in enumerate(rows, 1):
        status = code_status(entry, (measured or {}).get(bug))
        counts[status] = counts.get(status, 0) + 1
        lines.append(
            f"| {number} | `{bug}` | `{solo_invariant(root, bug) or '?'}` | "
            f"RED | **{status}** |"
        )
    total = len(rows)
    lines.extend(
        (
            "",
            "**Measured phase-2 fidelity:** "
            f"{counts.get('co-refuted', 0)}/{total} code-level kills; "
            f"{counts.get('unreachable', 0)} unreachable by construction; "
            f"{counts.get('gap', 0)} open gaps; {counts.get('pending', 0)} pending.",
            README_END,
        )
    )
    return "\n".join(lines)


def replace_readme_block(text: str, block: str) -> str:
    if text.count(README_START) != 1 or text.count(README_END) != 1:
        raise ValueError("formal/README.md needs exactly one phase-2 table marker pair")
    start = text.index(README_START)
    end = text.index(README_END, start) + len(README_END)
    return text[:start] + block + text[end:]


def check_readme(root: pathlib.Path, entries: dict, problems: list[str]) -> None:
    path = root / "formal" / "README.md"
    if not path.is_file():
        problems.append("formal/README.md is missing — no phase-2 fidelity table")
        return
    text = path.read_text()
    try:
        want = replace_readme_block(text, phase2_block(root, entries))
    except ValueError as error:
        problems.append(str(error))
        return
    if text != want:
        problems.append(
            "formal/README.md phase-2 fidelity table is stale — run "
            "python scripts/comutate.py run --write-readme"
        )


def lint(root: pathlib.Path, check_generated_readme: bool = True) -> list[str]:
    problems: list[str] = []
    floor, phase2_count, entries = load(root)
    # Before the closed world, the name space it is closed over: a collision
    # makes both directions below agree about a roster that is one short, and an
    # unpaired Solo hands a mutant an invariant that is not its own.
    stems = [p.stem for p in (root / "formal").glob("*.cfg")]
    problems.extend(prefix_collisions(stems))
    problems.extend(orphan_solos(stems))
    cfgs = roster(root)

    for bug in sorted(set(cfgs) - set(entries)):
        problems.append(f"{cfgs[bug]} has no comutant entry")
    for bug in sorted(set(entries) - set(cfgs)):
        problems.append(f"comutant {bug} has no mutant configuration — stale entry")

    pending = 0
    for bug, entry in sorted(entries.items()):
        status = entry.get("status")
        where = f"comutants.toml [{bug}]"
        if status not in STATUSES:
            problems.append(f"{where}: unknown status {status!r}")
            continue
        if status == "pending":
            pending += 1
            continue
        if status == "unreachable":
            if not entry.get("evidence", "").strip():
                problems.append(f"{where}: unreachable without evidence")
            continue
        # status == "patch"
        if not entry.get("slice"):
            problems.append(f"{where}: patch without a slice")
        if entry.get("expect") not in ("killed", "gap"):
            problems.append(f"{where}: expect must be 'killed' or 'gap'")
        target = root / entry.get("file", "")
        if not target.is_file():
            problems.append(f"{where}: no such file {entry.get('file')}")
            continue
        text = target.read_text()
        for i, (find, _) in enumerate(patch_pairs(entry), 1):
            n = text.count(find)
            if n != 1:
                problems.append(
                    f"{where}: anchor {i} resolves {n} times in {entry['file']} — "
                    "the code it names has moved; re-derive the patch"
                )
    if pending > floor:
        problems.append(
            f"{pending} pending comutants over the recorded floor of {floor} — "
            "lower the floor only by deriving patches, never raise it"
        )
    phase2 = phase2_entries(root, entries)
    if len(phase2) != phase2_count:
        problems.append(
            f"phase-2 roster has {len(phase2)} mutants, expected the roadmap's "
            f"fixed {phase2_count}"
        )
    if check_generated_readme:
        check_readme(root, entries, problems)
    return problems


def host_triple() -> str:
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    return re.search(r"^host: (\S+)$", out.stdout, re.M).group(1)


def run_one(root: pathlib.Path, bug: str, entry: dict, host: str) -> tuple[str, str]:
    """(verdict, detail) for one comutant, measured in a throwaway worktree."""
    wt = pathlib.Path("/tmp") / f"rsk-comutant-{bug}"
    if wt.exists():
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(wt)], cwd=root, check=False
        )
        shutil.rmtree(wt, ignore_errors=True)
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(wt), "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    try:
        # The worktree is HEAD, but the point of `run` in the dev loop is to
        # measure the tree in hand — a gap just closed by an uncommitted test
        # must read as killed now, not after a commit. Carry the tracked diff
        # over. (A comutant patch that collides with a staged edit to the same
        # lines is the author's to notice; the anchor check below still fires.)
        diff = subprocess.run(
            ["git", "diff", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        ).stdout
        if diff.strip():
            subprocess.run(
                ["git", "apply", "--whitespace=nowarn"],
                cwd=wt,
                input=diff,
                text=True,
                check=True,
            )
        target = wt / entry["file"]
        text = target.read_text()
        for find, replace in patch_pairs(entry):
            if text.count(find) != 1:
                return "anchor-gone", f"anchor resolves {text.count(find)}×"
            text = text.replace(find, replace)
        target.write_text(text)
        cmd = list(entry["slice"]) + ["--target", host]
        r = subprocess.run(
            cmd,
            cwd=wt,
            capture_output=True,
            text=True,
            env={
                **__import__("os").environ,
                # Sequential runs share the main build cache: only the patched
                # crate recompiles, instead of a cold dependency tree per mutant.
                "CARGO_TARGET_DIR": str(root / "target"),
            },
        )
        if r.returncode != 0:
            out = r.stdout + r.stderr
            # A compile error is not a kill: the tests never ran, so a broken
            # patch would masquerade as "the tests caught the defect". A real
            # test failure prints "test result:" / "FAILED"; a build break
            # prints "error[E" / "error:" and no test line. Tell them apart, or
            # a patch that does not compile scores a false killed — which is how
            # BugPpuatIsAGate first read (EF_PAUTHTOKEN is a KeyFid, not a u16).
            ran = [l for l in out.splitlines() if "FAILED" in l or "test result" in l]
            if ran:
                return "killed", ran[-1]
            if re.search(r"^error(\[E\d+\])?:", out, re.M):
                return "build-broke", "patch does not compile — not a kill"
            return "killed", "slice exited nonzero (no test output)"
        return "gap", "every slice command stayed green"
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(wt)], cwd=root, check=False
        )


def write_readme(root: pathlib.Path, entries: dict, measured: dict[str, str]) -> int:
    missing = [
        bug
        for bug, entry in phase2_entries(root, entries)
        if entry.get("status") == "patch" and bug not in measured
    ]
    if missing:
        print(
            "comutate: refusing an unmeasured phase-2 table: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    path = root / "formal" / "README.md"
    try:
        text = replace_readme_block(
            path.read_text(), phase2_block(root, entries, measured)
        )
    except (FileNotFoundError, ValueError) as error:
        print(f"comutate: {error}", file=sys.stderr)
        return 1
    path.write_text(text)
    print("comutate: wrote measured phase-2 table to formal/README.md")
    return 0


def run(root: pathlib.Path, only: str | None, write_table: bool = False) -> int:
    problems = lint(root, check_generated_readme=not write_table)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("comutate: lint failed — not running anything", file=sys.stderr)
        return 1
    _, _, entries = load(root)
    host = host_triple()
    failures = 0
    measured: dict[str, str] = {}
    for bug, entry in sorted(entries.items()):
        if only and bug != only:
            continue
        status = entry.get("status")
        inv = solo_invariant(root, bug) or "?"
        if status != "patch":
            if not only:
                print(f"  {bug:<34} {status:<12} {inv}")
            continue
        verdict, detail = run_one(root, bug, entry, host)
        measured[bug] = verdict
        mark = ""
        if verdict != entry["expect"]:
            mark = f"  !! expected {entry['expect']}"
            failures += 1
        print(f"  {bug:<34} {verdict:<12} {inv}  ({detail}){mark}")
    if only and not any(b == only for b in entries):
        print(f"comutate: no such comutant {only}", file=sys.stderr)
        return 2
    if failures:
        print(
            f"comutate: FAIL — {failures} verdict(s) differ from the record",
            file=sys.stderr,
        )
        return 1
    if only is None:
        statuses = [
            code_status(entry, measured.get(bug))
            for bug, entry in phase2_entries(root, entries)
        ]
        print(
            "comutate: phase 2 — "
            f"{statuses.count('co-refuted')}/{len(statuses)} code-level kills, "
            f"{statuses.count('unreachable')} unreachable, "
            f"{statuses.count('gap')} gaps, {statuses.count('pending')} pending"
        )
        if write_table:
            return write_readme(root, entries, measured)
    return 0


def audit(root):
    """(problems, one-line summary) — the --lint half, for the meta-gate."""
    problems = lint(pathlib.Path(root))
    floor, _, entries = load(pathlib.Path(root))
    counts: dict[str, int] = {}
    for e in entries.values():
        counts[e.get("status", "?")] = counts.get(e.get("status", "?"), 0) + 1
    summary = "comutate: ok — " + ", ".join(
        f"{v} {k}" for k, v in sorted(counts.items())
    ) + f"; pending floor {floor}"
    return problems, summary


def main():
    args = sys.argv[1:]
    if args == ["--lint"]:
        problems, summary = audit(ROOT)
        if problems:
            print("comutate:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        print(summary)
        return 0
    if args and args[0] == "run":
        tail = args[1:]
        write_table = "--write-readme" in tail
        names = [arg for arg in tail if arg != "--write-readme"]
        if len(names) > 1 or (write_table and names):
            print(
                "usage: comutate.py --lint | run [<Bug>] | run --write-readme",
                file=sys.stderr,
            )
            return 2
        return run(ROOT, names[0] if names else None, write_table)
    print(
        "usage: comutate.py --lint | run [<Bug>] | run --write-readme",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
