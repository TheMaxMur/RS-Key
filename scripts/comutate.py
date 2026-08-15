#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Co-refutation: inject each model mutant's defect into the Rust, expect red.

The security module's 28 `Bug*` switches and the store module's 5 each rebuild
a real RS-Key defect, and the TLC matrix proves the MODEL catches every one.
Nothing measured whether the code level — the unit tests, on the same defect —
catches them too. Three green checkers over three slightly different systems is
the failure mode this whole apparatus exists for, and the difference between
the two answers is a measured abstraction gap with a file and line attached.

The roster is `Mut_*` plus `StoreMut_*`, and `SeamMut_*` is DELIBERATELY not in
it: the seam mutants rebuild applet-status defects whose shipped fixes carry
their own regression tests measured against a YubiKey oracle (group E), and
their co-refutation belongs to M4, when the applet retry/authorization lattice
is modelled. An exclusion stated here is a plan; one implied by a glob would be
a hole.

`formal/comutants.toml` holds one entry per mutant: a `patch` (exact-snippet
find/replace — the defect, re-made in today's code), `unreachable` (the defect
became unreachable by construction after a shipped fix; the model measured it
and the evidence field says where), or `pending` (batch not yet derived,
floored so the count only goes down).

Two verbs:

* `--lint` — the cheap closed-world half, a `check.sh` row. Every `Mut_*.cfg`
  has exactly one entry and vice versa; every patch anchor resolves exactly
  once in the current tree (drifted code fails loudly instead of patching the
  wrong place); every patch names a slice and an expected verdict; the pending
  count is at most the recorded floor. It also derives each mutant's target
  invariant from its own `Solo_*.cfg` — this file deliberately does not record
  it, so it cannot disagree with the matrix.
* `run <Bug>|--all` — the measurement. A throwaway `git worktree` gets the
  patch, the slice runs there (sharing the main target dir — sequential, and a
  cold per-worktree build would cost more than the tests), the verdict is
  KILLED if any slice command fails, GAP if all stay green. The verdict must
  equal `expect`: a killed that came back green is a regression in exactly the
  sense floors.txt gives that word.

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

STATUSES = {"patch", "unreachable", "pending"}


def load(root: pathlib.Path):
    with open(root / "formal" / "comutants.toml", "rb") as fh:
        data = tomllib.load(fh)
    return data.get("pending_floor", 0), data.get("comutant", {})


#: The mutant-config prefixes this file's closed world covers, and the Solo
#: prefix each pairs with. `SeamMut_`/`SeamSolo_` are deliberately absent — see
#: the module docstring.
PREFIXES = (("Mut_", "Solo_"), ("StoreMut_", "StoreSolo_"))


def roster(root: pathlib.Path) -> dict[str, str]:
    """bug name -> its mutant configuration's filename, over both prefixes.

    `startswith` is anchored, so `Mut_` does not swallow `StoreMut_*.cfg` (an 'S'
    is not an 'M') and neither prefix matches `SeamMut_`, `LiveMut_` or
    `FairMut_`.
    """
    out: dict[str, str] = {}
    for p in sorted((root / "formal").glob("*.cfg")):
        for mut_pre, _ in PREFIXES:
            if p.name.startswith(mut_pre):
                out[p.stem.removeprefix(mut_pre)] = p.name
    return out


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


def lint(root: pathlib.Path) -> list[str]:
    problems: list[str] = []
    floor, entries = load(root)
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


def run(root: pathlib.Path, only: str | None) -> int:
    problems = lint(root)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("comutate: lint failed — not running anything", file=sys.stderr)
        return 1
    _, entries = load(root)
    host = host_triple()
    failures = 0
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
    return 0


def audit(root):
    """(problems, one-line summary) — the --lint half, for the meta-gate."""
    problems = lint(pathlib.Path(root))
    floor, entries = load(pathlib.Path(root))
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
        return run(ROOT, args[1] if len(args) > 1 else None)
    print("usage: comutate.py --lint | run [<Bug>]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
