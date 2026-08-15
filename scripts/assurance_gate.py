#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the security-property registry against the tree, both ways.

`assurance/properties.toml` names the security properties; `assurance/crates.toml`
classifies every workspace member. Everything else this gate reports — which
module defines a property, which configurations check it, which mutants target
it, which Kani harnesses, fuzz targets, Rust files and device tests carry its
name — is DERIVED here and printed, never stored. The registry's own worked
example is why: a hand-written evidence record for the tree's best-documented
property was wrong in three of six fields before any code existed (three
mutants listed of seven, two owner files of three, and two runtime tests that
do not exist). Deriving is not a nicety; it is the difference between a
registry and a fourth hand-kept roster, and this tree has already deleted one
guard that grew 800 lines defending three copies of a list.

What is checked, and the direction of each check:

* every invariant or temporal property that any formal/*.cfg actually checks
  has exactly one registry entry — so nothing TLC verifies is unnamed; and
  every non-risk entry names something a configuration actually checks — so
  the registry cannot advertise properties nothing verifies. This one check
  also covers mutant orphans: a Solo_*.cfg aimed at an unregistered invariant
  is an unregistered checked name.
* a status must equal the evidence ceiling. A Kani harness carrying the
  property's name forces BOUNDED; none allows only MODELLED-ONLY. PROVEN and
  OBSERVED are refused outright until evidence of those classes exists in the
  tree — a status rule nothing can trip is a check that cannot fail.
* ACCEPTED-RISK entries carry a ruling and are exactly the entries with no
  model: a ruled-away risk must be visible, and a checked invariant must not
  be filed as one.
* every formal/*.cfg is in a tier of `run-tlc.sh --tiers` or in [`EXEMPT_CFG`]
  with its reason — the "20 of 49 proofs run by nothing" class, one layer up.
* every [workspace] member appears in the crate ledger and vice versa, and
  each class carries what it obliges: a model that exists, a named gap, a
  planned roadmap module, evidence files that exist, or a reason. The ledger
  exists because two roadmap drafts enumerated crates from memory and missed
  four, including the second-largest in the tree.

Deliberately syntactic, like its siblings: it cannot say a statement means
what the invariant checks, or that an evidence file proves anything. It says
the graph is closed — nothing checked is unnamed, nothing named is unchecked,
nothing ships silently unclassified.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Configurations no tier runs, each with the reason a reader needs. Anything
#: else outside every tier is a matrix row nobody pulls, and fails the gate.
EXEMPT_CFG = {
    "Liveness_Full.cfg": "1475 s for the verdict the reduced constants give in 139 s; "
    "run by hand when the reduction is questioned (run-tlc.sh)",
}

#: The one status per evidence class that exists in the tree today. PROVEN
#: (unbounded deductive proof) and OBSERVED (runtime-only evidence) are named
#: here so the refusal message can say what to do the day they become real:
#: add the evidence class to the derivation, then admit the status.
STATUSES = {"BOUNDED", "MODELLED-ONLY", "ACCEPTED-RISK"}

#: A property tag in production Rust: `Refines \`Module!Invariant\` — SEC-X-NNN.`
#: Both halves are validated — the module against formal/, the name and the id
#: against the registry, and the pairing against itself, so a copy-pasted tag
#: whose id names one property and whose invariant names another is a finding
#: rather than two half-truths.
TAG = re.compile(r"Refines\s+`([A-Za-z0-9]+)!([A-Za-z0-9]+)`\s+—\s+(SEC-[A-Z]+-[0-9A-Z]+)")
SEC_ID = re.compile(r"\bSEC-[A-Z]+-[0-9A-Z]+\b")

CFG_KEYWORDS = re.compile(
    r"^(SPECIFICATION|CONSTANTS?|INVARIANTS?|PROPERT(?:Y|IES)|CONSTRAINTS?|"
    r"INIT|NEXT|SYMMETRY|VIEW|CHECK_DEADLOCK|ALIAS)\b"
)
BARE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TLA_DEF = re.compile(r"^([A-Z][A-Za-z0-9_]*)\s*==", re.M)
FN_DEF = re.compile(r"^\s*(?:pub\s+)?fn\s+([a-z0-9_]+)", re.M)


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def cfg_checked(path: pathlib.Path) -> list[str]:
    """The invariant/property names a configuration asks TLC to check."""
    names, section = [], None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        kw = CFG_KEYWORDS.match(line)
        if kw:
            word = kw.group(1)
            section = "check" if word.startswith(("INVARIANT", "PROPERT")) else None
            continue
        if section == "check" and BARE_NAME.match(line) and line != "TypeOK":
            names.append(line)
    return names


def checked_names(formal: pathlib.Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cfg in sorted(formal.glob("*.cfg")):
        for name in cfg_checked(cfg):
            out.setdefault(name, []).append(cfg.name)
    return out


def tla_definitions(formal: pathlib.Path) -> dict[str, str]:
    defs: dict[str, str] = {}
    for tla in sorted(formal.glob("*.tla")):
        for name in TLA_DEF.findall(tla.read_text()):
            defs.setdefault(name, tla.stem)
    return defs


def solo_target_counts(formal: pathlib.Path) -> dict[str, int]:
    """How many single-target mutant configurations aim at each name."""
    counts: dict[str, int] = {}
    for cfg in formal.glob("*.cfg"):
        if not cfg.name.startswith(
            (
                "Solo_",
                "SeamSolo_",
                "StoreSolo_",
                "LatSolo_",
                "AdminSolo_",
                "SoloClause_",
                "LiveMut_",
                "FairMut_",
            )
        ):
            continue
        names = cfg_checked(cfg)
        if len(names) == 1:
            counts[names[0]] = counts.get(names[0], 0) + 1
    return counts


def grep_word(files: list[pathlib.Path], word: str) -> list[str]:
    pat = re.compile(r"\b" + re.escape(word) + r"\b")
    return [f.name for f in files if pat.search(f.read_text(errors="ignore"))]


def derive(root: pathlib.Path, name: str, solo: dict[str, int]) -> dict:
    crates = root / "crates"
    kani_files = sorted(crates.glob("*/src/*kani*.rs"))
    rust_files = [
        f
        for f in sorted(crates.glob("*/src/**/*.rs"))
        if "kani" not in f.name and "tests" not in f.name
    ]
    fuzz_files = sorted((root / "fuzz" / "fuzz_targets").glob("*.rs"))
    test_files = sorted((root / "tests").glob("**/*.py"))
    sn = snake(name)
    harnesses = [
        fn
        for f in kani_files
        for fn in FN_DEF.findall(f.read_text(errors="ignore"))
        if sn in fn
    ]
    return {
        "mutants": solo.get(name, 0),
        "kani": harnesses,
        "fuzz": grep_word(fuzz_files, name),
        "rust": grep_word(rust_files, name),
        "tests": grep_word(test_files, name) + grep_word(test_files, sn),
    }


def tier_union(formal: pathlib.Path) -> set[str]:
    out = subprocess.run(
        [str(formal / "run-tlc.sh"), "--tiers"],
        cwd=formal,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    names: set[str] = set()
    for line in out.splitlines():
        _, _, rest = line.partition(":")
        names.update(rest.split())
    return names


def workspace_members(root: pathlib.Path) -> set[str]:
    with open(root / "Cargo.toml", "rb") as fh:
        manifest = tomllib.load(fh)
    return {m.rsplit("/", 1)[-1] for m in manifest["workspace"]["members"]}


def check_properties(root: pathlib.Path, findings: list[str]) -> list[dict]:
    formal = root / "formal"
    with open(root / "assurance" / "properties.toml", "rb") as fh:
        entries = tomllib.load(fh).get("property", [])
    checked = checked_names(formal)
    defs = tla_definitions(formal)
    solo = solo_target_counts(formal)

    ids = [e.get("id", "?") for e in entries]
    names = [e.get("name", "?") for e in entries]
    for kind, seq in (("id", ids), ("name", names)):
        for dup in sorted({x for x in seq if seq.count(x) > 1}):
            findings.append(f"duplicate {kind} in properties.toml: {dup}")

    by_name = {e["name"]: e for e in entries}
    risk = {n for n, e in by_name.items() if e.get("status") == "ACCEPTED-RISK"}

    for name in sorted(set(checked) - set(by_name)):
        findings.append(
            f"checked by {len(checked[name])} cfg(s) but not in the registry: {name}"
        )
    for name in sorted(set(by_name) - set(checked) - risk):
        findings.append(f"registered but checked by no configuration: {name}")

    rows = []
    for e in entries:
        name, status = e.get("name", "?"), e.get("status", "?")
        where = f"{e.get('id', '?')} ({name})"
        if status not in STATUSES:
            findings.append(
                f"{where}: status {status!r} — PROVEN/OBSERVED are refused until "
                "the tree grows that evidence class; add it to the derivation first"
            )
        if not e.get("statement", "").strip():
            findings.append(f"{where}: empty statement")
        if not e.get("source"):
            findings.append(f"{where}: empty source")
        if clause := e.get("clause_of"):
            if clause not in ids:
                findings.append(f"{where}: clause_of {clause!r} names no entry")
        if status == "ACCEPTED-RISK":
            if not e.get("ruling", "").strip():
                findings.append(f"{where}: ACCEPTED-RISK without a ruling")
            if name in checked:
                findings.append(
                    f"{where}: filed as a risk but checked by "
                    f"{checked[name][0]} — a checked invariant is not a ruling"
                )
            rows.append({"e": e, "d": None})
            continue
        if name not in defs:
            findings.append(f"{where}: no definition in any formal/*.tla module")
        d = derive(root, name, solo)
        if d["kani"] and status != "BOUNDED":
            findings.append(
                f"{where}: {len(d['kani'])} Kani harness(es) carry this name — "
                f"status must be BOUNDED, not {status}"
            )
        if not d["kani"] and status == "BOUNDED":
            findings.append(
                f"{where}: BOUNDED with no Kani harness carrying the name"
            )
        rows.append({"e": e, "d": d, "cfgs": len(checked.get(name, []))})
    return rows


def check_tags(root: pathlib.Path, findings: list[str], entries: list[dict]) -> None:
    """Every property tag in production Rust names real registry rows.

    And the other direction, scoped to where owners exist: every invariant the
    tree-as-it-stands configuration (Shipped.cfg) checks must be named in
    production Rust at least once. That set is derived from the cfg, not kept
    by hand — it is exactly the invariants whose Rust owners formal/README.md
    documents, and the column that measured 0-for-all until these tags landed.
    """
    by_id = {e.get("id"): e.get("name") for e in entries}
    modules = {p.stem for p in (root / "formal").glob("*.tla")}
    rust_files = [
        f
        for f in sorted((root / "crates").glob("*/src/**/*.rs"))
        if "kani" not in f.name and "tests" not in f.name
    ]
    for f in rust_files:
        text = f.read_text(errors="ignore")
        tagged_ids = set()
        for module, name, pid in TAG.findall(text):
            tagged_ids.add(pid)
            where = f"{f.name}: `{module}!{name}` — {pid}"
            if module not in modules:
                findings.append(f"{where}: no such formal/ module")
            if pid not in by_id:
                findings.append(f"{where}: id not in the registry")
            elif by_id[pid] != name:
                findings.append(
                    f"{where}: id belongs to {by_id[pid]!r} — mismatched pairing"
                )
        for pid in set(SEC_ID.findall(text)) - tagged_ids:
            if pid not in by_id:
                findings.append(f"{f.name}: {pid} is not in the registry")

    shipped = root / "formal" / "Shipped.cfg"
    if shipped.is_file():
        for name in cfg_checked(shipped):
            if not any(
                re.search(r"\b" + re.escape(name) + r"\b", f.read_text(errors="ignore"))
                for f in rust_files
            ):
                findings.append(
                    f"{name}: checked by Shipped.cfg but named nowhere in "
                    "production Rust — its owner lost the tag"
                )


def check_tiers(root: pathlib.Path, findings: list[str]) -> int:
    formal = root / "formal"
    tiered = tier_union(formal)
    present = {p.name for p in formal.glob("*.cfg")}
    for cfg in sorted(present - tiered - set(EXEMPT_CFG)):
        findings.append(f"{cfg}: in no tier of run-tlc.sh and not exempt")
    for cfg in sorted(tiered - present):
        findings.append(f"{cfg}: in a tier but no such file")
    for cfg in sorted(set(EXEMPT_CFG) - present):
        findings.append(f"{cfg}: exempt but no such file — stale exemption")
    return len(tiered)


def check_crates(root: pathlib.Path, findings: list[str]) -> dict[str, int]:
    with open(root / "assurance" / "crates.toml", "rb") as fh:
        ledger = tomllib.load(fh).get("crate", {})
    members = workspace_members(root)
    modules = {p.stem for p in (root / "formal").glob("*.tla")}

    for name in sorted(members - set(ledger)):
        findings.append(f"workspace member not in the crate ledger: {name}")
    for name in sorted(set(ledger) - members):
        findings.append(f"ledgered but not a workspace member: {name}")

    tally: dict[str, int] = {}
    for name, entry in sorted(ledger.items()):
        cls = entry.get("class", "?")
        tally[cls] = tally.get(cls, 0) + 1
        where = f"crates.toml [{name}]"
        if cls in ("state-modelled", "state-partial"):
            if entry.get("model") not in modules:
                findings.append(f"{where}: model {entry.get('model')!r} is no formal/ module")
            if cls == "state-partial" and not entry.get("gap", "").strip():
                findings.append(f"{where}: state-partial without a named gap")
        elif cls == "state-unmodelled":
            if not entry.get("planned", "").strip():
                findings.append(f"{where}: state-unmodelled without a planned module")
        elif cls == "pure":
            paths = entry.get("evidence", [])
            if not paths:
                findings.append(f"{where}: pure without evidence files")
            for p in paths:
                if not (root / p).is_file():
                    findings.append(f"{where}: evidence file missing: {p}")
        elif cls in ("out-of-scope", "embedded-binary"):
            if not entry.get("reason", "").strip():
                findings.append(f"{where}: {cls} without a reason")
        else:
            findings.append(f"{where}: unknown class {cls!r}")
    return tally


def audit(root: pathlib.Path):
    """(problems, evidence table, one-line summary) for this checkout."""
    root = pathlib.Path(root)
    findings: list[str] = []
    rows = check_properties(root, findings)
    check_tags(root, findings, [r["e"] for r in rows])
    tiered = check_tiers(root, findings)
    tally = check_crates(root, findings)

    table: list[str] = []
    for r in rows:
        e, d = r["e"], r["d"]
        if d is None:
            table.append(f"  {e['id']:<14} {e['name']:<40} {e['status']}")
            continue
        table.append(
            f"  {e['id']:<14} {e['name']:<40} {e['status']:<13}"
            f" cfgs={r['cfgs']:<3} mut={d['mutants']:<2} kani={len(d['kani'])}"
            f" fuzz={len(d['fuzz'])} rust={len(d['rust'])} test={len(d['tests'])}"
        )

    statuses: dict[str, int] = {}
    for r in rows:
        s = r["e"]["status"]
        statuses[s] = statuses.get(s, 0) + 1
    summary = (
        "assurance-gate: ok — "
        + f"{len(rows)} properties ("
        + ", ".join(f"{v} {k.lower()}" for k, v in sorted(statuses.items()))
        + f"), {sum(tally.values())} crates ledgered ("
        + ", ".join(f"{v} {k}" for k, v in sorted(tally.items()))
        + f"), {tiered} cfgs tiered + {len(EXEMPT_CFG)} exempt"
    )
    return findings, table, summary


def run(root: pathlib.Path) -> int:
    findings, table, summary = audit(root)
    for line in table:
        print(line)
    if findings:
        print(f"assurance-gate: {len(findings)} finding(s)", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main():
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
