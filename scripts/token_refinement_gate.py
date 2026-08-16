#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Tree-wide completeness gate for the phase-5 concrete event boundary."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([a-zA-Z0-9_]+)")
VOLATILE_WRITE = re.compile(r"\.paut\.(in_use|permissions|has_rp_id)\s*(?:=|&=)")
PERMISSION_OUTCOME = re.compile(r"\.paut\.permissions\s*&\s*PERM_(?:MC|GA|CM|ACFG)")


def functions(path: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = FN.match(line)
        if match:
            current = (match.group(1), [])
            found.append(current)
        if current is not None:
            current[1].append(line)
    return [(name, "\n".join(body)) for name, body in found]


def production_sources(root: Path) -> list[Path]:
    base = root / "crates" / "rsk-fido" / "src"
    return sorted(
        path
        for path in base.rglob("*.rs")
        if not path.name.endswith(("_tests.rs", "_kani.rs"))
        and path.name not in {"generated_token_edges.rs", "state_assurance.rs"}
    )


def key_names(root: Path) -> set[str]:
    state_assurance = root / "crates" / "rsk-fido" / "src" / "state_assurance.rs"
    match = re.search(
        r"TOKEN_PERSISTENT_FIDS[^=]*=\s*\[(.*?)\];",
        state_assurance.read_text(encoding="utf-8"),
        re.S,
    )
    if not match:
        return set()
    return set(re.findall(r"EF_[A-Z0-9_]+", match.group(1)))


def owners(entries: list[dict]) -> set[tuple[str, str]]:
    return {(entry["file"], entry["function"]) for entry in entries}


def discovered_volatile(root: Path) -> set[tuple[str, str]]:
    found = set()
    for path in production_sources(root):
        for name, body in functions(path):
            if VOLATILE_WRITE.search(body):
                found.add((str(path.relative_to(root)), name))
    return found


def discovered_persistent(root: Path, keys: set[str]) -> set[tuple[str, str]]:
    found = set()
    names = "|".join(sorted(keys))
    direct = re.compile(
        rf"\.(?:put|put_key|delete|force_delete)\s*\(\s*(?:[a-z]+::)*(?:{names})\b"
        rf"|put_sealed32\s*\([^;]*\b(?:{names})\b",
        re.S,
    )
    for path in production_sources(root):
        for name, body in functions(path):
            dynamic_pin = (
                name in {"write_pin_verifier", "spend_and_verify_pin_at"}
                and "fid == EF_PIN" in body
                and re.search(r"\.put\s*\(\s*fid\b", body, re.S)
            )
            if direct.search(body) or dynamic_pin:
                found.add((str(path.relative_to(root)), name))
    return found


def discovered_outcomes(root: Path) -> set[tuple[str, str]]:
    found = set()
    for path in production_sources(root):
        for name, body in functions(path):
            if PERMISSION_OUTCOME.search(body) or (
                path.name == "credmgmt.rs" and name == "authorized_by_ppuat" and "load_ppuat" in body
            ):
                if name != "abstract_token":
                    found.add((str(path.relative_to(root)), name))
    return found


def compare_axis(
    label: str,
    discovered: set[tuple[str, str]],
    declared: set[tuple[str, str]],
    findings: list[str],
) -> None:
    for item in sorted(discovered - declared):
        findings.append(f"{label}: unowned concrete site {item[0]}::{item[1]}")
    for item in sorted(declared - discovered):
        findings.append(f"{label}: stale owner {item[0]}::{item[1]}")


def audit(root: Path) -> tuple[list[str], str]:
    root = Path(root)
    manifest = root / "assurance" / "token_refinement.toml"
    export = root / "formal" / "generated" / "token_relation.txt"
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    findings: list[str] = []
    ops = {
        line.split("|", 2)[2]
        for line in export.read_text(encoding="utf-8").splitlines()
        if line.startswith("TOKEN|OP|")
    }
    for category in ["volatile_writer", "persistent_writer", "outcome_producer"]:
        for entry in data.get(category, []):
            if entry["op"] not in ops:
                findings.append(f"{category}: {entry['op']} is outside the generated TLA+ Ops domain")

    keys = key_names(root)
    if keys != {"EF_PIN", "EF_PAUTHTOKEN"}:
        findings.append(f"TokenPersistentView key derivation yielded {sorted(keys)!r}")
    compare_axis(
        "volatile",
        discovered_volatile(root),
        owners(data.get("volatile_writer", [])),
        findings,
    )
    generic = {
        (entry["file"], entry["function"])
        for entry in data.get("persistent_writer", [])
        if entry.get("generic")
    }
    compare_axis(
        "persistent",
        discovered_persistent(root, keys) | generic,
        owners(data.get("persistent_writer", [])),
        findings,
    )
    compare_axis(
        "outcome",
        discovered_outcomes(root),
        owners(data.get("outcome_producer", [])),
        findings,
    )
    summary = (
        "token-refinement-gate: GREEN "
        f"keys={len(keys)} volatile={len(discovered_volatile(root))} "
        f"persistent={len(discovered_persistent(root, keys) | generic)} "
        f"outcomes={len(discovered_outcomes(root))}"
    )
    return findings, summary


def main() -> int:
    findings, summary = audit(ROOT)
    if findings:
        print("token-refinement-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
