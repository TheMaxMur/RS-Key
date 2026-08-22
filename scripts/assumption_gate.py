#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the standing-assumption registry against the model, both ways.

An assumption is a Boolean model constant that is not a defect switch: the
switches (`Bug*`, `Fix*`, `Mutate*`, `Check*`) say "pretend the code is wrong
here", an assumption says "the hardware or the world behaves this way". The
difference matters because a switch is *meant* to be pinned per configuration,
and an assumption pinned one way is an axiom.

Three rules, and the third is why this file exists:

* every assumption constant has exactly one registry entry, and every entry
  names a constant some configuration assigns (no orphans either way);
* the entry carries what only a person can write — the statement, what would
  discharge it, and which way it fails if it is wrong;
* the constant is ASSIGNED BOTH WAYS by some configuration, and READ BY A
  DEFINITION SOME CONFIGURATION REACHES. `PowerOnClearsScratch2` satisfied
  neither: it was `TRUE` in all seven Boot configurations and appeared in its
  module only in `CONSTANTS` and in its own `ASSUME`, so deleting the `ASSUME`
  left every run bit-identical. An assumption nothing can vary and nothing
  reads is a comment with a type.

  The reachability half is the rule's own failure family one level in.
  "Mentioned anywhere in the module" was what this checked first, and
  `Orphan == PowerOnClearsScratch2` with nothing mentioning `Orphan` passes
  that while being exactly as inert.

Everything about *where* an assumption is used is derived here and printed.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal"
REGISTRY = ROOT / "assurance" / "assumptions.toml"

# A defect switch is pinned per configuration by design; an assumption is not.
SWITCH = re.compile(r"^(Bug|Fix|Mutate|Check)")
HAND_FIELDS = {"constant", "statement", "discharged_by", "risk"}
RISKS = {"security", "usability", "coverage"}


def constants_of(tla: Path) -> set[str]:
    """The names a module declares, from every CONSTANT/CONSTANTS form it uses."""
    names: set[str] = set()
    lines = tla.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        head = re.match(r"^CONSTANTS?\s*(.*)$", lines[i])
        if not head:
            i += 1
            continue
        rest = head.group(1).strip()
        if rest:  # one-line `CONSTANT Name` / `CONSTANTS A, B`
            names.update(re.findall(r"\w+", rest.split("\\*")[0]))
            i += 1
            continue
        i += 1
        while i < len(lines) and (lines[i].startswith((" ", "\t"))or not lines[i].strip()):
            body = lines[i].split("\\*")[0]
            names.update(re.findall(r"^\s*(\w+)\s*,?\s*$", body, re.M))
            i += 1
    return names


def assignments() -> dict[str, dict[str, str]]:
    """constant -> {config name: assigned value} over every generated cfg."""
    out: dict[str, dict[str, str]] = {}
    for cfg in sorted(FORMAL.glob("*.cfg")):
        block = re.search(
            r"^CONSTANTS?\s*$(.*?)^(?:INVARIANT|PROPERT|SYMMETRY|SPECIF|CHECK|=)",
            cfg.read_text(encoding="utf-8"), re.S | re.M)
        if not block:
            continue
        for line in block.group(1).splitlines():
            pair = re.match(r"\s*(\w+)\s*=\s*(.+?)\s*$", line)
            if pair:
                out.setdefault(pair.group(1), {})[cfg.name] = pair.group(2)
    return out


#: `Name ==` or `Name(args) ==` at column 0 — where a TLA+ definition starts.
DEFINITION = re.compile(r"^([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*==")

#: A column-0 line that ENDS the definition above it. `ASSUME` leads for the
#: reason this whole rule exists: a constant named only in its own `ASSUME` is
#: the shape being refused, and folding that line into whatever definition
#: happens to sit above it would satisfy the rule with the defect.
CLOSES = re.compile(
    r"^(====|ASSUME\b|THEOREM\b|VARIABLES?\b|CONSTANTS?\b|EXTENDS\b|RECURSIVE\b|LOCAL\b)"
)


def strip_comments(line: str, depth: int) -> tuple[str, int]:
    """Drop `\\*` tails and `(* … *)` spans, carrying the nesting depth across lines.

    Prose is not a reader. Every module carries block comments BELOW its first
    definition, so a constant named in one would otherwise land in that
    definition's mention set — a comment satisfying the rule against a comment.
    """
    out, i = [], 0
    while i < len(line):
        if depth:
            close = line.find("*)", i)
            if close < 0:
                return "".join(out), depth
            depth -= 1
            i = close + 2
            continue
        block, tail = line.find("(*", i), line.find("\\*", i)
        if tail >= 0 and (block < 0 or tail < block):
            out.append(line[i:tail])
            return "".join(out), depth
        if block < 0:
            out.append(line[i:])
            return "".join(out), depth
        out.append(line[i:block])
        depth += 1
        i = block + 2
    return "".join(out), depth


def definitions(tla: Path) -> dict[str, set[str]]:
    """definition name -> the identifiers its body mentions, comments stripped."""
    out: dict[str, set[str]] = {}
    current, depth = None, 0
    for raw in tla.read_text(encoding="utf-8").splitlines():
        line, depth = strip_comments(raw, depth)
        if CLOSES.match(line):
            current = None
            continue
        head = DEFINITION.match(line)
        if head:
            current = head.group(1)
            out.setdefault(current, set())
            line = line[head.end():]
        if current is not None:
            out[current].update(re.findall(r"[A-Za-z_]\w*", line))
    return out


def checked_names() -> set[str]:
    """Every name a configuration asks TLC to run or check, over all of them."""
    roots: set[str] = set()
    keys = re.compile(
        r"^\s*(SPECIFICATION|INIT|NEXT|INVARIANTS?|PROPERT(?:Y|IES)"
        r"|CONSTRAINTS?|SYMMETRY|VIEW|ALIAS)\b(.*)$")
    for cfg in sorted(FORMAL.glob("*.cfg")):
        listing = False
        for line in cfg.read_text(encoding="utf-8").splitlines():
            head = keys.match(line)
            if head:
                roots.update(re.findall(r"[A-Za-z_]\w*", head.group(2)))
                listing = True
                continue
            if listing:
                if line.startswith((" ", "\t")) and line.strip():
                    roots.update(re.findall(r"[A-Za-z_]\w*", line))
                    continue
                listing = False
    return roots


def read_by_an_action(name: str, tla: Path) -> bool:
    """Whether some definition a CONFIGURATION reaches mentions `name`.

    Mentioning it anywhere in the module is not the same thing, and the gap is
    the rule's own failure family one level in — the module docstring says which
    shapes, because they are the same ones a reader has to recognise.
    """
    defs = definitions(tla)
    seen, queue = set(), [r for r in checked_names() if r in defs]
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        if name in defs[current]:
            return True
        queue.extend(ref for ref in defs[current] if ref in defs and ref not in seen)
    return False


def audit() -> list[str]:
    assigned = assignments()
    modules = {tla: constants_of(tla) for tla in sorted(FORMAL.glob("*.tla"))}
    booleans = {
        name: cfgs for name, cfgs in assigned.items()
        if set(cfgs.values()) <= {"TRUE", "FALSE"} and not SWITCH.match(name)
    }
    registry = tomllib.loads(REGISTRY.read_text(encoding="utf-8"))
    entries = {e["constant"]: e for e in registry.get("assumption", [])}

    problems = []
    for name in sorted(set(booleans) - set(entries)):
        problems.append(f"{name}: assigned by {sorted(booleans[name])[0]} but not in the registry")
    for name in sorted(set(entries) - set(booleans)):
        problems.append(f"{name}: in the registry but no configuration assigns it")

    for name, entry in sorted(entries.items()):
        missing = HAND_FIELDS - set(entry)
        if missing:
            problems.append(f"{name}: registry entry is missing {sorted(missing)}")
        elif entry["risk"] not in RISKS:
            problems.append(f"{name}: risk {entry['risk']!r} is not one of {sorted(RISKS)}")
        if name not in booleans:
            continue
        arms = set(booleans[name].values())
        if arms != {"TRUE", "FALSE"}:
            problems.append(
                f"{name}: pinned {arms.pop()} by every configuration — an assumption "
                "no run can vary is an axiom; add the other arm")
        owners = [tla for tla, names in modules.items() if name in names]
        if not owners:
            problems.append(f"{name}: no module declares it")
        for tla in owners:
            if not read_by_an_action(name, tla):
                problems.append(
                    f"{name}: {tla.name} declares it, but nothing a configuration "
                    "runs or checks reaches a definition that reads it — so both "
                    "arms produce identical runs")
    return problems, booleans, entries


def main() -> int:
    problems, booleans, entries = audit()
    if problems:
        print("assumption-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"assumption-gate: ok — {len(entries)} standing assumption(s)")
    for name in sorted(entries):
        arms = booleans[name]
        both = {v: sorted(c for c, x in arms.items() if x == v) for v in ("TRUE", "FALSE")}
        print(f"  {name} [{entries[name]['risk']}] "
              f"TRUE={len(both['TRUE'])} cfg(s), FALSE={both['FALSE']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
