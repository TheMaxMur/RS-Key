#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold every TLC configuration above the scope its own mutants need.

`floors.txt` asks whether a run got smaller. This asks the question one level
out, which nothing asked before: **is the scope it ran at big enough to express
the defects the roster claims to catch?** A configuration can sit far above its
floor and still be blind, because the blindness is in the CONSTANTS, not in the
search -- and the verdict column shows GREEN either way.

It is not a hypothetical. Measured on this tree, two of the twenty-five module
mutants are GREEN one element below the shipped scope and RED at it:
`BugMetaAddDropsOnFault` needs a second FID (one to `meta_add`, one whose record
must survive it) and `BugContIgnoresChannel` needs a second channel (one to own
the transaction, one to splice into it). Drop `Fids` or `Channels` to a
singleton -- which nothing stopped before this file -- and those two rows go
green over a defect that is still there.

`formal/scopes.txt` therefore records ONE hand-written number per row: the
measured minimum at which that module's whole `*Mut_*` roster is still RED.
Everything else is derived, for the same reason the property registry derives
its evidence columns -- a hand-kept copy of a derivable fact rots, and this tree
has paid for that twice. In particular:

* the scope constants come from each module's own `CONSTANTS` blocks (a constant
  is a scope constant unless it is a `Bug`/`Fix`/`Mutate`/`Check` switch), so a
  new one cannot be added without a row;
* a configuration is matched to its module by its assignment set being exactly
  that module's transitive constants -- no filename convention, no prefix table.
  `run-tlc.sh` has such a table for picking the spec; duplicating it here would
  make this the sixth hand-kept roster a new module has to be threaded through,
  which is the failure mode the checklist in README already names;
* safety-tier membership comes from `run-tlc.sh --tiers`, the one place it
  lives, the same way `assurance_gate.py` reads it.

What it refuses: a scope constant with no row, a row naming no constant, and any
safety-tier configuration assigning a scope BELOW its recorded minimum.

Limits, so the row is not read as more than it is. The minimum is measured
against the roster that exists -- it says the current mutants all fire, never
that no defect needs more. Nothing here can know that a third channel would
expose a splice the second cannot, and the honest reading of a roster whose
minimum equals its shipped value is "nothing probes above this", not "above this
is safe". Non-safety tiers are exempt on purpose: the liveness tier runs one
relying party and one channel deliberately, and the token-refinement tier runs
the smallest scope that still has a token, because their properties are not the
ones these minima were measured against. Booleans carry `-` and are checked for
nothing but presence: `PowerOnClearsScratch2` is a modelling ASSUME, not a size.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMAL = ROOT / "formal"
SCOPES = FORMAL / "scopes.txt"

# A constant is a mutation switch, not a scope, if it is named like one. The
# generator spells every switch this way and `gen-configs.sh` is the only writer.
SWITCH = re.compile(r"^(Bug|Fix|Mutate|Check)[A-Z]")


def die(msg):
    print(f"scope-gate: {msg}", file=sys.stderr)
    raise SystemExit(1)


def constants_of(module, formal=FORMAL):
    """Every CONSTANTS name a module declares.

    Both spellings are in use and both are load-bearing: a block header on its
    own line, and the one-line `CONSTANT Name` the three late switches use.
    Reading only the block form loses exactly those three, and a parser that
    silently sees fewer constants than TLC does is the blind kind of green.
    """
    text = (formal / f"{module}.tla").read_text(encoding="utf-8")
    names, inside = [], False
    for line in text.splitlines():
        inline = re.fullmatch(r"CONSTANTS?\s+(.+?)\s*", line)
        if inline and not line.rstrip().endswith(","):
            names += [n.strip() for n in inline.group(1).split("\\*")[0].split(",")
                      if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", n.strip())]
            inside = False
            continue
        if re.fullmatch(r"CONSTANTS?\s*", line):
            inside = True
            continue
        if not inside:
            continue
        if not line.strip():
            inside = False
            continue
        body = line.split("\\*")[0].strip().rstrip(",")
        for name in body.split(","):
            name = name.strip()
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
                names.append(name)
    return names


def extended_by(module, formal=FORMAL):
    text = (formal / f"{module}.tla").read_text(encoding="utf-8")
    head = re.search(r"^EXTENDS (.+)$", text, re.M)
    if not head:
        return []
    return [n.strip() for n in head.group(1).split(",")
            if (formal / f"{n.strip()}.tla").exists()]


def scope_constants(names):
    """The constants that are a size, not a mutation switch."""
    return {n for n in names if not SWITCH.match(n)}


def ancestors(module, formal=FORMAL, seen=None):
    """Every module reachable through EXTENDS, transitively."""
    seen = set() if seen is None else seen
    for parent in extended_by(module, formal):
        if parent not in seen:
            seen.add(parent)
            ancestors(parent, formal, seen)
    return seen


def transitive_constants(module, formal=FORMAL, seen=None):
    seen = set() if seen is None else seen
    if module in seen:
        return set()
    seen.add(module)
    names = set(constants_of(module, formal))
    for parent in extended_by(module, formal):
        names |= transitive_constants(parent, formal, seen)
    return names


def defined_in(module, formal=FORMAL, seen=None):
    """Operator names a module defines, following EXTENDS.

    Needed because the constant set alone does not identify a module: an
    EXTENDS child that adds no constant of its own -- `RSKeyTokenRefinement`
    over `RSKeySecurityState`, `TraceSecurity` over `TraceSecurityData` -- has
    exactly its parent's constants, and a configuration would match both.
    """
    seen = set() if seen is None else seen
    if module in seen:
        return set()
    seen.add(module)
    text = (formal / f"{module}.tla").read_text(encoding="utf-8")
    names = set(re.findall(r"^([A-Za-z][A-Za-z0-9_]*)\s*(?:\(.*?\))?\s*==", text, re.M))
    for parent in extended_by(module, formal):
        names |= defined_in(parent, formal, seen)
    return names


def referenced_by(cfg):
    """The operator names a configuration names: its spec, invariants, properties."""
    text = cfg.read_text(encoding="utf-8")
    out = set()
    for head in ("SPECIFICATION", "INVARIANTS?", "PROPERTI?E?S?", "SYMMETRY"):
        for block in re.finditer(rf"^{head}\s*$(.*?)(?=^[A-Z]+\s*$|\Z)", text, re.M | re.S):
            out |= {ln.strip() for ln in block.group(1).splitlines()
                    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", ln.strip())}
        for inline in re.finditer(rf"^{head}\s+([A-Za-z][A-Za-z0-9_]*)\s*$", text, re.M):
            out.add(inline.group(1))
    return out


def assignments(cfg):
    """CONSTANT assignments of one configuration, as {name: raw value}."""
    text = cfg.read_text(encoding="utf-8")
    block = re.search(r"^CONSTANTS?\s*$(.*?)(?=^[A-Z]+\s*$|\Z)", text, re.M | re.S)
    out = {}
    if not block:
        return out
    for line in block.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("\\*"):
            continue
        hit = re.match(r"([A-Za-z][A-Za-z0-9_]*)\s*(?:=|<-)\s*(.+)$", line)
        if hit:
            out[hit.group(1)] = hit.group(2).strip()
    return out


def size_of(raw):
    """The scalar a scope value is compared on: a set's cardinality, or the number.

    A boolean is not a size -- it returns None and the row is presence-only.
    """
    if raw in ("TRUE", "FALSE"):
        return None
    if raw.startswith("{"):
        inner = raw.strip("{}").strip()
        return 0 if not inner else len([p for p in inner.split(",") if p.strip()])
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return None


def safety_tier(formal=FORMAL):
    out = subprocess.run([str(formal / "run-tlc.sh"), "--tiers"],
                         capture_output=True, text=True, cwd=formal)
    for line in out.stdout.splitlines():
        if line.startswith("safety:"):
            return set(line.split(":", 1)[1].split())
    raise SystemExit("scope-gate: run-tlc.sh --tiers printed no safety row")


def read_rows(scopes=SCOPES):
    """The one hand-written column, or the problems that stopped it parsing."""
    if not scopes.exists():
        return {}, [f"{scopes.name} is missing"]
    rows, problems = {}, []
    for n, line in enumerate(scopes.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("\\*"):
            continue
        parts = line.split()
        if len(parts) < 4:
            problems.append(
                f"{scopes.name}:{n}: expected `<module> <constant> <min> <invariant>`")
            continue
        module, const, minimum, invariant = parts[0], parts[1], parts[2], parts[3]
        if minimum != "-" and not re.fullmatch(r"\d+", minimum):
            problems.append(
                f"{scopes.name}:{n}: minimum must be a number or `-`, got {minimum!r}")
            continue
        if (minimum == "-") != (invariant == "-"):
            problems.append(f"{scopes.name}:{n}: a minimum and the invariant it was "
                            "measured against are recorded together or not at all")
            continue
        if (module, const) in rows:
            problems.append(f"{scopes.name}:{n}: {module} {const} recorded twice")
            continue
        rows[(module, const)] = (None if minimum == "-" else int(minimum), invariant)
    return rows, problems


def owner_of(cfg, modules, const_sets, defs, formal):
    """The module a configuration belongs to, or None when it is not unique."""
    names = set(assignments(cfg))
    wanted = referenced_by(cfg)
    owners = [m for m in modules if const_sets[m] == names and wanted <= defs[m]]
    # An EXTENDS child inherits every parent definition, so a configuration
    # naming only parent operators qualifies for both. The owner is the base --
    # the candidate that builds on no other candidate.
    owners = [m for m in owners
              if not any(o in ancestors(m, formal) for o in owners if o != m)]
    # `TraceSeams` and `TraceSeamsBad` are indistinguishable here on purpose:
    # they duplicate the harness because EXTENDS cannot be parameterized, so they
    # declare the same constants and define the same names. Which one owns a
    # configuration cannot change a scope verdict while their scope constants
    # agree -- so tie deterministically there, and only there.
    if len(owners) > 1 and len({frozenset(scope_constants(const_sets[m]))
                                for m in owners}) == 1:
        owners = [sorted(owners)[0]]
    return owners[0] if len(owners) == 1 else None


def audit(formal=FORMAL, scopes=SCOPES, safety=None):
    """Every way a configuration can be below the scope its own mutants need."""
    problems, spread = [], {}
    modules = sorted(p.stem for p in formal.glob("*.tla"))
    const_sets = {m: transitive_constants(m, formal) for m in modules}
    defs = {m: defined_in(m, formal) for m in modules}

    cfg_module = {}
    for cfg in sorted(formal.glob("*.cfg")):
        owner = owner_of(cfg, modules, const_sets, defs, formal)
        if owner is None:
            problems.append(f"{cfg.name}: no single module assigns exactly its "
                            "constants and defines every name it references")
            continue
        cfg_module[cfg] = owner

    declared = set()
    for cfg, module in cfg_module.items():
        for const, raw in assignments(cfg).items():
            if SWITCH.match(const):
                continue
            declared.add((module, const))
            spread.setdefault((module, const), {}).setdefault(raw, []).append(cfg.name)

    rows, row_problems = read_rows(scopes)
    problems += row_problems
    for module, const in sorted(declared - set(rows)):
        problems.append(f"{module} {const} is a scope constant with no row in "
                        f"{scopes.name}")
    for module, const in sorted(set(rows) - declared):
        problems.append(f"{scopes.name} records {module} {const}, which no "
                        "configuration assigns")
    for (module, const), (_, invariant) in sorted(rows.items()):
        if invariant != "-" and module in defs and invariant not in defs[module]:
            problems.append(f"{scopes.name} measures {module} {const} against "
                            f"{invariant}, which {module} does not define")

    if safety is None:
        safety = safety_tier(formal)
    for cfg, module in sorted(cfg_module.items(), key=lambda kv: kv[0].name):
        if cfg.name not in safety:
            continue
        checked = referenced_by(cfg)
        for const, raw in assignments(cfg).items():
            floor, invariant = rows.get((module, const), (None, None))
            got = size_of(raw)
            # A minimum measured against one invariant says nothing about a
            # configuration that does not check it. The fairness row runs one
            # channel on purpose and checks `OpAdvancesIsOneActivity`; holding it
            # to a minimum measured on `NoAuthorizationBypass` would be a red for
            # the wrong reason, and a gate that cries there gets deleted.
            if floor is None or got is None or invariant not in checked:
                continue
            if got < floor:
                problems.append(
                    f"{cfg.name}: {const} = {raw} is below the {floor} that "
                    f"{invariant} was measured to need -- some {module} mutant "
                    "is blind at this scope")
    return problems, cfg_module, spread, safety


def main():
    problems, cfg_module, spread, safety = audit()
    for problem in problems:
        print(f"scope-gate: {problem}", file=sys.stderr)
    if problems:
        raise SystemExit(1)
    held = len([c for c in cfg_module if c.name in safety])
    print(f"scope-gate: ok — {len(spread)} scope constants over "
          f"{len(set(cfg_module.values()))} modules, "
          f"{held} safety configs above their minima")
    for (module, const), values in sorted(spread.items()):
        if len(values) > 1:
            shown = ", ".join(f"{raw} ×{len(files)}" for raw, files in sorted(values.items()))
            print(f"  {module}.{const} runs at more than one scope: {shown}")


if __name__ == "__main__":
    main()
