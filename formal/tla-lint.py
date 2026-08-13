#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Two TLA+ traps this model has actually been bitten by, caught at the source.

Both turn a conjunct into something other than what it reads as, and neither is
an error to TLC -- the spec stays well-formed, the run stays GREEN, and the only
tell is a state count nobody was watching.

  PRECEDENCE   `x' = e /\\ y` parses as `(x' = e) /\\ y`, because `=` binds
               tighter than `/\\`. An assignment silently becomes an extra
               GUARD. It disabled both SELECT actions once and TLC reported
               GREEN over ONE distinct state (E164); it disabled PgpSetPwStatus
               a second time and BugSigPinNotSpent went green over it.

  PINNED       A variable assigned inside an action while the action's OWN
               top-level `UNCHANGED` also names it. The conjunction is simply
               false unless the new value equals the old, so the action exists,
               is reachable, and is disabled wherever it would have changed
               anything. A branch-local `UNCHANGED` is the legitimate IF-branch
               pair and is not flagged.

Run standalone, or through `run-tlc.sh`, which refuses to check anything until
this passes.
"""
import pathlib
import re
import sys

DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?\s*==")
ASSIGN = re.compile(r"\b([a-z][A-Za-z0-9_]*)'\s*=(?!=)")
TOP_UNCHANGED = re.compile(r"^ {4}/\\\s*UNCHANGED\b")
VARLIST = re.compile(r"UNCHANGED\s*(?:<<([^>]*)>>|([A-Za-z_][A-Za-z0-9_]*))", re.S)


def strip_comments(lines):
    """Drop `\\* ...` tails and (* ... *) blocks; keep line count stable."""
    out, depth = [], 0
    for line in lines:
        buf, i = "", 0
        while i < len(line):
            if line.startswith("(*", i):
                depth += 1
                i += 2
            elif line.startswith("*)", i) and depth:
                depth -= 1
                i += 2
            elif depth:
                i += 1
            elif line.startswith("\\*", i):
                break
            else:
                buf += line[i]
                i += 1
        out.append(buf)
    return out


def definitions(lines):
    """(name, 1-based start line, body lines) for every column-0 definition."""
    heads = [(i, m.group(1)) for i, m in
             ((i, DEF.match(l)) for i, l in enumerate(lines)) if m]
    return [(name, i + 1, lines[i:heads[k + 1][0] if k + 1 < len(heads) else len(lines)])
            for k, (i, name) in enumerate(heads)]


def top_level_unchanged(body):
    """Variables named by an UNCHANGED that is a conjunct of the action itself."""
    names, buf = set(), None
    for line in body + [""]:
        if TOP_UNCHANGED.match(line):
            if buf is not None:
                names |= _varlist(buf)
            buf = line
        elif buf is not None and re.match(r"^ {6,}\S", line) and ">>" not in buf:
            buf += " " + line
        elif buf is not None:
            names |= _varlist(buf)
            buf = None
    return names


def _varlist(buf):
    got = set()
    for m in VARLIST.finditer(buf):
        got |= {v.strip() for v in (m.group(1) or m.group(2)).split(",") if v.strip()}
    return got


STOP = re.compile(r"^(/\\|\\/|THEN\b|ELSE\b|IN\b)")

# IF / CASE / LET take the rest of the expression greedily, so a `/\` after one
# of them is inside that construct and is not the trap.
SWALLOWS = re.compile(r"^(IF|CASE|LET)\b")


def rhs_of_assignment(body, idx):
    """The assignment's right-hand side, continuation lines joined."""
    rhs = body[idx].split("=", 1)[1]
    for line in body[idx + 1:]:
        stripped = line.strip()
        if not stripped or STOP.match(stripped) or DEF.match(line):
            break
        rhs += " " + stripped
    return rhs


def unbracketed_conjunction(rhs):
    """A `/\\` or `\\/` outside every bracket -- the precedence trap's signature."""
    depth = 0
    for i, c in enumerate(rhs):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth <= 0:
            if rhs.startswith(("/\\", "\\/"), i):
                return True
            if SWALLOWS.match(rhs[i:]) and (i == 0 or not rhs[i - 1].isalnum()):
                return False
    return False


def check(path):
    lines = strip_comments(path.read_text().split("\n"))
    hits, defs = [], definitions(lines)
    for name, start, body in defs:
        pinned = {m.group(1) for line in body for m in [ASSIGN.search(line)] if m}
        pinned &= top_level_unchanged(body)
        for v in sorted(pinned):
            hits.append(f"{path.name}:{start}: {name} assigns {v}' and its own "
                        f"top-level UNCHANGED names {v} -- the action is pinned "
                        f"to a no-op wherever it would change {v}")
        for k, line in enumerate(body):
            m = ASSIGN.search(line)
            if m and unbracketed_conjunction(rhs_of_assignment(body, k)):
                hits.append(f"{path.name}:{start + k}: {name} reads as "
                            f"({m.group(1)}' = ...) /\\ ... -- `=` binds tighter "
                            f"than `/\\`; parenthesise the right-hand side")
    return hits, len(defs)


def main():
    here = pathlib.Path(__file__).resolve().parent
    modules = sorted(here.glob("*.tla"))
    if not modules:
        print("tla-lint: no .tla modules found", file=sys.stderr)
        return 2
    hits, total = [], 0
    for m in modules:
        found, n = check(m)
        hits += found
        total += n
    for h in hits:
        print(f"tla-lint: {h}", file=sys.stderr)
    if hits:
        print(f"tla-lint: FAIL -- {len(hits)} finding(s)", file=sys.stderr)
        return 1
    print(f"tla-lint: ok -- {total} definitions across {len(modules)} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
