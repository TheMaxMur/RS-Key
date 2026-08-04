#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""List the use sites a change did NOT touch, for definitions whose meaning
changed *silently*.

Narrowing a shared definition and reviewing only the site that motivated the
change is how a fix ships its own bug. `EF_DEV_CONF_MAX` shrank to bound WRITE
CONFIG; the same constant sized two readers, one of them a persisted record an
older build wrote wider, and neither reader was looked at. Nothing failed: the
value still type-checks, and no test had a fixture for the old width.

So the scope here is exactly the compiler-blind class:

  * Rust `const` / `static` whose **value** changed (a signature change is
    `cargo check`'s job; a body change is most of every diff),
  * Python module-level `NAME = …` and `def` **signatures** — Python checks
    neither, and a defaulted new parameter is invisible at every call site.

Everything else stays a human rule (AGENTS.md → "When you change X, also do Y"):
an invariant, an ownership rule or a comment can change a definition's meaning
without changing a line this can match.

Usage:  scripts/impact.py [<rev-range>]     # default: staged, else worktree

Prints nothing when every use site is inside the change. Always exits 0 — it
reports, it does not judge.
"""

import re
import subprocess
import sys

# A definition line, per language. Group `name` is what gets searched for.
RUST_DEF = re.compile(
    r"^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?(?:const|static)\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:"
)
PY_DEF = re.compile(
    r"^(?:(?P<name>[A-Z_][A-Z0-9_]*)\s*=(?!=)|\s*def\s+(?P<fname>[A-Za-z_][A-Za-z0-9_]*)\s*\()"
)
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout


def defined(line, path):
    """The name defined on `line`, or None. `path` picks the language."""
    if path.endswith(".rs"):
        m = RUST_DEF.match(line)
        return m.group("name") if m else None
    if path.endswith(".py"):
        m = PY_DEF.match(line)
        return (m.group("name") or m.group("fname")) if m else None
    return None


def parse(diff):
    """-> (touched lines per file, {name: defining file}).

    A name counts as *redefined* only when it appears on both a removed and an
    added definition line: added-only is new (nothing uses it yet) and
    removed-only is a deletion, which every consumer's compiler already refuses.
    The two lines must also *differ*: rewriting the block around a definition
    re-emits its unchanged line on both sides, and a definition that reads the
    same still means the same.
    """
    touched, gone, born, where = {}, {}, {}, {}
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            touched.setdefault(path, set())
            continue
        if line.startswith("@@"):
            m = HUNK.match(line)
            if m and path:
                start = int(m.group("start"))
                count = int(m.group("count") or 1)
                touched[path].update(range(start, start + count))
            continue
        if not path or line.startswith(("---", "diff ", "index ")):
            continue
        side = gone if line.startswith("-") else born if line.startswith("+") else None
        if side is None or not (name := defined(line[1:], path)):
            continue
        side.setdefault(name, set()).add(line[1:].strip())
        where.setdefault(name, path)
    return touched, {
        n: where[n] for n in gone.keys() & born.keys() if gone[n] != born[n]
    }


def is_def(text, path, name):
    """Whether `text` is the definition itself, so it is not an unread user."""
    return defined(text, path) == name


def uses(name):
    """Every `file:line` mentioning `name` as a whole word, code and docs."""
    try:
        out = git("grep", "-n", "-w", "--", name)
    except subprocess.CalledProcessError:
        return []  # git grep exits 1 on no match
    hits = []
    for line in out.splitlines():
        path, _, rest = line.partition(":")
        num, _, text = rest.partition(":")
        if num.isdigit():
            hits.append((path, int(num), text.strip()))
    return hits


def main():
    rng = sys.argv[1] if len(sys.argv) > 1 else None
    if rng:
        diff = git("diff", "-U0", rng)
    else:
        diff = git("diff", "-U0", "--cached") or git("diff", "-U0")
    if not diff.strip():
        return 0

    touched, redefined = parse(diff)
    report = []
    for name, path in sorted(redefined.items()):
        unread = [
            (f, n, t)
            for f, n, t in uses(name)
            if n not in touched.get(f, ()) and not (f == path and is_def(t, f, name))
        ]
        if unread:
            report.append((name, path, unread))
    if not report:
        return 0

    print("\n== unreviewed users of a redefined constant ==")
    print(
        "These definitions changed meaning without changing shape, so nothing\n"
        "downstream fails on its own. Read each site and ask whether it still\n"
        "holds — for a persisted record, ask what an older build could have\n"
        "written there (AGENTS.md → 'Define done as something checkable')."
    )
    for name, path, unread in report:
        print(f"\n{name}  (redefined in {path}) — {len(unread)} site(s) not in this change:")
        for f, n, text in unread[:20]:
            print(f"  {f}:{n}: {text[:96]}")
        if len(unread) > 20:
            print(f"  … and {len(unread) - 20} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
