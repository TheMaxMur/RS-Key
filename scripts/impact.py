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

import pathlib
import re
import subprocess
import sys

# How far back a changed line will look for the definition it sits inside. Bounds
# the scan; no definition in this tree spans anything close to it.
MAX_DEF_LINES = 200

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
    """-> (added lines per file, deletion anchors per file, {name: text set} removed,
    ditto added, {name: file}).

    The `+++` line is read as a header only between a `diff --git` and that file's
    first hunk. Matching it anywhere let a line of *content* beginning `++ b/`
    render as a header and retarget the parser, hiding the real use sites behind an
    authoritative-looking partial report (audit run-34 #34).

    A pure deletion adds no post-side line, so it is anchored on the line it
    followed: dropping an element from a constant is a value change too, and the
    anchor is what carries it to `enclosing_def`. Anchors do not count as reviewed —
    nobody read the line above a deletion by deleting below it.
    """
    touched, cut, gone, born, where = {}, {}, {}, {}, {}
    path, in_header = None, False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path, in_header = None, True
            continue
        if in_header and line.startswith("+++ "):
            # The prefix is forced to `b/` at the git call, so `diff.noprefix` and
            # `diff.mnemonicPrefix` cannot silence this.
            path = line[6:] if line.startswith("+++ b/") else line[4:]
            touched.setdefault(path, set())
            cut.setdefault(path, set())
            continue
        if line.startswith("@@"):
            in_header = False
            m = HUNK.match(line)
            if m and path:
                start = int(m.group("start"))
                count = int(m.group("count") or 1)
                touched[path].update(range(start, start + count))
                if count == 0:
                    cut[path].add(start)
            continue
        if not path or in_header:
            continue
        side = gone if line.startswith("-") else born if line.startswith("+") else None
        if side is None or not (name := defined(line[1:], path)):
            continue
        side.setdefault(name, set()).add(line[1:].strip())
        where.setdefault(name, path)
    return touched, cut, gone, born, where


def bracket_delta(line, path):
    """`line`'s bracket balance, skipping strings and the trailing comment.

    A `//`-commented `)` used to close a definition's span early, which drops the
    lines after it — and a dropped line is a use site nobody is told to read, the
    exact failure this file exists to prevent. Rust `'` is left alone (it is a
    lifetime far more often than a char literal).
    """
    quotes = '"' if path.endswith(".rs") else "\"'"
    comment = "//" if path.endswith(".rs") else "#"
    delta, quote, i = 0, None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in quotes:
            quote = ch
        elif line.startswith(comment, i):
            break
        elif ch in "([{":
            delta += 1
        elif ch in ")]}":
            delta -= 1
        i += 1
    return delta


def statement_end(lines, start, path):
    """Last line index of the definition statement opening at `lines[start]`.

    Bracket depth, so an unbalanced bracket inside a docstring can still overshoot
    — which reports a use site that did not need reading, the harmless direction.
    """
    depth = 0
    for i in range(start, min(len(lines), start + MAX_DEF_LINES)):
        depth += bracket_delta(lines[i], path)
        if depth > 0:
            continue
        if not path.endswith(".rs") or ";" in lines[i] or i > start:
            return i
    return start


def enclosing_def(lines, idx, path, *, below=False):
    """The definition whose statement spans `lines[idx]`, or None.

    A value-only edit to a multi-line definition changes no line the regexes can
    match, so `parse` saw nothing and the tool exited 0 — silently, for 340 of the
    tree's definitions, disproportionately the protocol-shaped ones (run-34 #33).
    Reproduced on `DEFAULT_MGM`, the PIV default management key: 21 unread sites.

    `below` asks whether the statement continues *past* `idx` — what a deletion
    anchor needs, since the removed lines sat after the anchor rather than on it.
    """
    if not 0 <= idx < len(lines):
        return None
    for start in range(idx, max(-1, idx - MAX_DEF_LINES), -1):
        if name := defined(lines[start], path):
            end = statement_end(lines, start, path)
            return name if (end > idx if below else end >= idx) else None
    return None


def post_lines(path, post, cache):
    """The file as the change leaves it — the side the hunk headers count lines in.

    `post` is the git object prefix for that side (`":"` = the index, `"<rev>:"` =
    a revision) or None for the worktree. Reading the worktree for a *staged* diff
    would size the search by lines nobody staged."""
    if path in cache:
        return cache[path]
    try:
        text = (
            pathlib.Path(path).read_text(errors="replace")
            if post is None
            else git("show", f"{post}{path}")
        )
    except (OSError, subprocess.CalledProcessError):
        text = ""
    cache[path] = text.splitlines()
    return cache[path]


def redefinitions(touched, cut, gone, born, where, post):
    """{name: defining file} for every definition this change altered in place.

    Added-only is new (nothing uses it yet) and removed-only is a deletion, which
    every consumer's compiler already refuses. A definition line re-emitted
    identically on both sides is a block rewrite around it, not a change to it.
    """
    fresh = born.keys() - gone.keys()
    out = {n: where[n] for n in gone.keys() & born.keys() if gone[n] != born[n]}
    cache = {}
    for path in touched.keys() | cut.keys():
        lines = post_lines(path, post, cache)
        added, anchors = touched.get(path, set()), cut.get(path, set())
        for num in added | anchors:
            below = num not in added
            name = enclosing_def(lines, num - 1, path, below=below)
            if not name or name in fresh or name in out:
                continue
            # The definition's own line, unchanged on both sides: a rewrite around
            # it, already excluded above. An anchor is not a written line, so the
            # test does not apply to it.
            if (
                not below
                and defined(lines[num - 1], path) == name
                and gone.get(name) == born.get(name)
            ):
                continue
            out[name] = where.get(name, path)
    return out


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
    # Force the a/ b/ prefixes: `diff.noprefix` and `diff.mnemonicPrefix` are common
    # personal settings, and either one used to make every diff parse as empty —
    # exit 0, indistinguishable from "nothing to report" (audit run-34 #34).
    fmt = ("-U0", "--src-prefix=a/", "--dst-prefix=b/")
    if rng:
        # `A..B` / `A...B` compare two revisions; a bare `A` compares it to the
        # worktree. `post` names the side the hunk line numbers belong to.
        diff = git("diff", *fmt, rng)
        post = f"{rng.rsplit('..', 1)[-1] or 'HEAD'}:" if ".." in rng else None
    elif staged := git("diff", *fmt, "--cached"):
        diff, post = staged, ":"
    else:
        diff, post = git("diff", *fmt), None
    if not diff.strip():
        return 0

    touched, cut, gone, born, where = parse(diff)
    if not touched:
        print("impact.py: could not parse the diff — reporting nothing is NOT a "
              "clean result here; check `git config diff.*`", file=sys.stderr)
        return 0
    redefined = redefinitions(touched, cut, gone, born, where, post)
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
