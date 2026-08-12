# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""How the roster guards read a command out of a file they do not run.

`kani_gate.py` and `roster_gate.py` both ask whether a hand-written `-p` list is
still the whole truth, and both read the same files to do it. Each had to learn
the same things: a trailing `\\` folds two lines into one command, a `#` kills
the rest of a line wherever on that line it falls, a `cargo …` in a workflow is
only *run* when it sits inside a step's `run:` scalar — and, since both guards
now walk the checkout looking for rosters, which directories are not the tree.

Those rules lived in two copies. 237fd00 judged the shared surface to be "a
five-line continuation-joiner", which was true then; ffbfaef then had to fix the
`#` rule in both scripts in one commit, and the coverage roster needs the `run:`
walk — block scalars, `- ` list items, indentation — as a third copy. Writing
that a third time is the defect both scripts exist to catch, one level up. What
a *package flag* is lives here for the same reason and later: the two had
drifted into different answers, one taking `--package` and the other not,
neither taking `--package=x`, so the same command read as two rosters.

Deliberately not here: what a roster *owes*. That differs per script and is the
reason there are two of them.
"""

import pathlib
import re
import subprocess

#: A `#` at a word boundary comments out the rest of the line — a shell one in
#: `check.sh` and inside a workflow's `run:` block, a YAML one beside it, a
#: heading in the docs' prose. Wherever it starts, nothing after it runs.
COMMENT = re.compile(r"(?:^|\s)#")

#: A step's `run:`: `run: <command>`, a `run: |` literal block, or a `run: >`
#: folded one. The indicator is captured because the two block styles are
#: different commands — `|` keeps its newlines, `>` folds the whole block into
#: one line, and reading a folded row line by line finds a `cargo` with no `-p`
#: after it and reports the row as gone while it sits there complete.
RUN_KEY = re.compile(r"run:\s*(?:(?P<fold>[|>])[-+\d]*)?\s*")

#: The package-selection flag in the spellings cargo takes: `-p x`,
#: `--package x`, `--package=x`.
PKG = re.compile(r"(?<![\w-])(?:-p|--package)[=\s]+([\w-]+)(?![\w-])")

#: The same flag with an operand a substitution fills in, so no reader can
#: resolve it from the flag alone: `-p ${c}`, `-p "$c"`, `-p @crate@`. The
#: roster is then the list being iterated — `nix/checks.nix` hid a twelve-crate
#: shortfall behind one of these, invisible to a `git grep -- '-p rsk-'`
#: census. A sigil, not "anything but a name", so that prose writing `-p …`
#: stays prose. Only meaningful inside cargo's arguments: a `mkdir -p` over a
#: variable directory matches it too.
PKG_GENERATED = re.compile(r"""(?<![\w-])(?:-p|--package)[=\s]+["']?[$@{%]""")


def invocation(verbs):
    """A `cargo <verb>` matcher over `verbs`, tolerating a `+toolchain`.

    `cargo +nightly llvm-cov …` is the same row; a matcher that misses it
    reports the row as deleted, which is the one message guaranteed to be read
    as a false alarm.
    """
    return re.compile(rf"(?<![\w-])cargo (?:\+\S+ )?({'|'.join(verbs)})(?![\w-])")


def packages(text):
    """The crates `text` selects by a readable package flag."""
    return frozenset(PKG.findall(text))


def strip_packages(text):
    """`text` with every readable package flag and its operand removed."""
    return PKG.sub(" ", text)


def split_at_comment(body):
    """`body` in two at the first `#`: what runs, and what is only quoted.

    Judged from the `#`, not from the line's first character: `true # cargo …`
    runs the `true`, and reading it as live is the hole both guards shipped with.
    """
    found = COMMENT.search(body)
    return (body[: found.start()], body[found.start() :]) if found else (body, "")


def logical_lines(text):
    """(indent, stripped text) per line, with `\\` continuations joined into one.

    A 250-character command gets reflowed onto several lines sooner or later, and
    a roster read off half of one fails a comparison nothing is wrong with. A
    guard that cries wolf on a formatting edit is a guard someone deletes.
    """
    parts, indent = [], 0
    for raw in text.splitlines():
        if not parts:
            indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1].strip())
            continue
        parts.append(stripped)
        yield indent, " ".join(p for p in parts if p)
        parts = []
    if parts:
        yield indent, " ".join(p for p in parts if p)


def yaml_runs(text):
    """(logical line, executed) over a workflow, empty lines dropped.

    Executed = inside a step's `run:` scalar; that is the only text a job runs.
    Everything else in the file — a header comment carrying the local equivalent,
    a step name, a `run:` some edit commented out — is a quotation of it. Whether
    a particular command on such a line is live is [`split_at_comment`]'s half of
    the answer, not this one's.

    A folded (`run: >`) block is yielded as the single line YAML makes of it, so
    a row wrapped for width reads as the command it is. Its blank line is a hard
    newline and ends the fold; a `#` inside it is not a YAML comment but text,
    and folding it onto the command is what makes it comment out the rest.
    """
    run_indent, folding, held = None, False, []
    for indent, body in [*logical_lines(text), (0, None)]:
        if folding and body and indent > run_indent:
            held.append(body)
            continue
        if held:  # the fold ended: a dedent, a blank line, or the file did
            yield " ".join(held), True
            held = []
        if not body:
            continue
        if body.startswith("- "):
            indent, body = indent + 2, body[2:]
        found = RUN_KEY.match(body)
        if body.startswith("#"):
            # A YAML comment, or a shell one inside the block. Reached only from
            # outside a fold — one inside it is text — and a comment shallower
            # than the scalar has ended it.
            executed, folding = False, False
        elif found:
            run_indent, folding, executed = indent, found["fold"] == ">", True
        elif run_indent is not None and indent > run_indent:
            executed = True  # a continuation line of the block scalar
        else:
            run_indent, folding, executed = None, False, False
        yield body, executed


def tree_files(root):
    """Every file of the checkout at `root`, relative: git's answer, not a walk.

    The tree is what git tracks plus what a contributor has just written; build
    output is not the tree, and a hand-written skip list gets the difference
    wrong. Walking the filesystem past `target/` and `.git` still descended into
    the mdBook output under `book/` and `site/`, where six generated copies of
    `docs/testing.md` each read as an unregistered roster owner. It also skips
    the agent worktrees under `.claude/`, whole second copies of the tree in
    which every proof reads as unreachable. No fallback if git is not there: a
    second path for reading the tree is a second answer to what the tree is.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    for rel in listing.split("\0"):
        if rel and (pathlib.Path(root) / rel).is_file():
            yield pathlib.Path(rel)
