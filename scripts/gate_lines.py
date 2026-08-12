# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""How the roster guards read a command out of a file they do not run.

`kani_gate.py` and `roster_gate.py` both ask whether a hand-written `-p` list is
still the whole truth, and both read the same files to do it. Each had to learn
the same three things: a trailing `\\` folds two lines into one command, a `#`
kills the rest of a line wherever on that line it falls, and a `cargo …` in a
workflow is only *run* when it sits inside a step's `run:` scalar.

Those rules lived in two copies. 237fd00 judged the shared surface to be "a
five-line continuation-joiner", which was true then; ffbfaef then had to fix the
`#` rule in both scripts in one commit, and the coverage roster needs the `run:`
walk — block scalars, `- ` list items, indentation — as a third copy. Writing
that a third time is the defect both scripts exist to catch, one level up.

Deliberately not here: what a roster *owes*. That differs per script and is the
reason there are two of them.
"""

import re

#: A `#` at a word boundary comments out the rest of the line — a shell one in
#: `check.sh` and inside a workflow's `run:` block, a YAML one beside it, a
#: heading in the docs' prose. Wherever it starts, nothing after it runs.
COMMENT = re.compile(r"(?:^|\s)#")

#: A step's `run:`, either `run: <command>` or a `run: |` block scalar.
RUN_KEY = re.compile(r"run:\s*(?:[|>][-+\d]*)?\s*")


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
    """
    run_indent = None
    for indent, body in logical_lines(text):
        if not body:
            continue
        if body.startswith("- "):
            indent, body = indent + 2, body[2:]
        if body.startswith("#"):
            executed = False  # a YAML comment, or a shell one inside the block
        elif RUN_KEY.match(body):
            run_indent, executed = indent, True
        elif run_indent is not None and indent > run_indent:
            executed = True  # a continuation line of the block scalar
        else:
            run_indent, executed = None, False
        yield body, executed
