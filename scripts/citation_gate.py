#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the TLA+ model still points at the code it says it models.

`formal/RSKeySecurityState.tla` and `formal/README.md` carry ~160 `file.rs:line`
citations — the whole bridge between the model and the implementation it claims
to abstract. They were checked once, by hand, in a review pass. Code moves; a
model whose citations have rotted is worse than no model, because it reads as
authoritative and sends the next reader to a line that no longer says what it
claims. Same failure as a stale CHANGELOG or an unbumped counter, so it lives
beside them.

## What is decidable, and what is not

That `clientpin.rs:35` still *means* what the model says is a review question.
That the file exists, that the line is inside it, and that a range runs forwards
are not, so those are the rules — plus one drift signal that costs nothing: a
citation whose first or last line is **blank**. Measured over all 162 citations
in the tree today, none lands on a blank line, and a line that has drifted onto
one has stopped being the code that was cited. It is deliberately not a
content check: a rule that fires whenever anything above a cited line moves
would be switched off inside a week, which is worse than no rule.

## Resolving a bare name

Most citations are a bare basename — `state.rs:284-291` — because the pages name
the directory once in prose and then stop repeating it. So a name without a `/`
is looked up in [`SEARCH`], in order, and the first hit wins. The order is the
model's own subject matter: the FIDO applet first, then the crates it is wired
through, then the firmware. Exactly one basename is ambiguous across that list
today — `vendor.rs` — and the ordering is right for it by measurement: the FIDO
applet's is 980 lines and its 894-901 / 962-968 are the BACKUP_FINALIZE and
`mark_backup_sealed` the model describes, while the firmware's is 197 lines and
could not hold either.

A citation carrying a `/` is a repo path and is taken literally.

## The continuation forms

Both pages write a second reference to the same file as a bare `` `:251` ``, and
a list as `presence.rs:259-266,288`. Those are read too, bound to the last file
named **on the same line** — a bare one with no file before it on its line is a
problem rather than a thing to skip, because skipping is how a citation stops
being checked without anyone deciding that.

## The floor

Each page must carry at least [`FLOOR`] citations. A regex that has stopped
matching finds nothing, loops over nothing and exits 0 — the shape four guards
in this tree shipped with. The floor is well under today's 104 and 58, and the
count only goes up as the model grows.

## Limits

It does not read `.py`, `.md` or `.tla` citations, only `.rs` ones: those are all
the pages carry. It cannot tell a citation that is merely *stale* from one that
is *wrong* — a line that drifted onto other code still passes. And [`SEARCH`] is
a hand-written list; entries are asserted to exist, not to be used, so an entry
whose last citation goes away sits there harmlessly rather than turning an
unrelated edit red.
"""

import pathlib
import re
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The pages that carry citations. Both, because the README's invariant table is
#: what a reader consults first and it cites more finely than the model does.
PAGES = (pathlib.Path("formal/RSKeySecurityState.tla"), pathlib.Path("formal/README.md"))

#: Where a bare basename is looked up, in order. The model's subject first.
SEARCH = (
    "crates/rsk-fido/src",
    "crates/rsk-device/src",
    "crates/rsk-usb/src",
    "crates/rsk-fs/src",
    "firmware/src",
)

#: Below this a page is not citing, it is failing to be parsed. Today: 104 and 58.
FLOOR = 25

#: `path.rs:12`, `path.rs:12-20`, `path.rs:12-20, 44`, and the continuation
#: `` `:44` `` that both pages use for a second reference to the same file. The
#: bare form must sit right after a backtick so ordinary prose punctuation is not
#: read as a line number.
CITE = re.compile(
    r"(?:(?<![\w/.-])(?P<file>[\w./-]+\.rs)|(?<=`))"
    r":(?P<refs>\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*)"
)
SPAN = re.compile(r"(\d+)(?:-(\d+))?")


def resolve(rel, tracked):
    """The file a citation names, or None. A `/` makes it a path, verbatim."""
    if "/" in rel:
        return rel if rel in tracked else None
    return next((f"{d}/{rel}" for d in SEARCH if f"{d}/{rel}" in tracked), None)


def citations(text):
    """(file or None, start, end, the citation as written) over one page.

    `file` is None for a continuation; binding it is the caller's, because the
    binding is per line and this yields per match.
    """
    for line in text.splitlines():
        for found in CITE.finditer(line):
            for span in SPAN.finditer(found.group("refs")):
                start = int(span.group(1))
                end = int(span.group(2)) if span.group(2) else start
                yield found.group("file"), start, end, found.group(0)


def audit(root):
    """(problems, one-line summary) for how the model cites this checkout."""
    root = pathlib.Path(root)
    # git's answer, like the other guards: a filesystem walk also finds the
    # agent worktrees under `.claude/` and the generated `book/`, whole second
    # copies of the tree in which a citation would resolve to the wrong file.
    tracked = {str(rel) for rel in gate_lines.tree_files(root) if rel.suffix == ".rs"}
    lengths, problems, total = {}, [], 0
    for missing in (d for d in SEARCH if not (root / d).is_dir()):
        problems.append(f"{missing} is in SEARCH but is not a directory any more")
    for page in PAGES:
        seen, here = None, 0
        for name, start, end, written in citations((root / page).read_text()):
            here += 1
            if name:
                seen = resolve(name, tracked)
                if seen is None:
                    problems.append(f"{page} cites `{written}`, and no such file is in the tree")
                    continue
            elif seen is None:
                problems.append(
                    f"{page} has a bare `{written}` with no file named before it"
                    " on its line, so nothing checks it"
                )
                continue
            if seen not in lengths:
                lengths[seen] = (root / seen).read_text().splitlines()
            body = lengths[seen]
            if start > end:
                problems.append(f"{page}: `{written}` runs backwards")
            elif end > len(body):
                problems.append(
                    f"{page}: `{written}` -> {seen}, which has {len(body)} lines"
                )
            elif not body[start - 1].strip() or not body[end - 1].strip():
                problems.append(
                    f"{page}: `{written}` -> {seen}, whose cited line is blank;"
                    " the code it named has moved"
                )
        if here < FLOOR:
            problems.append(
                f"{page} yielded {here} citations, under the floor of {FLOOR}:"
                " the page stopped citing, or this guard stopped reading it"
            )
        total += here
    return problems, f"citation-gate: ok — {total} citations across {len(PAGES)} pages resolve"


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("citation-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nThe model's `file.rs:line` citations are the only bridge between it\n"
            "and the code it abstracts. One that no longer resolves sends the next\n"
            "reader somewhere the claim was never true. Re-point it, or drop it."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
