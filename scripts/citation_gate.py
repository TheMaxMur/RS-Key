#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the TLA+ model still points at the code it says it models.

The eight `formal/*.tla` modules and `formal/README.md` carry ~230 `file.rs:line`
citations — the whole bridge between the model and the implementation it claims
to abstract. They were checked once, by hand, in a review pass. Code moves; a
model whose citations have rotted is worse than no model, because it reads as
authoritative and sends the next reader to a line that no longer says what it
claims. Same failure as a stale CHANGELOG or an unbumped counter, so it lives
beside them.

The phase-1 `Refines Module!Invariant — SEC-*` tags are the semantic-address
half of the same bridge. This gate shares their assurance check: every tag must
resolve to its defining module and registry row, and every invariant in the two
code-owning configurations must have a production tag.

## What is decidable, and what is not

That `clientpin.rs:35` still *means* what the model says is a review question.
That the file exists, that the line is inside it, and that a range runs forwards
are not, so those are the rules — plus one drift signal that costs nothing: a
citation whose first or last line is **blank**. Measured over all 175 citations
in the tree today, none lands on a blank line, and a line that has drifted onto
one has stopped being the code that was cited. It is deliberately not a
content check: a rule that fires whenever anything above a cited line moves
would be switched off inside a week, which is worse than no rule.

## Resolving a bare name

Most citations are a bare basename — `state.rs:284-291` — because the pages name
the directory once in prose and then stop repeating it. So a name without a `/`
is looked up in [`SEARCH`], in order. A name only one of them holds resolves to
it. A name **two** of them hold is a problem unless it is in [`AMBIGUOUS`] with
the file the model means and the measurement behind that choice — first-hit-wins
alone re-points every citation of a name the moment a file with that name appears
earlier in the list, silently and for the whole page. One name is registered
today (`vendor.rs`); several others (`ccid.rs`, `lib.rs`, `tests.rs`) are
ambiguous but uncited, so they cost nothing until they are cited.

A citation carrying a `/` is a repo path and is taken literally.

## The continuation forms

Both pages write a second reference to the same file as a bare `` `:251` ``, and
a list as `presence.rs:259-266,288`. Those are read too, bound to the last file
named in the same **paragraph** — a bare one with no file before it is a problem
rather than a thing to skip, because skipping is how a citation stops being
checked without anyone deciding that. A paragraph, not a line, because a sentence
in a markdown table wraps and the file it names is then one line up; not a page,
because that is how a bare `` `:1` `` came to be checked against a file three
hundred lines earlier.

Every dash a prose editor leaves behind counts as a range separator, and so does
a space either side of the colon. An en dash used to read as a single-line
citation with the upper bound thrown away — in pages whose prose already uses
`—`, `·` and `…` — and one space after the colon used to delete the citation
outright.

## The floor

Each page must carry at least its [`FLOOR`] citations — [`FLOOR_BY_PAGE`] where a
page legitimately cites fewer, the default otherwise. A regex that has stopped
matching finds nothing, loops over nothing and exits 0 — the shape four guards
in this tree shipped with. The floor is well under each page's real count (104,
58, 18, 12, 10, 11, 12, 8) and only rises as the model grows; the per-page
override is there so a
tight model is not mistaken for a broken regex, and so no page is ever padded
with citations it does not mean just to clear one number.

## Limits

[`PENDING`] is the debt this row landed with, not a permanent carve-out: three
citations another agent's in-flight commits rotted while this guard was being
written. Each names the commit that broke it and fails once it stops rotting.

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

import assurance_gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The pages that carry citations: the three model modules and the README, whose
#: invariant table a reader consults first and which cites more finely than the
#: modules do. `RSKeyStore.tla` is the flash layer, added when M3 landed.
PAGES = (
    pathlib.Path("formal/RSKeySecurityState.tla"),
    pathlib.Path("formal/RSKeyAppletSeams.tla"),
    pathlib.Path("formal/RSKeyStore.tla"),
    pathlib.Path("formal/RSKeyRetryLattice.tla"),
    pathlib.Path("formal/RSKeyAdminSurface.tla"),
    pathlib.Path("formal/RSKeyTrustedDisplay.tla"),
    pathlib.Path("formal/RSKeyBootHardening.tla"),
    pathlib.Path("formal/RSKeyTransport.tla"),
    pathlib.Path("formal/README.md"),
)

#: Where a bare basename is looked up, in order. The model's subject first.
SEARCH = (
    "crates/rsk-fido/src",
    "crates/rsk-device/src",
    "crates/rsk-usb/src",
    "crates/rsk-fs/src",
    "firmware/src",
)

#: A basename that more than one SEARCH directory holds, and the file the model
#: means, with the measurement behind it. Anything else ambiguous is a problem:
#: first-hit-wins silently re-points every citation of a name the moment a file
#: with that name appears earlier in the list.
AMBIGUOUS = {
    "vendor.rs": (
        "crates/rsk-fido/src/vendor.rs",
        "980 lines, and its 894-901 / 962-968 are the BACKUP_FINALIZE and"
        " mark_backup_sealed the model describes; firmware/src/vendor.rs is 197",
    ),
}

#: The citations a row landed over, each with the commit that rotted it. Empty
#: today: the two this guard shipped with — `reset.rs:126-132`, whose range
#: `a430f2d` had moved onto a blank line, and the bare `presence.rs`, which
#: `4798668` made resolve two ways — were both re-pointed by `formal/` itself.
#:
#: Checked in both directions, like `kani_gate.py`'s exclusions: an entry that no
#: longer fires is stale and fails, so each one ends when its citation is fixed.
PENDING: dict[str, str] = {}

#: Below this a page is not citing, it is failing to be parsed. Today: 111, 40, 82.
FLOOR = 25

#: Pages that legitimately cite fewer than the default — a smaller model is not a
#: broken regex, and padding a page to clear a floor is the failure this guard's
#: own docstring warns against. `RSKeyStore.tla` is the flash layer, a tight model
#: with 18 load-bearing citations; a floor of 9 still trips a regex that has
#: stopped matching (it finds ~0) without demanding the page be inflated.
FLOOR_BY_PAGE = {
    "RSKeyStore.tla": 9,
    "RSKeyRetryLattice.tla": 6,
    "RSKeyAdminSurface.tla": 5,
    "RSKeyTrustedDisplay.tla": 6,
    "RSKeyBootHardening.tla": 6,
    "RSKeyTransport.tla": 5,
}


def floor_for(page):
    return FLOOR_BY_PAGE.get(page.name, FLOOR)

#: `path.rs:12`, `path.rs:12-20`, `path.rs:12-20, 44`, and the continuation
#: `` `:44` `` that both pages use for a second reference to the same file. The
#: bare form must sit right after a backtick so ordinary prose punctuation is not
#: read as a line number.
#: Every dash a prose editor can leave behind. An en dash reads as a citation to
#: a single line with the upper bound silently discarded, in two pages whose prose
#: already uses `—` and `·` throughout — measured: `state.rs:284–99991` passed.
DASH = "-\u2010\u2011\u2012\u2013\u2014\u2212"
CITE = re.compile(
    r"(?:(?<![\w/.-])(?P<file>[\w./-]+\.rs)|(?<=`))"
    rf":\s*(?P<refs>\d+(?:\s*[{DASH}]\s*\d+)?(?:\s*,\s*\d+(?:\s*[{DASH}]\s*\d+)?)*)"
)
SPAN = re.compile(rf"(\d+)(?:\s*[{DASH}]\s*(\d+))?")


def resolve(rel, tracked):
    """(the file a citation names, a complaint). A `/` makes it a path, verbatim."""
    if "/" in rel:
        return (rel, None) if rel in tracked else (None, None)
    hits = [f"{d}/{rel}" for d in SEARCH if f"{d}/{rel}" in tracked]
    if len(hits) < 2:
        return (hits[0] if hits else None), None
    picked, why = AMBIGUOUS.get(rel, (None, None))
    if picked in hits:
        return picked, None
    return hits[0], (
        f"`{rel}` is in {len(hits)} of the search directories"
        f" ({', '.join(hits)}); write the path, or register which one is meant"
        + (f" (registered: {picked}, {why})" if picked else "")
    )


def citations(text):
    """(line number, file or None, start, end, the citation as written) per page.

    `file` is None for a continuation. The line number comes out too because the
    binding is per line: `seen` used to live for a whole page, so a bare `` `:1` ``
    three hundred lines below the last named file bound to it and passed.
    """
    for number, line in enumerate(text.splitlines(), 1):
        for found in CITE.finditer(line):
            for span in SPAN.finditer(found.group("refs")):
                start = int(span.group(1))
                end = int(span.group(2)) if span.group(2) else start
                yield number, found.group("file"), start, end, found.group(0)


def audit(root):
    """(problems, one-line summary) for how the model cites this checkout."""
    root = pathlib.Path(root)
    # git's answer, like the other guards: a filesystem walk also finds the
    # agent worktrees under `.claude/` and the generated `book/`, whole second
    # copies of the tree in which a citation would resolve to the wrong file.
    tracked = {str(rel) for rel in gate_lines.tree_files(root) if rel.suffix == ".rs"}
    lengths, problems, total, said, carried = {}, [], 0, set(), set()

    def note(key, complaint):
        """A problem, unless it is one this row landed over and has not fixed."""
        if key in PENDING:
            carried.add(key)
        else:
            problems.append(complaint)

    for missing in (d for d in SEARCH if not (root / d).is_dir()):
        problems.append(f"{missing} is in SEARCH but is not a directory any more")
    for page in PAGES:
        if not (root / page).is_file():
            problems.append(f"{page} is gone; the model's citations are unchecked")
            continue
        text = (root / page).read_text()
        blank = {n for n, line in enumerate(text.splitlines(), 1) if not line.strip()}
        seen, at, here = None, 0, 0
        for number, name, start, end, written in citations(text):
            here += 1
            if any(n in blank for n in range(at + 1, number)):
                # A continuation binds within its own PARAGRAPH. Page-wide, a
                # bare `:1` bound to a file named hundreds of lines earlier and
                # was checked against it; line-wide, a sentence that wraps in a
                # markdown table loses the file it named one line up.
                seen = None
            at = number
            if name:
                seen, complaint = resolve(name, tracked)
                if complaint and complaint not in said:
                    said.add(complaint)
                    note(name, f"{page}: {complaint}")
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
            if start < 1:
                # `:0` is not a line. It slipped past both bounds checks and then
                # read `body[-1]`, so it silently asserted about the LAST line.
                problems.append(f"{page}: `{written}` names line 0, which is not a line")
            elif start > end:
                problems.append(f"{page}: `{written}` runs backwards")
            elif end > len(body):
                note(written, f"{page}: `{written}` -> {seen}, which has {len(body)} lines")
            elif not body[start - 1].strip() or not body[end - 1].strip():
                note(
                    written,
                    f"{page}: `{written}` -> {seen}, whose cited line is blank;"
                    " the code it named has moved",
                )
        floor = floor_for(page)
        if here < floor:
            problems.append(
                f"{page} yielded {here} citations, under the floor of {floor}:"
                " the page stopped citing, or this guard stopped reading it"
            )
        total += here
    for key in sorted(set(PENDING) - carried):
        problems.append(
            f"`{key}` is in PENDING ({PENDING[key]}) but no longer rots; delete the entry"
        )
    assurance_gate.check_property_tags(root, problems)
    debt = f", {len(carried)} carried" if carried else ""
    return problems, (
        f"citation-gate: ok — {total} citations across {len(PAGES)} pages resolve; "
        f"phase-1 property tags close both ways{debt}"
    )


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("citation-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nThe model's `file.rs:line` citations are the only bridge between it\n"
            "and the code it abstracts. One that no longer resolves sends the next\n"
            "reader somewhere the claim was never true. Its phase-1 property tags\n"
            "must also resolve model→code and code→model. Repair or drop the claim."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
