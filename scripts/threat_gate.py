#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold each P0-family property against the threat it is against.

`docs/threat-model.md` is the root of the evidence chain every claim in
`assurance/properties.toml` hangs from, and 33 rows cited it by the file name
alone. "Against the threat model" names no threat: a property with no clause
behind it is either mis-scoped or unnecessary, and neither was visible — while a
stated threat with no property behind it was not visible either.

Four rules, and the third is the one the file exists for:

* the clause SET is derived from the markdown — every heading and every list
  item — and `assurance/threat_clauses.toml` must name each one exactly once. A
  new bullet is then a clause nobody classified, and a clause whose locked first
  line moved or was reworded is a citation gone stale, both red. The lock is
  content, not a line number: text inserted above a clause does not rot it.
* every P0-family property (the `p0-launch` + `p0b` tranches of
  `assurance/configurations.toml`, which is where "P0 family" is defined once)
  cites at least one `defence` clause as `docs/threat-model.md#ID`. The bare
  `docs/threat-model.md` spelling no longer satisfies it — naming the file is
  what this row was written to stop.
* a property with no clause is a FINDING, not a blank, and says which of the two
  it is: `missing-clause` (the page does not state a threat this tree defends
  against) or `defends-nothing`. Exactly one of the two lists holds each P0 row:
  an entry that is untraced AND cites a clause is a stale exemption and refused,
  and so is one for a property that has left the family. What is NOT refused is
  an entry for a property some clause on the page would now serve. WHICH clause
  serves which row is the judgement `why` records and nothing reads for truth, so
  there is nothing here to derive it from — and nothing backstops it either:
  measured, adding a clause while leaving the stale entry reddens only
  `test_threat_gate.py`'s ratchet, on the CLAUSE count, and bumping
  `FLOOR_CLAUSES` the way that failure asks for leaves both rows green with the
  exemption still standing. Deleting the entry is on whoever writes the clause;
  the report below prints the two halves side by side so it is at least legible.
* a `where` locks a clause's FIRST LINE and nothing under it, so a verdict
  elsewhere can rest on a sentence that is free to be rewritten. `rests_on` pins
  those sentences, and WHICH ones are owed is derived rather than remembered: an
  `[[untraced]]` whose `why` argues from a clause owes a pin inside that clause,
  and a clause body that hands part of its claim to a `PLAT-…` assumption owes a
  pin on the sentence that names it.

What it cannot say, like its siblings: whether a mapping is RIGHT. `why` is prose
and nothing reads it for truth. What it keeps honest is that the mapping is
total in both directions, that a cited clause is really on the page, that the
sentence a verdict argues from is still in the clause it argues from, and that a
row with no threat behind it says so out loud instead of reading as traced.

The unserved `defence` clauses are printed rather than refused: `firmware-flavor`
sections like anti-rollback or supply chain are real defences that no *state*
property is about, and refusing them would push a false mapping into the
registry. They are the other half of the finding and belong in front of a reader,
not in an exit code.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

import matrix_gate
import platform_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

DOC = pathlib.Path("docs/threat-model.md")
CLAUSES = pathlib.Path("assurance/threat_clauses.toml")
#: One definition of "the registry" and one of "the P0 family", both borrowed
#: rather than restated: a second copy of the tranche lists is the failure the
#: header of `assurance/properties.toml` is about.
REGISTRY = matrix_gate.REGISTRY
LEDGER = matrix_gate.LEDGER
#: The platform registry, borrowed for the same reason: a clause that hands part
#: of its claim to a `PLAT-…` assumption is held against the file that owns those
#: ids, never against a second list of them kept here.
ASSUMPTIONS = platform_gate.REGISTRY

#: A clause reference inside a `source` entry. The fragment is a registry id, not
#: a rendered anchor — `docs/threat-model.md` carries no HTML anchors.
REF = re.compile(rf"^{re.escape(str(DOC))}#([A-Z][A-Z0-9-]*)$")
#: An in-tree path used as a source, with the optional ` — section` tail the
#: registry already writes for `formal/README.md`. Checked for existence, so the
#: day stage 9C/9D/10 cite `docs/ct-audit.md`, `docs/unsafe.md` or
#: `docs/limitations.md` the citation is held to a file that is really there.
PATH_SOURCE = re.compile(r"^([A-Za-z0-9_./-]+\.(?:md|toml|tla|rs|py|sh))(?: — .*)?$")

KINDS = ("defence", "context")
#: What a P0-family row with no clause IS. Three, and the third arrived because
#: two of these rows had a `verdict` that contradicted their own `why`:
#: `missing-clause` says WRITE the clause, and `SEC-FIDO-007`'s why argues at
#: length that writing one would be worse — `formal/README.md` records the
#: invariant as inert on the shipped tree, so a clause would be a threat model
#: stronger than its firmware, the one direction this page may not be wrong in.
#: A register whose verdict column disagrees with its own reasoning is the
#: verdict column this file exists to replace.
VERDICTS = ("missing-clause", "defends-nothing", "would-overclaim")

#: The two verdicts that are DECISIONS rather than deferrals, and so are the
#: maintainer's. `missing-clause` is a page standing behind code that already
#: defends the threat and a contributor can close it by writing the clause;
#: saying a P0-family property defends nothing, or that its clause may never be
#: written, is not that.
MAINTAINER_VERDICTS = ("defends-nothing", "would-overclaim")

#: Floors AT today's counts, in the shape the rest of `scripts/` uses them: a
#: derivation that finds nothing satisfies every rule below over an empty roster.
#: 50 clauses is the page as it stands and 41 the P0 family as the tranches stand;
#: shrinking either for real is a deliberate edit here, in the same diff.
FLOOR_CLAUSES = 50
FLOOR_P0 = 41
#: The untraced list is a finding register, and a finding register that grows
#: silently is a hatch. Raising this is the deliberate admission that another
#: property has no threat behind it. THIS row holds it as a strict upper bound;
#: what holds it EQUAL, so that closing one is a deliberate edit too, is a
#: DIFFERENT gate row — `test_threat_gate.py`'s ratchet case, under
#: `pytest (gate scripts)` and not `threat-model traceability`. Three of the five
#: were closed at once by `TM-HOST-READ-FAULT`, which is what left it at two, and
#: both survivors were P0b until the counterpoint read the third: a link is not
#: coverage, and SEC-FIDO-007 came BACK here for it. The two P0b survivors are
#: closed now, one clause each — `TM-HOST-ALGO-CHANGE` and `TM-HOST-OTP-REPLAY` —
#: which leaves only the row whose verdict says the clause may never be written.
CEILING_UNTRACED = 1
#: A `why` shorter than this is a shrug with a verdict column. Same floor and
#: same reason as `matrix_gate.FLOOR_WORDS`, borrowed rather than re-picked.
FLOOR_WORDS = matrix_gate.FLOOR_WORDS
#: Who owes each untraced finding its clause. Borrowed the same way, from the
#: register that chose the four roles — an obligation nobody owns is a wish, and
#: this list is a register of obligations. Every entry today is `contributor`,
#: because a `missing-clause` finding is a page that is behind code already
#: defending the threat; a `defends-nothing` verdict, which no entry has yet,
#: says a P0-family property is against nothing and is the maintainer's.
OWNERS = platform_gate.OWNERS

#: What each record of `assurance/threat_clauses.toml` may say, and which tables
#: the file may have. `matrix_gate`'s `[[cell]]` has refused a stray field since
#: it shipped and its `[[question]]` did not, which is how the hole was found;
#: asked of this file, NEITHER record had a list and neither did the file, so a
#: key or a whole section added here was read by nothing and printed by nothing.
CLAUSE_FIELDS = ("id", "kind", "where", "why", "rests_on")
UNTRACED_FIELDS = ("id", "verdict", "why", "rests_on", "owner")
CLAUSE_TABLES = ("clause", "untraced")


#: A fence, in both of CommonMark's spellings and at any indent. Three of them
#: is the minimum, and a longer run is the same fence, so `startswith` after the
#: indent is the whole rule.
FENCE = re.compile(r"^\s*(?:```|~~~)")
#: A heading at ANY level, not the two this page happens to use: an `####` under
#: a section would otherwise be a clause the derivation cannot see, which is the
#: only direction that fails silently. Over-detection reddens instead.
HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
#: A list item in every marker CommonMark takes. The page writes `-` throughout;
#: `*`, `+` and an ordered item are the same clause written by someone else.
ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
#: A setext underline directly under text — a heading this derivation cannot see.
#: The "previous line is prose" test keeps an ordinary thematic break (blank
#: line, `---`, blank line) out of it. `-+` and not `-{3,}`: CommonMark makes a
#: SINGLE `-` an H2, and the first draft of this line demanded three, so the two
#: shortest spellings of the thing it refuses were the two it could not see.
SETEXT = re.compile(r"^\s*(?:=+|-+)\s*$")
#: Shapes that can carry a clause and that nothing above can read: a blockquote
#: callout, a table row, an HTML list. Refused rather than missed, for the reason
#: the whole file exists — a clause the derivation cannot see is the one
#: direction that fails green. A table is the likeliest: this repo's other docs
#: enumerate exactly this kind of thing in one.
UNREADABLE = re.compile(r"^\s*(?:>|\||</?(?:ul|ol|li|table|tr|dl|dt|dd)\b)")
#: A clause id, in the one spelling `source` can cite (`REF` takes `[A-Z]…`), so
#: a `TM-Host-Fuzz` is refused here rather than surfacing later as a message that
#: blames the citing row's spelling.
CLAUSE_ID = re.compile(r"TM-[A-Z0-9]+(?:-[A-Z0-9]+)*")
#: A platform-assumption id, in `assurance/platform.toml`'s spelling. A clause
#: body that writes one is handing part of its claim to an obligation discharged
#: somewhere else, which is a dependency and therefore owes a `rests_on` pin.
PLAT_ID = re.compile(r"PLAT-[A-Z0-9]+(?:-[A-Z0-9]+)*")
#: An HTML comment, stripped out of a clause body before anything is matched
#: against it. Commenting a sentence OUT takes it off the rendered page and
#: leaves it verbatim in the source, which is the one edit a substring lock reads
#: as no edit at all; a comment spliced mid-sentence renders as nothing and is
#: correctly no edit at all. Both fall out of removing them first.
COMMENT = re.compile(r"<!--.*?-->", re.S)
#: An inline code span, removed before the tag test below: `Fs<S>` in backticks
#: renders literally and hides nothing, and it is the only `<` this page has.
CODE_SPAN = re.compile(r"`[^`]*`")
#: A raw HTML tag. Inside a clause body some verdict PINS, this is refused rather
#: than interpreted — `<span hidden>`, `style="display:none"`, `<details>` and
#: `<script>` each keep a sentence in the source and off the page, and a rule that
#: enumerates which tags hide is a renderer with a shorter list than a browser's.
RAW_HTML = re.compile(r"</?[A-Za-z]")


def clause_units(text: str, problems: list[str] | None = None) -> list[tuple[int, str, str]]:
    """(line, enclosing section, first line) for every addressable clause.

    A heading or a list item, which is the whole structure this page has. Fenced
    blocks are skipped: the seed-backup mermaid diagram carries `-` lines that
    are arrows, not clauses. Lines are `rstrip`ped, so trailing whitespace is not
    a clause moving.
    """
    units: list[tuple[int, str, str]] = []
    section, fenced, previous = "", False, ""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if FENCE.match(line):
            fenced = not fenced
            previous = line
            continue
        if fenced:
            previous = line
            continue
        heading = HEADING.match(line)
        if heading:
            section = heading.group(2)
            units.append((number, section, line))
        elif ITEM.match(line):
            units.append((number, section, line))
        elif problems is None:
            pass
        elif SETEXT.match(line) and previous.strip():
            problems.append(
                f"{DOC}:{number}: a setext heading (or a thematic break under"
                " text) — this derivation reads `#` headings only, so a clause"
                " written that way would be invisible to it"
            )
        elif UNREADABLE.match(line):
            problems.append(
                f"{DOC}:{number}: a blockquote, table row or HTML list — a clause"
                " in one is invisible to this derivation. Write it as a `#`"
                f" heading or a `-` item: {line.strip()[:40]!r}"
            )
        previous = line
    return units


def blank_comments(text: str) -> str:
    """Every commented-out run, replaced by spaces, line count preserved.

    Whole-page and not per-clause: a `<!--` opened under one clause and closed
    under a later one hides text in BOTH, and stripping inside a body could not
    see either end of it. An unterminated one hides to the end of the page, which
    is what a browser does with it. Blanks rather than deletes so the line numbers
    `clause_units` already handed out still address the same lines.
    """
    blank = lambda run: re.sub(r"[^\n]", " ", run)  # noqa: E731 - one expression
    text = COMMENT.sub(lambda m: blank(m.group(0)), text)
    opened = text.find("<!--")
    return text if opened < 0 else text[:opened] + blank(text[opened:])


def clause_bodies(text: str, units: list[tuple[int, str, str]]) -> dict[str, str]:
    """first line -> everything UNDER it, down to the next clause, as one run.

    Whitespace is normalised, HTML comments and fenced blocks are dropped, so
    what is matched is the page's prose as far as MARKDOWN decides it. Past that
    it does not guess: raw HTML in a body some verdict pins is refused in
    `check_rests_on`, because `<span hidden>` renders to nothing and reads here
    as text still on the page. A pin is a sentence, not a
    layout: re-wrapping a paragraph or re-indenting a bullet leaves the same
    sentence, while a reword, a deletion, a character swap or a move into a
    comment or a code sample does not. Measured with THIS function over
    `git log --reverse 3d6ec61 -- docs/threat-model.md`, the page as it stood
    when the choice was made: 34 clause bodies changed with their first line
    intact against 12 first lines reworded, so a whole-body hash would have
    fired on 20 of those 30 commits — an alarm that is usually noise, and a
    suppressed ratchet is worse than none.
    """
    lines = blank_comments(text).splitlines()
    bodies: dict[str, str] = {}
    for index, (number, _section, first) in enumerate(units):
        end = units[index + 1][0] - 1 if index + 1 < len(units) else len(lines)
        # Fenced lines are dropped for the same reason `clause_units` skips them:
        # what is inside a fence is a sample, not a sentence the page asserts.
        kept, fenced = [], False
        for line in lines[number:end]:
            if FENCE.match(line):
                fenced = not fenced
            elif not fenced:
                kept.append(line)
        # `setdefault`: two clauses reading alike is already its own finding, and
        # a second body under the same key would only hide which one moved.
        bodies.setdefault(first, " ".join("\n".join(kept).split()))
    return bodies


def load(root: pathlib.Path, path: pathlib.Path) -> dict:
    return tomllib.loads((root / path).read_text(encoding="utf-8"))


def p0_family(root: pathlib.Path) -> list[str]:
    """The P0-family ids, in registry order, from the tranche lists."""
    doc = load(root, LEDGER).get("tranche", {})
    tranche = {pid: name for name in matrix_gate.TRANCHES for pid in doc.get(name, [])}
    ids = [entry.get("id") for entry in load(root, REGISTRY).get("property", [])]
    return [pid for pid in ids if tranche.get(pid) in matrix_gate.ROW_TRANCHES]


def check_clauses(
    root: pathlib.Path, problems: list[str]
) -> tuple[dict[str, dict], dict[str, str]]:
    """The roster, held against the page in both directions, and the bodies."""
    text = (root / DOC).read_text(encoding="utf-8")
    units = clause_units(text, problems)
    by_line: dict[str, list[int]] = {}
    for number, _section, line in units:
        by_line.setdefault(line, []).append(number)
    for line, numbers in sorted(by_line.items()):
        if len(numbers) > 1:
            problems.append(
                f"{DOC}: lines {numbers} read identically — two clauses this"
                f" roster cannot address apart: {line.strip()[:60]!r}"
            )
    if len(units) < FLOOR_CLAUSES:
        problems.append(
            f"{DOC}: derived {len(units)} clause(s), under the floor of"
            f" {FLOOR_CLAUSES} — the page shrank, or the derivation stopped"
            " seeing it. Shrink the floor here in the same diff"
        )

    document = load(root, CLAUSES)
    for table in sorted(set(document) - set(CLAUSE_TABLES)):
        problems.append(
            f"{CLAUSES}: carries a `{table}` table, which is not one of"
            f" {list(CLAUSE_TABLES)} — a section of this file no reader reads"
        )
    entries = document.get("clause", [])
    clauses: dict[str, dict] = {}
    for index, entry in enumerate(entries, 1):
        cid, where = entry.get("id"), entry.get("where")
        if not cid or not where:
            problems.append(f"{CLAUSES}: clause #{index} has no id or no `where`")
            continue
        if not CLAUSE_ID.fullmatch(cid):
            problems.append(
                f"{CLAUSES}: {cid!r} is not a clause id — `source` can only cite"
                " `TM-` and upper case, so any other spelling is uncitable"
            )
            continue
        if cid in clauses:
            problems.append(f"{CLAUSES}: duplicate clause id {cid}")
            continue
        if twin := next((c for c, e in clauses.items() if e["where"] == where), None):
            problems.append(
                f"{cid} and {twin} claim the same clause of {DOC} — one unit, one"
                " entry, or the page is classified twice and can be classified"
                " two ways at once"
            )
            continue
        if entry.get("kind") not in KINDS:
            problems.append(
                f"{cid}: kind {entry.get('kind')!r} is not one of {list(KINDS)}"
            )
        if entry.get("kind") == "context" and len(entry.get("why", "").split()) < FLOOR_WORDS:
            problems.append(
                f"{cid}: `context` says no property can serve this clause, and under"
                f" {FLOOR_WORDS} words that is an assertion with no argument"
            )
        if where not in by_line:
            problems.append(
                f"{cid}: `where` is not a clause of {DOC} any more — it was"
                f" reworded, deleted or re-indented: {where.strip()[:60]!r}"
            )
        if stray := sorted(set(entry) - set(CLAUSE_FIELDS)):
            problems.append(
                f"{cid}: carries {stray}, which nothing reads — the same key-nobody"
                " -holds hole its sibling record had, asked of this one"
            )
        clauses[cid] = entry

    claimed = {entry["where"] for entry in clauses.values()}
    for number, section, line in units:
        if line not in claimed:
            problems.append(
                f"{DOC}:{number}: a clause nobody classified — add it to {CLAUSES}"
                f" as `defence` or `context` (under {section!r}): {line.strip()[:60]!r}"
            )
    return clauses, clause_bodies(text, units)


def check_sources(
    root: pathlib.Path,
    clauses: dict[str, dict],
    family: list[str],
    problems: list[str],
) -> dict[str, list[str]]:
    """property id -> the clauses it cites, with every citation validated."""
    cited: dict[str, list[str]] = {}
    p0 = set(family)
    for entry in load(root, REGISTRY).get("property", []):
        pid = entry.get("id", "?")
        for source in entry.get("source", []):
            ref = REF.match(source)
            if ref:
                cid = ref.group(1)
                if cid not in clauses:
                    problems.append(
                        f"{pid}: source names {cid}, which is no clause of {CLAUSES}"
                    )
                elif clauses[cid].get("kind") != "defence":
                    problems.append(
                        f"{pid}: source names {cid}, which is"
                        f" {clauses[cid].get('kind')!r} and not a `defence` — assets,"
                        " an out-of-scope declaration or a process is not a threat a"
                        " property can be against"
                    )
                elif cid not in cited.setdefault(pid, []):
                    cited[pid].append(cid)
                continue
            if source == str(DOC):
                if pid in p0:
                    problems.append(
                        f"{pid}: source says {DOC} and nothing more — say WHICH"
                        f" clause, as `{DOC}#TM-…`"
                    )
                continue
            if DOC.name in source:
                # Anything else naming the page: `#tm-host-gates`, `./docs/…`,
                # a trailing slash. Each falls through every rule above while
                # LOOKING traced, which is the one outcome worth refusing.
                problems.append(
                    f"{pid}: {source!r} names the threat model in a spelling this"
                    f" row cannot resolve — write it as `{DOC}#TM-…`"
                )
                continue
            path = PATH_SOURCE.match(source)
            if path and not (root / path.group(1)).exists():
                problems.append(
                    f"{pid}: source cites {path.group(1)}, which is not in the tree"
                )
    return cited


def check_untraced(
    root: pathlib.Path,
    cited: dict[str, list[str]],
    family: list[str],
    problems: list[str],
) -> dict[str, dict]:
    entries = load(root, CLAUSES).get("untraced", [])
    untraced: dict[str, dict] = {}
    for index, entry in enumerate(entries, 1):
        pid = entry.get("id")
        if not pid:
            problems.append(f"{CLAUSES}: untraced #{index} has no id")
            continue
        if pid in untraced:
            problems.append(f"{CLAUSES}: {pid} is untraced twice")
            continue
        untraced[pid] = entry
        if pid not in family:
            problems.append(
                f"{pid}: untraced, but it is not a P0-family property — this list is"
                " the P0 family's finding register, not a place to park a row"
            )
        if entry.get("verdict") not in VERDICTS:
            problems.append(
                f"{pid}: verdict {entry.get('verdict')!r} is not one of"
                f" {list(VERDICTS)} — a row with no threat behind it is one of"
                " exactly those two things"
            )
        if len(entry.get("why", "").split()) < FLOOR_WORDS:
            problems.append(
                f"{pid}: untraced with a `why` under {FLOOR_WORDS} words — the"
                " finding IS the why, and `TODO` is not one"
            )
        if entry.get("owner") not in OWNERS:
            problems.append(
                f"{pid}: untraced and owed by {entry.get('owner')!r}, which is not"
                f" one of {sorted(OWNERS)} — this is a register of obligations, and"
                " an obligation nobody owns is a wish with a verdict column"
            )
        if entry.get("verdict") in MAINTAINER_VERDICTS and entry.get("owner") != "maintainer":
            problems.append(
                f"{pid}: verdict {entry.get('verdict')!r} owed by"
                f" {entry.get('owner')!r} — that verdict is a DECISION about what"
                " this project will never claim, not a piece of work a"
                " contributor can finish, and only the maintainer makes it"
            )
        if stray := sorted(set(entry) - set(UNTRACED_FIELDS)):
            problems.append(
                f"{pid}: untraced and carrying {stray}, which nothing reads — a key"
                " no rule holds is one the page never shows either"
            )
        if pid in cited:
            problems.append(
                f"{pid}: untraced and citing {', '.join(cited[pid])} — a stale"
                " exemption reads as a finding that is still open"
            )
    if len(untraced) > CEILING_UNTRACED:
        problems.append(
            f"{len(untraced)} untraced P0-family propert(ies), over the ceiling of"
            f" {CEILING_UNTRACED} — another property with no threat behind it is a"
            " deliberate admission; raise the ceiling here in the same diff"
        )
    return untraced


def check_rests_on(
    root: pathlib.Path,
    clauses: dict[str, dict],
    bodies: dict[str, str],
    untraced: dict[str, dict],
    problems: list[str],
) -> None:
    """The sentences below a locked first line that some verdict rests on.

    `where` is the clause's thesis and the rest of it is free text, so a verdict
    argued from a sentence FURTHER DOWN can be falsified by an edit this file
    never sees. Deleting the one that scopes the power-cut clause away from
    faulted reads is the worked example: three untraced verdicts turn wrong and
    every rule above stays green.

    The pins are not a list somebody has to remember to extend. Both halves are
    read off the tree — an `[[untraced]]` `why` that names a clause id IS the
    dependency, and a clause body that names a `PLAT-…` id IS the hand-off — so
    a new one arrives owing a pin instead of arriving unlocked. What this does
    not reach: a sentence load-bearing for a reason no entry registers.
    """
    rows = load(root, ASSUMPTIONS).get("assumption", [])
    assumptions = {r.get("id") for r in rows if isinstance(r, dict)}
    # (label, entry, hosts, owed). HOSTS is whose body may carry this entry's
    # pins — a clause pins inside itself, an untraced verdict inside the clause
    # its `why` argues from, so a pin cannot drift onto text the verdict never
    # mentioned. OWED is the narrower set a pin is DEMANDED for, and it is empty
    # for a clause: naming itself is not a dependency, `PLAT-…` below is.
    dependents: list[tuple[str, dict, list[str], list[str]]] = [
        (cid, entry, [cid], []) for cid, entry in clauses.items()
    ]
    for pid, entry in untraced.items():
        named = dict.fromkeys(CLAUSE_ID.findall(entry.get("why", "")))
        argues = [cid for cid in named if cid in clauses]
        # An id that resolves to no clause would otherwise DROP the demand below:
        # a `why` arguing from `TM-HOST-POWERCUT` owes a pin nowhere, so one typo
        # buys the exemption this rule exists to refuse.
        for cid in named:
            if cid not in clauses:
                problems.append(
                    f"{pid}: its `why` argues from {cid}, which is no clause of"
                    f" {CLAUSES} — a verdict cannot rest on a clause that is not"
                    " there, and a misspelt id owes a pin to nothing"
                )
        dependents.append((pid, entry, argues, argues))

    for label, entry, owners, owed in dependents:
        pins = entry.get("rests_on", [])
        if not isinstance(pins, list) or not all(isinstance(pin, str) for pin in pins):
            problems.append(
                f"{label}: `rests_on` is a list of verbatim sentences from a clause"
                f" body of {DOC}, and this is not one"
            )
            continue
        hosts = {cid: bodies.get(clauses[cid]["where"], "") for cid in owners}
        for cid, body in hosts.items():
            if pins and RAW_HTML.search(CODE_SPAN.sub(" ", body)):
                whose = "its" if cid == label else f"{cid}'s"
                problems.append(
                    f"{label}: {whose} body carries raw HTML, and a pin inside it"
                    " promises a sentence is on the page. Past markdown this row"
                    " cannot tell what renders — `<span hidden>` and `<details>`"
                    " leave the text in the source and take it off the page"
                )
        landed: set[str] = set()
        for pin in pins:
            want = " ".join(pin.split())
            if not want:
                problems.append(f"{label}: an empty `rests_on` pin locks nothing")
                continue
            here = [cid for cid, body in hosts.items() if want in body]
            landed.update(here)
            if here:
                continue
            # Say WHERE it went when it went somewhere: a sentence moved to a
            # sibling bullet reads as a reword, and the two want different fixes.
            elsewhere = [c for c, e in clauses.items() if want in bodies.get(e["where"], "")]
            moved = f" — it is under {', '.join(elsewhere)} now" if elsewhere else ""
            problems.append(
                f"{label}: `rests_on` pins text that is no longer in the body of"
                f" {' / '.join(owners) or '(no clause)'}{moved}. It was reworded,"
                f" deleted or split, and the verdict resting on it was not:"
                f" {want[:60]!r}"
            )
        for cid in owed:
            if cid not in landed:
                problems.append(
                    f"{label}: its `why` argues from {cid}, so it owes a `rests_on`"
                    f" pin inside {cid} — {CLAUSES} locks that clause's first line"
                    " only, and the sentence this rests on is below it"
                )
        if label not in clauses:
            continue
        for plat in dict.fromkeys(PLAT_ID.findall(bodies.get(entry["where"], ""))):
            if plat not in assumptions:
                problems.append(
                    f"{label}: its body names {plat}, which is no assumption of"
                    f" {ASSUMPTIONS} — a clause cannot hand its claim to a row that"
                    " is not there"
                )
            elif not any(plat in pin and len(pin.split()) >= FLOOR_WORDS
                         for pin in pins):
                problems.append(
                    f"{label}: its body hands part of its claim to {plat}, so it"
                    f" owes a `rests_on` pin on the sentence naming it — without one"
                    " that sentence can go, and the clause reads as a defence this"
                    " firmware implements"
                )


def audit(root) -> tuple[list[str], list[str], str]:
    """(problems, the report a reader needs, one-line summary) for this checkout."""
    root = pathlib.Path(root)
    problems: list[str] = []
    # A missing or unparseable input is a finding with a sentence, not a
    # traceback: the row goes red either way, and only one of the two says what
    # to do about it.
    for path in (DOC, CLAUSES, REGISTRY, LEDGER, ASSUMPTIONS):
        if not (root / path).is_file():
            problems.append(f"{path} is missing — the mapping is unchecked")
            return problems, [], "threat-gate: nothing to check"
    for path in (CLAUSES, REGISTRY, LEDGER, ASSUMPTIONS):
        try:
            load(root, path)
        except tomllib.TOMLDecodeError as error:
            problems.append(f"{path} cannot be read: {error}")
            return problems, [], "threat-gate: nothing to check"
    clauses, bodies = check_clauses(root, problems)
    family = p0_family(root)
    cited = check_sources(root, clauses, family, problems)
    if len(family) < FLOOR_P0:
        problems.append(
            f"{len(family)} P0-family propert(ies), under the floor of {FLOOR_P0} —"
            " the tranche lists shrank, and fewer rows owe a threat than when this"
            " floor was set. Shrink it here in the same diff"
        )
    untraced = check_untraced(root, cited, family, problems)
    check_rests_on(root, clauses, bodies, untraced, problems)
    for pid in family:
        if pid not in cited and pid not in untraced:
            problems.append(
                f"{pid}: no threat-model clause and no untraced verdict — name the"
                f" clause it serves as `{DOC}#TM-…`, or record in {CLAUSES} which of"
                f" {list(VERDICTS)} it is"
            )

    serves: dict[str, list[str]] = {}
    others: dict[str, list[str]] = {}
    for pid, ids in cited.items():
        for cid in ids:
            (serves if pid in family else others).setdefault(cid, []).append(pid)
    report = []
    for cid, entry in clauses.items():
        if entry.get("kind") != "defence":
            continue
        owners = serves.get(cid, [])
        # The outside-family owners are appended in BOTH branches: printing them
        # only when the P0 column is empty made a clause look thinner than it is,
        # and read as "answered only outside the family" when it was not.
        outside = f" (+ outside the P0 family: {', '.join(others[cid])})" if cid in others else ""
        rest = ", ".join(owners) if owners else "— no registered property"
        report.append(f"  {cid:<30} {len(owners):>2}  {rest}{outside}")
    for pid, entry in untraced.items():
        # The owner is printed, not just held: a field no reader ever sees is
        # the same field-nothing-reads hole as one no rule holds, one step out.
        report.append(
            f"  {pid:<30}  -  untraced [{entry.get('verdict')},"
            f" {entry.get('owner')}]"
        )
    defences = [c for c in clauses.values() if c.get("kind") == "defence"]
    summary = (
        f"threat-gate: ok — {len(clauses)} clause(s) ({len(defences)} defence,"
        f" {len(clauses) - len(defences)} context), {len(family) - len(untraced)}"
        f" of {len(family)} P0-family properties traced,"
        f" {len(serves)} clause(s) served, {len(untraced)} untraced"
    )
    return problems, report, summary


def run(root: pathlib.Path) -> int:
    problems, report, summary = audit(root)
    for line in report:
        print(line)
    if problems:
        print(f"threat-gate: {len(problems)} finding(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main() -> int:
    if sys.argv[1:]:
        print("usage: threat_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
