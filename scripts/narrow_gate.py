#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Give the narrower-than-the-firmware roster a reader, and each row a tree.

Stage 4's exit asks that "all narrower abstractions are either closed or carry a
separate complementary source obligation". The roster it asks that of is the
`### Narrower than the firmware` list on `formal/README.md`, and NOTHING READ IT.
Measured before this file: `grep -rn "Narrower than the firmware" scripts/`
found no reader, and deleting a whole bullet was exit 0 on `citation_gate.py`,
`claims_gate.py`, `run_count_gate.py`, `threat_gate.py`, `evidence_gate.py`,
`scope_gate.py`, `config_gen_gate.py` and `comutate.py --lint` alike.

One kind of bullet did redden a row, and for the wrong property: deleting the
one carrying `crates/rsk-device/src/presence.rs:196` fails `citation_gate.py`
because `formal/citations.lock` still locks that pair. That is the CITATION going
stale, not the disposition going missing, and `--relock` clears it — so the
abstraction could still be dropped, in two commands instead of one.

So the roster moves into `assurance/abstractions.toml` and this writes the page
back from it: markers, `--write`, a byte diff, a gate row. That is the
shape `bounds_gate.py` uses on `docs/assurance-bounds.md` and `comutate.py`
already uses on this very page, rather than a ninth mechanism. The page cannot
exempt itself by saying it is generated, either: nothing here reads the "do not
edit" line, the region is REBUILT from the ledger and compared byte for byte, so
a hand edit inside the markers is a diff.

## What is registered, and what is derived

Registered, because no script can derive a judgement: the `id`, the
`disposition`, which artifacts it rests on, the `why`, and the bullet's prose.
Derived, because a hand-kept copy of a derivable fact is the rot this tree has
paid for three times: whether each cited artifact is still there, whether a
mutant configuration is still REQUIRED RED and still in a tier that runs it,
whether a platform question still carries the status the disposition claims, and
the page itself.

The disposition vocabulary is the exit criterion's own four words, and each one
may rest only on the kind of artifact that can carry it ([`ALLOWED`]) — the shape
`matrix_gate.py` uses for `disposition` × `basis`. `closed` needs a configuration
the runner runs and `floors.txt` requires RED, which is the difference between a
hole that was repaired and a paragraph that says so; `open-obligation` needs a
question that is still open somewhere else, and reddens when that question is
settled, which is when this row has to be re-decided.

## The `why`, and why non-emptiness is not a rule

Every ledger in this tree that carries a `why` checked it for `.strip()` and
nothing more. Measured the day this file was written: `why = "banana"` in
`assurance/deleters.toml` is exit 0 on `deleter_gate.py`, and the same string in
`assurance/ghost_actions.toml` is exit 0 on `ghost_gate.py`. A field that admits
a fruit is a field that will admit `TODO`, and both read as a disposition in a
verdict column. So the `why` here owes two things a scanner can check: the word
floor `matrix_gate.py` already picked for exactly this ([`FLOOR_WORDS`],
borrowed rather than re-picked), and it must NAME every artifact the row cites.
The second is the load-bearing one — it is what makes the sentence be ABOUT the
evidence rather than beside it, and it is what `"banana"` cannot satisfy at any
length.

## Limits, so the row is not read as more than it is

Nothing here can say the roster is COMPLETE. Whether some other abstraction is
narrower than the firmware and unlisted is a judgement, and the only defence
against a quiet deletion is [`ROSTER_FLOOR`], which stands ON the count this tree
has rather than under it: the roster's whole subject is completeness, so losing
one row is the defect, and a floor at a third of it would be inert. Nor can this
say a disposition is RIGHT — that `bounded-elsewhere` is honest, that the
obligation cited is the one that would find the defect. What it keeps honest is
that every listed abstraction has one of four dispositions, that the artifact
each rests on is still in the tree and still says what the disposition claims,
and that the list a reader sees is the list the ledger holds.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

import claims_gate
import matrix_gate
import scope_gate
import verdict_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

LEDGER = pathlib.Path("assurance/abstractions.toml")
PAGE = pathlib.Path("formal/README.md")
FLOORS = pathlib.Path("formal/floors.txt")
SCOPES = pathlib.Path("formal/scopes.txt")
ASSUMPTIONS = pathlib.Path("assurance/assumptions.toml")
THREATS = pathlib.Path("assurance/threat_clauses.toml")
PLATFORM = pathlib.Path("assurance/platform.toml")
MATRIX = pathlib.Path("assurance/configurations.toml")
CRATES = pathlib.Path("crates")

#: The section this roster is, spelled as the page spells it. A literal because
#: it is what a hand would retype, and the completeness half below is exactly the
#: rule that it may not be retyped anywhere else.
HEADING = "### Narrower than the firmware — the risk direction, and the whole list"
#: The marker pair, spelled like the three this page already carries
#: (`<!-- phase2-comutants:start -->`, `<!-- assurance-table:start -->`,
#: `<!-- run-count-*:start -->`).
START = "<!-- narrow-roster:start -->"
END = "<!-- narrow-roster:end -->"
GENERATED_BY = "Generated by scripts/narrow_gate.py --write; do not edit."

#: The exit criterion's own vocabulary: "closed, bounded elsewhere, accepted, or
#: a separate issue with a P-level". The fourth is spelled `open-obligation`
#: because what this tree can check is the OBLIGATION being registered and still
#: open, never the issue number.
#:
#: The value is the citation kinds that disposition may rest on. Same shape as
#: `matrix_gate.ALLOWED`, for the same reason: a basis the tree cannot disagree
#: with is how a judgement nobody made takes the strongest word in the
#: vocabulary. `closed` may not rest on a settling question, and
#: `open-obligation` may not rest on a mutant that already falls.
ALLOWED = {
    "closed": ("cfg", "platform"),
    "bounded-elsewhere": ("scopes", "assumption", "test"),
    "accepted": ("threat", "platform"),
    "open-obligation": ("question", "platform"),
}

#: What a `platform:` row's own `status` must say for each disposition that may
#: cite one. This is the whole reason that kind is allowed under three words:
#: the ledger next door already tracks whether such a question is answered, so
#: the disposition here is held to it rather than being a second opinion about
#: it. A question that gets discharged reddens the `open-obligation` row citing
#: it — which is precisely when that row has to be re-decided.
PLATFORM_STATUS = {
    "closed": "discharged",
    "accepted": "accepted-risk",
    "open-obligation": "pending",
}

#: Every field an entry may carry, so a table added here is held by no rule and
#: shown to no reader — `deleter_gate.py`'s rule, for the same failure.
FIELDS = ("id", "disposition", "cites", "why", "body")
ID = re.compile(r"NAR-[A-Z0-9]+(?:-[A-Z0-9]+)*\Z")
CITE = re.compile(r"([a-z]+):(\S+)\Z")

#: Borrowed rather than re-picked, the way `threat_gate.py` borrows it: six words
#: is what this tree decided a reason has to be to be one, and picking a second
#: number here would make two rules that mean the same thing drift apart.
FLOOR_WORDS = matrix_gate.FLOOR_WORDS

#: Stands ON the count, not under it. Every other floor in this tree that guards
#: a DERIVATION (`bounds_gate.BOUNDS_FLOOR`, `floors.txt`'s distinct-state
#: numbers) sits below its measurement so ordinary churn does not trip it; this
#: one cannot, because the roster is a hand-written list whose whole subject is
#: completeness. A floor at a third of it would be satisfied by seven of these
#: ten rows, which is the deletion it exists to refuse. It is `>=` rather than
#: `==` so a NEW abstraction can be listed without a second edit — growth is not
#: the direction anything here is worried about.
ROSTER_FLOOR = 20

#: THE ROSTER, as a SET of ids. The floor above counts rows, and the thing this
#: ledger protects is WHICH rows: measured on the count-only version, dropping
#: `NAR-TWO-TRANSPORTS` and adding a filler row saying nothing is narrowed here
#: kept the count at ten, kept this row green, kept the claims and citation rows
#: green — and took "Two transports" off the page. So the ids are named, and a
#: registered abstraction can only leave by being deleted from BOTH files, which
#: is the two-edit shape `scope_gate.MEASURED_MINIMA` uses one row over.
#:
#: The second half is DERIVED and cannot go stale the same way: every scope
#: `scope_gate.MEASURED_MINIMA` pins is a measured narrowing, so each one owes a
#: row here ([`check_coverage`]). That is what caught this ledger being nine
#: tenths one module — three of the four pinned scopes were unregistered.
REQUIRED = {
    "NAR-CARDINALITY", "NAR-PERMSETS", "NAR-WAIT-SCOPE", "NAR-BUTTON-BUILD",
    "NAR-TOKENLESS-REGISTRATION", "NAR-ABSENT-FLOWS", "NAR-TWO-TRANSPORTS",
    "NAR-OATH-REMOVAL", "NAR-ASSIGNMENT-HOLES", "NAR-GATE-FIDS",
    "NAR-STORE-FIDS", "NAR-TRANSPORT-CHANNELS", "NAR-TRANSPORT-CHUNKS",
    "NAR-OTP-COUNTER", "NAR-RETRY-LATTICE", "NAR-ADMIN-CAPS", "NAR-BOOT-WEAK",
    "NAR-RESET-WINDOW", "NAR-FLASH-WRITES", "NAR-FACTORY-WIPE",
}

#: WHAT BELONGS HERE, and the one thing that does not — said because a silent
#: omission is the defect this file exists for. In: every narrowing the page's
#: roster is about, and every scope pinned in `scope_gate.MEASURED_MINIMA`,
#: whatever module it belongs to. Out, and named rather than dropped: the FUSED
#: `FactoryWipe` step in `RSKeyAppletSeams` — the wipe and the reboot are one
#: action there, so no state exists between them — because its honest
#: disposition is an open obligation and an open obligation needs an id, which
#: for a model question means a `class = "model-abstraction"` row in
#: `assurance/platform.toml`. That file is another agent's this session, so the
#: row cannot be added; this comment is the record that it is owed, and adding it
#: is what takes the item off this list and into `REQUIRED`.
#:
#: `platform.toml`'s `model-abstraction` rows are the other direction and are NOT
#: made one-to-one with this ledger: they are per-property model questions that
#: `platform_gate.py` already holds, and a row here cites one when the page's
#: roster is about it (four do). Requiring the reverse would duplicate that
#: ledger into this one.


def die(msg):
    print(f"narrow-gate: {msg}", file=sys.stderr)
    raise SystemExit(1)


def entries(root, findings):
    """The ledger, parsed, in file order — or the problems that stopped it."""
    path = root / LEDGER
    if not path.is_file():
        findings.append(f"{LEDGER} is missing — the roster has no registry again")
        return []
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as error:
        findings.append(f"{LEDGER} cannot be read as a registry: {error}")
        return []
    if stray := sorted(set(doc) - {"abstraction"}):
        findings.append(
            f"{LEDGER} carries {stray}, which nothing reads — a table added here"
            " is held by no rule and shown to no reader"
        )
    out, seen = [], set()
    for index, entry in enumerate(doc.get("abstraction", []), 1):
        where = f"{LEDGER} #{index}"
        if not isinstance(entry, dict):
            findings.append(f"{where}: not a table")
            continue
        rid = str(entry.get("id", "")).strip()
        if not ID.fullmatch(rid):
            findings.append(f"{where}: `{rid}` is not a `NAR-*` id")
            continue
        if missing := [f for f in FIELDS if f not in entry]:
            findings.append(f"{rid}: carries no {missing}")
            continue
        if stray := sorted(set(entry) - set(FIELDS)):
            findings.append(f"{rid}: carries {stray}, which nothing reads")
        if rid in seen:
            findings.append(f"{rid}: recorded twice")
            continue
        seen.add(rid)
        out.append(entry)
    return out


def flat(text):
    """Prose as one line. A wrapped `why` splits an id across a newline, and a
    substring test on the raw string would call that a missing citation."""
    return " ".join(str(text).split())


def cites_of(entry, findings):
    """[(kind, name)] for one entry, with the malformed ones reported."""
    out = []
    raw = entry.get("cites")
    if not isinstance(raw, list) or not raw:
        findings.append(
            f"{entry['id']}: cites nothing — a disposition resting on no artifact"
            " is the sentence this file replaced, in a field"
        )
        return out
    for item in raw:
        hit = CITE.fullmatch(str(item).strip())
        if not hit:
            findings.append(f"{entry['id']}: `{item}` is not a `<kind>:<name>` citation")
            continue
        out.append((hit.group(1), hit.group(2)))
    return out


def tier_configs(root):
    """Every configuration some tier runs, from the one place that list lives.

    `run-tlc.sh --tiers` rather than an `ls` of `formal/*.cfg`, and the
    difference is the rule: a mutant that exists but is in no tier is run by
    NOTHING, and a `closed` disposition resting on one rests on a configuration
    whose RED nobody has ever seen. This tree has already paid for that class
    once, with twenty Kani harnesses.
    """
    runner = root / "formal/run-tlc.sh"
    if not runner.is_file():
        return None
    out = subprocess.run(
        [str(runner), "--tiers"], capture_output=True, text=True, cwd=runner.parent
    )
    if out.returncode != 0:
        return None
    if not out.stdout.strip():
        return None
    return {name for line in out.stdout.splitlines() if ":" in line
            for name in line.split(":", 1)[1].split()}


def toml_ids(path, table, key, findings):
    """`{id: row}` for one ledger next door, or `{}` and one line saying why.

    Reported rather than raised: the gate that OWNS that ledger is where a
    malformed one is a finding, and this going down with a traceback beside it
    says less. But it is said, because it is the CAUSE — measured while writing
    the table one file over, a `platform.toml` that stops parsing makes every row
    citing it report `carries no PLAT-…`, which is thirty findings naming the
    wrong thing.
    """
    if not path.is_file():
        return {}
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as error:
        findings.append(
            f"{path.name} cannot be read, so nothing citing it resolves: {error}"
        )
        return {}
    return {str(row.get(key, "")).strip(): row for row in doc.get(table, [])
            if isinstance(row, dict)}


def test_functions(root):
    """Every `fn name(` under `crates/`, which is where a host test can live.

    Walked rather than asked of git: the corpus is the one AGENTS.md names for
    host-testable logic, and the two detached workspaces that drop generated
    `.rs` into the checkout are not in it.
    """
    out = {}
    for path in sorted((root / CRATES).rglob("*.rs")):
        for name in re.findall(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                               path.read_text(errors="replace"), re.M):
            out.setdefault(name, str(path.relative_to(root)))
    return out


class Tree:
    """Everything a citation can resolve against, read once per audit."""

    def __init__(self, root, tiers=None, findings=None):
        self.root = root
        findings = [] if findings is None else findings
        self.tiers = tier_configs(root) if tiers is None else tiers
        #: A tier list that could not be read is a FINDING, not a skipped rule.
        #: Measured: with `run-tlc.sh --tiers` exiting non-zero, every `cfg:`
        #: citation lost its "something runs it" half and the row printed `ok` —
        #: the twenty-Kani-harnesses class, arriving through the reader instead
        #: of through the roster. `scope_gate.safety_tier` raises on the same
        #: input; this reports, because one sentence beats a traceback beside a
        #: page diff, and the effect is the same: the row cannot go green.
        if self.tiers is None:
            findings.append(
                "formal/run-tlc.sh --tiers printed no tier list, so no `cfg:`"
                " citation can be held to a tier that runs it — a closure whose"
                " mutant nothing runs is what that half exists to refuse"
            )
        floors = root / FLOORS
        rows, _ratchets, _problems = verdict_gate.read_registry(
            floors.read_text(encoding="utf-8") if floors.is_file() else ""
        )
        self.verdicts = rows
        self.scopes, _ = scope_gate.read_rows(root / SCOPES)
        self.assumptions = toml_ids(root / ASSUMPTIONS, "assumption", "constant", findings)
        self.threats = toml_ids(root / THREATS, "clause", "id", findings)
        self.platform = toml_ids(root / PLATFORM, "assumption", "id", findings)
        self.tests = test_functions(root)
        self.questions = {}
        matrix = root / MATRIX
        if matrix.is_file():
            try:
                doc = tomllib.loads(matrix.read_text(encoding="utf-8"))
            except (tomllib.TOMLDecodeError, OSError) as error:
                findings.append(
                    f"{matrix.name} cannot be read, so no settling question"
                    f" resolves: {error}"
                )
                doc = {}
            self.questions = {str(q.get("column", "")).strip(): q
                              for q in doc.get("question", []) if isinstance(q, dict)}

    def verdict(self, name):
        first, _every = verdict_gate.resolve(self.verdicts, [name])
        return first[name]


def resolve(tree, entry, kind, name):
    """(what the page prints for this citation, problems) — the whole derivation.

    One function rather than a dispatch table because each arm is three lines and
    the interesting part is what it checks, which a table would hide.
    """
    disposition, rid = entry["disposition"], entry["id"]
    if kind == "cfg":
        if not (tree.root / "formal" / name).is_file():
            return None, [f"{rid}: cites `formal/{name}`, which is not in the tree"]
        row = tree.verdict(name)
        if row is None or row["want"] != "RED":
            return None, [
                f"{rid}: `{name}` is not required RED by {FLOORS} — a closure"
                " resting on a mutant nothing requires to fall is the paragraph"
                " again, one file over"
            ]
        if tree.tiers is not None and name not in tree.tiers:
            return None, [
                f"{rid}: `{name}` is in no tier `run-tlc.sh --tiers` lists, so"
                " nothing runs it and its RED has never been observed"
            ]
        return f"`formal/{name}` (required RED)", []
    if kind == "scopes":
        module, _, const = name.partition("/")
        row = tree.scopes.get((module, const))
        if row is None:
            return None, [f"{rid}: {SCOPES} has no `{module} {const}` row"]
        if row[0] is None:
            return None, [
                f"{rid}: {SCOPES} records `{module} {const}` with no measured"
                " minimum, so it bounds nothing — a `-` row is a note, not a bound"
            ]
        return f"`{SCOPES}` `{name}` (minimum {row[0]}, measured on `{row[1]}`)", []
    if kind == "assumption":
        if name not in tree.assumptions:
            return None, [f"{rid}: {ASSUMPTIONS} carries no `{name}`"]
        return f"`{ASSUMPTIONS}` `{name}`", []
    if kind == "test":
        where = tree.tests.get(name)
        if where is None:
            return None, [
                f"{rid}: no `fn {name}` under `{CRATES}/` — the complementary"
                " source obligation this row rests on has been deleted"
            ]
        return f"`{where}` `{name}`", []
    if kind == "threat":
        if name not in tree.threats:
            return None, [f"{rid}: {THREATS} carries no `{name}`"]
        return f"`{THREATS}` `{name}`", []
    if kind == "platform":
        row = tree.platform.get(name)
        if row is None:
            return None, [f"{rid}: {PLATFORM} carries no `{name}`"]
        want, got = PLATFORM_STATUS[disposition], str(row.get("status", "")).strip()
        if got != want:
            return None, [
                f"{rid}: disposed of as `{disposition}` while {PLATFORM} records"
                f" `{name}` as `{got}` rather than `{want}` — the question moved"
                " and this row has to be re-decided, not carried"
            ]
        return f"`{PLATFORM}` `{name}` ({got})", []
    if kind == "question":
        if name not in tree.questions:
            return None, [
                f"{rid}: {MATRIX} has no open settling question for the `{name}`"
                " column — an obligation nobody is holding is not one"
            ]
        return f"`{MATRIX}` — the `{name}` settling question", []
    return None, [f"{rid}: `{kind}:{name}` is not a citation kind this reads"]


def check_entry(tree, entry, findings, word_floor):
    """One row's disposition, its evidence and its reason. Returns the citations
    as the page prints them, so the render shows what was derived rather than
    what was typed."""
    rid = entry["id"]
    disposition = str(entry.get("disposition", "")).strip()
    if disposition not in ALLOWED:
        findings.append(
            f"{rid}: disposition `{disposition}` is not one of"
            f" {sorted(ALLOWED)} — the exit criterion's four words are the"
            " vocabulary, and a fifth is a row nobody has to answer for"
        )
        return []
    shown = []
    for kind, name in cites_of(entry, findings):
        if kind not in ALLOWED[disposition]:
            findings.append(
                f"{rid}: `{disposition}` may rest on {list(ALLOWED[disposition])}"
                f" and this row cites a `{kind}` — an artifact that cannot carry"
                " the word is how the strongest word in the vocabulary gets taken"
            )
            continue
        label, problems = resolve(tree, entry, kind, name)
        findings.extend(problems)
        if label is not None:
            shown.append((name, label))

    why = flat(entry.get("why", ""))
    #: DISTINCT words, not words. The pasteable defeat of the pair below, driven
    #: on this file: `banana banana banana RSKeySecurityState/Channels banana …`
    #: cleared a plain word count and named every citation, and the page
    #: published it as the disposition. Counting the vocabulary costs a `set()`
    #: and refuses that shape.
    #:
    #: What the pair still does NOT catch, said plainly rather than left to be
    #: found: ABOUTNESS. Any twelve different words that mention the artifact
    #: pass — a sentence can be fluent, on-topic and wrong, and no scanner here
    #: can tell a reason from a plausible one. What these two rules buy is that
    #: the field cannot be a shrug (`TODO`, `banana`) and cannot be prose about
    #: something else; that the reason is TRUE of the artifact rests on review,
    #: the same way `deleter_gate.py`'s last paragraph says of its own.
    words = why.split()
    if len(set(words)) < word_floor:
        findings.append(
            f"{rid}: a disposition with no reason is not one — `why` carries"
            f" {len(set(words))} distinct word(s), under {word_floor}"
        )
    for name, _label in shown:
        if name not in why:
            findings.append(
                f"{rid}: `why` never names `{name}` — a reason that is not ABOUT"
                " the artifact it rests on is prose beside the evidence, which is"
                " what a non-emptiness check admits"
            )

    body = str(entry.get("body", ""))
    #: A registered id may not be named in this ledger, and the reason is the
    #: trap this file was written against rather than a style rule.
    #: `claims_gate.mask_regions` blanks EVERY `<!-- name:start -->` region by
    #: SHAPE — deliberately, so a new generator's output is not read as
    #: hand-written prose — so the sixty lines this renders leave that row's sight
    #: the moment they become a region. The roster names no id today (measured:
    #: `SEC-` does not occur in the section), so this costs nothing and keeps it
    #: that way. A row that genuinely needs to say something about `SEC-FIDO-001`
    #: says it in the section's intro paragraph, which is not masked, or in the
    #: registry that owns the status.
    #: Matched over `claims_gate.normalise`, not over the raw string, because
    #: the raw match is the rule's own evasion list read as a whitelist. Driven,
    #: all three of the spellings that gate's docstring enumerates walked
    #: through: `SEC-FIDO-**001**`, `SEC\u2011FIDO\u2011002` and a zero-width
    #: space, published at `formal/README.md` with this row and the claims row
    #: both at exit 0. Same function, so the two rules cannot disagree about
    #: what an id looks like.
    seen = claims_gate.normalise(f"{body} {why}")
    for found in sorted({m.group(0) for m in claims_gate.ID.finditer(seen)}):
        findings.append(
            f"{rid}: names `{found}` — this ledger renders into a marked region,"
            " which the claims row masks by shape, so a sentence about a"
            " registered id would reach the page with nothing reading it"
        )
    heads = [line for line in body.splitlines() if line.startswith("- ")]
    if len(heads) != 1:
        findings.append(
            f"{rid}: `body` opens {len(heads)} bullets, not 1 — one entry is one"
            " abstraction, or the count this roster is floored on stops meaning"
            " the list a reader sees"
        )
    return shown


def trailer(entry, shown):
    """The disposition line the page prints under a bullet, wrapped as the page is."""
    artifacts = "; ".join(label for _name, label in shown) or "—"
    prose = (f"**Disposition: {entry['disposition']}** — {artifacts}."
             f" {flat(entry['why'])}")
    out, line = [], "  "
    for word in prose.split():
        if len(line) + len(word) + 1 > 80 and line.strip():
            out.append(line)
            line = "  " + word
        else:
            line = f"{line} {word}" if line.strip() else line + word
    out.append(line)
    return "\n".join(out)


def block(rows):
    """The generated region: every bullet, each followed by its disposition."""
    lines = [START, f"<!-- {GENERATED_BY} -->"]
    for entry, shown in rows:
        lines.append(str(entry["body"]).strip("\n"))
        lines.append(trailer(entry, shown))
    lines.append(END)
    return "\n".join(lines)


def replace_region(text, body):
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError(
            f"{PAGE} needs exactly one `{START}` / `{END}` pair — the roster is"
            " generated into it and a page with no markers has taken it back"
        )
    start = text.index(START)
    end = text.index(END, start) + len(END)
    return text[:start] + body + text[end:]


def section_of(text):
    """The roster section, or None. Everything the parallel rule is about."""
    if HEADING not in text:
        return None
    start = text.index(HEADING)
    # `find`, not `index`: the last section of a page has no next heading, and a
    # rule that raises there would report the page's SHAPE as a crash.
    rest = text.find("\n### ", start + len(HEADING))
    return text[start:rest if rest != -1 else len(text)]


def no_parallel_roster(root, findings):
    """The list may not be re-typed: not beside the region, not on another page.

    Two directions, because closing one is what the driven mutations exploited
    one gate over. The section keeps its heading and its warning paragraph and
    carries no bullet of its own; and the heading occurs on no other tracked
    page, which is the completeness half a rule naming one file cannot have.
    """
    text = (root / PAGE).read_text(encoding="utf-8") if (root / PAGE).is_file() else ""
    section = section_of(text)
    if section is None:
        findings.append(
            f"{PAGE} has no `{HEADING}` section — the page a reader reaches for"
            " the narrow list has stopped naming it at all"
        )
    elif START in section:
        outside = section.split(START)[0] + section.split(END)[-1]
        typed = [line for line in outside.splitlines() if line.startswith("- ")]
        if typed:
            findings.append(
                f"{PAGE} carries {len(typed)} roster bullet(s) outside the"
                " generated region — a second list beside the derived one is the"
                " hand-written roster again, with a generator's header on it"
            )
    for rel in claims_gate.markdown(root):
        if rel == str(PAGE):
            continue
        if HEADING in (root / rel).read_text(errors="replace"):
            findings.append(
                f"{rel} carries this roster's heading — the list is generated"
                f" into {PAGE} from {LEDGER}, and a second copy of it anywhere is"
                " a copy that rots"
            )


def check_coverage(rows, findings, required):
    """Which abstractions are here, not how many — both halves.

    The named half refuses the swap (a row out, a filler in, the count intact).
    The derived half asks the other gate: a scope pinned in
    `scope_gate.MEASURED_MINIMA` is a narrowing somebody MEASURED, so it owes a
    row, and this cannot drift from that file the way a second list would.
    """
    listed = {entry["id"] for entry, _shown in rows}
    for missing in sorted(required - listed):
        findings.append(
            f"{missing} is a registered abstraction and {LEDGER} no longer"
            " carries it — a roster held by a COUNT loses a row to any filler"
            " written in its place"
        )
    cited = {name for _entry, shown in rows for name, _label in shown}
    for module, const in sorted(scope_gate.MEASURED_MINIMA):
        if f"{module}/{const}" not in cited:
            findings.append(
                f"no row cites `scopes:{module}/{const}`, which"
                " scope_gate.MEASURED_MINIMA pins as a measured minimum — a scope"
                " narrow enough to need a witness is a narrowing this roster owes"
                " a disposition"
            )


def audit(root, tiers=None, roster_floor: int = ROSTER_FLOOR,
          word_floor: int = FLOOR_WORDS, required=REQUIRED):
    """(findings, one-line summary) for the roster, its dispositions and its page."""
    root = pathlib.Path(root)
    findings = []
    listed = entries(root, findings)
    tree = Tree(root, tiers, findings)
    rows = [(entry, check_entry(tree, entry, findings, word_floor)) for entry in listed]

    if len(rows) < roster_floor:
        findings.append(
            f"{len(rows)} abstraction(s) registered, under the floor of"
            f" {roster_floor} — the roster is a list whose subject is"
            " completeness, so one fewer row is one abstraction nobody disposed of"
        )
    check_coverage(rows, findings, required)
    no_parallel_roster(root, findings)

    path = root / PAGE
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        try:
            want = replace_region(text, block(rows))
        except ValueError as error:
            findings.append(str(error))
        else:
            if text != want:
                findings.append(
                    f"{PAGE} is not what the generator writes — run"
                    " `python scripts/narrow_gate.py --write` and commit the result"
                )

    counts = {}
    for entry, _shown in rows:
        counts[entry["disposition"]] = counts.get(entry["disposition"], 0) + 1
    spread = ", ".join(f"{n} {word}" for word, n in sorted(counts.items()))
    summary = (
        f"narrow-gate: ok — {len(rows)} narrower-than-firmware abstractions"
        f" ({spread}), {sum(len(s) for _e, s in rows)} citations resolved"
    )
    return findings, summary


def run(root, write=False):
    if write:
        findings = []
        listed = entries(root, findings)
        if findings:
            die("; ".join(findings))
        tree = Tree(root)
        rows = [(entry, check_entry(tree, entry, [], FLOOR_WORDS)) for entry in listed]
        path = root / PAGE
        path.write_text(replace_region(path.read_text(encoding="utf-8"), block(rows)),
                        encoding="utf-8")
        print(f"narrow-gate: wrote the roster into {PAGE}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("narrow-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nEvery abstraction narrower than the firmware owes a disposition —"
            f"\nclosed, bounded elsewhere, accepted or an open obligation — in"
            f"\n{LEDGER}, resting on an artifact the tree still has.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: narrow_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
