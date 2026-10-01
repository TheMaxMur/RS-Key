#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold every published sentence about a registered property to the registry.

Stage 0 item 3 and the last exit of stage 4 are ONE predicate — "a public claim
about a P0-family id is generated from the registry; one written by hand fails on
a docs row" — and it was closed by nothing. Measured before this file existed:
four false hand-written sentences, including "`SEC-FIDO-001` … PROVEN on
hardware" in `README.md`, gave EXIT=0 on all eight gates, because `scripts/
check.sh` carried no docs row at all and the CI step `docs.sh check` is `mdbook
build` plus `lychee --offline`.

**The literal criterion is not the one implemented, and the difference is stated
rather than hidden.** "Every sentence is GENERATED" would refuse
`docs/store-refinement.md`'s "which is why `SEC-STORE-002` is `BOUNDED` and not
more" — a true sentence doing work no generated table does. What is implemented
is the half that carries the risk: a hand-written status is accepted only when it
is the status the registry HOLDS for the id in the same sentence. So a true copy
stays and stops being able to rot; a copy that is wrong the day it is typed is
refused; and `PROVEN`, which is no row's status anywhere in this tree, is refused
of every id by construction — which is the measured failure above.

Two rules, and both are about a COPY:

* a sentence naming registered ids and an evidence word none of them holds is
  refused. Sentence and not paragraph, measured: over the shipped corpus the
  paragraph window reports two refusals and both are contrastive prose — "…
  `SEC-STORE-003` and `SEC-STORE-004` stay MODELLED-ONLY" beside the word
  `BOUNDED` about neither of them — while the sentence window reports zero and
  still catches all three injected false claims;
* a LINE carrying an id, a status and three or more bare integers is a
  transcribed row of the derived evidence vector, and belongs to the generator
  that derives it. `docs/authorization-slice.md` carried three such rows, and
  their `co` column said 0 where the tree says 1: right when typed, wrong within
  the week, and the sentence rule cannot see it because the STATUS half stayed
  true.

A THIRD rule, and it is the one thing here not about a copy: an id that copies
nothing because no registry holds it. Both rules above start from the ids the
registry KNOWS — `spans` kept `m.group(0) in status` and the paragraph was
`continue`d when that left none — so a sentence about an id nobody registered was
read by neither. Measured before this rule existed: "`SEC-BOOT-042` is
PROVEN-SOURCE on the shipped image." and "`SEC-BOOT-042` is MEASURED on an RP2350
A4 board." each gave EXIT=0 with ZERO findings, on a page in the shipped corpus,
and `SEC-BOOT` is a real family — the invention was two digits. The control that
did fall, "`SEC-FIDO-002` is BINARY-CHECKED", fell on the STATUS half and only
because `BINARY-CHECKED` is no row's status; invent the ID instead of the word
and nothing looked at all. So an id-shaped token on a hand-written page that the
registry does not hold is a finding naming the page and the token — which is
stage 12's "no orphan public claim", checkable in no other row. It is scored per
OCCURRENCE: an orphan has no subject, no clause and no status, so it is the only
rule here with no window to get wrong. What it did need was [`flat`], in both
directions and each measured: without it the orphan rule reads a legal
`SEC-\nSTORE-002` as an invented id, and the SPANS filter it shares — raw until
this rule made the disagreement visible — let "`SEC-\nSTORE-002` is PROVEN" out
at EXIT=0.

What this row does not do, measured rather than guessed — an independent review
drove 23 spellings and broke the first version with plain English before it
needed a trick one:

* it does not read English, and what it reads instead is the POLARITY of the
  clause a status word ends. NEGATION and TENSE were invisible: "`SEC-FIDO-001`
  is not BOUNDED" and "`SEC-FIDO-007` is no longer MODELLED-ONLY" were EXIT=0
  and each pushed the held count UP (11 → 12 → 13), so [`CLAIM_FLOOR`] was
  satisfiable by lies. The FIRST rule written for that read a four-word window
  against a flat list of markers, and an independent review measured what it
  bought: 2 of 24 false claims refused, and 6 of 12 TRUE sentences reddened —
  "was raised to BOUNDED", "has not stopped being BOUNDED". [`FLIP`] counts
  flippers and denies on an ODD count, which is what lets a double negative
  assert again; [`DATED`] takes a bare tense only where it touches the word.
  Re-measured on the constructed corpus that broke it, now in the tree as
  `test_claims_gate.LIES` and `TRUTHS`: 23 of 25 refused, 0 of 14 true sentences
  reddened. The two that escape are `ESCAPES` — a negator standing BEFORE the
  id, and one standing after the status word. MODALITY stays out: adding
  `would|could|should|may|might` reddens `CHANGELOG.md`'s "its `status` would
  have read `BOUNDED`", a true sentence about what the DERIVATION would say;
* the corpus of 66 real pages barely checks any of that, and "0 false positives
  over the corpus" would be precision this row does not have: 11 sites reach the
  rule at all and none of them is negated, so the first rule's window reported
  the same 0 findings at every width from 1 to 14 — a knob no measurement could
  move, which is why there is no window now. The one thing the real corpus does
  check is the clause split, and only since the window went (below). The rest of
  the discrimination is measured on the constructed corpus, which is why that
  corpus is in the tree rather than in a comment;
* most of this can be DELETED with the `published claims` row byte-identical,
  and a reader must not take that row's green as evidence of it. Measured:
  [`FLIP`] neutered to a pattern matching nothing, and the branch reverted to
  `held += 1`, each give EXIT=0 and the same summary — only `pytest (gate
  scripts)` sees the difference. [`CLAUSE`] is the exception and only since the
  word window went: neutered, the shipped tree REDDENS on `CHANGELOG.md`'s "It
  closes nothing and moves no status — the row stays `BOUNDED`", which is the
  one place a real page depends on where a clause ends;
* the vocabulary is CASE-SENSITIVE, so a lower-case `proven` in prose stays
  prose. That is a trade taken on a measurement: case-folding reports 45
  refusals over this corpus and almost every one is an ordinary word
  ("measured", "co-refuted");
* `_` is not stripped as emphasis, because stripping it turns
  `scripts/evidence_gate.py` into `evidencegate.py` and un-exempts all three
  generated pages. `PRO_VEN_` is therefore still a bypass, and this is the whole
  of what that trade costs;
* the transcribed-row rule catches the PIPE-TABLE layout and five others walk
  past it: an HTML `<table>`, the numbers on the next line, `mut 1 | co 0`,
  `45cfg | 11mut`, and the status moved to a header row. It catches the layout
  the author happened to use, not the copy;
* the corpus is markdown. A P0-family claim in a Rust doc comment
  (`store_meta_kani.rs` carries one, true today) is outside it;
* [`REGION`] takes the SHAPE of a generated region and not a roster of the
  generators, so an INVENTED marker is a working self-exemption from all three
  rules: measured, `<!-- bogus:start -->` around "`SEC-BOOT-042` is
  PROVEN-SOURCE" is EXIT=0 with the census unmoved. It is the same shape
  `is_generated` closed one level up, and it is left open for the reason its own
  comment gives — the real markers are part literal and part built with an
  f-string or `.format`, so a derived roster is the fragile half, and a
  hand-kept one would read a new generator's output as prose. Nothing anywhere
  holds a marker name to a generator, and `narrow_gate` and `run_count_gate`
  read the same primitive, so this is not a trade to re-take in one file;
* the orphan rule reads only the SHAPE, and the shape is [`ID`], held to every
  registry row by a case. That case holds it from getting too NARROW, and no
  registry row can witness the direction this rule needs — that `SEC-BOOT-042`
  is id-shaped is a fact about ids the registry does NOT have. So the tail is
  measured instead of derived, and widening it is worse: `SEC(-[A-Z0-9]+)+`
  reddens the shipped tree twice, on `CHANGELOG.md`'s `SEC-DISP` and
  `SEC-FIDO-NNN` — a family named as a family, and a placeholder;
* **the REVERSE direction is open, and the number is why.** "A registry row no
  hand-written page names" is not held, because it would report 34 of the 60 on
  a clean tree — measured, and they are not rot: every occurrence of all 34 is
  generator-written, on `docs/assurance-vector.md`, `docs/assurance-matrix.md`
  and `docs/platform-assumptions.md`, or inside one of the six generated REGIONS
  of `formal/README.md`, which drops that page from 60 registered ids to 8 once
  [`mask_regions`] has run. The weaker form — a row no page names AT ALL — is 0
  today and would be decorative: `evidence_gate` refuses a stale
  `docs/assurance-vector.md` and `assurance_gate` refuses a stale
  `formal/README.md` table, so a row missing from a generated page is already
  their finding. What stays unheld is the middle: a row that only ever appears
  in a table, which no prose has ever had to explain.

What it does is make the WORDS the registry owns unusable as a lie about a row
that registry holds, and the id itself unusable as a claim about nothing, in the
shapes above.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = pathlib.Path("assurance/properties.toml")

#: A `-` that may carry a hard-wrap. It replaces a normalising join that DELETED
#: the newline, and with it every reported line number after it — measured at 6
#: files and up to 12 lines on `docs/protocol.md`, and a guard whose whole output
#: is a citation cannot ship that. Matching across the break leaves offsets exact.
SOFT = r"-(?:\n[ \t]*)?"


def soft(word: str) -> str:
    """A literal `word` with every `-` allowed to carry a hard-wrap.

    Words only — applied to a PATTERN it rewrites the `-` inside `[A-Z]`, which
    is a character-range error and how this was caught.
    """
    return word.replace("-", SOFT)


#: A registered property id, in the three shapes the registry uses:
#: `SEC-FIDO-001`, the clause rows `SEC-FIDO-006A`, and the liveness rows
#: `SEC-FIDO-L01` — which a pattern anchored on a digit misses, and a test over
#: the registry is what caught that. Narrow on purpose otherwise:
#: `TM-HOST-GATES` and `PLAT-TOOL-004` are other registries' ids and other
#: rules' business.
ID = re.compile(r"\bSEC" + SOFT + r"[A-Z]+" + SOFT + r"[A-Z]?\d+[A-C]?\b")

#: The evidence vocabulary a published sentence may put beside an id. The three
#: the registry actually uses are held against this tuple by a CASE, not by
#: [`vocabulary`], which returns it verbatim — a reviewer read the first version
#: of this comment as a claim the function derives them, and it does not; the
#: rest are §4.2's
#: working classes plus the one §4.3 governs. `PROVEN` is here precisely BECAUSE
#: no row holds it: a word that is no id's status is refused of every id, which
#: is what makes the measured README sentence fall.
#:
#: Longest first, so `PROVEN-SOURCE` is never read as `PROVEN` with a suffix.
CLASSES = (
    "PROVEN-SOURCE",
    "BOUNDED-SOURCE",
    "MEASURED-PLATFORM",
    "BINARY-CHECKED",
    "MODEL-CHECKED",
    "MODELLED-ONLY",
    "ACCEPTED-RISK",
    "TRACE-LINKED",
    "CO-REFUTED",
    "MEASURED",
    "BOUNDED",
    "PROVEN",
)

#: The window: a PARAGRAPH. It was a sentence for one revision and that is how a
#: reviewer broke it in one line — a sentence beginning at column 0 saw only its
#: own line, so "`SEC-FIDO-001` is the authorization property.\nIt is PROVEN on
#: hardware." passed while the same words on one line were refused. Measured, this
#: corpus is hard-wrapped: 14 978 of 29 403 prose lines are 50-95 columns, so
#: whether a false claim was caught depended on where the author's editor wrapped.
PARAGRAPH = re.compile(r"\n\s*\n")

#: Clause boundaries. The em-dash is the load-bearing one, measured: without it
#: `CHANGELOG.md`'s "It closes nothing and moves no status — the row stays
#: `BOUNDED`" reads its neighbour's `nothing` and reddens. A comma splits ONLY
#: before a coordinating conjunction, which is the difference between "will not
#: be re-run, and the row stays BOUNDED" (a new clause, green) and "is not, on
#: any reading of the evidence, BOUNDED" (a parenthetical, refused) — an
#: unconditional comma let the second one through. `|`, `[` and `(` are NOT
#: boundaries: they were, and a markdown link, a parenthesis and a table cell
#: each emptied the run-up and walked a negation past. A newline is not a
#: boundary either — this corpus is hard-wrapped.
CLAUSE = re.compile(r"[.;:!?]|--|—|–|→|,(?=\s*(?:and|but|so|because|which|while|though|yet|or)\b)")

#: An inline HTML tag, removed before the clause is read: `is <em>not</em>
#: BOUNDED` renders as a negation and read as none.
TAG = re.compile(r"<[^>\n]{1,80}>")

#: What flips the POLARITY of a clause about a status. Counted, not merely
#: found, and an ODD count is what denies the row — because the six true
#: sentences an independent review broke the first version with are double
#: negatives: "has not stopped being BOUNDED" and "was never anything but
#: BOUNDED" each carry two flippers and assert the status. Longest first, so
#: `no longer` is one flipper and not `no` plus a word.
#:
#: Evaluated at exactly 11 sites — the ones that would otherwise count as
#: `held`. Of the 34 status words on the 66 pages the other 23 are inside a
#: [`SCOPED`] fragment or in a paragraph naming no registered id, and one of
#: those ("it does not promote MODELLED-ONLY to a proof", `formal/README.md`)
#: does carry a negator. It is true, and it is out of reach either way.
FLIP = re.compile(
    r"\b(?:no longer|no more|nowhere near|anything but|other than|far from"
    r"|short of|yet to|fails? to|failed to|used to be|stops? being"
    r"|stopped being|ceases? being|ceased being|never|neither|nor|not|no"
    r"|hardly|scarcely|barely|without|un|non)\b-?"
    r"|[a-z]n['’]t\b",
    re.I,
)

#: Tense that only reads as another time when it TOUCHES the word. `was` alone
#: is unusable and that is the measurement, not a guess: it reddens "was raised
#: to BOUNDED", "was and still is BOUNDED" and "had already been BOUNDED when
#: the slice opened", all true. Adjacent, none of those fire and "`SEC-FIDO-001`
#: was BOUNDED" still does. One parenthetical is allowed between, because "was,
#: until the revert, BOUNDED" is the shape that escaped adjacency and it is a
#: false claim; a second comma ends it, which is what keeps "was added to the
#: registry, and the row stays BOUNDED" out.
DATED = re.compile(
    r"\b(?:was|were|will be|shall be|will become)(?:\s*,[^,]{0,60},)?\s*$", re.I
)

#: Registered prose that uses the vocabulary as VOCABULARY. A paragraph
#: explaining the status ladder — "a Kani harness names it -> BOUNDED; anything
#: else -> MODELLED-ONLY" — is not a claim about the id that happens to be
#: nearest, and no distance threshold separates the two: measured over this
#: corpus, true copies sit at 4..1128 characters from their id and false ones at
#: 59..1163, which overlap. So they are registered by the fragment carrying them,
#: each with a reason, and a fragment that stops occurring exactly once is a
#: finding — the shape `run_count_gate.SCOPED` already uses.
SCOPED = {
    (
        "CHANGELOG.md",
        "No\n  configuration names it → `ACCEPTED-RISK`; a Kani harness names it →"
        " `BOUNDED`;\n  anything else → `MODELLED-ONLY`. All **59** rows rebuild"
        " exactly.",
    ): "the status ladder's own derivation, quoted; the words are its VALUES and"
    " the nearest id is an example being classified, not a row being claimed",
    (
        "CHANGELOG.md",
        "the harnesses are named so that they stay: `assurance_gate` forces `BOUNDED`",
    ): "prose about what the gate DOES with the word — the sentence's subject is"
    " the naming rule, not the property beside it",
    (
        "docs/store-refinement.md",
        "`assurance_gate` FORCES `BOUNDED` from a harness function name",
    ): "the same sentence one page over, and the same reading",
    (
        "docs/store-refinement.md",
        "`BOUNDED` there\n  would be a scalar going up while the domain went quietly down.",
    ): "a hypothetical the page argues AGAINST, which is the opposite of a claim"
    " that the row holds it",
}

#: `<!-- name:start -->` … `<!-- name:end -->`, the shape EVERY generator in this
#: tree marks its regions with. Derived from the shape rather than from a list of
#: generators: a list is one more roster to keep, and this row would then read a
#: new generator's output as hand-written prose.
REGION = re.compile(r"<!--\s*([a-z0-9-]+):start\s*-->")

#: A page some generator writes whole, said in its own first lines. Same reason:
#: the header is the page's own claim about itself, and a roster here would go
#: stale against it.
GENERATED_WHOLE = re.compile(r"Generated by scripts/[a-z_]+\.py")

#: A bare integer, for the transcribed-row rule, counted over the line with its
#: IDS BLANKED: the `007` of `SEC-FIDO-007` is a bare integer by every pattern,
#: and counting it took "`SEC-FIDO-007` is MODELLED-ONLY and 2 of 3
#: configurations check it" to three. Three, because the derived vector's
#: narrowest row still carries `cfgs`, `mut` and `co`.
NUMBER = re.compile(r"(?<![\w.])\d+(?![\w.])")
ROW_NUMBERS = 3

#: True copies the sweep must still find. A PARAMETER of [`audit`] and not a
#: global a case patches down, so the shipped value is the one every case runs
#: against — `SCAN_FLOOR` in `run_count_gate.py` shipped the other way and its own
#: commit message says the shipped 8 was therefore never checked.
#:
#: Under the measured 11. It is a floor on the SCANNER, not on the prose: a
#: masking bug, an empty corpus or a vocabulary that stopped matching all read as
#: "no claims found", which is indistinguishable from a clean tree. The first
#: version said "under the measured 4" and the tree measured 5 the day it shipped
#: — a number this rule could not see, because `scripts/` is not markdown.
CLAIM_FLOOR = 6

#: Pages the corpus must still hold, for the same reason one layer out: if the
#: listing ever answers short, every rule here passes over nothing. Under the
#: measured 66 hand-written of 69 tracked markdown — and the number is the one
#: the floor is COMPARED against, which the first version got wrong: it said
#: "under the measured 323" and 323 was the pre-exemption count of a different
#: corpus entirely.
CORPUS_FLOOR = 50

#: The sentence the Definition of done requires the project to keep saying, and
#: the ONE spelling this rule reads. Four pages say it today in FOUR spellings —
#: "**not** make RS-Key formally verified", "RS-Key is not formally verified",
#: and two more — so nothing could check it: a disclaimer with four spellings is
#: a disclaimer no rule can hold, and deleting all four left every gate green.
#: Emphasis is stripped before matching, so the bolded form counts and a fifth
#: spelling does not.
DISCLAIMER = "rs-key is not formally verified"

#: The paragraph the three generated pages emit, kept HERE and imported by them.
#: Three copies of a sentence whose whole purpose is that it cannot be quietly
#: dropped would be three places to drop it from, which is the defect one
#: directory over. It names where the residual risks are, because the Definition
#: of done asks for them BESIDE the claims and no generated page linked either
#: page before this.
DISCLAIMER_PARAGRAPH = (
    "**RS-Key is not formally verified.** This page is generated from the"
    " registry and reports what evidence exists, not that a whole-system theorem"
    " does. The Definition of done keeps this sentence a requirement until one"
    " exists, and `scripts/claims_gate.py` holds every page naming three or more"
    " registered properties to it. What is out of scope and what is accepted:"
    " [limitations](limitations.md) and the [threat model](threat-model.md)."
)

#: How many distinct registered ids make a page one a reader takes an assurance
#: claim FROM. Three, and MARKDOWN only: `.tla`, `.toml` and `.sh` name ids as
#: data and are not where anyone reads a summary. Measured, seven `.md` pages
#: clear it — `docs/assurance-vector.md` and `formal/README.md` at 59 each,
#: `docs/assurance-matrix.md` at 40, `docs/platform-assumptions.md` at 34 — and
#: exactly ONE of the eight carried the sentence.
DISCLAIMER_IDS = 3

#: Pages that must carry it, floored so the derivation going blind is a finding
#: rather than a clean run. Under the measured 8, and a PARAMETER of [`audit`]
#: like its two neighbours — it shipped as a global for one revision and its
#: mutation table reported the mutant SURVIVING, because a case can only reach a
#: global by monkeypatching it, which is the shape `SCAN_FLOOR` shipped with.
DISCLAIMER_FLOOR = 6


def vocabulary(root: pathlib.Path) -> tuple[dict, tuple]:
    """({id: status}, the words a claim may use).

    The statuses come from the registry rather than from [`CLASSES`], and the
    check that [`CLASSES`] still contains them is a test's — a status added to the
    registry and not here would otherwise be a word this row silently stops
    reading, which is the failure the whole file is about.
    """
    registry = tomllib.loads((root / REGISTRY).read_text(encoding="utf-8"))
    status = {
        str(row.get("id")): str(row.get("status"))
        for row in registry.get("property", [])
    }
    return status, CLASSES


def mask_regions(text: str) -> str:
    """`text` with every generated region blanked, newlines kept so a reported
    line number still points where it says."""
    out = text
    for found in REGION.finditer(text):
        end = f"<!-- {found.group(1)}:end -->"
        stop = text.find(end, found.start())
        if stop != -1:
            chunk = text[found.start() : stop + len(end)]
            out = out.replace(chunk, "\n" * chunk.count("\n"), 1)
    return out


def generated_pages(root: pathlib.Path) -> dict[str, str]:
    """{page: the header that exempts it} — DERIVED from the generators.

    Not the phrase in the page's own first bytes, which is what the first version
    read and which nothing checked. Driven on that version: a hand-written page
    exempted itself with `Generated by scripts/no_such_gate.py`, with a REAL
    generator's name over a page it does not write, and with the phrase in
    ordinary prose rather than in a comment — three passes at exit 0. Each
    generator names the file it writes in an `ARTIFACT` constant and its own
    header in `GENERATED_BY`; this is that pair, so a page is exempt only where
    the script that claims it really writes it.
    """
    out = {}
    for name in sorted((root / "scripts").glob("*_gate.py")):
        if name.name.startswith("test_"):
            continue
        source = name.read_text(errors="replace")
        page = re.search(r'^ARTIFACT = pathlib\.Path\("([^"]+)"\)', source, re.M)
        header = re.search(r'^GENERATED_BY = "([^"]+)"', source, re.M)
        if page and header:
            out[page.group(1)] = header.group(1)
    return out


def markdown(root: pathlib.Path) -> list[str]:
    """Every tracked `*.md`, which is the corpus a reader takes a claim from.

    `run_count_gate.scanned` was the first corpus and it is the WRONG one here:
    it is `docs/`, `formal/`, `.github/` plus the root, because a run-count is
    published there. Measured, that left 1018 tracked files out — every nested
    README, and `CHANGELOG.md`, which carried "the other three store properties
    stay MODELLED-ONLY" over a family of six. The run-count carve-out's own
    reason does not transfer: "an entry saying what a run cost at 0.4.10 stays
    0.4.10's" is true of a cost and false of a status.
    """
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return sorted(rel for rel in listing.split("\0") if rel and (root / rel).is_file())


def normalise(text: str) -> str:
    """`text` as a reader sees it, for the two rules that read words.

    Markdown emphasis, a zero-width space and the non-ASCII hyphens all render
    identically to what they hide, and each of them walked a literal `PROVEN`
    past the first version: `PRO**VEN**`, `PRO\u200bVEN`, `SEC\u2011FIDO\u2011001`.
    A hyphen at a line end is NOT joined here — [`soft`] lets the patterns cross
    it instead, because joining deleted a newline and every reported line number
    after it was early by one per join (up to 12 on `docs/protocol.md`, and a
    guard whose whole output is a citation cannot ship that). Case is NOT folded, and
    that is measured rather than lazy: over this corpus a case-insensitive
    vocabulary reports 45 refusals, and almost every one is an ordinary word —
    "measured", "co-refuted" — so the rule reads the SHOUTED forms the registry
    uses and a lower-case `proven` in prose stays prose.
    """
    text = text.replace("\u200b", "").replace("\u2011", "-").replace("\u2010", "-")
    # `*` and a backtick only. `_` is markdown emphasis too and stripping it was
    # measured to be worse than the hole it closes: it turns
    # `Generated by scripts/evidence_gate.py` into `evidencegate.py`, which
    # un-exempted all three generated pages at once. A `PRO_VEN_` bypass is left
    # open and said so here rather than paid for that way.
    return re.sub(r"[*`]", "", text)


#: How far into a page its generator's header must appear. The first bytes,
#: because further down it is prose that MENTIONS a generator rather than the
#: marker one writes. Named rather than typed at the comparison because
#: `platform_gate.py` asks this same question of an evidence path, and a second
#: literal there would be a second answer to it.
HEADER_WINDOW = 600


def is_generated(rel: str, text: str, exempt: dict[str, str]) -> bool:
    """Whether `rel` really is the page its claimed generator writes.

    Two halves, and the KEY alone is the weaker one: [`generated_pages`] says
    which page a `*_gate.py` CLAIMS, and this adds that the page agrees, by
    carrying that generator's own header. Split out of [`corpus`] because
    `platform_gate.hand_written` asked the same mapping the same question and
    read only the key — strictly weaker over the same data, so a page a
    generator names and does not write was evidence there and prose here.

    `text` is already [`normalise`]d, and the caller passes the copy it has: a
    second read to normalise again is how the two halves come to disagree.
    """
    header = exempt.get(str(rel))
    return bool(header) and header in text[:HEADER_WINDOW]


def corpus(root: pathlib.Path) -> list[tuple[str, str]]:
    """(path, hand-written text) for every markdown a claim can be typed in."""
    exempt = generated_pages(root)
    out = []
    for rel in markdown(root):
        text = normalise((root / rel).read_text(errors="replace"))
        if is_generated(rel, text, exempt):
            continue
        out.append((rel, mask_regions(text)))
    return out


def published(root: pathlib.Path) -> list[tuple[str, str]]:
    """(path, WHOLE text) for every markdown, generated pages included.

    The disclaimer rule reads this and not [`corpus`]: the three pages carrying
    the most registered ids are generated whole, so a rule over the hand-written
    residue would ask the sentence of everyone except the pages a reader most
    likely reads. Their generators emit it now.
    """
    return [
        (rel, normalise((root / rel).read_text(errors="replace")))
        for rel in markdown(root)
    ]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def run_up(chunk: str, at: int, floor: int) -> str:
    """The clause that GOVERNS the status word at `at`.

    `floor` is the attributed id's end when the id precedes the word, so a run-up
    never reaches back past the subject it is about; 0 when the word comes first
    and the id is the fallback behind it. A WORD window stood here for one
    revision and it was inert — the shipped corpus reports the same 0 findings at
    every width from 1 to 14, so the clause split is what bounds this, and a knob
    no measurement can move is a knob whose mutant nothing kills.
    """
    return CLAUSE.split(TAG.sub(" ", chunk[floor:at]))[-1]


def flat(word: str) -> str:
    """A vocabulary match with the hard wrap [`soft`] let it cross taken back out.

    Without it `MODELLED-\nONLY` compares unequal to its own registry status and
    the true copy is reported as a copy of nothing — the exact inversion this row
    exists to refuse, introduced by the fix for the line numbers and caught by
    the case that drives both directions.
    """
    return "".join(word.split())


def denied(clause: str) -> str | None:
    """The marker that makes `clause` not ASSERT the status in it, or None."""
    flips = FLIP.findall(clause)
    if len(flips) % 2:
        return flips[-1].strip()
    dated = DATED.search(clause)
    return dated.group(0).strip() if dated else None


def audit(
    root: pathlib.Path,
    claim_floor: int = CLAIM_FLOOR,
    corpus_floor: int = CORPUS_FLOOR,
    disclaimer_floor: int = DISCLAIMER_FLOOR,
) -> tuple[list[str], str]:
    root = pathlib.Path(root)
    findings: list[str] = []
    status, words = vocabulary(root)
    vocab = re.compile(r"\b(" + "|".join(soft(w) for w in words) + r")\b")
    pages = corpus(root)
    if len(pages) < corpus_floor:
        findings.append(
            f"the scan reached {len(pages)} page(s), under the floor of"
            f" {corpus_floor} — a corpus that shrank is a rule that stopped"
            " looking, and it reads exactly like a tree with nothing to find"
        )

    scoped = {(rel, frag): 0 for rel, frag in SCOPED}
    held = rows = 0
    for rel, text in pages:
        exempt = []
        for (page, fragment) in SCOPED:
            if page != rel:
                continue
            # Normalised the same way the text is, so a fragment may be quoted
            # from the page as written rather than as this rule reads it.
            needle = normalise(fragment)
            at = text.find(needle)
            if at != -1:
                scoped[(page, fragment)] = text.count(needle)
                exempt.append((at, at + len(needle)))
        cursor = 0
        for chunk in PARAGRAPH.split(text):
            base = text.find(chunk, cursor)
            cursor = base + len(chunk) if base != -1 else cursor
            # [`flat`] on the ID for the reason its docstring gives about the
            # STATUS word, and measured the same way: raw, `SEC-\nSTORE-002`
            # compares unequal to its own row, the span is dropped, and
            # "`SEC-\nSTORE-002` is PROVEN" is EXIT=0 on a corpus that wraps.
            spans = [
                (m.start(), m.end(), flat(m.group(0)))
                for m in ID.finditer(chunk)
                if flat(m.group(0)) in status
            ]
            if not spans:
                continue
            for word in vocab.finditer(chunk):
                where = max(base, 0) + word.start()
                if any(a <= where < b for a, b in exempt):
                    continue
                # The nearest id that PRECEDES the word, and the nearest overall
                # only when none does. Not the union over the paragraph: that let
                # two ids lend each other their statuses — "`SEC-FIDO-001` is
                # MODELLED-ONLY and `SEC-STORE-005` is BOUNDED" has both halves
                # backwards and scored TWO true copies. And not the nearest in
                # either direction: a LIST after a claim steals it, measured on
                # "`SEC-STORE-002` rises to BOUNDED. `SEC-STORE-001`, … stay
                # MODELLED-ONLY", where the first name of the list is two
                # characters from a word that is about the id before it. English
                # puts the subject first; the fallback covers a word in a heading
                # over a body that names the id.
                before = [s for s in spans if s[1] <= word.start()]
                subject = min(
                    before or spans,
                    key=lambda s: min(abs(s[0] - word.end()), abs(word.start() - s[1])),
                )
                near = subject[2]
                said = flat(word.group(0))
                if said == status[near]:
                    # The registry's word is not the registry's CLAIM when the
                    # clause denies it or dates it. Reported instead of held, so
                    # a lie stops paying into [`CLAIM_FLOOR`] as well as passing.
                    floor = subject[1] if subject[1] <= word.start() else 0
                    twist = denied(run_up(chunk, word.start(), floor))
                    if not twist:
                        held += 1
                        continue
                    findings.append(
                        f"{rel}:{line_of(text, where)}: says `{said}`"
                        f" beside {near} under `{twist}` — that IS the"
                        " registered status and the sentence does not assert it,"
                        " so a negated or re-dated restatement reads as a copy"
                        " here and as the opposite to a reader"
                    )
                    continue
                findings.append(
                    f"{rel}:{line_of(text, where)}: says `{said}` beside"
                    f" {near}, whose registered status is {status[near]} — a"
                    " hand-written status is a copy, and this one is not a copy of"
                    " anything"
                )
        # Per OCCURRENCE and not per paragraph: an orphan needs no subject, no
        # clause and no window, so it is the one rule here that cannot depend on
        # where an editor wrapped. [`ID`] and not a second pattern — a case
        # fullmatches every registry row against it, and the breadth this needs
        # is the direction no row can witness (docstring).
        for found in ID.finditer(text):
            name = flat(found.group(0))
            if name in status:
                continue
            findings.append(
                f"{rel}:{line_of(text, found.start())}: names {name}, which no"
                " registry row holds — the id is the whole of what a published"
                " claim points at, so one pointing nowhere cannot be held to a"
                " status, and the sentence around it is unfalsifiable instead of"
                " merely false"
            )

        for number, line in enumerate(text.splitlines(), 1):
            if not (ID.search(line) and vocab.search(line)):
                continue
            bare = NUMBER.findall(ID.sub(" ", line))
            if len(bare) < ROW_NUMBERS:
                continue
            rows += 1
            findings.append(
                f"{rel}:{number}: an id, a status and {len(bare)}"
                " bare numbers on one line is a transcribed row of the derived"
                " evidence vector — it belongs to the generator that derives it,"
                " because the status half can stay true while a column rots"
            )

    owed = 0
    for rel, text in published(root):
        if not rel.endswith(".md"):
            continue
        if len({i for i in ID.findall(text) if i in status}) < DISCLAIMER_IDS:
            continue
        owed += 1
        # Emphasis stripped, so `**not**` counts; nothing else is normalised,
        # because a rule that accepts any paraphrase accepts the paraphrase that
        # drops the word "not".
        if DISCLAIMER not in re.sub(r"[*_`]", "", text).lower():
            findings.append(
                f"{rel}: names {len({i for i in ID.findall(text) if i in status})}"
                f" registered properties and does not say {DISCLAIMER!r} — the"
                " Definition of done keeps that sentence a requirement, and a page"
                " a reader takes a status from is where it has to be"
            )
    if owed < disclaimer_floor:
        findings.append(
            f"{owed} page(s) owe the disclaimer, under the floor of"
            f" {disclaimer_floor} — the derivation that finds which pages make a"
            " claim went blind, and no page owing it reads as every page having it"
        )

    for (page, fragment), seen in sorted(scoped.items()):
        if seen != 1:
            findings.append(
                f"{page}: the registered fragment {fragment.splitlines()[0][:48]!r}"
                f" occurs {seen} time(s) — an exemption that stopped matching"
                " exempts nothing and hides whatever moved into its place, and a"
                " second copy is the rot this rule is about wearing an exemption"
            )

    if held < claim_floor:
        findings.append(
            f"the scan matched {held} true status copy/copies, under the floor of"
            f" {claim_floor} — the floor is on the SCANNER: a masking bug or a"
            " vocabulary that stopped matching reads as a tree with no claims in it"
        )
    summary = (
        f"claims-gate: ok — {len(pages)} published page(s), {held} hand-written"
        f" status(es) held against the registry, {rows} transcribed row(s),"
        f" {owed} page(s) carrying the disclaimer"
    )
    return findings, summary


def main() -> int:
    findings, summary = audit(ROOT)
    if findings:
        print("claims-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nA published status is a claim, and the registry is the only place"
            "\nthis tree decides one. Generate the sentence, or make it true.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
