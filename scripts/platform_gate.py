#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the second assumption registry — the ones no model constant can carry.

`scripts/assumption_gate.py` accepts exactly one shape: a Boolean TLA constant
some configuration assigns BOTH WAYS and some reachable definition reads. That
rule is what makes a model assumption falsifiable — you discharge it by running
the other arm — and it is measured, not asserted: `M7-Q2` (does the ROM clear
`WATCHDOG.scratch2` on return from BOOTSEL?) put into `assurance/assumptions.toml`
answers `in the registry but no configuration assigns it`. So does a recorded
board PASS, and so does `tools/emu` fidelity. They are statements about a
platform, a tool or an abstraction, and there is no arm to run.

**Why a second file and not a `class` field on the first.** A discriminator
inside `assumptions.toml` would pick which rules apply, and the rules it would
have to switch off are ALL THREE of the mechanical ones that file has — which
leaves "an entry exists". The `M7-Q2` answer measured above IS the orphan rule, so
the amendment must disable that as well as the both-arms and reachability rules;
and the counterfactual — that gate with the two constant rules skipped for
`platform` — passes `PowerOnClearsScratch2` pinned nine ways with nothing to
falsify it. Deleting a constant from that registry instead reddens it at once, so
a second file makes the misclass a red row rather than a spelling.

The classes differ in how they are DISCHARGED, which is the other half: a model
constant is discharged by a TLC run, an entry here by a board measurement, a
vendor erratum, a source audit or an accepted risk with an owner. Nothing here
can be discharged by anything this repository runs, and **only a small minority
of entries is discharged at all**. The count is DERIVED — [`run`] prints it on a
GREEN literal run and [`render`] opens the generated page with it — because the
typed copy that stood here read `two of thirty-three` against a registry that had
grown past sixty, and no rule holds a number a docstring states. Measured, the
"prints it on every run" this sentence claimed was false in two directions and
[`main`] was the wrong function: `--write` returns before the audit, and a red run
prints on stderr. The page is what a reader who never runs the gate sees.

Thirteen rules, and the first is the one that earns the file:

* **candidates are DERIVED, and every one is claimed.** Five derivations, each
  floored where its source exists and it found nothing:
  `slice:` the assumption ids the closed slice's bundle and the design pages
  carry — ten of them, and `docs/authorization-slice.md` measured **zero
  registered** before this file; `model:` every constant of the first registry,
  because a model assumption's own discharge is always a fact about the world;
  `board-only:` the suites `tests/emu.py` refuses by name that
  `scripts/usbip-guest.sh` does not run either — no runner in this tree can pass
  them, so each is a pending board obligation; `unsafe:` every `unsafe` SITE in
  first-party Rust, which is stage 10's "firmware unsafe invariant" half;
  `backend:` every semantic a crate-ledger row declares its model ABSTRACTS —
  the anchor for a row that no other derivation reaches ([`backend_candidates`]).
  Each reads a STRUCTURE and not a text: the shim's dict through `ast`, the
  guest's rows through `gate_lines`, Rust with its comments and strings removed,
  the ledger's `abstracts` as a list and not its `gap` prose.
  The review drove nine legal spellings past the first, text-reading versions.
* **both ways.** A `covers` token no derivation produces is an entry outliving
  its candidate — the shape that leaves a registry looking complete over a
  shorter list.
* **a discharge route and an owner, or the entry is a wish.** Both fields, the
  owner from a closed vocabulary, because "someone should measure this" names
  nobody.
* **a claim of discharge owes evidence.** Anything but `pending` needs artifacts
  in the tree; a silicon-class discharge needs the stepping it was taken on, a
  stepping written anywhere must be real whatever the class, and one carrying a
  stepping owes a raw artifact under `assurance/board/` — a rule met by any file
  that merely exists is met by `README.md`, which is how the review reached the
  hardware axis. That sentence then stood over that axis ALONE for as long as it
  was written down: on every other row `evidence = ["README.md"]` was exit 0,
  measured, and `PLAT-STORE-003`'s discharge records it. [`PROSE_PAGE`] is that
  axis's half and weaker: the comment there says which attacks it does not stop.
* **a maintainer-owned row owes a validated RECORD.** `assurance/board/<id>.toml`,
  plan half refused empty, result half refused while `planned`, an outcome the
  status must match BOTH ways, and SOME commit carrying this `expected` under
  `outcome = "planned"` — which is less than "the expectation predates the run",
  and the gap is priced at [`check_expected_predates`].
* **and a run that happened TRANSCRIBES THE CRITERION it was read against.**
  `outcome = "pass"` is a word, and the word was the whole claim: a record moved
  to `pass` with an `expected` byte-identical to its committed one and every
  clause above green — the plan half non-empty, the expectation unmoved, the
  status agreeing. `arm_taken` is refused unless it is the arm's own label, a
  full stop, and then the WHOLE of that record's `expected`, up to whitespace.
  The whole and not the arm alone: an arm runs to the next label, so criterion
  prose written after the first one belongs to exactly one arm and is dropped by
  every other quotation — `PLAT-ROM-001` is that shape today, and a fabricated
  PASS quoting 126 of its 327 characters was exit 0. An arm with no word after
  its `=` is not one. Not a banned word: `bundle_gate.DISPOSITIONS` measured that
  shape and the cheapest way past a refusal is typing the other word. What this
  still cannot reach is an `actual` that did not happen — nothing here measures a
  board.
* **links resolve.** `supports` names registry properties, `depends_on` and
  `refines` name entries here, `discharges` names constants of the first
  registry — and an entry covering `model:X` must discharge `X`, so the two
  registries cannot drift into two answers about the same constant.
* **a cell stays a cell.** A line break in `statement` or `discharge` — or in a
  record's `expected`, which the page publishes beside the outcome — takes the
  columns after it off the published row. A `<` used to be banned beside it and
  is ESCAPED now: `&lt;` reaches it, so a registry about measurement can write an
  inequality, and the ban's own message said no escape could.
* **a settled result is DATED.** A full-sha `evidence_commit`, read against the
  row's `evidence` and the paths its own `revalidated_by` names; stale is a page.
* **an accepted risk says WHERE it is published.** `out_of_scope_by` resolves to a
  `docs/limitations.md` section that names the row, and that page's ids resolve back.
* **the page is generated.** `docs/platform-assumptions.md` is written from the
  entries and byte-diffed, so a status cannot move without the diff that says so.
* **the unsafe page is held to the tree, both ways.** AGENTS.md requires
  `docs/unsafe.md` updated for every new site and nothing checked it: measured,
  that page's own `Runtime sites:` read 21 over a tree carrying 22, and the two
  `link_section` attributes in `rsk-rsa` were on no line of it. The count is
  derived and compared; so, now, is the FILE list in both directions, the
  numbering (it must partition the runtime sites), and the two markers this
  page's own opening sentence promises under every justification. The first
  version held the files ⊆ only, and a review drove four spellings through it at
  exit 0 ([`check_unsafe_page`]). None of this claims a JUSTIFICATION is right —
  only that page and tree enumerate the same sites.
* **a row NAMES where each site it claims lives, and the page draws the same
  grouping.** `covers` was checked for EXISTENCE both ways and for nothing else,
  which is not something a row can be WRONG about: measured, collapsing all 31
  site keys onto `PLAT-UNSAFE-009` — one of the two `discharged` rows — and
  emptying the other eleven was
  byte-identical output at exit 0. So a row must name the FILE of every site it
  covers in its own words ([`check_covered_files`]), and each numbered section of
  `docs/unsafe.md` names the row it enumerates and spans exactly that row's
  runtime sites ([`check_page_sections`]). Six rows were already wrong about the
  first half in the small.

`contradicts` is the one link kind of stage 1B item 3 left out. No pair in this
registry contradicts another, so the field would have no instance — and a rule
whose only exercise is its own mutation is the thing this programme keeps finding
switched off. It goes in when a real pair arrives.
"""

import ast
import collections
import pathlib
import re
import subprocess
import sys
import tomllib

import claims_gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parents[1]

REGISTRY = pathlib.Path("assurance/platform.toml")
MODEL_REGISTRY = pathlib.Path("assurance/assumptions.toml")
PROPERTIES = pathlib.Path("assurance/properties.toml")
BUNDLES = pathlib.Path("assurance/bundle")
ARTIFACT = pathlib.Path("docs/platform-assumptions.md")
EMU_SHIM = pathlib.Path("tests/emu.py")
USBIP_GUEST = pathlib.Path("scripts/usbip-guest.sh")
UNSAFE_PAGE = pathlib.Path("docs/unsafe.md")
#: The crate coverage ledger. A `state-partial` row names a model and the gap it
#: leaves; [`backend_candidates`] reads the STRUCTURED half of that gap.
CRATE_LEDGER = pathlib.Path("assurance/crates.toml")
#: Where a raw board result lands, and where every maintainer-owned row's RECORD
#: lives whether or not the run has happened: a discharge naming a stepping must
#: cite something from here, or any file in the tree that happens to exist stands
#: in for a measurement. See [`check_board_records`] for what a record must say.
BOARD_EVIDENCE = "assurance/board/"

#: Stage 10's inventory's eleven categories, plus the six the closed slice's own
#: assumption table produced that no hardware table has a row for. The class is
#: what a reader sorts by; it is deliberately NOT what decides whether a row is a
#: board result — the review measured that keying the hardware axis on
#: [`HARDWARE_CLASSES`] printed 0 over a discharged `tool-fidelity` row whose own
#: route reads "a board recording of the same session".
CLASSES = {
    "reset",
    "memory",
    "flash",
    "boot-rom",
    "otp",
    "trng",
    "timers",
    "multicore-xip",
    "input",
    "display",
    "toolchain",
    "tool-fidelity",
    "tool-tcb",
    "crypto-primitive",
    "model-abstraction",
    "threat-model",
    "build-configuration",
}

#: The classes whose discharge is a measurement on silicon, and so must record
#: the stepping. `toolchain` is not one: the Rust memory model and the linker
#: script are read, not measured. This obliges a stepping; it does not decide who
#: HAS one — a row of any class that records a real stepping is a board result.
HARDWARE_CLASSES = frozenset(
    {"reset", "memory", "flash", "boot-rom", "otp", "trng", "timers", "multicore-xip"}
)

STATUSES = {"pending", "discharged", "accepted-risk", "refuted"}

#: Who can actually do the discharging. `maintainer` is the one that means
#: hardware in this repo — see AGENTS.md's maintainer-only list.
OWNERS = {"maintainer", "contributor", "vendor", "upstream"}

HAND_FIELDS = {
    "id",
    "statement",
    "class",
    "discharge",
    "discharge_owner",
    "status",
    "failure_direction",
}
LINKS = ("depends_on", "refines", "discharges", "supports", "covers")
#: Optional because each is answerable ONCE, by the status that earns it: a trigger,
#: a date or a published risk on a row with none is a placeholder — 17 of the first.
OPTIONAL = set(LINKS) | {"evidence", "board_revision", "revalidated_by", "evidence_commit", "out_of_scope_by"}

#: `PLAT-<AREA>-<NNN>`. The area is free so a new class does not need a new
#: pattern, and the number is what makes the id stable across a re-sort.
ENTRY_ID = re.compile(r"^PLAT-[A-Z]+-\d{3}$")

#: A shipped part with a stepping, MENTIONED. `evidence_gate.py` searches a
#: bundle's every leaf with it, because a stepping the evidence depends on turns
#: up in prose; the declaration itself is [`names_a_stepping`]'s.
BOARD_REVISION = re.compile(r"\bRP2350[\s-]+A[0-9]\b")

#: A slice design's assumption id in prose. The bundle carries these as TOML and
#: is the authoritative half; this is the other spelling, because a design page
#: is written before its bundle exists. Narrow on purpose — a looser token reads
#: `SEC-FIDO-001`, `TM-HOST-GATES` and `RP2350-A2` as assumption ids.
SLICE_ID = re.compile(r"\bAS-[A-Z]+-\d+\b")

#: Every page under `docs/`, globbed. A two-name list was the first version and
#: the review drove it: a `docs/store-slice.md` carrying `AS-STORE-1` produced no
#: candidate and owed no entry, silently. A design page is written before its
#: bundle exists, which is the whole reason this half is here.
DESIGN_ROOT = pathlib.Path("docs")

#: The token, on source with comments and string literals REMOVED — which is the
#: rule, not the regex. The review measured the regex alone over raw text: 4 of
#: the 12 files it produced carry the word only in a line saying there is no
#: `unsafe` in them, and a fifth is a code generator emitting the word inside a
#: string. Stripping first means no form has to be enumerated: `unsafe {`,
#: `unsafe fn`, `unsafe impl`, `unsafe extern` and the 2024 `#[unsafe(…)]`
#: attribute all survive it, and prose does not.
UNSAFE = re.compile(r"\bunsafe\b")

#: First-party Rust is every `.rs` EXCEPT these, which is what the rule always
#: meant. A whitelist of roots was the first version and the review drove it: a
#: new top-level crate — `rsk-wipe/`'s own shape — was invisible. `third_party/`
#: is out for the reason `citation_gate.py` gives: a vendored fork's `unsafe` is
#: its author's invariant, not this tree's.
#:
#: A review reported this clause DECORATIVE: emptying the tuple is byte-identical,
#: because none of the 16 vendored `.rs` carries the token even in prose. That
#: verdict is REFUTED, and by the error it shares with the `~n` one below — the
#: arm was run on a tree where the clause cannot fire. Driven on its own defect
#: input (one `unsafe` block added under `third_party/`), the clause INTACT is
#: byte-identical and the clause REMOVED is exit 1 with three findings: the site
#: unclaimed, the page count 22 against 23, and the page naming no site in a
#: vendored file. It is load-bearing the moment a vendored crate grows one.
UNSAFE_EXCLUDED = ("third_party/",)

#: A Rust identifier, and the run of `#[…]` attributes an item may wear before
#: its own head. Both read the LEXED source, so neither can be written by a
#: comment or by the inside of a string.
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ATTR_RUN = re.compile(r"\s*#!?\[")

#: How many words of a site's own code name it. Six is measured and not chosen:
#: at five the two `critical_section::with(|_| unsafe { … })` bodies in
#: `rsk-wipe` agree — both open `connect_internal_flash`, `flash_exit_xip` — and
#: separate on the sixth (`flash_range_erase` against `flash_range_program`).
#: Fewer words collide, more words make an edit three statements away rename the
#: site. It is a FLOOR and not a length: [`site_keys`] spends more words on a
#: collision, so two sites that agree at six and part at seven get seven, and
#: what used to be an ordinal over them is gone.
SITE_WORDS = 6

#: A `name = "value"` pair an attribute DECLARES, read out of raw source. The
#: lexer blanks the value, and for a placement attribute it is the entire claim —
#: see [`unsafe_sites`].
#:
#: The PAIR and not the bare literal, and escape-aware, because a review drove
#: both: `#[unsafe(/* see "alpha" */ link_section = ".data.one")]` named the site
#: after the COMMENT — the one thing reading raw source must not allow — and
#: `#[unsafe(export_name = "a\b", link_section = ".data.one")]` made
#: `[^"\\]*` re-anchor on the escaped quote and capture the text BETWEEN the two
#: literals, so the slug read `export_name-link_section-link_section` and the
#: section name was gone. A pair needs a NAME, and [`unsafe_sites`] refuses one
#: whose name the lexer blanked, which is what puts comments back out of reach.
#: A raw string (`r#"…"#`) matches nothing here and contributes no words: no
#: attribute in this tree writes one, and a rule with no instance is decoration.
ATTR_DECLARED = re.compile(r'([A-Za-z_]\w*)\s*=\s*"((?:[^"\\]|\\.)*)"')

#: What separates two sites whose own code cannot separate them. A character no
#: Rust identifier carries, so `TIED_MARK in key` is the whole test, and
#: [`check_site_ordinals`] reports every key wearing one.
#:
#: The commit that introduced site keys recorded the `~n` removal arm at exit 0
#: and called the clause DECORATIVE. That verdict was wrong and the reason is the
#: most useful thing on this page: the arm was run on a CLEAN tree, where no two
#: sites collide and the clause cannot fire. Driven on its own defect input — a
#: duplicate site added, its substitution asserted — the clause INTACT is exit 1
#: with two findings (`…~2 … claimed by no entry`, and the page count one short),
#: and REMOVED it is exit 0 with the duplicate wholly invisible: the two keys
#: collapse into one that is already registered, and the count comes back into
#: agreement. So `~n` was load-bearing, and what replaced it spends words instead
#: of positions.
TIED_MARK = "~"

#: A site is in a BUILD SCRIPT (host-side, never in the image), or it is a
#: DECLARATION the compiler cannot check rather than an operation — the two
#: things `docs/unsafe.md` counts apart from its runtime sites, and so the two
#: [`runtime_sites`] takes out before comparing with that page's own number.
BUILD_SCRIPT = "build.rs"
DECLARATION_KINDS = frozenset({"attr", "extern"})

#: The page's own count of the sites it enumerates, as it writes it. Anchored on
#: the words rather than on a line, because the sentence is reflowed prose.
RUNTIME_SITES = re.compile(r"Runtime sites:\s*(\d+)")

#: A numbered justification heading of [`UNSAFE_PAGE`]: `### 4.` or `### 5–12.`.
#: All three dashes, because the page writes the en dash, a contributor will type
#: the hyphen, and the em dash is what that page already uses as a separator on
#: the same line — a range spelled with it read as a single number.
NUMBERED_HEADING = re.compile(r"^### (?P<first>\d+)(?:[–—-](?P<last>\d+))?\.(?P<rest>.*)$", re.M)

#: The same heading WITH the registry row it enumerates. Two patterns and not one
#: optional group, because a heading that carries no id has to be a finding rather
#: than a heading the grouping rules do not reach: a review collapsed every site
#: onto one row, deleted the ids from the other seven headings, and the whole
#: thing was byte-identical at exit 0 — the page still showed eight
#: justifications and seven of them anchored to nothing.
#:
#: The id is on the HEADING and not in the registry because the ordinal is the
#: page's — putting `5-12` in a row would be a transcribed position, which is the
#: shape this module refuses.
PAGE_SECTION = re.compile(
    NUMBERED_HEADING.pattern.replace(r"(?P<rest>.*)$", r".*?`(?P<row>PLAT-[A-Z]+-\d{3})`\s*$"),
    re.M,
)

#: What is on the page but not OF it: a fenced block and an HTML comment. Blanked
#: before anything below reads the page, and length-preserving so every offset
#: still lines up. Measured, both ways: a whole numbered justification wrapped in
#: `<!-- -->` — heading, prose and both markers — is invisible in the built book
#: and was byte-identical at exit 0, and so was the same section inside a `~~~`
#: fence. A rule that reads a page as a string reads what the page does not show.
PAGE_HIDDEN = re.compile(r"(?ms)^(?P<fence>```|~~~).*?^(?P=fence).*?$|<!--.*?-->")

#: A URL, taken out before [`RS_PATH`] reads the page. `docs/unsafe.md` links
#: embassy and cortex-m, and a link ending in `.rs` is a claim about somebody
#: else's tree: unstripped, one upstream permalink reddens this gate.
URL = re.compile(r"\bhttps?://\S+")

#: What this page's own opening sentence promises under every justification. A
#: heading whose body was deleted keeps its number and its id, and these are what
#: says the justification went with it.
SECTION_MARKERS = ("*Safe alternative:*", "*Containment:*")

#: A first-party source PATH as the page writes one. It must carry a `/`: the
#: page also says `main.rs` and `core1.rs` as shorthand inside prose about a file
#: it has already named in full, and reading those as claims would make the
#: page's own abbreviations into files that must exist.
RS_PATH = re.compile(r"\b[\w.-]+(?:/[\w.-]+)+\.rs\b")

GENERATED_BY = "Generated by scripts/platform_gate.py --write"


def names_a_stepping(value) -> bool:
    """Whether `value` IS a board revision, rather than mentioning one.

    Both registries that ask "which silicon" call THIS, and not a second copy of
    the token: `re.compile` returns the cached object for the same pattern text,
    so an identity test over two `BOARD_REVISION`s passes over a copy-paste and
    holds nothing. A function has no such cache.

    Whole value, because `search` over an otherwise free field takes "a red Pico
    2 (an RP2350 A2) I had lying around" and publishes it as a board result. Which
    steppings EXIST is Raspberry Pi's roster and not this tree's, so `RP2350 A9`
    is a part with a revision here.
    """
    return bool(BOARD_REVISION.fullmatch(str(value).strip()))


def _toml(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


def slice_candidates(root):
    """Assumption ids the closed slices declare, from both spellings.

    The bundle is structured — `[[assumption]] id` — and is where a slice's
    assumptions actually live once it closes. The design page is prose and comes
    first. Taking only the bundle would let a design table sit unregistered until
    someone closed the slice; taking only the prose would miss `TCB-1`/`TCB-2`,
    which no `AS-` pattern matches.
    """
    found = {}
    for path in sorted((root / BUNDLES).rglob("*.toml")):
        doc = _toml(path)
        for entry in doc.get("assumption", []):
            name = str(entry.get("id", "")).strip()
            if name:
                found.setdefault(name, str(path.relative_to(root)))
    for page in sorted((root / DESIGN_ROOT).rglob("*.md")):
        for name in SLICE_ID.findall(page.read_text(errors="replace")):
            found.setdefault(name, str(page.relative_to(root)))
    return found


def model_candidates(root):
    """Every constant of the first registry.

    All of them, not the ones whose `discharged_by` says "board": a model
    assumption is by construction a fact the model cannot establish, so its own
    discharge is always a statement about the world outside it. Reading the
    prose for a board-shaped word would be a rule bypassed by writing "silicon".
    """
    doc = _toml(root / MODEL_REGISTRY)
    return {
        str(entry["constant"]): str(MODEL_REGISTRY)
        for entry in doc.get("assumption", [])
        if entry.get("constant")
    }


def emu_refusals(root):
    """The suites `tests/emu.py` refuses by name, with the reason it gives.

    Read through `ast`, not a regex over the source. The regex was the first
    version and the review drove four legal spellings past it — single quotes,
    an implicit concatenation across lines, an f-string, and an empty reason —
    each of which parses, and none of which this tree has a formatter to rule
    out. A literal is what the shim actually has, so a literal is what is read.
    """
    tree = ast.parse((root / EMU_SHIM).read_text(encoding="utf-8"))
    for node in tree.body:
        targets = getattr(node, "targets", [])
        if not any(isinstance(t, ast.Name) and t.id == "UNSUPPORTED" for t in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            break
        out = {}
        for key, value in zip(node.value.keys, node.value.values):
            try:
                name = ast.literal_eval(key)
            except ValueError:
                continue
            try:
                reason = ast.literal_eval(value)
            except ValueError:
                # An f-string has no literal value; the KEY is what is derived
                # from, and a suite with an unreadable reason still owes an entry.
                reason = "no literal reason"
            out[str(name)] = str(reason)
        return out
    return {}


def board_only_candidates(root):
    """Refused by the emulator AND not run by the USB/IP guest: no runner at all.

    The guest names its suites two ways — `tests/02_*.py` as a glob and
    `tests/73_otp_keyboard.py` in full — so the match is on the `tests/NN_`
    prefix, which is the head of both. A suite the guest reaches through a
    variable would be over-reported here, and that direction is the safe one: an
    obligation registered that a runner already covers, never the reverse.

    The guest's CODE, not its text. Reading it whole was the first version and
    the review drove it both ways: a comment naming a board-only suite made its
    obligation disappear, and a comment naming a registered one turned a live
    obligation red with "no derivation produces it" — where the fix reads as
    deleting the row. `gate_lines` is imported here for exactly this and was not
    being used.
    """
    guest = "\n".join(
        gate_lines.split_at_comment(line)[0]
        for line in (root / USBIP_GUEST).read_text(encoding="utf-8").splitlines()
    )
    return {
        name: f"{EMU_SHIM} UNSUPPORTED ({reason})"
        for name, reason in emu_refusals(root).items()
        if f"tests/{name.split('_')[0]}_" not in guest
    }


def _blank(found):
    """A match's span, with every non-space character replaced by a space.

    Length-preserving, so an offset taken after the substitution still lines up
    with the file — the same discipline `gate_lines.rust_code` keeps, and the
    reason a blanked region cannot shift a `re.M` anchor onto the wrong line.
    """
    return re.sub(r"\S", " ", found.group(0))


def _matching(code, i, opener, closer):
    """The index just past the `closer` that balances the `opener` at `i`."""
    depth = 0
    while i < len(code):
        if code[i] == opener:
            depth += 1
        elif code[i] == closer:
            depth -= 1
            if not depth:
                return i + 1
        i += 1
    return len(code)


def _past_attributes(code, i):
    """Past a run of `#[…]`, so an attribute site is named by the ITEM it decorates.

    `#[inline(never)]` sits between `rsk-rsa`'s second `link_section` and the
    `fn` it places; without this the site is named `inline-never-pub-fn-step`,
    which renames it when an unrelated attribute is added beside it.
    """
    while (found := ATTR_RUN.match(code, i)) is not None:
        i = _matching(code, found.end() - 1, "[", "]")
    return i


def unsafe_sites(code, raw):
    """(offset, kind, words) per `unsafe` token in already-lexed Rust `code`.

    The KIND is the token that follows: `fn`, `impl`, `extern`, an `attr` for the
    2024 `#[unsafe(…)]` form, and `block` for everything else. The WORDS are the
    site's OWN code — its balanced `{ … }`, or up to the `;` where it has none —
    and [`site_keys`] takes the first [`SITE_WORDS`] of them.

    Deliberately content and not position. An ordinal — the n-th `unsafe` in the
    file — is derivable and stable-looking and is the shape this repo has already
    been bitten by: inserting a site above another renumbers every one below it,
    the candidate SET grows by one, and each surviving row keeps a key that now
    denotes a different site. That is green, and it is a row whose justification
    has silently re-pointed. A slug moves only when the site's own code moves.

    An `attr` reads past its attribute to the item AND takes the VALUES it
    declares out of `raw`, which is the one place this module reads source the
    lexer has not blanked. The reason is measured: with the literal dropped, the
    whole subject of `PLAT-UNSAFE-010` and `-011` — WHICH section the item is
    placed in — is invisible, and renaming `.start_block` to anything at all was
    byte-identical output at exit 0.

    Reading raw source is exactly what this module refuses everywhere else, so
    the door is held open one inch: a value counts only when its NAME survives
    the lexer. A review drove the version without that clause and a comment wrote
    the slug — `#[unsafe(/* see "alpha" */ …)]` produced
    `attr:link_section-alpha-…`, which then moves when the comment is edited.
    A name inside a comment is blanked in `code`, and that is the whole test.

    What this still cannot see is a section named INDIRECTLY:
    `#[unsafe(link_section = SEC_A)]` keys on `sec_a`, not on what `SEC_A`
    expands to, so changing the constant's VALUE is invisible. No attribute in
    this tree writes one; a row that starts to would owe a different rule.
    """
    for found in UNSAFE.finditer(code):
        after = found.end()
        while after < len(code) and code[after].isspace():
            after += 1
        if code[after : after + 1] == "(":
            kind = "attr"
            end = _matching(code, after, "(", ")")
            item = _past_attributes(
                code, next((i for i in range(end, len(code)) if code[i] not in ") ]\t\r\n"), end)
            )
            stop = min(
                (p for p in (code.find(c, item) for c in "{;=") if p >= 0),
                default=len(code),
            )
            declared = " ".join(
                pair.group(2)
                for pair in ATTR_DECLARED.finditer(raw, found.end(), end)
                if not code[pair.start(1)].isspace()
            )
            span = f"{code[found.end():end]} {declared} {code[item:stop]}"
        else:
            word = WORD.match(code, after)
            kind = word.group(0) if word and word.group(0) in ("fn", "impl", "extern") else "block"
            brace, semi = code.find("{", found.end()), code.find(";", found.end())
            end = (
                _matching(code, brace, "{", "}")
                if brace >= 0 and (semi < 0 or brace < semi)
                else (semi + 1 if semi >= 0 else len(code))
            )
            span = code[found.end() : end]
        words = [w.lower() for w in WORD.findall(span) if w != "unsafe"]
        if words and words[0] == kind:
            words = words[1:]  # `extern:extern-…` says the same thing twice
        yield found.start(), kind, words


def site_keys(code, raw):
    """`<kind>:<slug>` per site, in source order; a collision separated by MORE
    of the colliding sites' own words, never by where they sit.

    A plain `~2` over the duplicates was the first version and it carries the
    exact defect the ordinal above was rejected for, measured rather than
    reasoned: register `~2`, then SWAP the two colliding functions in the file
    and the output is byte-identical at exit 0 with each row's justification
    silently attached to the other one. Extending the slug instead moves a key
    only when the code under it moves.

    The ordinal survives for sites whose word lists are EQUAL, where no amount of
    their own code separates them — and there it can never be silent, because
    [`check_site_ordinals`] reports it. That is the honest residue: two sites the
    registry cannot name apart, said out loud rather than numbered.
    """
    sites = [(kind, words) for _offset, kind, words in unsafe_sites(code, raw)]
    seen = {}
    for index, (kind, words) in enumerate(sites):
        rivals = [
            other
            for position, (other_kind, other) in enumerate(sites)
            if position != index and other_kind == kind and other[:SITE_WORDS] == words[:SITE_WORDS]
        ]
        length = SITE_WORDS
        while rivals and length < len(words):
            length += 1
            rivals = [other for other in rivals if other[:length] == words[:length]]
        key = f"{kind}:" + ("-".join(words[:length]) or "anonymous")
        seen[key] = seen.get(key, 0) + 1
        yield key if seen[key] == 1 else f"{key}{TIED_MARK}{seen[key]}"


def unsafe_files(root):
    """rel -> (its lexed code, its raw text), per first-party `.rs` with the token."""
    out = {}
    for rel in sorted(gate_lines.tree_files(root)):
        if rel.suffix != ".rs" or str(rel).startswith(UNSAFE_EXCLUDED):
            continue
        raw = (root / rel).read_text(errors="replace")
        code = gate_lines.rust_code(raw)
        if UNSAFE.search(code):
            out[rel] = (code, raw)
    return out


def unsafe_candidates(root):
    """Every `unsafe` SITE of first-party Rust, keyed by its own code.

    Per FILE was the first version and it is the finding this replaced: seven
    candidates over thirty-one sites, all seven claimed by one entry, so
    `docs/unsafe.md`'s twenty-one numbered justifications stood behind a single
    registry row and a new `unsafe` in a file that already had one was **exit
    0** — the both-ways rule cannot see a candidate that did not change.
    """
    return {
        f"{rel}#{key}": f"an `unsafe` site in {rel}, justified in {UNSAFE_PAGE}"
        for rel, (code, raw) in unsafe_files(root).items()
        for key in site_keys(code, raw)
    }


def check_site_ordinals(found, findings):
    """The one position left in a site key, and it is never silent.

    [`site_keys`] separates a collision with the sites' own words; what it cannot
    separate is two sites whose word lists are EQUAL, and the `~n` there is a
    POSITION — the thing this whole derivation exists to avoid. So it is reported
    rather than shipped: the registry cannot name those two apart, and a swap of
    their enclosing items would re-point both rows with nothing to see.
    """
    for key in unsafe_keys(found):
        if TIED_MARK in key:
            findings.append(
                f"unsafe:{key}: two sites in {key.split('#', 1)[0]} whose own code"
                " is identical, so the only thing separating them is where they"
                f" sit — reordering them re-points every row that names a `{TIED_MARK}n`"
                " key, with no diff. Registering them does not settle it and this"
                " will stay red until they differ: name a local, or call the"
                " helper the second one wants, so each site says which it is"
            )


def unsafe_keys(found):
    """The `unsafe:` members of a candidate map, with the namespace taken off.

    Selected out of the whole map rather than derived a second time: a second
    walk of the tree is a second answer to which sites exist, and the page rules
    below have to be about the same set the both-ways rule claims.
    """
    return sorted(key.split(":", 1)[1] for key in found if key.startswith("unsafe:"))


def runtime_sites(found):
    """The candidate keys `docs/unsafe.md` counts as RUNTIME sites.

    Its own partition, derived rather than transcribed: that page keeps build
    scripts and the edition-2024 declarations in a section apart from the
    numbered ones, so the number to compare with is the sites that are neither.
    """
    return [
        key
        for key in unsafe_keys(found)
        if pathlib.Path(key.split("#", 1)[0]).name != BUILD_SCRIPT
        and key.split("#", 1)[1].split(":", 1)[0] not in DECLARATION_KINDS
    ]


def check_unsafe_page(root, found, registered, findings):
    """`docs/unsafe.md` has the same members as the tree, both ways.

    AGENTS.md makes updating that page a rule for every new site and no gate read
    it, so the drift went the way an unheld number always does: `Runtime sites:`
    said 21 while the tree carried 22 — the third sieve access, added with the
    section's own prose ("three call sites") and not with its heading — and the
    two `link_section` attributes in `rsk-rsa` were named nowhere on it.

    The first version held the count both ways and the FILES only one way, and a
    review drove four spellings straight through it, each byte-identical at exit
    0: four `.rs` paths added to the page that carry no site, an invented section
    claiming five sites that do not exist, a justification body deleted out from
    under its heading, and all eight numbered headings collapsed onto `### 99.`.
    Each is closed by reading the page's own shape rather than more prose —
    [`PAGE_SECTION`]'s numbering has to PARTITION the runtime sites, the `.rs`
    paths it names have to be the files that carry them, and a section has to
    carry the two things this page's own opening sentence promises under every
    justification (why a safe alternative does not work, and how the risk is
    contained). And then a second review drove three more, all of which are here:
    a section wrapped in an HTML comment or a fence ([`PAGE_HIDDEN`]), a heading
    with its row id deleted ([`NUMBERED_HEADING`]), and an upstream permalink
    ending in `.rs` reddening the ⊇ direction for a file in somebody else's tree
    ([`URL`]).

    What this still does NOT check is whether a justification is RIGHT; that is a
    reading, and the registry rows are where it is written down. What it does now
    check is that the page and the registry draw the SAME grouping: each numbered
    heading names the row it enumerates and spans exactly that row's runtime
    sites, which is what stops one row answering for all of them.
    """
    page = root / UNSAFE_PAGE
    text = PAGE_HIDDEN.sub(_blank, page.read_text(errors="replace") if page.is_file() else "")
    stated = RUNTIME_SITES.findall(text)
    runtime = runtime_sites(found)
    want = len(runtime)
    if len(stated) != 1:
        findings.append(
            f"{UNSAFE_PAGE}: {len(stated)} `Runtime sites: <n>` statements — the"
            " page's own count of what it enumerates is what holds it to the"
            f" tree, and the tree has {want}"
        )
    elif int(stated[0]) != want:
        findings.append(
            f"{UNSAFE_PAGE}: says `Runtime sites: {stated[0]}` and the tree has"
            f" {want} — a site added without its entry leaves the page's own"
            " number as the only thing that says so, which is why it is derived"
        )
    carriers = {key.split("#", 1)[0] for key in unsafe_keys(found)}
    named = set(RS_PATH.findall(URL.sub(" ", text)))
    for rel in sorted(carriers - named):
        findings.append(
            f"{UNSAFE_PAGE}: names no site in {rel}, which carries one —"
            " AGENTS.md makes this page the enumeration, and a file absent"
            " from it is a justification nobody wrote"
        )
    for rel in sorted(named - carriers):
        findings.append(
            f"{UNSAFE_PAGE}: names {rel}, which carries no `unsafe` site — the"
            " enumeration may not be LONGER than the tree either, or a page"
            " that has outlived the code reads as coverage of it"
        )
    check_page_sections(text, runtime, registered, findings)


# The mutation table for the site-key and grouping clauses, driven on THIS
# checkout rather than on the fixture, and each removal arm run on its OWN defect
# input — a removal arm on a clean tree is what recorded the previous `~n` clause
# as decorative when it was load-bearing. Every row is a byte delta against an
# unmutated run, never a bare exit code.
#
#   clause                  defect arm                       arm with the clause out
#   slug extension          ALPHA -> GAMMA on a colliding     ZERO DELTA, exit 0: both
#                           pair: exit 1, `covers '…-alpha',  sites collapse to `…~2` and
#                           which no derivation produces`     the 7th word is past the slug
#   raw attr literal        `.probe_section` renamed: exit 1, ZERO DELTA, exit 0 — which
#                           `covers '…link_section-           is what made PLAT-UNSAFE-010
#                           probe_section-…'`                 and -011 unfalsifiable
#   tied-key report         two byte-identical sites: exit 1, ZERO DELTA, exit 0: `~2`
#                           `whose own code is identical`     derives and says nothing
#   check_covered_files     the 31-site collapse: exit 1, 5x  those 5 findings vanish;
#                           `covers an `unsafe` site in <f>    the collapse is exit 0
#                           and never names that file`         but for the section rules
#   page ⊇ .rs paths        4 paths with no site: exit 1, 4x  ZERO DELTA, exit 0
#                           `names <f>, which carries no`
#   numbering partitions    a fabricated `### 23–27.`: exit 1, ZERO DELTA, exit 0
#                           `cover [1..27] and the tree has 22`
#   section markers         `### 4.`'s body deleted: exit 1,  ZERO DELTA, exit 0
#                           2x `carries no `*Safe …:*``
#   section names a row     `PLAT-BOGUS-999`: exit 1,         ZERO DELTA, exit 0
#                           `is not a row of assurance/…`
#   section size            the collapse: exit 1, 8x `spans   those 8 vanish
#                           N site(s) and the row covers 0`
#   row without a section   the collapse: exit 1, `covers 22  it vanishes
#                           runtime … and has no numbered`
#
# A second review then walked the collapse straight past all of that, and the six
# rows it forced are here too:
#
#   heading carries an id   the collapse with the seven other  ZERO DELTA, exit 0 —
#                           ids deleted from their headings:   the page shows eight
#                           exit 1, 7x `carries no `PLAT-…``   justifications, seven
#                                                              anchored to nothing
#   fences/comments blanked a `### 16–17.` section wrapped in  ZERO DELTA, exit 0, and
#                           `<!-- -->` (and again in a `~~~`   the built page has lost
#                           fence): exit 1, `cover [1..15,     the justification
#                           18..22]` + the row has no section
#   covers names a PATH     a row naming its file only inside  ZERO DELTA on the rule
#                           a URL superstring: exit 1, `never  (the page byte-diff was
#                           names that file`                   the only delta)
#   URLs stripped           an upstream permalink ending .rs:  a FALSE red — `names
#                           ZERO DELTA, exit 0                 github.com/…/gpio.rs`
#   attr name survives      `/* see "alpha" */` before the     the slug reads
#   the lexer               attribute's pair: the slug is      `link_section-alpha-…`
#                           the plain one                      and a COMMENT keys a site
#   escape-aware pair       `export_name = "a\b", link_section the slug reads
#                           = ".data.one"`: both values, in    `export_name-link_section-
#                           order                              link_section` and the
#                                                              section name is GONE
#
# What still gets through, measured and not guessed, and both are the same shape:
# a SWAP of two sites between two rows that preserves both group sizes and both
# file sets is byte-identical, exit 0 (`PLAT-UNSAFE-002` and `-003` are one site
# each in one file, so their `covers` can be exchanged with nothing to see).
# Closing it needs the page to enumerate sites by KEY rather than by ordinal,
# which is a page rewrite and not this change. So is a section named INDIRECTLY —
# `#[unsafe(link_section = SEC_A)]` keys on the constant's NAME, never on what it
# expands to; no attribute in this tree writes one.
def check_page_sections(text, runtime, registered, findings):
    """The numbered justifications partition the runtime sites, one row each.

    Four things, and the middle two are the anti-collapse rule. The numbers have
    to be 1..N with nothing missing and nothing twice — a fabricated section and
    eight headings collapsed onto one number both die here. Every numbered
    heading has to CARRY a row id, and then to span exactly the runtime sites
    that row covers, so `covers` is no longer a set the registry may draw any way
    it likes: the page draws it too, and the two have to agree. And a heading
    with no body is a justification that was deleted rather than written, caught
    by the two markers this page puts under every one of them.

    The id clause is the newest and it is the one a review needed: with only the
    span rule, the collapse was reachable again by deleting the ids from the
    seven headings it emptied — every remaining constraint then applied to one
    heading, and the page still showed eight justifications.
    """
    sections = list(PAGE_SECTION.finditer(text))
    anchored = {found.start() for found in sections}
    for found in NUMBERED_HEADING.finditer(text):
        if found.start() not in anchored:
            findings.append(
                f"{UNSAFE_PAGE}: section `{found['first']}` carries no"
                " `PLAT-…` id — the page's numbering IS the registry's grouping,"
                " so a numbered justification anchored to no row is one every"
                " rule below stops applying to"
            )
    # A section's BODY runs to the next numbered heading, or to the end of the
    # page. Sliced rather than split on `###`, so an unnumbered `###` between two
    # of them cannot make a body look empty.
    ends = [match.start() for match in sections[1:]] + [len(text)]
    seen, owners = [], {}
    for found, end in zip(sections, ends):
        first, last = int(found["first"]), int(found["last"] or found["first"])
        seen += list(range(first, last + 1))
        name = found["row"]
        body = text[found.end() : end]
        if name not in registered:
            findings.append(
                f"{UNSAFE_PAGE}: section `{found['first']}` names {name}, which is"
                f" not a row of {REGISTRY} — the page's enumeration is anchored on"
                " the registry, and an id nothing resolves anchors nothing"
            )
        elif name in owners:
            findings.append(
                f"{UNSAFE_PAGE}: {name} has two numbered sections — a row is one"
                " obligation, so two headings over it is a grouping the registry"
                " does not make"
            )
        else:
            owners[name] = last - first + 1
        for marker in SECTION_MARKERS:
            if marker not in body:
                findings.append(
                    f"{UNSAFE_PAGE}: section `{found['first']}` ({name}) carries no"
                    f" `{marker}` — this page's own opening sentence promises one"
                    " under every justification, and a heading whose body is gone"
                    " otherwise reads as an enumerated site"
                )
    if seen != list(range(1, len(runtime) + 1)):
        findings.append(
            f"{UNSAFE_PAGE}: the numbered sections cover {seen or 'nothing'} and"
            f" the tree has {len(runtime)} runtime site(s) — the numbering is the"
            " page's own partition of them, so a gap, a repeat or a number past"
            " the end is a site enumerated twice or not at all"
        )
    for name, entry in sorted(registered.items()):
        covered = sum(1 for key in runtime if f"unsafe:{key}" in entry.get("covers", []))
        if covered and name not in owners:
            findings.append(
                f"{name}: covers {covered} runtime `unsafe` site(s) and has no"
                f" numbered section in {UNSAFE_PAGE} — the page is the enumeration"
                " and a row that claims sites it does not enumerate is one row"
                " answering for another's"
            )
        elif name in owners and owners[name] != covered:
            findings.append(
                f"{name}: its {UNSAFE_PAGE} section spans {owners[name]} site(s)"
                f" and the row covers {covered} — the page and the registry are"
                " two halves of one grouping, and a `covers` set nothing else"
                " draws is a set one row can grow to hold every site"
            )


def backend_candidates(root):
    """Every semantic a crate-ledger row declares its model ABSTRACTS.

    The `abstracts` LIST, never the `gap` prose beside it. A regex over the prose
    was the obvious first reading and it is the shape this module refuses
    everywhere else: `rsk-store`'s gap sentence names six mechanics in running
    text, and which of the six are obligations is a decision, not a noun phrase a
    pattern can pick out. So the decision is written down as a list, in the ledger
    rather than here, and the both-ways rule does the rest -- a row deleted from
    `assurance/platform.toml` alone leaves its semantic claimed by nobody.

    Keyed `<crate>/<semantic>` because a semantic name is only unique per crate,
    and read for EVERY class: `abstracts` on a `pure` row would be a modelling
    claim in the wrong place, and producing its candidate is what says so.
    """
    doc = _toml(root / CRATE_LEDGER).get("crate", {})
    return {
        f"{crate}/{semantic}": f"{CRATE_LEDGER} [{crate}] abstracts"
        for crate, entry in sorted(doc.items())
        for semantic in entry.get("abstracts", [])
        if str(semantic).strip()
    }


def candidates(root):
    """namespace:key -> where the derivation found it."""
    out = {}
    for prefix, found in (
        ("slice", slice_candidates(root)),
        ("model", model_candidates(root)),
        ("board-only", board_only_candidates(root)),
        ("unsafe", unsafe_candidates(root)),
        ("backend", backend_candidates(root)),
    ):
        for key, where in found.items():
            out[f"{prefix}:{key}"] = where
    return out


#: Below this a derivation found none of a source that is there — the
#: loop-over-an-empty-set shape. Each is 1 and not a transcribed count: what
#: ratchets the sets is the both-ways rule, which turns a source that stopped
#: being read into one unclaimed-`covers` message per entry that named it.
FLOORS = {"slice": 1, "model": 1, "board-only": 1, "unsafe": 1, "backend": 1}


def entries(root, findings):
    """The registry's entries by id, with the shape rules applied."""
    doc = _toml(root / REGISTRY)
    for key in sorted(set(doc) - {"assumption"}):
        findings.append(
            f"{REGISTRY}: top-level `{key}` — the file holds `[[assumption]]`"
            " tables and nothing else"
        )
    out = {}
    for entry in doc.get("assumption", []):
        name = str(entry.get("id", "")).strip()
        if not ENTRY_ID.match(name):
            findings.append(
                f"{REGISTRY}: entry id {name or '(none)'!r} is not `PLAT-AREA-NNN`"
            )
            continue
        if name in out:
            findings.append(f"{name}: a second entry under the same id")
            continue
        out[name] = entry
    return out


def check_shape(name, entry, findings):
    """The fields only a person can write, and the closed vocabularies."""
    missing = HAND_FIELDS - set(entry)
    if missing:
        findings.append(f"{name}: is missing {sorted(missing)}")
    for key in sorted(set(entry) - HAND_FIELDS - OPTIONAL):
        findings.append(
            f"{name}: `{key}` is not a field of this registry — the hand-written"
            f" set is {sorted(HAND_FIELDS)} plus {sorted(OPTIONAL)}"
        )
    if entry.get("class") not in CLASSES:
        findings.append(
            f"{name}: class {entry.get('class')!r} is not one of {sorted(CLASSES)}"
        )
    if entry.get("status") not in STATUSES:
        findings.append(
            f"{name}: status {entry.get('status')!r} is not one of {sorted(STATUSES)}"
        )
    if entry.get("discharge_owner") not in OWNERS:
        findings.append(
            f"{name}: discharge_owner {entry.get('discharge_owner')!r} is not one"
            f" of {sorted(OWNERS)} — an obligation nobody owns is a wish"
        )
    if not str(entry.get("discharge", "")).strip():
        findings.append(
            f"{name}: no discharge route — an entry that cannot say what would"
            " settle it can never stop being pending"
        )


#: The suffix a page of prose has here, and the one kind of file a discharge may
#: NOT cite. Everything else is allowed — source, a model, a configuration, a
#: recorded log, a data table — because the defect this closes is narrow and
#: named: `check_evidence` accepted any path that exists, so
#: `evidence = ["README.md"]` on a `model-abstraction` discharge was **exit 0**,
#: measured on this tree before this rule. The board axis already refused that
#: shape ([`BOARD_EVIDENCE`]), and refused it only where the row records a
#: `board_revision`, so the module's own sentence — "a rule met by any file that
#: merely exists is met by `README.md`" — stood unenforced over every row that
#: records none. That was all 74 of them when this was written; `grep -c
#: '^board_revision'` answers 2 now, and 85 of the 87 still have only this rule.
#:
#: WHY THIS KIND. A hand-written page RESTATES a claim; it does not settle one.
#: The registry already has the field for a restatement and requires it —
#: `discharge` — so a page in `evidence` is the same sentence filed twice, and
#: the row then reads as settled by a paragraph someone wrote.
#:
#: A GENERATED page is not that, and the exemption is DERIVED rather than listed:
#: `claims_gate.generated_pages` reads every gate's own `ARTIFACT`/`GENERATED_BY`
#: pair, so `docs/assurance-matrix.md` — `PLAT-BUILD-001`'s second artifact — is
#: evidence because `matrix_gate.py` writes it from data, while a page that
#: merely SAYS it was generated is not (that gate's own drive: three self-exempt
#: spellings at exit 0). A blanket "no `.md`" would have reddened an honestly
#: discharged row, which is the false red this half exists to avoid.
#:
#: That mapping is asked through [`claims_gate.is_generated`] and not read here,
#: because reading it here read the KEY and stopped — the claim without the
#: agreement, which is strictly weaker than the gate the mapping comes from.
#: Measured: `docs/assurance-matrix.md` with its own header line deleted, a page
#: `matrix_gate.py` claims and no longer marks, was **exit 0** as evidence.
#:
#: NOR THE PAGE THIS GATE WRITES, which the carve-out let straight back in:
#: [`ARTIFACT`] is rendered from this registry and [`render`] emits every row's
#: `discharge` verbatim, so `PLAT-STORE-003` `discharged` with
#: `evidence = ["docs/platform-assumptions.md"]` was **exit 0** — the row citing
#: its own restatement. [`circular`] is that clause, and it is not `ARTIFACT`
#: alone: `docs/assurance-vector.md` names 67 of these rows, because
#: `evidence_gate.py` renders it partly from this registry, and citing it is the
#: same loop one hop out.
#:
#: EVERY path, not one of them. "At least one artifact" leaves the reviewer's
#: obvious move open — append `README.md` to a row that already cites three real
#: files and nothing sees it — and this module already refuses decoration in the
#: other direction ("an artifact nothing rests on is decoration").
#:
#: WHAT IT DOES NOT CHECK, said plainly because no shape rule can check
#: RELEVANCE and pretending otherwise is the claim inflation this registry
#: exists to refuse:
#: * not relevance. `evidence = ["deny.toml"]` on a `model-abstraction` discharge
#:   is still exit 0, measured. The rule refuses a KIND of file, never an
#:   unrelated one, and a reviewer reading this row still has to read the file.
#: * not `.txt`. `formal/floors.txt` is a verdict table and legitimate evidence
#:   for a run claim, so the suffix cannot stand for "prose" in general.
#: * not a generator that lies about what it writes. The carve-out is rooted in a
#:   DECLARATION — nothing here imports or runs a `*_gate.py` — so appending an
#:   `ARTIFACT`/`GENERATED_BY` pair to a script that generates nothing still
#:   mints an exemption. Measured on `scripts/spdx_gate.py`, which has neither
#:   and no `--write` at all: four appended lines made `evidence = ["README.md"]`
#:   legal registry-wide, exit 0. What the header half above costs that move is a
#:   second edit — the page must carry the marker too, so `README.md` has to be
#:   rewritten as well as named. Closing it outright means executing every other
#:   gate's renderer from this row, and that is a bigger thing than it buys.
#: * not the strong form. What makes [`BOARD_EVIDENCE`] work is that
#:   `assurance/board/<ID>.toml` is a file this gate SEPARATELY VALIDATES, field
#:   by field, against the row. The non-hardware analogue was measured and
#:   rejected: tying evidence to the row's own candidate turns `PLAT-CRED-004`
#:   RED — none of its three artifacts names its `covers` key `AS-CRED-5` or its
#:   own id — and `PLAT-BUILD-001`'s `firmware/Cargo.toml` names neither
#:   `AS-AUTH-2` nor `AlwaysUvShipped`, leaving only the generated page to tie
#:   the row to itself, which is circular. The real strong form is a validated
#:   `assurance/discharge/<ID>.toml` per row, and its cost is a record, a field
#:   contract, a floor and a mutation table for three live discharges. That is
#:   the shape to take when the count grows, not at three.
PROSE_PAGE = ".md"


def in_tree(rel, tree):
    """Whether `rel` is a file this checkout HAS, spelled the way it spells it.

    `(root / rel).exists()` was the first version and it answered two questions
    this rule never asked. A DIRECTORY passed: `evidence = ["docs"]` was **exit
    0**, which is this module's own "met by `README.md`" sentence with "the
    directory `README.md` sits in" substituted. And so did a spelling that is not
    in the tree at all: APFS folds case while [`PROSE_PAGE`] does not, so
    `evidence = ["README.MD"]` — the literal page the whole rule exists to refuse
    — was exit 0 on the machine this is developed on, and would have gone red on
    a case-sensitive runner as `is not in the tree`, which is the right colour for
    the wrong reason. `gate_lines.tree_files` is git's own listing: case-exact,
    with no directories in it, so both spellings go one colour on both.
    """
    return pathlib.Path(str(rel)) in tree


def hand_written(root, rel, generated):
    """Whether `rel` is a page of prose rather than an artifact.

    Case-folded, because a suffix is a spelling: [`in_tree`] has already settled
    that the path is git's own, so what is left to ask is what KIND of file it
    is, and `docs/UPPER.MD` is a page.

    `generated` is [`claims_gate.generated_pages`]'s mapping, computed once by
    [`audit`] and passed in: it opens every `scripts/*_gate.py`, and calling it
    per entry read them once for each of the registry's rows. What decides is
    that gate's own [`claims_gate.is_generated`] rather than this module's
    reading of its mapping — the key without the header was the weaker half of
    the same test, over the same data.
    """
    if not str(rel).lower().endswith(PROSE_PAGE):
        return False
    text = claims_gate.normalise((root / str(rel)).read_text(errors="replace"))
    return not claims_gate.is_generated(rel, text, generated)


def circular(root, name, rel, generated):
    """Whether `rel` is this registry, or a page rendered from it that names `name`.

    A row cannot be settled by a copy of itself. [`ARTIFACT`] is named outright
    because this gate writes it FROM this registry, whatever it happens to print
    there; so is [`REGISTRY`], the row's own home.

    The derived half is the one that answers "or any page generated from this
    registry": a generated page that NAMES the row carries the row, which is what
    being rendered from it means in the only sense that matters here. Measured,
    that is not a hypothetical second member — `docs/assurance-vector.md` names
    67 of these rows because `evidence_gate.py` renders its outstanding list from
    `platform_gate.entries`, and `docs/assurance-bounds.md` names three. Reading
    the page rather than the generator's source is deliberate: which pages a
    script writes is a declaration ([`PROSE_PAGE`] says what that costs), while
    which pages carry this row is a fact about the bytes.
    """
    path = pathlib.Path(str(rel))
    if path in (ARTIFACT, REGISTRY):
        return True
    if not str(rel).lower().endswith(PROSE_PAGE) or str(rel) not in generated:
        return False
    return name in (root / path).read_text(errors="replace")


def check_evidence(root, name, entry, findings, generated, tree):
    """A status other than `pending` owes artifacts, and a board owes a stepping.

    `generated` and `tree` have no default on purpose: a defaulted `{}` reads
    every page as hand-written, which is the safe direction, but a defaulted
    `None` treated as "skip" would let a caller switch the rule off by forgetting
    it — and an empty `tree` reads every artifact as absent, which is loud.
    """
    status = entry.get("status")
    evidence = entry.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else [evidence]
    board = str(entry.get("board_revision", "")).strip()
    # Whatever the class. Gating this on HARDWARE_CLASSES was the first version,
    # and the review put "a red Pico 2 I had lying around" in an `input` row.
    if board and not names_a_stepping(board):
        findings.append(
            f"{name}: board_revision {board!r} names no RP2350 stepping —"
            " a part with a revision, not a description of a desk"
        )
    if status in ("discharged", "refuted"):
        if not evidence:
            findings.append(
                f"{name}: status {status!r} with no `evidence` — a discharge"
                " claim with nothing behind it is the status moving on its own"
            )
        for rel in evidence:
            if not in_tree(rel, tree):
                findings.append(
                    f"{name}: evidence {rel!r} is not in the tree — git's own"
                    " listing, which has no directory in it and folds no case"
                )
            elif hand_written(root, rel, generated):
                findings.append(
                    f"{name}: evidence {rel!r} is a hand-written page — a page"
                    " of prose restates the claim rather than settling it, and"
                    " `discharge` is the field this registry already keeps for"
                    " the restatement"
                )
            elif circular(root, name, rel, generated):
                findings.append(
                    f"{name}: evidence {rel!r} carries this row rather than"
                    f" settling it — {REGISTRY} holds the row, {ARTIFACT} is"
                    " rendered from that and emits its `discharge` verbatim,"
                    " and a generated page that names the row is rendered from"
                    " it too, so the claim and its evidence are one sentence"
                )
        if not str(entry.get("revalidated_by", "")).strip():
            findings.append(
                f"{name}: status {status!r} with no `revalidated_by` — a settled"
                " assumption with no trigger stays settled through the change"
                " that unsettles it"
            )
        if entry.get("class") in HARDWARE_CLASSES and not board:
            findings.append(
                f"{name}: a {entry.get('class')} discharge records no"
                " `board_revision` — a platform result names the platform it"
                " was taken on"
            )
        # AWAKE since 2026-09-03: 2 of the 87 rows carry a `board_revision`, so
        # this arm judges them — a board claim owes a [`BOARD_EVIDENCE`] capture.
        if board and not any(str(rel).startswith(BOARD_EVIDENCE) for rel in evidence):
            findings.append(
                f"{name}: a discharge on {board!r} cites no artifact under"
                f" {BOARD_EVIDENCE} — a rule met by any file that merely exists"
                " is met by README.md, which is not a board result"
            )
    elif evidence or board or entry.get("revalidated_by"):
        findings.append(
            f"{name}: status {status!r} carries evidence, a board revision or a"
            " revalidation trigger — an artifact nothing rests on is decoration,"
            " and the entry still reads as undischarged"
        )


def check_links(name, entry, ids, properties, constants, findings):
    """Every link resolves, and `covers`/`discharges` agree about a constant."""
    for kind, universe, what in (
        ("depends_on", ids, "an entry of this registry"),
        ("refines", ids, "an entry of this registry"),
        ("discharges", constants, f"a constant of {MODEL_REGISTRY}"),
        ("supports", properties, f"a property of {PROPERTIES}"),
    ):
        for target in entry.get(kind, []):
            if target not in universe:
                findings.append(f"{name}: {kind} {target!r} is not {what}")
            elif kind in ("depends_on", "refines") and target == name:
                findings.append(f"{name}: {kind} names itself")
    discharges = set(entry.get("discharges", []))
    covered = {c.split(":", 1)[1] for c in entry.get("covers", []) if c.startswith("model:")}
    for constant in sorted(covered - discharges):
        findings.append(
            f"{name}: covers model:{constant} but does not discharge it — the"
            " entry claiming a model constant is the one that says what settles it"
        )
    for constant in sorted(discharges - covered):
        findings.append(
            f"{name}: discharges {constant!r} without covering `model:{constant}` —"
            " then the constant's candidate is claimed by some other entry and the"
            " two registries hold two answers about it"
        )


#: Where a row is allowed to say WHERE a site it covers lives. The union of its
#: own text and its own artifacts rather than the discharge prose alone: a
#: `pending` row has no `evidence` and a settled one has already listed the files
#: there, so requiring one field would move a path from where it belongs to where
#: the rule looks.
SITE_FIELDS = ("statement", "discharge", "evidence", "revalidated_by")


def check_covered_files(name, entry, findings):
    """A row NAMES the file of every `unsafe` site it claims.

    The `covers` relation was checked for EXISTENCE in both directions and for
    nothing else, and that is not a constraint a row can be WRONG about: measured
    on this checkout, collapsing all 31 site keys onto `PLAT-UNSAFE-009` and
    emptying the other eleven was byte-identical output at exit 0 — one row
    answering for every site, under the strongest disposition the registry has
    (`discharged`, which two of the twelve carry). This is the half a row can be
    wrong about. A collapse then has to claim, in the row's own words, that the
    reading covers files the row never mentions, and six rows here were already
    wrong about it in the small: `PLAT-UNSAFE-006` covered a `core1.rs` site
    while its discharge named neither file.

    Deliberately the FILE and not the site key. The key is the site's own code and
    already reddens when it moves; what this adds is that the row says where to go
    and look, which is the thing a reader needs and a collapse cannot fake.

    A PATH the row writes, not a substring of its prose. A substring test was the
    first version and a review walked it: `https://example.invalid/xfirmware/src/
    main.rs.bak` satisfies `firmware/src/main.rs`, so any superstring pays the
    rule. It is the same [`RS_PATH`] the page half uses, which is the point — two
    halves of one rule enforced at two strengths is the weaker one being the rule.
    """
    said = [entry.get(field, "") for field in SITE_FIELDS]
    text = " ".join(
        part for value in said for part in (value if isinstance(value, list) else [str(value)])
    )
    named = set(RS_PATH.findall(text))
    sites = [c.split(":", 1)[1] for c in entry.get("covers", []) if c.startswith("unsafe:")]
    for rel in sorted({site.split("#", 1)[0] for site in sites}):
        if rel not in named:
            findings.append(
                f"{name}: covers an `unsafe` site in {rel} and never names that"
                " file — a row that does not say where its sites are can be"
                " grown to cover any of them, which is how one row comes to"
                " answer for a whole page of justifications"
            )


#: `assurance/board/<ID>.toml`: the raw record a hardware measurement leaves
#: behind, and the reason it is a FILE rather than three more sentences in the
#: registry. Stage 2 item 9 asks for the board, the stepping, the boot
#: configuration, the firmware hash, the cut method, the first-boot capture and
#: BOTH values -- and the split below is what makes the file worth writing before
#: the run: the PLAN half is knowable in advance and the RESULT half is not, so
#: `expected` is pinned where it cannot be back-filled from what the board did.
#:
#: WHO OWES ONE is `discharge_owner == "maintainer"` and nothing else. Keying it
#: on [`HARDWARE_CLASSES`] was the first version and the review refused it with
#: this module's own words: the `CLASSES` comment above already records that the
#: class "is deliberately NOT what decides whether a row is a board result",
#: because a `tool-fidelity` row whose route reads "a board recording of the same
#: session" is a board result. Measured on the first version: 9 rows owed a
#: record while [`render`] told the reader 12 routes end at a board, and renaming
#: one row's class to `toolchain` deleted its obligation. Both numbers come from
#: the same expression now.
BOARD_PLAN_FIELDS = ("method", "boot_config", "expected")
#: `arm_taken` is a RESULT and belongs here for the same reason `actual` does:
#: which arm of `expected` the run took is knowable only after it. It is the
#: field that stops `outcome` being self-declared — see [`check_arm_taken`]. It
#: is also the one entry here that is owed CONDITIONALLY, and the condition is
#: in [`check_board_records`]: a record that states no arm under its outcome has
#: nothing to quote.
BOARD_RESULT_FIELDS = ("board", "stepping", "firmware_sha256",
                       "first_boot_capture", "actual", "arm_taken")
#: Read like any other field -- `note` had no rule at all in the first version,
#: and a review put "Ran it, RP2350 A2, sha 0xdeadbeef, PASSED" in it on a
#: `planned` record at exit 0.
BOARD_OPTIONAL_FIELDS = ("note",)
BOARD_KEYED_FIELDS = ("assumption", "outcome")
BOARD_OUTCOMES = {"planned", "pass", "fail", "inconclusive"}

#: Which registry status each outcome may sit under, in BOTH directions. The
#: reverse direction is the one that has actually gone wrong here: a run that was
#: taken and whose status never moved reads, from the registry alone, exactly
#: like a run nobody took -- PLAT-MEM-001 was that shape until its record was
#: promoted, and this rule is what makes such a promotion a diff in both files.
OUTCOME_STATUS = {"pass": "discharged", "fail": "refuted"}

BOARD_SHA = re.compile(r"[0-9a-f]{64}")

#: How an `expected` states an ARM: an outcome's own name, uppercased, an `=`,
#: and the OPENING OF A SENTENCE. The vocabulary is [`BOARD_OUTCOMES`]'s rather
#: than a second list, less `planned`, which is the state before any arm is taken
#: and so the one outcome with no arm.
#:
#: What the anchor is for, stated narrowly because a review measured the wide
#: version and it was wrong. The earlier claim here was that the anchor closes
#: the 84-character quote a `\b` label opens ("its own PASS = zero exit tells you
#: only that the command was accepted", prepended to PLAT-ROM-002). Re-measured
#: with the anchor reverted to `\b` and that sentence prepended to the real
#: record: the arms parse `['pass', 'pass', 'fail']` and the gate exits 1 saying
#: "`expected` states 2 PASS arms" — a DUPLICATE label, which is a clause of its
#: own in [`check_board_records`]. On the checkout untouched, that revert left
#: `python scripts/platform_gate.py` at exit 0 and fell three pytest cases, two
#: of them on the parser assertion and none on `tree.problems()`. So the anchor's
#: own job is the one shape nothing else sees: a mid-sentence label of an outcome
#: the record states NOWHERE ELSE, which would satisfy [`ARM_REQUIRED`] and let
#: `outcome` name it. Since the [`ARM_MISPLACED`] cases below assert findings
#: rather than the parser, the same revert now falls nine.
#:
#: What it costs is a plan-time red on prose that means the arm. Measured over
#: nine spellings: a semicolon and a colon are sentence ends here and stay green;
#: a comma, an em dash, an opening parenthesis, a `.)` or `."` before the label,
#: an ellipsis, and a sentence-case `Pass =` are all red. That red is worth
#: paying only if it says so — the finding used to read "`expected` states no
#: PASS arm" over an `expected` that visibly states one — so
#: [`ARM_MISPLACED`] is what turns each of those into its own diagnostic.
ARM_LABEL = re.compile(
    r"(?:\A|(?<=[.:;!?])\s+)("
    + "|".join(sorted(o.upper() for o in BOARD_OUTCOMES - {"planned"}))
    + r")\s*=\s*"
)

#: The same label WITHOUT the anchor and without the case, read only to tell an
#: author which red they are looking at. It states no rule: everything it matches
#: and [`ARM_LABEL`] does not is a spelling the record meant as an arm, and the
#: nine measured above are what a message has to name to be worth its red.
ARM_MISPLACED = re.compile(
    r"\b(" + "|".join(sorted(o.upper() for o in BOARD_OUTCOMES - {"planned"}))
    + r")\s*=\s*", re.IGNORECASE
)

#: A WORD in an arm's own body: two or more letters, so digits and punctuation
#: are not one. The floor a stated arm has to clear. Two shapes carry no
#: criterion at all and both are here: `PASS =` with nothing after it, which the
#: first version accepted as an arm and discharged on; and the `PASS = 0.` that
#: prose about a script's exit codes ("FAIL = 1 and PASS = 0.") mints without
#: anyone crafting it. A CHARACTER floor separates neither — `PLAT-DISPLAY-001`'s
#: whole PASS body is `both.`, five characters, so a length that admits this tree
#: admits `0.` with it. Measured over the 33 arms of the thirteen records: the
#: minimum is ONE word and no arm has zero, so the floor reddens nothing here.
#:
#: It is NOT what stops a quotation being twelve characters — [`arm_claim`] is,
#: and it carries the whole `expected` whatever any one arm says. What is left
#: for this floor is the record's own plan: an outcome whose arm has no body has
#: no criterion of its own, and the run that takes it is read against a field
#: that never says what taking it would mean.
ARM_WORD = re.compile(r"[^\W\d_]{2,}")

#: The arms every record owes BEFORE the board is powered, and "before" is a
#: convention here rather than something git is read for. [`check_expected_predates`]
#: asks only that SOME commit carry this `expected` with `outcome = "planned"`;
#: it reads no other field of that version and does not order it against the
#: capture. Driven on the DISCHARGED PLAT-ROM-002, two commits — a "re-plan" that
#: rewrites `expected`, sets `outcome = "planned"`, blanks the result half and
#: moves the registry row back to `pending`, then a second restoring the run —
#: exit 0 at all five points measured, including both intermediates, with the
#: quoted criterion going from 136 characters carrying "the CCID interface is
#: gone" to 39 that carry nothing. Blanking the result half is what removes the
#: red an earlier version of this comment priced the manoeuvre at. So the price
#: of writing an arm late is two commits nobody is looking for.
#: Not INCONCLUSIVE, and the ROSTER is the argument rather than its size, because
#: the size is a number in a comment and this one has already been wrong once (it
#: read five before PLAT-TIMER-003 arrived, and six until the TRNG split):
#: PLAT-OTP-001, PLAT-ROM-001, PLAT-ROM-002, PLAT-TIMER-003 and PLAT-XIP-001
#: state no such arm, and requiring one would put every one of them through those
#: two commits. PLAT-TRNG-001 was on this list until 2026-09-05, when the split
#: moved its board half to PLAT-TRNG-002 and that record states the arm.
#: What makes the honest inconclusive run recordable instead is the
#: other half, in [`check_board_records`]: `arm_taken` is owed only where the
#: record states an arm under the outcome. This tuple is what keeps that escape
#: out of `pass` and `fail`'s reach, so widening it is not a free edit --
#: `test_the_record_vocabulary_is_ratcheted` pins the pair, and
#: `test_an_expected_that_states_no_arm_is_a_finding` parametrizes over a LITERAL
#: and asserts this tuple against it, so narrowing the tuple reddens both cases
#: rather than collecting one fewer.
ARM_REQUIRED = ("pass", "fail")


#: Below this the obligation lost a row rather than discharging one. Four of the
#: TWELVE ROWS LIVE WHEN THIS WAS WRITTEN `covers` nothing and were `depends_on` by
#: nothing, so a review deleted each of them WITH its record and the gate stayed
#: green — the derivations do not produce a candidate for "the timer is monotonic",
#: and nothing else anchored them. A floor is the smallest thing that makes the
#: deletion a diff; what would make it a derivation is stage 10's inventory, which
#: is not this file's. THAT COUNT IS DATED AND NOT LIVE: a number spelled in prose
#: is the thing this constant exists to stop rotting silently, and the sentence is
#: kept as the reason the floor was written, never as a fact about the tree today.
#:
#: RATCHETED 12 -> 13 on 2026-09-05 for `PLAT-TIMER-003`, and the ratchet earns
#: its place rather than following the count: that row is the one the timebase
#: split left owned by nothing — three liveness properties `supports`-ed by a
#: DISCHARGED rate reading while the progress they actually rest on was
#: registered nowhere — so it is exactly the shape the paragraph above describes,
#: a row a later reviewer deletes WITH its record while the gate stays green. It
#: `covers` nothing, so no derivation anchors it. The one thing that names it,
#: `PLAT-TIMER-002`'s `depends_on`, is not an anchor a deletion respects: the
#: deletion takes the link with it and [`check_links`] then has nothing to resolve.
#: Measured on this tree: the row, its record and that link removed together is
#: exit 0 at a floor of 12 and exit 1 at 13, on the finding this constant prints.
#: LOWERING IT IS ALSO RED, and not here — `test_the_record_vocabulary_is_ratcheted`
#: pins it at `>= 13`, because this number is one line and a deletion that edits it
#: in the same diff would otherwise cost a reviewer nothing to miss.
BOARD_ROW_FLOOR = 13


def board_rows(ids):
    """The rows whose route ends at a board: `discharge_owner == "maintainer"`.

    One expression, called by both the obligation and the generated page, so the
    two cannot print different numbers about the same question.
    """
    return {n for n, e in ids.items() if e.get("discharge_owner") == "maintainer"}


def _text(record, key):
    """A field's value, or None if it is not a string at all.

    `str(record.get(key, ""))` was the first version and `str([])` is `"[]"`,
    which is not empty -- so `expected = []`, `expected = 42` and
    `expected = false` all satisfied "the half that must be written before the
    board is powered". Measured, all three at exit 0.
    """
    value = record.get(key)
    return value.strip() if isinstance(value, str) else None


def _spaced(text):
    """One run of whitespace is one space. The only difference `arm_taken` may
    have from the criterion it quotes: a TOML `\"\"\"…\"\"\"` wrapped for a reader is
    the same sentence, and refusing the wrap would buy nothing but a line length.
    It is also why nothing here may say VERBATIM, which two docstrings and the
    published page all did over this call."""
    return " ".join(str(text).split())


#: One arm of an `expected`: its label and the arm's own body. There is no third
#: member any more. A `claim` field held the quotation a discharge had to
#: reproduce — the preamble plus this one arm — and that quotation is what a
#: review measured as droppable: see [`arm_claim`].
Arm = collections.namedtuple("Arm", "outcome body")


def expected_arms(text):
    """The arms an `expected` states — the label, and the arm's own body.

    An arm runs from its label to the next one, so the last arm takes the tail.
    `PLAT-ROM-001`'s FAIL swallows the sentence after it — "No datasheet clause
    states it either way; a vendor erratum settles it as well as a board does",
    which is a statement about how the row may be discharged AT ALL rather than
    about failing. That boundary is what made the old per-arm quotation a rule
    about a FRAGMENT: the sentence is inside exactly one arm, so a PASS discharge
    quoted 126 characters of a 327-character `expected` and dropped 201 including
    that one. Driven on the real checkout, one commit, exit 0. It is not
    repairable by moving the boundary — the tail is inside the last arm's span
    with no marker to tell them apart, and the arm bodies here are not sentences
    (`PLAT-ROM-002`'s FAIL writes "i.e." mid-body), so a sentence-shaped rule
    reds the tree. What is repairable is the quotation, and [`arm_claim`] is it.

    A LIST and not a dict keyed by outcome: two arms wearing one label is a
    malformed record, and [`check_board_records`] says so by name — collapsing
    them here would hide the second.
    """
    marks = list(ARM_LABEL.finditer(text))
    ends = [mark.start() for mark in marks[1:]] + [len(text)]
    return [
        Arm(mark.group(1).lower(), _spaced(text[mark.end(): end]))
        for mark, end in zip(marks, ends)
    ]


def arm_claim(outcome, expected):
    """The ONE value `arm_taken` may carry under `outcome`: the arm, then all of it.

    One expression, called by the rule and by its finding, so the message cannot
    describe a value the check would refuse.

    The whole `expected` and not the arm's own span, because the span is what a
    review drove through. Criterion prose written after the first label belongs
    to exactly one arm and is dropped by every other claim, and that is not a
    contrivance: it is the live shape of `PLAT-ROM-001`, where a fabricated PASS
    quoted 126 characters and left behind the sentence saying an erratum settles
    the row as well as a board does. Quoting everything closes the family — there
    is nothing left in the field to omit. What it does NOT do is make the outcome
    less of a hand-typed word: the label is the only part of this value that
    varies with the outcome, exactly as the old per-arm quotation's label was.
    The gate never measures a board, and no shape of this field will change that.

    Up to whitespace ([`_spaced`]) and not byte-for-byte, so a TOML `\"\"\"…\"\"\"`
    may be wrapped for a reader. "Verbatim" is what this docstring and the
    published page both used to say, and it was false in both.
    """
    return _spaced(f"{outcome.upper()}. {expected}")


def check_arm_taken(rel, record, stated, findings):
    """The whole criterion the run was read against, and `outcome` agreeing.

    `outcome = "pass"` is a word, and a word is free: the flip that provoked this
    rule moved one record to `pass` with an `expected` byte-identical to the
    committed one and nothing else changed, and every rule above read only that
    both strings are non-empty and that one had not moved. What this rule adds is
    a TRANSCRIPTION: the word costs the whole of the criterion beside it, in the
    record's own text, so the operator who types it has the expectation under
    their hand and the reader has it under the outcome.

    What it does NOT do, and what an earlier version of this docstring claimed:
    make the value a quotation of text the record committed BEFORE the board was
    powered. [`check_expected_predates`] asks only that some commit carry this
    `expected` under `outcome = "planned"`, and a commit that says so can be
    written afterwards. Driven on the discharged PLAT-ROM-002: a "re-plan" commit
    rewriting `expected`, blanking the result half and moving the registry row
    back to `pending`, then a commit restoring the run — exit 0 at every point
    including both intermediates, and the quoted criterion went from 136
    characters to 39. Blanking the result half is what removes even the red
    intermediate. So what is enforced is that the tree CONTAINS a planned version
    of this text, not that it predates the run.

    What it also does not reach: an operator who transcribes the right criterion
    and writes an `actual` that did not happen — and `first_boot_capture` is met
    by any existing file that is not the record, so that residue needs no
    fabricated capture either. Nothing in the tree measures a board.

    The two clauses are two `if`s and not an `if`/`elif`, and the second re-states
    `taken` because of it. A chained arm cannot be deleted on its own — the delete
    is a `SyntaxError`, not a green run — and a clause whose deletion arm cannot
    be driven is the shape this file refuses everywhere else.
    """
    quoted = _spaced(_text(record, "arm_taken") or "")
    if not quoted:
        return  # an empty field is the result-half rule's finding, not a second one
    outcome = _text(record, "outcome")
    expected = _text(record, "expected") or ""
    taken = [o for o in sorted(stated) if arm_claim(o, expected) == quoted]
    if not taken:
        want = arm_claim(outcome or "", expected)
        findings.append(
            f"{rel}: `arm_taken` is not this record's `expected` under an arm it"
            " states — the value is the arm's label, a full stop, and then the"
            " WHOLE of `expected`, up to whitespace, because a quotation of one"
            " arm drops whatever the record wrote after the first label."
            f" Wanted: {want[:64]!r}…. Got: {quoted[:64]!r}"
        )
    if taken and outcome not in taken:
        findings.append(
            f"{rel}: `arm_taken` names the {taken[0].upper()} arm under outcome"
            f" {outcome!r} — the arm the run took and the word the registry moves"
            " on are one answer, and a record where they differ has recorded neither"
        )


def check_board_records(root, ids, findings, floor=None):
    """Every maintainer-owned row has a record, and it is complete FOR ITS OUTCOME.

    Not complete in general: a planned record must carry the plan half and must
    NOT carry the result half, because a result field filled before the run is a
    value nothing measured. And a stepping may appear only in `stepping` -- the
    review smuggled a whole board result through `boot_config` and `note` while
    every rule about result fields read `""`.
    """
    owed = board_rows(ids)
    floor = BOARD_ROW_FLOOR if floor is None else floor
    if len(owed) < floor:
        findings.append(
            f"{len(owed)} maintainer-owned row(s), below the floor of"
            f" {floor} — a row deleted with its record takes its"
            " obligation with it, and no derivation produces these candidates"
        )
    seen = set()
    for path in sorted((root / BOARD_EVIDENCE).glob("*.toml")):
        rel = path.relative_to(root)
        try:
            record = _toml(path)
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(f"{rel}: {error}")
            continue
        name = _text(record, "assumption") or ""
        if path.stem != name:
            findings.append(
                f"{rel}: names assumption {name!r} — the file is addressed by its"
                " row and a record filed under another name is read for neither"
            )
            continue
        seen.add(name)
        if name not in ids:
            findings.append(f"{rel}: {name} is not an entry of {REGISTRY}")
            continue
        allowed = set(
            BOARD_PLAN_FIELDS + BOARD_RESULT_FIELDS
            + BOARD_OPTIONAL_FIELDS + BOARD_KEYED_FIELDS
        )
        for key in sorted(set(record) - allowed):
            findings.append(f"{rel}: `{key}` is not a field of a board record")
        for key in sorted(set(record) & allowed):
            if _text(record, key) is None:
                findings.append(
                    f"{rel}: `{key}` is {type(record[key]).__name__} and not text —"
                    " a field read through `str()` is satisfied by an empty list"
                )
        outcome = _text(record, "outcome")
        if outcome not in BOARD_OUTCOMES:
            findings.append(
                f"{rel}: outcome {outcome!r} is not one of {sorted(BOARD_OUTCOMES)}"
            )
            continue
        for key in BOARD_PLAN_FIELDS:
            if not _text(record, key):
                findings.append(
                    f"{rel}: no `{key}` — the half of the record that is knowable"
                    " before the board is powered is the half that must be written"
                    " before it is"
                )
        expected = _text(record, "expected") or ""
        arms = expected_arms(expected)
        stated = {arm.outcome for arm in arms}
        # An EMPTY `expected` is the plan-field rule's finding above and not three
        # more here, the way an empty `arm_taken` is the result-field rule's.
        for missing in (o for o in ARM_REQUIRED if expected and o not in stated):
            # The label is THERE and the anchor is what refused it: say so.
            # Without this branch each of the nine measured spellings -- comma,
            # em dash, `(`, `.)`, `."`, ellipsis, sentence-case `Pass =` -- read
            # "states no PASS arm" over an `expected` that visibly states one.
            # Compared on group(1), because ARM_LABEL's own match starts at the
            # whitespace its lookbehind consumes and ARM_MISPLACED's at the label.
            read = {a.start(1) for a in ARM_LABEL.finditer(expected)}
            misplaced = [
                m.group(0).strip() for m in ARM_MISPLACED.finditer(expected)
                if m.group(1).lower() == missing and m.start(1) not in read
            ]
            if misplaced:
                findings.append(
                    f"{rel}: `expected` writes {misplaced[0]!r} where an arm has to"
                    " OPEN a sentence and be uppercase — a label is a word, and"
                    " prose about a verdict writes the word, so only a label after"
                    " `.`, `:`, `;`, `!`, `?` or at the start of the field is read"
                    " as an arm. A comma, a dash, a bracket or a quote before it"
                    " is not a sentence end here"
                )
                continue
            findings.append(
                f"{rel}: `expected` states no {missing.upper()} arm — `arm_taken`"
                " reproduces this record's `expected` under an arm it states, and"
                " cannot name one that is not there. [`check_expected_predates`]"
                " does not FREEZE this field — it asks only that some commit carry"
                " this `expected` under `outcome = \"planned\"` — so the reason to"
                " write the arm now is that later it costs two commits nobody is"
                " looking for"
            )
        # One label, one arm. It is a rule about the RECORD's plan rather than
        # about the quotation now -- [`arm_claim`] carries the whole field either
        # way -- and what it refuses is a record that says two different things
        # happen under one outcome, so `actual` can meet one and miss the other
        # and `outcome` reads the same. The cheap way to mint the second is prose
        # inside another arm's body, which [`ARM_LABEL`]'s anchor does not reach.
        for double in sorted({o for o in stated
                              if [a.outcome for a in arms].count(o) > 1}):
            findings.append(
                f"{rel}: `expected` states {[a.outcome for a in arms].count(double)}"
                f" {double.upper()} arms — one outcome, two criteria, and a run"
                " that met one of them records the same word as a run that met"
                " the other"
            )
        # A label with nothing behind it is not an arm. Also a plan rule and not
        # a quotation rule: what it refuses is an outcome the record labels and
        # never defines.
        for hollow in (arm for arm in arms if not ARM_WORD.search(arm.body)):
            findings.append(
                f"{rel}: `expected` states a {hollow.outcome.upper()} arm with no"
                " word in it — an arm whose body is empty or a bare number states"
                " no criterion for the outcome it labels, and the run that takes"
                " that outcome is read against a field that never says what taking"
                f" it would mean. Got: {hollow.body[:32]!r}"
            )
        # `expected` reaches the published page now ([`render`]), so it is held to
        # [`CELL_REFUSED`] the way `statement` and `discharge` are — named per
        # record here, refused outright by [`cell`] there. `<` is NOT in that set:
        # [`cell`] escapes it, and `&lt;` was measured through mdBook rendering as
        # a `<`. What is left is the line break, and it is worth naming what that
        # costs a DISCHARGED record: rewrapping `expected` is a new string, which
        # no `planned` commit carries, so a purely typographic repair goes through
        # [`check_expected_predates`]'s two commits. `arm_taken` is compared up to
        # whitespace ([`arm_claim`]) and reaches no page, so it may be wrapped
        # freely -- an asymmetry between the two, stated because it is not one a
        # reader would guess.
        carried = sorted({c for c in expected if c in CELL_REFUSED})
        if carried:
            findings.append(
                f"{rel}: `expected` carries {carried} — {ARTIFACT} publishes it"
                " into a `|`-delimited row, where a line break takes the columns"
                " after it off the page. Write it on one line; `arm_taken` may be"
                " wrapped, because it is compared up to whitespace and published"
                " nowhere"
            )
        # A stepping is a RESULT, so it may live in one field and no other. This
        # is the rule that makes the plan/result split about substance rather
        # than about which key a sentence was typed under.
        for key in sorted(set(record) & allowed - {"stepping"}):
            value = _text(record, key) or ""
            if BOARD_REVISION.search(value):
                findings.append(
                    f"{rel}: `{key}` names a stepping — a board revision belongs"
                    " in `stepping`, where the outcome rules can see it, and"
                    " nowhere else"
                )
        filled = [k for k in BOARD_RESULT_FIELDS if _text(record, k)]
        if outcome == "planned":
            for key in filled:
                findings.append(
                    f"{rel}: outcome 'planned' with `{key}` filled — a result"
                    " field on a run that has not happened is a value nothing"
                    " measured"
                )
        else:
            # `arm_taken` is owed where there is an ARM TO NAME. Without this
            # every honest INCONCLUSIVE run on the six records that state no
            # INCONCLUSIVE arm is red in every direction at once -- naming PASS
            # is the wrong label, a fresh sentence reproduces no `expected`, and
            # leaving the field empty is this loop -- and the only way out is the
            # post-hoc `planned` commit [`check_expected_predates`] exists to
            # make visible. It is not an exemption for `inconclusive`: the
            # condition is the RECORD's, so a record that does state that arm
            # still owes the quote, and [`ARM_REQUIRED`] holds PASS and FAIL open
            # so no word that moves a registry status can reach it.
            owed_fields = [k for k in BOARD_RESULT_FIELDS
                           if k != "arm_taken" or outcome in stated]
            for key in owed_fields:
                if key not in filled:
                    findings.append(f"{rel}: outcome {outcome!r} with no `{key}`")
            if "stepping" in filled and not names_a_stepping(_text(record, "stepping")):
                findings.append(
                    f"{rel}: stepping {record.get('stepping')!r} names no RP2350"
                    " stepping"
                )
            if not BOARD_SHA.fullmatch(_text(record, "firmware_sha256") or ""):
                findings.append(
                    f"{rel}: firmware_sha256 is not a sha256 — the image a board"
                    " result is about is the one field that cannot be recovered"
                    " later, and PLAT-MEM-001 is the row that lost it. Whole"
                    " value: a hash INSIDE a sentence is a sentence"
                )
            capture = _text(record, "first_boot_capture") or ""
            if capture and (not (root / capture).is_file() or capture == str(rel)):
                findings.append(
                    f"{rel}: first_boot_capture {capture!r} is not a file in the"
                    " tree beside this record — a record that is its own evidence"
                    " is the `met by README.md` rule one layer in"
                )
            check_expected_predates(root, rel, record, findings)
            check_arm_taken(rel, record, stated, findings)
        want = OUTCOME_STATUS.get(outcome)
        status = ids[name].get("status")
        if want and status != want:
            findings.append(
                f"{rel}: outcome {outcome!r} under a {status!r} row — {REGISTRY}"
                f" must read {want!r} or the measurement was taken and nothing moved"
            )
        if not want and status in ("discharged", "refuted"):
            findings.append(
                f"{rel}: outcome {outcome!r} under a {status!r} row — the status"
                " moved on a record that does not carry the run behind it"
            )
    for name in sorted(owed - seen):
        findings.append(
            f"{name}: maintainer-owned {ids[name].get('class')} row with no"
            f" {BOARD_EVIDENCE}{name}.toml — the expected value has to be on"
            " record before the board is read, not after"
        )


def board_says(root, name, key):
    """One field of one record for the generated page, or why it has none.

    Reported rather than counted: `render` printed the obligation and not what
    the records say, so nine `planned` files and nine PASSes read the same on the
    page the reader is pointed at. `expected` goes the same way and for the same
    reason one layer in — the page published `discharge`, the sentence a row says
    it is discharged BY, and never the criterion the run is read against, so a
    `pass` beside an unmet expectation read exactly like a met one. Measured on
    the page before this: `grep -c 'still owes' docs/platform-assumptions.md` = 0,
    over a record whose own INCONCLUSIVE arm ends on those words.
    """
    path = root / BOARD_EVIDENCE / f"{name}.toml"
    if not path.is_file():
        return "**no record**"
    try:
        return str(_toml(path).get(key, "")).strip() or f"**no {key}**"
    except (OSError, tomllib.TOMLDecodeError):
        return "**unreadable**"


def check_expected_predates(root, rel, record, findings):
    """SOME commit carries this `expected` under `outcome = "planned"`.

    Which is less than the heading this rule used to carry ("`expected` was
    committed BEFORE the run"). What it closes is the ONE-commit shape: a record
    created with `expected` and `actual` together, the expectation written to
    match what the board did. What it does not close is the two-commit shape, and
    the price is worth writing down because two docstrings priced it wrong.
    Driven on the discharged PLAT-ROM-002: commit one rewrites `expected` to a
    weaker question, sets `outcome = "planned"`, BLANKS the result half and moves
    the registry row back to `pending`; commit two restores the run with
    `arm_taken` naming the new text. `python scripts/platform_gate.py` is exit 0
    at all five points measured — before, both working trees, both commits — and
    the criterion went from 136 characters carrying "the CCID interface is gone"
    to 39 that carry nothing. Blanking the result half is what removes the red an
    earlier version priced this at; nothing here reads the capture's date, the
    commit order, or any other field of the older version.

    Read out of git rather than asserted, because the tree cannot tell one
    ordering from the other and history can tell some of it.
    """
    done = subprocess.run(
        ["git", "-C", str(root), "log", "--format=%H", "--", str(rel)],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        findings.append(f"{rel}: git log exited {done.returncode}")
        return
    want = _text(record, "expected")
    for commit in done.stdout.split():
        blob = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{rel}"],
            capture_output=True, text=True,
        )
        if blob.returncode != 0:
            continue
        try:
            older = tomllib.loads(blob.stdout)
        except tomllib.TOMLDecodeError:
            continue
        if _text(older, "outcome") == "planned" and _text(older, "expected") == want:
            return
    findings.append(
        f"{rel}: no committed version of this record carries this `expected`"
        " with outcome 'planned' — a result whose expectation was written in the"
        " same commit is an expectation written after the fact"
    )


def check_bundles(root, ids, findings):
    """A bundle's assumption is registered, and its own `registered` field says so.

    The field is hand-written and was `"no"` on eight of ten rows the day this
    registry did not exist. Derived here rather than read, because a claim about
    a registry that the registry does not have to agree with is the copy this
    tree keeps finding rotted.
    """
    claimed = {
        target
        for entry in ids.values()
        for target in entry.get("covers", [])
        if target.startswith("slice:")
    }
    for path in sorted((root / BUNDLES).glob("*.toml")):
        rel = path.relative_to(root)
        for entry in _toml(path).get("assumption", []):
            name = str(entry.get("id", "")).strip()
            if not name:
                continue
            registered = f"slice:{name}" in claimed
            written = str(entry.get("registered", "")).strip().lower()
            if not written:
                findings.append(f"{rel}: assumption {name} carries no `registered`")
            elif written.startswith("yes") != registered:
                findings.append(
                    f"{rel}: assumption {name} says registered={written[:20]!r} and"
                    f" {REGISTRY} {'does' if registered else 'does not'} claim it"
                )


#: The page that publishes what this project does NOT defend against, and the one
#: an `accepted-risk` row has to point INTO. `scripts/test_threat_gate.py` has a
#: case recording it as cited by nothing yet, and that was literal: before this
#: rule, ZERO rows of any `assurance/*.toml` named it, so stage 9 item 5 and stage 10
#: item 5 — "the accepted risk is published" — were both claims about a page no
#: register referenced and no gate could check.
LIMITATIONS = pathlib.Path("docs/limitations.md")

#: An `out_of_scope_by` value: that page, then a RENDERED anchor. The fragment is
#: an mdBook id and NOT a registry id, which is the one place this parts company
#: with `threat_gate.REF` — `docs/threat-model.md` carries no anchors and is
#: addressed by clause id, while this page is addressed by the heading a reader
#: lands on. Narrow on purpose: `#Cryptography`, `./docs/limitations.md#…`, a bare
#: path and a fragment with a space each fall through every rule below while
#: LOOKING published, which is the spelling `threat_gate.check_sources` refuses in
#: the same words.
OUT_OF_SCOPE_REF = re.compile(rf"^{re.escape(str(LIMITATIONS))}#([a-z0-9_-]+)$")

#: A markdown heading of that page, and the fenced run to skip over it — the two
#: shapes `threat_gate.clause_units` reads `docs/threat-model.md` with, for its
#: reason: a `#` inside a code sample is not a section, and a section that is not
#: there is an anchor that sends a reader nowhere.
PAGE_HEADING = re.compile(r"^(#{1,6})\s+(\S.*?)\s*$")
PAGE_FENCE = re.compile(r"^\s*(?:```|~~~)")

#: This registry's ids as PROSE writes them, which is the other direction of the
#: same citation. How many are on the page is not spelled here: it read `three`
#: until PLAT-TRNG-003 was published there on 2026-09-05 and nothing went red,
#: which is what a count in a comment is worth.
PAGE_ENTRY_ID = re.compile(r"\bPLAT-[A-Z]+-\d{3}\b")


def normalize_id(text):
    """mdBook's own `normalize_id`, which is what decides the anchor.

    Not reasoned about: measured against `book/limitations.html` out of a real
    `scripts/docs.sh build`, where `## Backup & migration` is `backup--migration`
    and `## Hardware / physical` is `hardware--physical`. TWO dashes, because the
    dropped character leaves the space on either side of it — a slugger that
    collapses the run links to an anchor the page does not have, and `lychee
    --offline` does not check fragments, so nothing else in this tree would say so.
    """
    out = []
    for char in str(text):
        if char.isalnum() or char in "_-":
            out.append(char.lower() if "A" <= char <= "Z" else char)
        elif char.isspace():
            out.append("-")
    return "".join(out)


def limitations_page(root):
    """(anchor -> heading text, anchor -> the ids that section names).

    One pass for both, because they are the two directions of one citation: a row
    pins a section, and the section names the row. `setdefault` on a repeated
    anchor keeps the FIRST, which is the id mdBook leaves unsuffixed.
    """
    path = root / LIMITATIONS
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    headings, mentions, anchor, fenced = {}, {}, "", False
    for line in text.splitlines():
        if PAGE_FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        found = PAGE_HEADING.match(line)
        if found:
            anchor = normalize_id(found.group(2))
            headings.setdefault(anchor, found.group(2))
            mentions.setdefault(anchor, set())
            continue
        for name in PAGE_ENTRY_ID.findall(line):
            mentions.setdefault(anchor, set()).add(name)
    return headings, mentions


def check_out_of_scope(name, entry, findings, headings, mentions):
    """An `accepted-risk` row says WHERE its risk is published, and the page agrees.

    The obligation is DERIVED from the page rather than declared here, the way
    `check_bundles` derives `registered`: a row is owed a pin when the page
    already names it. It is deliberately not ALL of them, and the split is by
    KIND rather than by count: `PLAT-MODEL-008` and `PLAT-MODEL-014` are model
    OVER-APPROXIMATIONS whose discharge route reads "nothing to run", and this
    page opens by saying it covers feature and hardware gaps. Minting an anchor
    for them would publish a proof-scope note as a user-facing limitation, which
    is a page saying something it does not mean; the honest reading is that
    `accepted-risk` is carrying two different things and splitting it is the
    maintainer's call. `PLAT-TRNG-003` is the other side of that line and was
    published on 2026-09-05: it is a hardware gap, which is what the page is for,
    and leaving it unpublished would have made [`render`]'s own sentence — that
    the unpublished rows are model over-approximations — false.
    """
    published = {n for ids in mentions.values() for n in ids}
    ref = str(entry.get("out_of_scope_by", "")).strip()
    if entry.get("status") == "accepted-risk":
        if not ref and name in published:
            findings.append(
                f"{name}: {LIMITATIONS} publishes this row and it carries no"
                " `out_of_scope_by` — a risk the page names and the registry does"
                " not point back at is a citation with one end, and which section"
                " publishes it is then a thing only a reader can find"
            )
    elif ref:
        findings.append(
            f"{name}: status {entry.get('status')!r} carries `out_of_scope_by` —"
            " the field says a risk was ACCEPTED and published, and a row that has"
            " not accepted one is pointing at a section about something else"
        )
    if not ref:
        return
    found = OUT_OF_SCOPE_REF.match(ref)
    if not found:
        findings.append(
            f"{name}: out_of_scope_by {ref!r} is not `{LIMITATIONS}#<anchor>` —"
            " the anchor is the mdBook id of a heading, lower-cased with every"
            " dropped character leaving its spaces behind, and any other spelling"
            " resolves to nothing while reading as published"
        )
        return
    anchor = found.group(1)
    if anchor not in headings or name not in mentions.get(anchor, set()):
        why = (
            "is no section of that page"
            if anchor not in headings
            else f"is {headings[anchor]!r}, which does not name this row"
        )
        findings.append(
            f"{name}: out_of_scope_by anchor `#{anchor}` {why} — the pin and the"
            " page have to agree about WHICH section publishes the risk, or the"
            " row points at a heading that stopped being about it"
        )


def check_published_ids(ids, findings, mentions):
    """Every `PLAT-…` the page writes is an entry of this registry.

    The reverse of the rule above and the cheaper half: `docs/limitations.md` sends
    a reader to several of these ids in prose, and a rename or a deletion here
    would leave the page authoritative and pointing at nothing. Not the other
    reverse — holding every SECTION to an accepted-risk row was measured and
    refused: most of that page's sections publish feature gaps (brainpool, X448,
    the USB identity) that are not platform assumptions at all, so the rule would
    be red by construction over content it has no business governing, which is
    the decoration this file refuses everywhere else. The counts that used to
    stand in this paragraph are gone for the reason [`PAGE_ENTRY_ID`] gives.
    """
    for anchor, names in sorted(mentions.items()):
        for name in sorted(names):
            if name not in ids:
                findings.append(
                    f"{LIMITATIONS}#{anchor} names {name}, which is no entry of"
                    f" {REGISTRY} — the page reads as authoritative about a row"
                    " that was renamed or deleted out from under it"
                )


#: The suffixes a path can have in this tree, used to read the in-tree paths a
#: row's own `revalidated_by` names. Filtered through `in_tree` afterwards, which
#: is what makes it a derivation rather than a guess: `formal/*.cfg` and
#: `git grep -n '…' -- crates` both survive this pattern and neither is a file, so
#: git's own listing is what decides.
PROSE_PATH = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:md|toml|tla|cfg|rs|py|sh|txt|log|json|nix|lock)"
)


def revalidation_inputs(root, entry, tree):
    """The files a settled row's claim is ABOUT: its `evidence`, plus every
    in-tree path its own `revalidated_by` names.

    The union and not `evidence` alone, and the reason is measured rather than
    symmetric with `evidence_gate.evidence_inputs`. `PLAT-CRED-004`'s trigger
    sentence names an emit in `formal/gen-configs.sh` that its whole discharge
    rests on, and that file is in no `evidence` list: read from `evidence`
    only, that row is behind ONE input; read from the union it is behind two, and
    the second is the file the row itself says would unsettle it. Nothing is added
    for the other two rows, so this is one measured input on one of three and not
    a wider net for its own sake.

    Not a second hand-written list either — `revalidated_by` is already there and
    already required of a settled row; what is new is reading it instead of only
    printing it.
    """
    evidence = entry.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else [evidence]
    prose = set(PROSE_PATH.findall(str(entry.get("revalidated_by", ""))))
    return sorted({str(rel) for rel in evidence} | {p for p in prose if in_tree(p, tree)})


def last_commit(root, rel):
    """The commit that last touched `rel`, or `""` — never a silent success.

    A git failure returns `""` and `freshness` reads that as NOT covered, which is
    the direction `evidence_gate.git`'s docstring names: a guard that reads a git
    failure as "nothing changed" reports fresh evidence over a history it could
    not open.
    """
    done = subprocess.run(
        ["git", "-C", str(root), "log", "-1", "--format=%H", "--", str(rel)],
        capture_output=True, text=True, check=False,
    )
    return done.stdout.strip() if done.returncode == 0 else ""


def freshness(root, commit, inputs, memo=None):
    """(verdict, the inputs the recorded commit does not cover).

    `evidence_gate.freshness`'s rule, asked of this registry's rows: an input is
    covered when the commit that last touched it IS, or is an ancestor of, the
    commit the row recorded. Pure committed history, so writing the page and then
    committing it cannot change the answer between the two — and so the hole is
    the same one that page names: an uncommitted edit to an input is invisible
    until it lands.

    `memo` is [`settled_freshness`]'s per-run cache of the `git log` half, and it
    is per RUN and not a module global: two rows here share
    `formal/RSKeySecurityState.tla`, and a cache that outlived one call would
    answer from a history a fixture has since committed to.
    """
    known = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True, text=True, check=False,
    )
    if known.returncode:
        return "unknown-commit", []
    memo = {} if memo is None else memo
    behind = []
    for rel in inputs:
        if rel not in memo:
            memo[rel] = last_commit(root, rel)
        last = memo[rel]
        if not last:
            behind.append(rel)  # never committed, or a history that would not open
            continue
        # A commit is its own ancestor, so this is the same answer for one less
        # process — and it is the common one, because the commit a result was
        # taken at is usually the one that wrote the artifacts it rests on.
        if last == commit:
            continue
        done = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", last, commit],
            capture_output=True, text=True, check=False,
        )
        if done.returncode:
            behind.append(rel)
    return ("fresh" if not behind else "stale"), behind


#: The statuses that owe a date. The same pair `check_evidence` already makes owe
#: `evidence` and `revalidated_by`: a result was recorded, so there is a commit it
#: was recorded AT. `accepted-risk` is not one — nothing was measured, so there is
#: no run for a date to be about, and a date there would be the decoration the
#: `elif` above already refuses in its own words.
SETTLED = ("discharged", "refuted")

#: What a date has to LOOK like: a full object name. Not `[0-9a-f]+`, because git
#: resolves an abbreviation and a REF alike — `evidence_commit = "HEAD"` passes
#: `cat-file`, dates the result at whatever is checked out, and reports every row
#: fresh forever, which is this module's "met by README.md" sentence with a
#: revision substituted. Measured: exit 0 before this line. An abbreviation is out
#: for the weaker but real reason that it stops being unique as history grows.
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def settled_freshness(root, registered, tree):
    """id -> (commit, verdict, inputs it is behind), for every dated settled row.

    Computed once by [`audit`] and handed to [`render`], because it shells out to
    git per input and both of them want the same answer.

    What the FILE-level anchor costs, measured at `be18565` and left here rather
    than in the page it is about — a number in a generated page rots with nothing
    to say so, which is this module's own founding complaint. Of the 200 commits
    before that one, 33 touch `firmware/src/main.rs` and so flip `PLAT-UNSAFE-001`
    stale; `git log -L` over the two lines that row covers finds ONE commit in the
    whole history and none of it inside that window. The site axis it wants is the
    `covers` key, which is the site's own code. A `git log -L` anchor was priced
    too: 84 ms against 11 ms for `git log -1 -- <file>` (median of seven), though
    it is CHEAPER than the unbounded `git log -- <rel>` [`last_commit`] runs, so
    the cost is not the argument — the line numbers are.
    """
    out, memo = {}, {}
    for name, entry in sorted(registered.items()):
        commit = str(entry.get("evidence_commit", "")).strip()
        if entry.get("status") not in SETTLED or not commit:
            continue
        inputs = revalidation_inputs(root, entry, tree)
        out[name] = (commit, *freshness(root, commit, inputs, memo))
    return out


def check_freshness(name, entry, findings, vector):
    """A settled row is DATED, and only a settled row is.

    Stage 10 item 3 asks that an assumption mark its dependent claims stale, and
    `grep -c stale` over this file answered 0: the registry had `revalidated_by`,
    a sentence naming what would unsettle a row, and no machine could tell whether
    that had happened. `evidence_gate` had the machine and reads bundles, not this
    file.

    Being STALE is not a finding here, for the reason it is not one there: measured
    over the 17 bundles that record a commit, 11 are stale, so a red on staleness
    is a gate that is red as its resting state. What is a finding is a settled row
    with no date at all, and one whose date this history does not have — the two
    ways the axis stops being computable. The staleness itself lands on
    [`ARTIFACT`], where a row going stale is a diff someone has to write and read.
    """
    commit = str(entry.get("evidence_commit", "")).strip()
    if entry.get("status") in SETTLED:
        if not commit:
            findings.append(
                f"{name}: status {entry.get('status')!r} with no `evidence_commit`"
                " — a result with no date cannot go stale, so `revalidated_by`"
                " stays a sentence nothing checks and the row reads settled"
                " through the change that unsettles it"
            )
    elif commit:
        findings.append(
            f"{name}: status {entry.get('status')!r} carries an"
            " `evidence_commit` — a date on a result nobody took, which is the"
            " same decoration as evidence under an undischarged row"
        )
    if commit and not COMMIT_SHA.fullmatch(commit):
        findings.append(
            f"{name}: `evidence_commit` {commit[:20]!r} is not a full commit sha"
            " — git resolves a ref and an abbreviation alike, so a date written"
            " `HEAD` moves with the checkout and reports the row fresh forever"
        )
    if commit and vector and vector[1] == "unknown-commit":
        findings.append(
            f"{name}: `evidence_commit` {commit[:12]} is not a commit this history"
            " has — an evidence date nothing can check"
        )


def inherits(name, registered):
    """What goes stale with `name`: the properties it supports, then the rows that
    rest on it. Stage 10 item 3's "dependent claims", derived from the links the
    registry already carries rather than from a second list of them.
    """
    onward = sorted(
        other
        for other, entry in registered.items()
        for kind in ("depends_on", "refines")
        if name in entry.get(kind, [])
    )
    return sorted(registered[name].get("supports", [])) + onward


def audit(root, board_floor=None):
    """(findings, one-line summary) for the registry, its candidates and its page."""
    root = pathlib.Path(root)
    findings = []
    found = candidates(root)
    for prefix, floor in sorted(FLOORS.items()):
        seen = sum(1 for key in found if key.startswith(f"{prefix}:"))
        if seen < floor:
            findings.append(
                f"the `{prefix}:` derivation found {seen} candidate(s), below its"
                f" floor of {floor} — its source is there and it read none of it,"
                " which looks exactly like a tree with nothing to register"
            )

    registered = entries(root, findings)
    properties = {
        str(row.get("id"))
        for row in _toml(root / PROPERTIES).get("property", [])
    }
    constants = set(model_candidates(root))

    # Once, not per entry: one opens every `scripts/*_gate.py`, the other shells
    # out to git.
    generated = claims_gate.generated_pages(root)
    tree = set(gate_lines.tree_files(root))
    headings, mentions = limitations_page(root)
    dated = settled_freshness(root, registered, tree)

    owner = {}
    for name, entry in sorted(registered.items()):
        check_shape(name, entry, findings)
        check_cells(name, entry, findings)
        check_evidence(root, name, entry, findings, generated, tree)
        check_freshness(name, entry, findings, dated.get(name))
        check_out_of_scope(name, entry, findings, headings, mentions)
        check_links(name, entry, registered, properties, constants, findings)
        check_covered_files(name, entry, findings)
        for target in entry.get("covers", []):
            if target not in found:
                findings.append(
                    f"{name}: covers {target!r}, which no derivation produces —"
                    " either the candidate is gone and the entry outlived it, or"
                    " the reader that found it stopped reading"
                )
            elif target in owner:
                findings.append(
                    f"{target} is claimed by both {owner[target]} and {name}"
                )
            else:
                owner[target] = name
    for target in sorted(set(found) - set(owner)):
        findings.append(
            f"{target}: derived from {found[target]} and claimed by no entry —"
            " register it or say here why it is not an assumption"
        )

    check_bundles(root, registered, findings)
    check_board_records(root, registered, findings, board_floor)
    check_published_ids(registered, findings, mentions)
    check_site_ordinals(found, findings)
    check_unsafe_page(root, found, registered, findings)

    try:
        want = render(root, registered, dated)
    except (OSError, ValueError, KeyError) as error:
        findings.append(f"{ARTIFACT} cannot be generated: {error}")
    else:
        path = root / ARTIFACT
        got = path.read_text(encoding="utf-8") if path.is_file() else ""
        if got != want:
            findings.append(
                f"{ARTIFACT} is not what the generator writes — run"
                " `python scripts/platform_gate.py --write` and commit the result."
                " A status that moves without this diff is a status that moved"
                " silently"
            )

    counts = {s: sum(1 for e in registered.values() if e.get("status") == s) for s in sorted(STATUSES)}
    summary = (
        f"platform-gate: ok — {len(registered)} assumption(s) over {len(found)}"
        " derived candidate(s); "
        + ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    )
    return findings, summary


#: The two fields of a row that reach the page as free prose, and so the two an
#: escape has an arm for. `class`, `status`, the id, `supports`, the board
#: outcome and the graph targets are closed vocabularies or ids [`check_shape`]
#: and [`check_links`] already refuse — and so is `discharge_owner`, which is why
#: [`render`] passes it through: a clause a rule above it makes unreachable is
#: decoration, and this file's own commit said so while wrapping it anyway.
#: `failure_direction` is hand-written prose and is NOT here, because no
#: generator in this tree renders it: `git grep failure_direction -- scripts/`
#: answers three hits in this file and none outside a test.
#: A board record's `expected` is rendered prose too and is NOT here for a
#: different reason: it is a field of a RECORD and this tuple is read against a
#: registry entry. [`check_board_records`] applies the same [`CELL_REFUSED`] set
#: to it, per record, which is where a record's other field rules already are.
RENDERED_PROSE = ("statement", "discharge")

#: What such a cell may not carry, which is the LINE BREAK and nothing else.
#: Both spellings measured through mdBook rather than reasoned about:
#:
#: * `\n` — a line break ends the row exactly as a bare `|` did. Measured with
#:   one in `PLAT-MODEL-002`'s discharge: the published row rendered four cells,
#:   its Owner and its whole `supports` list came off the page, and the gate,
#:   this suite and `mdbook build` were all **exit 0**. That is the pipe defect
#:   again, past the fix for the pipe defect.
#: * `\r` — the same break, plus a red that never converges: `read_text` folds it
#:   back to `\n`, so the byte-diff finds the page differs from the generator
#:   FOREVER and asks for a `--write` that cannot settle it. Measured: exit 1
#:   after `--write`, with a message about committing the result.
#:
#: `<` WAS here, and a review measured the reason it should not be: `&lt;` is an
#: escape that reaches it. Driven — `PASS = jitter &lt; 1 us` is exit 0 through
#: the gate, `--write` and `scripts/docs.sh check`, and the built HTML renders a
#: `<`. So [`cell`] applies that escape the way it applies `\|`, and a registry
#: whose subject is measurement can write an inequality. What is refused stays
#: refused for a reason no escape answers: a table cell cannot span two lines.
#:
#: NOT `>`: seven rows write one (`->`, `a > b`) and GFM prints `&gt;`. NOT `&`,
#: which three rows write. Nor the fullwidth `｜`, a tab, a leading `#`, a
#: trailing `\`, or a `|` inside a code span — all five measured at exit 0, seven
#: cells, no markup. A clause for a character no row carries and no arm can drive
#: is the shape this file refuses everywhere else.
CELL_REFUSED = "\r\n"


def check_cells(name, entry, findings):
    """The named half of [`cell`]'s refusal, per row and per field.

    Two guards over one rule, and they are not the same guard: this one names the
    entry and the field, which is what a contributor needs; [`cell`] is what
    stops the page being WRITTEN, and it is the only half `evidence_gate.py` has
    — that gate renders the same `statement` into `docs/assurance-vector.md` and
    never calls [`check_shape`].
    """
    for key in RENDERED_PROSE:
        carried = sorted({c for c in str(entry.get(key, "")) if c in CELL_REFUSED})
        if carried:
            findings.append(
                f"{name}: `{key}` carries {carried} — {ARTIFACT} interpolates it"
                " into a `|`-delimited row, where a line break takes Owner and"
                " Supports off the page. Write it on one line"
            )


def cell(text):
    r"""A markdown table cell. An unescaped `|` in prose ends the row otherwise.

    `PLAT-SOURCE-002`'s discharge writes `r.map(|()| tok)`, which wrote NINE
    cells into this table's seven columns: GFM DROPS the excess, so that row
    published a fragment of prose where its owner belongs and no `supports` at
    all. Measured through mdBook, the renderer the page is read in.

    Escaping the BACKSLASH as well was measured and is a REGRESSION: inside a
    table `\|` is the one sequence a code span honours, so `\in` would render
    `\\in` on the four rows that write one, while `\|` -> `\\|` already renders
    `\|` — restoring the `git grep` alternation `PLAT-MODEL-009` means the
    reader to paste, which this page had been eating.

    `<` is escaped here too, and that is a REPAIR rather than a second guard: it
    used to be in [`CELL_REFUSED`], where the message said "no escape reaches" —
    and `&lt;` reaches it. Driven: `PASS = jitter &lt; 1 us` in a record's
    `expected` is exit 0 through the gate, `--write` and `scripts/docs.sh check`,
    and mdBook renders a `<`. Writing the escape here is what lets an author who
    is measuring something write `<` at all; the ban told them nothing.

    [`CELL_REFUSED`] is what no escape reaches — the line break — and it RAISES
    rather than mangling: [`audit`] catches `ValueError` off [`render`] and so
    does `evidence_gate.audit`, so both pages refuse to be generated with a named
    finding, and [`run`] refuses the `--write` rather than writing the damage.
    Collapsing the break instead would end that raise and the two catches with
    it, and would silently reflow a contributor's paragraph into one line.
    """
    text = str(text)
    carried = sorted({c for c in text if c in CELL_REFUSED})
    if carried:
        raise ValueError(
            f"a table cell carries {carried}, which no escape reaches — a line"
            " break ends the row as a bare `|` does, and a cell is one line."
            f" In: {text.strip()[:48]!r}"
        )
    return text.replace("|", "\\|").replace("<", "&lt;")


def fields(names):
    """One half of a board record, as the page names it.

    Derived rather than transcribed: both halves were typed into that paragraph,
    so adding `arm_taken` to [`BOARD_RESULT_FIELDS`] would have left the page
    describing the record this file used to refuse.
    """
    return ", ".join(f"`{name}`" for name in names)


def render(root, registered=None, dated=None):
    """`docs/platform-assumptions.md` as the tree makes it."""
    root = pathlib.Path(root)
    registered = entries(root, []) if registered is None else registered
    if dated is None:
        dated = settled_freshness(root, registered, set(gate_lines.tree_files(root)))
    found = candidates(root)
    rows = sorted(registered.items())
    pending = [n for n, e in rows if e.get("status") == "pending"]
    discharged = [n for n, e in rows if e.get("status") == "discharged"]
    board = sorted(board_rows(dict(rows)))
    out = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        f"<!-- {GENERATED_BY} — do not edit by hand -->",
        "",
        "# Platform assumptions",
        "",
        claims_gate.DISCLAIMER_PARAGRAPH,
        "",
        "The assumptions no model constant can carry. `assurance/assumptions.toml`"
        " holds the other kind — a Boolean TLA constant a configuration assigns"
        " both ways — and refuses these by construction: `M7-Q2` put there answers"
        " `in the registry but no configuration assigns it`, and so does a board"
        " PASS, and so does emulator fidelity. They are statements about a"
        " platform, a tool or an abstraction, and there is no other arm to run.",
        "",
        f"**Discharged: {len(discharged)} of {len(rows)}.** That number is the"
        " point of the page. Everything else is an obligation with an owner and a"
        " named route, and none of it is evidence about anything yet.",
        "",
        "## What discharges what",
        "",
        f"Nothing in this repository can discharge {len(board)} of these rows:"
        " their route ends at a board, and AGENTS.md puts flashing and every"
        " board operation with the maintainer. A row moves off `pending` only"
        " with artifacts in the tree; a silicon-class row additionally with the"
        " stepping it was taken on, any row naming a stepping must name a real"
        f" one, and a row naming one owes a capture under `{BOARD_EVIDENCE}` —"
        " because a rule met by any file that merely exists is met by a README.",
        "",
        f"Each of those {len(board)} owes a RECORD as well —"
        f" `{BOARD_EVIDENCE}<id>.toml` — split into the half that is knowable"
        f" before the board is powered ({fields(BOARD_PLAN_FIELDS)}) and"
        f" the half that is not ({fields(BOARD_RESULT_FIELDS)})."
        " A result field on a run that has not"
        " happened is refused, and so is an `expected` first committed in the"
        " same commit as its result. `expected` is printed here beside the"
        " outcome rather than summarised, because the outcome is one word and the"
        " criterion is the thing it has to have met: a row whose own arm says it"
        " still owes a second instrument reads, in one word, exactly like one"
        " that owes nothing. `arm_taken` is what holds the two together — it"
        " names the arm the run took and then reproduces, up to whitespace, the"
        " WHOLE of the `expected` beside it. The whole and not the arm's own"
        " sentence, because criterion prose written after the first label belongs"
        " to one arm and is dropped by every other quotation: on the row about"
        " the boot ROM's scratch word, a PASS quoting its own arm leaves behind"
        " the sentence saying a vendor erratum settles the row as well as a board"
        " does. It is owed wherever the record states an arm under that outcome,"
        " which is every PASS and every FAIL.",
        "",
        "Two prices this page owes the reader rather than the rule. An arm has to"
        " OPEN a sentence — `PASS = …` after a full stop, colon or semicolon, and"
        " not after a comma, a dash, a bracket or an ellipsis, and not written"
        " `Pass =` — so seven honest spellings are a red at planning time, each"
        " with its own message saying the label is there and misplaced. And what"
        " is enforced about ORDER is smaller than it looks: the gate asks that"
        " some commit carry this `expected` under `outcome = \"planned\"`, not"
        " that the commit predates the run. A record can be re-planned and"
        " re-recorded in two commits, neither of them red, which is what it costs"
        " to weaken a criterion after the board has spoken."
        " What they say today:",
        "",
        "| record | outcome | expected |",
        "|---|---|---|",
        *(
            f"| `{name}` | {board_says(root, name, 'outcome')} |"
            f" {cell(board_says(root, name, 'expected'))} |"
            for name in board
        ),
        "",
        f"The candidates are DERIVED — {len(found)} of them, from the slice"
        " bundles and design pages, the model registry, the suites no runner in"
        " this tree can pass, every `unsafe` SITE in first-party Rust, and the"
        " semantics a crate-ledger row says its model abstracts. An unclaimed"
        " candidate reddens `scripts/platform_gate.py`; so does a claim on a"
        f" candidate that no longer exists. {len(unsafe_keys(found))} of them are"
        " `unsafe` sites, keyed by their own code rather than by a position, so"
        " that a site inserted above another cannot renumber a row onto a"
        " different one — and where two sites agree, the key spends MORE of their"
        " own words rather than numbering them, because a `~2` re-points on a"
        " reorder and that is the same defect one layer down.",
        "",
        "Which sites go under which row is not the registry's to choose alone."
        " `docs/unsafe.md` numbers its justifications, each heading names the row"
        " it enumerates, and the numbering has to partition the runtime sites with"
        " each row's section spanning exactly the sites that row covers. Every row"
        " also has to NAME, in its own words, the file of each site it claims."
        " Without those two, `covers` was checked only for existence in both"
        f" directions: collapsing all {len(unsafe_keys(found))} site keys onto one"
        " discharged row and emptying the eleven others was byte-identical output"
        " at exit 0.",
        "",
        "## The registry",
        "",
        "| ID | Class | Statement | Status | Discharged by | Owner | Supports |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, entry in rows:
        supports = ", ".join(f"`{p}`" for p in entry.get("supports", [])) or "—"
        out.append(
            f"| `{name}` | `{entry.get('class')}` | {cell(entry.get('statement'))} |"
            f" **{entry.get('status')}** | {cell(entry.get('discharge'))} |"
            f" {entry.get('discharge_owner')} | {supports} |"
        )
    settled = [n for n, e in rows if e.get("status") in SETTLED]
    stale = [n for n in settled if dated.get(n, ("", "", []))[1] == "stale"]
    out += [
        "",
        "## Freshness",
        "",
        f"A settled row records the commit its result was taken at, and {len(settled)}"
        " of these do. An input is COVERED when the commit that last touched it is"
        " an ancestor of that one; a row behind any of its inputs is **stale**, and"
        " the claims resting on it inherit that. The inputs are derived, not"
        " listed: a row's `evidence`, plus every in-tree path its own"
        " `revalidated_by` names — which is how `formal/gen-configs.sh` reaches"
        " `PLAT-CRED-004`, whose whole discharge rests on an emit in that file and"
        " whose `evidence` does not mention it.",
        "",
        "Committed history only, so an uncommitted edit to an input is invisible"
        " until it lands — the same hole `docs/assurance-vector.md` names about"
        f" itself. Stale is not a red: {len(stale)} of {len(settled)} are stale"
        " right now, and a gate red in its resting state is one nobody reads. What"
        " it costs instead is this page — a row going stale is a diff.",
        "",
        "That price is worth stating for the `unsafe` rows, because the input is a"
        " whole FILE and the claim is two lines of it. `PLAT-UNSAFE-001` is"
        " anchored on `firmware/src/main.rs`, so ANY commit touching that file"
        " flips it stale and owes this page a regeneration — including the many"
        " that cannot touch what the row is about. The site-level axis such a row"
        " wants is already elsewhere: its `covers` keys are the sites' own code,"
        " so a site that is rewritten reddens the row outright rather than dating"
        " it. Re-anchoring freshness on the site would mean `git log -L` over a"
        " line range — keyed on line numbers that shift, for a second answer to a"
        " question `covers` already answers by content.",
        "",
        "| ID | Taken at | Freshness | Behind | Claims that inherit it |",
        "|---|---|---|---|---|",
    ]
    for name in settled:
        commit, verdict, behind = dated.get(name, ("", "undated", []))
        onward = ", ".join(f"`{c}`" for c in inherits(name, registered)) or "—"
        out.append(
            f"| `{name}` | `{commit[:7] or '—'}` | **{verdict}** |"
            f" {', '.join(f'`{cell(rel)}`' for rel in behind) or '—'} | {onward} |"
        )
    headings, mentions = limitations_page(root)
    accepted = [n for n, e in rows if e.get("status") == "accepted-risk"]
    out += [
        "",
        "## Where the accepted risks are published",
        "",
        f"{len(accepted)} rows accept a risk rather than discharging it, and an"
        " accepted risk that is not published is a decision only this file knows"
        f" about. `{LIMITATIONS}` is where the project publishes them; a row the"
        " page names pins the section back, and the pin and the page must agree"
        " about which section that is.",
        "",
        "| ID | Published as |",
        "|---|---|",
    ]
    for name in accepted:
        ref = str(registered[name].get("out_of_scope_by", "")).strip()
        anchor = ref.partition("#")[2]
        out.append(
            f"| `{name}` | "
            + (f"[{cell(headings.get(anchor, anchor))}]({LIMITATIONS.name}#{anchor})"
               if ref else "**not published there**")
            + " |"
        )
    out.append(
        f"\nThe {sum(1 for n in accepted if not str(registered[n].get('out_of_scope_by', '')).strip())}"
        " unpublished rows are model OVER-APPROXIMATIONS whose discharge route"
        " reads `nothing to run`, and that page opens by saying it covers feature"
        " and hardware gaps. An anchor minted for them would publish a proof-scope"
        " note as a user-facing limitation, so the status word is what is carrying"
        " two different things here, and splitting it is a decision and not a"
        " generated table's."
    )
    out += [
        "",
        "## The graph",
        "",
        "Stage 1B item 3's link vocabulary, less `contradicts`: no pair here"
        " contradicts another, and a link kind with no instance is a rule whose"
        " only exercise is its own mutation.",
        "",
        "| From | Link | To |",
        "|---|---|---|",
    ]
    edges = [
        (name, kind, target)
        for name, entry in rows
        for kind in ("depends_on", "refines", "discharges")
        for target in entry.get(kind, [])
    ]
    for name, kind, target in edges:
        out.append(f"| `{name}` | `{kind}` | `{target}` |")
    out += [
        "",
        f"`supports` is in the table above, on {sum(1 for _, e in rows if e.get('supports'))}"
        f" of {len(rows)} rows. A property it names is CONDITIONAL on that row"
        " while the row is pending; nothing here upgrades a property's evidence.",
        "",
        "## What this page may not be read as",
        "",
        f"- that any of these {len(rows)} statements is known to be true —"
        f" {len(pending)} are `pending`, which means no artifact in this tree"
        " records a result for them. `pending` covers two states this page cannot"
        " tell apart: a run nobody took, and a run that happened and whose capture"
        " never reached a record. A row in the second says so in its own discharge"
        " route, because nothing here can derive it.",
        f"- that the list is complete. {len(FLOORS)} derivations produce it, and"
        " stage 10's inventory names eleven categories — a category with no"
        " candidate source is a category this page cannot see.",
        "- that a discharged row makes a property proved. It removes a condition;"
        " the property's own evidence is `docs/assurance-vector.md`'s.",
        "",
    ]
    return "\n".join(out)


def run(root, write=False, board_floor=None):
    if write:
        # `--write` runs no rule, so [`cell`]'s raise arrives here as the only
        # thing between a refused character and a damaged page. Named rather than
        # a traceback, and the page is left alone: nothing half-written.
        try:
            page = render(root)
        except ValueError as error:
            print(f"platform-gate: {ARTIFACT} not written — {error}", file=sys.stderr)
            return 1
        (root / ARTIFACT).write_text(page, encoding="utf-8")
        print(f"platform-gate: wrote {ARTIFACT}")
        return 0
    findings, summary = audit(root, board_floor)
    if findings:
        print("platform-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: platform_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
