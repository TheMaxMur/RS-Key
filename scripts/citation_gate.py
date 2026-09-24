#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the TLA+ model still points at the code it says it models.

The `formal/*.tla` modules, `formal/README.md` and `formal/comutants.toml` carry
the `file.rs:line` citations — the whole bridge between the model and the
implementation it claims to abstract. [`PAGES`] is the list and the success line
counts them, so neither number is written down here to go stale. They were
checked once, by hand, in a review pass. Code moves; a model whose citations
have rotted is worse than no model, because it reads as authoritative and sends
the next reader to a line that no longer says what it claims. Same failure as a
stale CHANGELOG or an unbumped counter, so it lives beside them.

The same claim is made in code — Kani proof headers, two test files and one fuzz
target cite the call site they stand in for — and for a long time only the
`formal/` half was read. Measured when the code half was added: 42 such
citations, **19 naming code the surrounding prose was never about**, while the
SAME three token gates cited on `formal/README.md` had followed every shift.
`lib.rs:207`, introduced as "the dispatch prologue every CBOR command runs
first", was 79 lines out and pointed at the response *epilogue*. So the code
half is [`code_pages`]: derived from the tree rather than named, because which
proof headers cite is not a decision anyone should be re-transcribing.

The phase-1 `Refines Module!Invariant — SEC-*` tags are the semantic-address
half of the same bridge. This gate shares their assurance check: every tag must
resolve to its defining module and registry row, and every invariant in the two
code-owning configurations must have a production tag.

## What is decidable, and what is not

That `clientpin.rs:35` still *means* what the model says is a review question.
That the file exists, that the line is inside it, and that a range runs forwards
are not, so those are the rules — plus one drift signal that costs nothing: a
citation whose first or last line is **blank**. Measured over every citation the
gate reads, none lands on a blank line, and a line that has drifted onto
one has stopped being the code that was cited. It is not a blanket
content check, for the reason such a rule deserves: one that fires whenever
anything above a cited line moves gets switched off inside a week. What *is*
decidable is narrower, and is the failure this row kept missing — the cited text
still exists in the file, at a different line. [`LOCK`] records what each
citation pointed at, and only a locked line found ELSEWHERE is reported, naming
the line it moved to. An edit in place leaves nothing to find and stays green.
Measured: 75 citations rotted across three commits while this row printed `ok`,
and every one of them was a move.

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

This is the NAMED half only. A derived page is in the set *because* it cites, so
a per-page floor there asserts nothing; [`CODE_PAGES_FLOOR`] and
[`SCRIPT_PAGES_FLOOR`] hold the size of each derived set instead — two numbers,
because one over the union cannot say which finder stopped finding — and what
actually ratchets that half is [`LOCK`]: a page that stops being read turns every
entry it had into an orphan, by name.

Each page must carry at least its [`FLOOR`] citations — [`FLOOR_BY_PAGE`] where a
page legitimately cites fewer, the default otherwise. A regex that has stopped
matching finds nothing, loops over nothing and exits 0 — the shape four guards
in this tree shipped with. Every floor sits well under its page's real count, so
it trips a regex that has stopped matching and nothing else; the per-page
override is there so a tight model is not mistaken for a broken regex, and so no
page is ever padded with citations it does not mean just to clear one number.

## Limits

[`PENDING`] is the debt this row landed with, not a permanent carve-out: three
citations another agent's in-flight commits rotted while this guard was being
written. Each names the commit that broke it and fails once it stops rotting.
It is NOT the tool for a widening's own findings, and the registry half was where
that was decided: an entry there silences a live rot on the next run and is
buried outright by the [`LOCK`] rewrite the widening needs anyway, so the debt
would end up neither reported nor fixed. A widening that reddens the row leaves
it red until the pages are repaired.

It resolves `.rs`, `.sh`, `.txt` and `.py` citations, and only on `.rs` pages,
`.py` pages under `scripts/`, the evidence bundles, the assurance registries and
the named `formal/` ones. The registries were the last substantive citing surface
no gate read, and opening them went the way opening every surface has gone: 122
citations over 9 pages, **4 of them already wrong** — one span whose first line is
now blank, and three bare continuations resolved against the last `.rs` file their
paragraph named when all three mean `RSKeySecurityState.tla`. Same the round
before, which swept the reset class and found **2 of 2** of `security_trace.py`'s
reset citations pointing at the wrong line, and the same every time before that
(`RSKeyAppletPolicies.tla` 1 of 4, `comutants.toml` 15 of 16, the code half 19 of
42, the bundles 31 of 517 — and eight more that RESOLVE and are wrong, which is
what [`KEYED`] below is about).

What cites and is still read by nobody, by family. `CHANGELOG.md` and the
`assurance/bundle/logs/` transcripts cite the tree as it stood and MUST be allowed
to rot; this guard, its own table, `test_impact.py` and `test_kani_sh.py` quote
rot or cite into a `tmp_path`; the `tests/*.py` device scripts and the `docs/`
prose pages carry live model→code claims that only a person reads. `docs/` is by
far the largest and is the next widening rather than an oversight — measured over
this guard's own reader on the day the registries were taken: 229 citations over
6 pages, of which 6 are already wrong, and 4 of those 6 are the SAME four the
registries just surfaced, because `docs/platform-assumptions.md` restates
`assurance/platform.toml`. The other 2 are bare names that resolve in none of
[`SEARCH`]'s five directories, so taking `docs/` needs a repair pass of its own
before the flag flips — the argument [`EXTS`] makes one axis over.
Named here so each stays a decision. A citation *edited in place* still passes, and one that was
wrong the day it was written locks wrong — so the lock diff is a thing to read,
not a proof it hands you. And [`SEARCH`] is
a hand-written list; entries are asserted to exist, not to be used, so an entry
whose last citation goes away sits there harmlessly rather than turning an
unrelated edit red.

## A keyed table is cited by its KEY

A line number is the wrong anchor for a file whose rows have names. Six bundle
citations into `formal/floors.txt` named a `\\*` COMMENT where the sentence was
about a data row; two of the six had been re-anchored by hand that same morning
and rotted again within hours, because the file gained three comment lines. So
[`KEYED`] holds the files whose rows are cited by NAME — `floors.txt:Solo_*.cfg`
— and the check is that the name is some row's key. Comment edits above it move
nothing. The line form still works on the same file and is still locked, because
a citation whose subject IS the prose has no key to name (`floors.txt:50`, whose
sentence is about the undercount that comment carries).

`scripts/check.sh` is the second such file and the worse one, because its rows
move whenever ANY row lands above them. Measured over one day: `SEC-FIDO-002`'s
three citations of the `comutants lint` row were written as `:725` at `b185fc3`,
where line 725 really was that row; by `b66c004` two of the three still said
`:725` — a `counter_writers_gate` COMMENT by then — and the third had been
re-anchored to `:772`; `d544aa1` moved all three to `:785`. The lock recorded the
comment as faithfully as the row and the gate printed `ok` over both. Its rows
have names with SPACES in them, so the key is quoted the way the file itself
writes it: `scripts/check.sh:"comutants lint"`. The bundles are TOML basic
strings, where that arrives as `\\"comutants lint\\"`, so the backslashes are
tolerated — one syntax, two encodings of a quote.

Two rules make a key an anchor rather than a guess, and both are asked of the
whole table rather than of the citations: a KEYED file the tree no longer has is
a dead entry (the rule [`SEARCH`] already has), and a key carried by two rows
names no one row, so it is refused the way an ambiguous basename is. Measured
today: `floors.txt` 70 rows, `check.sh` 113 (99 `run`, 14 `run_tests`), no name
used twice in either.
"""

import pathlib
import re
import sys

import assurance_gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The pages that carry citations: the model modules, the README — whose
#: invariant table a reader consults first, and which cites more finely than the
#: modules do — and the co-refutation ledger. A page absent here is not checked
#: at all, which is the one failure this list can have, so it is the thing to
#: extend when a module starts citing.
#: `formal/RSKeyTokenGate.tla` is DELIBERATELY absent, and the exclusion is
#: stated because a page missing from this tuple is a page nothing checks — which
#: is how `RSKeyAppletPolicies.tla` kept a rotted citation. That module is tier
#: A's REQUIREMENT half: `RequiredGate` is transcribed from CTAP 2.3 and must not
#: be read off the code any more than off the relation, so it cites spec sections
#: and no `file.rs:NNN` at all. Nothing there can rot. Give it an entry the day
#: it names a line of Rust.
PAGES = (
    pathlib.Path("formal/RSKeySecurityState.tla"),
    pathlib.Path("formal/RSKeyAppletSeams.tla"),
    pathlib.Path("formal/RSKeyStore.tla"),
    pathlib.Path("formal/RSKeyRetryLattice.tla"),
    pathlib.Path("formal/RSKeyAdminSurface.tla"),
    pathlib.Path("formal/RSKeyTrustedDisplay.tla"),
    pathlib.Path("formal/RSKeyBootHardening.tla"),
    pathlib.Path("formal/RSKeyTransport.tla"),
    # The applet-policy module was the ninth `.tla` carrying citations and the
    # only one this tuple did not name, so all four of its citations were
    # unchecked — and one had rotted: `rsk-otp/src/lib.rs:564-569` was the swap's
    # write-back tail ending on a blank line, not the access-code gate it claims.
    pathlib.Path("formal/RSKeyAppletPolicies.tla"),
    # The replay harness cites too, and R4c's whole content is a code rule
    # quoted into TLA+ — the one page where a rotted citation would leave the
    # model asserting a gate the firmware no longer has.
    pathlib.Path("formal/TraceSecurity.tla"),
    pathlib.Path("formal/README.md"),
    # The co-refutation ledger cites as finely as the modules and was guarded by
    # nothing: 13 of its 16 citations named a file this gate could not resolve,
    # and two landed on unrelated code — one of them wrong the day it was written.
    pathlib.Path("formal/comutants.toml"),
    # Not a model page but the config generator, and it makes the same kind of
    # model-to-code claim: the two firmware constants its SYMMETRY argument is
    # priced against. Both had moved — `consts.rs:361,334` named `EF_LARGEBLOB`
    # and a doc comment, not MAX_PIN_RETRIES and PIN_MISMATCH_LIMIT.
    pathlib.Path("formal/gen-configs.sh"),
)

#: Where a CITATION IN CODE lives. The `formal/` pages above are named one by
#: one because there are thirteen of them and each was a decision; the code half
#: is DERIVED, because it is not a decision — a Kani proof header or a fuzz
#: target that cites code by line is making exactly the claim this row exists
#: for, and transcribing which ones do is how the next one arrives unchecked.
#: Measured when this was added: 7 files, 42 citations, of which 19 named code
#: the surrounding prose was never about — while the SAME three call sites,
#: cited on the gated `formal/README.md`, had followed the code.
#:
#: `.rs` under these roots and nowhere else. The roots are every first-party
#: Rust of the tree -- the workspace's two non-`crates/` members, the two detached
#: workspaces under `tools/`, and the fuzz targets. `third_party/` is the one
#: `.rs` directory left out, and it is left out because a vendored fork's
#: citations are its author's, not this tree's. The rest of the exclusions are
#: not Rust and each has its own reason. `CHANGELOG.md` cites the tree as it
#: stood at each entry, so its citations MUST be allowed to rot; this guard's own
#: fixtures, and `scripts/citation_gate.py` itself, quote the rotted examples they
#: exist to describe; the `docs/` pages cite in prose and are read by nobody but a
#: person. Named limits, not oversights — see "Limits" above. The `assurance/`
#: registries were the fourth name in that sentence and are no longer: they are
#: [`assurance_pages`] now, counted by the success line, which is the repair for
#: what the sentence used to end on. It carried a "rough count over them" of 62
#: distinct citations "that nothing resolves" — a number typed once, held by
#: nothing, and stale by more than double when it was finally read.
CODE_ROOTS = ("crates/", "firmware/", "fuzz/", "tools/", "rsk-wipe/")

#: Below this the derivation found nothing and every code page silently went
#: unchecked — the loop-over-an-empty-set shape. It is deliberately 1 and not a
#: transcribed count: what ratchets the derived set is [`LOCK`], which turns a
#: page that stops being read into one orphaned entry per citation it had -- by
#: measurement, taking the set from 7 pages to 1 produces 34 orphan messages and
#: no floor message. The floor is the only signal in exactly one state: a tree
#: with no lock file at all, where every lock rule is skipped.
CODE_PAGES_FLOOR = 1

#: The other half of the derivation. The host tooling makes model→code claims in
#: exactly the same shape a proof header does — `security_trace.py` names the two
#: predicates its recorder stands in for — and it was the last substantive citing
#: surface nothing read: the reset sweep found BOTH of its reset citations naming
#: `reset.rs:187` for a predicate that is on `:211`, which `formal/README.md` had
#: right all along.
SCRIPT_ROOT = "scripts/"

#: The `scripts/` files whose citations are FIXTURES rather than claims, each a
#: decision rather than a name pattern — a `test_*.py` rule would hand the next
#: script a free pass by what it is called, which is the argument [`CODE_ROOTS`]
#: makes against reading `foo_tests.rs` off a name. A file added here owes its
#: reason on the line.
#:
#: File-level and not per-citation, measured rather than assumed. Dropping the set
#: outright reddens 62 of the 142 citations these four carry, every one of them a
#: fixture; checking only the citations that write a repo PATH still reddens 31 of
#: 46, and 27 of those are `test_impact.py`/`test_kani_sh.py`, whose trees exist
#: only inside a `tmp_path`. What the narrowing would buy is the 19 path-carrying
#: citations in the two `citation_gate` files, of which 4 are quoted rot on
#: purpose. And it would NOT have caught the rot that raised the question: the two
#: sentences about the derived-invariant fallback wrote a bare `run-tlc.sh:200-203`
#: and a bare `run-tlc.sh` resolves in none of the five [`SEARCH`] directories, so
#: the report would have been "no such file" — the wrong reason, on a citation
#: whose line had simply moved. Both are written `formal/run-tlc.sh:231-234` now,
#: which is the form a narrowing could check; that repair is what a narrowing is
#: worth, and it costs nothing.
SCRIPT_EXEMPT = frozenset(
    {
        # Quotes the rotted citations it exists to describe.
        "scripts/citation_gate.py",
        # This guard's own mutation table: every citation in it is deliberately
        # broken in one direction or another.
        "scripts/test_citation_gate.py",
        # Synthetic trees — `src/lib.rs:8`, `crates/rsk-x/src/torn.rs:9`. Their
        # citations name files that exist only inside a `tmp_path`.
        "scripts/test_impact.py",
        "scripts/test_kani_sh.py",
    }
)


#: The scripts half's own floor, kept apart from [`CODE_PAGES_FLOOR`] rather than
#: shared: one number over the union cannot tell "the `.rs` finder stopped
#: finding" from "the `.py` finder did", and a signal that cannot say which is a
#: signal someone argues away.
SCRIPT_PAGES_FLOOR = 1

#: The evidence bundles, and the third derived half. Every `.toml` directly under
#: here is a page — no "does it cite?" filter, unlike the two halves above:
#: `bundle_gate.py` already holds this directory to a per-row evidence contract,
#: so a bundle that cites NOTHING is a finding rather than a file that opts out.
#: Read off the directory for the reason `bundle_gate.py` gives at its own
#: `BUNDLE_DIR`: a roster written down is a roster to remember to extend, and the
#: next bundle then arrives unchecked. Measured the day this was added: 517
#: citations over the eleven bundles of that day, of which 20 were already wrong
#: by this row's own rules — 12 naming a file the tree does not have, 4 landing
#: on a blank line, 2 past the end, 2 basenames that resolve two ways — plus 11
#: bare continuations bound to nothing. Not one was reachable from any gate before.
BUNDLE_ROOT = "assurance/bundle/"

#: The bundle half's own floor, apart from its two siblings for the same reason
#: they are apart from each other. It is 1, not 17: what a number here can catch
#: is the derivation finding NOTHING, and the roster ratchet — a bundle leaving —
#: is `bundle_gate.py`'s `ROSTER_FLOOR`, which already refuses it. Two guards
#: holding one number is how the second one comes to disagree with the first.
#:
#: It said `BUNDLE_FLOOR` until it was read by hand, and that name EXISTS — it is
#: `bounds_gate.py`'s, and it is 17 as well — so the sentence named a real
#: constant of the right value in the wrong guard. Nothing here could see it:
#: this file resolves `file:line` SPANS, and a symbol named in prose carries no
#: line to resolve, so a reference to a name is checked by a reader or by no one.
BUNDLE_PAGES_FLOOR = 1


def _cites(root, rel):
    """Whether `rel` carries a citation.

    `errors="replace"`: `tree_files` lists untracked files too, and one that is
    not valid UTF-8 would end this row in a traceback -- which reads as a broken
    guard, which is how a guard gets switched off.
    """
    return next(citations((root / rel).read_text(errors="replace")), None) is not None


def code_pages(root, tracked):
    """Tracked `.rs` files under [`CODE_ROOTS`] that cite code by line.

    The suffix is asserted here rather than inherited from `tracked`, which now
    carries every suffix [`CITE`] can NAME: a `tools/*.sh` is a citable target,
    not a proof header, and letting it in through the caller's set would widen
    this half by a side effect of the other one.
    """
    return tuple(
        pathlib.Path(rel)
        for rel in sorted(tracked)
        if rel.endswith(".rs") and rel.startswith(CODE_ROOTS) and _cites(root, rel)
    )


def script_pages(root):
    """`.py` under [`SCRIPT_ROOT`] that cite code by line, less [`SCRIPT_EXEMPT`]."""
    return tuple(
        rel
        for rel in sorted(gate_lines.tree_files(root))
        if rel.suffix == ".py"
        and str(rel).startswith(SCRIPT_ROOT)
        and str(rel) not in SCRIPT_EXEMPT
        and _cites(root, rel)
    )


def bundle_pages(root):
    """Every `.toml` directly under [`BUNDLE_ROOT`], citing or not."""
    return tuple(
        rel
        for rel in sorted(gate_lines.tree_files(root))
        if rel.suffix == ".toml" and rel.parent == pathlib.Path(BUNDLE_ROOT.rstrip("/"))
    )


#: The assurance registries, and the fourth derived half. The `.toml` under here
#: that [`BUNDLE_ROOT`] does not hold — the property, platform, toolchain and
#: abstraction registries, and the board records — make the same model→code claim
#: a proof header does and were the largest citing surface nothing opened: the
#: comment this replaced said "a rough count over them is 62 distinct", which was
#: stale by more than double, and nothing could hold it because no page set had
#: them. Measured the day they were added, over this guard's own reader: 9 files
#: cite, 122 citations, of which FOUR were already wrong by this row's own
#: rules — one blank-line span and three bare continuations bound to the wrong
#: file entirely. No number is written down here; the success line counts them.
#:
#: Citing is the filter, unlike [`BUNDLE_ROOT`] one directory over, and the
#: difference is which guard owns the contract. `bundle_gate.py` holds every
#: bundle to a per-row evidence contract, so a bundle citing nothing is a
#: finding; a registry citing nothing is ordinary — `assurance/properties.toml`
#: is a table of property tags and names no line of Rust at all — so the `.rs`
#: and `.py` halves' rule applies and a page is here BECAUSE it cites.
ASSURANCE_ROOT = "assurance/"


def assurance_pages(root):
    """`.toml` under [`ASSURANCE_ROOT`] outside [`BUNDLE_ROOT`] that cite by line."""
    bundle = pathlib.Path(BUNDLE_ROOT.rstrip("/"))
    return tuple(
        rel
        for rel in sorted(gate_lines.tree_files(root))
        if rel.suffix == ".toml"
        and str(rel).startswith(ASSURANCE_ROOT)
        and rel.parent != bundle
        and _cites(root, rel)
    )


#: The registry half's own floor, apart from its three siblings for the reason
#: they are apart from each other: one number over the union cannot say WHICH
#: finder stopped finding. It is 1 for [`CODE_PAGES_FLOOR`]'s reason — what a
#: number here catches is the derivation finding nothing, and what ratchets the
#: set is [`LOCK`], which turns a page that stops being read into one orphan per
#: citation it had.
ASSURANCE_PAGES_FLOOR = 1


#: Pages that must write a repo path, never a bare basename. `comutants.toml`
#: reasons about five applets at once, so `lib.rs:1020` names nothing decidable —
#: for a reader either. SEARCH cannot fix that; only the page can.
#: `RSKeyAppletPolicies.tla` is the same shape over four applets: its bare
#: `keypairgen.rs` named a crate outside SEARCH, and `lib.rs` would have named
#: two of them. Widening SEARCH instead would make `lib.rs` ambiguous AND cited.
PATHS_ONLY = frozenset({"comutants.toml", "RSKeyAppletPolicies.tla"})

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

#: What each citation pointed at when it was last locked, so drift is decidable.
#: `--relock` regenerates it; the diff is the review surface, and is meant to be
#: read — this file records an assertion, it does not prove one.
LOCK = pathlib.Path("formal/citations.lock")

#: Below this a page is not citing, it is failing to be parsed.
FLOOR = 25

#: Pages that legitimately cite fewer than the default — a smaller model is not a
#: broken regex, and padding a page to clear a floor is the failure this guard's
#: own docstring warns against. `RSKeyStore.tla` is the flash layer, a tight model
#: whose floor of 9 still trips a regex that has stopped matching (it finds 0)
#: without demanding the page be inflated.
FLOOR_BY_PAGE = {
    "RSKeyStore.tla": 9,
    "RSKeyRetryLattice.tla": 6,
    "RSKeyAdminSurface.tla": 5,
    "RSKeyTrustedDisplay.tla": 6,
    "RSKeyBootHardening.tla": 6,
    "RSKeyTransport.tla": 5,
    "comutants.toml": 8,
    # The tightest page here, and deliberately so: it defers the PIV/OpenPGP retry
    # counters to RSKeyRetryLattice. A floor of 3 still trips a regex that has
    # stopped matching, which finds 0.
    "RSKeyAppletPolicies.tla": 3,
    # One `consts.rs:a,b` pair, priced into the SYMMETRY argument beside it. A
    # floor of 1 is thin, but the failure it exists for — a regex that has
    # stopped matching — still finds 0, and this page cannot grow much.
    "gen-configs.sh": 1,
    # The harness carries R4c's two rules and the pad the first of them is scoped
    # by; the β projection above them cites nothing.
    "TraceSecurity.tla": 3,
}


def floor_for(page):
    return FLOOR_BY_PAGE.get(page.name, FLOOR)

#: `path.rs:12`, `path.rs:12-20`, `path.rs:12-20, 44`, and the continuation
#: `` `:44` `` that both pages use for a second reference to the same file. The
#: bare form must sit right after a backtick AND be closed by one: over the
#: curated pages "a backtick before it" was enough, but the derived set is 450
#: source files, where `` `LED_PERIOD_MS`: 250 ms `` is ordinary English and used
#: to turn the row red with a message about a citation nobody wrote. Every real
#: continuation in the tree is already closed (`` `:523-535` ``).
#:
#: A filename may not start right after a `:` either, or the path half of
#: `https://host/path/pio.rs:120` reads as a citation to `//host/path/pio.rs` --
#: realistic in an embedded crate that references upstream HAL source. Prose
#: punctuation is unaffected: "see: state.rs:12" has a space in between.
#: Every dash a prose editor can leave behind. An en dash reads as a citation to
#: a single line with the upper bound silently discarded, in two pages whose prose
#: already uses `—` and `·` throughout — measured: `state.rs:284–99991` passed.
#: `.sh` and `.txt` beside `.rs`, because the bundles cite the RUNNER as finely
#: as they cite the firmware — `formal/run-tlc.sh:231-234` is the derivation their
#: reason-comparison argument rests on — and the `.rs`-only group made every one
#: of those invisible. Priced before flipping it, over the whole tree and not
#: just the pages: 122 citations the group had never seen, of which exactly ONE
#: (`scripts/bcd_gate.py` -> `fuzz-coverage.sh:39-41`) lands on a page that was
#: already read, and it resolves. The rest are on the bundles and on pages this
#: guard does not read. Widening further was measured and REFUSED: `.tla`, `.md`,
#: `.toml` and `.cfg` take the tree-wide count to 2438 and turn 72 bundle
#: citations red at once, because [`SEARCH`] holds five `.rs` directories and a
#: bare `RSKeySecurityState.tla` resolves in none of them. That is a corpus
#: widening of its own, with its own repair pass, not a character class.
#:
#: `.py` was the last of those, and it took exactly that repair pass. The bundles
#: cite the GATES as finely as they cite the firmware, and the group made all of
#: it invisible: 32 occurrences of 23 distinct citations in [`BUNDLE_ROOT`],
#: unresolvable and unlockable, of which **17 named code the citing sentence was
#: not about**, 6 of them on a blank line: a bounds check finds those 6 and no
#: more, and only content finds the rest. The family it cites is this
#: guard's own: three bundles sent a reader to `platform_gate.py:724-753` for
#: `check_bundles`, which is at `:926-954`, and a commit message defended a code
#: placement with the rot as its reason. Two side effects, both measured and both
#: repaired rather than tolerated: `scripts/test_run_tlc.py` joins [`script_pages`]
#: (its only citation is a `.py` one, and it resolves), and two continuations on
#: `SEC-FIDO-003.toml:112` lost their binding to a `.py` citation landing between
#: them and the file they meant -- they name that file outright now.
#:
#: WHAT IS STILL BLIND, over the pages this gate opens, and the count turns on the
#: key. As WRITTEN -- one `file:lines` string, no continuations, once tree-wide --
#: 199 over 12 pages, in 284 matches (`.toml` 115, `.tla` 84, `.md` 63, `.cfg` 17,
#: `.yml` 4, `.log` 1); one more is `refs` eating the `2` of a ratio `2:1`.
#: `.c`/`.h`/`.S` are 0 -- but 107 `.sh`/`.py`/`.txt` citations resolve.
#:
#: RE-PRICED when the registries were taken, because a refusal recorded once is
#: the shape this file exists to catch. Adding `.toml|.tla|.md|.cfg|.yml|.log`
#: costs 449 findings at 1734 citations, and the split is what decides it: 19
#: BLANK-LINE rots and 2 past-end, every one of them real and every one in a file
#: the widening does not own, against **75 unresolvable names, 73 of them BARE**.
#: Those 73 are not rot; they are [`SEARCH`] holding five `.rs` directories while
#: a bare `RSKeySecurityState.tla` lives in `formal/` and a bare `ci.yml` in
#: `.github/workflows/` -- 49 of the 75 are that one module. Two `scripts/`
#: fixtures would need [`SCRIPT_EXEMPT`] entries as well, both of them writing
#: synthetic `docs/` pages into a `tmp_path`. So the widening is a corpus repair
#: pass with a resolver change under it, and it stays a decision rather than a
#: character class -- the same verdict as before, now with the numbers that
#: support it rather than the ones that had gone stale.
EXTS = "rs|sh|txt|py"
DASH = "-\u2010\u2011\u2012\u2013\u2014\u2212"


def cite_pattern(exts):
    """The citation reader for an extension set.

    Built from `exts` rather than written out, for [`row_pattern`]'s reason one
    group over: taking an extension back out of [`EXTS`] has to take its
    citations out of the reader too, or the deletion arm removes a name and
    measures a pattern that still matches.

    ## The bare form must be BACKTICKED, and widening that was measured and REFUSED

    The second alternative is zero-width and demands a backtick either side, so
    a continuation written as plain prose -- `at :82, then the gate sweep at
    :83` -- is read by nothing. That hole is real and it has bitten: one commit
    moved `reset.rs` twice and left 21 such refs pointing at the wrong lines
    while this row printed `ok`, four of them inside one clause whose whole
    subject is the ORDER of the five lines it names.

    So the citING side was widened on trial -- every bare `:NNN` bound to the
    last `file.ext:NNN` of its paragraph, with two guards that each fix a whole
    false-positive class: the binder reads EVERY extension (not just [`EXTS`])
    and a ref whose nearest binder is outside them is skipped, so
    `RSKeySecurityState.tla:1778 ... at :1195` stops binding to whatever `.rs`
    came before; and the digits may not be followed by a letter, or
    `0x{v:02x}` and `{n:5d}` are citations.

    Measured over the pages this gate reads. On the repaired tree: 148
    newly-read refs, 102 skipped by the guards, **12 findings of which 2 are
    real** -- a bare `:277-288` for `presence.rs`, which has 262 lines, and a
    bare `:633-645` for `state.rs`, which lands on a blank. The other 10 are
    honest text: every one is a ref whose subject is `RSKeySecurityState.tla`
    or `formal/comutants.toml`, named in the same sentence WITHOUT a line
    number, so no binder can reach it and the ref lands on the last `.rs` name
    instead. Strengthening the binder does not save it -- `the module's own
    :1751 comment` sits in a sentence that has already named `state.rs:601-616`,
    and nothing local decides between the two.

    And the noise is the smaller half. Of the 148, only 12 land out of bounds or
    on a blank; the rest are checked against a file the sentence never named and
    PASS -- a silently wrong check, which is the failure [`AMBIGUOUS`] exists to
    refuse, arriving here 140 at a time.

    Against that, what it buys on the rot it was proposed for: run over the six
    pages as they stood before the repair, it fires 12 times and reaches **5 of
    the 21** stale refs -- only those that happen to land on a blank line. The
    other 16 sit on wrong-but-non-blank lines, which no bounds rule can see and
    only [`LOCK`] can; and the lock would first have to record them, at the
    wrong lines they already hold.

    A variant that skips any paragraph naming a non-[`EXTS`] file was priced
    too: it removes 7 of the 10 false positives and adds a rule that turns the
    check OFF for a whole paragraph the moment its prose cites a `.md` -- fires
    on honest text AND stops firing silently, which is both failures at once.

    So the reader stays as it is, and the hole stays named. What closes it is
    the pages writing the continuation the way the gate already reads it,
    inside backticks; that is a corpus repair, not a character class -- the same
    verdict [`EXTS`] reaches one axis over, and for the same reason.
    """
    return re.compile(
        rf"(?:(?<![\w/.:-])(?P<file>[\w./-]+\.(?:{exts}))|(?<=`)(?=:[^`]*`))"
        rf":\s*(?P<refs>\d+(?:\s*[{DASH}]\s*\d+)?(?:\s*,\s*\d+(?:\s*[{DASH}]\s*\d+)?)*)"
    )


CITE = cite_pattern(EXTS)
SPAN = re.compile(rf"(\d+)(?:\s*[{DASH}]\s*(\d+))?")

#: Files whose rows have NAMES, so a line number is the wrong anchor for them,
#: with how to read a row's key. `floors.txt` is a table keyed by configuration
#: or glob — its own header says so — and a line into it moves whenever the prose
#: above it does. Measured: six bundle citations named a comment where the
#: sentence was about a row, two of them re-anchored by hand that morning and
#: rotted again the same day by three added comment lines. A key does not move,
#: so `floors.txt:Solo_*.cfg` is checked by LOOKUP and is not in [`LOCK`] at all:
#: the key IS the content, and what the row then says is `verdict_gate.py`'s
#: ratchet, not a second copy of it here.
#:
#: It is not a BAN on the line form into a keyed file, and that was decided by
#: measurement too: `SEC-FIDO-006B.toml`'s `formal/floors.txt:50` is about the
#: undercount that COMMENT carries, which has no key to name. The lock is what
#: covers those. `SEC-FIDO-006.toml`'s `scripts/check.sh:551` is the same shape
#: one file over, and it still resolves, is still locked and still drifts.
#:
#: `.py` was ASKED and REFUSED, because a Python file looks keyed and is not: the
#: bundles cite the gates, `def name` reads like a row key, and a name does not
#: move. Measured over the twenty distinct `.py` citations the bundles carry, by
#: asking of each whether its span IS a whole top-level definition — 8 are, and a
#: key would lose nothing on those; 9 sit strictly INSIDE one and would lose which
#: rule in it the sentence is about; 3 name no single definition at all (a module
#: docstring, a `#:` comment with its constant, two adjacent functions). Worse
#: than partial: the key would not be UNIQUE, which is the one rule that makes a
#: key an anchor. `comutate.py`'s CARGO_TARGET_DIR and RUSTFLAGS citations are two
#: different claims inside `run_slice`, and the three `29_reset_power_cut.py` ones
#: are three different assertions inside `main` — five distinct claims collapsing
#: onto two keys, which is the ambiguous-row failure refused above. So `.py` keeps
#: the line form, and [`LOCK`] covers all twenty rather than a key covering eight.
#:
#: A key function answers None for a line that carries no row, because the second
#: entry is mostly shell.
CHECK_ROW = re.compile(r'\s*(?:run|run_tests)\s+"([^"]*)"')


def check_row(line):
    """The row name `check.sh` prints, or None for a line that is not a row.

    Both helpers name the row with their FIRST argument -- `run() { …; echo
    "== $1 =="; … }` and `run_tests`'s `local name=$1` -- so this reads the same
    string the runner puts in the log.
    """
    found = CHECK_ROW.match(line)
    return found.group(1) if found else None


KEYED = {
    # Columns are `<config or glob>  <GREEN|RED>  …`; `\*` opens a comment and
    # `expect_for` in `run-tlc.sh` skips exactly those, so this reads the same
    # column the runner matches on.
    "formal/floors.txt": lambda line: line.split()[0],
    "scripts/check.sh": check_row,
}


def row_pattern(keyed):
    """`file:key`, with the key quoted when it has spaces in it.

    Built from `keyed` rather than written out, so taking a file back out of
    [`KEYED`] takes its citations out of this too -- which is what the deletion
    arm has to be able to do. `\\?` on each quote because the evidence bundles are
    TOML basic strings and a literal `"` reaches this reader escaped; an unquoted
    key stops at the first space and then fails as the wrong key, rather than
    silently reading half a row name.
    """
    return re.compile(
        r"(?<![\w/.:-])(?P<file>" + "|".join(re.escape(k) for k in keyed) + r")"
        r':(?:\\?"(?P<quoted>[^"\\\n]+)\\?"|(?P<row>[@A-Za-z][\w*.-]*))'
    )


ROW = row_pattern(KEYED)


def row_lines(text, key):
    """(line number, row key) for every row a keyed table carries, in order."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith(("\\*", "#")):
            continue
        name = key(line)
        if name is not None:
            found.append((number, name))
    return found


def rows_of(text, key):
    """The keys a keyed table offers, comments and blank lines dropped."""
    return {name for _, name in row_lines(text, key)}


def resolve(rel, tracked, page=None):
    """(the file a citation names, a complaint). A `/` makes it a path, verbatim.

    A bare name on a page that IS code resolves against that page's own directory
    first. Without it every `lib.rs:207` in a proof header is ambiguous across
    four of the five [`SEARCH`] roots, and the one it means is the sibling the
    author was looking at. The `formal/` pages hold no `.rs` siblings, so this
    cannot re-point any citation that predates it.
    """
    if "/" in rel:
        return (rel, None) if rel in tracked else (None, None)
    hits = [f"{d}/{rel}" for d in SEARCH if f"{d}/{rel}" in tracked]
    if len(hits) == 1:
        return hits[0], None
    picked, why = AMBIGUOUS.get(rel, (None, None))
    if picked in hits:
        return picked, None
    # Only now the sibling. Taken FIRST it silently outranked [`AMBIGUOUS`], which
    # exists to stop exactly that: a page in `firmware/src/` citing `vendor.rs`
    # would have got the 197-line file the registry says is not meant, with no
    # complaint. As a tie-break it decides only what nothing else can.
    if page is not None:
        sibling = str(pathlib.PurePosixPath(page).parent / rel)
        if sibling in tracked:
            return sibling, None
    if not hits:
        return None, None
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


def lock_text(line):
    """A cited line as the lock stores it: stripped, and tabs made harmless."""
    return line.strip().replace("\t", " ")


def read_lock(root):
    """{(page, file, start, end): (first line, last line)} as last locked."""
    path = root / LOCK
    if not path.is_file():
        return {}
    locked = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        page, rel, span, first, last = line.split("\t")
        start, _, end = span.partition("-")
        locked[(page, rel, int(start), int(end))] = (first, last)
    return locked


def write_lock(root, entries):
    body = "".join(
        f"{page}\t{rel}\t{start}-{end}\t{first}\t{last}\n"
        for (page, rel, start, end), (first, last) in sorted(entries.items())
    )
    (root / LOCK).write_text(
        "# Generated by `scripts/citation_gate.py --relock`. One line per citation:\n"
        "# page, cited file, span, and the first and last line as they read when\n"
        "# locked. Read the diff — a changed line here is a citation changing what\n"
        "# it points at, which is the thing this file exists to make visible.\n"
        + body
    )


def audit(root, relock=False):
    """(problems, one-line summary) for how the model cites this checkout."""
    root = pathlib.Path(root)
    # git's answer, like the other guards: a filesystem walk also finds the
    # agent worktrees under `.claude/` and the generated `book/`, whole second
    # copies of the tree in which a citation would resolve to the wrong file.
    tracked = {
        str(rel)
        for rel in gate_lines.tree_files(root)
        if rel.suffix.lstrip(".") in EXTS.split("|")
    }
    lengths, problems, total, said, carried = {}, [], 0, set(), set()
    locked, entries, cited = read_lock(root), {}, set()

    def note(key, complaint):
        """A problem, unless it is one this row landed over and has not fixed."""
        if key in PENDING:
            carried.add(key)
        else:
            problems.append(complaint)

    for missing in (d for d in SEARCH if not (root / d).is_dir()):
        problems.append(f"{missing} is in SEARCH but is not a directory any more")
    # Asked of the TABLE, not of the citations into it: a key is only an anchor
    # while it is unique and the file is there, and either can stop being true in
    # a commit that cites nothing.
    for rel, key in KEYED.items():
        if rel not in tracked:
            problems.append(
                f"{rel} is in KEYED but the tree does not carry it any more;"
                " every row citation of it would be checked against nothing"
            )
            continue
        at = {}
        for number, name in row_lines((root / rel).read_text(), key):
            at.setdefault(name, []).append(number)
        for name, numbers in sorted(at.items()):
            if len(numbers) > 1:
                problems.append(
                    f"{rel} has {len(numbers)} rows named `{name}`"
                    f" (lines {', '.join(str(n) for n in numbers)}); a citation of"
                    " that key names no one row, so rename one or cite by line"
                )
    derived, scripted = code_pages(root, tracked), script_pages(root)
    bundled, registries = bundle_pages(root), assurance_pages(root)
    for found, floor, where in (
        (derived, CODE_PAGES_FLOOR, "/, ".join(CODE_ROOTS)),
        (scripted, SCRIPT_PAGES_FLOOR, SCRIPT_ROOT),
        (bundled, BUNDLE_PAGES_FLOOR, BUNDLE_ROOT),
        (registries, ASSURANCE_PAGES_FLOOR, ASSURANCE_ROOT),
    ):
        if len(found) < floor:
            problems.append(
                f"{len(found)} code page(s) under {where} cite by line,"
                f" under the floor of {floor}: the derivation stopped finding them"
            )
    derived += scripted + bundled + registries
    for page in PAGES + derived:
        if not (root / page).is_file():
            problems.append(f"{page} is gone; the model's citations are unchecked")
            continue
        text = (root / page).read_text()
        blank = {n for n, line in enumerate(text.splitlines(), 1) if not line.strip()}
        seen, at, here = None, 0, 0
        for found in ROW.finditer(text):
            here += 1
            rel = found.group("file")
            want = found.group("quoted") or found.group("row")
            if rel not in tracked:
                problems.append(f"{page} cites `{found.group(0)}`, and no such file is in the tree")
            elif want not in rows_of((root / rel).read_text(), KEYED[rel]):
                note(
                    found.group(0),
                    f"{page}: `{found.group(0)}` names no row of {rel};"
                    " the row was renamed or removed, or the key is a comment's",
                )
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
                if page.name in PATHS_ONLY and "/" not in name:
                    problems.append(
                        f"{page}: `{written}` is a bare name on a page that must"
                        " write a repo path; nothing decides which crate it means"
                    )
                seen, complaint = resolve(name, tracked, page)
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
            # Recorded before the ladder, not inside it: a citation that trips an
            # earlier rule is still cited, and reporting it as an orphaned lock
            # entry too is one cause wearing two messages.
            cited.add((str(page), seen, start, end))
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
            elif locked or relock:
                # Absent a lock file there is nothing to compare against, and a
                # tree that has never been locked is not lying about anything;
                # `test_the_lock_covers_every_citation` is what keeps it present.
                key = (str(page), seen, start, end)
                now = (lock_text(body[start - 1]), lock_text(body[end - 1]))
                entries[key] = now
                was = locked.get(key)
                if was is None and not relock:
                    problems.append(
                        f"{page}: `{written}` is not in {LOCK}; check that it points"
                        " where you mean it to, then re-run with --relock"
                    )
                elif was is not None and was != now and not relock:
                    # Only a citation whose locked text is still IN the file has
                    # demonstrably moved. Edited in place it is simply gone, and
                    # firing on that is the false alarm this row would die of.
                    moved = [n for n, l in enumerate(body, 1) if lock_text(l) == was[0]]
                    if moved:
                        # Nearest, not first: a locked line is often not unique
                        # (`pub fn reset(&mut self) {` is in state.rs three
                        # times), and first-match sends the reader to the wrong
                        # one — the very thing this page's citations are for.
                        near = min(moved, key=lambda n: abs(n - start))
                        others = (
                            f" ({len(moved) - 1} other line(s) read the same)"
                            if len(moved) > 1
                            else ""
                        )
                        note(
                            written,
                            f"{page}: `{written}` -> {seen} was locked to"
                            f" `{was[0][:48]}`, which is now at :{near}{others};"
                            " the citation has drifted",
                        )
        # A derived page is in the set BECAUSE it cites, so a per-page floor
        # there asserts nothing; what ratchets that half is the lock.
        floor = CODE_PAGES_FLOOR if page in derived else floor_for(page)
        if here < floor:
            problems.append(
                f"{page} yielded {here} citations, under the floor of {floor}:"
                " the page stopped citing, or this guard stopped reading it"
            )
        total += here
    if relock:
        write_lock(root, entries)
    else:
        for page, rel, start, end in sorted(set(locked) - cited):
            problems.append(
                f"{LOCK} still locks `{rel}:{start}-{end}` for {page}, which no"
                " longer cites it; re-run with --relock"
            )
    for key in sorted(set(PENDING) - carried):
        problems.append(
            f"`{key}` is in PENDING ({PENDING[key]}) but no longer rots; delete the entry"
        )
    assurance_gate.check_property_tags(root, problems)
    debt = f", {len(carried)} carried" if carried else ""
    return problems, (
        f"citation-gate: ok — {total} citations across {len(PAGES)} model pages, "
        f"{len(derived) - len(scripted) - len(bundled) - len(registries)} code pages, "
        f"{len(scripted)} script pages, {len(bundled)} evidence bundles "
        f"and {len(registries)} assurance registries resolve; "
        f"phase-1 property tags close both ways{debt}"
    )


#: The complaints a rewrite BURIES: the three that are about the lock rather than
#: about the tree. Everything else survives a relock and is printed by the run
#: after it. Named so the report below cannot silently stop covering a family.
LAUNDERED = ("has drifted", f"is not in {LOCK}", f"{LOCK} still locks")


def laundered(problems):
    return [p for p in problems if any(m in p for m in LAUNDERED)]


def relock_report(root):
    """What a `--relock` is about to silence, read off the tree it silences it on.

    `--relock` is not a repair tool, and for one commit in this tree's history it
    was used as one: the eight `RSKeyTransport.tla` citations that `c91dff0`
    moved were re-locked at their new lines with the pages left saying the old
    thing, and the row printed `ok` over the result for eleven days. It printed
    ONE line then — "rewritten; read the diff" — and a diff of 549 tab-separated
    rows is not a thing anyone reads. So the pass runs twice: once against the
    OLD lock to say what the rewrite will bury, then the rewrite. Two text scans;
    the row itself is unaffected, because this runs only under `--relock`.
    """
    return laundered(audit(root)[0])


def main():
    if "--relock" in sys.argv[1:]:
        buried = relock_report(ROOT)
        problems, _ = audit(ROOT, relock=True)
        print(f"citation-gate: {LOCK} rewritten; read the diff before committing it")
        for line in buried:
            print(f"  rewritten: {line}")
        if buried:
            print(
                f"\n{len(buried)} citation(s) above were re-locked, not repaired."
                " A DRIFTED one is a page still\nsaying what the code no longer says"
                " — fix the page by CONTENT first, then re-lock."
            )
        for line in problems:
            print(f"  {line}")
        return 1 if problems else 0
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
