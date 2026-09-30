#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Emit every published run-count from a recorded run, and refuse a typed one.

A run-count is a number that says how much a roster run covered or produced —
`190 rows`, `2916 s`, `19 GREEN, 175 RED`. SEVEN were stale in the tree this was
written against, counted the day it was written: `safety` published as 190 rows
where `--tiers` listed 195, `78` mutation switches with a family where 79 have
one, `194 configurations … 20 GREEN and 174 RED` in the weekly workflow against
195/21/174, a phase-2 baseline of `28 rows` and a `69-entry` roster against 30
and 71, a slice page at `57 properties … 194 tiered` against 59 and 199, and
`Shipped.cfg` at `48.7 M distinct states — 539 s` where the run this file records
says 77 563 872 and half an hour. The seventh is the one `docs/testing.md`
introduces as the paragraph to quote, where the model's state space stood at
`48,679,968` — 63% of the measured count. None is a typo. They are one defect: a
number whose only copy of the truth is the moment somebody typed it.

Three rules in two halves, because either half alone leaves the class open.

* **Emitted.** The published sentences live in named regions this script writes
  from [`RECORD`] and the tree, and the gate diffs them — the shape
  `assurance_gate.py` and `comutate.py` already use on `formal/README.md`. A
  hand edit to a number inside a region is a diff, not an opinion.
* **Not said twice.** What the regions PRINT may not appear as a literal anywhere
  else — a value at [`VALUE_FLOOR`] and up, a value with the UNIT the region put
  beside it at any magnitude ([`phrased`]), and the provenance a region prints
  verbatim ([`spoken`]). All three are generated from what the region says rather
  than hunted for as a shape, so they need no noun list, no trigger and no guess
  about phrasing, and their spellings are closed by construction. This is the
  rule the one below cannot be, and the one below is the rule this cannot be: it
  sees a correct copy about to rot and never a stale one.
* **Refused elsewhere.** A region cannot stop the NEXT sentence being typed
  somewhere else, and the completeness half is where every guard in this tree has
  failed. So every tracked text file under [`SCANNED_TREES`] — `docs/`, `formal/`
  and `.github/`, which is how the criterion names them — and every tracked page
  at the root is scanned for the vocabulary, and a run-count outside a region is
  a finding unless [`SCOPED`] registers it with the scope it is history to. This
  half is armed by [`NAMES_A_RUN`] in the same PARAGRAPH, which is a one-word
  opt-out and is why the three generated rules above exist: a paragraph
  restating every published number and naming no run was five lines at exit 0.

What the record does **not** prove is that a real TLC ran: `--record` ingests
logs, and a log can be typed. What it proves is what rot cannot fake — that the
matrix covers every configuration of the tier as the tree lists it *today*, that
every verdict is the one `floors.txt` requires, that no row came back under its
floor or carrying the runner's `!!`, and that the row count, the wall clock and
the tally are counted here rather than stored. The class this row exists for is a
number going stale, not a person forging 199 mutually consistent rows.

Which left the record itself typeable, and that was the hole under all of it:
`states`, `depth` and the wall clock were held against nothing and `distinct`
only from below, so editing `distinct=77563872` to `48679968` and `1869s` to
`539s` and running `--write` put six published sentences back to the exact defect
this file is named after, with every sibling row green. So each `[[run]]` now
also keeps [`TLC_ROW`] — TLC's own banner, start line and closing sentences, per
configuration, out of the per-configuration logs at `--record` time — and the
gate re-derives the row from them. Two programs' accounts of one run, in one
file. It is not a signature and does not pretend to be: someone writing both
halves can still write them to agree. It is the difference between rot, which is
one careless number, and a forgery, which is a decision.

The kept line is TLC's, so what it says about ITSELF is checkable too, and four
things it says were read by nothing: the banner's workers and cores and the start
line's date, which left `date`, `host` and `workers` typeable outright; the
`states left on queue` in the same sentence as the state count, so a GREEN row
could claim an exhaustive run while its own next words said a billion states
were never reached; whether `states` is even as large as `distinct`; and whether
a row that came back GREEN printed a state count at all — `check_record` skips
the distinct floor on a non-digit, so both halves agreeing there is nothing to
compare took a row out of [`FLOORS`] entirely. And [`CLOCK_SLACK`] was a per-row
bound on a quantity the published sentence adds up, which is [`TIER_SLACK`].

And what it deliberately does not reach: `scripts/` and `assurance/`. Both were
counted when this was written. `scripts/` held eight, six of them the measured
defect that motivated a guard ("33 rows cited it by the file name"), read by
whoever edits that guard one screen from its own live summary line; the other two
are a live claim and `scripts/test_config_gen_gate.py` pins them to the tree.
`assurance/` holds `bundle/*.toml`, itself a record of measurements and held by
`bundle_gate.py` -- and one more that this said it did not: the settling
question in `assurance/configurations.toml` that `matrix_gate.py` renders into
`docs/assurance-matrix.md` carries, verbatim once parsed, the sentence registered
in [`SCOPED`] for the rendered page. It is written across TOML line
continuations, so a grep for the rendered form does not find it. The DOCS copy is registered and the copy a
human edits is out of the scan, which is the wrong way round. Neither directory
is published documentation, and "the documentation claims a run nobody watched"
is what this is about; the honest statement is that this row does not reach the
generator's INPUT, only its output.

`CHANGELOG.md` is published and is still out, and the reason first given for it
was wrong: not "every line sits under a version heading", because
`## [Unreleased]` is not a scope and a live claim typed there is a live claim --
one about this very rule went stale under it. It is out because the tree holds 74
run-count literals under that heading today, all of them entries that BECOME a
version's when the release lands, and registering 74 historical figures one at a
time is not a trade this row can pay. An entry saying what a run cost at 0.4.10
does not go stale; an entry saying what it costs now does, and nothing here
sees it.
"""

import fnmatch
import os
import pathlib
import re
import subprocess
import sys
import textwrap
import tomllib

#: The nine shipped baseline configurations, from the gate that already needs
#: that list. A second copy here would be the defect one directory over.
import assurance_gate

#: Which generator writes which page, for the same reason: `claims_gate` already
#: derives that pair from every generator's own `ARTIFACT`/`GENERATED_BY`, having
#: measured what asking the PAGE instead lets through.
import claims_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The recorded runs. One `[[run]]` per tier, each holding the runner's own
#: output verbatim; every number this gate publishes is counted back out of it.
RECORD = pathlib.Path("formal/runs.toml")
RUNNER = pathlib.Path("formal/run-tlc.sh")
FLOORS = pathlib.Path("formal/floors.txt")
COMUTANTS = pathlib.Path("formal/comutants.toml")

#: Where the runner leaves TLC's own output, one log per configuration. Gitignored
#: and rewritten by the next run, so `--record` reads them while they exist and
#: keeps what they said; nothing at gate time can go looking.
LOG_DIR = pathlib.Path("formal/out")

#: Configurations of a tier that no recorded run covers. Zero, because a tier
#: whose roster has moved since the last run is one the documentation may not
#: describe as observed. Raising it is allowed and deliberate — the generated
#: sentence then says how many rows nobody watched, which is the honest form of
#: the claim rather than its absence.
UNOBSERVED_FLOOR = 0

#: Below this the scan found nothing, which is what a scan does when its
#: vocabulary stops matching the tree's spelling rather than when the tree stops
#: saying it. Well under what the tree holds and far above zero, like
#: `config_gen_gate.FLOOR` and `docs_constants.MIN_PAIRS`.
SCAN_FLOOR = 8

#: And every rule has to match something of its own, because one number over four
#: rules and a trigger cannot see the loss of the rule carrying most of them.
#: Measured by killing each in turn against this tree: `COUNT` dead leaves 19
#: literals and `CLOCK` dead leaves 16, both comfortably over the 8 above, and
#: `TALLY` dead leaves 28 — every one of its matches is also a `LOOSE_TALLY`, so
#: the aggregate floor cannot see it go at all. Only the trigger's death (2 left)
#: was visible. ONE, not a fraction of what each holds today: a vocabulary either
#: still matches the tree's spelling or it does not, and a fraction of 2 is 0.
#:
#: What it does NOT see, said plainly because the justification above reads as
#: though it did: a rule NARROWED. Hollowing `GROUP` — dropping the NBSP and the
#: two thin spaces, which is the bypass `340e515` added them for — moves none of
#: the five tallies at all, 3/20/13/5/66 before and after, and neither does
#: hollowing `JOIN`. Only `test_every_grouping_the_count_rule_holds` and its
#: sibling see that, by asserting the WHOLE literal a page holds rather than that
#: some finding fired: with a separator gone the rule matches the tail and reports
#: `'563 872 rows'`, which is a finding about a number that is not on the page.
RULE_FLOOR = 1

#: What a scope label has to BE. It cannot be checked for truth — no program
#: tells a right scope from a wrong one, and `"the liveness tier in 2019, on a
#: Raspberry Pi"` passes every rule here and always will. What was checkable and
#: was not checked is that there is one at all: the values of [`SCOPED`] were
#: never read, so `""`, `None`, a single word and six nonsense words each bought
#: a brand-new stale literal an exemption. Eight words, against a measured
#: minimum of ten and a median of twenty-four, so the floor refuses boilerplate
#: rather than judging prose.
LABEL_WORDS = 8

#: Literals one fragment may exempt. A registry entry buys silence for its own
#: span, and a span can be a whole paragraph: seven literals went quiet under one
#: entry, which is an exemption nobody sized. Measured maximum today is three, in
#: four sentences -- the `COVERAGE=1` sweep's five fell to three when the model it
#: swept moved past two of them; a fourth in one sentence means splitting the
#: registration, not widening it.
#:
#: Held ONE above that maximum rather than merely over it, for the reason under
#: the two ceilings below: raising it to 99 was a surviving mutant, because a cap
#: with headroom is a cap nothing has to move.
SCOPE_SPAN_CAP = 4

#: And the registry as a whole only grows deliberately: this EQUALS `len(SCOPED)`,
#: so a bump belongs in the diff beside the entry that needs it, the way every
#: other ratchet here moves. An exemption list that grows without anyone noticing
#: is the colander this row exists to not become.
#:
#: Equal and not merely an upper bound, because the difference is what a mutation
#: run measured: `fb406e8` wrote of `SCAN_FLOOR` that "it monkeypatches the floor
#: down on a fixture, so the shipped 8 had never been exercised against the
#: shipped tree" -- and then this file shipped three ceilings with exactly that
#: defect. Lowering a FLOOR is caught, because the cases that drive it drive the
#: real tree; raising a CEILING was not, because nothing said where the ceiling
#: should be. Now `test_the_real_checkout_is_green` says. (This number also read
#: 27 in its own comment one commit after being written, thirty lines from the
#: constant, in the guard whose whole subject is a hand-typed number going
#: stale. `scripts/` is outside the scan, so nothing was ever going to catch it.)
SCOPE_CEILING = 40

#: The other rule, and the one the shape scan cannot be: a value the generator
#: PRINTS may not appear as a literal anywhere else. It needs no noun list, no
#: paragraph-local trigger and no guess about how a sentence is phrased, because
#: the spellings are generated FROM the number instead of parsed out of prose —
#: which is the hole every one of the four rules above has, unboundedly.
#:
#: It is floored by magnitude because a small derived value is every other number
#: in the tree. Measured as occurrences of a value the regions print, outside a
#: region, over the scanned corpus: **7 404** at no floor, **1 942** over ten,
#: **283** over a hundred, **138** over a thousand — of which 117 are the
#: copyright year — and **10** over ten thousand, EVERY ONE of them a real second
#: copy and every one registered below. So the false-positive rate is 0 at this
#: floor and rises steeply just under it; five digits is where coincidence stops.
#:
#: Re-measured, because the first three of those rows were taken with a matcher
#: `0941089` then fixed and read 10 862 / 2 236 / 264. The two that carry the
#: decision, a thousand and ten thousand, were right either way.
#:
#: What it does not reach, said plainly: a value written ROUNDED (`77.6 M` is in
#: the tree and this rule cannot see it), and a number that is STALE — one whose
#: value matches nothing derived today. The shape scan above is what sees those,
#: which is why both rules are here and neither is a supplement to the other.
VALUE_FLOOR = 10_000

#: The published sentences only grow. So a set that has SHRUNK is a sentence that
#: stopped being generated, which is the other half of the region rule and the
#: half nothing held: deleting an entry from `region_bodies`, deleting its two
#: markers and retyping the sentence by hand left the row green over the exact
#: state count this gate is named after. Lowering this is allowed and is how a
#: page gets retired — deliberately, in the diff, not by a deletion nobody sees.
REGION_FLOOR = 8

GENERATED_BY = "Generated by scripts/run_count_gate.py --write"

#: Pages another gate writes whole. Their numbers are already emitted, by a
#: generator with its own diff row, and re-flagging them would ask an author to
#: register a literal they may not edit. Checked both ways: an entry whose page
#: has stopped saying so is a stale carve-out.
GENERATED_ELSEWHERE = {
    "docs/assurance-vector.md": "Generated by scripts/evidence_gate.py --write",
    # What a WHOLE-page carve-out costs, measured here rather than found later. A
    # run-count typed into a bundle's `stops_*` or `shipped_relation` reaches this
    # page through `bounds_gate.render` and NOTHING sees it: driven, `999 rows …
    # 4321 s … 17 GREEN and 182 RED` into SEC-FIDO-006, `--write`, and run-count,
    # bounds and bundle all exit 0. Which is what the two literals this silences
    # ARE — the scan was reading bundle prose off the rendering. Typed onto the
    # PAGE it is still caught, one row over, by the bounds byte diff (exit 1).
    # SCOPED cannot take this page: `three switches` stands on it 4 times and the
    # exactly-once rule refuses the entry — and the same 4 are why the cover given
    # up was already partial, the scan reaching 1 because COUNT arms on
    # NAMES_A_RUN in the same paragraph.
    "docs/assurance-bounds.md": "Generated by scripts/bounds_gate.py --write",
}

#: A run-count that is history, and what it is history TO. Registered by the
#: sentence fragment carrying it, which must occur exactly once in that file: a
#: figure worth a scope label is worth saying once, and a second copy is the rot
#: this row is about wearing an exemption. A literal counts as scoped only if it
#: falls INSIDE that fragment's one occurrence, so a fragment cannot exempt a
#: number that merely resembles one of its own.
#:
#: What an entry does NOT buy, and this is open: when a value the regions print
#: MOVES, a registered copy reddens only once its fragment exempts nothing -- the
#: rule below. Measured when `Shipped.cfg` went from 77 563 872 to 108 618 956:
#: four copies reddened, and the fifth, the `COVERAGE=1` sweep, stayed silent
#: because its fragment still covers literals of other rules. Eight of these
#: entries exempt more than one literal and would hide a stale value the same
#: way. Closing it needs the registry to say which
#: value each entry is a copy OF, and half of these entries are quoting a figure
#: that is deliberately historical and must NOT track anything.
SCOPED = {
    # Historical roster figures: the sentence's subject is what the tree WAS.
    (
        "docs/testing.md",
        "`safety` was 2003 s here",
    ): "the tier before the token-less makeCredential widening, in a paragraph whose "
    "whole subject is the ratio between then and the generated figure above it",
    (
        "docs/testing.md",
        "run 32684551258 discharged it in 1 h 14 m 47 s",
    ): "a GitHub-hosted runner, named by workflow run id — no local record can emit it, "
    "and the projection off it is labelled a projection where it is made",
    (
        ".github/workflows/deep-checks.yml",
        "156 of the 194 configurations",
    ): "what the roster was the day this row was added, in a sentence whose subject is "
    "that nothing ran it until then",
    (
        "formal/README.md",
        "102 of the then-192\nconfigurations",
    ): "the finding that produced the verdict registry, in that registry's own mutation "
    "table — and already carrying its scope label, in the word `then-`",
    (
        "formal/run-tlc.sh",
        "168 of the 177 RED",
    ): "the finding that produced the derived-invariant rule, in the comment that "
    "introduces it — the tree's shape on the day the runner stopped skipping the "
    "reason comparison, not a tally of anything the runner emits",
    (
        "formal/README.md",
        "passed all 98\nrows",
    ): "the merge gate's row count on the day that falsification was run, quoted as the "
    "evidence that a weakened floor passed it",
    # One configuration, not a roster. `formal/runs.toml` holds each of these per
    # row and could emit them; six more generated regions, to publish figures no
    # claim rests on, is not the trade this row is for.
    (
        "docs/formal.md",
        "finished 48.7 M-state GREEN was reported",
    ): "one configuration's size, in the narrative of the NUL-hole defect rather than a "
    "tally of anything",
    (
        "formal/README.md",
        "finished 48.7 M-state GREEN as",
    ): "the same configuration in the same narrative, one page over",
    (
        ".github/workflows/deep-checks.yml",
        "finished 48.7 M-state GREEN as VACUOUS",
    ): "and again in the row's own comment, for the same reason",
    (
        ".github/workflows/deep-checks.yml",
        "said 194 rows, 20 GREEN and 174 RED, and the tier had moved past all\n#          three",
    ): "the copy that stood in this comment, quoted where it stood so the row says why "
    "it stopped counting for itself",
    (
        ".github/workflows/deep-checks.yml",
        "said 48.7 M and 539 s until that file existed",
    ): "the copy that rotted, quoted where it stood — the sentence exists to say why "
    "the row now points at the record instead",
    (
        "formal/README.md",
        "539 s, 1285 s\nand 2034 s are three readings",
    ): "three readings of `Shipped.cfg` across one round of model work — the sentence is "
    "about their state counts being equal, not about a tier",
    (
        "formal/README.md",
        "2804 s against the plain run's 2034 s**, GREEN over the same 986 836 197\ngenerated and 77 563 872 distinct",
    ): "the `COVERAGE=1` sweep of `Shipped.cfg` against its plain run, dated in place — "
    "and the two counts it swept, which are the point of `the same`",
    (
        "formal/README.md",
        "runs out of memory**\nafter 1500 s",
    ): "`Liveness.cfg` failing at the 4 GB default — the observation that put a heap "
    "column in `floors.txt`, and kept as the older observation it is",
    (
        "formal/README.md",
        "distinct states at depth 43, in **1555 s**",
    ): "the same configuration at 12 GB on the reduced constants, the other half of that "
    "one measurement",
    # A LIVE figure the regions already print, restated in the narrative that is
    # about it. Registered rather than rewritten: the number carries the argument
    # in each of these sentences. What the registry buys is that they are now
    # KNOWN second copies — the next time the model widens, this list is the list
    # of prose that goes stale with it, where before nothing could name them.
    (
        "docs/assurance-matrix.md",
        "GREEN over 31 451 172 distinct states at depth 51",
    ): "`AlwaysUv.cfg`'s own size, in the cell arguing that the model half of that "
    "column is answered and the code half is not",
    (
        "formal/gen-configs.sh",
        "They cost 108 618 956 now",
    ): "`Shipped.cfg`'s size in the generator's own note on why the real constants were "
    "kept over the reduced ones, which is an argument about the two numbers",
    (
        "formal/README.md",
        "at\n108 618 956 after `c92bfb3`",
    ): "the count the fingerprint estimate is a closed form IN, in the paragraph about "
    "what `exhaustive` means — the estimate is meaningless without it",
    (
        "formal/README.md",
        "**108 618 956 at depth 58**",
    ): "the configuration's size today, in the sentence that re-derives the floor as a "
    "third of it — a floor stated as a ratio is nothing without the count",
    (
        "formal/README.md",
        "GREEN over 14 514 424 distinct\nstates at the liveness constants",
    ): "`Fairness.cfg`'s distinct count, the space the invariant is checked over, beside "
    "the 5% it cost when it went in — dated in place by its commit",
    # ONE configuration's own measurement, in the narrative that is about it,
    # reached by widening the nouns to `states` and `mutants` — what a run
    # PRODUCED is a run-count by the same definition as what it covered.
    (
        "docs/testing.md",
        "against a 120-minute cap",
    ): "the weekly workflow's timeout, which is a cap the row is written with rather "
    "than a duration anything measured",
    (
        "formal/README.md",
        "330 of 666 states against 666",
    ): "one action's firing count inside the dead-action narrative, where the ratio "
    "between the two is the whole observation",
    (
        "formal/README.md",
        "fewer than 2 distinct states or a depth below 2",
    ): "the runner's own VACUOUS threshold, quoted where the rule is explained — a "
    "constant of the rule and not a measurement of anything",
    (
        "formal/README.md",
        "All three boot mutants redden",
    ): "how many mutants the boot module has, which is a property of that family and "
    "moves when somebody adds one",
    (
        "formal/README.md",
        "replays GREEN: 13 actions",
    ): "what the seam-trace replay covers, in the pipeline stage that is about that "
    "trace rather than about a tier",
    (
        "formal/README.md",
        "explored **40 459 667\nstates without a counterexample**",
    ): "the mutant that stopped firing after a fix made its defect unreachable, which "
    "is the measurement the expected-verdict column exists because of",
    (
        "formal/floors.txt",
        "explored 40 459 667 states",
    ): "the same measurement in this file's own header, where it is the argument for "
    "the VERDICT column existing at all",
    # And the third copy, which stood unregistered through every run of this gate
    # because nothing in its block named a run: the comment saying `` `safety` ``
    # and `` `liveness` `` that arms it went in twenty lines below, long after the
    # sentence did.
    (
        "formal/run-tlc.sh",
        "# 40 459 667 states without a counterexample",
    ): "the same measurement in the runner's own comment, where it is the argument for "
    "the `!! expected` mark printed under it — the observation the whole expected-verdict "
    "apparatus in this function exists because of",
    (
        "formal/README.md",
        "swept the FIDO module's 77.6 M states",
    ): "`Shipped.cfg`'s size ROUNDED, in the `COVERAGE=1` sentence — the rounding is "
    "why the exact-value rule cannot see it and this one has to",
    (
        "formal/README.md",
        "It grew to **7 903 336 distinct states**",
    ): "`Liveness.cfg` at the 4 GB default before the heap column existed, in the "
    "paragraph about why it needs 12 GB",
    (
        "formal/README.md",
        "GREEN** over the same 7 903 336\ndistinct states",
    ): "the same older reading one paragraph down, which is the point of `the same`",
    # Neither: a count of something that is not a roster run at all.
    (
        "docs/authorization-slice.md",
        "25 wildcard families covering 165 of 200 configurations, every one `RED -`",
    ): "`verdict_gate.py`'s own summary line, in a row that tells the reader to run it — "
    "the verdict registry's coverage, which that gate prints live every run",
    (
        "docs/authorization-slice.md",
        "already model-checked on two\n  configurations",
    ): "how many configurations check one property — `assurance_gate.py`'s derivation "
    "and no run's, and measured STALE when this entry was written, along with seven "
    "more on that page. A registry sentence generated from its registry is the "
    "stage-0 criterion, and it is not this row",
    (
        "formal/README.md",
        "roadmap's original 28-row phase-2 denominator and is 31 now",
    ): "the denominator a roadmap fixed, deliberately not the live roster — the whole "
    "point of the sentence is that it does not move",
    (
        "formal/README.md",
        "names all seven rows it\nwould blind",
    ): "how many `floors.txt` rows carry a fourth column, a property of that file",
    # Reached by widening a published unit into the vocabulary the shape scan
    # already enumerates: `85 entries` is the roster, a sentence seven commits in
    # this series have now had to hand-correct — 69 -> 71 -> 72 -> 73 -> 76 -> 79
    # -> 80 -> 85 -> 87. The eighth correction was MISSED by its own commit and
    # caught by review: a seam batch grew the roster and the sentence stood.
    (
        "formal/README.md",
        "**31 of 31 mutants are caught",
    ): "the phase-2 baseline said as what it counts rather than as rows, in the sentence "
    "arguing that each mutant is caught by the invariant NAMING it — the ratio is the "
    "claim, and the generated roster line carries the same 30",
    (
        "docs/formal.md",
        "93 entries: all 87 executable patches are killed",
    ): "the whole-tree roster restated in the page that introduces the phase-2 "
    "table, whose generated region beside it gives the phase-2 line and not this "
    "total",
    # `` `NoStatusAfterARefusedAuth` | 73 states `` stood here while the roster
    # read 73 and one lattice mutant explored 73 states. At 76 the coincidence was
    # gone, the cell fell under no rule, and the entry retired as it predicted; the
    # boot family took the roster to 79, the OATH seam batch takes it to 85, and it
    # stays gone.
    # `` `BugPanelCancelable` | … | 230 states `` collided the day the safety tier
    # reached 230 configurations, and retired as predicted when the tier reached
    # 242 -- where `` `BugCmWalkIgnoresChannel` | … | 1 242 states `` collided in
    # turn, read as 242 through its thousands space. Same class, same retirement:
    # a co-mutant's state count, in a column of state counts, that moves when that
    # mutant's model does.
    (
        "formal/README.md",
        "channel equality | `NoAuthorizationBypass` | 1 242 states",
    ): "a co-mutant's own state count in the co-refutation table, which the tier's "
    "configuration count reached by coincidence — the column beside it is all state "
    "counts and none of them is a roster",
    (
        "formal/README.md",
        "**93 entries: all 87 executable patches killed",
    ): "the co-mutant roster restated where its composition is broken down, which the "
    "generated line beside it does not give — the copy that read 69, then 71, 72 and "
    "73, re-measured by hand in four commits of this series. Its own claim that a "
    "registered fragment cannot check whether its sentence is still true is REFUTED "
    "at 76: the region began printing `76-entry`, every fragment carrying 73 stopped "
    "exempting anything, and all three went red in one run — the boot family moved it "
    "again, to 79, then 80, and the OATH seam batch to 85, which also turned the "
    "sentence's `zero gaps` into one",
    (
        "formal/README.md",
        "`ok — 191 configuration(s)` and exited 0",
    ): "a verbatim gate summary inside a mutation table: the string the row printed over "
    "a mutated tree, which is evidence only while it is quoted unchanged — 191 because "
    "`formal/` held 192 configurations the day the derivation was fixed and one is "
    "exempt. It was registered here reading 195, which a bulk retype of every live count "
    "on the page had put there and no roster ever printed. The pair, not this copy, is "
    "what holds it now: `test_verdict_gate.py` quotes the same measurement and "
    "`test_the_pre_fix_reading_is_quoted_with_one_number_in_both_places` compares them",
}

#: The Results table, split into the half a script cannot produce and the half it
#: must. WHICH configurations belong on one line and what to call it is a
#: judgement and lives here; every number beside them is counted out of the
#: record. Closed in both directions: a recorded configuration in no group is a
#: row the table would not show, and a group matching nothing is a line about a
#: family that has gone.
#: The one region that is a table rather than a sentence: one line per
#: configuration, cells of bare numbers in shared units. Named once, because two
#: rules ask the question — `fill` may not touch it, and [`phrased`] may not read
#: it, since `1 s` and `3` are the whole tree's numbers rather than a claim.
TABLE_REGION = ("formal/README.md", "results-table")

TABLE_GROUPS = (
    ("`Shipped.cfg` — the tree as it stands, `SYMMETRY` on, firmware constants",
     ("Shipped.cfg",)),
    ("`AlwaysUv.cfg` — AS-AUTH-2's other arm: the build that ships it",
     ("AlwaysUv.cfg",)),
    ("`PermWide.cfg` — `WidePerms`'s other arm: all sixteen permission subsets",
     ("PermWide.cfg",)),
    ("`PermWideMut_*.cfg` — and what says that arm's observers can fail",
     ("PermWideMut_*.cfg",)),
    ("`ForceChange.cfg` — `ForceChangeModelled`'s other arm: EF_MINPINLEN[1], the"
     " forced-PIN-change gate",
     ("ForceChange.cfg",)),
    ("`Historical_E76.cfg` — the seed-lead taken back out", ("Historical_E76.cfg",)),
    ("`Historical_E77.cfg` — the grant back in phase 2 **and** the consumer fix out",
     ("Historical_E77.cfg",)),
    ("`Mut_*.cfg` — mutant against the whole invariant set", ("Mut_*.cfg",)),
    ("`Solo_*.cfg` — the same mutants against their **own** target only",
     ("Solo_*.cfg",)),
    ("`SoloClause_*.cfg` — and against **one clause** of it", ("SoloClause_*.cfg",)),
    ("`Fairness.cfg` — `ENABLED OpAdvances => ~Idle`, at the liveness constants",
     ("Fairness.cfg",)),
    ("`FairMut_*.cfg` — E160 verbatim", ("FairMut_*.cfg",)),
    ("`Seams.cfg` — the second module: the applet seams", ("Seams.cfg",)),
    ("`SeamMut_*.cfg` / `SeamSolo_*.cfg`", ("SeamMut_*.cfg", "SeamSolo_*.cfg")),
    ("`Store.cfg` — the third module: the flash layer", ("Store.cfg",)),
    ("`StoreMut_*.cfg` / `StoreSolo_*.cfg`", ("StoreMut_*.cfg", "StoreSolo_*.cfg")),
    ("`StoreInduction.cfg` — `IndInv /\\ Next => IndInv'`, the probe that found one",
     ("StoreInduction.cfg",)),
    ("`StoreInductionMut_*.cfg` — what says that probe can go red",
     ("StoreInductionMut_*.cfg",)),
    ("`Lattice.cfg` — the fourth module: the retry/recovery lattice", ("Lattice.cfg",)),
    ("`LatMut_*.cfg` / `LatSolo_*.cfg`", ("LatMut_*.cfg", "LatSolo_*.cfg")),
    ("`LatInduction.cfg` — `IndInv /\\ Next => IndInv'`, the probe that found NOTHING",
     ("LatInduction.cfg",)),
    ("`LatInductionMut_*.cfg` — what says that probe can go red",
     ("LatInductionMut_*.cfg",)),
    ("`Policies.cfg` — all four applets' stateful operation policies",
     ("Policies.cfg",)),
    ("`PolicyMut_*.cfg` / `PolicySolo_*.cfg`", ("PolicyMut_*.cfg", "PolicySolo_*.cfg")),
    ("`Admin.cfg` — the fifth module: the administrative surface", ("Admin.cfg",)),
    ("`AdminMut_*.cfg` / `AdminSolo_*.cfg`", ("AdminMut_*.cfg", "AdminSolo_*.cfg")),
    ("`Display.cfg` — the sixth module: the trusted-display ceremony",
     ("Display.cfg",)),
    ("`DispMut_*.cfg` / `DispSolo_*.cfg`", ("DispMut_*.cfg", "DispSolo_*.cfg")),
    ("`Boot.cfg` / `BootCarry.cfg` — the seventh module, and its open hardware "
     "assumption's other arm", ("Boot.cfg", "BootCarry.cfg")),
    ("`BootMut_*.cfg` / `BootSolo_*.cfg` / `BootCarryMut_*.cfg`",
     ("BootMut_*.cfg", "BootSolo_*.cfg", "BootCarryMut_*.cfg")),
    ("`BootInduction.cfg` — `IndInv /\\ Next => IndInv'` from ANY admitted state",
     ("BootInduction.cfg",)),
    ("`BootInductionMut_*.cfg`", ("BootInductionMut_*.cfg",)),
    # The two arms of the write/re-arm order, which every row above collapses
    # into one step. One line, because the pair is one experiment: the RED arm is
    # the order the tree ships and the GREEN one is the order it does not, and a
    # reader given either alone would take it for a property of the split.
    ("`Historical_Boot*.cfg` — the write/re-arm order the tree ships, and the one"
     " it does not",
     ("Historical_BootWriteThenRearm.cfg", "Historical_BootRearmThenWrite.cfg")),
    ("`Transport.cfg` — the eighth module: the CTAPHID reassembler",
     ("Transport.cfg",)),
    ("`TransMut_*.cfg` / `TransSolo_*.cfg`", ("TransMut_*.cfg", "TransSolo_*.cfg")),
    ("`TraceSeams.cfg` / `TraceSeamsBad.cfg` — phase 4: a recorded session "
     "replayed, and one the model must refuse",
     ("TraceSeams.cfg", "TraceSeamsBad.cfg")),
    ("`TraceSecurity.cfg` — raw C-state --beta--> B and alpha == gamma(B)",
     ("TraceSecurity.cfg",)),
    ("`TraceSecurityBad*.cfg` — the shifts the replay must refuse, one control "
     "among them", ("TraceSecurityBad*.cfg",)),
    ("`TokenGate*.cfg` — tier A's requirement half, its oracle, their "
     "disagreement, and one forbidden edge", ("TokenGate*.cfg",)),
    ("`TokenRefinement*.cfg` — phase 5: native B -> A state refinement",
     ("TokenRefinement*.cfg",)),
    ("`Liveness.cfg` — the three temporal properties, at the heap `floors.txt` "
     "gives it", ("Liveness.cfg",)),
    ("`LiveMut_*.cfg` — one mutant per property", ("LiveMut_*.cfg",)),
)


# --- the vocabulary --------------------------------------------------------
#
# Enumerated rather than inferred, because the spellings are where this tree's
# rules get walked around: `= TRUE \\* comment` past `= TRUE`, `Fs::delete(fs,`
# past `fs.delete(`, a table EMPTIED past a table deleted. So: digits grouped by
# space, comma or underscore (`77 563 872`), and the words two…twenty, because
# `four liveness rows` is in the tree and `4` is not. Below `two` there is no
# roster claim to make — `one row` is a hundred sentences and no run-count.

#: Written with explicit escapes because the class was `[\x20\x20,_]` — the plain
#: space TWICE and neither the NBSP nor a thin space at all, while its comment
#: said three characters. A trailing `.5` because `48.7 M-state GREEN` was
#: reported as `'7 M-state GREEN'`, the literal cut at the decimal point; a
#: trailing `+` because `190+ rows` walked past it.
GROUP = r"[\x20\u00a0\u2009\u202f,_]"
NUM = rf"[0-9]+(?:{GROUP}[0-9]{{3}})*(?:\.[0-9]+)?\+?"
WORD = (
    r"two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|"
    r"fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty"
)
COUNTED = rf"(?:{NUM}|{WORD})"
#: What a roster is counted in. `switches` is here because a mutation family is a
#: roster too, and its count went stale by one on the same page as the rest.
#: What a roster is counted in. `switches` is here because a mutation family is a
#: roster too, and its count went stale by one on the same page as the rest.
#: `states` and `mutants` because what a run PRODUCED is a run-count by the same
#: definition as what it covered — and `77.6 M states` is a rounded second copy
#: that the value rule cannot see, so this is the only rule that reaches it.
#: The inventory nouns are deliberately NOT here: `properties`, `invariants`,
#: `models`, `families`, `tiers`, `harnesses`, `proofs`, `suites`, `cases` count
#: what the tree HAS, not what a run did, and they belong to `assurance_gate`'s
#: registry — measured, they add 9 findings and not one is about a run.
NOUN = r"rows?|configurations?|configs?|cfgs?|switches|entr(?:y|ies)|states?|mutants?"

#: A tally is a run-count wherever it stands — nothing else in this tree is
#: counted in GREEN and RED — so this trigger needs no runner beside it.
TALLY = re.compile(rf"\b{NUM}\s*(?:\*\*)?\s*(?:GREEN|RED)\b|\b(?:GREEN|RED)\s*[:=]\s*{NUM}\b")
#: `20 that must come back GREEN` is a tally the tight form cannot see. Bounded
#: to one clause so a paragraph is not joined end to end.
LOOSE_TALLY = re.compile(rf"\b{NUM}\b[^.|\n]{{0,48}}?\b(?:GREEN|RED)\b")
#: `195 — rows` walked past a `[-\s]?` separator, because an em dash is not `-`;
#: `_195 rows_` walked past the leading `\b`, because `_` is a word character and
#: there is no boundary between two of them. So the left edge is "not a digit"
#: rather than a word boundary. `_` stays OUT of the join: with it in, the count
#: could reach across an identifier and `93\tfido_state` in `citations.lock` read
#: as a run-count — measured.
JOIN = r"[-\u2013\u2014\s]"
COUNT = re.compile(
    rf"(?<![0-9.])(?:{COUNTED})\s*(?:\*\*)?{JOIN}?\s*(?:\w+{JOIN})?(?:{NOUN})(?![a-z])", re.I
)
#: `3 hours` and `a 54-minute run` and `finished in 00:53:45` were all a run's
#: wall clock spelled a way this did not hold. `about an hour` is not: there is
#: no number in it, and no numeric rule reaches a sentence that gives none.
#: How this tree spells a wall clock. Named, because [`phrase_pattern`] asks the
#: same question of a unit: `3225 seconds` is `3225 s` said another way.
CLOCK_UNIT = r"s|secs?|seconds?|min|minutes?|h|hrs?|hours?|m"
CLOCK = re.compile(
    rf"\b{NUM}\s*-?\s*(?:{CLOCK_UNIT})\b" r"|\b[0-9]{1,2}:[0-9]{2}:[0-9]{2}\b"
)
#: What has to stand beside a count or a clock for it to be a claim about a run.
#: A tally needs nothing; these two are counted in units other things share.
NAMES_A_RUN = re.compile(r"run-tlc|run_tlc|comutate|`safety`|`liveness`|--tiers")

#: The marker pair, spelled exactly like the two this tree already has
#: (`<!-- assurance-table:start -->`, `<!-- phase2-comutants:start -->`) with a
#: namespace prefix, because three of these regions share one file.
START = "<!-- run-count-{}:start -->"
END = "<!-- run-count-{}:end -->"
MARKER = re.compile(r"<!-- run-count-([a-z0-9-]+):start -->")


# --- the record ------------------------------------------------------------

#: One line of `run-tlc.sh` output. The verdict field is everything between the
#: configuration and `states=`: a RED carries the invariant it fell on and a
#: FLOOR carries its arithmetic, and both are the part worth keeping.
ROW = re.compile(
    r"^(?P<cfg>\S+\.cfg)\s+(?P<verdict>\S.*?)\s+states=(?P<states>\S+)"
    r"\s+distinct=(?P<distinct>\S+)\s+depth=(?P<depth>\S+)\s+(?P<seconds>\d+)s(?P<mark>.*)$"
)


#: What TLC says about its own run, in TLC's words. The runner greps the first
#: three out of `formal/out/<cfg>.log` to build the matrix row above; `--record`
#: keeps them, and the gate re-derives the row from them. So the two halves of
#: every published number are a `printf` in a shell script and a sentence a JVM
#: wrote, and moving one by hand contradicts the other.
TLC_SUMMARY = re.compile(
    r"^(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue\.$", re.M
)
TLC_DEPTH = re.compile(r"^The depth of the complete state graph search is (\d+)\.$", re.M)
TLC_FINISHED = re.compile(r"^Finished in (?:\d+h \d+min|(?:\d+min )?\d+s)\b", re.M)
TLC_STARTED = re.compile(r"^Starting\.\.\. \((\d{4}-\d\d-\d\d)[ T]([\d:]+)\)$", re.M)
TLC_BANNER = re.compile(r"^Running .*? with (\d+) workers? on (\d+) cores? .*?\(([^,]+),", re.M)

#: One kept line: the configuration, then TLC's own sentences joined in the order
#: it prints them. The two state-space halves are genuinely absent on a run that
#: died on an initial state — `TokenGateDisagreement.cfg` generated nothing, so
#: the runner recorded `?` there and TLC printed only its clock. The two
#: provenance halves are not optional: TLC prints its banner and its start line
#: on every run, and they are the ONLY second source `date`, `host` and
#: `workers` have. Each was a field somebody typed, and each was driven to an
#: absurd value with `--write` and the row at exit 0 — while `--record` had
#: already parsed both lines and thrown them away.
TLC_ROW = re.compile(
    r"^(?P<cfg>\S+\.cfg)"
    r"\s+with (?P<workers>\d+) workers? on (?P<cores>\d+) cores? \((?P<arch>[^)]+)\)"
    r"\s+Starting\.\.\. \((?P<date>\d{4}-\d\d-\d\d) (?P<time>[\d:]+)\)"
    r"(?:\s+(?P<states>\d+) states generated, (?P<distinct>\d+) distinct states found,"
    r" (?P<queue>\d+) states left on queue\.)?"
    r"(?:\s+The depth of the complete state graph search is (?P<depth>\d+)\.)?"
    r"\s+Finished in (?:(?P<hours>\d+)h (?P<hminutes>\d+)min"
    r"|(?:(?P<minutes>\d+)min )?(?P<seconds>\d+)s)$"
)

#: Seconds the runner's wall clock may exceed TLC's own `Finished in`. It brackets
#: the JVM, so it is always the larger of the two; the gap is start-up and
#: teardown. Measured 0-2 s over all 199 rows of the recorded run, and set here
#: well above that so a cold page cache does not redden the row — while a clock
#: rewritten to tell a different story about cost (539 s over a run TLC timed at
#: 31min 08s) cannot pass either bound.
CLOCK_SLACK = 30

#: And the same gap SUMMED over a tier, per row, because the bound above is a
#: per-row one on a quantity the published sentence adds up: 30 s each over 195
#: rows put the legal safety total at [3064..8914] s against a recorded 3225 --
#: +176 % of headroom under a bound that reads tight, and that total is the
#: numerator of `docs/testing.md`'s CI-cap projection. Driven: every row moved to
#: its own TLC clock plus 30 published `3225 s` as `8914 s`, `--write` and the
#: row both at exit 0. Measured per row over the recorded runs: mean 0.83 s and
#: 1.00 s, max 2 s, so three is well clear of a JVM bracket and nowhere near a
#: rewritten cost. `CLOCK_SLACK` is added once on top, so one genuinely cold row
#: anywhere in the tier still fits.
TIER_SLACK = 3


def matrix_rows(text):
    """The rows of one recorded matrix, in the order the runner printed them."""
    return [found.groupdict() for line in text.splitlines() if (found := ROW.match(line.strip()))]


def elapsed(found, prefix=""):
    """`Finished in 31min 08s` as seconds. Past an hour TLC prints `01h 12min` and
    drops the seconds, so there this is the minute the run finished in."""
    return (
        int(found[prefix + "hours"] or 0) * 3600
        + int(found[prefix + "hminutes"] or found[prefix + "minutes"] or 0) * 60
        + int(found[prefix + "seconds"] or 0)
    )


def clock_slack(found):
    """How far the runner's clock may run past TLC's for one row: the JVM bracket,
    and the up to 59 s TLC's own clock no longer shows past an hour."""
    return CLOCK_SLACK + (59 if found["hours"] else 0)


def tlc_line(root, cfg):
    """What `formal/out/<cfg>.log` says about itself, as one kept line — or the
    reason there is nothing to keep. Read at `--record` time and only there: the
    logs are gitignored, which is exactly why what they said has to be stored."""
    log = root / LOG_DIR / (cfg[:-4] + ".log")
    if not log.is_file():
        raise RuntimeError(f"{log.relative_to(root)} is missing — record a run, do not type one")
    text = log.read_text(errors="replace")
    finished = TLC_FINISHED.search(text)
    if not finished:
        raise RuntimeError(f"{log.relative_to(root)}: TLC never said it finished")
    banner, started = TLC_BANNER.search(text), TLC_STARTED.search(text)
    if not banner or not started:
        raise RuntimeError(f"{log.relative_to(root)}: its log carries no TLC banner or start time")
    parts = [
        cfg,
        f"with {banner[1]} workers on {banner[2]} cores ({banner[3]})",
        f"Starting... ({started[1]} {started[2]})",
    ]
    if summary := TLC_SUMMARY.findall(text):
        parts.append("{} states generated, {} distinct states found, {} states left on queue.".format(*summary[-1]))
    if depth := TLC_DEPTH.findall(text):
        parts.append(f"The depth of the complete state graph search is {depth[-1]}.")
    parts.append(finished.group(0).strip())
    return " ".join(parts), text


def tiers(root):
    """tier -> [configuration], from the runner. `--tiers` is a pure query there
    precisely so a gate may ask without a jar, a JVM or a lint pass."""
    done = subprocess.run(
        [str(root / RUNNER), "--tiers"], capture_output=True, text=True, cwd=root / "formal"
    )
    if done.returncode != 0:
        raise RuntimeError(f"{RUNNER} --tiers exited {done.returncode}: {done.stderr.strip()[:200]}")
    listed = {}
    for line in done.stdout.splitlines():
        if ": " in line:
            tier, members = line.split(": ", 1)
            listed[tier.strip()] = members.split()
    if not listed:
        raise RuntimeError(f"{RUNNER} --tiers listed no tier")
    return listed


def floors(root):
    """The `floors.txt` rows in file order — first match wins, as the runner reads them."""
    rows = []
    for line in (root / FLOORS).read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("\\*", "#")):
            rows.append(stripped.split())
    return rows


def expected(rows, cfg):
    """(verdict, minimum distinct) `floors.txt` asks of `cfg`, either possibly None."""
    for row in rows:
        if fnmatch.fnmatchcase(cfg, row[0]):
            floor = row[2] if len(row) > 2 else "-"
            return (row[1] if len(row) > 1 else None), (int(floor) if floor.isdigit() else None)
    return None, None


def load(root):
    """The recorded runs, keyed by tier, each with its matrix parsed."""
    path = root / RECORD
    if not path.is_file():
        raise RuntimeError(f"{RECORD} is missing — no run has been recorded")
    runs = {}
    for entry in tomllib.loads(path.read_text()).get("run", []):
        tier = entry.get("tier")
        if not tier:
            raise RuntimeError(f"{RECORD}: a [[run]] with no tier")
        if tier in runs:
            raise RuntimeError(f"{RECORD}: two [[run]] entries for {tier!r} — one run per tier")
        runs[tier] = dict(entry, rows=matrix_rows(entry.get("matrix", "")))
    if not runs:
        raise RuntimeError(f"{RECORD} holds no [[run]] — nothing to publish")
    return runs


def check_tlc(where, run, findings):
    """Every published number of a row, re-derived from what TLC said about the
    same run and compared to what the runner printed.

    The fields with no second source were the whole of the record's exposure:
    `check_record` held the roster, the verdicts and the floors, so a `distinct`,
    a wall clock, the date, the host or the workers could be retyped and
    `--write` would carry it into six published sentences. Neither half is proof
    a run happened — both are bytes in a committed file — but they are two
    different programs' accounts of it, and an edit to one is now a contradiction
    rather than an opinion.

    And what the kept line says about ITSELF is checkable without the matrix at
    all: a GREEN row prints a state count and leaves nothing on its queue, no run
    finds more distinct states than it generated, and the rows agree with each
    other about the box they ran on.
    """
    kept = {}
    for line in run.get("tlc", "").splitlines():
        if found := TLC_ROW.match(line.strip()):
            if found["cfg"] in kept:
                findings.append(f"{where}: {found['cfg']} has two TLC summaries")
            kept[found["cfg"]] = found
        elif line.strip():
            findings.append(f"{where}: {line.strip()[:60]!r} is not a TLC summary line")
    stamps, gaps, truncated = set(), [], 0
    for row in run["rows"]:
        found = kept.pop(row["cfg"], None)
        if found is None:
            findings.append(
                f"{where}: {row['cfg']} is in the matrix and TLC's own summary of it is"
                " not — re-record the run, the row has nothing to check it against"
            )
            continue
        stamps.add((found["date"], found["workers"], found["cores"], found["arch"]))
        green = row["verdict"].startswith("GREEN")
        # TLC prints a summary on every run that reaches a verdict, so a GREEN
        # row without one is not the run it says it is — and `check_record`'s
        # distinct floor is skipped on `?`, so a row could escape `floors.txt`
        # with both halves politely agreeing that there is nothing to compare.
        if green and found["states"] is None:
            findings.append(
                f"{where}: {row['cfg']} came back GREEN and TLC printed no state count"
                " at all — a run that reaches a verdict prints a summary, and this row"
                f" then escapes the floor {FLOORS} puts under it"
            )
        if found["states"] is not None:
            # Two fields of TLC's own sentence that nothing read. `queue` was
            # captured and never compared, so a record could claim an exhaustive
            # GREEN while its own next word said a billion states were never
            # explored; and no run can find more distinct states than it made.
            if green and int(found["queue"]):
                findings.append(
                    f"{where}: {row['cfg']} came back GREEN and TLC left"
                    f" {found['queue']} states on its queue — an exhaustive run leaves"
                    " none, so the verdict and the sentence under it disagree"
                )
            if int(found["states"]) < int(found["distinct"]):
                findings.append(
                    f"{where}: {row['cfg']} generated {found['states']} states and found"
                    f" {found['distinct']} distinct among them — no run finds more"
                    " distinct states than it generated"
                )
        for field in ("states", "distinct", "depth"):
            # `?` is the runner's spelling of "TLC printed none", and TLC leaves
            # both halves out on a run that died on an initial state. So the two
            # must agree about ABSENCE as well as about a number.
            mine, theirs = row[field], found[field]
            if mine != (theirs if theirs is not None else "?"):
                findings.append(
                    f"{where}: {row['cfg']} recorded {field}={mine} and TLC's own summary"
                    f" says {theirs if theirs is not None else 'nothing'} — one of the two"
                    " was edited by hand"
                )
        gap = int(row["seconds"]) - elapsed(found)
        gaps.append(gap)
        truncated += clock_slack(found) - CLOCK_SLACK
        if not 0 <= gap <= clock_slack(found):
            findings.append(
                f"{where}: {row['cfg']} recorded {row['seconds']}s and TLC timed itself at"
                f" {elapsed(found)}s — the runner's clock brackets the JVM, so the gap"
                f" belongs in 0..{clock_slack(found)}s and this one is {gap}s"
            )
    budget = CLOCK_SLACK + TIER_SLACK * len(gaps) + truncated
    if sum(gaps) > budget:
        findings.append(
            f"{where}: the rows are {sum(gaps)}s longer than TLC timed them, over the"
            f" {budget}s a {len(gaps)}-row tier gets — the per-row bound is on a"
            " quantity the published sentence ADDS UP, and this is a wall clock"
            " rewritten to tell a different story about cost"
        )
    # ONE finding for a provenance field, not one per row: 199 copies of "the
    # date is wrong" is the report defect where a reader is told the tree is
    # wrong when one field of one line is.
    if len(stamps) > 1:
        findings.append(
            f"{where}: the kept summaries disagree about date/workers/cores/arch"
            f" ({len(stamps)} readings) — a record assembled from two runs"
        )
    elif stamps:
        # `arch` is here for the reason `queue` is read at all: it was captured by
        # `TLC_ROW` and compared to nothing. A JVM does not print the brand string
        # `host` wears, so the only checkable claim left in it is that every row
        # says the same box — which `provenance` asks of the LOGS at `--record`
        # time and nothing asked of the record afterwards.
        (date, workers, cores, _), = stamps
        # `host` is the log's core count wearing the local machine's brand
        # string, so the banner holds the half of it a JVM knows. Read as a
        # number rather than as `host`'s own spelling of it, which is `1 cores`.
        counted = re.search(r"\((\d+) cores?\)", str(run.get("host", "")))
        for field, mine, theirs, agrees in (
            ("date", str(run.get("date", "")), date, str(run.get("date", "")) == date),
            ("workers", str(run.get("workers", "")), workers,
             str(run.get("workers", "")) == workers),
            ("host", str(run.get("host", "")), f"{cores} core(s)",
             counted is not None and counted.group(1) == cores),
        ):
            if not agrees:
                findings.append(
                    f"{where}: recorded {field}={mine!r} and TLC's own banner says"
                    f" {theirs!r} — one of the two was typed"
                )
    for cfg in sorted(kept):
        findings.append(f"{where}: TLC's summary of {cfg} is kept and the matrix has no such row")


#: What a recorded run's numbers actually depend on: the modules, the
#: configurations, the verdict registry and the two shell scripts that build and
#: drive them. NOT `formal/README.md`, whose generated regions `--write` moves
#: right after `--record`, and not the record itself.
MODEL = (":(glob)formal/*.tla", ":(glob)formal/*.cfg", "formal/floors.txt",
         "formal/run-tlc.sh", "formal/gen-configs.sh")


#: A comment is not a state space. These modules carry `file.rs:NNN` citations
#: that `citation_gate.py` re-anchors every time the code under them moves, and a
#: name-only diff called six of them changed over a commit that refreshed nothing
#: but line numbers -- driven, and it reddened the row. So the comparison is of
#: what TLC would read. A `#` is only a comment in a shell script at the start of
#: a line, because one inside a string is not, and in a `.tla` it is an operator.
COMMENTS = {
    ".tla": (re.compile(r"\(\*.*?\*\)", re.S), re.compile(r"\\\*.*$", re.M)),
    ".cfg": (re.compile(r"\(\*.*?\*\)", re.S), re.compile(r"\\\*.*$", re.M)),
    ".txt": (re.compile(r"\\\*.*$", re.M), re.compile(r"^[ \t]*#.*$", re.M)),
    ".sh": (re.compile(r"^[ \t]*#.*$", re.M),),
}


def uncommented(rel, text):
    """`text` as TLC would read it: no comments, no blank lines."""
    for rule in COMMENTS.get(pathlib.PurePosixPath(rel).suffix, ()):
        text = rule.sub("", text)
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip())


def checked_out_since(root, commit):
    """What of [`MODEL`] this working tree MEANS that `commit` did not.

    The gate reads model CONTENT for exactly two things -- the `Bug*` switch
    names and `Shipped.cfg`'s `INVARIANTS` -- so an edit that changed the state
    space without moving the roster or `floors.txt` left every published count
    stale and the row green. The record carries the commit; this is the question
    it lets the row ask.
    """
    listed = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", commit, "--", *MODEL],
        capture_output=True, text=True,
    )
    if listed.returncode != 0:
        return []
    moved = []
    for rel in sorted(q for q in listed.stdout.split("\n") if q):
        was = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{rel}"], capture_output=True, text=True
        )
        here = root / rel
        if was.returncode != 0 or not here.is_file():
            moved.append(rel)
        elif uncommented(rel, was.stdout) != uncommented(rel, here.read_text()):
            moved.append(rel)
    return moved


def check_record(root, runs, listed, floor_rows, findings):
    """Whether each recorded run is a run of the tier as this tree lists it now."""
    for tier, run in sorted(runs.items()):
        where = f"{RECORD} [{tier}]"
        check_tlc(where, run, findings)
        for field in ("command", "date", "commit", "host", "workers", "tlc"):
            if not str(run.get(field, "")).strip():
                findings.append(f"{where}: no {field} — a result with no provenance")
        commit = str(run.get("commit", ""))
        if commit and not re.fullmatch(r"[0-9a-f]{40}", commit):
            findings.append(f"{where}: commit {commit!r} is not a full 40-character object name")
        elif commit and (root / ".git").exists():
            known = subprocess.run(
                ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
                capture_output=True,
            )
            if known.returncode != 0:
                findings.append(f"{where}: commit {commit} is in no history here")
            for moved in checked_out_since(root, commit):
                findings.append(
                    f"{where}: {moved} has moved since {commit[:12]}, the commit this run"
                    " is recorded against — the roster and the floors can still agree"
                    " while every published count is of a state space that has gone."
                    " Re-run the tier and `--record` it"
                )
        seen = [r["cfg"] for r in run["rows"]]
        for cfg in sorted({c for c in seen if seen.count(c) > 1}):
            findings.append(f"{where}: {cfg} recorded {seen.count(cfg)} times")
        for cfg in sorted(set(seen) - set(listed[tier])):
            findings.append(f"{where}: {cfg} is recorded and the tier no longer lists it")
        missing = sorted(set(listed[tier]) - set(seen))
        if len(missing) > UNOBSERVED_FLOOR:
            findings.append(
                f"{where}: {len(missing)} configuration(s) the tier lists are in no"
                f" recorded run, over the floor of {UNOBSERVED_FLOOR} — re-run"
                f" `./formal/run-tlc.sh {tier}` and `--record` it, or raise the floor"
                f" and let the sentence say so ({', '.join(missing[:4])}"
                f"{', …' if len(missing) > 4 else ''})"
            )
        for row in run["rows"]:
            if row["mark"].strip():
                findings.append(
                    f"{where}: {row['cfg']} carries the runner's own"
                    f" `{row['mark'].strip()}` — a failed row is not a published result"
                )
            want, floor = expected(floor_rows, row["cfg"])
            got = row["verdict"].split(":")[0].strip()
            if want and want != got:
                findings.append(
                    f"{where}: {row['cfg']} recorded {got} and {FLOORS} now requires"
                    f" {want} — the record is of a tree this one is not"
                )
            if floor is not None and row["distinct"].isdigit() and int(row["distinct"]) < floor:
                findings.append(
                    f"{where}: {row['cfg']} recorded {row['distinct']} distinct, under the"
                    f" {floor} {FLOORS} now asks of it"
                )


# --- what the regions say --------------------------------------------------


def totals(rows):
    """Counted on every call, never stored: a stored total is the second copy
    this row exists to remove."""
    green = sum(1 for r in rows if r["verdict"].startswith("GREEN"))
    red = sum(1 for r in rows if r["verdict"].startswith("RED"))
    return {
        "rows": len(rows),
        "green": green,
        "red": red,
        "seconds": sum(int(r["seconds"]) for r in rows),
    }


def facts(root, runs, listed):
    """Every number the regions print, derived here and nowhere else."""
    out = {"tier": {}}
    for tier, run in runs.items():
        out["tier"][tier] = dict(
            totals(run["rows"]),
            date=run.get("date", "?"),
            host=run.get("host", "?"),
            workers=run.get("workers", "?"),
            unobserved=len(set(listed.get(tier, [])) - {r["cfg"] for r in run["rows"]}),
        )
    # In the runner's own tier order, and over EVERY recorded tier rather than a
    # pair named here: a third tier would otherwise vanish from the Results table
    # while `check_record` went on saying its rows were fine.
    order = [t for t in listed if t in runs] + [t for t in runs if t not in listed]
    out["ordered"] = [r for tier in order for r in runs[tier]["rows"]]
    out["row"] = {r["cfg"]: r for r in out["ordered"]}
    switches = set()
    for module in sorted((root / "formal").glob("*.tla")):
        switches |= set(re.findall(r"\bBug[A-Za-z0-9]+", module.read_text()))
    families = set()
    for cfg in (root / "formal").glob("*.cfg"):
        if found := re.search(r"Bug[A-Za-z0-9]+", cfg.name):
            families.add(found.group(0))
    # What `Shipped.cfg` asserts, less `TypeOK`: a type invariant is a
    # well-formedness check on the state, not one of the security properties the
    # published claim is counting.
    block = re.search(
        r"^INVARIANTS\n((?:[ \t]+\S+\n)+)", (root / "formal/Shipped.cfg").read_text(), re.M
    )
    named = [n for n in (block.group(1).split() if block else []) if n != "TypeOK"]
    comutants = tomllib.loads((root / COMUTANTS).read_text())
    return dict(
        out,
        invariants=len(named),
        switches=len(switches),
        families=len(families),
        familyless=sorted(switches - families),
        models=len(assurance_gate.OWNER_CFGS),
        phase2=comutants["phase2_count"],
        comutants=len(comutants["comutant"]),
    )


#: The same two…twenty this scan reads, because the page it replaced wrote `the
#: nine shipped models` and the generator wrote `the 9`. A roster of nine is a
#: sentence, not a table cell.
WORDED = dict(zip(range(2, 21), WORD.split("|")))


def worded(count):
    """`nine`, where a page would write the word rather than the digit."""
    return WORDED.get(count, str(count))


def fill(text):
    """A sentence wrapped the way the pages around it are. The table below is not
    put through this: a markdown row is one line whatever its length."""
    return textwrap.fill(text, width=79, break_long_words=False, break_on_hyphens=False)


def region_bodies(f, findings=None):
    """(file, region id) -> what it owns, from `facts` and nothing else."""
    safety, liveness = f["tier"].get("safety", {}), f["tier"].get("liveness", {})
    both_green = safety.get("green", 0) + liveness.get("green", 0)
    both_red = safety.get("red", 0) + liveness.get("red", 0)
    unseen = safety.get("unobserved", 0) + liveness.get("unobserved", 0)
    # A raised UNOBSERVED_FLOOR owes its reader this. Empty at the floor of 0,
    # which is why the sentence around it must read without it.
    caveat = (
        f" {unseen} configuration{'' if unseen == 1 else 's'} of the two tiers"
        f" {'was' if unseen == 1 else 'were'} in no observed run." if unseen else ""
    )
    familyless = ", ".join(f"`{n}`" for n in f["familyless"]) or "none"
    has = "have" if len(f["familyless"]) != 1 else "has"
    bodies = {
        ("docs/testing.md", "tlc-roster"): (
            f"`safety` is the {worded(f['models'])} shipped models, the {f['families']} mutation"
            f" switches that have a configuration family of their own ({f['switches']}"
            f" `Bug*` switches exist; {familyless} {has} none), floors and the vacuity"
            " check."
        ),
        ("docs/testing.md", "tlc-measured"): (
            f"Both tiers are measured runs, not sums. On {safety.get('date', '?')}, on"
            f" the {safety.get('host', '?')} of the Kani table above at the default"
            f" `WORKERS={safety.get('workers', '?')}`, `safety` came"
            f" back over **{safety.get('rows', 0)} configurations in"
            f" {safety.get('seconds', 0)} s — {safety.get('green', 0)} GREEN,"
            f" {safety.get('red', 0)} RED, and not one row that missed what `floors.txt`"
            f" asks of it**; `liveness` took **{liveness.get('seconds', 0)} s** for its"
            f" {liveness.get('rows', 0)}, at the heap that file gives each of them.{caveat}"
        ),
        ("docs/testing.md", "comutate-roster"): (
            f"The original phase-2 baseline is fixed at {f['phase2']} rows, and the full"
            f" {f['comutants']}-entry live roster runs weekly."
        ),
        ("docs/formal.md", "tlc-measured"): (
            f"Both timings are one run each on {safety.get('date', '?')}, on an"
            f" {safety.get('host', '?')} at the default"
            f" `WORKERS={safety.get('workers', '?')}`: `safety` over"
            f" {safety.get('rows', 0)} configurations in {safety.get('seconds', 0)} s and"
            f" `liveness` over {liveness.get('rows', 0)} in {liveness.get('seconds', 0)} s"
            f" — {both_green} GREEN, {both_red} RED, no row short of its floor.{caveat}"
        ),
        ("formal/README.md", "tlc-measured"): (
            f"**Every row above is from one run on {safety.get('date', '?')}**:"
            " `./run-tlc.sh safety` and then `./run-tlc.sh liveness`, which is what"
            f" `all` does, on an {safety.get('host', '?')} at the default"
            f" `WORKERS={safety.get('workers', '?')}` and whatever heap `floors.txt`"
            f" gives each configuration. {safety.get('rows', 0)} safety rows in"
            f" **{safety.get('seconds', 0)} s** and {liveness.get('rows', 0)} liveness"
            f" rows in **{liveness.get('seconds', 0)} s**; {both_green} GREEN,"
            f" {both_red} RED, and not one row missed what `floors.txt` requires of it —"
            f" which is what makes the command exit 0 rather than merely finish.{caveat}"
        ),
        ("formal/README.md", "results-table"): results_table(
            f["ordered"], [] if findings is None else findings
        ),
        ("docs/testing.md", "shipped-row"): (
            f"TLC checks {f['invariants']} named invariants exhaustively over"
            f" {spaced(f['row']['Shipped.cfg']['distinct'])} distinct states at the"
            " firmware's own PIN-retry constants."
        ),
        ("formal/README.md", "liveness-row"): (
            "`./run-tlc.sh all` runs `Liveness.cfg` at the heap `floors.txt` gives it,"
            f" and it is **{f['row']['Liveness.cfg']['verdict']} over"
            f" {spaced(f['row']['Liveness.cfg']['distinct'])} distinct states in"
            f" {f['row']['Liveness.cfg']['seconds']} s**, in the same matrix run as"
            " everything else in the Results table."
        ),
    }
    return {k: (v if k == TABLE_REGION else fill(v)) for k, v in bodies.items()}


def grouped(rows, findings):
    """(label, [row]) per table group, first match winning as the runner's own
    `floors.txt` reading does. Closed both ways: a configuration in no group and
    a group matching nothing are each a line the table would be wrong without."""
    left, out = list(rows), []
    for label, patterns in TABLE_GROUPS:
        mine = [r for r in left if any(fnmatch.fnmatchcase(r["cfg"], p) for p in patterns)]
        if not mine:
            findings.append(
                f"{RECORD}: the Results group {label.split(' — ')[0]} matches no recorded"
                " configuration — a table line about a family that has gone"
            )
        left = [r for r in left if r not in mine]
        out.append((label, mine))
    for row in left:
        findings.append(
            f"{RECORD}: {row['cfg']} is in no Results group — the table would not show"
            " it, and the sentence under it says every row is from one run"
        )
    return out


def spaced(value):
    """`986 836 197`, the way this page has always written a state count."""
    return f"{int(value):,}".replace(",", " ")


def span(values, unit="", group=True):
    """A cell. `—` when TLC reported no such field on some row: the runner writes
    `?` there, and `int('?')` would take the whole table down over one blank.

    `group` because this page has always written a state count with its digits
    grouped and a wall clock without — `2034 s`, never `2 034 s`.
    """
    numbers = [int(v) for v in values if str(v).isdigit()]
    if len(numbers) != len(values) or not numbers:
        return "—"
    lo, hi = min(numbers), max(numbers)
    show = spaced if group else str
    return show(lo) + unit if lo == hi else f"{show(lo)}{unit} – {show(hi)}{unit}"


def verdict_cell(rows):
    """What the group came back as. A single row keeps the invariant it fell on,
    because that — not the colour — is the result."""
    if len(rows) == 1:
        got = rows[0]["verdict"]
        return f"**{got}**" if got.startswith("GREEN") else f"`{got}`"
    heads = sorted({r["verdict"].split(":")[0].strip() for r in rows})
    if len(heads) == 1:
        return f"all {len(rows)} **{heads[0]}**" if heads[0] == "GREEN" else f"all {len(rows)} {heads[0]}"
    return ", ".join(
        f"{sum(1 for r in rows if r['verdict'].startswith(h))} {h}" for h in heads
    )


def results_table(rows, findings):
    """The Results table: the grouping is a judgement, every number is counted."""
    out = [
        "| Configuration | Verdict | States generated | Distinct | Depth | Wall |",
        "|---|---|---|---|---|---|",
    ]
    for label, mine in grouped(rows, findings):
        if not mine:
            continue
        count = "" if len(mine) == 1 else f"{len(mine)} × "
        out.append(
            f"| {count}{label} | {verdict_cell(mine)}"
            f" | {span([r['states'] for r in mine])}"
            f" | {span([r['distinct'] for r in mine])}"
            f" | {span([r['depth'] for r in mine])}"
            f" | {span([r['seconds'] for r in mine], ' s', group=False)} |"
        )
    return "\n".join(out)


def wrap(name, body):
    return f"{START.format(name)}\n<!-- {GENERATED_BY}; do not edit. -->\n{body}\n{END.format(name)}"


def replace(text, name, body):
    """One named region, swapped for what the generator writes.

    Whatever the start marker's line begins with is carried onto every line the
    region emits, so a region may sit inside a markdown blockquote — which is
    where `docs/testing.md` keeps the one paragraph this project asks to be
    quoted, and where its state count stood at 63% of the measured one. Only `>`
    and whitespace, because anything else is prose the generator would swallow.
    """
    start, end = START.format(name), END.format(name)
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f"needs exactly one {name!r} marker pair")
    head = text.index(start)
    prefix = text[text.rfind("\n", 0, head) + 1 : head]
    if prefix.strip(" \t>"):
        raise ValueError(f"{name!r} follows {prefix!r}; a marker owns its line")
    body = wrap(name, body).replace("\n", "\n" + prefix)
    return text[:head] + body + text[text.index(end, head) + len(end) :]


def rendered(root, bodies):
    """path -> the file as the generator would write it."""
    out = {}
    for (rel, name), body in sorted(bodies.items()):
        out[rel] = replace(out.get(rel) or (root / rel).read_text(), name, body)
    return out


# --- the scan --------------------------------------------------------------


#: The published trees, BY DIRECTORY, which is how the criterion names them. It
#: was a suffix whitelist under each — `docs/**/*.md`, `formal/README.md` alone,
#: `.github/**/*.{yml,yaml,md}` and two named root pages — and every gap in that
#: list was a place a count could be typed with the row green: a new `formal/*.md`
#: page, `floors.txt`'s own header prose, a `\*` comment in a `.tla`, a `#` one in
#: a `.sh` or a `.toml`, a `.json` or a `.sh` under `.github/`, `SECURITY.md`,
#: `COMPLIANCE.md`, `AGENTS.md`, `CODEX.md`, a `docs/` page that is not markdown.
#: All 22 driven, all exit 0. Widening cost 0 literals over this tree once the two
#: carve-outs below are taken out — `.tla`, `.cfg`, `.sh`, `.txt`, `.svg` and
#: `.lock` contribute nothing at all — so the narrow list was buying no quiet.
SCANNED_TREES = ("docs", "formal", ".github")

#: Files under those trees that are not a place a run-count gets TYPED. This is
#: the SECOND exemption registry on this row, and it shipped with exactly the
#: defect the first one was measured to have: two carve-outs whose reasons nothing
#: read and whose number nothing ratcheted. It is held to [`LABEL_WORDS`] and
#: [`CARVE_OUT_CEILING`] now, like `SCOPED`, and each file is checked to still
#: exist — a carve-out for a file nobody has is one nobody is reading.
NOT_TYPED_HERE = {
    "formal/runs.toml": "the record itself: every number in it is a run's own output, and the"
    " gate holds each of them against TLC's own account of the same run",
    "CHANGELOG.md": "every line of it sits under a version heading, which is exactly the"
    " scope label a historical figure needs — an entry saying what a run cost at 0.4.10"
    " does not go stale, it stays 0.4.10's",
    "formal/citations.lock": "nobody types a sentence into it: `citation_gate.py --relock`"
    " copies a cited SOURCE line into every row verbatim, so what reads as a count there"
    " is Rust, not prose. Driven — the day the evidence bundles joined that gate's corpus"
    " the file gained 503 rows and one of them was `77-77` beside"
    " `cfg!(feature = \"always-uv\")`, reported as `'77-77\\tcfg'`; a SCOPED entry for it"
    " would name a fragment the next relock rewrites",
}

#: Three, and EQUAL to `len(NOT_TYPED_HERE)` for [`SCOPE_CEILING`]'s reason. A
#: fourth file that is not a place a run-count gets typed is a claim worth making
#: in a diff.
CARVE_OUT_CEILING = 3


def tracked(root):
    """Every path git knows about under the scanned trees, plus the root's own
    pages. `git ls-files` and not a glob, because it is what makes "not the
    untracked planning document at the root" a MECHANISM rather than a wish: the
    old rule named two root pages by hand and its own test said the reason was
    untrackedness, which the two-name whitelist did not implement.
    """
    done = subprocess.run(
        # `:(glob)` so `*` stops at a `/`: the plain pathspec is depth-blind and
        # would pull in every `README.md` under `crates/` and `tools/` as well.
        ["git", "-C", str(root), "ls-files", "-z", "--", *SCANNED_TREES, ":(glob)*.md"],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        raise RuntimeError(f"git ls-files exited {done.returncode}: {done.stderr.strip()[:200]}")
    return sorted(q for q in done.stdout.split("\0") if q)


def scanned(root, findings=None):
    """The published trees, in a fixed order so two findings read the same way.

    A file that does not decode was dropped rather than reported, and there is a
    difference between the two reasons it might not: an image carries no prose and
    is nothing to this rule, while a page in some other encoding is a page the
    scan silently stops reading. Told apart the way git tells them apart, by a NUL
    byte. Measured over this tree: 21 files do not decode, every one an image and
    every one with a NUL in it, so the report costs nothing today.
    """
    out = []
    for rel in tracked(root):
        if rel in NOT_TYPED_HERE:
            continue
        path = root / rel
        try:
            path.read_text()
        except UnicodeDecodeError:
            if findings is not None and b"\0" not in path.read_bytes():
                findings.append(
                    f"{rel}: tracked under a scanned tree and does not decode as UTF-8,"
                    " and it is not binary — a page the scan cannot read is a page a"
                    " run-count can be typed into with nothing to see it"
                )
            continue
        except OSError:
            # A page that is THERE and cannot be read is the same silence as one
            # that does not decode. A missing one is not: a tracked file deleted
            # but not yet `git rm`ed is an ordinary working tree, not a hole.
            if findings is not None and path.exists():
                findings.append(
                    f"{rel}: tracked under a scanned tree and cannot be read — a page"
                    " the scan skips is a page a run-count can be typed into with"
                    " nothing to see it"
                )
            continue
        out.append(path)
    return out


def mask_regions(text):
    """The same text with every region blanked and its newlines kept, so a line
    number a finding reports still points where it says."""
    out = text
    for found in MARKER.finditer(text):
        end = END.format(found.group(1))
        stop = text.find(end, found.start())
        if stop != -1:
            chunk = text[found.start() : stop + len(end)]
            out = out.replace(chunk, "\n" * chunk.count("\n"), 1)
    return out


#: A conversion specification is a placeholder, not a measurement: the digits in
#: `%-38s` are a FIELD WIDTH, and `printf '%-42s %-38s states=%-9s …'` was read as
#: `42s`, `38s`, `38s states`, `9s`, `8s` and `3s` — six run-counts of a run that
#: never happened, in the runner's own matrix line. They became findings without
#: that line changing a byte: a comment twenty lines below it began saying
#: `` `safety` `` and `` `liveness` ``, and a shell function has no blank line in
#: it, so [`NAMES_A_RUN`] armed [`COUNT`] and [`CLOCK`] over all 55 lines at once.
#:
#: A width is REQUIRED, and that narrowing is the whole rule: the only digits a
#: specification can contribute are its width and its precision, so `%s`, `%%`,
#: `%F` and `%APPDATA%` can never produce a number and stay out of it. Measured
#: over the scanned corpus: 5 matches, every one of the five widths above — and
#: 23 in 7 files with the width made optional, `date +%F`, an SSH `ControlPath`
#: and a Windows environment variable among them.
FORMAT = re.compile(
    r"%[-+#0' ]*(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:hh|ll|[hlLqjzt])?[diouxXeEfFgGaAcspnb%]"
)

#: What replaces one, and deliberately NOT a space: whitespace here could JOIN a
#: number to a noun that `%-3s` stood between, and a line that is only a
#: specification would go blank and move a block boundary. `~` is in no class any
#: rule here matches, so this masking can only take a match away, never make one.
FORMAT_FILL = "~"


def mask_formats(text):
    """The same text with every conversion specification blanked and its LENGTH
    kept, so an offset taken from it still lands where it says — the discipline
    [`mask_regions`] keeps with newlines, one level down."""
    return FORMAT.sub(lambda found: FORMAT_FILL * len(found.group(0)), text)


def blocks(path, text):
    """(offset, first line, text) per paragraph — or per contiguous comment run in YAML.

    The unit is the paragraph and not the line because the sentence carrying a
    run-count rarely names the run on the same line: `docs/testing.md` names
    `safety` two lines above the tally that belongs to it, and a line-scoped rule
    read that tally as belonging to nothing.

    A markdown table row is its own block, because a table has no blank line in
    it: `docs/authorization-slice.md`'s twelve-row table was one block, and one
    cell naming `run-tlc.sh` turned the trigger on for the other eleven.

    So is a line of YAML that is not a comment. Only comment runs were read at
    all, which made a count in a `name:`, an `env:` or a
    `run: echo '21 GREEN, 174 RED' >> $GITHUB_STEP_SUMMARY` invisible — the
    workflow's own PUBLISHED OUTPUT, driven, exit 0. Its own block and not part
    of a paragraph, for the table row's reason: a whole workflow file has few
    blank lines in it, and one step naming the runner would arm every other.
    """
    yaml = path.suffix in (".yml", ".yaml")
    out, current, start, at = [], [], None, None
    offset = 0
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        body = line.rstrip("\n")
        comment = body.strip().startswith("#")
        keep = comment if yaml else body.strip() != ""
        alone = body.lstrip().startswith("|") if not yaml else False
        if yaml and body.strip() and not comment:
            keep, alone = True, True
        if current and (not keep or alone):
            out.append((at, start, "\n".join(current)))
            current, start, at = [], None, None
        if keep:
            if start is None:
                start, at = number, offset
            current.append(body)
            if alone:
                out.append((at, start, body))
                current, start, at = [], None, None
        offset += len(line)
    if current:
        out.append((at, start, "\n".join(current)))
    return out


def scoped_spans(rel, text, findings):
    """(start, stop) of each registered fragment in this file, once each."""
    spans = {}
    for key in sorted(k for k in SCOPED if k[0] == rel):
        times = text.count(key[1])
        if times == 0:
            findings.append(
                f"{rel}: scoped {key[1][:48]!r} matches nothing — a stale exemption is"
                " one nobody is reading"
            )
        elif times > 1:
            findings.append(
                f"{rel}: scoped {key[1][:48]!r} occurs {times} times — a figure worth a"
                " scope label is worth saying once"
            )
        else:
            at = text.index(key[1])
            spans[key] = (at, at + len(key[1]))
    return spans


#: Every way this tree can group a long number, as a CLASS and not a list of
#: whole spellings. A newline and a tab are in it because `77 563 872` re-wrapped
#: by an editor is `77 563` at the end of one line and `872` at the start of the
#: next, and a list of whole spellings could not see that — the same
#: enumerate-the-shapes mistake this rule exists in order not to make, one level
#: down inside it. Measured over the corpus: 0 such occurrences today and 0 new
#: false positives, so it costs nothing and closes the spelling before it lands.
#:
#: Written with explicit escapes, and as the class's CONTENTS so its second
#: reader shares them rather than retyping them. Both were the measured defect:
#: this held the plain space TWICE and the three invisible characters raw --
#: which is the bug [`GROUP`]'s own comment is about, two hundred lines up -- and
#: `emitted` carried a retyped copy of the class with the newline left out. So a
#: value the generator wrapped mid-number was read as `563 872`, and the real
#: `77 563 872` was then hunted for by nothing at all, silently.
GROUPING = r"\x20\u00a0\u2009\u202f,_\n\r\t"
GROUPER = f"[{GROUPING}]"


def groupings(value):
    """One number and every way this tree groups it, as a pattern fragment. The
    groups stay three digits wide, so a spaced-out digit string cannot match."""
    return rf"{GROUPER}?".join(re.escape(part) for part in f"{value:,}".split(","))


def spelled(value):
    r"""One number and every grouping of it, as a pattern, anchored on both sides
    against a digit or a decimal point so a value cannot match inside a longer
    one.

    A word character on either side is a hex constant or an identifier, not this
    number: `0x77563872` matched while the guard was `[\d.,_]`. A trailing `.` is
    only refused when a digit follows it, or a value at the end of a sentence
    would stop being one.
    """
    return re.compile(r"(?<!\w)(?<![.,])" + groupings(value) + r"(?!\w)(?![.,]\d)")


def emitted(bodies):
    """The values the generated regions print that are big enough to be nobody
    else's. Read back out of the rendered bodies rather than listed beside them:
    a second list would be the copy this rule exists to refuse."""
    out = set()
    for body in bodies.values():
        for text in re.findall(rf"\d[\d{GROUPING}]*\d|\d", body):
            digits = re.sub(r"[^\d]", "", text)
            if digits and int(digits) >= VALUE_FLOOR:
                out.add(int(digits))
    return out


#: What may stand between a published value and the unit the generator wrote
#: beside it: whitespace, an emphasis pair, one dash, or a code span the VALUE
#: opens. A closing backtick is deliberately not in it — `WORKERS=2` followed by
#: `` ` `` and ` and` is a value and the next word, and `2 and` is not a claim
#: about anything. Neither is `phase-2 baseline`, which is why the value may not
#: carry a hyphen on its left either.
UNIT_JOIN = r"(?:\*\*)?(?:[ \t\n]+`?|[-\u2013\u2014]|)[ \t\n]*"
PAIR = re.compile(rf"(?<![-\w.])({NUM}|{WORD}){UNIT_JOIN}([A-Za-z][A-Za-z*`]*)")


def phrased(bodies):
    """Every `<value> <unit>` the PROSE regions print, as the generator wrote it.

    [`VALUE_FLOOR`] is floored by magnitude because a bare small number is every
    other number in the tree — which left `8 named invariants`, `the nine shipped
    models`, `18 cores` and `WORKERS=2` under no rule at all, in any paragraph. A
    value WITH ITS UNIT is not every other number, so this reaches below that
    floor; and like the value rule it is generated from what the region says, so
    it needs no [`NOUN`] list and, above all, no [`NAMES_A_RUN`] beside it.

    That trigger is why this rule is here. It is paragraph-local, so a paragraph
    restating every number the regions publish and not spelling `safety`,
    `liveness`, `run-tlc`, `comutate` or `--tiers` was five lines at exit 0 —
    and dropping it is not the answer either: measured over this tree, the shape
    scan goes from 41 literals to 549 and 505 of them want registering.

    Not the Results table: its cells are `3` and `1 s`, and a rule hunting those
    tree-wide is a rule about every number there is. Measured over the scanned
    corpus at the time of writing: 21 pairs, ONE occurrence outside a region.
    """
    out = set()
    for key, body in bodies.items():
        if key == TABLE_REGION:
            continue
        for found in PAIR.finditer(body):
            if unit := found.group(2).strip("*`"):
                out.add((found.group(1), unit))
    return out


#: Provenance a region prints VERBATIM rather than as a count, and that no rule
#: above can reach: the run's date, whose three numbers are all under
#: [`VALUE_FLOOR`], and the `WORKERS=` it ran at, whose unit stands on the LEFT
#: of the value so [`PAIR`] pairs it with the next word instead. Each is
#: published on three pages and each was held by nothing. Measured: 0
#: occurrences outside a region today, so the rule costs no registration.
VERBATIM = re.compile(r"\d{4}-\d\d-\d\d|\b[A-Z][A-Z_]*=[\w.]+")


def spoken(bodies):
    """The provenance strings the prose regions print, as they print them."""
    return {
        found.group(0)
        for key, body in bodies.items()
        if key != TABLE_REGION
        for found in VERBATIM.finditer(body)
    }


def phrase_pattern(counted, unit):
    """One published `<value> <unit>`, in every grouping of the value and in
    whatever case the prose around it uses — `21 GREEN` and `21 green` are the
    same second copy.

    And in whatever unit of the same KIND, because the generator's word is not
    the only one a page uses: `3225 seconds` is `3225 s`, and `71 entries` is the
    `71-entry` roster — which is the sentence a commit in this very series had to
    hand-correct from 69. Widened only into the two vocabularies this file
    already enumerates for the shape scan, never into a list invented here.
    Measured: 4 more occurrences over the tree, 2 of them real second copies.
    """
    left = (
        groupings(int(re.sub(r"[^\d]", "", counted)))
        if counted[0].isdigit()
        else re.escape(counted)
    )
    if re.fullmatch(CLOCK_UNIT, unit):
        right = rf"(?:{CLOCK_UNIT})"
    elif re.fullmatch(NOUN, unit, re.I):
        right = rf"(?:{NOUN})"
    else:
        right = re.escape(unit)
    return re.compile(rf"(?<![-\w])(?<![.,]){left}(?!\w){UNIT_JOIN}{right}(?!\w)", re.I)


def check_scope(root, findings):
    """What is checkable about [`SCOPED`] itself, which was nothing at all.

    Not the label's TRUTH — a description of an entirely different run passes
    here and no rule can change that, which is the honest limit of a prose
    exemption. Nor "written for its entry" in any sense a program can hold:
    driven, eight words of nonsense, a neighbour's label with ONE word changed or
    its last word deleted, and `"the the the the the the the the"` are all
    accepted, and only the byte-identical paste is refused. What these hold is
    that a label exists, is not a verbatim copy of another entry's, and points at
    a file this gate actually reads.
    """
    pages = {p.relative_to(root).as_posix() for p in scanned(root)}
    seen = {}
    for (rel, fragment), label in sorted(SCOPED.items()):
        where = f"SCOPED[{rel}, {fragment[:36]!r}]"
        if rel not in pages:
            findings.append(
                f"{where}: names a file the scan does not read — an exemption from a rule"
                " that was never going to fire is one nobody can check"
            )
        words = len(str(label or "").split())
        if words < LABEL_WORDS:
            findings.append(
                f"{where}: its scope is {words} word(s), under {LABEL_WORDS} — the entry"
                " is what the figure is history TO, and a label nobody wrote is a"
                " literal nobody scoped"
            )
        elif label in seen:
            findings.append(
                f"{where}: its scope is word for word {seen[label]}'s — one of the two"
                " was pasted, and a pasted label describes the other entry"
            )
        else:
            seen[label] = where
    if len(SCOPED) != SCOPE_CEILING:
        findings.append(
            f"{len(SCOPED)} scoped entries against a ceiling of {SCOPE_CEILING} — move"
            " it in the same diff as the entry that needs it, so the exemption surface"
            " grows where somebody can see it. A ceiling with headroom is one nobody"
            " has to move, which is how raising it to 999 survived a mutation run"
        )


def scan(root, owned, values, pairs, said, findings):
    """How many run-count literals the published trees hold, and where.

    `owned` is what the generator writes. A marker pair it does NOT own would
    otherwise be the hole this whole row is about wearing the row's own clothes:
    `mask_regions` would blank it out of the scan and nothing would diff it, so a
    typed number inside one would be invisible from both sides. Measured on this
    file — a `liveness-row` pair reached the tree before its generator did.
    """
    found = 0
    #: One tally per rule, so `RULE_FLOOR` can ask each whether it still matches
    #: the tree. `names-a-run` counts BLOCKS, not literals: it is the trigger, and
    #: what it can lose is the arming, not a match of its own.
    per = dict.fromkeys(("tally", "count", "clock", "loose-tally", "names-a-run"), 0)
    per["emitted-value"] = len(values)
    per["emitted-phrase"] = len(pairs)
    per["emitted-verbatim"] = len(said)
    wanted = {v: spelled(v) for v in sorted(values)}
    phrases = {pair: phrase_pattern(*pair) for pair in sorted(pairs)}
    phrases.update({(text, ""): re.compile(rf"(?<!\w){re.escape(text)}(?!\w)") for text in sorted(said)})
    #: literals each registered fragment actually exempts, so an entry can be
    #: held to buying silence for a bounded, non-zero number of them.
    exempted = {}
    for path in scanned(root, findings):
        rel = path.relative_to(root).as_posix()
        text = path.read_text()
        for marker in MARKER.finditer(text):
            if owned is not None and (rel, marker.group(1)) not in owned:
                findings.append(
                    f"{rel}: a run-count region named {marker.group(1)!r} that the"
                    " generator does not write — nothing diffs what is inside it and"
                    " the scan cannot see it either"
                )
        if rel in GENERATED_ELSEWHERE:
            if GENERATED_ELSEWHERE[rel] not in text:
                findings.append(
                    f"{rel}: carved out as written by `{GENERATED_ELSEWHERE[rel]}` and it"
                    " no longer says so — a stale carve-out is an unread page"
                )
            continue
        # Both halves read the MASKED text. A region is replaced by its own
        # newline count rather than deleted, but the bytes still move, and spans
        # taken from the original then land beside the literals they cover.
        masked = mask_regions(text)
        spans = scoped_spans(rel, masked, findings)
        exempted.update(dict.fromkeys(spans, 0))
        # And then the field widths, for every rule below and for none of the
        # above: a registered fragment is prose somebody wrote and may say `%-38s`
        # if it is quoting one. Length-preserving, so the spans just taken still
        # land on the literals they cover.
        masked = mask_formats(masked)
        # The value rule reads the whole masked file rather than its blocks: it
        # needs no trigger beside the literal, so a paragraph is not the unit of
        # anything here, and a number in a table cell is as much a second copy as
        # one in a sentence.
        # ONE literal, ONE finding, across the rules as well as within them:
        # `77 563 872 distinct` is a value the regions print AND a phrase they
        # print, and reporting it twice would say the page holds two — and, in a
        # registered fragment, would spend `SCOPE_SPAN_CAP` twice over.
        claimed = []
        for value, pattern in wanted.items():
            for m in pattern.finditer(masked):
                claimed.append((m.start(), m.end()))
                if inside := [k for k, (lo, hi) in spans.items() if lo <= m.start() and m.end() <= hi]:
                    exempted[inside[0]] += 1
                    continue
                findings.append(
                    f"{rel}:{masked[: m.start()].count(chr(10)) + 1}: {m.group(0)!r} is a"
                    f" second copy of {value}, which the generated regions print — say it"
                    " in the region, point at the region, or register it in"
                    " scripts/run_count_gate.py SCOPED with what it is history to"
                )
        for at, start, block in blocks(path, masked):
            triggers = [(m, "tally") for m in TALLY.finditer(block)]
            if NAMES_A_RUN.search(block):
                per["names-a-run"] += 1
                tight = [m.span() for m, _ in triggers]
                triggers += [
                    (m, name)
                    for rx, name in ((COUNT, "count"), (LOOSE_TALLY, "loose-tally"), (CLOCK, "clock"))
                    for m in rx.finditer(block)
                    if rx is not LOOSE_TALLY
                    or not any(m.start() <= lo and hi <= m.end() for lo, hi in tight)
                ]
            for _, name in triggers:
                per[name] += 1
            # ONE literal, ONE finding, twice over: a loose tally that swallows a
            # tight one is the same claim read wider (`1849 s**; 19 GREEN`), and
            # the two tally forms match `19 GREEN` at the same span. Reporting
            # either pair twice would say the page holds two.
            for begin, stop, literal in sorted({
                (at + m.start(), at + m.end(), m.group(0).strip()) for m, _ in triggers
            }):
                found += 1
                claimed.append((begin, stop))
                if inside := [k for k, (lo, hi) in spans.items() if lo <= begin and stop <= hi]:
                    exempted[inside[0]] += 1
                    continue
                findings.append(
                    f"{rel}:{start}: {literal!r} is a run-count outside every generated"
                    " region — put the sentence in one, or register it in"
                    " scripts/run_count_gate.py SCOPED with what it is history to"
                )
        for said_as, pattern in phrases.items():
            for m in pattern.finditer(masked):
                if any(lo < m.end() and m.start() < hi for lo, hi in claimed):
                    continue
                if inside := [k for k, (lo, hi) in spans.items() if lo <= m.start() and m.end() <= hi]:
                    exempted[inside[0]] += 1
                    continue
                findings.append(
                    f"{rel}:{masked[: m.start()].count(chr(10)) + 1}: {m.group(0)!r} is a"
                    f" second copy of `{' '.join(said_as).strip()}`, which the generated"
                    " regions print — say it in the region, point at the region, or"
                    " register it in scripts/run_count_gate.py SCOPED with what it is"
                    " history to"
                )
    for key, count in sorted(exempted.items()):
        where = f"SCOPED[{key[0]}, {key[1][:36]!r}]"
        if count == 0:
            findings.append(
                f"{where}: its fragment is in the page and exempts no literal — the rules"
                " have moved past it, and an exemption for nothing is one nobody reads"
            )
        elif count > SCOPE_SPAN_CAP:
            findings.append(
                f"{where}: one fragment exempts {count} literals, over the cap of"
                f" {SCOPE_SPAN_CAP} — split the registration; a span this wide is an"
                " exemption nobody sized"
            )
    widest = max(exempted.values(), default=0)
    if exempted and SCOPE_SPAN_CAP != widest + 1:
        findings.append(
            f"the widest registered fragment exempts {widest} literal(s) and the cap is"
            f" {SCOPE_SPAN_CAP} — it sits one above the widest, or it is headroom nobody"
            " has to move and raising it costs a diff line nobody reads"
        )
    for name, count in sorted(per.items()):
        if count < RULE_FLOOR:
            findings.append(
                f"the {name} rule matched {count}, under the floor of {RULE_FLOOR} — one"
                " rule of the scan has stopped matching this tree's spelling, which the"
                f" {SCAN_FLOOR} the whole scan is floored at cannot see"
            )
    return found


# --- the row ---------------------------------------------------------------


def audit(root):
    """(findings, one-line summary) for what this checkout publishes about its runs."""
    root = pathlib.Path(root)
    findings = []
    try:
        runs, listed = load(root), tiers(root)
    except (RuntimeError, OSError, tomllib.TOMLDecodeError) as error:
        return [str(error)], "run-count-gate: nothing published"
    # Before anything reads the record: a tier with no record at all. Reported
    # here and alone, because everything below fires on it in a way that
    # misdescribes it — the Results groups say the family has gone from the tree
    # and the region generator says `KeyError`, and a reader believes the tree is
    # wrong when a run is simply missing.
    unmatched = [
        f"{RUNNER} lists {tier} and {RECORD} has no run of it — record one with"
        f" `./formal/run-tlc.sh {tier} | tee <log>` and"
        " `python scripts/run_count_gate.py --record <log>`"
        for tier in sorted(set(listed) - set(runs))
    ] + [
        f"{RECORD} has a run of {tier} and {RUNNER} lists no tier by that name"
        for tier in sorted(set(runs) - set(listed))
    ]
    if unmatched:
        return unmatched, "run-count-gate: the record and the tiers disagree"
    check_record(root, runs, listed, floors(root), findings)

    bodies, owned = {}, None
    try:
        bodies = region_bodies(facts(root, runs, listed), findings)
        owned, want = set(bodies), rendered(root, bodies)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        # ONE cause, ONE message: with no roster of regions every marker in the
        # tree reads as unowned, and a page of those for one broken generator is
        # the report defect where the reader is told the tree is wrong.
        findings.append(f"the generated regions cannot be built: {error}")
        want = {}
    for rel, text in sorted(want.items()):
        if (root / rel).read_text() != text:
            findings.append(
                f"{rel}: a generated region is not what the generator writes — run"
                " `python scripts/run_count_gate.py --write` and commit the result"
            )

    for rel, why in sorted(NOT_TYPED_HERE.items()):
        if not (root / rel).is_file():
            findings.append(
                f"{rel}: carved out of the scan as {why[:48]}…, and there is no such file"
                " — a carve-out nobody has is one nobody is reading"
            )
        if len(str(why or "").split()) < LABEL_WORDS:
            findings.append(
                f"{rel}: carved out of the scan in {len(str(why or '').split())} word(s),"
                f" under {LABEL_WORDS} — the same rule its sibling registry has, because"
                " it is the same kind of exemption"
            )
    if len(NOT_TYPED_HERE) != CARVE_OUT_CEILING:
        findings.append(
            f"{len(NOT_TYPED_HERE)} file(s) carved out of the scan against a ceiling of"
            f" {CARVE_OUT_CEILING} — a page that is not a place a run-count gets typed is"
            " a claim, and it belongs in a diff beside the reason for it"
        )

    # The other direction on [`GENERATED_ELSEWHERE`], and the half the staleness
    # rule inside `scan` is NOT: it asks the page, and a page saying so is the
    # page's own word. Driven before this existed — a listed page with the phrase
    # in ordinary prose was exempt at exit 0, which is the pass `claims_gate`
    # measured and closed by asking the GENERATOR instead.
    writes = claims_gate.generated_pages(root)
    for rel, header in sorted(GENERATED_ELSEWHERE.items()):
        if writes.get(rel) != header:
            findings.append(
                f"{rel}: carved out as written by `{header}` and no generator in"
                " `scripts/` names it as the page it writes — the carve-out is the"
                " generator's word or it is the page's own"
            )

    if len(bodies) < REGION_FLOOR:
        findings.append(
            f"the generator writes {len(bodies)} region(s), under the floor of"
            f" {REGION_FLOOR} — a published sentence has stopped being generated, and a"
            " sentence nothing writes is one somebody types"
        )

    check_scope(root, findings)
    found = scan(root, owned, emitted(bodies), phrased(bodies), spoken(bodies), findings)
    if found < SCAN_FLOOR:
        findings.append(
            f"the scan matched {found} literal(s), under the floor of {SCAN_FLOOR} — the"
            " vocabulary stopped matching the tree rather than the tree stopped saying it"
        )

    return findings, (
        f"run-count-gate: ok — {len(runs)} recorded tier run(s),"
        f" {sum(len(r['rows']) for r in runs.values())} of"
        f" {sum(len(v) for v in listed.values())} configuration(s) observed,"
        f" {len(bodies)} generated region(s), {found} literal(s) scanned,"
        f" {len(SCOPED)} scoped"
    )


# --- the recorder ----------------------------------------------------------


def host(cores):
    """The machine, asked rather than typed — a hand-written host is the same
    defect as a hand-written count, about a fact nobody can check later.

    `cores` comes from TLC's banner rather than from `os.cpu_count()`, because
    the recorder need not be the machine that ran. The brand string is the one
    fact of the three the JVM does not print, so it stays local and the arch is
    held against the banner to say the two are the same box.
    """
    brand = subprocess.run(
        ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
    )
    name = brand.stdout.strip() if brand.returncode == 0 else ""
    return f"{name or os.uname().machine} ({cores} cores)"


#: The one ISA under two names each. Folded rather than substring-matched: the
#: banner's `aarch64` does not contain `uname`'s `arm64`, so the plain comparison
#: refused every honest record on this machine.
ARCH = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}


def arch(text):
    """Whichever ISA name [`ARCH`] knows appears in `text`, folded."""
    return next((v for k, v in ARCH.items() if k in text), text)


def provenance(logs):
    """(date, workers, cores, earliest start) as TLC reported them, over one
    tier's logs.

    Read out of the run and not off the recorder: `WORKERS=9 … --record` over a
    log whose banner says two published *"at the default `WORKERS=9`"* on three
    pages, and `date.today()` is the day somebody got round to recording. One
    disagreement among the logs is a record assembled from two runs.
    """
    seen, first = {}, None
    for cfg, text in sorted(logs.items()):
        banner, started = TLC_BANNER.search(text), TLC_STARTED.search(text)
        if not banner or not started:
            raise RuntimeError(f"{cfg}: its log carries no TLC banner or start time")
        # `uname` and the JVM spell one ISA two ways — `arm64` here, `aarch64` in
        # the banner — so the names are folded before they are compared. Compared
        # at all because `host` is the log's core count wearing the local machine's
        # brand string, and those are one box or the field is a fiction.
        if arch(banner.group(3)) != arch(os.uname().machine):
            raise RuntimeError(
                f"{cfg}: TLC ran on {banner.group(3)!r} and this is"
                f" {os.uname().machine} — record where the run happened"
            )
        stamp = f"{started.group(1)} {started.group(2)}"
        first = stamp if first is None else min(first, stamp)
        seen.setdefault((started.group(1), int(banner.group(1)), int(banner.group(2))), []).append(cfg)
    if len(seen) != 1:
        spread = "; ".join(f"{k} ({len(v)} row(s), e.g. {v[0]})" for k, v in sorted(seen.items()))
        raise RuntimeError(f"the logs disagree about date/workers/cores — {spread}")
    return (*next(iter(seen)), first)


def quoted(value):
    """A TOML scalar. Basic strings, because a verdict can carry anything TLC put
    on its error line — including the quotes a literal string could not hold."""
    if isinstance(value, int):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def record(root, log):
    """Fold a `run-tlc.sh` capture into [`RECORD`], one `[[run]]` per whole tier."""
    root = pathlib.Path(root)
    rows = matrix_rows(pathlib.Path(log).read_text(errors="replace"))
    if not rows:
        raise RuntimeError(f"{log}: no `<cfg> <verdict> states=… distinct=… depth=… Ns` row")
    listed = tiers(root)
    seen = {r["cfg"] for r in rows}
    covered = [tier for tier, members in listed.items() if set(members) <= seen]
    if not covered:
        raise RuntimeError(
            f"{log} covers no tier whole: it holds {len(seen)} configuration(s) and the"
            f" smallest tier needs {min(len(v) for v in listed.values())}."
            " A partial run is not a roster run"
        )
    stray = seen - {cfg for tier in covered for cfg in listed[tier]}
    if stray:
        raise RuntimeError(f"{log}: {len(stray)} row(s) belong to no covered tier: {sorted(stray)[:4]}")

    kept = {}
    if (root / RECORD).is_file():
        for entry in tomllib.loads((root / RECORD).read_text()).get("run", []):
            kept[entry["tier"]] = entry
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    for tier in covered:
        members = set(listed[tier])
        mine = [r for r in rows if r["cfg"] in members]
        matrix = "\n".join(
            f"{r['cfg']:<44} {r['verdict']:<40} states={r['states']:<10}"
            f" distinct={r['distinct']:<9} depth={r['depth']:<3} {r['seconds']}s{r['mark']}"
            for r in mine
        )
        summaries, logs = [], {}
        for r in mine:
            line, text = tlc_line(root, r["cfg"])
            summaries.append(line)
            logs[r["cfg"]] = text
        date, workers, cores, started = provenance(logs)
        # RE-RECORDING THE SAME RUN MOVES NOTHING. `--record` used to stamp
        # `date.today()` and HEAD on every call, so running it twice over one
        # capture republished the run as a different, later one — of a tree it had
        # never seen. An unchanged matrix is the same run; only what its logs said
        # gets attached, and the provenance already recorded stands.
        same = kept.get(tier, {}) if kept.get(tier, {}).get("matrix", "").strip() == matrix else {}
        if same and (same.get("date"), same.get("workers")) != (date, workers):
            raise RuntimeError(
                f"{tier} is recorded as {same.get('date')} at WORKERS={same.get('workers')}"
                f" and these logs are {date} at {workers} — the matrix is the same run's"
                " and the logs beside it are not"
            )
        if not same:
            # The commit is the one field with no second copy anywhere — TLC does
            # not know it. So the only claim worth refusing is the one that is
            # checkable: a HEAD younger than the run is a record of a tree the run
            # never saw, which is what a `--record` after an unrelated commit writes.
            when = subprocess.run(
                ["git", "-C", str(root), "log", "-1", "--format=%cd",
                 "--date=format:%Y-%m-%d %H:%M:%S", head.stdout.strip()],
                capture_output=True, text=True,
            ).stdout.strip()
            if when > started:
                raise RuntimeError(
                    f"HEAD was committed {when} and {tier} started {started} — record"
                    " before committing, or re-run the tier: a run of a tree that no"
                    " longer exists is the same defect one level up"
                )
        kept[tier] = {
            "tier": tier,
            "command": f"./formal/run-tlc.sh {tier}",
            "date": same.get("date", date),
            "commit": same.get("commit", head.stdout.strip()),
            "host": same.get("host", host(cores)),
            "workers": same.get("workers", workers),
            "matrix": matrix,
            "tlc": "\n".join(summaries),
        }
    body = HEADER
    for _, entry in sorted(kept.items()):
        body += "\n[[run]]\n"
        for key, value in entry.items():
            if key in ("matrix", "tlc"):
                # A LITERAL multi-line string: TLC's generic error line reaches
                # this file verbatim and TLA+ operators are `/\` and `\/`, which
                # a basic string reads as escapes and refuses to parse.
                if "'''" in value:
                    raise RuntimeError(f"a {key} row carries ''', which no TOML string holds")
                body += f"{key} = '''\n{value}\n'''\n"
            else:
                body += f"{key} = {quoted(value)}\n"
    (root / RECORD).write_text(body)
    print(f"run-count-gate: recorded {', '.join(sorted(covered))} into {RECORD}")
    return 0


#: What the record says about itself. Prose only: every number under it is a row
#: of a matrix a run printed.
HEADER = """\
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# OBSERVED ROSTER RUNS. Written by `python scripts/run_count_gate.py --record
# <log>` over a capture of `formal/run-tlc.sh`, and read back by that gate to
# emit every run-count the documentation publishes.
#
# `matrix` is the runner's own output, unedited, one line per configuration, and
# no total is stored beside it: the row count, the wall clock and the GREEN/RED
# tally are COUNTED out of it on every gate run, so no total here can disagree
# with the rows it is a total of. That disagreement is what this file exists for
# -- seven published run-counts were stale on the day it was written, one of them
# in the paragraph the docs introduce as the one to quote.
#
# `tlc` is the SAME run in TLC's own words: the banner, the start line and the
# closing sentences of each `formal/out/<cfg>.log`, kept at `--record` time
# because those logs are gitignored and the next run overwrites them. The gate
# re-derives every row's states, distinct states and depth from it, holds the
# runner's wall clock to TLC's -- per row and summed over the tier -- and holds
# `date`, `host` and `workers` to what the banner and the start line say. It also
# reads what the kept line says about itself: a GREEN row prints a state count
# and leaves nothing on its queue, and no run finds more distinct states than it
# generated. This does NOT make a run unforgeable -- both halves are bytes in a
# committed file -- and it is not meant to. It makes a number here unrottable BY
# HAND: `distinct` and the clock had no second source at all, so editing one and
# running `--write` restored six published sentences to the exact defect this
# file was added to close, with the gate green. Now the edit contradicts a
# sentence a JVM wrote, in this file, on the next line but one.
#
# A run is a run of the tier as `run-tlc.sh --tiers` lists it TODAY: the gate
# holds every listed configuration against this matrix, every verdict against
# `floors.txt`, and refuses a row the runner marked `!!`. A roster that grows
# therefore reddens the row until somebody runs it again, which is the point --
# "the whole tier, all green" is otherwise a sentence about a tree that has gone.
"""


def run(root, argv):
    if argv[:1] == ["--record"]:
        return record(root, argv[1])
    if argv[:1] == ["--write"]:
        runs, listed = load(root), tiers(root)
        # The generator is the laundry, and the row's own message sends people to
        # it: edit a number in the record, run this, and six published sentences
        # agree with the edit. So it refuses the same record the row refuses,
        # over the same checks — the ones about whether the record is a run.
        refused = []
        check_record(root, runs, listed, floors(root), refused)
        if refused:
            print(f"run-count-gate: {len(refused)} finding(s) in {RECORD} — refusing to"
                  " publish from it", file=sys.stderr)
            for finding in refused:
                print(f"  {finding}", file=sys.stderr)
            return 1
        for rel, text in sorted(rendered(root, region_bodies(facts(root, runs, listed))).items()):
            (root / rel).write_text(text)
            print(f"run-count-gate: wrote {rel}")
        return 0
    findings, summary = audit(root)
    if findings:
        print(f"run-count-gate: {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    usage = "usage: run_count_gate.py [--write | --record <log>]"
    if argv and argv[0] not in ("--write", "--record"):
        print(usage, file=sys.stderr)
        return 2
    if argv[:1] == ["--record"] and len(argv) != 2 or argv[:1] == ["--write"] and len(argv) != 1:
        print(usage, file=sys.stderr)
        return 2
    return run(ROOT, argv)


if __name__ == "__main__":
    raise SystemExit(main())
