# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `platform_gate.py` is verified against.

Every rule is broken once on a fixture and the break must be the finding it
claims to be — the message is asserted, never the count, because a red run whose
reason nobody read proves as little as one that cannot go red. Then the real
checkout closes the other direction.

**Every rule broken at least once, and the count is not the claim.** The first
table was 30/30 and an adversarial review broke four of its rules with the suite
green; the second was 47 and a review of the board-record rules broke EIGHT more
— a whole vocabulary, a `fullmatch` loosened to `search`, and three loops each
pinned by one field of three or five. Those eight have a case apiece below, and
the lesson is the count itself: a table that reports a total says nothing about
which rule the next mutation will walk through — the model floor zeroed (the other three derivations had a floor case and
that one did not), the design-page list narrowed, `BOARD_REVISION` loosened to
the bare part number, and two vocabularies widened by a member. Each has its case
here now, and the pattern is the one this programme keeps meeting: the table was
written against the rules the author had in mind, and a value can be moved
without a rule being deleted.

Every spelling below is one that got past a first version, measured rather than
imagined: a slice assumption in a bundle, in a bundle SUBDIRECTORY, and on a
design page the list never named; a board-only suite the USB/IP guest names as a
glob (`tests/02_*.py`), in full (`tests/73_otp_keyboard.py`), and in a COMMENT
that runs nothing; four legal spellings of an `UNSUPPORTED` entry the shim's own
regex could not read; the word `unsafe` in a line comment, a doc comment, a
nested block comment and a string literal; a new crate at the top of the tree;
and a board revision written `RP2350 A2`, `A2` alone, and `RP2350` alone. The
five derivations are floored apart rather than in total, because a floor over the
union cannot tell "the `unsafe` finder stopped finding" from "the bundle reader
did" — and the floors are asserted by VALUE, because a key set does not see a 0.

The prose-page cases below are the newest, and the spellings are the ones the
rule was driven against on the real checkout rather than imagined: a page as the
SOLE evidence (exit 0 before the rule), a page APPENDED to three real artifacts
(what "at least one artifact" would have missed), a page carrying a real
generator's header over a file that generator does not write, and — green, and
asserted so that widening it is a diff — an artifact of legal shape that is
plainly irrelevant. Two co-refutations, each read for direction: deleting the
rule leaves the three red cases finding NOTHING, and dropping the generated-page
carve-out reddens `PLAT-BUILD-001` on the real checkout, which is the false red
and the opposite direction.

The `unsafe` cases carry the newest holes, and two of them are corrections of
verdicts written down in this table's own prose. An insert case and a duplicate
case were both here and a REORDER was not — so the `~2` over two colliding sites
had exactly the defect the file-position ordinal was rejected for, measured on
the checkout: register `~2`, swap the two functions, byte-identical at exit 0
with each justification silently attached to the other one. The `~n` clause was
then recorded as DECORATIVE off a removal arm at exit 0, and `UNSAFE_EXCLUDED`
after it; both arms were run on a CLEAN tree, where neither clause can fire.
Driven on their own defect inputs — a duplicate site, and one `unsafe` under
`third_party/` — the first is exit 1 with two findings and the second exit 1 with
three. Both verdicts are wrong, and the arms are recorded beside the code they
are about. A collision case here also has to collide AT the boundary: written
with five words against six, the keys differ with no rule applied, and the case
passes over a derivation that only counts.

Then a review drove FOUR spellings past that rule, each measured at exit 0 on the
real checkout, and every one of them has a case here: the page this gate itself
writes, cited by a row that page is rendered FROM (and this registry, the same
loop with no page in it); a DIRECTORY, because `.exists()` is not `is_file()` and
the module's founding sentence survives with "the directory README.md sits in"
substituted; `README.MD`, which APFS folds and a `.md` suffix test does not, so
the literal page the rule exists to refuse passed locally and would have reddened
on CI as `is not in the tree` — the right colour for the wrong reason; and a page
whose generator CLAIMS it without marking it, which this gate accepted because it
read the KEY of `claims_gate`'s mapping and that gate reads the key and the
header. The green arms are the ones that say the clauses are not "no `.md`" and
not "no generated page": the matrix page is still evidence, and so is a generated
page that names a DIFFERENT row.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import gate_lines
import platform_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

MODEL_REGISTRY = """\
[[assumption]]
constant = "WorldIsFlat"
statement = "A model constant the fixture pins both ways."
discharged_by = "a measurement"
risk = "coverage"
"""

PROPERTIES = """\
[[property]]
id = "SEC-T-001"
name = "FooStaysClosed"
status = "MODELLED-ONLY"
statement = "Foo stays closed."
source = ["spec"]
"""

BUNDLE = """\
[property]
id = "SEC-T-001"

[[assumption]]
id = "AS-T-1"
statement = "The emulator answers as the board."
registered = "yes — PLAT-TOOL-001"
"""

DESIGN_PAGE = """\
# The slice

| id | Assumption |
|---|---|
| `AS-T-2` | A design-page assumption with no bundle row yet |
"""

#: A generator, reduced to the pair `claims_gate.generated_pages` reads. It is in
#: the fixture because the prose-page exemption is DERIVED from that pair and not
#: from anything a page says about itself: a tree with no `*_gate.py` reads every
#: `.md` as hand-written, and the carve-out's green arm would then pass for the
#: wrong reason — there would be no exempt page in the tree to accept.
MATRIX_GATE = '''\
"""A generator of one page."""
import pathlib

ARTIFACT = pathlib.Path("docs/assurance-matrix.md")
GENERATED_BY = "Generated by scripts/matrix_gate.py --write"
'''

#: The page that generator claims, and the same header over a page it does NOT.
#: The second is the spelling the exemption must refuse — `claims_gate`'s own
#: drive walked three self-exempting pages past a version that read the header,
#: and reading the pair instead is what stops it. Neither carries an `AS-` token:
#: `docs/` is the design-page corpus, so a slice id here would derive a candidate
#: nothing claims and redden every case in this file.
GENERATED_PAGE = """\
<!-- Generated by scripts/matrix_gate.py --write — do not edit by hand -->

| column | value |
|---|---|
| a | 1 |
"""

#: This module's own `ARTIFACT`/`GENERATED_BY` pair, in a file shaped like the
#: script that carries it — built from the constants rather than retyped, so the
#: fixture cannot claim a page or a header the checkout does not. Without it the
#: fixture has no `platform_gate.py` in its `scripts/`, `docs/platform-assumptions.md`
#: reads as hand-written there and reads as generated on the checkout, and the
#: circularity clause is never reached by any case in this file.
SELF_GATE = f'''\
"""This gate, reduced to the pair the exemption is read from."""
import pathlib

ARTIFACT = pathlib.Path("{platform_gate.ARTIFACT}")
GENERATED_BY = "{platform_gate.GENERATED_BY}"
'''

#: The second generated page, and the one that separates "generated" from "not a
#: restatement": it is written from data like the matrix page AND it names a row
#: of this registry. That is `docs/assurance-vector.md` on the real checkout —
#: `evidence_gate.py` renders its outstanding list from `platform_gate.entries`,
#: so it names 67 of the 72 rows, measured. It names a row here that does NOT
#: cite it, so the fixture's green arm is the per-row half of the rule.
VECTOR_GATE = '''\
"""A generator of the outstanding-obligation page."""
import pathlib

ARTIFACT = pathlib.Path("docs/assurance-vector.md")
GENERATED_BY = "Generated by scripts/vector_gate.py --write"
'''

VECTOR_PAGE = """\
<!-- Generated by scripts/vector_gate.py --write — do not edit by hand -->

| row | outstanding |
|---|---|
| PLAT-FLASH-001 | a board run |
"""

#: The page that publishes what the project does not defend against, shaped like
#: the real one in the three ways the rules read: a section that NAMES a row (so
#: the pin has something to agree with), a section that names none (so "the
#: anchor resolves" is not the same rule as "the section is about this row"), and
#: a FENCED block carrying a heading and an id — both invisible, because a `#`
#: inside a code sample is not a section and an id inside one is not a citation.
#: `## Silicon & desk` is not decoration either: it is the double-dash anchor,
#: which is what a slugger that collapses runs of dropped characters gets wrong.
LIMITATIONS_PAGE = """\
# Limitations — what this fixture does not do

## Silicon & desk

- **A residual, deferred with a stated price.** See `PLAT-CRYPTO-001`.

## Protocol / compatibility

- **A feature gap no row of the registry is about.**

```text
## A heading inside a fence
PLAT-BOGUS-999
```
"""

EMU_SHIM = '''\
"""The shim."""
UNSUPPORTED = {
    "29_reset_power_cut": "cuts physical USB power during a flash write",
    "02_usb_interfaces": "reads the USB descriptors; this shim serves reports",
    "73_otp_keyboard": "drives the OTP keyboard interface over raw USB",
}
'''

USBIP_GUEST = """\
#!/usr/bin/env bash
for t in tests/02_*.py; do run "$t"; done
run tests/73_otp_keyboard.py
"""

UNSAFE_RS = """\
pub fn steal() {
    unsafe { core::ptr::null::<u8>().read() };
}
"""

#: Two sites that AGREE on all six of [`platform_gate.SITE_WORDS`] and part on the
#: seventh — `rsk-wipe`'s pair one word further along. Written out rather than
#: derived from `UNSAFE_RS`, because the collision has to be at the boundary: with
#: five words against six the keys differ with no rule applied at all, and every
#: case here then passes over a derivation that only counts.
COLLIDING_RS = """\
pub fn alpha() {
    unsafe { core::ptr::null::<u8>().read().wrapping_add(ALPHA) };
}

pub fn beta() {
    unsafe { core::ptr::null::<u8>().read().wrapping_add(BETA) };
}
"""

#: The three shapes the review drove past the first version of the derivation:
#: a line comment, a doc comment and a string literal, each carrying the word.
PROSE_RS = """\
//! `no_std`, no alloc, no `unsafe`.
/* the unsafe direction, and /* a nested */ span */
pub const EMITTED: &str = "\\n    unsafe fn ";
/// which for the erase length is the unsafe direction
pub const N: u8 = 1;
"""

#: The enumeration AGENTS.md requires, reduced to the two things the page rules
#: read: a `Runtime sites:` count, and a line naming every file that carries one.
#: TWO, because `UNSAFE_RS` is one `block` site and the fixture writes it twice —
#: and the fixture's build-script and declaration sites are deliberately NOT in
#: that number, which is the partition the real page makes and this one must too.
#: No `AS-` token: `docs/` is the design-page corpus, so a slice id here would
#: derive a candidate nothing claims and redden every case in this file.
UNSAFE_MD = """\
# The `unsafe` audit

**Runtime sites: 2.** One in `crates/rsk-a/src/lib.rs` and one in
`firmware/src/main.rs`, each a read through a null pointer.

### 1\u20132. The null reads \u2014 `PLAT-TOOLCHAIN-001`

*Safe alternative:* none, the fixture needs a site.
*Containment:* the fixture never runs.
"""

#: Two crates, and only one declares an `abstracts` list — so the derivation is
#: SELECTING rather than returning a candidate per ledger row. The `gap` prose
#: names a semantic the list leaves out, which is the real ledger's shape too: a
#: mechanic can be named without being an obligation.
CRATE_LEDGER = """\
[crate.rsk-a]
class = "state-partial"
model = "Mini"
gap = "the tear guarantee, and page reclaim, are backend mechanics the model abstracts."
abstracts = ["tear"]

[crate.rsk-b]
class = "pure"
evidence = ["assurance/properties.toml"]
"""

REGISTRY = """\
[[assumption]]
id = "PLAT-TOOL-001"
class = "tool-fidelity"
statement = "The emulator answers as the board."
discharge = "A board recording of the same session."
discharge_owner = "maintainer"
status = "pending"
failure_direction = "security: every trace-linked claim is about the emulator"
covers = ["slice:AS-T-1"]
supports = ["SEC-T-001"]

[[assumption]]
id = "PLAT-MODEL-001"
class = "model-abstraction"
statement = "A design-page assumption with no bundle row yet."
discharge = "The store slice."
discharge_owner = "contributor"
status = "pending"
failure_direction = "coverage: a cardinality nothing runs"
covers = ["slice:AS-T-2"]

[[assumption]]
id = "PLAT-BUILD-001"
class = "build-configuration"
statement = "The world is flat, as the build sees it."
discharge = "The manifest."
discharge_owner = "contributor"
status = "discharged"
evidence = ["assurance/properties.toml"]
revalidated_by = "any change to the manifest, or to assurance/crates.toml"
evidence_commit = "0000000000000000000000000000000000000000"
failure_direction = "coverage: the arm the tree does not take is the stricter one"
covers = ["model:WorldIsFlat"]
discharges = ["WorldIsFlat"]
supports = ["SEC-T-001"]

[[assumption]]
id = "PLAT-CRYPTO-001"
class = "crypto-primitive"
statement = "A residual the page publishes and this registry accepts."
discharge = "A hardening with a stated price, deferred rather than taken."
discharge_owner = "contributor"
status = "accepted-risk"
out_of_scope_by = "docs/limitations.md#silicon--desk"
failure_direction = "security: a residual nobody wrote down anywhere a user reads"

[[assumption]]
id = "PLAT-FLASH-001"
class = "flash"
statement = "The tear model is the one the store assumes."
discharge = "A recorded PASS on a throwaway board."
discharge_owner = "maintainer"
status = "pending"
failure_direction = "security: a torn write could leave a credential live"
covers = ["board-only:29_reset_power_cut"]
supports = ["SEC-T-001"]

[[assumption]]
id = "PLAT-STORE-001"
class = "model-abstraction"
statement = "The tear guarantee holds one layer up, in the KV library."
discharge = "A recorded verdict for the durability target."
discharge_owner = "contributor"
status = "pending"
failure_direction = "security: a torn remove restoring an older committed value"
covers = ["backend:rsk-a/tear"]

[[assumption]]
id = "PLAT-TOOLCHAIN-001"
class = "toolchain"
statement = "Every unsafe upholds an invariant the compiler cannot check."
discharge = "A source audit per site, in crates/rsk-a/src/lib.rs and firmware/src/main.rs."
discharge_owner = "contributor"
status = "pending"
failure_direction = "security: the one class safe Rust does not rule out"
covers = [
  "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",
  "unsafe:firmware/src/main.rs#block:core-ptr-null-u8-read",
]
"""

#: The placeholder `Tree.__init__` swaps for the commit it just made. A literal
#: sha of the right SHAPE, so a fixture that forgot the swap reads
#: `unknown-commit` — the finding — rather than the missing-field one, which is a
#: different rule and would report this file's own mistake as that rule's case.
COMMIT_AT_INIT = "0" * 40

#: `git commit` with an identity and WITHOUT a signature. `commit.gpgsign = true`
#: is a plausible global and it costs 0.166 s a commit measured here — 173 cases
#: is 29 s of the suite spent signing throwaway fixtures, and what it signs is a
#: temp directory nobody will ever verify.
COMMIT_AS = (
    "-c", "user.name=t", "-c", "user.email=t@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "-q",
)

#: The `PLAT-STORE-001` block verbatim, so the deletion test removes ONE row and
#: reddens for one reason. A truncation would take PLAT-TOOLCHAIN-001 with it and
#: orphan two `unsafe:` candidates as well.
STORE_ROW = REGISTRY[
    REGISTRY.index('[[assumption]]\nid = "PLAT-STORE-001"'):
    REGISTRY.index('[[assumption]]\nid = "PLAT-TOOLCHAIN-001"')
]


#: The fixture record's expectation, in the arm shape every record in the
#: checkout writes. Split into its parts because the cases below both REWRITE the
#: expectation and NAME one of its arms, and a literal retyped at each of them
#: is the copy this suite's own subject keeps finding rotted.
#:
#: The PREAMBLE is its own name because the cases drive it on both sides of the
#: rule change: it used to be the half a per-arm quotation carried, and the shape
#: that refuted that rule is prose written AFTER the first label, which no
#: quotation of one arm carries. `PASS_CLAIM` comes from `arm_claim` rather than
#: being typed, so the fixture cannot state a value the gate would refuse — the
#: same reason the gate has one expression for it.
#: The record vocabulary, written out ONCE for this file. Every case that loops
#: over a record-field tuple loops over these and asserts the gate's tuple
#: against them, because parametrizing over the constant a case guards makes
#: NARROWING it collect one case fewer instead of failing — measured, and the
#: measurement is in [`ARMS_OWED`]. `test_the_record_vocabulary_is_ratcheted`
#: reads these too rather than retyping them, which is the twin this tree has a
#: commit of its own about.
PLAN_FIELDS = ("method", "boot_config", "expected")
RESULT_FIELDS = ("board", "stepping", "firmware_sha256", "first_boot_capture",
                 "actual", "arm_taken")

PREAMBLE = "Old-or-refused at every offset."
PASS_ARM = "PASS = no plausible wrong value at any offset tried."
FAIL_ARM = "FAIL = one record reading back as a value nobody wrote."
BOARD_EXPECTED = f"{PREAMBLE} {PASS_ARM} {FAIL_ARM}"
PASS_CLAIM = platform_gate.arm_claim("pass", BOARD_EXPECTED)
FAIL_CLAIM = platform_gate.arm_claim("fail", BOARD_EXPECTED)
#: The value the OLD rule accepted: the preamble and one arm. It is now the
#: sharpest `NOT_AN_ARM` case there is, because it is what an operator who read
#: the previous version of the page would write.
OLD_PASS_CLAIM = f"{PREAMBLE} {PASS_ARM}"

#: The one maintainer-owned hardware row of the fixture, and so the one that
#: owes a record. Written in the PLANNED shape: the plan half filled, the result
#: half empty, which is what a row nobody can discharge here must look like.
BOARD_RECORD = f"""\
assumption = "PLAT-FLASH-001"
method = "A supply cut at a controlled offset into a store write."
boot_config = "The default image, 4 MB."
expected = "{BOARD_EXPECTED}"
outcome = "planned"
board = ""
stepping = ""
firmware_sha256 = ""
first_boot_capture = ""
actual = ""
arm_taken = ""
"""

#: The same record after a run: every result field filled, and the registry row
#: is expected to have moved with it.
BOARD_PASS = BOARD_RECORD.replace(
    'outcome = "planned"', 'outcome = "pass"'
).replace('board = ""', 'board = "Waveshare RP2350 Zero"').replace(
    'stepping = ""', 'stepping = "RP2350 A4"'
).replace(
    'firmware_sha256 = ""', 'firmware_sha256 = "' + "0" * 63 + '1"'
).replace(
    'first_boot_capture = ""', 'first_boot_capture = "assurance/board/flash-cut.log"'
).replace('actual = ""', 'actual = "Old-or-refused at all 64 offsets."').replace(
    'arm_taken = ""', f'arm_taken = "{PASS_CLAIM}"'
)


class Tree:
    """A checkout shaped like this one, small enough to break one rule at a time."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.write("assurance/assumptions.toml", MODEL_REGISTRY)
        self.write("assurance/properties.toml", PROPERTIES)
        self.write("assurance/bundle/SEC-T-001.toml", BUNDLE)
        self.write("assurance/platform.toml", REGISTRY)
        self.write("assurance/crates.toml", CRATE_LEDGER)
        self.write("assurance/board/PLAT-FLASH-001.toml", BOARD_RECORD)
        # The SECOND maintainer-owned row, and its class is not a silicon class.
        # It is here because keying the obligation on `HARDWARE_CLASSES` was the
        # first version and left this exact shape unobliged — a `tool-fidelity`
        # row whose route reads "a board recording of the same session".
        self.write(
            "assurance/board/PLAT-TOOL-001.toml",
            BOARD_RECORD.replace("PLAT-FLASH-001", "PLAT-TOOL-001"),
        )
        self.write("docs/authorization-slice.md", DESIGN_PAGE)
        self.write("docs/limitations.md", LIMITATIONS_PAGE)
        # A generated page and the generator that claims it, plus the same
        # header over a page nothing writes — the two arms of the prose-page
        # exemption, which is derived from the pair and not from the header.
        self.write("scripts/matrix_gate.py", MATRIX_GATE)
        self.write("docs/assurance-matrix.md", GENERATED_PAGE)
        self.write("docs/self-exempt.md", GENERATED_PAGE)
        # And a generated page that NAMES a row — of a row that does not cite it,
        # so the carve-out's green arm is not "any generated page".
        self.write("scripts/vector_gate.py", VECTOR_GATE)
        self.write("docs/assurance-vector.md", VECTOR_PAGE)
        self.write("scripts/platform_gate.py", SELF_GATE)
        self.write("tests/emu.py", EMU_SHIM)
        self.write("scripts/usbip-guest.sh", USBIP_GUEST)
        self.write("crates/rsk-a/src/lib.rs", UNSAFE_RS)
        self.write("firmware/src/main.rs", UNSAFE_RS)
        # Tracked-but-safe Rust, so the `unsafe:` derivation is selecting rather
        # than returning everything it walks.
        self.write("crates/rsk-a/src/safe.rs", "pub const N: u8 = 1;\n")
        # Three spellings of the word OUTSIDE code, in one file. Four of the
        # twelve files the first derivation produced were exactly this.
        self.write("crates/rsk-a/src/prose.rs", PROSE_RS)
        self.write("docs/unsafe.md", UNSAFE_MD)
        self.git("init", "-q")
        # A real commit, because the freshness axis is pure committed history and
        # a fixture that only ever `git add`s has none: without one every settled
        # row reads `unknown-commit` and no case below can tell the axis working
        # from the axis blind. `assurance/board/` is held OUT of it for the
        # opposite reason — `check_expected_predates` walks a record's history for
        # a `planned` version, and committing the planned records here would hand
        # that rule the version it is looking for and switch it off.
        self.git("add", "-A", "--", ".", ":(exclude)assurance/board")
        self.git(*COMMIT_AS, "-m", "the fixture")
        self.edit("assurance/platform.toml", COMMIT_AT_INIT, self.head())
        self.git("add", "-A")
        self.regenerate()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def append(self, rel, text):
        (self.root / rel).write_text((self.root / rel).read_text() + text)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def head(self):
        done = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        )
        return done.stdout.strip()

    def commit(self, message="a state of the tree"):
        """A real commit, because `check_expected_predates` reads history and a
        fixture that only ever `git add`s has none to read."""
        self.git("add", "-A")
        self.git(*COMMIT_AS, "-m", message)

    def regenerate(self):
        self.write("docs/platform-assumptions.md", platform_gate.render(self.root))

    def problems(self, board_floor=2):
        """`board_floor` is a PARAMETER, the way this tree's other floors are:
        the fixture carries two maintainer-owned rows and the checkout thirteen,
        and a floor hard-coded to the checkout's number reddens every case."""
        return platform_gate.audit(self.root, board_floor)[0]


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def sites_by_key(tree, rel):
    """key -> the site's own source text, for one file of the fixture.

    What a site key has to be STABLE against is a permutation of the file, and a
    key SET cannot see that: the two strings are the same either way, and each
    naming the other body is exactly the defect. So the cases below compare what
    each key denotes.
    """
    raw = (tree.root / rel).read_text()
    code = gate_lines.rust_code(raw)
    return {
        key: raw[offset : offset + 60]
        for key, (offset, _kind, _words) in zip(
            platform_gate.site_keys(code, raw), platform_gate.unsafe_sites(code, raw)
        )
    }


def only(problems, needle):
    """The problems mentioning `needle`, and AT MOST ONE of them.

    A message is asserted, never a count — but "at least one" is not what this
    name says, and a rule widened to fire the same sentence on a second row was
    invisible to it. The exclusive reading, which is what the name most suggests
    — that the match is the WHOLE finding list — was measured and refused: it
    turns 61 of these 115 cases red, and reading them, every one is a break that
    legitimately trips more than one rule (a `pass` record under a `pending` row
    also has no capture in the tree). Exclusivity here would manufacture false
    reds; the noise beside an asserted message is what this still cannot see, and
    that is written down rather than left to be found again.
    """
    hit = [p for p in problems if needle in p]
    assert len(hit) <= 1, hit
    return hit


# --- both directions of green -------------------------------------------------


def test_the_fixture_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    findings, summary = platform_gate.audit(ROOT)
    assert findings == [], findings
    assert summary.startswith("platform-gate: ok")


def test_the_fixture_derives_all_five_candidate_kinds(tree):
    """A fixture missing a namespace would pass that namespace's rules vacuously."""
    found = platform_gate.candidates(tree.root)
    assert set(found) == {
        "slice:AS-T-1",
        "slice:AS-T-2",
        "model:WorldIsFlat",
        "board-only:29_reset_power_cut",
        "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",
        "unsafe:firmware/src/main.rs#block:core-ptr-null-u8-read",
        "backend:rsk-a/tear",
    }, sorted(found)


def test_the_backend_derivation_reads_the_list_and_not_the_gap_prose(tree):
    """`page reclaim` is in the fixture's `gap` sentence and not in `abstracts`.

    A regex over the prose was the obvious first reading of this source, and it
    would produce a candidate for every mechanic a sentence happens to name --
    turning "the ledger mentions it" into "the registry owes a row for it".
    Which mechanics are OBLIGATIONS is a decision, so it is a list.
    """
    found = platform_gate.candidates(tree.root)
    assert "backend:rsk-a/tear" in found
    assert not [k for k in found if "reclaim" in k], sorted(found)
    # And the key is per-crate: `rsk-b` declares no list, so it produces nothing.
    assert not [k for k in found if k.startswith("backend:rsk-b/")], sorted(found)


def test_the_checkout_derives_what_it_is_measured_at():
    """The four counts this row's own docstring in `check.sh` is written from.

    Not a transcription that drifts: each is an assertion about the SHAPE of the
    derivation. `board-only` is the one worth pinning by name — it is the pair of
    files that produced it, and either of them changing changes what this tree
    says it owes a board.
    """
    found = platform_gate.candidates(ROOT)
    kinds = {prefix: [k for k in found if k.startswith(f"{prefix}:")] for prefix in platform_gate.FLOORS}
    assert set(kinds["board-only"]) == {
        "board-only:29_reset_power_cut",
        "board-only:51_secure_reboot",
        "board-only:53_ccid_pinpad",
        "board-only:54_sram_residue",
        "board-only:90_otp_mkek_migration",
    }, kinds["board-only"]
    assert set(kinds["model"]) == {
        "model:PowerOnClearsScratch2",
        "model:AlwaysUvShipped",
        "model:WidePerms",
        "model:ForceChangeModelled",
        "model:RekeyOrderModelled",
    }, kinds["model"]
    assert len(kinds["slice"]) >= 8, kinds["slice"]
    # SITES, not files. The seven first-party `.rs` that carry the token bounded
    # the old derivation at 7 whatever the tree did; 24 of these are what
    # `docs/unsafe.md` numbers, and the rest are build-script and declaration
    # sites that page keeps apart. Asserted as a floor above what a file-keyed
    # derivation could ever reach, and as a shape: every key names its site.
    assert len(kinds["unsafe"]) >= 22, kinds["unsafe"]
    assert all("#" in k for k in kinds["unsafe"]), kinds["unsafe"]
    steals = [k for k in kinds["unsafe"] if "anypin-steal" in k]
    assert len(steals) == 9, steals


# --- rule 1: every derived candidate is claimed --------------------------------


def test_an_unclaimed_bundle_assumption_is_a_finding(tree):
    tree.append(
        "assurance/bundle/SEC-T-001.toml",
        '\n[[assumption]]\nid = "AS-T-9"\nstatement = "A ninth."\nregistered = "no"\n',
    )
    assert only(tree.problems(), "slice:AS-T-9: derived from")


def test_an_unclaimed_design_page_assumption_is_a_finding(tree):
    """The other spelling: prose, written before the slice has a bundle."""
    tree.append("docs/authorization-slice.md", "\n| `AS-T-3` | A third |\n")
    assert only(tree.problems(), "slice:AS-T-3: derived from")


def test_an_unclaimed_model_constant_is_a_finding(tree):
    tree.append(
        "assurance/assumptions.toml",
        '\n[[assumption]]\nconstant = "SkyIsGreen"\nstatement = "s"\n'
        'discharged_by = "d"\nrisk = "coverage"\n',
    )
    assert only(tree.problems(), "model:SkyIsGreen: derived from")


def test_an_unclaimed_board_only_suite_is_a_finding(tree):
    tree.edit(
        "tests/emu.py",
        '"73_otp_keyboard"',
        '"54_sram_residue": "measures SRAM residue on a real chip",\n    "73_otp_keyboard"',
    )
    assert only(tree.problems(), "board-only:54_sram_residue: derived from")


def test_an_unclaimed_unsafe_site_is_a_finding(tree):
    tree.write("crates/rsk-b/src/lib.rs", UNSAFE_RS)
    tree.git("add", "-A")
    assert only(
        tree.problems(),
        "unsafe:crates/rsk-b/src/lib.rs#block:core-ptr-null-u8-read: derived from",
    )


def test_a_deleted_store_row_leaves_its_backend_semantic_unclaimed(tree):
    """The anchor. Before `abstracts` the four `PLAT-STORE-*` rows covered nothing,
    so deleting one -- or all of them -- was exit 0 on every rule."""
    tree.edit("assurance/platform.toml", STORE_ROW, "")
    tree.regenerate()
    assert only(tree.problems(), "backend:rsk-a/tear: derived from")


def test_a_usbip_glob_covers_its_suite(tree):
    """`tests/02_*.py` is a glob and `tests/73_otp_keyboard.py` is a full name.

    Both are how the guest actually writes them, and a rule that read only one
    would report an obligation for a suite a runner already passes.
    """
    found = platform_gate.candidates(tree.root)
    assert "board-only:02_usb_interfaces" not in found
    assert "board-only:73_otp_keyboard" not in found


# --- rule 2: and the other way -------------------------------------------------


def test_a_covers_no_derivation_produces_is_a_finding(tree):
    tree.edit("assurance/platform.toml", '"slice:AS-T-1"', '"slice:AS-T-404"')
    assert only(tree.problems(), "covers 'slice:AS-T-404', which no derivation produces")


def test_a_candidate_claimed_twice_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'covers = ["board-only:29_reset_power_cut"]',
        'covers = ["board-only:29_reset_power_cut", "slice:AS-T-1"]',
    )
    assert only(tree.problems(), "slice:AS-T-1 is claimed by both")


# --- rule 3: a discharge route and an owner ------------------------------------


def test_a_missing_hand_field_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'failure_direction = "coverage: a cardinality nothing runs"\n', "")
    assert only(tree.problems(), "PLAT-MODEL-001: is missing ['failure_direction']")


def test_a_field_outside_the_schema_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\nconfidence = "high"\n')
    assert only(tree.problems(), "`confidence` is not a field of this registry")


def test_a_top_level_table_beside_the_entries_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\n[summary]\ndischarged = 18\n')
    assert only(tree.problems(), "top-level `summary`")


def test_a_class_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'class = "flash"', 'class = "vibes"')
    assert only(tree.problems(), "class 'vibes' is not one of")


def test_a_status_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'status = "discharged"', 'status = "probably-fine"')
    assert only(tree.problems(), "status 'probably-fine' is not one of")


def test_an_owner_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharge_owner = "maintainer"\nstatus = "pending"\nfailure_direction = "security: every', 'discharge_owner = "someone"\nstatus = "pending"\nfailure_direction = "security: every')
    assert only(tree.problems(), "an obligation nobody owns is a wish")


def test_an_empty_discharge_route_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharge = "The store slice."', 'discharge = "   "')
    assert only(tree.problems(), "no discharge route")


def test_a_bad_entry_id_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'id = "PLAT-FLASH-001"', 'id = "flash-tear"')
    assert only(tree.problems(), "entry id 'flash-tear' is not `PLAT-AREA-NNN`")


def test_a_duplicate_entry_id_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'id = "PLAT-MODEL-001"', 'id = "PLAT-TOOL-001"')
    assert only(tree.problems(), "PLAT-TOOL-001: a second entry under the same id")


# --- rule 4: a claim of discharge owes evidence --------------------------------


def test_a_discharge_with_no_evidence_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'evidence = ["assurance/properties.toml"]\n', "")
    assert only(tree.problems(), "with no `evidence`")


def test_a_discharge_naming_evidence_that_is_not_there_is_a_finding(tree):
    tree.edit("assurance/platform.toml", '"assurance/properties.toml"]', '"assurance/gone.toml"]')
    assert only(tree.problems(), "evidence 'assurance/gone.toml' is not in the tree")


def test_a_discharge_citing_a_hand_written_page_is_a_finding(tree):
    """The hole this rule closes, in the spelling it was measured in: on the real
    checkout `evidence = ["README.md"]` on a `model-abstraction` discharge was
    exit 0, and only the board axis refused that shape."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/authorization-slice.md"]',
    )
    assert only(tree.problems(), "'docs/authorization-slice.md' is a hand-written page")


def test_a_hand_written_page_beside_real_artifacts_is_a_finding(tree):
    """EVERY path, not one of them. `at least one artifact` leaves the obvious
    move open — append a page to a row that already cites a real file."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.toml", "docs/authorization-slice.md"]',
    )
    assert only(tree.problems(), "'docs/authorization-slice.md' is a hand-written page")


def test_a_generated_page_is_evidence(tree):
    """The false red a blanket `no .md` would have cost: `docs/assurance-matrix.md`
    is `PLAT-BUILD-001`'s second artifact on the real checkout, and a script
    writes it from data."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/assurance-matrix.md"]',
    )
    assert tree.problems() == []


def test_a_page_that_only_says_it_is_generated_is_not_evidence(tree):
    """The exemption is the generator's `ARTIFACT`/`GENERATED_BY` pair, never the
    phrase in the page. This page carries a real generator's header verbatim and
    that generator writes another file."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/self-exempt.md"]',
    )
    assert only(tree.problems(), "'docs/self-exempt.md' is a hand-written page")


def test_the_prose_rule_does_not_check_relevance(tree):
    """The limit, asserted so that widening it is a diff rather than a surprise.
    A shape rule refuses a KIND of file and cannot refuse an unrelated one:
    `deny.toml` on a `model-abstraction` discharge is exit 0 on the real checkout
    too, measured. What stops that is a reviewer reading the row."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["scripts/usbip-guest.sh"]',
    )
    assert tree.problems() == []


def test_the_page_this_gate_writes_is_not_evidence_for_its_own_row(tree):
    """The carve-out let straight back in the one page that cannot settle
    anything here. Measured on the real checkout before this clause:
    `PLAT-STORE-003` `discharged` with `evidence = ["docs/platform-assumptions.md"]`
    was exit 0, and `render` emits that row's own `discharge` into that page."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/platform-assumptions.md"]',
    )
    assert only(tree.problems(), "'docs/platform-assumptions.md' carries this row")


def test_this_registry_is_not_evidence_for_its_own_row(tree):
    """The same loop with no page in it at all: the row's own home is not a
    `.md`, so every prose rule walked past it — exit 0 on the real checkout."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/platform.toml"]',
    )
    assert only(tree.problems(), "'assurance/platform.toml' carries this row")


def test_a_generated_page_that_names_the_row_is_not_evidence(tree):
    """Not `ARTIFACT` alone, which was the narrower reading considered: a page
    another generator renders from this registry is the same loop one hop out.
    `docs/assurance-vector.md` is that page on the real checkout and names 67 of
    the 72 rows; citing it from one of them was exit 0."""
    tree.edit("docs/assurance-vector.md", "PLAT-FLASH-001", "PLAT-BUILD-001")
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/assurance-vector.md"]',
    )
    assert only(tree.problems(), "'docs/assurance-vector.md' carries this row")


def test_a_generated_page_that_names_another_row_is_evidence(tree):
    """The per-row half, and the direction that keeps the clause from being
    `no generated page`: the fixture's vector page names `PLAT-FLASH-001`, and
    `PLAT-BUILD-001` citing it is not citing a restatement of itself."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/assurance-vector.md"]',
    )
    assert tree.problems() == []


def test_a_directory_is_not_evidence(tree):
    """`.exists()` answered a question this rule never asked: `evidence = ["docs"]`
    was exit 0 on the real checkout, which is this module's own `met by
    README.md` sentence with the directory README.md sits in substituted."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs"]',
    )
    assert only(tree.problems(), "evidence 'docs' is not in the tree")


def test_a_miscased_evidence_path_is_not_in_the_tree(tree):
    """The spelling the whole rule exists to refuse, and it passed locally:
    `evidence = ["README.MD"]` was exit 0 on the real checkout, because APFS
    folds case and the `.md` test did not — while a case-sensitive runner would
    have gone red as `is not in the tree`, the right colour for the wrong
    reason. git's listing is case-exact, so this case asserts one message on
    both filesystems."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.TOML"]',
    )
    assert only(tree.problems(), "'assurance/properties.TOML' is not in the tree")


def test_an_upper_case_page_is_still_a_page(tree):
    """The other half of that fold, held apart from it: a page git really lists
    under `.MD` is in the tree, so only the case-folded suffix refuses it. Both
    clauses had to go for `README.MD` to come back, measured — either alone
    still reddens it, which is why they have a case each."""
    tree.write("docs/upper-case.MD", "# A page\n\nProse, nothing more.\n")
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/upper-case.MD"]',
    )
    assert only(tree.problems(), "'docs/upper-case.MD' is a hand-written page")


def test_a_page_its_generator_claims_but_does_not_mark_is_not_evidence(tree):
    """`claims_gate` asks its mapping two questions and this gate asked one: the
    KEY says which page a generator CLAIMS, the header says the page agrees.
    Reading the key alone made this strictly weaker over the same data —
    `docs/assurance-matrix.md` with its header line deleted was exit 0."""
    tree.edit(
        "docs/assurance-matrix.md",
        "<!-- Generated by scripts/matrix_gate.py --write — do not edit by hand -->\n",
        "",
    )
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["docs/assurance-matrix.md"]',
    )
    assert only(tree.problems(), "'docs/assurance-matrix.md' is a hand-written page")


def test_a_discharge_with_no_revalidation_trigger_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'revalidated_by = "any change to the manifest, or to assurance/crates.toml"\n',
        "",
    )
    assert only(tree.problems(), "with no `revalidated_by`")


def test_a_hardware_discharge_with_no_board_revision_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'discharge_owner = "maintainer"\nstatus = "pending"\nfailure_direction = "security: a torn',
        'discharge_owner = "maintainer"\nstatus = "discharged"\n'
        'evidence = ["assurance/properties.toml"]\nrevalidated_by = "a new stepping"\n'
        'failure_direction = "security: a torn',
    )
    assert only(tree.problems(), "discharge records no `board_revision`")


def test_a_bare_stepping_is_not_a_board_revision(tree):
    """`A2` alone is what a Kani harness's own claims are named, not silicon."""
    tree.edit(
        "assurance/platform.toml",
        'discharge_owner = "maintainer"\nstatus = "pending"\nfailure_direction = "security: a torn',
        'discharge_owner = "maintainer"\nstatus = "discharged"\n'
        'evidence = ["assurance/properties.toml"]\nboard_revision = "A2"\n'
        'revalidated_by = "a new stepping"\nfailure_direction = "security: a torn',
    )
    assert only(tree.problems(), "board_revision 'A2' names no RP2350 stepping")


def test_a_pending_entry_carrying_evidence_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'failure_direction = "coverage: a cardinality nothing runs"',
        'evidence = ["assurance/properties.toml"]\n'
        'failure_direction = "coverage: a cardinality nothing runs"',
    )
    assert only(tree.problems(), "an artifact nothing rests on is decoration")


# --- rule 5: links resolve -----------------------------------------------------


def test_supports_naming_no_property_is_a_finding(tree):
    """A property depending on an assumption that does not exist, from the side
    that can be checked: the registry's id vocabulary is the one that is real."""
    tree.edit("assurance/platform.toml", 'supports = ["SEC-T-001"]\n\n[[assumption]]\nid = "PLAT-MODEL-001"', 'supports = ["SEC-T-404"]\n\n[[assumption]]\nid = "PLAT-MODEL-001"')
    assert only(tree.problems(), "supports 'SEC-T-404' is not a property")


def test_depends_on_naming_no_entry_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\ndepends_on = ["PLAT-GONE-001"]\n')
    assert only(tree.problems(), "depends_on 'PLAT-GONE-001' is not an entry")


def test_refines_naming_itself_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\nrefines = ["PLAT-TOOLCHAIN-001"]\n')
    assert only(tree.problems(), "PLAT-TOOLCHAIN-001: refines names itself")


def test_discharges_naming_no_constant_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharges = ["WorldIsFlat"]', 'discharges = ["SkyIsGreen"]')
    assert only(tree.problems(), "discharges 'SkyIsGreen' is not a constant")


def test_covering_a_model_constant_without_discharging_it_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharges = ["WorldIsFlat"]\n', "")
    assert only(tree.problems(), "covers model:WorldIsFlat but does not discharge it")


def test_discharging_a_constant_without_covering_it_is_a_finding(tree):
    """The half that keeps the two registries from holding two answers.

    Without it a second entry could claim the discharge of a constant a first
    entry covers, and each would look complete on its own.
    """
    tree.edit("assurance/platform.toml", 'covers = ["model:WorldIsFlat"]\n', "")
    assert only(tree.problems(), "without covering `model:WorldIsFlat`")


# --- rule 6: the page, and a status that moves silently ------------------------


def test_a_status_that_moves_without_the_page_is_a_finding(tree):
    """The whole content of "not silently": the flip is cheap, the diff is what
    this buys — and the byte-diff is what makes the diff compulsory."""
    tree.edit("assurance/platform.toml", 'status = "discharged"', 'status = "accepted-risk"')
    problems = tree.problems()
    assert only(problems, "docs/platform-assumptions.md is not what the generator writes")


def test_a_hand_edit_of_the_page_is_a_finding(tree):
    tree.edit("docs/platform-assumptions.md", "Discharged: 1 of 7.", "Discharged: 5 of 7.")
    assert only(tree.problems(), "docs/platform-assumptions.md is not what the generator writes")


def test_the_page_carries_every_entry_and_its_status(tree):
    page = (tree.root / "docs/platform-assumptions.md").read_text()
    for name in ("PLAT-TOOL-001", "PLAT-MODEL-001", "PLAT-BUILD-001", "PLAT-FLASH-001"):
        assert f"`{name}`" in page, name
    assert "Discharged: 1 of 7." in page


# --- rule 7: the bundle's own `registered` field -------------------------------


def test_a_bundle_saying_no_over_a_registered_assumption_is_a_finding(tree):
    """It said `no` on eight of ten rows the day this registry did not exist."""
    tree.edit("assurance/bundle/SEC-T-001.toml", 'registered = "yes — PLAT-TOOL-001"', 'registered = "no"')
    assert only(tree.problems(), "assurance/platform.toml does claim it")


def test_a_bundle_saying_yes_over_an_unregistered_assumption_is_a_finding(tree):
    """The claim is checked in both directions, so neither word is free."""
    tree.edit("assurance/platform.toml", 'covers = ["slice:AS-T-1"]', "covers = []")
    problems = tree.problems()
    assert only(problems, "assurance/platform.toml does not claim it")
    assert only(problems, "slice:AS-T-1: derived from")


def test_a_bundle_assumption_with_no_registered_field_is_a_finding(tree):
    tree.edit("assurance/bundle/SEC-T-001.toml", 'registered = "yes — PLAT-TOOL-001"\n', "")
    assert only(tree.problems(), "carries no `registered`")


# --- rule 8: a reader that stopped reading -------------------------------------


def test_the_board_only_derivation_is_floored(tree):
    """A source that is there and read as empty looks exactly like nothing to do."""
    tree.edit("tests/emu.py", "UNSUPPORTED = {", "UNSUPPORTED_SUITES = {")
    assert only(tree.problems(), "the `board-only:` derivation found 0 candidate(s)")


def test_the_slice_derivation_is_floored(tree):
    tree.write("assurance/bundle/SEC-T-001.toml", '[property]\nid = "SEC-T-001"\n')
    tree.write("docs/authorization-slice.md", "# The slice\n")
    assert only(tree.problems(), "the `slice:` derivation found 0 candidate(s)")


def test_the_unsafe_derivation_is_floored(tree):
    tree.write("crates/rsk-a/src/lib.rs", "pub const N: u8 = 1;\n")
    tree.write("firmware/src/main.rs", "pub const N: u8 = 1;\n")
    assert only(tree.problems(), "the `unsafe:` derivation found 0 candidate(s)")


def test_the_model_derivation_is_floored(tree):
    """The fourth floor. The review drove `model: 0` past a table that had the
    other three and asserted only the KEY set, so zeroing one was free."""
    tree.write("assurance/assumptions.toml", "# no constants\n")
    assert only(tree.problems(), "the `model:` derivation found 0 candidate(s)")


def test_the_backend_derivation_is_floored(tree):
    """The fifth floor, and the one that answers deleting the ANCHOR rather than
    the row: emptying `abstracts` would otherwise retire four obligations by
    editing one line in a file the registry's own rules never open."""
    tree.edit("assurance/crates.toml", 'abstracts = ["tear"]', "")
    assert only(tree.problems(), "the `backend:` derivation found 0 candidate(s)")


def test_the_floors_are_apart_not_in_total(tree):
    """One number over the union cannot say WHICH reader stopped — and a floor of
    0 is a floor nothing can fall below, which the key set alone does not see."""
    assert platform_gate.FLOORS == {
        "slice": 1, "model": 1, "board-only": 1, "unsafe": 1, "backend": 1,
    }


# --- the row that runs it ------------------------------------------------------


def test_check_sh_runs_this_gate():
    """Its own row, including that a `#` in front of it is not an invocation."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/platform_gate.py")


def test_the_entry_point_exits_nonzero_on_a_finding(tmp_path):
    """Through `main()`, not `audit()`: the row runs the script, and a guard that
    finds a problem and returns 0 is one `check.sh` steps straight over."""
    tree = Tree(tmp_path)
    tree.edit("assurance/platform.toml", '"slice:AS-T-1"', '"slice:AS-T-404"')
    assert platform_gate.run(tree.root, board_floor=2) == 1
    assert platform_gate.run(Tree(tmp_path / "clean").root, board_floor=2) == 0


# --- the spellings the review drove past the first version ---------------------


def test_the_word_in_a_comment_or_a_string_is_not_an_unsafe_site(tree):
    """Four of the twelve files the first derivation produced carried the word
    only in a line saying the file has no `unsafe`; a fifth emitted it inside a
    string. Stripping first is what makes the form list unnecessary."""
    found = platform_gate.candidates(tree.root)
    assert not [k for k in found if "prose.rs" in k], sorted(found)
    assert "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read" in found


def test_every_syntactic_form_of_unsafe_still_counts(tree):
    """And the other direction: stripping must not take the code with it."""
    for body, want in (
        ("pub fn f() { unsafe { g() } }", "block:g"),
        ("pub unsafe fn f() {}", "fn:f"),
        ("unsafe impl Send for T {}", "impl:send-for-t"),
        ('unsafe extern "C" { fn g(); }', "extern:fn-g"),
        ('#[unsafe(link_section = ".data")]\npub static X: u8 = 0;',
         "attr:link_section-data-pub-static-x-u8"),
    ):
        tree.write("crates/rsk-c/src/lib.rs", body + "\n")
        tree.git("add", "-A")
        found = platform_gate.candidates(tree.root)
        assert f"unsafe:crates/rsk-c/src/lib.rs#{want}" in found, (body, sorted(found))


def test_a_comment_in_the_usbip_guest_neither_covers_nor_uncovers(tree):
    """Both directions, and both were red on the first version: a comment naming
    a board-only suite made its obligation vanish, and a comment naming a
    registered one turned a live row into "no derivation produces it"."""
    tree.append("scripts/usbip-guest.sh", "\n# tests/29_reset_power_cut.py is board-only\n")
    assert tree.problems() == []
    tree.edit(
        "tests/emu.py",
        '"73_otp_keyboard"',
        '"91_glitch_detector": "needs a real glitch detector",\n    "73_otp_keyboard"',
    )
    tree.append("scripts/usbip-guest.sh", "\n# tests/91_glitch_detector.py is board-only too\n")
    assert only(tree.problems(), "board-only:91_glitch_detector: derived from")


def test_four_legal_spellings_of_an_unsupported_entry(tree):
    """Single quotes, an implicit concatenation, an f-string and an empty reason.
    Each parses, this tree has no Python formatter to rule any of them out, and
    each was invisible to the regex the first version read the shim with."""
    for spelling in (
        "'91_glitch_detector': 'needs a real glitch detector',",
        '"91_glitch_detector": (\n        "needs a real glitch"\n        " detector"\n    ),',
        '"91_glitch_detector": f"needs a real glitch detector",',
        '"91_glitch_detector": "",',
    ):
        tree.write("tests/emu.py", EMU_SHIM.replace(
            '    "73_otp_keyboard"', f"    {spelling}\n    \"73_otp_keyboard\""))
        assert only(tree.problems(), "board-only:91_glitch_detector: derived from"), spelling


def test_a_new_top_level_crate_is_not_invisible(tree):
    """`rsk-wipe/`'s own shape. A whitelist of roots missed it silently."""
    tree.write("rsk-probe/src/main.rs", UNSAFE_RS)
    tree.git("add", "-A")
    assert only(
        tree.problems(),
        "unsafe:rsk-probe/src/main.rs#block:core-ptr-null-u8-read: derived from",
    )


def test_a_vendored_fork_is_still_out(tree):
    """The one exclusion, and it is a decision rather than a name pattern."""
    tree.write("third_party/x/src/lib.rs", UNSAFE_RS)
    tree.git("add", "-A")
    assert tree.problems() == []


def test_a_design_page_the_list_never_named(tree):
    """A two-page hardcode; the review put `AS-STORE-1` on a third page."""
    tree.write("docs/store-slice.md", "| `AS-STORE-1` | A torn write is detectable |\n")
    assert only(tree.problems(), "slice:AS-STORE-1: derived from")


def test_a_bundle_in_a_subdirectory(tree):
    """`glob` and not `rglob` was the first version."""
    tree.write(
        "assurance/bundle/store/SEC-T-002.toml",
        '[property]\nid = "SEC-T-002"\n\n[[assumption]]\nid = "AS-T-7"\n'
        'statement = "s"\nregistered = "no"\n',
    )
    assert only(tree.problems(), "slice:AS-T-7: derived from")


# --- the board-result rules the hardware axis rests on -------------------------


def test_a_board_revision_that_names_no_stepping_is_a_finding(tree):
    """On ANY class. Gating this on the silicon classes was the first version,
    and the review put "a red Pico 2 I had lying around" in a `tool-fidelity`
    row, where nothing looked at it."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.toml"]\nboard_revision = "a red Pico 2"',
    )
    assert only(tree.problems(), "names no RP2350 stepping")


def test_a_desk_with_the_part_named_inside_it_is_not_a_board_revision(tree):
    """`search` over an otherwise free field: the desk description the arm above
    refuses keeps the finding by being ABOUT a part, and loses it the moment it
    names one. Driven at the sibling axis, where it published `1 of 3`."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.toml"]\n'
        'board_revision = "a red Pico 2 (an RP2350 A2) I had lying around"',
    )
    assert only(tree.problems(), "names no RP2350 stepping")


def test_a_part_without_a_stepping_is_not_a_board_revision(tree):
    """The other half of the token, and the half the first table left open:
    `A2` alone was driven and `RP2350` alone was not, so loosening the pattern to
    the part number survived. `evidence_gate.py` reads this same object."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.toml"]\nboard_revision = "RP2350"',
    )
    assert only(tree.problems(), "board_revision 'RP2350' names no RP2350 stepping")


def test_a_board_result_owes_a_capture_not_just_a_file_that_exists(tree):
    """`README.md` satisfied "the evidence is in the tree" and flipped the public
    page's headline sentence. A capture lives under `assurance/board/`."""
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.toml"]\nboard_revision = "RP2350 A2"',
    )
    problems = tree.problems()
    assert only(problems, "cites no artifact under assurance/board/")
    tree.write("assurance/board/run.log", "a capture\n")
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/board/run.log"]',
    )
    tree.regenerate()
    assert tree.problems() == []


# --- the raw record a hardware measurement leaves behind (stage 2 п.9) --------
#
# The registry already obliged a stepping and an artifact PATH; what it could not
# say was what has to be IN the artifact, so a discharge could cite any file that
# exists. These cases hold the field split in both directions: the plan half must
# be written before the board is powered, and the result half must not.


def test_a_maintainer_hardware_row_without_a_record_is_a_finding(tree):
    (tree.root / "assurance/board/PLAT-FLASH-001.toml").unlink()
    assert only(tree.problems(), "with no assurance/board/PLAT-FLASH-001.toml")


def test_a_record_filed_under_another_name_is_a_finding(tree):
    (tree.root / "assurance/board/PLAT-FLASH-001.toml").rename(
        tree.root / "assurance/board/PLAT-OTHER-001.toml"
    )
    problems = tree.problems()
    assert only(problems, "names assumption 'PLAT-FLASH-001'")
    # And the row it was owed to is still owed one: a misfiled record is not a
    # record, which is the half a name check alone would leave open.
    assert only(problems, "with no assurance/board/PLAT-FLASH-001.toml")


def test_a_record_for_no_registry_row_is_a_finding(tree):
    tree.write(
        "assurance/board/PLAT-GHOST-001.toml",
        BOARD_RECORD.replace("PLAT-FLASH-001", "PLAT-GHOST-001"),
    )
    assert only(tree.problems(), "PLAT-GHOST-001 is not an entry of")


def test_a_missing_plan_field_is_a_finding(tree):
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              f'expected = "{BOARD_EXPECTED}"',
              'expected = ""')
    assert only(tree.problems(), "no `expected`")


def test_a_field_outside_the_record_schema_is_a_finding(tree):
    tree.append("assurance/board/PLAT-FLASH-001.toml", 'verdict = "looked fine"\n')
    assert only(tree.problems(), "`verdict` is not a field of a board record")


def test_an_outcome_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              'outcome = "planned"', 'outcome = "looked ok"')
    assert only(tree.problems(), "outcome 'looked ok' is not one of")


def test_a_result_field_on_a_planned_run_is_a_finding(tree):
    """The direction that matters: an expected value can be written before the
    board is powered and a measured one cannot, so a filled `actual` under
    `planned` is a number nothing took."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              'actual = ""', 'actual = "old-or-refused, I am sure"')
    assert only(tree.problems(), "outcome 'planned' with `actual` filled")


def test_a_pass_with_an_empty_result_field_is_a_finding(tree):
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace('first_boot_capture = "assurance/board/flash-cut.log"',
                                  'first_boot_capture = ""'))
    tree.edit("assurance/platform.toml",
              '''id = "PLAT-FLASH-001"
class = "flash"
statement = "The tear model is the one the store assumes."
discharge = "A recorded PASS on a throwaway board."
discharge_owner = "maintainer"
status = "pending"''',
              '''id = "PLAT-FLASH-001"
class = "flash"
statement = "The tear model is the one the store assumes."
discharge = "A recorded PASS on a throwaway board."
discharge_owner = "maintainer"
status = "discharged"
evidence = ["assurance/board/PLAT-FLASH-001.toml"]
revalidated_by = "a new board revision"
board_revision = "RP2350 A4"''')
    tree.regenerate()
    assert only(tree.problems(), "outcome 'pass' with no `first_boot_capture`")


def test_a_pass_whose_firmware_hash_is_not_a_hash_is_a_finding(tree):
    """PLAT-MEM-001 is the row that lost exactly this field: a 2026-08-05 run
    whose result is in prose and whose image nobody can name."""
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace("0" * 63 + "1", "the release build, I think"))
    problems = tree.problems()
    assert only(problems, "firmware_sha256 is not a sha256")


def test_a_pass_under_a_pending_row_is_a_finding(tree):
    """The reverse direction, and the one the registry alone cannot see: a run
    that was taken and a status that never moved reads like no run at all."""
    tree.write("assurance/board/PLAT-FLASH-001.toml", BOARD_PASS)
    assert only(tree.problems(), "outcome 'pass' under a 'pending' row")


def test_a_planned_record_under_a_discharged_row_is_a_finding(tree):
    tree.edit("assurance/platform.toml",
              '''discharge = "A recorded PASS on a throwaway board."
discharge_owner = "maintainer"
status = "pending"''',
              '''discharge = "A recorded PASS on a throwaway board."
discharge_owner = "maintainer"
status = "discharged"
evidence = ["assurance/board/PLAT-FLASH-001.toml"]
revalidated_by = "a new board revision"
board_revision = "RP2350 A4"''')
    tree.regenerate()
    assert only(tree.problems(), "outcome 'planned' under a 'discharged' row")


def test_a_pass_whose_stepping_is_prose_is_a_finding(tree):
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace('stepping = "RP2350 A4"',
                                  'stepping = "a red Pico 2 I had lying around"'))
    assert only(tree.problems(), "names no RP2350 stepping")


# --- what the first review of THIS rule found ---------------------------------
#
# Eight of its rules could be deleted or narrowed with the suite still green, and
# two of the five "plan" fields could never be reported at all. The cases below
# are one per surviving mutation, driven; the rules they hold were rewritten in
# the same diff. The review's own list is the docstring of each.


@pytest.mark.parametrize("field", PLAN_FIELDS)
def test_every_plan_field_is_pinned(tree, field):
    """M15: the loop was pinned by ONE case on `expected`, so narrowing it to
    `("expected",)` left `method` and `boot_config` unheld.

    Over the LITERAL and not over the gate's tuple, for the reason
    [`ARMS_OWED`] records: parametrizing over the constant a case guards makes
    narrowing it collect one case fewer instead of failing. Three cases in this
    file were that shape, and the equality below is what turns each of them from
    a case that vanishes into a case that reds.
    """
    assert platform_gate.BOARD_PLAN_FIELDS == PLAN_FIELDS
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              f'{field} = "', f'{field} = ""\nunused_{field} = "')
    assert only(tree.problems(), f"no `{field}`")


@pytest.mark.parametrize("field", RESULT_FIELDS)
def test_every_result_field_is_refused_on_a_planned_run(tree, field):
    """M4: pinned by ONE case on `actual`, so four of the five could be filled
    before the run with the suite green."""
    assert platform_gate.BOARD_RESULT_FIELDS == RESULT_FIELDS
    tree.edit("assurance/board/PLAT-FLASH-001.toml", f'{field} = ""',
              f'{field} = "written before anything ran"')
    assert only(tree.problems(), f"outcome 'planned' with `{field}` filled")


@pytest.mark.parametrize("field", RESULT_FIELDS)
def test_every_result_field_is_required_on_a_run_that_happened(tree, field):
    """M5: pinned by ONE case on `first_boot_capture`."""
    assert platform_gate.BOARD_RESULT_FIELDS == RESULT_FIELDS
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace(f'{field} = "', f'{field} = ""\nunused_{field} = "'))
    assert only(tree.problems(), f"outcome 'pass' with no `{field}`")


def test_a_fail_may_not_sit_under_a_pending_row(tree):
    """M2: `OUTCOME_STATUS`'s second entry had no case at all, so deleting
    `"fail": "refuted"` left a recorded FAILURE under a `pending` row green."""
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace('outcome = "pass"', 'outcome = "fail"'))
    assert only(tree.problems(), "outcome 'fail' under a 'pending' row")


def test_an_inconclusive_run_still_owes_its_result_fields(tree):
    """The third outcome, which no case exercised either: a run that happened
    and settled nothing still happened ON something."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              'outcome = "planned"', 'outcome = "inconclusive"')
    problems = tree.problems()
    assert only(problems, "outcome 'inconclusive' with no `board`")
    assert only(problems, "outcome 'inconclusive' with no `firmware_sha256`")


def test_a_hash_inside_a_sentence_is_not_a_hash(tree):
    """M16: `fullmatch` -> `search` was the loosening this repo already measured
    once on `BOARD_REVISION`, and no case held it here."""
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace("0" * 63 + "1",
                                  "the release build " + "0" * 63 + "1 I think"))
    assert only(tree.problems(), "firmware_sha256 is not a sha256")


def test_a_stepping_smuggled_into_another_field_is_a_finding(tree):
    """The review put a whole board result through `boot_config` and `note` while
    every rule about result fields read `""`. A stepping lives in one field."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              'boot_config = "The default image, 4 MB."',
              'boot_config = "The default image, 4 MB, on the RP2350 A2 board."')
    assert only(tree.problems(), "`boot_config` names a stepping")


def test_a_note_is_read_like_every_other_field(tree):
    """`note` had no rule at all: "Ran it, RP2350 A2, PASSED" on a planned record
    was exit 0."""
    tree.append("assurance/board/PLAT-FLASH-001.toml",
                'note = "Ran it on the RP2350 A4, passed at every offset."\n')
    assert only(tree.problems(), "`note` names a stepping")


@pytest.mark.parametrize("value", ("42", "[]", "false", '["", ""]'))
def test_a_plan_field_that_is_not_text_is_a_finding(tree, value):
    """`str(record.get(key, ""))` made `str([])` == "[]" a filled field. Four
    types measured green before the rule read the type."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              f'expected = "{BOARD_EXPECTED}"',
              f"expected = {value}")
    assert only(tree.problems(), "`expected` is")


def test_a_capture_that_is_not_in_the_tree_is_a_finding(tree):
    """A complete false discharge passed: `first_boot_capture` was any non-empty
    string and no path was resolved."""
    tree.write("assurance/board/PLAT-FLASH-001.toml", BOARD_PASS)
    assert only(tree.problems(), "is not a file in the tree beside this record")


def test_a_record_may_not_be_its_own_capture(tree):
    """`check_evidence`'s `assurance/board/` rule is satisfied by the record
    itself, so without this the artifact requirement is circular."""
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace('first_boot_capture = "assurance/board/flash-cut.log"',
                                  'first_boot_capture = "assurance/board/PLAT-FLASH-001.toml"'))
    assert only(tree.problems(), "is not a file in the tree beside this record")


def test_an_expected_written_in_the_same_commit_as_the_result_is_a_finding(tree):
    """The whole plan/result split is a convention until history says otherwise:
    one commit can create the record with `expected` and `actual` together,
    `expected` written to match what the board did."""
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.write("assurance/board/PLAT-FLASH-001.toml", BOARD_PASS)
    tree.commit("a result and its expectation, at once")
    assert only(tree.problems(), "no committed version of this record carries")


def test_an_expected_committed_before_the_run_is_accepted(tree):
    """The other direction, so the rule is not simply 'no result ever passes'."""
    tree.commit("the plan")
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.write("assurance/board/PLAT-FLASH-001.toml", BOARD_PASS)
    tree.commit("the run")
    assert not only(tree.problems(), "no committed version of this record carries")


# --- the criterion a run was read against, in the record's own words ----------
#
# `outcome = "pass"` is a word and a word is free. Measured before this rule: a
# record moved to `pass` with an `expected` byte-identical to the committed one,
# a full result half and a fabricated `actual` — `python scripts/platform_gate.py`
# exit 0, with every clause above green.
#
# TWO versions have been refuted here and the cases are what they cost. The
# first read `arm_taken` against the arm ALONE, and an arm starts at its label —
# so on a record whose criterion sits above the arms the arm is a pronoun:
# `arm_taken = "PASS = both."`, twelve characters, discharged `PLAT-DISPLAY-001`
# over a fabricated `actual` at exit 0. The second carried the preamble as well,
# and a review drove the mirror image of the same hole: criterion prose written
# AFTER the first label belongs to exactly one arm and is dropped by every other
# quotation. Live on the checkout, no contrivance and one commit —
# `PLAT-ROM-001`'s FAIL arm swallows "No datasheet clause states it either way;
# a vendor erratum settles it as well as a board does", a statement about how the
# row may be discharged AT ALL, and a fabricated PASS quoting 126 characters of
# its 327-character `expected` was exit 0.
#
# So the value is the arm's label and then ALL of `expected`. There is nothing
# left in the field to omit, which is the only closure available: the tail is
# inside the last arm's span with no marker, and a sentence-shaped boundary reds
# the tree (`PLAT-ROM-002`'s FAIL body writes "i.e." mid-body). The cases below
# drive that, refuse both refuted shapes by name, and keep the two directions
# that must stay green: a real discharge, and an honest INCONCLUSIVE on a record
# that states no such arm.


@pytest.mark.parametrize("outcome", ("pass", "fail", "inconclusive"))
def test_a_run_that_happened_names_the_criterion_it_met(tree, outcome):
    """The constructed defect, in all three shapes a run can have.

    Named for [`platform_gate.check_arm_taken`] and now driving it. The version
    this replaces EMPTIED the field instead, which is the result-half
    completeness loop's finding — the required-on-a-run case above parametrizes
    over [`RESULT_FIELDS`] and already covers `arm_taken`, so this case's
    `[pass]` shape was a verbatim duplicate of it. Measured: with
    `check_arm_taken`'s call deleted this case was GREEN, three passed, over the
    one rule it is named for.
    """
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace('outcome = "pass"', f'outcome = "{outcome}"')
               .replace(f'arm_taken = "{PASS_CLAIM}"',
                        'arm_taken = "It all looked fine on the day."'))
    assert only(tree.problems(), "is not this record's `expected`")


def test_a_criterion_written_after_the_arms_cannot_be_dropped(tree):
    """The refutation of the per-arm quotation, in the shape it was driven in.

    A framing sentence, the arms, and THEN the criterion — the ordering
    `PLAT-ROM-001` writes today. Under the old rule the PASS claim carried
    neither the criterion nor the sentence about the erratum, and quoting it was
    exit 0; here that same value is refused and the satisfying one carries the
    whole field. Both halves are asserted, because a rule that refused every
    value would pass the first alone.
    """
    tail = ("The delays are listed in the transcript, and a run that lists none"
            " settles nothing either way.")
    rewritten = f"{PREAMBLE} {PASS_ARM} {FAIL_ARM} {tail}"
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED, rewritten)
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.commit("the plan")
    run = BOARD_PASS.replace(f'expected = "{BOARD_EXPECTED}"',
                             f'expected = "{rewritten}"')
    # what the OLD rule accepted: the preamble and the PASS arm, tail dropped
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               run.replace(f'arm_taken = "{PASS_CLAIM}"',
                           f'arm_taken = "{OLD_PASS_CLAIM}"'))
    assert only(tree.problems(), "is not this record's `expected`")
    assert tail not in OLD_PASS_CLAIM
    whole = platform_gate.arm_claim("pass", rewritten)
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               run.replace(f'arm_taken = "{PASS_CLAIM}"', f'arm_taken = "{whole}"'))
    tree.commit("the run")
    assert not only(tree.problems(), "`arm_taken`")
    assert tail in whole


#: `ARM_REQUIRED`'s value, written out. NOT the constant itself: parametrizing
#: over the constant makes narrowing it COLLECT ONE FEWER CASE instead of failing
#: — measured, `("pass", "fail") -> ("pass",)` took this file from 245 to 244
#: collected with nothing red, and the `[fail]` case simply was not there. The
#: case body asserts the constant against this literal, so the narrowing is a red
#: in every case rather than a case that vanishes. Second instance of that class
#: in one review; the sibling is a floor parametrized over itself.
ARMS_OWED = ("pass", "fail")


@pytest.mark.parametrize("missing", ARMS_OWED)
def test_an_expected_that_states_no_arm_is_a_finding(tree, missing):
    """The arms are owed BEFORE the run as a convention, NOT because
    `check_expected_predates` forbids a later one — which is what this suite and
    the gate both said until it was driven. That rule asks only that SOME commit
    carry this `expected` with `outcome = "planned"`, and it reads no other field
    of that version: a discharged record can be re-planned and re-recorded in two
    commits, both green, the criterion rewritten in between. The price of writing
    an arm late is those two commits, not a refusal."""
    assert platform_gate.ARM_REQUIRED == ARMS_OWED
    arm = {"pass": PASS_ARM, "fail": FAIL_ARM}[missing]
    tree.edit("assurance/board/PLAT-FLASH-001.toml", f" {arm}", "")
    assert only(tree.problems(), f"`expected` states no {missing.upper()} arm")


#: Every spelling of an arm the anchor refuses, with the one it accepts beside
#: them. Measured on the real parser: a semicolon and a colon END a sentence
#: here; a comma, an em dash, an opening bracket, a `.)` or `."` before the
#: label, an ellipsis, and a sentence-case `Pass =` do not. All seven were a red
#: reading "`expected` states no PASS arm" — a message that tells the author the
#: arm is missing when it is visibly there, and never mentions the anchor.
MISPLACED_PASS = {
    "comma": "The clock behaves, PASS = expiry observed.",
    "em dash": "The clock behaves — PASS = expiry observed.",
    "parenthesis": "The clock behaves (PASS = expiry observed).",
    "full stop in brackets": "The clock behaves (it does.) PASS = expiry observed.",
    # TOML-escaped, because the fixture writes it inside a basic string.
    "full stop in quotes": 'The clock behaves \\"it does.\\" PASS = expiry observed.',
    "ellipsis": "The clock behaves… PASS = expiry observed.",
    "sentence case": "The clock behaves. Pass = expiry observed.",
}
ACCEPTED_PASS = {
    "full stop": "The clock behaves. PASS = expiry observed.",
    "semicolon": "The clock behaves; PASS = expiry observed.",
    "colon": "The clock behaves: PASS = expiry observed.",
}


@pytest.mark.parametrize("spelling", sorted(MISPLACED_PASS))
def test_a_misplaced_label_says_it_is_misplaced(tree, spelling):
    """The anchor's cost, with a message that describes it.

    The red is the trade this file takes; the wrong diagnostic was not. Both
    halves: the misplaced-label finding is there, and the "states no PASS arm"
    one — which would send the author looking for an arm they can see — is not.
    """
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED,
              f"{MISPLACED_PASS[spelling]} {FAIL_ARM}")
    problems = tree.problems()
    assert only(problems, "where an arm has to OPEN a sentence")
    assert not only(problems, "states no PASS arm")


@pytest.mark.parametrize("spelling", sorted(ACCEPTED_PASS))
def test_a_sentence_end_the_anchor_accepts_is_green(tree, spelling):
    """The green arm, and the half that says the anchor is not "punctuation".
    Without it the case above passes over a rule that refused every spelling."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED,
              f"{ACCEPTED_PASS[spelling]} {FAIL_ARM}")
    assert not only(tree.problems(), "`expected`")


#: An arm with nothing behind its `=`, in the three shapes that reach a record:
#: the label ending the field, a label and punctuation, and the `PASS = 0.` that
#: needs no crafting at all — prose documenting a script's exit codes mints it.
#: All three were quotable arms, and `arm_taken = "PASS ="` discharged.
HOLLOW_EXPECTED = (
    f"{PREAMBLE} {FAIL_ARM} PASS =",
    f"{PREAMBLE} PASS =. {FAIL_ARM}",
    f"{PREAMBLE} PASS = 0. {FAIL_ARM}",
)


@pytest.mark.parametrize("hollow", HOLLOW_EXPECTED)
def test_an_arm_with_no_word_in_it_is_not_an_arm(tree, hollow):
    """`PASS =` was an arm, and `arm_taken = "PASS ="` discharged.

    It is no longer the quotation this protects — `arm_claim` carries the whole
    `expected` whatever any one arm says — so what is left for the floor is the
    record's PLAN: an outcome whose arm has no body states no criterion of its
    own, and a run that takes it is read against a field that never said what
    taking it would mean. One WORD and not a character count:
    `PLAT-DISPLAY-001`'s whole PASS body is `both.`, five characters, so a length
    admitting this tree admits `0.` with it. Measured over the 33 arms of the
    thirteen records — minimum one word, none with zero.
    """
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED, hollow)
    assert only(tree.problems(), "states a PASS arm with no word in it")


def test_an_expected_that_opens_on_its_arms_is_quoted_whole(tree):
    """The rule that used to be here is GONE, and this is its replacement.

    A record whose `expected` opens on its first label was refused, on the ground
    that the quotation would then be the arm alone — a pronoun on three of the
    thirteen records. `arm_claim` carries the whole field, so that ground is gone:
    the value an operator must write is the same length whether or not a framing
    sentence stands above the arms. What is left is a weak `expected`, which no
    rule here can strengthen — the measured floor is two letters either way. So
    the record is GREEN and the quotation still carries every word of it.
    """
    opened = f"{PASS_ARM} {FAIL_ARM}"
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED, opened)
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.commit("the plan")
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace(f'expected = "{BOARD_EXPECTED}"',
                                  f'expected = "{opened}"')
               .replace(f'arm_taken = "{PASS_CLAIM}"',
                        f'arm_taken = "{platform_gate.arm_claim("pass", opened)}"'))
    tree.commit("the run")
    problems = tree.problems()
    # Targeted rather than `== []`: the fixture's registry row is still `pending`,
    # which is a finding of the status rule and not this one's.
    assert not only(problems, "`expected`") and not only(problems, "`arm_taken`")
    assert FAIL_ARM in platform_gate.arm_claim("pass", opened)


def test_two_arms_under_one_label_is_a_finding(tree):
    """A rule about the record's PLAN, since `arm_claim` carries the whole field
    either way: what it refuses is a record saying two different things happen
    under one outcome, so a run that meets one and misses the other writes the
    same word. The cheap way to mint the second is prose inside another arm's
    body, which the sentence anchor refuses; this is the shape it does NOT reach.
    """
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED,
              f"{BOARD_EXPECTED} PASS = it also worked.")
    assert only(tree.problems(), "`expected` states 2 PASS arms")


def test_a_label_a_sentence_merely_WRITES_is_not_an_arm(tree):
    """An arm opens a sentence, because a label is a word and prose about a
    verdict writes the word.

    What the anchor buys, measured rather than asserted: under a bare `\\b` this
    prose parses as `['PASS', 'PASS', 'FAIL']`, and the DUPLICATE is what
    `check_board_records` reds on its own — so the 84-character quote this
    comment used to credit the anchor with closing was already closed. The job
    that is the anchor's alone is a mid-sentence label of an outcome the record
    states NOWHERE ELSE, which would satisfy `ARM_REQUIRED` and let `outcome`
    name it. The record must stay GREEN, which is the half that says the anchor
    is not a new red.
    """
    prose = ("Read the verdict off the host, not off the script: its own"
             " PASS = zero exit tells you only that the command was accepted.")
    tree.edit("assurance/board/PLAT-FLASH-001.toml", PREAMBLE, f"{prose} {PREAMBLE}")
    expected = tomllib.loads(
        (tree.root / "assurance/board/PLAT-FLASH-001.toml").read_text()
    )["expected"]
    arms = platform_gate.expected_arms(expected)
    assert [arm.outcome for arm in arms] == ["pass", "fail"], arms
    # The measurement the comment above rests on, in the test rather than in
    # prose: a bare `\b` mints a THIRD arm out of that sentence, and a duplicate
    # label is refused by a clause of its own.
    bare = re.compile(r"\b(PASS|FAIL|INCONCLUSIVE)\s*=\s*")
    assert [m.group(1) for m in bare.finditer(expected)] == ["PASS", "PASS", "FAIL"]
    problems = tree.problems()
    for needle in ("`expected` states", "OPEN a sentence", "is not this record's"):
        assert not only(problems, needle), needle


def test_a_label_inside_another_arms_body_is_not_a_second_arm(tree):
    """The same anchor one layer in. `FAIL = … which the script reports as
    PASS = it disagreed with the model.` parsed as three arms, and the third was
    quotable on its own — an arm minted out of another arm's prose."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml", FAIL_ARM,
              f"{FAIL_ARM[:-1]}, which the script reports as PASS = it disagreed.")
    arms = platform_gate.expected_arms(
        tomllib.loads(
            (tree.root / "assurance/board/PLAT-FLASH-001.toml").read_text()
        )["expected"]
    )
    assert [arm.outcome for arm in arms] == ["pass", "fail"], arms
    assert not only(tree.problems(), "`expected` states 2 PASS arms")


#: Everything an operator might reach for that is not the value. The first is the
#: whole point — a bare `PASS` is the self-declared word this rule exists to
#: refuse. `PASS_ARM` and `PREAMBLE` are the FIRST refutation's two halves: the
#: arm without the sentence it back-references, and that sentence without the arm.
#: `OLD_PASS_CLAIM` is the SECOND refutation's: the value the previous rule
#: accepted, which drops whatever the record wrote after its first label — this
#: is the case an operator who read the previous page would write, so it is the
#: one that must be refused by name. The last two are near misses: the arm
#: without its label, and the arm with the clause it does not want dropped.
NOT_AN_ARM = (
    "PASS",
    "pass",
    "n/a",
    "—",
    "tbd",
    "It all looked fine on the day.",
    "offset",
    PASS_ARM,
    PREAMBLE,
    OLD_PASS_CLAIM,
    BOARD_EXPECTED,
    "no plausible wrong value at any offset tried.",
    "PASS = no plausible wrong value.",
)


@pytest.mark.parametrize("quoted", NOT_AN_ARM)
def test_an_arm_taken_that_is_not_this_record_s_criterion_is_a_finding(tree, quoted):
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace(f'arm_taken = "{PASS_CLAIM}"',
                                  f'arm_taken = "{quoted}"'))
    assert only(tree.problems(), "is not this record's `expected`")


def test_naming_ANY_arm_is_not_enough(tree):
    """The FAIL value carries the same whole `expected` and differs by its label
    alone. That label is the one part of the value the outcome varies, so it is
    the part this clause reads — and a record where the two disagree has recorded
    neither."""
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace(f'arm_taken = "{PASS_CLAIM}"',
                                  f'arm_taken = "{FAIL_CLAIM}"'))
    assert only(tree.problems(), "`arm_taken` names the FAIL arm under outcome 'pass'")


def test_a_wrapped_quote_is_the_same_quote(tree):
    """The one difference `arm_taken` may have from the criterion: whitespace. A
    TOML triple-quote wrapped for a reader is the same sentence, and refusing the
    wrap would buy a line length and cost the operator a reason to copy blind.
    It is also why nothing here may claim the quote is VERBATIM.

    `expected` does NOT get this, and the asymmetry is deliberate rather than an
    oversight: that field is published into a `|`-delimited row, where a line
    break takes the columns after it off the page. It costs a discharged record
    two commits to REWRAP its `expected`, which is what the record's own finding
    now says out loud.
    """
    wrapped = 'arm_taken = """\n' + PASS_CLAIM.replace(". ", ".\n  ", 2) + '"""'
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace(f'arm_taken = "{PASS_CLAIM}"', wrapped))
    assert "\n" in wrapped and wrapped.count("\n") >= 3
    assert not only(tree.problems(), "`arm_taken`")


def test_a_discharge_that_quotes_its_own_criterion_is_accepted(tree):
    """The direction that matters most: a rule that reds an honest row is worse
    than the hole. `PLAT-MEM-001` and `PLAT-ROM-002` are the checkout's two, and
    `test_this_checkout_is_green` is where they are read."""
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.commit("the plan")
    tree.write("assurance/board/PLAT-FLASH-001.toml", BOARD_PASS)
    tree.commit("the run")
    assert not only(tree.problems(), "`arm_taken`")


def test_an_inconclusive_run_on_a_record_with_no_such_arm_is_recordable(tree):
    """The false red the first version of this rule introduced.

    `ARM_REQUIRED` leaves INCONCLUSIVE out — a rule that reddens an honest row is
    worse than the hole — and then demanded a quote whose label is the outcome,
    which on a record with no INCONCLUSIVE arm is unsatisfiable. Driven on
    `PLAT-TIMER-001`, one of the SIX such records in the checkout: an empty field
    is "outcome 'inconclusive' with no `arm_taken`", naming PASS is "names the
    PASS arm under outcome 'inconclusive'", and a fresh INCONCLUSIVE sentence is
    "not this record's `expected`" — every candidate red at once, and the only
    escape the post-hoc `planned` commit `check_expected_predates` makes visible.
    """
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.commit("the plan")
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace('outcome = "pass"', 'outcome = "inconclusive"')
               .replace(f'arm_taken = "{PASS_CLAIM}"', 'arm_taken = ""'))
    tree.commit("the run")
    assert not only(tree.problems(), "`arm_taken`")


def test_the_escape_is_out_of_reach_of_a_word_that_moves_the_registry(tree):
    """What keeps `pass` out of the exemption above is `ARM_REQUIRED`, one rule
    away — so the reach is asserted here rather than reasoned about. Deleting the
    PASS arm to earn the exemption reddens the record on the way out, and the
    second assertion records what that costs: the field finding really is gone,
    and the red comes from the other clause."""
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.write("assurance/board/PLAT-FLASH-001.toml",
               BOARD_PASS.replace(f'arm_taken = "{PASS_CLAIM}"', 'arm_taken = ""')
               .replace(f" {PASS_ARM}", ""))
    problems = tree.problems()
    assert only(problems, "`expected` states no PASS arm")
    assert not only(problems, "with no `arm_taken`")


@pytest.mark.parametrize("carried", ("\\n", "\\r"))
def test_a_record_expected_is_held_to_the_published_cell(tree, carried):
    """`expected` reaches `docs/platform-assumptions.md` now, so it is held to
    `CELL_REFUSED` the way `statement` and `discharge` are. Named per record
    here; `cell` is what stops the page being written, and it cannot say which
    record the 48 characters it quotes came from."""
    tree.edit("assurance/board/PLAT-FLASH-001.toml",
              "Old-or-refused", f"Old-or{carried}-refused")
    assert only(tree.problems(), "`expected` carries")


def test_a_less_than_in_an_expected_is_written_and_not_refused(tree):
    """`<` WAS refused, over a message reading "which no escape reaches".

    It is reached by `&lt;`, and the ban told the author nothing about that — on
    a registry whose subject is measurement, `PASS = jitter < 1 us` was
    unwritable. So `cell` escapes it, and this drives both halves: the record is
    green, and the published cell carries the escape rather than the raw `<`.
    `scripts/docs.sh check` and the built HTML are the third half and are not
    this suite's; they were driven by hand and render a `<`.
    """
    tree.edit("assurance/board/PLAT-FLASH-001.toml", PASS_ARM,
              "PASS = jitter < 1 us at every offset tried.")
    tree.regenerate()
    assert tree.problems() == []
    header, rows = board_table(platform_gate.render(tree.root))
    carried = next(r for r in rows if "`PLAT-FLASH-001`" in r[0])[header.index(" expected ")]
    assert "&lt; 1 us" in carried and "< 1 us" not in carried


def test_the_arms_are_split_at_the_next_label():
    """The parser. The boundary is the record's, and it is why the QUOTATION is
    the whole field rather than one arm: the last arm swallows whatever follows
    it, so prose after the first label belongs to exactly one arm. That is
    `PLAT-ROM-001` today, and the reason `Arm` no longer has a `claim`."""
    text = ("Preamble. PASS = a b. FAIL = c, and a trailing sentence."
            " INCONCLUSIVE = d e.")
    assert platform_gate.expected_arms(text) == [
        ("pass", "a b."),
        ("fail", "c, and a trailing sentence."),
        ("inconclusive", "d e."),
    ]
    assert platform_gate.expected_arms("no arms here at all") == []
    # An `expected` that opens on its first label parses, and is no longer a
    # finding: `arm_claim` carries the whole field either way.
    assert platform_gate.expected_arms("PASS = a b.") == [("pass", "a b.")]
    # The value the rule wants is the label, a full stop, and all of `expected`.
    assert platform_gate.arm_claim("fail", text) == f"FAIL. {text}"
    # Up to whitespace, on the argument as well as on the field.
    assert platform_gate.arm_claim("pass", " a\n  b ") == "PASS. a b"


def test_the_page_publishes_the_expected_beside_the_outcome():
    """Half of the rule is a person's. The page carried `discharge` — the
    sentence a row says it is discharged BY — and never the criterion the run is
    read against, so a `pass` beside an unmet expectation read like a met one.
    Measured on the page before this: `grep -c 'still owes'` was 0 over a record
    whose own INCONCLUSIVE arm ends on those words.

    `render(ROOT)` and not the committed page: reading the file made this case
    survive BOTH mutations of the column it is named for — the byte-diff in
    `audit` is what caught them, so this case's own subject was held by another.
    """
    page = platform_gate.render(ROOT)
    assert "| record | outcome | expected |" in page
    record = tomllib.loads((ROOT / "assurance/board/PLAT-FLASH-001.toml").read_text())
    assert record["expected"] in page
    for arm in platform_gate.expected_arms(record["expected"]):
        assert arm.body in page, arm


def test_the_page_names_the_record_fields_from_the_tuples(monkeypatch):
    """`fields` says it is "derived rather than transcribed", and nothing read it.

    Measured: hard-coding today's two lists in place of `fields(BOARD_PLAN_FIELDS)`
    and `fields(BOARD_RESULT_FIELDS)` left this file at 234 passed and the gate at
    exit 0 — the claim was a docstring over a call site no case could tell from a
    literal. A field added to either tuple would then have left the page
    describing a record the gate refuses.
    """
    assert platform_gate.fields(("a", "b")) == "`a`, `b`"
    added = platform_gate.BOARD_RESULT_FIELDS + ("photograph_sha256",)
    monkeypatch.setattr(platform_gate, "BOARD_RESULT_FIELDS", added)
    page = platform_gate.render(ROOT)
    assert "`photograph_sha256`" in page
    monkeypatch.setattr(platform_gate, "BOARD_PLAN_FIELDS",
                        platform_gate.BOARD_PLAN_FIELDS + ("rig",))
    assert "`rig`" in platform_gate.render(ROOT)


def test_the_record_vocabulary_is_ratcheted():
    """M6/M10: widening `BOARD_OUTCOMES` or the sha alphabet moves the
    vocabulary with no rule deleted and no case red.

    [`platform_gate.BOARD_ROW_FLOOR`] is here for the axis the sibling case
    below cannot cover, and it is a tooth that case COST when it stopped
    spelling the number: holding the obligation equal to the constant catches a
    row ADDED without a ratchet, and it made hiding a row DELETED one edit
    cheaper, because lowering the constant to match the smaller tree now
    reddens nothing anywhere. Measured both ways on this checkout, deleting
    `PLAT-TIMER-003` with its record and the `depends_on` that names it: at a
    floor of 13 the gate is exit 1 on its own finding; with the floor lowered
    to 12 in the same diff the gate is exit 0 and every case here passed —
    198 of them — until this line. `>=`, not `==`: a genuine later ratchet has
    to raise the constant and must not have to edit this case to do it.
    """
    assert platform_gate.BOARD_OUTCOMES == {"planned", "pass", "fail", "inconclusive"}
    assert platform_gate.BOARD_PLAN_FIELDS == PLAN_FIELDS
    assert platform_gate.BOARD_RESULT_FIELDS == RESULT_FIELDS
    assert platform_gate.BOARD_SHA.pattern == r"[0-9a-f]{64}"
    assert set(platform_gate.OUTCOME_STATUS) == {"pass", "fail"}
    assert platform_gate.BOARD_ROW_FLOOR >= 13, platform_gate.BOARD_ROW_FLOOR
    # The arm vocabulary is BOARD_OUTCOMES', less the one state that has no arm.
    # ARM_REQUIRED is load-bearing twice: it is the list of arms a record owes,
    # and it is what holds `pass` and `fail` out of `check_board_records`'
    # exemption for an outcome the record states no arm under.
    assert platform_gate.ARM_REQUIRED == ARMS_OWED
    assert platform_gate.ARM_WORD.pattern == r"[^\W\d_]{2,}"
    assert set(platform_gate.ARM_LABEL.findall("PASS = a. FAIL = b. INCONCLUSIVE = c.")) == {
        o.upper() for o in platform_gate.BOARD_OUTCOMES - {"planned"}
    }
    assert not platform_gate.ARM_LABEL.search("the run printed PASS and stopped")
    # The anchor's own arm: a label a SENTENCE writes is not one. What that buys
    # is narrower than this comment used to claim -- under `\b` the sentence
    # below mints a DUPLICATE PASS, which is a finding of its own -- so what is
    # pinned here is the anchor, and the double-arm case is where the other half
    # is driven.
    assert not platform_gate.ARM_LABEL.search("its own PASS = zero exit tells you")
    # The diagnostic pattern is the same vocabulary, unanchored and case-blind.
    # It states no rule; widening the RULE by widening it instead is a diff here.
    assert platform_gate.ARM_MISPLACED.flags & re.IGNORECASE
    assert [m.group(1) for m in
            platform_gate.ARM_MISPLACED.finditer("behaves, Pass = a. FAIL = b.")
            ] == ["Pass", "FAIL"]


def test_the_obligation_and_the_page_count_the_same_rows():
    """The first version obliged 9 rows while the page it generates told the
    reader 12 routes end at a board. One expression now.

    Held to [`platform_gate.BOARD_ROW_FLOOR`] rather than to a literal, and that
    is a tooth rather than tidiness: the literal was `12`, it went red on
    `PLAT-TIMER-003` and its repair could have been a second `13` — one more
    hard-coded twin of a number that had just moved. The gate's own rule is `at
    least the floor`, so ADDING a row without ratcheting is green there (13 >= 12)
    and the new row is then as deletable as the four that made this constant
    necessary. Equality here is what makes the ratchet a step someone has to take.
    """
    registered = platform_gate.entries(ROOT, [])
    owed = platform_gate.board_rows(registered)
    assert len(owed) == platform_gate.BOARD_ROW_FLOOR, sorted(owed)
    page = (ROOT / "docs/platform-assumptions.md").read_text()
    assert f"discharge {len(owed)} of these rows" in page


def test_a_board_row_deleted_with_its_record_is_a_finding(tree):
    """The review deleted four rows, each WITH its record, at exit 0: they cover
    nothing and nothing depends on them, so only a floor sees them go."""
    row = tree.root / "assurance/platform.toml"
    text = row.read_text()
    start = text.index('[[assumption]]\nid = "PLAT-FLASH-001"')
    end = text.index("[[assumption]]", start + 1)
    row.write_text(text[:start] + text[end:])
    (tree.root / "assurance/board/PLAT-FLASH-001.toml").unlink()
    tree.regenerate()
    assert only(tree.problems(), "below the floor of")


# --- the pipe that ended the row ----------------------------------------------


#: How a GFM table splits a row: on a `|` that no backslash precedes. Modelled
#: here rather than assumed, and the model was MEASURED through mdBook — the
#: renderer this page is actually read in — on five spellings: a bare `|` splits;
#: `\|`, `\\|` and a `|` inside a code span do not; and a row with more cells
#: than the header has the excess DROPPED, which is why `PLAT-SOURCE-002` lost
#: its owner and its whole `supports` list off the published page rather than
#: showing a visibly broken one.
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


def registry_table(page):
    """The assumption table as a renderer sees it: header cells, then row cells.

    Both halves come out of ONE `render` call but two different code paths — the
    header is a literal in that function, the rows are built from the registry —
    so a case comparing them is not comparing a value with itself.
    """
    lines = page.splitlines()
    head = next(i for i, line in enumerate(lines) if line.startswith("| ID | Class |"))
    rows = []
    for line in lines[head + 2:]:
        if not line.startswith("| `PLAT-"):
            break
        rows.append(UNESCAPED_PIPE.split(line)[1:-1])
    return UNESCAPED_PIPE.split(lines[head])[1:-1], rows


def board_table(page):
    """The RECORD table the same way, because it grew a prose column.

    A second reader and not a parameter on the first: the two tables have
    different headers and different row keys, and a shared one would have to be
    told which — which is the copy this suite keeps finding rotted.
    """
    lines = page.splitlines()
    head = next(i for i, line in enumerate(lines) if line.startswith("| record |"))
    rows = []
    for line in lines[head + 2:]:
        if not line.startswith("| `PLAT-"):
            break
        rows.append(UNESCAPED_PIPE.split(line)[1:-1])
    return UNESCAPED_PIPE.split(lines[head])[1:-1], rows


#: A discharge route in both shapes the real registry writes. The bare `|` is
#: `PLAT-SOURCE-002`'s (`r.map(|()| tok)`), which ended its row four columns
#: early; the `\|` is `PLAT-MODEL-009`'s `git grep` alternation, which does NOT
#: end the row — markdown eats the backslash instead and publishes a grep pattern
#: that no longer means alternation. One case, because one helper answers both.
PIPED_DISCHARGE = r'Run `a | b`, then `git grep -n "x\|y"`.'

#: The fixture's own text for each field [`platform_gate.RENDERED_PROSE`] names,
#: on the one row (`PLAT-MODEL-001`) whose every cell the cases below read. Both
#: fields get every case: `cell` at `statement` was DELETABLE with this suite at
#: 117 passed, because no registry row carries a pipe there and neither pipe case
#: injected into it — a call site nothing drives is a call site nothing keeps.
FIXTURE_PROSE = {
    "statement": 'statement = "A design-page assumption with no bundle row yet."',
    "discharge": 'discharge = "The store slice."',
}

#: Where each field lands in a rendered row, so a case can read the cell it
#: poisoned instead of counting cells and hoping. From the header, not typed.
COLUMN = {"statement": "Statement", "discharge": "Discharged by"}


def poisoned_row(tree, field, value):
    """Poison one field of `PLAT-MODEL-001`, render, and hand back that row.

    Returns `(header, rows, cell)` so a case can assert the shape of the WHOLE
    table and the content of the ONE cell it wrote — the two halves that a cell
    count alone and a round-trip alone each miss.
    """
    tree.edit("assurance/platform.toml", FIXTURE_PROSE[field], f"{field} = '{value}'")
    header, rows = registry_table(platform_gate.render(tree.root))
    assert rows, "the fixture rendered no assumption rows"
    row = next(r for r in rows if "`PLAT-MODEL-001`" in r[0])
    return header, rows, row[header.index(f" {COLUMN[field]} ")].strip()


@pytest.mark.parametrize("field", sorted(FIXTURE_PROSE))
def test_a_pipe_in_rendered_prose_does_not_end_the_row(tree, field):
    """A `|` in prose is a cell separator, and the row runs into its neighbours.

    Measured before the fix on the real checkout: 72 rows of 7 cells, one of 10
    and one of 9, against a 7-column header — and GFM drops the excess, so two
    rows published a fragment of a grep pattern where the owner belongs and no
    `supports` at all.

    The second assertion is the one this case was missing: deleting the poison
    left it GREEN, counting seven cells on an un-poisoned fixture and asserting
    nothing at all. It also refuses the degenerate escape — a `cell` that DROPS
    the pipe gives seven cells too, and gives a route with no `|` left in it.
    """
    header, rows, carried = poisoned_row(tree, field, PIPED_DISCHARGE)
    # The count is DERIVED from the header of the same table. A literal 7 here is
    # a second copy of the column count, and a column added to both halves of
    # `render` would leave it asserting the old shape.
    assert [len(row) for row in rows] == [len(header)] * len(rows)
    assert "|" in carried, carried


@pytest.mark.parametrize("field", sorted(FIXTURE_PROSE))
def test_the_escape_carries_the_prose_rather_than_dropping_it(tree, field):
    """Seven cells is not enough: deleting the `|` would also give seven.

    The other side of the oracle, un-escaped by GFM's rule that `\\|` is a
    literal `|` and compared against the TOML the registry holds. That rule is
    also `cell`'s own inverse, so this case cannot tell the helper's escape from
    the renderer's — nothing under `scripts/` runs a renderer. What pins the two
    together is the measurement recorded above [`UNESCAPED_PIPE`], re-taken for
    this change on thirteen spellings through `mdbook build`, and the `docs` row
    of `check.sh`, which builds the book on every run. A case that shelled out to
    mdBook here would hard-require the binary in a suite that is otherwise pure
    Python — `scripts/conftest.py` allows no skip to soften that — to re-measure
    what the gate already builds one row over.
    """
    _header, _rows, carried = poisoned_row(tree, field, PIPED_DISCHARGE)
    assert carried.replace("\\|", "|") == PIPED_DISCHARGE


def test_a_pipe_in_a_record_expected_does_not_end_the_row(tree):
    """`cell` at the record table's `expected` column had no case at all.

    Measured: with `cell()` dropped from that column the suite was fully green,
    this case not yet among it. No record in the checkout carries a `|` in
    `expected` and no fixture put one there, so the call site the new column
    added was driven by nothing — which is exactly what `FIXTURE_PROSE` above
    records about `statement` one table over. A `|` is the one character `cell`
    ESCAPES rather than raising on, so this is the escape's arm and not
    `CELL_REFUSED`'s; both halves are asserted for the same reason the registry
    cases assert both — a `cell` that DROPPED the pipe would give the right cell
    count too.
    """
    piped = f"{PREAMBLE} Read it back with `dd | xxd`. {PASS_ARM} {FAIL_ARM}"
    tree.edit("assurance/board/PLAT-FLASH-001.toml", BOARD_EXPECTED, piped)
    header, rows = board_table(platform_gate.render(tree.root))
    assert rows, "the fixture rendered no record rows"
    assert [len(row) for row in rows] == [len(header)] * len(rows)
    carried = next(r for r in rows if "`PLAT-FLASH-001`" in r[0])[header.index(" expected ")]
    assert carried.strip().replace("\\|", "|") == piped


# --- and the characters no escape reaches -------------------------------------


#: Each with what it costs, measured on the real checkout through mdBook. The
#: line break is the pipe defect again, past the fix for the pipe defect: with
#: one in `PLAT-MODEL-002`'s discharge the published row rendered FOUR cells,
#: Owner and Supports were empty, and `platform_gate.py`, this suite and
#: `mdbook build` were all exit 0. `\r` is that break plus a red that never
#: converges — `read_text` folds it to `\n`, so the byte-diff asks forever for a
#: `--write` that cannot settle it.
#:
#: The three `<` payloads are NOT here any more. They were, under a message
#: reading "which no escape reaches" — and `&lt;` reaches them, so `cell` writes
#: that escape and they moved to `ESCAPED_MARKUP` below. What is left is the one
#: thing no escape answers: a cell is one line.
REFUSED = {
    "line break": "a\\nb",
    "carriage return": "a\\rb",
}

#: The green arm, and it is the half that says the rule is not "punctuation".
#: Every one measured at exit 0, seven cells and no markup: `>` (seven real rows
#: write one), `&` (three do), the fullwidth `｜`, a tab, a leading `#`, a
#: trailing backslash, and a `|` inside a code span. Widening the rule to any of
#: them is a diff here rather than a silent tightening.
RENDERS = ["a > b", "a & b", "a ｜ b", "a\\tb", "# a b", "a b \\\\", "a `x | y` b"]

#: What `<` used to be refused for, kept as the arm that says the ESCAPE is what
#: replaced the ban. `</td><td>` exited `mdbook build` 101 raw and `<script>` and
#: `<!-- -->` reached the built page as markup; escaped, each is text. Both
#: halves are asserted below — the gate is green AND the cell carries `&lt;` —
#: because a `cell` that DROPPED the character would give a green gate too.
ESCAPED_MARKUP = {
    "table injection": "a</td><td>b",
    "script": "a<script>alert(1)</script>b",
    "comment": "a<!-- c -->b",
}


@pytest.mark.parametrize("field", sorted(FIXTURE_PROSE))
@pytest.mark.parametrize("what", sorted(REFUSED))
def test_a_character_no_escape_reaches_is_a_finding(tree, field, what):
    """Named, and it names the field: `check_shape` reads neither."""
    tree.edit(
        "assurance/platform.toml", FIXTURE_PROSE[field], f'{field} = "{REFUSED[what]}"'
    )
    assert only(tree.problems(), f"`{field}` carries")


@pytest.mark.parametrize("what", sorted(REFUSED))
def test_the_page_refuses_to_be_generated_rather_than_carrying_it(tree, what):
    """The second guard, and the one `evidence_gate.py` has instead of the first.

    That gate renders the same `statement` into `docs/assurance-vector.md` and
    never calls `check_shape`, so `cell`'s raise is the whole of what stops the
    damage there. Both `audit`s catch `ValueError` off their `render`.
    """
    tree.edit(
        "assurance/platform.toml",
        FIXTURE_PROSE["discharge"],
        f'discharge = "{REFUSED[what]}"',
    )
    assert only(tree.problems(), "cannot be generated")


@pytest.mark.parametrize("field", sorted(FIXTURE_PROSE))
@pytest.mark.parametrize("payload", RENDERS)
def test_a_character_that_renders_is_not_refused(tree, field, payload):
    tree.edit("assurance/platform.toml", FIXTURE_PROSE[field], f'{field} = "{payload}"')
    tree.regenerate()
    assert tree.problems() == []


@pytest.mark.parametrize("field", sorted(FIXTURE_PROSE))
@pytest.mark.parametrize("what", sorted(ESCAPED_MARKUP))
def test_markup_is_escaped_rather_than_refused(tree, field, what):
    """The repair `<` got instead of the ban it used to carry.

    Both halves, because either alone is satisfied by a `cell` that drops the
    character: the gate is green over a field that carries markup, AND the cell
    that reaches the page carries `&lt;` where the field carried `<`.
    """
    payload = ESCAPED_MARKUP[what]
    _header, _rows, carried = poisoned_row(tree, field, payload)
    tree.regenerate()
    assert tree.problems() == []
    assert "<" not in carried, carried
    assert carried == payload.replace("<", "&lt;")


def test_write_refuses_the_page_rather_than_writing_the_damage(tree, capsys):
    """`--write` runs no rule, so the raise is the only thing standing there.

    A traceback would be the crash this file refuses everywhere else, and a
    half-written page would be worse: the assertion is that the page on disk is
    the one that was there before. The payload is a LINE BREAK now: `<br>` used
    to be one and is escaped instead, so this case would have driven nothing.
    """
    tree.edit(
        "assurance/platform.toml", FIXTURE_PROSE["discharge"],
        "discharge = \"\"\"a\nb\"\"\"",
    )
    before = (tree.root / platform_gate.ARTIFACT).read_text()
    assert platform_gate.run(tree.root, write=True) == 1
    assert (tree.root / platform_gate.ARTIFACT).read_text() == before
    assert "not written" in capsys.readouterr().err


def test_the_owner_is_refused_by_its_vocabulary_and_not_by_an_escape(tree):
    """Why `render` does not wrap `discharge_owner`, and why that is checkable.

    `OWNERS` is closed and `check_shape` reads it, so the one spelling an escape
    there would have to survive is already a finding. The commit that added the
    escape said exactly this and wrapped the field anyway; deleting that call
    left this suite at 117 passed, because nothing could reach it.
    """
    tree.edit(
        "assurance/platform.toml",
        'discharge_owner = "contributor"\nstatus = "pending"\nfailure_direction = "coverage: a cardinality',
        'discharge_owner = "contri|butor"\nstatus = "pending"\nfailure_direction = "coverage: a cardinality',
    )
    assert only(tree.problems(), "discharge_owner 'contri|butor' is not one")
    assert "discharge_owner" not in platform_gate.RENDERED_PROSE


# --- rule 9: a settled result is dated, and goes stale when an input moves ------
#
# Stage 10's exit criterion 3 — "every assumption automatically marks dependent
# claims stale" — measured at 0: `grep -c stale scripts/platform_gate.py` found
# nothing, and the tree's only freshness machine (`evidence_gate.freshness`) reads
# bundles, not this registry. These cases are that axis. Being stale is NOT a
# finding, for the reason it is not one there: 11 of the 11 bundles that record a
# commit are stale, so a red on staleness is a gate red at rest. The staleness
# lands on the page, and the page's byte-diff is what makes it something a person
# has to write down — which is what the last three cases here drive.


def test_a_settled_row_with_no_evidence_commit_is_a_finding(tree):
    """`revalidated_by` is a sentence saying what would unsettle the row, and
    before this nothing could tell whether it had happened."""
    tree.edit("assurance/platform.toml", f'evidence_commit = "{tree.head()}"\n', "")
    assert only(tree.problems(), "with no `evidence_commit`")


def test_an_evidence_commit_under_a_pending_row_is_a_finding(tree):
    """The other half of `check_evidence`'s own sentence — an artifact nothing
    rests on is decoration — asked of the date rather than of the artifact. That
    `elif` cannot say it: `evidence_commit` is not one of the three fields it
    reads, and widening it was measured against the rule it would weaken."""
    tree.edit(
        "assurance/platform.toml",
        'status = "pending"\nfailure_direction = "security: every trace-linked',
        f'status = "pending"\nevidence_commit = "{COMMIT_AT_INIT}"\n'
        'failure_direction = "security: every trace-linked',
    )
    assert only(tree.problems(), "carries an\n `evidence_commit`".replace("\n", ""))


def test_an_evidence_commit_this_history_does_not_have_is_a_finding(tree):
    """`evidence_gate`'s own words: an evidence date nothing can check. The
    fixture's placeholder is a sha of the right SHAPE, so this rule is what a
    forgotten substitution would report — not the missing-field rule."""
    tree.edit("assurance/platform.toml", tree.head(), COMMIT_AT_INIT)
    assert only(tree.problems(), "is not a commit this history has")


def test_a_settled_row_is_fresh_until_an_input_it_cites_moves(tree):
    """Both directions of the axis over one input, through the page."""
    assert "| `PLAT-BUILD-001` | `" in platform_gate.render(tree.root)
    assert "**fresh**" in platform_gate.render(tree.root)
    tree.append("assurance/properties.toml", "\n")
    tree.commit("the evidence moves")
    assert "**stale**" in platform_gate.render(tree.root)
    assert "`assurance/properties.toml`" in platform_gate.render(tree.root)


def test_the_inputs_include_the_paths_the_trigger_names_and_evidence_does_not(tree):
    """The union half, driven by the file only `revalidated_by` names.

    `assurance/crates.toml` is in no `evidence` list here and neither is
    `formal/gen-configs.sh` on the real checkout, where `PLAT-CRED-004`'s whole
    discharge rests on an emit in that file. Read from `evidence` alone that row
    is behind one input; read from the union it is behind two, and the second is
    the one its own trigger sentence points at."""
    assert "assurance/crates.toml" in platform_gate.revalidation_inputs(
        tree.root, platform_gate.entries(tree.root, [])["PLAT-BUILD-001"],
        set(gate_lines.tree_files(tree.root)),
    )
    tree.append("assurance/crates.toml", "\n# a change to a file only the trigger names\n")
    tree.commit("an input the evidence list does not carry moves")
    assert "`assurance/crates.toml`" in platform_gate.render(tree.root)


def test_an_input_that_was_never_committed_counts_as_behind(tree):
    """A git failure and a never-committed file take the same road, and it is the
    loud one: a guard that reads either as `nothing changed` reports fresh
    evidence over a history it could not open."""
    tree.write("assurance/board/flash-cut.log", "a capture\n")
    tree.git("add", "-A")
    tree.edit(
        "assurance/platform.toml",
        'evidence = ["assurance/properties.toml"]',
        'evidence = ["assurance/properties.toml", "assurance/board/flash-cut.log"]',
    )
    assert "`assurance/board/flash-cut.log`" in platform_gate.render(tree.root)


def test_the_freshness_of_a_row_is_on_the_page(tree):
    """The rendering is the enforcement: staleness is not a finding, so a verdict
    that never reached the page would be an axis nothing in `check.sh` can see."""
    tree.append("assurance/properties.toml", "\n")
    tree.commit("the evidence moves")
    assert only(tree.problems(), "is not what the generator writes")


def test_what_goes_stale_with_a_row_is_derived_from_its_own_links(tree):
    """Stage 10 п.3's `dependent claims`, from the links the registry carries."""
    registered = platform_gate.entries(tree.root, [])
    assert platform_gate.inherits("PLAT-BUILD-001", registered) == ["SEC-T-001"]
    tree.edit(
        "assurance/platform.toml",
        'id = "PLAT-MODEL-001"\nclass = "model-abstraction"',
        'id = "PLAT-MODEL-001"\ndepends_on = ["PLAT-BUILD-001"]\nclass = "model-abstraction"',
    )
    registered = platform_gate.entries(tree.root, [])
    assert platform_gate.inherits("PLAT-BUILD-001", registered) == [
        "SEC-T-001", "PLAT-MODEL-001",
    ]


# --- rule 10: an accepted risk says where it is published ----------------------
#
# Stage 9 п.5 and stage 10 п.5 both turn on it and both were unverifiable:
# measured, ZERO rows of any `assurance/*.toml` referenced `docs/limitations.md`,
# and `scripts/test_threat_gate.py` has a case recording it as cited by nothing.
# The obligation is DERIVED from the page — a row is owed a pin when the page
# already names it — the way `check_bundles` derives `registered` rather than
# reading a field that can disagree with the tree.


def test_an_accepted_risk_the_page_names_owes_a_pin(tree):
    tree.edit(
        "assurance/platform.toml",
        'out_of_scope_by = "docs/limitations.md#silicon--desk"\n',
        "",
    )
    assert only(tree.problems(), "publishes this row and it carries no")


def test_a_pin_under_a_status_that_accepted_no_risk_is_a_finding(tree):
    """The decoration direction. `PLAT-FLASH-001` is the shape on the real
    checkout: the page names it and it is `pending`, so it is owed nothing and
    may claim nothing."""
    tree.edit(
        "assurance/platform.toml",
        'status = "pending"\nfailure_direction = "security: a torn write',
        'status = "pending"\nout_of_scope_by = "docs/limitations.md#silicon--desk"\n'
        'failure_direction = "security: a torn write',
    )
    assert only(tree.problems(), "carries `out_of_scope_by`")


@pytest.mark.parametrize(
    "spelling",
    [
        "docs/limitations.md#Silicon--desk",  # an anchor mdBook lower-cases
        "./docs/limitations.md#silicon--desk",  # the page by another path
        "docs/limitations.md",  # the page and nothing more
        "limitations.md#silicon--desk",  # the link a reader of the page would write
        "docs/limitations.md#silicon desk",  # a heading where an anchor goes
    ],
)
def test_a_pin_in_a_spelling_that_resolves_to_nothing_is_a_finding(tree, spelling):
    """Each one falls through every rule below it while LOOKING published, which
    is what `threat_gate.check_sources` refuses in the same words."""
    tree.edit(
        "assurance/platform.toml", "docs/limitations.md#silicon--desk", spelling
    )
    assert only(tree.problems(), "is not `docs/limitations.md#<anchor>`")


def test_a_pin_to_a_section_that_is_not_on_the_page_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        "docs/limitations.md#silicon--desk",
        "docs/limitations.md#no-such-section",
    )
    assert only(tree.problems(), "is no section of that page")


def test_a_pin_to_a_section_that_does_not_publish_the_row_is_a_finding(tree):
    """`lychee --offline` does not check fragments and mdBook does not check
    which section a fragment lands in, so an anchor that resolves is not the same
    claim as a section that is about this row."""
    tree.edit(
        "assurance/platform.toml",
        "docs/limitations.md#silicon--desk",
        "docs/limitations.md#protocol--compatibility",
    )
    assert only(tree.problems(), "which does not name this row")


def test_a_heading_rename_moves_the_anchor_and_the_pin_goes_red(tree):
    """The one edit that breaks the link with nothing in the registry touched."""
    tree.edit("docs/limitations.md", "## Silicon & desk", "## Silicon and desk")
    assert only(tree.problems(), "is no section of that page")


def test_the_anchor_is_mdbooks_own_normalisation(tree):
    """A KAT against a real `scripts/docs.sh build`, not against a reading of
    mdBook's source: these five ids were read out of `book/limitations.html`. The
    double dash is the one a slugger that collapses runs gets wrong — the dropped
    character leaves the space on either side of it."""
    assert platform_gate.normalize_id("Cryptography") == "cryptography"
    assert platform_gate.normalize_id("Backup & migration") == "backup--migration"
    assert platform_gate.normalize_id("Hardware / physical") == "hardware--physical"
    assert platform_gate.normalize_id("Protocol / compatibility") == "protocol--compatibility"
    assert platform_gate.normalize_id(
        "Limitations — what RS-Key does not do, and why"
    ) == "limitations--what-rs-key-does-not-do-and-why"


def test_an_id_on_the_page_that_is_no_row_of_the_registry_is_a_finding(tree):
    """The reverse direction, and the cheap half: the page sends a reader to
    three of these ids in prose, and a rename would leave it authoritative and
    pointing at nothing."""
    tree.edit("docs/limitations.md", "`PLAT-CRYPTO-001`", "`PLAT-GONE-001`")
    assert only(tree.problems(), "which is no entry of assurance/platform.toml")


def test_a_heading_and_an_id_inside_a_fence_are_not_read(tree):
    """The green arm, and it is load-bearing rather than decorative: the fixture's
    fence carries `PLAT-BOGUS-999` and a `##` line, and dropping the fence skip
    turns the first into an unregistered id and the second into an anchor the
    page does not have."""
    headings, mentions = platform_gate.limitations_page(tree.root)
    assert "a-heading-inside-a-fence" not in headings
    assert not any("PLAT-BOGUS-999" in ids for ids in mentions.values())
    tree.edit("docs/limitations.md", "```text\n## A heading inside a fence\n", "")
    tree.edit("docs/limitations.md", "PLAT-BOGUS-999\n```\n", "PLAT-BOGUS-999\n")
    assert only(tree.problems(), "PLAT-BOGUS-999, which is no entry")


def test_where_a_risk_is_published_is_on_the_page(tree):
    """The rendering, driven the way the freshness one is: a heading rename that
    the registry follows leaves every rule green and the page wrong."""
    tree.edit("docs/limitations.md", "## Silicon & desk", "## Silicon & the desk")
    tree.edit(
        "assurance/platform.toml",
        "docs/limitations.md#silicon--desk",
        "docs/limitations.md#silicon--the-desk",
    )
    assert only(tree.problems(), "is not what the generator writes")
    assert "silicon--the-desk" in platform_gate.render(tree.root)


def test_a_row_the_page_does_not_name_is_owed_no_pin(tree):
    """The obligation is DERIVED, so it is not `every accepted-risk row`. On the
    real checkout that is the honest half: 2 of the 4 accepted-risk rows are model
    OVER-APPROXIMATIONS whose route reads `nothing to run`, and that page opens by
    saying it covers feature and hardware gaps — an anchor minted for them would
    publish a proof-scope note as a user-facing limitation."""
    tree.edit("docs/limitations.md", "See `PLAT-CRYPTO-001`.", "Nobody is named here.")
    tree.edit(
        "assurance/platform.toml",
        'out_of_scope_by = "docs/limitations.md#silicon--desk"\n',
        "",
    )
    assert not only(tree.problems(), "carries no")
    assert "**not published there**" in platform_gate.render(tree.root)


def test_an_evidence_commit_that_is_a_ref_and_not_a_sha_is_a_finding(tree):
    """`git cat-file -e HEAD^{commit}` succeeds, so the `unknown-commit` rule
    cannot see this: a date written `HEAD` resolves, moves with the checkout, and
    reports every row fresh forever. Measured at exit 0 before the shape rule."""
    tree.edit("assurance/platform.toml", tree.head(), "HEAD")
    assert only(tree.problems(), "is not a full commit sha")


def test_an_abbreviated_evidence_commit_is_a_finding(tree):
    """The weaker half of the same rule, and it is a different failure: an
    abbreviation resolves today and stops being unique as history grows."""
    tree.edit("assurance/platform.toml", tree.head(), tree.head()[:12])
    assert only(tree.problems(), "is not a full commit sha")


def test_a_heading_of_the_published_page_is_a_table_cell_too(tree):
    """The new cells come from a file `check_cells` does not read.

    `RENDERED_PROSE` names the two REGISTRY fields that reach the page as prose,
    and a heading of `docs/limitations.md` is a third source that is neither. The
    named half cannot see it, so [`cell`] is the whole of what stands between
    that heading and the page — and both of its escapes are driven here. It used
    to be the RAISE that was driven instead, over `<b>`; `<` is escaped now, and
    a heading is one line by construction, so nothing a heading can carry raises.
    That is the point rather than a gap: the escape reaches what the ban did not.
    """
    tree.edit("docs/limitations.md", "## Silicon & desk", "## Silicon <b>&</b> desk")
    tree.edit("assurance/platform.toml", "#silicon--desk", "#silicon-bb-desk")
    tree.regenerate()
    assert tree.problems() == []
    # `&` is deliberately NOT escaped -- three real rows write one and GFM prints
    # it -- so this line is also the arm that says the escape is `<` and nothing
    # that merely looks like it.
    assert ("| `PLAT-CRYPTO-001` | [Silicon &lt;b>&&lt;/b> desk]"
            "(limitations.md#silicon-bb-desk) |") in platform_gate.render(tree.root)
    tree.edit("docs/limitations.md", "## Silicon <b>&</b> desk", "## Silicon | desk")
    tree.edit("assurance/platform.toml", "#silicon-bb-desk", "#silicon--desk")
    assert "| `PLAT-CRYPTO-001` | [Silicon \\| desk](limitations.md#silicon--desk) |" in (
        platform_gate.render(tree.root)
    )


# --- the file->site move, and the two rules it makes checkable ------------------


def test_a_second_site_in_a_file_that_already_has_one_is_a_finding(tree):
    """The whole reason the derivation moved off the FILE.

    Keyed by file, this append changes no candidate: `crates/rsk-a/src/lib.rs`
    was already produced and already claimed, so a fresh `unsafe` under a row
    that had never been read for it was exit 0 — measured on this fixture before
    the move. Keyed by site it is a candidate nobody claims.
    """
    tree.append("crates/rsk-a/src/lib.rs", "pub fn two() {\n    unsafe { q() };\n}\n")
    assert only(
        tree.problems(),
        "unsafe:crates/rsk-a/src/lib.rs#block:q: derived from",
    )
    # And the site that WAS there is still the one the row claims: the new one
    # did not renumber it onto a neighbour.
    assert not only(tree.problems(), "covers 'unsafe:crates/rsk-a/src/lib.rs#block:core-ptr")


def test_a_row_naming_a_site_that_is_gone_is_a_finding(tree):
    """The other direction, and it fires on a REWRITE and not only a deletion.

    A site whose code changed is a justification that was written about
    something else, which is the state a file key could never reach: the file
    still carries `unsafe`, so the candidate was identical either way.
    """
    tree.edit("crates/rsk-a/src/lib.rs", "core::ptr::null::<u8>().read()", "other()")
    assert only(
        tree.problems(),
        "covers 'unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read', which no"
        " derivation produces",
    )


def test_inserting_a_site_does_not_re_point_an_existing_row(tree):
    """The arm that refuses the obvious key, `<path>#<n-th unsafe in file>`.

    An ordinal is derivable and stable-looking and is wrong in the one way that
    is silent: this insertion makes the OLD site the second `unsafe` of the file,
    so the row's `#1` would keep resolving — to the new site, whose justification
    nobody has written. Measured here as the green half: the surviving key still
    derives, and the only finding is the new site being unclaimed.
    """
    tree.edit(
        "crates/rsk-a/src/lib.rs",
        "pub fn steal() {",
        "pub fn first() {\n    unsafe { earlier() };\n}\n\npub fn steal() {",
    )
    found = platform_gate.candidates(tree.root)
    assert "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read" in found
    assert "unsafe:crates/rsk-a/src/lib.rs#block:earlier" in found
    assert only(tree.problems(), "unsafe:crates/rsk-a/src/lib.rs#block:earlier: derived from")
    assert not only(tree.problems(), "which no derivation produces")


def test_two_colliding_sites_are_separated_by_their_own_words(tree):
    """`rsk-wipe`'s shape at six words, forced here at one — and the arm that
    refuses the ordinal a second time, one level down.

    `~2` over the duplicates was the first version, and it carries the exact
    defect `<path>#<n-th unsafe>` was rejected for: measured on the checkout,
    register `~2` and then SWAP the two colliding functions and the output is
    byte-identical at exit 0 with each row's justification now attached to the
    other one. So a collision spends MORE of the sites' own words instead.
    """
    tree.write("crates/rsk-c/src/lib.rs", COLLIDING_RS)
    tree.git("add", "-A")
    found = {k for k in platform_gate.candidates(tree.root) if "rsk-c" in k}
    assert found == {
        "unsafe:crates/rsk-c/src/lib.rs#block:core-ptr-null-u8-read-wrapping_add-alpha",
        "unsafe:crates/rsk-c/src/lib.rs#block:core-ptr-null-u8-read-wrapping_add-beta",
    }, sorted(found)
    assert not [k for k in found if platform_gate.TIED_MARK in k], sorted(found)


def test_reordering_two_colliding_sites_does_not_re_point_a_row(tree):
    """The case the first version had no arm for, and the defect it was blind to.

    An insert case and a duplicate case were both here; a REORDER was not, and it
    is the one an ordinal over the duplicates gets wrong. Written both ways: the
    swap moves no key (nothing about either site changed), and editing the word
    that separates them DOES move one — which under `~2` was byte-identical,
    because the seventh word was past the end of the slug either way.
    """
    tree.write("crates/rsk-c/src/lib.rs", COLLIDING_RS)
    tree.git("add", "-A")
    before = sites_by_key(tree, "crates/rsk-c/src/lib.rs")
    first, second = COLLIDING_RS.split("\n\n")
    tree.edit("crates/rsk-c/src/lib.rs", f"{first}\n\n{second}", f"{second}\n\n{first}")
    # The MAPPING and not the key set. A set comparison passes under the ordinal
    # BY CONSTRUCTION — `~1` and `~2` are the same two strings after a swap, and
    # each denoting the other body is the whole defect. Measured: with the
    # extension removed this assertion is the one that falls.
    assert sites_by_key(tree, "crates/rsk-c/src/lib.rs") == before, "a swap re-pointed a key"
    tree.edit("crates/rsk-c/src/lib.rs", "BETA", "GAMMA")
    moved = {k for k in platform_gate.candidates(tree.root) if "rsk-c" in k}
    assert "unsafe:crates/rsk-c/src/lib.rs#block:core-ptr-null-u8-read-wrapping_add-gamma" in moved
    assert (
        "unsafe:crates/rsk-c/src/lib.rs#block:core-ptr-null-u8-read-wrapping_add-beta" not in moved
    ), sorted(moved)


def test_sites_their_own_code_cannot_separate_are_reported(tree):
    """The residue, and it is never silent.

    Two sites whose word lists are EQUAL leave nothing but a position to tell
    them apart. The key still carries an ordinal — dropping it would collapse two
    candidates into one and lose a site — but the pair is a finding, because a
    row naming `~2` re-points if anyone reorders them.
    """
    tree.append("crates/rsk-a/src/lib.rs", UNSAFE_RS.replace("steal", "again"))
    found = platform_gate.candidates(tree.root)
    assert "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read~2" in found, sorted(found)
    assert only(tree.problems(), "whose own code is identical")


def test_an_attribute_site_is_named_by_its_section_and_by_its_item(tree):
    """Both halves, because each was a hole on its own.

    The ITEM half first: `rsk-rsa` carries the attribute twice with an
    `#[inline(never)]` between the second and its `fn`, and reading the attribute
    alone made the two placements one candidate.

    The SECTION half is the newer one and it is what makes `PLAT-UNSAFE-010` and
    `-011` falsifiable at all. Their whole subject is WHICH section the item is
    placed in, that name is a string literal, and the lexer blanks it — so
    renaming `.start_block` to anything at all was byte-identical output at exit
    0, measured on the checkout. Asserted here by two placements of the same
    item shape that differ ONLY in the section they name.
    """
    tree.write(
        "crates/rsk-c/src/lib.rs",
        '#[unsafe(link_section = ".data.one")]\npub static A: u8 = 0;\n'
        '#[unsafe(link_section = ".data.two")]\n#[inline(never)]\npub fn b() {}\n',
    )
    tree.git("add", "-A")
    found = {k for k in platform_gate.candidates(tree.root) if "rsk-c" in k}
    assert found == {
        "unsafe:crates/rsk-c/src/lib.rs#attr:link_section-data-one-pub-static-a",
        "unsafe:crates/rsk-c/src/lib.rs#attr:link_section-data-two-pub-fn-b",
    }, sorted(found)
    # And the section name is the discriminator, not decoration beside it: the
    # arm that was exit 0 before the raw literal was read.
    tree.edit("crates/rsk-c/src/lib.rs", ".data.two", ".data.three")
    moved = {k for k in platform_gate.candidates(tree.root) if "rsk-c" in k}
    assert "unsafe:crates/rsk-c/src/lib.rs#attr:link_section-data-three-pub-fn-b" in moved
    assert "unsafe:crates/rsk-c/src/lib.rs#attr:link_section-data-two-pub-fn-b" not in moved


def test_a_comment_inside_an_attribute_cannot_write_a_slug(tree):
    """The raw read is one inch of door, and this is what holds it there.

    A review drove the version without the name clause and a comment wrote the
    slug: `#[unsafe(/* see "alpha" */ link_section = ".data.one")]` keyed on
    `alpha`, so editing a COMMENT moved a site — the exact class the lexer
    exists to stop, walked in through the one place this module reads raw
    source. Three spellings, and the first version was green over all three:
    a quoted word in a comment, a comment shaped like a real `name = "value"`
    pair, and an escaped quote in an EARLIER literal, which made `[^"\\\\]*`
    re-anchor and capture the text between the two literals — the slug then read
    `export_name-link_section-link_section` and the section name was gone.
    """
    plain = 'unsafe:crates/rsk-c/src/lib.rs#attr:link_section-data-one-pub-static-a'
    for body in (
        '#[unsafe(/* see "alpha" */ link_section = ".data.one")]\npub static A: u8 = 0;\n',
        '#[unsafe(/* q = "boom" */ link_section = ".data.one")]\npub static A: u8 = 0;\n',
        '#[unsafe(link_section = ".data.one")]\npub static A: u8 = 0;\n',
    ):
        tree.write("crates/rsk-c/src/lib.rs", body)
        tree.git("add", "-A")
        found = {k for k in platform_gate.candidates(tree.root) if "rsk-c" in k}
        assert found == {plain}, (body, sorted(found))
    # The escape case keeps BOTH declared values and does not lose the section.
    tree.write(
        "crates/rsk-c/src/lib.rs",
        '#[unsafe(export_name = "a\\b", link_section = ".data.one")]\npub static A: u8 = 0;\n',
    )
    tree.git("add", "-A")
    found = {k for k in platform_gate.candidates(tree.root) if "rsk-c" in k}
    assert found == {
        "unsafe:crates/rsk-c/src/lib.rs#attr:export_name-link_section-a-b-data-one"
    }, sorted(found)


def test_the_unsafe_page_count_is_held_to_the_tree(tree):
    """The page AGENTS.md requires, and the drift it shipped with.

    `docs/unsafe.md` said `Runtime sites: 21` over a tree carrying 22 — the third
    sieve access, added with that section's own prose and not with its heading.
    No rule read the page at all, so the number was true on the day it was typed
    and nothing after.
    """
    tree.edit("docs/unsafe.md", "Runtime sites: 2.", "Runtime sites: 3.")
    assert only(tree.problems(), "says `Runtime sites: 3` and the tree has 2")


def test_the_unsafe_page_states_its_count_exactly_once(tree):
    """Both ways: none is a page with nothing to hold, two is a page with two
    answers, and picking the first would make appending a second free."""
    tree.edit("docs/unsafe.md", "**Runtime sites: 2.**", "The sites are enumerated below.")
    assert only(tree.problems(), "0 `Runtime sites: <n>` statements")
    tree.append("docs/unsafe.md", "\nRuntime sites: 2, again.\n")
    tree.edit("docs/unsafe.md", "The sites are enumerated below.", "**Runtime sites: 2.**")
    assert only(tree.problems(), "2 `Runtime sites: <n>` statements")


def test_a_file_carrying_a_site_must_be_named_on_the_unsafe_page(tree):
    """A count alone is met by editing one digit. This is the half that costs
    prose, and it is the direction a new FILE of `unsafe` arrives in."""
    tree.write("crates/rsk-b/src/lib.rs", UNSAFE_RS)
    tree.edit("assurance/platform.toml",
              '"unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",',
              '"unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",\n'
              '  "unsafe:crates/rsk-b/src/lib.rs#block:core-ptr-null-u8-read",')
    tree.edit("assurance/platform.toml", "and firmware/src/main.rs.",
              "firmware/src/main.rs and crates/rsk-b/src/lib.rs.")
    tree.edit("docs/unsafe.md", "Runtime sites: 2.", "Runtime sites: 3.")
    tree.edit("docs/unsafe.md", "### 1\u20132.", "### 1\u20133.")
    tree.git("add", "-A")
    tree.regenerate()
    assert only(tree.problems(), "names no site in crates/rsk-b/src/lib.rs")
    # And the green arm, so the rule is not "every file, always": naming it is
    # what settles it, and nothing else about the page changed.
    tree.append("docs/unsafe.md", "\nAlso `crates/rsk-b/src/lib.rs`.\n")
    assert tree.problems() == []


def test_the_page_may_not_name_a_file_that_carries_no_site(tree):
    """The other direction, and it was open: ⊆ only.

    Measured on the checkout, four `.rs` paths added to that page carry no site
    and were byte-identical at exit 0. A page longer than the tree reads as
    coverage of code that is gone, which is the same lie as the count being low.
    Only a PATH counts — the page's own `main.rs` shorthand is not a claim.
    """
    tree.append("docs/unsafe.md", "\nAlso `crates/rsk-gone/src/lib.rs`.\n")
    assert only(tree.problems(), "names crates/rsk-gone/src/lib.rs, which carries no")
    tree.edit("docs/unsafe.md", "`crates/rsk-gone/src/lib.rs`", "`gone.rs`")
    assert tree.problems() == []


def test_one_row_may_not_answer_for_every_site(tree):
    """The finding this whole grouping half was written for.

    `covers` was checked for EXISTENCE both ways and nothing else, so measured on
    the checkout: collapse all 31 site keys onto the one `discharged` row, empty
    the other eleven, and the output is byte-identical at exit 0 — one row
    standing for a whole page of justifications, under the strongest disposition
    the registry has. Forced here at two rows and two sites.
    """
    tree.edit(
        "assurance/platform.toml",
        'covers = [\n  "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",\n'
        '  "unsafe:firmware/src/main.rs#block:core-ptr-null-u8-read",\n]',
        'covers = []',
    )
    tree.edit(
        "assurance/platform.toml",
        'covers = ["backend:rsk-a/tear"]',
        'covers = [\n  "backend:rsk-a/tear",\n'
        '  "unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",\n'
        '  "unsafe:firmware/src/main.rs#block:core-ptr-null-u8-read",\n]',
    )
    problems = tree.problems()
    assert only(problems, "PLAT-STORE-001: covers an `unsafe` site in crates/rsk-a/src/lib.rs")
    assert only(problems, "PLAT-STORE-001: covers an `unsafe` site in firmware/src/main.rs")
    assert only(problems, "PLAT-STORE-001: covers 2 runtime `unsafe` site(s) and has no")
    assert only(problems, "PLAT-TOOLCHAIN-001: its docs/unsafe.md section spans 2 site(s)")


def test_a_row_names_the_file_of_every_site_it_covers(tree):
    """The half a row can be WRONG about, and six rows here already were.

    `PLAT-UNSAFE-006` covered a `core1.rs` site while its discharge named neither
    file; five more were the same shape. A row that does not say where its sites
    are can be grown to cover any of them with nothing to read.
    """
    tree.edit("assurance/platform.toml", "and firmware/src/main.rs.", "and elsewhere.")
    assert only(tree.problems(), "covers an `unsafe` site in firmware/src/main.rs and never names")
    # A PATH, not a substring: a superstring paid the first version of this rule,
    # while the page half of the SAME rule already compared path sets. Two
    # strengths for one rule is the weaker one being the rule.
    tree.edit("assurance/platform.toml", "and elsewhere.",
              "and https://example.invalid/xfirmware/src/main.rs.bak.")
    assert only(tree.problems(), "covers an `unsafe` site in firmware/src/main.rs and never names")
    # Green from any of its own fields, not the discharge alone: a `pending` row
    # has no `evidence` and a settled one has already listed its files there.
    tree.edit("assurance/platform.toml", "and https://example.invalid/xfirmware/src/main.rs.bak.",
              "and elsewhere.\"\nevidence = [\"firmware/src/main.rs\"]\nunused = \"")
    assert not only(tree.problems(), "covers an `unsafe` site in firmware/src/main.rs and never names")


def test_the_page_numbering_partitions_the_runtime_sites(tree):
    """Three spellings, each byte-identical at exit 0 on the checkout before this.

    A fabricated section claiming sites past the end, every heading collapsed
    onto one number, and a number used twice. The page's own ordinals ARE its
    partition of the sites, so a gap or a repeat is a site enumerated twice or
    not at all — and nothing else on the page says which.
    """
    tree.append("docs/unsafe.md", "\n### 3–7. Five sites that do not exist — `PLAT-TOOL-001`\n\n"
                                  "*Safe alternative:* none.\n*Containment:* none.\n")
    assert only(tree.problems(), "the numbered sections cover [1, 2, 3, 4, 5, 6, 7]")
    tree.edit("docs/unsafe.md", "### 3–7. Five sites that do not exist — `PLAT-TOOL-001`\n\n"
                                "*Safe alternative:* none.\n*Containment:* none.\n", "")
    tree.edit("docs/unsafe.md", "### 1–2.", "### 99.")
    assert only(tree.problems(), "the numbered sections cover [99]")


def test_a_numbered_section_owes_the_body_the_page_promises(tree):
    """A heading with its justification deleted keeps its number and its id.

    Measured on the checkout: deleting a justification body outright was
    byte-identical at exit 0. The two markers are this page's own opening
    sentence — every entry says why a safe alternative does not work and how the
    risk is contained — so their absence is the body's absence.
    """
    tree.edit("docs/unsafe.md", "*Safe alternative:* none, the fixture needs a site.\n", "")
    assert only(tree.problems(), "carries no `*Safe alternative:*`")
    tree.edit("docs/unsafe.md", "*Containment:* the fixture never runs.\n", "")
    assert only(tree.problems(), "carries no `*Containment:*`")


def test_a_numbered_heading_with_no_row_id_is_a_finding(tree):
    """The spelling a second review walked the whole anti-collapse rule through.

    With only the span rule, a heading that carries no id matches nothing and so
    is constrained by nothing: collapse every site onto one row, delete the ids
    from the headings you emptied, and the page still shows its justifications
    while every rule below applies to the one heading left. Measured on the
    checkout at eight headings and 22 sites: byte-identical, exit 0.
    """
    tree.edit("docs/unsafe.md", " — `PLAT-TOOLCHAIN-001`", "")
    assert only(tree.problems(), "section `1` carries no `PLAT-…` id")


def test_a_section_the_page_does_not_show_does_not_count(tree):
    """A rule that reads a page as a string reads what the page does not show.

    Measured on the checkout, both byte-identical at exit 0: a whole numbered
    justification wrapped in `<!-- -->`, and the same one inside a `~~~` fence.
    The built book loses the justification; the gate counted it as present, with
    both markers, numbered.
    """
    for hide, show in (("<!--\n", "-->\n"), ("~~~text\n", "~~~\n")):
        tree.edit("docs/unsafe.md", "### 1–2.", f"{hide}### 1–2.")
        tree.append("docs/unsafe.md", show)
        assert only(tree.problems(), "the numbered sections cover nothing"), hide
        tree.edit("docs/unsafe.md", f"{hide}### 1–2.", "### 1–2.")
        tree.edit("docs/unsafe.md", show, "")
    assert tree.problems() == []


def test_the_page_does_not_owe_a_site_for_an_upstream_link(tree):
    """The ⊇ direction's false red, and the carve-out is URLs and nothing wider.

    `docs/unsafe.md` links embassy and cortex-m; a permalink ending in `.rs` is a
    claim about somebody else's tree, and unstripped it reddened this gate for a
    file that could never carry a site here. The green arm is paired with the red
    one so the carve-out is not "any path with a dot in it".
    """
    tree.append("docs/unsafe.md", "\nSee https://example.invalid/a/b/gpio.rs for the pattern.\n")
    assert tree.problems() == []
    tree.append("docs/unsafe.md", "\nAnd `vendor/a/b/gpio.rs`.\n")
    assert only(tree.problems(), "names vendor/a/b/gpio.rs, which carries no")


def test_a_numbered_section_names_a_row_of_the_registry(tree):
    """The anchor, both ways: an id that resolves to nothing anchors nothing, and
    two headings over one row is a grouping the registry does not make."""
    tree.edit("docs/unsafe.md", "`PLAT-TOOLCHAIN-001`", "`PLAT-BOGUS-999`")
    assert only(tree.problems(), "names PLAT-BOGUS-999, which is not a row of")
    tree.edit("docs/unsafe.md", "`PLAT-BOGUS-999`", "`PLAT-TOOLCHAIN-001`")
    tree.edit("docs/unsafe.md", "### 1–2. The null reads",
              "### 1. The first null read — `PLAT-TOOLCHAIN-001`\n\n"
              "*Safe alternative:* none.\n*Containment:* none.\n\n"
              "### 2. The null reads")
    assert only(tree.problems(), "PLAT-TOOLCHAIN-001 has two numbered sections")


def test_a_build_script_site_is_not_a_runtime_site(tree):
    """The page's own partition, derived. A build-script `unsafe` is host-side
    and never in the image, and that page files it apart from the numbered
    sites — so counting it would make the page's honest number red."""
    tree.write("crates/rsk-a/build.rs", UNSAFE_RS)
    tree.edit("assurance/platform.toml",
              '"unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",',
              '"unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",\n'
              '  "unsafe:crates/rsk-a/build.rs#block:core-ptr-null-u8-read",')
    tree.edit("assurance/platform.toml", "and firmware/src/main.rs.",
              "firmware/src/main.rs and crates/rsk-a/build.rs.")
    # Named on the page like the real build scripts are — the file half of the
    # rule is about EVERY file with a site, and only the COUNT is partitioned.
    tree.append("docs/unsafe.md", "\nBuild-time: `crates/rsk-a/build.rs`.\n")
    tree.git("add", "-A")
    tree.regenerate()
    assert tree.problems() == []
    assert platform_gate.runtime_sites(platform_gate.candidates(tree.root)) == [
        "crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",
        "firmware/src/main.rs#block:core-ptr-null-u8-read",
    ]


def test_a_declaration_site_is_not_a_runtime_site(tree):
    """The other half of that partition: `unsafe extern` and `#[unsafe(…)]` mark
    declarations rather than operations, and the page files them with the build
    scripts. Both kinds, because one of them alone was the first version."""
    tree.append(
        "crates/rsk-a/src/lib.rs",
        'unsafe extern "C" {\n    fn r();\n}\n#[unsafe(link_section = ".x")]\npub static Z: u8 = 0;\n',
    )
    tree.edit("assurance/platform.toml",
              '"unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",',
              '"unsafe:crates/rsk-a/src/lib.rs#block:core-ptr-null-u8-read",\n'
              '  "unsafe:crates/rsk-a/src/lib.rs#extern:fn-r",\n'
              '  "unsafe:crates/rsk-a/src/lib.rs#attr:link_section-x-pub-static-z-u8",')
    tree.regenerate()
    assert tree.problems() == []
