# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `narrow_gate.py` is verified against.

Every rule is broken once and the break must be the finding it claims to be,
then the cases that must stay GREEN close the other direction: a guard that
cannot go green is deleted as fast as one that cannot go red.

The fixture is A COPY OF THE REAL LEDGER and the real neighbours it resolves
against, not a mini-tree, and that is deliberate rather than lazy.
[`narrow_gate.ROSTER_FLOOR`] is this tree's own count, so a synthetic roster
would be under it before a case touched it and the only way to test any other
rule would be to hand `audit` a smaller floor — which is the shape this tree has
already measured as a hole: a ceiling a case patches down is a ceiling whose
shipped value nothing exercises. Copying means the numbers under test are the
numbers the gate runs with, and the floor is reached by REMOVING a row, which
is the direction it exists for.

The one thing handed in rather than copied is the tier list: `run-tlc.sh
--tiers` needs the whole `formal/` and every module in it, so the fixture would
be the checkout. It is a parameter of `audit` for the same reason the floors are.
"""

import pathlib
import shutil
import subprocess
import sys
import tomllib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import narrow_gate

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The configurations the shipped ledger cites, which are the only `formal/*.cfg`
#: the fixture needs: the rules are about the ones a row RESTS on.
CITED = (
    "Solo_BugUvNotRqdIgnoresRk.cfg",
    "Solo_BugTokenlessIgnoresAlwaysUv.cfg",
    "SeamSolo_BugRemoveCodeUnvalidated.cfg",
    "SeamSolo_BugPinFreshOutlivesPin.cfg",
    "SeamSolo_BugPinFreshNotSpent.cfg",
    "SeamSolo_BugSigPinNotSpent.cfg",
)


def cited_sources(root):
    """Every `crates/` file a `test:` citation of the shipped ledger resolves to.

    DERIVED, not listed, and that is the difference between this and the tuple
    above: a `.cfg` the ledger stops citing is a file the fixture copies for
    nothing, while a `test:` row whose file the fixture does NOT copy reddens
    four unrelated cases with `the complementary source obligation ... has been
    deleted` -- a green case failing for a reason that is not the case. Measured:
    `NAR-OTP-COUNTER` arriving with `crates/rsk-otp/src/counter_kani.rs` did
    exactly that, while `narrow_gate.py` itself stayed green on the real tree.
    """
    where = narrow_gate.test_functions(root)
    ledger = tomllib.loads((root / narrow_gate.LEDGER).read_text(encoding="utf-8"))
    return sorted(
        {
            where[name]
            for entry in ledger.get("abstraction", [])
            for kind, _, name in (str(c).partition(":") for c in entry.get("cites", []))
            if kind == "test" and name in where
        }
    )


class Tree:
    """The real ledger, the real page and everything they resolve against."""

    def __init__(self, root):
        self.root = root
        for rel in (
            "assurance/abstractions.toml",
            "assurance/assumptions.toml",
            "assurance/threat_clauses.toml",
            "assurance/platform.toml",
            "assurance/configurations.toml",
            "formal/README.md",
            "formal/scopes.txt",
            "formal/floors.txt",
            *cited_sources(ROOT),
        ):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / rel, root / rel)
        for name in CITED:
            shutil.copy(ROOT / "formal" / name, root / "formal" / name)
        self.git("init", "-q")
        self.git("add", "-A")

    def git(self, *args):
        subprocess.run(
            ["git", "-C", str(self.root), *args], check=True, capture_output=True
        )

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git("add", "-A")

    def edit(self, rel, old, new, count=1):
        """Replace `old` exactly `count` times, failing loudly if the tree moved.

        The assertion is the case: a `str.replace` that matches nothing leaves
        the fixture unpatched and the case then proves that an unmutated tree is
        green, which this tree has measured happening.
        """
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == count, (
            f"{rel} says {old!r} {text.count(old)} times, not {count}"
        )
        path.write_text(text.replace(old, new))
        self.git("add", "-A")

    def edit_after(self, rel, anchor, old, new):
        """Replace the FIRST `old` after `anchor`. For a value a ledger repeats.

        `status = "pending"` is fifty-odd rows of `platform.toml`, so a
        whole-file replace is not the mutation, and appending a second `status`
        key is not it either: that is a DUPLICATE KEY, the file stops parsing,
        and every row citing it reports `carries no PLAT-…`. Measured — the first
        spelling of the case below was exactly that red, for the wrong reason.
        """
        path = self.root / rel
        text = path.read_text()
        start = text.index(anchor)
        at = text.index(old, start)
        path.write_text(text[:at] + new + text[at + len(old):])
        self.git("add", "-A")

    def entry(self, rid, field, value):
        """Rewrite one `'''`-quoted field of one `[[abstraction]]`, by id.

        Anchored on the entry rather than on the text, because `why` and `body`
        are prose blocks that no neighbouring literal identifies.
        """
        path = self.root / narrow_gate.LEDGER
        text = path.read_text()
        start = text.index(f'id = "{rid}"')
        head = text.index(f"{field} = '''", start) + len(f"{field} = '''")
        tail = text.index("'''", head)
        path.write_text(text[:head] + f"\n{value}\n" + text[tail:])
        self.git("add", "-A")

    def drop_entry(self, rid):
        path = self.root / narrow_gate.LEDGER
        text = path.read_text()
        start = text.index(f'[[abstraction]]\nid = "{rid}"')
        after = text.find("[[abstraction]]", start + 16)
        assert after > start, f"{rid} is the last entry; the case needs another"
        path.write_text(text[:start] + text[after:])
        self.git("add", "-A")

    def problems(self, tiers=CITED, **floors):
        return narrow_gate.audit(self.root, set(tiers), **floors)[0]

    def regenerate(self):
        """`--write` after a ledger edit, so a case can ask what survives it."""
        narrow_gate.run(self.root, write=True)
        self.git("add", "-A")


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    return [p for p in problems if needle in p]


# --- the copied tree, and the real one ---------------------------------------


def test_the_copied_tree_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    """The control the fixture cannot be: the tiers come from the runner here."""
    assert narrow_gate.audit(ROOT)[0] == []


# --- the roster itself -------------------------------------------------------


def test_a_deleted_entry_is_under_the_floor(tree):
    tree.drop_entry("NAR-TWO-TRANSPORTS")
    assert only(tree.problems(), f"under the floor of {narrow_gate.ROSTER_FLOOR}")


def test_a_deleted_entry_stays_red_after_the_page_is_regenerated(tree):
    """The silent-deletion path, and the reason the floor stands ON the count:
    drop a row, run `--write`, and the page agrees with the ledger again — the
    byte diff has nothing to say and only the floor is left."""
    tree.drop_entry("NAR-TWO-TRANSPORTS")
    tree.regenerate()
    problems = tree.problems()
    assert only(problems, "under the floor")
    assert not only(problems, "not what the generator writes")


def test_an_added_abstraction_is_not_a_finding(tree):
    """The floor refuses SHRINKING, not growth: a newly recognised abstraction
    is registered by writing it down, not by editing a number too."""
    text = (tree.root / narrow_gate.LEDGER).read_text()
    tree.write(
        str(narrow_gate.LEDGER),
        text
        + "\n[[abstraction]]\nid = \"NAR-EXTRA\"\ndisposition = \"accepted\"\n"
        "cites = [\"threat:TM-HOST-TWO-TRANSPORTS\"]\n"
        "why = '''\nTM-HOST-TWO-TRANSPORTS is the clause this eleventh row would"
        " rest on, said in enough words to be a reason.\n'''\n"
        "body = '''\n- **An eleventh narrowing**, written down rather than"
        " remembered.\n'''\n",
    )
    tree.regenerate()
    assert tree.problems() == []


def test_an_id_recorded_twice(tree):
    text = (tree.root / narrow_gate.LEDGER).read_text()
    start = text.index('[[abstraction]]\nid = "NAR-TWO-TRANSPORTS"')
    after = text.index("[[abstraction]]", start + 16)
    tree.write(str(narrow_gate.LEDGER), text + "\n" + text[start:after])
    assert only(tree.problems(), "recorded twice")


def test_a_field_nothing_reads(tree):
    tree.edit(
        str(narrow_gate.LEDGER),
        'id = "NAR-TWO-TRANSPORTS"',
        'id = "NAR-TWO-TRANSPORTS"\nseverity = "low"',
    )
    assert only(tree.problems(), "which nothing reads")


def test_a_body_carrying_two_bullets(tree):
    tree.entry(
        "NAR-TWO-TRANSPORTS",
        "body",
        "- **Two transports** (CTAPHID, CCID).\n- **And a second one smuggled in.**",
    )
    assert only(tree.problems(), "opens 2 bullets, not 1")


# --- the `why`, which was checked for non-emptiness everywhere else -----------


def test_banana_is_not_a_reason(tree):
    """The measured case. `why = "banana"` is exit 0 on `deleter_gate.py` and on
    `ghost_gate.py` today, because both ask `.strip()` and nothing else."""
    tree.entry("NAR-TWO-TRANSPORTS", "why", "banana")
    problems = tree.problems()
    assert only(problems, f"distinct word(s), under {narrow_gate.FLOOR_WORDS}")
    assert only(problems, "never names `TM-HOST-TWO-TRANSPORTS`")


def test_a_long_reason_that_names_no_artifact(tree):
    """The half the word floor cannot carry: prose of any length that is not
    ABOUT the evidence. A rule that only counted words would pass this."""
    tree.entry(
        "NAR-TWO-TRANSPORTS",
        "why",
        "This has comfortably more than the required number of words in it, and"
        " says nothing whatever about which artifact the disposition rests on.",
    )
    problems = tree.problems()
    assert only(problems, "never names `TM-HOST-TWO-TRANSPORTS`")
    assert not only(problems, "under")


def test_a_reason_naming_only_one_of_two_artifacts(tree):
    """Half-adopted is the shape a column comes to look complete in."""
    tree.entry(
        "NAR-GATE-FIDS",
        "why",
        "PLAT-MODEL-009 is the EF_MINPINLEN question and it is still pending in"
        " the platform ledger, which is the whole of the disposition here.",
    )
    assert only(tree.problems(), "never names `PLAT-MODEL-011`")


# --- the disposition, and what each may rest on ------------------------------


def test_a_disposition_outside_the_vocabulary(tree):
    tree.edit(
        str(narrow_gate.LEDGER),
        'id = "NAR-TWO-TRANSPORTS"\ndisposition = "accepted"',
        'id = "NAR-TWO-TRANSPORTS"\ndisposition = "mostly fine"',
    )
    assert only(tree.problems(), "is not one of")


def test_a_closure_resting_on_a_settling_question(tree):
    """`closed` may not rest on an artifact that says the question is OPEN."""
    tree.edit(
        str(narrow_gate.LEDGER),
        'id = "NAR-BUTTON-BUILD"\ndisposition = "open-obligation"',
        'id = "NAR-BUTTON-BUILD"\ndisposition = "closed"',
    )
    assert only(tree.problems(), "may rest on ['cfg', 'platform']")


def test_a_citation_that_is_not_a_kind_and_a_name(tree):
    tree.edit(
        str(narrow_gate.LEDGER),
        'cites = ["threat:TM-HOST-TWO-TRANSPORTS"]',
        'cites = ["TM-HOST-TWO-TRANSPORTS"]',
    )
    assert only(tree.problems(), "is not a `<kind>:<name>` citation")


def test_a_row_that_cites_nothing(tree):
    tree.edit(
        str(narrow_gate.LEDGER),
        'cites = ["threat:TM-HOST-TWO-TRANSPORTS"]',
        "cites = []",
    )
    assert only(tree.problems(), "cites nothing")


# --- each citation kind, held against the tree -------------------------------


def test_a_mutant_configuration_that_is_gone(tree):
    (tree.root / "formal/SeamSolo_BugRemoveCodeUnvalidated.cfg").unlink()
    tree.git("add", "-A")
    assert only(tree.problems(), "which is not in the tree")


def test_a_mutant_no_longer_required_red(tree):
    """A closure resting on a mutant `floors.txt` lets come back GREEN is the
    paragraph again, one file over."""
    tree.edit("formal/floors.txt", "SeamSolo_*.cfg", "SeamSoloOther_*.cfg")
    assert only(tree.problems(), "is not required RED")


def test_a_mutant_no_tier_runs(tree):
    """Twenty Kani harnesses sat green in this tree because nothing ran them."""
    assert only(
        tree.problems(tiers=[c for c in CITED if c != "Solo_BugUvNotRqdIgnoresRk.cfg"]),
        "is in no tier",
    )


def test_a_scope_row_that_bounds_nothing(tree):
    tree.edit(
        "formal/scopes.txt",
        "RSKeyStore             Fids                   2   NoRecordLostToMetaWrite",
        "RSKeyStore             Fids                   -   -",
    )
    tree.edit(
        str(narrow_gate.LEDGER),
        '"scopes:RSKeySecurityState/Channels",',
        '"scopes:RSKeyStore/Fids",',
    )
    tree.entry(
        "NAR-CARDINALITY",
        "why",
        "RSKeyStore/Fids and RSKeySecurityState/RPs are where the cardinality is"
        " recorded, which is what this disposition rests on.",
    )
    assert only(tree.problems(), "no measured minimum")


def test_a_standing_assumption_that_is_gone(tree):
    tree.edit("assurance/assumptions.toml", 'constant = "WidePerms"',
              'constant = "WidePermsRenamed"')
    assert only(tree.problems(), "carries no `WidePerms`")


def test_a_complementary_unit_test_that_is_gone(tree):
    tree.edit(
        "crates/rsk-device/src/presence_tests.rs",
        "fn w8_a_cancel_that_raced_in_does_not_leak_into_the_next_wait()",
        "fn w8_renamed_out_from_under_the_disposition()",
    )
    assert only(tree.problems(), "the complementary")


def test_a_threat_clause_that_is_gone(tree):
    tree.edit("assurance/threat_clauses.toml", 'id = "TM-HOST-TWO-TRANSPORTS"',
              'id = "TM-HOST-TWO-TRANSPORTS-RENAMED"')
    assert only(tree.problems(), "carries no `TM-HOST-TWO-TRANSPORTS`")


def test_a_platform_question_that_has_been_settled(tree):
    """The rule that makes `open-obligation` mean something: when the question
    next door is answered, this row has to be re-decided rather than carried."""
    tree.edit_after(
        "assurance/platform.toml",
        'id = "PLAT-MODEL-009"',
        'status = "pending"',
        'status = "discharged"',
    )
    assert only(tree.problems(), "rather than `pending`")


def test_a_settling_question_that_is_gone(tree):
    tree.edit("assurance/configurations.toml", 'column = "largeblob-ext"',
              'column = "largeblob-ext-renamed"')
    assert only(tree.problems(), "no open settling question")


# --- the page ----------------------------------------------------------------


def test_a_hand_edit_inside_the_region(tree):
    """The trap this file was written against: the region SAYS it is generated,
    and nothing here reads that line — the bytes are rebuilt and compared."""
    tree.edit("formal/README.md", "- **Two transports** (CTAPHID, CCID).",
              "- **Three transports** (CTAPHID, CCID, OTP).")
    assert only(tree.problems(), "not what the generator writes")


def test_a_bullet_deleted_from_the_page(tree):
    text = (tree.root / "formal/README.md").read_text()
    start = text.index("- **Two transports** (CTAPHID, CCID).")
    end = text.index("\n- **OATH", start)
    tree.write("formal/README.md", text[:start] + text[end + 1:])
    assert only(tree.problems(), "not what the generator writes")


def test_the_markers_removed(tree):
    tree.edit("formal/README.md", narrow_gate.START + "\n", "")
    assert only(tree.problems(), "needs exactly one")


def test_a_bullet_typed_beside_the_generated_one(tree):
    tree.edit(
        "formal/README.md",
        f"\n{narrow_gate.START}",
        "\n- **An eleventh narrowing**, typed straight onto the page.\n"
        f"{narrow_gate.START}",
    )
    assert only(tree.problems(), "outside the generated region")


def test_the_roster_copied_onto_another_page(tree):
    """The completeness half — the half every guard in this tree has failed."""
    tree.write("docs/copy.md", f"{narrow_gate.HEADING}\n\n- **One credential**\n")
    assert only(tree.problems(), "carries this roster's heading")


def test_the_section_renamed_away(tree):
    tree.edit("formal/README.md", narrow_gate.HEADING, "### Some narrowing notes")
    assert only(tree.problems(), "has stopped naming it at all")


def test_prose_about_narrowness_elsewhere_is_not_a_copy(tree):
    """The rule is the heading, not a keyword hunt: a page that DISCUSSES the
    narrow list is what a doc tree is for, and reddening it would get the rule
    deleted."""
    tree.write(
        "docs/notes.md",
        "The model is narrower than the firmware in several places; formal/README.md"
        " lists them and assurance/abstractions.toml disposes of each.\n",
    )
    assert tree.problems() == []


def test_a_registered_id_written_into_the_ledger(tree):
    """The trap one layer down. `claims_gate.mask_regions` blanks every marked
    region by SHAPE, so prose that becomes a region leaves the claims row's
    sight — and this ledger's whole output is a region."""
    tree.entry(
        "NAR-TWO-TRANSPORTS",
        "why",
        "TM-HOST-TWO-TRANSPORTS is the clause, and SEC-FIDO-002 is PROVEN over"
        " both of the transports it names.",
    )
    assert only(tree.problems(), "names `SEC-FIDO-002`")


# --- what the adversarial review broke, kept broken -------------------------


@pytest.mark.parametrize(
    "spelling",
    (
        "SEC-FIDO-**001**",
        "SEC‑FIDO‑001",
        "SEC-FIDO-0​01",
    ),
)
def test_the_id_evasions_claims_gate_already_names(tree, spelling):
    """Matched on the RAW string, all three walked through and the page
    published `PROVEN` beside a registered id at exit 0 on both rows. The fix is
    to match what `claims_gate` matches: its own `normalise`."""
    tree.entry(
        "NAR-TWO-TRANSPORTS",
        "why",
        f"TM-HOST-TWO-TRANSPORTS is the clause, and {spelling} is PROVEN over"
        " both transports it names.",
    )
    assert only(tree.problems(), "names `SEC-FIDO-001`")


def test_banana_with_the_names_pasted_in(tree):
    """The review's refutation of the first spelling: a word count and a
    substring test are both satisfied by filler with the citations pasted into
    it. A reason is six DIFFERENT words."""
    tree.entry(
        "NAR-CARDINALITY",
        "why",
        "banana banana banana RSKeySecurityState/Channels banana banana banana"
        " RSKeySecurityState/RPs banana banana banana banana.",
    )
    problems = tree.problems()
    assert only(problems, "distinct word(s), under")
    assert not only(problems, "never names")


def test_a_filler_row_cannot_take_a_deleted_one_s_place(tree):
    """A floor on a COUNT cannot hold a roster. Measured on the count-only
    version: this swap kept it at ten and green, with the bullet gone."""
    tree.drop_entry("NAR-TWO-TRANSPORTS")
    text = (tree.root / narrow_gate.LEDGER).read_text()
    tree.write(
        str(narrow_gate.LEDGER),
        text
        + "\n[[abstraction]]\nid = \"NAR-FILLER\"\ndisposition = \"accepted\"\n"
        "cites = [\"threat:TM-HOST-TWO-TRANSPORTS\"]\n"
        "why = '''\nTM-HOST-TWO-TRANSPORTS is named here only so that this filler"
        " row satisfies every other rule.\n'''\n"
        "body = '''\n- **Nothing in particular is narrowed here.**\n'''\n",
    )
    tree.regenerate()
    assert only(tree.problems(), "NAR-TWO-TRANSPORTS is a registered abstraction")


def test_a_pinned_scope_with_no_row(tree):
    """The derived half: a scope `scope_gate.MEASURED_MINIMA` pins is a
    narrowing somebody measured, so it owes a disposition here."""
    tree.edit(
        str(narrow_gate.LEDGER),
        'cites = ["scopes:RSKeyStore/Fids"]',
        'cites = ["scopes:RSKeySecurityState/RPs"]',
    )
    tree.entry(
        "NAR-STORE-FIDS",
        "why",
        "RSKeySecurityState/RPs is cited here instead, which leaves the pinned"
        " store minimum with no row at all.",
    )
    assert only(tree.problems(), "no row cites `scopes:RSKeyStore/Fids`")


def test_a_runner_that_cannot_list_its_tiers(tree):
    """It soft-failed: with `--tiers` exiting non-zero every `cfg:` citation
    lost its "something runs it" half and the row printed `ok`."""
    runner = tree.root / "formal/run-tlc.sh"
    runner.write_text("#!/bin/sh\nexit 3\n")
    runner.chmod(0o755)
    tree.git("add", "-A")
    assert only(narrow_gate.audit(tree.root)[0], "printed no tier list")
