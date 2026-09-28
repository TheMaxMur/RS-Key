# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `claims_gate.py`.

The fixture is the SHIPPED corpus with one sentence appended, because the rule is
about what a person types into a real page and a synthetic tree would prove it
about prose nobody has to keep true. Every case here appends and asserts, or
reverts one rule and asserts the shipped tree goes red.
"""

import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import claims_gate  # noqa: E402

pytestmark = pytest.mark.assurance

ROOT = claims_gate.ROOT
PAGE = "README.md"


@pytest.fixture
def tree(tmp_path):
    """A checkout carrying every page the corpus reads, plus the registry.

    Copied rather than synthesised, and `git init`ed because the corpus is
    `git ls-files`: a walk would descend into `target/` and into any agent
    worktree, which is the defect `deleter_gate` shipped with.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    for rel in listing:
        if not rel:
            continue
        source = ROOT / rel
        if not source.is_file():
            continue
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, target)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    # `run_count_gate.tracked` asks `git ls-files` for the CACHE, so a fixture
    # that only `init`s answers an empty corpus and every rule here passes over
    # nothing — measured, and it is the same "the scan found none" shape the
    # floors exist for.
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def findings(root, **kwargs):
    return claims_gate.audit(root, **kwargs)[0]


def say(root, sentence, page=PAGE):
    path = root / page
    path.write_text(path.read_text() + "\n\n" + sentence + "\n")


def test_this_checkout_is_green():
    assert findings(ROOT) == []


def test_the_fixture_is_this_checkout(tree):
    assert findings(tree) == []


# The measured failure this row exists for: four false hand-written sentences,
# including this one in README.md, at EXIT=0 on all eight gates.
@pytest.mark.parametrize(
    "sentence",
    [
        "`SEC-FIDO-001` is PROVEN on hardware.",
        "The store slice leaves `SEC-STORE-005` BOUNDED today.",
        "`SEC-FIDO-007` is MEASURED on an RP2350 A4 board.",
        "`SEC-FIDO-002` is BINARY-CHECKED against the shipped ELF.",
        "We rate `SEC-STORE-001` PROVEN-SOURCE after the store slice.",
    ],
)
def test_a_status_no_row_holds_is_refused(tree, sentence):
    say(tree, sentence)
    reported = findings(tree)
    assert any("is a copy, and this one is not a copy of anything" in f for f in reported), reported


def test_a_true_status_is_kept(tree):
    """The half a `generated or refused` rule would have cost: a hand-written
    sentence that is TRUE does work no generated table does, and it stays."""
    say(tree, "`SEC-FIDO-001` is BOUNDED, which is why the slice could close.")
    assert findings(tree) == []


def test_a_true_status_stops_being_able_to_rot(tree):
    """And what it buys: the same sentence reddens when the registry moves."""
    say(tree, "`SEC-FIDO-001` is BOUNDED, which is why the slice could close.")
    registry = tree / claims_gate.REGISTRY
    registry.write_text(
        registry.read_text().replace(
            'id = "SEC-FIDO-001"\nname = "NoAuthorizationBypass"\nstatus = "BOUNDED"',
            'id = "SEC-FIDO-001"\nname = "NoAuthorizationBypass"\nstatus = "MODELLED-ONLY"',
            1,
        )
    )
    reported = findings(tree)
    assert any("SEC-FIDO-001" in f and "BOUNDED" in f for f in reported), reported


def test_a_transcribed_vector_row_is_refused(tree):
    """The rule the sentence rule cannot cover: the STATUS half stays true while a
    column rots. `docs/authorization-slice.md` carried three such rows and their
    `co` column said 0 where the tree says 1."""
    say(tree, "| `SEC-FIDO-007` | MODELLED-ONLY | 3 | 1 | 0 | 0 | 0 | 0 | 1 |")
    reported = findings(tree)
    assert any("transcribed row" in f for f in reported), reported


def test_two_numbers_beside_an_id_are_ordinary_prose(tree):
    """The floor under that rule, and why it is 3: `2 of 3 configurations` is a
    sentence, not a table."""
    say(tree, "`SEC-FIDO-007` is MODELLED-ONLY and 2 of 3 configurations check it.")
    assert findings(tree) == []


def test_a_generated_region_is_not_hand_written(tree):
    """Every generator in this tree marks its output; a rule that read those as
    prose would demand an author fix a table they may not edit."""
    say(
        tree,
        "<!-- claims-test:start -->\n"
        "| `SEC-FIDO-007` | PROVEN | 3 | 1 | 1 | 0 | 0 | 0 | 1 |\n"
        "<!-- claims-test:end -->",
    )
    assert findings(tree) == []


def test_a_wholly_generated_page_is_not_hand_written(tree):
    """`docs/assurance-vector.md` says so in its own first lines, and its numbers
    are already held by the generator that writes them."""
    (tree / "docs/assurance-vector.md").write_text(
        "<!-- Generated by scripts/evidence_gate.py --write -->\n"
        "| `SEC-FIDO-007` | PROVEN | 3 | 1 | 1 | 0 |\n"
    )
    assert findings(tree) == []


def test_an_unregistered_id_is_another_registry_s_business(tree):
    say(tree, "`PLAT-TOOL-004` is PROVEN and `TM-HOST-GATES` is MEASURED.")
    assert findings(tree) == []


def test_a_contrastive_status_must_name_its_subject(tree):
    """Words are scoped to the sentence, ids to the lines it touches — so a
    contrast whose second half names nobody is judged against the id beside it,
    and refused. Found on the shipped tree, not invented here: `formal/README.md`
    said "`SEC-STORE-002` is `BOUNDED`; the other three store properties stay
    `MODELLED-ONLY`" — and the family has six members, so the sentence was also
    wrong by two."""
    say(
        tree,
        "`SEC-FIDO-001` is BOUNDED and its store siblings are MODELLED-ONLY.",
    )
    reported = findings(tree)
    assert any("MODELLED-ONLY" in f and "SEC-FIDO-001" in f for f in reported), reported


def test_naming_the_subject_is_what_makes_the_contrast_legal(tree):
    """The repair the rule asks for, and the whole of it."""
    say(
        tree,
        "`SEC-FIDO-001` is BOUNDED and `SEC-STORE-005` is MODELLED-ONLY.",
    )
    assert findings(tree) == []


def test_a_table_row_is_not_one_sentence(tree):
    """A cell boundary ends the window: reading a whole row as one let a status in
    the third column excuse a word in the ninth."""
    say(tree, "| `SEC-FIDO-001` | BOUNDED | PROVEN-SOURCE |")
    reported = findings(tree)
    assert any("PROVEN-SOURCE" in f for f in reported), reported


def test_the_shipped_corpus_is_over_its_floor():
    assert len(claims_gate.corpus(ROOT)) >= claims_gate.CORPUS_FLOOR


def test_a_corpus_that_shrank_is_a_rule_that_stopped_looking(tree):
    reported = findings(tree, corpus_floor=10_000)
    assert any("under the floor of 10000" in f for f in reported), reported


def test_a_scanner_that_matches_nothing_is_not_a_clean_tree(tree):
    """The floor is on the SCANNER. Driven by asking for more true copies than the
    tree holds, which is what a masking bug or a dead vocabulary looks like."""
    reported = findings(tree, claim_floor=10_000)
    assert any("true status copy" in f for f in reported), reported


def test_every_registry_status_is_in_the_vocabulary():
    """A status added to the registry and not to `CLASSES` is a word this row
    silently stops reading — the exact failure the file is about, one level in."""
    registry = tomllib.loads((ROOT / claims_gate.REGISTRY).read_text(encoding="utf-8"))
    used = {str(row.get("status")) for row in registry.get("property", [])}
    assert used <= set(claims_gate.CLASSES), sorted(used - set(claims_gate.CLASSES))


def test_the_vocabulary_is_matched_longest_first():
    """`PROVEN-SOURCE` read as `PROVEN` plus a suffix would report the wrong word
    and, worse, would let `PROVEN-SOURCE` pass wherever `PROVEN` is legal."""
    order = list(claims_gate.CLASSES)
    for shorter in order:
        for longer in order:
            if longer != shorter and longer.startswith(shorter):
                assert order.index(longer) < order.index(shorter), (shorter, longer)


def test_the_id_pattern_reaches_the_clause_rows():
    """`SEC-FIDO-006A` is a registry row of its own, and a pattern that stopped at
    the digits would exempt three P0-launch ids."""
    registry = tomllib.loads((ROOT / claims_gate.REGISTRY).read_text(encoding="utf-8"))
    for row in registry.get("property", []):
        assert claims_gate.ID.fullmatch(str(row["id"])), row["id"]


def test_main_prints_a_summary_and_reports_findings(tree, capsys, monkeypatch):
    assert claims_gate.main() == 0
    assert capsys.readouterr().out.startswith("claims-gate: ok —")
    say(tree, "`SEC-FIDO-001` is PROVEN on hardware.")
    monkeypatch.setattr(claims_gate, "ROOT", tree)
    assert claims_gate.main() == 1
    assert "PROVEN" in capsys.readouterr().err


def test_the_page_that_carried_the_measured_rows_no_longer_does():
    """`docs/authorization-slice.md`'s three transcribed rows are the reason this
    file exists; a case asserts they are gone rather than merely that the row is
    green, because the row would also be green if the scan stopped reading."""
    page = (ROOT / "docs/authorization-slice.md").read_text()
    assert not re.search(r"\|\s*`SEC-FIDO-00\d`\s*\|\s*(BOUNDED|MODELLED-ONLY)\s*\|", page)
    assert "assurance-vector.md" in page


# ---- the sentence the Definition of done requires -----------------------------
#
# Four pages said it in FOUR spellings — "**not** make RS-Key formally verified",
# "RS-Key is not formally verified", and two more — so nothing could hold it, and
# deleting all four left every gate green. One spelling now, and the three pages
# carrying the MOST registered ids are generated, so their generators emit it.


def test_a_page_of_claims_without_the_disclaimer_is_refused(tree):
    page = tree / "docs/store-refinement.md"
    page.write_text(
        page.read_text().replace("**RS-Key is not formally verified**", "RS-Key is fine")
    )
    reported = findings(tree)
    assert any("does not say" in f and "store-refinement" in f for f in reported), reported


def test_the_bolded_spelling_counts(tree):
    """Emphasis is stripped before matching, so `**not**` reads the same. Nothing
    else is normalised: a rule that accepts any paraphrase accepts the paraphrase
    that drops the word "not"."""
    page = tree / "docs/store-refinement.md"
    page.write_text(
        page.read_text().replace(
            "**RS-Key is not formally verified**", "RS-Key **is not** formally verified"
        )
    )
    assert findings(tree) == []


def test_a_paraphrase_does_not_count(tree):
    page = tree / "docs/store-refinement.md"
    page.write_text(
        page.read_text().replace(
            "**RS-Key is not formally verified**",
            "this does not make RS-Key formally verified",
        )
    )
    reported = findings(tree)
    assert any("does not say" in f and "store-refinement" in f for f in reported), reported


def test_the_generated_pages_are_asked_too(tree):
    """The rule reads `published`, not `corpus`: the three pages naming the most
    ids are generated whole, and a rule over the hand-written residue would ask
    the sentence of everyone except the pages a reader most likely reads."""
    page = tree / "docs/assurance-vector.md"
    page.write_text(page.read_text().replace("RS-Key is not formally verified", "x"))
    reported = findings(tree)
    assert any("assurance-vector" in f and "does not say" in f for f in reported), reported


def test_a_page_naming_two_ids_is_not_a_summary(tree):
    say(tree, "`SEC-FIDO-001` and `SEC-FIDO-002` are both BOUNDED.", page="SECURITY.md")
    assert findings(tree) == []


def test_the_generators_emit_the_sentence_rather_than_a_hand_written_copy():
    """A copy in the page and not in the generator is one `--write` from gone —
    and three copies of the paragraph would be three places to drop it from, so
    the three generators emit the ONE in `claims_gate`."""
    for gate in ("evidence_gate.py", "matrix_gate.py", "platform_gate.py"):
        source = (ROOT / "scripts" / gate).read_text(encoding="utf-8")
        assert "claims_gate.DISCLAIMER_PARAGRAPH" in source, gate
        assert "RS-Key is not formally verified" not in source, f"{gate} keeps a copy"
    assert claims_gate.DISCLAIMER in claims_gate.DISCLAIMER_PARAGRAPH.lower()


def test_a_disclaimer_derivation_that_went_blind_is_not_a_clean_tree(tree):
    """The floor's own arm. It shipped as a global for one revision and this
    mutant SURVIVED — a case can only reach a global by patching it, which is
    patching the thing under test."""
    reported = findings(tree, disclaimer_floor=10_000)
    assert any("owe the disclaimer" in f for f in reported), reported


def test_the_disclaimer_floor_is_under_the_shipped_count():
    pages = [
        rel
        for rel, text in claims_gate.published(ROOT)
        if rel.endswith(".md")
        and len(set(claims_gate.ID.findall(text))) >= claims_gate.DISCLAIMER_IDS
    ]
    assert len(pages) >= claims_gate.DISCLAIMER_FLOOR, pages


# ---- what an independent review broke, and what closed it --------------------
#
# The first version scoped WORDS to a sentence and IDS to the lines that sentence
# touched, and took the union of the named ids' statuses. A reviewer broke the
# headline claim in one line, with plain English and no trick spelling, and the
# five cases of `test_a_status_no_row_holds_is_refused` went with it: re-typed the
# way a hard-wrapping author writes, all five passed. Measured on this corpus,
# 14 978 of 29 403 prose lines are 50-95 columns, so whether a false claim was
# caught depended on where the editor wrapped.


@pytest.mark.parametrize(
    "sentence",
    [
        "The authorization slice closes on `SEC-FIDO-001`.\nIt is PROVEN on hardware.",
        "The store slice leaves `SEC-STORE-005` where it was.\nIt is BOUNDED today.",
        "We re-ran `SEC-FIDO-007` on the bench.\nIt is MEASURED on an RP2350 A4 board.",
        "`SEC-FIDO-001` is the authorization property.\nIt is PROVEN on hardware.",
    ],
)
def test_a_line_break_does_not_hide_a_false_claim(tree, sentence):
    say(tree, sentence)
    reported = findings(tree)
    assert any("is not a copy of anything" in f for f in reported), reported


@pytest.mark.parametrize(
    "sentence",
    [
        "`SEC-FIDO-001` is MODELLED-ONLY and `SEC-STORE-005` is BOUNDED.",
        "`SEC-FIDO-001` and `SEC-FIDO-007` are both BOUNDED.",
    ],
)
def test_two_ids_do_not_lend_each_other_their_statuses(tree, sentence):
    """The union bug: A18 above has BOTH halves backwards and scored two `held`
    true copies. Attribution is to the nearest id that PRECEDES the word."""
    say(tree, sentence)
    reported = findings(tree)
    assert any("is not a copy of anything" in f for f in reported), reported


def test_a_list_after_a_claim_does_not_steal_it(tree):
    """And the reason attribution prefers a PRECEDING id: nearest-in-either-
    direction let the first name of a following list take a word that is about
    the id before it, two characters away."""
    say(
        tree,
        "`SEC-STORE-002` rises to BOUNDED. `SEC-STORE-001`, `SEC-STORE-003`,"
        " `SEC-STORE-004`, `SEC-STORE-005` and `SEC-STORE-006` stay MODELLED-ONLY."
        "\n\n**RS-Key is not formally verified.**",
        page="README.md",
    )
    assert findings(tree) == []


@pytest.mark.parametrize(
    "spelling",
    [
        "`SEC-FIDO-001` is PRO**VEN** on hardware.",
        "`SEC-FIDO-001` is PRO\u200bVEN on hardware.",
        "`SEC\u2011FIDO\u2011001` is PROVEN on hardware.",
        "`SEC-FIDO-001` is PROVEN on hard-\nware.",
    ],
)
def test_a_spelling_that_renders_the_same_reads_the_same(tree, spelling):
    """Emphasis, a zero-width space and the non-ASCII hyphens all render
    identically to what they hide, and each walked a literal `PROVEN` past the
    first version."""
    say(tree, spelling)
    reported = findings(tree)
    assert any("is not a copy of anything" in f for f in reported), reported


def test_the_corpus_reaches_the_changelog(tree):
    """`run_count_gate.scanned` was the first corpus and left 1018 tracked files
    out, `CHANGELOG.md` among them — and `CHANGELOG.md` carried "the other three
    store properties stay MODELLED-ONLY" over a family of six. The run-count
    carve-out's reason does not transfer: it is about a COST staying its
    release's, and a status was wrong the day it was typed."""
    say(tree, "`SEC-FIDO-001` is PROVEN on hardware.", page="CHANGELOG.md")
    reported = findings(tree)
    assert any("CHANGELOG.md" in f and "PROVEN" in f for f in reported), reported


@pytest.mark.parametrize(
    "header",
    [
        "<!-- Generated by scripts/no_such_gate.py --write -->",
        "<!-- Generated by scripts/evidence_gate.py --write -->",
        "The tables here are Generated by scripts/evidence_gate.py --write.",
    ],
)
def test_a_page_cannot_exempt_itself_by_saying_it_is_generated(tree, header):
    """Three passes at exit 0 on the first version: a script that does not exist,
    a real script over a page it does not write, and the phrase in ordinary
    prose. The exempt set is derived from each generator's own `ARTIFACT` and
    `GENERATED_BY` pair, so only the page a script really writes is exempt."""
    page = tree / "docs/threat-model.md"
    page.write_text(header + "\n" + page.read_text() + "\n\n`SEC-FIDO-001` is PROVEN.\n")
    reported = findings(tree)
    assert any("threat-model" in f and "PROVEN" in f for f in reported), reported


def test_the_generated_page_roster_is_the_generators_own():
    """The roster is EXACT, so a page joining it is a decision in a diff.

    `docs/assurance-bounds.md` joined when the scope table stopped being typed
    into `docs/authorization-slice.md`: it names eight registered ids, so it owes
    the disclaimer, and it is exempt from the hand-written-claim rules only
    because `bounds_gate.py` really writes it.
    """
    pages = claims_gate.generated_pages(ROOT)
    assert pages == {
        "docs/assurance-vector.md": "Generated by scripts/evidence_gate.py --write",
        "docs/assurance-matrix.md": "Generated by scripts/matrix_gate.py --write",
        "docs/platform-assumptions.md": "Generated by scripts/platform_gate.py --write",
        "docs/assurance-bounds.md": "Generated by scripts/bounds_gate.py --write",
    }, pages


def test_a_registered_exemption_that_stopped_matching_is_a_finding(tree):
    """An exemption exempts a FRAGMENT, and one that no longer occurs hides
    whatever moved into its place."""
    (page, fragment) = next(iter(claims_gate.SCOPED))
    target = tree / page
    target.write_text(target.read_text().replace(fragment, "gone", 1))
    reported = findings(tree)
    assert any("occurs 0 time(s)" in f for f in reported), reported


def test_a_registered_exemption_copied_twice_is_a_finding(tree):
    (page, fragment) = next(iter(claims_gate.SCOPED))
    target = tree / page
    target.write_text(target.read_text() + "\n\n" + fragment + "\n")
    reported = findings(tree)
    assert any("occurs 2 time(s)" in f for f in reported), reported


def test_every_registered_exemption_carries_a_reason():
    for key, reason in claims_gate.SCOPED.items():
        assert len(reason.split()) >= 8, key


@pytest.mark.parametrize(
    "floor", ["CLAIM_FLOOR", "CORPUS_FLOOR", "DISCLAIMER_FLOOR"]
)
def test_a_floor_tracks_the_tree_rather_than_sitting_at_zero(floor):
    """Lowering a floor was UNCAUGHT: the cases that drive each one pass their own
    value, so the constant they ship with binds nothing, and
    `test_the_shipped_corpus_is_over_its_floor` only gets easier as the floor
    drops. Held between half the measurement and the measurement, so 0 fails and
    an over-raise fails too."""
    measured = {
        "CLAIM_FLOOR": _measure_held(),
        "CORPUS_FLOOR": len(claims_gate.corpus(ROOT)),
        "DISCLAIMER_FLOOR": _measure_owed(),
    }[floor]
    value = getattr(claims_gate, floor)
    assert measured // 2 <= value <= measured, (floor, value, measured)


# ---- polarity: what a review measured the first rule at ----------------------
#
# The hole, measured on the shipped tree without a pipe: `python
# scripts/claims_gate.py` with "`SEC-FIDO-001` is not BOUNDED." appended to
# README.md exited 0, and the summary's held count went 11 -> 12; with
# "`SEC-FIDO-007` is no longer MODELLED-ONLY, and `SEC-FIDO-001` was BOUNDED."
# it exited 0 at 13. The lie did not merely pass — it PAID INTO the floor whose
# job is to prove the scanner still reads anything.
#
# The FIRST rule for that read a four-word window against a flat marker list. An
# independent review measured it at 2 of 24 lies refused and 6 of 12 TRUE
# sentences reddened, which is the worse half — a guard that reddens prose with
# every right to exist. These three lists ARE that measurement, in the tree
# rather than in a comment, because the 66 real pages cannot check any of it:
# they report 0 findings at every setting that was tried.

#: False claims. Each uses the registry's own word about the right id and denies
#: or re-dates it; every one was appended to `README.md` with the row GREEN.
LIES = (
    "`SEC-FIDO-001` is not BOUNDED.",
    "`SEC-FIDO-001` isn't BOUNDED.",
    "`SEC-FIDO-001` has never been BOUNDED.",
    "`SEC-FIDO-001` is far from BOUNDED.",
    "`SEC-FIDO-001` has yet to be BOUNDED.",
    "`SEC-FIDO-001` is nowhere near BOUNDED.",
    "`SEC-FIDO-001` is anything but BOUNDED.",
    "`SEC-FIDO-001` is hardly BOUNDED.",
    "`SEC-FIDO-001` fails to be BOUNDED.",
    "`SEC-FIDO-001` is **not**, on any reading of the evidence, BOUNDED.",
    "`SEC-FIDO-001` is **not** [BOUNDED](docs/formal.md).",
    "`SEC-FIDO-001` is **never** (BOUNDED).",
    "| `SEC-FIDO-001` | **not** achieved | BOUNDED |",
    "`SEC-FIDO-001` is <em>not</em> BOUNDED.",
    "`SEC-FIDO-001` **isn't** yet what anyone would call BOUNDED.",
    "`SEC-FIDO-001` remains un-BOUNDED.",
    "`SEC-FIDO-001` **stops** being BOUNDED.",
    "`SEC-FIDO-001` stopped being BOUNDED.",
    "`SEC-FIDO-001` used to be BOUNDED.",
    "`SEC-FIDO-001` was BOUNDED.",
    "`SEC-FIDO-001` **was**, until the revert, BOUNDED.",
    "`SEC-FIDO-001` will be BOUNDED once the harness lands.",
    "`SEC-FIDO-007` is no longer MODELLED-ONLY.",
    "`SEC-FIDO-001` is the authorization property.\nIt is not BOUNDED.",
)

#: TRUE sentences that must stay green, and the half that matters more: six of
#: these are what the review broke the first rule with. Three are double
#: negatives that assert the status, which is why [`claims_gate.FLIP`] counts
#: parity instead of matching a marker; three carry a past or future auxiliary
#: about a row that holds the status TODAY, which is why bare tense is only read
#: where it touches the word.
TRUTHS = (
    "`SEC-FIDO-001` was raised to BOUNDED by the reset harness.",
    "`SEC-FIDO-001` was and still is BOUNDED.",
    "`SEC-FIDO-001` has not stopped being BOUNDED.",
    "`SEC-FIDO-001` will stay BOUNDED for as long as the harness carries its name.",
    "`SEC-FIDO-001` was never anything but BOUNDED.",
    "`SEC-FIDO-001` had already been BOUNDED when the slice opened,"
    " and is BOUNDED now.",
    "`SEC-FIDO-001` is BOUNDED, which is why the slice could close.",
    "`SEC-FIDO-001` was added to the registry in March and is BOUNDED.",
    "`SEC-FIDO-001` closes nothing and moves no status — the row stays BOUNDED.",
    "`SEC-FIDO-001`'s `status` would have read BOUNDED with one harness or four.",
    "`SEC-FIDO-001` will not be re-run, and the row stays BOUNDED.",
    "`SEC-STORE-002` rises to BOUNDED.",
    "`SEC-FIDO-001`'s status is still BOUNDED.",
    "`SEC-FIDO-001` and `SEC-STORE-002` rise to BOUNDED.",
)

#: The lies that still walk past, asserted as escaping so the docstring's claim
#: cannot rot into coverage it does not have. Closing either is welcome and will
#: redden this case, which is the point of listing them.
ESCAPES = (
    # The negator stands BEFORE the id, and the run-up starts at the subject —
    # which it must: with the floor at 0 the clause reaches into the previous
    # table cell and `docs/authorization-slice.md` reddens on true prose.
    ("**No** evidence in this tree makes `SEC-FIDO-001` BOUNDED.", "BOUNDED"),
    # The negation is AFTER the word. A trailing window would hand the next id's
    # clause to this one.
    ("`SEC-FIDO-001` is BOUNDED - except that it is not.", "BOUNDED"),
)


def verdict(sentence, word="BOUNDED"):
    """What `audit` decides about `sentence`, through the shipped helpers.

    A replica of the two lines in `audit` that read the clause, so 39 sentences
    cost one fixture copy instead of 39; `test_the_replica_agrees_with_the_row`
    is what keeps it from drifting away from the thing it stands in for.
    """
    text = claims_gate.normalise(sentence)
    found = claims_gate.ID.search(text)
    at = text.index(claims_gate.normalise(word))
    floor = found.end() if found and found.end() <= at else 0
    return claims_gate.denied(claims_gate.run_up(text, at, floor))


@pytest.mark.parametrize("sentence", LIES)
def test_a_denied_or_re_dated_copy_is_not_a_copy(sentence):
    word = "MODELLED-ONLY" if "MODELLED-ONLY" in sentence else "BOUNDED"
    assert verdict(sentence, word), sentence


@pytest.mark.parametrize("sentence", TRUTHS)
def test_a_true_sentence_stays_true(sentence):
    assert verdict(sentence) is None, (sentence, verdict(sentence))


@pytest.mark.parametrize("sentence,word", ESCAPES)
def test_the_measured_escape_still_escapes(sentence, word):
    assert verdict(sentence, word) is None, "an escape closed — update ESCAPES"


def test_the_replica_agrees_with_the_row(tree):
    """The one case that costs a fixture: what `verdict` says, the row says. Both
    directions, because a replica that agreed only on refusals would let every
    true sentence above be checked by something the gate never runs."""
    for sentence in LIES[:4] + TRUTHS[:4] + tuple(s for s, _ in ESCAPES):
        page = tree / PAGE
        keep = page.read_text()
        say(tree, sentence)
        red = any("does not assert it" in f for f in findings(tree))
        page.write_text(keep)
        assert red is bool(verdict(sentence)), sentence


def test_the_lie_stops_paying_into_the_floor(tree):
    """The second half of the finding, and the one a verdict column hides: the
    sentence passed AND raised `held`, so a corpus of nothing but negations
    satisfied `CLAIM_FLOOR`."""
    before = _measure_held(tree)
    say(tree, "`SEC-FIDO-001` is not BOUNDED.")
    assert _measure_held(tree) == before, "a refused claim still counted as held"


def test_the_polarity_count_is_what_saves_the_double_negatives(tree):
    """The mutant for the parity: read as `any flipper denies`, three TRUE
    sentences redden — which is exactly the review's finding, reproduced."""
    say(tree, "`SEC-FIDO-001` has not stopped being BOUNDED.")
    assert findings(tree) == [], "the control must be green before it is mutated"
    naive = claims_gate.denied

    def any_flipper(clause):
        return (claims_gate.FLIP.findall(clause) or [None])[0]

    assert any_flipper is not naive, "the mutant did not take"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(claims_gate, "denied", any_flipper)
        assert any("does not assert it" in f for f in findings(tree))


def test_a_boundary_that_matters_and_one_that_does_not(tree):
    """The CONTROL, and the previous one was a no-op: `RUN_UP_WORDS = 5` left the
    row byte-identical, and so did every value from 1 to 30. This pair is not.
    Dropping `—` from `CLAUSE` reddens a true sentence; dropping `→` changes
    nothing — so the table measures which boundary does work, not that a constant
    was retyped."""
    say(tree, "`SEC-FIDO-001` closes nothing and moves no status — the row stays BOUNDED.")
    assert findings(tree) == [], "the control must be green before it is mutated"
    for mark, must_redden in (("|—", True), ("|→", False)):
        pattern = claims_gate.CLAUSE.pattern.replace(mark, "", 1)
        assert pattern != claims_gate.CLAUSE.pattern, f"{mark} is not in CLAUSE"
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(claims_gate, "CLAUSE", re.compile(pattern))
            reported = findings(tree)
            red = any("does not assert it" in f for f in reported)
            assert red is must_redden, (mark, reported)


def test_the_rule_is_defended_by_pytest_and_by_nothing_else(tree):
    """Said in the docstring and asserted here: with [`FLIP`] neutered the
    `published claims` row is byte-identical, so a reader who takes that row's
    green as evidence of this feature is taking it as evidence of nothing. The
    docstring first claimed the same of `CLAUSE` and this case refuted it."""
    baseline = claims_gate.audit(tree)
    never = re.compile(r"(?!x)x")
    assert not never.search("is not "), "the neutered pattern still matches"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(claims_gate, "FLIP", never)
        assert claims_gate.audit(tree) == baseline
    # The branch itself, reverted: `denied` answering None is `held += 1` again.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(claims_gate, "denied", lambda clause: None)
        assert claims_gate.denied("is not ") is None, "the revert did not take"
        assert claims_gate.audit(tree) == baseline
    # And the one that is NOT free, which this case measured rather than assumed:
    # `CLAUSE` became load-bearing on the real corpus when the word window went.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(claims_gate, "CLAUSE", never)
        assert claims_gate.audit(tree) != baseline


def test_a_reported_line_is_the_line_in_the_file(tree):
    """A guard whose only output is a citation shipped with the citation wrong:
    `normalise` JOINED a hyphenated line break, deleting the newline, so every
    finding below one was early — 6 files, and it said `docs/formal.md:266` for
    268. `soft` crosses the break in the pattern instead."""
    page = "docs/formal.md"
    raw = (tree / page).read_text()
    assert re.search(r"-\n[ \t]*\S", raw), f"{page} carries no hyphen-wrap to drift on"
    say(tree, "`SEC-FIDO-001` is not BOUNDED.", page=page)
    lines = (tree / page).read_text().splitlines()
    want = next(n for n, line in enumerate(lines, 1) if "is not BOUNDED" in line)
    got = [f for f in findings(tree) if f.startswith(f"{page}:")]
    assert got and got[0].startswith(f"{page}:{want}:"), (want, got)


#: A hard wrap in the RAW file, which is what the reader looks at and where the
#: deleted newline was. Not `-\n[ \t]*\S` — 11 of `docs/protocol.md`'s 12 sites are
#: followed by a BLANK line and the join deleted those newlines too, so a pattern
#: demanding a continuation finds ONE of them and measures a twelfth of the drift.
#: Counted on the raw text and not on a [`normalise`]d copy, which invents two more
#: by stripping a trailing `*`.
WRAP = re.compile(r"-\n[ \t]*")


def worst_wrapped(root):
    """(page, the 1-based lines its hard wraps end) for the worst hand-written page.

    Derived rather than named. Measured over the tracked corpus today:
    `docs/protocol.md` 12, `CHANGELOG.md` 6, `docs/anti-rollback.md` 5,
    `formal/README.md` 3, `docs/formal.md` 2, `docs/reset-refinement.md` 1 — all
    of it the author's editor rather than a decision, so a case naming the page
    goes stale the week the prose is rewrapped, which this file has already been
    bitten by twice.
    """
    best = ("", [])
    for rel, _ in claims_gate.corpus(root):
        raw = (root / rel).read_text(errors="replace")
        at = [raw.count("\n", 0, found.start()) + 1 for found in WRAP.finditer(raw)]
        if len(at) > len(best[1]):
            best = (rel, at)
    return best


def test_a_claim_below_a_hard_wrap_cites_its_own_line(tree):
    """BOTH citations this row prints, under the wraps that used to move them.

    The sibling above appends at the END of `docs/formal.md`, two wraps down.
    This one puts the claims DIRECTLY under the last wrap of the worst page — 12
    wraps on `docs/protocol.md` — and asserts the other line the row prints, the
    transcribed-row rule's, which nothing asserted: `enumerate(text.splitlines(),
    2)` was 104 passed. Measured end to end before this case existed: 89 claims
    over all 66 hand-written pages, drift 0; with `re.sub(r"-\n[ \t]*", "-",
    text)` back in [`normalise`], exactly the six pages above drift by 12/6/5/3/2/1.

    Killed here, and each read for its DIRECTION rather than its colour: the join
    (the sentence cited 12 EARLY, one per wrap above it), a join narrowed to a
    lowercase continuation, and the row's own off-by-one (the row cited one LATE
    while the sentence stayed exact). The generated-region half stays the
    sibling's — the worst-wrapped page carries no region to mask.
    """
    page, wraps = worst_wrapped(tree)
    assert len(wraps) >= 2, f"{page} is the worst at {len(wraps)} wrap(s) — nothing drifts"
    lines = (tree / page).read_text(errors="replace").split("\n")
    # Below the wrapped word, not between its halves, and bottom-most so every
    # wrap on the page is above it — the drift is the count of joins ABOVE.
    lines[wraps[-1] + 1 : wraps[-1] + 1] = [
        "",
        "`SEC-FIDO-001` is not BOUNDED.",
        "",
        "| `SEC-FIDO-007` | MODELLED-ONLY | 3 | 1 | 0 |",
        "",
    ]
    (tree / page).write_text("\n".join(lines))
    assert sum("is not BOUNDED" in line for line in lines) == 1, "the page already said it"
    assert sum("MODELLED-ONLY | 3" in line for line in lines) == 1, "the page already had the row"
    said = next(n for n, line in enumerate(lines, 1) if "is not BOUNDED" in line)
    row = next(n for n, line in enumerate(lines, 1) if "MODELLED-ONLY | 3" in line)
    reported = [f for f in findings(tree) if f.startswith(f"{page}:")]
    assert any(
        f.startswith(f"{page}:{said}:") and "does not assert it" in f for f in reported
    ), (said, reported)
    assert any(
        f.startswith(f"{page}:{row}:") and "transcribed row" in f for f in reported
    ), (row, reported)


def test_a_claim_above_every_hard_wrap_is_the_control(tree):
    """The other arm, and it has to stay GREEN.

    The same claim on the same page with no wrap ABOVE it keeps its line under
    the join, so its sibling going red is the wraps and not a blanket miscount.
    Measured with the join put back: this case passes while the sibling reports
    12 lines early (`docs/protocol.md:1192` for the 1201 the file holds) — the
    drift is the durable half of that, the line numbers move with the prose.
    """
    page, wraps = worst_wrapped(tree)
    lines = (tree / page).read_text(errors="replace").split("\n")
    lines[wraps[0] - 1 : wraps[0] - 1] = ["", "`SEC-FIDO-001` is not BOUNDED.", ""]
    (tree / page).write_text("\n".join(lines))
    assert sum("is not BOUNDED" in line for line in lines) == 1, "the page already said it"
    said = next(n for n, line in enumerate(lines, 1) if "is not BOUNDED" in line)
    assert said < wraps[0] + 3, (said, wraps[0])
    reported = [f for f in findings(tree) if f.startswith(f"{page}:")]
    assert any(
        f.startswith(f"{page}:{said}:") and "does not assert it" in f for f in reported
    ), (said, reported)


@pytest.mark.parametrize(
    "sentence,refused",
    [
        ("`SEC-FIDO-007` is MODELLED-\nONLY.", False),
        ("`SEC-FIDO-001` is MODELLED-\nONLY.", True),
    ],
)
def test_a_status_word_split_by_a_hard_wrap_still_reads(tree, sentence, refused):
    """What replaced the join has to do the join's job: `MODELLED-ONLY` broken
    over two lines is still the word, in both directions."""
    say(tree, sentence)
    assert bool(findings(tree)) is refused, findings(tree)


def test_modality_is_out_because_the_corpus_holds_the_prose_it_would_redden():
    """The false-positive measurement, kept live rather than asserted in a
    comment: `would|could|should|may|might` is the obvious next widening and it
    reddens one real sentence. Anchored by CONTENT — `CHANGELOG.md` moved 105
    lines under this file mid-session, and both line numbers cited here were
    stale within the hour."""
    quoted = "its `status` would have read `BOUNDED`"
    assert quoted in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), (
        "the measured sentence moved; re-measure the trade"
    )
    line = claims_gate.normalise(quoted)
    clause = claims_gate.run_up(line, line.index("BOUNDED"), 0)
    assert not claims_gate.denied(clause), clause
    assert re.search(r"\b(?:would|could|should|may|might)\b", clause, re.I), clause


def _measure_held(root=ROOT):
    summary = claims_gate.audit(root)[1]
    return int(re.search(r"(\d+) hand-written", summary).group(1))


def _measure_owed():
    summary = claims_gate.audit(ROOT)[1]
    return int(re.search(r"(\d+) page\(s\) carrying", summary).group(1))


# ---- the orphan: an id no registry holds -------------------------------------
#
# The measured hole. Both rules above START from the ids the registry knows —
# `spans` kept `m.group(0) in status` and the paragraph was `continue`d when that
# left none — so a sentence about an INVENTED id was read by neither.
# "`SEC-BOOT-042` is PROVEN-SOURCE on the shipped image." and the same with
# `MEASURED` were each EXIT=0 with ZERO findings, appended to a real corpus page.
# The control that did fall, "`SEC-FIDO-002` is BINARY-CHECKED", fell on the
# STATUS half and only because that word is no row's status: invent the id rather
# than the word and nothing looked at all.


@pytest.mark.parametrize(
    "sentence",
    [
        "`SEC-BOOT-042` is PROVEN-SOURCE on the shipped image.",
        "`SEC-BOOT-042` is MEASURED on an RP2350 A4 board.",
        # `SEC-BOOT` is a real family and `MODELLED-ONLY` is a real status: the
        # invention is two digits, and neither half of the copy rules sees it.
        "`SEC-BOOT-042` is MODELLED-ONLY, like the rest of its family.",
        "`SEC-FIDO-042` and `SEC-STORE-009` are BOUNDED.",
    ],
)
def test_an_id_no_registry_holds_is_refused(tree, sentence):
    say(tree, sentence)
    reported = findings(tree)
    assert any("no registry row holds" in f for f in reported), reported


def test_an_orphan_needs_no_status_word_anywhere(tree):
    """Which is why it is a rule of its own and not a widening of the copy rules:
    an id with no row has no status to be held to, so the sentence around it is
    unfalsifiable rather than false, and it stays a finding with no evidence word
    on the page at all."""
    say(tree, "The boot slice is tracked as `SEC-BOOT-042` and reviewed monthly.")
    reported = findings(tree)
    assert any("SEC-BOOT-042" in f and "no registry row holds" in f for f in reported)
    assert not any("copy of anything" in f for f in reported), reported


def test_the_orphan_rule_is_scored_per_occurrence(tree):
    """It has no window, which is the one thing the other two rules had to get
    right twice. 14 978 of 29 403 prose lines here are 50-95 columns, so a
    sentence- or paragraph-scoped rule catches a lie depending on where an editor
    wrapped; two orphans one blank line apart are two findings either way."""
    say(tree, "`SEC-BOOT-042` is PROVEN-SOURCE.\n\nAnd `SEC-BOOT-043` is not.")
    reported = [f for f in findings(tree) if "no registry row holds" in f]
    assert len(reported) == 2, reported


def test_the_shape_reaches_an_id_the_registry_does_not_hold():
    """`test_the_id_pattern_reaches_the_clause_rows` holds [`ID`] from getting too
    NARROW, and 59 registered rows cannot witness the direction this rule needs:
    that a plausible id NOBODY registered is id-shaped. That half is asserted
    here, because it is the half the registry can never supply."""
    status = claims_gate.vocabulary(ROOT)[0]
    for invented in (
        "SEC-BOOT-042",
        "SEC-FIDO-099",
        "SEC-STORE-007",
        "SEC-FIDO-L09",
        "SEC-PQC-001",
    ):
        assert claims_gate.ID.fullmatch(invented), invented
        assert invented not in status, invented


def test_widening_the_shape_would_redden_the_shipped_tree():
    """The other side of that trade, kept live rather than argued in a comment:
    the obvious next shape — a namespace and any further segments — reads
    `CHANGELOG.md`'s `SEC-DISP` family and its `SEC-FIDO-NNN` placeholder as
    invented ids. Anchored by CONTENT, because `CHANGELOG.md` moves."""
    broad = re.compile(r"\bSEC(?:-[A-Z0-9]+)+\b")
    status = claims_gate.vocabulary(ROOT)[0]
    over = {
        m.group(0)
        for _, text in claims_gate.corpus(ROOT)
        for m in broad.finditer(text)
        if m.group(0) not in status
    }
    assert {"SEC-DISP", "SEC-FIDO-NNN"} <= over, (
        f"the prose this trade was measured on is gone; re-measure the shape: {over}"
    )


@pytest.mark.parametrize(
    "prose",
    [
        # The first three are quoted from the shipped corpus.
        "The three `SEC-DISP-*` cells stay `gap` for that reason.",
        "Refines `RSKeySecurityState!<Invariant>` — SEC-FIDO-NNN. So a reader can tell.",
        "One cell moved: `SEC-DISP-001/002/003 × firmware-display` is now `gap`.",
        "`PLAT-TOOL-004` is PROVEN and `TM-HOST-GATES` is MEASURED.",
        "See `formal/SEC-Boot.cfg`, `scripts/sec-fido-001.py` and the key `sec-boot-042`.",
    ],
)
def test_a_sec_shaped_token_that_is_not_a_claim_stays_prose(tree, prose):
    """A family named as a family, a placeholder, a run of cells, another
    registry's ids, and three lower-case spellings. A rule that fired on any of
    these would be measuring spelling rather than holding a claim."""
    say(tree, prose)
    assert findings(tree) == []


@pytest.mark.parametrize(
    "sentence,refused",
    [
        ("A note on the cache half: `SEC-\nSTORE-002` is BOUNDED today.", False),
        ("A note on the cache half: `SEC-\nSTORE-002` is PROVEN today.", True),
    ],
)
def test_an_id_split_by_a_hard_wrap_is_still_its_own_row(tree, sentence, refused):
    """Both directions, and each was a hole [`flat`] closes — measured by
    reverting the two sites alone. Without it here, the orphan rule reads a legal
    wrap as an invention; without it in `spans`, the subject is dropped and
    "`SEC-\\nSTORE-002` is PROVEN" is EXIT=0 on a corpus that wraps."""
    say(tree, sentence)
    assert bool(findings(tree)) is refused, findings(tree)


def test_a_wrapped_true_claim_still_pays_into_the_scanner_floor(tree):
    """Green is not enough on the true half: if the wrapped id is merely dropped,
    the claim goes unchecked and reads exactly like a page with nothing on it —
    which is what `held` staying put measured before [`flat`] reached `spans`."""
    before = _measure_held(tree)
    say(tree, "A note on the cache half: `SEC-\nSTORE-002` is BOUNDED today.")
    assert _measure_held(tree) == before + 1


def test_a_shape_derived_from_the_registry_blinds_the_rule(tree):
    """The removal arm that no other rule here catches, and the "fix" this rule
    must never be given: an [`ID`] built FROM the 59 registry rows leaves `held`
    and the disclaimer count untouched — every floor stays satisfied — and makes
    the orphan invisible again. The shape is the load-bearing half."""
    say(tree, "`SEC-BOOT-042` is PROVEN-SOURCE on the shipped image.")
    assert any("no registry row holds" in f for f in findings(tree))
    status = claims_gate.vocabulary(ROOT)[0]
    derived = re.compile(
        r"\b(?:" + "|".join(re.escape(i) for i in sorted(status, key=len, reverse=True)) + r")\b"
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(claims_gate, "ID", derived)
        assert findings(tree) == [], "the mutation did not blind the rule"


def test_the_row_and_not_the_helper(tree):
    """The gate runs `python scripts/claims_gate.py`. Fourteen of thirty gates
    here were byte-identical to baseline when their entry function's non-zero
    return was flipped to zero — the exit PATH was unheld, this file among them.
    A shared case drives that generically now; this drives it over THIS rule's
    defect, because a generic red says nothing about which finding made it. The
    fixture copies `scripts/`, so the copied script's own `ROOT` is the fixture."""
    row = [sys.executable, "scripts/claims_gate.py"]
    green = subprocess.run(row, cwd=tree, capture_output=True, text=True)
    assert green.returncode == 0, (green.stdout, green.stderr)
    assert green.stdout.startswith("claims-gate: ok —")
    say(tree, "`SEC-BOOT-042` is PROVEN-SOURCE on the shipped image.")
    red = subprocess.run(row, cwd=tree, capture_output=True, text=True)
    assert red.returncode == 1, (red.stdout, red.stderr)
    assert "SEC-BOOT-042" in red.stderr and "no registry row holds" in red.stderr


# ---- and the direction that is NOT held --------------------------------------


def test_the_reverse_direction_would_redden_a_clean_tree():
    """Why "a registry row no HAND-WRITTEN page names" is a measurement in the
    docstring and not a rule in the file. The number is held here because a
    number nothing checks has already rotted: if it ever reaches 0 the rule
    becomes free, and that is a decision to re-take rather than a comment."""
    status = claims_gate.vocabulary(ROOT)[0]
    named = {
        i
        for _, text in claims_gate.corpus(ROOT)
        for i in claims_gate.ID.findall(text)
        if i in status
    }
    unnamed = set(status) - named
    assert unnamed, "the reverse rule is now free — re-take the decision"
    said, rows = re.search(
        r"report (\d+) of the (\d+) on\s+a clean tree", claims_gate.__doc__
    ).groups()
    assert (int(said), int(rows)) == (len(unnamed), len(status)), (said, rows)


def test_those_rows_are_generator_written_and_not_rot():
    """The other half of the same decision, and the half that makes it a
    measurement rather than a preference: they are not missing, they are in
    TABLES. `formal/README.md` is hand-written and names all 59 — until
    [`mask_regions`] runs over its six generated regions."""
    status = claims_gate.vocabulary(ROOT)[0]
    everywhere = {
        i
        for _, text in claims_gate.published(ROOT)
        for i in claims_gate.ID.findall(text)
        if i in status
    }
    assert everywhere == set(status), sorted(set(status) - everywhere)
    raw = claims_gate.normalise((ROOT / "formal/README.md").read_text(encoding="utf-8"))
    assert {i for i in claims_gate.ID.findall(raw) if i in status} == set(status)
    masked = {
        i for i in claims_gate.ID.findall(claims_gate.mask_regions(raw)) if i in status
    }
    kept = int(re.search(r"registered ids to (\d+)", claims_gate.__doc__).group(1))
    assert len(masked) == kept, sorted(masked)


def test_the_orphan_citation_is_the_line_in_the_file(tree):
    """This rule's WHOLE output is a citation, and the copy rules already shipped
    one wrong for the reason `test_a_reported_line_is_the_line_in_the_file` holds
    above. Same page, because a page carrying no hyphen-wrap cannot drift — and
    an orphan finding is cited from a different pass, so it drifts separately."""
    page = "docs/formal.md"
    raw = (tree / page).read_text()
    assert re.search(r"-\n[ \t]*\S", raw), f"{page} carries no hyphen-wrap to drift on"
    say(tree, "The boot slice is tracked as `SEC-BOOT-042`.", page=page)
    lines = (tree / page).read_text().splitlines()
    want = next(n for n, line in enumerate(lines, 1) if "SEC-BOOT-042" in line)
    got = [f for f in findings(tree) if "no registry row holds" in f]
    assert got and got[0].startswith(f"{page}:{want}:"), (want, got)


@pytest.mark.parametrize(
    "spelling",
    [
        "`SEC-**BOOT**-042` is PROVEN-SOURCE.",
        "`SEC‑BOOT‑042` is PROVEN-SOURCE.",
        "`SEC​-BOOT-042` is PROVEN-SOURCE.",
        "`SEC-BOOT-\n042` is PROVEN-SOURCE.",
    ],
)
def test_an_orphan_spelled_to_render_the_same_reads_the_same(tree, spelling):
    """[`normalise`] and [`soft`] are shared with the copy rules, and a rule that
    inherited only one of them would be bypassable by emphasis or by the
    editor's wrap. Reported under the flattened name in every case."""
    say(tree, spelling)
    reported = [f for f in findings(tree) if "no registry row holds" in f]
    assert reported and all("SEC-BOOT-042" in f for f in reported), reported


def test_a_registry_that_went_blind_fails_loud(tree):
    """The direction the three floors exist for, and this rule answers it the
    other way round: a registry that stops parsing makes every id an orphan
    rather than every page clean, one finding per occurrence in the corpus. So a
    floor here would be the decoration — the failure is already red, loudly."""
    (tree / claims_gate.REGISTRY).write_text("# emptied\n")
    reported = [f for f in findings(tree) if "no registry row holds" in f]
    assert len(reported) > claims_gate.CLAIM_FLOOR, reported


def test_an_invented_region_marker_still_exempts_a_paragraph(tree):
    """The inherited bypass, asserted rather than described so it cannot be
    believed closed: [`REGION`] takes the SHAPE, so `<!-- bogus:start -->` around
    a false claim is EXIT=0 for all three rules. The trade is stated in the
    docstring; this case is what would go red if someone closed it, which is the
    day to delete the paragraph that says it is open."""
    say(tree, "<!-- bogus:start -->\n\n`SEC-BOOT-042` is PROVEN-SOURCE.\n\n<!-- bogus:end -->")
    assert findings(tree) == []
