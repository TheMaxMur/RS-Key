# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""One mutation per rule `threat_gate.py` states, both directions.

The fixture is a five-file tree — a threat model, a clause roster, a property
registry, the tranche ledger and the platform registry — because every rule here
is about the fit BETWEEN them, and a mutation of one has to be seen from the
others. The floors are monkeypatched down for the fixture and asserted at their
real values against the real tree, so a case cannot go red for the wrong reason
(a six-clause fixture under a floor of 44 reddens every case, and none of them
for the rule it names).
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import gate_lines
import platform_gate
import threat_gate

pytestmark = pytest.mark.assurance

DOC = "\n".join(
    [
        "# Threat model",
        "",
        "## Assets",
        "",
        "The seed, the passkeys, the PINs.",
        "",
        "## Attackers, strongest defense first",
        "",
        "### 1. A hostile host (malware on the computer)",
        "",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.",
        "- What a hostile host **can** do: drive an operation you authorized.",
        "  A residual, not a defence.",
        "- **A flash write can be interrupted.** Write order is what buys it,",
        "  and under the order sits `PLAT-FLASH-001`, discharged by a board run.",
        "  **Scope: the interrupted write.** A faulted read is another condition.",
        "",
        "## Zeroization",
        "",
        "Key-grade material in RAM is wiped when its use ends.",
        "",
        "```mermaid",
        "sequenceDiagram",
        "    - this arrow is not a clause",
        "```",
        "",
    ]
)

CLAUSES = """
[[clause]]
id = "TM-TITLE"
kind = "context"
where = "# Threat model"
why = "the page's own title; every clause of it is an entry below"

[[clause]]
id = "TM-ASSETS"
kind = "context"
where = "## Assets"
why = "the asset inventory the rest of the page defends, not a threat"

[[clause]]
id = "TM-ATTACKERS"
kind = "context"
where = "## Attackers, strongest defense first"
why = "a container heading; each attacker below is a clause of its own"

[[clause]]
id = "TM-HOST"
kind = "defence"
where = "### 1. A hostile host (malware on the computer)"

[[clause]]
id = "TM-HOST-GATES"
kind = "defence"
where = "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO."

[[clause]]
id = "TM-HOST-AUTHORIZED-OPS"
kind = "context"
where = "- What a hostile host **can** do: drive an operation you authorized."
why = "a stated residual: what an authorized key deliberately does not prevent"

[[clause]]
id = "TM-HOST-POWER-CUT"
kind = "defence"
where = "- **A flash write can be interrupted.** Write order is what buys it,"
rests_on = ["and under the order sits `PLAT-FLASH-001`, discharged by a board run."]

[[clause]]
id = "TM-ZEROIZATION"
kind = "defence"
where = "## Zeroization"

[[untraced]]
id = "SEC-STORE-001"
verdict = "missing-clause"
owner = "contributor"
why = "not TM-HOST-POWER-CUT, which scopes itself to the interrupted write"
rests_on = ["**Scope: the interrupted write.** A faulted read is another condition."]
"""

PLATFORM = """
[[assumption]]
id = "PLAT-FLASH-001"
class = "flash"
statement = "A torn write leaves the old record or a detectably bad one."
"""

PROPERTIES = """
[[property]]
id = "SEC-FIDO-001"
name = "NoAuthorizationBypass"
status = "BOUNDED"
statement = "s"
source = ["CTAP 2.3 §6.5", "docs/threat-model.md#TM-HOST-GATES"]

[[property]]
id = "SEC-FIDO-007"
name = "RamNeverOutlivesFlashSeed"
status = "MODELLED-ONLY"
statement = "s"
source = ["docs/threat-model.md#TM-ZEROIZATION"]

[[property]]
id = "SEC-STORE-001"
name = "NoOrphanedMetadata"
status = "MODELLED-ONLY"
statement = "s"
source = ["docs/store-refinement.md"]

[[property]]
id = "SEC-ADM-001"
name = "AdminSurfaceAlwaysReachable"
status = "MODELLED-ONLY"
statement = "s"
source = ["docs/threat-model.md"]
"""

LEDGER = """
[tranche]
p0-launch = ["SEC-FIDO-001", "SEC-FIDO-007", "SEC-STORE-001"]
p0b = []
p1 = ["SEC-ADM-001"]
out-of-queue = []
"""


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A five-file checkout the gate is pointed at, with the floors scaled to it."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "assurance").mkdir()
    (tmp_path / "docs" / "threat-model.md").write_text(DOC, encoding="utf-8")
    (tmp_path / "docs" / "store-refinement.md").write_text("prose", encoding="utf-8")
    (tmp_path / threat_gate.CLAUSES).write_text(CLAUSES, encoding="utf-8")
    (tmp_path / threat_gate.REGISTRY).write_text(PROPERTIES, encoding="utf-8")
    (tmp_path / threat_gate.LEDGER).write_text(LEDGER, encoding="utf-8")
    (tmp_path / threat_gate.ASSUMPTIONS).write_text(PLATFORM, encoding="utf-8")
    monkeypatch.setattr(threat_gate, "FLOOR_CLAUSES", 8)
    monkeypatch.setattr(threat_gate, "FLOOR_P0", 3)
    return tmp_path


def problems(tree):
    return threat_gate.audit(tree)[0]


def edit(tree, path, old, new):
    target = tree / path
    text = target.read_text(encoding="utf-8")
    assert old in text, old
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_the_fixture_is_clean(tree):
    """A table whose baseline is already red proves nothing below it."""
    assert problems(tree) == []


def test_the_shipped_tree_is_clean():
    """No fixture and the real floors: this is the row `check.sh` runs."""
    assert threat_gate.audit(threat_gate.ROOT)[0] == []


def test_the_shipped_ratchets_are_this_trees_counts():
    """The floors and the ceiling, AT the tree rather than under it.

    Every case below monkeypatches them, so nothing pinned their shipped values:
    measured, `FLOOR_CLAUSES = FLOOR_P0 = 0` and `CEILING_UNTRACED = 999` left
    the whole table green. The sibling this file borrows its constants from
    closed the same hole in `test_matrix_gate.py`.
    """
    root = threat_gate.ROOT
    doc = (root / threat_gate.DOC).read_text(encoding="utf-8")
    assert threat_gate.FLOOR_CLAUSES == len(threat_gate.clause_units(doc))
    assert threat_gate.FLOOR_P0 == len(threat_gate.p0_family(root))
    untraced = threat_gate.load(root, threat_gate.CLAUSES)["untraced"]
    assert threat_gate.CEILING_UNTRACED == len(untraced)


#: Clauses whose bodies are locked past their first line, and how many pins each
#: carries. A pin inside a clause is VOLUNTARY — nothing derives it the way an
#: `[[untraced]]` `why` or a `PLAT-…` hand-off does — so measured, deleting every
#: pin of both applet-policy clauses leaves the traceability row and this file at
#: exit 0, with 530 and 648 words of body rewritable again. A floor and not an
#: equality: another lock is an improvement and must not read as a regression.
FLOOR_PINS = {"TM-HOST-ALGO-CHANGE": 2, "TM-HOST-OTP-REPLAY": 3}


def test_the_voluntarily_pinned_clauses_still_carry_their_pins():
    """The hole inside the hole `rests_on` closes.

    `where` locks a clause's first line and a pin locks a sentence under it — but
    an undemanded pin is itself deletable at exit 0, which leaves the body free
    text again by exactly the edit the pin was written to refuse. Both clauses
    here were reviewed into their current wording (the drop is conditional, the
    residual count is six), and it is those sentences the pins hold.
    """
    clauses = threat_gate.load(threat_gate.ROOT, threat_gate.CLAUSES)["clause"]
    pins = {c["id"]: len(c.get("rests_on", [])) for c in clauses}
    for cid, floor in FLOOR_PINS.items():
        assert pins.get(cid, 0) >= floor, (cid, pins.get(cid, 0), floor)


def test_a_new_bullet_is_a_clause_nobody_classified(tree):
    edit(
        tree,
        "docs/threat-model.md",
        "## Zeroization",
        "- **Fuzzing.** Every parser has a target.\n\n## Zeroization",
    )
    assert any("nobody classified" in p for p in problems(tree)), problems(tree)


def test_a_reworded_clause_rots_its_roster_entry(tree):
    """The lock is the clause's first line, so a reword is a citation moving."""
    edit(
        tree,
        "docs/threat-model.md",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.",
        "- **Protocol gates.** PINs/UV, touch on FIDO.",
    )
    found = problems(tree)
    assert any("not a clause of" in p and "TM-HOST-GATES" in p for p in found), found


def test_a_deleted_clause_rots_its_roster_entry(tree):
    """The other spelling of the same edit: removed, not reworded."""
    edit(tree, "docs/threat-model.md", "## Zeroization\n", "")
    found = problems(tree)
    assert any("not a clause of" in p and "TM-ZEROIZATION" in p for p in found), found


def test_text_inserted_above_a_clause_does_not_rot_it(tree):
    """The reason `where` is content and not a line number.

    `formal/citations.lock` pays for the other choice: any inserted line shifts
    every citation below it, and re-pointing them is where five agents have gone
    wrong. A clause that only moved down the page is not a finding.
    """
    edit(tree, "docs/threat-model.md", "## Assets", "One more paragraph.\n\n## Assets")
    assert problems(tree) == []


@pytest.mark.parametrize(
    "marker",
    ["* **Fuzzing.** Every parser has a target.",
     "+ **Fuzzing.** Every parser has a target.",
     "1. **Fuzzing.** Every parser has a target.",
     "#### Fuzzing",
     "###### Fuzzing"],
)
def test_a_clause_in_another_spelling_is_still_a_clause(tree, marker):
    """The page writes `-` and `##`; the same clause by another hand is `*`, `+`,
    an ordered item or a deeper heading. A derivation that cannot SEE one is the
    only direction that fails green, so every marker CommonMark takes counts."""
    edit(tree, "docs/threat-model.md", "## Zeroization", f"{marker}\n\n## Zeroization")
    assert any("nobody classified" in p for p in problems(tree)), problems(tree)


@pytest.mark.parametrize("rule", ["=", "=======", "-", "--", "---", "-------"])
def test_a_setext_heading_is_refused_rather_than_missed(tree, rule):
    """The one heading spelling no regex above can read; refuse it out loud.

    Every underline length, because the first draft demanded `-{3,}` and
    CommonMark makes a SINGLE `-` an H2 — the rule written for one spelling,
    inside the guard written to close that.
    """
    edit(tree, "docs/threat-model.md", "## Zeroization", f"Fuzzing\n{rule}\n\n## Zeroization")
    found = problems(tree)
    assert any("setext heading" in p for p in found), found


@pytest.mark.parametrize(
    "shape",
    ["> - **Rate limiting.** A callout.",
     "> **Rate limiting.** A callout.",
     "| Threat | Defence |",
     "<ul><li><b>Rate limiting.</b> In HTML.</li></ul>"],
)
def test_a_clause_in_a_shape_this_row_cannot_read_is_refused(tree, shape):
    """A blockquote, a table row or an HTML list can each carry a clause and
    none of them is a heading or a list item. A table is the likeliest — this
    repo's other docs enumerate exactly this kind of thing in one."""
    edit(tree, "docs/threat-model.md", "## Zeroization", f"{shape}\n\n## Zeroization")
    found = problems(tree)
    assert any("cannot read" in p or "invisible" in p for p in found), found


def test_a_thematic_break_between_blank_lines_is_not_one(tree):
    """The other arm: an ordinary `---` rule is legal markdown, not a heading."""
    edit(tree, "docs/threat-model.md", "## Zeroization", "---\n\n## Zeroization")
    assert problems(tree) == []


def test_trailing_whitespace_is_not_a_clause_moving(tree):
    """`where` is the clause's text, and two trailing spaces are not a rewrite."""
    edit(
        tree,
        "docs/threat-model.md",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.  ",
    )
    assert problems(tree) == []


def test_a_tilde_fence_hides_its_contents_too(tree):
    """`~~~` is the other fence CommonMark takes, and a `-` line inside one is
    no more a clause than a `-` line inside a mermaid diagram."""
    edit(tree, "docs/threat-model.md", "## Zeroization", "~~~\n- not a clause\n~~~\n\n## Zeroization")
    assert problems(tree) == []


def test_an_arrow_inside_a_fence_is_not_a_clause(tree):
    """The mermaid diagram carries `-` lines; reading them as clauses would put
    the roster permanently one entry short of a page nobody can classify."""
    assert "- this arrow is not a clause" in (tree / "docs/threat-model.md").read_text()
    assert problems(tree) == []


def test_a_p0_row_with_no_clause_and_no_verdict_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, '\n[[untraced]]\nid = "SEC-STORE-001"', '\n[[unused]]\nid = "x"')
    found = problems(tree)
    assert any("no untraced verdict" in p and "SEC-STORE-001" in p for p in found), found


def test_the_bare_file_name_does_not_trace_a_p0_row(tree):
    """What 34 rows said. Naming the page names no threat."""
    edit(tree, threat_gate.REGISTRY, '"docs/store-refinement.md"', '"docs/threat-model.md"')
    found = problems(tree)
    assert any("say WHICH clause" in p for p in found), found


def test_the_tranche_is_what_decides_the_bare_spelling(tree):
    """The rule is scoped to the P0 family on purpose, so prove BOTH arms.

    `SEC-ADM-001` cites the page as a whole and is clean because it is `p1`; the
    same source text in `p0b` is a finding. A rule that reddened it either way
    would be a wider change wearing this one's justification, and one that
    reddened it neither way would be no rule at all.
    """
    assert all("SEC-ADM-001" not in p for p in problems(tree))
    # MOVED, not copied: `matrix_gate.py` owns the "in two tranches" rule, and a
    # property in both reads as the later one here.
    edit(tree, threat_gate.LEDGER, 'p0b = []', 'p0b = ["SEC-ADM-001"]')
    edit(tree, threat_gate.LEDGER, 'p1 = ["SEC-ADM-001"]', "p1 = []")
    found = problems(tree)
    assert any("SEC-ADM-001" in p and "say WHICH clause" in p for p in found), found


def test_a_clause_id_that_does_not_exist_is_refused(tree):
    edit(tree, threat_gate.REGISTRY, "#TM-ZEROIZATION", "#TM-ZEROISATION")
    found = problems(tree)
    assert any("is no clause of" in p for p in found), found


@pytest.mark.parametrize(
    "spelling",
    ["docs/threat-model.md#tm-zeroization",
     "./docs/threat-model.md#TM-ZEROIZATION",
     "docs/threat-model.md #TM-ZEROIZATION",
     "threat-model.md#TM-ZEROIZATION"],
)
def test_a_clause_reference_this_row_cannot_resolve_is_refused(tree, spelling):
    """Each of these falls through every rule while LOOKING like a citation."""
    edit(tree, threat_gate.REGISTRY, "docs/threat-model.md#TM-ZEROIZATION", spelling)
    found = problems(tree)
    assert any("cannot resolve" in p for p in found), found


def test_a_missing_input_is_a_sentence_not_a_traceback(tree):
    """Red either way; only one of the two says what to do about it."""
    (tree / threat_gate.CLAUSES).unlink()
    found = problems(tree)
    assert found == [f"{threat_gate.CLAUSES} is missing — the mapping is unchecked"]


def test_unparseable_toml_is_a_sentence_not_a_traceback(tree):
    (tree / threat_gate.CLAUSES).write_text("[[clause]\nid =", encoding="utf-8")
    found = problems(tree)
    assert len(found) == 1 and "cannot be read" in found[0], found


def test_an_empty_roster_does_not_pass_vacuously(tree):
    """A rule that loops over nothing holds over nothing."""
    (tree / threat_gate.CLAUSES).write_text("# nothing here\n", encoding="utf-8")
    found = problems(tree)
    assert sum("nobody classified" in p for p in found) == 8, found


def test_a_context_clause_cannot_be_served(tree):
    """"Serving" the asset list is not a claim, so citing one is a finding."""
    edit(tree, threat_gate.REGISTRY, "#TM-ZEROIZATION", "#TM-ASSETS")
    found = problems(tree)
    assert any("not a `defence`" in p and "TM-ASSETS" in p for p in found), found


def test_a_stale_untraced_entry_is_refused(tree):
    """The exemption outliving its finding — `assurance_gate.py`'s own rule."""
    edit(
        tree,
        threat_gate.REGISTRY,
        '"docs/store-refinement.md"',
        '"docs/threat-model.md#TM-HOST"',
    )
    found = problems(tree)
    assert any("stale" in p and "SEC-STORE-001" in p for p in found), found


def test_an_untraced_verdict_must_be_one_of_the_two(tree):
    edit(tree, threat_gate.CLAUSES, 'verdict = "missing-clause"', 'verdict = "later"')
    found = problems(tree)
    assert any("is not one of" in p and "SEC-STORE-001" in p for p in found), found


def test_an_untraced_shrug_is_refused(tree):
    edit(
        tree,
        threat_gate.CLAUSES,
        'why = "not TM-HOST-POWER-CUT, which scopes itself to the interrupted write"',
        'why = "TODO"',
    )
    found = problems(tree)
    assert any("under" in p and "words" in p and "SEC-STORE-001" in p for p in found), found


def test_an_untraced_finding_nobody_owns_is_refused(tree):
    """Stage 0's exit bullet, on the second register that carries open items.
    `verdict` already types what would end the finding — `missing-clause` means
    write the clause — and who owes it was the missing half."""
    edit(tree, threat_gate.CLAUSES, 'owner = "contributor"\n', "")
    found = problems(tree)
    assert any("owed by None" in p and "SEC-STORE-001" in p for p in found), found
    assert any("an obligation nobody owns is a wish" in p for p in found), found


def test_an_untraced_owner_outside_the_four_roles_is_refused(tree):
    """One vocabulary across the registers: `platform_gate` chose it and this
    borrows it, so `someone` is as refused here as it is there."""
    edit(tree, threat_gate.CLAUSES, 'owner = "contributor"', 'owner = "someone"')
    found = problems(tree)
    assert any("owed by 'someone'" in p for p in found), found


def test_the_owner_vocabulary_is_the_one_platform_gate_already_chose():
    """Borrowed, not copied — the identity is the assertion, for the reason the
    `FLOOR_WORDS` above it is borrowed rather than re-picked."""
    assert threat_gate.OWNERS is platform_gate.OWNERS


def test_a_field_an_untraced_entry_does_not_read_is_refused(tree):
    """Neither record in this file had a field list, so a key added to one was
    held by no rule and shown by no reader — the hole `matrix_gate`'s
    `[[question]]` had, asked of its sibling register."""
    edit(tree, threat_gate.CLAUSES, 'verdict = "missing-clause"', 'verdict = "missing-clause"\nreview_by = "2027-01-01"')
    found = problems(tree)
    assert any("carrying ['review_by']" in p for p in found), found


def test_a_field_a_clause_does_not_read_is_refused(tree):
    """And of the other record in the same file: closing one of two is how a
    class survives its own fix."""
    edit(tree, threat_gate.CLAUSES, 'where = "## Zeroization"', 'where = "## Zeroization"\nnote = "later"')
    found = problems(tree)
    assert any("carries ['note']" in p and "TM-ZEROIZATION" in p for p in found), found


def test_a_table_the_clause_file_does_not_read_is_refused(tree):
    """And of the file itself, which is where the same question ran out."""
    edit(tree, threat_gate.CLAUSES, "[[untraced]]", '[[review]]\nwhen = "2027-01-01"\n\n[[untraced]]')
    found = problems(tree)
    assert any("carries a `review` table" in p for p in found), found


def test_the_report_shows_who_owes_each_untraced_finding(tree):
    """A field the reader never sees is the same hole one step out: the gate
    would hold it and the register would still read as unowned."""
    lines = threat_gate.audit(tree)[1]
    assert any("untraced [missing-clause, contributor]" in line for line in lines), lines


def test_an_untraced_entry_for_a_row_outside_the_p0_family_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'id = "SEC-STORE-001"\nverdict', 'id = "SEC-ADM-001"\nverdict')
    found = problems(tree)
    assert any("not a P0-family property" in p for p in found), found


def test_the_untraced_ceiling_holds(tree, monkeypatch):
    """A finding register that grows silently is a hatch."""
    monkeypatch.setattr(threat_gate, "CEILING_UNTRACED", 0)
    found = problems(tree)
    assert any("over the ceiling" in p for p in found), found


def test_a_context_clause_owes_its_argument(tree):
    edit(
        tree,
        threat_gate.CLAUSES,
        'why = "the asset inventory the rest of the page defends, not a threat"',
        'why = "n/a"',
    )
    found = problems(tree)
    assert any("TM-ASSETS" in p and "no argument" in p for p in found), found


def test_a_clause_kind_outside_the_two_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'id = "TM-HOST"\nkind = "defence"', 'id = "TM-HOST"\nkind = "note"')
    found = problems(tree)
    assert any("is not one of" in p and "TM-HOST" in p for p in found), found


def test_a_clause_id_source_cannot_cite_is_refused(tree):
    """`REF` takes `TM-` and upper case; anything else is an entry no `source`
    can name, and the failure would otherwise surface as a message blaming the
    citing row's spelling."""
    edit(tree, threat_gate.CLAUSES, 'id = "TM-HOST"\nkind', 'id = "TM-Host"\nkind')
    found = problems(tree)
    assert any("not a clause id" in p for p in found), found


def test_a_clause_entry_missing_a_field_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'where = "## Zeroization"\n', "")
    found = problems(tree)
    assert any("has no id or no `where`" in p for p in found), found


def test_an_untraced_entry_with_no_id_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, '[[untraced]]\nid = "SEC-STORE-001"\n', "[[untraced]]\n")
    found = problems(tree)
    assert any("has no id" in p for p in found), found


def test_a_property_untraced_twice_is_refused(tree):
    """One row, one verdict: two entries can carry two different ones."""
    text = (tree / threat_gate.CLAUSES).read_text(encoding="utf-8")
    block = text[text.index("[[untraced]]"):]
    (tree / threat_gate.CLAUSES).write_text(text + "\n" + block, encoding="utf-8")
    found = problems(tree)
    assert any("untraced twice" in p for p in found), found


def test_a_duplicate_clause_id_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'id = "TM-ZEROIZATION"', 'id = "TM-HOST"')
    found = problems(tree)
    assert any("duplicate clause id" in p for p in found), found


def test_two_entries_claiming_one_clause_are_refused(tree):
    """The mirror of the rule above: one page unit, one classification. Two of
    them can disagree about `kind`, and whichever came first would win."""
    edit(tree, threat_gate.CLAUSES, 'where = "## Zeroization"', 'where = "## Assets"')
    found = problems(tree)
    assert any("claim the same clause" in p for p in found), found


def test_two_clauses_that_read_alike_are_refused(tree):
    """The roster addresses a clause by its text; two of them cannot be told apart."""
    edit(tree, "docs/threat-model.md", "## Zeroization", "## Assets\n\n## Zeroization")
    found = problems(tree)
    assert any("read identically" in p for p in found), found


def test_a_source_naming_a_file_that_is_not_there_is_refused(tree):
    """The hook stages 9C/9D/10 land on: `docs/ct-audit.md`, `docs/unsafe.md`
    and `docs/limitations.md` are cited by nothing yet, and a citation of a page
    that moved reads as authoritative while pointing at nothing."""
    edit(tree, threat_gate.REGISTRY, '"docs/store-refinement.md"', '"docs/ct-audit.md"')
    found = problems(tree)
    assert any("not in the tree" in p for p in found), found


def test_the_clause_floor_is_not_vacuous(tree, monkeypatch):
    """A derivation that finds nothing satisfies every rule above it."""
    monkeypatch.setattr(threat_gate, "FLOOR_CLAUSES", 44)
    found = problems(tree)
    assert any("under the floor" in p for p in found), found


def test_the_p0_floor_is_not_vacuous(tree):
    """The tranche lists are another file's, so an emptied one arrives silently."""
    edit(tree, threat_gate.LEDGER, 'p0-launch = ["SEC-FIDO-001", "SEC-FIDO-007", ', "p0-launch = [")
    found = problems(tree)
    assert any("under the floor" in p and "P0-family" in p for p in found), found


PIN = "**Scope: the interrupted write.** A faulted read is another condition."


@pytest.mark.parametrize(
    "rewrite",
    [pytest.param("", id="deleted"),
     pytest.param("  **Scope: the write.** A faulted read is another condition.\n",
                  id="reworded"),
     pytest.param("  **Scope: the interrupted write.** A faulted read is another"
                  " condition\n", id="stop-dropped"),
     pytest.param("  **Scope: the “interrupted” write.** A faulted read is another"
                  " condition.\n", id="smart-quotes"),
     pytest.param(f"  <!-- {PIN} -->\n", id="commented-out"),
     pytest.param(f"  <!-- {PIN}\n", id="comment-left-open"),
     pytest.param(f"  ```\n  {PIN}\n  ```\n", id="fenced-into-a-sample"),
     pytest.param("  *Scope: the interrupted write.* A faulted read is another"
                  " condition.\n", id="emphasis-weakened")],
)
def test_a_rewrite_below_the_locked_first_line_is_refused(tree, rewrite):
    """The hole `rests_on` exists for: `where` locks line one and nothing under it.

    Deleting the sentence that scopes this clause away from faulted reads leaves
    three untraced verdicts arguing from text that is gone, and every rule above
    stays green over it. Each spelling here is a way to make that edit look like
    something else — a word, a full stop, a quote pair, the emphasis that carries
    "Scope" as a keyword. The last three are the ones a substring lock reads as
    no edit at all — each takes the sentence off the page, or out of its prose,
    and leaves it in the source byte for byte. `comment-left-open` and
    `fenced-into-a-sample` were both GREEN when only closed comments were
    stripped, which is why the body now drops fenced lines and everything after
    an unterminated `<!--` as well.
    """
    edit(tree, "docs/threat-model.md", f"  {PIN}\n", rewrite)
    found = problems(tree)
    assert any("no longer in the body" in p and "SEC-STORE-001" in p for p in found), found


def test_the_pinned_sentence_moved_to_another_clause_says_where_it_went(tree):
    """A sentence in the wrong clause reads as a reword and is not one.

    The pin is scoped to the clause the verdict argues from, so text that walked
    to a sibling is refused — and the message names the new host, because "it was
    reworded" would send the reader looking for an edit nobody made.
    """
    edit(tree, "docs/threat-model.md", f"  {PIN}\n", "")
    edit(
        tree,
        "docs/threat-model.md",
        "Key-grade material in RAM is wiped when its use ends.",
        f"Key-grade material in RAM is wiped when its use ends. {PIN}",
    )
    found = problems(tree)
    assert any("it is under TM-ZEROIZATION now" in p for p in found), found


@pytest.mark.parametrize(
    "rewrite",
    [pytest.param("  **Scope: the interrupted write.** A faulted read is\n"
                  "  another condition.\n", id="reflowed"),
     pytest.param("      **Scope: the interrupted write.** A faulted read is another"
                  " condition.\n", id="re-indented"),
     pytest.param("  **Scope: the interrupted write.** A faulted read is another"
                  " condition.   \n", id="trailing-space"),
     pytest.param("  **Scope: the interrupted write.**\u00a0A faulted read is another"
                  " condition.\n", id="non-breaking-space"),
     pytest.param("  **Scope: the <!-- n -->interrupted write.** A faulted read is"
                  " another condition.\n", id="comment-spliced")],
)
def test_a_pin_is_a_sentence_and_not_a_layout(tree, rewrite):
    """The other arm, and the reason the pin is normalised rather than verbatim.

    Measured by `clause_bodies` over `git log --reverse 3d6ec61 -- <the page>`,
    34 bodies changed with their first line intact against 12 first lines
    reworded, so a pin that fired on every re-wrap would fire on most edits. `comment-spliced` is the
    mirror of `commented-out` above and the reason both come out right: a comment
    inside a sentence renders as nothing, so the sentence on the page is the same
    one. `non-breaking-space` is the one that is a real gap rather than a choice \u2014
    `str.split()` counts U+00A0 as whitespace, so that substitution is invisible
    here, and it is invisible to a reader too.
    """
    edit(tree, "docs/threat-model.md", f"  {PIN}\n", rewrite)
    assert problems(tree) == []


def test_a_comment_opened_under_an_earlier_clause_still_hides_the_pin(tree):
    """The half a per-clause strip cannot see: neither end is in this body.

    Opened under the bullet above and closed after the pinned sentence, a browser
    hides everything between — including the whole clause — while every byte
    stays in the source. Comments are blanked over the WHOLE page for this.
    """
    edit(tree, "docs/threat-model.md", "  A residual, not a defence.",
         "  A residual, not a defence. <!--")
    edit(tree, "docs/threat-model.md", f"  {PIN}\n", f"  {PIN}\n  -->\n")
    found = problems(tree)
    assert any("no longer in the body" in p and "SEC-STORE-001" in p for p in found), found


@pytest.mark.parametrize(
    "wrapper",
    [pytest.param('<span hidden>{}</span>', id="span-hidden"),
     pytest.param('<div style="display:none">{}</div>', id="display-none"),
     pytest.param('<details><summary>x</summary>{}</details>', id="details"),
     pytest.param('<script type="text/plain">{}</script>', id="script")],
)
def test_raw_html_in_a_pinned_body_is_refused_rather_than_interpreted(tree, wrapper):
    """Each of these renders to nothing (or to a click) and matches as present.

    A rule that enumerated the hiding tags would be a renderer with a shorter
    list than a browser's, which is the shape this file has been bitten by. So a
    pinned body may not carry raw HTML at all, and the row says why.
    """
    edit(tree, "docs/threat-model.md", f"  {PIN}\n", f"  {wrapper.format(PIN)}\n")
    found = problems(tree)
    assert any("raw HTML" in p for p in found), found


def test_a_code_span_is_not_raw_html(tree):
    """The other arm, and the false positive the page already contains once:
    `Fs<S>` in backticks renders literally and hides nothing."""
    edit(
        tree,
        "docs/threat-model.md",
        "  and under the order sits `PLAT-FLASH-001`,",
        "  and `Fs<S>` under the order sits `PLAT-FLASH-001`,",
    )
    edit(
        tree,
        threat_gate.CLAUSES,
        "and under the order sits `PLAT-FLASH-001`, discharged by a board run.",
        "and `Fs<S>` under the order sits `PLAT-FLASH-001`, discharged by a board run.",
    )
    assert problems(tree) == []


def test_a_pin_that_is_only_the_assumption_id_locks_no_sentence(tree):
    """`PLAT-FLASH-001` alone satisfies "the pin names the assumption" and leaves
    the sentence around it free to be replaced by its own opposite."""
    edit(
        tree,
        threat_gate.CLAUSES,
        'rests_on = ["and under the order sits `PLAT-FLASH-001`, discharged by a board run."]',
        'rests_on = ["PLAT-FLASH-001"]',
    )
    found = problems(tree)
    assert any("owes a `rests_on` pin on the sentence naming it" in p for p in found), found


def test_a_malformed_platform_registry_is_a_sentence_not_a_traceback(tree):
    """`assumption` holding strings rather than tables — red either way, and only
    one of the two says what to do about it."""
    (tree / threat_gate.ASSUMPTIONS).write_text(
        'assumption = ["PLAT-FLASH-001"]\n', encoding="utf-8"
    )
    found = problems(tree)
    assert any("is no assumption of" in p for p in found), found


def test_a_verdict_arguing_from_a_clause_owes_a_pin_inside_it(tree):
    """The completeness half, derived: naming a clause in `why` IS the dependency.

    A `locks` list somebody has to remember to extend is the hole this repo has
    shipped in five guards running; the `why` already names what the verdict
    rests on, so the pin is owed the moment the argument is written.
    """
    edit(tree, threat_gate.CLAUSES, f'rests_on = ["{PIN}"]\n', "")
    found = problems(tree)
    assert any("owes a `rests_on` pin inside TM-HOST-POWER-CUT" in p for p in found), found


def test_a_why_arguing_from_a_clause_id_that_does_not_exist_is_refused(tree):
    """The demand is keyed on the `why` naming a clause, so a TYPO drops it.

    Measured on the real tree before this rule: mistype the id and delete the
    pin, and the row exits 0 — one character buys the exemption the rule above
    exists to refuse. It is the shape this repo keeps shipping: a guard bypassed
    by a spelling nobody enumerated, here inside the guard written to close it.
    """
    edit(tree, threat_gate.CLAUSES, "not TM-HOST-POWER-CUT,", "not TM-HOST-POWERCUT,")
    edit(tree, threat_gate.CLAUSES, f'rests_on = ["{PIN}"]\n', "")
    found = problems(tree)
    assert any("TM-HOST-POWERCUT" in p and "is no clause of" in p for p in found), found


def test_a_pin_from_a_clause_the_why_never_names_is_refused(tree):
    """Ownership: a pin may only lock text of the clause it argues from."""
    edit(
        tree,
        threat_gate.CLAUSES,
        f'rests_on = ["{PIN}"]',
        'rests_on = ["Key-grade material in RAM is wiped when its use ends."]',
    )
    found = problems(tree)
    assert any(
        "SEC-STORE-001" in p and "it is under TM-ZEROIZATION now" in p for p in found
    ), found


def test_a_clause_handing_its_claim_to_an_assumption_owes_a_pin(tree):
    """The second derivation, and the second sentence of clause A it protects.

    A body that writes a `PLAT-…` id is saying part of this defence is discharged
    somewhere else and is not yet. Delete that sentence and the clause reads as a
    defence the firmware implements, which is the claim getting stronger by an
    edit — the one direction that must not pass.
    """
    edit(
        tree,
        threat_gate.CLAUSES,
        'rests_on = ["and under the order sits',
        'unused = ["and under the order sits',
    )
    found = problems(tree)
    assert any("owes a `rests_on` pin on the sentence naming it" in p for p in found), found


def test_deleting_the_assumption_sentence_rots_its_pin(tree):
    """The other arm of the same rule: the pin is what makes the demand bite."""
    edit(
        tree,
        "docs/threat-model.md",
        "  and under the order sits `PLAT-FLASH-001`, discharged by a board run.\n",
        "",
    )
    found = problems(tree)
    assert any(
        "TM-HOST-POWER-CUT" in p and "no longer in the body" in p for p in found
    ), found


def test_a_clause_naming_an_assumption_that_is_not_registered_is_refused(tree):
    """A hand-off to a row that is not in `assurance/platform.toml` hands off to
    nothing, and reads on the page exactly like one that does."""
    edit(tree, "docs/threat-model.md", "`PLAT-FLASH-001`", "`PLAT-FLASH-009`")
    edit(tree, threat_gate.CLAUSES, "`PLAT-FLASH-001`", "`PLAT-FLASH-009`")
    found = problems(tree)
    assert any("is no assumption of" in p for p in found), found


def test_a_rests_on_that_is_not_a_list_of_strings_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, f'rests_on = ["{PIN}"]', f'rests_on = "{PIN}"')
    found = problems(tree)
    assert any("is a list of verbatim sentences" in p for p in found), found


def test_an_empty_pin_locks_nothing(tree):
    edit(tree, threat_gate.CLAUSES, f'rests_on = ["{PIN}"]', 'rests_on = ["   "]')
    found = problems(tree)
    assert any("locks nothing" in p for p in found), found


def test_the_platform_registry_is_an_input_of_this_row(tree):
    """It became one when a clause could hand its claim to an assumption id."""
    (tree / threat_gate.ASSUMPTIONS).unlink()
    found = problems(tree)
    assert found == [f"{threat_gate.ASSUMPTIONS} is missing — the mapping is unchecked"]


def test_check_assurance_sh_runs_this_gate():
    """The row, with its flags — a name match cannot pin those.

    `test_gate_scripts.py` covers the set; this covers the invocation, the way
    `crate_graph` and `security_trace` pin theirs.
    """
    text = (threat_gate.ROOT / "scripts/check-assurance.sh").read_text()
    assert gate_lines.runs(text, "scripts/threat_gate.py"), "check-assurance.sh does not run it"
    assert 'run "threat-model traceability" python scripts/threat_gate.py' in text


# ---- the verdict column may not disagree with its own `why` -------------------
#
# Two rows had a `verdict` that argued against their own reasoning:
# `missing-clause` says WRITE the clause, and `SEC-FIDO-007`'s `why` argues at
# length that writing one would be a threat model stronger than its firmware.
# `would-overclaim` is that third answer, and it is the maintainer's for the same
# reason `defends-nothing` is: it decides what this project will never claim.


def test_the_third_verdict_is_the_maintainers(tree):
    edit(tree, threat_gate.CLAUSES, 'verdict = "missing-clause"', 'verdict = "would-overclaim"')
    found = problems(tree)
    assert any("is a DECISION about what" in p for p in found), found


def test_the_third_verdict_with_its_owner_is_accepted(tree):
    edit(tree, threat_gate.CLAUSES, 'verdict = "missing-clause"', 'verdict = "would-overclaim"')
    edit(tree, threat_gate.CLAUSES, 'owner = "contributor"', 'owner = "maintainer"')
    assert problems(tree) == []


def test_the_maintainer_verdicts_are_a_subset_of_the_vocabulary():
    """A word in one roster and not the other is a rule nothing can reach."""
    assert set(threat_gate.MAINTAINER_VERDICTS) <= set(threat_gate.VERDICTS)


def test_the_shipped_register_obeys_the_owner_rule():
    """Asserted over the SHIPPED file, not only over the fixture: the rule was
    added because a shipped row broke it."""
    import tomllib

    doc = tomllib.loads(
        (threat_gate.ROOT / threat_gate.CLAUSES).read_text(encoding="utf-8")
    )
    for entry in doc.get("untraced", []):
        if entry.get("verdict") in threat_gate.MAINTAINER_VERDICTS:
            assert entry.get("owner") == "maintainer", entry.get("id")
