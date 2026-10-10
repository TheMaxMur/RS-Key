# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `bundle_gate.py`.

One arm per rule, each breaking the real bundle in one place — the fixture IS the
shipped bundle, because a synthetic one would prove the rules about a document
nobody has to keep true. The two arms worth naming are the ones the contract
turns on: a group that keeps its heading and loses its body, and a cost written
as a range.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bundle_gate  # noqa: E402

ROOT = bundle_gate.ROOT


def scalar(value):
    """One TOML value. `json.dumps` because a basic string escapes the same way."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(scalar(v) for v in value) + "]"
    return json.dumps(str(value))


def dump(doc) -> str:
    """The bundle, re-serialised.

    The arms below delete a group and write the document back, and they cannot do
    that by cutting HEADING lines out of the text: the orphaned body then lands in
    whatever table precedes it and `tomllib` raises. Measured — 8 of the 20
    parametrized cases were a `TOMLDecodeError` and asserted nothing, on exactly
    the array-of-tables groups the contract is mostly made of.
    """
    out = []
    for key, value in doc.items():
        rows = value if isinstance(value, list) else [value]
        head = f"[[{key}]]" if isinstance(value, list) else f"[{key}]"
        for row in rows:
            out.append(head)
            for field, item in row.items():
                out.append(f"{field} = {scalar(item)}")
            out.append("")
    return "\n".join(out) + "\n"


def method_targets(doc):
    """The files the method rows point at, resolved the way the gate resolves
    them — derived rather than transcribed, so a new row arrives in the fixture
    instead of quietly dangling in it."""
    for row in doc.get("method", []):
        for word in re.split(r"[\s+]+", str(row.get("artifact", ""))):
            name = word.strip(bundle_gate.TRIM).partition("::")[0]
            found = bundle_gate.resolve(ROOT, name)
            if found is not None:
                yield str(found.relative_to(ROOT))


def tree(tmp_path):
    """A checkout carrying EVERY real bundle, the registry, every artifact and
    every file a method row's `artifact` names.

    Every bundle and not just [`bundle_gate.BUNDLE`], because the roster is the
    directory now: a fixture holding one of two would put the shipped roster
    under its own floor and make every case in this file fail for the wrong
    reason — the failure mode this table exists to refuse.

    The slice page comes too, because `METHODS` is now held against п.3 and a
    fixture without it would report a missing page in every case here — the
    fixture asserted instead of the rule.
    """
    for fixed in (bundle_gate.REGISTRY, bundle_gate.SLICE):
        (tmp_path / fixed).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / fixed, tmp_path / fixed)
    for relative in bundle_gate.bundles(ROOT):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, tmp_path / relative)
        doc = tomllib.loads((ROOT / relative).read_text())
        for name in [row["path"] for row in doc["artifact"]] + list(method_targets(doc)):
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, target)
    return tmp_path


def rewrite(root, change):
    """Apply `change` to the parsed bundle and write it back."""
    path = root / bundle_gate.BUNDLE
    doc = tomllib.loads(path.read_text())
    change(doc)
    path.write_text(dump(doc))


def edit(root, old, new, count=1):
    path = root / bundle_gate.BUNDLE
    text = path.read_text()
    assert text.count(old) >= count, old
    path.write_text(text.replace(old, new, count))


def findings(root):
    return bundle_gate.audit(root)[0]


def test_the_real_bundle_is_green():
    assert findings(ROOT) == []


def test_the_fixture_is_the_real_bundle(tmp_path):
    assert findings(tree(tmp_path)) == []


@pytest.mark.parametrize("group", bundle_gate.GROUPS)
def test_a_missing_group_blocks_the_exit(tmp_path, group):
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc.pop(group))
    assert any(f"group `{group}` is missing" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("group", bundle_gate.GROUPS)
def test_a_group_that_keeps_its_heading_and_loses_its_body(tmp_path, group):
    """Ten headings with one line each satisfy "all ten groups are present",
    which is the whole reason this counts leaves."""
    root = tree(tmp_path)

    def strip(doc):
        doc[group] = (
            [{"kept": "one line"}] if isinstance(doc[group], list) else {"kept": "one line"}
        )

    rewrite(root, strip)
    problems = findings(root)
    assert any(f"group `{group}` carries 1 leaf" in p for p in problems), problems


@pytest.mark.parametrize(
    "group,field",
    [(g, f) for g, fields in bundle_gate.REQUIRED.items() for f in fields],
)
def test_a_named_field_the_contract_owes_is_found_missing(tmp_path, group, field):
    """A leaf floor counts VOLUME. Renaming a field keeps the count, and padding
    a group with a long list of anything clears the floor — measured green.

    A trailing `*` is a prefix, so the arm for it drops the whole family: popping
    the literal key `bound_*` would raise `KeyError` and go red for the wrong
    reason, which is the shape this repo keeps paying for.
    """
    root = tree(tmp_path)

    def drop(doc):
        rows = doc[group] if isinstance(doc[group], list) else [doc[group]]
        gone = [field] if not field.endswith("*") else [
            key for key in rows[0] if key.startswith(field[:-1])
        ]
        assert gone, f"{field} matches nothing in row 0, so this case asserts nothing"
        for key in gone:
            rows[0].pop(key)

    rewrite(root, drop)
    assert any(f"no `{field}` — the contract names it" in p for p in findings(root)), findings(
        root
    )


@pytest.mark.parametrize("group", ["mutation", "cost", "artifact"])
def test_a_row_that_is_not_a_table(tmp_path, group):
    """`audit` has a finding for exactly this and never printed it: the filtered
    list was built and the UNFILTERED one iterated, so `mutation = ["a string"]`
    was an `AttributeError` traceback out of `row.get` — EXIT=1 for the wrong
    reason, in the file that exists to name the reason."""
    root = tree(tmp_path)
    path = root / bundle_gate.BUNDLE
    doc = tomllib.loads(path.read_text())
    doc.pop(group)
    path.write_text(f'{group} = ["a string, not a table"]\n' + dump(doc))
    problems = findings(root)
    assert any("is not a table" in p for p in problems), problems


def test_the_three_rosters_name_the_same_ten_groups():
    """`GROUPS` without `FLOORS` is a KeyError; `FLOORS` without `GROUPS` is
    silently dead, and that is the direction nothing would have shown."""
    assert set(bundle_gate.GROUPS) == set(bundle_gate.FLOORS) == set(bundle_gate.REQUIRED)


#: The contract's fields, by hand. The table above parametrizes over `REQUIRED`,
#: so it is a DRIFTER: removing `bound_*` from `REQUIRED["method"]` removes the
#: case with it — measured, 150 collected to 149, and the two failures that
#: arrived came from hand-written arms and not from the roster the commit
#: credited. This is the pin the drifter cannot be.
CONTRACT = {
    "property": ("id", "invariant", "statement", "subjects", "requirement", "threat_clause"),
    "build": ("commit", "tree_state", "matrix_column", "cargo_features", "host_triple"),
    "method": ("obligation", "method", "artifact", "bound_*", "shipped_relation", "cfg",
               "features"),
    "tool": ("name", "version", "provenance", "invocation", "environment"),
    "result": (),
    "artifact": ("run", "path", "bytes", "sha256"),
    "assumption": ("id", "statement", "kind", "discharger", "expressible", "registered"),
    "mutation": ("level", "mutant", "invocation", "expected", "verdict", "fell", "direction"),
    "freshness": ("measured",),
    "cost": ("artifact", "human_minutes", "runner_seconds", "peak_memory_mb", "basis"),
}


def test_every_field_the_contract_names_is_still_named():
    """A field dropped from `REQUIRED` takes its own negative arm with it, so the
    roster needs a copy nothing derives. Removing one here is a deliberate line
    in the diff, which is what a contract change should be."""
    assert bundle_gate.REQUIRED == CONTRACT


def test_a_log_of_the_same_length_is_not_the_same_log(tmp_path):
    """A byte count is satisfied by any file of that length — measured green
    before the digest, by swapping a 10-byte log for a different 10-byte one."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    target = root / doc["artifact"][0]["path"]
    raw = target.read_bytes()
    target.write_bytes(bytes((b ^ 0x20) if b > 0x40 else b for b in raw))
    assert len(target.read_bytes()) == len(raw)
    assert any("is not the one the run wrote" in p for p in findings(root)), findings(root)


def test_an_absolute_artifact_path_escapes_the_tree(tmp_path):
    """`root / "/etc/hosts"` is `/etc/hosts`, so `is_file()` passes and only the
    byte count is compared. "In the tree" is not what that checks."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["artifact"][0].update(path="/etc/hosts"))
    assert any("is absolute" in p for p in findings(root)), findings(root)


def test_every_bound_stripped_from_every_method_row(tmp_path):
    """The measured hole, in the shape it was driven: all 30 `bound_*` keys out
    of all 8 rows took the leaf count 419 -> 389 and left the exit at 0, because
    every floor still cleared. Roadmap §7.2 wants the bound as structured data
    and the only structured thing about it was that nothing read it."""
    root = tree(tmp_path)

    def strip(doc):
        for row in doc["method"]:
            for key in [k for k in row if k.startswith("bound_")]:
                row.pop(key)

    rewrite(root, strip)
    assert any("no `bound_*`" in p for p in findings(root)), findings(root)


def test_a_bound_is_owed_per_row_and_not_per_group(tmp_path):
    """A group-wide rule is cleared by one row keeping its bounds, and the row
    that lost them is the one whose scope stopped being stated."""
    root = tree(tmp_path)

    def strip(doc):
        row = doc["method"][-1]
        for key in [k for k in row if k.startswith("bound_")]:
            row.pop(key)

    rewrite(root, strip)
    assert any("method #8: no `bound_*`" in p for p in findings(root)), findings(root)


def test_a_bound_key_of_any_name_satisfies_the_row(tmp_path):
    """Bounds are per method — a sequence length here, a cardinality there — so
    naming one key would be requiring the wrong one. The NAMES are free; how
    many there are is not."""
    root = tree(tmp_path)

    def rename(doc):
        for row in doc["method"]:
            for order, key in enumerate([k for k in row if k.startswith("bound_")]):
                row[f"bound_a_name_nobody_wrote_{order}"] = row.pop(key)

    rewrite(root, rename)
    assert findings(root) == []


def test_every_row_reduced_to_one_bound(tmp_path):
    """The ratchet the roster left: `REQUIRED`'s `bound_*` is satisfied by ONE
    key, so all 8 rows at a single `bound_nothing = 0` was EXIT=0 over 397
    leaves — the measured hole was zero bounds and its replacement was one."""
    root = tree(tmp_path)

    def strip(doc):
        for row in doc["method"]:
            for key in [k for k in row if k.startswith("bound_")]:
                row.pop(key)
            row["bound_nothing"] = 0

    rewrite(root, strip)
    problems = findings(root)
    assert any("bound(s), under the floor of 2" in p for p in problems), problems
    assert any("key(s) over the method rows" in p for p in problems), problems


def test_a_bound_that_is_a_flag(tmp_path):
    """`bound_x = false` cleared the roster and bounds nothing."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][0].update({"bound_states": False}))
    assert any("never a flag" in p for p in findings(root)), findings(root)


def test_a_key_named_literally_bound_underscore(tmp_path):
    """The wildcard itself: `any(k.startswith("bound_"))` is true of `bound_`."""
    root = tree(tmp_path)

    def wildcard(doc):
        row = doc["method"][1]
        for key in [k for k in row if k.startswith("bound_")]:
            row.pop(key)
        row["bound_"] = 1
        row["bound_states"] = 2
        row["bound_pairs"] = 3

    rewrite(root, wildcard)
    assert any("is the prefix and not a name" in p for p in findings(root)), findings(root)


def test_a_bound_group_stripped_to_just_over_the_row_floor(tmp_path):
    """Eight rows at the per-row floor is 16 against the 30 the bundle carries,
    which is why the group has a floor of its own."""
    root = tree(tmp_path)

    def thin(doc):
        for row in doc["method"]:
            for key in [k for k in row if k.startswith("bound_")][2:]:
                row.pop(key)

    rewrite(root, thin)
    problems = findings(root)
    assert not any("bound(s), under the floor of 2" in p for p in problems), problems
    assert any("key(s) over the method rows" in p for p in problems), problems


@pytest.mark.parametrize(
    "value",
    ["n/a", "N/A", "N / A", "na", "-", "--", "—", "?", ".", "...", "…",
     "none", "None", "nil", "TBD", "todo", "unknown", "not applicable", 0],
)
@pytest.mark.parametrize("field", bundle_gate.PROSE_FIELDS)
def test_a_prose_field_occupied_by_a_non_answer(tmp_path, field, value):
    """`shipped_relation` refused a dropped key, an empty string and a
    whitespace-only one, and took `"n/a"` at exit 0 — the same dropped field in
    a spelling the REQUIRED roster cannot see."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][0].update({field: value}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


def test_none_is_an_answer_where_none_is_an_answer(tmp_path):
    """The two leaves the widening below is exempted at, and the only two: five
    method rows answer `cfg` with exactly `none` and four answer `features`,
    and there `none` means the build had none of it."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert [r["cfg"] for r in doc["method"]].count("none") == 5, doc["method"]
    assert [r.get("features") for r in doc["method"]].count("none") == 4, doc["method"]
    assert findings(root) == []


@pytest.mark.parametrize("field", ["cfg", "features"])
def test_the_exemption_is_the_value_and_not_the_field(tmp_path, field):
    """Exempting the two FIELDS outright takes `cfg = "n/a"` back — the same
    dropped field one spelling over, which is the defect this rule is named for."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][0].update({field: "n/a"}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "path",
    ["mutation.fell", "mutation.verdict", "mutation.expected", "build.commit",
     "build.host_triple", "tool.version", "property.statement", "property.invariant",
     "cost.basis", "freshness.measured"],
)
def test_a_leaf_outside_the_two_prose_fields_occupied_by_a_non_answer(tmp_path, path):
    """The measured scope of the first version: a sweep setting each of the
    bundle's 348 string leaves to `"n/a"` in turn left 266 at EXIT=0, and the
    non-answer rule owned 18 of the 57 refusals — all of them `[[method]]`.
    Every one of these was green while the docstring said each `[[mutation]]`
    records the assertion that FELL."""
    group, field = path.split(".")
    root = tree(tmp_path)

    def occupy(doc):
        rows = doc[group] if isinstance(doc[group], list) else [doc[group]]
        assert field in rows[0], f"{path} is not in the bundle any more"
        rows[0][field] = "n/a"

    rewrite(root, occupy)
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


#: The vocabulary, by hand. NOT parametrized over `bundle_gate.NON_ANSWERS`:
#: a table built from the constant loses a case when the constant loses a member,
#: which is the deletion this exists to catch. Measured — deleting 10 of the 18
#: members left `pytest scripts/test_bundle_gate.py` at EXIT=0, 150 passed, and
#: the table beside it had hand-written 19 values that reached 8 of them.
VOCABULARY = frozenset(
    {
        "na", "notapplicable", "noanswer", "seeabove", "ditto",
        "none", "nil", "null", "nothing",
        "unknown", "unspecified", "undefined", "unclear",
        "tbd", "tba", "tobedetermined", "todo", "xxx", "pending", "wip",
    }
)


def test_the_vocabulary_is_the_one_this_table_drives():
    """Equality, so a member deleted from the gate fails here rather than
    silently deleting its own case."""
    assert bundle_gate.NON_ANSWERS == VOCABULARY


@pytest.mark.parametrize("word", sorted(VOCABULARY))
def test_every_word_of_the_vocabulary_is_refused(tmp_path, word):
    """Driven through the gate, from the HAND roster: deleting `null`,
    `nothing`, `unspecified`, `undefined`, `unclear`, `tobedetermined`, `xxx`,
    `pending`, `wip` and the `n\\a` spelling was green over all 150 cases."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update({"fell": word}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "spelling",
    ["n.a.", "t.b.d.", "N/A;", "todo:", "not-applicable", "(none)", "TBA",
     "no answer", "see above", "ditto", "N.A", "tbd;", "  none  "],
)
def test_a_non_answer_wearing_punctuation(tmp_path, spelling):
    """The vocabulary compared with whitespace removed and a trailing `.!?…`
    stripped, so `;` and `:` bought a second spelling of the same word and all
    of these were EXIT=0. Normalized to alphanumerics now."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update({"fell": spelling}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


def test_a_method_artifact_naming_a_harness_that_is_gone(tmp_path):
    """The measured hole: deleting one of the four harnesses left the exit at 0,
    and the bundle's own `kani=4` line green at 3."""
    root = tree(tmp_path)
    harness = root / "crates/rsk-fido/src/state_kani.rs"
    harness.write_text(
        harness.read_text().replace("no_authorization_bypass_walk_owner", "a_harness_by_another_name")
    )
    assert any("declares no `" in p for p in findings(root)), findings(root)


def test_a_file_that_mentions_the_harness_is_not_the_file_that_has_it(tmp_path):
    """This rule's own first version read the file's raw text, and
    `credmgmt_kani.rs` names `no_authorization_bypass_walk_owner` in a doc
    comment — so pointing the walk row at the wrong file resolved at exit 0."""
    root = tree(tmp_path)
    mentions = (root / "crates/rsk-fido/src/credmgmt_kani.rs").read_text()
    assert "no_authorization_bypass_walk_owner" in mentions, "the fixture lost the mention"
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner",
         "credmgmt_kani.rs::no_authorization_bypass_walk_owner")
    assert any("declares no `no_authorization_bypass" in p for p in findings(root)), findings(root)


def test_a_harness_is_matched_whole_and_not_by_suffix(tmp_path):
    """The suffix arm belongs to the elision alone. Everywhere, it would make
    `::owner` resolve against `no_authorization_bypass_walk_owner` — the rule
    loosened by the shape it was written to support."""
    root = tree(tmp_path)
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner", "state_kani.rs::owner")
    assert any("declares no `owner`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("symbol", ["STEPS", "StepRng", "OP_STOP"])
def test_a_bounded_proof_discharged_by_a_const_or_a_struct(tmp_path, symbol):
    """`DECLARED` matches a const, a struct and anything under `#[cfg(test)]`, so
    the whole rule was "the file declares SOMETHING by that name": all three were
    measured green on the walk row."""
    root = tree(tmp_path)
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner", f"state_kani.rs::{symbol}")
    assert any("naming no `#[kani::proof]`" in p for p in findings(root)), findings(root)


def test_a_harness_that_lost_its_proof_attribute(tmp_path):
    """The name survives the deletion of the thing that makes it a proof. Before
    this, only `kani_gate.py`'s global count floor moved — 92 to 91, a different
    row, and blind to WHICH harness went."""
    root = tree(tmp_path)
    harness = root / "crates/rsk-fido/src/state_kani.rs"
    harness.write_text(harness.read_text().replace("#[kani::proof]\nfn no_authorization_bypass_walk_owner",
                                                   "fn no_authorization_bypass_walk_owner"))
    assert any("naming no `#[kani::proof]`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "target", ["CHANGELOG.md", "README.md", "assurance/bundle/SEC-FIDO-001.toml"],
)
def test_a_bounded_proof_discharged_by_any_file_in_the_tree(tmp_path, target):
    """Six of the eight rows carry no `::` at all, so for them the rule was "a
    file of that name exists". All three of these were EXIT=0 on the walk row."""
    root = tree(tmp_path)
    (root / target).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / target, root / target)
    edit(root, 'artifact = "crates/rsk-fido/src/state_kani.rs'
               '::no_authorization_bypass_walk_owner"', f'artifact = "{target}"')
    assert any("and no .rs" in p for p in findings(root)), findings(root)


def test_a_model_check_row_discharged_by_something_that_is_not_a_configuration(tmp_path):
    """The other half of the same rule, on the four rows that name a bare
    `Name.cfg`: the file resolving is not the file being a configuration."""
    root = tree(tmp_path)
    shutil.copy(ROOT / "CHANGELOG.md", root / "CHANGELOG.md")
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "CHANGELOG.md"')
    assert any("and no .cfg" in p for p in findings(root)), findings(root)


#: The check that RAN a published vector table, and the table it ran. Both real:
#: the arms below are about which of the two discharges the obligation.
KAT_TEST = "crates/rsk-mldsa/src/sign_tests.rs::acvp_keygen_pk_exact"
KAT_VECTORS = "crates/rsk-mldsa/src/testvectors.rs::KeyGenKat"

#: A `tests/*.py` — a runner by the directory it is in — and the two `.py` files
#: that resolved a KAT row at exit 0 before the `.py` arm had teeth. The second
#: pair is deliberately one file that declares `def`s and one that declares none,
#: so the refusal is about the row naming no RUNNER and not about the file being
#: empty of functions.
KAT_RUNNER = "tests/00_ctaphid_transport.py"
KAT_NOT_A_RUNNER = ("scripts/bundle_gate.py", "tools/rsk/__init__.py")

#: A `.py` outside `tests/` that a runner really does collect — the shape the
#: `def` arm exists for, once the arm stopped taking any `def` at all.
KAT_COLLECTED_CASE = "tools/rsk/test_audit.py::test_detail_of_a_single_config_write"


def as_kat(root, artifact):
    r"""Row #5 re-methoded to `KAT/differential` and pointed at `artifact`.

    Carrying the files that artifact names in by hand, because `tree` derives the
    fixture from the SHIPPED bundles and no shipped bundle uses the word — the
    rules below are the ones a first such row would meet.

    Split the way the GATE splits, on `[\s+]+` and not on `" + "`, and skipping
    the elision marker: a `path.rs::a + …b` row is one file and one back-
    reference, and copying `…b` as a path raised `FileNotFoundError` out of the
    fixture instead of reporting anything about the rule.
    """
    for word in re.split(r"[\s+]+", artifact):
        token = word.strip(bundle_gate.TRIM)
        if not token or token.startswith(bundle_gate.ELISION):
            continue
        name = token.partition("::")[0]
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / name, root / name)
    rewrite(root, lambda doc: doc["method"][4].update(
        {"method": "KAT/differential", "artifact": artifact}))
    return root


def test_a_kat_row_discharged_by_the_test_that_ran_the_vectors(tmp_path):
    """The control the arms below are read against: an ACVP `#[test]` over
    published vectors is what the word means, and it is green."""
    assert findings(as_kat(tree(tmp_path), KAT_TEST)) == []


def test_a_kat_row_discharged_by_the_vector_table_itself(tmp_path):
    """`DECLARED` matches the struct the vectors sit in, so without the `#[test]`
    arm the rule degenerates to "the file declares SOMETHING by that name" — the
    hole `::STEPS` walked through one method over. The table is the INPUT."""
    root = as_kat(tree(tmp_path), KAT_VECTORS)
    assert any("nothing that RAN the vectors" in p for p in findings(root)), findings(root)


def test_a_kat_row_discharged_by_a_tests_script(tmp_path):
    """The `.py` half of the method's own word, and the arm that pins the CONTENT
    of `METHOD_KIND["KAT/differential"]`: dropping `".py"` from the tuple makes
    this row resolve `['.py']` against `('.rs',)` and the kind rule fires. Before
    it, the tuple's second member was held only by an error-message substring
    built from `'/'.join(wanted)` — the spelling checked, the behaviour not."""
    assert findings(as_kat(tree(tmp_path), KAT_RUNNER)) == []


@pytest.mark.parametrize("target", KAT_NOT_A_RUNNER)
def test_a_kat_row_discharged_by_a_python_file_that_ran_nothing(tmp_path, target):
    """The measured hole. The `#[test]` arm was guarded on `".rs" in kinds` and
    the non-`.rs` branch only checked `symbol in text` when a `::symbol` was
    written, so a bare `.py` path carried no requirement past the file existing:
    this gate's OWN file and the host CLI's `__init__` were each EXIT=0."""
    root = as_kat(tree(tmp_path), target)
    assert any("nothing that RAN the vectors" in p for p in findings(root)), findings(root)


def test_a_kat_row_discharged_by_a_python_file_naming_a_def_it_declares(tmp_path):
    """The other half of the `.py` tooth, and the `.rs` arm's shape one language
    over: a script outside `tests/` discharges the row by naming the function,
    never by being a file. `symbol in text` is not that check — the name occurs
    in this file's own docstring too, which is why [`bundle_gate.definitions`]
    parses rather than matches.

    ANY `def` was the first spelling and it is not the `.rs` arm's shape: that
    one demands `#[test]`, and this one took `method_references`, a gate function
    that never ran a vector. It is [`bundle_gate.PYTEST_FUNCTION`]'s prefix now,
    which is the name pytest keys on where Rust has an attribute — so the case
    reads with a collected `def` and the gate function it used to accept is the
    arm one file over.
    """
    assert findings(as_kat(tree(tmp_path), KAT_COLLECTED_CASE)) == []


def test_a_kat_row_naming_the_vectors_and_the_script_that_ran_them(tmp_path):
    """The gradient. Adding the vector table to a green row must not redden it —
    the first spelling of this rule refused exactly this row while passing the
    weaker `.py`-only one, which is a worse failure than the hole it left."""
    assert findings(as_kat(tree(tmp_path), f"{KAT_VECTORS} + {KAT_RUNNER}")) == []


def test_a_kat_row_discharged_by_any_file_in_the_tree(tmp_path):
    """The kind half, on the one word whose kind is a PAIR: `.md` is neither."""
    root = as_kat(tree(tmp_path), "CHANGELOG.md")
    assert any("and no .rs/.py" in p for p in findings(root)), findings(root)


def test_the_kat_word_and_its_kind_are_one_change_or_neither(tmp_path, monkeypatch):
    """The guard-deletion mutant. `METHOD_KIND` losing the entry while `METHODS`
    keeps the word leaves `CHANGELOG.md` discharging a KAT obligation at exit 0:
    the runner rule is conditioned on the row reaching an artifact of its own
    KIND, so with the kind gone nothing stops a `.md`. A word added to the
    vocabulary ALONE is a widening, and this is the arm that says so.

    Red BEFORE the mutant and green after, in one case: `== []` alone passes for
    any reason the fixture is green, which is a case that asserts the fixture and
    not the rule.
    """
    root = as_kat(tree(tmp_path), "CHANGELOG.md")
    assert any("and no .rs/.py" in p for p in findings(root)), findings(root)
    monkeypatch.delitem(bundle_gate.METHOD_KIND, "KAT/differential")
    assert findings(root) == []


def test_every_method_kind_names_a_word_of_the_vocabulary():
    """A kind keyed on a word `METHODS` does not carry is silently dead — the
    direction `FLOORS` without `GROUPS` is, one roster over."""
    assert set(bundle_gate.METHOD_KIND) <= set(bundle_gate.METHODS)


def test_what_a_python_file_defines_is_parsed_and_not_matched(tmp_path):
    """A `def` in a comment or a string is what a pattern would take: the `.rs`
    half already paid for the difference — `credmgmt_kani.rs` names a harness in
    a doc comment and resolved the wrong file at exit 0. A file that does not
    parse defines nothing, which reddens the row resting on it."""
    source = tmp_path / "runner.py"
    source.write_text(
        "# def commented_out():\n"
        'TEXT = "def in_a_string(): pass"\n'
        "def ran_the_vectors():\n"
        "    async def nested(): pass\n"
    )
    assert bundle_gate.definitions(source) == {"ran_the_vectors", "nested"}
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n")
    assert bundle_gate.definitions(broken) == set()


def test_what_a_rust_file_declares_and_which_of_them_are_proofs(tmp_path):
    """`gate_lines.rust_code` blanks string literals BEFORE this runs, so the
    `extern "…"` alternative the pattern first carried could never match and
    `pub extern "C" fn target` was reported as undeclared — a branch nothing can
    take, wrong in the direction that refuses real code. And a `#[test]` fn is a
    declaration and not a harness, which is the half `::STEPS` walked through."""
    source = tmp_path / "x.rs"
    source.write_text(
        'pub extern "C" fn exported() {}\n'
        "\n"
        "/// A doc comment, blank by the time this runs.\n"
        "#[kani::proof]\n"
        "fn a_harness() {}\n"
        "\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn a_test() {}\n"
        "}\n"
    )
    declared, proofs, tests = bundle_gate.declarations(source)
    assert {"exported", "a_harness", "a_test", "tests"} <= set(declared), declared
    assert proofs == {"a_harness"}, proofs
    assert tests == {"a_test"}, tests


@pytest.mark.parametrize(
    "word", ["bounded proofs", "model check", "reviewed", "KAT differential", ""],
)
def test_a_method_word_outside_the_vocabulary(tmp_path, word):
    """The kind rule reads this field, so a typo silently drops it: `bounded
    proofs` is not `bounded proof`, and the harness arm stops applying."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][4].update({"method": word}))
    assert any("is in no row of §4.1's vocabulary" in p for p in findings(root)), findings(root)


def test_a_bound_written_as_prose_answers_something(tmp_path):
    """Half the bounds are numbers and `bound_totals` is a sentence, so requiring
    the KEY is satisfied by one bound reading `n/a` — measured green."""
    root = tree(tmp_path)

    def blank(doc):
        row = doc["method"][2]
        row[[k for k in row if k.startswith("bound_")][0]] = "n/a"

    rewrite(root, blank)
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


def test_a_numeric_bound_is_never_a_non_answer(tmp_path):
    """`bound_reset_window = 0` is a real bound — the window exercised closed."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert 0 in [r.get("bound_reset_window") for r in doc["method"]], doc["method"]
    assert findings(root) == []


def test_an_elided_harness_is_resolved_against_the_file_before_it(tmp_path):
    """`…_creds_begin_at_call_site` is a second harness in the file the token
    before it named, so it is the spelling a `::`-only reader walks past."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…_creds_begin_at_the_wrong_site")
    assert any("ends 0 declaration(s)" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("elision", ["…site", "…e", "…n", "...site"])
def test_an_elision_that_resolves_on_any_suffix(tmp_path, elision):
    """`…site` ends the antecedent's OWN harness — the second reference
    discharged by the first, which is the self-reference `superseded_by` refuses
    one function away. All four were EXIT=0."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", elision)
    assert any("declaration(s) of" in p for p in findings(root)), findings(root)


def test_an_elision_that_names_the_token_before_it(tmp_path):
    """The ambiguity count alone does not reach this one: `…rps_begin_at_call_site`
    ends exactly ONE declaration, and it is the harness the `::` token already
    named — one row, one proof, counted twice. Measured: dropping the
    already-named clause and keeping the count left all 169 cases green."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…rps_begin_at_call_site")
    assert any("ends 0 declaration(s)" in p for p in findings(root)), findings(root)


def test_a_bare_ellipsis_elides_nothing(tmp_path):
    """The symbol is falsy, so the resolver never went looking: EXIT=0."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…")
    assert any("elides nothing" in p for p in findings(root)), findings(root)


def test_an_extension_the_resolver_does_not_read_is_not_silence(tmp_path):
    """The `gives up, says nothing` arm: `.tlaa` in row 8 was skipped as prose
    because the row's OTHER token resolved, so `resolved > 0` and the typo was
    never looked at — EXIT=0, while `formal/DoesNotExist.tla` reddened."""
    root = tree(tmp_path)
    edit(root, "formal/RSKeySecurityState.tla", "formal/RSKeySecurityState.tlaa")
    assert any("extension this resolver does not read" in p for p in findings(root)), findings(root)


def test_a_bare_configuration_that_is_not_in_formal(tmp_path):
    """Four of the eight rows name a `.cfg` with no directory. Reading only
    `path::harness` leaves every one of them unresolved."""
    root = tree(tmp_path)
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "NoSuchThing.cfg"')
    assert any("is not in the tree" in p for p in findings(root)), findings(root)


def test_a_rust_file_named_without_its_harness(tmp_path):
    """A file resolves and proves nothing: the harness is what a bounded proof
    is identified by, and the file outlives any one of them."""
    root = tree(tmp_path)
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner", "state_kani.rs")
    assert any("names a Rust file and no `::harness`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("escape", ["absolute", "dot-dot"])
def test_a_method_artifact_that_escapes_the_tree(tmp_path, escape):
    """Both spellings point at a file that really is there — in the REAL tree.
    `root / "/x"` is `/x` and `root / "../../x"` climbs out, so `is_file()`
    answers yes to each and "in the tree" is not what that checks."""
    root = tree(tmp_path)
    real = ROOT / "formal/Shipped.cfg"
    target = str(real) if escape == "absolute" else os.path.relpath(real, root)
    assert (root / target).is_file(), target
    edit(root, 'artifact = "Shipped.cfg"', f'artifact = "{target}"')
    assert any("is not in the tree" in p for p in findings(root)), findings(root)


def test_a_method_row_whose_artifact_is_only_prose(tmp_path):
    root = tree(tmp_path)
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "a careful reading of the code"')
    assert any("resolves nothing in the tree" in p for p in findings(root)), findings(root)


def test_prose_beside_a_reference_is_not_demanded_to_resolve(tmp_path):
    """Two rows trail off into prose — `bounds table`, `over …`. A rule that
    demanded every word resolve is one that gets switched off inside a week."""
    root = tree(tmp_path)
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "Shipped.cfg, read against B1/B2 and the ladder"')
    assert findings(root) == []


def test_a_blank_leaf_is_a_dropped_field(tmp_path):
    root = tree(tmp_path)
    edit(root, 'id = "SEC-FIDO-001"', 'id = ""')
    assert any("is empty" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "value", ['"1.5 to 3x"', '"a few hours"', '"unknown"', '"~500 s"']
)
def test_a_cost_written_as_a_range_is_refused(tmp_path, value):
    """The whole point of the first closed slice is that its cost is MEASURED.
    An estimate in any of the three voids the measurement, and the design page
    is where the calibration counterpart's estimate is labelled as one."""
    root = tree(tmp_path)
    import re

    path = root / bundle_gate.BUNDLE
    path.write_text(
        re.sub(r"runner_seconds = [0-9.]+", f"runner_seconds = {value}", path.read_text(), count=1)
    )
    assert any("is not a number" in p for p in findings(root)), findings(root)


def test_a_cost_naming_a_log_that_is_in_no_artifact_row(tmp_path):
    """`[[artifact]].path` has 10 values and `[[cost]].artifact` 11, ten of them
    byte-identical and none of them joined: re-pointing all 11 at a log that is
    nowhere was EXIT=0."""
    root = tree(tmp_path)

    def repoint(doc):
        for row in doc["cost"]:
            row["artifact"] = "a log that does not exist anywhere.log"

    rewrite(root, repoint)
    assert any("the path of no `[[artifact]]` row" in p for p in findings(root)), findings(root)


def test_a_raw_artifact_with_no_cost_row(tmp_path):
    """The other direction. Item 10 is three numbers per artifact, so a log that
    nothing costs is a run whose cost was dropped."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["cost"].pop(0))
    assert any("with no `[[cost]]` row" in p for p in findings(root)), findings(root)


def test_a_cost_row_for_work_with_no_artifact_of_its_own(tmp_path):
    """The eleventh row is prose on purpose — the gates, the ledger axes and the
    adversarial review produced no log of their own — so the join is asked of a
    value shaped like a path and not of every value."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    prose = [r["artifact"] for r in doc["cost"] if r["artifact"].startswith("the work")]
    assert len(prose) == 1, [r["artifact"] for r in doc["cost"]]
    assert findings(root) == []


def test_a_missing_cost_field_is_found(tmp_path):
    root = tree(tmp_path)
    import re

    path = root / bundle_gate.BUNDLE
    path.write_text(re.sub(r"peak_memory_mb = [0-9.]+\n", "", path.read_text(), count=1))
    assert any("the item measures three, not one" in p for p in findings(root)), findings(root)


def test_an_artifact_that_is_not_in_the_tree(tmp_path):
    root = tree(tmp_path)
    gone = tomllib.loads((root / bundle_gate.BUNDLE).read_text())["artifact"][0]["path"]
    (root / gone).unlink()
    assert any("is not a log" in p for p in findings(root)), findings(root)


def test_a_summarized_log_is_not_an_artifact(tmp_path):
    """The byte count is what tells the unedited output from a tidied one."""
    root = tree(tmp_path)
    target = tomllib.loads((root / bundle_gate.BUNDLE).read_text())["artifact"][0]["path"]
    (root / target).write_text("summary only\n")
    assert any("was edited is not the unedited output" in p for p in findings(root)), findings(root)


def test_a_mutation_with_no_direction_is_not_a_verdict(tmp_path):
    """Two of twenty-four co-refutation patches scored a kill for the INVERSE
    defect, and the tell was that every failure said 'should have succeeded'."""
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "red"')
    assert any("is not one of" in p for p in findings(root)), findings(root)


def test_an_inverse_kill_with_no_disposition_is_not_a_verdict(tmp_path):
    """`"inverse"` was in the vocabulary and cost nothing: `"banana"` was refused
    and the word that names a kill for the OPPOSITE defect published at exit 0.
    Refusing it outright would have been worse — the cheapest way past a refusal
    is to type `modelled`, which nothing here resolves against a real run."""
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "inverse"')
    assert any("an INVERSE kill is a finding about the mutant" in p for p in findings(root)), (
        findings(root)
    )


@pytest.mark.parametrize("value", ["banana", "", "modelled ", "superseded_by", "n/a"])
def test_an_inverse_disposition_outside_the_vocabulary(tmp_path, value):
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update(direction="inverse", disposition=value))
    assert any("is not one of ('superseded'" in p for p in findings(root)), findings(root)


def test_a_superseded_inverse_kill_names_the_row_that_replaced_it(tmp_path):
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update(
        direction="inverse", disposition="superseded", superseded_by="a mutant nobody drove"))
    assert any("names no OTHER row" in p for p in findings(root)), findings(root)


def test_an_inverse_kill_cannot_supersede_itself(tmp_path):
    """A plain membership test over the group's own names is satisfied by the
    row's own `mutant`, which is the claim with nothing behind it again."""
    root = tree(tmp_path)

    def selfsame(doc):
        row = doc["mutation"][0]
        row.update(direction="inverse", disposition="superseded", superseded_by=row["mutant"])

    rewrite(root, selfsame)
    assert any("names no OTHER row" in p for p in findings(root)), findings(root)


def test_an_inverse_kill_kept_as_a_finding_still_owes_its_reading(tmp_path):
    """`reading` is where the direction is argued, and it is the whole content of
    a row that admits its kill was for the other defect."""
    root = tree(tmp_path)

    def strip(doc):
        row = doc["mutation"][0]
        row.update(direction="inverse", disposition="kept-as-a-finding")
        row["reading"] = "   "

    rewrite(root, strip)
    assert any("with no `reading`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("disposition", bundle_gate.DISPOSITIONS)
def test_a_disposed_inverse_kill_is_admitted_and_counted_apart(tmp_path, disposition):
    """The positive arm, and the reason the word is not simply refused: an
    inverse kill stays SAYABLE, and the success line says how many there are so
    it cannot be read as a verdict."""
    root = tree(tmp_path)

    def dispose(doc):
        rows = doc["mutation"]
        rows[0].update(direction="inverse", disposition=disposition,
                       superseded_by=rows[1]["mutant"])

    rewrite(root, dispose)
    problems, summary = bundle_gate.audit(root)
    assert problems == [], problems
    assert "9 mutation verdict(s) and 1 disposed as inverse" in summary, summary


@pytest.mark.parametrize(
    "key,old,new",
    [("gate_registry", "kani=4", "kani=99"),
     ("gate_registry", "cfgs=50", "cfgs=51"),
     ("gate_ledger", "walk=4", "walk=5"),
     ("gate_assumption", "FALSE=91", "FALSE=90"),
     ("gate_ghost", "24 route(s)", "25 route(s)"),
     ("gate_matrix", "1400 cells", "1401 cells")],
)
def test_a_transcribed_gate_line_that_the_gate_does_not_derive(tmp_path, key, old, new):
    """The second half of the hole `35afe59` named and did not close: editing
    `kani=4` to `kani=99` left `bundle-gate`, `evidence-gate` AND
    `assurance-gate` at EXIT=0, because `REQUIRED["result"]` names no field and
    the group is held only by a leaf floor of 18.

    `FALSE=88` was the arm that found a real one: the bundle said 88 and the tree
    held 89 `AlwaysUvShipped = FALSE` configurations at every commit from
    `58df09d` onwards, so the number was wrong the day it was typed.

    The two moving arms are typed here as well, and that is the cost of holding a
    transcription by mutating it: `cfgs=46` and `FALSE=89` both went stale the
    day the EF_MINPINLEN[1] gate added three configurations, and these cases went
    RED for the right reason — the bundle had been corrected and the case had
    not. A count in a test parameter is a third copy; what keeps it honest is
    that it fails loudly rather than passing over a bundle nobody re-derived.

    It has happened again and the same way round: `cfgs=49` moved to 50 with the
    two PermWide mutant configurations, and `24 routes` became `24 route(s)` when
    the five gate lines were re-derived out of `gate_corpus` instead of retyped.
    Both arms went RED against a corrected bundle, which is this case working.
    """
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"][key], doc["result"][key]
        doc["result"][key] = doc["result"][key].replace(old, new)

    rewrite(root, retype)
    problems = findings(root)
    assert any(f"result.{key}" in p for p in problems), problems


@pytest.mark.parametrize(
    "old,new",
    [("volatile=11/10", "volatile=11/12"),
     ("persistent=14/5", "persistent=14/11"),
     ("outcomes=7/6", "outcomes=7/12")],
)
def test_a_transcribed_fraction_denominator_is_that_gate_s(tmp_path, old, new):
    """The pair rule reads `persistent=14/5` as `persistent=14` and stops at the
    slash, so the denominator was left to the bare-integer rule — which asks only
    whether the number stands SOMEWHERE in the derived line. Every denominator
    here is replaced by one the SAME line carries (`11` off `api=11`, `12` off
    `softlock=12`), so the old two rules are both satisfied and only
    [`bundle_gate.CLAIMED_FRACTION`] can speak: measured, all three were exit 0
    before it. 33 denominators over 11 bundles were held that way.

    The count is asserted because it is the whole point — one finding, quoting
    the WHOLE token. A message naming `persistent=14` would be the pair rule
    firing on something else, and this case passing over it."""
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"]["gate_ledger"], doc["result"]["gate_ledger"]
        doc["result"]["gate_ledger"] = doc["result"]["gate_ledger"].replace(old, new, 1)

    rewrite(root, retype)
    problems = findings(root)
    assert [p for p in problems if f"`{new}`" in p], problems
    assert len(problems) == 1, problems


def test_a_transcribed_assumption_total_is_the_line_s_own(tmp_path):
    """The one leftover of `gate_assumption` the bare-integer rule reads, with ten
    `TRUE=` / `FALSE=` pairs behind it to match any small number — `5 → 3` was
    exit 0 off `ForceChangeModelled TRUE=3`. It is the same bite SEC-FIDO-003's
    own leaf records at `4` off `PowerOnClearsScratch2 FALSE=4`, still standing in
    the one line that had it.

    TWO findings now and the second one is the point: `standing` is a noun the
    same derived line writes a count for, so [`bundle_gate.CLAIMED_UNIT`] refuses
    this edit as well. Measured, both ways round — the swap is exit 1 with
    `CLAIMED_TOTAL` deleted, and exit 1 with the unit clause deleted. The count
    stays asserted because it is still the discriminator it was: what it now says
    is that exactly these two rules speak and no third one fired somewhere else."""
    root = tree(tmp_path)
    total = f"5 {bundle_gate.STANDING}"

    def retype(doc):
        line = doc["result"]["gate_assumption"]
        assert total in line, line
        doc["result"]["gate_assumption"] = line.replace(total, f"3 {bundle_gate.STANDING}", 1)

    rewrite(root, retype)
    problems = findings(root)
    assert [p for p in problems if f"`3 {bundle_gate.STANDING}`" in p], problems
    assert [p for p in problems if "says `3 standing assumption(s)` and" in p], problems
    assert len(problems) == 2, problems


def test_the_assumption_total_read_is_the_line_s_first():
    """SEC-FIDO-003's leaf QUOTES the `4 standing assumption(s)` it once carried,
    in the sentence that records the bite. A rule reading every occurrence calls
    that bundle red over its own history — measured, exit 1 on an unedited tree —
    so the total is the one the line opens with and the prose stays unread."""
    line = (
        f"assumption-gate: 5 {bundle_gate.STANDING} — the `4 {bundle_gate.STANDING}`"
        " that stood here stayed GREEN off `PowerOnClearsScratch2 FALSE=4`"
    )
    assert bundle_gate.CLAIMED_TOTAL.search(line).group(1) == "5"


@pytest.mark.parametrize(
    "key,old,new,says",
    [("gate_matrix", "(37 covered", "(109 covered", "109 covered"),
     ("gate_ghost", "21 action(s)", "24 action(s)", "24 action(s) record"),
     ("gate_matrix", "1111 gap", "109 gap", "109 gap"),
     ("gate_ghost", "11 guard(s)", "21 guard(s)", "21 guard(s)"),
     ("gate_matrix", "0 conditional", "37 conditional", "37 conditional"),
     ("gate_matrix", "40 P0-family", "35 P0-family", "35 P0-family properties")],
)
def test_a_transcribed_unit_count_is_the_one_that_noun_was_written_for(
    tmp_path, key, old, new, says
):
    """`gate_ghost` and `gate_matrix` carry no `name=value` pair anywhere, so the
    pair rule reads NOTHING in them and all 33 + 99 of their numbers fell to the
    bare-integer rule — "do these digits stand somewhere in the derived line".

    Every swap here takes its digits off a SIBLING count of the very line it
    falsifies (`109` off `109 out-of-scope`, `24` off `24 route(s)`, `21` off `21
    action(s)`, `37` off `37 covered`, `35` off `35 build`), so the old rules are
    all satisfied and only [`bundle_gate.CLAIMED_UNIT`] can speak: measured, every
    one was exit 0 before it. A swap onto a number the line NO LONGER carries is
    a case the bare-integer rule answers as well, which is how `(139 covered`
    stopped belonging here the hour `139 equivalent` became `143`.

    The count is asserted, and so is the DIRECTION of the message: it must say
    the claim carries a number the gate did not write for that noun. A case that
    goes red because a sibling rule fired somewhere else is a case that proves
    nothing about this one.

    The READING is asserted too, and two of them are two words long. Each claim
    position is reported once, on the LONGEST spelling the gate wrote a count
    for, so `40 P0-family properties → 35` is one finding about `P0-family
    properties` rather than two about the same drift. Typed out rather than
    derived for the reason every count here is: it is the third copy that fails
    loudly instead of the one that agrees with itself.

    `gap` has moved twice under these arms — four cells went from `gap` to
    `equivalent` while this case was being written, so `958 gap` became `954 gap`,
    and the three `display-keys` packages plus the GEEK board took it to `1111
    gap`. Each time this parameter went red for the right reason: the bundles had
    been re-derived and the case had not. It stays a typed number for the
    neighbour's reason one case up — a third copy that fails loudly beats one that
    passes over a bundle nobody re-derived."""
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"][key], doc["result"][key]
        doc["result"][key] = doc["result"][key].replace(old, new, 1)

    rewrite(root, retype)
    problems = findings(root)
    assert [p for p in problems if f"says `{says}`" in p], problems
    assert len(problems) == 1, problems


def test_a_unit_count_the_gate_line_quotes_again_is_prose(tmp_path):
    """A count the row CITES rather than transcribes, which is what the carve-out
    has to let through: SEC-FIDO-003's leaf quotes the `4 standing assumption(s)`
    it once carried, and a version reading every occurrence called it red over its
    own history — measured, and on this wider vocabulary still exactly one false
    finding.

    What marks the citation is BACKTICKS and no longer position. The
    first-occurrence version it replaces was a rule about LAYOUT: nothing required
    the transcription to come first, and the same sentence is 2 findings written
    before it and 0 written after — measured end to end, both ways. Both halves
    are here, because a carve-out with no negative arm is a rule switched off.

    `109` is a number the derived line HAS — off `109 out-of-scope` — so the
    bare-integer rule stays quiet and this case is about the carve-out and nothing
    else."""
    root = tree(tmp_path)

    def quote(doc):
        doc["result"]["gate_matrix"] += " The tier this replaced read `109 covered`."

    rewrite(root, quote)
    assert findings(root) == [], findings(root)


def test_a_unit_count_the_gate_line_restates_unquoted_is_a_transcription(tmp_path):
    """The other half of the carve-out above, and the hole it closes. The same
    sentence unquoted is read as a second transcription wherever it stands —
    AFTER the transcription, which is the placement the first-occurrence version
    let through at exit 0."""
    root = tree(tmp_path)

    def restate(doc):
        doc["result"]["gate_matrix"] += " The tier this replaced read 109 covered."

    rewrite(root, restate)
    problems = findings(root)
    assert [p for p in problems if "says `109 covered`" in p], problems
    assert len(problems) == 1, problems


@pytest.mark.parametrize(
    "key,old,new,says",
    [("gate_matrix", "35 build configurations", "37 build-configurations",
      "37 build-configurations"),
     ("gate_matrix", "1111 gap)", "109 gaps)", "109 gaps"),
     ("gate_matrix", "1400 cells", "109 cell", "109 cell"),
     ("gate_ghost", "11 guard(s)", "24 guards", "24 guards"),
     ("gate_ghost", "21 action(s) record", "24 actions record", "24 actions")],
)
def test_a_transcribed_unit_count_is_read_however_its_noun_is_spelt(
    tmp_path, key, old, new, says
):
    """One character of noun drift used to skip the comparison entirely.

    The vocabulary is the gate's own words, and a claim noun that was not one of
    them literally was not read at all — so `35 build configurations → 37
    build-configurations` was exit 0 while the byte-identical `37 build
    configurations` was exit 1, naming the drift it was supposed to catch. Every
    swap here is that shape: a plural, a singular, a `(s)` spelled out, a space
    turned into a hyphen, each carrying a count off a SIBLING of the same line so
    no older rule can speak.

    Held on a stem now ([`bundle_gate.unit_stem`]), and on the two-word reading of
    the position as well, which is the only thing that reaches
    `build-configurations` — the gate writes `build` and `configurations` as two
    words and the claim fuses them into one."""
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"][key], doc["result"][key]
        doc["result"][key] = doc["result"][key].replace(old, new, 1)

    rewrite(root, retype)
    problems = findings(root)
    assert [p for p in problems if f"says `{says}`" in p], problems
    assert len(problems) == 1, problems


def test_the_unit_stem_is_a_spelling_and_not_a_split():
    """What the stem may and may not collapse.

    A plural, a `(s)` and a hyphen are spellings of one noun. A hyphen SPLIT is
    not: `out-of-scope` reduced to `out` would be a vocabulary entry the gate
    never wrote, and the first thing a prose number collides with — which is the
    failure mode this rule has already had twice."""
    assert bundle_gate.unit_stem("gaps") == bundle_gate.unit_stem("gap")
    assert bundle_gate.unit_stem("guard(s)") == bundle_gate.unit_stem("guards")
    assert bundle_gate.unit_stem("build-configurations") == bundle_gate.unit_stem(
        "build configurations"
    )
    assert bundle_gate.unit_stem("out-of-scope") == "out of scope"
    assert bundle_gate.unit_stem("is") == "is"


def test_a_gate_line_whose_every_count_is_quoted_is_not_a_transcription(tmp_path):
    """The carve-out's own degeneracy arm, and the reason [`bundle_gate.UNIT_FLOOR`]
    exists. Opening `gate_matrix` with one backtick puts the whole transcription
    inside a quotation, and every count in it stops being compared with nothing
    said — the failure this tree keeps finding in its own new guards. The bundle
    reads 4 of its 12 then, under the floor of 9."""
    root = tree(tmp_path)
    edit(root, 'gate_matrix = "matrix-gate', 'gate_matrix = "`matrix-gate')
    problems = findings(root)
    assert [p for p in problems if "reading(s) over its gate lines" in p], problems
    assert len(problems) == 1, problems


def test_a_count_whose_noun_the_gate_never_wrote_is_the_row_s_own(tmp_path):
    """The vocabulary is the GATE's, derived from its own line, so a bundle
    counting something the gate does not count is prose — `gate_matrix` ends in a
    sentence about the slice and that sentence is the row's to write. A rule
    holding every `<count> <noun>` against every number the line carries is the
    naive version, and it fires on honest text."""
    root = tree(tmp_path)

    def add(doc):
        doc["result"]["gate_matrix"] += " The slice adds 40 reviews of its own."

    rewrite(root, add)
    assert findings(root) == [], findings(root)


@pytest.mark.parametrize(
    "old,new,says",
    [("PowerOnClearsScratch2 TRUE=11 FALSE=4", "PowerOnClearsScratch2 TRUE=2 FALSE=13",
      "`PowerOnClearsScratch2 TRUE=2` and the gate derives `TRUE=11`"),
     ("AlwaysUvShipped TRUE=5 FALSE=91", "AlwaysUvShipped TRUE=5 FALSE=93",
      "`AlwaysUvShipped FALSE=93` and the gate derives `FALSE=91`"),
     ("WidePerms TRUE=3 FALSE=93", "WidePerms TRUE=11 FALSE=93",
      "`WidePerms TRUE=11` and the gate derives `TRUE=3`")],
)
def test_a_transcribed_pair_whose_name_repeats_belongs_to_its_own_constant(
    tmp_path, old, new, says
):
    """`gate_assumption` writes ten pairs under two names, and `name=value` alone
    identified none of them.

    It is [`bundle_gate.registry_line`]'s lesson one field over: the pair rule
    asked "does SOME constant have this" where it meant "does THIS constant have
    this". Every swap here takes its values off another constant's arms four
    tokens down the same line, so the pair rule, the fraction rule and the
    bare-integer rule are all satisfied and only the owner clause can speak:
    measured end to end, `PowerOnClearsScratch2 TRUE=11 FALSE=4 → TRUE=2
    FALSE=13` is exit 0 with byte-identical output before it, and 101 of that
    line's 129 numbers were held that loosely.

    The leaf this bite is recorded in credits the pair rule with catching the
    earlier drift. It could not have: it caught it because those digits stood
    nowhere in the line at all, which is the bare-integer rule."""
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"]["gate_assumption"], doc["result"]["gate_assumption"]
        doc["result"]["gate_assumption"] = doc["result"]["gate_assumption"].replace(
            old, new, 1
        )

    rewrite(root, retype)
    problems = findings(root)
    assert [p for p in problems if says in p], problems


def test_a_pair_name_written_once_stays_the_pair_rule_s(tmp_path):
    """The clause above is scoped to names that REPEAT, so the ledger's nine axes
    and the registry's seven are untouched by it — a widening that reached them
    would make every pair depend on the word a bundle happens to put in front of
    it, and the eleven bundles reflow that word freely.

    Driven rather than argued: `keys=2` moved off its own line is still ONE
    finding, and it is the pair rule's."""
    root = tree(tmp_path)

    def retype(doc):
        doc["result"]["gate_ledger"] = doc["result"]["gate_ledger"].replace(
            "GREEN keys=2", "GREEN, the ledger says: keys=2", 1
        )

    rewrite(root, retype)
    assert findings(root) == [], findings(root)


def test_the_owner_of_a_pair_is_the_last_word_that_is_not_one():
    """What `owner` means, on the line the clause exists for."""
    line = "5 x AlwaysUvShipped TRUE=5 FALSE=91 ForceChangeModelled TRUE=3 FALSE=93"
    assert bundle_gate.owned_pairs(line) == [
        ("AlwaysUvShipped", "TRUE", "5"),
        ("AlwaysUvShipped", "FALSE", "91"),
        ("ForceChangeModelled", "TRUE", "3"),
        ("ForceChangeModelled", "FALSE", "93"),
    ]
    assert bundle_gate.owned_pairs("keys=2 api=11") == [("", "keys", "2"), ("", "api", "11")]


@pytest.mark.parametrize(
    "key,old,new,says",
    [("gate_matrix", "40 P0-family", "40 P37-family", "`P0-family`"),
     ("gate_ghost", "record NoAuthorizationBypass over", "record NoAuthorizationBypasx over",
      "`NoAuthorizationBypass`"),
     ("gate_ledger", "token-refinement-gate: GREEN", "token-refinement-gate: RED",
      "`GREEN`")],
)
def test_a_transcription_copies_the_gate_s_words_and_not_only_its_digits(
    tmp_path, key, old, new, says
):
    """Every rule above reads DIGITS, so the word carrying the verdict rotted
    freely and the digits inside a NAME were never numbers to begin with.

    `GREEN → RED` is the shape at its plainest: a green ledger transcribed as a
    red one, with every count still correct, was exit 0. `P0-family → P37-family`
    and a misspelt invariant are the same edit on a name, and they are also where
    38 of the numbers no rule holds in position live — `P0-family`'s `0`,
    `PowerOnClearsScratch2`'s `2`, `SEC-FIDO-001`'s `001` — because a digit
    inside a name is not a count of anything and no count rule can reach it.

    `37` is a number the matrix line carries, off `37 covered`, so the
    bare-integer rule stays quiet and only [`bundle_gate.gate_words`] speaks."""
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"][key], doc["result"][key]
        doc["result"][key] = doc["result"][key].replace(old, new, 1)

    rewrite(root, retype)
    problems = findings(root)
    assert [p for p in problems if says in p and "drops the gate's own" in p], problems
    assert len(problems) == 1, problems


def test_a_lowercase_word_of_a_derived_line_is_the_gate_s_prose(tmp_path):
    """Where that rule stops. `ok`, `record`, `over` and `consulting` are the
    gate's sentence and not its data — SEC-FIDO-005 drops the `ok` from two of its
    lines, and requiring it would be the rule firing on honest text. Measured over
    all eleven: it is the only word a capital-or-digit filter has to spare.

    So are the PAIR names, which two rules already hold in position: requiring the
    word `TRUE` is satisfied on SEC-FIDO-003 — the one bundle that transcribes no
    arm counts at all — only by the phrase "TRUE/FALSE" in a sentence about not
    transcribing them, and a check resting on prose is the thing this file is
    about."""
    root = tree(tmp_path)
    edit(root, "matrix-gate: ok — 40 P0-family", "matrix-gate: 40 P0-family")
    assert findings(root) == [], findings(root)


@pytest.mark.parametrize(
    "old,new,says",
    [("NoAuthorizationBypass                    BOUNDED",
      "NoAuthorizationBypass                    MODELLED-ONLY", "carries the verdict"),
     ('gate_registry = "SEC-FIDO-001   ', 'gate_registry = "SEC-FIDO-50   ', "drops `SEC-FIDO-001`")],
)
def test_the_registry_row_transcribed_is_named_and_answered_by_this_property_s(
    tmp_path, old, new, says
):
    """The roster gate's half of the same rule, and it cannot be the other half.

    Its corpus is a roster, so the claim transcribes ONE row of it and abbreviates:
    two of the eleven bundles write the id and the verdict without the invariant
    name, and requiring every derived word there is the rule firing on honest text
    — measured, 2 of 11. What the row is held to instead is its own id, its own
    verdict, and no sibling's verdict; every one of the eleven carries all three
    today, and the roster is where the alternatives come from rather than a list
    here.

    `50` is `cfgs=50` off the row's own line, so the id swap is answered by this
    clause and not by the bare-integer rule."""
    root = tree(tmp_path)
    edit(root, old, new)
    problems = findings(root)
    assert [p for p in problems if says in p], problems


def test_the_unit_vocabulary_stops_where_another_rule_already_reads():
    """The lookbehind, which is what keeps this clause off numbers already
    compared IN POSITION by the pair and fraction rules. Without the `=`, the
    joined arm line offers `91 ForceChangeModelled` as a count of a constant
    name; without the `/`, `persistent=14/5 outcomes=7/6` offers `5 outcomes`,
    which is a roster size read as a count of the axis after it."""
    arms = f"5 {bundle_gate.STANDING} AlwaysUvShipped TRUE=5 FALSE=91 ForceChangeModelled"
    assert bundle_gate.derived_units(arms) == {
        "standing": ({"5"}, "standing"),
        "standing assumption": ({"5"}, "standing assumption(s)"),
    }
    ledger = "GREEN keys=2 api=11 volatile=11/10 persistent=14/5 outcomes=7/6 walk=4"
    assert bundle_gate.derived_units(ledger) == {}


@pytest.mark.parametrize("key", bundle_gate.GATE_RESULTS)
def test_a_transcribed_gate_line_with_its_numbers_taken_out(tmp_path, key):
    """Both rules above compare the numbers a line HAS, so a line with none
    satisfies them — the same spelling as the roster satisfied by one key, one
    rule over. It clears the leaf floor and the non-answer rule too."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["result"].update({key: "the gate was green"}))
    assert any("carries no number" in p for p in findings(root)), findings(root)


def test_a_result_line_transcribing_a_gate_this_file_cannot_derive(tmp_path):
    """The resolver's own lesson one group over: a `gate_*` key nothing knows how
    to check must say so rather than be skipped."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["result"].update({"gate_nobody": "nobody-gate: 7 things"}))
    assert any("cannot" in p and "derive" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("key", bundle_gate.GATE_RESULTS)
def test_a_transcribed_gate_line_deleted(tmp_path, key):
    """Deleting one leaves the group at 21 leaves against a floor of 18, so the
    volume rule cannot see it — the roster is what does."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["result"].pop(key))
    assert any(f"`result.{key}` is gone" in p for p in findings(root)), findings(root)


def cycle(doc, length, reading=None):
    """The first `length` rows inverse, each superseded by the next, the last by
    the first — every row a step and none of them a result."""
    rows = doc["mutation"]
    for order in range(length):
        rows[order].update(
            direction="inverse", disposition="superseded",
            superseded_by=rows[(order + 1) % length]["mutant"],
            reading=reading or f"row {order} is a step towards row {order + 1}",
        )


@pytest.mark.parametrize("length", [2, 3])
def test_a_superseded_by_cycle_corrects_nothing(tmp_path, length):
    """Self-reference was excluded and cycles were not: A superseded by B and B
    by A printed `8 mutation verdict(s) and 2 disposed as inverse` at EXIT=0,
    with neither mutant corrected."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: cycle(doc, length))
    assert any("reaches no corrected mutant" in p for p in findings(root)), findings(root)


def test_a_group_that_disposed_of_every_row(tmp_path):
    """All ten rows inverse in a ten-cycle printed `0 mutation verdict(s) and 10
    disposed as inverse` at EXIT=0 — a table that killed nothing, published as
    one that killed ten."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: cycle(doc, 10))
    problems = findings(root)
    assert any("under the floor of 8" in p for p in problems), problems


def test_every_inverse_row_carrying_the_same_reading(tmp_path):
    """The reading argues THIS row's direction. Ten `kept-as-a-finding` rows all
    reading `x` was EXIT=0, and so was one sentence copied across all ten."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: cycle(doc, 3, reading="the same sentence, three times"))
    assert any("share one `reading`" in p for p in findings(root)), findings(root)


def test_the_disposition_register_on_a_row_it_is_not_about(tmp_path):
    """`disposition = "banana"` beside a `superseded_by` naming no row at all,
    on a `modelled` row, was silently accepted and never validated."""
    root = tree(tmp_path)

    def stray(doc):
        doc["mutation"][0].update(disposition="banana",
                                  superseded_by="a row that does not exist")

    rewrite(root, stray)
    assert any("the disposition register belongs to" in p for p in findings(root)), findings(root)


def test_a_reading_is_owed_by_every_direction_not_only_by_the_inverse_one(tmp_path):
    """The first version of the rule above refused `reading` on a `modelled` row
    and reddened all ten of the real bundle's — it argues whichever direction the
    row records, so it belongs on any of them."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert all(str(row.get("reading", "")).strip() for row in doc["mutation"]), doc["mutation"]
    assert findings(root) == []


def test_a_mutation_that_does_not_say_which_assertion_fell(tmp_path):
    root = tree(tmp_path)
    import re

    path = root / bundle_gate.BUNDLE
    path.write_text(re.sub(r'fell = "[^"]*"\n', 'fell = ""\n', path.read_text(), count=1))
    assert any("is empty" in p for p in findings(root)), findings(root)


def test_a_property_the_registry_does_not_carry(tmp_path):
    root = tree(tmp_path)
    edit(root, 'id = "SEC-FIDO-001"', 'id = "SEC-NOPE-999"')
    assert any("is in no row of" in p for p in findings(root)), findings(root)


def test_a_group_outside_the_contract_is_refused(tmp_path):
    root = tree(tmp_path)
    path = root / bundle_gate.BUNDLE
    path.write_text(path.read_text() + '\n[extra]\nnote = "not a group"\n')
    assert any("is in no group of the contract" in p for p in findings(root)), findings(root)


def test_an_empty_roster_is_under_the_floor(tmp_path):
    (tmp_path / "assurance").mkdir()
    assert any("under the floor of" in p for p in findings(tmp_path)), findings(tmp_path)


def test_a_bundle_removed_from_the_roster_reddens(tmp_path):
    """The direction that matters: a closed slice unclosing itself, silently.

    The floor is passed as a PARAMETER at the SHIPPED value, so this case proves
    the rule about the number the tree actually ships rather than about a 1 the
    case wrote. Deleting one bundle from an n-bundle tree must leave n-1 < n.
    """
    root = tree(tmp_path)
    shipped = len(bundle_gate.bundles(root))
    assert shipped >= bundle_gate.ROSTER_FLOOR, shipped
    (root / bundle_gate.bundles(root)[0]).unlink()
    reported = bundle_gate.audit(root, roster_floor=shipped)[0]
    assert any("under the floor of" in p for p in reported), reported


def test_the_shipped_floor_is_not_above_the_shipped_roster():
    """A floor over the count is the row red on a tree nobody touched."""
    assert len(bundle_gate.bundles(ROOT)) >= bundle_gate.ROSTER_FLOOR


def test_a_second_bundle_is_audited_and_not_merely_counted(tmp_path):
    """The roster is the DIRECTORY: a file dropped in is held to the contract.

    Without this the generalisation is a counter — `len(glob)` past a floor —
    and a second bundle arrives green because nothing opens it. Measured on the
    first version, which globbed for the count and audited `BUNDLE`.
    """
    root = tree(tmp_path)
    first = bundle_gate.bundles(root)[0]
    text = (root / first).read_text().replace('id = "SEC-FIDO-001"', 'id = "SEC-FIDO-002"', 1)
    # Broken in ONE place, and in the place the contract turns on: a copy that is
    # merely valid proves only that the roster counted it.
    (root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-002.toml").write_text(
        text[: text.index("[[cost]]")]
    )
    reported = findings(root)
    assert any("SEC-FIDO-002.toml" in p and "`cost`" in p for p in reported), reported


def test_a_bundle_named_for_a_property_it_does_not_carry(tmp_path):
    """A copy under a new name is the first slice twice, and every other rule
    passes it: same ten groups, same floors, same artifact digests."""
    root = tree(tmp_path)
    first = bundle_gate.bundles(root)[0]
    shutil.copy(root / first, root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-007.toml")
    reported = findings(root)
    assert any("is named for" in p and "SEC-FIDO-007" in p for p in reported), reported


def test_a_bundle_that_is_not_readable_as_toml(tmp_path):
    """The glob finds it, so it must be a finding and not a traceback."""
    root = tree(tmp_path)
    (root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-008.toml").write_text("[property\nid =")
    reported = findings(root)
    assert any("is not readable as TOML" in p for p in reported), reported


def test_main_prints_a_summary_and_reports_findings(tmp_path, capsys, monkeypatch):
    assert bundle_gate.main() == 0
    assert capsys.readouterr().out.startswith("bundle-gate: ok —")
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "red"')
    monkeypatch.setattr(bundle_gate, "ROOT", root)
    assert bundle_gate.main() == 1
    assert "direction" in capsys.readouterr().err


def test_a_transcribed_registry_count_is_this_property_s(tmp_path):
    """The corpus for `gate_registry` is EVERY property's vector joined, so a pair
    was compared against all of them: `rust=1` is true of thirty other rows, and a
    bundle whose own property had moved to `rust=2` kept the old number at exit 0.
    Found by a real move, not invented — tagging the producer of `SEC-FIDO-007`'s
    antecedent took its `rust` column up and this row stayed green."""
    root = tree(tmp_path)
    bundle = root / bundle_gate.BUNDLE
    doc = tomllib.loads(bundle.read_text())
    line = doc["result"]["gate_registry"]
    # A count that is real SOMEWHERE in the roster and wrong for this property.
    doc["result"]["gate_registry"] = re.sub(r"\bkani=\d+", "kani=1", line)
    bundle.write_text(dump(doc))
    reported = findings(root)
    assert any("gate_registry" in p and "kani=1" in p for p in reported), reported


def test_the_registry_line_picked_is_the_subject_s():
    corpus = "  SEC-FIDO-001 A rust=2\n  SEC-FIDO-007 B rust=9\n"
    assert "rust=9" in bundle_gate.registry_line(corpus, "SEC-FIDO-007")
    assert "rust=2" in bundle_gate.registry_line(corpus, "SEC-FIDO-001")
    # No subject, or one the roster does not carry: the whole corpus, which is
    # the previous behaviour and refuses nothing extra.
    assert bundle_gate.registry_line(corpus, "SEC-NOPE-999") == corpus


# ---- a number printed next to a log occurs in that log ----------------------
#
# The measured population is 198 numbers over 63 joins, and the arms below are
# one per clause of `quoted_join` plus the floor: each deletes its clause alone
# and the gate goes green over the defect underneath it.

QUOTED = "is in no line of"
RECONCILED = ("is 446 passed and 172 failed", "is 493 passed and 176 failed")


def edit_in(root, bundle, old, new, count=1):
    """`edit`, on a bundle other than [`bundle_gate.BUNDLE`]."""
    path = root / bundle_gate.BUNDLE_DIR / bundle
    text = path.read_text()
    assert text.count(old) >= count, old
    path.write_text(text.replace(old, new, count))


def quoted(root):
    """THIS rule's findings, and the population it reached.

    Scoped to the rule rather than to `audit`, because a green arm here asserts
    that the transcription rule says nothing — not that every other rule in the
    file is also green, which is `test_the_real_bundle_is_green`'s claim and not
    this table's.
    """
    reported = []
    return reported, bundle_gate.quoted_numbers(root, reported)


def test_a_run_result_reconciled_with_a_later_measurement(tmp_path):
    """The defect this rule was written for. `assurance/configurations.toml`
    forbids exactly this by hand — "the pair 446/172 is NOT a superseded version
    of this one and must not be reconciled with it" — and until now nothing read
    it: `446` and `172` are integers of the log, `493` and `176` are not."""
    root = tree(tmp_path)
    edit_in(root, "SEC-FIDO-006B.toml", *RECONCILED)
    reported = findings(root)
    assert any(QUOTED in p and "493 passed" in p for p in reported), reported
    assert any(QUOTED in p and "176 failed" in p for p in reported), reported


def test_an_artifact_run_is_joined_to_the_path_beside_it(tmp_path):
    """An `[[artifact]].run` names its log in the neighbouring field, not in its
    own prose. Five rows quote a number that way, `172 failures` among them."""
    root = tree(tmp_path)
    edit(root, "the 172 failures", "the 176 failures")
    reported = findings(root)
    assert any(QUOTED in p and "176 failed" in p and "artifact[10].run" in p for p in reported), reported


def test_a_search_number_is_joined_by_the_configuration_it_names(tmp_path):
    """195 of the 198 arrive this way: the leaf says `ForceChange.cfg` and the
    tree carries `tlc-ForceChange.log`."""
    root = tree(tmp_path)
    edit_in(root, "SEC-FIDO-003.toml", "depth 46, 177 s", "depth 47, 177 s")
    reported = findings(root)
    assert any(QUOTED in p and "47 depth" in p for p in reported), reported


def test_the_log_is_the_quoting_bundle_s_own_copy(tmp_path):
    """Six bundles carry a `tlc-ForceChange.log` and they are not the same run.
    Against the union, any number true of any copy stood in this one: 49 is a
    depth of another bundle's ForceChange and of nothing in this one."""
    root = tree(tmp_path)
    edit_in(root, "SEC-FIDO-003.toml", "depth 46, 177 s", "depth 49, 177 s")
    reported = findings(root)
    assert any(QUOTED in p and "49 depth" in p for p in reported), reported
    assert any("SEC-FIDO-003/tlc-ForceChange.log" in p for p in reported), reported


def test_a_number_reworded_out_of_the_rule_s_reach(tmp_path):
    """The floor is the rule's own non-degeneracy row. Every join can stop
    matching with no finding lost — the numbers simply stop being read — and the
    summary line reads the same either way. `depth of 46` is not `depth 46`."""
    root = tree(tmp_path)
    edit_in(root, "SEC-FIDO-003.toml", "depth 46, 177 s", "depth of 46, 177 s")
    reported = findings(root)
    assert any("under the floor of" in p and "quoted number" in p for p in reported), reported


def test_the_floors_are_the_measured_tree(tmp_path):
    """AT the measurement and not under it, so a join that stops forming is a
    diff someone has to write rather than a quieter summary line."""
    quoted, joins = bundle_gate.quoted_numbers(tree(tmp_path), [])
    assert (quoted, joins) == (bundle_gate.QUOTE_FLOOR, bundle_gate.QUOTE_JOIN_FLOOR)


def test_a_line_range_citation_is_not_a_measurement(tmp_path):
    """The control, and not a no-op. One `result` leaf of SEC-FIDO-006B ends a
    line-range citation on the word `states`, which is a range and a verb — the
    one false finding the shipped tree produced without `STARTS`. This moves the
    digits that would be read, and the leaf stays green."""
    root = tree(tmp_path)
    edit_in(root, "SEC-FIDO-006B.toml", "-225 states and", "-987 states and")
    reported, population = quoted(root)
    assert reported == []
    # Not a no-op: without `STARTS` the same leaf is `987 states` against a log
    # that prints no 987, which is how this control was measured.
    assert population == (bundle_gate.QUOTE_FLOOR, bundle_gate.QUOTE_JOIN_FLOOR)
    assert re.search(bundle_gate.STARTS + r"\d", "sh" + ":400-987") is None
    assert re.search(bundle_gate.STARTS + r"\d", "at 987 states") is not None


def test_a_leaf_naming_two_configurations_joins_neither(tmp_path):
    """`Historical_E76.cfg` and `Mut_BugSeedDoesNotLead.cfg` in one sentence,
    where the number belongs to the second and only the first has a log here.
    Resolving "the one that has an artifact" reported that true number as false."""
    corpus = bundle_gate.log_corpus(tree(tmp_path))
    where = pathlib.Path("SEC-FIDO-005.toml")
    named, shapes = bundle_gate.quoted_join(
        {}, where, "result.x", "Historical_E76.cfg, and Mut_BugSeedDoesNotLead.cfg at 1 875 109 states", corpus
    )
    assert (named, shapes) == (set(), {})
    named, _ = bundle_gate.quoted_join(
        {}, where, "result.x", "Historical_E76.cfg alone at 1 875 109 states", corpus
    )
    assert named == {"assurance/bundle/logs/SEC-FIDO-005/tlc-Historical_E76.log"}


def test_a_runner_s_vocabulary_does_not_reach_a_configuration_s_log(tmp_path):
    """The join decides the vocabulary. A leaf that names only `AlwaysUv.cfg`
    and quotes a cargo run would otherwise send `446 passed` to TLC's summary —
    inert on the tree as it stands, because that leaf names the log too."""
    root = tree(tmp_path)
    corpus = bundle_gate.log_corpus(root)
    where = pathlib.Path("SEC-FIDO-006B.toml")
    named, shapes = bundle_gate.quoted_join({}, where, "result.x", "AlwaysUv.cfg — 446 passed", corpus)
    assert named and shapes == bundle_gate.QUOTED_SEARCH
    named, shapes = bundle_gate.quoted_join(
        {}, where, "result.x", "assurance/bundle/logs/cargo-test-always-uv.log is 446 passed", corpus
    )
    assert named == {"assurance/bundle/logs/cargo-test-always-uv.log"}
    assert set(shapes) == set(bundle_gate.QUOTED_SEARCH) | set(bundle_gate.QUOTED_RESULT)


def test_a_grouped_number_and_the_log_s_own_spelling_are_one_number(tmp_path):
    """`106 956 959` here, `106956959` and `45,810` there. Both sides are reduced
    to their digits, so the grouping is a spelling and not a difference."""
    root = tree(tmp_path)
    edit_in(root, "SEC-FIDO-003.toml", "106 956 959 states", "106956959 states")
    assert quoted(root)[0] == []
    edit_in(root, "SEC-FIDO-003.toml", "106956959 states", "106 956 950 states")
    assert any(QUOTED in p and "106956950 states" in p for p in quoted(root)[0]), quoted(root)[0]


def test_the_gzipped_log_is_never_decompressed_for_a_join(tmp_path):
    """15.8 MB of CBMC unwinding lines behind a 339 KB `.gz`, and no leaf joins
    to it. Reading the corpus eagerly would put that in every case above."""
    root = tree(tmp_path)
    cache = {}
    bundle_gate.quoted_numbers(root, [])
    assert not any(name.endswith(".gz") for name in bundle_gate.log_corpus(root)[0] & set(cache))
    assert bundle_gate.log_integers(root, "assurance/bundle/logs/kani-state-tier.log.gz", cache)


# ---- the evidence store, held the other way -------------------------------
#
# The forward half — a `[[artifact]].path` names a file the tree has — was the
# only one that existed, and it cannot see a log that stopped being cited. The
# arms below are one per clause of `orphan_evidence` plus the floor, and each is
# read against the finding SET the tree already produces rather than against an
# empty one, so a rule elsewhere going red for its own reasons cannot make an arm
# here pass or fail. Measured population the day they were written: 100 files in
# the store, 100 distinct `[[artifact]].path`, no orphan and nothing dangling.

ORPHAN = "no bundle cites"
STORE_UNDER = "evidence file(s), under the floor of"
#: The one artifact of the store no leaf quotes a number out of, so removing it
#: moves no `quoted_numbers` join. `SEC-FIDO-001` carries it, which is
#: [`bundle_gate.BUNDLE`], so [`rewrite`] reaches its rows.
UNJOINED = "assurance/bundle/logs/kani-state-tier.log.gz"


def orphans(root, store_floor=bundle_gate.STORE_FLOOR):
    """THIS rule's findings, and the store population it walked.

    Scoped to the rule, for [`quoted`]'s reason: a green arm here has to assert
    that the store rule says nothing, not that every other rule in the file is
    also green — which is `test_the_real_bundle_is_green`'s claim and not this
    table's.
    """
    reported = []
    return reported, bundle_gate.orphan_evidence(root, reported, store_floor)


def drop(root, relative, body=b"a log nobody claims\n"):
    """Put a file in the store that no bundle's `[[artifact]]` row names."""
    target = root / bundle_gate.STORE / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    return f"{bundle_gate.STORE}/{relative}"


def test_the_shipped_store_is_orphan_free_and_over_its_floor():
    """The measurement the floor stands on, read off the REAL tree.

    Off `ROOT` and not off the fixture, because the fixture copies what the
    bundles cite and would therefore be orphan-free by construction — a fixture
    agreeing with itself says nothing about the store. `>=` and not `==` for
    [`bundle_gate.ROSTER_FLOOR`]'s reason: a file arriving comes WITH its
    `[[artifact]]` row or the rule above names it, and it is a file LEAVING that
    the floor is set at the measurement to catch.
    """
    reported, stored = orphans(bundle_gate.ROOT)
    assert reported == [], reported
    assert stored >= bundle_gate.STORE_FLOOR, stored


@pytest.mark.parametrize(
    "relative",
    [
        # At the root of the store, where three logs already live.
        "orphan-run.log",
        # And nested, which is where 97 of the 100 are: a `glob` in place of
        # `rglob` reads three files and reports nothing about the other 97.
        "SEC-FIDO-004/orphan-run.log",
        # A directory of its own, which is how a new slice's evidence arrives.
        "SEC-FIDO-009/tlc-Shipped.log",
    ],
)
def test_a_file_in_the_store_that_no_bundle_cites(tmp_path, relative):
    root = tree(tmp_path)
    target = drop(root, relative)
    reported, _ = orphans(root)
    assert any(ORPHAN in p and target in p for p in reported), reported


def test_an_orphan_wearing_a_cited_basename(tmp_path):
    """The hole a name-keyed reading ships with, and it is not hypothetical here:
    15 basenames are carried by more than one directory, `tlc-Shipped.log` by all
    eleven. Against a set of NAMES this file is cited eleven times over and the
    rule says nothing, while the run it holds is in no bundle at all."""
    root = tree(tmp_path)
    cited = {
        str(row["path"])
        for bundle in bundle_gate.bundles(root)
        for row in bundle_gate.parsed(root, bundle).get("artifact", [])
    }
    name = "tlc-Shipped.log"
    assert sum(1 for p in cited if p.endswith("/" + name)) == 11, cited
    target = drop(root, f"SEC-FIDO-004/copies/{name}")
    assert target not in cited
    reported, _ = orphans(root)
    assert any(ORPHAN in p and target in p for p in reported), reported


@pytest.mark.parametrize("relative", ["README.md", "SEC-FIDO-004/.gitkeep"])
def test_the_store_carries_no_exemption_because_it_needs_none(tmp_path, relative):
    """Decided by measurement, not by anticipation. The store holds 100 files and
    every one is a `.log` or a `.log.gz`; there is no `README`, no `.gitkeep` and
    no hidden entry, so a carve-out for them would be a rule for a case the tree
    does not have — and a category that arrives already excused is where the next
    uncited log goes. Anything that is not cited is named, whatever it is called;
    admitting one is then a diff someone writes."""
    on_disk = sorted(
        p.suffix for p in (bundle_gate.ROOT / bundle_gate.STORE).rglob("*") if p.is_file()
    )
    assert set(on_disk) == {".log", ".gz"}, set(on_disk)
    target = drop(root := tree(tmp_path), relative)
    assert any(ORPHAN in p and target in p for p in orphans(root)[0])


def test_a_directory_in_the_store_is_not_an_orphan(tmp_path):
    """The control, and not a no-op. The store is ten directories deep already,
    so a rule reading entries rather than FILES reports ten orphans on a tree
    nobody touched. The twin below is the same construction with one file in it,
    and it is red — which is what says this control is about `is_file()` and not
    about the rule having gone quiet."""
    root = tree(tmp_path)
    (root / bundle_gate.STORE / "SEC-FIDO-009").mkdir()
    reported, stored = orphans(root)
    assert reported == [], reported
    assert stored == bundle_gate.STORE_FLOOR, stored
    (root / bundle_gate.STORE / "SEC-FIDO-009/tlc-Shipped.log").write_bytes(b"x")
    assert [p for p in orphans(root)[0] if ORPHAN in p], "the twin must be red"


def test_a_log_named_by_a_method_row_and_by_no_artifact_row(tmp_path):
    """Cited means an `[[artifact]].path`, and the widening is not free. Three
    method rows name a log — accepting that as a citation would make a file with
    no digest, no byte count and no `[[cost]]` row legal in the store, which is
    every rule beside this one walked past for the file it is walked past on."""
    root = tree(tmp_path)
    named = "assurance/bundle/logs/SEC-FIDO-004/tlc-Historical_E77.log"
    text = (root / "assurance/bundle/SEC-FIDO-004.toml").read_text()
    assert named in text, named
    path = root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-004.toml"
    doc = tomllib.loads(path.read_text())
    del doc["artifact"][
        next(i for i, row in enumerate(doc["artifact"]) if row["path"] == named)
    ]
    path.write_text(dump(doc))
    # Still named by a `[[method]]` row, and still not cited.
    assert named in path.read_text()
    assert any(ORPHAN in p and named in p for p in orphans(root)[0]), orphans(root)[0]


def test_evidence_can_leave_with_every_other_clause_green(tmp_path):
    """The floor's own non-degeneracy row, and the reason it is not decoration.

    A log deleted TOGETHER WITH the `[[artifact]]` and `[[cost]]` rows that cite
    it is invisible to every other rule in this file: the orphan clause above is
    silent because the file is gone, the forward rule is silent because the row
    is gone, the cost join is silent because both ends went, and the `artifact`
    and `cost` leaf floors are 8 and 12 against 40 and 55. Asserted as a DELTA on
    the finding set, so the arm says "this and nothing else appeared" rather than
    "the tree is green", which is not this table's claim.
    """
    root = tree(tmp_path)
    before = set(findings(root))
    rewrite(root, lambda doc: (
        doc["artifact"].__delitem__(
            next(i for i, row in enumerate(doc["artifact"]) if row["path"] == UNJOINED)
        ),
        doc["cost"].__delitem__(
            next(i for i, row in enumerate(doc["cost"]) if row["artifact"] == UNJOINED)
        ),
    ))
    (root / UNJOINED).unlink()
    appeared = set(findings(root)) - before
    assert len(appeared) == 1, appeared
    assert STORE_UNDER in appeared.pop()


def test_the_store_cannot_be_emptied_into_silence(tmp_path):
    """The other end of the same clause, stated directly. With every file gone
    the rule above has nothing to walk and would print the same summary line as a
    full store; the floor is what makes zero a finding rather than a quiet run.

    Scoped, because emptying the store also fires the forward rule a hundred
    times, and this arm is about the clause that is left when those go too."""
    root = tree(tmp_path)
    for target in (root / bundle_gate.STORE).rglob("*"):
        if target.is_file():
            target.unlink()
    reported, stored = orphans(root)
    assert stored == 0
    assert [p for p in reported if STORE_UNDER in p] == [
        f"{bundle_gate.STORE}: 0 evidence file(s), under the floor of"
        f" {bundle_gate.STORE_FLOOR} — the rule above goes quiet when the store"
        " empties, and a log deleted with its `[[artifact]]` and `[[cost]]` rows"
        " is a run this slice can no longer show"
    ], reported


def test_a_cited_log_that_is_not_in_the_tree(tmp_path):
    """The forward half, which had no arm of its own. Measured before this was
    written: nothing dangles — all 100 cited paths are files — so the direction
    was held by a rule nothing had ever driven."""
    root = tree(tmp_path)
    (root / UNJOINED).unlink()
    reported = findings(root)
    assert any("a path is not a log" in p and UNJOINED in p for p in reported), reported


def gate_process(root):
    """`python scripts/bundle_gate.py`'s exit code and stderr, from its own
    process, over `root`.

    `check.sh`'s `slice evidence bundle` row reads that exit code and nothing
    else, and a table driving `audit` proves nothing about it — the family this
    tree has measured fourteen times over. `main()` is reached through `-c`
    rather than by running the file, because the row's own `ROOT` is the
    checkout the script lives in and the fixture is elsewhere; [`gate_corpus`] is
    primed BEFORE the swap so the five derivations it caches are the real tree's,
    which is what `main()` compares against when the row runs for real.
    """
    program = "\n".join((
        "import pathlib, sys",
        f"sys.path.insert(0, {str(ROOT / 'scripts')!r})",
        "import bundle_gate",
        "bundle_gate.gate_corpus()",
        f"bundle_gate.ROOT = pathlib.Path({str(root)!r})",
        "raise SystemExit(bundle_gate.main())",
    ))
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=False
    )
    return done.returncode, done.stderr


def test_the_row_and_not_the_helper(tmp_path):
    """The PROCESS goes red over an uncited file, and over that alone.

    Read as a delta between two real runs rather than as `0` against `1`: the
    tree this ships into can be red for a rule this table does not own, and an
    arm asserting the control's exit code would then be measuring that instead.
    What is drift-proof is that the defect run's own exit code is a failing one
    and that the ONE FINDING it prints which the control does not is this rule's.

    Findings, not lines, and that distinction is why this case failed the day
    `bundle_gate` first went green: `bundle-gate:` heads the red path only, so a
    GREEN control puts it in the delta too and a line count reads 2. The banner
    is not a finding; it is how the reader knows findings follow.
    """
    root = tree(tmp_path)
    control_code, control_err = gate_process(root)
    assert "Traceback" not in control_err, control_err
    target = drop(root, "SEC-FIDO-004/orphan-run.log")
    defect_code, defect_err = gate_process(root)
    assert defect_code == 1, (defect_code, defect_err)
    banner = "bundle-gate:"
    appeared = {
        l
        for l in set(defect_err.splitlines()) - set(control_err.splitlines())
        if l.strip() != banner
    }
    assert len(appeared) == 1, appeared
    line = appeared.pop()
    assert ORPHAN in line and target in line, line
