#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Present each property's evidence as a vector, and hold the scalar to it.

`assurance/properties.toml` carries one word per property, and roadmap §4.1 says
that word mixes axes which move independently: `MEASURED` is neither above nor
below `BOUNDED` — one is about a platform, the other about a finite set of
execution paths. The first closed slice measured the cost of the mixing exactly.
It moved `SEC-FIDO-001` from one Kani harness to four and landed the first mutant
in this tree ever to redden a proof, **and the scalar would have read the same
with one harness or four**, because `assurance_gate.py` derives `BOUNDED` from a
harness NAME and looks at nothing else.

So the six axes roadmap §12 item 12 names are printed apart, beside the model
breadth the scalar already had, and every one is DERIVED. A hand-kept column is
not an option here: the registry's own header records a hand-written evidence
record that was wrong in three of six fields before a line of code existed.

| Axis | What it counts | Read out of |
|---|---|---|
| model | configurations naming the invariant, and the subset asserting it | `formal/*.cfg` + `formal/floors.txt` |
| co | model mutants whose CODE twin was driven and killed | `formal/comutants.toml` |
| trace | those configurations that replay a session, and the subset accepting it | the generator handshake below |
| kani | harnesses carrying the invariant's snake name | `crates/*/src/*kani*.rs` |
| hardware | board results: a bundle's declaration, and a platform assumption discharged with its stepping | `assurance/bundle/*.toml` + `assurance/platform.toml` |
| scope | the built images the ledger disposes this property on | `assurance/configurations.toml` |
| freshness | whether a bundle's commit post-dates every evidence input | `git log` |

`hardware` has two sources. A bundle's DECLARATION is one, and the rules below
are about a declaration never arriving without the board it was taken on.
`assurance/platform.toml` is the other, and it is where a board result actually
lands: that registry holds the obligations no model constant can carry, so a row
moving to `discharged` with its stepping recorded is a measurement, and an axis
that did not read it would go on printing "no property was measured on a board"
over one. Neither source may invent a number and neither may pin one: the
registry was all-`pending` when this was written and two rows are discharged on
an A4 now, which is why the page's own paragraph is templated off the axis.

Nothing here re-derives what a sibling row owns. Which configurations exist and
what each names is `assurance_gate.py`'s; whether the ledger's columns are the
tree's is `matrix_gate.py`'s; whether a bundle carries the ten-group contract is
`bundle_gate.py`'s. This row owns five rules the others do not:

* **the round trip.** The v1 `status` is reconstructed from two axes — no model
  is `ACCEPTED-RISK`, a harness is `BOUNDED`, otherwise `MODELLED-ONLY` — and a
  written word that differs is a finding. That is stage 1B's "the 59 properties
  are representable without losing existing data" as a predicate rather than a
  paragraph. §4.3 condition 11 asks on which inputs such an oracle DISAGREES
  with what it checks, and this one's answer is measured and is **none**: it
  reads the same two derivations `assurance_gate.py` forces the word from, so
  every state it fires in is a state that gate already refuses. That is not a
  weakness of the rule, it is the result — the word carries no information of
  its own, which is exactly why the migration is lossless;
* **the hand-written field set is closed.** The registry header has said
  "HAND-WRITTEN FIELDS ONLY" since it was written and nothing checked it, so a
  hand-written `kani = 4` or `hardware = "verified on a board"` column was free
  — which is §4.1's failure in its cheapest form;
* **a hardware claim owes a board, and a board owes a claim.** Three spellings
  of the claim — `hardware` among a bundle's subjects, a `measurement` method
  row, and a concrete RP2350 stepping written anywhere in the bundle — each of
  which must be accompanied by `build.board_revision`; and the inverse, so a
  board field nothing rests on cannot sit there while the axis reads 0. The
  third spelling is the review's: `expires_on_stepping` is the bundle schema's
  own board-dependency field and the first two rules walked straight past a
  stepping named in it, which is closing one spelling of two all over again. And
  the declaration itself is held to `platform_gate.py`'s vocabulary, not merely
  to being non-empty: the token was shared and the RULE was not, so every OTHER
  leaf was searched for a real stepping while `build.board_revision` took
  anything — `"a red Pico 2 I had lying around"` published **1 of 59** carrying
  a result measured on a board;
* **an axis's reader must still reach the tree.** Each derivation is floored
  where its SOURCE exists and it found none of it — sessions with no replaying
  module, comutants resolving to no invariant, a ledger disposing of no
  registry id. A column of zeroes reads as "no evidence" and is indistinguishable
  from a reader that stopped reading, which is the pair `token_refinement_gate.py`
  shipped;
* **the public page is generated.** `docs/assurance-vector.md` is written from
  the vector and byte-diffed, so a release sentence cannot outrun the axes — and
  an owner edit that makes a bundle stale rewrites the sentence rather than
  leaving it standing.

Deliberately not here: whether an axis's number is DESERVED. Nothing can say
that four harnesses are the right four. What this row keeps honest is that six
different questions are answered with six different numbers, that a zero is
visible instead of being masked by a neighbour, and that the one word the tree
already published remains reconstructible from them.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

import assurance_gate
import comutate
import claims_gate
import gate_lines
import platform_gate
import run_count_gate
import scope_gate
import verdict_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

REGISTRY = pathlib.Path("assurance/properties.toml")
LEDGER = pathlib.Path("assurance/configurations.toml")
BUNDLES = pathlib.Path("assurance/bundle")
ARTIFACT = pathlib.Path("docs/assurance-vector.md")
TRACES = pathlib.Path("formal/traces")
FLOORS = pathlib.Path("formal/floors.txt")
#: The gate's two runners; the row that replays a session may sit in either.
CHECKS = (pathlib.Path("scripts/check.sh"), pathlib.Path("scripts/check-assurance.sh"))

GENERATED_BY = "Generated by scripts/evidence_gate.py --write"

#: Every key a hand may write in a `[[property]]`, from the registry's own
#: header. An eighth is refused: a derivable column written by hand is the one
#: failure that file records having already paid for.
WRITTEN_FIELDS = frozenset(
    {"id", "name", "status", "statement", "source", "ruling", "clause_of"}
)

#: And at the document's top level, because `[hardware]` beside `[[property]]`
#: is the same column arriving through the other door.
DOCUMENT_KEYS = frozenset({"property"})

#: The spellings of "this evidence came off a board": §4.1's subject vocabulary,
#: its method vocabulary, and a concrete silicon revision written anywhere in the
#: bundle. The third was found by the review of this file — `expires_on_stepping`
#: is the bundle schema's own board-dependency field, and a rule reading only the
#: first two walked past a stepping named in it. Compared lowercased and
#: stripped; `subjects_absent` is read by none of them, because listing hardware
#: as ABSENT is the honest case and the tree's only bundle makes it.
HARDWARE_SUBJECT = "hardware"
MEASUREMENT_METHOD = "measurement"
BOARD_FIELD = "board_revision"
#: Is this value a shipped part with a stepping, not the bare `A2` — the bundle's
#: Kani claims are named `B1`/`B2` and a looser token reads those as silicon. The
#: sibling registry's own RULE and not a second copy of its token: `re.compile`
#: hands back the CACHED object for the same pattern text, so an identity test
#: over two `BOARD_REVISION`s is green over the copy-paste it exists to refuse.
names_a_stepping = platform_gate.names_a_stepping
#: And the token, for [`board_mentions`] alone: a stepping the evidence depends
#: on turns up in prose, where MENTIONING one anywhere is the whole claim.
BOARD_REVISION = platform_gate.BOARD_REVISION

#: A `scripts/<name>.py` reference inside a TLA+ module: the module naming the
#: generator that rebuilds it. Half of the trace handshake.
GENERATOR = re.compile(r"scripts/([A-Za-z0-9_]+\.py)")

#: The ledger's dispositions this vector reports as scope. `gap` is not among
#: them and cannot be: a gap is an UNPLACED cell, so counting one needs
#: `matrix_gate.py`'s derived column list and would be a second answer to how
#: many built images the tree has.
SCOPE_DISPOSITIONS = ("covered", "equivalent", "out-of-scope", "conditional")


def registry(root):
    with open(root / REGISTRY, "rb") as fh:
        return tomllib.load(fh)


def recorded_sessions(root):
    """The raw sessions on disk, by file name."""
    return {p.name for p in sorted((root / TRACES).glob("*.jsonl"))}


def check_rows(root):
    """Both runners' rows as CODE, one logical line each.

    A row someone commented out is not a row: `gate_lines` exists because
    comparing this file's raw text left eleven guards switched off with the suite
    green.
    """
    return [
        gate_lines.split_at_comment(body)[0]
        for rel in CHECKS
        if (root / rel).is_file()
        for _indent, body in gate_lines.logical_lines((root / rel).read_text(errors="ignore"))
    ]


def trace_data_modules(root):
    """module -> the recorded sessions a generator rebuilds it from.

    A handshake in both directions: the module names the script that writes it,
    and that script — or the ONE gate row that runs it — names a session
    that exists. Both halves are load-bearing. `security_trace.py` never names
    its session; the row passes it as an argument. And reading `check.sh` whole
    rather than per row was measured wrong here before it shipped:
    `RSKeySecurityState` names `ghost_gate.py`, `ghost_gate.py` has a row, and
    another row names the session — so 92 configurations came back trace-linked
    instead of 11, and every FIDO property grew trace evidence it does not have.

    Returned per session, not as a set of modules, because the review measured
    the half-stop: moving one row's session into a shell variable left the other
    session wired, so a "did the derivation find anything" floor stayed silent
    while four properties quietly lost their trace evidence.
    """
    sessions = recorded_sessions(root)
    if not sessions:
        return {}
    rows = check_rows(root)
    out = {}
    for tla in sorted((root / "formal").glob("*.tla")):
        for script in sorted(set(GENERATOR.findall(tla.read_text(errors="ignore")))):
            source = root / "scripts" / script
            text = source.read_text(errors="ignore") if source.is_file() else ""
            wired = {s for s in sessions if s in text}
            for row in rows:
                if script in row:
                    wired |= {s for s in sessions if s in row}
            if wired:
                out.setdefault(tla.stem, set()).update(wired)
    return {module: sorted(found) for module, found in out.items()}


def expected_verdicts(root):
    """configuration -> the verdict `formal/floors.txt` says it must produce.

    Read through `verdict_gate.py`'s own parser rather than a second one: that
    file records how many ways this registry can be read differently from the
    runner that consumes it. Needed because a configuration NAMING an invariant
    is not a configuration asserting it — 43 of the 46 that name
    `NoAuthorizationBypass` are mutants whose whole purpose is that it falls, and
    counting them as evidence FOR it is §4.1's error inside the page written to
    end it.
    """
    path = root / FLOORS
    if not path.is_file():
        return {}
    rows, _ratchets, _problems = verdict_gate.read_registry(path.read_text(encoding="utf-8"))
    names = [p.name for p in (root / "formal").glob("*.cfg")]
    first, _every = verdict_gate.resolve(rows, names)
    return {name: row["want"] for name, row in first.items() if row}


def trace_configurations(root):
    """The configurations whose owning module replays a recorded session.

    The owner comes from `scope_gate.owner_of`, which matches a configuration to
    its module by the constants it assigns and the operators it names — not by
    its file name. `Mut`/`Solo`/`Trace` in a file name is not a classifier here
    for the same reason `verdict_gate.py` refuses it as one.
    """
    formal = root / "formal"
    data = set(trace_data_modules(root))
    if not data:
        return set()
    modules = sorted(p.stem for p in formal.glob("*.tla"))
    replays = {m for m in modules if data & (scope_gate.ancestors(m, formal) | {m})}
    constants = {m: scope_gate.transitive_constants(m, formal) for m in modules}
    defined = {m: scope_gate.defined_in(m, formal) for m in modules}
    return {
        cfg.name
        for cfg in sorted(formal.glob("*.cfg"))
        if scope_gate.owner_of(cfg, modules, constants, defined, formal) in replays
    }


def scope_of(root):
    """property id -> {disposition: the columns the ledger disposes it on}."""
    path = root / LEDGER
    if not path.is_file():
        return {}
    with open(path, "rb") as fh:
        doc = tomllib.load(fh)
    out = {}
    for cell in doc.get("cell", []):
        for pid in cell.get("properties", []):
            for column in cell.get("columns", []):
                out.setdefault(pid, {}).setdefault(
                    cell.get("disposition", "?"), set()
                ).add(column)
    return out


def bundles(root, findings):
    """property id -> its raw evidence bundle, one per closed slice."""
    out = {}
    for path in sorted((root / BUNDLES).glob("*.toml")):
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        pid = doc.get("property", {}).get("id")
        if not pid:
            findings.append(f"{path.name}: a bundle with no property id names nothing")
            continue
        if pid in out:
            findings.append(f"{path.name}: a second bundle for {pid}")
            continue
        out[pid] = doc
    return out


def leaves(value, path=""):
    """(path, text) for every scalar in a bundle, so a rule can read them all."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for index, item in enumerate(value, 1):
            yield from leaves(item, f"{path}[{index}]")
    else:
        yield path, str(value)


def hardware_claims(doc):
    """Every spelling in which a bundle claims a RESULT off a board, or none.

    The subject list is read by its EXACT key: `subjects_absent` naming hardware
    is a bundle saying it has no board result, which is the honest case the tree
    actually has, and a prefix match would redden it for being honest.
    """
    reasons = []
    subjects = doc.get("property", {}).get("subjects", [])
    subjects = subjects if isinstance(subjects, list) else [subjects]
    if HARDWARE_SUBJECT in [str(s).strip().lower() for s in subjects]:
        reasons.append(f"`{HARDWARE_SUBJECT}` among property.subjects")
    methods = [row for row in doc.get("method", []) if isinstance(row, dict)]
    if MEASUREMENT_METHOD in [str(m.get("method", "")).strip().lower() for m in methods]:
        reasons.append(f"a `{MEASUREMENT_METHOD}` method row")
    return reasons


def board_backed(root, findings):
    """property id -> the platform assumptions whose BOARD RESULT it rests on.

    A row of `assurance/platform.toml` that is `discharged` and records the
    stepping it was taken on IS a board result — that registry is where one
    lands, because a board obligation has no model constant to be written as.
    Reading it here is what stops the page printing "no property was measured on
    a board" over a measurement, and it invents nothing: every such row is
    `pending`, so this returns {} today.

    Keyed on the STEPPING, not on the class. Keying on `HARDWARE_CLASSES` was the
    first version and the review drove the same defect one class over: the
    emulator-fidelity row's discharge route is "a board recording of the same
    session", and discharging it printed 0 over ten properties.

    The floor is on ENTRIES READ, not on properties backed: a tree whose
    obligations are all pending has no board evidence, which is a fact; a
    registry with entries this cannot resolve is a reader that stopped reading.
    """
    path = root / platform_gate.REGISTRY
    if not path.is_file():
        return {}
    # Not discarded: `platform_gate.entries` drops a malformed id silently, and a
    # dropped row is one this axis would read as absent rather than as broken.
    entries = platform_gate.entries(root, findings)
    if not entries:
        findings.append(
            f"{platform_gate.REGISTRY} is there and this derivation resolved no"
            " entry from it — the hardware axis then reads 0 for the reason a"
            " tree with no board result reads 0, and the two are not the same"
        )
        return {}
    out = {}
    for name, entry in sorted(entries.items()):
        if entry.get("status") != "discharged":
            continue
        if not names_a_stepping(entry.get(BOARD_FIELD, "")):
            continue
        for pid in entry.get("supports", []):
            out.setdefault(pid, []).append(name)
    return out


def board_mentions(doc):
    """Where a bundle names a concrete silicon revision, in any field.

    Not a result claim by itself — the third spelling is about a stepping that
    the evidence DEPENDS on turning up somewhere other than the field the gate
    reads. `expires_on_stepping` is the bundle schema's own board-dependency
    field, and a rule reading only subjects and methods walked past a stepping
    written into it. The tree's only bundle names the trigger and no revision,
    which is why the token and not the word is what this matches.
    """
    return [where for where, text in leaves(doc) if BOARD_REVISION.search(text)]


def git(root, *args):
    """`git` in `root`, raising unless it succeeded.

    Never a silent empty string: a guard that reads a git failure as "nothing
    changed" reports fresh evidence over a history it could not open.
    """
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if done.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {done.stderr.strip()[:200]}")
    return done.stdout


def comutant_patch_files(root, name):
    """The production files this property's driven code twins patch.

    The review of this file measured what the `Refines`-tag grep alone misses:
    `SEC-FIDO-001`'s bundle names seven co-refutation owners and the tag reaches
    two, because five carry no tag — which `docs/authorization-slice.md` had
    already recorded. A freshness axis built on the tagged two calls evidence
    fresh over an edit to the very code the kill was measured against.

    The skip is `comutate.anchor_shape_problems` and not a second reading of the
    registry's schema. This file's own was `"site" not in entry and "file" not in
    entry`, which is the entry with no anchors AND HALF of the entry with a
    broken one: measured on the shipped registry with `find` deleted from
    `BugTokenSurvivesPinChange`, this row exited 1 on `KeyError: 'find'` raised
    inside `comutate.patch_sites` — the same traceback the `comutants lint` row
    gave, in a gate that does not own the file.
    """
    src = root / "formal" / "comutants.toml"
    if not src.is_file():
        return []
    entries = tomllib.loads(src.read_text(encoding="utf-8")).get("comutant", {})
    out = set()
    for bug in assurance_gate.co_refuted(root).get(name, []):
        entry = entries.get(bug, {})
        if comutate.anchor_shape_problems(bug, entry):
            continue
        for path, _find, _replace in comutate.patch_sites(entry):
            if (root / path).is_file():
                out.add(path)
    return sorted(out)


def evidence_inputs(root, name, pid, checked, module):
    """The files a property's recorded evidence is ABOUT, derived.

    Its model and the modules that model EXTENDS, every configuration checking
    it, the record those configurations were last OBSERVED in, the Kani files
    carrying its harnesses, the production owners whose `Refines` tag names it,
    and the files its killed code twins patch. Derived rather than read from the
    bundle's own `expires_on_owner_change`, which is a hand-written list of the
    same thing — and which named two classes this derivation had to grow before
    it agreed with it.

    `run_count_gate.RECORD` is the newest of those classes, and the tree
    demonstrated it against this function rather than an argument suggesting it.
    A bundle transcribes a TLC closing line per configuration, and a RED closing
    is where the run STOPPED, not where the model ends — so it moves when the
    tier is re-run with the model untouched. Measured across `982fb2f`, which
    touches the record and generated pages and NO model, configuration or source:
    `Mut_BugTokenlessIgnoresAlwaysUv.cfg` went 61236/10696 to 59974/10559, and a
    bundle dated at its parent read `fresh` over 45 derived inputs with every
    number in the tree re-measured underneath it. Anchored on the whole file and
    not on a tier or a row, because `--record` rewrites it wholesale and a row
    anchor is the line-number key `docs/platform-assumptions.md` already argues
    against. Conditioned on the property HAVING a configuration: one with none
    transcribes no run, and dating it against the record would be the decoration
    this module refuses everywhere else.
    """
    out = set()
    if module:
        out.add(f"formal/{module}.tla")
        for parent in scope_gate.ancestors(module, root / "formal"):
            out.add(f"formal/{parent}.tla")
    if checked.get(name):
        out.add(str(run_count_gate.RECORD))
    out |= {f"formal/{cfg}" for cfg in checked.get(name, [])}
    out |= set(comutant_patch_files(root, name))
    snake = assurance_gate.snake(name)
    for path in sorted((root / "crates").glob("*/src/*kani*.rs")):
        text = path.read_text(errors="ignore")
        if any(snake in fn for fn in assurance_gate.FN_DEF.findall(text)):
            out.add(str(path.relative_to(root)))
    for path in assurance_gate.production_rust(root):
        text = path.read_text(errors="ignore")
        if any(
            tag_id == pid and tag_name == name
            for _module, tag_name, tag_id in assurance_gate.TAG.findall(text)
        ):
            out.add(str(path.relative_to(root)))
    return sorted(out)


# The mutation table for the run-record clause above. Each arm was driven on a
# COPY of `scripts/` under the session scratchpad, never on the file being
# edited, so no arm's verdict is a mutant reading another mutant. Every row names
# the assertion that fell AND its direction: a case that says "fresh where stale
# was owed" is this defect, and one that says the reverse is its inverse.
#
#   clause                 the arm with the clause out            direction
#   `out.add(RECORD)`      `..._re_recorded_run_after_the_        `assert 'fresh' ==
#                          bundle_goes_stale` fails, and          'stale'` — the axis
#                          `..._not_dated_against_the_record`     called a bundle current
#                          fails on its positive half             over a re-recorded tier
#   the `if checked`       only `..._not_dated_against_the_       `assert 'formal/runs.
#   condition              record` fails, on its `not in` half    toml' not in …` — the
#                          (4 passed, 1 failed)                   record dated a property
#                                                                 no configuration checks
#   `RECORD` itself        swapped for `formal/floors.txt`: the   same two, same
#   (the imported          same two cases fall                    directions — the clause
#   constant)                                                     is the record's, not any
#                                                                 neighbouring formal/ file
#
# And the arm that needs no fixture, because this tree's own HEAD is the defect.
# `982fb2f` touches `formal/runs.toml` and four generated pages, no model, no
# configuration, no source — and it re-ran both tiers. Dated at its parent
# `68eaca6` and read at it: `SEC-FIDO-002` is `stale` behind `formal/runs.toml`
# over 46 inputs with the clause, and `fresh` over 45 with it out. `SEC-FIDO-006A`
# the same at 6 and 5. That commit moved `Mut_BugTokenlessIgnoresAlwaysUv.cfg`
# from 61236/10696 to 59974/10559, a line `SEC-FIDO-002`'s own bundle transcribes.
#
# What the clause does NOT do, said because the 22 rows it moved on the page are
# +1 each and a reader could take them for a repair: every bundle here was stale
# before it. Measured over the 104 (bundle, input) pairs behind them, 91 moved in
# content, 5 in comments alone, 8 are configurations that did not yet exist — and
# 80 of the 81 TLC closings the bundles cite differ from `formal/runs.toml`'s
# today, `Shipped.cfg` by 77563872 distinct states against 108618956. The clause
# buys a date that cannot be right for the wrong reason; it buys no freshness.


def freshness(root, commit, inputs):
    """(verdict, the inputs the recorded commit does not cover).

    Pure history: an input is covered when the commit that last touched it is an
    ancestor of — or is — the commit the bundle recorded. Deliberately not the
    working tree, so writing the page and then committing it cannot change the
    answer between the two. The hole that leaves is named in the page: an
    uncommitted edit to an owner is invisible until it lands.
    """
    known = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if known.returncode:
        return "unknown-commit", []
    behind = []
    for rel in inputs:
        last = git(root, "log", "-1", "--format=%H", "--", rel).strip()
        if not last:
            behind.append(rel)  # never committed: the recorded commit cannot cover it
            continue
        done = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", last, commit],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode:
            behind.append(rel)
    return ("fresh" if not behind else "stale"), behind


def reconstruct(vector):
    """The v1 scalar, as a function of two axes. The whole round trip."""
    if not vector["model"]:
        return "ACCEPTED-RISK"
    return "BOUNDED" if vector["kani"] else "MODELLED-ONLY"


def vectors(root, findings):
    """The evidence vector of every registry row, in registry order."""
    formal = root / "formal"
    document = registry(root)
    for key in sorted(set(document) - DOCUMENT_KEYS):
        findings.append(
            f"{REGISTRY}: top-level `{key}` is a hand-written column — every field"
            " but the seven the header names is DERIVED, and a copy of a derived"
            " field is what that header records already rotting"
        )
    entries = document.get("property", [])
    checked = assurance_gate.checked_names(formal)
    modules = assurance_gate.tla_definitions(formal)
    solo = assurance_gate.solo_target_counts(formal)
    co = assurance_gate.co_refuted(root)
    replayed = trace_configurations(root)
    asserts = expected_verdicts(root)
    placed = scope_of(root)
    bundle = bundles(root, findings)
    measured = board_backed(root, findings)

    rows = []
    for entry in entries:
        pid, name = entry.get("id", "?"), entry.get("name", "?")
        where = f"{pid} ({name})"
        for key in sorted(set(entry) - WRITTEN_FIELDS):
            findings.append(
                f"{where}: `{key}` is a hand-written column — the registry's"
                " hand-written fields are id, name, status, statement, source,"
                " ruling and clause_of; everything else is derived and printed"
            )
        cfgs = checked.get(name, [])
        derived = assurance_gate.derive(root, name, solo)
        traced = [cfg for cfg in cfgs if cfg in replayed]
        vector = {
            "model": len(cfgs),
            # A configuration that NAMES the invariant is not one that asserts
            # it: the mutants exist for it to fall in.
            "asserted": len([cfg for cfg in cfgs if asserts.get(cfg) == "GREEN"]),
            "co": len(co.get(name, [])),
            "trace": len(traced),
            "accepted": len([cfg for cfg in traced if asserts.get(cfg) == "GREEN"]),
            "kani": len(derived["kani"]),
            "hardware": len(measured.get(pid, ())),
            "scope": {
                disposition: sorted(placed.get(pid, {}).get(disposition, ()))
                for disposition in SCOPE_DISPOSITIONS
            },
        }
        doc = bundle.get(pid)
        if doc is None:
            vector["freshness"], vector["commit"], vector["behind"] = "unrecorded", "", []
        else:
            commit = str(doc.get("build", {}).get("commit", "")).strip()
            inputs = evidence_inputs(root, name, pid, checked, modules.get(name))
            if not commit:
                findings.append(f"{pid}: its bundle records no build commit to date it")
                verdict, behind = "unrecorded", []
            else:
                verdict, behind = freshness(root, commit, inputs)
            if verdict == "unknown-commit":
                findings.append(
                    f"{pid}: its bundle records commit {commit[:12]}, which this"
                    " history does not have — an evidence date nothing can check"
                )
            board = str(doc.get("build", {}).get(BOARD_FIELD, "")).strip()
            # The sibling registry's own rule, not its token: a `search` here
            # published "a red Pico 2 (an RP2350 A2) I had lying around" as a
            # board result, which is the desk the finding's words refuse.
            stepping = names_a_stepping(board)
            reasons = hardware_claims(doc)
            mentions = [where for where in board_mentions(doc) if where != f"build.{BOARD_FIELD}"]
            if board and not stepping:
                findings.append(
                    f"{pid}: its bundle records `build.{BOARD_FIELD}` {board!r},"
                    " which names no RP2350 stepping — a part with a revision, not"
                    " a description of a desk"
                )
            if reasons and not board:
                findings.append(
                    f"{pid}: its bundle claims a board result ({'; '.join(reasons)})"
                    f" and records no `build.{BOARD_FIELD}` — a platform result"
                    " names the platform it was taken on"
                )
            if mentions and not board:
                findings.append(
                    f"{pid}: its bundle names a silicon revision at `{mentions[0]}`"
                    f" and records no `build.{BOARD_FIELD}` — a stepping the"
                    " evidence depends on belongs in the field the gate reads,"
                    " not only in the prose beside it"
                )
            if board and not reasons:
                findings.append(
                    f"{pid}: its bundle records `build.{BOARD_FIELD}` and claims no"
                    " result on it — a board field nothing rests on is decoration,"
                    " and the axis stays 0 while the page reads as if it did not"
                )
            vector["hardware"] += 1 if reasons and stepping else 0
            vector["freshness"], vector["commit"], vector["behind"] = verdict, commit, behind

        written = entry.get("status", "?")
        rebuilt = reconstruct(vector)
        if written != rebuilt:
            findings.append(
                f"{where}: status {written!r} does not rebuild from the vector,"
                f" which gives {rebuilt!r} (model={vector['model']},"
                f" kani={vector['kani']}) — the v1 word must stay reconstructible"
                " or the migration lost what a v1 reader relies on"
            )
        rows.append({"entry": entry, "vector": vector, "rebuilt": rebuilt})
    return rows


def check_rollups(root, rows, findings):
    """The three sections a generated page can emit EMPTY and still regenerate.

    The byte-diff catches a section that changed and not one that collapsed to a
    header with nothing under it — a regenerated empty table is what the page
    "makes", so it matches itself. Same family as the mutation table that was
    deleted versus the one that was emptied, one layer out.
    """
    columns = per_column(root, rows)
    if not columns:
        if (root / "Cargo.toml").is_file():
            findings.append(
                "the per-column rollup is empty — `matrix_gate` gave no built images,"
                " so the page would print coverage over nothing"
            )
        # No workspace manifest: no built images to enumerate, which is a fact
        # about this checkout rather than a reader that stopped. The rules below
        # are all about a rollup that HAS a source.
        return
    ids = {row["entry"]["id"] for row in rows} & set(scope_of(root))
    for name, _kind, _published, placed, unplaced in columns:
        if placed + unplaced != len(ids):
            findings.append(
                f"column `{name}` accounts for {placed + unplaced} of {len(ids)}"
                " ledger rows — the rollup is counting a different denominator"
                " than the ledger it reads"
            )
    kinds = {kind for _n, kind, _p, _pl, _u in columns}
    for owed in ("package", "feature", "board"):
        if owed not in kinds:
            findings.append(
                f"the rollup names no `{owed}` column — the axis feature blindness"
                " is about would be missing from the page without a word"
            )
    pending = [row for row in outstanding(root, rows) if row[0] == "platform"]
    if not pending and any(
        entry.get("status") == "pending"
        for entry in platform_gate.entries(root, []).values()
    ):
        findings.append(
            "the outstanding list names no platform obligation while the registry"
            " holds a pending one — the consolidated list stopped reading a source"
        )
    made = packet(root, rows)
    if not made["artifacts"] or not made["runs"]:
        findings.append(
            "the review packet names no artifact or no model run — a packet that"
            " lists nothing reproduces nothing"
        )


def check_derivations(root, rows, findings):
    """Each axis's reader must still reach the tree it reads.

    The floors are scoped to "the source is there and the derivation found none
    of it", never to "the tree has none". A tree with no recorded session has no
    trace evidence, which is a fact; a tree with two sessions and no replaying
    module is a reader that stopped reading, which is the failure
    `token_refinement_gate.py` shipped and this one is written after.

    Floored PER SESSION and not in total, because the review measured the half
    stop: passing one row's session through a shell variable — changing nothing
    about what runs — left the other session wired, took four properties' trace
    evidence away, and a total floor printed a smaller number in silence.
    """
    sessions = recorded_sessions(root)
    data = trace_data_modules(root)
    claimed = {session for found in data.values() for session in found}
    for session in sorted(sessions - claimed):
        findings.append(
            f"{TRACES}/{session} is replayed by no formal/ module this derivation"
            " can reach — the handshake runs from a module's named generator to"
            " that generator or its own gate row, and this session is on"
            " neither, so its properties' trace evidence just gets smaller"
        )
    if data and not any(row["vector"]["trace"] for row in rows):
        findings.append(
            f"{len(data)} replaying module(s) and not one property carries trace"
            " evidence — the configuration owner lookup stopped reading the tree"
        )
    comutants = root / "formal" / "comutants.toml"
    if comutants.is_file() and not any(row["vector"]["co"] for row in rows):
        findings.append(
            "formal/comutants.toml exists and no property carries a co-refuted"
            " twin — the invariant lookup stopped resolving"
        )
    if (root / FLOORS).is_file() and not any(row["vector"]["asserted"] for row in rows):
        findings.append(
            f"{FLOORS} exists and no property is asserted by any configuration —"
            " the verdict lookup stopped resolving, and every `asserted of naming`"
            " on the page then reads 0 of something"
        )
    if (root / LEDGER).is_file() and not any(
        any(row["vector"]["scope"].values()) for row in rows
    ):
        findings.append(
            f"{LEDGER} disposes of no property in the registry — the two id"
            " vocabularies have drifted apart and the scope axis is empty"
        )


def scope_columns(vector):
    """Every column the property is CLAIMED on: covered, equivalent, conditional.

    `out-of-scope` is the ledger saying the claim is not made there, so it is not
    a column a release may name — which is the whole reason the three are counted
    apart rather than added up.
    """
    return sorted(
        set(vector["scope"]["covered"])
        | set(vector["scope"]["equivalent"])
        | set(vector["scope"]["conditional"])
    )


def claims(rows):
    """The sentences a release may print, built from the axes rather than typed.

    Both lists are conditional on the axes, because a prohibition templated with
    its own count inverts into the claim it forbids the moment the count moves:
    "no property was measured on a board — the hardware axis is **1 of 59**" is
    what the review of this function got out of it in one edit.
    """
    total = len(rows)
    asserted = [r for r in rows if r["vector"]["asserted"]]
    co = [r for r in rows if r["vector"]["co"]]
    # The one number in this registry that is read backwards, and the only one
    # with hand-written copies in the tree that had already gone stale.
    modelled_only = [r for r in rows if r["rebuilt"] == "MODELLED-ONLY"]
    modelled_only_co = [r for r in modelled_only if r["vector"]["co"]]
    accepted = [r for r in rows if r["vector"]["accepted"]]
    refused = [r for r in rows if r["vector"]["trace"] > r["vector"]["accepted"]]
    kani = [r for r in rows if r["vector"]["kani"]]
    hardware = [r for r in rows if r["vector"]["hardware"]]
    dated = [r for r in rows if r["vector"]["freshness"] in ("fresh", "stale")]
    fresh = [r for r in rows if r["vector"]["freshness"] == "fresh"]
    widest = max((len(scope_columns(r["vector"])) for r in rows), default=0)
    may = [
        f"**{len(asserted)} of {total}** security properties are ASSERTED by at"
        " least one finite TLA+ configuration whose recorded verdict is GREEN,"
        " and hold exhaustively over that configuration's constants.",
        f"**{len(co)} of {total}** carry a model mutant whose code twin"
        " `formal/comutants.toml` records as patched into the real tree and"
        " killed. That verdict is re-driven by the weekly `comutate run`, not by"
        " the gate that writes this page.",
        f"**{len(modelled_only_co)} of the {len(modelled_only)}** rows the v1 word"
        " calls `MODELLED-ONLY` carry such a twin: the word means *no Kani"
        " harness*, and never *untested*.",
        f"**{len(accepted)} of {total}** are checked by a configuration that"
        f" ACCEPTS a recorded session, and **{len(refused)}** by one that must"
        " REFUSE a negative one.",
        f"**{len(kani)} of {total}** carry at least one Kani harness named after"
        " them. That is all `BOUNDED` keys on — a harness NAME, not the"
        " `#[kani::proof]` attribute, not a bound, not a `cfg` — so it points at"
        " the bundle's method table and is never the proof itself.",
        f"Rows carrying a dated raw evidence bundle: **{len(dated)} of {total}**;"
        f" of those, still ahead of every input they are about: **{len(fresh)}**.",
        f"No property is claimed on more than **{widest}** built image(s) of the"
        " configuration ledger; every other column is a gap or out of scope.",
    ]
    must_not = [
        "that any property is *proven* or *verified* without qualification — no"
        " row carries an unbounded deductive proof, and `PROVEN-SOURCE` is"
        " refused by the registry until one exists.",
        "that a `kani` count is a proof of anything in particular — the axis"
        " counts harnesses carrying the property's name, and what each one"
        " bounds is the bundle's method table.",
        "that a `model` count is the strength of the evidence — its denominator"
        " counts every configuration NAMING the invariant, and most of those are"
        " mutants that exist for it to fall in. `asserted` is the half a claim"
        " may rest on, and for a `clause_of` row it can be 0 while the parent"
        " invariant carrying that clause is asserted.",
        "that the model-checked properties hold on *the firmware* — they hold on"
        " the images the scope axis names, and `docs/assurance-matrix.md` carries"
        " the rest of that row.",
        "that the reconstructed `v1` column is an independent check on the"
        " registry's word. It reads the two derivations `assurance_gate.py`"
        " already forces that word from, so its disagreement set is empty on"
        " every input that gate accepts: it records that the scalar is a"
        " projection, and cannot discover that it is not.",
    ]
    if hardware:
        may.append(
            f"**{len(hardware)} of {total}** carry a result measured on a board,"
            " each naming the revision it was taken on."
        )
    else:
        must_not.append(
            "that any property was measured on a board — **no** row carries a"
            " hardware result. A bundle claiming one without a board revision is"
            " refused rather than published, and every obligation of the"
            " platform registry is still `pending`."
        )
    if len(dated) < total:
        must_not.append(
            f"that {total - len(dated)} of the rows are current — they carry no"
            " evidence date at all, so nothing here says when they were last true."
        )
    return may, must_not


def per_column(root, rows):
    """(column, kind, published, placed, unplaced) for every built image.

    The rollup roadmap §1B item 7 asks for by name and the tree did not have. Its
    columns come from `matrix_gate` and NOT from the ledger: a cell nobody wrote
    is a `gap`, so counting gaps needs the derived list of images, and asking the
    ledger how many images exist would be a second answer to a question one gate
    already owns.

    `placed` is any disposition the ledger actually wrote — including
    `out-of-scope`, which is a decision. `unplaced` is the remainder, which is the
    number the feature columns exist to make visible: six of them are `gap` for
    every row, and that reads as coverage only while nobody prints it.
    """
    import matrix_gate

    # Scoped the way `check_derivations` scopes its floors: a checkout with no
    # workspace manifest has no built images to enumerate, which is a fact about
    # that tree and not a reader that stopped. `check_rollups` asks for the
    # emptiness only where the source IS there.
    if not (root / "Cargo.toml").is_file():
        return []
    columns = matrix_gate.columns(root, matrix_gate.workspace(root))
    scope = scope_of(root)
    ids = [row["entry"]["id"] for row in rows if row["entry"]["id"] in scope]
    out = []
    for column in columns:
        placed = sum(
            1
            for pid in ids
            if any(column.name in named for named in scope.get(pid, {}).values())
        )
        out.append((column.name, column.kind, column.published, placed, len(ids) - placed))
    return out


def outstanding(root, rows):
    """Every stale or pending thing, in one list instead of across two pages.

    Three sources, because "stale" has three spellings here and reading only one
    is how a page reports a clean tree over an unclean one: a bundle whose commit
    is behind an input it is about, a P0-family property with no bundle at all,
    and a platform obligation still `pending`.
    """
    out = []
    for row in rows:
        vector, entry = row["vector"], row["entry"]
        if vector["freshness"] == "stale":
            out.append(
                (
                    "bundle",
                    entry["id"],
                    f"{len(vector['behind'])} input(s) newer than `{vector['commit'][:7]}`",
                )
            )
    have = {row["entry"]["id"] for row in rows if row["vector"]["freshness"] != "unrecorded"}
    for pid in sorted(scope_of(root)):
        if pid not in have:
            out.append(("bundle", pid, "no raw evidence bundle"))
    for entry in platform_gate.entries(root, []).values():
        if entry.get("status") == "pending":
            # RAW, and the cut is on raw text on purpose: escaping first lets
            # `[:70]` land between the `\` and the `|` it was written for.
            # [`render`] escapes what this returns — see the comment there.
            out.append(("platform", entry.get("id", "?"), str(entry.get("statement", ""))[:70]))
    return out


def packet(root, rows):
    """The reviewer's packet for THIS commit: what to reproduce, and with what.

    Roadmap §1B item 7 asks for it and the tree had no such output — 0 mentions. It
    is small on purpose: the assurance CASE is stage 12, and what 1B owes is that
    a reviewer arriving at a release commit is not left to find the artifacts by
    reading the history. So every line here is derived — the artifacts from the
    generators that write them, the model runs from the record that provenances
    them, and the counts from the vector this page already publishes.

    It deliberately does NOT claim the packet is sufficient. A reviewer who runs
    all of it has reproduced the software evidence and nothing about a board.
    """
    # NOT `HEAD`. A generated page that embeds the tree's head commit is stale the
    # instant it is committed — the value changes between writing the page and
    # landing it, so the gate would go red on its own output, forever. That is the
    # rule the `freshness` axis already states about itself and this section broke
    # on its first full gate run. The packet is FOR the commit that carries it,
    # which is the file's own position in history and needs no field; the commits
    # that do vary are each bundle's, and they are in the table above.
    runs = []
    path = root / pathlib.Path("formal/runs.toml")
    if path.is_file():
        for entry in tomllib.loads(path.read_text(encoding="utf-8")).get("run", []):
            runs.append(
                (
                    entry.get("tier", "?"),
                    entry.get("command", "?"),
                    entry.get("date", "?"),
                    (entry.get("commit", "") or "")[:7],
                    entry.get("host", "?"),
                )
            )
    stale = [row for row in rows if row["vector"]["freshness"] == "stale"]
    return {
        "artifacts": [
            (str(ARTIFACT), "python scripts/evidence_gate.py"),
            ("docs/assurance-matrix.md", "python scripts/matrix_gate.py"),
            ("docs/platform-assumptions.md", "python scripts/platform_gate.py"),
            ("formal/README.md", "python scripts/assurance_gate.py"),
        ],
        "runs": runs,
        "bundles": sorted(p.stem for p in (root / BUNDLES).glob("*.toml")),
        "stale": [row["entry"]["id"] for row in stale],
        "properties": len(rows),
    }


def render(root, rows=None):
    """`docs/assurance-vector.md` as the tree makes it."""
    rows = vectors(root, []) if rows is None else rows
    may, must_not = claims(rows)
    # Templated off the axis for the reason [`claims`] is: the untemplated copy
    # of this paragraph asserted an all-`pending` registry through the commit
    # that discharged two rows, and `--write` reproduced it. A COUNT and not a
    # branch on emptiness -- a row discharged with a stepping that supports no
    # property leaves this axis 0, so "0" cannot be spelled "all pending".
    measured = [r for r in rows if r["vector"]["hardware"]]
    out = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        f"<!-- {GENERATED_BY} — do not edit by hand -->",
        "",
        "# Assurance vector",
        "",
        claims_gate.DISCLAIMER_PARAGRAPH,
        "",
        "One word per property mixes questions that move independently. Roadmap"
        " §4.1 argues it; the first closed slice measured it. That slice took"
        " `SEC-FIDO-001` from one Kani harness to four and landed the first"
        " mutant in this tree ever to redden a proof — and its `status` would"
        " have read `BOUNDED` either way, because the word is derived from a"
        " harness *name*.",
        "",
        "So the axes are printed apart. Every one is derived from the tree on"
        " every gate run by `scripts/evidence_gate.py`, which also regenerates"
        " this page and refuses a stale copy of it.",
        "",
        "## The axes",
        "",
        "| Axis | What it counts | Read out of |",
        "|---|---|---|",
        "| `model` | `asserted of naming`: configurations naming the invariant, and the subset whose recorded verdict is GREEN | `formal/*.cfg` + `formal/floors.txt` |",
        "| `co` | model mutants whose code twin was patched into the tree and killed | `formal/comutants.toml` |",
        "| `trace` | `accepted of replaying`: configurations that replay a recorded session, and the subset that accepts it | the module's generator handshake |",
        "| `kani` | harnesses carrying the invariant's name — what `BOUNDED` keys on | `crates/*/src/*kani*.rs` |",
        "| `hardware` | board results: a bundle's declaration, and a platform assumption discharged with the stepping it was taken on | `assurance/bundle/*.toml` + `assurance/platform.toml` |",
        "| `scope` | the built images the ledger disposes the property on | `assurance/configurations.toml` |",
        "| `freshness` | whether a bundle's commit post-dates every input it is about | `git log` |",
        "",
        "Three readings the axes are built to stop. A `kani` count does not fill"
        " in for `hardware`: a bounded proof is about execution paths and a board"
        " result is about a platform, and neither substitutes for the other. A"
        " `trace` count is DIRECT — a recorded session reaches a property only"
        " if a configuration checking that property replays it, so the refinement"
        " properties carry the session and the invariants they refine do not"
        " inherit it. And a configuration NAMING an invariant is not one"
        " ASSERTING it: most of them are mutants that exist for it to fall in,"
        " which is why `model` and `trace` are printed as two numbers each.",
        "",
        "`hardware` reads two sources, and together they give"
        f" **{len(measured)} of {len(rows)}**. One is a bundle's DECLARATION,"
        " and the gate's job there is that a declaration cannot arrive without"
        " the board revision it was taken on. The other is"
        " `docs/platform-assumptions.md`'s registry, which is where a board"
        " result actually lands — an obligation moving to `discharged` with a"
        " real stepping recorded is what moves this column, whatever class it is"
        " filed under.",
        "",
        "Neither direction of that number says more than it is. A `0` is"
        " \"nothing here was measured on hardware\" and never a measurement: the"
        " axis prints the same 0 over a question nobody asked and over one a"
        " board refused to answer. A non-zero is not the property holding on"
        " hardware either — it is THESE rows and no others, on the stepping and"
        " the boot configuration they name, and it lapses when either moves.",
        "",
        "The `freshness` axis reads committed history only, so an uncommitted"
        " edit to an owner is invisible until it lands. That is deliberate: the"
        " answer must not change between writing this page and committing it.",
        "",
        "## What a release may say",
        "",
    ]
    out += [f"- {line}" for line in may]
    out += [
        "",
        "## What a release may not say",
        "",
    ]
    out += [f"- {line}" for line in must_not]
    out += [
        "",
        "## The vector",
        "",
        "`v1` is the one word `assurance/properties.toml` publishes,"
        " **reconstructed here from `model` and `kani`** rather than copied: no"
        " configuration names it and it is `ACCEPTED-RISK`, a harness names it"
        " and it is `BOUNDED`, anything else is `MODELLED-ONLY`. All 59 rebuild"
        " exactly, which is the migration being lossless — and the reason it is"
        " lossless is that the word holds nothing of its own.",
        "",
        "| ID | Property | Model | Co | Trace | Kani | Hardware | Claimed on | Out of scope | Freshness | v1 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for row in rows:
        entry, vector = row["entry"], row["vector"]
        if vector["freshness"] == "unrecorded":
            fresh = "—"
        elif vector["freshness"] == "fresh":
            fresh = f"`{vector['commit'][:7]}` fresh"
        else:
            fresh = f"`{vector['commit'][:7]}` {vector['freshness']}"
            if vector["behind"]:
                fresh += f" ({len(vector['behind'])} input(s) newer)"
        out.append(
            f"| `{entry['id']}` | `{entry['name']}` |"
            f" {vector['asserted']} of {vector['model']} |"
            f" {vector['co']} | {vector['accepted']} of {vector['trace']} |"
            f" {vector['kani']} |"
            f" {vector['hardware']} | {len(scope_columns(vector))} |"
            f" {len(vector['scope']['out-of-scope'])} | {fresh} |"
            f" {row['rebuilt']} |"
        )
    out += [
        "",
        "`Model` and `Trace` read *asserted of naming* and *accepted of"
        " replaying*. A `0 of 1` is a real state and not a defect: a clause row"
        " is asserted through the parent invariant its `clause_of` names, and"
        " `RequiredGateAgreesWithRelation` is registered precisely so that it is"
        " REFUTED.",
        "",
        "`Claimed on` counts the columns disposed `covered`, `equivalent` or"
        " `conditional`; `Out of scope` counts the ones where the ledger says the"
        " claim is not made. Their sum is not the number of built images —"
        " everything else is a `gap`, and `docs/assurance-matrix.md` is the page"
        " that counts those.",
        "",
        "## Coverage by built image",
        "",
        "The same 40 P0-family rows, counted the other way round: per column"
        " rather than per property. `Placed` is a disposition the ledger actually"
        " wrote, `out-of-scope` included, because a decision not to claim is a"
        " decision. `Unplaced` is the remainder, and it is what a per-property"
        " count cannot show — a property claimed on twenty images looks well"
        " covered while an image nobody disposed anything on stays invisible."
        " The columns are `matrix_gate.py`'s, so this asks nothing about how many"
        " built images exist that another gate already answers.",
        "",
        "| Column | Kind | Published | Placed | Unplaced |",
        "|---|---|---|---:|---:|",
    ]
    rollup = per_column(root, rows)
    if not rollup:
        out.append("| — | — | — | 0 | 0 |")
    for name, kind, published, placed, unplaced in rollup:
        out.append(
            f"| `{name}` | {kind} | {'yes' if published else 'no'} |"
            f" {placed} | {unplaced} |"
        )
    listed = outstanding(root, rows)
    out += [
        "",
        "Read the feature rows first: every one of them carries the same handful"
        " of placed cells and the rest unplaced, which is the shape roadmap §12"
        " calls feature blindness. A default-build proof is not a proof about the"
        " image a feature builds, and the column is where that stops being"
        " invisible.",
        "",
        "## Stale and pending, in one place",
        "",
        "Three spellings of \"not current\", which used to sit on two different"
        " pages and in a registry: a bundle whose commit is behind an input it is"
        " about, a P0-family property with no raw bundle at all, and a platform"
        " obligation still waiting on a board. Reading any one of them alone"
        " reports a clean tree over an unclean one.",
        "",
        "| Kind | Subject | What is outstanding |",
        "|---|---|---|",
    ]
    # HERE and not at [`outstanding`]'s `[:70]`: that runs under `check_rollups`
    # too, outside `audit`'s try, where the raise is a traceback and not a
    # finding — measured. The order is still cut-then-escape either way.
    for kind, subject, why in listed:
        out.append(f"| {kind} | `{subject}` | {platform_gate.cell(why)} |")
    made = packet(root, rows)
    out += [
        "",
        "## Review packet",
        "",
        "For the commit that carries this page — which is why no commit is named"
        " here: a generated page that embeds the tree's head is stale the moment"
        " it lands, and this section learned that on its first gate run. Every"
        " line is derived; none of it claims to be sufficient, because a reviewer"
        " who runs all of it has reproduced the software evidence and nothing"
        " about a board. The assurance case itself is a later stage's artifact.",
        "",
        "**Generated artifacts, and the command that reproduces each.**",
        "",
        "| Artifact | Regenerated by |",
        "|---|---|",
    ]
    for artifact, command in made["artifacts"]:
        out.append(f"| `{artifact}` | `{command}` |")
    out += [
        "",
        "**Model runs this tree publishes counts from.**",
        "",
        "| Tier | Command | Taken | Against | Host |",
        "|---|---|---|---|---|",
    ]
    for tier, command, date, commit, host in made["runs"]:
        out.append(f"| `{tier}` | `{command}` | {date} | `{commit}` | {host} |")
    out += [
        "",
        f"**Raw evidence bundles:** {', '.join('`' + b + '`' for b in made['bundles']) or 'none'}"
        f" — of {made['properties']} registered properties."
        + (
            f" Stale against this commit: {', '.join('`' + s + '`' for s in made['stale'])}."
            if made["stale"]
            else ""
        ),
        "",
    ]
    return "\n".join(out)


def audit(root):
    """(findings, one-line summary) for the vector, its axes and its page."""
    root = pathlib.Path(root)
    findings = []
    rows = vectors(root, findings)
    check_derivations(root, rows, findings)
    check_rollups(root, rows, findings)

    try:
        want = render(root, rows)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        findings.append(f"{ARTIFACT} cannot be generated: {error}")
    else:
        path = root / ARTIFACT
        got = path.read_text(encoding="utf-8") if path.is_file() else ""
        if got != want:
            findings.append(
                f"{ARTIFACT} is not what the generator writes — run"
                " `python scripts/evidence_gate.py --write` and commit the result"
            )

    axes = {
        "asserted": sum(1 for r in rows if r["vector"]["asserted"]),
        "co": sum(1 for r in rows if r["vector"]["co"]),
        "trace-accepted": sum(1 for r in rows if r["vector"]["accepted"]),
        "kani": sum(1 for r in rows if r["vector"]["kani"]),
        "hardware": sum(1 for r in rows if r["vector"]["hardware"]),
        "dated": sum(1 for r in rows if r["vector"]["freshness"] != "unrecorded"),
    }
    summary = (
        f"evidence-gate: ok — {len(rows)} properties as vectors, "
        + ", ".join(f"{count} {axis}" for axis, count in axes.items())
        + "; every v1 status rebuilds from model+kani"
    )
    return findings, summary


def run(root, write=False):
    if write:
        (root / ARTIFACT).write_text(render(root), encoding="utf-8")
        print(f"evidence-gate: wrote {ARTIFACT}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("evidence-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: evidence_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
