#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the security-property registry against the tree, both ways.

`assurance/properties.toml` names the security properties; `assurance/crates.toml`
classifies every workspace member. Everything else this gate reports — which
module defines a property, which configurations check it, which mutants target
it, which Kani harnesses, fuzz targets, Rust files and device tests carry its
name — is DERIVED here and printed, never stored. The registry's own worked
example is why: a hand-written evidence record for the tree's best-documented
property was wrong in three of six fields before any code existed (three
mutants listed of seven, two owner files of three, and two runtime tests that
do not exist). Deriving is not a nicety; it is the difference between a
registry and a fourth hand-kept roster, and this tree has already deleted one
guard that grew 800 lines defending three copies of a list.

What is checked, and the direction of each check:

* every invariant or temporal property that any formal/*.cfg actually checks
  has exactly one registry entry — so nothing TLC verifies is unnamed; and
  every non-risk entry names something a configuration actually checks — so
  the registry cannot advertise properties nothing verifies. This one check
  also covers mutant orphans: a Solo_*.cfg aimed at an unregistered invariant
  is an unregistered checked name.
* a status must equal the evidence ceiling. A Kani harness carrying the
  property's name forces BOUNDED; none allows only MODELLED-ONLY. PROVEN and
  OBSERVED are refused outright until evidence of those classes exists in the
  tree — a status rule nothing can trip is a check that cannot fail.
* ACCEPTED-RISK entries carry a ruling and are exactly the entries with no
  model: a ruled-away risk must be visible, and a checked invariant must not
  be filed as one.
* every formal/*.cfg is in a tier of `run-tlc.sh --tiers` or in [`EXEMPT_CFG`]
  with its reason — the "20 of 49 proofs run by nothing" class, one layer up.
* every [workspace] member appears in the crate ledger and vice versa, and
  each class carries what it obliges: a model that exists, a named gap, a
  planned roadmap module, evidence that is what [`EVIDENCE_SUFFIX`] says the
  field names — the crate's own differential/KAT/proof files — or a reason. That
  last one used to be "a file that exists", which is a rule `README.md` meets
  ([`platform_gate.PROSE_PAGE`] is the same sentence on the other axis). The
  ledger
  exists because two roadmap drafts enumerated crates from memory and missed
  four, including the second-largest in the tree.

Deliberately syntactic, like its siblings: it cannot say a statement means
what the invariant checks, or that an evidence file proves anything. It says
the graph is closed — nothing checked is unnamed, nothing named is unchecked,
nothing ships silently unclassified.
"""

import functools
import pathlib
import re
import subprocess
import sys
import tomllib

# `gate_lines.tree_files` and `platform_gate.in_tree`, borrowed rather than
# reimplemented: two registries answering "is this path a file of the tree"
# differently is the defect, and a second membership line here is how that starts.
import gate_lines
import platform_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

README_START = "<!-- assurance-table:start -->"
README_END = "<!-- assurance-table:end -->"

# Every shipped model has production owners. A baseline added here automatically
# turns each of its checked properties into a required, validated Rust tag.
OWNER_CFGS = (
    "Shipped.cfg",
    "Seams.cfg",
    "Store.cfg",
    "Lattice.cfg",
    "Policies.cfg",
    "Admin.cfg",
    "Display.cfg",
    "Boot.cfg",
    "Transport.cfg",
)

#: Configurations no tier runs, each with the reason a reader needs. Anything
#: else outside every tier is a matrix row nobody pulls, and fails the gate.
EXEMPT_CFG = {
    "Liveness_Full.cfg": "1475 s for the verdict the reduced constants give in 139 s; "
    "run by hand when the reduction is questioned (run-tlc.sh)",
    "TokenExport.cfg": "serialization-only TLC input consumed by "
    "scripts/export_token_relation.py; it is not a model-checking verdict row",
}

#: The one status per evidence class that exists in the tree today. PROVEN
#: (unbounded deductive proof) and OBSERVED (runtime-only evidence) are named
#: here so the refusal message can say what to do the day they become real:
#: add the evidence class to the derivation, then admit the status.
STATUSES = {"BOUNDED", "MODELLED-ONLY", "ACCEPTED-RISK"}

#: A property tag in production Rust: `Refines \`Module!Invariant\` — SEC-X-NNN.`
#: Both halves are validated — the module against formal/, the name and the id
#: against the registry, and the pairing against itself, so a copy-pasted tag
#: whose id names one property and whose invariant names another is a finding
#: rather than two half-truths.
TAG = re.compile(r"Refines\s+`([A-Za-z0-9]+)!([A-Za-z0-9]+)`\s+—\s+(SEC-[A-Z]+-[0-9A-Z]+)")
SUPPORT_TAG = re.compile(
    r"Supports\s+`([A-Za-z0-9]+)!([A-Za-z0-9]+)`\s+—\s+(SEC-[A-Z]+-[0-9A-Z]+)"
)
SEC_ID = re.compile(r"\bSEC-[A-Z]+-[0-9A-Z]+\b")

CFG_KEYWORDS = re.compile(
    r"^(SPECIFICATION|CONSTANTS?|INVARIANTS?|PROPERT(?:Y|IES)|CONSTRAINTS?|"
    r"INIT|NEXT|SYMMETRY|VIEW|CHECK_DEADLOCK|ALIAS)\b"
)
BARE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TLA_DEF = re.compile(r"^([A-Z][A-Za-z0-9_]*)\s*==", re.M)
FN_DEF = re.compile(r"^\s*(?:pub\s+)?fn\s+([a-z0-9_]+)", re.M)


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def cfg_checked(path: pathlib.Path) -> list[str]:
    """The invariant/property names a configuration asks TLC to check."""
    names, section = [], None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        kw = CFG_KEYWORDS.match(line)
        if kw:
            word = kw.group(1)
            section = "check" if word.startswith(("INVARIANT", "PROPERT")) else None
            continue
        if section == "check" and BARE_NAME.match(line) and line != "TypeOK":
            names.append(line)
    return names


def checked_names(formal: pathlib.Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cfg in sorted(formal.glob("*.cfg")):
        for name in cfg_checked(cfg):
            out.setdefault(name, []).append(cfg.name)
    return out


def tla_definitions(formal: pathlib.Path) -> dict[str, str]:
    defs: dict[str, str] = {}
    for tla in sorted(formal.glob("*.tla")):
        for name in TLA_DEF.findall(tla.read_text()):
            defs.setdefault(name, tla.stem)
    return defs


#: The filename families a mutant run is spelled with. Module-level so the
#: mutation table can hold the shipped tree against this list instead of copying
#: it — a second roster is what rots. `BootCarryMut_` is deliberately absent
#: though it is solo-shaped: it re-runs the SAME three defects on the
#: assumption's other constant arm, and this column counts defects, not runs.
SOLO_CFG_PREFIXES = (
    "Solo_",
    "SeamSolo_",
    "StoreSolo_",
    "LatSolo_",
    "PolicySolo_",
    "AdminSolo_",
    "DispSolo_",
    "BootSolo_",
    "TransSolo_",
    "SoloClause_",
    "LiveMut_",
    "FairMut_",
)


def solo_target_counts(formal: pathlib.Path) -> dict[str, int]:
    """How many single-target mutant configurations aim at each name.

    A prefix says a configuration is mutant-SHAPED; only its CONSTANTS say
    whether a defect stands behind the credit. Reading the name alone was the
    hole: a `StoreSolo_*.cfg` with every `Bug*` switched to FALSE — arming
    nothing, so its run is the shipped model under another filename — scored the
    same `mut` as one arming a real defect, and the row published that green.
    Measured on a copy of this tree: `NoRecordLostToMetaWrite` held `mut=2`
    across the strip, output byte-identical, EXIT=0.

    `comutate.armed_subject` is the reader and is reused rather than restated —
    it is the rule [`co_refuted`] already resolves a kill through, and two
    parsers disagreeing about one file is the defect this column had. It also
    refuses a configuration arming two unrelated defects, which says which one
    fired but not which property either breaks.

    Under-crediting is the safe direction, so nothing here guesses: a switch
    spelled anything but TRUE/FALSE leaves `armed` empty, the count drops, and
    the generated README goes stale — the row reddens instead of publishing a
    number nothing arms.
    """
    # The sibling next to THIS file, not one under the tree being audited: a
    # fixture root has no `scripts/`, and the reader must be the shipped one.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import comutate
    import verdict_gate

    companion = comutate.companions(formal.parent)
    counts: dict[str, int] = {}
    for cfg in formal.glob("*.cfg"):
        if not cfg.name.startswith(SOLO_CFG_PREFIXES):
            continue
        # `cfg_checked` and not `Config.targets` for the name: the three
        # `LiveMut_` configurations aim at a temporal PROPERTY and carry no
        # INVARIANTS block, which `targets` reads — measured, they are the three
        # rows swapping readers here would silently drop.
        names = cfg_checked(cfg)
        if len(names) != 1:
            continue
        if comutate.armed_subject(verdict_gate.Config(cfg), companion) is None:
            continue
        counts[names[0]] = counts.get(names[0], 0) + 1
    return counts


def grep_word(files: list[pathlib.Path], word: str) -> list[str]:
    pat = re.compile(r"\b" + re.escape(word) + r"\b")
    return [f.name for f in files if pat.search(f.read_text(errors="ignore"))]


#: The structure a `mod` declaration is read out of. Files are reached through
#: their DECLARATION, so what gates a file is written in its parent, not in it —
#: and the declaration is found by scanning, not by a line regex, because the
#: line regex this replaced answered "production" to ELEVEN legal spellings
#: rustc withholds, measured by running the fourteen `SPELLINGS` of the mutation
#: table beside this file against that regex; the other three are clauses of the
#: scanner rather than holes it inherited. Measured on the shipped tree: collapsing all
#: 187 cfg-carrying declarations onto one line each — the shape
#: `#[cfg(test)] mod tests;`, which only `cargo fmt` objects to and this gate
#: never runs — took `production_rust` from 182 to 394, every `.rs` in the tree,
#: with no finding printed. [`_scan`] carries the rest of the table.
MOD_DECL = re.compile(
    r"(?:pub(?:[ \t\r\n]*\([^)]*\))?[ \t\r\n]+)?(?:unsafe[ \t\r\n]+)?"
    r"mod[ \t\r\n]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*(?P<end>[;{])"
)
INCLUDE_DECL = re.compile(r'include\s*!\s*\(\s*"(?P<rel>[^"\\]+)"\s*\)\s*;')
#: What a scan stops on: an attribute, the `mod` keyword, and the braces that say
#: which inline block a declaration sits in.
STRUCTURE = re.compile(r"\#!?\[|\bmod\b|\binclude\b|[{}]")
ATTR_OPEN = re.compile(r"\#(?P<inner>!?)\[")
SPACE = re.compile(r"[ \t\r\n]*")
CFG_ATTR = re.compile(r"(?s)\Acfg\((?P<expr>.*)\)\Z")
#: `#[cfg_attr(P, cfg(E))]` gates on E only when P holds, which is the
#: implication `any(not(P), E)` and needs no second evaluator.
CFG_ATTR_ATTR = re.compile(r"(?s)\Acfg_attr\((?P<body>.*)\)\Z")
PATH_ATTR = re.compile(r'(?s)\Apath[ \t\r\n]*=[ \t\r\n]*"(?P<rel>[^"]+)"\Z')

#: Where a comment or a literal starts. A structural scan that reads inside
#: either is how `#[cfg(test)] // why` parsed as an ungated declaration and a
#: `/* */` above a prologue `#![cfg(test)]` parsed as a production file; a string
#: holding `/*` would be worse still, eating the rest of the file as a comment.
LITERAL = re.compile("//|/\\*|(?<![A-Za-z0-9_])(?:b?r\\#*|b)?\"|\"|'")
#: A `'` opens a char literal only if it closes; otherwise it is a lifetime.
CHAR_LIT = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|.)|[^\\'\n])'")

#: The file names whose plain `mod x;` resolves BESIDE them. Everywhere else the
#: children of `foo.rs` live in `foo/`, and a resolver that forgets it looks for
#: `render/applets.rs` at `src/applets.rs`, finds nothing, and drops the whole
#: declaration unrecorded. Measured: eleven files under
#: `crates/rsk-ui/src/render/` had no declarer at all, so a `#[cfg(test)] mod
#: helper;` written in `render.rs` withheld nothing and its leaf was production.
#: A `#[path]` is deliberately NOT this rule — the reference makes it relative to
#: the declaring file's own directory in both shapes, which is what
#: `crates/rsk-oath/src/tests.rs` naming `code_tests.rs` BESIDE it rests on.
#: Two rules because Rust has two, and it is the one clause here whose loss the
#: SHIPPED tree notices: resolving `#[path]` under the child home as well takes
#: `production_rust` from 182 to 327 and reddens the row. 138 of those 145 are
#: `*_tests.rs` or `*kani*.rs` — which is what the deleted name filter used to
#: hide, and the reason the filter was not merely inert but load-BLIND: it was
#: standing in front of this rule, catching its failures by their spelling.
ROOT_MODULES = ("mod.rs", "lib.rs", "main.rs")

#: The two cfg atoms no shipped image sets. `kani` is a `--cfg` the proof runner
#: passes and `test` is cargo's; a module reachable only through them is in no
#: firmware anybody can build, so a `Refines` tag inside it is a tag on a mirror.
NEVER_SHIPPED = ("test", "kani")


def _cfg_atom(atom: str, shippable: frozenset[str]) -> bool | None:
    """One cfg atom under `test = kani = FALSE`: True, False, or None for free.

    None means "some buildable configuration could set it", which keeps the file.
    The failure direction is deliberate: over-counting a production owner is a
    column one too high, under-counting one hides an owner AND reddens
    `check_property_tags`, so anything unrecognised stays free.
    """
    atom = atom.strip()
    if atom in NEVER_SHIPPED:
        return False
    feature = re.fullmatch(r'feature[ \t]*=[ \t]*"([^"]+)"', atom)
    if feature:
        return None if feature.group(1) in shippable else False
    return None


def _split_top(expr: str) -> list[str]:
    """`expr` cut at its top-level commas — a cfg combinator's operands, and the
    predicate/attribute split a `cfg_attr` needs, which is why it is one function
    and not the loop `_cfg_holds` used to carry inline."""
    parts, depth, start = [], 0, 0
    for index, char in enumerate(expr):
        depth += (char == "(") - (char == ")")
        if char == "," and depth == 0:
            parts.append(expr[start:index])
            start = index + 1
    parts.append(expr[start:])
    return parts


def _cfg_holds(expr: str, shippable: frozenset[str]) -> bool | None:
    """`expr` under `test = kani = FALSE`, three-valued. None is satisfiable.

    A hand parser and not a tokenizer because the grammar in this tree is three
    combinators deep; anything it does not recognise answers None, which keeps
    the file. `not(feature = "largeblob-ext")` is why the free value cannot be
    TRUE: `conformance/largeblobs.rs` is the DEFAULT build's large-blob design
    and an optimistic TRUE would have dropped it as unreachable.
    """
    expr = expr.strip()
    for combinator in ("all", "any", "not"):
        if not expr.startswith(f"{combinator}("):
            continue
        parts = _split_top(expr[len(combinator) + 1 : -1])
        held = [_cfg_holds(part, shippable) for part in parts if part.strip()]
        if combinator == "not":
            return None if held[0] is None else not held[0]
        if combinator == "any":
            return True if True in held else (None if None in held else False)
        return False if False in held else (None if None in held else True)
    return _cfg_atom(expr, shippable)


def _child_home(source: pathlib.Path) -> pathlib.Path:
    """The directory `source`'s own child modules live in."""
    return source.parent if source.name in ROOT_MODULES else source.parent / source.stem


def _gate(cfgs) -> str:
    """The one cfg expression a list of them AND to. rustc ANDs stacked
    attributes; a loop keeping the LAST read `#[cfg(test)] #[cfg(feature =
    "display")] mod helper;` as `display` alone and called the leaf production.
    `all(…)` and not a boolean because the same string is the reason printed."""
    return cfgs[0] if len(cfgs) == 1 else f"all({', '.join(cfgs)})"


def _blanked(text: str) -> tuple[str, str]:
    """`text` with comments gone, and again with literal INTERIORS gone too.

    Offsets are preserved in both, so a span found in one reads out of the
    other: the structure scan needs `{`, `#[` and `//` inside a literal to be
    invisible, and `#[path = "…"]` needs the literal back.
    """
    plain, deep, pos = list(text), list(text), 0
    while (found := LITERAL.search(text, pos)) is not None:
        start, token = found.start(), found.group(0)
        if token in ("//", "/*"):
            if token == "//":
                stop = text.find("\n", start)
                stop = len(text) if stop < 0 else stop
            else:
                depth, stop = 1, start + 2  # rustc nests block comments
                while stop < len(text) and depth:
                    step = 2 if text[stop : stop + 2] in ("/*", "*/") else 1
                    depth += (text[stop : stop + 2] == "/*") - (
                        text[stop : stop + 2] == "*/"
                    )
                    stop += step
            for index in range(start, stop):
                if text[index] != "\n":
                    plain[index] = deep[index] = " "
        elif token == "'":
            literal = CHAR_LIT.match(text, start)
            if literal is None:  # a lifetime, and it holds no syntax
                pos = start + 1
                continue
            stop, interior = literal.end(), range(start + 1, literal.end() - 1)
            for index in interior:
                deep[index] = " "
        else:
            hashes = token.count("#")
            closer = '"' + "#" * hashes if "r" in token else '"'
            stop = _string_end(text, found.end(), closer, raw="r" in token)
            for index in range(found.end(), stop - len(closer)):
                if text[index] != "\n":
                    deep[index] = " "
        pos = stop
    return "".join(plain), "".join(deep)


def _string_end(text: str, body: int, closer: str, raw: bool) -> int:
    """One past a string literal whose body starts at `body`."""
    if raw:
        stop = text.find(closer, body)
        return len(text) if stop < 0 else stop + len(closer)
    index = body
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index + 1
        index += 1
    return len(text)


def _attr_cfgs(body: str) -> list[str]:
    """The cfg expressions one attribute imposes, `cfg_attr` included."""
    found = CFG_ATTR.match(body)
    if found:
        return [found.group("expr")]
    found = CFG_ATTR_ATTR.match(body)
    if not found:
        return []
    parts = _split_top(found.group("body"))
    predicate = parts[0].strip()
    return [
        f"any(not({predicate}), {expr})"
        for part in parts[1:]
        for expr in _attr_cfgs(part.strip())
    ]


#: Keyed on the TEXT and not on a path, so a file edited between two calls in
#: one process is re-scanned and only an identical file is reused. `derive` asks
#: `production_rust` once per property, which is 58 passes over the same 394
#: files; without this the scan costs 22 s of a 29 s row.
@functools.cache
def _scan(text: str) -> tuple[tuple[str, ...], tuple[dict, ...]]:
    """(the cfgs the FILE applies to itself, one record per `mod NAME;`).

    A scanner and not a line regex, because every spelling below is legal Rust
    that rustc withholds and the regex called production — measured one at a
    time by moving `SEC-ADM-001`'s only tag into the leaf and reading the row:

    * two `#[cfg]` attributes stacked. rustc ANDs them; the old loop kept the
      LAST, so `#[cfg(test)] #[cfg(feature = "display")]` read as `display`.
    * the attribute on the `mod` line, an attribute broken over three lines, and
      a `// why` after `)]` — three ways for a run of attributes to stop being a
      run of whole lines. Only the first two are spellings `cargo fmt` rejoins.
    * a doc comment, a `pub(crate)`, or a bracket-carrying sibling attribute
      (`#[cfg_attr(test, deny[warnings])]`, which rustc accepts) standing
      between the cfg and the `mod` it gates.
    * `#[cfg_attr(P, cfg(E))]` in place of the cfg, which is the implication
      [`CFG_ATTR_ATTR`] turns it into rather than a second evaluator.
    * an enclosing `mod inner { … }` carrying the cfg, and a `#[path]` inside
      one, which also moves where the leaf resolves: rustc puts the children of
      an inline block under a directory named for it, in BOTH the `mod.rs` and
      the non-`mod.rs` shape (checked against rustc 1.96, not reasoned about).
    * a `/* */` or a trailing `// …` around a prologue `#![cfg(test)]`, and a
      second `#![cfg]` stacked either side of it — both orders, because the rule
      taking the LAST attribute and the rule taking the FIRST are wrong in
      opposite ones and either pair alone leaves half the AND unfalsified.

    Eleven of the fourteen survive `cargo fmt --all --check` unchanged, measured
    by writing each into `crates/rsk-device/` and running the row: the same-line
    attribute, the three-line one and the `/* */` prologue are the three a
    formatter would have caught, and no other row in the gate reads any of them.

    Inner attributes belong to the block they open, which is what keeps
    `mod inner { #![cfg(test)] … }` from withholding the whole file: only depth
    zero answers for the file.
    """
    plain, deep = _blanked(text)
    own: list[str] = []
    blocks: list[dict] = []
    records: list[dict] = []
    depth, pos = 0, 0
    while (found := STRUCTURE.search(deep, pos)) is not None:
        start, token = found.start(), found.group(0)
        if token in ("{", "}"):
            depth, pos = depth + (1 if token == "{" else -1), start + 1
            while blocks and blocks[-1]["depth"] > depth:
                blocks.pop()
            continue
        if token == "#![":
            pos = stop = _attr_end(deep, found.end() - 1)
            inside = blocks[-1] if blocks and blocks[-1]["depth"] == depth else None
            if inside is not None:
                inside["cfgs"] += _attr_cfgs(_attr_body(plain[start:stop]))
            elif not blocks and depth == 0:
                own += _attr_cfgs(_attr_body(plain[start:stop]))
            continue
        cfgs, rel, cursor = [], None, start
        while (opened := ATTR_OPEN.match(deep, cursor)) and not opened.group("inner"):
            stop = _attr_end(deep, opened.end() - 1)
            body = _attr_body(plain[cursor:stop])
            cfgs += _attr_cfgs(body)
            named = PATH_ATTR.match(body)
            rel = named.group("rel") if named else rel
            cursor = SPACE.match(deep, stop).end()
        declaration = MOD_DECL.match(deep, cursor)
        included = INCLUDE_DECL.match(plain, cursor) if deep.startswith("include", cursor) else None
        module_depth = blocks[-1]["depth"] if blocks else 0
        if included is not None and depth == module_depth:
            records.append({
                "name": "include",
                "cfgs": tuple([c for b in blocks for c in b["cfgs"]] + cfgs),
                "rel": included.group("rel"),
                "dirs": (),
            })
            pos = included.end()
            continue
        if declaration is None:
            # Not a module. Step past the FIRST attribute only, so the braces of
            # whatever it does gate still move `depth`.
            pos = start + 1 if start == cursor else _attr_end(deep, found.end() - 1)
            continue
        pos, name = declaration.end(), declaration.group("name")
        if declaration.group("end") == "{":
            blocks.append({"depth": depth + 1, "cfgs": cfgs, "dir": rel or name})
            depth += 1
            continue
        # The enclosing BLOCKS' cfgs and not the file's own: a declaration is
        # withheld outright, and a file its own prologue withholds still keeps a
        # `#[path]` leaf that a shipped module also names. That second rule is
        # `cfg_excluded`'s fixed point, and folding the prologue in here would
        # overrule it.
        records.append(
            {
                "name": name,
                "cfgs": tuple([c for b in blocks for c in b["cfgs"]] + cfgs),
                "rel": rel,
                "dirs": tuple(b["dir"] for b in blocks),
            }
        )
    # Tuples because the answer is CACHED: a caller that appended to the list it
    # was handed would gate every later file on the last one's cfg.
    return tuple(own), tuple(records)


def _attr_body(source: str) -> str:
    """The inside of one `#[…]` or `#![…]`."""
    return source[source.index("[") + 1 : source.rindex("]")].strip()


def _attr_end(deep: str, bracket: int) -> int:
    """One past the `]` closing the attribute whose `[` is at `bracket`."""
    depth, index = 0, bracket
    while index < len(deep):
        depth += (deep[index] == "[") - (deep[index] == "]")
        index += 1
        if not depth:
            break
    return index


@functools.cache
def shippable_features(root: pathlib.Path) -> frozenset[str]:
    """Feature names a FIRMWARE image can be built with, to a fixed point.

    Derived from the manifests, not listed, and rooted at `firmware` rather than
    at "every `[features]` key in the workspace" — the difference is the whole
    yield. A rule reading keys calls `test-util` shippable because three crates
    declare it; a rule reading every `[features]` VALUE calls `assurance-trace`
    shippable because `rsk-device`'s `security-trace` enables it. Neither is
    reachable from an image: `test-util` is asked for thirteen times and every
    one is a `[dev-dependencies]` edge, and `security-trace` is asked for once,
    by `tools/emu`, which is not a firmware.

    `[dev-dependencies]` is never followed. An optional dependency's `dep:`
    prefix and a weak `crate?/feat` both reduce to the feature they name, which
    is the safe side: naming a feature keeps its module in the production set.
    """
    tables = {}
    for manifest in [root / "firmware" / "Cargo.toml"] + sorted(
        (root / "crates").glob("*/Cargo.toml")
    ):
        try:
            doc = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        tables[str(doc.get("package", {}).get("name", manifest.parent.name))] = doc

    def requested(doc: dict) -> set[str]:
        """Features this manifest's own non-dev dependency edges turn on."""
        out = set()
        for spec in doc.get("dependencies", {}).values():
            if isinstance(spec, dict):
                out.update(str(f) for f in spec.get("features", []))
        return out

    firmware = tables.get("firmware", {})
    features = set(firmware.get("features", {})) | requested(firmware)
    crates = {"firmware"}
    changed = True
    while changed:
        changed = False
        for name in sorted(crates):
            doc = tables.get(name, {})
            for dep in doc.get("dependencies", {}):
                if dep in tables and dep not in crates:
                    crates.add(dep)
                    features |= requested(tables[dep])
                    changed = True
        for name in sorted(crates):
            for key, enables in tables.get(name, {}).get("features", {}).items():
                if key not in features:
                    continue
                for target in enables if isinstance(enables, list) else []:
                    word = str(target).removeprefix("dep:").rpartition("/")[2].lstrip("?")
                    if word and word not in features:
                        features.add(word)
                        changed = True
    return frozenset(features)


def rust_sources(root: pathlib.Path) -> list[pathlib.Path]:
    """Every `.rs` of the firmware and its crates, before any cfg is read."""
    return list((root / "crates").glob("*/src/**/*.rs")) + list(
        (root / "firmware" / "src").glob("**/*.rs")
    )


def declared_targets(root: pathlib.Path):
    """Resolve module declarations and literal file-relative `include!` calls.

    Separate from [`cfg_excluded`] because the ORPHAN census reads it too, and a
    census that re-derived the resolution rule would be asserting its own copy.
    """
    for parent in rust_sources(root):
        for record in _scan(parent.read_text(errors="ignore"))[1]:
            name, dirs = record["name"], record["dirs"]
            # A `#[path]` is relative to the declaring FILE's directory; a plain
            # `mod` resolves under [`_child_home`]. Two rules and not one,
            # because Rust has two — `crates/rsk-ui/src/render.rs` names both
            # shapes and the single-rule version resolved neither `render/`.
            # An enclosing `mod inner { … }` adds a directory to BOTH.
            home = _child_home(parent).joinpath(*dirs)
            if record["rel"]:
                # One candidate and no fallback, because rustc has none:
                # `#[path = "gone.rs"]` is `couldn't read src/gone.rs` even with
                # `gone/mod.rs` sitting there, measured on rustc 1.96. The
                # fallback that stood here answered a second file for a
                # declaration rustc refuses to resolve at all.
                candidates = [(home if dirs else parent.parent) / record["rel"]]
            else:
                candidates = [home / f"{name}.rs", home / name / "mod.rs"]
            target = next((c for c in candidates if c.is_file()), None)
            if target is not None:
                yield parent, target, record


def cfg_excluded(root: pathlib.Path) -> dict[pathlib.Path, str]:
    """Files no buildable image compiles: a withheld `mod`, and what it reaches.

    The `kani`/`tests` filename filter this replaced read a NAME, and the six
    `*_assurance.rs` mirrors carry neither: measured, `store_assurance.rs`
    (`#[cfg(any(kani, test))]`) was counted as a production owner of
    `SEC-STORE-002`, `-003`, `-004` and `-006`, and `transport_assurance.rs` of
    `SEC-TRANS-003` — §2 principle 7 in the one direction it forbids, a
    proof-only mirror standing in for the code it mirrors.

    A file is reached through a declaration, through the directory a declaration
    shuts, or through a chain of both, so the closure is a fixed point over all
    three. The DIRECTORY under a withheld declaration is shut —
    `crates/rsk-fido/src/lib.rs` says `#[cfg(test)] mod conformance;` and
    `conformance/mod.rs` then declares its eighteen siblings plainly, every one a
    production owner-in-waiting. And a file whose `mod` declarations ALL sit in
    withheld files is shut with them, because a `#[path]` leaf need not live
    under the directory that named it: `crates/rsk-oath/src/tests.rs` is withheld
    and names `code_tests.rs`, which sits BESIDE it and not under the `tests/`
    that shuts. Measured, eleven such files — and the sentence that stood here
    said they were "held out today only by the legacy name filter", which the
    same commit's own fixed point had already made false. Re-measured before the
    filter was deleted: the filter decided ZERO files, `production_rust` being
    182 with it and 182 without.

    The last way in is what the file says about ITSELF. An inner `#![cfg(test)]`
    at depth zero shuts a module whatever its declaration says, and no spelling
    of a declaration can see it; that is [`_scan`]'s `own`, and it is the
    direction the name filter was standing in for without ever being able to
    reach — a `helper.rs` is spelled like production and a `manifests.rs` like a
    test. It shuts the module's DIRECTORY too, which is the only clause that
    reaches an orphan sitting under one.

    One live declarer keeps a file: the same source can be `#[path]`-included
    from a shipped module and from a test. Only the directory half can still
    drop such a file (a production `#[path = "conformance/shared.rs"]` under a
    withheld `conformance/`), and it does so LOUDLY — the file stops owning its
    tag and `check_tags` names the unowned invariant.

    The closure was `matrix_gate.production_rust`'s alone. It belongs at THIS
    layer, where the reader lives and where `evidence_gate` also calls in;
    `matrix_gate` imports this module, so the edge only runs one way, and its
    own copy now filters an already-closed set rather than answering second.
    """
    shippable = shippable_features(root)
    out: dict[pathlib.Path, str] = {}
    shut: dict[pathlib.Path, str] = {}
    declarers: dict[pathlib.Path, set[pathlib.Path]] = {}
    for parent in rust_sources(root):
        own, _ = _scan(parent.read_text(errors="ignore"))
        if own and _cfg_holds(_gate(own), shippable) is False:
            why = f"{parent.name} applies `#![cfg({_gate(own)})]` to itself"
            out.setdefault(parent.resolve(), why)
            # The one clause the declaration half cannot reach: a file under this
            # module's directory that NO `mod` names. It is compiled by nothing
            # either way, and without this it comes back as an ORPHAN, which
            # [`production_rust`] keeps.
            shut.setdefault(_child_home(parent).resolve(), why)
    for parent, target, record in declared_targets(root):
        # Every declaration, not only the withheld ones: what decides the second
        # closure below is whether a file has a live declarer LEFT.
        declarers.setdefault(target.resolve(), set()).add(parent.resolve())
        expr = _gate(record["cfgs"])
        if not record["cfgs"] or _cfg_holds(expr, shippable) is not False:
            continue
        why = f"{parent.name} declares `mod {record['name']}` under cfg({expr})"
        out[target.resolve()] = why
        # Where the refused module's own children sit. Taken off the RESOLVED
        # target so a `#[path]` re-point carries its sub-tree with it.
        shut[_child_home(target).resolve()] = why
    sources = rust_sources(root)
    # `setdefault` and the `break` pick the NEAREST reason and decide nothing
    # else: every caller reads the KEYS, so the value is a message to whoever
    # reads this mapping and never a membership test. Untested on purpose.
    for source in sources:
        resolved = source.resolve()
        for ancestor in resolved.parents:
            if ancestor in shut:
                out.setdefault(resolved, f"{shut[ancestor]}, above this file")
                break
    # To a fixed point, because a shut leaf can declare the next one, and over a
    # SORTED pass so which chains one round settles is not filesystem order.
    # `<=` and not "intersects": one live declarer means an image still compiles
    # the file, and dropping it would cost that module its tag.
    changed = True
    while changed:
        changed = False
        for target, parents in sorted(declarers.items()):
            if target not in out and parents <= out.keys():
                out[target] = f"{sorted(parents)[0].name} declares it and is withheld"
                changed = True
    return out


def production_rust(root: pathlib.Path) -> list[pathlib.Path]:
    """Every `.rs` some buildable image compiles, and nothing else.

    What decides it is [`cfg_excluded`] alone — the cfg on the declarations that
    reach a file, plus the cfg it applies to itself. A `"kani" not in f.name and
    "tests" not in f.name` filter stood here as well until this commit, and it
    read a SPELLING: an `attests.rs` would have been withheld for holding the
    letters `tests`, and a `helper.rs` under a `#[cfg(test)] mod` kept for not.
    Deleting it moved nothing — 182 files before and after, the same list both
    ways and no printed column — because every file it decided is decided by a
    cfg too. What it cost while it stood is at [`ROOT_MODULES`]: it was hiding
    the resolution rule's failures behind their file names.

    Not cargo's own answer, which was the third candidate. A dep-info file is the
    list for ONE feature combination, so a single unit under-counts production
    for everything behind a feature that build did not set: measured against the
    `firmware.d` `check.sh` leaves in `target/`, 38 of these 182 are absent —
    every `rsk-ui` render screen, `rsk-display` and `rsk-slip39` among them, and
    each one is code some image ships. Unioning the combinations means building
    them all, inside a registry gate whose own docstring says it is deliberately
    syntactic, and the verdict would then depend on a toolchain and a build
    cache. Nor "the file's items are all cfg-gated", which needs an item parser
    to answer and gets a file of test helpers around one shipped `pub fn` wrong
    in the direction that hides an owner. The declaration and the prologue are
    read off the tree and cost a regex.

    One thing the filter did that this does NOT: an ORPHAN — a file no `mod`
    declaration reaches and no manifest names as a root — is compiled by nothing
    and is counted production here anyway. Deliberate, but NOT because
    over-counting is cheap, which is what the reason here used to say: 34 of the
    59 rows sit at `rust = 1`, so on most of the table one over-counted owner is
    exactly the difference between EXIT 1 naming the missing owner and EXIT 0
    saying nothing. Both directions are silent, and what settles it is the
    asymmetry in SCALE — withholding orphans buys a resolver gap the power to
    drop owners across the whole table at once, where keeping them costs one row
    per orphan — together with the census: the shipped tree has none, every `.rs`
    under `crates/*/src` and `firmware/src` is reached by a declaration or is a
    crate root, so the rule decides zero files today. Asserted, not remembered:
    `test_an_orphan_owns_its_tag_and_the_shipped_tree_has_none` runs
    [`declared_targets`] over the real tree, and it is the same function
    `cfg_excluded` resolves with. `test_matrix_gate` has one orphan, and it is a
    `screen_kani.rs` that nothing declares.

    Mutation table for the classifier, driven through `check_property_tags` on a
    fixture and re-driven on a copy of the shipped tree:

    * `helper.rs` under `#[cfg(test)] mod helper;` in a NON-`mod.rs` parent,
      carrying an invariant's only tag → red, `no Refines tag in production
      Rust`. Before [`_child_home`] the declaration resolved to nothing and the
      leaf was a production owner at EXIT=0.
    * the same file with the `#[cfg(test)]` removed → green. Depth and the
      parent's shape are not what withholds it; the cfg is.
    * a plainly-declared `attests.rs` carrying that tag → green here, red under
      the re-inserted name filter with the same `no Refines tag` message. The
      message is the tell: it is the finding for a MISSING owner, printed over a
      file every image compiles. CORRECTION, and it belongs at the clause
      because a commit message cannot be rewritten: `bb324bf` reported this as
      an observation about `crates/rsk-device/src/attests.rs`. That file does
      not exist and `git log --all` over it is empty; `SEC-ADM-001`'s only tag
      is in `ccid.rs`. The arm is real — it was built by MOVING that tag onto a
      new `attests.rs` — but it is a construction, and on the shipped tree ZERO
      production files carry `tests` or `kani` in the name, which is the census
      `test_the_shipped_tree_holds_no_file_the_name_filter_would_have_decided`
      asserts. The filter was inert in both directions.
    * a prologue `#![cfg(test)]` over a plainly-declared file → red. Without the
      inner-attribute half of [`_scan`] a proof-only mirror stands in as the
      owner, which is the `*_assurance.rs` defect with the gate on the other
      side of the file.
    * `mod inner { #![cfg(test)] }` inside a shipped file → green. An inner
      attribute answers for the block it OPENS, and a rule handing every one of
      them to the file takes that file's tag with it — the row then reports a
      missing owner that is sitting right there.
    * a prologue `#![cfg(target_os = "none")]` → green. `is False` and not `is
      not True`: a satisfiable expression keeps the file, and the mutant reading
      the three-valued answer as two drops a shipped owner.
    """
    excluded = cfg_excluded(root)
    files = list((root / "crates").glob("*/src/**/*.rs"))
    files.extend((root / "firmware" / "src").glob("**/*.rs"))
    return [f for f in sorted(files) if f.resolve() not in excluded]


#: What a `[[property]]` may say, and the only table this file may have. Neither
#: was held: an invented key in the first record left this row at EXIT=0, measured
#: — so a field added to the property registry was read by nothing and shown to no
#: reader, which is exactly the hole `matrix_gate`'s `[[question]]` had.
PROPERTY_FIELDS = ("clause_of", "id", "name", "ruling", "source", "statement", "status")
TABLES = ("property",)


@functools.cache
def co_refuted(root: pathlib.Path) -> dict[str, list[str]]:
    """invariant -> the comutants that patch real code for it and expect a kill.

    A model mutant whose CODE twin was driven against the real suite and caught is
    evidence about the code, not only about the model — and the status ladder
    cannot see it, because BOUNDED keys on a Kani harness name. Most of the
    MODELLED-ONLY rows carry one, which reads in the table as "no evidence at
    all"; how many is generated into `assurance/reports/assurance-vector.md`, because the
    number written here had gone stale by two. Derived rather than hand-recorded,
    like every other column; `scripts/comutate.py` owns the invariant lookup and
    is reused.
    """
    src = root / "formal" / "comutants.toml"
    if not src.is_file():
        # Absence is "no co-refutation evidence", not a failure: whether the file
        # must exist is `comutate.py --lint`'s row, and duplicating that here
        # would be a second owner for one rule.
        return {}
    sys.path.insert(0, str(root / "scripts"))
    import comutate

    entries = tomllib.loads(src.read_text())["comutant"]
    index = comutate.solo_index(root)
    out: dict[str, list[str]] = {}
    for bug, entry in sorted(entries.items()):
        if entry.get("status") != "patch" or entry.get("expect") != "killed":
            continue
        # Plural: a bug's kill is evidence for every invariant a solo-style
        # configuration shows it breaks, not only for the one whose FILENAME
        # carries the bug. Four of the six P0-launch rows reading `co = 0` had a
        # killed code twin standing in a configuration named after the invariant.
        for inv in comutate.solo_invariants(root, bug, index):
            out.setdefault(inv, []).append(bug)
    return out


def derive(root: pathlib.Path, name: str, solo: dict[str, int]) -> dict:
    crates = root / "crates"
    kani_files = sorted(crates.glob("*/src/*kani*.rs"))
    rust_files = production_rust(root)
    fuzz_files = sorted((root / "fuzz" / "fuzz_targets").glob("*.rs"))
    test_files = sorted((root / "tests").glob("**/*.py"))
    sn = snake(name)
    harnesses = [
        fn
        for f in kani_files
        for fn in FN_DEF.findall(f.read_text(errors="ignore"))
        if sn in fn
    ]
    return {
        "mutants": solo.get(name, 0),
        "co": co_refuted(root).get(name, []),
        "kani": harnesses,
        "fuzz": grep_word(fuzz_files, name),
        "rust": grep_word(rust_files, name),
        "tests": grep_word(test_files, name) + grep_word(test_files, sn),
    }


def formal_supports(
    root: pathlib.Path,
    entries: list[dict],
    definitions: dict[str, str],
    findings: list[str],
) -> dict[str, list[str]]:
    """Validated cross-model support edges, derived from formal source tags."""
    by_id = {e.get("id"): e.get("name") for e in entries}
    modules = {p.stem for p in (root / "formal").glob("*.tla")}
    supports: dict[str, list[str]] = {}
    for tla in sorted((root / "formal").glob("*.tla")):
        for module, name, pid in SUPPORT_TAG.findall(tla.read_text(errors="ignore")):
            where = f"{tla.name}: Supports `{module}!{name}` — {pid}"
            if module not in modules:
                findings.append(f"{where}: no such formal/ module")
            elif definitions.get(name) != module:
                findings.append(
                    f"{where}: {name!r} is defined by "
                    f"{definitions.get(name, 'no module')}, not {module}"
                )
            if pid not in by_id:
                findings.append(f"{where}: id not in the registry")
            elif by_id[pid] != name:
                findings.append(
                    f"{where}: id belongs to {by_id[pid]!r} — mismatched pairing"
                )
            if module in modules and definitions.get(name) == module and by_id.get(pid) == name:
                supports.setdefault(name, []).append(tla.stem)
    return {name: sorted(set(owners)) for name, owners in supports.items()}


def tier_union(formal: pathlib.Path) -> set[str]:
    out = subprocess.run(
        [str(formal / "run-tlc.sh"), "--tiers"],
        cwd=formal,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    names: set[str] = set()
    for line in out.splitlines():
        _, _, rest = line.partition(":")
        names.update(rest.split())
    return names


def workspace_members(root: pathlib.Path) -> set[str]:
    with open(root / "Cargo.toml", "rb") as fh:
        manifest = tomllib.load(fh)
    return {
        tomllib.loads((root / member / "Cargo.toml").read_text())["package"]["name"]
        for member in manifest["workspace"]["members"]
    }


def check_properties(root: pathlib.Path, findings: list[str]) -> list[dict]:
    formal = root / "formal"
    with open(root / "assurance" / "properties.toml", "rb") as fh:
        doc = tomllib.load(fh)
    entries = doc.get("property", [])
    if stray := sorted(set(doc) - set(TABLES)):
        findings.append(
            f"properties.toml carries {stray}, which nothing reads — a table added"
            " here is held by no rule and shown to no reader"
        )
    for entry in entries:
        if extra := sorted(set(entry) - set(PROPERTY_FIELDS)):
            findings.append(
                f"{entry.get('id', '?')}: carries {extra}, which nothing reads"
            )
    checked = checked_names(formal)
    defs = tla_definitions(formal)
    solo = solo_target_counts(formal)
    supports = formal_supports(root, entries, defs, findings)

    ids = [e.get("id", "?") for e in entries]
    names = [e.get("name", "?") for e in entries]
    for kind, seq in (("id", ids), ("name", names)):
        for dup in sorted({x for x in seq if seq.count(x) > 1}):
            findings.append(f"duplicate {kind} in properties.toml: {dup}")

    by_name = {e["name"]: e for e in entries}
    risk = {n for n, e in by_name.items() if e.get("status") == "ACCEPTED-RISK"}

    for name in sorted(set(checked) - set(by_name)):
        findings.append(
            f"checked by {len(checked[name])} cfg(s) but not in the registry: {name}"
        )
    for name in sorted(set(by_name) - set(checked) - risk):
        findings.append(f"registered but checked by no configuration: {name}")

    rows = []
    for e in entries:
        name, status = e.get("name", "?"), e.get("status", "?")
        where = f"{e.get('id', '?')} ({name})"
        if status not in STATUSES:
            findings.append(
                f"{where}: status {status!r} — PROVEN/OBSERVED are refused until "
                "the tree grows that evidence class; add it to the derivation first"
            )
        if not e.get("statement", "").strip():
            findings.append(f"{where}: empty statement")
        if not e.get("source"):
            findings.append(f"{where}: empty source")
        if clause := e.get("clause_of"):
            if clause not in ids:
                findings.append(f"{where}: clause_of {clause!r} names no entry")
        if status == "ACCEPTED-RISK":
            if not e.get("ruling", "").strip():
                findings.append(f"{where}: ACCEPTED-RISK without a ruling")
            if name in checked:
                findings.append(
                    f"{where}: filed as a risk but checked by "
                    f"{checked[name][0]} — a checked invariant is not a ruling"
                )
            rows.append({"e": e, "d": None, "module": None, "support": [], "cfgs": 0})
            continue
        if name not in defs:
            findings.append(f"{where}: no definition in any formal/*.tla module")
        d = derive(root, name, solo)
        if d["kani"] and status != "BOUNDED":
            findings.append(
                f"{where}: {len(d['kani'])} Kani harness(es) carry this name — "
                f"status must be BOUNDED, not {status}"
            )
        if not d["kani"] and status == "BOUNDED":
            findings.append(
                f"{where}: BOUNDED with no Kani harness carrying the name"
            )
        rows.append(
            {
                "e": e,
                "d": d,
                "module": defs.get(name),
                "support": supports.get(name, []),
                "cfgs": len(checked.get(name, [])),
            }
        )
    return rows


def check_tags(root: pathlib.Path, findings: list[str], entries: list[dict]) -> None:
    """Every property tag in production Rust names real registry rows.

    And the other direction, scoped to where owners exist: every invariant the
    phase-1 owner configurations check must carry a validated production tag.
    That set is derived from the cfgs, not kept by hand.
    """
    by_id = {e.get("id"): e.get("name") for e in entries}
    definitions = tla_definitions(root / "formal")
    modules = {p.stem for p in (root / "formal").glob("*.tla")}
    rust_files = production_rust(root)
    tagged_names: set[str] = set()
    for f in rust_files:
        text = f.read_text(errors="ignore")
        tagged_ids = set()
        for module, name, pid in TAG.findall(text):
            tagged_ids.add(pid)
            tagged_names.add(name)
            where = f"{f.name}: `{module}!{name}` — {pid}"
            if module not in modules:
                findings.append(f"{where}: no such formal/ module")
            elif definitions.get(name) != module:
                findings.append(
                    f"{where}: {name!r} is defined by "
                    f"{definitions.get(name, 'no module')}, not {module}"
                )
            if pid not in by_id:
                findings.append(f"{where}: id not in the registry")
            elif by_id[pid] != name:
                findings.append(
                    f"{where}: id belongs to {by_id[pid]!r} — mismatched pairing"
                )
        for pid in set(SEC_ID.findall(text)) - tagged_ids:
            if pid not in by_id:
                findings.append(f"{f.name}: {pid} is not in the registry")

    for cfg_name in OWNER_CFGS:
        cfg = root / "formal" / cfg_name
        if cfg.is_file():
            for name in cfg_checked(cfg):
                if name in tagged_names:
                    continue
                findings.append(
                    f"{name}: checked by {cfg_name} but has no Refines tag in "
                    "production Rust"
                )


def check_property_tags(root: pathlib.Path, findings: list[str]) -> None:
    """Load the registry and hold its production tags in both directions."""
    path = root / "assurance" / "properties.toml"
    if not path.is_file():
        findings.append("assurance/properties.toml is missing — tags are unchecked")
        return
    with open(path, "rb") as fh:
        entries = tomllib.load(fh).get("property", [])
    check_tags(root, findings, entries)


def markdown_table(rows: list[dict]) -> str:
    """The generated traceability table embedded in formal/README.md."""
    lines = [
        "| ID | Property | Status | Model | Support | Rust | Mutants | Co-refuted | Kani | Fuzz | Runtime |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        e, d = row["e"], row["d"]
        if d is None:
            evidence = ("—", "—", "—", "—", "—", "—", "—", "—")
        else:
            evidence = (
                f"`{row['module']}`",
                ", ".join(f"`{m}`" for m in row["support"]) or "—",
                str(len(d["rust"])),
                str(d["mutants"]),
                str(len(d["co"])),
                str(len(d["kani"])),
                str(len(d["fuzz"])),
                str(len(d["tests"])),
            )
        lines.append(
            f"| `{e['id']}` | `{e['name']}` | {e['status']} | "
            + " | ".join(evidence)
            + " |"
        )
    return "\n".join(lines)


def crate_ledger(root: pathlib.Path) -> dict[str, dict]:
    with open(root / "assurance" / "crates.toml", "rb") as fh:
        return tomllib.load(fh).get("crate", {})


def crate_ledger_table(ledger: dict[str, dict]) -> str:
    lines = [
        "### Workspace coverage ledger — generated",
        "",
        "| Crate | Class | Model / evidence | Named gap / disposition |",
        "|---|---|---|---|",
    ]
    for name, entry in sorted(ledger.items()):
        if model := entry.get("model"):
            evidence = f"`{model}`"
        else:
            evidence = "<br>".join(f"`{p}`" for p in entry.get("evidence", [])) or "—"
        disposition = (
            entry.get("gap")
            or entry.get("planned")
            or entry.get("reason")
            or "—"
        )
        lines.append(f"| `{name}` | {entry.get('class', '?')} | {evidence} | {disposition} |")
    return "\n".join(lines)


def readme_block(rows: list[dict], ledger: dict[str, dict]) -> str:
    return (
        f"{README_START}\n"
        "<!-- Generated by scripts/assurance_gate.py --write-readme; do not edit. -->\n"
        f"{markdown_table(rows)}\n\n"
        f"{crate_ledger_table(ledger)}\n"
        f"{README_END}"
    )


def replace_readme_block(text: str, block: str) -> str:
    if text.count(README_START) != 1 or text.count(README_END) != 1:
        raise ValueError("formal/README.md needs exactly one assurance table marker pair")
    start = text.index(README_START)
    end = text.index(README_END, start) + len(README_END)
    return text[:start] + block + text[end:]


def check_readme(
    root: pathlib.Path,
    rows: list[dict],
    ledger: dict[str, dict],
    findings: list[str],
) -> None:
    path = root / "formal" / "README.md"
    if not path.is_file():
        findings.append("formal/README.md is missing — no published traceability table")
        return
    text = path.read_text()
    try:
        want = replace_readme_block(text, readme_block(rows, ledger))
    except ValueError as error:
        findings.append(str(error))
        return
    if text != want:
        findings.append(
            "formal/README.md traceability table is stale — run "
            "python scripts/assurance_gate.py --write-readme"
        )


def check_tiers(root: pathlib.Path, findings: list[str]) -> int:
    formal = root / "formal"
    tiered = tier_union(formal)
    present = {p.name for p in formal.glob("*.cfg")}
    for cfg in sorted(present - tiered - set(EXEMPT_CFG)):
        findings.append(f"{cfg}: in no tier of run-tlc.sh and not exempt")
    for cfg in sorted(tiered - present):
        findings.append(f"{cfg}: in a tier but no such file")
    for cfg in sorted(set(EXEMPT_CFG) - present):
        findings.append(f"{cfg}: exempt but no such file — stale exemption")
    return len(tiered)


#: What a `pure` row's `evidence` must BE. Not open-ended: this ledger's own
#: header says the field "names the differential/KAT/proof files", so the honest
#: set is nameable rather than merely non-prose — measured, 20 paths over 9 rows,
#: every one a `.rs` under its own crate's `src/` or under `fuzz/fuzz_targets/`.
#: Before this, the test was `.is_file()`: `evidence = ["README.md"]` on
#: `rsk-led` was **exit 0** once `--write-readme` was run, and so was
#: `["README.MD"]`, which APFS folds and no suffix rule does.
#:
#: WHY NOT [`platform_gate.PROSE_PAGE`]'s RULE, which this replaces the missing
#: half of. That axis refuses one KIND of file and says outright it cannot check
#: relevance; copied here it is INSUFFICIENT rather than wrong, because
#: `["deny.toml"]` and `["assurance/crates.toml"]` are not pages and are not
#: differentials either. Its generated-page carve-out is the wrong shape here
#: too: `formal/README.md` is the page THIS gate writes and
#: [`crate_ledger_table`] prints each `pure` row's own evidence into it, so the
#: carve-out would admit a row settled by the page that prints its settlement.
#: The suffix half refuses every page, generated or not, and that loop with it —
#: which is why there is no separate `circular` clause here.
#:
#: REFUTED BY MEASUREMENT, not taste. Tying evidence to the row's own subject is
#: the strong form `platform_gate` had to reject (two of its three honest rows go
#: red); on THIS axis it costs zero, because a `pure` row's subject is a
#: directory rather than a prose assumption. The step ABOVE it is what fails
#: here: requiring a cited fuzz target to name its crate reddens
#: `fuzz/fuzz_targets/mldsa_roundtrip.rs` and `mldsa_verify.rs`, which are
#: `rsk-mldsa`'s evidence and reach it through `rsk_crypto`'s re-export —
#: `fuzz/Cargo.toml` names `rsk-mldsa` nowhere. Two of twenty, and for the same
#: reason as the platform refutation: the tie runs through an indirection. So
#: the fuzz half below is a DIRECTORY allowance and not a tie.
#:
#: WHAT IT STILL DOES NOT CHECK. That the file is REACHED by its crate's module
#: tree: `crates/rsk-slip39/src/tests.rs` is hooked in as a plain `mod tests;`
#: while every other cited file uses `#[path]`, so both forms would have to be
#: resolved — the "proofs run by nothing" class one layer out, and a bigger thing
#: than this. And a `pure` crate whose differential legitimately lived in a
#: SIBLING crate would be a false red; none does today.
EVIDENCE_SUFFIX = ".rs"


def evidence_homes(name: str) -> tuple[str, ...]:
    """The two places crate `name`'s differential/KAT/proof files may sit."""
    return (f"crates/{name}/src/", "fuzz/fuzz_targets/")


def check_crates(
    root: pathlib.Path, findings: list[str], tree: set[pathlib.Path]
) -> tuple[dict[str, int], dict[str, dict]]:
    """`tree` has no default on purpose: an empty one reads every artifact as
    absent, which is loud, while a defaulted `None` treated as "skip" would let a
    caller switch the rule off by forgetting it."""
    ledger = crate_ledger(root)
    members = workspace_members(root)
    modules = {p.stem for p in (root / "formal").glob("*.tla")}

    for name in sorted(members - set(ledger)):
        findings.append(f"workspace member not in the crate ledger: {name}")
    for name in sorted(set(ledger) - members):
        findings.append(f"ledgered but not a workspace member: {name}")

    tally: dict[str, int] = {}
    for name, entry in sorted(ledger.items()):
        cls = entry.get("class", "?")
        tally[cls] = tally.get(cls, 0) + 1
        where = f"crates.toml [{name}]"
        if cls in ("state-modelled", "state-partial"):
            if entry.get("model") not in modules:
                findings.append(f"{where}: model {entry.get('model')!r} is no formal/ module")
            if cls == "state-partial" and not entry.get("gap", "").strip():
                findings.append(f"{where}: state-partial without a named gap")
        elif cls == "state-unmodelled":
            if not entry.get("planned", "").strip():
                findings.append(f"{where}: state-unmodelled without a planned module")
        elif cls == "pure":
            paths = entry.get("evidence", [])
            if not paths:
                findings.append(f"{where}: pure without evidence files")
            for p in paths:
                if not platform_gate.in_tree(p, tree):
                    findings.append(
                        f"{where}: evidence file missing: {p} — git's own listing,"
                        " which has no directory in it and folds no case"
                    )
                elif not str(p).lower().endswith(EVIDENCE_SUFFIX):
                    findings.append(
                        f"{where}: evidence {p!r} is not Rust source — this field"
                        " names the differential/KAT/proof files, and a page, a"
                        " manifest or a data table is none of the three"
                    )
                elif not str(p).startswith(evidence_homes(name)):
                    findings.append(
                        f"{where}: evidence {p!r} is neither {name}'s own source"
                        f" ({evidence_homes(name)[0]}) nor a fuzz target — a file"
                        " under another crate settles that crate, not this row"
                    )
        elif cls in ("out-of-scope", "embedded-binary"):
            if not entry.get("reason", "").strip():
                findings.append(f"{where}: {cls} without a reason")
        else:
            findings.append(f"{where}: unknown class {cls!r}")
    return tally, ledger


def audit(root: pathlib.Path, check_generated_readme: bool = True):
    """(problems, evidence table, one-line summary) for this checkout."""
    root = pathlib.Path(root)
    findings: list[str] = []
    rows = check_properties(root, findings)
    check_property_tags(root, findings)
    tiered = check_tiers(root, findings)
    tally, ledger = check_crates(root, findings, set(gate_lines.tree_files(root)))
    if check_generated_readme:
        check_readme(root, rows, ledger, findings)

    table: list[str] = []
    for r in rows:
        e, d = r["e"], r["d"]
        if d is None:
            table.append(f"  {e['id']:<14} {e['name']:<40} {e['status']}")
            continue
        table.append(
            f"  {e['id']:<14} {e['name']:<40} {e['status']:<13}"
            f" cfgs={r['cfgs']:<3} mut={d['mutants']:<2} co={len(d['co'])}"
            f" kani={len(d['kani'])}"
            f" fuzz={len(d['fuzz'])} rust={len(d['rust'])} test={len(d['tests'])}"
        )

    statuses: dict[str, int] = {}
    for r in rows:
        s = r["e"]["status"]
        statuses[s] = statuses.get(s, 0) + 1
    summary = (
        "assurance-gate: ok — "
        + f"{len(rows)} properties ("
        + ", ".join(f"{v} {k.lower()}" for k, v in sorted(statuses.items()))
        + f"), {sum(tally.values())} crates ledgered ("
        + ", ".join(f"{v} {k}" for k, v in sorted(tally.items()))
        + f"), {tiered} cfgs tiered + {len(EXEMPT_CFG)} exempt"
    )
    return findings, table, summary


def run(root: pathlib.Path) -> int:
    findings, table, summary = audit(root)
    for line in table:
        print(line)
    if findings:
        print(f"assurance-gate: {len(findings)} finding(s)", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def write_readme(root: pathlib.Path) -> int:
    root = pathlib.Path(root)
    findings, _, _ = audit(root, check_generated_readme=False)
    if findings:
        print(
            "assurance-gate: refusing to publish a table from an invalid tree",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    property_findings: list[str] = []
    rows = check_properties(root, property_findings)
    if property_findings:
        raise AssertionError(property_findings)
    path = root / "formal" / "README.md"
    try:
        text = replace_readme_block(
            path.read_text(), readme_block(rows, crate_ledger(root))
        )
    except (FileNotFoundError, ValueError) as error:
        print(f"assurance-gate: {error}", file=sys.stderr)
        return 1
    path.write_text(text)
    print(f"assurance-gate: wrote {len(rows)} properties to formal/README.md")
    return 0


def main():
    if sys.argv[1:] == ["--write-readme"]:
        return write_readme(ROOT)
    if sys.argv[1:]:
        print("usage: assurance_gate.py [--write-readme]", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
