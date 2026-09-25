#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold `docs/testing.md`'s roster of `cfg(kani)` shrinks to the crates, both ways.

A shrink is production source that means something different under Kani than in
the shipped build — an array cut to 16 so CBMC does not bit-blast 2 KiB, a file
id aliased into a 24-bit map. Each one narrows what every proof over it says, so
the page that describes the proofs enumerates them and each states, where it is
written, what it stops proving.

That roster was hand-kept and has rotted twice. `ef3a7c6` wrote it as "the tree's
only `cfg(kani)` change to production source", which was true that week and false
by the next: `rsk-usb`'s `CTAP_MAX_MESSAGE` was already there, `5b8b563` added
`rsk-fs`'s `FID_PRESENT_BYTES` and the sentence stayed green, and `f0778de` then
retyped it by hand to name four. Four was wrong the day it was written —
`rsk-sdk` shrinks **two** constants, not one — which is the argument for deriving
the set rather than remembering to retype it.

## What counts as a shrink

Every item in production source whose `cfg` mentions `kani`, less two kinds:

* a proof-module hook — `#[cfg(kani)] #[path = "…"] mod proofs;` and the
  verification modules beside it. Those *are* the proofs; rostering them would
  bury the five items this page is about under the thirty-five that need none.
* an item that is present in a `cargo test` build too. `#[cfg(any(test, kani))]`
  is verification-support code, and it belongs to the test layer; kani appears in
  it as one member of a set, not as a condition of its own. Decided by evaluating
  the predicate in three worlds — shipped, kani, test — with every other flag
  UNKNOWN, so the shape of the spelling does not matter, only what it decides.

  With one override, because that exclusion is otherwise a way through it: a name
  the file defines **more than once** is an arm set, and an arm set that mentions
  kani at all is a shrink however it is spelled. `#[cfg(any(kani, test))] const
  FID_PRESENT_BYTES = 3;` beside a `not(any(kani, test))` arm shrinks production
  exactly as much as `#[cfg(kani)]` does.

Which files are production is walked, not listed: from each crate's `lib.rs`
through its `mod` declarations, and a module reached only through a cfg naming
`kani` or `test` is verification source along with everything below it. Every
`.rs` under `crates/*/src` has to be reached by that walk — one that is not is a
file this guard cannot classify, so it is a failure rather than a skip.

## The rationale

The roster says a shrink exists; it cannot say the shrink is sound. What it can
check is that somebody wrote down why, next to the arm Kani actually compiles —
a comment block above it, or above the run of same-cfg arms it belongs to, since
`rsk-sdk`'s one paragraph covers both of its constants and says so ("both
arrays"). [`RATIONALE_FLOOR`] is what "wrote down why" means here.

Rejected: requiring a `///` doc comment. Two of the tree's five shrinks and one
of its three compensating assertions use `//`, all three are genuine reasons, and
the marker is a rendering choice — a rule that reddened them would be teaching
the wrong lesson. Also rejected: requiring the word `kani` or `proof` in the
block. It is keyword-matching in both directions — `// kani` satisfies it and
`rsk-sdk`'s paragraph, which explains the shrink in CBMC's terms, does not.

## What this is not

It does not read values. What `CHAIN_BUF_SIZE` is under Kani and what it ships at
is in the code and in the comment beside it; copying either into the docs would
make the page a third place for them to rot, which is the failure this file
exists to end. The roster is names.

It does not follow a `cfg` into an expression. `cfg!(kani)` inside a function
body is a divergence with no item to name, so it stops the gate rather than being
skipped — the same for an inner `#![cfg(kani)]`, which gates a whole production
file, and for an item kind this parser cannot name. Fail-closed, because a
spelling nobody has decided about is exactly how a roster acquires a hole.

Its own mutation table is `scripts/test_shrink_gate.py`.
"""

from __future__ import annotations

import collections
import pathlib
import re
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The page that owes the roster, and the table in it. Three columns so a row is
#: decidable on its own: two files can shrink the same name, and one file can
#: hold two anonymous assertions, so neither the name nor the file is a key.
ROSTER_PAGE = pathlib.Path("docs/testing.md")
ROW = re.compile(r"^\|\s*`(rsk-[a-z0-9-]+)`\s*\|\s*`([^`|]+)`\s*\|\s*`([^`|]+)`\s*\|\s*$", re.M)

#: Where the crates are, and the file each crate's walk starts from.
CRATES = "crates"
CRATE_ROOT = "src/lib.rs"

#: Item kinds that are a hook rather than a shrink: the proof modules and the
#: verification modules. `use` is deliberately NOT here — an aliased import is a
#: way to swap a type under Kani, and rostering it loudly beats skipping it.
HOOK_KINDS = frozenset({"mod"})

#: Kinds this parser can name. Anything else after a kani-only attribute stops
#: the gate: an `impl` block cannot be rostered by name, and a roster that
#: silently skips what it cannot name is the hole one file over.
NAMED_KINDS = frozenset(
    {"const", "static", "fn", "struct", "enum", "union", "trait", "type", "macro_rules!", "use"}
)

#: An anonymous `const _: () = assert!(…)`, the shape every compensating
#: assertion here takes. Rostered under this label, disambiguated by its crate and
#: file; an item with no name slot at all (an `impl`) stops the gate instead.
ANONYMOUS = "const _"

#: Below this a comment block is a label, not a reason. The shortest rationale in
#: the tree is 203 characters; set well under it so rewording one does not trip
#: the rule, and over the `// proof-only shrink` a hurried edit leaves behind.
RATIONALE_FLOOR = 80

#: The worlds a `cfg` predicate is evaluated in. Every other flag is UNKNOWN, so
#: `all(kani, feature = "x")` is "maybe present under Kani" rather than a guess.
SHIPPED = {"kani": False, "test": False}
KANI = {"kani": True, "test": False}
TEST = {"kani": False, "test": True}

TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[(),=]")

#: An item header: visibility, the modifiers that may precede a keyword, then the
#: keyword. `const` is only a keyword here when nothing turns it into `const fn`.
KEYWORD = re.compile(
    r"\s*(?:(?:pub\s*(?:\([^)]*\)\s*)?)|(?:default\s+)|(?:unsafe\s+)|(?:async\s+)"
    r"|(?:const\s+(?=fn\b|unsafe\b|extern\b))|(?:extern\s+\"[^\"]*\"\s+))*"
    r"(const|static|fn|struct|enum|union|trait|type|impl|mod|use|macro_rules!|extern)\b"
)
#: The name an item declares. A bare `_` matches, which is what makes
#: `const _: () = assert!(…)` readable at all — see [`ANONYMOUS`].
NAME = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)")
PATH_ATTR = re.compile(r'^\s*path\s*=\s*"([^"]+)"\s*$')
MOD_DECL = re.compile(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
CFG_BANG = re.compile(r"(?<![\w:])cfg!\s*\(")
KANI_WORD = re.compile(r"(?<![\w:])kani(?![\w:])")


def attributes(code):
    """(start, end, body_start, body_end, inner) for every attribute in `code`.

    Bracket-matched rather than line-matched: rustfmt wraps a long predicate over
    several lines, and a rule that reads one line of `#[cfg(any(\\n  test,\\n
    kani))]` sees a `cfg` mentioning neither.
    """
    out, i, n = [], 0, len(code)
    while i < n:
        if code[i] == "#" and (code[i + 1 : i + 2] == "[" or code[i + 1 : i + 3] == "!["):
            opened = code.index("[", i)
            depth, k = 0, opened
            while k < n:
                if code[k] in "[({":
                    depth += 1
                elif code[k] in "])}":
                    depth -= 1
                    if not depth:
                        break
                k += 1
            out.append((i, k + 1, opened + 1, k, code[i + 1] == "!"))
            i = k + 1
            continue
        i += 1
    return out


def attribute_groups(code):
    """(attributes, item start, inner, group start) — consecutive attributes as one.

    An item's attributes are the run above it with nothing but whitespace
    between, which is how `#[cfg(kani)]` and `#[path = "…"]` reach the same `mod`.
    """
    found, out, i = attributes(code), [], 0
    while i < len(found):
        if found[i][4]:
            out.append(([found[i]], found[i][1], True, found[i][0]))
            i += 1
            continue
        group = [found[i]]
        while i + 1 < len(found) and not found[i + 1][4] and not code[found[i][1] : found[i + 1][0]].strip():
            i += 1
            group.append(found[i])
        out.append((group, group[-1][1], False, group[0][0]))
        i += 1
    return out


def item_at(code, pos):
    """(kind, name, end) of the item starting at `pos`; kind None if unrecognised."""
    head = KEYWORD.match(code, pos)
    if not head:
        return None, None, pos
    kind = head.group(1)
    if kind in ("impl", "extern"):
        return kind, None, head.end()
    named = NAME.match(code, head.end())
    return (kind, named.group(1), named.end()) if named else (kind, None, head.end())


def parse_predicate(body):
    """A `cfg`/`cfg_attr` attribute body as nested tuples, or None if it is neither.

    `("call", name, args)`, `("flag", name)`, `("opt", name)`. The body comes from
    code with string literals already blanked, so `feature = "kani-x"` cannot be
    read as naming the flag.
    """
    tokens = TOKEN.findall(body)
    if not tokens or tokens[0] not in ("cfg", "cfg_attr"):
        return None
    node, _ = _parse(tokens, 0)
    if node[0] != "call" or not node[2]:
        return None
    return node[2][0]  # `cfg(pred)`, and `cfg_attr(pred, …)`'s first argument


def _parse(tokens, i):
    name = tokens[i]
    i += 1
    if i < len(tokens) and tokens[i] == "(":
        i += 1
        args = []
        while i < len(tokens) and tokens[i] != ")":
            arg, i = _parse(tokens, i)
            args.append(arg)
            if i < len(tokens) and tokens[i] == ",":
                i += 1
        return ("call", name, tuple(args)), i + 1
    if i < len(tokens) and tokens[i] == "=":
        i += 1
        if i < len(tokens) and tokens[i] not in (",", ")"):
            i += 1
        return ("opt", name), i
    return ("flag", name), i


def evaluate(node, world):
    """The predicate in `world`: True, False, or None for "depends on a flag we
    are not modelling". Kleene, so an unknown under an `any` that is already true
    does not make the answer unknown."""
    if node[0] == "flag":
        return world.get(node[1])
    if node[0] == "opt":
        return None
    _, name, args = node
    values = [evaluate(arg, world) for arg in args]
    if name == "not":
        return None if not values or values[0] is None else not values[0]
    if name == "all":
        if any(value is False for value in values):
            return False
        return None if any(value is None for value in values) else True
    if name == "any":
        if any(value is True for value in values):
            return True
        return None if any(value is None for value in values) else False
    return None


def mentions_kani(node):
    return node is not None and (
        (node[0] == "flag" and node[1] == "kani")
        or (node[0] == "call" and any(mentions_kani(arg) for arg in node[2]))
    )


def child_dir(path):
    """Where a module file's children live: its own directory for a crate root or
    a `mod.rs`, a directory named after it otherwise."""
    return path.parent if path.name in ("lib.rs", "mod.rs") else path.parent / path.stem


def module_targets(path, raw):
    """(name, attribute bodies, file) for every non-inline `mod` declared here."""
    code = gate_lines.rust_code(raw)
    attributed = {}
    for group, start, inner, _above in attribute_groups(code):
        if inner:
            continue
        kind, name, after = item_at(code, start)
        if kind != "mod" or name is None or code[after:].lstrip().startswith("{"):
            continue
        attributed[name] = [raw[a[2] : a[3]] for a in group]
    out = []
    for found in MOD_DECL.finditer(code):
        name = found.group(1)
        bodies = attributed.get(name, [])
        declared = next((PATH_ATTR.match(b).group(1) for b in bodies if PATH_ATTR.match(b)), None)
        if declared:
            # `#[path]` resolves against the directory of the file it is written
            # in, not the module's own — `render.rs` reaches `render_tests.rs`
            # beside it, never `render/render_tests.rs`.
            target = path.parent / declared
        else:
            below = child_dir(path)
            target = below / f"{name}.rs"
            if not target.is_file() and (below / name / "mod.rs").is_file():
                target = below / name / "mod.rs"
        out.append((name, bodies, target))
    return out


def classify_files(root):
    """(production, verification, problems) over `crates/*/src`, walked from each
    crate root through its `mod` declarations."""
    production, verification, problems, seen = set(), set(), [], set()
    for crate_root in sorted((root / CRATES).glob(f"*/{CRATE_ROOT}")):
        pending = [(crate_root, True)]
        while pending:
            path, is_production = pending.pop()
            if (path, is_production) in seen:
                continue
            seen.add((path, is_production))
            if not path.is_file():
                problems.append(
                    f"FAIL: {path.relative_to(root)} is declared as a module but does not exist."
                )
                continue
            (production if is_production else verification).add(path)
            raw = path.read_text(encoding="utf-8", errors="replace")
            for _name, bodies, target in module_targets(path, raw):
                gated = any(
                    mentions_verification(parse_predicate(gate_lines.rust_code(body)))
                    for body in bodies
                )
                pending.append((target, is_production and not gated))
    return production, verification, problems


def mentions_verification(node):
    """Whether a `mod`'s cfg puts its file behind `kani` or `test`."""
    if node is None:
        return False
    if node[0] == "flag":
        return node[1] in ("kani", "test")
    if node[0] == "call":
        return any(mentions_verification(arg) for arg in node[2])
    return False


class Arm:
    """One cfg-gated item: where it is, what it is, and what its predicate says."""

    def __init__(self, rel, line, attr_line, kind, name, predicate):
        self.rel, self.line, self.attr_line = rel, line, attr_line
        self.kind, self.name, self.predicate = kind, name, predicate
        #: Whether the file defines this name more than once. Filled in once the
        #: whole file is read, since the other arm may be written below this one.
        self.arm_set = False

    @property
    def crate(self):
        return self.rel.parts[1]

    @property
    def source(self):
        return str(pathlib.PurePath(*self.rel.parts[3:]))

    @property
    def label(self):
        return ANONYMOUS if self.name == "_" else self.name

    @property
    def key(self):
        return (self.crate, self.source, self.label)

    @property
    def where(self):
        return f"{self.rel} line {self.line}"

    def verification_support(self):
        """Present in a `cargo test` build for the same reason it is present under
        Kani — so it is test-layer scaffolding, not a shrink of what ships."""
        return evaluate(self.predicate, TEST) == evaluate(self.predicate, KANI)


def arms_of(root, rel, problems):
    """Every kani-conditioned item in one production file, problems appended."""
    raw = (root / rel).read_text(encoding="utf-8", errors="replace")
    if "kani" not in raw:
        return []
    code = gate_lines.rust_code(raw)
    for found in CFG_BANG.finditer(code):
        closed = code.find(")", found.start())
        if KANI_WORD.search(code[found.start() : len(code) if closed < 0 else closed]):
            at = code[: found.start()].count("\n") + 1
            problems.append(
                f"FAIL: {rel} line {at} makes a kani decision inside an expression "
                "(`cfg!`). This roster is over items; lift it to one, or teach "
                "shrink_gate.py what to call it."
            )
    out, definitions = [], collections.Counter()
    for group, start, inner, above in attribute_groups(code):
        predicate = next(
            (
                node
                for node in (parse_predicate(code[a[2] : a[3]]) for a in group)
                if mentions_kani(node)
            ),
            None,
        )
        kind, name, _end = item_at(code, start)
        if name and name != "_" and kind not in HOOK_KINDS and kind != "use":
            definitions[name] += 1
        if predicate is None:
            continue
        line = code[:start].count("\n") + 1
        # Where the ATTRIBUTES begin, not the item: rustfmt wraps a long predicate
        # over four lines, and a reason scanned upward from the item would find
        # `feature = "x"` sitting where the paragraph is.
        attr_line = code[:above].count("\n") + 1
        if inner:
            problems.append(
                f"FAIL: {rel} line {line} gates the whole file on kani with an inner "
                "`#![cfg(…)]`. Put the condition on the `mod` that declares it, so the "
                "module walk can see it."
            )
            continue
        if kind in HOOK_KINDS:
            continue
        if kind not in NAMED_KINDS or name is None:
            problems.append(
                f"FAIL: {rel} line {line} is a kani-conditioned `{kind or '?'}` this "
                "roster cannot name. Give it a name, or teach shrink_gate.py the kind."
            )
            continue
        out.append(Arm(rel, line, attr_line, kind, name, predicate))
    # Counted over the whole file first: an arm set is what tells a shrink from
    # scaffolding, and the second arm can be written below the one being judged.
    for arm in out:
        arm.arm_set = definitions[arm.name] > 1
    return out


def rationale(root, arms):
    """arm -> the comment block above it, following a run of same-cfg arms up.

    `rsk-sdk` writes one paragraph over `#[cfg(kani)] const CHAIN_BUF_SIZE` and
    `#[cfg(kani)] const RESP_CHAIN_CAP` and says it covers both; the second has no
    block of its own and inherits the first's.
    """
    out = {}
    by_file = collections.defaultdict(list)
    for arm in arms:
        by_file[arm.rel].append(arm)
    for rel, group in by_file.items():
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        group.sort(key=lambda a: a.line)
        for index, arm in enumerate(group):
            block, above = [], arm.attr_line - 2
            while above >= 0 and lines[above].strip().startswith("//"):
                block.append(lines[above].strip().lstrip("/").strip())
                above -= 1
            previous = group[index - 1] if index else None
            if not block and previous is not None and inherits(lines, previous, arm):
                out[arm] = out.get(previous, "")
                continue
            out[arm] = " ".join(reversed(block))
    return out


def inherits(lines, previous, arm):
    """Whether `arm` is the next item of `previous`'s run: same predicate, and
    nothing but that item's own body between them."""
    if previous.predicate != arm.predicate:
        return False
    return all(line.strip() for line in lines[previous.line - 1 : arm.attr_line - 1])


def rostered(root):
    """(the derived roster as a Counter, every arm behind it, problems)."""
    production, verification, problems = classify_files(root)
    everything = set((root / CRATES).glob("*/src/**/*.rs"))
    for stray in sorted(everything - production - verification):
        problems.append(
            f"FAIL: {stray.relative_to(root)} is under a crate's `src` but no `mod` "
            "declaration reaches it, so this guard cannot say whether it ships."
        )
    arms = []
    for path in sorted(production):
        arms += arms_of(root, path.relative_to(root), problems)
    shrinks = [a for a in arms if a.arm_set or not a.verification_support()]
    # One row per NAME, not per arm: a shrink is written twice by construction
    # (the shipped definition and the Kani one), and a page that said
    # `FID_PRESENT_BYTES` twice would be describing the spelling, not the tree.
    # The anonymous assertions have no name to collapse on, so they count singly
    # and a second one in the same file is a row the page still owes.
    derived = collections.Counter(a.key for a in shrinks if a.name == "_")
    derived.update({a.key for a in shrinks if a.name != "_"})
    return derived, shrinks, problems


def tabled(root):
    """The roster the page states, as a Counter of the same key."""
    page = (root / ROSTER_PAGE).read_text(encoding="utf-8")
    return collections.Counter(ROW.findall(page))


def audit(root=ROOT):
    """(problems, the derived roster, the arms behind it)."""
    derived, shrinks, problems = rostered(root)
    stated = tabled(root)
    for key, count in sorted((derived - stated).items()):
        where = next(a.where for a in shrinks if a.key == key)
        problems.append(
            f"FAIL: {ROSTER_PAGE} has no row for `{key[0]}` `{key[1]}` `{key[2]}` "
            f"({where}){'' if count == 1 else f', {count} of them'}."
        )
    for key, _count in sorted((stated - derived).items()):
        problems.append(
            f"FAIL: {ROSTER_PAGE} rosters `{key[0]}` `{key[1]}` `{key[2]}`, which is no "
            "longer a kani-only item of that file."
        )
    reasons = rationale(root, shrinks)
    for arm in sorted(shrinks, key=lambda a: (str(a.rel), a.line)):
        if evaluate(arm.predicate, KANI) is False and any(
            other.key == arm.key and evaluate(other.predicate, KANI) is not False
            for other in shrinks
        ):
            continue  # the shipped arm of a name whose Kani arm carries the reason
        if len(reasons.get(arm, "")) < RATIONALE_FLOOR:
            problems.append(
                f"FAIL: {arm.where} shrinks `{arm.label}` under kani with no reason "
                f"written above it ({len(reasons.get(arm, ''))} characters of comment, "
                f"floor {RATIONALE_FLOOR}). Say what it stops proving."
            )
    return problems, derived, shrinks


def main():
    problems, derived, shrinks = audit()
    if problems:
        print("shrink-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    crates = sorted({key[0] for key in derived})
    print(
        f"shrink-gate: ok — {sum(derived.values())} kani-only item(s) over "
        f"{len(shrinks)} arm(s) in {len(crates)} crate(s), all rostered by {ROSTER_PAGE}"
    )
    for key in sorted(derived):
        lines = ", ".join(
            str(a.line) for a in sorted(shrinks, key=lambda a: a.line) if a.key == key
        )
        print(f"  {key[0]}/{key[1]}: {key[2]} (line {lines})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
