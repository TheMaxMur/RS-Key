#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Tree-wide completeness gate for the phase-5 concrete event boundary.

Every vocabulary this gate matches on is read out of the tree, because the four
holes the 2026-08-26 rescan found were all one class: a set spelled once in the
source and a second time in a regex here. The Fs write API was four names of
eleven, the permission set four of seven, the fid-parameter helpers two names in
an `if`, and the production/test split knew `*_tests.rs` but not
`#[cfg(test)] mod`. Each miss is silent — the site is simply never discovered, so
the roster stays "complete" over a shorter list.

The 2026-08-31 rescan closed four more of the same class, and it is the same
lesson a fifth time — each one was a set the tree spells and this file did not.
A probe of 23 write spellings against the fixture found 8 MISSED, in four causes,
and only the first two had ever been written down anywhere:

  * `let fid = EF_PIN; fs.put(fid, ..)` — the fid one `let` away from the write;
  * `let f = 0x1000u16 + 0x80; fs.put(f, ..)` — the same, ARITHMETIC, and named
    by nothing anywhere: it spells neither `EF_PIN` nor `0x1080`;
  * a permission mask behind a helper taking `permissions: u8`, or one `let`
    away (`let p = paut.permissions; p & PERM_MC`);
  * `*st = rsk_fido::FidoState::new()` — the whole token replaced, spelling
    neither `self` nor a `.paut.`, in a crate the writer axes could not see.

Five shapes a §7.7 review drove through are STATED EXCLUSIONS rather than rules,
and none of them exists in this tree today — they are rot holes, not live unowned
writers: a fid rebuilt with `u16::from_be_bytes`, a write inside a macro body, a
write inside a closure, a helper taking `&mut PinUvAuthToken`, and a gate helper
taking `&PinUvAuthToken`. The last two look cheap and are not: deriving the token
struct's NAME from its fields resolves to `AssertionState`, which shares
`last_used_ms` with it — measured, and it produced a false owner
(`getassertion.rs::arm_get_next_assertion`) on the first run. A correct rule needs
the name `token_fields` already hardcodes, which would be a third spelling of the
one thing this file exists to spell once.

The coarse rules the previous paragraph refused — "names a token fid and calls
any writer", "hands `paut.permissions` to anything" — cost 5 and 1 false owners,
and that refusal was right. What replaced them is not a coarser rule but a
narrower one: the LOCAL actually passed to the writer is resolved against the
`let` that bound it (folding integer arithmetic, so the second shape above is
found by evaluation and not by a pattern), and the permission clause requires a
caller to hand the live byte in. Measured on this tree: 0 false owners from
either, and one real unowned writer from the fourth.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

import bcd_gate

ROOT = Path(__file__).resolve().parents[1]

FIDO = Path("crates/rsk-fido/src")
STATE = FIDO / "state.rs"
PROJECTION = FIDO / "state_assurance.rs"
CONSTS = FIDO / "consts.rs"
STORE = Path("crates/rsk-fs/src/fs.rs")
MANIFEST = Path("assurance/token_refinement.toml")
EXPORT = Path("formal/generated/token_relation.txt")
# matrix_gate's own generated artifact, diffed against its generator by the
# "build-configuration matrix" row. Reading the column names here reuses that
# derivation; re-deriving the axis is what item 0 exists to prevent.
MATRIX = Path("docs/assurance-matrix.md")

# Roadmap stage 4 п.4: every production writer is one of these three.
DISPOSITIONS = ("step", "stutter", "out-of-scope")
#: Three writer axes and three GUARD axes. The token half was ledgered and the
#: other three clauses of `NoAuthorizationBypass` — the walk's owning channel,
#: the retry budget's soft lock and the reset window — were owned nowhere at all,
#: which is what made "the ledger covers the property" a sentence about one
#: quarter of it. Their sites are guards rather than writers, so they get their
#: own axes rather than a column: a guard writes no token field, and every rule
#: on the writer axes reads one.
AXES = (
    "volatile_writer",
    "persistent_writer",
    "outcome_producer",
    "walk_owner",
    "softlock_owner",
    "reset_window_owner",
)
RESET = FIDO / "reset.rs"
#: The three units the guard axes reach. The soft lock is marshalled across a
#: warm reset by the BOARD — `FidoState::pin_lock` has ZERO callers inside
#: `rsk-fido`, measured — so a family scanned with `catalogue()` alone derives an
#: empty roster and every rule below passes over it.
UNITS = (
    (FIDO, "lib.rs"),
    (Path("crates/rsk-device/src"), "lib.rs"),
    (Path("firmware/src"), "main.rs"),
)
#: A roster cannot derive to nothing without someone saying so. Set under the
#: measured counts so ordinary movement does not trip them and a derivation that
#: stopped reading does.
FLOORS = {
    # 7 and not 6: the roster grew to 11 when the whole-token clause learned to
    # read the state type off its `paut` field, and a floor left at the old
    # slack would let the new clause rot back out again unreported.
    "volatile_writer": 7,
    "persistent_writer": 8,
    "outcome_producer": 5,
    "walk_owner": 3,
    "softlock_owner": 8,
    # 1, not 2, and the difference is a measured direction failure: at 2 —
    # the derived count — renaming `in_reset_window` reported "the derivation
    # stopped reading the tree" and SUPPRESSED the two accurate `stale owner`
    # lines. A floor set AT the measurement turns a deleted guard into a report
    # about the guard's reader.
    "reset_window_owner": 1,
}

FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"fn\s+([a-zA-Z0-9_]+)"
)
# Comments and string literals are blanked before any match: `reset()` names
# EF_PIN in prose only, and a model constant commented `\* TRUE` has already cost
# this programme one green run over a dead assumption. Char literals go too —
# a lone `'{'` desynchronises the brace depth below, and every writer after it in
# the file is then swallowed into the previous function's body, silently.
NOT_CODE = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)'|//[^\n]*|/\*.*?\*/", re.S)
ASSIGN = r"(?:[-+&|^*/%]|<<|>>)?=[^=]"
IN_PLACE = r"(?:copy_from_slice|clone_from_slice|fill|swap|iter_mut|as_mut|get_mut)"
# A receiver is any expression, not one identifier: `Fs::put(&mut ctx.fs, EF_PIN)`
# and `Fs::delete(c.fs, EF_PIN)` are the same write as `fs.put(EF_PIN, ..)`.
RECEIVER = r"(?:[^,;()]|\([^()]*\))*?,\s*"
#: One call's argument list, one level of nesting allowed. A non-greedy `.*?\)`
#: stops at the FIRST close paren, so `put_sealed32(dev.without_otp(), fs, fid, ..)`
#: hides every argument after the inner call — the fid among them.
ARGUMENTS = r"((?:[^()]|\([^()]*\))*)\)"
PUBLIC = re.compile(r"\s*pub(?:\([^)]*\))?\s")
COLUMN_ROW = re.compile(r"^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|")
WHOLE = re.compile(r"\*self\s*=[^=]")
#: `Self` means the token's owner only in the file that declares it, so the same
#: write one crate over has to name the TYPE — and that name is derived, off the
#: struct carrying `pub paut`, never spelled here.
WHOLE_TYPED = r"\*\s*[\w.]*\w\s*=\s*(?:\w+\s*::\s*)*{state}\b"
#: The swap primitives, which replace the token with no `=` on the left of it.
SWAP = r"\b(?:replace|swap)\s*\([^;]*?\b{state}\s*::\s*\w+\s*\("
#: Any whole-value write through a dereference. Meaningless on its own — it is
#: paired with `state_holders`, which decides whether the name is the token's.
DEREF = re.compile(r"\*\s*([a-z_]\w*)\s*=[^=]")
#: The session MAC, anchored on the token FIELD instead of on a method name: the
#: one place a `paut` field leaves `state.rs` as a call argument IS the
#: `pinUvAuthParam` check, so the method (`verify_token`) and the primitive it
#: bottoms out in (`pinproto::verify`) both fall out of one anchor. That deleted
#: the last two hand-lists in this file — the second was a `(file, function,
#: callee)` triple naming the persistent `pcmr` grant, which touches no `paut` at
#: all and which the primitive now finds by what it MACs over. Measured: 5
#: production callers of the primitive, 1 of them over a token record.
MAC_ANCHOR = r"((?:\w+\s*::\s*)+\w+)\s*\(\s*[^,()]*,\s*&\s*self\.paut\.(?:{fields})\b"
LET = re.compile(r"\blet\b")
#: Rust's literal suffixes, so `0x1000u16 + 0x80` reaches an integer folder as
#: `0x1000 + 0x80`. Underscores survive — Python's own literals take them.
SUFFIX = re.compile(r"\b(0[xXbBoO][0-9A-Fa-f_]+|\d[\d_]*)(?:u|i)(?:8|16|32|64|128|size)\b")
#: Arithmetic and nothing else. A `Name` node is what makes `EF_RP + i` fold to
#: nothing, and that is the whole reason this costs no false owner: a fid built
#: out of a runtime value is not a constant fid.
FOLDABLE = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Constant,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.LShift,
    ast.RShift,
    ast.BitOr,
    ast.BitAnd,
    ast.BitXor,
    ast.USub,
    ast.UAdd,
)


def functions(text: str) -> list[tuple[str, str]]:
    """(name, code) per `fn`, bodies closed by brace depth.

    Depth rather than "up to the next `fn`": the old line-run form attributed a
    `const fn`'s body to whatever plain `fn` preceded it, and `state.rs` has five.
    """
    lines = NOT_CODE.sub(lambda m: " " * (m.group(0).count("\n")), text).splitlines()
    found, index = [], 0
    while index < len(lines):
        head = FN.match(lines[index])
        if head is None:
            index += 1
            continue
        depth, started, cursor, body = 0, False, index, []
        while cursor < len(lines):
            body.append(lines[cursor])
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            started = started or "{" in lines[cursor]
            if started and depth <= 0:
                break
            cursor += 1
        found.append((head.group(1), "\n".join(body)))
        index = cursor + 1
    return found


def bindings(body: str) -> list[tuple[int, list[str], str, str]]:
    """(offset, names bound, type annotation, right-hand side) per `let`.

    Bracket-aware rather than `[^;]*`, in both halves: `let mut a: [u8; 32] = ..`
    carries a semicolon in the type and `let Some(t) = f() else { return; };` one
    in the block, and a regex stopping at the first `;` reads the first as having
    no initialiser at all and the second as ending before its own `=`.

    The OFFSET is what lets a reader ask which binding governs a given use, and
    the annotation is how a name declares the token's owner without an rhs that
    spells it (`let st: FidoState = ...`).
    """
    found = []
    for start in LET.finditer(body):
        depth, cursor, split = 0, start.end(), None
        while cursor < len(body):
            char = body[cursor]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif depth <= 0 and char == ";":
                break
            elif depth <= 0 and char == "=" and body[cursor + 1 : cursor + 2] not in ("=", ">"):
                split = cursor if split is None else split
            cursor += 1
        if split is None:
            continue
        head = body[start.end() : split].split(":", 1)
        names = [w for w in re.findall(r"\b[a-z_]\w*\b", head[0]) if w != "mut"]
        found.append((start.start(), names, head[1] if len(head) > 1 else "", body[split + 1 : cursor]))
    return found


def bound_locals(body: str, carries, before: int | None = None) -> set[str]:
    """Every local transitively bound from a declaration `carries(annotation, rhs)` accepts.

    Transitive because `let a = EF_PIN; let b = a;` puts the fid two hops from
    the write, and a one-hop rule is a rule about how the author spaced it.

    LAST BINDING BEFORE THE USE wins, and both halves of that matter. Without
    "last", `let f = EF_PIN; let f = EF_RP; fs.put(f, ..)` is a false owner —
    the gate would demand a disposition for a write of the RP record. Without
    "before the use", the repair overshoots the other way and
    `let f = EF_PIN; fs.put(f, ..); let f = EF_RP;` stops being found at all,
    which is the same rule losing a real writer to make a cosmetic one go away.
    """
    latest: dict[str, tuple[str, str]] = {}
    for at, names, annotation, rhs in bindings(body):
        if before is not None and at >= before:
            continue
        for name in names:
            latest[name] = (annotation, rhs)
    keyed: set[str] = set()
    while True:
        # The two halves stay APART all the way down: `carries` folds the rhs as
        # an expression, and `" = " + rhs` is not one — prefixing the annotation
        # cost the arithmetic clause its only case, silently, until the table said so.
        grown = {
            name
            for name, (annotation, rhs) in latest.items()
            if name not in keyed
            and (
                carries(annotation, rhs)
                or any(w in keyed for w in re.findall(r"\b[a-z_]\w*\b", rhs))
            )
        }
        if not grown:
            return keyed
        keyed |= grown


def folds_to(expression: str, values: set[int]) -> bool:
    """Whether a Rust integer expression evaluates to one of `values`.

    Folded and not matched, because `0x1000u16 + 0x80` IS `EF_PIN` and spells
    neither of its two discoverable names. Only literals and arithmetic: a shift
    is bounded because two short literals can otherwise ask for a number no
    machine finishes, and anything carrying a Name folds to nothing at all.
    """
    try:
        tree = ast.parse(SUFFIX.sub(r"\1", expression).strip(), mode="eval")
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, FOLDABLE):
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.LShift, ast.RShift)):
            if not isinstance(node.right, ast.Constant) or not 0 <= node.right.value <= 64:
                return False
        if isinstance(node, ast.Constant) and (
            not isinstance(node.value, int) or abs(node.value) > 0xFFFF_FFFF
        ):
            return False
    return eval(compile(tree, "<fid>", "eval"), {"__builtins__": {}}) in values  # noqa: S307


def parameters(body: str) -> dict[str, str]:
    """{name: declared type} out of a function's OWN signature parens.

    Bounded to the signature, so a mask on a local is not read as a mask on
    something a caller could hand in — that distinction is the whole precision of
    the permission clause below. The TYPE is carried because a parameter is how
    the token's owner arrives at the board half: `fido_state: &RefCell<FidoState>`
    is what makes `*st = ..` a whole-token write two `let`s later.
    """
    start = body.find("(")
    if start < 0:
        return {}
    depth, cursor = 0, start
    while cursor < len(body):
        if body[cursor] == "(":
            depth += 1
        elif body[cursor] == ")":
            depth -= 1
            if depth == 0:
                break
        cursor += 1
    signature, declared, depth, last = body[start + 1 : cursor], {}, 0, 0
    for index, char in enumerate(signature + ","):
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= 1
        elif char == "," and depth <= 0:
            name, _, kind = signature[last:index].partition(":")
            name = name.strip().removeprefix("mut ").strip()
            if re.fullmatch(r"[a-z_]\w*", name):
                declared[name] = kind
            last = index + 1
    return declared


#: A `const` item is a fid spelling no `let` reader can see: it lives outside every
#: `fn`, so `bindings()` walks straight past `const ALIAS: u16 = 0x1080;` and the
#: `fs.put(ALIAS, ..)` under it is discovered by nothing. Folded to the VALUE, so
#: `rsk-piv`'s own `EF_PIN = 0xD180` is not one of these by name.
CONST_ITEM = re.compile(r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:[^=;]*=\s*([^;]*);")


def key_aliases(root: Path, values: set[int]) -> set[str]:
    """Every scanned `const` whose value IS a token fid, under whatever name."""
    found = set()
    for path in scanned_sources(root):
        text = NOT_CODE.sub(" ", path.read_text(encoding="utf-8"))
        found |= {
            name for name, rhs in CONST_ITEM.findall(text) if folds_to(rhs, values)
        }
    return found


def state_holders(body: str, state: str, before: int | None = None) -> set[str]:
    """The names in this body whose TYPE is the token's owner.

    Parameters first, then transitively through `let`, which is the chain the
    board half actually writes: `fido_state: &RefCell<FidoState>` →
    `let mut st = fido_state.borrow_mut()` → `*st = ..`. Derived this way the
    clause stops caring what the RIGHT-hand side spells, so `*st = Default::default()`
    is the same finding as `*st = FidoState::new()` — and the first names no type
    at all, which is why a right-hand-side rule cannot see it.
    """
    if not state:
        return set()
    named = re.compile(rf"\b{state}\b")
    holders = {name for name, kind in parameters(body).items() if named.search(kind)}

    def carries(annotation: str, rhs: str) -> bool:
        return any(
            named.search(text) or any(w in holders for w in re.findall(r"\b[a-z_]\w*\b", text))
            for text in (annotation, rhs)
        )

    while True:
        grown = bound_locals(body, carries, before) - holders
        if not grown:
            return holders
        holders |= grown


def scanned_sources(root: Path) -> list[Path]:
    """Every production `.rs` of the units the axes are derived over.

    ONE exclusion set for the writer axes and the guard axes, because there were
    two and they differed. And `UNITS`, not `rsk-fido` alone: measured 2026-08-31,
    `rsk-device`'s `AppletHandler::new` replaces the whole session token at
    power-up and was owned by nobody, because the writer axes could not see the
    crate at all — the guard axes had scanned it since the day they were written.
    """
    return sorted(
        path
        for unit, _ in UNITS
        for path in (root / unit).rglob("*.rs")
        if not path.name.endswith(("_tests.rs", "_kani.rs"))
        and path.name not in {"generated_token_edges.rs", "state_assurance.rs"}
    )


def test_only_sources(root: Path) -> set[str]:
    """The scanned files no build but a test one compiles.

    Walked with `bcd_gate`'s module-graph reader rather than a second one, and it
    is the walk that matters: `conformance/` is nineteen files declared by one
    `#[cfg(test)] mod conformance;`, and a name pattern calls every one of them
    production.
    """
    known = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for unit, _ in UNITS
        for path in (root / unit).rglob("*.rs")
    }
    seen, gated = set(), set()
    queue = [
        (rel, False)
        for unit, entry in UNITS
        if (rel := (unit / entry).as_posix()) in known
    ]
    while queue:
        rel, is_gated = queue.pop()
        if (rel, is_gated) in seen:
            continue
        seen.add((rel, is_gated))
        if is_gated:
            gated.add(rel)
        for name, operand, own in bcd_gate.declarations(known[rel]):
            child = bcd_gate.resolve(rel, name, operand, known)
            if child:
                queue.append((child, is_gated or own))
    return gated - {rel for rel, is_gated in seen if not is_gated}


def token_fields(root: Path) -> list[str]:
    body = re.search(
        r"pub struct PinUvAuthToken \{(.*?)\n\}", (root / STATE).read_text(), re.S
    )
    return re.findall(r"pub (\w+): ", body.group(1))


def permissions(root: Path) -> list[str]:
    return re.findall(r"pub const (PERM_[A-Z0-9_]+)", (root / STATE).read_text())


def abstraction(root: Path) -> tuple[list[str], list[str]]:
    """(token fields, permissions) the α of `abstract_token` actually observes."""
    text = (root / PROJECTION).read_text()
    return (
        sorted(set(re.findall(r"self\.paut\.(\w+)", text))),
        sorted(set(re.findall(r"PERM_[A-Z0-9_]+", text))),
    )


def key_names(root: Path) -> set[str]:
    match = re.search(
        r"TOKEN_PERSISTENT_FIDS[^=]*=\s*\[(.*?)\];",
        (root / PROJECTION).read_text(encoding="utf-8"),
        re.S,
    )
    if not match:
        return set()
    return set(re.findall(r"EF_[A-Z0-9_]+", match.group(1)))


def key_spellings(root: Path, keys: set[str]) -> set[str]:
    """Each token record's name AND the literal it is defined as.

    `fs.delete(0x1080)` writes clientPIN's verifier as surely as
    `fs.delete(EF_PIN)` does, and the constant is what makes the number
    findable — reading it here is the difference between a rule and a habit.
    """
    consts = (root / CONSTS).read_text(encoding="utf-8")
    out = set(keys)
    for key in keys:
        found = re.search(rf"\b{key}\s*:[^=]*=\s*(?:\w+::new\()?\s*(0[xX][0-9A-Fa-f]+)", consts)
        if found:
            out.add(found.group(1))
    return out


def store_writers(root: Path) -> set[str]:
    """The `Fs` methods that reach `storage.write`/`remove`/`compact`.

    Derived to a fixed point over the private helpers, because the hand-written
    four missed `delete_key`, `force_delete_halves`, `factory_wipe`, `compact`
    and all three `meta_*` — seven ways to write a token record unseen.
    """
    text = (root / STORE).read_text()
    bodies = dict(functions(text))
    writers = {
        name
        for name, body in bodies.items()
        if re.search(r"self\.storage\.(?:write|remove|compact)\s*\(", body)
    }
    while True:
        grown = {
            name
            for name, body in bodies.items()
            if name not in writers
            and any(re.search(rf"self\.{callee}\s*\(", body) for callee in writers)
        }
        if not grown:
            # The public half through `FN`, not a second `pub fn` pattern: this
            # gate exists because a set was spelled twice, and `pub(crate) fn`
            # appears 149 times in this tree.
            public = {name for name, body in functions(text) if PUBLIC.match(body)}
            return writers & public
        writers |= grown


def catalogue(root: Path) -> dict[tuple[str, str], str]:
    found = {}
    for path in scanned_sources(root):
        rel = str(path.relative_to(root))
        for name, body in functions(path.read_text(encoding="utf-8")):
            found[(rel, name)] = body
    return found


def state_owner(root: Path) -> tuple[str, str | None]:
    """The struct that owns the session token, read off its `pub paut` field.

    A FINDING and not a traceback if the anchor moves, for `lock_vocabulary`'s
    reason and one more of its own: an empty type name turns `WHOLE_TYPED` into
    `\\*\\s*[\\w.]*\\w\\s*=`, which owns every dereferencing assignment in three
    crates — a derivation that stopped reading would report the tree as unowned
    rather than as unscanned.
    """
    text = (root / STATE).read_text(encoding="utf-8")
    for found in re.finditer(r"pub struct (\w+) \{(.*?)\n\}", text, re.S):
        if re.search(r"\n\s*pub paut\s*:", found.group(2)):
            return found.group(1), None
    return "", f"state: {STATE} declares no struct with a `pub paut` field — the whole-token write is derived from it"


def mac_vocabulary(root: Path, fields: list[str]) -> tuple[str, str, str | None]:
    """(the method that MACs the session token, the primitive it calls, a problem)."""
    anchor = re.compile(MAC_ANCHOR.format(fields="|".join(fields)))
    for name, body in functions((root / STATE).read_text(encoding="utf-8")):
        if found := anchor.search(body):
            return name, re.sub(r"\s+", "", found.group(1)), None
    return "", "", f"outcome: {STATE} hands no `paut` field to a MAC — the token check and its primitive are both read off that call"


def self_owners(root: Path, state: str) -> set[str]:
    """The scanned files where `Self` MEANS the token's owner.

    `*self = Self::new()` is only a token write inside an `impl` of that type, and
    the type is derived — so a second `impl FidoState` in a new file is covered
    without an edit here, while `*self = Self::new()` in any other impl stays
    what it is: a write of something else entirely.
    """
    if not state:
        return set()
    impl = re.compile(rf"\bimpl\b[^\n{{]*\b{state}\b")
    return {
        str(path.relative_to(root))
        for path in scanned_sources(root)
        if impl.search(path.read_text(encoding="utf-8"))
    }


def discovered_volatile(
    code: dict, fields: list[str], seen: list[str], owners: set[str], state: str
) -> tuple[set, set]:
    """(every writer of a token field, the subset α observes)."""
    every = re.compile(
        rf"\.paut(?:\.(?:{'|'.join(fields)}))?\s*{ASSIGN}"
        rf"|\.paut\.(?:{'|'.join(fields)})\.{IN_PLACE}\s*\("
        # `&mut …paut` covers `mem::take`/`replace`/`swap` too: mutating a field
        # through them needs the borrow, so a second alternative was dead.
        rf"|&mut\s+[\w.]*\bpaut\b"
    )
    visible = re.compile(rf"\.paut\.(?:{'|'.join(seen)})\s*{ASSIGN}")
    # `FidoState::reset` is `*self = Self::new()`, which replaces the token
    # wholesale — every abstract bit at once, and not one `.paut.` in sight.
    # `Self` only means the token's owner in the file that declares it; one crate
    # over the same write names the TYPE, and `crates/rsk-device/src/ctap.rs:122`
    # is that write at every power-up.
    typed = re.compile(WHOLE_TYPED.format(state=state)) if state else None
    # `mem::replace(st, FidoState::new())` moves the same bits with no `=` in
    # sight. Scoped to the swap primitives naming the type, NOT to the type
    # anywhere: `RefCell::new(FidoState::new())` at `firmware/src/main.rs:1310`
    # BUILDS the one session cell at boot and replaces nothing, and a rule reading
    # `FidoState::new` alone owns it. Measured: this alternative adds 0 sites.
    swapped = re.compile(SWAP.format(state=state)) if state else None

    def replaces_the_whole_token(site: tuple[str, str], body: str) -> bool:
        if site[0] in owners and WHOLE.search(body):
            return True
        if typed and typed.search(body):
            return True
        if swapped and swapped.search(body):
            return True
        # `*st = Default::default()` names no type at all, so nothing above can
        # see it. Answered from the LEFT-hand side instead: `st` is derived to be
        # the token's owner through its parameter type, and then what is assigned
        # into it does not matter.
        return any(
            found.group(1) in state_holders(body, state, found.start())
            for found in DEREF.finditer(body)
        )

    whole = {site for site, body in code.items() if replaces_the_whole_token(site, body)}
    writers = {site for site, body in code.items() if every.search(body)} | whole
    return writers, {site for site in writers if visible.search(code[site])} | whole


def record_vocabulary(code: dict, keys: set[str]) -> tuple[re.Pattern, set[int], set[str]]:
    """(names a token record, the fids as NUMBERS, the functions that read one).

    One derivation for three clauses that each needed it: the persistent axis's
    own `naming`, the fid folder, and the grant clause below — which asks what a
    MAC was taken OVER and answers it with the same "this expression reaches a
    token record" test.
    """
    alternation = "|".join(sorted(keys, key=len, reverse=True))
    mentions = re.compile(rf"\b(?:{alternation})\b")
    values = {int(key, 16) for key in keys if key.lower().startswith("0x")}
    return mentions, values, {site[1] for site, body in code.items() if mentions.search(body)}


def discovered_outcomes(
    code: dict,
    perms: list[str],
    seen: list[str],
    vocabulary: tuple[re.Pattern, set[int], set[str]],
    method: str,
    primitive: str,
) -> tuple[set, set]:
    """(every authorization producer, the subset α observes).

    Independent queries, unioned: the token-MAC check every command gate calls,
    and a mask of `paut.permissions` against any `PERM_*`. They name the same six
    sites, which is the evidence that neither spelling is the only door — and a
    seventh that checked the MAC and forgot the mask would be a bypass the mask
    query alone could not see.

    Two more were added after a 2026-08-31 probe measured them MISSED, and both
    ask the same question one hop out: the mask may be on a local bound from the
    live byte (`let p = paut.permissions; p & PERM_MC`), or on a PARAMETER of a
    helper a caller hands the live byte to. Requiring the hand-off is what makes
    the second precise — the coarse "hands `paut.permissions` to anything" cost a
    false owner, and this costs none, measured, while still owning the pair.
    """
    mentions, _, readers = vocabulary
    joined = "|".join(perms)
    live = re.compile(r"\.paut\.permissions\b")
    masks = rf"\.paut\.permissions\s*[&|^]\s*\(?\s*(?:{joined})"
    clauses = [masks, rf"(?:{joined})\s*[&|^]\s*[\w.]*\.paut\.permissions"]
    if method:
        clauses.append(rf"(?:\.|::){method}\s*\(")
    every = re.compile("|".join(clauses))
    visible = re.compile(rf"\.paut\.permissions\s*[&|^]\s*\(?\s*(?:{'|'.join(seen)})")
    masked = re.compile(
        rf"\b([a-z_]\w*)\s*[&|^]\s*\(?\s*(?:{joined})\b|\b(?:{joined})\s*[&|^]\s*\(?\s*([a-z_]\w*)\b"
    )
    #: The live byte masked against a NAME, which is the half of the pair the
    #: `masked` pattern above cannot express: there the constant is spelled and
    #: the byte is the variable, here it is the other way round.
    against = re.compile(
        r"\.paut\.permissions\s*[&|^]\s*\(?\s*([a-z_]\w*)\b"
        r"|\b([a-z_]\w*)\s*[&|^]\s*\(?\s*[\w.]*\.paut\.permissions\b"
    )

    def masks_one_of(body: str, names: set[str]) -> bool:
        return any((found[0] or found[1]) in names for found in masked.findall(body))

    producers = {site for site, body in code.items() if every.search(body)}
    producers |= {
        site
        for site, body in code.items()
        for found in masked.finditer(body)
        if (found.group(1) or found.group(2))
        in bound_locals(body, lambda _a, rhs: bool(live.search(rhs)), found.start())
    }
    # The MIRROR of the clause above, and the fifth spelling of the same cause:
    # the live byte can be in the local, or the PERMISSION can. Taught one and
    # left blind to the other, `let need = PERM_MC; paut.permissions & need`
    # slipped — a review found it, not this file.
    constant = re.compile(rf"\b(?:{joined})\b")
    producers |= {
        site
        for site, body in code.items()
        for found in against.finditer(body)
        if (found.group(1) or found.group(2))
        in bound_locals(body, lambda _a, rhs: bool(constant.search(rhs)), found.start())
    }
    gates = {site for site, body in code.items() if masks_one_of(body, parameters(body))}
    for gate in gates:
        calls = re.compile(rf"\b{gate[1]}\s*\(([\s\S]*?)\)")
        for caller, body in code.items():
            if caller != gate and any(live.search(f.group(1)) for f in calls.finditer(body)):
                producers |= {gate, caller}
    # The persistent `pcmr` grant: an authorization that never touches `paut`, so
    # no clause above can see it. Found by what the MAC is taken OVER — a local
    # bound from a token record, or from a function that reads one — which is why
    # 4 of the primitive's 5 production callers (they MAC under an ECDH secret)
    # are not here. It was a hand-named triple until this replaced it.
    grant = set()
    if primitive and readers:
        key = re.compile(rf"{re.escape(primitive)}\s*\(\s*[^,()]*,\s*&?\s*(?:mut\s+)?([a-z_]\w*)")

        def from_a_record(_annotation: str, rhs: str) -> bool:
            return bool(mentions.search(rhs)) or any(
                word in readers for word in re.findall(r"\b[a-z_]\w*\b", rhs)
            )

        for site, body in code.items():
            if any(
                found.group(1) in bound_locals(body, from_a_record, found.start())
                for found in key.finditer(body)
            ):
                grant.add(site)
    producers |= grant
    return producers, {site for site in producers if visible.search(code[site])} | grant


def fid_parameter_types(code: dict, generic: set, call: str) -> set[str]:
    """The TYPES a fid parameter is declared with, read off the sites that already
    write one they were handed: `put_sealed32(.., fid: KeyFid, ..)` gives `KeyFid`.

    DERIVED rather than named, so a second spelling arrives with its own sites
    instead of joining a hand-list here — the mistake this file's own header
    records for the two rosters it used to carry. Measured today: `KeyFid`, `u16`.

    The FIRST argument of the write and not [`discovered_persistent`]'s receiver
    form: that one lets the receiver swallow the fid and hand back the argument
    after it, which taught this `&[u8]` and made every payload parameter a fid.
    """
    first = re.compile(call + r"\s*([a-z_]\w*)\s*[,).]")
    kinds = set()
    for site in generic:
        declared = parameters(code[site])
        for found in first.finditer(code[site]):
            kind = declared.get(found.group(1))
            if kind:
                kinds.add(kind.strip())
    return kinds


def discovered_persistent(
    code: dict,
    writers: set[str],
    keys: set[str],
    vocabulary: tuple[re.Pattern, set[int], set[str]],
) -> tuple[set, set]:
    """(every writer of a token record, the fid-parameter helpers among them).

    Four clauses, because a token record is written four ways: the fid is named
    here, the fid arrives as a parameter, the fid is named here and handed to
    something whose parameter it becomes, or the fid sits in a LOCAL. The third
    covers `reset::sweep`, whose fid arrives as a *predicate* —
    `sweep(ctx, is_fido_gate_fid)`.

    The fourth was measured MISSED on 2026-08-31, in two spellings: `let fid =
    EF_PIN; fs.put(fid, ..)` and `let f = 0x1000u16 + 0x80; fs.put(f, ..)`, the
    second of which spells no discoverable name at all. Resolved against the
    binding rather than guessed from the mention — "names a token fid and calls
    any writer" costs 5 false owners on this tree and this costs 0.

    The second clause reaches THROUGH a fid-parameter helper as far as the chain
    goes ([`fid_parameter_types`]), which is what the hop count above cost when
    it was one: `migrate_keydev_boot` names EF_PAUTHTOKEN and hands it to
    `migrate_slot`, which hands it to `put_sealed32`, and only that last hop is a
    receiver call. Measured 2026-09-16, when the boot re-seal of the grant record
    became a production write no clause here could see.
    """
    call = rf"(?:\.|::)(?:{'|'.join(sorted(writers, key=len, reverse=True))})\s*\("
    alternation = "|".join(sorted(keys, key=len, reverse=True))
    named = re.compile(rf"{call}\s*(?:{RECEIVER})?(?:[a-z_]+::)*(?:{alternation})\b")
    parameterised = re.compile(rf"{call}\s*(?:{RECEIVER})?[a-z_]\w*\s*[,).]")
    localised = re.compile(rf"{call}\s*(?:{RECEIVER})?([a-z_]\w*)\s*[,).]")
    mentions, values, naming = vocabulary

    generic = {site for site, body in code.items() if parameterised.search(body)}
    kinds = fid_parameter_types(code, generic, call)

    def hands_its_fid(body: str, targets: set) -> set:
        """Which of `targets` this body reaches with a fid of its OWN — the hop a
        receiver call cannot make, and the only one that carries the record."""
        own = {name for name, kind in parameters(body).items() if kind.strip() in kinds}
        if not own:
            return set()
        return {
            target
            for target in targets
            if any(
                own & set(re.findall(r"\b([a-z_]\w*)\b", found.group(1)))
                for found in re.finditer(rf"\b{re.escape(target[1])}\s*\({ARGUMENTS}", body)
            )
        }

    grew = True
    while grew:
        grew = False
        for site, body in code.items():
            if site not in generic and hands_its_fid(body, generic):
                generic.add(site)
                grew = True
    handed_down = {site: hands_its_fid(code[site], generic) for site in generic}

    def carries_a_key(arguments: str) -> bool:
        return bool(mentions.search(arguments)) or any(
            word in naming for word in re.findall(r"\b([a-z_]\w*)\b", arguments)
        )

    def is_a_fid(_annotation: str, rhs: str) -> bool:
        return bool(mentions.search(rhs)) or folds_to(rhs, values)

    reached, handing = set(), set()
    for site in generic:
        calls = re.compile(rf"\b{site[1]}\s*\({ARGUMENTS}")
        for caller, body in code.items():
            if caller == site:
                continue
            for found in calls.finditer(body):
                if carries_a_key(found.group(1)):
                    reached.add(site)
                    handing.add(caller)
    # A named key that reached a helper reaches every helper THAT one hands it to,
    # or a chain owns its top and its bottom and nothing in between.
    frontier = list(reached)
    while frontier:
        for target in handed_down.get(frontier.pop(), ()):
            if target not in reached:
                reached.add(target)
                frontier.append(target)
    direct = {site for site, body in code.items() if named.search(body)}
    local = {
        site
        for site, body in code.items()
        for found in localised.finditer(body)
        if found.group(1) in bound_locals(body, is_a_fid, found.start())
    }
    return direct | local | reached | handing, reached


#: The channel test IS the walk guard: a `CredMgmtState` method that compares the
#: cursor's owner with the request's. Derived rather than named, so a third walk
#: arriving with the same shape arrives as an unowned site.
CHANNEL_TEST = re.compile(r"self\.channel\s*==\s*channel")
#: §6.6's window is the only predicate in `reset.rs` that reads both halves of the
#: power-up: the boot's own origin and the deadline.
WINDOW = ("warm_boot", "RESET_WINDOW_MS")
#: The soft lock's accessor, and the anchor both halves of its vocabulary come
#: out of: its RETURN TYPE is the wire form the board carries across a reset, and
#: its BODY names the two `FidoState` fields the lock is made of.
LOCK_ACCESSOR = "pin_lock"
#: Anchored to the `fn` line: searching the whole body picks a `->` inside a
#: nested closure as the wire type.
RETURNS = re.compile(r"^[^\n{]*->\s*(\w+)")


def walk_guards(root: Path) -> list[str]:
    """Every `state.rs` method that IS the channel test.

    Not scoped to `CredMgmtState` — nothing here parses impl blocks — and the
    scan is the wider one on purpose: a second type growing the same guard is a
    site this axis should own, not one it should miss.
    """
    return sorted(
        name
        for name, body in functions((root / STATE).read_text(encoding="utf-8"))
        if CHANNEL_TEST.search(body)
    )


def window_guards(root: Path) -> list[str]:
    """The `reset.rs` predicate keyed on the power-up."""
    return sorted(
        name
        for name, body in functions((root / RESET).read_text(encoding="utf-8"))
        if all(word in body for word in WINDOW)
    )


def lock_vocabulary(root: Path):
    """(the lock's wire type, its fields, the methods that move it, a problem).

    All three out of `FidoState::pin_lock`: naming the type here as well would be
    the second spelling this whole file exists to delete. Both ways the anchor can
    move — the accessor renamed, its return type no longer a bare name — are a
    FINDING, because a traceback here aborts every one of the six axes before any
    of them is compared.
    """
    bodies = dict(functions((root / STATE).read_text(encoding="utf-8")))
    if LOCK_ACCESSOR not in bodies:
        return "", [], [], f"softlock: {STATE} defines no `{LOCK_ACCESSOR}` — the whole family hangs off it"
    accessor = bodies[LOCK_ACCESSOR]
    found = RETURNS.search(accessor)
    if not found:
        return "", [], [], f"softlock: `{LOCK_ACCESSOR}` returns no bare type — the wire form is read off its signature"
    kind = found.group(1)
    fields = sorted(set(re.findall(r"self\.(\w+)", accessor)))
    methods = sorted(n for n, b in bodies.items() if re.search(rf"\b{kind}\b", b))
    return kind, fields, methods, None


def guard_sites(root: Path, guards: list[str], kind: str | None) -> set[tuple[str, str]]:
    """The guards themselves and every production function that calls one.

    Scanned over `UNITS` rather than `crates/rsk-fido` alone, and the reason is
    the measurement: `pin_lock` / `restore_pin_lock` have no caller inside the
    applet at all. `kind`, where a family has one, also catches a board half that
    only ever names the wire TYPE — `Hooks::store_pin_lock` calls neither guard.
    """
    # An EMPTY vocabulary must derive NOTHING, and `\b(?:)\s*[(<]` derives
    # everything — it matches any open paren, so a family whose derivation
    # stopped reading would own the whole tree and its floor would never trip.
    # Measured on this file's own fixture, which is where the floor arms found it.
    call = re.compile(r"\b(?:" + "|".join(guards) + r")\s*[(<]") if guards else None
    named = re.compile(rf"\b{kind}\b") if kind else None
    found: set[tuple[str, str]] = set()
    # `scanned_sources`, so the guard scan and the writer scan agree about what
    # production is out of ONE definition. They had two and they differed: this
    # one read `state_assurance.rs` and `generated_token_edges.rs`, which the
    # writer axes deliberately do not.
    for path in scanned_sources(root):
        rel = str(path.relative_to(root))
        for name, body in functions(path.read_text(encoding="utf-8")):
            if name in guards or (call and call.search(body)) or (named and named.search(body)):
                found.add((rel, name))
    return found


def foreign_writers(root: Path, writers: set[str], keys: set[str]) -> list[str]:
    """Token-record writes outside the SCANNED units, which the axes assume away.

    Scoped by the import rather than by the name: `rsk-piv` defines its own
    `EF_PIN` (0xD180 against FIDO's 0x1080), so a name-only sweep of the tree
    reports three PIV sites that write a different record entirely.

    `UNITS` and not `FIDO` alone since 2026-08-31: `rsk-device` and `firmware`
    are on the persistent axis proper now, and a site reported by both rules
    reads as two sites — one message per write, or the roster is a count of
    spellings.
    """
    call = rf"(?:\.|::)(?:{'|'.join(sorted(writers, key=len, reverse=True))})\s*\("
    alternation = "|".join(sorted(keys, key=len, reverse=True))
    named = re.compile(rf"{call}\s*(?:{RECEIVER})?(?:[a-z_]+::)*(?:{alternation})\b")
    # The module, not the two names: `use rsk_fido::consts;` then `consts::EF_PIN`
    # reaches the same record, and a glob import names neither.
    imports = re.compile(r"rsk_fido::consts\b")
    findings = []
    # `tools/` is in the bases, and that is a DECISION rather than a default: the
    # emulator holds a live `FidoState` and is the phase-4 recording apparatus —
    # every trace-linked claim in the programme rests on it — so a token write in
    # there is exactly the write nobody would see. It matched 0 files' writes when
    # it was added; leaving it out silently is what let `rsk-device` hide.
    # `rsk-mgmt`/`rsk-oath`/`rsk-openpgp` are reached by the same walk and match
    # nothing, because the scope is the IMPORT and they do not take it.
    for base in (root / "crates", root / "firmware", root / "tools"):
        for path in sorted(base.rglob("*.rs")):
            rel = path.relative_to(root)
            if any(rel.is_relative_to(unit) for unit, _ in UNITS) or path.name.endswith(
                ("_tests.rs", "_kani.rs")
            ):
                continue
            text = path.read_text(encoding="utf-8")
            if not imports.search(text):
                continue
            for name, body in functions(text):
                if named.search(body):
                    findings.append(f"foreign: unowned concrete site {rel}::{name}")
    return findings


def matrix_columns(root: Path) -> set[str]:
    return {
        found.group(1)
        for line in (root / MATRIX).read_text(encoding="utf-8").splitlines()
        if (found := COLUMN_ROW.match(line))
    }


def owners(entries: list[dict]) -> set[tuple[str, str]]:
    return {(entry["file"], entry["function"]) for entry in entries}


def compare_axis(label: str, discovered: set, declared: set, findings: list[str]) -> None:
    for item in sorted(discovered - declared):
        findings.append(f"{label}: unowned concrete site {item[0]}::{item[1]}")
    for item in sorted(declared - discovered):
        findings.append(f"{label}: stale owner {item[0]}::{item[1]}")


def check_entry(
    label: str,
    entry: dict,
    ops: set[str],
    visible: bool,
    columns: set[str],
    test_only: bool,
    findings: list[str],
) -> None:
    site = f"{entry['file']}::{entry['function']}"
    disposition = entry.get("disposition", "step")
    if disposition not in DISPOSITIONS:
        findings.append(f"{label}: {site} carries disposition {disposition!r}")
        return
    if disposition == "step":
        if entry.get("op") not in ops:
            findings.append(f"{label}: {entry.get('op')} is outside the generated TLA+ Ops domain")
        if visible is False:
            findings.append(f"{label}: {site} is a step over state the abstraction cannot see")
    else:
        if "op" in entry:
            findings.append(f"{label}: {site} is {disposition} and still names an op")
        if not entry.get("why", "").strip():
            findings.append(f"{label}: {site} is {disposition} with no reason")
        if visible is True:
            findings.append(f"{label}: {site} writes abstract state and is not a step")
    if entry.get("test_only", False) is not test_only:
        state = "is" if test_only else "is not"
        findings.append(f"{label}: {site} {state} compiled only under cfg(test)")
    column = entry.get("column")
    if column is not None and column not in columns:
        findings.append(f"{label}: {site} names configuration {column!r}, which the matrix has no column for")
    if column is not None and not entry.get("why", "").strip():
        findings.append(f"{label}: {site} is configuration-conditional with no reason")


#: What a record of `assurance/token_refinement.toml` may say, and which tables the
#: file may have. Neither was held: an invented key in the first record left this
#: row at EXIT=0, measured, so a field added here was read by nothing and printed
#: by nothing.
#:
#: ONE union rather than a list per table, and that is a correction the suite made
#: rather than a preference. Per-table lists derived from the records that exist
#: today refuse `column` on a `[[volatile_writer]]` — no record carries one — while
#: the shared per-entry checker above accepts it from every table, so two
#: parametrized cases went red on a key the gate itself reads. An allowlist taken
#: from the DATA under-approximates the contract; this one is taken from the keys
#: the CODE reads.
ENTRY_FIELDS = (
    "column",
    "disposition",
    "file",
    "function",
    "generic",
    "op",
    "test_only",
    "why",
)
TABLES = (
    "volatile_writer",
    "persistent_writer",
    "outcome_producer",
    "walk_owner",
    "softlock_owner",
    "reset_window_owner",
)


def audit(root: Path, floors: dict[str, int] | None = None) -> tuple[list[str], str]:  # noqa: C901 — one clause per axis
    # A PARAMETER, because the fixture is one member per family and the shipped
    # numbers are calibrated on the checkout: a case that reassigns the module
    # global instead leaves it reassigned for whatever runs next in the process,
    # and the arms that falsify the REAL floors then falsify a stand-in.
    floors = FLOORS if floors is None else floors
    root = Path(root)
    data = tomllib.loads((root / MANIFEST).read_text(encoding="utf-8"))
    findings: list[str] = []
    if stray := sorted(set(data) - set(TABLES)):
        findings.append(
            f"{MANIFEST} carries {stray}, which nothing reads — a table added here"
            " is held by no rule and shown to no reader"
        )
    for table in TABLES:
        for entry in data.get(table, []):
            if extra := sorted(set(entry) - set(ENTRY_FIELDS)):
                findings.append(
                    f"{MANIFEST} [[{table}]] {entry.get('function', '?')}: carries"
                    f" {extra}, which nothing reads"
                )
    ops = {
        line.split("|", 2)[2]
        for line in (root / EXPORT).read_text(encoding="utf-8").splitlines()
        if line.startswith("TOKEN|OP|")
    }
    keys = key_names(root)
    if keys != {"EF_PIN", "EF_PAUTHTOKEN"}:
        findings.append(f"TokenPersistentView key derivation yielded {sorted(keys)!r}")

    code = catalogue(root)
    fields, perms = token_fields(root), permissions(root)
    seen_fields, seen_perms = abstraction(root)
    writers = store_writers(root)
    spellings = key_spellings(root, keys)
    spellings |= key_aliases(root, {int(k, 16) for k in spellings if k.lower().startswith("0x")})
    vocabulary = record_vocabulary(code, spellings)
    state, state_problem = state_owner(root)
    method, primitive, mac_problem = mac_vocabulary(root, fields)
    findings.extend(problem for problem in (state_problem, mac_problem) if problem)
    volatile, volatile_seen = discovered_volatile(
        code, fields, seen_fields, self_owners(root, state), state
    )
    outcomes, outcomes_seen = discovered_outcomes(
        code, perms, seen_perms, vocabulary, method, primitive
    )
    persistent, generic = discovered_persistent(code, writers, spellings, vocabulary)
    kind, lock_fields, lock_methods, lock_problem = lock_vocabulary(root)
    if lock_problem:
        findings.append(lock_problem)
    if lock_fields and lock_fields != ["needs_power_cycle", "new_pin_mismatches"]:
        findings.append(f"the soft lock's field derivation yielded {lock_fields!r}")
    found = {
        # `None` on all three guard axes: alpha reads `paut.in_use`,
        # `permissions` and `has_rp_id`, and a guard writes none of them. The
        # visibility rule has nothing to say here, and saying it anyway would
        # make every one of these a step over state the abstraction cannot see.
        "walk_owner": (guard_sites(root, walk_guards(root), None), None),
        "softlock_owner": (guard_sites(root, lock_methods, kind), None),
        "reset_window_owner": (guard_sites(root, window_guards(root), None), None),
        "volatile_writer": (volatile, volatile_seen),
        # `None`: presence is what alpha reads of these records, and no regex
        # here can tell a write that changes it from one that rewrites in place.
        # `Noop` in the Ops domain is how a persistent stutter is spelled instead.
        "persistent_writer": (persistent, None),
        "outcome_producer": (outcomes, outcomes_seen),
    }
    gated = test_only_sources(root)
    columns = matrix_columns(root)
    for axis in AXES:
        label = axis.removesuffix("_writer").removesuffix("_producer").removesuffix("_owner")
        entries = data.get(axis, [])
        if len(found[axis][0]) < floors[axis]:
            # Reported BESIDE the comparison, never instead of it. Skipping the
            # comparison made a deleted guard read as a broken reader — the same
            # failure one register over from a red run nobody read the reason for.
            findings.append(
                f"{label}: {len(found[axis][0])} site(s) derived, under the floor of"
                f" {floors[axis]} — the derivation stopped reading the tree, and every"
                " rule below passes over the empty set"
            )
        compare_axis(label, found[axis][0], owners(entries), findings)
        for entry in entries:
            site = (entry["file"], entry["function"])
            # A stale owner is already named once; judging its fields as well
            # would bury that one message under the consequences of it.
            if site not in found[axis][0]:
                continue
            check_entry(
                label,
                entry,
                ops,
                None if found[axis][1] is None else site in found[axis][1],
                columns,
                site[0] in gated,
                findings,
            )
            if axis == "persistent_writer" and entry.get("generic", False) != (site in generic):
                state = "does" if site in generic else "does not"
                findings.append(f"{label}: {site[0]}::{site[1]} {state} write a fid it was handed")
    findings.extend(foreign_writers(root, writers, spellings))

    scanned = {site[0] for site in volatile | persistent | outcomes}
    summary = (
        f"token-refinement-gate: GREEN keys={len(keys)} api={len(writers)} "
        f"volatile={len(volatile)}/{len(volatile_seen)} "
        f"persistent={len(persistent)}/{len(generic)} "
        f"outcomes={len(outcomes)}/{len(outcomes_seen)} "
        f"walk={len(found['walk_owner'][0])} "
        f"softlock={len(found['softlock_owner'][0])} "
        f"window={len(found['reset_window_owner'][0])} "
        f"testonly={len(scanned & gated)}"
    )
    return findings, summary


def main(floors: dict[str, int] | None = None) -> int:
    findings, summary = audit(ROOT, floors)
    if findings:
        print("token-refinement-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
