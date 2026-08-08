#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every constant the docs state a value for still has that value in code.

A number written into prose is a copy, and copies rot silently: the constant
moves, the code keeps compiling, every test keeps passing, and the docs go on
asserting the old value to whoever reads them. `architecture.md` spent the whole
capacity-work era telling readers `MAX_DYNAMIC_FILES` was 256 while the code had
raised it to 1280 — a fivefold error in the section that exists to reason about
how full a key can get. `docs/protocol.md` is worse than that, being the wire
spec third-party tools implement against: a file id that drifts there is a bug
they inherit.

`scripts/impact.py` covers the other direction (which *code* sites still assume a
constant's old meaning). Nothing was reading the docs.

Deliberately syntactic, and deliberately narrow. It only compares a value the
docs state right next to the constant's name — ``FOO`` (`123`) or ``FOO`` = 123 —
against integer literals the code assigns to that name. It cannot tell whether
the surrounding prose is *right*, only that the number in it is still the
number. Values with units (`1408 KB`, `30 s`) are out of scope: the code holds
bytes or milliseconds and converting here would invent precision.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# `const NAME: u16 = 0x1091;` and the newtype form `const NAME: KeyFid =
# KeyFid::new(0x1091);` — the latter is how every file id is declared.
RUST_CONST = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]{2,})\s*:\s*\w+\s*=\s*"
    r"(?:\w+::new\()?\s*(0x[0-9a-fA-F_]+|[0-9][0-9_]*)\s*\)?\s*;",
    re.M,
)
# ``NAME`` immediately followed by the value: `(123`, `(`0x7b``, `= 123`, `is 123`.
DOC_VALUE = re.compile(
    r"`([A-Z][A-Z0-9_]{2,})`\**\s*(?:\(|=\s*|is\s+)`?(0x[0-9a-fA-F]+|[0-9][0-9_,]*)\b"
)
# Coverage is small because the docs rarely state a constant's value next to its
# name — 5 pairs today, and that is the honest ceiling of this shape, not a
# placeholder. The floor sits at the current count on purpose: dropping below it
# means the scanner stopped matching the docs rather than found nothing to say,
# and a checker that silently matches nothing passes whatever it is shown
# (audit run-34 #9). Raise it when you add coverage; lowering it is a decision.
MIN_PAIRS = 5


def rust_constants():
    """name -> {values}. A name defined in two crates keeps both; a doc value
    matching either is accepted, since the docs rarely say which crate."""
    index = {}
    for src in sorted(ROOT.glob("crates/*/src/**/*.rs")) + sorted(ROOT.glob("firmware/src/**/*.rs")):
        # Test files hold their own copies of these values as fixtures, and a name
        # defined in two places accepts either — so a stale literal in a `_tests.rs`
        # goes on vouching for a doc after the real constant moved (audit run-37).
        if src.name.endswith("_tests.rs") or src.name in ("tests.rs", "kani.rs"):
            continue
        for name, raw in RUST_CONST.findall(src.read_text()):
            raw = raw.replace("_", "")
            index.setdefault(name, set()).add(int(raw, 16) if raw.startswith("0x") else int(raw))
    return index


def main():
    index = rust_constants()
    checked, wrong = 0, []
    for doc in sorted(ROOT.glob("docs/**/*.md")):
        for line_no, line in enumerate(doc.read_text().splitlines(), 1):
            for name, raw in DOC_VALUE.findall(line):
                if name not in index:
                    continue  # not a constant this repo defines
                clean = raw.replace(",", "").replace("_", "")
                value = int(clean, 16) if clean.startswith("0x") else int(clean)
                checked += 1
                if value not in index[name]:
                    wrong.append((doc.relative_to(ROOT), line_no, name, raw,
                                  sorted(index[name])))

    for doc, line_no, name, raw, actual in wrong:
        shown = ", ".join(hex(v) if raw.startswith("0x") else str(v) for v in actual)
        print(f"FAIL: {doc}:{line_no}: {name} documented as {raw}, code says {shown}",
              file=sys.stderr)
    if wrong:
        print(f"\n{len(wrong)} documented constant(s) no longer match the code. Fix the\n"
              "docs, or — if the docs are right and the code drifted — fix the code.",
              file=sys.stderr)
        return 1

    if checked < MIN_PAIRS:
        print(f"FAIL: only {checked} documented constants found (expected >= {MIN_PAIRS}).\n"
              "The scanner has lost the docs' shape; it is now passing vacuously.",
              file=sys.stderr)
        return 1

    print(f"docs-constants: ok ({checked} values checked against {len(index)} constants)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
