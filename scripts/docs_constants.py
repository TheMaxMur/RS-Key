#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert every constant copied out of the code still matches it — in the docs,
in the on-device tests, and in the published metadata statements.

A number written anywhere but its `const` is a copy, and copies rot silently: the
constant moves, the code keeps compiling, and the copy goes on asserting the old
value to whoever reads it. `architecture.md` spent the whole capacity-work era
telling readers `MAX_DYNAMIC_FILES` was 256 while the code had raised it to 1280 —
a fivefold error in the section that exists to reason about how full a key can
get. `docs/protocol.md` is worse than that, being the wire spec third-party tools
implement against: a file id that drifts there is a bug they inherit.

The other two sources joined after `MAX_LARGE_BLOB_SIZE` moved from a flat 2048 to
`rsk_fs::MAX_VALUE_BYTES` (2046) on 2026-08-04 and left **four** copies behind: the
interop allow-list, `tests/25_large_blobs.py`, and both metadata statements — which
are *published*, so that drift reached relying parties, not just CI. Each copy was
its own reviewer's job and each was missed, which is the argument for checking them
mechanically rather than remembering to.

- **docs** (`docs/**/*.md`): a value stated next to the name — ``FOO`` (`123`).
- **tests** (`tests/*.py`): a module-level `FOO = 123` naming a Rust constant.
  The literal an assertion actually uses, not prose about it.
- **metadata** (`metadata/*.json`): FIDO's camelCase keys, mapped to the constant
  each publishes by [`METADATA_CONSTANTS`].

`scripts/impact.py` covers the other direction (which *code* sites still assume a
constant's old meaning).

Deliberately syntactic, and deliberately narrow: it compares integer literals
against integer literals. It cannot tell whether the surrounding prose is *right*,
only that the number in it is still the number. Values with units (`1408 KB`,
`30 s`) are out of scope — the code holds bytes or milliseconds and converting here
would invent precision. One indirection *is* resolved (`const A = B;`), because an
alias is exactly where the large-blob value hid: the name in the docs and the
literal in the code were two hops apart, and a scanner that only reads literals had
nothing to say about it.
"""
import json
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
# `const NAME: usize = other::NAME2;` / `= NAME2 as u64;` — one constant standing
# for another. Resolved to a fixpoint below, so a name still reaches its literal
# through any chain of aliases. Arithmetic (`A + B`, `A - 1`) is deliberately not
# followed: evaluating code here would make this a second implementation of it.
RUST_ALIAS = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]{2,})\s*:\s*\w+\s*=\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]{2,})\s*(?:as\s+\w+\s*)?;",
    re.M,
)
# ``NAME`` immediately followed by the value: `(123`, `(`0x7b``, `= 123`, `is 123`.
DOC_VALUE = re.compile(
    r"`([A-Z][A-Z0-9_]{2,})`\**\s*(?:\(|=\s*|is\s+)`?(0x[0-9a-fA-F]+|[0-9][0-9_,]*)\b"
)
# A module-level `NAME = 2046` in a test — no indentation, so a local inside a
# function is not mistaken for the fixture the assertions read.
PY_CONST = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*=\s*(0x[0-9a-fA-F_]+|[0-9][0-9_]*)\s*(?:#.*)?$")
# `"maxSerializedLargeBlobArray": 2046` in a metadata statement.
JSON_VALUE = re.compile(r'"([A-Za-z][A-Za-z0-9]*)"\s*:\s*([0-9]+)\s*,?\s*$')

# The metadata statements publish device constants under FIDO's names, so the
# link back to the code has to be written down. Only entries whose Rust side is
# (or aliases) a plain literal can be checked; `maxMsgSize` and `maxPINLength`
# are computed expressions and fall out of the index by themselves.
METADATA_CONSTANTS = {
    "maxCredentialCountInList": "MAX_CREDENTIAL_COUNT_IN_LIST",
    "maxCredentialIdLength": "MAX_CRED_ID_LENGTH",
    "maxSerializedLargeBlobArray": "MAX_LARGE_BLOB_SIZE",
    "minPINLength": "MIN_PIN_LENGTH",
    "maxCredBlobLength": "MAX_CREDBLOB_LENGTH",
    "maxRPIDsForSetMinPINLength": "MAX_MIN_PIN_RPIDS",
    "remainingDiscoverableCredentials": "MAX_RESIDENT_CREDENTIALS",
    "maxMsgSize": "CTAP_MAX_MESSAGE",
    "maxPINLength": "MAX_PIN_LENGTH",
}

# Coverage is small because these sources rarely state a constant's value next to
# its name; the counts below are what the tree holds today, not placeholders. The
# floors sit at the current counts on purpose: dropping below one means the
# scanner stopped matching that source rather than found nothing to say, and a
# checker that silently matches nothing passes whatever it is shown (audit run-34
# #9). They are per source so a source going quiet cannot hide behind another's
# pairs. Raise one when you add coverage; lowering one is a decision.
MIN_PAIRS = {"docs": 5, "tests": 44, "metadata": 12}


def rust_constants():
    """name -> {values}. A name defined in two crates keeps both; a copy matching
    either is accepted, since the docs rarely say which crate."""
    index, aliases = {}, {}
    for src in sorted(ROOT.glob("crates/*/src/**/*.rs")) + sorted(ROOT.glob("firmware/src/**/*.rs")):
        # Test files hold their own copies of these values as fixtures, and a name
        # defined in two places accepts either — so a stale literal in a `_tests.rs`
        # goes on vouching for a doc after the real constant moved (audit run-37).
        if src.name.endswith("_tests.rs") or src.name in ("tests.rs", "kani.rs"):
            continue
        text = src.read_text()
        for name, raw in RUST_CONST.findall(text):
            raw = raw.replace("_", "")
            index.setdefault(name, set()).add(int(raw, 16) if raw.startswith("0x") else int(raw))
        for name, target in RUST_ALIAS.findall(text):
            aliases.setdefault(name, set()).add(target)

    # Follow the aliases until nothing new resolves. Bounded by the number of
    # unresolved names, so a cycle (`A = B; B = A;`) stops instead of spinning.
    for _ in range(len(aliases) + 1):
        grew = False
        for name, targets in aliases.items():
            for target in targets:
                for value in index.get(target, ()):
                    if value not in index.setdefault(name, set()):
                        index[name].add(value)
                        grew = True
        if not grew:
            break
    return {name: values for name, values in index.items() if values}


def scan_docs(index):
    """(path, line, name, raw, values) for every value the docs state."""
    for doc in sorted(ROOT.glob("docs/**/*.md")):
        for line_no, line in enumerate(doc.read_text().splitlines(), 1):
            for name, raw in DOC_VALUE.findall(line):
                yield from _pair(index, doc, line_no, name, raw)


def scan_tests(index):
    """The same, for the fixture constants the on-device suites assert against."""
    for src in sorted(ROOT.glob("tests/*.py")):
        for line_no, line in enumerate(src.read_text().splitlines(), 1):
            m = PY_CONST.match(line)
            if m:
                yield from _pair(index, src, line_no, m.group(1), m.group(2))


def scan_metadata(index):
    """The same, for the published FIDO metadata statements."""
    for src in sorted(ROOT.glob("metadata/*.json")):
        for line_no, line in enumerate(src.read_text().splitlines(), 1):
            m = JSON_VALUE.match(line.strip())
            if m and m.group(1) in METADATA_CONSTANTS:
                yield from _pair(index, src, line_no, METADATA_CONSTANTS[m.group(1)], m.group(2))


def _pair(index, path, line_no, name, raw):
    """One comparison, or nothing when the name is not a constant this repo
    defines as a literal."""
    if name not in index:
        return
    clean = raw.replace(",", "").replace("_", "")
    value = int(clean, 16) if clean.startswith("0x") else int(clean)
    yield path.relative_to(ROOT), line_no, name, raw, value, sorted(index[name])


def main():
    index = rust_constants()
    checked, wrong = {}, []
    for source, scan in (("docs", scan_docs), ("tests", scan_tests), ("metadata", scan_metadata)):
        checked[source] = 0
        for path, line_no, name, raw, value, actual in scan(index):
            checked[source] += 1
            if value not in actual:
                wrong.append((path, line_no, name, raw, actual))

    for path, line_no, name, raw, actual in wrong:
        shown = ", ".join(hex(v) if raw.startswith("0x") else str(v) for v in actual)
        print(f"FAIL: {path}:{line_no}: {name} copied as {raw}, code says {shown}", file=sys.stderr)
    if wrong:
        print(f"\n{len(wrong)} copied constant(s) no longer match the code. Fix the copy,\n"
              "or — if the copy is right and the code drifted — fix the code.",
              file=sys.stderr)
        return 1

    for source, floor in MIN_PAIRS.items():
        if checked[source] < floor:
            print(f"FAIL: only {checked[source]} constant(s) found in {source} (expected "
                  f">= {floor}).\nThe scanner has lost that source's shape; it is now passing "
                  "vacuously.", file=sys.stderr)
            return 1

    total = sum(checked.values())
    detail = ", ".join(f"{n} {s}" for s, n in checked.items())
    print(f"docs-constants: ok ({total} values checked against {len(index)} constants — {detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
