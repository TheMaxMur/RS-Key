#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the level 11C decision record's measurements to the tree.

`docs/verified-compilation.md` declines verified compilation for the RP2350, and
every reason it gives is a number about this tree: how much of the one
already-foreign kernel is assembly, how many of the FIDO gate functions are
generic over a trait, how many `[[boundary]]` rows a second FFI boundary would
join, how much of `scripts/check.sh` is Rust-shaped. A decision record whose
numbers nothing re-derives is a decision that was true the day it was typed —
which is the defect `scripts/docs_constants.py` is named after, one register out:
that row holds a doc's copy of a Rust `const`, and none of these is a `const`.

Deliberately the same shape as that row and NOT a generated region. A region
would make the page's argument unreadable in the diff — the numbers are inside
sentences that reason with them — and the reader of a decision record is a person
following an argument, not a table. So each rule is a pattern with a hole: the
tree says what the number is, the page has to say the same, and a sentence that
was REWORDED AWAY is a finding too, because a pattern that stops matching reports
the same way a wrong value does. That is the half `docs_constants.py` leaves
open — deleting a stated constant there is exit 0 — and it is the half that
matters here, since the cheapest way to make a stale decision record green is to
stop saying the thing that went stale.

Nothing here is hand-written except the sentence shapes. Every value is derived
on the run, so the page cannot be repaired by editing this file.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = pathlib.Path("docs/verified-compilation.md")

#: Below this the derivation found nothing and the page went unchecked — the
#: loop-over-an-empty-set shape audit run-34 #9 is about. It is the rule COUNT,
#: so it moves only when a rule is added or retired, deliberately, in the diff.
RULE_FLOOR = 10

#: A `fn` a reader would call a function of the crate, and the `<` that makes it
#: generic. Production files only, the way `assurance_gate.py` counts: a name
#: with `kani` or `tests` in it is a fixture, not the surface a port would carry.
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[a-z_][a-z_0-9]*", re.M)
GENERIC_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[a-z_][a-z_0-9]*<", re.M)
STORAGE_BOUND = re.compile(r"<S: Storage")

#: A `check.sh` row. Both spellings, because `run_tests` is a row like any other
#: and counting only `run` reported 101 where the file has 115.
ROW = re.compile(r"^\s*(run|run_tests)\s+\"([^\"]+)\"(.*)$", re.M)

#: The rows whose whole input is cargo metadata or `.rs` source, so a kernel in
#: another language is not a thing they can fail about. Named rather than matched
#: on a shape: each was read once and the reason is the row's own derivation, and
#: a pattern would quietly acquire the next row that merely looks like one.
BLIND_ROWS = (
    "cargo-audit (SCA)",
    "cargo-audit (tui SCA)",
    "cargo-audit (emu SCA)",
    "cargo-deny",
    "cargo-vet (supply-chain)",
    "crate roster",
    "crate graph",
    "kani roster",
    "kani shrink roster",
)


def lines(rel: str) -> int:
    return len((ROOT / rel).read_text(errors="replace").splitlines())


def fido_functions() -> tuple[int, int, int]:
    """(generic, total, `<S: Storage` sites) over rsk-fido's production files."""
    generic = total = bound = 0
    for src in sorted((ROOT / "crates/rsk-fido/src").glob("*.rs")):
        if "kani" in src.name or "tests" in src.name:
            continue
        text = src.read_text(errors="replace")
        generic += len(GENERIC_FN.findall(text))
        total += len(FN.findall(text))
        bound += len(STORAGE_BOUND.findall(text))
    return generic, total, bound


def boundaries() -> tuple[int, int]:
    """(every `[[boundary]]` row, the linker-symbol ones).

    Read off the registry's own `id =` lines rather than through a TOML parse: the
    kinds are a prefix of the id (`import:` / `unit:`) and the linker half is the
    one whose importing file is the firmware binary, which is what makes it a
    symbol's ADDRESS rather than a function a compiler could be verified about.
    """
    text = (ROOT / "assurance/toolchain.toml").read_text()
    ids = re.findall(r'^id = "((?:import|export|unit):[^"]+)"', text, re.M)
    linker = [i for i in ids if i.startswith("import:firmware/src/main.rs:")]
    return len(ids), len(linker)


def roster() -> tuple[int, int, int, int]:
    """(tools, distinct roles, tools whose provenance names a file, unpinned).

    The same four scalars `scripts/toolchain_gate.py` prints, re-derived here
    rather than copied off its summary — the page reasons WITH them, so a copy on
    the page would rot exactly the way a copy in the registry would. `unpinned` is
    the one provenance with no file behind it, which is what makes the third
    number the first minus the fourth rather than a fact of its own.
    """
    text = (ROOT / "assurance/toolchain.toml").read_text()
    # Anchored at a line start: the registry's own header prose writes
    # `[[tool]]` twice while explaining what a row is, and an unanchored split
    # counted both — 15 rows where the file has 13.
    rows_ = re.findall(r"^\[\[tool\]\]$", text, re.M)
    roles = set(re.findall(r'^role = "([^"]+)"', text, re.M))
    unpinned = len(re.findall(r'^provenance = "unpinned"', text, re.M))
    return len(rows_), len(roles), len(rows_) - unpinned, unpinned


def categories() -> int:
    """The criterion's TCB categories the registry reaches.

    Derived the way the roster itself argues it: three are TOOLS with a role that
    answers for a category, the fourth is the `[[boundary]]` set, and the two the
    header names as absent — LLVM passes and the bootrom — are absent because no
    file of this tree records them.
    """
    text = (ROOT / "assurance/toolchain.toml").read_text()
    roles = set(re.findall(r'^role = "([^"]+)"', text, re.M))
    return len({"compiler", "linker", "assembler"} & roles) + (1 if boundaries()[0] else 0)


def rows() -> tuple[int, int, int, int, int, int, int, int, int]:
    """The gate's shape: total, cargo, python, other, and the four twin classes."""
    found = ROW.findall((ROOT / "scripts/check.sh").read_text())
    cargo = [r for r in found if re.search(r"\bcargo\b", r[2])]
    python = [r for r in found if re.search(r"python|pytest", r[2]) and r not in cargo]
    blind = [r for r in found if r[1] in BLIND_ROWS]
    counted = {
        kind: len([r for r in found if r[1].startswith(kind)])
        for kind in ("clippy", "rustdoc", "fmt")
    }
    tests = len([r for r in found if r[0] == "run_tests"])
    return (
        len(found),
        len(cargo),
        len(python),
        len(found) - len(cargo) - len(python),
        len(blind),
        counted["clippy"],
        counted["rustdoc"],
        counted["fmt"],
        tests,
    )


def derived() -> list[tuple[str, int, re.Pattern]]:
    """(what it is, what the tree says, the sentence that has to say it).

    Every pattern carries exactly one hole and must match the page exactly once.
    Two matches is as much a finding as none: a value restated is a value with a
    second place to rot, which is the rule `run_count_gate.py` calls "not said
    twice" and the reason this list holds a COUNT of matches rather than a hit.
    """
    c = lines("crates/rsk-rsa/csrc/bignum_high_level.c")
    asm = lines("crates/rsk-rsa/csrc/bignum_asm.S")
    generic, total, bound = fido_functions()
    every, linker = boundaries()
    total_rows, cargo, python, other, blind, clippy, rustdoc, fmt, tests = rows()
    tools, roles, held, unpinned = roster()
    reached = categories()
    reduction = sum(
        lines(f"crates/rsk-mldsa/src/{name}.rs") for name in ("reduce", "ntt", "round")
    )
    return [
        ("rsk-fido/src/state.rs", lines("crates/rsk-fido/src/state.rs"),
         re.compile(r"(\d+) lines in `state\.rs` alone")),
        # The Rust and asm halves stand INSIDE the pattern rather than in a hole
        # of their own: one sentence states all three, so a drift in either of
        # them stops the pattern matching and is reported as the sentence going
        # away — which is the same finding, arrived at from the other side.
        ("the RSA wrapper's C half", c,
         re.compile(rf"{lines('crates/rsk-rsa/src/lib.rs')} Rust, (\d+) C, {asm} asm")),
        ("the assembly's share", round(100 * asm / (asm + c)),
         re.compile(r"(\d+)% of the foreign half by line")),
        ("the ML-DSA reduction kernel", reduction,
         re.compile(r"(\d+) lines, no generic function")),
        ("generic functions in rsk-fido", generic,
         re.compile(r"(\d+) of \d+ functions are generic")),
        ("functions in rsk-fido", total,
         re.compile(r"\d+ of (\d+) functions are generic")),
        ("`<S: Storage` sites", bound,
         re.compile(r"(\d+) of those carry\s+`<S: Storage`")),
        ("the header's contract", lines("crates/rsk-rsa/csrc/bignum_high_level.h"),
         re.compile(r"(\d+) lines of widths")),
        ("registered tools", tools, re.compile(r"(\d+) registered tools")),
        ("distinct roles", roles, re.compile(r"carrying (\d+) distinct roles")),
        ("tools with a pin file", held, re.compile(r"which (\d+) name a file that pins them")),
        ("unpinned tools", unpinned, re.compile(r"and (\d+) is\s+unpinned")),
        ("TCB categories reached", reached,
         re.compile(r"the registry reaches (\d+) and\s+says\s+why")),
        ("`[[boundary]]` rows", every, re.compile(r"\w+ of the (\w+) `\[\[boundary\]\]` rows")),
        ("linker-symbol boundaries", linker,
         re.compile(r"(\w+) of the \w+ `\[\[boundary\]\]` rows")),
        ("check.sh rows", total_rows, re.compile(r"runs (\d+) rows")),
        ("cargo rows", cargo, re.compile(r"(\d+) invoke `cargo`")),
        ("python rows", python, re.compile(r"(\d+) are Python")),
        ("other rows", other, re.compile(r"(\d+) are\s+neither")),
        ("blind rows", blind, re.compile(r"\*\*Structurally blind, all (\w+):\*\*")),
        ("clippy rows", clippy, re.compile(r"(\d+) clippy rows")),
        ("rustdoc rows", rustdoc, re.compile(r"(\d+) rustdoc rows")),
        ("fmt rows", fmt, re.compile(r"(\d+) fmt rows")),
        ("cargo test rows", tests, re.compile(r"(\d+)\s+`cargo test` rows")),
    ]


#: The page spells small counts as words where a sentence reads better that way,
#: so the comparison is against both spellings rather than the digits alone. A
#: closed list: a value that outgrows it is a value the page should be writing in
#: digits, and the miss is reported as a mismatch rather than passed over.
WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
    8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
}


def audit(root: pathlib.Path = ROOT) -> tuple[list[str], str]:
    page = (root / PAGE).read_text(errors="replace")
    findings, checked = [], 0
    for name, value, pattern in derived():
        hits = pattern.findall(page)
        if not hits:
            findings.append(
                f"{PAGE}: the sentence stating {name} is gone — the tree says"
                f" {value}, and nothing on the page claims it any more"
                f" (pattern {pattern.pattern!r})"
            )
            continue
        if len(hits) > 1:
            findings.append(
                f"{PAGE}: {name} is stated {len(hits)} times; a value restated is"
                " a value with a second place to rot"
            )
            continue
        checked += 1
        said = hits[0]
        if said not in (str(value), WORDS.get(value)):
            findings.append(
                f"{PAGE}: {name} reads {said!r}, the tree says {value}"
            )
    if checked + len(findings) < RULE_FLOOR:
        findings.append(
            f"{PAGE}: only {checked + len(findings)} rule(s) ran against a floor of"
            f" {RULE_FLOOR} — the derivation stopped finding, which is a checker"
            " that passes whatever it is shown"
        )
    return findings, (
        f"level11c-gate: ok — {checked} measurement(s) of"
        f" {PAGE} re-derived from the tree and held"
    )


def main(argv=None) -> int:
    if argv:
        print("usage: level11c_gate.py", file=sys.stderr)
        return 2
    findings, summary = audit()
    if findings:
        print("level11c-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
