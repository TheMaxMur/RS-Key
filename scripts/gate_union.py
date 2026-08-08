#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the device-wide wipe names every applet's gate predicate.

`Fs::factory_wipe` deletes the records that *gate* an applet in a second phase,
after everything else is provably gone, because a prefix that took a gate first
and then lost power leaves the applet's secrets reachable. Each applet exports
the predicate naming its own gate records; `gates_wiped_last` in the firmware is
their union.

The union is hand-maintained across four crates and nothing in the type system
notices an arm that is missing — the code compiles, and a test written against
the remaining arms still passes. That is not hypothetical: `is_oath_lock_fid`
was private for a release, so the firmware could not name it and OATH was simply
left out; a torn device reset then served every surviving TOTP secret with no
access code at all (audit run-36).

So this is the check: every `is_*_{gate,lock}_fid` in the tree must appear in the
union, and every applet that owes one must still have one. It is deliberately
syntactic — it cannot prove an applet exports the *right* fids (that is each
crate's own host tests), only that none is silently absent from the caller.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNION = ROOT / "firmware/src/ccid_handler.rs"
UNION_FN = "gates_wiped_last"

# `fn is_<applet>_gate_fid(fid: u16) -> bool` / `..._lock_fid`, at any visibility.
# Requiring `pub` is what made this check pass on the very tree it recites: the
# missing `is_oath_lock_fid` was a bare `fn` there, so the scan never saw it
# (audit run-37).
EXPORT = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(?P<name>is_[a-z0-9_]+_(?:gate|lock)_fid)\s*\(",
    re.MULTILINE,
)

#: Applets whose records gate access to secrets, so each owes the union one arm.
#: Without a roster an absent predicate shows up as nothing at all — deleting one
#: reads exactly like an applet that has no gate records (audit run-37).
APPLETS_OWING_A_GATE = ("rsk-fido", "rsk-oath", "rsk-openpgp", "rsk-piv")


def union_body(text):
    """The body of `gates_wiped_last` with comments stripped, or None if absent.

    Comments must not satisfy the membership test: a deleted call whose explanatory
    comment stayed behind ("// is_oath_lock_fid handled elsewhere") is exactly how an
    arm goes missing while the check stays green.
    """
    start = text.find(f"fn {UNION_FN}")
    if start < 0:
        return None
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                body = text[i : j + 1]
                return "\n".join(
                    line.split("//")[0] for line in body.splitlines()
                )
    return None


def sources():
    """Every non-test Rust file a gate predicate can live in. `firmware/src` is in
    scope because a predicate defined there is named by the union in the same crate
    — the one place a `pub`-less one is idiomatic, and it used to be unscanned."""
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")) + sorted(
        (ROOT / "firmware/src").glob("**/*.rs")
    ):
        if path.name.endswith("_tests.rs") or path.name in ("tests.rs", "kani.rs"):
            continue
        # crates/<crate>/src/… — the firmware's own sources belong to no applet.
        rel = path.relative_to(ROOT)
        yield (rel.parts[1] if rel.parts[0] == "crates" else "firmware"), path


def main():
    body = union_body(UNION.read_text())
    if body is None:
        print(f"gate-union: {UNION_FN} not found in {UNION.relative_to(ROOT)}")
        return 1

    missing, contributing = [], set()
    for crate, path in sources():
        for m in EXPORT.finditer(path.read_text()):
            name = m.group("name")
            if name in body:
                contributing.add(crate)
            else:
                missing.append((name, path.relative_to(ROOT)))

    if missing:
        print(f"gate-union: {UNION_FN} does not name:")
        for name, path in missing:
            print(f"  {name}  ({path})")
        print(
            "\nA gate record left out of the union is deleted in phase 1 of the\n"
            "device-wide wipe, so a power cut there leaves that applet's secrets\n"
            "behind a re-provisioned default — or, for OATH, behind nothing."
        )

    absent = [c for c in APPLETS_OWING_A_GATE if c not in contributing]
    if absent:
        print(f"gate-union: no gate predicate found in: {absent}")
        print(
            "\nEach of these applets gates secrets behind a record the wipe must\n"
            "delete last, so each owes the union an arm. Without this roster a\n"
            "predicate that was renamed or deleted reads as an applet that simply\n"
            "has none, and says nothing at all."
        )

    if missing or absent:
        return 1
    print("gate-union: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
