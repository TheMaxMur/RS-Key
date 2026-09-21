#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Nothing a host ceremony can reach may borrow a cell the dispatch is holding.

`crates/rsk-device/src/ctap.rs` builds `rsk_fido::Ctx` out of four `RefCell`
borrows — the store, the DRBG, the presence backend, the FIDO state — and keeps
all four alive for the whole CBOR command. On a display build the presence
backend is `rsk_display::TouchPresence`, so the dispatch then calls the panel
*through* a handle onto the same `Ui` that holds the same cells. A second
`borrow_mut()` down there is a `BorrowMutError`; `panic-halt` turns that into a
board that answers nothing until it is unplugged.

That is issue #107, and it was not a typo: the scrambled PIN pad drew its digit
order from the shared DRBG, which is correct on every screen the *device* raises
(the worker is parked) and fatal on the one a *host* raises. `collect_pin_impl`
had carried "must never read `fs`" in its comments since the built-in-UV path
landed. The comment was right, nobody extended it to `rng`, and a comment cannot
be extended by the compiler — hence this row.

What is derived, and from where:

* the CELLS. Read out of `ctap.rs`'s dispatch block itself, not listed here: if
  that block stops holding one, this row stops guarding it, and if it starts
  holding a fifth the fifth is guarded the same day. A rule whose subject is
  typed into the guard is a second place for the truth to live;
* the ROOTS — what a dispatch can call. The methods of `TouchPresence`'s
  `UserPresence` impl, plus its `pub` methods, which is how the CCID secure-PIN
  path reaches `collect_pin_titled` (`firmware/src/worker.rs`) without going
  through the trait. Associated functions with no `self` receiver are not roots:
  a dispatch holds a handle and calls methods on it, it does not construct one;
* the REACH. A one-hop-at-a-time walk over `.name(` calls across the crate's
  production sources. Deliberately over-approximate — any method whose *name* a
  reachable body mentions is walked, receiver unexamined — because the failure
  this stops is a panic on a trusted display and the cheap direction to be wrong
  in is "too many functions checked";
* the SITES. Every `self.<cell>.borrow…` in the crate, attributed to its
  enclosing function by walking back to the nearest `fn`.

Red when those last two intersect. Four floors sit under it because each of the
derivations above can fail to nothing, and all four of the failures are silent —
an empty reach and a clean tree print the same line. Measured on the tree as it
stands: with the #107 borrow put back, this names `pin.rs` `collect_pin()` at
EXIT=1; with it removed, EXIT=0 over 39 reachable functions.

What this is not: it does not say a reachable function is *correct*, and it does
not look at `RefCell`s the display owns alone (`ui`, the panel). Only the four
the dispatch is already holding when it calls in.
"""

import pathlib
import re
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The dispatch that holds the cells, and the crate that is called from inside it.
DISPATCH = pathlib.Path("crates/rsk-device/src/ctap.rs")
CRATE = "crates/rsk-display"
#: Where the host-facing handle lives — the only file roots are read from.
HANDLE = f"{CRATE}/src/presence.rs"

#: The call that receives the borrows. The block that holds them is the one
#: CONTAINING it, found by walking up on brace depth — not by a line window. A
#: window was the first spelling and it was wrong: the real `ctap.rs` borrowed
#: `hooks` nineteen lines above the handoff and a fourteen-line window excluded
#: it by that spacing alone, so an unrelated edit in between would have widened
#: the rule silently. Measured on the fixture, where the same borrow sits two
#: lines out: `hooks` was derived as held and a display-only borrow of it went
#: red. Depth also has to be counted rather than stopping at the first `{`, since
#: `let mut ctx = rsk_fido::Ctx {` opens one between the borrows and the handoff.
HANDOFF = re.compile(r"rsk_fido::process_cbor\s*\(")
#: `let mut fsb = self.fs.borrow_mut();` — the name of the cell, not the local.
HELD = re.compile(r"self\s*\.\s*(\w+)\s*\.\s*borrow_mut\s*\(")

#: A function definition at the head of its line, with its receiver. `receiver`
#: is what separates a method from an associated function: `fn new(ui: &…)` is
#: not something a dispatch holding a handle can call.
FN = re.compile(
    r"^(?P<indent>\s*)(?P<vis>pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)"
    r"\s*(?:<[^>]*>)?\s*\((?P<receiver>\s*&?\s*(?:mut\s+)?self\b)?"
)
#: The trait impl whose methods a dispatch calls. Matched on the handle's own
#: type so a second `UserPresence` impl in the crate cannot widen the roots.
TRAIT_IMPL = re.compile(r"^impl\b.*\bUserPresence\s+for\s+TouchPresence\b", re.M)
#: A called name, last path segment only, receiver unexamined.
CALLEE = re.compile(r"\.\s*([a-z_]\w*)\s*\(")
#: `use`/`mod` lines, where a name is imported rather than called.
IMPORT = re.compile(r"^\s*(?:pub\s+)?(?:use|mod)\b")
#: cfg-gated siblings, by the convention AGENTS.md states. They never reach the
#: image, so a borrow there panics no device.
CFG_GATED = re.compile(r"(?:^|_)(tests|kani)\.rs$")

#: Each floor names the silent failure under it. A derivation that finds nothing
#: satisfies the rule above it, and the row prints "ok" over an empty set.
FLOOR_CELLS = 2  # the dispatch block stopped parsing
FLOOR_ROOTS = 4  # the trait impl stopped being found
FLOOR_REACH = 20  # the call walk stopped following edges
FLOOR_SITES = 10  # the borrow pattern stopped matching


def sources(root):
    """Every production `.rs` of the display crate, from `git ls-files`.

    Not a filesystem walk: an agent worktree under `.claude/` is a second copy of
    the checkout, and every site in it would be derived twice (`gate_lines`).
    """
    out = []
    for relative in sorted(gate_lines.tree_files(root)):
        rel = relative.as_posix()
        if relative.suffix != ".rs" or not rel.startswith(CRATE + "/"):
            continue
        if CFG_GATED.search(relative.name):
            continue
        out.append((rel, (root / relative).read_text().splitlines()))
    return out


def cells(root):
    """The `RefCell`s `ctap.rs` holds across `process_cbor`, read from the tree.

    Bounded by the enclosing block: walk up from the handoff, count braces, and
    stop on the line that opened it. A borrow taken and released ABOVE that line
    is not held across the dispatch and is not this rule's business — `hooks` is
    exactly that, and it is borrowed again inside the display on purpose.
    """
    lines = (root / DISPATCH).read_text().splitlines()
    found = set()
    for number, line in enumerate(lines):
        if not HANDOFF.search(line):
            continue
        depth = 0
        for above in reversed(lines[:number]):
            if above.strip().startswith("//"):
                continue
            depth += above.count("}") - above.count("{")
            if depth < 0:
                break
            found.update(HELD.findall(above))
    return found


def functions(rel, lines):
    """[(name, start, end, vis, is_method)] for one file, ends by indentation."""
    decls = []
    for number, line in enumerate(lines):
        found = FN.match(line)
        if found:
            decls.append((number, found))
    out = []
    for index, (number, found) in enumerate(decls):
        indent = len(found.group("indent"))
        end = len(lines)
        for after in range(number + 1, len(lines)):
            if lines[after].startswith(" " * indent + "}") and lines[after].strip() == "}":
                end = after
                break
        for later, other in decls[index + 1 :]:
            if later > number and len(other.group("indent")) <= indent:
                end = min(end, later)
                break
        out.append(
            (
                found.group("name"),
                number,
                end,
                found.group("vis") is not None,
                found.group("receiver") is not None,
            )
        )
    return out


def roots(root):
    """The methods a host dispatch can call on the handle.

    The `UserPresence` impl's own methods, plus every `pub` method beside them —
    `collect_pin_titled` is reached from `firmware/src/worker.rs` directly, not
    through the trait, so a roots list that only read the impl would leave the
    CCID secure-PIN path outside the rule.
    """
    lines = (root / HANDLE).read_text().splitlines()
    # The impl BLOCK, not "everything below the impl line": a private helper
    # written after the trait would otherwise read as a root, which is the safe
    # direction to be wrong in but says something untrue in the summary.
    spans = []
    for number, line in enumerate(lines):
        if not TRAIT_IMPL.match(line):
            continue
        end = next(
            (at for at in range(number + 1, len(lines)) if lines[at] == "}"), len(lines)
        )
        spans.append((number, end))
    found = set()
    for name, start, _end, is_pub, is_method in functions(HANDLE, lines):
        if not is_method:
            continue
        if is_pub or any(a < start < b for a, b in spans):
            found.add(name)
    return found


def graph(root):
    """({(file, fn): {names called}}, {(file, fn): [(line, text)]} for borrows)."""
    edges, sites = {}, {}
    held = cells(root)
    borrow = re.compile(rf"self\s*\.\s*(?:{'|'.join(sorted(held))})\s*\.\s*borrow")
    for rel, lines in sources(root):
        for name, start, end, _pub, _method in functions(rel, lines):
            key = (rel, name)
            body = lines[start + 1 : end]
            calls = edges.setdefault(key, set())
            for number, line in enumerate(body, start + 2):
                if IMPORT.match(line) or line.strip().startswith("//"):
                    continue
                calls.update(CALLEE.findall(line))
                if borrow.search(line):
                    sites.setdefault(key, []).append((number, line.strip()))
    return edges, sites


def reachable(edges, start):
    """Every `(file, fn)` a dispatch can get to, over-approximating the receiver."""
    by_name = {}
    for key in edges:
        by_name.setdefault(key[1], []).append(key)
    seen, pending = set(), [k for name in start for k in by_name.get(name, [])]
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        for callee in edges[key]:
            pending.extend(by_name.get(callee, []))
    return seen


def audit(root):
    """Every borrow a host ceremony can reach, plus the floors under the answer."""
    problems = []
    held = cells(root)
    if len(held) < FLOOR_CELLS:
        return [
            f"{DISPATCH} yielded {sorted(held)} — under the floor of {FLOOR_CELLS}."
            " The dispatch block stopped parsing, so the rule below has no subject"
            " and every function in the crate reads as clean"
        ]
    entry = roots(root)
    if len(entry) < FLOOR_ROOTS:
        return [
            f"{HANDLE} yielded {sorted(entry)} — under the floor of {FLOOR_ROOTS}."
            " The host-facing surface stopped being found, so nothing is reachable"
            " and nothing can be red"
        ]
    edges, sites = graph(root)
    if len(sites) < FLOOR_SITES:
        return [
            f"{len(sites)} function(s) in {CRATE} borrow {sorted(held)} — under the"
            f" floor of {FLOOR_SITES}. The borrow pattern stopped matching, so the"
            " intersection below is empty for the wrong reason"
        ]
    reach = reachable(edges, entry)
    if len(reach) < FLOOR_REACH:
        return [
            f"{len(reach)} function(s) reachable from {sorted(entry)} — under the"
            f" floor of {FLOOR_REACH}. The call walk stopped following edges, so"
            " the rule holds over the roots alone"
        ]
    for key in sorted(reach & sites.keys()):
        rel, name = key
        for number, text in sites[key]:
            problems.append(
                f"{rel}:{number} `{name}` borrows a cell the dispatch is holding"
                f" — {text}"
            )
    return problems


def run(root):
    try:
        problems = audit(root)
    except OSError as error:
        problems = [f"the display crate cannot be read for this rule: {error}"]
    if problems:
        print("display-borrow-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nA host CBOR command holds the store, the DRBG, the presence backend\n"
            "and the FIDO state borrowed for its whole dispatch, and then calls the\n"
            "trusted display through them. Borrowing one of those cells down there\n"
            "is a BorrowMutError, and under `panic-halt` that is a key which answers\n"
            "nothing until it is unplugged — issue #107, from one unauthenticated\n"
            "command. Read what you need before the ceremony, or derive it.",
            file=sys.stderr,
        )
        return 1
    held = cells(root)
    entry = roots(root)
    edges, sites = graph(root)
    reach = reachable(edges, entry)
    print(
        f"display-borrow-gate: ok — {len(reach)} functions reachable from"
        f" {len(entry)} host entry points, none of them borrows"
        f" {'/'.join(sorted(held))}; {len(sites)} that do are display-only"
    )
    return 0


def main():
    if sys.argv[1:]:
        print("usage: display_borrow_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
