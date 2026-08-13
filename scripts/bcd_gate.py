#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the build counter moved with the code that reaches the image.

`bcdDevice` (`config.device_release` in firmware/src/main.rs) is the USB build
counter, and AGENTS.md has asked for +1 hex on every firmware-behaviour change
since the repo existed. Nothing checked it. It was skipped three times in two
days, and a skipped bump is not visible in a diff — the number still reads
plausibly, the gate is green, and two builds that behave differently report the
same version to every host tool that keys off it.

The rule, one sentence: **if anything that can reach the firmware image has moved
since the counter last did, the counter has to move.**

## The base

Wasefire's `ci-changelog.sh` — the mechanism this is ported from — asks the same
question against `origin/main..`. That does not transfer: this repo is ~143
commits ahead of `origin/develop` and never pushes, so `origin/develop..` would
name the whole tree and the row would be red forever. The base here is the last
commit whose diff actually changed the counter's *value* (candidates come from
`git log -G`, and each is confirmed against its parent — `-G` also matches a
commit that merely moved the line, which would silently reset the base).

## Uncommitted work

The comparison ends at the **working tree**, not at HEAD, and untracked files
count. `check.sh` runs on a dirty tree, and the point of the row is to say the
bump is missing *before* the commit rather than after it. A bump that is itself
still uncommitted counts as the bump, so editing firmware and bumping in one
unfinished batch is green — which is the ordinary way of working here.

## What "can reach the image" means

Not "which files changed": measured over the last 120 commits, a path-only rule
fires on 20 of them, almost all doc-comment and test-wiring commits that are
correctly unbumped — including two commits that sit between the current HEAD and
the current base, so the row would have been red on a clean tree the day it
landed. A guard that cries wolf is a guard someone deletes.

So the paths below are only the first filter, and each changed **line** inside
them is then asked whether it can end up in the binary. A line cannot when it is
a comment, a `#[cfg(…test…)]` / `#[cfg(…kani…)]` attribute, the `#[path]`/`mod`
declaration of a module that is cfg-gated, or a `const _: () = …` compile-time
assertion (an anonymous const item emits no code) — and, for each of those, only
when the line is *nothing but* that construct, since
`#[cfg(not(test))] pub const TIMEOUT_MS: u32 = 1;` carries a cfg and ships every
byte of the const. Blank-line changes are dropped; whitespace changes are **not**
(`-w` also ignores whitespace inside a string literal, and a USB descriptor
losing its spaces produced an empty diff). Everything else counts, and one line
is enough.

Documentation under those paths (`.md`, `.txt`) is excluded: nothing in
`crates/` or `firmware/` calls `include_str!`/`include_bytes!`, so prose cannot
reach the binary, and demanding a bump for a crate README is the false alarm that
gets a guard deleted. Every other `.toml` there — the board knobs — is compared
as parsed TOML like a manifest, so a comment edit is not a build input either.

Which files are cfg-gated is read out of the module graph, not off a name
pattern: a crate root's `#[cfg(test)] mod tests;` carries no `#[path]`, and
`tests.rs` then declares `put_tests`, `increasing_tests` … with no `cfg` of their
own because they inherit it. A name pattern would also hand anyone a free pass by
calling a file `foo_tests.rs`. Resolution that fails leaves the file counted,
which is the safe direction.

Measured on the same 120 commits: 108 agree, 12 fire without a bump — nine of
them cfg-wiring the graph now excuses, two are `const _: ()` assertions, and
`03e98c7e` is a real unbumped change to `rsk-usb`'s CTAPHID timeout. **Zero
commits bumped without this rule firing**, which is the direction that matters:
the rule does not miss.

## The paths

`firmware/` and `crates/` — all 24 crates reach a shipped firmware flavour
(`rsk-ui`, `rsk-bip39`, `rsk-slip39` and `mipidsi` only the `display` one, which
is shipped too), so there is no host-only crate to carve out. Cargo's own
non-lib targets (`crates/*/tests|benches|examples/`) are excluded: cargo never
builds them into a lib. A manifest is compared as parsed TOML over the sections
that reach a build, so adding a dev-dependency for a new test does not fire.

Deliberately **not** here, each because its edits mix image-changing and
host-only concerns and the row would misfire on the second kind: `Cargo.lock`
(moves for a host-only dev-dependency), `rust-toolchain.toml` and the root
`Cargo.toml` (`[profile]`/`[patch]` do change the image, but so does adding a
workspace member; both are maintainer-gated and rare). `rsk-wipe/` is a separate
signed binary with its own identity, not this counter's.

## No escape hatch, deliberately

A surviving line is one that can change the emitted image, and `bcdDevice` is a
*build* counter — CHANGELOG.md's own words. Bumping for a behaviour-neutral
refactor that still moves the binary is correct, not noise, and costs one hex
digit. So there is no env var and no skip list: a floor the environment can lower
is not a ratchet (`scripts/fuzz-coverage.sh:39-41`). If this guard is ever *wrong*
about reachability, fix the reachability rule here where the fix is reviewable.

## The counter only goes up

Checked on the newest bump. The three collisions were all a **stale** number
copied out of a document instead of read from `main.rs`, so a value that does not
exceed the one before it is the shape of that mistake.

## CHANGELOG.md

The semantic rule ("wire- or user-visible changes need an `[Unreleased]` entry")
is not mechanically decidable. The checkable subset is: **a bump owes a CHANGELOG
entry.** Asked over the span that starts just before the bump and ends at the
working tree, so forgetting it in the bump commit and adding it in the next one
clears the row — requiring the same commit would leave it red until the *next*
bump, with no way to clear it.

`docs/protocol.md` moving without a CHANGELOG entry is deliberately **not** a
rule: measured, 9 of the last 250 commits to that page carried no entry and at
least six were prose-only (diagrams, naming, tightening), which is exactly the
class no mechanical rule can tell from a wire change.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = pathlib.Path("firmware/src/main.rs")
CHANGELOG = pathlib.Path("CHANGELOG.md")

#: The counter itself. `firmware/src/main.rs` binds it once and hands the same
#: local to `config.device_release` and to the vendor `version` reply, so this
#: matches the binding and nothing else.
RELEASE = re.compile(r"let device_release: u16 = (0x[0-9A-Fa-f]+)")
#: The same binding as a plain substring. `git log -G` takes a POSIX *basic*
#: regex, where `(` and `+` are literals, so handing it [`RELEASE`]'s pattern
#: finds nothing and every commit reads as "never bumped".
RELEASE_TEXT = "let device_release: u16 = 0x"

#: The one unbumped span this ratchet landed over, and its owner. `4798668
#: refactor(presence)` lifted the scope arbitration out of `firmware/src/
#: presence.rs` into `crates/rsk-device/src/presence.rs` — behaviour unchanged by
#: its own account, emitted image not, which is what this row asks about. It was
#: in flight when the row landed and is not this change's to bump.
#:
#: Keyed on the BASE, so it expires by itself: any bump moves the base, this stops
#: matching, and the guard says to delete the line. A debt with a name and an end,
#: the way `kani_gate.py` records its own.
LANDED_OVER = ("32b9fa32", "4798668 refactor(presence), in flight when this row landed")

#: Everything the linker can pull into a firmware image, before the line filter.
VISIBLE = ("firmware/", "crates/")
#: Cargo's non-lib targets: compiled by `cargo test`/`cargo bench`, never by the
#: lib build the firmware links.
NOT_A_LIB_TARGET = re.compile(r"^crates/[^/]+/(tests|benches|examples)/")
#: Prose, wherever it sits. Nothing in `crates/` or `firmware/` reaches for a
#: file with `include_str!`/`include_bytes!` (measured: no call site in either),
#: so a crate README or a licence text cannot end up in the binary — and asking
#: for a bump on one is the false alarm that gets a guard deleted.
PROSE = (".md", ".txt")
#: Manifest tables that decide what a lib build compiles. `dev-dependencies`,
#: `[[test]]` and `[[bench]]` are absent on purpose — a test-only dependency is
#: the single most common reason a firmware crate's manifest moves.
MANIFEST_TABLES = (
    "dependencies",
    "build-dependencies",
    "target",
    "features",
    "lib",
    "bin",
    "package",
    "profile",
    "patch",
)

#: A `mod x;` that names a file. An inline `mod x { … }` adds no file, so it is
#: not one, and its body is ordinary code that the line filter reads as such.
MOD_DECL = re.compile(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;\s*$")
#: An OUTER attribute — `#[…]`. `#![…]` applies to the enclosing file, not to the
#: item below it, and reading one as if it did let `#![cfg_attr(not(test),
#: no_std)]` at the top of a `lib.rs` gate the first `mod` under it: three
#: shipping modules (rsk-oath's seal, rsk-rescue's keydev, rsk-ui's aa) were
#: outside the counter entirely.
ATTRIBUTE = re.compile(r"^\s*#\[")
#: A line that is nothing but attributes. The exemptions below are about lines
#: that emit no code, and `#[cfg(not(test))] pub const X: u32 = 1;` emits plenty.
ONLY_ATTRIBUTES = re.compile(r"^(?:#!?\[[^\]]*\]\s*)+$")
#: A cfg predicate mentioning `test` or `kani`, in any nesting (`any`, `all`,
#: `not`) and as `cfg_attr` too. `not(test)` is here on purpose: the attribute
#: line itself emits nothing either way, and the code it gates is judged on its
#: own lines.
CFG_TEST = re.compile(r"#!?\[\s*cfg(?:_attr)?\s*\([^)]*\b(?:test|kani)\b")
PATH_ATTR = re.compile(r'#\s*!?\[\s*path\s*=\s*"([^"]+)"\s*\]')
#: `const _: () = …` — an anonymous const item, evaluated at compile time and
#: emitting no code. Anchored at both ends (rustfmt keeps one item per line), so
#: a second item smuggled onto the same line is still read as code.
CONST_ASSERT = re.compile(r"^const _: \(\) = .*(?:;|\{)$")


def git(root, *args, missing_ok=False):
    """`git` in `root`, raising unless it succeeded or `missing_ok` allows it.

    A raise, never a silent "": a guard that reads a git failure as "no change"
    is one that goes green the day the command's spelling breaks.
    """
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if done.returncode and not (missing_ok and done.returncode in (1, 128)):
        raise RuntimeError(f"git {' '.join(args)}: {done.stderr.strip()[:300]}")
    return done.stdout if not done.returncode else ""


def listing(text):
    """A NUL-separated `git` listing as a list. `-z` because git QUOTES a path
    with a non-ASCII byte otherwise, and a quoted path matches no prefix here —
    a file that cannot be classified is a file that is never asked about."""
    return [rel for rel in text.split("\0") if rel]


def read(root, rev, rel):
    """`rel` at `rev`, or from the working tree when `rev` is None. '' if absent."""
    if rev is None:
        path = pathlib.Path(root) / rel
        return path.read_text(errors="replace") if path.is_file() else ""
    return git(root, "show", f"{rev}:{rel}", missing_ok=True)


def release(text):
    """The counter's value in a `main.rs`, or None if it does not bind one.

    Comment lines are dropped first. `RELEASE.search` over the raw file takes the
    *first* match anywhere, so one line of prose quoting the binding — a
    `// next release: … = 0xFFFF` note, a doc comment explaining the counter —
    became the value the guard read. That flips the working tree into "the bump
    is here", which skips the reachability check for the whole tree.
    """
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("//"))
    found = RELEASE.search(code)
    return int(found.group(1), 16) if found else None


def bump_commit(root):
    """The newest commit whose diff changed the counter's value.

    `-G` yields candidates: it also matches a commit that only moved the line,
    and taking the first one blindly would let a reformat of `main.rs` reset the
    base and wave a whole span of firmware changes through. Each candidate is
    confirmed against its parent, so a mover is skipped rather than trusted.
    """
    listing = git(root, "log", "--format=%H", "-G", RELEASE_TEXT, "--", str(MAIN), missing_ok=True)
    for sha in listing.split():
        now = release(read(root, sha, MAIN))
        before = release(read(root, f"{sha}^", MAIN))
        if now is not None and now != before:
            return sha, now, before
    return None, None, None


def parent(root, sha):
    """`sha^`, or the empty tree when `sha` is the first commit of a history.

    Only a fixture reaches the second case, but resolving it here keeps the
    CHANGELOG span from being a `git` error that reads as "no entry".
    """
    got = git(root, "rev-parse", "--verify", "--quiet", f"{sha}^", missing_ok=True).strip()
    return got or git(root, "hash-object", "-t", "tree", "/dev/null").strip()


def files(root, base):
    """(paths that differ between `base` and the working tree, the untracked ones).

    Untracked files are added by hand and kept apart: `git diff` cannot see them
    at all, so a brand new `crates/rsk-fido/src/thing.rs` — exactly the change
    this row is for — would otherwise be a path with an empty diff and no hit.
    """
    tracked = listing(git(root, "diff", "--name-only", "-z", base))
    new = listing(git(root, "ls-files", "-z", "--others", "--exclude-standard"))

    def mine(names):
        return [
            rel
            for rel in dict.fromkeys(names)
            if rel.startswith(VISIBLE)
            and not NOT_A_LIB_TARGET.match(rel)
            and not rel.endswith(PROSE)
        ]

    untracked = set(mine(new))
    return sorted(set(mine(tracked)) | untracked), untracked


def units(paths):
    """The build units owning `paths`: a crate directory, or `firmware`."""
    found = set()
    for rel in paths:
        parts = rel.split("/")
        found.add("/".join(parts[:2]) if parts[0] == "crates" else parts[0])
    return sorted(found)


def sources(root, rev, unit):
    """The `.rs` files of one build unit at `rev`, as {path: text}."""
    if rev is None:
        found = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", unit)
    else:
        found = git(root, "ls-tree", "-r", "-z", "--name-only", rev, "--", unit, missing_ok=True)
    return {
        rel: read(root, rev, rel)
        for rel in listing(found)
        if rel.endswith(".rs") and not NOT_A_LIB_TARGET.match(rel)
    }


def declarations(text):
    """(module name, `#[path]` operand or None, cfg-gated) per `mod x;` in `text`."""
    held = []
    for line in text.splitlines():
        found = MOD_DECL.match(line)
        if found:
            attrs = "\n".join(held)
            operand = PATH_ATTR.search(attrs)
            yield found.group(1), operand and operand.group(1), bool(CFG_TEST.search(attrs))
            held = []
        elif ATTRIBUTE.match(line):
            held.append(line)
        else:
            # A blank line ends the run too: an attribute is attached to the item
            # it touches, and treating a gap as transparent let a file-level
            # `#![cfg_attr(not(test), no_std)]` gate the first `mod` below it.
            held = []


def resolve(parent, name, operand, known):
    """The file a `mod` declaration names, out of `known`, or None.

    Every spelling rustc accepts is tried because a miss leaves the module
    ungated, and an ungated module is one whose changes this row still reads.
    """
    here = parent.rsplit("/", 1)[0]
    stem = parent.rsplit("/", 1)[1].removesuffix(".rs")
    if operand:
        return f"{here}/{operand}" if f"{here}/{operand}" in known else None
    roots = [here] if stem in ("lib", "main", "mod") else [f"{here}/{stem}", here]
    for base in roots:
        for candidate in (f"{base}/{name}.rs", f"{base}/{name}/mod.rs"):
            if candidate in known:
                return candidate
    return None


def gated(root, rev, unit):
    """(ungated files, gated files, ungated declarations, gated declarations).

    Both halves, because an exemption has to be revision-aware: a module that was
    cfg-gated at the base and is *not* gated now has just entered the image, and
    unioning only the gated sides excused both it and the `mod` line that let it
    in. What is gated on one side and plain on the other is not gated.

    Walked from the crate roots so gating is inherited: `tests.rs` is declared
    `#[cfg(test)] mod tests;` with no `#[path]`, and the modules *it* declares
    carry no `cfg` at all because they do not need one. The declarations come
    back too because a `mod x;` line is judged on its own, away from the
    `#[path]` above it that says which file it names.
    """
    known = sources(root, rev, unit)
    seen, out, decls, declared = set(), set(), set(), set()
    queue = [(rel, False) for rel in (f"{unit}/src/lib.rs", f"{unit}/src/main.rs") if rel in known]
    while queue:
        rel, gate = queue.pop()
        if (rel, gate) in seen:
            continue
        seen.add((rel, gate))
        if gate:
            out.add(rel)
        for name, operand, own in declarations(known[rel]):
            declared.add((rel, name))
            if gate or own:
                decls.add((rel, name))
            child = resolve(rel, name, operand, known)
            if child:
                queue.append((child, gate or own))
    # A file reachable both gated and ungated is in the image; the ungated walk
    # wins, so subtract what the walk also reached without a gate.
    # Reached WITHOUT a gate — not merely "not gated". A file no root reaches is
    # compiled by nothing, so it is in neither half, and newly hooking it up must
    # not read as "it used to be in the image".
    plain = {rel for rel, gate in seen if not gate}
    return plain, out - plain, declared - decls, decls


def manifest(text, rel):
    """A TOML build input reduced to what a build actually reads.

    A `Cargo.toml` keeps only the tables a lib or bin build compiles from; any
    other TOML under these paths — `firmware/boards/*.toml`, the board knobs — is
    compared whole, minus its comments, which parsing drops for free.
    """
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return text  # unparseable: compare it verbatim rather than excuse it
    if not rel.endswith("Cargo.toml"):
        return parsed
    return {name: value for name, value in parsed.items() if name in MANIFEST_TABLES}


def changed_lines(root, base, rel, untracked):
    """Added and removed lines for one file, blank-line changes dropped.

    Deliberately NOT `-w`: it ignores whitespace inside string literals too, so
    `"YubiKey RSK OTP+FIDO+CCID"` losing its spaces — a USB descriptor every host
    tool reads — produced an empty diff. `cargo fmt --check` is a gate row, so a
    reindent that is not part of a real edit does not happen here anyway.
    """
    if rel in untracked:
        yield from read(root, None, rel).splitlines()
        return
    diff = git(
        root, "diff", "--ignore-blank-lines", "-U0", base, "--", rel, missing_ok=True
    )
    for line in diff.splitlines():
        if line[:1] in "+-" and not line.startswith(("+++", "---")):
            yield line[1:]


def reaches_image(line, rel, excused, decls):
    """Whether one changed line can end up in the binary.

    Each excuse asks that the line be *nothing but* the construct it names.
    `#[cfg(not(test))] pub const TIMEOUT_MS: u32 = 1;` carries a cfg mentioning
    `test` and ships every byte of that const.
    """
    body = line.strip()
    if not body or body.startswith("//"):
        return False
    if CONST_ASSERT.match(body):
        return False
    if ONLY_ATTRIBUTES.match(body):
        if CFG_TEST.search(body):
            return False
        operand = PATH_ATTR.search(body)
        if operand and f"{rel.rsplit('/', 1)[0]}/{operand.group(1)}" in excused:
            return False
    decl = MOD_DECL.match(body)
    return not (decl and (rel, decl.group(1)) in decls)


def image_changes(root, base):
    """[(path, the line that decided it)] for everything the image can feel."""
    paths, untracked = files(root, base)
    plain, gated_files, plain_decls, gated_decls = set(), set(), set(), set()
    for unit in units(paths):
        for rev in (base, None):
            open_files, gate, open_decls, gates = gated(root, rev, unit)
            plain |= open_files
            gated_files |= gate
            plain_decls |= open_decls
            gated_decls |= gates
    # Gated on every side that has it. A file gated at the base and un-gated now
    # has just entered the image, and so has the `mod` line that let it in.
    excused = gated_files - plain
    decls = gated_decls - plain_decls
    hits = []
    for rel in paths:
        if rel in excused:
            continue
        if rel.endswith(".toml"):
            # Parsed, not textual: a board knob's comment is not a build input,
            # and a manifest's `[dev-dependencies]` is not one either.
            before, after = read(root, base, rel), read(root, None, rel)
            if manifest(before, rel) != manifest(after, rel):
                hits.append((rel, "a table a build reads"))
            continue
        if not rel.endswith(".rs"):
            hits.append((rel, "not a Rust source file, so every byte counts"))
            continue
        for line in changed_lines(root, base, rel, untracked):
            if reaches_image(line, rel, excused, decls):
                hits.append((rel, line.strip()[:72]))
                break
    return hits


def audit(root):  # noqa: C901 — one clause per failure mode, each named
    """(problems, one-line summary) for how this checkout tracks its counter."""
    root = pathlib.Path(root)
    head = release(read(root, "HEAD", MAIN))
    now = release(read(root, None, MAIN))
    if now is None:
        return [f"{MAIN} no longer binds `let device_release: u16 = 0x…`"], ""
    base, at_base, before_base = bump_commit(root)
    if base is None:
        return [f"no commit in this history ever changed the counter in {MAIN}"], ""

    problems, carried = [], []
    tree_bumps = head is not None and now != head
    if tree_bumps:
        # The bump is in the working tree, so the span it has to cover is empty.
        # What is left to check is that it goes up, and that it is written down.
        was, span = head, "HEAD"
    else:
        was, span = before_base, parent(root, base)
        landed, why = LANDED_OVER
        # An empty entry is no entry — the fixtures run without one, and `""` is
        # a prefix of every sha.
        owns = bool(landed) and base.startswith(landed)
        for rel, line in image_changes(root, base):
            if owns:
                carried.append(f"{rel}: {line}")
            else:
                problems.append(f"{rel} changed since {base[:8]} bumped the counter: {line}")
        if landed and not carried:
            problems.append(
                f"LANDED_OVER names {landed} ({why}) but nothing is unbumped there"
                f" any more — the base is {base[:8]}; delete the entry"
            )

    if was is not None and now <= was:
        problems.append(
            f"the counter is 0x{now:04X} and was 0x{was:04X}: it only goes up,"
            " and a number that does not is the shape of one copied out of a"
            f" stale document instead of read from {MAIN}"
        )
    if not (root / CHANGELOG).is_file():
        problems.append(f"{CHANGELOG} is gone; deleting it is not a way to satisfy this row")
    elif not git(root, "diff", "--name-only", span, "--", str(CHANGELOG)).strip():
        problems.append(
            f"{CHANGELOG} has not moved since {span}: a bump is a released"
            " behaviour change and owes an [Unreleased] entry"
        )
    where = "the working tree" if tree_bumps else base[:8]
    debt = f"; carried from {LANDED_OVER[1]}: {len(carried)} files" if carried else ""
    return problems, (
        f"bcd-gate: ok — 0x{now:04X}, bumped by {where}, nothing unbumped since{debt}"
    )


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("bcd-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            f"\nA firmware-behaviour change bumps `config.device_release` in {MAIN}\n"
            "by +1 hex and says why in CHANGELOG.md. Read the current value from\n"
            "that file — never from a document that quotes it — and add the entry\n"
            "in the same change."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
