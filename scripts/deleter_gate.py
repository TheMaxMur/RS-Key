#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the delete-family caller dispositions against the tree, both ways.

`Fs::delete`, `Fs::delete_key`, `Fs::force_delete` and `Fs::force_delete_halves`
(and `delete_over`/`delete_key_over`, the first two over a pre-OTP record)
all remove the value whatever their metadata drop did, and all of them RETURN what
the drop did — `Err` names a state (the value is gone, a record may still stand
over it) rather than a no-op. Which callers may discard that answer and which may
not is a judgement per call site, and `assurance/deleters.toml` is where those
judgements live.

A ledger of judgements is only worth the roster under it. This one is DERIVED
here and compared with the file; nothing about which sites exist is stored. Two
findings in this tree are why:

* `assurance/crates.toml` exists because two roadmap drafts enumerated crates
  from memory and missed four, including the second-largest;
* the audit this file comes out of began by refuting a sentence in
  `docs/store-refinement.md` that named "the one caller in the tree that deletes
  a fid carrying a head". There were two, and the second was the one hiding a
  faulted drop, on the reset path.

What is checked, and the direction of each:

* every derived call site has exactly one entry, and every entry names a site
  that is still there. A new caller arrives unaudited and the row goes red;
* the `answer` recorded — whether the site reads the deleter's `Result` or
  discards it — is DERIVED from the statement, so turning a reading caller into
  a discarding one cannot pass as an unrelated edit. Both ENDS of the statement
  are read, because the four spellings of "discard" sit at both: `let _ =`, the
  same binding without the `let`, `drop(…)` around the call, and a trailing
  `.ok();`;
* `disposition` and `answer` must agree: `must-read` needs `read`,
  `best-effort` needs `discarded`. That is the pair that makes the judgement
  falsifiable by the code rather than by a reviewer's memory;
* the call text at the recorded line must still be that call. A citation whose
  line has moved reports where it went, the way `citation_gate.py` does;
* the VALUE half of the contract, which the ledger did not carry at all. The
  three outcomes a caller can get are typed in `rsk-fs` — `Removal { value,
  record }` — and the verbs differ in the first of them: `delete`/`delete_key`
  skip the backend removal when the present cache reads absent, `force_delete`
  and `force_delete_halves` do not. That is DERIVED from the verb, so it is not
  a second copy of it, and one rule rests on it: a `wipe-sweep` site may not use
  a conditional verb. The reason is in `force_delete`'s own rustdoc — a
  re-enumerating wipe reads the backend directly, so a delete that no-ops on a
  torn-migration false-absent key keeps re-finding it and loops forever. The
  limit it inherits, said here rather than left to be found: `class` is a
  hand-written disposition, so relabelling a sweep as `bookkeeping` dodges the
  rule. `verb` cannot be relabelled — it is held against the call text at the
  recorded line — but `class` is exactly the kind of judgement this file's last
  paragraph says no script can check;
* `metadata = "drops-head"` is allowed only for a crate that actually mints
  EF_META heads, and that set is derived too. The whole metadata axis rests on
  "`rsk-piv` mints the only heads"; a second minter arriving silently is how that
  premise stops being true while every disposition still reads as though it is;
* the roster is not empty. A derivation that finds nothing satisfies every rule
  above, which is the failure mode a verdict column cannot show.

And a SECOND roster, over the removals `Fs` performs on its own behalf. The
delete family is not the only way a record leaves the medium: `Fs::factory_wipe`
erases the whole device through `self.storage.remove`, which is not one of the
four verbs, from inside `crates/rsk-fs` — which `SKIP_DIRS` excludes. So the 43
sites above never included the one sweep that erases everything, and "all five
`wipe-sweep` rows closed" said nothing about it. A registry that is complete
over a predicate nobody checked measures the predicate's blind spot, not the
tree. What is derived for each, and the direction:

* the enclosing method, and the call text at the recorded line, the way the
  citations above are held. A new removal path in `Fs` arrives undisposed-of and
  the row goes red;
* whether that method re-arms the at-rest scrub (`request_rescrub` or `attempt_rescrub`, rsk-fs
  `EF_HARDENED`). DERIVED from the method BODY, so deleting the call flips the
  axis rather than passing as an unrelated edit — a tombstone appends like a
  re-seal, so a sweep that supersedes a pre-OTP-sealed record under a latched
  marker leaves it readable in a flash dump for the life of the key;
* `scrub` and `rearms` must agree, the pair that makes the judgement falsifiable
  by the code rather than by a reviewer's memory.

Deliberately not here: whether a disposition is *right*. That is prose in the
ledger, and no script can check it. What this row keeps honest is that each one
is still about a site that exists, still describes what that site does with the
answer, and still covers every site there is.
"""

import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = pathlib.Path("assurance/deleters.toml")

#: The removal verbs. `delete_key` is `delete` over a `KeyFid`, so it carries the
#: identical contract; `force_delete` differs only in that the backend removal is
#: unconditional; `force_delete_halves` is that one with its two answers handed
#: back apart, which is the shape a reset sweep needs (see their rustdoc).
#: `delete_over`/`delete_key_over` are the first two over a pre-OTP record.
VERBS = ("delete", "delete_key", "force_delete", "force_delete_halves",
         "delete_over", "delete_key_over")
#: The leading `.` is the whole receiver test: it is what separates `fs.delete(`
#: from `Foo::delete(` and from any `_delete(` suffix of a longer name. The
#: second alternative is the SAME call spelled UFCS — `Fs::force_delete(fs, x)`,
#: `<Fs<S>>::delete(fs, x)` — which the receiver test alone cannot see: two new
#: callers were added that way, one of them deleting the FIDO seed, and the
#: roster count did not move. Longest verb alternative last is deliberate —
#: `delete` is tried first and the `\s*\(` after it is what sends `.delete_key(`
#: back for the longer one.
CALL = re.compile(rf"(?:\.|(?:\bFs\b|>)::)({'|'.join(VERBS)})\s*\(")

#: Where a delete caller cannot be. `crates/rsk-fs` defines the family, so its
#: own uses are the implementation rather than callers of it; `fuzz/` drives the
#: API rather than shipping a decision. Held to the roadmap's own wording, so the
#: counts here reproduce the ones §3.4 records. Nothing else is excluded by name:
#: `third_party/` stays in, because a call there would be a decision too.
SKIP_DIRS = ("crates/rsk-fs", "fuzz")

#: Not scope — determinism. `tools/emu` and `tools/tui` are their own workspaces
#: with their own `target/`, and a build there drops generated `.rs` under the
#: checkout, so a roster walking the tree would depend on whether anyone had run
#: cargo. Matched by path COMPONENT, at any depth.
#: A cfg-gated source by the convention AGENTS.md states: tests and proofs live
#: in sibling files hooked with `#[path]`. Derived from the naming rule rather
#: than listed, so `reset_refinement_kani.rs` — whose `reset.delete` is the
#: refinement model's own verb, not this file system's — is out by the rule that
#: puts every other proof file out.
CFG_GATED = re.compile(r"(?:^|_)(tests|kani)\.rs$")

#: Where an EF_META head can come from. Derived, because every `drops-head`
#: disposition below rests on the answer being one crate.
MINT = re.compile(r"\.meta_add(?:_reserve)?\s*\(")

#: A statement that throws the answer away, at its HEAD. Three spellings, and
#: two of them used to derive as `read`: `let _ = …`, the same binding without
#: the `let` (Rust 2021 destructuring assignment), and `drop(…)` around the call.
#: All three pass `cargo fmt --check` and `clippy -D warnings`, so a must-read
#: site could be converted into any of them with this row still green.
DISCARD = re.compile(r"^\s*(?:let\s+)?_\s*(?::[^=]*)?=|^\s*drop\s*\(")

#: The fourth spelling, and the only one that shows at the statement's END:
#: `….ok();` throws the `Result` away exactly as `let _ =` does, and
#: `statement_head` cannot see it.
DISCARD_TAIL = re.compile(r"\.ok\s*\(\s*\)\s*;$")

#: How far forward a statement may run before the walk gives up and calls the
#: site a reader. A delete call statement is a line or a short `.method()` chain;
#: past that the forward walk is guessing.
STATEMENT_LINES = 12

#: A statement boundary: the line before a statement's first line ends in one of
#: these, or is blank, or is a comment. Walking back to it is what lets a call on
#: a `.method()` continuation line be read against the `let` that owns it.
BOUNDARY = re.compile(r"[;{},]$|^$|^//|^/\*|^\*")

#: The roster cannot shrink to nothing without someone saying so. Measured at 43
#: (33 `delete`/`delete_key` + 10 of the two `force_delete` spellings) when this
#: landed; floored well under that so ordinary movement does not trip it and a
#: broken derivation does.
FLOOR_SITES = 30

#: A removal `Fs` performs on its own behalf, through the backend rather than
#: through the delete family. `crates/rsk-fs` is out of `SKIP_DIRS`' scope and
#: `remove` is not one of `VERBS`, so these are invisible to the roster above —
#: twice over, which is why they are derived here instead of by widening either.
FS_CRATE = "crates/rsk-fs"
FS_REMOVE = re.compile(r"\.storage\.remove\s*\(")

#: The method a removal sits in, walked back to. `rustfmt` puts an `impl` method's
#: `fn` and its closing brace at one indent, which is what makes the span exact —
#: and the span is what the `rearms` axis is derived over.
FN = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")

#: The at-rest lap's re-arm (`crate::request_rescrub`, rsk-fs `EF_HARDENED`).
REARM = re.compile(r"\b(?:request_rescrub|attempt_rescrub)\s*\(")


#: What a `scrub` disposition claims, and the derived `rearms` it must agree with.
SCRUBS = {"re-arms": True, "deferred-to-caller": False}

#: The `Fs` roster cannot empty out silently either. One is the floor because the
#: derivation is over a single crate: at zero every rule below it passes.
FLOOR_REMOVALS = 1

DISPOSITIONS = {"must-read": "read", "best-effort": "discarded"}
#: The derived `answer` as a verb, so a message reads as a sentence.
PHRASE = {"read": "reads", "discarded": "discards"}
CLASSES = ("wipe-sweep", "secret-or-gate", "metadata", "bookkeeping")
METADATA = ("drops-head", "none")

#: Whether the verb's backend removal is gated on the present cache. DERIVED
#: from the verb rather than recorded beside it: a field a caller could set
#: independently of the call it describes is a second copy of the call.
REMOVAL = {
    "delete": "conditional",
    "delete_key": "conditional",
    "force_delete": "unconditional",
    "force_delete_halves": "unconditional",
    "delete_over": "conditional",
    "delete_key_over": "conditional",
}


def sources(root):
    """Every `.rs` file a delete caller could live in, in a stable order.

    From `git ls-files` and not from a walk. The hand-written skip list below it
    got the difference wrong in the direction that stops the row being about the
    tree: an agent worktree under `.claude/worktrees/` is a whole second copy of
    the checkout, and this row went RED on 19 sites of a file it had already
    disposed of once — same path, different prefix. `gate_lines.tree_files` says
    so in its own docstring, and five gates already read the tree that way.
    """
    out = []
    for relative in sorted(gate_lines.tree_files(root)):
        if relative.suffix != ".rs":
            continue
        rel = relative.as_posix()
        if any(rel == d or rel.startswith(d + "/") for d in SKIP_DIRS):
            continue
        if CFG_GATED.search(relative.name):
            continue
        out.append((rel, root / relative))
    return out


def statement_head(lines, index):
    """The first line of the statement `lines[index]` belongs to.

    A call can sit on a `.method()` continuation, where the `let _ =` that
    discards it is lines above. Reading only the call's own line calls every one
    of those a reader, which is the direction that hides a discard.
    """
    at = index
    while at > 0 and not BOUNDARY.search(lines[at - 1].strip()):
        at -= 1
    return lines[at]


def statement_tail(lines, index):
    """The last line of the statement `lines[index]` belongs to, or `None`.

    `….ok();` discards at the END, where [`statement_head`] cannot see it. A line
    that opens a block is not a simple statement — `if ….is_err() {` READS the
    answer — so the walk stops there rather than running into the body and
    reading someone else's `;`.
    """
    for at in range(index, min(index + STATEMENT_LINES, len(lines))):
        text = lines[at].strip()
        if text.endswith("{"):
            return None
        if text.endswith(";"):
            return text
    return None


def disposal(lines, index):
    """`"discarded"` or `"read"`: what the statement at `lines[index]` does with
    the deleter's `Result`. Both ends of the statement, because the spellings sit
    at both ends."""
    if DISCARD.match(statement_head(lines, index)):
        return "discarded"
    tail = statement_tail(lines, index)
    if tail is not None and DISCARD_TAIL.search(tail):
        return "discarded"
    return "read"


def sites(root):
    """[(file, line, call text, verb, answer)] for the whole checkout."""
    found = []
    for rel, path in sources(root):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            for hit in CALL.finditer(line):
                found.append(
                    (rel, number, line.strip(), hit.group(1), disposal(lines, number - 1))
                )
    return found


def one_liner(text):
    """A `fn` whose body opens and closes on its own line: it encloses nothing
    below it, and it has no closing brace of its own for the span walk to find, so
    it would otherwise swallow every removal after it in the real method."""
    return "}" in text and text.count("{") == text.count("}")


def enclosing(lines, index):
    """`(method name, body lines)` for the `fn` that `lines[index]` sits in.

    The nearest preceding `fn` is NOT it: a nested helper sits between a method's
    `fn` and its body, and walking back to the first one names the helper for a
    removal that is not in it — with the whole entry then red about a function that
    removes nothing. So a candidate must CONTAIN the line: its closing brace, at its
    own indent, has to come after it. A helper whose body opens and closes on its
    own line has no such brace to find and encloses nothing, so it is skipped by
    shape. Taking the span to that brace rather than to the next `fn` is the other
    half — a helper must not end a method's span early and hide the re-arm after it.
    """
    for at in range(index, -1, -1):
        opened = FN.match(lines[at])
        if not opened or one_liner(lines[at]):
            continue
        indent, name = opened.group(1), opened.group(2)
        close = f"{indent}}}"
        end = next(
            (n for n in range(at + 1, len(lines)) if lines[n].rstrip() == close),
            len(lines),
        )
        if end > index:
            return name, lines[at:end]
    return None, []


def fs_removals(root):
    """[(file, line, call text, method, re-arms)] — `Fs`'s own backend removals."""
    found = []
    for relative in sorted(gate_lines.tree_files(root)):
        rel = relative.as_posix()
        if relative.suffix != ".rs" or not rel.startswith(FS_CRATE + "/"):
            continue
        if CFG_GATED.search(relative.name):
            continue
        lines = (root / relative).read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if not FS_REMOVE.search(line):
                continue
            method, body = enclosing(lines, number - 1)
            found.append(
                (rel, number, line.strip(), method, any(REARM.search(b) for b in body))
            )
    return found


def minters(root):
    """The crates that write an EF_META head, derived from the calls."""
    out = set()
    for rel, path in sources(root):
        if MINT.search(path.read_text()):
            out.add("/".join(rel.split("/")[:2]))
    return out


def entries(root):
    with (root / LEDGER).open("rb") as handle:
        return tomllib.load(handle)


#: What a `[[site]]` may say, and which tables the file may have. Neither had a
#: list: a key added here was read by nothing and printed by nothing, and a whole
#: new table was invisible in both directions. Measured before the rule went in —
#: an invented key in the first record left this row at EXIT=0. The idiom is
#: `scripts/threat_gate.py`'s, which learned it from `matrix_gate`'s `[[cell]]`.
SITE_FIELDS = (
    "answer",
    "call",
    "class",
    "disposition",
    "file",
    "line",
    "metadata",
    "verb",
    "why",
)
TABLES = ("fs_removal", "head_minters", "site")

#: What an `[[fs_removal]]` may say. Same rule as `SITE_FIELDS`: a key nothing
#: reads is a key nothing holds.
FS_REMOVAL_FIELDS = ("call", "file", "line", "method", "rearms", "scrub", "why")


def audit(root):
    """Every disagreement between the ledger and the tree, each reported once."""
    problems = []
    doc = entries(root)
    derived = sites(root)
    if len(derived) < FLOOR_SITES:
        problems.append(
            f"{len(derived)} call sites derived, under the floor of {FLOOR_SITES}"
            " — the derivation found (almost) nothing, so every rule below passed"
            " over an empty roster"
        )
        return problems

    ledger = {(e["file"], e["line"]): e for e in doc.get("site", [])}
    if len(ledger) != len(doc.get("site", [])):
        problems.append("two entries name the same file and line")

    by_key = {(rel, line): (call, verb, answer) for rel, line, call, verb, answer in derived}
    for key in sorted(by_key.keys() - ledger.keys()):
        rel, line = key
        problems.append(
            f"{rel}:{line} `{by_key[key][0]}` calls the delete family and"
            f" {LEDGER} does not dispose of it"
        )
    for key in sorted(ledger.keys() - by_key.keys()):
        rel, line = key
        elsewhere = [
            str(n) for r, n, call, _, _ in derived
            if r == rel and call == ledger[key]["call"]
        ]
        where = f"; it is at :{', :'.join(elsewhere)} now" if elsewhere else ""
        problems.append(
            f"{LEDGER} disposes of {rel}:{line}, which calls nothing{where}"
        )

    for key in sorted(by_key.keys() & ledger.keys()):
        rel, line = key
        call, verb, answer = by_key[key]
        entry = ledger[key]
        if entry["call"] != call:
            problems.append(
                f"{rel}:{line} was disposed of as `{entry['call']}` and reads"
                f" `{call}` now"
            )
        if entry["verb"] != verb:
            problems.append(f"{rel}:{line} calls `{verb}`, disposed of as `{entry['verb']}`")
        if entry["answer"] != answer:
            problems.append(
                f"{rel}:{line} {PHRASE[answer]} the deleter's answer and is"
                f" disposed of as `{entry['answer']}` — re-decide the site, do not"
                " re-label it"
            )

    mints = minters(root)
    if mints != set(doc["head_minters"]):
        problems.append(
            f"the crates that write an EF_META head are {sorted(mints)}, and"
            f" {LEDGER} says {sorted(doc['head_minters'])} — every `drops-head`"
            " disposition rests on that set"
        )
    if stray := sorted(set(doc) - set(TABLES)):
        problems.append(
            f"{LEDGER} carries {stray}, which nothing reads — a table added here is"
            " held by no rule and shown to no reader"
        )
    for entry in doc.get("site", []):
        where = f"{entry['file']}:{entry['line']}"
        if stray := sorted(set(entry) - set(SITE_FIELDS)):
            problems.append(f"{where}: carries {stray}, which nothing reads")
        if entry["class"] not in CLASSES:
            problems.append(f"{where}: class `{entry['class']}` is not one of {CLASSES}")
        if entry["metadata"] not in METADATA:
            problems.append(f"{where}: metadata `{entry['metadata']}` is not one of {METADATA}")
        if entry["disposition"] not in DISPOSITIONS:
            problems.append(
                f"{where}: disposition `{entry['disposition']}` is not one of"
                f" {sorted(DISPOSITIONS)}"
            )
        elif DISPOSITIONS[entry["disposition"]] != entry["answer"]:
            problems.append(
                f"{where}: disposed of as `{entry['disposition']}` while the site"
                f" {PHRASE[entry['answer']]} the answer"
            )
        if not entry.get("why", "").strip():
            problems.append(f"{where}: a disposition with no reason is not one")
        if entry["metadata"] == "drops-head" and "/".join(
            entry["file"].split("/")[:2]
        ) not in mints:
            problems.append(
                f"{where}: claims to drop an EF_META head from a crate that mints none"
            )
        if entry["class"] == "wipe-sweep" and REMOVAL.get(entry["verb"]) != "unconditional":
            problems.append(
                f"{where}: a wipe sweep on `{entry['verb']}`, whose backend removal"
                " is skipped when the present cache reads absent — the sweep"
                " re-enumerates from the backend, so a false-absent key is"
                " re-found on every pass and the wipe does not terminate"
            )
    problems += audit_fs_removals(root, doc)
    return problems


def audit_fs_removals(root, doc):
    """The second roster: what `Fs` removes on its own behalf, and whether it
    re-arms the at-rest lap over what it supersedes."""
    problems = []
    derived = fs_removals(root)
    if len(derived) < FLOOR_REMOVALS:
        return [
            f"{len(derived)} backend removals derived inside {FS_CRATE}, under the"
            f" floor of {FLOOR_REMOVALS} — `Fs::factory_wipe` erases the device"
            " through one, so a derivation that finds none is broken rather than"
            " a tree with no wipe in it"
        ]

    ledger = {(e["file"], e["line"]): e for e in doc.get("fs_removal", [])}
    if len(ledger) != len(doc.get("fs_removal", [])):
        problems.append("two `fs_removal` entries name the same file and line")
    by_key = {(rel, line): (call, method, rearms) for rel, line, call, method, rearms in derived}
    for key in sorted(by_key.keys() - ledger.keys()):
        rel, line = key
        problems.append(
            f"{rel}:{line} `{by_key[key][0]}` removes from the backend inside"
            f" `{by_key[key][1]}` and {LEDGER} does not dispose of it — the delete"
            " family's roster cannot see this one, twice over"
        )
    for key in sorted(ledger.keys() - by_key.keys()):
        rel, line = key
        elsewhere = [
            str(n) for r, n, call, _, _ in derived
            if r == rel and call == ledger[key]["call"]
        ]
        where = f"; it is at :{', :'.join(elsewhere)} now" if elsewhere else ""
        problems.append(
            f"{LEDGER} disposes of a backend removal at {rel}:{line}, which removes"
            f" nothing{where}"
        )

    for key in sorted(by_key.keys() & ledger.keys()):
        rel, line = key
        call, method, rearms = by_key[key]
        entry = ledger[key]
        where = f"{rel}:{line}"
        if entry["call"] != call:
            problems.append(
                f"{where} was disposed of as `{entry['call']}` and reads `{call}` now"
            )
        if entry["method"] != method:
            problems.append(
                f"{where} is in `{method}`, disposed of as `{entry['method']}`"
            )
        if entry["rearms"] != rearms:
            did = "re-arms" if rearms else "does not re-arm"
            problems.append(
                f"{where}: `{method}` {did} the at-rest scrub and is disposed of as"
                f" `rearms = {str(entry['rearms']).lower()}` — a tombstone appends"
                " like a re-seal, so re-decide the path, do not re-label it"
            )

    for entry in doc.get("fs_removal", []):
        where = f"{entry['file']}:{entry['line']}"
        if stray := sorted(set(entry) - set(FS_REMOVAL_FIELDS)):
            problems.append(f"{where}: carries {stray}, which nothing reads")
        if entry["scrub"] not in SCRUBS:
            problems.append(
                f"{where}: scrub `{entry['scrub']}` is not one of {sorted(SCRUBS)}"
            )
        elif SCRUBS[entry["scrub"]] != entry["rearms"]:
            problems.append(
                f"{where}: disposed of as `{entry['scrub']}` while `rearms ="
                f" {str(entry['rearms']).lower()}`"
            )
        if not entry.get("why", "").strip():
            problems.append(f"{where}: a disposition with no reason is not one")
    return problems


def run(root):
    try:
        problems = audit(root)
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        problems = [f"{LEDGER} cannot be read as a disposition ledger: {error}"]
    if problems:
        print("deleter-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery caller of the Fs delete family owes a\n"
            "disposition: whether discarding the deleter's answer is an allowed\n"
            "best-effort wipe there, or a device reporting success over a record\n"
            "or a secret that is still in flash. Decide the site in\n"
            f"{LEDGER}; a label that disagrees with the code is not a decision.",
            file=sys.stderr,
        )
        return 1
    total = len(sites(root))
    doc = tomllib.loads((root / LEDGER).read_text(encoding="utf-8"))
    kinds = {k: 0 for k in ("conditional", "unconditional")}
    for entry in doc.get("site", []):
        kinds[REMOVAL[entry["verb"]]] = kinds[REMOVAL[entry["verb"]]] + 1
    inside = fs_removals(root)
    rearming = sum(1 for *_, rearms in inside if rearms)
    print(
        f"deleter-gate: ok — {total} call sites, each disposed of; "
        + ", ".join(f"{n} {k}" for k, n in kinds.items())
        + " backend removal"
        + f"; {len(inside)} removals inside {FS_CRATE}, {rearming} re-arming the"
        " at-rest scrub"
    )
    return 0


def main():
    if sys.argv[1:]:
        print("usage: deleter_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
