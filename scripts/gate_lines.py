# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""How the roster guards read a command out of a file they do not run.

`kani_gate.py` and `roster_gate.py` both ask whether a hand-written `-p` list is
still the whole truth, and both read the same files to do it. Each had to learn
the same things: a trailing `\\` folds two lines into one command, a `#` kills
the rest of a line wherever on that line it falls, a `cargo …` in a workflow is
only *run* when it sits inside a step's `run:` scalar — and, since both guards
now walk the checkout (one for proofs, one for stray package selections), which
directories are not the tree.

Those rules lived in two copies. 237fd00 judged the shared surface to be "a
five-line continuation-joiner", which was true then; ffbfaef then had to fix the
`#` rule in both scripts in one commit, and the coverage roster needs the `run:`
walk — block scalars, `- ` list items, indentation — as a third copy. Writing
that a third time is the defect both scripts exist to catch, one level up. What
a *package flag* is lives here for the same reason and later: the two had
drifted into different answers, one taking `--package` and the other not,
neither taking `--package=x`, so the same command read as two rosters.

The whole of "which packages is this command about" followed, and later still,
because a quarter of that answer each is what the three guards were reading —
`roster_gate` knew `--exclude`, `matrix_gate` knew only `-p`, and none of them
could see an operand an expansion fills in. [`selection`] is that answer; a
caller resolves a manifest path against its own checkout, which is the half
that cannot live here.

How to read *Rust* joined for the same reason and later still. `platform_gate.py`
grew a lexer so its unsafe inventory would not be written by a comment saying a
file has none; `shrink_gate.py` needs the same answer about `#[cfg(kani)]`, and a
second copy would have inherited the same gap (see [`rust_code`]).

Deliberately not here: what a roster *owes*. That differs per script and is the
reason there are two of them.
"""

import collections
import pathlib
import re
import subprocess

#: A `#` at a word boundary comments out the rest of the line — a shell one in
#: `check.sh` and inside a workflow's `run:` block, a YAML one beside it, a
#: heading in the docs' prose. Wherever it starts, nothing after it runs.
COMMENT = re.compile(r"(?:^|\s)#")

#: A step's `run:`: `run: <command>`, a `run: |` literal block, or a `run: >`
#: folded one. The indicator is captured because the two block styles are
#: different commands — `|` keeps its newlines, `>` folds the whole block into
#: one line, and reading a folded row line by line finds a `cargo` with no `-p`
#: after it and reports the row as gone while it sits there complete.
RUN_KEY = re.compile(r"run:\s*(?:(?P<fold>[|>])[-+\d]*)?\s*")

#: The package-selection flag in the spellings cargo takes: `-p x`,
#: `--package x`, `--package=x`.
PKG = re.compile(r"(?<![\w-])(?:-p|--package)[=\s]+([\w-]+)(?![\w-])")
#: The same flag with an operand a substitution fills in — `-p "$c"`, the shape a
#: `for c in …; do cargo kani -p "$c"; done` roster takes. [`PKG`] reads nothing
#: there and the row then looks like one that selects nothing, which is the
#: permissive answer; this one says the selection is unreadable so a caller can
#: refuse it. A sigil rather than "anything but a name", so prose writing
#: `-p <crate>` stays prose.
PKG_GENERATED = re.compile(r"""(?<![\w-])(?:-p|--package)[=\s]+["']?[$@{%]\S*""")
#: `--manifest-path <path>`: cargo's OTHER answer to which package, and the one
#: `scripts/check.sh` writes twenty times against `tools/tui`, `tools/emu` and
#: `fuzz`. Read here rather than beside each caller for the reason the package
#: flag is: they had drifted into two answers once already.
MANIFEST_PATH = re.compile(r"""(?<![\w-])--manifest-path[=\s]+["']?([^\s"']+)""")
#: `--exclude x`, the third: `--workspace --exclude firmware` selects the tree
#: less that name, and a reader that stops at [`PKG`] reads it as the whole one.
EXCLUDE = re.compile(r"(?<![\w-])--exclude[=\s]+([\w-]+)(?![\w-])")
#: And its generated operand, on [`PKG_GENERATED`]'s rule and for its reason.
EXCLUDE_GENERATED = re.compile(r"""(?<![\w-])--exclude[=\s]+["']?[$@{%]\S*""")

#: What a cargo command says about which packages it is about. Four fields
#: rather than four functions, because the question is one question and the
#: guards that ask it were reading a quarter of the answer each: `roster_gate`
#: knew `--exclude` and not `--manifest-path`, `matrix_gate` knew neither, and
#: `kani_gate` could not see a `-p` an expansion fills in.
Selection = collections.namedtuple("Selection", "named manifests excluded generated")


def selection(text):
    """Every way `text` names the packages it is about, in one answer.

    Deliberately syntactic and deliberately NOT resolved: which workspace member
    a manifest path is depends on the checkout, and the checkout belongs to the
    caller. What is here is the reading of the FLAGS — the half that was being
    written twice, and that had already drifted into two answers over `-p`.

    `generated` is the operands no reader can resolve, and it is a third thing
    beside naming a crate and naming none: a row whose selection an expansion
    fills in selects something, and reading it as "selects nothing" is the
    permissive direction in every caller here.
    """
    return Selection(
        named=frozenset(PKG.findall(text)),
        manifests=tuple(MANIFEST_PATH.findall(text)),
        excluded=frozenset(EXCLUDE.findall(text)),
        generated=tuple(
            found.group(0).strip()
            for pattern in (PKG_GENERATED, EXCLUDE_GENERATED)
            for found in pattern.finditer(text)
        ),
    )


def invocation(verbs):
    """A `cargo <verb>` matcher over `verbs`, tolerating a `+toolchain`.

    `cargo +nightly llvm-cov …` is the same row; a matcher that misses it
    reports the row as deleted, which is the one message guaranteed to be read
    as a false alarm.
    """
    return re.compile(rf"(?<![\w-])cargo (?:\+\S+ )?({'|'.join(verbs)})(?![\w-])")


def packages(text):
    """The crates `text` selects by a readable package flag.

    One field of [`selection`] rather than its own read of [`PKG`]: two callers
    asking "which crates does this name" off two matchers is the drift this file
    exists to stop, and it is how `--package=x` came to be a selection to one
    guard and not to the other.
    """
    return selection(text).named


def strip_packages(text):
    """`text` with every readable package flag and its operand removed."""
    return PKG.sub(" ", text)


def split_at_comment(body):
    """`body` in two at the first `#`: what runs, and what is only quoted.

    Judged from the `#`, not from the line's first character: `true # cargo …`
    runs the `true`, and reading it as live is the hole both guards shipped with.
    """
    found = COMMENT.search(body)
    return (body[: found.start()], body[found.start() :]) if found else (body, "")


def runs(text, needle):
    """Whether `text`'s CODE — not its prose — carries `needle`.

    A guard named only in a comment is run by nothing, and counting one is a hole
    this repo has now shipped twice. `kani_gate.py` read a commented-out
    invocation as live; and a `#` typed in front of a `check.sh` row left every
    assertion that the row is wired in green, because each compared the file's
    RAW text — measured, all eleven `*_gate.py` rows commented out at once and
    `pytest scripts -q` identical to its baseline. Deliberately the conservative
    direction: a real invocation carrying a trailing `#` is missed and goes red,
    which is loud, where a comment counted as an invocation is silent.
    """
    return any(needle in split_at_comment(body)[0] for _indent, body in logical_lines(text))


def logical_lines(text):
    """(indent, stripped text) per line, with `\\` continuations joined into one.

    A 250-character command gets reflowed onto several lines sooner or later, and
    a roster read off half of one fails a comparison nothing is wrong with. A
    guard that cries wolf on a formatting edit is a guard someone deletes.
    """
    parts, indent = [], 0
    for raw in text.splitlines():
        if not parts:
            indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1].strip())
            continue
        parts.append(stripped)
        yield indent, " ".join(p for p in parts if p)
        parts = []
    if parts:
        yield indent, " ".join(p for p in parts if p)


def yaml_runs(text):
    """(logical line, executed) over a workflow, empty lines dropped.

    Executed = inside a step's `run:` scalar; that is the only text a job runs.
    Everything else in the file — a header comment carrying the local equivalent,
    a step name, a `run:` some edit commented out — is a quotation of it. Whether
    a particular command on such a line is live is [`split_at_comment`]'s half of
    the answer, not this one's.

    A folded (`run: >`) block is yielded as the single line YAML makes of it, so
    a row wrapped for width reads as the command it is. Its blank line is a hard
    newline and ends the fold; a `#` inside it is not a YAML comment but text,
    and folding it onto the command is what makes it comment out the rest.
    """
    run_indent, folding, held = None, False, []
    for indent, body in [*logical_lines(text), (0, None)]:
        if folding and body and indent > run_indent:
            held.append(body)
            continue
        if held:  # the fold ended: a dedent, a blank line, or the file did
            yield " ".join(held), True
            held = []
        if not body:
            continue
        if body.startswith("- "):
            indent, body = indent + 2, body[2:]
        found = RUN_KEY.match(body)
        if body.startswith("#"):
            # A YAML comment, or a shell one inside the block. Reached only from
            # outside a fold — one inside it is text — and a comment shallower
            # than the scalar has ended it.
            executed, folding = False, False
        elif found:
            run_indent, folding, executed = indent, found["fold"] == ">", True
        elif run_indent is not None and indent > run_indent:
            executed = True  # a continuation line of the block scalar
        else:
            run_indent, folding, executed = None, False, False
        yield body, executed


def rust_code(text):
    """`text` with comments, string literals and char literals blanked, spans kept.

    A lexer, not a token list, because the alternative is enumerating every form
    a token takes and the review showed that list is the thing that goes wrong:
    `unsafe` appears in `//! no unsafe`, in `/// the unsafe direction`, and inside
    a `"\\n    unsafe fn "` a code generator emits, and a `#[cfg(kani)]` appears in
    prose about one. Handles `//` to end of line, nested `/* … */`, `"…"` with
    backslash escapes, `r#"…"#` and the `b` prefixes of both.

    Char and byte literals are here because leaving them out is not a smaller
    lexer, it is a wrong one: `b'"'` in `rsk-usb`'s keyboard map opened a string
    that ran to the end of the file, and the module walk below then read that
    file as declaring no modules at all. Measured over the checkout: 154 `.rs`
    files lex differently with them handled, and `platform_gate.py`'s unsafe
    inventory is unchanged on every one — the gap was reachable, not yet reached.
    A lifetime is left alone by construction (`'a` has no closing quote).
    """
    out, i, n = [], 0, len(text)
    while i < n:
        char = text[i]
        if char == "/" and text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
        elif char == "/" and text.startswith("/*", i):
            depth, start = 1, i
            i += 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            out.append(" " * (i - start))
        elif (raw := RAW_STRING.match(text, i)) is not None:
            close = '"' + raw.group(1)
            end = text.find(close, raw.end())
            end = n if end < 0 else end + len(close)
            out.append(" " * (end - i))
            i = end
        elif (lit := CHAR_LITERAL.match(text, i)) is not None:
            out.append(" " * (lit.end() - i))
            i = lit.end()
        elif char == '"' or text.startswith('b"', i):
            start, i = i, i + (2 if char == "b" else 1)
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i = min(i + 1, n)
            out.append(" " * (i - start))
        else:
            out.append(char)
            i += 1
    return "".join(out)


#: `r"…"`, `r#"…"#` and their `b` forms. The hashes are captured because they are
#: part of the closing delimiter.
RAW_STRING = re.compile(r'b?r(#*)"')

#: `'x'`, `'\n'`, `b'"'` — never a lifetime, which has no closing quote.
CHAR_LITERAL = re.compile(r"b?'(?:\\.|[^\\'])'")


def tree_files(root):
    """Every file of the checkout at `root`, relative: git's answer, not a walk.

    The tree is what git tracks plus what a contributor has just written; build
    output is not the tree, and a hand-written skip list gets the difference
    wrong. Walking the filesystem past `target/` and `.git` still descended into
    the mdBook output under `book/` and `site/`, where six generated copies of
    `assurance/reports/testing-evidence.md` each read as an unregistered roster owner. It also skips
    the agent worktrees under `.claude/`, whole second copies of the tree in
    which every proof reads as unreachable. No fallback if git is not there: a
    second path for reading the tree is a second answer to what the tree is.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    for rel in listing.split("\0"):
        if rel and (pathlib.Path(root) / rel).is_file():
            yield pathlib.Path(rel)
