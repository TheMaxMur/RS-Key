#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Assert the Kani rows, all of them, run every harness the tree has.

`cargo kani` is invoked with a hand-written `-p` list, and a crate that is not on
it is not proven — but nothing says so. The row was named "prove every harness"
and it was running 29 of 49. Never added: `rsk-ui` (the trusted display's
touch-target geometry — the anti-phishing consent surface), `rsk-led`
(`EF_LED_CONF`, a persisted record with a published wire format), `rsk-slip39`
and `rsk-bip39`. Green daily, asserting nothing about any of them. A harness in
an unlisted crate is worse than no harness, because the reviewer believes it
runs.

No per-crate count is written in that sentence any more, and the deletion is the
point: it used to say "`rsk-ui` (12 proofs" and the crate carried 14, in the same
words `assurance/crates.toml` and the `--write-readme` mirror of it in
formal/README.md were also carrying. A count belongs where something derives it,
so the ledger's is held to the tree by [`ledger_claims`] and this file states
none.

Third time a gate script has been the finding rather than the instrument (after
the test filter that matched nothing and the fuzz row blind to `[[bin]]`
targets), and the first two were fixed at the site with no guard, which is why
there was a third. So: the roster is checked, not remembered.

Since the proofs split into tiers — a fast one on every pull request, the
security-state crates when a change reaches them, all of them daily — the roster
is no longer a string to compare. `scripts/kani.sh` owns tier → crates and prints
the table with `--tiers`; this reads that table and asks four things of it:

* the `all` tier is exactly the crates carrying a `#[kani::proof]`, less
  [`EXCLUDED`] — both directions, so a crate with an unrun proof fails and so
  does a listed crate whose proof went away;
* every other tier is a non-empty subset of it, because a tier that selects
  nothing is a row that exits 0 having proved nothing (`kani.sh` floors the
  harness count for the same reason, one layer down);
* every tier is invoked by a row CI actually **runs** — inside a step's `run:`
  scalar, left of any `#`. Counting matching strings is not enough: a workflow
  header's local-equivalent comment is a second copy in the same file, so putting
  a `#` in front of the `run:` line once left three agreeing rosters and this
  guard green over a job that proved nothing. "Uncommented" is judged from the
  `#`, not from the line's first character — `run: true # scripts/kani.sh all`
  runs the `true`;
* and every tier is in assurance/reports/testing-evidence.md, which is what a reader copies and which
  says CI runs the same commands.

The counts those tiers are floored at are read the same way. `kani.sh`'s
`FLOOR_*`/`COVERS_*` say how many harnesses and `kani::cover!`s a run must come
back with, assurance/reports/testing-evidence.md prints the same numbers in a table, and all four sets
were kept by the instruction "raise it in the commit that adds one". They drifted:
`FLOOR_all` sat at 64 against a tree of 65, so one harness could have gone missing
under a floor that still passed. Counted from the source here instead, both
directions — a floor under the tree is loose, one over it demands more than a run
can report — and the same for the page's table. The count is comment-stripped,
because two `*_kani.rs` files discuss `kani::cover!` in prose, and a spelling
neither counter can see is refused by name rather than skipped: an uncounted
harness is a floor set one too low, which is the drift, and it would be silent.

Nothing outside `scripts/kani.sh` may write a `cargo kani` package selection into
a file that runs one. That is the rule the old three-way string comparison was
standing in for, and it is the one that stops a fifth copy from appearing the day
someone wants a fifth tier. It used to be a rule about three NAMED files, and the
list is what kept going wrong. `scripts/check.sh` arrived on it late, because it
was in NEITHER guard's reach: this one read the workflows and the page, and
`roster_gate.py` reads `check.sh` but hands the `kani` verb over by name —
correctly, since its rule is "selects the whole tree" and a Kani row selects the
proof-carrying subset on purpose. The hand-off went nowhere, and adding one file
to the list left the same hand-off open one file over: `nix/checks.nix` runs
`cargo`, `roster_gate` reads it and hands `kani` over, and a live
`cargo kani -p rsk-sha512 -p rsk-ec` there measured GREEN under both guards after
the fix. So is a roster in any other `scripts/*.sh`, one in a `.yaml` workflow
(the glob was `*.yml`), and one an expansion fills in (`-p "$c"` matches no crate
name). All four are closed by asking the CHECKOUT rather than a list — see
[`sources`] — and all four were found latent, which is the state every guard hole
in this tree has been found in. A `cargo kani -p <crate>` in a source file's doc
comment or an evidence bundle is still not in scope: it tells a reader how one
run was made, it does not claim to say what CI proves.

Deliberately syntactic. It cannot say a harness proves anything worth proving —
that is the harness's own business — only that the solver is pointed at it.
"""

import collections
import pathlib
import re
import subprocess
import sys
import tomllib

import gate_lines
import roster_gate
import toolchain_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = pathlib.Path(".github/workflows")
DOCS = pathlib.Path("assurance/reports/testing-evidence.md")
RUNNER = pathlib.Path("scripts/kani.sh")
#: The gate script. Not a workflow, so no pin is looked for in it — but a tier
#: named on one of its rows is a tier CI runs, because the merge gate is a CI
#: row, and that is the whole of what this constant now decides. Which files are
#: read for a roster is [`sources`]' walk and no longer a list this could be
#: missing from.
CHECK = pathlib.Path("scripts/check.sh")
#: The crate ledger. `assurance_gate.py --write-readme` mirrors its prose into
#: formal/README.md, so a count stated here is stated twice and repaired once.
LEDGER = pathlib.Path("assurance/crates.toml")

#: A proof count claimed in the ledger's prose. Only this shape, and only inside a
#: `[crate.X]` table, because that is what makes the number decidable: the section
#: says which crate, and both spellings the ledger uses — a digit and the word
#: `zero` — then count. A claim in ordinary prose elsewhere is not, and a rule
#: that hunted for one would fire on every sentence about proofs — the shape a
#: guard gets switched off for. Live claims when this landed: three, on `rsk-ui`,
#: `rsk-ec` and `rsk-sha512`.
CLAIM = re.compile(r"\b(?:(\d+)|zero|no) Kani proofs?\b")

#: Crates with a harness the daily row deliberately does not run, each with the
#: measured reason. An exclusion is a debt, so it is checked too: one naming a crate
#: that no longer has a proof is stale and fails, rather than quietly covering for a
#: harness someone deleted.
EXCLUDED = {
    "rsk-bench": "`summarize` sorts `samples[warmup..]`, a symbolic-length slice, so "
    "CBMC unwinds it without a bound: no verdict in 5 min, and none with "
    "--default-unwind 5 either (measured, kani 0.67.0, 2026-08-11).",
}

#: The tier that has to hold every crate. The others are subsets of it, so this is
#: the one the coverage question is asked of.
FULL = "all"

#: The name the workflows pin the prover with. Kani's verdicts are
#: version-dependent, so an unpinned local install is a different tool.
PIN_VAR = "KANI_VERSION"
#: The shape a pin has to have. `latest` is an assignment, not a pin; the quotes
#: the earlier spelling of this required are YAML's and not part of the value.
PINNED = re.compile(r"[\d.]+")
DOC_PIN = re.compile(r"kani-verifier --version ([\d.]+)")

#: An invocation of the tier runner, with or without a `./` and whatever drives it.
#: The tier may be spelled out or come from a matrix — `${{ … }}` is captured
#: whole so it can be resolved below rather than read as a tier named `${{`.
INVOKED = re.compile(r"(?<![\w/-])(?:\./)?scripts/kani\.sh\s+(\$\{\{[^}]*\}\}|\S+)")

#: The matrix reference the weekly row names its tier with.
MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.(\w+)\s*\}\}\Z")
#: `key: [a, b]`, and the `key:` / `- a` block form, inside a `matrix:` block.
MATRIX_INLINE = re.compile(r"^(\w+):\s*\[([^\]]*)\]\s*$")
MATRIX_KEY = re.compile(r"^(\w+):\s*$")
MATRIX_ITEM = re.compile(r"^-\s*[\"']?([\w.-]+)[\"']?\s*$")

#: The two shapes the floors are counts of. Every one in this tree is written
#: exactly like this, `#[kani::proof]` alone on its line.
HARNESS = re.compile(r"#\[kani::proof\]")
COVER = re.compile(r"\bkani::cover!")

#: Code that names one of them in a spelling neither counter sees: a contract
#: harness, a `cfg_attr` form, an import that could rename the macro. Refused, not
#: skipped — the miss would set a floor low, which is exactly the drift.
UNSEEN = re.compile(r"kani::(?:proof|cover)|^\s*use\s+kani(?:::|\s*;)")

#: A raw-string opener — `r"`, `r#"`, `br##"` — with its hashes, so the matching
#: close is found rather than the first quote after it.
RAW_STRING = re.compile(r'(?:b|c)?r(#*)"')
#: A char literal, so `'"'` cannot open a string and `'/'` cannot open a comment.
#: A lifetime does not match it: `'a` has no closing quote.
CHAR_LIT = re.compile(r"'(?:\\.|[^\\'])'")

#: `kani.sh`'s ratchets, and the columns assurance/reports/testing-evidence.md prints beside them:
#: `| `pr` | 13 | 49 | 23 | …` is crates, harnesses, covers.
RATCHET = re.compile(r"^\s*(?:readonly\s+)?(FLOOR|COVERS)_(\w+)=\"?(\d+)\"?\s*(?:#.*)?$", re.M)
DOC_ROW = re.compile(r"^\|\s*`(\w+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", re.M)

#: A hand-written roster: `cargo kani` with a package flag on it. `cargo kani
#: setup` carries none and is not one.
KANI = gate_lines.invocation(("kani",))

Use = collections.namedtuple("Use", "path tier executed")


def tiers(root):
    """tier → crates, as `scripts/kani.sh` itself reports them.

    Asked of the script rather than parsed out of it: `--tiers` and the run path
    go through the same `case`, so a tier this is shown is a tier that would
    actually run. Parsing the shell would be a second reading of the same table,
    which is the defect this guard exists to catch, one level up.
    """
    listing = subprocess.run(
        [str(root / RUNNER), "--tiers"], capture_output=True, check=True, text=True
    ).stdout
    out = {}
    for line in listing.splitlines():
        name, _, crates = line.partition(":")
        if name.strip():
            out[name.strip()] = frozenset(crates.split())
    return out


def is_workflow(read):
    """Whether a source is a workflow — the only shape with a matrix or a pin.

    Asked of the reader it is walked with, not of a second list of paths: the
    reader is what decides which lines of the file run, so one answer decides
    both and a file cannot be a workflow to one clause and prose to the next.
    """
    return read is gate_lines.yaml_runs


def matrices(text):
    """(key → the values a `strategy.matrix` gives it, keys declared twice over).

    Syntactic, like the rest of this guard: the dev shell has no YAML parser, and
    a second way of reading a workflow would be a second answer to what CI runs.
    A key declared twice with different values is reported rather than merged —
    the wrong guess is a tier counted as proved by a job that does not prove it.

    `include:` entries (`- tier: light1`) are deliberately not read: they carry a
    colon, no rule below matches them, and the tier then reads as run by nobody.
    That is the safe direction — it fails loudly instead of passing quietly.
    """
    table, conflicts = {}, set()
    block, matrix_indent, key = {}, None, None

    def close():
        # One `matrix:` block at a time, merged only when it ends: reading the
        # accumulating `- item` form straight into `table` would make a second
        # job's differing matrix look like a continuation of the first's.
        for name, values in block.items():
            if name in table and table[name] != values:
                conflicts.add(name)
            table[name] = values
        block.clear()

    for indent, body in gate_lines.logical_lines(text):
        if not body or body.startswith("#"):
            continue
        if matrix_indent is not None and indent <= matrix_indent:
            close()
            matrix_indent, key = None, None
        if body.rstrip() == "matrix:":
            matrix_indent, key = indent, None
            continue
        if matrix_indent is None:
            continue
        if found := MATRIX_INLINE.match(body):
            key = found.group(1)
            block[key] = tuple(
                v.strip().strip("\"'") for v in found.group(2).split(",") if v.strip()
            )
        elif found := MATRIX_KEY.match(body):
            key = found.group(1)
        elif (found := MATRIX_ITEM.match(body)) and key:
            block[key] = block.get(key, ()) + (found.group(1),)
    close()
    return table, conflicts


def referenced_keys(text):
    """The `matrix.<key>` names a tier runner on `text` takes its tier from."""
    return {
        ref.group(1)
        for found in INVOKED.finditer(text)
        if (ref := MATRIX_REF.match(found.group(1)))
    }


def uses(rel, text, read):
    """Every `scripts/kani.sh <tier>` on `text`, flagged executed or not.

    Executed means inside a step's `run:` scalar *and* left of the `#` — the only
    copy a job runs. A prose or comment copy is a quotation of it. Documentation
    is never executed, whatever it looks like.

    A tier named `${{ matrix.<key> }}` expands to that key's values: the weekly
    row proves one tier per runner, and which tiers those are is in the matrix,
    not on the `run:` line.
    """
    table = matrices(text)[0] if is_workflow(read) else {}
    for body, in_run in read(text):
        live, quoted = gate_lines.split_at_comment(body)
        for segment, executed in ((live, in_run), (quoted, False)):
            for found in INVOKED.finditer(segment):
                ref = MATRIX_REF.match(found.group(1))
                if ref is None:
                    yield Use(rel, found.group(1), executed)
                    continue
                for value in table.get(ref.group(1), ()):
                    yield Use(rel, value, executed)


def handwritten(rel, text, read):
    """Every hand-written `cargo kani` package selection on `text` — there should be none.

    A commented-out one counts, in the gate script as in a workflow header: a
    roster nobody runs today is one somebody uncomments, and either way it is a
    second list a reader copies. The carve-out is the FILE SET and not a rule
    inside this loop — a source file's doc comment is never opened here.

    All of `gate_lines.selection`, not `-p` alone. A `for c in rsk-a rsk-b; do
    cargo kani -p "$c"; done` is a roster written in shell, and it was invisible
    because the operand is not a crate name; a `--manifest-path` picks the crate
    by its directory instead. Both are the list this file forbids, spelled so the
    matcher walks past.
    """
    for body, _executed in read(text):
        for found in KANI.finditer(body):
            tail = body[found.start() :]
            selected = gate_lines.selection(tail)
            spelled = (
                sorted(f"-p {crate}" for crate in selected.named)
                + [f"--manifest-path {raw}" for raw in selected.manifests]
                + [g for g in selected.generated if gate_lines.PKG_GENERATED.match(g)]
            )
            if spelled:
                yield rel, " ".join(spelled)


#: The suffixes of a file that RUNS a command, and so a file a roster can be
#: written into. `.md`, `.toml` and `.rs` are deliberately out: they QUOTE one —
#: `assurance/bundle/*.toml` records a real `cargo kani -p rsk-fido --harness …`
#: run seven times over, and each is a record of what was done, not a claim about
#: what CI proves.
RUNS_CARGO = (".sh", ".nix")

#: A file this guard reads, and whether a `scripts/kani.sh <tier>` written there
#: says anything about which tiers exist and which CI runs. The flag is the
#: difference between the walk's two questions and it is not cosmetic: measured
#: with the walk and no flag, `scripts/reproduce.sh`'s two recipe strings name
#: six tiers between them — so deleting a workflow's Kani row would have been
#: covered by a string in a help table — while `formal/run-tlc.sh` names
#: `scripts/kani.sh` twice in prose and both read as tiers that do not exist.
#: Two findings in opposite directions off one widening, which is the shape a
#: guard gets switched off for.
Source = collections.namedtuple("Source", "path text read ci")


def sources(root):
    """Every file that runs a command, with its reader and what its tiers mean.

    Two questions off one walk. Whether a second `-p` roster exists is asked of
    the whole checkout — every workflow, every `.sh`, every `.nix`, and the page
    — because a named list of files is how this guard's last hole was shaped:
    `nix/checks.nix` runs `cargo`, `roster_gate` has read it since the day it was
    written and hands the `kani` verb over, and this file read the workflows,
    the page and `scripts/check.sh`. A roster there was the second roster this
    file exists to forbid and both guards printed `ok` — the identical
    hand-off-to-nowhere `7ab2428` closed one file over, and it survived that
    commit. The other three spellings measured green the same day: a roster in
    any other `scripts/*.sh`, one in a `.yaml` workflow (the glob was `*.yml`),
    and one an expansion fills in.

    Which tiers CI proves is the narrower question, and only the four files that
    ANSWER it are asked: a `./scripts/kani.sh pr` inside a help table is not a CI
    row, and a `scripts/kani.sh` in a sentence is not a tier. The set is derived
    from `gate_lines.tree_files` for the reason `roster_gate.stray_excludes`
    derives its own: the copy that got away was invisible to a census that was
    told where to look, and the walk costs 0.02 s over 1514 files.

    `roster_gate.py`'s readers, not a second set of them, for the reason this
    file already asks `toolchain_gate` what an `env:` block says. Which reader a
    file gets decides one thing here and not the other: [`handwritten`] discards
    the executed flag by design, so `shell` and `prose` give the roster rule
    IDENTICAL line sets, while [`uses`] reads it — a `./scripts/kani.sh <tier>`
    row in `check.sh` is a CI row under `shell` and a quotation under `prose`.
    Measured both ways: on the shipped tree the choice is worth nothing in either
    rule, because `check.sh` runs no tier at all; move `ci.yml`'s `state` row into
    `check.sh` and `prose` goes red saying no CI row runs that tier while `shell`
    stays green. `7ab2428` recorded that arm on the `all` tier, which the weekly
    workflow row runs and `check.sh` never did, and it does not reproduce.
    """
    for rel in sorted(gate_lines.tree_files(root)):
        if rel == RUNNER:
            continue  # the tier table itself; every roster in it is the roster
        if rel.parent == WORKFLOWS and rel.suffix in (".yml", ".yaml"):
            read, ci = gate_lines.yaml_runs, True
        elif rel == DOCS:
            read, ci = roster_gate.prose, True
        elif rel.suffix in RUNS_CARGO:
            read, ci = roster_gate.shell, rel == CHECK
        else:
            continue
        try:
            yield Source(rel, (root / rel).read_text(), read, ci)
        except (OSError, UnicodeDecodeError):
            continue


def workflow_pins(root):
    """{workflow -> every value its `env:` blocks give [`PIN_VAR`]}.

    EVERY workflow, because the name is assigned three times across two files —
    ci.yml:155, deep-checks.yml:354 and :446 — and this read deep-checks.yml
    alone. Measured before the change: moving ci.yml's literal alone was exit 0
    here, and so was moving deep-checks.yml's SECOND assignment, which a
    `search` for the first never reached.

    `toolchain_gate.env_values` is the reader rather than a second regex, for the
    reason `platform_gate` asks `claims_gate.is_generated` instead of re-reading
    its mapping: it judges the `env:` block structurally, so a `with:` or
    `inputs:` key of the same name is not taken for a pin, and one reading of a
    workflow is one answer to what CI installs.
    """
    return {
        str(source.path): values
        for source in sources(root)
        if is_workflow(source.read)
        and (values := toolchain_gate.env_values(source.text, PIN_VAR))
    }


def blanked(chunk):
    """`chunk` as spaces, newlines kept — so line numbers and the quoted line hold."""
    return "".join(ch if ch == "\n" else " " for ch in chunk)


def code_lines(text):
    """(`text`'s lines with strings and comments blanked, a `/*` still open at EOF).

    Prose is not a harness: `presence_kani.rs` and `rsa-asm/src/kani.rs` each
    discuss `kani::cover!` in a doc comment, and counting those two puts a floor
    above anything a run can report.

    Strings are stripped *first*, and that ordering is the whole of it. A `/*`
    inside a string literal — `rsk-wipe/build.rs` has the shape — otherwise opens
    a block comment that never closes and swallows the rest of the file, taking
    the refusal below down with it, so the under-count would be silent in exactly
    the place it must not be. Rust that compiles never ends inside a block
    comment, so a depth left over at EOF means the scan mis-read something.
    """
    out, i, n, depth = [], 0, len(text), 0
    while i < n:
        raw = RAW_STRING.match(text, i)
        if raw and not (i and (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = text.find('"' + raw.group(1), raw.end())
            end = n if close < 0 else close + 1 + len(raw.group(1))
        elif text[i] == '"':
            end = i + 1
            while end < n and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end = min(end + 1, n)
        elif char := CHAR_LIT.match(text, i):
            end = char.end()
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
        elif text.startswith("/*", i):
            depth, end = 1, i + 2
            while end < n and depth:
                if text.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif text.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
        else:
            out.append(text[i])
            i += 1
            continue
        out.append(blanked(text[i:end]))
        i = end
    return "".join(out).splitlines(), depth != 0


def counted(text):
    """(harnesses, covers, the reasons a count taken here cannot be trusted)."""
    lines, swallowed = code_lines(text)
    harnesses = covers = 0
    reasons = []
    for line in lines:
        harnesses += len(HARNESS.findall(line))
        covers += len(COVER.findall(line))
        if UNSEEN.search(COVER.sub("", HARNESS.sub("", line))):
            reasons.append(f"{line.strip()} — neither counter can see that spelling")
    if swallowed:
        reasons.append("a /* … */ is still open at end of file — the scan stopped there")
    return harnesses, covers, reasons


def crates_with_proofs(root):
    """(harnesses per crate, covers per crate, orphans, uncountable lines).

    The whole tree is walked, not `crates/*/src`: the root `cargo kani` reaches only
    workspace members, so a harness under `fuzz/`, `tools/*` (detached workspaces) or
    `firmware/` (thumbv8m-only) is run by nothing and no `-p` can fix it. Scanning
    just the places a proof is *supposed* to live is how the blind spot gets rebuilt.
    """
    harnesses, covers = collections.Counter(), collections.Counter()
    orphans, unseen = [], []
    for rel in gate_lines.tree_files(root):
        if rel.suffix != ".rs":
            continue
        text = (root / rel).read_text()
        if "kani" not in text:
            continue
        found, reached, odd = counted(text)
        # Collected before the early return: a file whose *only* kani content is a
        # spelling nothing counts has found == reached == 0, and that is precisely
        # the file the refusal exists for.
        unseen += [f"{rel}: {reason}" for reason in odd]
        if not found and not reached:
            continue
        if rel.parts[0] != "crates":
            orphans.append(rel)
            continue
        # Guarded, not `+= 0`: a `Counter` inserts the key either way, and the
        # membership of these two is what says which crates are proven and which
        # carry a cover no harness reaches.
        if found:
            harnesses[rel.parts[1]] += found
        if reached:
            covers[rel.parts[1]] += reached
    return harnesses, covers, sorted(orphans), unseen


def ledger_claims(root, harnesses):
    """Problems where `assurance/crates.toml` states a proof count the tree denies.

    A stated count is a ratchet like `FLOOR_*` and fails in both directions for
    the same reasons — under the tree it covers a harness that went away, over it
    claims a proof nobody wrote. What made this one worth deriving is that it is
    stated TWICE: `--write-readme` copies the sentence into formal/README.md, so
    the pair drifted together and read as two sources agreeing.
    """
    path = root / LEDGER
    if not path.is_file():
        return [f"{LEDGER} is gone, so the proof counts it states are unchecked"]
    with open(path, "rb") as fh:
        ledger = tomllib.load(fh).get("crate", {})
    problems = []
    for crate, entry in sorted(ledger.items()):
        for field, value in sorted(entry.items()):
            if not isinstance(value, str):
                continue
            for found in CLAIM.finditer(value):
                said = int(found[1]) if found[1] else 0
                if not (root / "crates" / crate).is_dir():
                    problems.append(
                        f"{LEDGER} [crate.{crate}] {field} says `{found[0]}`, and"
                        f" there is no crates/{crate} for this to count in"
                    )
                elif said != harnesses[crate]:
                    problems.append(
                        f"{LEDGER} [crate.{crate}] {field} says `{found[0]}`;"
                        f" crates/{crate} carries {harnesses[crate]} #[kani::proof]"
                    )
    return problems


def ratchets(root, table, harnesses, covers):
    """Problems where a floor, or a number the page prints, is not the tree's count.

    Both directions are wrong and they fail differently. A floor under the tree is
    loose — the harness that goes missing takes it with it, which is how
    `FLOOR_all` came to sit at 64 against 65 — and one over the tree asks for more
    than any run can report, which fails the row after it has done the work.
    """
    kept = {(k, t): int(v) for k, t, v in RATCHET.findall((root / RUNNER).read_text())}
    rows, printed = {}, collections.Counter()
    for found in DOC_ROW.finditer((root / DOCS).read_text()):
        printed[found[1]] += 1
        rows[found[1]] = (int(found[2]), int(found[3]), int(found[4]))
    problems = []
    # A dict comprehension over `finditer` is last-match-wins, and `DOC_ROW` is
    # anchored to no heading — a second table repeating a tier would quietly
    # decide the check. Counted instead, so the duplicate is the finding.
    for tier, times in sorted(printed.items()):
        if times > 1:
            problems.append(
                f"{DOCS} prints {times} rows for `{tier}`; only one may say what"
                " the tree carries"
            )
    for tier, crates in sorted(table.items()):
        counts = (sum(harnesses[c] for c in crates), sum(covers[c] for c in crates))
        for kind, want, shape in (
            ("FLOOR", counts[0], "#[kani::proof]"),
            ("COVERS", counts[1], "kani::cover!"),
        ):
            got = kept.get((kind, tier))
            if got != want:
                # Named, not `=None`: the message used to point at a file that
                # plainly reads `FLOOR_pr=49` and call it None.
                reads = (
                    f"{kind}_{tier} is not written there"
                    if got is None
                    else f"{kind}_{tier}={got}"
                )
                problems.append(
                    f"scripts/kani.sh: {reads}, and the crates on that tier carry"
                    f" {want} {shape}"
                )
        if tier not in rows:
            problems.append(f"{DOCS}'s tier table has no `{tier}` row to check")
        elif rows[tier] != (len(crates), *counts):
            problems.append(
                f"{DOCS} prints {rows[tier]} for `{tier}`; the tree has"
                f" {(len(crates), *counts)} (crates, harnesses, covers)"
            )
    return problems


def audit(root):  # noqa: C901 — one clause per failure mode, each named
    """(problems, one-line summary) for how this checkout points Kani at its tree."""
    root = pathlib.Path(root)
    table = tiers(root)
    found = list(sources(root))
    seen = [u for s in found if s.ci for u in uses(s.path, s.text, s.read)]
    loose = sorted({pair for s in found for pair in handwritten(s.path, s.text, s.read)})
    harnesses, covers, orphans, unseen = crates_with_proofs(root)
    proven = set(harnesses)
    problems = []
    # Only for a key a `scripts/kani.sh ${{ matrix.… }}` actually names: the fuzz,
    # miri and mutants rows all shard on a `matrix.shard` of their own, and their
    # differing lists say nothing about what Kani proves.
    for source in found:
        if is_workflow(source.read):
            conflicts = matrices(source.text)[1] & referenced_keys(source.text)
            for key in sorted(conflicts):
                problems.append(
                    f"{source.path} declares `matrix.{key}` twice with different values; "
                    "which tiers a row proves would be a guess"
                )

    for line in unseen:
        problems.append(
            f"{line}, so every floor it belongs to would sit one too low;"
            " write harnesses `#[kani::proof]` and covers `kani::cover!`"
        )
    for crate in sorted(set(covers) - proven):
        problems.append(f"{crate} has a kani::cover! but no #[kani::proof] to reach it")
    for rel, spelled in loose:
        problems.append(
            f"{rel} writes its own `cargo kani` roster (`{spelled}`); scripts/kani.sh"
            " owns the tiers, and a second copy is one nothing keeps in step"
        )
    for use in seen:
        if use.tier not in table and use.tier != "--tiers":
            problems.append(
                f"{use.path} runs `scripts/kani.sh {use.tier}`, which is not a tier"
            )
    run_by_ci = {u.tier for u in seen if u.executed and u.tier in table}
    covered = frozenset().union(frozenset(), *(table[t] for t in run_by_ci))
    for tier in sorted(table):
        # FULL is the roster anchor, not a row of its own: the daily run splits it
        # into halves so the one that can exhaust the runner's memory takes only
        # its own crates down. It is satisfied when the rows that DO run prove
        # every crate it names — and only then. Every other tier still owes a row,
        # which is what keeps this from becoming a way to retire one quietly.
        split = tier == FULL and table[tier] <= covered
        if tier not in run_by_ci and not split:
            problems.append(
                f"no CI row runs the `{tier}` tier: it is in no step's `run:`, or"
                " that line is commented out — a tier nobody runs proves nothing"
            )
        if not [u for u in seen if u.tier == tier and u.path == DOCS]:
            problems.append(
                f"{DOCS} does not carry the `{tier}` tier; it is what a reader"
                " copies, and it says CI runs the same commands"
            )

    if FULL not in table:
        problems.append(f"scripts/kani.sh no longer defines the `{FULL}` tier")
        table[FULL] = frozenset()
    listed = table[FULL]
    for crate in sorted(proven - listed - set(EXCLUDED)):
        problems.append(f"{crate} has a #[kani::proof] that no CI row runs")
    for crate in sorted(listed - proven):
        problems.append(f"{crate} is on the `{FULL}` tier but has no #[kani::proof]")
    for crate in sorted(set(EXCLUDED) - proven):
        problems.append(f"{crate} is excluded but has no #[kani::proof] to exclude")
    for crate in sorted(set(EXCLUDED) & listed):
        problems.append(f"{crate} is both excluded and on the `{FULL}` tier")
    for tier, crates in sorted(table.items()):
        if not crates:
            problems.append(f"the `{tier}` tier is empty; it would prove nothing")
        for crate in sorted(crates - listed):
            problems.append(f"{crate} is on the `{tier}` tier but not on `{FULL}`")
    for rel in orphans:
        problems.append(f"{rel} has a #[kani::proof] or kani::cover! no tier can reach")
    problems += ratchets(root, table, harnesses, covers)
    problems += ledger_claims(root, harnesses)

    pinned = workflow_pins(root)
    said = sorted({value for values in pinned.values() for value in values})
    loose = sorted(
        f"{rel} ({value})"
        for rel, values in pinned.items()
        for value in values
        if not PINNED.fullmatch(value)
    )
    got = DOC_PIN.search((root / DOCS).read_text())
    if not pinned or loose:
        problems.append(
            f"{PIN_VAR} is not pinned in the workflow"
            + (f": {', '.join(loose)}" if loose else "")
        )
    elif len(said) > 1:
        # The half a one-file read cannot have. Three literals agreeing is what
        # makes any of them the version CI installs; two that disagree make the
        # tier a reader copies and the tier CI runs different tools.
        problems.append(
            f"{PIN_VAR} is written {sum(len(v) for v in pinned.values())} time(s)"
            f" across {len(pinned)} workflow file(s) and they disagree — "
            + "; ".join(
                f"{rel} pins {', '.join(sorted(set(values)))}"
                for rel, values in sorted(pinned.items())
            )
        )
    elif not got:
        problems.append(f"{DOCS} installs kani-verifier without --version")
    elif got.group(1) != said[0]:
        problems.append(f"{DOCS} installs kani {got.group(1)}, CI pins {said[0]}")

    summary = (
        f"kani-gate: ok — {len(table)} tiers over {len(listed)} crates, "
        f"{sum(harnesses[c] for c in listed)} harnesses and "
        f"{sum(covers[c] for c in listed)} kani::cover! counted from source, "
        f"excluded: {', '.join(EXCLUDED)}"
    )
    return problems, summary


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("kani-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA crate absent from the `all` tier is not proven, and the row that\n"
            "says it proves every harness stays green either way. Add it to\n"
            "scripts/kani.sh and to assurance/reports/testing-evidence.md, or record it in EXCLUDED with\n"
            "the measured reason."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
