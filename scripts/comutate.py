#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Co-refutation: inject each model mutant's defect into the Rust, expect red.

The security module's original 28 `Bug*` switches and the later store, admin,
display and transport modules each rebuild a real RS-Key defect, and the TLC
matrix proves the MODEL catches every one.
Nothing measured whether the code level — the unit tests, on the same defect —
catches them too. Three green checkers over three slightly different systems is
the failure mode this whole apparatus exists for, and the difference between
the two answers is a measured abstraction gap with a file and line attached.

The roster is `Mut_*`, `StoreMut_*`, `AdminMut_*`, `DispMut_*`, `TransMut_*`, —
since the applet batch — `SeamMut_*`, `LatMut_*`, `PolicyMut_*`, and `BootMut_*`.
The applet batch was the answer to a measured skew: 31 of the first 43 patches
landed in `rsk-fido`, `rsk-device` and `rsk-fs`, and the four applet crates that
four of the nine modules are written about held ZERO. "TLC is green over the
applets" was therefore fidelity nobody had measured, not fidelity measured and
found good.

`BootMut_*` was the FOURTH exclusion until its three switches were registered,
and how it fell is the point of writing exclusions down. The stated ground was
that two of its three defended sites live in `firmware/`, which has no host
tests by construction. Only one did: the scratch-word carry's model conjunct is
`lock' = recorded`, and that assignment is `restore_pin_lock` at
crates/rsk-fido/src/state.rs:449-452 — `firmware/src/pin_lock.rs` holds the
register encode, not the restore. The marker-after-lap order really was in
`firmware/`, where a patch could not have scored a kill in any case since a
build failure is classified `build-broke` below, so it was lifted into
`crates/rsk-fs` to be measurable at all. An exclusion reasoned about the MODULE
read as covering three sites nobody had opened, and `roster()` matching no
prefix made that reading unfalsifiable in BOTH directions. `test_comutate.py`
drives an unregistered `BootMut_*.cfg` through `lint()` now, so the tuple below
is wiring a test holds rather than prose.

Three families remain DELIBERATELY out, because an exclusion stated here is a
plan and one implied by a glob is a hole:

* `LiveMut_*` and `FairMut_*` — these are not defect switches. They break a
  LIVENESS property or the fairness shape under it, and the code-level question
  co-refutation asks ("does the same defect fail a host test?") has no meaning
  for a temporal property no unit test states. Named here rather than left to
  the glob, because the glob was how they were out before: `roster()` simply did
  not match them, which is the shape of hole this file exists to refuse.

* `TokenGateMut_*` — tier A's mutant edits `AllowedEventRel` itself, and no
  production function's body IS that relation. A code twin would have to be
  invented rather than found, and an invented twin is a second model wearing a
  patch. What tier A's edge asserts about the code is already carried by the
  eleven `Mut_*` twins of this property, one of which now reddens its Kani
  harness as well as the unit suite.

`formal/comutants.toml` holds one entry per mutant: a `patch` (exact-snippet
find/replace — the defect, re-made in today's code), `unreachable` (the defect
became unreachable by construction after a shipped fix; the model measured it
and the evidence field says where), or `pending` (batch not yet derived,
floored so the count only goes down).

A `patch` may additionally carry a `proof` — a second command, run in the same
worktree after the slice killed, plus the `proof_names` string one of its failed
checks must carry. It exists because 0 of the 67 slices ran `cargo kani`, so no
Kani harness in this tree was reddened by any recorded mutant: a proof falsified
by nothing is the same shape as a guard whose wiring nothing exercises. The
`--target <host>` this file appends goes on a `cargo test` and nowhere else —
`cargo kani` has no such flag — and two TOOL LIMITS (a CBMC timeout, an
unsupported construct) end in the same `VERIFICATION:- FAILED` a real refutation
does, so both are refused by name rather than counted as kills.

Which is only half of it, because for its first life nothing compared that name
to the tree. `--harness` took any string, `-p` took any package, and the patch
could land in a crate that package never compiles — three ways to record a RED
that cannot happen, all of which come back `proof-survived` once a quarter and
none of which a gate row could see. [`proof_problems`] is the three rules, and
a name search is not one of them: `--harness` must resolve to a real
`#[kani::proof]` DECLARED BY the package `-p` names.

The lint closes those three statically and the fourth cannot be closed there at
all: a tool that does not RUN on the host reaches no verdict, and `proof-survived`
was read off the absence of a failure, so "the harness stayed green" and "the
harness never answered" were one word. Measured on the first CI run of this half
— `BugCmWalkIgnoresChannel` reddens `NoAuthorizationBypass/B1` on the maintainer's
host and came back `proof-survived` from the Linux runner. `VERIFICATION:-
SUCCESSFUL` is the only thing that verdict is read off now; anything else is
`proof-broke` carrying the tool's own line.

Three modes:

* `--lint` — the cheap closed-world half, a `check.sh` row. Every `Mut_*.cfg`
  has exactly one entry and vice versa; every patch anchor resolves exactly
  once in the current tree (drifted code fails loudly instead of patching the
  wrong place); every patch names a slice and an expected verdict; the pending
  count is at most the recorded floor. It also derives each mutant's target
  invariant from its own `Solo_*.cfg` — this file deliberately does not record
  it, so it cannot disagree with the matrix.
* `run [<Bug>]` — the measurement. A throwaway `git worktree` gets the
  patch, the slice runs there (sharing the main target dir — sequential, and a
  cold per-worktree build would cost more than the tests), the verdict is
  KILLED if any slice command fails, GAP if all stay green. The verdict must
  equal `expect`: a killed that came back green is a regression in exactly the
  sense floors.txt gives that word.
* `run --write-readme` — the same full measurement, followed by publication of
  the roadmap's original 28-row fidelity table. It refuses to publish from a
  partial run; ordinary lint then rejects table drift. The full roster runs in
  the weekly `deep-checks` workflow alongside `cargo-mutants`.

Deliberately NOT in `run`: fuzz targets (sampling is not a deterministic kill)
and full Kani tiers (minutes-per-harness belongs in the weekly row, and the
sequence proofs' own falsifiability is measured by their own table).
"""

import functools
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = ROOT / "formal" / "comutants.toml"
README_START = "<!-- phase2-comutants:start -->"
README_END = "<!-- phase2-comutants:end -->"

STATUSES = {"patch", "unreachable", "pending"}


def load(root: pathlib.Path):
    with open(root / "formal" / "comutants.toml", "rb") as fh:
        data = tomllib.load(fh)
    return (
        data.get("pending_floor", 0),
        data.get("phase2_count", 28),
        data.get("comutant", {}),
    )


#: The mutant-config prefixes this file's closed world covers, and the Solo
#: prefix each pairs with. Liveness and fairness prefixes are deliberately
#: absent — see the module docstring.
PREFIXES = (
    ("Mut_", "Solo_"),
    ("StoreMut_", "StoreSolo_"),
    ("AdminMut_", "AdminSolo_"),
    ("DispMut_", "DispSolo_"),
    ("TransMut_", "TransSolo_"),
    ("SeamMut_", "SeamSolo_"),
    ("LatMut_", "LatSolo_"),
    ("PolicyMut_", "PolicySolo_"),
    ("BootMut_", "BootSolo_"),
)


def roster(root: pathlib.Path) -> dict[str, str]:
    """bug name -> its mutant configuration's filename, over every prefix.

    `startswith` is anchored, so `Mut_` does not swallow `StoreMut_*.cfg` or
    `SeamMut_*.cfg` (an 'S' is not an 'M'), `BootMut_` does not swallow the
    `BootCarryMut_*.cfg` and `BootInductionMut_*.cfg` that re-arm the same three
    switches under other bounds — they would collide on the roster key — and no
    prefix matches `LiveMut_` or `FairMut_`.

    The keys are bug names with the prefix stripped, so two families sharing a
    bug name would silently collapse to one entry — see `prefix_collisions`,
    which the lint runs before trusting anything this returns.
    """
    out: dict[str, str] = {}
    for p in sorted((root / "formal").glob("*.cfg")):
        for mut_pre, _ in PREFIXES:
            if p.name.startswith(mut_pre):
                out[p.stem.removeprefix(mut_pre)] = p.name
    return out


def orphan_solos(stems) -> list[str]:
    """`Bug*` Solo configurations with no mutant of their own family.

    The other half of the same closed world. `solo_invariant` resolves a bug by
    walking the families and keeping the LAST Solo file that exists, so a stray
    `<Family>Solo_<Bug>.cfg` — a leftover rename, or a Solo written ahead of its
    mutant — silently STEALS the invariant another family's mutant is judged by,
    and `roster` never sees it because the stem matches no `Mut_` prefix. Only
    `Bug*` stems are paired: `Solo_<Invariant>.cfg` and `SoloClause_*.cfg` are
    solo runs of an invariant or a clause, which have no mutant by design.
    """
    have = set(stems)
    out: list[str] = []
    for stem in sorted(have):
        for mut_pre, solo_pre in PREFIXES:
            if stem.startswith(solo_pre):
                bug = stem.removeprefix(solo_pre)
                if bug.startswith("Bug") and f"{mut_pre}{bug}" not in have:
                    out.append(
                        f"{stem}.cfg has no {mut_pre}{bug}.cfg — a Solo without "
                        "its own mutant steals the invariant that mutant is "
                        "judged by"
                    )
    return out


def prefix_collisions(stems) -> list[str]:
    """Problem lines for configuration stems two prefixes map onto ONE key.

    Eight families share one name space, and `roster` keys on the name with its
    prefix stripped: a second `BugX` under another prefix does not collide
    loudly, it OVERWRITES. Both closed-world directions then stay green over a
    roster holding one fewer mutant — the exact silent-shrink shape floors.txt
    exists for, one layer up. The families are disjoint today; this is what
    keeps them so when a tenth module reuses a good name.
    """
    seen: dict[str, str] = {}
    out: list[str] = []
    for stem in sorted(stems):
        for mut_pre, _ in PREFIXES:
            if stem.startswith(mut_pre):
                bug = stem.removeprefix(mut_pre)
                if bug in seen:
                    out.append(
                        f"{stem}.cfg and {seen[bug]}.cfg are one roster key "
                        f"({bug}) — rename one"
                    )
                seen[bug] = stem
    return out


def phase2_entries(root: pathlib.Path, entries: dict) -> list[tuple[str, dict]]:
    """The original 28 FIDO mutants, excluding later module extensions."""
    cfgs = roster(root)
    return sorted(
        (bug, entry)
        for bug, entry in entries.items()
        if cfgs.get(bug, "").startswith("Mut_")
    )


def solo_invariants(root: pathlib.Path, bug: str, index=None) -> list[str]:
    """Every invariant a solo-style configuration proves this bug breaks.

    [`solo_invariant`] answers with ONE, resolved by filename, and that is the
    name the published table column takes. It is not the whole evidence: a
    configuration named after the INVARIANT rather than the bug —
    `Solo_RamNeverOutlivesFlashSeed.cfg` — arms a switch too, and where it arms
    THIS one and nothing else its RED is the same proof under another filename.
    Measured before this existed: two bugs were credited with one invariant each
    while the tree carried five more, and FOUR of the six P0-launch rows reading
    `co = 0` had a killed code twin standing in one of them.

    Armed ALONE is the whole condition, not a nicety. `Solo_BugSetPinKeepsPpuat
    .cfg` arms a companion switch as well — the shipped seed-lead makes its own
    defect unreachable otherwise — and reading that as evidence for the companion
    credits `BugPpuatIsAGate` with an invariant it does not break. The first
    measurement said five bugs were under-credited; with this condition it says
    two, and the difference is exactly the two-armed pairs.

    What the column means after this is worth stating, because it is one axis and
    not two: that a faithful defect of this property exists at both levels and the
    suite kills the code half. It does not say the killing TEST is a test of this
    property. That is a stronger claim, it has no column, and inventing one here
    would be the false ladder §4.1 refuses.

    The parse is `verdict_gate.Config`'s, not a second copy: it already reads a
    configuration's armed switches and decides solo-style from the INVARIANTS
    block, and two parsers disagreeing about one file is the defect one directory
    over.

    `index` is the whole-tree pass [`solo_index`] does, handed in by a caller that
    asks about every bug — the 67 killed entries against 201 configurations is
    13 000 parses if each call rescans, and this runs inside a gate row.

    One asymmetry, and it stopped being harmless: the subject rule is the INDEX's,
    so the filename half accepts what the index would refuse. Both two-armed
    configurations (`Solo_BugSetPinKeepsPpuat.cfg`,
    `Solo_BugBackupSealedNotAGate.cfg`) are read by name, and this comment used to
    say that was "not live — both bugs are `status = unreachable`, so neither
    reaches the column". One of them stopped being unreachable and the sentence
    stayed. The index reads the pair now too, through [`armed_subject`] — which is
    what the filename half was quietly doing all along. The difference is that the
    index also reaches a configuration named after the INVARIANT, and that is
    where `SEC-FIDO-006C`'s evidence had been sitting unread.
    """
    if index is None:
        index = solo_index(root)
    named = solo_invariant(root, bug)
    out = [named] if named else []
    return out + [inv for inv in index.get(bug, []) if inv != named]


#: `companion_bug`'s case arms in `formal/gen-configs.sh`. A companion is a
#: REACHABILITY aid and not a second defect: the shipped tree makes the mutant's
#: own defect unreachable, so its configuration rebuilds the older tree beside it.
#: Read out of the generator rather than restated here, because the generator is
#: where a third pair would be added and a copy is what this tree keeps finding
#: rotted.
COMPANION_ARM = re.compile(
    r"^\s*(Bug[A-Za-z0-9_]+)\)\s*echo\s+(Bug[A-Za-z0-9_]+)\s*;;", re.M
)


@functools.cache
def companions(root: pathlib.Path) -> dict[str, str]:
    """bug -> the switch its configurations arm beside it, from the generator."""
    try:
        text = (root / "formal" / "gen-configs.sh").read_text(encoding="utf-8")
    except OSError:
        return {}
    body = text.partition("companion_bug()")[2].partition("\n}")[0]
    return dict(COMPANION_ARM.findall(body))


def armed_subject(config, companion: dict[str, str]) -> str | None:
    """Which bug a configuration is ABOUT, or None if that is not decidable.

    One armed switch is the whole answer. Two is the answer as well when the
    second is the first's COMPANION -- `SoloClause_ResetKeepsTheBackupSeal.cfg`
    arms `BugBackupSealedNotAGate` with `BugSeedDoesNotLead` beside it, because
    the shipped seed-lead makes the defect unreachable alone, and refusing that
    pair left the clause it is named for reading `co = 0` on the very commit that
    drove its code twin. Anything else is None: a configuration arming two real
    defects says which one fired, not which property either breaks.

    The companion is never the subject. Crediting it would give `BugPpuatIsAGate`
    an invariant it does not break, which is the defect the armed-alone condition
    was written against and which this rule keeps out.
    """
    if len(config.armed) == 1:
        return config.armed[0]
    if len(config.armed) != 2:
        return None
    first, second = config.armed
    if companion.get(first) == second:
        return first
    if companion.get(second) == first:
        return second
    return None


def solo_index(root: pathlib.Path) -> dict[str, list[str]]:
    """bug -> the invariants of every solo-style configuration arming it ALONE.

    One pass over `formal/*.cfg`, and no memo of its own — `assurance_gate
    .co_refuted` is already `@functools.cache`d on the same key, which is why its
    tests call `cache_clear()`, so a second one here would cache a cache. Anything
    calling this directly gets the tree as it stands now.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import verdict_gate

    out: dict[str, list[str]] = {}
    for cfg in sorted((root / "formal").glob("*.cfg")):
        try:
            config = verdict_gate.Config(cfg)
        except (OSError, UnicodeDecodeError):
            continue
        # `not disarmed` is what keeps a CONTROL from being read as a kill: a
        # configuration that switches an observer OFF expects GREEN, and
        # `verdict_gate.Config.want` says so. Not live today — the one such
        # configuration, `TraceSecurityBadAlphaNoR4b.cfg`, escapes only because it
        # checks three invariants and so is not solo-style — but the pattern exists
        # in this tree and the next solo-style one would be credited as evidence.
        subject = armed_subject(config, companions(root))
        if subject and not config.disarmed and config.solo and config.targets:
            found = out.setdefault(subject, [])
            if config.targets[0] not in found:
                found.append(config.targets[0])
    return out


def solo_invariant(root: pathlib.Path, bug: str) -> str | None:
    solo = None
    for _, solo_pre in PREFIXES:
        candidate = root / "formal" / f"{solo_pre}{bug}.cfg"
        if candidate.is_file():
            solo = candidate
    if solo is None:
        return None
    names = [
        line.strip()
        for line in solo.read_text().splitlines()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.strip())
        and line.strip() not in ("TypeOK", "INVARIANTS", "SPECIFICATION", "CONSTANTS")
    ]
    return names[-1] if names else None


def patch_sites(entry: dict):
    """(file, find, replace) for every site the entry patches, in order.

    Two forms. The flat one — `file` plus `find`/`replace`, `find2`/`replace2`, …
    with no ceiling — is ONE file with several anchors, which is what most
    switches need. A switch that guards one rule at call sites in DIFFERENT files
    uses the `[[comutant.X.site]]` array instead: `BugAdminOpensKeyOps` is
    quantified over PW1 and PW2 and lands on four gates across two files, and
    while an entry could name only one file it patched what fitted and left the
    rest in prose — honest, and still unmeasured.

    `anchor_shape_problems` refuses the ways either form goes quietly wrong.
    """
    if "site" in entry:
        for site in entry["site"]:
            yield site["file"], site["find"], site.get("replace", "")
        return
    yield entry["file"], entry["find"], entry.get("replace", "")
    n = 2
    while f"find{n}" in entry:
        yield entry["file"], entry[f"find{n}"], entry.get(f"replace{n}", "")
        n += 1


def anchor_fields(where: str, what: str, holder: dict, keys) -> list[str]:
    """The anchor keys `holder` does not answer with a non-empty string.

    Both forms read `file` and `find` by SUBSCRIPT, and only the `[[site]]` half
    was ever held to answering them: a flat entry missing `file` left the gate row
    printing `KeyError: 'file'` out of `patch_sites`, and `find = ["a", "b"]` —
    the shape an author reaches for when one anchor is not enough — a `TypeError`
    out of `str.count`. A traceback is not a finding: it names a line of this
    file and not the entry a reader has to go fix.
    """
    out: list[str] = []
    for key in keys:
        value = holder.get(key)
        if not isinstance(value, str) or not value:
            out.append(
                f"{where}: {what} has no {key!r} — an anchor field is a non-empty"
                f" string and this one is {value!r}"
            )
    return out


def anchor_shape_problems(bug: str, entry: dict) -> list[str]:
    """The ways an entry's anchors are silently not applied.

    Every one of these leaves a patch that reads as covering its switch and does
    less: the numbering walk stops at the first gap, so a `find3` written without
    a `find2` never runs; a `replace4` whose `find4` was renamed away edits
    nothing; and an entry carrying both forms would have its flat half ignored
    entirely. A cap of three anchors used to make the first two impossible by
    construction — lifting it is what puts them in reach.

    The rest is the same asymmetry read the other way: the `[[site]]` half's own
    fields were validated and the flat half's were not, so the form MOST entries
    use was the one whose holes came out as a traceback. [`anchor_fields`] is one
    rule over both.
    """
    where = f"comutants.toml [{bug}]"
    out: list[str] = []
    numbered = {
        int(k.removeprefix("find")) for k in entry if re.fullmatch(r"find\d+", k)
    }
    replaces = {
        int(k.removeprefix("replace")) for k in entry if re.fullmatch(r"replace\d+", k)
    }
    if "site" in entry:
        for key in ("file", "find", "replace", *(f"find{n}" for n in numbered)):
            if key in entry:
                out.append(
                    f"{where}: carries both a [[site]] array and a top-level "
                    f"{key!r} — the flat half would never be applied"
                )
        sites = entry["site"]
        # `[comutant.X.site]` with ONE bracket pair is a table, not an array of
        # them, and the walk below then reads its KEYS as sites — `'str' object
        # has no attribute 'get'`, out of the rule written to report the hole.
        if not isinstance(sites, list) or not all(isinstance(s, dict) for s in sites):
            out.append(
                f"{where}: `site` is {type(sites).__name__} and not an array of"
                " tables — `[[comutant.X.site]]` takes two bracket pairs, and one"
                " makes it a table whose keys the walk would read as sites"
            )
            return out
        for i, site in enumerate(sites, 1):
            out.extend(anchor_fields(where, f"site {i}", site, ("file", "find")))
        return out
    out.extend(
        anchor_fields(
            where,
            "the flat form",
            entry,
            ("file", "find", *(f"find{n}" for n in sorted(numbered))),
        )
    )
    if numbered and sorted(numbered) != list(range(2, max(numbered) + 1)):
        out.append(
            f"{where}: anchors {sorted(numbered)} are not contiguous from 2 — "
            "the walk stops at the first gap, so the rest never applies"
        )
    for n in sorted(replaces - numbered):
        out.append(f"{where}: replace{n} has no find{n} — it edits nothing")
    return out


def code_status(entry: dict, measured: str | None = None) -> str:
    if entry.get("status") == "patch":
        verdict = measured or entry.get("expect", "?")
        return "co-refuted" if verdict == "killed" else verdict
    return entry.get("status", "?")


def phase2_block(
    root: pathlib.Path, entries: dict, measured: dict[str, str] | None = None
) -> str:
    rows = phase2_entries(root, entries)
    counts: dict[str, int] = {}
    lines = [
        README_START,
        "<!-- Generated by scripts/comutate.py run --write-readme; do not edit. -->",
        "| # | Mutant | Target invariant | Model | Code level |",
        "|---:|---|---|---|---|",
    ]
    for number, (bug, entry) in enumerate(rows, 1):
        status = code_status(entry, (measured or {}).get(bug))
        counts[status] = counts.get(status, 0) + 1
        lines.append(
            f"| {number} | `{bug}` | `{solo_invariant(root, bug) or '?'}` | "
            f"RED | **{status}** |"
        )
    total = len(rows)
    lines.extend(
        (
            "",
            "**Measured phase-2 fidelity:** "
            f"{counts.get('co-refuted', 0)}/{total} code-level kills; "
            f"{counts.get('unreachable', 0)} unreachable by construction; "
            f"{counts.get('gap', 0)} open gaps; {counts.get('pending', 0)} pending.",
            README_END,
        )
    )
    return "\n".join(lines)


def replace_readme_block(text: str, block: str) -> str:
    if text.count(README_START) != 1 or text.count(README_END) != 1:
        raise ValueError("formal/README.md needs exactly one phase-2 table marker pair")
    start = text.index(README_START)
    end = text.index(README_END, start) + len(README_END)
    return text[:start] + block + text[end:]


def check_readme(root: pathlib.Path, entries: dict, problems: list[str]) -> None:
    path = root / "formal" / "README.md"
    if not path.is_file():
        problems.append("formal/README.md is missing — no phase-2 fidelity table")
        return
    text = path.read_text()
    try:
        want = replace_readme_block(text, phase2_block(root, entries))
    except ValueError as error:
        problems.append(str(error))
        return
    if text != want:
        problems.append(
            "formal/README.md phase-2 fidelity table is stale — run "
            "python scripts/comutate.py run --write-readme"
        )


def flag_value(argv, flag: str) -> str | None:
    """The token after `flag` in a command line, or None when it is absent or last.

    Token form only. `--harness=x` is deliberately unread: [`lint`] refuses an
    entry whose `proof` does not carry `--harness` as its own token, so a reader
    for the other spelling is a branch nothing here can take — the rule
    `bundle_gate` states as covering spellings this tree does not use.
    """
    for i, token in enumerate(argv):
        if token == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def workspace_packages(root: pathlib.Path) -> dict[str, str]:
    """package name -> its member directory, out of `[workspace] members`.

    `-p` takes the PACKAGE and the directory need not spell it, so both halves
    are read off the manifests rather than one inferred from the other.
    """
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for rel in manifest["workspace"]["members"]:
        member = tomllib.loads((root / rel / "Cargo.toml").read_text(encoding="utf-8"))
        out[member["package"]["name"]] = rel
    return out


def crate_sources(root: pathlib.Path, rel: str) -> list[pathlib.Path]:
    """One member's `.rs` files. `target/` under a member is output, not source."""
    base = root / rel
    return sorted(
        p for p in base.rglob("*.rs") if "target" not in p.relative_to(base).parts
    )


def crate_of(packages: dict[str, str], path: str) -> str | None:
    """The workspace package whose directory holds `path`, longest member first."""
    best = None
    for crate, rel in packages.items():
        if path == rel or path.startswith(rel.rstrip("/") + "/"):
            if best is None or len(packages[best]) < len(rel):
                best = crate
    return best


#: The manifest tables a dependency can be written in. Dev and build count, and
#: so does `optional = true`: the question [`workspace_edges`] answers is whether
#: `cargo kani -p <crate>` COULD compile a patch over there, and a refusal is
#: only honest when the answer is no under every feature selection.
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def workspace_edges(root: pathlib.Path, packages: dict[str, str]) -> dict[str, set[str]]:
    """crate -> the workspace crates its manifest names, in any dependency table."""
    out: dict[str, set[str]] = {}
    for crate, rel in packages.items():
        manifest = tomllib.loads((root / rel / "Cargo.toml").read_text(encoding="utf-8"))
        holders = [manifest, *manifest.get("target", {}).values()]
        out[crate] = {
            dep
            for holder in holders
            for table in DEP_TABLES
            for dep in holder.get(table, {})
            if dep in packages
        }
    return out


def visible_from(root: pathlib.Path, packages: dict[str, str], crate: str) -> set[str]:
    """`crate` and every workspace crate reachable from it — what `-p` compiles."""
    edges = workspace_edges(root, packages)
    seen, todo = {crate}, [crate]
    while todo:
        for dep in edges.get(todo.pop(), set()) - seen:
            seen.add(dep)
            todo.append(dep)
    return seen


def kani_harnesses(root: pathlib.Path, packages: dict[str, str]) -> dict[str, set[str]]:
    """crate -> the `#[kani::proof]` harnesses its own sources declare.

    `bundle_gate.declarations` does the reading rather than a second Rust parser
    here, and the defect it was written against is exactly the one a substring
    match would leave open: `credmgmt_kani.rs` NAMES a harness of another file
    in a doc comment, and what a file mentions is not what it declares.

    Only the files carrying the attribute at all are parsed — 29 of the tree's
    399 `.rs` today; the rest cannot declare a harness.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import bundle_gate

    out: dict[str, set[str]] = {}
    for crate, rel in packages.items():
        found: set[str] = set()
        for path in crate_sources(root, rel):
            if "kani::proof" in path.read_text(encoding="utf-8", errors="replace"):
                found |= bundle_gate.declarations(path)[1]
        out[crate] = found
    return out


def declaring_file(root: pathlib.Path, rel: str, name: str) -> str | None:
    """The member's file declaring `name` as an item, or None.

    Reached only once the harness did not resolve, and only to tell the two ways
    that happens apart: a name nobody wrote, and a name that IS an item of the
    crate carrying no `#[kani::proof]`. `cargo kani --harness` matches neither,
    and the second is the one that reads like evidence — `::STEPS` and
    `::StepRng` are both live items of the file this entry's harness lives in.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import bundle_gate

    for path in crate_sources(root, rel):
        if name in path.read_text(encoding="utf-8", errors="replace"):
            if name in bundle_gate.declarations(path)[0]:
                return str(path.relative_to(root))
    return None


def proof_world(root: pathlib.Path) -> tuple[dict[str, str], dict[str, set[str]]]:
    """(packages, harnesses) — the closed world a `proof` half is resolved in.

    An unreadable workspace manifest yields empty rosters on purpose: `-p` then
    names no member and [`proof_problems`] says so in a line a reader can act
    on, where `KeyError: 'package'` names a line of this file instead. The
    fallback is not silent — it cannot make the row green.
    """
    try:
        packages = workspace_packages(root)
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return {}, {}
    return packages, kani_harnesses(root, packages)


def proof_problems(
    root: pathlib.Path,
    bug: str,
    entry: dict,
    packages: dict[str, str],
    harnesses: dict[str, set[str]],
) -> list[str]:
    """The ways a `proof` half records a RED that cannot happen.

    The field exists so a kill is credited to a Kani harness, and until this ran
    nothing compared what it holds to the tree: `--harness` took any string, `-p`
    took any package, and the patch could land in a crate that package never
    compiles. Every one of the three ends the same way at run time — the harness
    is not built or not reached, `proof_verdict` reads `proof-broke`, and the
    entry's `expect = "killed"` fails for a reason that is about the RECORD and
    not about the code. That verdict is a weekly row; this is the gate row.

    What it still does not say: that the harness's property is the mutant's. That
    is `proof_names`' job at run time, and inventing a static answer here would be
    the false ladder the module docstring refuses.
    """
    where = f"comutants.toml [{bug}]"
    proof = entry["proof"]
    crate = flag_value(proof, "-p")
    harness = flag_value(proof, "--harness")
    known = crate in packages
    out: list[str] = []
    if not known:
        out.append(
            f"{where}: the proof runs `-p {crate}`, which is no workspace member"
            " — cargo answers a package-spec error, and a run that never built a"
            " harness reaches no verdict"
        )
    if known and harness not in harnesses[crate]:
        elsewhere = sorted(c for c, names in harnesses.items() if harness in names)
        if harness is None:
            why = "--harness carries no value — it is absent, or the proof's last token"
        elif elsewhere:
            why = (
                f"--harness {harness} is declared in {', '.join(elsewhere)} and not"
                f" in {crate}"
            )
        elif declared := declaring_file(root, packages[crate], harness):
            why = f"--harness {harness} is {declared}, which carries no #[kani::proof]"
        else:
            why = f"--harness {harness} names no #[kani::proof] in the workspace"
        out.append(
            f"{where}: {why} — `cargo kani -p {crate}` matches no harness, so the"
            " RED this entry records cannot happen"
        )
    if known and not anchor_shape_problems(bug, entry):
        reach = visible_from(root, packages, crate)
        touched = sorted(
            {crate_of(packages, p) or p for p, _find, _replace in patch_sites(entry)}
        )
        if touched and not any(t in reach for t in touched):
            out.append(
                f"{where}: the patch lands in {', '.join(touched)}, which"
                f" `cargo kani -p {crate}` never compiles — the harness would prove"
                " the UNPATCHED code and its colour would say nothing about this"
                " mutant"
            )
    return out


def lint(root: pathlib.Path, check_generated_readme: bool = True) -> list[str]:
    problems: list[str] = []
    floor, phase2_count, entries = load(root)
    # Before the closed world, the name space it is closed over: a collision
    # makes both directions below agree about a roster that is one short, and an
    # unpaired Solo hands a mutant an invariant that is not its own.
    stems = [p.stem for p in (root / "formal").glob("*.cfg")]
    problems.extend(prefix_collisions(stems))
    problems.extend(orphan_solos(stems))
    cfgs = roster(root)

    for bug in sorted(set(cfgs) - set(entries)):
        problems.append(f"{cfgs[bug]} has no comutant entry")
    for bug in sorted(set(entries) - set(cfgs)):
        problems.append(f"comutant {bug} has no mutant configuration — stale entry")

    pending = 0
    # Built on the first proof half and not before: it reads every member
    # manifest and every `.rs` that names the attribute, which is a whole tree
    # walk this row need not pay for while no entry carries one.
    world: tuple[dict[str, str], dict[str, set[str]]] | None = None
    for bug, entry in sorted(entries.items()):
        status = entry.get("status")
        where = f"comutants.toml [{bug}]"
        if status not in STATUSES:
            problems.append(f"{where}: unknown status {status!r}")
            continue
        if status == "pending":
            pending += 1
            continue
        if status == "unreachable":
            if not entry.get("evidence", "").strip():
                problems.append(f"{where}: unreachable without evidence")
            continue
        # status == "patch"
        if not entry.get("slice"):
            problems.append(f"{where}: patch without a slice")
        if entry.get("expect") not in ("killed", "gap"):
            problems.append(f"{where}: expect must be 'killed' or 'gap'")
        if ("proof" in entry) != bool(entry.get("proof_names", "").strip()):
            problems.append(
                f"{where}: a proof and the check it must fell go together — a proof "
                "whose reason nothing compares is a RED nobody read"
            )
        if "proof" in entry:
            if entry.get("expect") != "killed":
                problems.append(f"{where}: a proof half only means anything under expect = 'killed'")
            if "--harness" not in entry["proof"]:
                problems.append(
                    f"{where}: the proof must name --harness — an unrelated harness "
                    "failing in the same run would be credited to this patch"
                )
            if world is None:
                world = proof_world(root)
            problems.extend(proof_problems(root, bug, entry, *world))
        shape = anchor_shape_problems(bug, entry)
        problems.extend(shape)
        if shape:
            continue
        for i, (path, find, _) in enumerate(patch_sites(entry), 1):
            target = root / path
            if not target.is_file():
                problems.append(f"{where}: anchor {i} names no such file {path}")
                continue
            n = target.read_text().count(find)
            if n != 1:
                problems.append(
                    f"{where}: anchor {i} resolves {n} times in {path} — "
                    "the code it names has moved; re-derive the patch"
                )
    if pending > floor:
        problems.append(
            f"{pending} pending comutants over the recorded floor of {floor} — "
            "lower the floor only by deriving patches, never raise it"
        )
    phase2 = phase2_entries(root, entries)
    if len(phase2) != phase2_count:
        problems.append(
            f"phase-2 roster has {len(phase2)} mutants, expected the roadmap's "
            f"fixed {phase2_count}"
        )
    if check_generated_readme:
        check_readme(root, entries, problems)
    return problems


#: What a Kani run prints when a check fell. Two TOOL LIMITS print the same last
#: line -- a CBMC timeout and an unsupported Rust construct -- so a harness that
#: did not converge would score a kill wearing the right colour. Refused by name,
#: which is the same rule `floors.txt`'s invariant column applies one tier up.
PROOF_FAILED = "VERIFICATION:- FAILED"
#: Its other half, and the only thing `proof-survived` may be read OFF. Absence
#: of a failure is not a green harness: a run that never produced either line --
#: a tool that could not load, a build that did not compile, a filter that
#: matched nothing -- left an exit code the old rule answered "stayed green".
PROOF_SUCCEEDED = "VERIFICATION:- SUCCESSFUL"
#: The one line Kani prints per check that ACTUALLY fell. Everything below is
#: read out of these and nothing else: `not currently supported` also appears in
#: a codegen WARNING and in the description of checks that are unreachable, on a
#: run that ends SUCCESSFUL — measured, and it made the first real run of this
#: half report `proof-broke` over a harness that had converged and passed.
PROOF_FELL = "Failed Checks:"
PROOF_TIMED_OUT = "CBMC timed out"
PROOF_NOT_A_KILL = ("not currently supported", "unwinding assertion")

#: The shapes rustc uses to QUOTE THE FILE BACK inside a diagnostic: the `-->`
#: locator, numbered echo lines (`676 | ...`, and `676 | | ...` for a multi-line
#: span), the annotation bars, `= note:`/`= help:` footers, the `...` elision,
#: and the `676 -`/`676 +` pair a structured suggestion renders. Nothing cargo or
#: libtest prints takes any of them, which is what makes this separable: the
#: words below are then read only where a TEST wrote them. Measured, not
#: supposed -- deleting `meta_find` reddens rsk-fs with `error: expected item
#: after doc comment`, whose echo carries that fn's own doc line `/// read that
#: FAILED reads as "no record" here`, and it alone scored the patch `killed`.
RUSTC_QUOTES = re.compile(r"^\s*(?:-->|\.\.\.|\||=|\d+\s*[|+-])")
#: cargo's line when the test binary RAN and died -- a stack overflow, a signal
#: -- so libtest never reached its summary. It has to be answered before the
#: `error:` search below, which matches this cargo line exactly as readily as it
#: matches rustc: measured on an overflow in `rsk-fs` (0 `test result:` lines, 0
#: `FAILED` lines, SIGABRT), and the verdict was `build-broke` over a suite that
#: caught the defect by crashing on it.
TEST_BINARY_DIED = "error: test failed"


def with_target(cmd: list[str], host: str) -> list[str]:
    """`--target <host>` on a `cargo test` and on nothing else."""
    return cmd + ["--target", host] if cmd[:2] == ["cargo", "test"] else list(cmd)


def slice_env(cmd: list[str], root: pathlib.Path) -> dict[str, str]:
    """The environment one slice or proof runs in.

    The dev shell is nix's and the Kani toolchain is not: `cargo kani setup`
    downloads CBMC's own binaries, built against the runner's glibc, and
    `LD_LIBRARY_PATH` puts nix's libraries in front of theirs. Measured on the
    weekly row -- `goto-cc: /lib/x86_64-linux-gnu/libc.so.6: version
    `GLIBC_ABI_DT_X86_64_PLT' not found (required by /nix/store/...-glibc-2.42-61
    /lib/libm.so.6)`, a nix libm beside the system libc, exit 1 and no verdict.
    Dropped for a kani command and kept for every other, because a `cargo test`
    slice is nix-built and its libudev, libpcsclite and libSDL2 are on that path.
    """
    env = {
        **__import__("os").environ,
        # Sequential runs share the main build cache: only the patched
        # crate recompiles, instead of a cold dependency tree per mutant.
        "CARGO_TARGET_DIR": str(root / "target"),
        # `scripts/kani.sh`'s reason, and it applies to any kani slice run
        # from here: on x86_64 a harness that hashes reaches `cpufeatures`'
        # inline-asm CPU probe, which Kani calls unsupported -- a tool limit
        # wearing the shape of a property violation, invisible on aarch64.
        "RUSTFLAGS": (
            __import__("os").environ.get("RUSTFLAGS", "")
            + ' --cfg sha2_backend="soft" --cfg poly1305_force_soft'
            " --cfg sha1_force_soft"
        ).strip(),
    }
    if cmd[:2] == ["cargo", "kani"]:
        env.pop("LD_LIBRARY_PATH", None)
    return env


def run_slice(cmd: list[str], wt: pathlib.Path, root: pathlib.Path, host: str):
    """One command in the worktree, sharing the main build cache.

    `--target` goes on a `cargo test` and nowhere else: `cargo kani` has no such
    flag, answers `error: unexpected argument '--target' found`, and this file's
    own classifier would read that clap error as `build-broke` -- a mutant that
    never ran, recorded as a patch that does not compile.
    """
    cmd = with_target(cmd, host)
    return subprocess.run(
        cmd, cwd=wt, capture_output=True, text=True, env=slice_env(cmd, root)
    )


def tool_said(out: str, width: int = 160) -> str:
    """The one line worth carrying out of a proof run that reached no verdict.

    The FIRST line that says `error`, since cargo and rustc cascade and a driver
    wraps its child's failure in its own -- not anchored, because the child names
    itself first (`cbmc: error while loading shared libraries: ...`). A loader
    message need not carry the word, so otherwise the last thing it said.
    """
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    said = next((l for l in lines if "error" in l.lower()), None)
    said = said or (lines[-1] if lines else "it printed nothing at all")
    return said[:width]


def reached_no_verdict(out: str) -> bool:
    """Neither of Kani's two verdict lines: the harness never answered at all."""
    return PROOF_SUCCEEDED not in out and PROOF_FAILED not in out


def proof_tail(out: str, keep: int = 25) -> str:
    """The tool's own last words, for a run that answered nothing.

    One line of detail named `goto-cc exited with status 1` and not why. Kani
    suppresses a child's output unless the command says `--verbose`, which is why
    the roster's proof does, and the worktree is gone by the next statement.
    """
    lines = [line.rstrip() for line in out.splitlines() if line.strip()]
    head = "  the proof answered nothing; its last words:\n"
    return head + "\n".join(f"  | {line[:200]}" for line in lines[-keep:])


def proof_verdict(out: str, code: int, names: str) -> tuple[str, str] | None:
    """(verdict, detail) when the proof half did NOT redden for its own reason."""
    if PROOF_TIMED_OUT in out:
        return "proof-broke", f"the harness did not converge: {PROOF_TIMED_OUT}"
    fell = [line.strip() for line in out.splitlines() if line.strip().startswith(PROOF_FELL)]
    for line in fell:
        for limit in PROOF_NOT_A_KILL:
            if limit in line:
                return "proof-broke", f"a check fell on a TOOL limit: {limit}"
    if reached_no_verdict(out):
        return "proof-broke", f"the harness reached no verdict: {tool_said(out)}"
    if code == 0 or PROOF_FAILED not in out:
        return "proof-survived", "the harness stayed green under the patch"
    # Scoped to the failed lines for the same reason: Kani lists EVERY check with
    # its description, so `names` appears whether or not that check fell.
    if not any(names in line for line in fell):
        return "proof-wrong-reason", f"a check fell and none of them named {names}"
    return None


def host_triple() -> str:
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    return re.search(r"^host: (\S+)$", out.stdout, re.M).group(1)


def worktree_path(bug: str) -> pathlib.Path:
    """Where one comutant is measured.

    A function rather than a literal because `test_comutate.py` has to arrange a
    stale registration at this exact path; a second typing of it leaves that case
    green over the defect the moment the path moves, which was measured.
    """
    return pathlib.Path("/tmp") / f"rsk-comutant-{bug}"


def run_one(root: pathlib.Path, bug: str, entry: dict, host: str) -> tuple[str, str]:
    """(verdict, detail) for one comutant, measured in a throwaway worktree."""
    wt = worktree_path(bug)
    if wt.exists():
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(wt)], cwd=root, check=False
        )
        shutil.rmtree(wt, ignore_errors=True)
    # --force clears a registration that outlived its directory (a swept /tmp, a
    # reboot) at THIS path only, where `worktree prune` drops a sibling's too. A
    # non-empty directory still refuses, so every other add failure stays loud.
    subprocess.run(
        ["git", "worktree", "add", "--force", "--detach", str(wt), "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    try:
        # The worktree is HEAD, but the point of `run` in the dev loop is to
        # measure the tree in hand — a gap just closed by an uncommitted test
        # must read as killed now, not after a commit. Carry the tracked diff
        # over. (A comutant patch that collides with a staged edit to the same
        # lines is the author's to notice; the anchor check below still fires.)
        diff = subprocess.run(
            ["git", "diff", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        ).stdout
        if diff.strip():
            subprocess.run(
                ["git", "apply", "--whitespace=nowarn"],
                cwd=wt,
                input=diff,
                text=True,
                check=True,
            )
        # Grouped by file, so an entry may patch several: one read and one write
        # each, with every anchor counted BEFORE any of them is applied.
        edits: dict[pathlib.Path, str] = {}
        for path, find, replace in patch_sites(entry):
            target = wt / path
            text = edits.get(target, target.read_text())
            if text.count(find) != 1:
                return "anchor-gone", f"anchor resolves {text.count(find)}× in {path}"
            edits[target] = text.replace(find, replace)
        for target, text in edits.items():
            target.write_text(text)
        r = run_slice(list(entry["slice"]), wt, root, host)
        if r.returncode == 0:
            return "gap", "every slice command stayed green"
        out = r.stdout + r.stderr
        # A compile error is not a kill: the tests never ran, so a broken patch
        # would masquerade as "the tests caught the defect" — which is how
        # BugPpuatIsAGate first read (EF_PAUTHTOKEN is a KeyFid, not a u16).
        #
        # So read the two words only where cargo or libtest WROTE them, never
        # where rustc quoted the file back. Refused the cheaper swap to
        # `any("test result" in l)`: it buys this misclassification's inverse.
        ran = [
            l
            for l in out.splitlines()
            if ("FAILED" in l or "test result" in l) and not RUSTC_QUOTES.match(l)
        ]
        if not ran:
            # That inverse, concretely, and the reason this clause comes first.
            died = [
                l.strip()
                for l in out.splitlines()
                if TEST_BINARY_DIED in l and not RUSTC_QUOTES.match(l)
            ]
            if died:
                return "killed", died[0]
            # Kept broad on purpose: it is also what catches a clap usage error
            # from a malformed slice, which `could not compile` would not.
            if re.search(r"^error(\[E\d+\])?:", out, re.M):
                return "build-broke", "patch does not compile — not a kill"
            ran = ["slice exited nonzero (no test output)"]
        if "proof" not in entry:
            return "killed", ran[-1]
        # THE PROOF HALF. 0 of the 67 slices reddened a Kani harness, so the
        # property's proof was falsified by nothing — the same shape as a guard
        # whose wiring nothing exercises, one layer in.
        proof = run_slice(list(entry["proof"]), wt, root, host)
        text = proof.stdout + proof.stderr
        if reached_no_verdict(text):
            print(proof_tail(text), file=sys.stderr)
        refused = proof_verdict(text, proof.returncode, entry["proof_names"])
        if refused:
            return refused
        named = [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith(PROOF_FELL) and entry["proof_names"] in line
        ]
        return "killed", f"{ran[-1]}; proof: {named[0]}"
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(wt)], cwd=root, check=False
        )


def write_readme(root: pathlib.Path, entries: dict, measured: dict[str, str]) -> int:
    missing = [
        bug
        for bug, entry in phase2_entries(root, entries)
        if entry.get("status") == "patch" and bug not in measured
    ]
    if missing:
        print(
            "comutate: refusing an unmeasured phase-2 table: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    path = root / "formal" / "README.md"
    try:
        text = replace_readme_block(
            path.read_text(), phase2_block(root, entries, measured)
        )
    except (FileNotFoundError, ValueError) as error:
        print(f"comutate: {error}", file=sys.stderr)
        return 1
    path.write_text(text)
    print("comutate: wrote measured phase-2 table to formal/README.md")
    return 0


def run(root: pathlib.Path, only: str | None, write_table: bool = False) -> int:
    problems = lint(root, check_generated_readme=not write_table)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("comutate: lint failed — not running anything", file=sys.stderr)
        return 1
    _, _, entries = load(root)
    host = host_triple()
    failures = 0
    measured: dict[str, str] = {}
    for bug, entry in sorted(entries.items()):
        if only and bug != only:
            continue
        status = entry.get("status")
        inv = solo_invariant(root, bug) or "?"
        if status != "patch":
            if not only:
                print(f"  {bug:<34} {status:<12} {inv}")
            continue
        verdict, detail = run_one(root, bug, entry, host)
        measured[bug] = verdict
        mark = ""
        if verdict != entry["expect"]:
            mark = f"  !! expected {entry['expect']}"
            failures += 1
        print(f"  {bug:<34} {verdict:<12} {inv}  ({detail}){mark}")
    if only and not any(b == only for b in entries):
        print(f"comutate: no such comutant {only}", file=sys.stderr)
        return 2
    if failures:
        print(
            f"comutate: FAIL — {failures} verdict(s) differ from the record",
            file=sys.stderr,
        )
        return 1
    if only is None:
        statuses = [
            code_status(entry, measured.get(bug))
            for bug, entry in phase2_entries(root, entries)
        ]
        print(
            "comutate: phase 2 — "
            f"{statuses.count('co-refuted')}/{len(statuses)} code-level kills, "
            f"{statuses.count('unreachable')} unreachable, "
            f"{statuses.count('gap')} gaps, {statuses.count('pending')} pending"
        )
        if write_table:
            return write_readme(root, entries, measured)
    return 0


def audit(root):
    """(problems, one-line summary) — the --lint half, for the meta-gate."""
    problems = lint(pathlib.Path(root))
    floor, _, entries = load(pathlib.Path(root))
    counts: dict[str, int] = {}
    for e in entries.values():
        counts[e.get("status", "?")] = counts.get(e.get("status", "?"), 0) + 1
    summary = "comutate: ok — " + ", ".join(
        f"{v} {k}" for k, v in sorted(counts.items())
    ) + f"; pending floor {floor}"
    return problems, summary


def main():
    args = sys.argv[1:]
    if args == ["--lint"]:
        problems, summary = audit(ROOT)
        if problems:
            print("comutate:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        print(summary)
        return 0
    if args and args[0] == "run":
        tail = args[1:]
        write_table = "--write-readme" in tail
        names = [arg for arg in tail if arg != "--write-readme"]
        if len(names) > 1 or (write_table and names):
            print(
                "usage: comutate.py --lint | run [<Bug>] | run --write-readme",
                file=sys.stderr,
            )
            return 2
        return run(ROOT, names[0] if names else None, write_table)
    print(
        "usage: comutate.py --lint | run [<Bug>] | run --write-readme",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
