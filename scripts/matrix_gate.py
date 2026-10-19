#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the property × build-configuration matrix against the tree it is about.

Every assurance claim this project makes reads as being about "the firmware",
and the firmware is not one thing. `nix build` produces twenty-two named images,
`firmware/Cargo.toml` carries features no flake package expresses, and
`firmware/boards/` is a third axis under both. A property proved on the default
build is, without a per-configuration disposition, silently asserted about
builds where the thing it is about does not exist — the sharpest case being the
four `no-touch` packages, which remove the physical-consent gate that the
P0-launch authorization properties are about.

So: columns are DERIVED from `nix/firmware.nix`, `firmware/Cargo.toml` and
`firmware/boards/`, rows from `assurance/properties.toml`, and neither is
written down anywhere a hand can edit. `assurance/configurations.toml` holds the
half no derivation can produce — what each cell's disposition IS — and
`docs/assurance-matrix.md` is regenerated from both and diffed, the way
`config_gen_gate.py` diffs `formal/*.cfg`. A new package, a new feature, a new
board or a new P0-family property therefore arrives as forty (or thirty-one)
`gap` cells in a file that no longer matches its generator, which is the row
going red.

The five dispositions are the roadmap's: `covered`, `equivalent`, `conditional`,
`out-of-scope`, `gap`. A cell with anything else is refused, and so is an
`equivalent` cell whose basis is missing — that pair is the whole point of the
row, because "the names look similar" is exactly how a false equivalence gets
written. `equivalent` accepts ONE basis, [`SAME_FEATURES`], and it is machine
checked: the two columns' derived per-crate cargo-feature closures must be
equal. `firmware-display` cannot be equivalent to `firmware` under that rule,
and neither can any `no-touch` package, whatever a reviewer believes.

No disposition rests on prose. Each one asserts something about the tree —
`covered` that the evidence was produced HERE, `out-of-scope` that the code or
the gate is absent — so each names a basis the tree can disagree with, and
[`ALLOWED`] says which. The one unchecked basis this file shipped with was the
hole the rest of it was built to close: `equivalent` was refused on it because
it asserts sameness, and `covered` asserts MORE and took it, so every un-placed
cell could be re-declared `covered` and the row still printed ok.

What this cannot say, deliberately: whether a disposition is RIGHT. `why` is
prose and no script reads it for truth. What the row keeps honest is that every
applicable cell has one, that an `equivalent` names a column it really does
compile like, that an `out-of-scope` claiming an absent crate is claiming one
that is really absent, and that a column carrying `gap` cells also carries the
question that would settle them — a `gap` with no question is a shrug with a
verdict column.

And that the question names an OWNER and a ROUTE OUT, which is stage 0's last
exit bullet: an owner and a decision, or a deferral with a review point. The
owner is `platform_gate`'s four-role vocabulary, borrowed rather than re-picked.
The review point is [`SETTLES`] — an event, not a date, and the argument for that
is where the field is defined. Two of its four values are ones the tree can
already refuse: `sameness` where the derived closure delta is non-empty, which is
what three never-published measurement columns had been parked on, and `absence`
where neither basis `out-of-scope` takes can reach a row, which is every board
preset. The rest of a question is prose and stays unjudged — four candidate rules
for telling a real one from six nonsense words were measured against the
questions in the tree and all four were refuted by them ([`check_question`]).
"""

import functools
import pathlib
import re
import sys
import tomllib

import assurance_gate
import claims_gate
import gate_lines
import platform_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

LEDGER = pathlib.Path("assurance/configurations.toml")
REGISTRY = pathlib.Path("assurance/properties.toml")
ARTIFACT = pathlib.Path("docs/assurance-matrix.md")
FLAKE = pathlib.Path("nix/firmware.nix")
MANIFEST = pathlib.Path("firmware/Cargo.toml")
BOARDS = pathlib.Path("firmware/boards")
RELEASE = pathlib.Path(".github/workflows/release-build.yml")
CHECK = pathlib.Path("scripts/check.sh")

#: The roadmap's five values. A sixth is not a new kind of evidence, it is a
#: cell nobody classified.
DISPOSITIONS = ("covered", "equivalent", "conditional", "out-of-scope", "gap")
#: What a `[[cell]]` may DECLARE. `gap` is missing on purpose: by this file's
#: design a gap is the ABSENCE of a cell, and a declared one puts the cell in the
#: placed set — which took the column out of the "owes a settling question" rule
#: while the grid still printed `gap` in all 37 of its cells.
DECLARABLE = tuple(d for d in DISPOSITIONS if d != "gap")
#: Three letters each, so a 31-column grid fits a page.
CODE = {
    "covered": "cov",
    "equivalent": "equ",
    "conditional": "cnd",
    "out-of-scope": "oos",
    "gap": "gap",
}

#: The one basis `equivalent` accepts, and the reason it is the only one: it is
#: the only claim of sameness this tree can CHECK. The cell names `same_as`, and
#: the two columns' derived per-crate feature closures must be identical — so
#: the delta between them is knobs — and the cell has to WRITE THOSE DOWN in
#: `knob_delta`, which is checked too. Without that half the rule was vacuous on
#: every cell that used it: all of them compared an empty feature set with an
#: empty one, while `FLASH_SIZE`, `KVMAIN`, `LED_KIND` and `led_order` — real
#: `rustc-env`/`rustc-cfg` inputs, and a regenerated `memory.x` — moved unread.
#:
#: WHOLE-workspace, and the narrower reading is a programme decision rather than
#: a knob here: run over the OWNER crates' closure alone, the same rule clears
#: 733 of the 954 `gap` cells against 190 today (measured 2026-09-02). The
#: argument for leaving that on the table is in the ledger's header, beside the
#: number.
SAME_FEATURES = "same-cargo-features"
#: The property's owner crates are not compiled into this column at all. Checked
#: against the same feature resolution, so `rsk-ui` being absent is a fact and
#: not a recollection.
CRATE_ABSENT = "crate-absent"
#: The cell names `feature`; the column enables it, and production Rust really
#: does gate on it, at a site inside the property's own owners — or, where the
#: site is `firmware`'s glue, behind a `hook` the owners name. What the gate is
#: (a `no-touch` presence auto-confirm, say) is the `why`'s job; that the switch
#: exists, is thrown here, and is THIS property's is this one's.
GATE_COMPILED_OUT = "gate-compiled-out"
#: This column IS the default build: no cargo features, no knobs.
DEFAULT_BUILD = "default-build"
#: The cell names `evidence`: `check.sh` rows that PRODUCED the registry's
#: evidence for this property, on THIS configuration — same cargo features, same
#: build knobs. `covered` is the strongest word in the vocabulary and it was the
#: only one resting on nothing, so every un-placed cell could be re-declared
#: `covered` and the row still printed ok.
#:
#: Both halves, because the ledger's definition has two sentences and reading
#: either alone is how this basis goes wrong in opposite directions. "The
#: registry's evidence was produced on this configuration" is the CLAIM; "the
#: cell names the `check.sh` rows that produced it, and the gate re-derives
#: whether those rows really build THIS image" is how the claim is SPELLED. The
#: second is a necessary condition on the first, never a replacement for it —
#: and until [`registry_evidence`] the gate ran only the second, which measured
#: 80 `gap` cells one edit from `covered` on eight `cargo test` rows that produce
#: no registered evidence for any of them.
CHECK_SH_ROWS = "check-sh-rows"
BASES = (SAME_FEATURES, CRATE_ABSENT, GATE_COMPILED_OUT, DEFAULT_BUILD, CHECK_SH_ROWS)
#: Which bases each disposition may rest on. There is deliberately no unchecked
#: one left: `stated` used to be legal for everything except `equivalent`, and
#: writing a STRONGER word than the rule refused — `covered`, or `conditional`,
#: or `out-of-scope` — retired all 955 `gap` cells at EXIT=0. Every disposition
#: asserts something about the tree, so the tree has to be able to disagree.
ALLOWED = {
    "covered": (DEFAULT_BUILD, CHECK_SH_ROWS),
    "conditional": (DEFAULT_BUILD, CHECK_SH_ROWS),
    "equivalent": (SAME_FEATURES,),
    "out-of-scope": (CRATE_ABSENT, GATE_COMPILED_OUT),
}
#: What every cell says, and the extra fields each basis reads on top. A cell
#: carrying one its basis does not read is a field nothing checks — and `render`
#: prints `same_as` whatever the disposition is, so the page would show a
#: sameness the gate never derived.
CELL_FIELDS = ("properties", "columns", "disposition", "basis", "why")
BASIS_FIELDS = {
    SAME_FEATURES: ("same_as", "knob_delta"),
    GATE_COMPILED_OUT: ("feature", "cfg", "hook"),
    CHECK_SH_ROWS: ("evidence",),
    CRATE_ABSENT: (),
    DEFAULT_BUILD: (),
}

#: The tranches §5 of the roadmap defines. `p0-launch` + `p0b` is the P0 family,
#: and the P0 family is the matrix's rows; the other two are carried so the
#: classification is TOTAL over the registry. A property nobody classified would
#: otherwise be a row nobody misses.
TRANCHES = ("p0-launch", "p0b", "p1", "out-of-queue")
ROW_TRANCHES = ("p0-launch", "p0b")

#: Floors, AT today's counts rather than under them. A derivation that finds
#: (almost) nothing satisfies every rule below over an empty roster, which is the
#: shape seven guards in this tree have shipped with — but 12 against 19 packages
#: catches only the collapse, never the slide, and losing four boards one at a
#: time is how an axis quietly stops being an axis. Shrinking one for real is
#: then a deliberate edit here, in the same diff as the shrink.
FLOOR_PACKAGES = 22
FLOOR_BOARDS = 7
FLOOR_ROWS = 40
#: A `why` or a settling question shorter than this is a placeholder rather than
#: prose: `.strip()` alone let `"?"` and `"TODO"` stand as the question that would
#: settle a whole column. Six, because the ledger's shortest real question is
#: seven words and its shortest `why` is forty-five. It catches a placeholder;
#: no script can catch a bad question.
FLOOR_WORDS = 6

#: Who owes each open question an answer. Borrowed from `platform_gate` rather
#: than re-picked, the way `threat_gate` borrows [`FLOOR_WORDS`] from here: that
#: file chose these four roles for the reason this register needs them — "someone
#: should look at this" names nobody — and a second vocabulary would be two
#: answers to one question. `maintainer` is the role that means a decision no
#: derivation can produce; it is AGENTS.md's maintainer-only list.
OWNERS = platform_gate.OWNERS

#: What would settle a column's `gap` cells, TYPED — and it is deliberately not a
#: date. `platform_gate` already argued the calendar half down for its own
#: register ("a trigger for a measurement nobody has made is a placeholder") and
#: that argument is adopted, but not by analogy: the two registers face opposite
#: ways. `revalidated_by` asks what would UNSETTLE a settled result, which a
#: pending row cannot answer; this asks what would SETTLE an open one, which is
#: answerable exactly when the question is well posed. A calendar `review_by`
#: is the thing that cannot be built here: enforced it reddens `check.sh` on a
#: day nobody touched the tree, and the repair is to move the date; unenforced it
#: is the field-nothing-reads this file refuses on `[[cell]]`. What prompts the
#: review instead is the row itself — the artifact is regenerated and diffed on
#: every run, so a new package, feature, board or property reprints the question.
#:
#: The four values are this file's own [`ALLOWED`] table read backwards: each
#: names the `[[cell]]` the question would become, and the last names the one no
#: derivation can produce. All four stay even where nothing claims one — today no
#: question says `sameness`, and it is the exits from the disposition table that
#: have to be TOTAL, or a column whose honest route is an equivalence is made to
#: write a wrong answer. What earns its place is the REFUSAL, not the value.
SETTLES = {
    "evidence": (CHECK_SH_ROWS,),
    "absence": (CRATE_ABSENT, GATE_COMPILED_OUT),
    "sameness": (SAME_FEATURES,),
    "ruling": (),
}
#: What a `[[question]]` may say. `[[cell]]` has had this since it shipped and
#: `[[question]]` had none, so a key added to one was read by nothing and printed
#: by nothing — the field-that-does-not-exist half of the field-nothing-checks
#: hole one record type over.
QUESTION_FIELDS = ("column", "text", "owner", "settled_by")
#: And the same question one level out, asked because the one above was: the
#: ledger's own tables. A mistyped `[[cell]]` is caught today only by the cells
#: going missing and the artifact then not matching, but a table nobody reads
#: under a NEW name — `[[note]]`, `[[review]]` — is a section of this file that
#: exists for no reader at all, which is the shape both rules above are about.
LEDGER_TABLES = ("tranche", "cell", "question")

#: A property tag in production Rust. Same two spellings `assurance_gate.py`
#: validates; read here only for WHICH CRATE owns each property, which is what
#: `crate-absent` rests on.
OWNER_TAG = re.compile(
    r"(?:Refines|Supports)\s+`[A-Za-z0-9]+![A-Za-z0-9]+`\s+—\s+(SEC-[A-Z]+-[0-9A-Z]+)"
)

#: `--features a,b` / `--features=a,b`, in the spellings cargo takes. Used on
#: `check.sh` rows AND on a flake package's `cargoFlags`, because a hand-rolled
#: word scan over the latter read `--features=a,b` as no features at all — and an
#: empty feature set is what makes a column look like the default build.
FEATURE_FLAG = re.compile(r"(?<![\w-])--features[=\s]+([\w,.-]+)")
#: A `cargoFlags` binding, WHOLE — up to the `;`, not up to the first `]`. In the
#: spellings Nix takes rather than the one nixfmt happens to write: no
#: `nixfmt --check` row exists in this tree, so `cargoFlags= [`, `cargoFlags  = [`
#: and `cargoFlags =[` are as real as the canonical form, and each read as NO
#: flags — which prints a published flavor as the default build. Whole, because
#: `[ "a" ] ++ extra` is a list plus flags a `\[(.*?)\]` never sees.
CARGO_FLAGS = re.compile(r"(?<![\w-])cargoFlags\s*=\s*([^;]*);")
#: A literal string in a Nix list.
NIX_STRING = re.compile(r'"([^"]*)"')
#: `attr = mkFirmware { … }`, in the spellings nixfmt leaves and the ones it does
#: not: the `=` and the call may be on separate lines (this file already breaks
#: two other bindings that way), the indent is not fixed, and `mkFirmware{` is
#: legal Nix. Nothing in `check.sh` runs `nixfmt --check`, so the shape cannot be
#: assumed.
PACKAGE = re.compile(r"^[ \t]*([A-Za-z0-9_-]+)\s*=\s*mkFirmware\s*\{", re.M)
#: Every call of the builder, however it is written. The count is compared with
#: what [`PACKAGE`] matched: a package the pattern above cannot see is a column
#: that never exists, and this is the only thing that notices.
INVOCATION = re.compile(r"(?<![\w-])mkFirmware\s*\{")
#: A `key = value;` inside a package body. Not `^`-anchored: a one-line body is
#: legal and the anchored version dropped its knobs, which turned the package
#: into the default build in the matrix.
KNOB = re.compile(r"(?<![\w-])([a-zA-Z][A-Za-z0-9]*)\s*=\s*([^;]+);")
#: Nothing in a package body is a knob under these names: the image's name, and
#: the raw `cargoFlags` list, whose feature half is the feature axis and whose
#: residual half [`cargo_flags`] re-adds as one knob.
NOT_A_KNOB = ("name", "cargoFlags")
#: A `check.sh` row: `run "<label>" <command>`, or the `run_tests` sibling. The
#: label is how a `covered` cell names its evidence.
ROW = re.compile(r'^run(?:_tests)?\s+"([^"]+)"\s+(\S.*)$')
#: A `VAR=value` in a row's `env` prefix — the build knobs that row pins.
ROW_ENV = re.compile(r"(?<![\w-])([A-Z][A-Z0-9_]*)=(\S+)")
#: How Rust READS an environment variable, in both places a build knob can be
#: read: `env::var` in a `build.rs` while the package is built, and `env!` /
#: `option_env!` while it is compiled. The name has to be a literal: the firmware
#: script also loops `env::var(k)` over a board preset's keys, and a preset is
#: reached by its NAME rather than by spelling its keys out, which is the note
#: [`env_name`] already carries.
ENV_READ = re.compile(
    r'(?<![\w-])(?:env::var(?:_os)?|option_env!|env!)\s*\(\s*"([A-Z][A-Z0-9_]*)"'
)
#: The OTHER spelling of the same fact, and the reason it is one: cargo reruns a
#: build script when a declared variable changes, so a script that reads a knob
#: it never declares rebuilds stale, and one that declares a knob it never reads
#: has a dead line. Two spellings of one thing, held to each other by
#: [`unreadable_env_reads`] and unioned by [`env_reads`], rather than one of them
#: picked. Picking cost a measured false alarm in the direction that matters
#: most: rewrite `env::var("FLASH_SIZE")` as the equally valid
#: `use std::env::var; var("FLASH_SIZE")` and [`ENV_READ`] loses the knob, so an
#: HONEST row — one that really does build `firmware` at `FLASH_SIZE=16M` — was
#: refused for "no package it builds reads it", which is false. A false negative
#: on an honest row is worse than the hole it was closing, and the repair is not
#: a longer regex: the union keeps the row green and the cross-check names the
#: spelling this file cannot see, at the site, the way a floor a counter cannot
#: read is refused by name rather than skipped.
RERUN_ENV = re.compile(r"cargo:{1,2}rerun-if-env-changed=([A-Z][A-Z0-9_]*)")
#: The release workflow's flavor loop.
PKG_LOOP = re.compile(r"for pkg in ([^;]+); do")
#: Both of them: the build and the reproducibility rebuild are two lists that
#: have to be one, and without a floor a reflow that hides one of them leaves the
#: comparison running over a single list, in silence.
FLOOR_LOOPS = 2

#: A backticked token in a `why` or a `[[question]]` body. The prose is not
#: judged for truth anywhere in this file — but a prose argument that CITES the
#: tree can at least be held to citing something that is there, which is the rule
#: `citation_gate.py` runs over `formal/` one directory across. Measured before
#: it was written: the ledger's prose cites fourteen things — ten paths and four
#: `check.sh` rows — and not one of them was read by anything. All fourteen
#: resolve; two of the CLAIMS around them did not survive being re-read, and no
#: rule here catches that. What this catches is the step below it: rename a
#: `check.sh` row and the `bench` question's whole "covered has nothing to rest
#: on here" argument points at no row at all, grid unchanged, EXIT=0.
CITED = re.compile(r"`([^`]+)`")
#: Which of those tokens is a claim about a file: a `/` and an extension. A token
#: without both is vocabulary (`rsk-fido/bench`, `EF_META`, `flash.size_mb=4`)
#: and is deliberately unchecked — this rule is about citations, not spelling.
CITED_PATH = re.compile(r"^[A-Za-z0-9_.*-]+(?:/[A-Za-z0-9_.*-]+)+\.[A-Za-z0-9]+$")
#: And which is a claim about a `check.sh` row: the label shape, `foo (bar)`.
#: The false positive this admits is backticked prose that happens to carry
#: parentheses; there is none in the ledger today, and the red it would raise
#: names the token and says to drop the ticks — which is a worse failure than
#: silence in exactly one direction, and it is the survivable one.
CITED_ROW = re.compile(r"^\S.*\s\([^()]*\)$")
#: The other half of the row namespace, and it is the larger half: 54 of the 113
#: rows carry no ` (…)` at all (`fmt`, `kani roster`, `published claims`,
#: `formal citations`), so the shape above sees 52% of what a rename can break
#: and a ledger citing any of the rest stayed green through one. A row with no
#: shape cannot be told from vocabulary by LOOKING at it — the "require a token
#: the derivation knows" rule [`check_question`] measured was refuted by the
#: tree's own questions — so the citation says which it is, and the prefix is the
#: file the row lives in: `` `check.sh: kani roster` ``.
CITED_CHECK_ROW = re.compile(r"^check\.sh:\s*(\S.*)$")

#: The cargo subcommand a row runs, past any `env VAR=… ` prefix.
CARGO_SUB = re.compile(r"(?<![\w-])cargo\s+(\w+)")
#: The ones that build the image and execute nothing in it. A `check.sh` row
#: that is not cargo at all (`firmware_size_budget`, a shell function reading the
#: ELF) is deliberately not here: those DO measure something, and which of them
#: measures a given property is the `why`'s judgement, not a subcommand's.
#:
#: `check` is anticipatory and says so: this tree has 0 `cargo check` rows, so no
#: input reaches that member and nothing here can falsify it. It stays because
#: the member that CAN be falsified is `doc` — 8 `rustdoc` rows exist, none of
#: them pinned to a column's features today — and dropping a correct entry to
#: raise a mutation score is how the next `cargo check` row becomes evidence.
COMPILE_ONLY = ("build", "check", "clippy", "doc")

#: What a broken input raises before it can become a finding. A traceback is a
#: red too, and a much worse one: it names a line of this file rather than the
#: file whose shape changed.
MALFORMED = (AttributeError, KeyError, OSError, TypeError, tomllib.TOMLDecodeError)

GENERATED_BY = "Generated by scripts/matrix_gate.py --write"


# --- the tree ---------------------------------------------------------------


def _nix_blocks(text):
    """(attr, body) for each `attr = mkFirmware { … };` in the packages set."""
    for found in PACKAGE.finditer(text):
        at, depth = found.end() - 1, 0
        for index in range(at, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    yield found.group(1), text[at + 1 : index]
                    break


def cargo_flags(name, body):
    """(cargo features, the rest of the list) for one package's `cargoFlags`.

    The rest is a knob and not a footnote: `--no-default-features` and
    `--profile release-fast` build a different image, and a column whose derived
    features AND knobs are both empty IS the default build — which is a basis the
    gate accepts and an equivalence whose whole delta reads as nothing.
    """
    found = CARGO_FLAGS.search(body)
    if not found:
        return (), ""
    value = found.group(1).strip()
    listed = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    unread = NIX_STRING.sub(" ", listed).strip()
    if unread:
        raise ValueError(
            f"{FLAKE}: `{name}`'s cargoFlags carries {unread!r}, which is not a literal"
            " flag — a flag this gate cannot read is a column derived wrong"
        )
    joined = " ".join(NIX_STRING.findall(listed))
    features = tuple(f for group in FEATURE_FLAG.findall(joined) for f in group.split(","))
    return features, " ".join(FEATURE_FLAG.sub(" ", joined).split())


def packages(root):
    """The flake's firmware images: name -> (features, knobs).

    Keyed by the `name` each package builds, not by the attribute: `default` and
    `firmware` are one image under two attributes, and counting them twice would
    put a phantom column in the matrix.
    """
    text = (root / FLAKE).read_text()
    code = "\n".join(
        gate_lines.split_at_comment(body)[0] for _indent, body in gate_lines.logical_lines(text)
    )
    out = {}
    for _attr, body in _nix_blocks(text):
        name = re.search(r'name\s*=\s*"([^"]+)"', body).group(1)
        features, residual = cargo_flags(name, body)
        knobs = {
            key: value.strip().strip('"')
            for key, value in KNOB.findall(body)
            if key not in NOT_A_KNOB
        }
        if residual:
            knobs["cargoFlags"] = residual
        derived = (frozenset(features), knobs)
        if out.setdefault(name, derived) != derived:
            raise ValueError(
                f"{FLAKE} builds `{name}` from two mkFirmware blocks that derive"
                f" differently — {sorted(out[name][0])} {out[name][1]} and"
                f" {sorted(features)} {knobs}. One image name is one column, so the"
                " second block replaced the first with no message at all"
            )
    seen, called = len(list(_nix_blocks(text))), len(INVOCATION.findall(code))
    if seen != called:
        raise ValueError(
            f"{FLAKE} calls mkFirmware {called} time(s) and this gate reads {seen}"
            " package(s) — a package written in a spelling the pattern cannot see is"
            " a column that never exists"
        )
    return out


def published(root):
    """The packages `release-build.yml` ships, and whether its two lists agree."""
    text = (root / RELEASE).read_text()
    loops = [
        frozenset(PKG_LOOP.search(body).group(1).split())
        for body, executed in gate_lines.yaml_runs(text)
        if executed and PKG_LOOP.search(gate_lines.split_at_comment(body)[0])
    ]
    return loops


def boards(root):
    """`firmware/boards/**/*.toml`: preset -> the knobs it sets, flattened.

    Recursive, because `build.rs` reads `boards/{BOARD}.toml` with no rule
    against a `/` in the name — so `BOARD=vendor/foo` builds from a nested file a
    flat glob calls no board at all.
    """
    out = {}
    for path in sorted((root / BOARDS).rglob("*.toml")):
        doc = tomllib.loads(path.read_text())
        out[path.relative_to(root / BOARDS).with_suffix("").as_posix()] = {
            f"{section}.{key}": value
            for section, body in doc.items()
            for key, value in body.items()
        }
    return out


def manifest_features(root):
    return tuple(tomllib.loads((root / MANIFEST).read_text())["features"])


def cargo_part(command):
    """The cargo invocation inside a row's command, or "" if there is none.

    `-p` and `--features` are cargo's own flags and mean nothing to anything
    else, so they are read from here on and nowhere else. `python tests/emu.py
    tests/29_reset_power_cut.py -p rsk-fido --features fips-profile` hands
    `emu.py` two arguments it never reads, and both were credited: the row
    "selected" the property's owner crate and "matched" the column's feature set,
    and four `gap` cells took `covered` on it at EXIT=0. Derived from the command
    rather than from a list of the programs that take the flags, which would be a
    second roster beside [`COMPILE_ONLY`] with nothing holding the two together.
    """
    found = re.search(r"(?<![\w-])cargo(?![\w-])", command)
    return command[found.start() :] if found else ""


def check_sh_rows(root):
    """label -> (cargo features, env knobs, command) for every `check.sh` row.

    One reader for both things the ledger asks of `check.sh`: which features
    reach a build of `firmware`, and whether the row a `covered` cell names
    builds the column it claims about. Read off each row's CODE — a commented-out
    row is not a row, and it is not evidence either.
    """
    out = {}
    for _indent, body in gate_lines.logical_lines((root / CHECK).read_text()):
        found = ROW.match(gate_lines.split_at_comment(body)[0].strip())
        if not found:
            continue
        label, command = found.groups()
        features = frozenset(
            feature
            for group in FEATURE_FLAG.findall(cargo_part(command))
            for feature in group.split(",")
        )
        # The knobs sit in the `env …` prefix, ahead of the cargo they wrap.
        env = {
            key: value.strip('"')
            for key, value in ROW_ENV.findall(command.split(" cargo ", 1)[0])
        }
        if label in out:
            raise ValueError(
                f"{CHECK} has two rows named {label!r} — a cell's evidence would name"
                " both and the gate would read one of them"
            )
        out[label] = (features, env, command)
    return out


def check_sh_firmware_features(root):
    """Every feature a `check.sh` row hands to a build of `firmware`.

    The rule this serves is the roadmap's: a cargo feature with a `check.sh` row
    and no column.
    """
    return {
        feature
        for features, _env, command in check_sh_rows(root).values()
        if "cargo " in command and "firmware" in gate_lines.packages(command)
        for feature in features
    }


def env_name(knob):
    """The env var `mkFirmware` hands `build.rs` for the flake argument `knob`.

    Mechanical (`flashSize` -> `FLASH_SIZE`), because the flake writes the pair
    itself and a table here would go stale beside `build.rs`. A board preset's
    keys (`flash.size_mb`) are a third vocabulary and deliberately map to
    nothing: a row reaches a board by its NAME, not by spelling its keys out.
    """
    return re.sub(r"(?<!^)(?=[A-Z])", "_", knob).upper()


# --- cargo feature resolution ----------------------------------------------


def _deps(doc):
    out = {}
    for section in ("dependencies", "build-dependencies"):
        for name, spec in doc.get(section, {}).items():
            out[name] = spec if isinstance(spec, dict) else {}
    return out


def workspace(root):
    """package name -> its parsed manifest, for every [workspace] member."""
    members = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["members"]
    out = {}
    for member in members:
        doc = tomllib.loads((root / member / "Cargo.toml").read_text())
        out[doc["package"]["name"]] = doc
    return out


def resolve(manifests, extra):
    """(crates compiled in, crate -> its enabled features) for `firmware` + `extra`.

    Cargo's own resolution, over workspace members only: an external crate cannot
    own a property, so its features would be a column nothing reads. Weak
    (`dep?/feat`) edges fire only when the optional dependency is already in,
    which is what makes `fips-profile` leave `rsk-display` alone on a build
    without a screen.
    """
    enabled, present, queue, held = {}, set(), [], []

    def add(crate):
        if crate not in manifests or crate in present:
            return
        present.add(crate)
        for name, spec in _deps(manifests[crate]).items():
            if not spec.get("optional"):
                add(name)
        queue.append((crate, "default"))

    add("firmware")
    queue.extend(("firmware", feature) for feature in extra)

    seen = set()
    while True:
        while queue:
            crate, feature = queue.pop()
            if crate not in manifests or (crate, feature) in seen:
                continue
            seen.add((crate, feature))
            table = manifests[crate].get("features", {})
            deps = _deps(manifests[crate])
            if feature not in table:
                # An optional dependency doubles as an implicit feature of its name.
                if deps.get(feature, {}).get("optional"):
                    add(feature)
                    enabled.setdefault(crate, set()).add(feature)
                continue
            enabled.setdefault(crate, set()).add(feature)
            for item in table[feature]:
                if item.startswith("dep:"):
                    add(item[4:])
                elif "/" in item:
                    dep, sub = item.split("/", 1)
                    is_weak = dep.endswith("?")
                    dep = dep.rstrip("?")
                    if is_weak:
                        held.append((dep, sub))
                        continue
                    add(dep)
                    queue.append((dep, sub))
                else:
                    queue.append((crate, item))
        # A `dep?/feat` edge fires only once its optional dependency is in, and
        # the edge is usually walked before it arrives. Re-offering the held ones
        # until nothing moves is what makes the answer independent of the order
        # the features were given in.
        live = [pair for pair in held if pair[0] in present]
        if not live:
            break
        held = [pair for pair in held if pair not in live]
        queue.extend(live)
    return frozenset(present), {c: frozenset(f) for c, f in enabled.items()}


# --- the axes ---------------------------------------------------------------


class Column:
    """One buildable configuration: what it turns on, and what that compiles."""

    def __init__(self, name, kind, features, knobs, is_published, manifests):
        self.name = name
        self.kind = kind
        self.features = frozenset(features)
        self.knobs = knobs
        self.published = is_published
        self.present, self.closure = resolve(manifests, sorted(self.features))

    @property
    def default(self):
        return not self.features and not self.knobs


def columns(root, manifests):
    """Every column, derived from the three axes, in a stable order."""
    out, loops = [], published(root)
    shipped = frozenset.union(*loops) if loops else frozenset()
    for name, (features, knobs) in packages(root).items():
        out.append(Column(name, "package", features, knobs, name in shipped, manifests))
    expressed = {f for _c in out for f in _c.features}
    for feature in manifest_features(root):
        if feature not in expressed:
            out.append(Column(feature, "feature", [feature], {}, False, manifests))
    for preset, knobs in boards(root).items():
        out.append(Column(preset, "board", [], knobs, False, manifests))
    return out


def reference_column(cols):
    """The default build: the column every closure delta is measured against.

    Derived (no cargo feature, no build knob) rather than named, so a renamed
    `firmware` cannot leave the page silently measuring against nothing. Picking
    the first of several is not a choice: two columns with no feature and no knob
    resolve the same workspace, so they are one image under two names.
    """
    return next((column for column in cols if column.default), None)


@functools.cache
def production_rust(root):
    """The `.rs` files a buildable image can compile — `assurance_gate`'s reader.

    Not a filename filter. That is what both readers here used to be, and
    `assurance_gate.cfg_excluded` was written to replace it: six `*_assurance.rs`
    mirrors carry neither `kani` nor `tests` in the name and were counted as
    production. Measured here, the two readers differed on 18 files, all in the
    permissive direction.

    A memo and a name now, nothing more: `ff0b277` moved the sub-tree closure
    this used to add on top DOWN into `cfg_excluded`, and measured, the filter
    left behind drops 0 of 182 files — replacing this body with a bare call
    leaves the page byte-identical. What keeps it a function is the cache: the
    three call sites below and the two `production_rust.cache_clear()` in the
    tests, against an `assurance_gate.production_rust` that re-reads every
    source on each call.
    """
    return assurance_gate.production_rust(root)


def owners(root):
    """property id -> the crates whose production Rust carries its tag."""
    found = {}
    for path in production_rust(root):
        rel = path.relative_to(root).parts
        crate = rel[1] if rel[0] == "crates" else "firmware"
        for pid in OWNER_TAG.findall(path.read_text(errors="ignore")):
            found.setdefault(pid, set()).add(crate)
    return {pid: frozenset(crates) for pid, crates in found.items()}


def registry(root):
    doc = tomllib.loads((root / REGISTRY).read_text())
    return [(entry["id"], entry["name"]) for entry in doc["property"]]


@functools.cache
def names_artifact(artifact):
    """Whether a row's command NAMES this evidence artifact, not merely spells it.

    A plain `in` is too loose in the one direction that matters: the fuzz target
    `pqc` is inside `--features advertise-pqc`, and a `covered` cell would then
    rest on a row that only enables a feature named after it. The separators a
    path or a flag puts around a real mention are boundaries; a `-` is not.
    """
    return re.compile(rf"(?<![\w-]){re.escape(artifact)}(?![\w-])")


@functools.cache
def registry_evidence(root, name):
    """The RUNNABLE artifacts the registry derives as this property's evidence.

    `assurance/properties.toml` stores no evidence field — "everything else is
    DERIVED by scripts/assurance_gate.py and printed, never stored", because a
    hand-written copy rotted in three of six fields. So this is that derivation,
    restricted to the three classes something can RUN: the Kani harnesses whose
    function name carries the invariant, the fuzz targets that name it, and the
    `tests/*.py` scripts that do. `assurance_gate.derive`'s fourth class is
    `rust`, the production files carrying the tag, and it is deliberately not
    here: that is the CODE the statement is about, not evidence that it holds.

    Read for one thing — whether a `check.sh` row a `covered` cell names produced
    any of it. A crate's unit tests are in NO class, which is why the eight
    `cargo test` rows the 80-cell measurement found cannot carry the word: they
    run `rsk-fido`'s own suite at another compilation, which is a real thing to
    have done and is not the registry's evidence for `SEC-FIDO-001`.

    The formal invariant every entry must name is the class left out on purpose:
    it is not run by a `check.sh` row at all, and a column whose route out is a
    model run at its own constants is exactly what `settled_by = "evidence"` on
    that column already says.

    Each artifact is spelled the way a row would NAME it: a harness by its
    function (`--harness foo`), a fuzz target and a device script by their STEM
    (`cargo fuzz run pqc`, `python tests/10_foo.py`). `assurance_gate.grep_word`
    hands back file names, and `pqc.rs` appears in no command anybody writes.
    """
    sn = assurance_gate.snake(name)
    harnesses = [
        fn
        for path in sorted((root / "crates").glob("*/src/*kani*.rs"))
        for fn in assurance_gate.FN_DEF.findall(path.read_text(errors="ignore"))
        if sn in fn
    ]
    fuzz = sorted((root / "fuzz" / "fuzz_targets").glob("*.rs"))
    scripts = sorted((root / "tests").glob("**/*.py"))
    named = assurance_gate.grep_word(fuzz, name)
    named += assurance_gate.grep_word(scripts, name) + assurance_gate.grep_word(scripts, sn)
    stems = [pathlib.Path(found).stem for found in named]
    return tuple(sorted(set(harnesses) | set(stems)))


# --- the ledger -------------------------------------------------------------


def ledger(root):
    return tomllib.loads((root / LEDGER).read_text())


def expand(doc, problems):
    """[((property, column), entry)] for every cell the ledger disposes of."""
    cells = []
    for index, entry in enumerate(doc.get("cell", [])):
        try:
            pids, cols = entry["properties"], entry["columns"]
        except KeyError as missing:
            problems.append(f"cell #{index + 1} has no {missing}")
            continue
        for pid in pids:
            for column in cols:
                cells.append(((pid, column), entry))
    return cells


def audit(root):
    """(problems, one-line summary) for the matrix, the ledger and the artifact."""
    root = pathlib.Path(root)
    problems = list(unreadable_env_reads(root))
    manifests = workspace(root)
    cols = columns(root, manifests)
    by_name = {column.name: column for column in cols}
    if len(by_name) != len(cols):
        problems.append("two columns derive to the same name")
    kinds = {kind: [c for c in cols if c.kind == kind] for kind in ("package", "feature", "board")}
    if len(kinds["package"]) < FLOOR_PACKAGES or len(kinds["board"]) < FLOOR_BOARDS:
        problems.append(
            f"derived {len(kinds['package'])} package(s) and {len(kinds['board'])} board(s),"
            f" under the floors of {FLOOR_PACKAGES}/{FLOOR_BOARDS} — an axis that shrank"
            " stopped covering what it used to, and one that collapsed satisfies every"
            " rule below over an empty matrix. Shrink the floor here in the same diff"
        )
        return problems, "matrix-gate: derivation failed"

    loops = published(root)
    if len(loops) < FLOOR_LOOPS:
        problems.append(
            f"{RELEASE} shows {len(loops)} `for pkg in …` flavor loop(s), under the"
            f" floor of {FLOOR_LOOPS} — the build and its reproducibility rebuild are"
            " two lists whose agreement is the check, and one of them is unreadable"
        )
    elif len({frozenset(loop) for loop in loops}) != 1:
        problems.append(
            f"{RELEASE}'s flavor loops disagree: {[sorted(loop) for loop in loops]}"
        )
    for name in sorted(frozenset.union(*loops) if loops else frozenset()):
        if name not in by_name:
            problems.append(f"{RELEASE} publishes {name}, which {FLAKE} does not build")

    # The roadmap's rule is "a cargo feature with a check.sh row and no column".
    # A manifest feature always HAS one — `columns` synthesises it — so the only
    # way to reach the rule is a row naming a feature the manifest no longer
    # defines, and that is the branch. A second `elif` asking whether some column
    # carries it was unreachable by construction, which is a rule that cannot fail.
    manifest = manifest_features(root)
    for feature in sorted(check_sh_firmware_features(root)):
        if feature not in manifest:
            problems.append(
                f"a check.sh row builds firmware with `--features {feature}`, which"
                f" {MANIFEST} does not define — a stale row, or a column nothing can derive"
            )

    try:
        doc = ledger(root)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{LEDGER} cannot be read as a disposition ledger: {error}"], "matrix-gate: no ledger"

    for table in sorted(set(doc) - set(LEDGER_TABLES)):
        problems.append(
            f"{LEDGER} carries a `{table}` table, which is not one of"
            f" {list(LEDGER_TABLES)} — a section of this file no reader reads"
        )
    ids = [pid for pid, _name in registry(root)]
    names = dict(registry(root))
    tranche, seen = {}, []
    for name in TRANCHES:
        for pid in doc.get("tranche", {}).get(name, []):
            tranche[pid] = name
            seen.append(pid)
    for pid in sorted(set(seen)):
        if seen.count(pid) > 1:
            problems.append(f"{pid} is in more than one tranche")
    for pid in ids:
        if pid not in tranche:
            problems.append(
                f"{pid} is in {REGISTRY} and in no tranche of {LEDGER} — say which"
                " queue it belongs to, or it is a row the matrix silently has no opinion on"
            )
    for pid in sorted(set(seen) - set(ids)):
        problems.append(f"{LEDGER} puts {pid} in a tranche and {REGISTRY} has no such property")
    for name in sorted(set(doc.get("tranche", {})) - set(TRANCHES)):
        problems.append(f"{LEDGER} names tranche `{name}`, which is not one of {TRANCHES}")

    rows = [pid for pid in ids if tranche.get(pid) in ROW_TRANCHES]
    if len(rows) < FLOOR_ROWS:
        problems.append(
            f"{len(rows)} P0-family row(s), under the floor of {FLOOR_ROWS} — the"
            " tranche lists shrank, and a matrix with fewer rows makes fewer claims"
            " than the one this floor was set at. Shrink the floor here in the same diff"
        )
        return problems, "matrix-gate: derivation failed"

    own = owners(root)
    cells = expand(doc, problems)
    placed = {}
    for key, entry in cells:
        pid, column = key
        where = f"{pid} × {column}"
        if key in placed:
            problems.append(f"{where} is disposed of twice")
            continue
        placed[key] = entry
        if pid not in rows:
            problems.append(
                f"{where}: {pid} is not a P0-family property, so it is not a row of this matrix"
            )
            continue
        if column not in by_name:
            problems.append(f"{where}: no such build configuration")
            continue
        problems.extend(check_cell(root, pid, by_name[column], entry, by_name, own, names))

    problems.extend(check_chains(placed))
    problems.extend(check_citations(root, doc))

    questions = {q.get("column"): q.get("text", "") for q in doc.get("question", [])}
    for column in sorted(set(questions) - set(by_name)):
        problems.append(f"{LEDGER} carries a settling question for `{column}`, which is no column")
    gaps = {}
    for column in cols:
        open_rows = [pid for pid in rows if (pid, column.name) not in placed]
        if open_rows:
            gaps[column.name] = open_rows
            if len(questions.get(column.name, "").split()) < FLOOR_WORDS:
                problems.append(
                    f"{column.name} has {len(open_rows)} `gap` cell(s) and no settling"
                    f" question in {LEDGER} — a gap with no question is a shrug, and"
                    f" one under {FLOOR_WORDS} words (`?`, `TODO`) is the same shrug"
                )
    for column in sorted(set(questions) - set(gaps)):
        if column in by_name:
            problems.append(
                f"{column} carries a settling question and has no `gap` cell left to settle"
            )
    for entry in doc.get("question", []):
        problems.extend(
            check_question(root, entry, by_name, reference_column(cols), gaps, own)
        )

    counts = {value: 0 for value in DISPOSITIONS}
    counts["gap"] = sum(len(open_rows) for open_rows in gaps.values())
    for _key, entry in placed.items():
        if entry.get("disposition") in counts:
            counts[entry["disposition"]] += 1
    summary = (
        f"matrix-gate: ok — {len(rows)} P0-family properties × {len(cols)} build"
        f" configurations = {len(rows) * len(cols)} cells"
        f" ({', '.join(f'{counts[v]} {v}' for v in DISPOSITIONS)})"
    )
    return problems, summary


def check_citations(root, doc):
    """Every file and `check.sh` row the ledger's prose names, held to the tree.

    `why` and `text` are the half of this file no script reads for truth, and
    that stays true — this reads them only for the tokens they POINT at. A path
    citation has to resolve (a glob counts: `formal/*.cfg` is one claim about 216
    files) and a row citation has to be a row `check_sh_rows` can find. Rotting a
    citation is how the arguments here go wrong quietly: the sentence still
    parses, the disposition still type-checks, and the reader has no way to tell
    a live reference from a dead one without opening every file named.
    """
    rows, problems = check_sh_rows(root), []
    for kind, field in (("cell", "why"), ("question", "text")):
        for index, entry in enumerate(doc.get(kind, [])):
            where = f"{LEDGER}: {kind} #{index + 1}"
            for token in CITED.findall(str(entry.get(field, ""))):
                # A `why` is a TOML block whose lines are joined with `\`, so a
                # token that wraps arrives already flat — but a block written
                # WITHOUT the continuations keeps the newline, and the token then
                # matches neither pattern below and is checked by nothing. 0 of
                # the 208 tokens in the tree wrap today; the arm is what keeps
                # that a fact about the prose rather than a fact about the rule.
                token = " ".join(token.split())
                prefixed = CITED_CHECK_ROW.match(token)
                if CITED_PATH.match(token):
                    # The glob alone, and it is not a shortcut: this read
                    # `not (root / token).exists() and not list(...)`, and the
                    # first half could not distinguish an input from the second.
                    # `CITED_PATH`'s class admits no `[` or `?`, so the only
                    # metacharacter that reaches here is `*` — and a file
                    # literally named `vec*.rs` matches the pattern `vec*.rs`.
                    # Measured over the whole class: `glob` is non-empty wherever
                    # `exists` is true and in one case more (a broken symlink),
                    # which is the direction that never turns a live citation
                    # dead. The boundary that makes this safe is pinned below.
                    if not list(root.glob(token)):
                        problems.append(
                            f"{where} cites `{token}`, which is not in the tree — a"
                            " dead citation reads exactly like a live one"
                        )
                elif prefixed and prefixed.group(1) not in rows:
                    problems.append(
                        f"{where} cites `{token}`, and {CHECK} has no row"
                        f" {prefixed.group(1)!r} — the `check.sh:` prefix is what makes"
                        " a shapeless row label citable, so this one has been renamed"
                    )
                elif not prefixed and CITED_ROW.match(token) and token not in rows:
                    problems.append(
                        f"{where} cites `{token}`, which is no {CHECK} row — either"
                        " the row was renamed and the argument now points at"
                        " nothing, or this is prose that should lose its backticks"
                    )
    return problems


def check_question(root, entry, by_name, reference, gaps, own):
    """Who owes a column's open rows an answer, and what would settle them.

    Stage 0's last exit bullet, and its two halves are unequal. The owner is a
    closed vocabulary and simply checked. The deferral is the part that had to be
    designed: `settled_by` names the `[[cell]]` the question would become, and
    two of its four values are ones the tree can already REFUSE — `sameness` on a
    column whose closure delta is non-empty (the answer this file's three
    measurement columns were parked on, now derived), and `absence` on a column
    that enables no gating feature and compiles the default crate set, which is
    every board preset.

    What it still cannot do is tell six real words from six nonsense ones. FOUR
    candidate rules were measured against the questions already in the tree and
    every one of them was refuted by those questions: requiring a `?` (14 of 28
    carry none and read as statements), requiring no two alike (the `-pqc`
    siblings honestly share a route, and six `[[cell]]` `why` bodies are already
    word for word), requiring a token the derivation knows (7 of 28 are about
    flash geometry and GPIO pins and name no identifier at all), and capping a
    maintainer-owed question so it stays answerable in a sentence — which is
    exactly backwards, because what saves the maintainer from re-deriving is the
    measurement, and the only question here that needs a ruling carries 105 words
    of it. So the stub is made to satisfy four claims the tree can disagree with
    instead of one it cannot, and the rest is what `run_count_gate.check_scope`
    says of its own labels: no program tells a right one from a wrong one.
    """
    column = entry.get("column")
    where = f"{LEDGER}: the settling question for `{column}`"
    stray = sorted(set(entry) - set(QUESTION_FIELDS))
    problems = [] if not stray else [
        f"{where} carries {stray}, which nothing reads — `[[cell]]` has refused a"
        f" field outside its own list since it shipped and this record had no list,"
        f" so a key added here was checked by nothing and printed by nothing"
    ]
    owner, settles = entry.get("owner"), entry.get("settled_by")
    if owner not in OWNERS:
        problems.append(
            f"{where} is owed by {owner!r}, which is not one of {sorted(OWNERS)}"
            " — an open question nobody owns is a wish with a column number"
        )
    if settles not in SETTLES:
        problems.append(
            f"{where} says `settled_by = {settles!r}`, which is not one of"
            f" {sorted(SETTLES)} — a deferral that cannot name what would end it"
            " is not deferred"
        )
        return problems
    if settles == "ruling" and owner != "maintainer":
        problems.append(
            f"{where} waits on a ruling and is owed by {owner!r} — a decision no"
            " derivation can produce is the maintainer's, per AGENTS.md"
        )
    open_rows, here = gaps.get(column, []), by_name.get(column)
    if here is None or reference is None:
        return problems
    if settles == "sameness" and closure_delta(here, reference):
        problems.append(
            f"{where} waits on an equivalence, and {sorted(closure_delta(here, reference))}"
            " compile unlike the default build — `same-cargo-features` is the only"
            " basis `equivalent` takes and the tree already refuses it here"
        )
    if settles == "absence" and not absence_reachable(root, here, open_rows, own):
        problems.append(
            f"{where} waits on the code being absent, and this column enables no"
            " feature production Rust gates on and compiles every open row's owner"
            " — neither basis `out-of-scope` takes can reach a cell here"
        )
    return problems


def absence_reachable(root, column, open_rows, own):
    """Whether `out-of-scope` could reach ANY open row of this column.

    Both of its bases, because either would do: an owner crate this column does
    not compile, or a cargo feature it enables that production Rust really gates
    on. A board preset has neither — it sets knobs and no feature, and compiles
    the default crate set — so the route is one the tree has already closed
    there. It says the route is OPEN, never that it is right: `check_gate` proves
    a switch exists in the property's blast radius, not that throwing it removed
    the property's gate, which is how a feature that only ADDS surface could
    still take the word.
    """
    if any(feature for feature in column.features if cfg_sites(root, feature)):
        return True
    return any(own.get(pid) and not (own[pid] & column.present) for pid in open_rows)


def check_chains(placed):
    """Every `equivalent` cell, followed until it reaches evidence or does not.

    An equivalence is a claim ABOUT another column: it inherits that column's
    disposition for the same property, and one step is not where that ends. A
    chain into a `gap` reaches nobody's judgement (`abrobot-4m` = `abrobot-16m`,
    whose own cells are undecided) and a closed one never reaches anything at all
    (`firmware-2mb` = `firmware-16mb` = `firmware-2mb`). Both were EXIT=0.
    """
    problems, split = [], {}
    for (pid, column), entry in placed.items():
        if entry.get("disposition") != "equivalent":
            continue
        # Keyed on the COLUMN, and the pair `(column, same_as)` it used to be
        # keyed on was an escape: closure equality is an equivalence relation, so
        # a second cell had only to name a DIFFERENT identical-closure column to
        # make a new key. Measured: a second `firmware-16mb` cell saying
        # `same_as = "waveshare-one"` — which chains to the same `firmware` — was
        # EXIT=0 for 5 more rows, its `why` free to contradict the first's.
        split.setdefault(column, set()).add(id(entry))
        seen, at = [column], entry.get("same_as")
        while True:
            if at in seen:
                problems.append(
                    f"{pid} × {column}: the `same_as` chain closes on itself"
                    f" ({' -> '.join(str(c) for c in [*seen, at])}) and reaches no evidence"
                )
                break
            seen.append(at)
            step = placed.get((pid, at))
            if step is None:
                problems.append(
                    f"{pid} × {column}: `same_as` reaches {pid} × {at}, which is a `gap`"
                    " — an equivalence to a cell nobody decided is undecided too"
                )
                break
            if step.get("disposition") == "equivalent":
                at = step.get("same_as")
                continue
            if step.get("disposition") != "covered":
                problems.append(
                    f"{pid} × {column}: `same_as` reaches a `{step.get('disposition')}`"
                    f" cell at {pid} × {at} — an equivalence carries that column's"
                    " disposition, so say THAT one here rather than pointing at it"
                )
            break
    for column, entries in sorted(split.items(), key=str):
        if len(entries) > 1:
            problems.append(
                f"{column}: {len(entries)} `equivalent` cells claim this one column"
                " — sameness of the derived closure is an equivalence relation, so"
                " they are one cell split in two whatever each names in `same_as`,"
                " and the halves are free to argue opposite things. Widen the first"
                " cell's `properties` instead, where the `why` that refuses the"
                " other rows is standing"
            )
    return problems


def check_cell(root, pid, column, entry, by_name, own, names):
    """Every way one cell's disposition disagrees with the tree."""
    where = f"{pid} × {column.name}"
    problems = []
    disposition, basis = entry.get("disposition"), entry.get("basis")
    if disposition not in DECLARABLE:
        problems.append(
            f"{where}: disposition `{disposition}` is not one of {DECLARABLE}"
            + (" — a gap is the ABSENCE of a cell here, and declaring one takes the"
               " column out of the rule that makes it owe a settling question"
               if disposition == "gap" else "")
        )
        return problems
    if len(entry.get("why", "").split()) < FLOOR_WORDS:
        problems.append(
            f"{where}: a disposition with no reason is not one — `why` is under"
            f" {FLOOR_WORDS} words"
        )
    if basis not in BASES:
        problems.append(f"{where}: basis `{basis}` is not one of {BASES}")
        return problems
    if basis not in ALLOWED[disposition]:
        problems.append(
            f"{where}: `{disposition}` may rest on {list(ALLOWED[disposition])} and this"
            f" cell says `{basis}` — a basis the tree cannot disagree with is how a"
            " judgement nobody made takes the strongest word in the vocabulary"
        )
        return problems
    stray = sorted(set(entry) - set(CELL_FIELDS) - set(BASIS_FIELDS[basis]))
    if stray:
        problems.append(
            f"{where}: carries {stray}, which basis `{basis}` does not read — a field"
            " nothing checks, and the page prints it beside the ones that are checked"
        )
    if basis == SAME_FEATURES:
        other = by_name.get(entry.get("same_as"))
        if other is None:
            problems.append(f"{where}: basis `{basis}` names no column in `same_as`")
        elif other.name == column.name:
            problems.append(f"{where}: `same_as` names its own column")
        elif closure_delta(column, other):
            problems.append(
                f"{where}: claims to compile like {other.name}, and"
                f" {sorted(closure_delta(column, other))} compile"
                " differently — an equivalence the tree refutes"
            )
        else:
            problems.extend(check_knobs(where, column, other, entry))
    if basis == CRATE_ABSENT:
        here = sorted(own.get(pid, frozenset()) & column.present)
        if here:
            problems.append(
                f"{where}: claims {pid}'s owners are absent, and {here} are compiled in"
            )
        elif not own.get(pid):
            problems.append(
                f"{where}: claims {pid}'s owners are absent and no production Rust owns"
                " it at all, so the claim is about nothing"
            )
    if basis == GATE_COMPILED_OUT:
        problems.extend(check_gate(root, where, pid, column, entry, own))
    if basis == DEFAULT_BUILD and not column.default:
        problems.append(
            f"{where}: basis `{basis}` on a column that enables {sorted(column.features)}"
            f" and sets {sorted(column.knobs)}"
        )
    if basis == CHECK_SH_ROWS:
        problems.extend(check_evidence(root, where, pid, column, entry, own, names))
    return problems


def check_gate(root, where, pid, column, entry, own):
    """A compiled-out gate, held to the switch the cell says was thrown.

    That the feature exists is not the claim — the claim is that THIS property's
    gate is what went. Eight store and boot rows declared out-of-scope on
    `firmware-fips` with `feature = "fips-profile"` passed on nothing more than
    some production Rust somewhere gating on that feature. So the cell names the
    `cfg` site(s), each one has to really gate on the feature, and each has to
    sit in the property's blast radius — which is the property's OWN owners, and
    was `carries | {"firmware"}`.

    That union is the hole this function shipped with, and it is the same hole
    one door over: `firmware` owns exactly one of the forty rows, so admitting it
    for all forty admits every `firmware/` switch as every property's gate. The
    reassembler is the measurement — `crates/rsk-usb` carries no `cfg` for any of
    the fourteen features in play and is compiled and live in all thirty-one
    columns, and `SEC-TRANS-001/002/003` × the nine columns whose feature has a
    `firmware/` site took `out-of-scope` on `firmware/src/presence.rs` at EXIT=0.
    27 cells, on a switch that is the touch button.

    So `firmware` is not a member of the radius, it is a ROUTE INTO it, and the
    cell has to say which one: [`hook`] names the trait the firmware site
    implements on the applets' behalf. Two things are then derived, and both
    refuse rather than excuse. The feature must gate code INSIDE that
    `impl <hook> for …` block, not merely somewhere in the file — `no-touch`
    gates inside `impl rsk_sdk::UserPresence for ButtonPresence`, while
    `strict-config`'s one site in `worker.rs` sits in an inherent `impl Worker`
    and reaches neither `MsgHandler` nor `ApduHandler`, which are the two traits
    `rsk-usb` would otherwise have named. And every one of the property's owner
    crates has to name the hook: `rsk-fido`, `rsk-device`, `rsk-oath` and
    `rsk-rescue` all name `UserPresence` and `rsk-usb` does not.

    What it still cannot say is that the hook is what the STATEMENT is about;
    that link is prose, and four crate-level rules for deriving it (the site's
    crate mentions, its `use` graph, a shared threat-model anchor, a shared
    identifier) were each measured against this pair and each admitted the false
    cell — `presence.rs` and `rsk-usb` share 177 identifiers once comments count.
    The trait is the narrowest thing the tree writes down, so it is the one asked
    for.
    """
    feature = entry.get("feature")
    if feature not in column.features:
        return [
            f"{where}: basis `{GATE_COMPILED_OUT}` names `{feature}`,"
            " which this column does not enable"
        ]
    gating = {str(path.relative_to(root)) for path in cfg_sites(root, feature)}
    if not gating:
        return [
            f"{where}: basis `{GATE_COMPILED_OUT}` names `{feature}`,"
            " and no production Rust gates on it"
        ]
    named = entry.get("cfg") or []
    if not named:
        return [
            f"{where}: basis `{GATE_COMPILED_OUT}` and no `cfg` — the tree gates on"
            f" `{feature}` in {sorted(gating)}, and which of those is {pid}'s gate is"
            " the whole claim"
        ]
    problems, carries, glue = [], own.get(pid, frozenset()), []
    for site in named:
        if site not in gating:
            problems.append(
                f"{where}: names `{site}`, which does not gate on `{feature}` —"
                f" the tree's sites are {sorted(gating)}"
            )
            continue
        crate = site.split("/")[1] if site.startswith("crates/") else "firmware"
        if crate in carries:
            continue
        if crate != "firmware":
            problems.append(
                f"{where}: `{site}` gates on `{feature}` in `{crate}`, and {pid} is"
                f" carried by {sorted(carries)} — that switch is another property's gate"
            )
            continue
        glue.append(site)
    hook = entry.get("hook")
    if glue and not hook:
        return problems + [
            f"{where}: {sorted(glue)} gate on `{feature}` in `firmware`, which does"
            f" not carry {pid} ({sorted(carries)} does) — name the `hook` the site"
            " implements for it, or the glue crate is every property's gate"
        ]
    if hook:
        problems.extend(check_hook(root, where, pid, feature, named, hook, carries))
    return problems


def check_hook(root, where, pid, feature, named, hook, carries):
    """The trait a `firmware/` gate stands in for, held to both of its ends.

    Read whenever a cell declares one, not only where the glue route needs it: a
    `hook` that were checked only when required would be a field nothing reads on
    every other cell, which is the shape `[[cell]]` has refused since it shipped.
    """
    impls = [site for site in named if impl_gates(root, site, hook, feature)]
    problems = []
    if not impls:
        problems.append(
            f"{where}: no `cfg` named here implements `{hook}` with `{feature}`"
            " gating code inside that impl — the hook is how a glue site becomes"
            f" {pid}'s gate, so a switch elsewhere in the file is not it"
        )
    leaf = names_artifact(hook.split("::")[-1])
    if not any(leaf.search(text) for text in crate_rust(root, carries)):
        problems.append(
            f"{where}: {sorted(carries)} — the crate(s) whose production Rust"
            f" carries {pid} — never name `{hook}`, so this hook wires some other"
            " property's code and the gate behind it is that property's"
        )
    return problems


#: An `impl <trait> for <type>` header, with the trait path AS WRITTEN. Generics
#: on either side are skipped: `impl<'a> Foo<'a> for Bar<'a>` is the same wiring
#: as `impl Foo for Bar`, and a cell made to spell the lifetimes out would be
#: naming the file's formatting rather than the trait.
IMPL_FOR = re.compile(
    r"^[ \t]*impl(?:\s*<[^>]*>)?\s+((?:[A-Za-z_]\w*::)*[A-Z]\w*)(?:\s*<[^>]*>)?\s+for\s[^{;]*\{",
    re.M,
)


@functools.cache
def impl_gates(root, site, hook, feature):
    """Whether `feature` gates code inside an `impl <hook> for …` at `site`.

    Brace-matched from the header rather than read to the next `impl`, because an
    inherent `impl Worker` sitting after the trait one would otherwise donate its
    switches to the trait above it — which is exactly the pair the reassembler
    measurement turns on. An unbalanced file yields no block and the caller then
    refuses, which is the direction a parse this crude has to fail in.
    """
    text = (root / site).read_text(errors="ignore")
    pattern = re.compile(rf'feature\s*=\s*"{re.escape(feature)}"')
    for found in IMPL_FOR.finditer(text):
        if found.group(1) != hook:
            continue
        at, depth = found.end() - 1, 0
        for index in range(at, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    if pattern.search(text[at : index + 1]):
                        return True
                    break
    return False


@functools.cache
def crate_rust(root, crates):
    """The production Rust of `crates`, as text. Cached: one read per gate cell."""
    out = []
    for path in production_rust(root):
        rel = path.relative_to(root).parts
        if (rel[1] if rel[0] == "crates" else "firmware") in crates:
            out.append(path.read_text(errors="ignore"))
    return tuple(out)


def check_evidence(root, where, pid, column, entry, own, names):
    """The `check.sh` rows a `covered` cell names, held to the cell it is under.

    Two things, and both are needed. A row is about this COLUMN only if it builds
    this column — the same cargo features and the same build knobs; features
    alone are vacuously equal on the six board presets and on every column whose
    delta is geometry, which is most of them. And a row is about this PROPERTY
    only if it selects a crate whose production Rust carries the property's tag:
    without that half, a row that merely COMPILES the image counted, and
    `build firmware (test, --features no-touch)` re-declared the four presence
    statements `covered` on the very image that removes their gate.

    And a third, which used to be left to the `why`: a row that only COMPILES is
    refused outright. Measured before the rule was written — 89 cells would pass
    the two checks above today, and 9 of them name nothing but a `cargo build` or
    a `cargo clippy` row. `build firmware (display)` builds the exact image
    `firmware-display` is and runs not one line of it, so `covered` on it asserts
    that a statement HOLDS there on the strength of the compiler accepting the
    file. That is the same "a row that merely compiles the image counted" the
    owner-crate half was added for, one step in: the row now selects the right
    crate and still measures nothing.

    And a fourth, which is the ledger's own first sentence and the one the gate
    ran without: `covered` says THE REGISTRY'S EVIDENCE was produced here, so the
    row has to have produced some of it. [`registry_evidence`] derives what that
    is — a Kani harness, a fuzz target, a `tests/*.py` — and a row that names
    none of them measured something else. Measured before the rule was written:
    80 `gap` cells passed every check above on an existing row, carried by eight
    `cargo test` rows, and not one of the eight produces any registered evidence
    for any of the 40 rows. That is what made `test (bench)` — four selector
    tests and one ignored loop — a legal basis for ten `covered` cells while the
    same ledger's prose argued it was not; the two halves of the definition were
    being read one at a time.

    And a fifth, on the knob half of the first: a knob is pinned only if the
    command the `env` prefix wraps can SEE it. The prefix used to be read on its
    own, so `env FLASH_SIZE=16M cargo kani -p rsk-fido …` "built" the sixteen-
    megabyte image on a package whose build script reads `AAGUID` and nothing
    else — the `-p`/`--features`-read-out-of-any-text hole with the third field
    playing the part. [`inert_knobs`] carries the measurement.

    And a sixth, which is the fifth one's own input: WHICH packages the row
    compiles, in all four spellings cargo has for it rather than in `-p` alone.
    [`cargo_roots`] carries that, and the coupling is the finding — the knob rule
    and the owner rule read the same answer, so widening one without the other
    opens the hole it closes. Measured on the shipped tree with only `-p` read:
    a `--manifest-path crates/rsk-fido/Cargo.toml` row and a `--workspace
    --exclude firmware --exclude rsk-wipe` row both walked past the knob rule —
    `builds` saw no selection and took the whole workspace, in which `firmware`
    reads every knob — and both were then caught one clause down for naming no
    owner crate, which is a different sentence and only accidentally true.
    """
    named = entry.get("evidence") or []
    if not named:
        return [
            f"{where}: basis `{CHECK_SH_ROWS}` and no `evidence` — name the rows that"
            " produced it, or the claim is the prose basis this vocabulary dropped"
        ]
    rows, problems, inert, runs_owner = check_sh_rows(root), [], [], False
    artifacts = registry_evidence(root, names[pid]) if pid in names else ()
    produces = False
    for label in named:
        if label not in rows:
            problems.append(f"{where}: names `{label}`, which is no {CHECK} row")
            continue
        features, env, command = rows[label]
        if features != column.features:
            problems.append(
                f"{where}: `{label}` builds {sorted(features)} and this column is"
                f" {sorted(column.features)} — evidence from another image"
            )
        cargo = cargo_part(command)
        roots, unreadable = cargo_roots(root, cargo)
        open_knobs = unpinned_knobs(column, env)
        if open_knobs:
            problems.append(
                f"{where}: `{label}` does not pin {open_knobs} — the row ran at other"
                " build knobs than this column's, so it measured another image"
            )
        if unreadable:
            problems.append(
                f"{where}: `{label}` selects its packages with {list(unreadable)}, which"
                " names no `[workspace] member` this gate can resolve — which packages"
                " the row compiles decides both the knob rule and the owner rule, and"
                " `covered` may not rest on a selection nobody can read"
            )
        dead = inert_knobs(root, column, env, roots or frozenset())
        if dead:
            problems.append(
                f"{where}: `{label}` sets {dead} in an `env` prefix and no package it"
                f" builds reads {'them' if len(dead) > 1 else 'it'} — a knob the"
                " command in front of it never sees pins nothing, so the row built"
                " this tree's default geometry and measured the default image"
            )
        # Held back rather than appended: the owner-crate message below is
        # emitted only over an otherwise-clean row, so raising this one inline
        # would SUPPRESS it — and a row that both compiles nothing and names the
        # wrong crate owes the reader both reasons, not whichever ran first.
        subcommand = CARGO_SUB.search(command)
        if subcommand and subcommand.group(1) in COMPILE_ONLY:
            inert.append(
                f"{where}: `{label}` runs `cargo {subcommand.group(1)}` — it compiles"
                f" this column and executes none of it, so it cannot say {pid} holds"
                " here. `covered` is the word for a measurement"
            )
        for word in name_filters(cargo):
            if not selected_tests(root, roots or frozenset(), word):
                inert.append(
                    f"{where}: `{label}` filters `cargo test` on `{word}`, and no"
                    f" `#[test]` in {sorted(roots or ()) or 'the workspace'}"
                    " carries that name — the row runs 0 tests and exits 0, which is"
                    " a green row that measured nothing"
                )
        runs_owner |= bool(own.get(pid, frozenset()) & (roots or frozenset()))
        produces |= any(names_artifact(artifact).search(command) for artifact in artifacts)
    if not runs_owner and not problems:
        problems.append(
            f"{where}: no row named here selects {sorted(own.get(pid, frozenset()))},"
            f" the crate(s) whose production Rust carries {pid} — a row that compiles"
            " this image is not evidence about this property"
        )
    if not produces:
        inert.append(
            f"{where}: no row named here runs any of {pid}'s registered evidence"
            f" ({list(artifacts) or 'the registry derives none that a row can run'})"
            " — `covered` says the REGISTRY's evidence was produced on this"
            " configuration, and a crate's own unit tests are in none of its classes"
        )
    return problems + inert


#: A `#[test]` function — what a `cargo test` name filter can actually select.
#: A Kani harness is `#[cfg(kani)]` and is compiled by no `cargo test`, and the
#: `_assurance.rs` mirror beside it is a plain `pub fn` of the same name, so a
#: bare `fn` scan would have found the name and excused the row. The attribute is
#: the whole rule.
TEST_FN = re.compile(r"#\[(?:\w+::)*test\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+(\w+)")


def name_filters(cargo):
    """The positional name filters a `cargo test` command passes the harness.

    `cargo test … --target "$HOST" reset_keeps_the_pin_gate` prints `running 0
    tests … 664 filtered out` and exits 0, and the gate read that as evidence —
    this repo's own recorded trap (`cargo test -- a b --exact` selects zero tests
    at rc 0), arriving inside the matrix. Which words are operands is derived
    from the command: a `-` token takes the next word unless that word is itself
    a `-` token, so `--workspace --exclude firmware` reads correctly and so does
    `--target "$HOST" bench`. The shape it cannot see is a boolean flag written
    immediately before the filter (`cargo test --release bench`), which reads the
    filter as that flag's operand and lets the row through; none of this tree's
    14 `cargo test` rows is written that way.
    """
    words = cargo.split()
    if words[:2] != ["cargo", "test"]:
        return []
    out, at = [], 2
    while at < len(words):
        word = words[at]
        if word.startswith("-"):
            takes = "=" not in word and at + 1 < len(words) and not words[at + 1].startswith("-")
            at += 2 if takes else 1
            continue
        out.append(word)
        at += 1
    return out


@functools.cache
def member_dirs(root):
    """package name -> its directory, for every [workspace] member."""
    members = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["members"]
    out = {}
    for member in members:
        doc = tomllib.loads((root / member / "Cargo.toml").read_text())
        out[doc["package"]["name"]] = member
    return out


@functools.cache
def selected_tests(root, crates, word):
    """Whether any `#[test]` in `crates` carries `word` — cargo's substring match.

    An empty `crates` is `--workspace` and every member is searched, which is the
    permissive reading of the one input this cannot resolve; the refusal it
    raises is about a name nothing in the tree answers to, and widening the
    haystack only makes that refusal harder to earn.
    """
    dirs = member_dirs(root)
    for crate in sorted(crates) or sorted(dirs):
        where = root / dirs.get(crate, crate)
        if not where.is_dir():
            continue
        for path in sorted(where.rglob("*.rs")):
            if any(word in name for name in TEST_FN.findall(path.read_text(errors="ignore"))):
                return True
    return False


def knob_pins(column):
    """The `VAR=value` pairs a row's `env` prefix has to carry to build this column.

    One reader for both knob rules, because they are two questions about the same
    short list: whether the row SET each of them, and whether anything the row
    builds ever READS it. A board preset is one pair however many keys it sets —
    a row reaches a board by its name, which is [`env_name`]'s note.
    """
    if column.kind == "board":
        return {"BOARD": column.name}
    return {env_name(key): value for key, value in column.knobs.items()}


def unpinned_knobs(column, env):
    """The column's build knobs a row leaves at some other value, as `KEY=value`."""
    return sorted(
        f"{var}={value}" for var, value in knob_pins(column).items() if env.get(var) != value
    )


@functools.cache
def env_spellings(root, crate):
    """(the variables `crate` READS by name, the ones it only DECLARES a rerun on).

    Two sets and not one, because they are the same fact written two ways and the
    file needs both answers: their union is what a package reads (a knob whose
    read this file cannot lex is still read), their difference is a spelling no
    reader here can see. [`RERUN_ENV`] carries the measurement that made the
    split necessary.
    """
    where = root / member_dirs(root).get(crate, crate)
    if not where.is_dir():
        return frozenset(), frozenset()
    read, declared = set(), set()
    for path in sorted(where.rglob("*.rs")):
        text = path.read_text(errors="ignore")
        read.update(ENV_READ.findall(text))
        declared.update(RERUN_ENV.findall(text))
    return frozenset(read), frozenset(declared - read)


def env_reads(root, crate):
    """The environment variables `crate`'s own sources read, by either spelling.

    Measured on this tree before the rule above it was written: the five
    variables the matrix can ask a row about — `BOARD`, `FLASH_SIZE`, `KVMAIN`,
    `LED_KIND`, `VIDPID` — are read by `firmware` and `rsk-wipe` and by nothing
    else in the workspace, while `rsk-fido`'s build script reads `AAGUID` and
    `rsk-sdk`'s reads `FW_VERSION`. That last pair is the shape [`builds`] is
    about: a knob can be read by a package the row never names.

    The declared half is unioned in rather than trusted alone: on its own it
    would let a package claim a reader with one dead `println!`, which is the
    permissive direction. What stops that is [`unreadable_env_reads`], which is
    red on exactly the rows this union is green on.
    """
    read, declared_only = env_spellings(root, crate)
    return read | declared_only


def unreadable_env_reads(root):
    """Knobs a package declares a rerun on and no reader here can find it reading.

    The live half of the knob rule, and deliberately live: it runs over the
    workspace on every invocation, where [`inert_knobs`] runs only under a
    `covered` cell whose basis is `check-sh-rows` — of which this ledger has
    none today, so that clause's only exercise is its fixture.

    Measured on this tree: 38 declarations across `firmware`, `rsk-wipe`,
    `rsk-fido` and `rsk-sdk`, and every one of them is also a literal read, so
    this is silent. It is not silent on the rewrite that motivated it.
    """
    return [
        f"{member_dirs(root)[crate]} declares `cargo:rerun-if-env-changed={var}`"
        f" and no `env::var(\"{var}\")` in `{crate}` that this gate can read —"
        " the knob rule reads the literal spelling, so a row that DOES build this"
        " knob would be told no package it builds reads it. Write the read out,"
        " or drop the declaration"
        for crate in sorted(member_dirs(root))
        for var in sorted(env_spellings(root, crate)[1])
    ]


def cargo_roots(root, cargo):
    """(the workspace packages `cargo` NAMES or None if it names none, unreadable spellings).

    `gate_lines.selection` reads the flags; this resolves them against THIS
    checkout, which is the half that cannot live there. All four of cargo's
    spellings, because reading only `-p` was the same hole one field over as the
    two this file has already closed: `--manifest-path crates/rsk-fido/Cargo.toml`
    and `--workspace --exclude firmware --exclude rsk-wipe` each select something
    quite different from the whole tree, `scripts/check.sh` writes the first
    twenty times over (fifteen of them on a `run` row, every one naming a
    manifest outside this workspace) and the second five, and neither was read.

    `None` is the answer for a command that names no selection, and it is not the
    empty set: the two callers below have to read that case in OPPOSITE
    directions and one value cannot carry both. [`builds`] takes it as
    `--workspace` — the permissive reading of an input nothing can resolve, and
    the same one [`selected_tests`] takes — while the owner-crate rule takes it
    as naming nobody, because a row that names no crate is not a row about this
    property. Reading it one way in both places is a hole either way round:
    permissively, a bare `cargo test --workspace` becomes evidence about every
    property in the tree; strictly, every `--exclude` row is refused for a reason
    that is not true of it.

    An unresolvable spelling is neither, and it is returned rather than guessed —
    a manifest outside `[workspace] members` (`tools/emu/Cargo.toml`), one behind
    a substitution (`"$src/Cargo.toml"`), a generated `-p`. Guessing costs a hole
    in one direction and a false alarm in the other, and there is no third answer
    that is true of both `tools/emu` and `$src`.
    """
    sel = gate_lines.selection(cargo)
    by_dir = {rel: name for name, rel in member_dirs(root).items()}
    named, unreadable = set(sel.named), list(sel.generated)
    for raw in sel.manifests:
        where = str(pathlib.PurePosixPath(raw).parent)
        if where in ("", "."):
            continue  # the workspace root: every member, which is the default below
        if where in by_dir:
            named.add(by_dir[where])
        else:
            unreadable.append(f"--manifest-path {raw}")
    if not named and sel.excluded:
        named = set(workspace(root)) - set(sel.excluded)
    return (frozenset(named) or None), tuple(unreadable)


@functools.cache
def builds(root, crates):
    """The workspace packages a row's cargo invocation compiles, dependencies included.

    A build script runs for every package in the unit graph and not only for the
    ones named on the command line, so `-p firmware` really does read whatever
    `rsk-fido`'s `build.rs` reads. `crates` comes from [`cargo_roots`], which
    reads all four of cargo's selection spellings; an empty one is that
    function's `None` — no selection named — and every member is walked.
    """
    manifests = workspace(root)
    out, queue = set(), list(crates or manifests)
    while queue:
        crate = queue.pop()
        if crate in out or crate not in manifests:
            continue
        out.add(crate)
        queue.extend(_deps(manifests[crate]))
    return frozenset(out)


def inert_knobs(root, column, env, crates):
    """The knobs a row's `env` prefix sets that nothing the row builds ever reads.

    The fifth of this file's holes in one family, and the twin of the `-p` and
    `--features` one a field over: those were read out of any text on the row
    until they were read from the cargo invocation, and a knob was read out of
    the `env` prefix and never asked whether the command it prefixes can see it.
    Driven on this tree before the rule: `env FLASH_SIZE=16M cargo kani -p
    rsk-fido --harness reset_keeps_the_pin_gate` carried `SEC-FIDO-006A` ×
    `firmware-16mb` to `covered` at EXIT=0, on a package whose build script reads
    `AAGUID` and nothing else. One such row per column and the maximal false
    ledger measures 37 -> 102 `covered` over eight of the ten knob-bearing
    columns, still at EXIT=0.

    Only the knobs the row actually NAMES, so each one raises one finding:
    a knob the prefix leaves out is already [`unpinned_knobs`]'s, and a reader
    owed two messages about one variable is owed one.
    """
    reads = {var for crate in builds(root, crates) for var in env_reads(root, crate)}
    return sorted(var for var in knob_pins(column) if var in env and var not in reads)


def closure_delta(column, other):
    """crate -> (its features here, its features there) where the two differ.

    The cargo half of an equivalence, and ONE derivation read twice: `check_cell`
    refuses a `same-cargo-features` cell whose delta is non-empty, and `render`
    prints the same delta for every column. So the page shows the sameness the
    gate checks rather than a sentence someone has to keep true — which is what
    the three never-published measurement builds needed, their whole story being
    that delta (`bench` moves `rsk-fido` and pulls `rsk-bench` in; `keygen-bench`
    moves one flag on `firmware` and nothing else).

    `None` on a side means the crate is not compiled into that column at all, and
    it is not `frozenset()`: a crate present with no features of its own is not
    an absent one, and reading both as "no features" hid `rsk-bench` entering the
    image — the one delta of the three that reaches a crate boundary.
    """
    out = {}
    for crate in sorted(column.present | other.present):
        here = column.closure.get(crate, frozenset()) if crate in column.present else None
        there = other.closure.get(crate, frozenset()) if crate in other.present else None
        if here != there:
            out[crate] = (here, there)
    return out


def _crate_delta(crate, here, there):
    """One [`closure_delta`] entry, for the page. Absence is said, not implied."""
    if there is None:
        return f"`{crate}` (added)"
    if here is None:
        return f"`{crate}` (absent)"
    marks = [f"+`{f}`" for f in sorted(here - there)]
    marks += [f"-`{f}`" for f in sorted(there - here)]
    return f"`{crate}` " + " ".join(marks)


def knob_delta(column, other):
    """The build knobs the two columns do not agree on, as `key=value`.

    With the VALUE, because the names alone cannot see the edit that matters:
    `waveshare-one` earns its equivalence by setting seven knobs to the values
    `build.rs` already defaults to, and moving its `flash.size_mb` from 4 to 16
    leaves the name list identical. No attempt is made to reconcile the two
    spellings of one knob (a flake argument `flashSize`, a board key
    `flash.size_mb`) — that would be a mapping table going stale beside
    `build.rs`, and both spellings reaching the reader is the honest answer.

    A knob this column does not set at all reads `(unset)` and not `key=`, which
    is the empty string a knob can also be SET to. No pair in the ledger today
    puts a knob on the far side only, so nothing here moves — the spelling is for
    the first cell that does.
    """
    return sorted(
        f"{key}={column.knobs[key]}" if key in column.knobs else f"{key}=(unset)"
        for key in set(column.knobs) | set(other.knobs)
        if column.knobs.get(key) != other.knobs.get(key)
    )


def check_knobs(where, column, other, entry):
    """The half of an equivalence the feature closure cannot see.

    Every `same-cargo-features` cell in this tree compares an empty feature set
    with an empty one — that is what "the delta is knobs" MEANS — so without this
    the row's one machine-checked rule was vacuous on all of them. The knobs are
    compile-time: `build.rs` turns them into `rustc-env` constants, two
    `rustc-cfg` values and a regenerated `memory.x`.
    """
    if len(entry.get("columns", [])) != 1:
        return [
            f"{where}: an `equivalent` cell names {len(entry['columns'])} columns —"
            " the knob delta is per column, so each one is its own cell"
        ]
    derived = knob_delta(column, other)
    declared = entry.get("knob_delta")
    if declared is None:
        return [
            f"{where}: an `equivalent` on identical cargo features owes a"
            f" `knob_delta`; the tree derives {derived}"
        ]
    if sorted(declared) != derived:
        return [
            f"{where}: declares the knob delta {sorted(declared)} and the tree"
            f" derives {derived} — re-decide the cell, do not re-label it"
        ]
    return []


@functools.cache
def cfg_sites(root, feature):
    """The production files that gate on `feature` — the switch's existence.

    Production on [`production_rust`]'s reading, which is `assurance_gate`'s: a
    `cfg` in a file no buildable image compiles is not a gate in the image, and a
    cell that named one would be pointing at code the firmware never runs.
    """
    if not feature:
        return []
    pattern = re.compile(rf'feature\s*=\s*"{re.escape(feature)}"')
    return [
        path
        for path in production_rust(root)
        if pattern.search(path.read_text(errors="ignore"))
    ]


# --- the artifact -----------------------------------------------------------


def render(root):
    """`docs/assurance-matrix.md` as the derivation and the ledger make it."""
    manifests = workspace(root)
    cols = columns(root, manifests)
    doc = ledger(root)
    entries = registry(root)
    ids = [pid for pid, _name in entries]
    names = dict(entries)
    tranche = {
        pid: name for name in TRANCHES for pid in doc.get("tranche", {}).get(name, [])
    }
    rows = [pid for pid in ids if tranche.get(pid) in ROW_TRANCHES]
    placed = dict(expand(doc, []))
    questions = {q["column"]: q for q in doc.get("question", [])}

    out = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        f"<!-- {GENERATED_BY} — do not edit by hand -->",
        "",
        "# Assurance matrix",
        "",
        claims_gate.DISCLAIMER_PARAGRAPH,
        "",
        "Which security property is claimed about which buildable image. The rows are"
        " the P0-family properties of `assurance/properties.toml`; the columns are"
        " derived from `nix/firmware.nix`, `firmware/Cargo.toml` and"
        " `firmware/boards/`, so a new package, feature or board arrives as a column"
        " of `gap` cells rather than as silence. `scripts/matrix_gate.py` regenerates"
        " this page and `scripts/check.sh` diffs it.",
        "",
        "The point of the page is the thing a single-build claim hides: **the firmware"
        " is not one thing.** Four of the twenty-two images remove the physical-consent"
        " gate the authorization properties are about, one swaps the CTAP large-blob"
        " surface with no flake package at all, and the board axis changes the flash"
        " geometry on which a whole KV store once survived a \"successful\" wipe.",
        "",
        "These are the **committed** configurations, not the buildable ones. Every"
        " `mkFirmware` knob falls back to a like-named environment variable and"
        " `lib.mkFirmware` is exported, so `FLASH_SIZE=2M nix build --impure .#firmware`"
        " is an image no column below describes — including under a disposition whose"
        " reason says \"no cargo feature and no build knob\". What this page disposes of"
        " is what the flake ships and what CI builds; a one-off `--impure` combination"
        " is outside it by construction.",
        "",
        "| Disposition | Code | Means |",
        "|---|---|---|",
        "| `covered` | `cov` | the evidence the registry records was produced on"
        " this configuration; on any column but the default build the cell names the"
        " `check.sh` rows, and the gate re-derives both that they build THIS image"
        " and that they ran evidence the registry actually derives for the property —"
        " a Kani harness, a fuzz target or a `tests/*.py`, never a crate's unit tests |",
        "| `equivalent` | `equ` | this configuration enables exactly the cargo features another does; `same_as` names it, the gate re-derives both closures, and the cell must write down the build knobs that still differ |",
        "| `conditional` | `cnd` | claimed only under a stated condition |",
        "| `out-of-scope` | `oos` | the claim is not made here — the code it is about is absent, or the gate it is about is compiled out |",
        "| `gap` | `gap` | nobody has decided yet; the column's settling question is below |",
        "",
        "## The axes",
        "",
        f"- **{len([c for c in cols if c.kind == 'package'])} flake packages**"
        f" (`nix/firmware.nix`), of which"
        f" **{len([c for c in cols if c.kind == 'package' and c.published])}** are"
        " published by `.github/workflows/release-build.yml` — the published set is a"
        " named subset of the matrix, never the matrix.",
        f"- **{len([c for c in cols if c.kind == 'feature'])} orthogonal cargo features**"
        " (`firmware/Cargo.toml`) that no flake package expresses.",
        f"- **{len([c for c in cols if c.kind == 'board'])} board presets**"
        " (`firmware/boards/*.toml`): `BOARD=<name>` sets the same knobs the flake"
        " arguments do, and no cargo feature.",
        "",
        "## Columns",
        "",
        "The last cell is DERIVED, not declared: the per-crate cargo-feature"
        " closure this column resolves to, against the default build's. It is the"
        " same derivation the `equivalent` rule refuses a cell on, so a column"
        " reading `—` there compiles the workspace exactly as the default build"
        " does and its whole delta is knobs — and a column that names a crate has"
        " that crate's code moving under every row of its column, which is the"
        " fact a `gap` there is about.",
        "",
        "| # | Configuration | Kind | Published | Cargo features | Knobs | Compiles unlike the default build |",
        "|---|---|---|---|---|---|---|",
    ]
    index = {column.name: f"{n:02d}" for n, column in enumerate(cols, 1)}
    # The default build is derived (no feature, no knob) rather than named, so a
    # renamed `firmware` cannot leave the page measuring against nothing in
    # silence. Without one there is no origin to measure from and the cell says so.
    reference = reference_column(cols)
    for column in cols:
        feats = ", ".join(f"`{f}`" for f in sorted(column.features)) or "—"
        knobs = ", ".join(f"`{k}={v}`" for k, v in sorted(column.knobs.items())) or "—"
        flag = "yes" if column.published else ("n/a" if column.kind != "package" else "no")
        if reference is None:
            delta = "n/a — no column derives as the default build"
        else:
            delta = ", ".join(
                _crate_delta(crate, here, there)
                for crate, (here, there) in closure_delta(column, reference).items()
            ) or "—"
        out.append(
            f"| {index[column.name]} | `{column.name}` | {column.kind} | {flag}"
            f" | {feats} | {knobs} | {delta} |"
        )

    out += [
        "",
        "## The matrix",
        "",
        f"{len(rows)} rows × {len(cols)} columns = {len(rows) * len(cols)} cells."
        " Column numbers are the table above.",
        "",
        "| Property | " + " | ".join(index[c.name] for c in cols) + " |",
        "|---" * (len(cols) + 1) + "|",
    ]
    for pid in rows:
        line = [f"`{pid}`"]
        for column in cols:
            entry = placed.get((pid, column.name))
            line.append(CODE[entry["disposition"]] if entry else CODE["gap"])
        out.append("| " + " | ".join(line) + " |")

    out += ["", "## Dispositions", ""]
    for entry in doc.get("cell", []):
        cs = ", ".join(f"`{c}`" for c in entry["columns"])
        ps = ", ".join(f"`{p}`" for p in entry["properties"])
        extra = ""
        if entry.get("same_as"):
            knobs = ", ".join(f"`{k}`" for k in entry.get("knob_delta", [])) or "none"
            extra = f" (`same_as = {entry['same_as']}`; knob delta: {knobs})"
        elif entry.get("feature"):
            sites = ", ".join(f"`{s}`" for s in entry.get("cfg", [])) or "none"
            hook = entry.get("hook")
            extra = f" (`feature = {entry['feature']}`; gate: {sites}"
            extra += f"; hook: `{hook}`)" if hook else ")"
        out += [
            f"**{entry['disposition']}** — basis `{entry['basis']}`{extra}",
            "",
            f"- columns: {cs}",
            f"- properties: {ps}",
            f"- {entry['why']}",
            "",
        ]

    own = owners(root)
    # The caveat on the middle column, DERIVED — and the diagnosis that came with
    # it was backwards. "Three P0-family rows carry no production tag" was EXACT
    # when it was written at 41ddf88 (`SEC-FIDO-006A/B/C`, re-derived there) and
    # went to zero at fc7491a, which tagged them. So it was not a number wrong on
    # arrival, it was one that ROTTED — which is the stronger argument for
    # deriving it, and the weaker one was the one recorded.
    untagged = sorted(pid for pid in rows if not own.get(pid))
    blind = (
        f"{len(untagged)} P0-family row(s) carry no production tag at all"
        f" ({', '.join(f'`{pid}`' for pid in untagged)}) and count as not moving,"
        " which is the one direction this number can be wrong in."
        if untagged
        else "Every P0-family row carries a production tag, so the one direction"
        " this number could be wrong in — an untagged row counting as not moving —"
        " is empty here."
    )
    out += [
        "## Open gaps",
        "",
        "The middle column is derived, and it is what a `gap` here costs: the open"
        " rows whose OWNING crates — the ones whose production Rust carries the"
        " property's tag — are among the crates the column compiles unlike the"
        " default build, above. Outside it, the code the statement is about did not"
        " move and the question is whether the rest of the image reaches it; inside"
        " it, the statement is about a different compilation. " + blind,
        "",
        "",
        "The two after it are the ledger's, and they are Stage 0's last exit"
        " bullet: who owes the answer, and what would end the deferral. `Settled"
        " by` is typed rather than dated — `evidence` is a `check.sh` row built at"
        " this column, `absence` an `out-of-scope` argument, `sameness` an"
        " `equivalent` one, and `ruling` a decision no derivation can produce,"
        " which is the maintainer's. The gate refuses `sameness` where the closure"
        " delta is non-empty and `absence` where neither of its bases can reach a"
        " row, so two of the four are claims the tree can already disagree with.",
        "",
        "| Configuration | `gap` rows | of which the owner crate moves | Owed by | Settled by | The question that would settle them |",
        "|---|---|---|---|---|---|",
    ]
    for column in cols:
        open_rows = [pid for pid in rows if (pid, column.name) not in placed]
        if open_rows:
            moved = set(closure_delta(column, reference)) if reference else set()
            reaches = sum(1 for pid in open_rows if own.get(pid, frozenset()) & moved)
            asked = questions.get(column.name, {})
            out.append(
                f"| `{column.name}` | {len(open_rows)} | {reaches}"
                f" | {asked.get('owner', '')} | `{asked.get('settled_by', '')}`"
                f" | {asked.get('text', '')} |"
            )

    out += [
        "",
        "## Property names",
        "",
        "| ID | Invariant | Tranche |",
        "|---|---|---|",
    ]
    for pid in rows:
        out.append(f"| `{pid}` | `{names[pid]}` | {tranche[pid]} |")
    return "\n".join(out) + "\n"


def run(root, write=False):
    root = pathlib.Path(root)
    if write:
        (root / ARTIFACT).write_text(render(root))
        print(f"matrix-gate: wrote {ARTIFACT}")
        return 0
    try:
        problems, summary = audit(root)
    except (*MALFORMED, ValueError) as error:
        problems, summary = [f"the axes cannot be derived from the tree: {error}"], ""
    # Always, not only on an otherwise-clean ledger: a new package arrives as a
    # column of gaps AND a stale artifact, and the reader who has to regenerate
    # should be told so in the same run rather than on the next one.
    try:
        want = render(root)
    except (*MALFORMED, ValueError) as error:
        problems.append(f"{ARTIFACT} cannot be generated from {LEDGER}: {error}")
    else:
        # Bytes, not text: `read_text` folds `\r\n` to `\n`, so a CRLF copy
        # compared as text is equal to a LF one — the lesson `config_gen_gate.py`
        # already wrote down, in the very file this row names as its model.
        got = (root / ARTIFACT).read_bytes() if (root / ARTIFACT).is_file() else b""
        if want.encode() != got:
            problems.append(
                f"{ARTIFACT} is not what the generator writes — run"
                " `python scripts/matrix_gate.py --write` and commit the result"
            )
    if problems:
        print(f"matrix-gate: {len(problems)} finding(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery P0-family property owes each buildable configuration a"
            " disposition:\ncovered, equivalent, conditional, out-of-scope or gap."
            f" Decide the cell in\n{LEDGER}; a claim about \"the firmware\" that is"
            " true of one image\nand untested on eighteen others is the failure this row"
            " is for.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


def main():
    argv = sys.argv[1:]
    if argv and argv != ["--write"]:
        print("usage: matrix_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    sys.exit(main())
