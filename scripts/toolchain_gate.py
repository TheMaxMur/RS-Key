#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The build and verification toolchain, enumerated from the files that pin it.

Stage 11A work 1's fourth exit criterion asks that compiler, linker, LLVM passes,
assembler, bootrom and FFI be enumerated in the TCB **by a generator from the
pinned toolchain closure, not by a list in prose**. Measured against the tree
this was written for, one of those six was generated and five were not: the
compiler set comes out of the image's own DWARF (scripts/elf_gate.py's
`DW_AT_producer` reader), and `flip-link`, `rust-lld`, `arm-none-eabi-as`, the
bootrom and every FFI boundary appeared in no registry, no gate and no page. A
`grep -rn "flip-link\\|rust-lld" assurance/ scripts/*.py` answered with nothing.

What did exist was per-bundle: a `[[tool]]` group inside each evidence bundle,
floored at 20 leaves by scripts/bundle_gate.py, 92 rows over 17 bundles and 12
distinct names. Those rows carry a `version` STRING and no hash of any kind — the
only sha256 a bundle holds is on an `[[artifact]]`. A version string in a bundle
is a record of what somebody wrote down at the time, which is the right thing for
a bundle and not a thing anything re-reads.

So this gate reads assurance/toolchain.toml, and the rule that makes the file
worth having is that **a `pin` is never the authority**. Each row also names a
`provenance` — a file this script opens on every run — and the row is refused
unless that file still says the same value. The registry is therefore a second
copy that cannot rot silently, rather than a second copy that can.

## The rules

1. **`flake.lock:<input>`** resolves through the lock's `root` node to a real
   node, and `pin` equals that node's `locked.rev`.
2. **`Cargo.lock:<pkg>`** resolves to exactly one `[[package]]`, and `pin` equals
   its `checksum`. This is the rule that catches `cortex-m` — a PREBUILT asm blob
   assembled by a 2021 nightly and shipped as bytes, the second DWARF producer of
   the image and the one producer in it that no nix input pins.
3. **`workflow:<file>:<VAR>`** resolves to a real `env:` assignment in that file,
   and every workflow that assigns `VAR` assigns the SAME value. `KANI_VERSION`
   is written three times — .github/workflows/ci.yml:155,
   .github/workflows/deep-checks.yml:354 and :446 — and this rule names the
   disagreeing files. It is no longer the only holder: `scripts/kani_gate.py`
   read one of those files and now reads all of them, because the hold here is
   CONTINGENT and that one is not. Measured: deleting the `cargo-kani` row from
   the registry and re-running `--write` is exit 0 — 12 tools, 11 resolved, both
   floors below are still clear — and with it gone, moving ci.yml:155 alone was
   exit 0 again.
4. **`unpinned`** is legal only where `pin` names a `PLAT-TOOL*` row of
   assurance/platform.toml whose `status` is still `pending`. Without it the
   registry becomes the quiet place to park a gap: a row saying nothing pins this
   would satisfy every other rule here.
5. **Both ways over the flake's root inputs.** Every root input is named by some
   tool's provenance or carries a `[[not_tcb]]` row with a reason, and every
   `[[not_tcb]]` names a root input that still exists. A registry that lists only
   what somebody remembered is undetectable from the inside — each row can be
   correct while the set is short — and that is the failure this whole class of
   file exists to prevent.
6. **Both ways over the FFI boundaries.** Every place a name in this tree binds
   to a symbol Rust does not define — an item an `extern` block declares, an item
   defined here for a foreign caller, a foreign translation unit a `build.rs`
   hands to `cc` — is derived from the tree and claimed by a `[[boundary]]` row,
   and every row claims a crossing the tree still has. Each row also names the
   pinned `[[tool]]` that produces the FOREIGN half, and that tool has to answer
   for one of the criterion's categories: this is the join that makes an FFI
   enumeration part of the toolchain closure rather than a second list beside it.
   Measured: 8 imports over 3 `extern` blocks in 2 files, 0 exports, 2 units.
7. **The TCB list is PRINTED**, into a generated region of docs/supply-chain.md
   that is byte-diffed on every run, the way scripts/ct_gate.py owns a region of
   docs/ct-audit.md. A region and not an `ARTIFACT`/`GENERATED_BY` pair:
   `claims_gate.generated_pages` reads that pair to excuse a page WHOLE, and
   docs/supply-chain.md is prose that must stay under the claims rule.

Two structural rules hold the derivation itself, because every per-row rule above
is satisfied by an empty roster. [`RESOLVED_FLOOR`] counts rows whose pin was
actually READ OUT OF A FILE and matched — a registry that quietly moved every row
to `unpinned` would pass rules 1-5 and check nothing — and the category map is
held against the criterion's own six names, so a category cannot be dropped from
the printed table by deleting its line.

## What this does NOT prove

Stated plainly, because the difference is the whole distance between this and the
criterion it serves. This proves that **every tool named here carries a `pin`
equal to the value in the file that pins it.** It does not prove:

* that the tool which actually RAN was that version. Nothing here observes a
  process. `rustc -vV` would answer for the machine it is typed on, which is the
  compiler that WOULD build the image rather than the one that did — the same
  distinction scripts/elf_gate.py's DWARF reader exists to make;
* that any contributor's `PATH` holds the pinned tool. `nix develop` is a
  convention this repository asks for and a file cannot enforce;
* that a `/nix/store` path still matches its `narHash`. A hash recorded in a file
  proves that the file says the hash.

And it enumerates **4 of the criterion's 6 categories**: compiler, linker and
assembler as tools with a pin held against its source, and FFI as its BOUNDARIES
— which is a different kind of answer and worth saying plainly. A boundary is a
place in the source, not a version, so what rule 6 proves is that the set is
complete against the tree and that each crossing's foreign half comes off a
pinned producer. It does not pin the boundary itself; nothing can, because there
is nothing there to pin.

It is also the boundaries **of this tree**, and that word is doing work. A
dependency's own `extern` block is in the dependency's source, not here, so no
reader of this checkout can enumerate it — the reason `third_party/` is out one
step further in. Measured over `Cargo.lock`: 25 of the 276 checksummed crates
carry `extern "C"` or `#[no_mangle]` in their own source, `cortex-m` and
`cortex-m-rt` among them. What this file says about those is what a `[[tool]]`
row says: which pin fixes them. Not which symbols they cross on.

**LLVM passes and the bootrom have no machine-readable source anywhere in this
tree** — rustc's LLVM version is written in no file here and its pass pipeline in
none anywhere; the bootrom is burned into the RP2350 and
assurance/platform.toml's PLAT-ROM-001 is the assumption standing in its place.
Claiming the criterion closed on this generator would be exactly the "criteria
satisfied by writing sentences" failure the criteria were rewritten to prevent.
The generated region prints the split so a reader of the page sees it without
opening this file.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

REGISTRY = pathlib.Path("assurance/toolchain.toml")
FLAKE_LOCK = pathlib.Path("flake.lock")
CARGO_LOCK = pathlib.Path("Cargo.lock")
PLATFORM = pathlib.Path("assurance/platform.toml")
WORKFLOWS = pathlib.Path(".github/workflows")
PAGE = pathlib.Path("docs/supply-chain.md")

#: The region this script owns inside an otherwise hand-written page — see rule 6
#: for why it is a region and not a whole-page carve-out. The name deliberately
#: does not start `run-count-`: that prefix is `run_count_gate.MARKER`, and a
#: region wearing it there is one that gate demands to be the owner of.
REGION = "toolchain-tcb"
REGION_HEADER = "<!-- Generated by scripts/toolchain_gate.py --write; do not edit. -->"

#: Hand-written keys, and the whole of them. The same discipline
#: `scripts/evidence_gate.py` enforces on a property row: an eighth key is how a
#: derived value starts being stored, and a stored derived value is the rot.
TOOL_FIELDS = ("name", "role", "provenance", "pin", "statement")
NOT_TCB_FIELDS = ("input", "reason")
#: A `[[boundary]]` CLAIMS a derived id; it does not declare one. Which file the
#: boundary is in, what ABI it crosses and what guards it are all read out of the
#: tree by [`boundary_candidates`] and printed, never stored here.
BOUNDARY_FIELDS = ("id", "provider", "statement")

#: A closed vocabulary. `role` decides which of the criterion's categories a row
#: answers for, so an open one would let a category be "covered" by a word nobody
#: agreed on.
ROLES = ("compiler", "linker", "assembler", "packager", "prover", "checker", "runtime")

#: The criterion's own six, spelled here so the printed table cannot lose one by
#: a deleted line. [`covers`] asserts the three maps below partition it exactly.
CRITERION = ("compiler", "linker", "llvm-passes", "assembler", "bootrom", "ffi")

#: role -> the criterion category a row of that role answers for. The roles not
#: in this map (packager, prover, checker, runtime) are TCB and are NOT among the
#: criterion's six; the printed table says so rather than quietly counting them.
ANSWERS_FOR = {"compiler": "compiler", "linker": "linker", "assembler": "assembler"}

#: The one category no `role` answers for, because it is not enumerated as TOOLS.
#: An FFI boundary is a place in the SOURCE, so [`boundary_candidates`] derives
#: the set from the tree and each `[[boundary]]` row joins one to the pinned tool
#: that produces its foreign half. Named here rather than folded into
#: [`ANSWERS_FOR`] so the partition assertion below still says which map reaches
#: it: a category answered by a different derivation is not the same claim as one
#: answered by a row's `role`.
BOUNDARY_CATEGORY = "ffi"

#: Categories this generator names only through something ADJACENT to them. Kept
#: apart from the reachable ones because "partial" read as "covered" is the exact
#: overclaim the criterion was rewritten against. Empty since `ffi` moved out of
#: it, and kept — the map is the place a category goes when it is half-reached,
#: and deleting it would make the next one look like a choice between covered and
#: unreachable.
PARTIAL: dict[str, str] = {}

#: Categories no generator in this tree can reach, with the reason each is out of
#: reach. A category here is one this file must never report as enumerated.
UNREACHABLE = {
    "llvm-passes": (
        "rustc's LLVM version is written in no file of this tree and its pass"
        " pipeline in none anywhere; `rustc -vV` would answer for one machine"
    ),
    "bootrom": (
        "burned into the RP2350; no file here records a version or a hash for it"
        " (assurance/platform.toml's PLAT-ROM-001 stands in its place)"
    ),
}

PROVENANCE = re.compile(
    r"^(?:unpinned"
    r"|flake\.lock:(?P<flake>[\w.-]+)"
    r"|Cargo\.lock:(?P<cargo>[\w.+-]+)"
    r"|workflow:(?P<wf>[\w./-]+):(?P<var>[A-Z][A-Z0-9_]*))$"
)
#: The `unpinned` escape's target: a PLAT-TOOL* id of assurance/platform.toml.
#: `PLAT-TOOL` and not `PLAT-TOOL-`, so PLAT-TOOLCHAIN-00N is admissible too —
#: the toolchain rows are the ones a compiler gap belongs on.
GAP_ID = re.compile(r"^PLAT-TOOL[A-Z]*-\d{3}$")

#: A workflow `env:` assignment, indent kept so [`env_values`] can ask what block
#: it sits in. A `with:` or `inputs:` key of the same name is not a pin.
ASSIGN = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z_][\w-]*):\s*\"?(?P<value>[^\"#\n]*?)\"?\s*$")
BLOCK = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z_][\w-]*):\s*$")

#: First-party Rust is every `.rs` except these — the exclusion
#: `scripts/platform_gate.py` gives its reason for: a vendored fork's `unsafe` is
#: its author's invariant. The same holds one step further here, and it is not a
#: hole today: `third_party/` declares no `extern` item and no `#[no_mangle]` at
#: all, so the set this skips is empty and the skip is a rule, not a carve-out.
FIRST_PARTY_EXCLUDED = ("third_party/",)

#: The modifier run in front of an item, captured so `m.start()` lands on the
#: FIRST token and [`cfg_gate`] can walk back from it. Matching at `extern`
#: instead was the first version and it is wrong on this tree's only guarded
#: block: `#[cfg(target_os = "none")]\nunsafe extern "C" {` walks back from
#: `extern`, meets `unsafe`, and reports the block unconditional.
MODIFIERS = r"(?:\b(?:pub(?:\s*\([^)]*\))?|unsafe|safe|const|async)\s+)*"

#: An `extern` block, on source `gate_lines.rust_code` has been over — which is
#: why there is no `"C"` in the pattern. The lexer BLANKS string literals, so the
#: ABI spelling is gone from the text this matches and is read back out of `raw`
#: by [`ABI`] at the same offset. Matching `extern\s*"C"` here finds nothing at
#: all, silently, which is the failure mode this file's floors exist for.
EXTERN_BLOCK = re.compile(MODIFIERS + r"\bextern\s*\{")
#: An item inside such a block: `fn f(…);` or `static X: T;`, `static mut X: T;`.
EXTERN_ITEM = re.compile(
    r"(?:\bpub(?:\s*\([^)]*\))?\s+)?(?:\b(?:unsafe|safe)\s+)*"
    r"\b(?P<kind>fn|static)\s+(?:mut\s+)?(?P<name>[A-Za-z_]\w*)"
)
#: The other direction: an item this tree DEFINES with a foreign ABI. `fn NAME`
#: and not `fn(`, so a `extern "C" fn(u32)` in type position is not an export.
EXTERN_FN = re.compile(MODIFIERS + r"\bextern\s+fn\s+(?P<name>[A-Za-z_]\w*)")
#: `#[no_mangle]`, `#[export_name = …]` and their 2024 `#[unsafe(…)]` forms. The
#: NAME is taken from the item that follows, never from `export_name`'s value:
#: that value is a string literal and the lexer has blanked it.
MANGLED = re.compile(r"#\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name)\b")
#: The item an attribute run stands above, searched forward from it.
MANGLED_ITEM = re.compile(r"\b(?:fn|static)\s+(?:mut\s+)?(?P<name>[A-Za-z_]\w*)")
#: The ABI spelling, matched against `raw` inside the span of a code match.
ABI = re.compile(r'\bextern\s+"(?P<abi>[^"]*)"')
#: A `cc::Build` source file. The path is a string literal, so — same span trick
#: as [`ABI`] — the call is found in the lexed text and the argument read out of
#: `raw` at the offset the lexer preserved.
CC_BUILD = "cc::Build"
CC_FILE = re.compile(r"\.file\s*\(")
STRING_ARG = re.compile(r'\s*(?P<raw>b?r#*)?"(?P<body>[^"]*)"')

#: Rows whose pin was read out of a file and matched. Under the measured 12 —
#: every per-row rule above is satisfied by a roster of nothing, and rule 4's
#: escape is satisfied by a roster of nothing but escapes. It is the floor that
#: says the gate opened files.
RESOLVED_FLOOR = 10
#: Distinct roles carried. Under the measured 7: a roster that collapsed onto one
#: role would keep every pin correct while the category table said nothing.
ROLE_FLOOR = 5
#: Boundaries the tree yields. Under the measured 10, and it is the floor the
#: both-ways rule below cannot supply: a reader that stopped matching produces
#: nothing, and every unclaimed-candidate finding it would have raised goes with
#: it. The other direction still fires while the registry has rows, so this is
#: specifically the both-emptied-together case — which is what a lexer change
#: plus a `--write` looks like.
#:
#: It does NOT floor the three namespaces separately, because one of them is
#: legitimately empty: this tree exports nothing across a C ABI, so an
#: `export:` floor would have to be 0 and a floor of 0 is the shape it is here to
#: refuse. That half of the reader is held by
#: `test_toolchain_gate.py::test_an_export_is_a_boundary_too` and by nothing in
#: the tree, and it is the one place this generator's set could go short without
#: a floor noticing.
BOUNDARY_FLOOR = 8


def registry(root: pathlib.Path, findings: list[str], text: str | None = None):
    """The hand-written half: the tools and the not-TCB inputs.

    `text` is handed in so a case can mutate the registry without writing to the
    working tree — the shape `elf_gate.registry` uses, for the reason it records:
    a table that writes and restores in a `finally` leaves the tree edited when
    the run is interrupted.
    """
    path = root / REGISTRY
    try:
        raw = path.read_text(encoding="utf-8") if text is None else text
        data = tomllib.loads(raw)
    except (OSError, tomllib.TOMLDecodeError) as error:
        findings.append(f"{REGISTRY}: {error}")
        return {}, {}

    tools: dict[str, dict] = {}
    for entry in data.get("tool", []):
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            findings.append(f"{REGISTRY}: a [[tool]] with no `name`")
            continue
        if name in tools:
            findings.append(f"{REGISTRY}: `{name}` is registered twice")
            continue
        if extra := sorted(set(entry) - set(TOOL_FIELDS)):
            findings.append(
                f"{REGISTRY}: `{name}` carries {extra} — the hand-written fields"
                f" are {list(TOOL_FIELDS)} and everything else is derived"
            )
        if missing := [f for f in TOOL_FIELDS if not entry.get(f)]:
            findings.append(f"{REGISTRY}: `{name}` is missing {missing}")
            continue
        if entry["role"] not in ROLES:
            findings.append(
                f"{REGISTRY}: `{name}` has role {entry['role']!r}, which is not"
                f" one of {list(ROLES)}"
            )
            continue
        tools[name] = entry

    not_tcb: dict[str, str] = {}
    for entry in data.get("not_tcb", []):
        name = entry.get("input")
        if not isinstance(name, str) or not name:
            findings.append(f"{REGISTRY}: a [[not_tcb]] with no `input`")
            continue
        if extra := sorted(set(entry) - set(NOT_TCB_FIELDS)):
            findings.append(
                f"{REGISTRY}: not-TCB `{name}` carries {extra} — the"
                f" hand-written fields are {list(NOT_TCB_FIELDS)}"
            )
        if not entry.get("reason"):
            findings.append(
                f"{REGISTRY}: not-TCB `{name}` states no reason — a bare"
                " exclusion is the gap parked under a different heading"
            )
            continue
        not_tcb[name] = entry["reason"]

    bounds: dict[str, dict] = {}
    for entry in data.get("boundary", []):
        name = entry.get("id")
        if not isinstance(name, str) or not name:
            findings.append(f"{REGISTRY}: a [[boundary]] with no `id`")
            continue
        if name in bounds:
            findings.append(
                f"{REGISTRY}: boundary `{name}` is claimed twice — two rows"
                " describing one crossing means one of them is unreviewed"
            )
            continue
        if extra := sorted(set(entry) - set(BOUNDARY_FIELDS)):
            findings.append(
                f"{REGISTRY}: boundary `{name}` carries {extra} — the"
                f" hand-written fields are {list(BOUNDARY_FIELDS)} and the rest"
                " is read out of the tree"
            )
        if missing := [f for f in BOUNDARY_FIELDS if not entry.get(f)]:
            findings.append(f"{REGISTRY}: boundary `{name}` is missing {missing}")
            continue
        bounds[name] = entry
    return tools, not_tcb, bounds


def block_end(code: str, opener: int) -> int:
    """The offset of the `}` closing the block whose `{` is at or after `opener`."""
    depth, at = 0, code.index("{", opener)
    while at < len(code):
        if code[at] == "{":
            depth += 1
        elif code[at] == "}":
            depth -= 1
            if depth == 0:
                return at
        at += 1
    return len(code)


def cfg_gate(raw: str, code: str, at: int) -> str:
    """The `#[cfg(…)]` attributes standing above the item at offset `at`.

    Decided on `code` and read out of `raw`. `gate_lines.rust_code` blanks a
    comment and a string literal to spaces of the same width, so the two texts
    index identically: bracket-matching on `code` cannot be fooled by a `]` in a
    doc comment, and slicing `raw` gives the attribute's real spelling back.

    Bracket-matched rather than line-walked, which is not the same rule on a
    `#[cfg(all(\\n … \\n))]`: the line above such an item is `))]` and a
    line-walker reads it as no attribute at all, printing "unconditional" over a
    guarded boundary. Non-`cfg` attributes are stepped over, not stopped at — a
    `#[cfg]` above a `#[doc]` above the item still guards it.
    """
    gates, pos = [], at
    while True:
        end = pos
        while end > 0 and code[end - 1].isspace():
            end -= 1
        if end == 0 or code[end - 1] != "]":
            break
        depth, start = 0, end
        while start > 0:
            start -= 1
            if code[start] == "]":
                depth += 1
            elif code[start] == "[":
                depth -= 1
                if depth == 0:
                    break
        if depth != 0 or start == 0 or code[start - 1] != "#":
            break
        text = " ".join(raw[start - 1 : end].split())
        if text.startswith("#[cfg"):
            gates.append(text)
        pos = start - 1
    return " ".join(reversed(gates)) if gates else "unconditional"


def rust_boundaries(rel, raw, code, out):
    """The `import:` and `export:` halves of one `.rs` file, into `out`."""
    for match in EXTERN_BLOCK.finditer(code):
        abi = ABI.search(raw, match.start(), match.end())
        spelling = f'extern "{abi.group("abi")}"' if abi else "extern (default ABI)"
        where = f"{rel}, {spelling}, {cfg_gate(raw, code, match.start())}"
        body = code[match.end() : block_end(code, match.start())]
        for item in EXTERN_ITEM.finditer(body):
            out[f"import:{rel}:{item.group('name')}"] = where

    for match in EXTERN_FN.finditer(code):
        abi = ABI.search(raw, match.start(), match.end())
        spelling = f'extern "{abi.group("abi")}"' if abi else "extern (default ABI)"
        out[f"export:{rel}:{match.group('name')}"] = (
            f"{rel}, {spelling} definition, {cfg_gate(raw, code, match.start())}"
        )

    for match in MANGLED.finditer(code):
        item = MANGLED_ITEM.search(code, match.end())
        if item is None:
            continue
        out[f"export:{rel}:{item.group('name')}"] = (
            f"{rel}, {' '.join(raw[match.start() : match.end()].split())} symbol,"
            f" {cfg_gate(raw, code, match.start())}"
        )


def cc_units(rel, raw, code, out, findings):
    """The `unit:` half of one `build.rs`: what it hands `cc` to compile.

    `.file(…)` and not `rerun-if-changed`: the four paths that list are the two
    translation units plus their two headers, and a header is an input to a unit
    rather than a unit of its own. The path is relative to the manifest
    directory, which is this script's parent, so the id is repo-relative and a
    reader can open it.
    """
    if CC_BUILD not in code:
        return
    for match in CC_FILE.finditer(code):
        argument = STRING_ARG.match(raw, match.end())
        if argument is None or argument.group("raw"):
            findings.append(
                f"{rel}: a `.file(…)` whose argument is not a plain string"
                " literal — the unit it compiles cannot be read out of the call"
            )
            continue
        unit = rel.parent / argument.group("body")
        out[f"unit:{unit}"] = f"{rel}, {CC_BUILD}"


def boundary_candidates(root, findings):
    """{boundary id -> where the derivation found it}.

    Every place a name in this tree binds to a symbol Rust does not define, which
    is what the criterion's `ffi` category asks to be enumerated. Three shapes and
    the id prefix says which: `import:` an item an `extern` block declares,
    `export:` an item defined here for a foreign caller, `unit:` a foreign
    translation unit a `build.rs` compiles into the image.

    Keyed `<file>:<symbol>` and never `<file>:<line>`: a line number is correct
    on the run that writes it and wrong on the next edit above it, and this tree
    has already paid for citations pinned that way.
    """
    out: dict[str, str] = {}
    for rel in sorted(gate_lines.tree_files(root)):
        if rel.suffix != ".rs" or str(rel).startswith(FIRST_PARTY_EXCLUDED):
            continue
        raw = (root / rel).read_text(encoding="utf-8", errors="replace")
        code = gate_lines.rust_code(raw)
        rust_boundaries(rel, raw, code, out)
        if rel.name == "build.rs":
            cc_units(rel, raw, code, out, findings)
    return out


def flake_inputs(root: pathlib.Path, findings: list[str], text: str | None = None):
    """{root input -> its locked `rev`}.

    ONLY the rev. Every node also carries `lastModified`, and a rule that hashed
    the node would redden on a plain re-fetch — the no-op refresh that moves
    nixpkgs's `1780243769` and nothing else. A gate that goes red on a refetch is
    a row nobody keeps.
    """
    try:
        raw = (root / FLAKE_LOCK).read_text(encoding="utf-8") if text is None else text
        lock = json.loads(raw)
    except (OSError, ValueError) as error:
        findings.append(f"{FLAKE_LOCK}: {error}")
        return {}
    nodes = lock.get("nodes", {})
    top = nodes.get(lock.get("root", "root"), {}).get("inputs", {})
    inputs = {}
    for name, key in top.items():
        # A `follows` entry is a list of path components, not a node key.
        if not isinstance(key, str):
            continue
        rev = nodes.get(key, {}).get("locked", {}).get("rev")
        if rev is None:
            findings.append(f"{FLAKE_LOCK}: root input `{name}` locks no rev")
            continue
        inputs[name] = rev
    if not inputs:
        findings.append(
            f"{FLAKE_LOCK}: no root input resolved — the lock format moved under"
            " the parser and every flake.lock rule below is now vacuous"
        )
    return inputs


def cargo_checksums(root: pathlib.Path, findings: list[str], text: str | None = None):
    """{package name -> [checksum, …]}, a list because a name can be locked twice."""
    try:
        raw = (root / CARGO_LOCK).read_text(encoding="utf-8") if text is None else text
        lock = tomllib.loads(raw)
    except (OSError, tomllib.TOMLDecodeError) as error:
        findings.append(f"{CARGO_LOCK}: {error}")
        return {}
    found: dict[str, list[str]] = {}
    for pkg in lock.get("package", []):
        if "checksum" in pkg:
            found.setdefault(pkg.get("name", ""), []).append(pkg["checksum"])
    return found


def env_values(text: str, var: str) -> list[str]:
    """Every value `var` takes as an `env:` key of `text`.

    Structural rather than a bare line match: the same name under `with:` or
    `inputs:` is an argument, not a pin, and a workflow that moved the assignment
    out of `env:` has stopped pinning it.
    """
    lines = text.splitlines()
    values = []
    for at, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        assign = ASSIGN.match(line)
        if not assign or assign.group("key") != var:
            continue
        indent = len(assign.group("indent"))
        for prev in reversed(lines[:at]):
            if not prev.strip() or prev.lstrip().startswith("#"):
                continue
            if len(prev) - len(prev.lstrip()) >= indent:
                continue
            block = BLOCK.match(prev)
            if block and block.group("key") == "env":
                values.append(assign.group("value"))
            break
    return values


def workflow_texts(root: pathlib.Path) -> dict[str, str]:
    """Every workflow file, so rule 3 can ask what the OTHER ones say."""
    directory = root / WORKFLOWS
    if not directory.is_dir():
        return {}
    return {
        str(WORKFLOWS / path.name): path.read_text(encoding="utf-8")
        for path in sorted(directory.iterdir())
        if path.suffix in (".yml", ".yaml")
    }


def gaps(root: pathlib.Path, findings: list[str], text: str | None = None):
    """{PLAT id -> status} for the rows rule 4's escape may point at."""
    try:
        raw = (root / PLATFORM).read_text(encoding="utf-8") if text is None else text
        data = tomllib.loads(raw)
    except (OSError, tomllib.TOMLDecodeError) as error:
        findings.append(f"{PLATFORM}: {error}")
        return {}
    return {a["id"]: a.get("status") for a in data.get("assumption", []) if "id" in a}


def resolve(name, entry, sources, findings) -> bool:
    """Hold one row's `pin` against the file its `provenance` names.

    True when a file was opened and agreed — which is what [`RESOLVED_FLOOR`]
    counts, and the reason `unpinned` returns False rather than passing quietly.
    """
    provenance, pin = entry["provenance"], entry["pin"]
    match = PROVENANCE.match(provenance)
    if not match:
        findings.append(
            f"{REGISTRY}: `{name}` has provenance {provenance!r}, which is none of"
            " `flake.lock:<input>`, `Cargo.lock:<pkg>`,"
            " `workflow:<file>:<VAR>` or `unpinned`"
        )
        return False

    if provenance == "unpinned":
        status = sources["gaps"].get(pin)
        if not GAP_ID.match(pin):
            findings.append(
                f"{REGISTRY}: `{name}` is unpinned and its `pin` is {pin!r}, which"
                " is not a PLAT-TOOL* id — an unpinned tool has to name the open"
                " obligation that owns the gap"
            )
        elif status is None:
            findings.append(
                f"{REGISTRY}: `{name}` is unpinned against {pin}, and"
                f" {PLATFORM} has no such row"
            )
        elif status != "pending":
            findings.append(
                f"{REGISTRY}: `{name}` is unpinned against {pin}, whose status in"
                f" {PLATFORM} is {status!r} and not 'pending' — the obligation was"
                " closed while the tool it covers stayed unpinned"
            )
        return False

    if key := match.group("flake"):
        rev = sources["flake"].get(key)
        if rev is None:
            findings.append(
                f"{REGISTRY}: `{name}` names {FLAKE_LOCK} input `{key}`, which is"
                " not a root input of the lock"
            )
            return False
        if rev != pin:
            findings.append(
                f"{REGISTRY}: `{name}` pins {key} at {pin} and {FLAKE_LOCK} locks"
                f" it at {rev}"
            )
            return False
        return True

    if key := match.group("cargo"):
        checksums = sources["cargo"].get(key, [])
        if len(checksums) != 1:
            findings.append(
                f"{REGISTRY}: `{name}` names {CARGO_LOCK} package `{key}`, which"
                f" is locked {len(checksums)} time(s) with a checksum — a pin"
                " needs exactly one"
            )
            return False
        if checksums[0] != pin:
            findings.append(
                f"{REGISTRY}: `{name}` pins {key} at {pin} and {CARGO_LOCK} locks"
                f" it at {checksums[0]}"
            )
            return False
        return True

    where, var = match.group("wf"), match.group("var")
    said = {
        rel: values
        for rel, text in sources["workflows"].items()
        if (values := env_values(text, var))
    }
    mine = said.get(where)
    if not mine:
        findings.append(
            f"{REGISTRY}: `{name}` names {var} in {where}, and no `env:` block"
            " there assigns it"
        )
        return False
    if any(value != pin for value in mine):
        findings.append(
            f"{REGISTRY}: `{name}` pins {var} at {pin} and {where} assigns"
            f" {sorted(set(mine))}"
        )
        return False
    # Every file that assigns the name has to agree. `kani_gate.py` asks the
    # same question of the same files now; this half is the one that also holds
    # them to the registry's `pin`, and that half is this gate's alone.
    disagree = sorted(
        f"{rel} ({', '.join(sorted(set(values)))})"
        for rel, values in said.items()
        if any(value != pin for value in values)
    )
    if disagree:
        findings.append(
            f"{REGISTRY}: `{name}` pins {var} at {pin}, and {', '.join(disagree)}"
            f" disagree — the value is written {sum(len(v) for v in said.values())}"
            f" time(s) across {len(said)} workflow file(s) and one gate reads one"
        )
        return False
    return True


def covers(tools, found):
    """{criterion category -> what answers for it}, plus its two escapes.

    The maps are asserted to PARTITION [`CRITERION`] rather than merely to fit
    inside it: a category dropped from all of them would vanish from the table
    silently, which is the one failure a printed table has that prose does not.

    `ffi` is filled from the DERIVED set and not from the registry's rows, which
    is the difference between a generated table and a transcribed one. A row that
    claims a boundary the tree no longer has is a finding; it is not a line in
    the table.
    """
    reached = {c: [] for c in ANSWERS_FOR.values()}
    for name, entry in sorted(tools.items()):
        if category := ANSWERS_FOR.get(entry["role"]):
            reached[category].append(name)
    reached[BOUNDARY_CATEGORY] = sorted(found)
    return reached


def audit(
    root: pathlib.Path,
    registry_text=None,
    resolved_floor=RESOLVED_FLOOR,
    role_floor=ROLE_FLOOR,
    boundary_floor=BOUNDARY_FLOOR,
):
    findings: list[str] = []
    tools, not_tcb, bounds = registry(root, findings, registry_text)
    sources = {
        "flake": flake_inputs(root, findings),
        "cargo": cargo_checksums(root, findings),
        "gaps": gaps(root, findings),
        "workflows": workflow_texts(root),
    }
    found = boundary_candidates(root, findings)

    named = (
        set(ANSWERS_FOR.values())
        | {BOUNDARY_CATEGORY}
        | set(PARTIAL)
        | set(UNREACHABLE)
    )
    if named != set(CRITERION):
        findings.append(
            f"the category map covers {sorted(named)} and the criterion names"
            f" {list(CRITERION)} — a category in neither map is one the printed"
            " table would not mention at all"
        )

    resolved = 0
    for name, entry in sorted(tools.items()):
        resolved += resolve(name, entry, sources, findings)

    # Rule 5, both ways. Neither direction implies the other: the first catches a
    # tool arriving with no row, the second a row outliving its input.
    claimed = {
        m.group("flake")
        for entry in tools.values()
        if (m := PROVENANCE.match(entry["provenance"])) and m.group("flake")
    }
    for name in sorted(sources["flake"]):
        if name not in claimed and name not in not_tcb:
            findings.append(
                f"{REGISTRY}: {FLAKE_LOCK} root input `{name}` is in no tool's"
                " provenance and carries no [[not_tcb]] row — the registry is"
                " short of the closure it says it enumerates"
            )
    for name in sorted(not_tcb):
        if name not in sources["flake"]:
            findings.append(
                f"{REGISTRY}: not-TCB `{name}` is not a root input of"
                f" {FLAKE_LOCK} — a stale exclusion excuses nothing"
            )
        elif name in claimed:
            findings.append(
                f"{REGISTRY}: `{name}` is both a tool's provenance and a"
                " [[not_tcb]] row; it cannot be out of the TCB and pin a tool in it"
            )

    # Rule 7, both ways over the FFI boundaries, for rule 5's reason one category
    # along: a roster of boundaries somebody remembered is short in a way no row
    # of it is wrong. `provider` is held too — a boundary whose foreign half is
    # produced by nothing pinned is a name in a list, not an enumeration.
    for name, entry in sorted(bounds.items()):
        if name not in found:
            findings.append(
                f"{REGISTRY}: boundary `{name}` is claimed by a row and no"
                " derivation produces it — either the crossing is gone and the"
                " row outlived it, or the reader that found it stopped reading"
            )
        provider = entry["provider"]
        if provider not in tools:
            findings.append(
                f"{REGISTRY}: boundary `{name}` names provider `{provider}`,"
                " which is not a [[tool]] of this registry — the foreign half of"
                " a boundary has to be produced by something pinned"
            )
        elif (role := tools[provider]["role"]) not in ANSWERS_FOR:
            findings.append(
                f"{REGISTRY}: boundary `{name}` is produced by `{provider}`,"
                f" whose role is {role!r} — a foreign half comes off a"
                f" {sorted(ANSWERS_FOR)}, not off a {role}"
            )
    for name in sorted(set(found) - set(bounds)):
        findings.append(
            f"{REGISTRY}: {found[name]} declares boundary `{name}`, which no"
            " [[boundary]] row claims — a crossing reached the tree without"
            " anything saying which pinned tool produces its far side"
        )

    # [`BOUNDARY_CATEGORY`] is not in this loop, and leaving it out is the
    # measured call: an empty `ffi` is an empty `found`, which is the floor below
    # word for word. A branch here for it went red in exactly the states the
    # floor already reddens in, so it was a second wording of one clause.
    reached = covers(tools, found)
    for category, names in sorted(reached.items()):
        if not names and category != BOUNDARY_CATEGORY:
            findings.append(
                f"no registered tool answers for the criterion's `{category}`"
                " category — it is printed as covered by an empty set"
            )

    if len(found) < boundary_floor:
        findings.append(
            f"{len(found)} boundary(s) derived from the tree, under the measured"
            f" {boundary_floor} — a reader that has stopped matching produces"
            " nothing and raises no unclaimed-candidate finding either"
        )
    if resolved < resolved_floor:
        findings.append(
            f"{resolved} pin(s) resolved against a file, under the measured"
            f" {resolved_floor} — every per-row rule here is satisfied by a"
            " roster that resolves nothing"
        )
    roles = {entry["role"] for entry in tools.values()}
    if len(roles) < role_floor:
        findings.append(
            f"{len(roles)} role(s) carried, under the measured {role_floor} — a"
            " roster collapsed onto one role keeps every pin correct and says"
            " nothing about which categories are reached"
        )

    try:
        want = render(root, tools, not_tcb, reached, bounds, found)
    except (OSError, ValueError) as error:
        findings.append(f"{PAGE} cannot be generated: {error}")
    else:
        if (root / PAGE).read_text(encoding="utf-8") != want:
            findings.append(
                f"{PAGE}'s `{REGION}` region is not what the generator writes —"
                " run `python scripts/toolchain_gate.py --write` and commit it"
            )

    summary = (
        f"toolchain-gate: ok — {len(tools)} tool(s) over {len(roles)} role(s),"
        f" {resolved} pin(s) held against the file that pins them,"
        f" {len(tools) - resolved} unpinned against an open obligation;"
        f" {len(found)} FFI boundary(s) derived from the tree and claimed;"
        f" {len(reached)} of {len(CRITERION)} TCB categories enumerated,"
        f" {len(PARTIAL)} partial, {len(UNREACHABLE)} out of reach"
    )
    return findings, summary


def cell(value) -> str:
    """One GFM table cell. A pipe is the only character a cell has to escape, and
    escaping the backslash with it is a measured regression in this tree."""
    return str(value).replace("|", "\\|")


def body(tools, not_tcb, reached, bounds, found) -> list[str]:
    """The region. Every line of it is derived from the four pin files."""
    out = [
        f"<!-- {REGION}:start -->",
        REGION_HEADER,
        "",
        "Generated by `scripts/toolchain_gate.py` from `assurance/toolchain.toml`"
        " and the files that pin it. Each `pin` below was re-read out of its"
        " provenance on the run that wrote this table; a row whose file no longer"
        " says the same thing fails `check-assurance.sh`.",
        "",
        "| Tool | Role | Pinned by | Pin |",
        "|---|---|---|---|",
    ]
    for name, entry in sorted(tools.items()):
        pin = entry["pin"]
        where = entry["provenance"]
        if where == "unpinned":
            where, pin = "**nothing**", f"open obligation `{pin}`"
        else:
            where, pin = f"`{where}`", f"`{pin}`"
        out.append(f"| `{name}` | {entry['role']} | {where} | {pin} |")
    out += [
        "",
        "Root inputs of `flake.lock` deliberately outside this TCB:",
        "",
    ]
    out += [f"- `{name}` — {reason}" for name, reason in sorted(not_tcb.items())]
    out += [
        "",
        "**The FFI boundaries.** Every place a name in this tree binds to a symbol"
        " Rust does not define, read out of the tree on the run that wrote this"
        " table: an item an `extern` block declares (`import`), an item defined"
        " here for a foreign caller (`export`), and a foreign translation unit a"
        " `build.rs` compiles into the image (`unit`). The set is held both ways —"
        " a crossing no `[[boundary]]` row claims fails `check-assurance.sh`, and so does a"
        " row for a crossing that is no longer there.",
        "",
        "| Boundary | Kind | Derived from | Foreign side produced by |",
        "|---|---|---|---|",
    ]
    for name, where in sorted(found.items()):
        kind, subject = name.split(":", 1)
        if kind != "unit":
            subject = subject.split(":", 1)[1]
        provider = bounds.get(name, {}).get("provider")
        out.append(
            f"| `{cell(subject)}` | {kind} | `{cell(where)}` |"
            f" {f'`{cell(provider)}`' if provider else '**unclaimed**'} |"
        )
    out += [
        "",
        "**Coverage against the six TCB categories.** Enumerated here, each with a"
        " pin held against its source file:",
        "",
    ]
    out += [
        f"- **{category}** — {', '.join(f'`{n}`' for n in names)}"
        if category != BOUNDARY_CATEGORY
        else f"- **{category}** — the {len(names)} boundary(s) in the table above,"
        " each joined to the pinned tool that produces its foreign half"
        for category, names in sorted(reached.items())
    ]
    if PARTIAL:
        out += ["", "Named only in part:", ""]
        out += [f"- **{category}** — {why}" for category, why in sorted(PARTIAL.items())]
    out += ["", "Not enumerated by this generator at all, and not by any other:", ""]
    out += [f"- **{category}** — {why}" for category, why in sorted(UNREACHABLE.items())]
    out += [
        "",
        "What the table proves is that each tool it names carries a pin equal to"
        " the value in the file that pins it. It does not prove that the tool"
        " which actually ran was that version, that a contributor's `PATH` holds"
        " it, or that a `/nix/store` path still matches its `narHash`.",
        "",
        "And the boundaries are the boundaries **of this tree**. A dependency"
        " declares its own, in its own source, where no reader of this checkout"
        " can see them: 25 of `Cargo.lock`'s 276 checksummed crates carry"
        " `extern \"C\"` or `#[no_mangle]`, `cortex-m` and `cortex-m-rt` among"
        " them. For those, what is recorded here is the pin that fixes the crate,"
        " not the symbols it crosses on.",
        "",
        f"<!-- {REGION}:end -->",
    ]
    return out


def render(root: pathlib.Path, tools, not_tcb, reached, bounds, found) -> str:
    text = (root / PAGE).read_text(encoding="utf-8")
    start, end = f"<!-- {REGION}:start -->", f"<!-- {REGION}:end -->"
    head, tail = text.find(start), text.find(end)
    if head == -1 or tail == -1 or tail < head:
        raise ValueError(f"{PAGE} needs exactly one {REGION!r} marker pair")
    written = "\n".join(body(tools, not_tcb, reached, bounds, found))
    return text[:head] + written + text[tail + len(end) :]


def run(root: pathlib.Path, write=False) -> int:
    if write:
        findings: list[str] = []
        tools, not_tcb, bounds = registry(root, findings)
        found = boundary_candidates(root, findings)
        if findings:
            for finding in findings:
                print(f"  {finding}", file=sys.stderr)
            return 1
        (root / PAGE).write_text(
            render(root, tools, not_tcb, covers(tools, found), bounds, found),
            encoding="utf-8",
        )
        print(f"toolchain-gate: wrote the {REGION} region of {PAGE}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("toolchain-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: toolchain_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
