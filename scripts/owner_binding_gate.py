#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Every registered δC/Step owner, bound to the image that ships.

`assurance/token_refinement.toml` owns 48 rows over 45 source sites, and until
this row nothing asked whether any of them is in the firmware. A ledger of
functions is a claim about the SOURCE; the property is about the DEVICE, and the
step between the two — this function, that symbol, this ELF — was written
nowhere. Stage 11A work 4 is that step, and `BINARY-CHECKED` is the VALUE of a
`method` field here rather than a word in a sentence.

**The measurement that decides the design: 22 of the 45 owners have NO SYMBOL.**
Counted on the default image: 15 owners are standalone functions
`arm-none-eabi-nm` defines, 21 exist only as a DWARF abstract instance folded
into their callers (`seed.rs::clear_ppuat` at 4 call sites,
`state.rs::AssertionState::reset` at 5), and 8 are not in the image at all. A
gate written over the symbol table would call 21 correctly-owned,
correctly-shipped functions missing — which is worse than no gate, because the
fix for that noise is to delete the rule.

**A site is a QUALIFIED PATH, and that is a defect this gate shipped with.**
Keyed on `DW_AT_name`, `state.rs::reset` was ONE site merging the twelve DIEs of
four functions — `AssertionState`, `CredMgmtState`, `LargeBlobState` and
`FidoState` all declare `fn reset` in that file — and `bind` then took its
concrete instance from one and its symbol from another. Driven: deleting the two
production callers of the `authenticatorReset` session wipe
(`reset.rs::ctx.state.reset()`, `ctap.rs::scrub_secrets`) and rebuilding drops
`_ZN8rsk_fido5state9FidoState5reset17h…E` from the image, and the gate still said
`ok` — the owner reclassified `symbol`→`inlined` on the 15 call sites of its
three SIBLINGS. So identity is the demangled linkage name, and the count a file
must produce comes from the SOURCE (`declarations`): a function that vanishes
from the image would otherwise take its own requirement with it.

So the evidence for an inlined owner is a CALL SITE and not a debug-info entry.
`DW_TAG_subprogram` with `DW_AT_inline` says the compiler emitted a description
of the function; `DW_TAG_inlined_subroutine` pointing back at it through
`DW_AT_abstract_origin` says a caller kept the code. The first without the
second is documentation of a function that is not there, and this gate reads it
as `absent` — which is the whole difference between "absent because inlined" and
"absent because it did not make it in". Rust puts the name and the file on a
`DW_AT_declaration` DIE inside the type and hangs the instances off it by
`DW_AT_specification`, so both are resolved through that chain; 5711
specification references in this image, and reading the instances alone finds
`DW_AT_name` on none of them.

Two readers are imported rather than rewritten: `elf_gate` for which ELF, which
tools, and the `DW_AT_producer` parser — a STRIPPED image would otherwise read
as 45 absent owners and this gate would be decorative, so no producers is
refused before anything else is judged — and `ct_gate.demangle` for the legacy
`_ZN…` scheme 1332 of this image's symbols use, so a finding names a function
and not a mangling. The roster and its production/test split come from
`token_refinement_gate`, which derives both from the tree.

Scope is the DEFAULT image and the row's POSITION is what makes that true:
`check.sh` rebuilds `target/…/release/firmware` three more times below this row,
so the same row moved down to the other Python gates would audit the no-touch
binary. `assurance/image.toml` names the same path, and this gate holds its own
artifact against that field so the two cannot drift onto different binaries.
"""

from __future__ import annotations

import collections
import hashlib
import pathlib
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ct_gate  # noqa: E402  the symbol reader, so a finding names a function
import elf_gate  # noqa: E402  which ELF, which tools, and what compiled it
import gate_lines  # noqa: E402  what a workflow RUNS, as against what it says
import token_refinement_gate as refinement  # noqa: E402  the roster and its splits

ROOT = pathlib.Path(__file__).resolve().parent.parent

REGISTRY = pathlib.Path("assurance/owner_binding.toml")
#: Cargo-default legacy diagnostic; the shipping TrustZone boundary needs its
#: own binding evidence and is not discharged by this reader.
IMAGE_MANIFEST = pathlib.Path("firmware/Cargo.toml")

#: Each subject and the ONE status word it may carry. Source→binary and
#: bit-for-bit are different questions with different evidence, and the pairing
#: is held in both directions: a reproducibility row may not wear
#: `BINARY-CHECKED`, and the binding row may not hide behind `MEASURED`.
SUBJECTS = {"owner->image": "BINARY-CHECKED", "bit-for-bit": "MEASURED"}
#: The subject this gate discharges, and the method that subject must carry.
#: Which row is which is decided by the SUBJECT — what the claim is ABOUT — and
#: never by the method, which is the status word under audit here. Keyed on the
#: method, `registry` chose a row's owed fields from the very value the pairing
#: rule exists to check, so swapping the two methods changed the shape and the
#: shape findings returned first: the pairing rule was unreachable from a
#: registry, driven and measured before this line said `subject`.
DISCHARGES = "owner->image"
DISCHARGED = SUBJECTS[DISCHARGES]

#: The subject this gate is NOT, refused by name rather than by falling off the
#: end of `SUBJECTS`. `owner->image` says a registered owner is IN the shipped
#: binary; `source->binary` says the emitted machine code does what the source
#: says, which is a property of the COMPILER and which nothing in this tree
#: establishes — `assurance/platform.toml`'s `PLAT-TOOLCHAIN-001` is `pending`
#: and its discharge sentence is "Nothing in the tree bridges MIR to the image
#: today". Presence is not semantics: an owner can be in the image and
#: miscompiled, so a row that read this gate's evidence as the frontier would
#: close, in a `method` field, an obligation the registry still holds open.
FRONTIER = "source->binary"
FRONTIER_ROW = "PLAT-TOOLCHAIN-001"

CLAIM_FIELDS = {"subject", "method", "artifact", "build", "statement"}
ABSENT_FIELDS = {"file", "function", "basis", "why"}
#: Owed by a claim this gate does NOT discharge, and refused on the one it does:
#: the row it verifies itself may not also name a second verifier.
ELSEWHERE = "verified_by"
#: Where a verifier can live. "A file that exists" is the rule f124135 threw out
#: one registry over — met by `README.md` — so the named file must be a workflow
#: AND must RUN the row's own build command, read through `gate_lines`' `run:`
#: walk. Measured over this repo's eight workflows: `release-build.yml` carries 4
#: executed `nix build` lines and `ci.yml` none, so the rule separates them.
WORKFLOWS = ".github/workflows/"

#: Why a registered owner may be missing from the image. Disjoint by
#: construction — see [`basis_holds`] — so a row cannot be relabelled with a
#: neighbouring basis and stay green.
BASES = ("cfg-gated", "trait-default-body", "const-evaluated", "unlinked-crate", "unreached")

#: A roster cannot lose its evidence class without someone saying so. Measured
#: at 21 inlined owners; set ~30% under it, the slack the neighbouring gates
#: carry, so ordinary code motion does not trip it. What it is actually for: if
#: the abstract-origin reader breaks, the cheap repair is an `[[absent]]` row per
#: owner, and 21 of those are legal one at a time. Under this floor they are not.
FLOORS = {"inlined": 14}

#: A DIE header: `<depth><offset>: Abbrev Number: N (DW_TAG_…)`.
DIE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((DW_TAG_\w+)\)")
ATTRIBUTE = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$")
INDIRECT = re.compile(r"^\(indirect string, offset: 0x[0-9a-f]+\):\s*")
UNIT = re.compile(r"^  Compilation Unit @ offset \S+:")

#: The line-program header `readelf --debug-dump=rawline` prints per CU. Its
#: `Offset:` is the CU DIE's `DW_AT_stmt_list`, which is how a `DW_AT_decl_file`
#: index — 1-based, DWARF 4 — is resolved to a path at all.
PROGRAM = re.compile(r"^  Offset:\s+(\S+)")
TABLE_ROW = re.compile(r"^  (\d+)\t(\d+)\t\d+\t\d+\t(.*)$")
DIRECTORY_ROW = re.compile(r"^  (\d+)\t(.*)$")

#: The attribute block directly above a `fn`, and the `fn` itself. `{name}` is
#: substituted, so this reads the ATTRIBUTES a `#[cfg]` sits in — a question
#: `token_refinement_gate.functions` cannot answer, since its bodies start at the
#: `fn` line and it blanks comments and strings first.
DECLARATION = (
    r"((?:^[ \t]*#\[[^\n]*\]\n)*)"
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?"
    r"(?:(?:const|async|unsafe|extern[ \t]+\"[^\"]*\")[ \t]+)*"
    r"fn[ \t]+{name}\b"
)
CFG_FEATURE = re.compile(r'#\[cfg\([^\n]*?feature\s*=\s*"([^"]+)"')
TRAIT_ITEM = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:unsafe[ \t]+)?trait[ \t]+\w+", re.M)
#: An `impl` or `trait` header, so a `fn` can be attributed to the item it sits
#: in. Which one is prose for the reader; the RULE is how many there are. Read to
#: the OPENING BRACE and not to the newline: `AppletHandler`'s impl in
#: `crates/rsk-device/src/ctap.rs` puts its parameter list on one line and the
#: self type on the next.
ITEM = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:unsafe[ \t]+)?(?:impl|trait)\b([^{;]*)", re.M
)

#: The trees a caller is looked for in, and the trees a crate is looked for in.
#: NOT `token_refinement_gate.catalogue`, whose three directories are the WRITER
#: AXES' scope: measured, that scope answered `callers elsewhere: []` for two
#: owners whose production caller is `crates/rsk-display`, so an owner called
#: only from a fourth crate could be registered `unreached` and accepted.
FIRST_PARTY = ("crates", "firmware")


def registry(root: pathlib.Path, findings: list[str], text: str | None = None):
    """The hand-written half: the two claims, and the registered absences.

    `text` is the registry handed in, so a case can mutate it without writing to
    the working tree — the defect swept out of `ct_gate`'s and `elf_gate`'s
    tables, where a `finally` an interrupt never runs was the restore path.
    """
    doc = tomllib.loads(
        (root / REGISTRY).read_text(encoding="utf-8") if text is None else text
    )
    for key in sorted(set(doc) - {"claim", "absent"}):
        findings.append(f"{REGISTRY}: top-level `{key}` — the file holds `[[claim]]` and `[[absent]]`")
    # `[claim]` and `[[claim]]` are one bracket apart and TOML accepts both: the
    # first hands this a dict, whose iteration yields its KEYS, and every rule
    # below then asks a string for `.get`. A finding, not a traceback.
    for name in ("claim", "absent"):
        rows = doc.get(name, [])
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            findings.append(f"{REGISTRY}: `{name}` is not an array of tables — write `[[{name}]]`")
            doc[name] = []

    claims = list(doc.get("claim", []))
    for index, claim in enumerate(claims):
        where = f"{REGISTRY}: claim {index + 1}"
        # Before the shape, because the shape is decided by the subject: a row
        # naming the frontier would otherwise be answered "no `verified_by`",
        # which is true and is not what is wrong with it.
        if claim.get("subject") == FRONTIER:
            findings.append(
                f"{where}: `{FRONTIER}` is not a subject this gate may carry — a"
                " symbol and an inlined call site say an owner is IN the image,"
                " not that the emitted code does what the source says, and"
                f" {FRONTIER_ROW} still holds that obligation open"
            )
            continue
        discharged = claim.get("subject") == DISCHARGES
        owed = CLAIM_FIELDS if discharged else CLAIM_FIELDS | {ELSEWHERE}
        for key in sorted(set(claim) - owed):
            findings.append(
                f"{where}: `{key}` is not a field this registry reads"
                + (f" on the `{DISCHARGES}` row — it is verified HERE" if key == ELSEWHERE else "")
            )
        for key in sorted(owed - set(claim)):
            findings.append(f"{where}: no `{key}`")
        # An empty string is not an answer. `assurance/board/*.toml` ships
        # `firmware_sha256 = ""` in eleven files, so this is the tree's own
        # spelling of a field left blank and a presence test walks past it.
        for key in sorted(owed & set(claim)):
            if not str(claim[key]).strip():
                findings.append(f"{where}: `{key}` is empty")

    seen: dict[tuple[str, str], int] = {}
    absents = list(doc.get("absent", []))
    for index, row in enumerate(absents):
        where = f"{REGISTRY}: absent {index + 1}"
        for key in sorted(set(row) - ABSENT_FIELDS):
            findings.append(f"{where}: `{key}` is not a field this registry reads")
        for key in sorted(ABSENT_FIELDS - set(row)):
            findings.append(f"{where}: no `{key}`")
        for key in sorted(ABSENT_FIELDS & set(row)):
            if not str(row[key]).strip():
                findings.append(f"{where}: `{key}` is empty")
        site = (str(row.get("file", "")), str(row.get("function", "")))
        if site in seen:
            findings.append(f"{where}: `{site[0]}::{site[1]}` is registered absent twice")
        seen[site] = index
    return claims, absents


def read(root: pathlib.Path, artifact: pathlib.Path) -> dict[str, str]:
    """The three reads of the binary plus its digest, in ONE place.

    Injected as a whole, so the mutation table needs neither a linked image nor a
    cross toolchain — and, more to the point, does not silently read the WRONG
    image: at the `pytest (gate scripts)` row `target/` holds the no-touch build,
    while the row this file is the rule for reads the default one ~250 rows
    earlier.

    The digest is [`digest`]'s and never stored: this image's DWARF carries an
    absolute `DW_AT_comp_dir`, so its sha256 is a fact about one checkout.
    """
    binary = str(root / artifact)

    def out(*argv: str) -> str:
        return subprocess.run(argv, capture_output=True, text=True, check=True).stdout

    return {
        "defined": out(elf_gate.NM, "--defined-only", binary),
        "dwarf": out(elf_gate.READELF, "--debug-dump=info", binary),
        "rawline": out(elf_gate.READELF, "--debug-dump=rawline", binary),
        "digest": digest(root / artifact),
    }


def digest(path: pathlib.Path) -> str:
    """The sha256 the summary stamps a run with, DERIVED from the artifact.

    Its own function so a case can drive it without an image: as a line inside
    [`read`] — which nothing but the row itself calls — it could be replaced by a
    constant and every case stayed green, which is a digest that stamps nothing.
    Nowhere is it STORED; `assurance/owner_binding.toml`'s header says why.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_paths(rawline: str) -> dict[int, dict[int, str]]:
    """{line-program offset: {file index: path}} out of `--debug-dump=rawline`.

    The path a `DW_AT_decl_file` index means lives in the CU's own file-name
    table, not in the DIE, and the tables differ per CU — index 87 is one file in
    the firmware unit and another in `rsk-fs`. Keyed by the offset the CU DIE's
    `DW_AT_stmt_list` names, which is the only thing that ties the two dumps.
    """
    tables: dict[int, dict[int, str]] = {}
    offset, directories, files, section = None, {}, {}, None
    for line in rawline.splitlines():
        found = PROGRAM.match(line)
        if found:
            if offset is not None:
                tables[offset] = files
            offset, directories, files, section = int(found.group(1), 0), {}, {}, None
            continue
        if "The Directory Table" in line:
            section = "directory"
            continue
        if "The File Name Table" in line:
            section = "file"
            continue
        if line.startswith(" Opcodes") or line.strip().startswith("Opcode "):
            section = None
            continue
        if section == "directory":
            row = DIRECTORY_ROW.match(line)
            if row:
                directories[int(row.group(1))] = row.group(2).strip()
        elif section == "file":
            row = TABLE_ROW.match(line)
            if row:
                folder = directories.get(int(row.group(2)), "")
                name = row.group(3).strip()
                files[int(row.group(1))] = f"{folder}/{name}" if folder else name
    if offset is not None:
        tables[offset] = files
    return tables


def relative(path: str, comp_dir: str) -> str:
    """`path` as the repo spells it. A remapped build emits it relative already."""
    if comp_dir and path.startswith(comp_dir + "/"):
        return path[len(comp_dir) + 1 :]
    return path.removeprefix("./")


def instances(dwarf: str, tables: dict[int, dict[int, str]]):
    """({(file, function): [DIE, …]}, {DIE offset: inlined call sites}).

    Rust hangs a method's name and file on a `DW_AT_declaration` DIE inside the
    type and points the instances at it with `DW_AT_specification`, so identity
    is resolved through that chain — and through `DW_AT_abstract_origin`, which
    is how an inlined call site reaches its abstract instance. Reading the
    instances alone finds a name on none of them: 5711 specification references
    in this image against 23631 subprograms.
    """
    subprograms: dict[int, dict] = {}
    call_sites: collections.Counter = collections.Counter()
    current, table, comp_dir = None, {}, ""
    for line in dwarf.splitlines():
        if UNIT.match(line):
            current, table, comp_dir = None, {}, ""
            continue
        header = DIE.match(line)
        if header:
            offset, tag = int(header.group(2), 16), header.group(3)
            if tag in ("DW_TAG_compile_unit", "DW_TAG_subprogram", "DW_TAG_inlined_subroutine"):
                current = {"tag": tag, "offset": offset}
                if tag == "DW_TAG_subprogram":
                    subprograms[offset] = current
            else:
                current = None
            continue
        attribute = ATTRIBUTE.match(line)
        if attribute is None or current is None:
            continue
        key, value = attribute.group(1), attribute.group(2).strip()
        if current["tag"] == "DW_TAG_compile_unit":
            if key == "DW_AT_stmt_list":
                table = tables.get(int(value, 0), {})
            elif key == "DW_AT_comp_dir":
                comp_dir = INDIRECT.sub("", value)
        elif current["tag"] == "DW_TAG_inlined_subroutine":
            if key == "DW_AT_abstract_origin":
                call_sites[int(value.strip("<>"), 16)] += 1
        elif key in ("DW_AT_name", "DW_AT_linkage_name"):
            current[key] = INDIRECT.sub("", value)
        elif key == "DW_AT_decl_file":
            current["file"] = relative(table.get(int(value), ""), comp_dir)
        elif key in ("DW_AT_specification", "DW_AT_abstract_origin"):
            current[key] = int(value.strip("<>"), 16)
        elif key in ("DW_AT_low_pc", "DW_AT_inline", "DW_AT_declaration"):
            current[key] = value

    def qualify(die: dict, fallback: str) -> str:
        """`FidoState::reset`, not `reset` — the KEY, and the whole of this bug.

        Keeps `fallback` when the mangling is one `ct_gate` does not read (the v0
        scheme, a C name): a wrong path would attribute a symbol to the wrong
        function, and the collapse a fallback causes is caught downstream by the
        source-anchored count.
        """
        mangled = die.get("DW_AT_linkage_name")
        if not mangled:
            return fallback
        path = ct_gate.demangle(mangled)
        return path if path.rsplit("::", 1)[-1] == fallback.rsplit("::", 1)[-1] else fallback

    def identity(die: dict, depth: int = 0):
        if depth > 8:
            return None
        if die.get("file") and "DW_AT_name" in die:
            # `reset<firmware::handler::FidoRng>` is one function; the generic
            # arguments are what make one `fn` several linkage names.
            return (die["file"], qualify(die, die["DW_AT_name"].split("<")[0]))
        for key in ("DW_AT_specification", "DW_AT_abstract_origin"):
            origin = subprograms.get(die.get(key))
            if origin is not None:
                found = identity(origin, depth + 1)
                if found:
                    # The instance's own linkage name where it has one, and the
                    # declaration's path — never the bare name — where it does not.
                    return (found[0], qualify(die, found[1]))
        return None

    by_site: dict[tuple[str, str], list[dict]] = collections.defaultdict(list)
    for die in subprograms.values():
        site = identity(die)
        if site:
            by_site[site].append(die)
    inlined: collections.Counter = collections.Counter()
    for offset, count in call_sites.items():
        origin = subprograms.get(offset)
        site = identity(origin) if origin else None
        if site:
            inlined[site] += count
    return by_site, inlined


def roster(root: pathlib.Path) -> list[tuple[str, str, str]]:
    """(axis, file, function) per registered owner, deduplicated, in file order.

    Read out of `token_refinement_gate`'s own manifest and axes: the ledger has
    six of them, and naming a subset here would be a second roster that goes
    stale the day a seventh arrives.
    """
    doc = tomllib.loads((root / refinement.MANIFEST).read_text(encoding="utf-8"))
    seen, out = set(), []
    for axis in refinement.AXES:
        for entry in doc.get(axis, []):
            site = (str(entry.get("file", "")), str(entry.get("function", "")))
            if site in seen:
                continue
            seen.add(site)
            out.append((axis, site[0], site[1]))
    return out


def default_features(root: pathlib.Path, rel: str) -> set[str]:
    """Features on in the DEFAULT image for the crate `rel` lives in.

    Three sources, because a feature is on if any of them turns it on: the
    crate's own `default`, the image crate's `default` closure, and what
    `firmware`'s dependency table asks of that crate. Measured on this tree: all
    three are empty — neither manifest declares a `default` list and
    `rsk-device = { workspace = true }` enables nothing — which is the fact that
    makes `security-trace` an honest absence rather than a hopeful one, and also
    the reason this function cannot be driven from the tree in the direction that
    matters. Its cases build the manifests they read.
    """
    manifest = None
    for parent in (root / rel).parents:
        if (parent / "Cargo.toml").is_file():
            manifest = parent / "Cargo.toml"
            break
    if manifest is None:
        return set()
    package = tomllib.loads(manifest.read_text(encoding="utf-8"))
    on = set(package.get("features", {}).get("default", []))

    binary = root / IMAGE_MANIFEST
    if not binary.is_file():
        return on
    image = tomllib.loads(binary.read_text(encoding="utf-8"))
    table = image.get("features", {})
    queue, walked = list(table.get("default", [])), set()
    while queue:
        entry = queue.pop()
        if entry in walked:
            continue
        walked.add(entry)
        queue.extend(table.get(entry, []))
    crate = manifest.parent.name
    # `"/" in e` before the split: an optional dependency mints an IMPLICIT
    # feature of its own name, so `default = ["rsk-display"]` is a legal entry
    # with no slash in it — and this line used to raise IndexError on one.
    on |= {e.split("/", 1)[1] for e in walked if "/" in e and e.split("/", 1)[0].rstrip("?") == crate}
    if manifest == binary:
        on |= {e for e in walked if "/" not in e}
    dependency = image.get("dependencies", {}).get(crate)
    if isinstance(dependency, dict):
        on |= set(dependency.get("features", []))
    return on


def invoked(build: str) -> str:
    """The verb phrase of a build command: the words before its first operand.

    `nix build .#firmware` -> `nix build`, `cargo build --release -p firmware` ->
    `cargo build`. Derived from the row's own `build` rather than typed a second
    time here, which is the shape this whole registry exists to avoid.
    """
    words = []
    for word in str(build).split():
        if word.startswith(("-", ".", "/")):
            break
        words.append(word)
    return " ".join(words)


def in_trait_item(text: str, function: str) -> bool:
    """Whether `function` is a provided body inside a `trait` item.

    Brace-counted rather than pattern-matched: a trait body holds nested blocks,
    and a regex that stops at the first `}` reads the trait as ending inside its
    first default method.
    """
    for head in TRAIT_ITEM.finditer(text):
        start = text.find("{", head.end())
        if start == -1:
            continue
        depth, cursor = 0, start
        while cursor < len(text):
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        if re.search(rf"\bfn[ \t]+{re.escape(function)}\b", text[start:cursor]):
            return True
    return False


def declarations(text: str, function: str) -> list[str]:
    """The `impl`/`trait` each `fn function` in `text` sits in, in file order.

    The SOURCE ANCHOR, and it exists because the roster names an owner by its
    BARE name: `state.rs` declares four `fn reset`, and how many functions the
    image owes for that row cannot come from the image — a function that is gone
    is simply not among its own candidates.

    It counts every declaration, `#[cfg]`-gated ones included. Measured, no file
    in the roster has two of a name where one is gated — the only file with more
    than one at all is `state.rs` — so the exclusion is not written; a sibling
    behind an off feature would report as a shortfall, and the message names it.
    """
    blocks = []
    for head in ITEM.finditer(text):
        start = text.find("{", head.end())
        if start == -1:
            continue
        depth, cursor = 0, start
        while cursor < len(text):
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        # `impl Trait for Type` is Type's; `impl<S: Storage<T>> FidoState<S>` is
        # FidoState's, so a leading parameter list is scanned off BALANCED —
        # `<[^>]*>` stops inside the first nested one and takes `Storage` for it.
        item = head.group(1).lstrip()
        if item.startswith("<"):
            depth = 0
            for index, char in enumerate(item):
                depth += (char == "<") - (char == ">")
                if depth == 0:
                    item = item[index + 1 :]
                    break
        item = item.strip().rsplit(" for ", 1)[-1].split("<")[0].split()
        blocks.append((start, cursor, item[0].split("::")[-1] if item else ""))
    found = []
    for site in re.finditer(DECLARATION.format(name=re.escape(function)), text, re.M):
        # The LAST enclosing header is the innermost one — `blocks` is in source
        # order — and a `fn` in no `impl` at all is a free function, labelled "".
        inside = [b for b in blocks if b[0] < site.end() < b[1]]
        found.append(inside[-1][2] if inside else "")
    return found


def callers(root: pathlib.Path) -> dict[tuple[str, str], str]:
    """{(file, function): body} over every first-party production `.rs`.

    `token_refinement_gate.functions` is the reader, but NOT its `catalogue`: that
    walks the three directories the writer axes are derived over, and measured,
    71 files against this walk's 244 — which is how two owners called only from
    `crates/rsk-display` read as called by nobody.
    """
    found = {}
    for base in FIRST_PARTY:
        for path in sorted((root / base).rglob("*.rs")):
            if path.name.endswith(("_tests.rs", "_kani.rs")):
                continue
            rel = str(path.relative_to(root))
            for name, body in refinement.functions(path.read_text(encoding="utf-8", errors="replace")):
                found[(rel, name)] = body
    return found


def crates(root: pathlib.Path) -> dict[str, str]:
    """{package name: directory} in the image's workspace, without nested namespaces."""
    root_manifest = root / "Cargo.toml"
    workspace = (
        tomllib.loads(root_manifest.read_text(encoding="utf-8")).get("workspace", {})
        if root_manifest.is_file() else {}
    )
    members = workspace.get("members")
    manifests = (
        sorted(root / member / "Cargo.toml" for member in members
               if any(member == base or member.startswith(f"{base}/")
                      for base in FIRST_PARTY))
        if isinstance(members, list)
        else sorted(manifest for base in FIRST_PARTY
                    for manifest in (root / base).rglob("Cargo.toml"))
    )
    found = {}
    for manifest in manifests:
        package = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package")
        if isinstance(package, dict) and package.get("name"):
            found[str(package["name"])] = str(manifest.parent.relative_to(root))
    return found


def linked_crates(root: pathlib.Path) -> set[str]:
    """The directories the DEFAULT image links, walked from `firmware`'s manifest.

    An `optional` dependency is out unless a default feature turns it on, which
    is the whole rule here: `rsk-display` and `rsk-ui` are optional behind
    `display`, and no manifest in this tree declares a `default` list at all.
    """
    where = crates(root)
    reached, queue = set(), [str(IMAGE_MANIFEST.parent)]
    while queue:
        rel = queue.pop()
        if rel in reached or not (root / rel / "Cargo.toml").is_file():
            continue
        reached.add(rel)
        manifest = tomllib.loads((root / rel / "Cargo.toml").read_text(encoding="utf-8"))
        on = default_features(root, f"{rel}/src")
        for name, spec in manifest.get("dependencies", {}).items():
            optional = isinstance(spec, dict) and spec.get("optional")
            if optional and not ({name, f"dep:{name}"} & on):
                continue
            if name in where:
                queue.append(where[name])
    return reached


def basis_holds(root: pathlib.Path, rel: str, function: str, basis: str, catalogue: dict):
    """(does it hold, what was measured) for one registered absence.

    The five are DISJOINT: `unreached` is refused of a site that is cfg-gated, a
    trait's provided body, a `const fn` or called at all, so relabelling a row
    with a neighbouring basis reddens instead of passing. Without that, the one
    row that is genuinely cfg-gated also has no caller in scope, and its basis
    could be swapped for a weaker one silently.
    """
    text = (root / rel).read_text(encoding="utf-8", errors="replace")
    found = re.search(DECLARATION.format(name=re.escape(function)), text, re.M)
    if found is None:
        return False, f"no `fn {function}` in {rel}"
    gated = sorted(set(CFG_FEATURE.findall(found.group(1))) - default_features(root, rel))
    provided = in_trait_item(text, function)
    constant = bool(re.search(rf"\bconst[ \t]+fn[ \t]+{re.escape(function)}\b", text))
    called = sorted(
        {where for (where, _name), body in catalogue.items()
         if where != rel and re.search(rf"\b{re.escape(function)}\s*\(", body)}
    )
    linked = linked_crates(root)
    reachable = sorted(c for c in called if any(c.startswith(f"{d}/") for d in linked))
    if basis == "cfg-gated":
        return bool(gated), f"cfg features off in the default image: {gated}"
    if basis == "trait-default-body":
        return provided, f"declared inside a `trait` item: {provided}"
    if basis == "const-evaluated":
        return constant and not called, f"`const fn`: {constant}, callers: {called}"
    if basis == "unlinked-crate":
        return (
            bool(called) and not reachable and not gated and not provided and not constant,
            f"callers: {called}, of them in a crate the default image links:"
            f" {reachable}, cfg-gated: {gated}, trait body: {provided},"
            f" `const fn`: {constant}",
        )
    if basis == "unreached":
        return (
            not called and not gated and not provided and not constant,
            f"callers: {called}, cfg-gated: {gated},"
            f" trait body: {provided}, `const fn`: {constant}",
        )
    return False, f"`{basis}` is not one of {list(BASES)}"


def bind(site, dies, inlined, defined):
    """(disposition, the symbol or the evidence) for ONE qualified function.

    `symbol` needs a linkage name the image DEFINES — a concrete instance whose
    symbol is nowhere is a finding of its own, not a quieter pass. `inlined`
    needs a CALL SITE: an abstract instance with none is a description of a
    function the image does not carry, which is exactly the case a rule written
    over debug info alone reads as present. That last clause is UNFALSIFIABLE on
    this tree's images and stays because of what it is for, not what it catches:
    measured over the 5071 functions this image identifies, `abstract with zero
    call sites` is 0 — a function whose callers all go loses its abstract
    instance with them (driven: the acceptance image for the qualified key does
    not keep one), so the shape this refuses is one the linker has not produced
    here. It is a fixture case and not a row that holds it.

    A concrete instance decides before an abstract one because 159 functions
    carry both: the same `fn` inlined at some call sites and emitted standalone
    for the rest is `symbol`, and reading the abstract half first would report a
    function `nm` defines as evidence-by-call-site.
    """
    concrete = [d for d in dies if "DW_AT_low_pc" in d]
    abstract = [d for d in dies if "DW_AT_inline" in d]
    names = sorted({d["DW_AT_linkage_name"] for d in dies if "DW_AT_linkage_name" in d})
    if concrete:
        shipped = [n for n in names if n in defined]
        if not shipped:
            return "unsymbolised", names[0] if names else "(no linkage name)"
        return "symbol", ct_gate.demangle(shipped[0])
    if abstract and inlined.get(site, 0):
        return "inlined", f"{inlined[site]} call site(s), {ct_gate.demangle(names[0]) if names else site[1]}"
    return "absent", f"{len(dies)} DIE(s), {inlined.get(site, 0)} call site(s)"


def audit(root, registry_text=None, raw=None, sites=None, gated=None, floors=FLOORS):
    """`raw` is [`read`]'s dict and `sites`/`gated` the roster and its test half,
    each handed in by a case that has no image and no tree to derive them from."""
    findings: list[str] = []
    claims, absents = registry(root, findings, registry_text)
    if findings:
        return findings, ""

    subjects = collections.Counter(c["subject"] for c in claims)
    for subject, count in sorted(subjects.items()):
        if subject not in SUBJECTS:
            findings.append(f"{REGISTRY}: `{subject}` is not one of {sorted(SUBJECTS)}")
        elif count != 1:
            findings.append(f"{REGISTRY}: {count} claims on subject `{subject}` — one each")
    for subject in sorted(set(SUBJECTS) - set(subjects)):
        findings.append(
            f"{REGISTRY}: no claim on subject `{subject}` — both are rows so the"
            " pairing rule runs over data rather than over a comment"
        )
    for claim in claims:
        want = SUBJECTS.get(claim["subject"])
        if want and claim["method"] != want:
            findings.append(
                f"{REGISTRY}: subject `{claim['subject']}` carries"
                f" `{claim['method']}`, and its method is `{want}` — source→binary"
                " and bit-for-bit are different evidence, and reading the second"
                " as the first launders a supply-chain claim into a code one"
            )
    if findings:
        return findings, ""

    for claim in claims:
        if claim["subject"] == DISCHARGES:
            continue
        elsewhere = str(claim[ELSEWHERE])
        tool = invoked(claim["build"])
        if not elsewhere.startswith(WORKFLOWS) or not (root / elsewhere).is_file():
            findings.append(
                f"{REGISTRY}: subject `{claim['subject']}` is verified by"
                f" `{elsewhere}`, which is no workflow of this repo — a rule met"
                " by any file that merely exists is met by README.md"
            )
        elif not any(
            executed and tool in gate_lines.split_at_comment(line)[0]
            for line, executed in gate_lines.yaml_runs(
                (root / elsewhere).read_text(encoding="utf-8")
            )
        ):
            findings.append(
                f"{REGISTRY}: `{elsewhere}` runs no `{tool}`, so it verifies"
                f" nothing about subject `{claim['subject']}` — a workflow that"
                " only MENTIONS the command is the same hole one indirection out"
            )
    binding = [c for c in claims if c["subject"] == DISCHARGES]
    if len(binding) != 1:
        findings.append(f"{REGISTRY}: {len(binding)} claims on `{DISCHARGES}` — exactly one is this gate's")
        return findings, ""
    claim = binding[0]

    # `elf_gate`'s own registry, so the two rows in this window cannot drift onto
    # different binaries. Its findings are its row's business; only the path is.
    registered = elf_gate.registry(root, []).get("elf")
    artifact = pathlib.Path(claim["artifact"])
    if registered and str(artifact) != registered:
        findings.append(
            f"{REGISTRY}: the `{DISCHARGED}` artifact is `{artifact}` and"
            f" {elf_gate.REGISTRY} names `{registered}` — two registries on two"
            " binaries is how a row comes to certify the image it does not audit"
        )
    if raw is None and not (root / artifact).is_file():
        findings.append(f"{artifact} — build it first: {claim['build']}")
    if findings:
        return findings, ""

    try:
        raw = read(root, artifact) if raw is None else raw
        by_site, inlined = instances(raw["dwarf"], source_paths(raw["rawline"]))
        compiled = elf_gate.producers(raw["dwarf"])
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        return [f"{artifact}: {error}"], ""
    defined = {line.split()[-1] for line in raw["defined"].splitlines() if line.strip()}

    # Before anything is judged: a stripped image answers `absent` to every
    # question below, and three of those answers are the ones this gate WANTS.
    if not compiled:
        return [
            f"{artifact}: no DW_AT_producer in the image — nothing here read a"
            " compiler, so every owner would resolve `absent` and the three"
            " test-only rows would pass on it"
        ], ""

    sites = roster(root) if sites is None else sites
    gated = refinement.test_only_sources(root) if gated is None else gated
    owners = {(f, fn) for _axis, f, fn in sites}
    exempt = {(str(r["file"]), str(r["function"])): r for r in absents}
    catalogue = callers(root)

    counts: collections.Counter = collections.Counter()
    bound = 0
    for axis, where, function in sites:
        site = (where, function)
        # The roster names a BARE function and one file can declare four of them,
        # so an owner is every qualified path in that file ending in its name —
        # and the count it owes comes from the source, never from the image.
        candidates = sorted(k for k in by_site if k[0] == where and k[1].rsplit("::", 1)[-1] == function)
        declared = declarations((root / where).read_text(encoding="utf-8", errors="replace"), function)
        bound += len(candidates)
        if candidates and len(candidates) < len(declared):
            findings.append(
                f"{axis} `{where}::{function}`: the file declares"
                f" {len(declared)} `fn {function}` ({', '.join(declared)}) and the"
                f" image carries {len(candidates)}"
                f" ({', '.join(k[1] for k in candidates)}) — the roster names this"
                " owner by its bare name, so every function of that name is owed"
            )
        judged = [bind(k, by_site[k], inlined, defined) for k in candidates]
        # The WEAKEST answer is the owner's: a sibling with a symbol does not put
        # a function that is nowhere into the image, which is this row's defect.
        disposition, evidence = min(
            judged or [("absent", f"0 DIE(s), {len(declared)} declared")],
            key=lambda pair: ("absent", "unsymbolised", "inlined", "symbol").index(pair[0]),
        )
        if len(judged) > 1:
            evidence = "; ".join(f"{k[1]} {d}" for k, (d, _e) in zip(candidates, judged))
        counts[disposition] += 1
        # The test-only question is asked FIRST and of every disposition,
        # `unsymbolised` included: what makes it a defect is that the function is
        # on a device, not the form the linker left it in.
        if where in gated:
            counts["test-only"] += 1
            if disposition != "absent":
                findings.append(
                    f"{axis} `{where}::{function}` is TEST-ONLY and is in the"
                    f" shipped image as `{disposition}` ({evidence}) — a"
                    " conformance-only writer reachable on a device is a defect,"
                    " not a bookkeeping mismatch"
                )
            if site in exempt:
                findings.append(
                    f"{REGISTRY}: `{where}::{function}` is registered absent and"
                    " its absence is DERIVED from the module graph — a"
                    " hand-written row is a second answer to it"
                )
            continue
        if disposition == "unsymbolised":
            findings.append(
                f"{axis} `{where}::{function}`: the image carries a concrete"
                f" instance and defines no symbol for it ({evidence}) — a"
                " standalone function nothing can name is not a binding"
            )
            continue
        if disposition != "absent":
            if site in exempt:
                findings.append(
                    f"{REGISTRY}: `{where}::{function}` is registered absent on"
                    f" basis `{exempt[site]['basis']}` and the image binds it as"
                    f" `{disposition}` ({evidence}) — a stale exemption"
                )
            continue
        row = exempt.get(site)
        if row is None:
            findings.append(
                f"{axis} `{where}::{function}` is in no part of the image"
                f" ({evidence}) and {REGISTRY} registers no absence for it"
            )
            continue
        held, measured = basis_holds(root, where, function, str(row["basis"]), catalogue)
        if not held:
            findings.append(
                f"{REGISTRY}: `{where}::{function}` claims basis"
                f" `{row['basis']}` and the tree does not bear it — {measured}"
            )

    for site in sorted(set(exempt) - set(owners)):
        findings.append(
            f"{REGISTRY}: `{site[0]}::{site[1]}` is registered absent and"
            f" {refinement.MANIFEST} owns no such site"
        )

    if counts["inlined"] < floors["inlined"]:
        findings.append(
            f"{artifact}: {counts['inlined']} owner(s) bound by an inlined call"
            f" site, floor {floors['inlined']} — that class is 22 of 45 on this"
            " image, and losing it silently turns the roster into exemptions"
        )

    summary = (
        f"owner-binding: ok — {len(sites)} registered owner(s) {DISCHARGED}"
        f" against {artifact} sha256 {raw['digest'][:16]}…,"
        f" {counts['symbol']} symbol / {counts['inlined']} inlined /"
        f" {counts['absent']} absent ({len(exempt)} registered,"
        f" {counts['test-only']} test-only) over {bound} bound function(s),"
        f" {sum(compiled.values())} compile unit(s) from {len(compiled)} producer(s)"
    )
    return findings, summary


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: owner_binding_gate.py", file=sys.stderr)
        return 2
    findings, summary = audit(ROOT)
    if findings:
        print("owner-binding:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
