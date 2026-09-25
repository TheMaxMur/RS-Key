# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `owner_binding_gate.py`.

Every case runs against RECORDED `arm-none-eabi-readelf` / `arm-none-eabi-nm`
output and a registry handed in as text, so nothing here needs a linked image, a
cross toolchain or a write to the working tree — and nothing SKIPS, which is the
only state `check.sh` cannot tell from a pass.

The recorded DWARF is verbatim in form and elided in bulk: the real dump is
2 052 650 lines and 165 compile units, and the DIEs kept here are the five shapes
the parser reads — a concrete instance carrying its own name, an abstract
instance carrying its own name, a `DW_AT_declaration` with the abstract instance
hung off it by `DW_AT_specification` (5711 of those in the real image, and the
shape a reader of instances alone finds no name on), and the two
`DW_TAG_inlined_subroutine` call sites that are the evidence for `inlined`.

What the cases deliberately do NOT hand in: the tree. `basis_holds` and
`callers` read the real `crates/` and `firmware/`, so the five bases are driven
against the source they are claims about rather than against a fixture that would
agree with them by construction. Two of them — `cfg-gated` under a feature the
manifests turn ON, and `unreached` where something calls — are the exception and
say so: this tree cannot produce either, so those arms build the crate they read.

What this table cannot fail on, said here rather than discovered later: the
parsers meeting a `readelf` whose OUTPUT format moved. That is the row's job — it
runs the real tools over the real image — and it is the split `test_ct_gate.py`
and `test_elf_gate.py` already make.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gate_lines  # noqa: E402
import owner_binding_gate as gate  # noqa: E402
import token_refinement_gate as refinement  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: `arm-none-eabi-readelf --debug-dump=rawline`, one line program. The directory
#: table is RELATIVE for first-party code — the build remaps it — and the file
#: index is 1-based, DWARF 4.
RAWLINE = """Raw dump of debug contents of section .debug_line:

  Offset:                      0
  Length:                      259119
  DWARF Version:               4
  Prologue Length:             14889
  Minimum Instruction Length:  1
  Opcode Base:                 13

 Opcodes:
  Opcode 1 has 0 args

 The Directory Table (offset 0x1c):
  1\tcrates/rsk-fido/src
  2\tcrates/rsk-device/src
  3\tcrates/rsk-fido/src/conformance

 The File Name Table (offset 0x203f):
  Entry\tDir\tTime\tSize\tName
  1\t1\t0\t0\treset.rs
  2\t1\t0\t0\tseed.rs
  3\t1\t0\t0\tstate.rs
  4\t2\t0\t0\tctap.rs
  5\t3\t0\t0\tmod.rs

  Offset:                      0x3f492
  Length:                      1024
  DWARF Version:               4

 The Directory Table (offset 0x3f01c):
  1\tcrates/rsk-fs/src

 The File Name Table (offset 0x3f03f):
  Entry\tDir\tTime\tSize\tName
  1\t1\t0\t0\tring.rs
"""

#: `arm-none-eabi-readelf --debug-dump=info`. One CU, and the DIE bodies the
#: parser does not read elided. `sweep` is a concrete instance, `clear_ppuat` an
#: abstract one that names itself, `mark_token_used` an abstract one that reaches
#: its name through `DW_AT_specification`, and the two inlined subroutines are
#: the call sites that make the last two evidence rather than documentation.
DWARF = """  Compilation Unit @ offset 0:
   Length:        0x169cbd (32-bit)
   Version:       4
   Abbrev Offset: 0
   Pointer Size:  4
 <0><b>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <c>   DW_AT_producer    : (indirect string, offset: 0xdde5a): clang LLVM (rustc version 1.96.0 (ac68faa20 2026-05-25))
    <10>   DW_AT_language    : 28\t(Rust)
    <12>   DW_AT_name        : (indirect string, offset: 0x19db5d): firmware/src/main.rs/@/firmware.63ca95cc0d98da63-cgu.0
    <16>   DW_AT_stmt_list   : 0
    <1a>   DW_AT_comp_dir    : (indirect string, offset: 0x1ab1a): /Users/maxmur/Code/RS-Key
 <1><96c6a>: Abbrev Number: 14 (DW_TAG_subprogram)
    <96c6b>   DW_AT_low_pc      : 0x1006bd6c
    <96c6f>   DW_AT_high_pc     : 0xc2
    <96c79>   DW_AT_linkage_name: (indirect string, offset: 0x2af260): _ZN8rsk_fido5reset5sweep17hb74b7f7c3f715bcfE
    <96c7d>   DW_AT_name        : (indirect string, offset: 0x209ee3): sweep<rsk_store::SeqStorage<firmware::flash_storage::SharedFlash>, firmware::handler::FidoRng>
    <96c81>   DW_AT_decl_file   : 1
    <96c82>   DW_AT_decl_line   : 106
 <2><96c90>: Abbrev Number: 7 (DW_TAG_variable)
    <96c91>   DW_AT_name        : (indirect string, offset: 0x209000): FIDO_SEED_FIDS
    <96c95>   DW_AT_decl_file   : 4
 <1><ac850>: Abbrev Number: 169 (DW_TAG_subprogram)
    <ac852>   DW_AT_linkage_name: (indirect string, offset: 0x285c0e): _ZN8rsk_fido4seed11clear_ppuat17h90b7fc19f5c74d0fE
    <ac856>   DW_AT_name        : (indirect string, offset: 0x26b166): clear_ppuat<rsk_store::SeqStorage<firmware::flash_storage::SharedFlash>>
    <ac85a>   DW_AT_decl_file   : 2
    <ac85c>   DW_AT_decl_line   : 337
    <ac862>   DW_AT_inline      : 1\t(inlined)
 <2><83ef1>: Abbrev Number: 131 (DW_TAG_subprogram)
    <83ef3>   DW_AT_linkage_name: (indirect string, offset: 0x2b48a2): _ZN8rsk_fido5state9FidoState15mark_token_used17h299e14bc1842cea0E
    <83ef7>   DW_AT_name        : (indirect string, offset: 0x1a1b3f): mark_token_used
    <83efb>   DW_AT_decl_file   : 3
    <83efc>   DW_AT_decl_line   : 491
    <83efe>   DW_AT_declaration : 1
 <1><90000>: Abbrev Number: 17 (DW_TAG_subprogram)
    <90001>   DW_AT_specification: <0x83ef1>
    <90005>   DW_AT_inline      : 1\t(inlined)
 <2><2c7>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <2c8>   DW_AT_abstract_origin: <0xac850>
    <2cc>   DW_AT_low_pc      : 0x10003486
    <2d0>   DW_AT_high_pc     : 0x2
 <2><2e0>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <2e1>   DW_AT_abstract_origin: <0x90000>
    <2e4>   DW_AT_low_pc      : 0x100034a0
    <2e8>   DW_AT_high_pc     : 0x6
 <1><ad000>: Abbrev Number: 169 (DW_TAG_subprogram)
    <ad002>   DW_AT_linkage_name: (indirect string, offset: 0x2af260): _ZN8rsk_fido5reset5sweep17hb74b7f7c3f715bcfE
    <ad006>   DW_AT_name        : (indirect string, offset: 0x209ee3): sweep<rsk_store::SeqStorage<firmware::flash_storage::SharedFlash>, firmware::handler::FidoRng>
    <ad00a>   DW_AT_decl_file   : 1
    <ad00c>   DW_AT_decl_line   : 106
    <ad012>   DW_AT_inline      : 1\t(inlined)
 <2><2f0>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <2f1>   DW_AT_abstract_origin: <0xad000>
    <2f4>   DW_AT_low_pc      : 0x100034b0
    <2f8>   DW_AT_high_pc     : 0x4
"""

#: The four `fn reset` of `crates/rsk-fido/src/state.rs`, verbatim in shape and
#: the reason this table exists: one bare name, four functions, and the roster
#: row is the `FidoState` one. `FidoState::reset` is the concrete instance; the
#: three siblings are abstract with a call site each.
FIDO_RESET = """ <1><b0000>: Abbrev Number: 14 (DW_TAG_subprogram)
    <b0001>   DW_AT_low_pc      : 0x1006c000
    <b0005>   DW_AT_high_pc     : 0x40
    <b0009>   DW_AT_linkage_name: (indirect string, offset: 0x2af300): _ZN8rsk_fido5state9FidoState5reset17h0123456789abcdefE
    <b000d>   DW_AT_name        : (indirect string, offset: 0x209f00): reset
    <b0011>   DW_AT_decl_file   : 3
    <b0012>   DW_AT_decl_line   : 426
"""
SIBLING_RESETS = """ <1><b1000>: Abbrev Number: 169 (DW_TAG_subprogram)
    <b1002>   DW_AT_linkage_name: (indirect string, offset: 0x2af310): _ZN8rsk_fido5state14AssertionState5reset17haaaaaaaaaaaaaaaaE
    <b1006>   DW_AT_name        : (indirect string, offset: 0x209f00): reset
    <b100a>   DW_AT_decl_file   : 3
    <b100c>   DW_AT_decl_line   : 96
    <b1012>   DW_AT_inline      : 1\t(inlined)
 <1><b2000>: Abbrev Number: 169 (DW_TAG_subprogram)
    <b2002>   DW_AT_linkage_name: (indirect string, offset: 0x2af320): _ZN8rsk_fido5state13CredMgmtState5reset17hbbbbbbbbbbbbbbbbE
    <b2006>   DW_AT_name        : (indirect string, offset: 0x209f00): reset
    <b200a>   DW_AT_decl_file   : 3
    <b200c>   DW_AT_decl_line   : 193
    <b2012>   DW_AT_inline      : 1\t(inlined)
 <1><b3000>: Abbrev Number: 169 (DW_TAG_subprogram)
    <b3002>   DW_AT_linkage_name: (indirect string, offset: 0x2af330): _ZN8rsk_fido5state14LargeBlobState5reset17hccccccccccccccccE
    <b3006>   DW_AT_name        : (indirect string, offset: 0x209f00): reset
    <b300a>   DW_AT_decl_file   : 3
    <b300c>   DW_AT_decl_line   : 241
    <b3012>   DW_AT_inline      : 1\t(inlined)
 <2><300>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <301>   DW_AT_abstract_origin: <0xb1000>
    <304>   DW_AT_low_pc      : 0x100034c0
    <308>   DW_AT_high_pc     : 0x4
 <2><310>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <311>   DW_AT_abstract_origin: <0xb2000>
    <314>   DW_AT_low_pc      : 0x100034d0
    <318>   DW_AT_high_pc     : 0x4
 <2><320>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <321>   DW_AT_abstract_origin: <0xb3000>
    <324>   DW_AT_low_pc      : 0x100034e0
    <328>   DW_AT_high_pc     : 0x4
"""
RESET_SYMBOL = "1006c000 t _ZN8rsk_fido5state9FidoState5reset17h0123456789abcdefE\n"
RESET_SITE = ("volatile_writer", "crates/rsk-fido/src/state.rs", "reset")

#: `arm-none-eabi-nm --defined-only`. `sweep` is defined; the two inlined owners
#: are NOT, which is the whole point of them.
DEFINED = """1006bd6c t _ZN8rsk_fido5reset5sweep17hb74b7f7c3f715bcfE
100952b0 t _ZN4core3ptr70drop_in_place$LT$core..option..Option$GT$17ha07151873ef7e222E
"""

RECORDED = {
    "defined": DEFINED,
    "dwarf": DWARF,
    "rawline": RAWLINE,
    "digest": "395dd99af9987bbfb3a8987333a6a6e2ebf81ae627648037a22c7f76e88af3f3",
}

#: The roster the cases audit: one owner of each disposition, plus the two the
#: rules about absence are written for.
SITES = [
    ("persistent_writer", "crates/rsk-fido/src/reset.rs", "sweep"),
    ("persistent_writer", "crates/rsk-fido/src/seed.rs", "clear_ppuat"),
    ("volatile_writer", "crates/rsk-fido/src/state.rs", "mark_token_used"),
    ("softlock_owner", "crates/rsk-device/src/ctap.rs", "security_trace_snapshot"),
    ("volatile_writer", "crates/rsk-fido/src/conformance/mod.rs", "arm_token"),
]
GATED = {"crates/rsk-fido/src/conformance/mod.rs"}
#: A PARAMETER, at the fixture's own measurement. The shipped floor is 14 against
#: 20 and is not reachable by a five-owner roster; handing it in is how both arms
#: stay drivable without patching the number the real row is judged by.
FLOORS = {"inlined": 2}

CLAIMS = """
[[claim]]
subject = "owner->image"
method = "BINARY-CHECKED"
artifact = "target/thumbv8m.main-none-eabihf/release/firmware"
build = "cargo build --release -p firmware"
statement = "every registered owner is bound to this ELF"

[[claim]]
subject = "bit-for-bit"
method = "MEASURED"
artifact = "result/firmware.uf2"
build = "nix build .#firmware"
verified_by = ".github/workflows/release-build.yml"
statement = "the published images rebuild bit-identical; this gate does not discharge it"
"""

ABSENT = """
[[absent]]
file = "crates/rsk-device/src/ctap.rs"
function = "security_trace_snapshot"
basis = "cfg-gated"
why = "compiled only into the emulator's trace build"
"""


def raw(**overrides) -> dict:
    return {**RECORDED, **overrides}


def run(registry_text=None, **kwargs):
    """`audit` over the fixture, with the roster and the floor handed in."""
    return gate.audit(
        ROOT,
        registry_text=CLAIMS + ABSENT if registry_text is None else registry_text,
        raw=kwargs.pop("raw", RECORDED),
        sites=kwargs.pop("sites", SITES),
        gated=kwargs.pop("gated", GATED),
        floors=kwargs.pop("floors", FLOORS),
        **kwargs,
    )


def check_sh() -> str:
    return (ROOT / "scripts/check.sh").read_text(encoding="utf-8")


def row(needle: str) -> int:
    """The line `check.sh` RUNS `needle` on — a `#` in front of it is not a row."""
    for number, line in enumerate(check_sh().splitlines(), 1):
        if needle in gate_lines.split_at_comment(line)[0]:
            return number
    raise AssertionError(f"check.sh runs no {needle!r}")


# ---- the control -------------------------------------------------------------


def test_the_fixture_is_green_and_says_what_it_measured():
    """The control. Not a no-op: it drives all three dispositions, both claim
    subjects, the specification chain, the concrete-before-abstract precedence,
    the registered absence and its basis."""
    findings, summary = run()
    assert not findings, findings
    assert "1 symbol / 2 inlined / 2 absent" in summary, summary
    assert "(1 registered, 1 test-only) over 3 bound function(s)" in summary, summary
    assert "BINARY-CHECKED" in summary and "395dd99af9987bbf" in summary, summary


def test_the_shipped_registry_and_tree_are_green_together():
    """The control the row itself runs, minus the image: the real registry, the
    real roster, the real module graph and the real bases."""
    findings: list[str] = []
    claims, absents = gate.registry(ROOT, findings)
    assert not findings, findings
    assert {c["subject"]: c["method"] for c in claims} == gate.SUBJECTS
    sites = {(f, fn) for _axis, f, fn in gate.roster(ROOT)}
    assert len(sites) == 47, len(sites)
    # The shipped floor, held from BOTH sides. Zero is the weakening a case
    # cannot see — the cases hand their own floor in — and a floor set AT the
    # measurement of 21 turns a deleted guard into a report about its reader,
    # which is the failure `token_refinement_gate.FLOORS` records paying for.
    assert 0 < gate.FLOORS["inlined"] < 21, gate.FLOORS
    catalogue = gate.callers(ROOT)
    for entry in absents:
        assert (entry["file"], entry["function"]) in sites, entry
        held, measured = gate.basis_holds(
            ROOT, entry["file"], entry["function"], entry["basis"], catalogue
        )
        assert held, (entry, measured)


def test_the_roster_deduplicates_a_ledger_that_owns_more_rows_than_sites():
    """48 rows over 45 sites, so the dedup is load-bearing on live data — and it
    is asserted HERE and not through `audit`, whose oracle would have to rebuild
    a set of sites and re-deduplicate them to compare at all."""
    doc = tomllib.loads((ROOT / refinement.MANIFEST).read_text(encoding="utf-8"))
    rows = sum(len(doc.get(axis, [])) for axis in refinement.AXES)
    sites = gate.roster(ROOT)
    assert rows == 50, rows
    assert len(sites) == 47 == len({(f, fn) for _axis, f, fn in sites}), len(sites)


# ---- the registry shape ------------------------------------------------------


def test_an_unknown_top_level_table_is_refused():
    findings, _ = run(CLAIMS + ABSENT + '\n[[binding]]\nfile = "x"\n')
    assert any("top-level `binding`" in f for f in findings), findings


def test_a_claim_missing_a_field_is_refused():
    findings, _ = run(CLAIMS.replace('build = "cargo build --release -p firmware"\n', "") + ABSENT)
    assert any("claim 1: no `build`" in f for f in findings), findings


def test_an_empty_artifact_is_not_an_answer():
    """`assurance/board/*.toml` ships `firmware_sha256 = ""` in eleven files, so
    a blank field is this tree's own spelling and a presence test walks past it."""
    findings, _ = run(CLAIMS.replace(
        'artifact = "target/thumbv8m.main-none-eabihf/release/firmware"', 'artifact = ""'
    ) + ABSENT)
    assert any("claim 1: `artifact` is empty" in f for f in findings), findings


def test_an_empty_build_is_not_an_answer():
    findings, _ = run(CLAIMS.replace(
        'build = "cargo build --release -p firmware"', 'build = "   "'
    ) + ABSENT)
    assert any("claim 1: `build` is empty" in f for f in findings), findings


def test_an_absent_row_missing_its_basis_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace('basis = "cfg-gated"\n', ""))
    assert any("absent 1: no `basis`" in f for f in findings), findings


def test_an_absent_row_with_an_empty_why_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace(
        'why = "compiled only into the emulator\'s trace build"', 'why = ""'
    ))
    assert any("absent 1: `why` is empty" in f for f in findings), findings


def test_the_same_site_registered_absent_twice_is_refused():
    findings, _ = run(CLAIMS + ABSENT + ABSENT)
    assert any("registered absent twice" in f for f in findings), findings


def test_one_bracket_short_of_an_array_of_tables_is_a_finding():
    """`[claim]` and `[[claim]]` are one bracket apart and TOML takes both: the
    first hands the reader a dict, whose iteration yields its KEYS, and every
    rule then asks a string for `.get`. Written as ONE table because a `[claim]`
    followed by a `[[claim]]` is a decode error rather than this shape."""
    one = CLAIMS.split("[[claim]]")[1]
    findings, _ = run("[claim]" + one + ABSENT)
    assert any("is not an array of tables" in f for f in findings), findings


def test_a_field_the_registry_does_not_read_is_refused():
    findings, _ = run(CLAIMS + ABSENT + 'note = "x"\n')
    assert any("`note` is not a field" in f for f in findings), findings


# ---- BINARY-CHECKED is a value, and it is not reproducibility ----------------


def test_the_reproducibility_row_may_not_wear_binary_checked():
    """The exit criterion, driven: source→binary and bit-for-bit are different
    evidence, and the second wearing the first's word is the laundering."""
    findings, _ = run(CLAIMS.replace(
        'subject = "bit-for-bit"\nmethod = "MEASURED"',
        'subject = "bit-for-bit"\nmethod = "BINARY-CHECKED"',
    ) + ABSENT)
    assert any("`bit-for-bit` carries `BINARY-CHECKED`" in f for f in findings), findings


def test_the_binding_row_may_not_hide_behind_measured():
    """The pairing holds in BOTH directions, so `BINARY-CHECKED` cannot be
    dropped from the registry by relabelling the row that carries it."""
    findings, _ = run(CLAIMS.replace(
        'subject = "owner->image"\nmethod = "BINARY-CHECKED"',
        'subject = "owner->image"\nmethod = "MEASURED"',
    ) + ABSENT)
    assert any("`owner->image` carries `MEASURED`" in f for f in findings), findings


def test_a_subject_outside_the_vocabulary_is_refused():
    findings, _ = run(CLAIMS.replace('subject = "bit-for-bit"', 'subject = "vibes"') + ABSENT)
    assert any("`vibes` is not one of" in f for f in findings), findings


def test_the_compiler_frontier_is_refused_by_name():
    """`owner->image` is not `source->binary`. A symbol and an inlined call site
    say a function is IN the image; they say nothing about whether the emitted
    code does what the source says, and `PLAT-TOOLCHAIN-001` is `pending` on
    exactly that. Refused by NAME rather than by falling off the end of the
    vocabulary, so the message says why."""
    findings, _ = run(CLAIMS.replace('subject = "owner->image"', 'subject = "source->binary"') + ABSENT)
    assert any("PLAT-TOOLCHAIN-001 still holds that obligation open" in f
               for f in findings), findings
    assert not any("is not one of" in f for f in findings), findings
    # And it is refused INSTEAD of, not alongside: `registry` decides a row's
    # owed fields from its subject, so the shape complaint would answer the
    # frontier row "no `verified_by`" — true, and not what is wrong with it.
    assert len(findings) == 1, findings


def test_a_missing_subject_is_refused_so_the_pairing_runs_over_data():
    """A one-row registry makes the pairing rule a comment: with nothing on the
    other subject nothing ever exercises it."""
    findings, _ = run(CLAIMS.split("[[claim]]")[0] + "[[claim]]" + CLAIMS.split("[[claim]]")[1] + ABSENT)
    assert any("no claim on subject `bit-for-bit`" in f for f in findings), findings


def test_two_rows_on_one_subject_are_refused():
    findings, _ = run(CLAIMS + CLAIMS.split("[[claim]]")[2].join(["[[claim]]", ""]) + ABSENT)
    assert any("claims on subject `bit-for-bit`" in f for f in findings), findings


def test_the_row_this_gate_discharges_may_not_name_a_second_verifier():
    findings, _ = run(CLAIMS.replace(
        'statement = "every registered owner is bound to this ELF"',
        'statement = "x"\nverified_by = ".github/workflows/ci.yml"',
    ) + ABSENT)
    assert any("it is verified HERE" in f for f in findings), findings


def test_a_row_this_gate_does_not_discharge_must_name_its_verifier():
    findings, _ = run(CLAIMS.replace(
        'verified_by = ".github/workflows/release-build.yml"\n', ""
    ) + ABSENT)
    assert any("claim 2: no `verified_by`" in f for f in findings), findings


def test_a_verifier_that_is_not_a_file_is_refused():
    findings, _ = run(CLAIMS.replace(
        ".github/workflows/release-build.yml", ".github/workflows/no-such-job.yml"
    ) + ABSENT)
    assert any("no workflow of this repo" in f for f in findings), findings


def test_a_verifier_that_is_a_page_rather_than_a_job_is_refused():
    """The bypass `f124135` threw out one registry over, in this rule's own
    shape: `README.md` exists, mentions `nix build`, and verifies nothing."""
    findings, _ = run(CLAIMS.replace(
        ".github/workflows/release-build.yml", "README.md"
    ) + ABSENT)
    assert any("no workflow of this repo" in f for f in findings), findings


def test_a_workflow_that_runs_the_build_is_what_verifies_it():
    """Not "a workflow that exists": measured over this repo's eight, four
    executed `nix build` lines in `release-build.yml` and none in `ci.yml`."""
    findings, _ = run(CLAIMS.replace(
        ".github/workflows/release-build.yml", ".github/workflows/ci.yml"
    ) + ABSENT)
    assert any("runs no `nix build`" in f for f in findings), findings


def test_the_tool_a_verifier_must_run_is_read_off_the_row():
    """`invoked` stops at the first operand, so the rule is the claim's own
    `build` and not a second copy of it typed into this gate."""
    assert gate.invoked("nix build .#firmware") == "nix build"
    assert gate.invoked("cargo build --release -p firmware") == "cargo build"
    assert gate.invoked("env FLASH_SIZE=16M cargo build") == "env FLASH_SIZE=16M cargo build"


def test_the_artifact_is_held_against_the_other_registry_in_this_window():
    """Two registries on two binaries is how a row comes to certify the image it
    does not audit: `assurance/image.toml` names the same path, and the no-touch
    build overwrites it ~250 rows later."""
    findings, _ = run(CLAIMS.replace(
        "target/thumbv8m.main-none-eabihf/release/firmware",
        "target/thumbv8m.main-none-eabihf/release/rsk-wipe",
    ) + ABSENT)
    assert any("names `target/thumbv8m.main-none-eabihf/release/firmware`" in f for f in findings), findings


def test_an_artifact_that_is_not_there_says_which_command_makes_it():
    """The message a fresh checkout gets, and the one every other case walks past
    by injecting `raw`: no build, no image, and a row that must say so rather
    than resolve 44 owners `absent` against a file it never opened."""
    findings, _ = run(CLAIMS.replace(
        "target/thumbv8m.main-none-eabihf/release/firmware", "target/nothing/here/firmware",
    ) + ABSENT, raw=None)
    assert any("build it first: cargo build --release -p firmware" in f for f in findings), findings


# ---- the image ---------------------------------------------------------------


def test_the_digest_is_the_artifacts_own_sha256(tmp_path):
    """The stamp in the summary, held to the bytes. Nothing STORES it — the
    registry header says why — so the only thing that makes it a receipt rather
    than decoration is that it is derived, and a constant prints just as well."""
    blob = tmp_path / "firmware"
    blob.write_bytes(b"\x7fELF, more or less")
    assert gate.digest(blob) == hashlib.sha256(blob.read_bytes()).hexdigest()
    first = gate.digest(blob)
    blob.write_bytes(b"\x7fELF, more or less!")
    assert gate.digest(blob) != first


def test_read_runs_the_three_tools_over_the_artifact_it_is_handed(tmp_path, monkeypatch):
    """The only function the row calls and no case does — every case injects
    `raw` — so its wiring is where a wrong flag or a dropped key would sit
    unreported. Driven with the tools stubbed: which ARGV, and the digest of the
    file it was pointed at."""
    seen: list[tuple[str, ...]] = []

    def stub(argv, **_kwargs):
        seen.append(tuple(argv))
        return type("Done", (), {"stdout": f"out of {argv[1]}"})()

    monkeypatch.setattr(gate.subprocess, "run", stub)
    (tmp_path / "fw").write_bytes(b"\x7fELF")
    out = gate.read(tmp_path, pathlib.Path("fw"))
    binary = str(tmp_path / "fw")
    assert seen == [
        (gate.elf_gate.NM, "--defined-only", binary),
        (gate.elf_gate.READELF, "--debug-dump=info", binary),
        (gate.elf_gate.READELF, "--debug-dump=rawline", binary),
    ], seen
    assert set(out) == {"defined", "dwarf", "rawline", "digest"}
    assert out["digest"] == hashlib.sha256(b"\x7fELF").hexdigest()


def test_a_stripped_image_is_refused_before_any_owner_is_judged():
    """Every owner resolves `absent` on a stripped binary, and three of those
    answers are ones this gate WANTS — so the vacuity guard runs first."""
    findings, _ = run(raw=raw(dwarf=DWARF.replace("DW_AT_producer", "DW_AT_nothing")))
    assert findings and "no DW_AT_producer" in findings[0], findings
    assert len(findings) == 1, findings


def test_an_inlined_owner_is_bound_by_a_call_site_and_not_by_debug_info():
    """The decision the whole design turns on. An abstract instance with no
    `DW_TAG_inlined_subroutine` pointing at it describes a function the image
    does not carry, and reading it as present makes the gate decorative."""
    findings, _ = run(raw=raw(dwarf=DWARF.replace("DW_AT_abstract_origin: <0xac850>", "DW_AT_abstract_origin: <0x1>")))
    assert any("crates/rsk-fido/src/seed.rs::clear_ppuat" in f and "no part of the image" in f
               for f in findings), findings


def test_an_owner_reached_only_through_a_specification_is_still_found():
    """Rust hangs the name and the file on a `DW_AT_declaration` inside the type;
    dropping the chain loses every method in the roster at once."""
    findings, _ = run(raw=raw(dwarf=DWARF.replace("DW_AT_specification: <0x83ef1>", "DW_AT_specification: <0x2>")))
    assert any("crates/rsk-fido/src/state.rs::mark_token_used" in f for f in findings), findings


# ---- a site is a qualified path, not a bare name ------------------------------


def test_four_functions_of_one_name_are_four_sites():
    """The defect this row shipped with. Keyed on `DW_AT_name`, `state.rs::reset`
    was ONE site merging twelve DIEs of four functions, and `bind` then took its
    concrete instance from one and its symbol from another."""
    by_site, _inlined = gate.instances(DWARF + FIDO_RESET + SIBLING_RESETS, gate.source_paths(RAWLINE))
    resets = sorted(k[1] for k in by_site if k[1].rsplit("::", 1)[-1] == "reset")
    assert resets == [
        "rsk_fido::state::AssertionState::reset",
        "rsk_fido::state::CredMgmtState::reset",
        "rsk_fido::state::FidoState::reset",
        "rsk_fido::state::LargeBlobState::reset",
    ], resets


def test_an_instance_with_no_linkage_name_keeps_its_declarations_path():
    """The `DW_AT_specification` shape, 5711 of them in the real image: the
    instance carries `DW_AT_inline` and nothing else, so a resolver that reads
    the linkage name off the INSTANCE drops back to the bare name and splits one
    function into two sites — driven, that reported `mark_token_used` absent."""
    by_site, _inlined = gate.instances(DWARF, gate.source_paths(RAWLINE))
    state = "crates/rsk-fido/src/state.rs"
    assert (state, "rsk_fido::state::FidoState::mark_token_used") in by_site
    assert (state, "mark_token_used") not in by_site


def test_a_mangling_this_reader_does_not_speak_keeps_the_bare_name():
    """`ct_gate.demangle` returns the v0 scheme and plain C names unchanged, and
    a path whose last component is not the `fn` is not that function's path. The
    fallback is the bare name — a collapse the source-anchored count catches, and
    strictly better than attributing a symbol to the wrong function."""
    v0 = DWARF.replace(
        "_ZN8rsk_fido5reset5sweep17hb74b7f7c3f715bcfE",
        "_RNvNtCsbG6fPTLZAcM_8rsk_fido5reset5sweep",
    )
    by_site, _inlined = gate.instances(v0, gate.source_paths(RAWLINE))
    assert ("crates/rsk-fido/src/reset.rs", "sweep") in by_site
    assert ("crates/rsk-fido/src/reset.rs", "rsk_fido::reset::sweep") not in by_site


def test_every_function_of_the_name_the_file_declares_is_owed():
    """The false pass, driven. Deleting the two production callers of the
    `authenticatorReset` session wipe drops
    `_ZN8rsk_fido5state9FidoState5reset17h…E` from the image, and the owner's
    candidates drop with it — so the count comes from `state.rs`, which declares
    four, and never from the image, where three is all there is to count."""
    findings, _ = run(
        sites=SITES + [RESET_SITE],
        raw=raw(dwarf=DWARF + SIBLING_RESETS, defined=DEFINED),
    )
    assert len(findings) == 1, findings
    assert "declares 4 `fn reset` (AssertionState, CredMgmtState, LargeBlobState, FidoState)" in findings[0]
    assert "the image carries 3" in findings[0] and "FidoState::reset" not in findings[0].split("carries 3")[1]


def test_an_impl_header_split_across_lines_still_names_its_item():
    """The `AppletHandler` impl of `crates/rsk-device/src/ctap.rs` puts the
    parameter list on one line and the self type on the next, so a header read to
    the NEWLINE labels that item with the empty string a free function gets."""
    text = (ROOT / "crates/rsk-device/src/ctap.rs").read_text(encoding="utf-8")
    assert gate.declarations(text, "new") == ["AppletHandler"]
    assert gate.declarations(text, "handle_cbor") == ["AppletHandler"]
    free = (ROOT / "firmware/src/pin_lock.rs").read_text(encoding="utf-8")
    assert gate.declarations(free, "encode") == [""], "a free function is in no item"


def test_the_innermost_item_is_the_one_a_fn_belongs_to():
    """A legal shape this tree does not carry, constructed: an `impl` inside a
    function body encloses a second `fn door`, and reading the OUTERMOST header
    attributes it to `Outer`."""
    source = (
        "impl Outer {\n    fn door() {}\n    fn wrapper() {\n"
        "        impl Inner {\n            fn door() {}\n        }\n    }\n}\n"
    )
    assert gate.declarations(source, "door") == ["Outer", "Inner"]
    # And an item ENDS: a `fn` after the closing brace is a free function, which
    # a brace counter that never balances attributes to the block above it.
    assert gate.declarations("impl Outer {\n    fn door() {}\n}\nfn door() {}\n", "door") == ["Outer", ""]


def test_an_owner_takes_the_WEAKEST_of_the_functions_it_names():
    """`FidoState::reset` is a symbol and its three siblings are inlined; the
    owner is `inlined`. A sibling with a symbol does not put a function that is
    nowhere into the image, which is the whole of what went wrong here."""
    both = dict(
        sites=SITES + [RESET_SITE],
        raw=raw(dwarf=DWARF + FIDO_RESET + SIBLING_RESETS, defined=DEFINED + RESET_SYMBOL),
    )
    findings, summary = run(**both)
    assert not findings, findings
    assert "1 symbol / 3 inlined / 2 absent" in summary, summary
    assert "over 7 bound function(s)" in summary, summary
    # And the evidence names all four, because an owner that is four functions
    # reported through one of them says nothing about the other three.
    findings, _ = run(CLAIMS + ABSENT + """
[[absent]]
file = "crates/rsk-fido/src/state.rs"
function = "reset"
basis = "unreached"
why = "stale"
""", **both)
    assert any("stale exemption" in f and f.count("::reset ") == 4 for f in findings), findings


def test_a_concrete_instance_decides_before_an_abstract_one():
    """159 functions in the real image carry both — inlined at some call sites
    and emitted standalone for the rest. `sweep` is that shape here, and reading
    the abstract half first reports a function `nm` defines as
    evidence-by-call-site."""
    by_site, inlined = gate.instances(DWARF, gate.source_paths(RAWLINE))
    site = ("crates/rsk-fido/src/reset.rs", "rsk_fido::reset::sweep")
    assert inlined[site] == 1 and len(by_site[site]) == 2, (inlined[site], by_site[site])
    defined = {line.split()[-1] for line in DEFINED.splitlines() if line.strip()}
    assert gate.bind(site, by_site[site], inlined, defined)[0] == "symbol"


def test_a_concrete_instance_with_no_symbol_is_its_own_finding():
    """Not a quieter pass: a standalone function the image defines no name for is
    a binding nothing can audit."""
    findings, _ = run(raw=raw(defined=""))
    assert any("defines no symbol for it" in f and "reset.rs::sweep" in f for f in findings), findings


def test_the_decl_file_index_is_resolved_through_the_line_program():
    """A `DW_AT_decl_file` is an index into the CU's OWN table; index 1 is a
    different file in another unit, so a reader that guesses binds nothing."""
    findings, _ = run(raw=raw(rawline=RAWLINE.replace("  1\t1\t0\t0\treset.rs", "  1\t1\t0\t0\tzzz.rs")))
    assert any("crates/rsk-fido/src/reset.rs::sweep" in f for f in findings), findings


def test_an_absolute_directory_table_is_still_bound():
    """A build that does not remap emits `DW_AT_comp_dir` plus absolute
    directories, and the owner paths are repo-relative. Driven, because this
    image's first-party directories happen to be relative already: with the
    normaliser removed the fixture stays green and this case does not."""
    absolute = RAWLINE.replace("  1\tcrates/", "  1\t/Users/maxmur/Code/RS-Key/crates/")
    findings, summary = run(raw=raw(rawline=absolute))
    assert not findings, findings
    assert "1 symbol" in summary, summary


def test_the_floor_holds_the_inlined_class():
    """A PARAMETER, not a global: the arm is driven by raising it, never by a
    case reaching into the module to lower the shipped one."""
    findings, _ = run(floors={"inlined": 3})
    assert any("floor 3" in f for f in findings), findings


# ---- who may be absent -------------------------------------------------------


def test_a_test_only_owner_in_the_shipped_image_is_named_a_defect():
    """The direction matters: this fires when the conformance writer IS present,
    not when it is missing."""
    findings, _ = run(gated={"crates/rsk-fido/src/reset.rs"})
    assert any("is TEST-ONLY and is in the shipped image as `symbol`" in f for f in findings), findings


def test_a_test_only_owner_may_not_carry_a_hand_written_absence():
    """Its absence is DERIVED from the module graph; a row answering it is a
    second answer to a derived question."""
    findings, _ = run(CLAIMS + ABSENT + """
[[absent]]
file = "crates/rsk-fido/src/conformance/mod.rs"
function = "arm_token"
basis = "unreached"
why = "conformance only"
""")
    assert any("its absence is DERIVED from the module graph" in f for f in findings), findings


def test_an_absent_owner_with_no_registered_row_is_refused():
    findings, _ = run(CLAIMS)
    assert any("registers no absence for it" in f and "security_trace_snapshot" in f
               for f in findings), findings


def test_a_stale_exemption_is_refused():
    """A row kept for an owner the image now binds is one nobody will notice go
    stale — the allowlist would then be shorter than the contract by one. Its
    evidence names the FUNCTION: `ct_gate.demangle` is the only reason a finding
    reads `rsk_fido::reset::sweep` rather than the mangling `nm` prints."""
    findings, _ = run(CLAIMS + ABSENT.replace(
        'file = "crates/rsk-device/src/ctap.rs"\nfunction = "security_trace_snapshot"',
        'file = "crates/rsk-fido/src/reset.rs"\nfunction = "sweep"',
    ))
    assert any("stale exemption" in f and "(rsk_fido::reset::sweep)" in f
               for f in findings), findings


def test_an_absence_for_a_site_no_axis_owns_is_refused():
    findings, _ = run(CLAIMS + ABSENT + """
[[absent]]
file = "crates/rsk-fido/src/getinfo.rs"
function = "get_info"
basis = "unreached"
why = "not an owner at all"
""")
    assert any("owns no such site" in f for f in findings), findings


# ---- the bases, driven against the real tree ---------------------------------


def bases_of(function: str):
    """Which of the five the tree bears for one real absent owner."""
    catalogue = gate.callers(ROOT)
    where = {
        "security_trace_snapshot": "crates/rsk-device/src/ctap.rs",
        "store_pin_lock": "crates/rsk-device/src/lib.rs",
        "store_local_pin": "crates/rsk-fido/src/clientpin.rs",
        "spend_and_verify_local_pin": "crates/rsk-fido/src/clientpin.rs",
        "round_trips": "firmware/src/pin_lock.rs",
    }[function]
    return {
        basis: gate.basis_holds(ROOT, where, function, basis, catalogue)[0]
        for basis in gate.BASES
    }


def test_each_registered_absence_bears_exactly_one_basis():
    """Disjoint by construction, and that is the point: one row is genuinely
    cfg-gated AND has no caller in scope, so without the exclusions its basis
    could be swapped for a weaker one and stay green."""
    assert bases_of("security_trace_snapshot") == {
        "cfg-gated": True, "trait-default-body": False, "const-evaluated": False,
        "unlinked-crate": False, "unreached": False}
    assert bases_of("store_pin_lock") == {
        "cfg-gated": False, "trait-default-body": True, "const-evaluated": False,
        "unlinked-crate": False, "unreached": False}
    assert bases_of("round_trips") == {
        "cfg-gated": False, "trait-default-body": False, "const-evaluated": True,
        "unlinked-crate": False, "unreached": False}


def test_a_door_called_only_from_an_unlinked_crate_is_not_unreached():
    """The word has to match the derivation. Both `clientpin.rs` doors ARE called
    — from `crates/rsk-display`, which the default image does not link — and
    reading that as "nobody calls it" is what let a scope of three directories
    answer for a tree of twenty-seven crates."""
    for door in ("store_local_pin", "spend_and_verify_local_pin"):
        assert bases_of(door) == {
            "cfg-gated": False, "trait-default-body": False,
            "const-evaluated": False, "unlinked-crate": True, "unreached": False}, door


def test_a_caller_outside_the_writer_axes_three_directories_is_still_a_caller():
    """Measured: 71 files against 244. `token_refinement_gate.catalogue` is the
    axes' own scope and cannot see `crates/rsk-display` at all."""
    wide = {f for f, _fn in gate.callers(ROOT)}
    narrow = {f for f, _fn in refinement.catalogue(ROOT)}
    assert "crates/rsk-display/src/pin.rs" in wide - narrow
    assert "crates/rsk-fido/src/clientpin.rs" in wide & narrow
    assert len(wide) > len(narrow), (len(wide), len(narrow))


def test_the_default_images_closure_is_walked_and_leaves_the_optional_crates_out():
    """`unlinked-crate` rests on this walk. Cross-checked against
    `cargo tree -p firmware -e normal`: the same 22 crates, and the six it
    leaves out are the `display`/`bench` optionals nothing turns on and
    `rsk-secret`, which nothing uses yet."""
    linked = gate.linked_crates(ROOT)
    assert "firmware" in linked and "crates/rsk-fido" in linked
    assert set(gate.crates(ROOT).values()) - linked == {
        "crates/rsk-bench", "crates/rsk-bip39", "crates/rsk-display",
        "crates/rsk-secret", "crates/rsk-slip39", "crates/rsk-ui"}


def test_an_optional_dependency_a_default_feature_turns_on_is_linked(tmp_path):
    """The arm the real tree cannot drive: no manifest in it declares a `default`
    list, so an optional dependency is out whatever the walk does with features.
    Here one is `optional` AND named by `default`, and it must be IN."""
    (tmp_path / "crates/thing").mkdir(parents=True)
    (tmp_path / "crates/thing/Cargo.toml").write_text('[package]\nname = "thing"\n', encoding="utf-8")
    (tmp_path / "firmware").mkdir(parents=True)
    # `default = ["screen"]`, `screen = ["thing"]` — one hop, so the closure is
    # WALKED: a feature list names features, and reading only `default` stops at
    # the first name that is not a dependency.
    manifest = ('[package]\nname = "firmware"\n[dependencies]\n'
                'thing = {{ path = "../crates/thing", optional = true }}\n'
                '[features]\ndefault = [{on}]\nscreen = ["thing"]\n')
    (tmp_path / "firmware/Cargo.toml").write_text(manifest.format(on=""), encoding="utf-8")
    assert gate.linked_crates(tmp_path) == {"firmware"}
    (tmp_path / "firmware/Cargo.toml").write_text(manifest.format(on='"screen"'), encoding="utf-8")
    assert gate.linked_crates(tmp_path) == {"firmware", "crates/thing"}


def test_a_basis_over_a_function_the_file_no_longer_declares_is_refused():
    """An `[[absent]]` row outliving its `fn` is the shape every registry rots
    into, and without the guard it is an AttributeError rather than a finding."""
    held, measured = gate.basis_holds(
        ROOT, "crates/rsk-fido/src/state.rs", "no_such_writer", "unreached", {}
    )
    assert not held and "no `fn no_such_writer`" in measured, measured


def test_unreached_still_holds_of_a_function_nobody_calls(tmp_path):
    """No registered row wears it any more — both former ones are
    `unlinked-crate` — so the word's own arm is constructed: a `fn` in no item,
    behind no `cfg`, that nothing in the tree calls."""
    (tmp_path / "crates/thing/src").mkdir(parents=True)
    (tmp_path / "crates/thing/Cargo.toml").write_text('[package]\nname = "thing"\n', encoding="utf-8")
    (tmp_path / "crates/thing/src/a.rs").write_text("fn door() {}\n", encoding="utf-8")
    assert gate.basis_holds(tmp_path, "crates/thing/src/a.rs", "door", "unreached", {})[0]
    caller = {("crates/thing/src/b.rs", "opens"): "fn opens() { door(); }"}
    held, measured = gate.basis_holds(tmp_path, "crates/thing/src/a.rs", "door", "unreached", caller)
    assert not held, measured


def test_a_relabelled_basis_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace('basis = "cfg-gated"', 'basis = "unreached"'))
    assert any("claims basis `unreached` and the tree does not bear it" in f
               for f in findings), findings


def test_a_basis_outside_the_vocabulary_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace('basis = "cfg-gated"', 'basis = "trust me"'))
    assert any("is not one of" in f and "trust me" in f for f in findings), findings


def test_a_feature_turned_on_by_default_stops_being_a_basis():
    """`cfg-gated` is a claim about the DEFAULT image, so it is re-derived from
    the manifests rather than read off the attribute."""
    assert "security-trace" not in gate.default_features(ROOT, "crates/rsk-device/src/ctap.rs")
    assert gate.default_features(ROOT, "crates/rsk-fido/src/clientpin.rs") == set()


def test_the_default_feature_set_is_subtracted_by_basis_holds_itself(tmp_path):
    """Driven through `basis_holds` and not through `default_features`: this
    tree's manifests declare no `default` list at all, so a case that only calls
    the reader leaves the SUBTRACTION — the half that makes `cfg-gated` a claim
    about the default image — held by nothing."""
    (tmp_path / "crates/thing/src").mkdir(parents=True)
    (tmp_path / "crates/thing/src/a.rs").write_text(
        '#[cfg(feature = "screen")]\nfn door() {}\n', encoding="utf-8"
    )
    manifest = '[package]\nname = "thing"\n[features]\ndefault = [{on}]\nscreen = []\n'
    (tmp_path / "crates/thing/Cargo.toml").write_text(manifest.format(on=""), encoding="utf-8")
    assert gate.basis_holds(tmp_path, "crates/thing/src/a.rs", "door", "cfg-gated", {})[0]
    (tmp_path / "crates/thing/Cargo.toml").write_text(manifest.format(on='"screen"'), encoding="utf-8")
    held, measured = gate.basis_holds(tmp_path, "crates/thing/src/a.rs", "door", "cfg-gated", {})
    assert not held, measured


def crate(tmp_path, manifest: str, image: str = "") -> pathlib.Path:
    """A two-manifest tree, because this tree cannot drive the rule.

    Measured: neither `rsk-device` nor `firmware` declares a `default` list and
    `rsk-device = { workspace = true }` enables nothing, so `default_features`
    returns the empty set here whatever it reads — a case written over the real
    manifests is green with the function stubbed out to `set()`, driven.
    """
    (tmp_path / "crates/thing/src").mkdir(parents=True)
    (tmp_path / "crates/thing/Cargo.toml").write_text(manifest, encoding="utf-8")
    (tmp_path / "crates/thing/src/a.rs").write_text("fn a() {}\n", encoding="utf-8")
    if image:
        (tmp_path / "firmware").mkdir(parents=True)
        (tmp_path / "firmware/Cargo.toml").write_text(image, encoding="utf-8")
    return tmp_path


def test_a_crates_own_default_list_is_read(tmp_path):
    root = crate(tmp_path, '[package]\nname = "thing"\n[features]\ndefault = ["screen"]\nscreen = []\n')
    assert gate.default_features(root, "crates/thing/src/a.rs") == {"screen"}


def test_the_image_crates_default_closure_reaches_a_dependency_feature(tmp_path):
    """`default = ["big"]`, `big = ["thing/screen"]` — one hop, and the closure is
    walked rather than read, because a feature list names features."""
    root = crate(
        tmp_path,
        '[package]\nname = "thing"\n[features]\nscreen = []\n',
        '[package]\nname = "firmware"\n[features]\ndefault = ["big"]\nbig = ["thing/screen"]\n',
    )
    assert gate.default_features(root, "crates/thing/src/a.rs") == {"screen"}


def test_a_feature_the_image_asks_of_a_dependency_is_on(tmp_path):
    root = crate(
        tmp_path,
        '[package]\nname = "thing"\n[features]\nscreen = []\n',
        '[package]\nname = "firmware"\n[dependencies]\nthing = { path = "../crates/thing", features = ["screen"] }\n',
    )
    assert gate.default_features(root, "crates/thing/src/a.rs") == {"screen"}


def test_a_trait_body_is_found_by_brace_counting_and_not_by_a_pattern():
    """A trait body holds nested blocks; a regex stopping at the first `}` reads
    the trait as ending inside its own first default method. And it has to END
    where its braces do: every `fn` of `rsk-device/src/lib.rs` is inside the one
    trait, so the arm that says the block CLOSES is constructed here — a counter
    that never balances runs the item to EOF and swallows what follows it."""
    text = (ROOT / "crates/rsk-device/src/lib.rs").read_text(encoding="utf-8")
    assert gate.in_trait_item(text, "store_pin_lock")
    assert not gate.in_trait_item(text, "no_such_method_anywhere")
    closes = "trait Hooks {\n    fn provided(&self) { let _ = |x| { x }; }\n}\n\nfn after() {}\n"
    assert gate.in_trait_item(closes, "provided")
    assert not gate.in_trait_item(closes, "after")


# ---- the wiring --------------------------------------------------------------


def test_the_row_reads_the_default_image_because_of_where_it_sits():
    """The claim says the DEFAULT profile and nothing but the row's POSITION
    makes that true: `target/…/release/firmware` is one path four `-p firmware`
    rows write in turn, so this row moved down to the other Python gates would
    audit the no-touch binary. Measured: 0 `bootsel` symbols in that image
    against the default image's 2."""
    default = row('run "build firmware (release)"')
    audits = row("python scripts/owner_binding_gate.py")
    rebuilds = [
        row('run "build firmware (16M)"'),
        row('run "build firmware (display)"'),
        row("--features no-touch"),
    ]
    assert default < audits < min(rebuilds), (default, audits, rebuilds)
    assert max(rebuilds) < row("python -m pytest scripts -q"), rebuilds


def test_main_returns_one_and_writes_its_findings_to_stderr(monkeypatch, capsys):
    """The half `check.sh` actually reads. Every other case drives `audit`, so
    the exit code — the whole of what the row is judged by — and the stream each
    half is printed on were held by nothing but the row itself."""
    monkeypatch.setattr(gate, "audit", lambda root: (["a finding"], ""))
    assert gate.main([]) == 1
    out = capsys.readouterr()
    assert out.err.splitlines() == ["owner-binding:", "  a finding"] and not out.out, out
    monkeypatch.setattr(gate, "audit", lambda root: ([], "owner-binding: ok — …"))
    assert gate.main([]) == 0
    out = capsys.readouterr()
    assert "owner-binding: ok" in out.out and not out.err, out
    assert gate.main(["--why"]) == 2, "this gate takes no arguments"
    assert "usage: owner_binding_gate.py" in capsys.readouterr().err
    # And the argv it reads when handed none is the PROCESS's, which is how
    # `check.sh` calls it — a default of `None` runs the audit on any arguments.
    monkeypatch.setattr(gate.sys, "argv", ["owner_binding_gate.py", "--why"])
    assert gate.main() == 2


def test_each_compile_units_own_file_table_is_kept():
    """A `DW_AT_decl_file` is an index into the CU's OWN table, and the tables
    differ per unit — index 1 is `reset.rs` in the firmware program and `ring.rs`
    in the second. A reader that keeps one table binds owners to whatever file
    the last program happened to name."""
    tables = gate.source_paths(RAWLINE)
    assert set(tables) == {0, 0x3F492}, sorted(tables)
    assert tables[0][1] == "crates/rsk-fido/src/reset.rs"
    assert tables[0x3F492][1] == "crates/rsk-fs/src/ring.rs"


def test_a_die_that_is_not_a_subprogram_does_not_donate_its_attributes():
    """`DW_TAG_variable` carries `DW_AT_name` and `DW_AT_decl_file` too, and the
    parser is line-oriented: a reader that does not drop the current DIE at a tag
    it does not read hands `sweep` the NEXT DIE's file."""
    by_site, _inlined = gate.instances(DWARF, gate.source_paths(RAWLINE))
    assert ("crates/rsk-fido/src/reset.rs", "rsk_fido::reset::sweep") in by_site
    assert not [k for k in by_site if "FIDO_SEED_FIDS" in k[1]], sorted(by_site)


def test_the_row_sits_with_the_other_readers_of_this_image():
    """Beside `ct_gate` and `elf_gate`, which read the same binary in the same
    window and whose registry this one holds its artifact against."""
    assert row("python scripts/elf_gate.py") < row("python scripts/owner_binding_gate.py")


def test_the_table_can_go_red():
    """The mutation table, DERIVED and not typed: every statement of
    `scripts/owner_binding_gate.py` deleted in turn — 462 of them, in a copy of
    the tree, one pytest run each, with the exit code taken from the process (no
    pipe) and the FAILING ASSERTION read for its DIRECTION. Unmutated: rc 0,
    **69 passed, 0 skipped**. The sweep measured **422 killed, 40 survived**, no
    syntax errors; three of those forty — `main`'s argv default and its two
    `stderr` prints — were closed afterwards and driven one at a time, leaving
    **37**. The predecessor of this table was 39 hand-written arms, and an
    adversarial review found 16 survivors it had never enumerated — which is why
    the enumeration is a sweep now and the survivors are NAMED below.

    * **Python, not the gate** — 5: `from __future__ import annotations`, the
      `sys.path` insert this file makes first anyway, `return None` where Python
      returns it regardless, and the `if __name__ == "__main__"` guard no import
      takes.
    * **Defensive against shapes the toolchain does not emit** — 16. The
      `DW_TAG_compile_unit` reset (every rustc CU DIE carries `DW_AT_stmt_list`
      AND `DW_AT_comp_dir`, so the previous unit's values are overwritten before
      anything reads them), `identity`'s depth-8 recursion cap (a cyclic
      `DW_AT_specification`), the `Opcodes` reset (`readelf` prints the opcode
      table BEFORE both tables in all 165 programs of this image), the
      `start == -1` arms of the two brace counters (an `impl`/`trait` header with
      no `{`), and `default_features` over a path under no `Cargo.toml`.
    * **`continue`s whose fall-through is harmless** — 5: the branches they leave
      test mutually exclusive line shapes, and the one after the `unsymbolised`
      finding risks only a second finding on the same site.
    * **Reachable only from a registry two rules already refuse** — 5:
      `len(binding) != 1` (the subject-count and both-subjects rules return
      first) and the `if findings: return` after the pairing block.
    * **The injection seams themselves** — 3: `raw`, `sites` and `gated` are what
      every case hands in, so `x if x is None else` cannot be driven from here.
      `read`, `roster` and `test_only_sources` are each driven on their own.
    * **`depth = 0` before the generics scan** — 1, unkillable by construction:
      the brace counter above it leaves `depth` at 0.
    * **A guard whose case would HANG** — 2: `if entry in walked` is the cycle
      guard of the feature-closure walk, and `default = ["a"], a = ["b"],
      b = ["a"]` without it does not fail, it spins. A suite that hangs is a
      worse failure mode than the defect, so this one is stated instead.
    A deletion is ONE defect shape, so these are EDITS, driven the same way and
    each read for which assertion fell and in which direction:

    * `SUBJECTS["bit-for-bit"] = "BINARY-CHECKED"` → 22 cases, and the direction
      is the one that matters:
      `test_the_reproducibility_row_may_not_wear_binary_checked` fails on
      `findings == []` — the laundered row was ACCEPTED, not "refused for the
      wrong reason" — while the control fails because the honest `MEASURED` row
      is now refused. The vocabulary IS the rule
    * `DISCHARGES = "bit-for-bit"` → both claims then wear the undischarged shape
      and the `verified_by` rules invert
    * `FRONTIER = "owner->image"` → the subject this gate exists to carry becomes
      the one it refuses
    * `identity` keyed on `DW_AT_name` again, the defect this row shipped with →
      `test_four_functions_of_one_name_are_four_sites`, and the arm that matters
      is `test_every_function_of_the_name_the_file_declares_is_owed`: the count
      comes from `state.rs`, so a function that leaves the image cannot take its
      own requirement with it
    * `bind` returning `symbol` without consulting `nm`
    * `invoked()` returning the whole command → `nix build .#firmware` is a
      substring of no workflow line, so every verifier is refused
    * `unreached` dropping its exclusions → the pair that says the bases are a
      PARTITION and not a menu: the row that is genuinely cfg-gated also has no
      caller in scope
    * `FLOORS["inlined"] = 0` → `assert 0 < 0`; `= 21` → `assert 21 < 21`. The
      cases hand their own floor in, so the shipped value is held from both sides
      by a range instead — zero is the weakening, and a floor set AT the
      measurement turns a deleted guard into a report about its reader
    * `roster()` reading one axis instead of `refinement.AXES` (44 -> 11), and
      dropping its dedup (44 -> 48): the ledger owns 48 rows over 44 sites, and
      an oracle that rebuilds a SET of sites re-deduplicates them and cannot see
      it
    * `DW_AT_decl_file` read `+ 1` → every owner shifts one file over
    * the test-only defect clause off → the assertion that falls is the
      "should have been refused" one
    """
    assert gate.SUBJECTS["owner->image"] == gate.DISCHARGED
    assert gate.SUBJECTS["bit-for-bit"] != gate.DISCHARGED
