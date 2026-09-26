# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `elf_gate.py`.

Every case runs against RECORDED tool output and a registry handed in as text.
Neither the ELF nor the working tree is touched here, and NOTHING in this file
skips — the three corrections an audit drove, each of them measured:

* **7 of the 13 cases used to skip on a missing image, at exit 0.** Measured in a
  checkout with no `target/`: `6 passed, 7 skipped`, `pytest` exit **0**, and the
  row `check.sh` reads is that exit code. The docstring here claimed every case
  ran against the real image; a skipped case runs against nothing.
* **They read the WRONG image when they did run.** The `image segments and
  allocator` row sits deliberately inside the window where `target/` holds the
  DEFAULT build; `pytest (gate scripts)` is ~250 rows later, after the 16 MB,
  display and no-touch rebuilds have overwritten that one path. Measured on the
  tree `check.sh` left: the image standing at the pytest row defines **0**
  `bootsel` symbols, the default image **2**.
  [`test_the_row_reads_the_default_image_because_of_where_it_sits`] holds that
  window by content rather than by a line number that would rot. Measured while
  fixing it, and worth not over-claiming: today the no-touch image satisfies this
  registry too — same 5 LOAD segments, same W+X, same 165 compile units — so the
  defect was that the cases certified a DIFFERENT binary than the row, not that
  they were green over a difference. The next profile divergence is what it costs.
* **One case wrote `assurance/image.toml` and restored it in a `finally`** — the
  only test under `scripts/` that touched the working tree, 90 minutes after the
  same defect was swept out of `ct_gate`'s table. The registry is handed in now.

What that trades away, said here rather than discovered later: these cases cannot
fail on the parsers meeting a `readelf`/`nm` whose OUTPUT format moved. That is
the row's job — it runs the real tools over the real image — and the split is the
one `test_ct_gate.py` already makes. The recorded text is verbatim tool output
from a `cargo build --release -p firmware` of `9cafee7`, with the DIE lines the
DWARF parser does not read elided; the arms no case can drive are recorded in
[`test_the_image_arms_were_driven_by_hand`].
"""

from __future__ import annotations

import copy
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_gate  # noqa: E402
import gate_lines  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: `arm-none-eabi-readelf -lW`, verbatim. Five LOAD segments: the vector table,
#: `.text`, the read-only tail, `.data` — the one that RUNS in RAM and is STORED
#: in flash, which is why both addresses are parsed — and `.bss`.
PHDR = """
Elf file type is EXEC (Executable file)
Entry point 0x1000013d
There are 6 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000134 0x10000000 0x10000000 0x0013c 0x0013c R   0x4
  LOAD           0x000274 0x1000013c 0x1000013c 0xb8170 0xb8170 R E 0x8
  LOAD           0x0b83ec 0x100b82ac 0x100b82ac 0x0cefc 0x0cefc R   0x10
  LOAD           0x0c52e8 0x2002baa0 0x100c51a8 0x01ec0 0x01ec0 RWE 0x4
  LOAD           0x0c71c0 0x2002d960 0x2002d960 0x00000 0x52694 RW  0x20
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0

 Section to Segment mapping:
  Segment Sections...
   00     .vector_table .start_block
   01     .text
   02     .bi_entries .rodata
   03     .data
   04     .bss
   05
"""

#: `arm-none-eabi-nm --defined-only`, the four symbols the rule matches and four
#: neighbours it must NOT: `___rdl_alloc_error_handler` is the shim, not the
#: handler, and `dealloc`/`deallocate`/`handle_alloc_error` are `alloc` machinery
#: rather than the surface. A fixture of four clean lines would pass over a
#: regex that matched everything with "alloc" in it.
DEFINED = """1000053a t _RNvCsGIExRX8pES_7___rustc12___rust_alloc
1000054c t _RNvCsGIExRX8pES_7___rustc14___rust_dealloc
1000057c t _RNvCsGIExRX8pES_7___rustc14___rust_realloc
10041e42 t _RNvCsGIExRX8pES_7___rustc25___rdl_alloc_error_handler
1003d5c0 t _RNvCsGIExRX8pES_7___rustc26___rust_alloc_error_handler
10041e9a t _RNvNtCs1bu0FZYAZ3A_5alloc5alloc18handle_alloc_error
1009e8dc t _ZN5alloc7raw_vec20RawVecInner$LT$A$GT$10deallocate17hd6fb662329047188E
1004e658 t _ZN79_$LT$embedded_alloc..llff..Heap$u20$as$u20$core..alloc..global..GlobalAlloc$GT$7dealloc17h0e3c912a2475acbcE
"""

#: `arm-none-eabi-nm -u`. Empty, and that is the measurement: a fully linked
#: image has nothing left undefined.
UNDEFINED = ""

#: `arm-none-eabi-readelf --debug-dump=info --dwarf-depth=1`, verbatim but for
#: the DIE lines the parser does not read. Two compilers: the pinned rustc, and
#: the 2021 nightly that built the prebuilt `cortex-m` `asm/lib.rs` blob.
DWARF = """  Compilation Unit @ offset 0x169a19:
   Length:        0xcfae (32-bit)
   Version:       4
   Abbrev Offset: 0
   Pointer Size:  4
 <0><169a24>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <169a25>   DW_AT_producer    : (indirect string, offset: 0xddb9d): clang LLVM (rustc version 1.96.0 (ac68faa20 2026-05-25))
    <169a2b>   DW_AT_name        : (indirect string, offset: 0x2b0a87): /x/aes-0.8.4/src/lib.rs/@/aes.bd11237b4c9947f0-cgu.0
 <1><169a3f>: ...
  Compilation Unit @ offset 0x1769cb:
 <0><1769d6>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <1769d7>   DW_AT_producer    : (indirect string, offset: 0xddb9d): clang LLVM (rustc version 1.96.0 (ac68faa20 2026-05-25))
    <1769de>   DW_AT_name        : (indirect string, offset: 0x14f3b0): /x/base16ct-1.0.0/src/lib.rs/@/base16ct.9e5d178a000455a-cgu.0
 <1><1769ea>: ...
  Compilation Unit @ offset 0x482897:
 <0><4828a7>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <4828a8>   DW_AT_producer    : (indirect string, offset: 0x3399e9): clang LLVM (rustc version 1.59.0-nightly (c5ecc1570 2021-12-15))
    <4828ae>   DW_AT_name        : (indirect string, offset: 0x20ae0c): asm/lib.rs
 <1><4828ba>: ...
"""

RECORDED = {"phdr": PHDR, "defined": DEFINED, "undefined": UNDEFINED, "dwarf": DWARF}

PINNED = "clang LLVM (rustc version 1.96.0 (ac68faa20 2026-05-25))"
BLOB = "clang LLVM (rustc version 1.59.0-nightly (c5ecc1570 2021-12-15))"


def edited(text: str, old: str, new: str, count: int = 1) -> str:
    """`text` with one edit, and the anchor asserted to have RESOLVED.

    A mutation whose anchor silently missed leaves the case asserting that a
    clean input is clean — green, and about nothing.
    """
    assert old in text, old
    return text.replace(old, new, count)


def raw(**overrides) -> dict:
    """The recorded reads with one of them mutated."""
    return {**RECORDED, **overrides}


def shipped():
    findings: list[str] = []
    image = elf_gate.registry(ROOT, findings)
    assert not findings, findings
    return image


def registry_text() -> str:
    return (ROOT / elf_gate.REGISTRY).read_text(encoding="utf-8")


def check_sh() -> str:
    return (ROOT / "scripts/check.sh").read_text(encoding="utf-8")


def row(needle: str) -> int:
    """The line `check.sh` RUNS `needle` on — a `#` in front of it is not a row."""
    for number, line in enumerate(check_sh().splitlines(), 1):
        if needle in gate_lines.split_at_comment(line)[0]:
            return number
    raise AssertionError(f"check.sh runs no {needle!r}")


def test_the_registry_is_the_shape_the_gate_reads():
    image = shipped()
    assert image["profile"] == "default"
    assert image["writable_executable"] == [".data"]
    assert set(image["allocator"]) == {
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "__rust_alloc_error_handler",
    }
    assert set(image["producers"]) == {PINNED, BLOB}


def test_the_registry_refuses_a_key_it_does_not_read():
    findings: list[str] = []
    before = registry_text()
    elf_gate.registry(
        ROOT,
        findings,
        text=edited(before, 'profile = "default"', 'profile = "default"\nnote2 = "x"'),
    )
    assert any("is not a field this registry reads" in f for f in findings), findings
    # The half that is about the TABLE and not the rule: the mutation was handed
    # in, so the tracked file is byte-identical afterwards.
    assert registry_text() == before


def test_a_field_the_registry_lost_is_a_finding():
    """The direction that catches a rule being DISABLED rather than broken:
    delete `producers` and the set stops being held, with every other rule green."""
    findings: list[str] = []
    block = f'producers = [\n    "{PINNED}",\n    "{BLOB}",\n]\n'
    elf_gate.registry(ROOT, findings, text=edited(registry_text(), block, ""))
    assert any("no `producers`" in f for f in findings), findings


def test_the_linker_regions_parse():
    where = elf_gate.regions(ROOT)
    assert set(where) == {"FLASH", "KVMAIN", "KVCNT", "RAM"}
    assert where["FLASH"][0] == 0x10000000
    assert where["RAM"][0] == 0x20000000


def test_the_recorded_image_is_clean():
    """The control. Without it every case below could pass over a dead parser."""
    findings, summary = elf_gate.audit(ROOT, raw=RECORDED)
    assert not findings, findings
    assert "5 LOAD segment(s) inside 4" in summary
    assert "1 writable-executable as registered" in summary
    assert "4 allocator symbol(s) from 1 declaration, 0 undefined" in summary
    assert "3 compile unit(s) from 2 registered producer(s)" in summary


def test_a_second_writable_executable_segment_is_a_finding():
    image = copy.deepcopy(shipped())
    image["writable_executable"] = []
    findings, _ = elf_gate.audit(ROOT, image=image, raw=RECORDED)
    assert any("writable AND executable" in f for f in findings), findings


def test_an_allocator_symbol_that_is_not_registered_is_a_finding():
    image = copy.deepcopy(shipped())
    image["allocator"] = ["__rust_alloc"]
    findings, _ = elf_gate.audit(ROOT, image=image, raw=RECORDED)
    assert any("allocator surface" in f for f in findings), findings


def test_a_vector_table_away_from_the_flash_origin_is_a_finding():
    image = copy.deepcopy(shipped())
    image["vector_section"] = ".text"
    findings, _ = elf_gate.audit(ROOT, image=image, raw=RECORDED)
    assert any("not at" in f and "FLASH origin" in f for f in findings), findings


def test_a_segment_outside_every_region_is_a_finding():
    # FLASH shrunk to one page: `.text` no longer fits any region, and neither
    # does the vector table's own segment.
    linker = edited(
        (ROOT / elf_gate.LINKER).read_text(encoding="utf-8"),
        "FLASH  : ORIGIN = 0x10000000, LENGTH = 2560K",
        "FLASH  : ORIGIN = 0x10000000, LENGTH = 4K",
    )
    findings, _ = elf_gate.audit(ROOT, linker=linker, raw=RECORDED)
    assert any("outside every" in f for f in findings), findings


def test_code_landing_in_the_kv_store_is_a_finding():
    # The rule the partition table cannot state: KVMAIN moved down onto the code
    # the linker already placed. The table fences the store from BOOTSEL; this
    # fences it from the linker.
    linker = edited(
        (ROOT / elf_gate.LINKER).read_text(encoding="utf-8"),
        "KVMAIN : ORIGIN = 0x10280000, LENGTH = 1408K",
        "KVMAIN : ORIGIN = 0x10001000, LENGTH = 1408K",
    )
    findings, _ = elf_gate.audit(ROOT, linker=linker, raw=RECORDED)
    assert any("erased by its own store" in f for f in findings), findings


def test_an_entry_point_outside_flash_is_a_finding():
    """A linked image whose entry is in RAM does not boot at all, and the rule
    that says so had no case: it was asserted directly on the real ELF, which is
    the assertion that vanished when the image was missing."""
    findings, _ = elf_gate.audit(
        ROOT, raw=raw(phdr=edited(PHDR, "Entry point 0x1000013d", "Entry point 0x2000013d"))
    )
    assert any("entry point" in f and "outside FLASH" in f for f in findings), findings


def test_a_vector_section_no_segment_carries_is_a_finding():
    """The other half of the vector rule: the case above moves the table, this
    one makes it VANISH. A registry naming a section the linker no longer emits
    would otherwise leave `table` empty and every address rule silent."""
    image = copy.deepcopy(shipped())
    image["vector_section"] = ".no_such_section"
    findings, _ = elf_gate.audit(ROOT, image=image, raw=RECORDED)
    assert any("no LOAD segment carries" in f for f in findings), findings


def test_a_linker_script_with_no_regions_is_a_finding():
    """Vacuity, one layer down: with no region parsed, "inside a region" and
    "not inside the KV store" are both true of everything."""
    findings, _ = elf_gate.audit(ROOT, linker="", raw=RECORDED)
    assert any("no MEMORY region parsed" in f for f in findings), findings


def test_a_program_header_table_the_parser_cannot_read_is_a_finding():
    """And one layer down again: `readelf`'s row format moving is the way this
    whole file goes quiet, so "fewer than two LOAD segments" is its own finding
    rather than a silent pass over an empty list."""
    findings, _ = elf_gate.audit(ROOT, raw=raw(phdr=""))
    assert any("the parser found nothing" in f for f in findings), findings


def test_an_undefined_symbol_is_a_finding():
    """`nm -u` empty is a measurement, not a certainty: a `#[no_mangle]` C symbol
    nothing provides links here and traps at the call."""
    findings, _ = elf_gate.audit(ROOT, raw=raw(undefined="         U __aeabi_memcpy\n"))
    assert any("undefined symbol(s)" in f for f in findings), findings


def test_a_third_compiler_is_a_finding():
    """The producer rule's point: the image's trusted computing base is the set
    of compilers that wrote it, and one arriving through a dependency changed
    nothing else this file reads."""
    findings, _ = elf_gate.audit(
        ROOT,
        raw=raw(
            dwarf=edited(DWARF, BLOB, "GNU C17 15.2.0 -mcpu=cortex-m33 -O2")
        ),
    )
    assert any("DWARF producers are" in f for f in findings), findings


def test_a_producer_the_registry_holds_and_the_image_lost_is_a_finding():
    """Held BOTH ways. The blob leaving is not a defect, but it is a change to
    what built the image, and a set that only grows is a set nobody re-reads."""
    findings, _ = elf_gate.audit(ROOT, raw=raw(dwarf=edited(DWARF, BLOB, PINNED)))
    assert any("DWARF producers are" in f for f in findings), findings


def test_an_image_with_no_producer_at_all_is_a_finding():
    """The vacuity control: a stripped image answers every rule above with
    nothing, and an empty set would otherwise match an emptied registry."""
    findings, _ = elf_gate.audit(ROOT, raw=raw(dwarf=""))
    assert any("no DW_AT_producer" in f for f in findings), findings


def test_exactly_one_global_allocator_is_declared():
    """The other end of the allocator question, over the SOURCE. The symbol rule
    is a list of spellings and a rule that is a list of spellings is bypassed by
    one nobody listed; a second `#[global_allocator]` is a different heap
    whatever its symbols are called. Measured: one, `firmware/src/main.rs`."""
    declared = [
        path.relative_to(ROOT)
        for root_dir in elf_gate.FIRST_PARTY_RUST
        for path in sorted((ROOT / root_dir).rglob("*.rs"))
        if elf_gate.GLOBAL_ALLOCATOR.search(path.read_text(errors="replace"))
    ]
    assert [str(p) for p in declared] == ["firmware/src/main.rs"], declared


def test_the_declaration_pattern_is_anchored_to_the_attribute():
    """Not to the word: `docs/unsafe.md` and this docstring both say
    `global_allocator`, and a rule that matched the word would count them."""
    assert elf_gate.GLOBAL_ALLOCATOR.search("#[global_allocator]\n")
    assert elf_gate.GLOBAL_ALLOCATOR.search("    #[global_allocator]\n")
    assert not elf_gate.GLOBAL_ALLOCATOR.search("// a global_allocator lives here")
    assert not elf_gate.GLOBAL_ALLOCATOR.search("let global_allocator = 1;")


def test_the_row_reads_the_default_image_because_of_where_it_sits():
    """The registry says DEFAULT profile; nothing but the row's POSITION makes
    that true. `target/…/release/firmware` is one path that four `-p firmware`
    rows write in turn, so the row moved down to the other Python gates would
    audit the no-touch binary against a registry describing the shipped one —
    silently, since both are ELFs the parsers read. Measured on the tree
    `check.sh` leaves: 0 `bootsel` symbols in that image against the default
    image's 2."""
    default = row('run "build firmware (release)"')
    audits = row("python scripts/elf_gate.py")
    rebuilds = [
        row('run "build firmware (16M)"'),
        row('run "build firmware (display)"'),
        row("--features no-touch"),
    ]
    pytest_row = row("python -m pytest scripts -q")
    assert default < audits < min(rebuilds), (default, audits, rebuilds)
    assert max(rebuilds) < pytest_row, (rebuilds, pytest_row)


def test_the_table_can_go_red():
    """The mutation table: one arm per rule, each driven through this file with
    the exit code taken from the process and the FAILING ASSERTION read.

    Unmutated: rc 0, **23 passed, 0 skipped** — the 0 is half the point, since
    the version this replaces ran 6 passed / 7 skipped at rc 0 in a checkout with
    no image. Every arm is one edit to `scripts/elf_gate.py` unless it says
    otherwise, run in a copy of the tree at `9cafee7` with `target/` pointed at a
    default-profile build, `PYTHONDONTWRITEBYTECODE=1`:

    * the producer set comparison → `elif False` — rc 1, **2** cases
    * the vacuity guard `if not compiled` off — rc 1, the stripped-image case
    * `registry()` ignoring its handed-in `text` — rc 1, **2** cases: the arm that
      says the table drives the rule while writing nothing
    * the W+X comparison off — rc 1, one case
    * the undefined-symbol rule off — rc 1, one case
    * the entry-point rule off — rc 1, one case. The case this replaces asserted
      the property on the ELF directly and never called `audit`, so deleting the
      rule left it GREEN — the arm that says a case must drive the guard
    * the "no segment carries the vector section" guard off — rc 1, 2 cases, and
      by `IndexError` rather than by a missing finding: that guard stands in
      front of `table[0]`, so it is load-bearing twice over
    * the "no MEMORY region parsed" guard off — rc 1, the empty-linker case, with
      the region-containment findings still reported and the specific one gone
    * the "fewer than two LOAD segments" guard off — rc 1, the empty-header case
    * `check.sh`'s row MOVED down to the other Python gates — rc 1,
      `assert 816 < 569`, i.e. the row now runs after the rebuilds
    * one mutation anchor edited so it no longer resolves — rc 1, and it falls
      inside [`edited`], which is the guard that stops a case asserting that a
      clean input is clean
    * **CONTROL**: a comment added to `elf_gate.py` — rc 0, 23 passed

    Every rule arm but the three vacuity ones failed with `AssertionError: []` —
    the rule reported NOTHING where a finding was expected. None failed the other
    way round, which is the reading that would have meant the case models the
    inverse defect; the three exceptions are read one by one above.

    One trap, measured here: pytest's assertion-rewrite cache is keyed on
    (mtime, size), so a mutation of the SAME LENGTH — `0x1000013d` for
    `0xdeadbeef` — was served from `__pycache__` on the next run after the file
    was restored, and a case failed over a mutation that was no longer there.
    `-p no:cacheprovider` does not cover it; `PYTHONDONTWRITEBYTECODE=1` does.
    """
    assert elf_gate.REGISTRY == pathlib.Path("assurance/image.toml")


def test_the_image_arms_were_driven_by_hand():
    """Recorded, because a case cannot relink the firmware.

    Measured on a `cargo build --release -p firmware` of `9cafee7` — the DEFAULT
    profile, built into its own `CARGO_TARGET_DIR` so the tree's no-touch test
    image survived — with `arm-none-eabi-readelf -lW`, `arm-none-eabi-nm` and
    `arm-none-eabi-readelf --debug-dump=info --dwarf-depth=1`:

    | fact | measured |
    |---|---|
    | LOAD segments | 5 (`.vector_table`+`.start_block`, `.text`, `.bi_entries`+`.rodata`, `.data`, `.bss`) |
    | writable AND executable | 1, `.data`, at run address `0x2002baa0` and load address `0x100c51a8` |
    | allocator symbols defined | 3 |
    | undefined symbols | 0 |
    | entry point | `0x1000013d`, inside `.text` |
    | compile units | 165: 164 from the pinned rustc, 1 from the 2021 nightly (`asm/lib.rs`) |

    The `.data` segment is the reason the W+X rule is "exactly the registered
    one" and not "none": it carries the routines that must not run from XIP
    flash, and a blanket rule would be red on a correct image. The load address
    in the table this replaces read `0x100c4f08` — a number that had rotted
    behind an image nothing re-measured, which is the same drift the recorded
    fixtures above are dated for.
    """
    assert elf_gate.UNITS == {"": 1, "K": 1024, "M": 1024 * 1024}
