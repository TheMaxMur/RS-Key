# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `ct_gate.py`.

Two halves, and the split is what they can decide. The cases above the fixtures
run against a RECORDED disassembly and a registry handed in as text: the parser
and the RULE are what they are about, and neither the ELF nor the working tree is
touched. That the registry is handed in is a correction an independent review
drove — the first version wrote `assurance/ct_sites.toml` from a case and
restored it in a `finally`.

The second half — from `whole_image` down — drives the ROW, `python
scripts/ct_gate.py`, as a subprocess with the DISASSEMBLER substituted: the real
image's real objdump output, cut to the functions the site is inlined into,
mutated at the instruction level and fed back. It is what the recorded table in
[`test_the_image_arms_were_driven_by_hand`] could not be, because a case cannot
relink the firmware: those five arms edited Rust and rebuilt by hand, and nothing
re-ran them. These do, every session. Neither half touches the working tree.

Which image the second half reads is whichever `target/` holds — after
`check.sh`'s later rows that is the no-touch build, and after
`cargo build --release -p firmware` it is the default one. No case here reads a
count off it, so both drive these arms; pinning the default image is the row's
job, not this file's.

The fixtures are the shipped comparator's actual lowering, copied out of
`arm-none-eabi-objdump -d -l --inlines` on the release image, with the inline
chain kept intact because attribution is half of what is under test.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ct_gate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The paths are assembled rather than written out: `citation_gate.py` reads
#: `scripts/*.py` for `<file>.rs:<line>` and would resolve a fixture's synthetic
#: path against the tree, where it is not.
MAC = "/x/crates/rsk-crypto/src/mac.rs"
PIN = "/x/crates/rsk-openpgp/src/pin.rs"
CODE = "/x/crates/rsk-oath/src/code.rs"

CHAIN = (
    f"inlined by {MAC}:60 (_ZN10rsk_crypto3mac5ct_eq17h0000000000000000E)\n"
    f"inlined by {PIN}:93 (_ZN11rsk_openpgp3pin9check_pin17h0000000000000001E)"
)

#: The shipped loop, verbatim in shape: two byte loads, a flag-setting XOR, the
#: PUBLIC bound in its wide spelling, a branchless accumulate, the back edge,
#: then the barrier's spill/reload and the terminal reduction to a bool.
CLEAN = f"""{CHAIN}
10000000:\tf818 2001 \tldrb.w\tr2, [r8, r1]
{CHAIN}
10000004:\t5c6b      \tldrb\tr3, [r5, r1]
{CHAIN}
10000006:\t3101      \tadds\tr1, #1
{CHAIN}
10000008:\t4053      \teors\tr3, r2
{CHAIN}
1000000a:\tf1b1 0f20 \tcmp.w\tr1, #32
{CHAIN}
1000000e:\tea40 0003 \torr.w\tr0, r0, r3
{CHAIN}
10000012:\td1f5      \tbne.n\t10000000
{CHAIN}
10000014:\tf88d 0098 \tstrb.w\tr0, [sp, #152]
{CHAIN}
10000018:\tf89d 0098 \tldrb.w\tr0, [sp, #152]
{CHAIN}
1000001c:\t2800      \tcmp\tr0, #0
{CHAIN}
1000001e:\td005      \tbeq.n\t1000002a
"""

#: The defect: the loop branches on the XOR of two loaded bytes instead of on
#: the counter. One line moved, and it is the shape an early exit compiles to.
LEAKY = CLEAN.replace(
    "1000000a:\tf1b1 0f20 \tcmp.w\tr1, #32", "1000000a:\tf1b1 0f20 \tnop.w\tr1, #32"
)

#: The same defect ONE ARITHMETIC STEP further from the load, which is the shape
#: `if diff & 0x80 != 0 { return false; }` really compiles to. A depth-1 rule
#: reports zero here; a review drove that on the real image and it did.
TRANSITIVE = f"""{CHAIN}
10000100:\tf818 2001 \tldrb.w\tr2, [r8, r1]
{CHAIN}
10000104:\t5c6b      \tldrb\tr3, [r5, r1]
{CHAIN}
10000106:\t4053      \teors\tr3, r2
{CHAIN}
10000108:\tb2db      \tsxtb\tr3, r3
{CHAIN}
1000010a:\t2b00      \tcmp\tr3, #0
{CHAIN}
1000010c:\td1f8      \tbne.n\t10000100
"""

#: A PREDICATED compare, which is what `mac.rs`'s public length-equality early
#: return really lowers to. Here its operand comes from a buffer, so the case
#: asserts the taint is FOUND: a rule that refused any run containing an `IT`
#: reported the documented public return as a finding, and one that skipped the
#: predicated `cmpeq` would miss this. Either way the case falls.
PREDICATED = f"""{CHAIN}
100001fc:\tf89d 1010 \tldrb.w\tr1, [r8, #16]
{CHAIN}
10000200:\t2801      \tcmp\tr0, #1
{CHAIN}
10000202:\tbf08      \tit\teq
{CHAIN}
10000204:\t458b      \tcmpeq\tfp, r1
{CHAIN}
10000206:\td01f      \tbeq.n\t10000248
"""

#: The same shape over a value the frame itself stored — a spill, not a buffer.
PREDICATED_SPILL = f"""{CHAIN}
100002fc:\tf88d 1010 \tstrb.w\tr1, [sp, #16]
{CHAIN}
10000300:\tf89d 1010 \tldrb.w\tr1, [sp, #16]
{CHAIN}
10000304:\t2801      \tcmp\tr0, #1
{CHAIN}
10000306:\tbf08      \tit\teq
{CHAIN}
10000308:\t458b      \tcmpeq\tfp, r1
{CHAIN}
1000030a:\td01f      \tbeq.n\t10000348
"""

#: A literal-pool load: the base is `pc`, so it can only be reading a constant.
LITERAL = f"""{CHAIN}
10000300:\t4b02      \tldr\tr3, [pc, #8]
{CHAIN}
10000302:\t2b00      \tcmp\tr3, #0
{CHAIN}
10000304:\td004      \tbeq.n\t10000310
"""

#: A second frame under the SAME outermost one, so the block below is next in
#: address order without being reachable from the comparator's — which is the
#: whole point: the frame check alone does not separate them.
OTHER = f"inlined by {PIN}:97 (_ZN11rsk_openpgp3pin9check_pin17h0000000000000001E)"

#: The comparator's loop, then an unconditional `b`, then a block that branches
#: on a register the comparator happened to leave in `r4`. Copied in shape from
#: `OtpApplet::process` at 0x10036fb0/0x10036fe0/0x10036ff8, where the branch is
#: `apdu.p1 == P1_CHAL_HMAC_SLOT1 || …` — an attacker's own APDU byte. Nothing
#: falls through the `b`, so the load is not a definition this branch can read.
ACROSS_BLOCKS = f"""{CHAIN}
10000400:\t5cc4      \tldrb\tr4, [r0, r3]
{CHAIN}
10000402:\t4066      \teors\tr6, r4
{CHAIN}
10000404:\t2b06      \tcmp\tr3, #6
{CHAIN}
10000406:\td1fb      \tbne.n\t10000400
{OTHER}
10000408:\te707      \tb.n\t10000500
{OTHER}
1000040a:\tf004 0022 \tand.w\tr0, r4, #34
{OTHER}
1000040e:\t2838      \tcmp\tr0, #56
{OTHER}
10000410:\td155      \tbne.n\t10000500
"""

#: The other direction of the same rule, and the one that matters more: a store
#: on the far side of a `b` must NOT excuse the load as a reload of it.
STORE_ACROSS_BLOCKS = f"""{OTHER}
10000600:\tf88d 0098 \tstrb.w\tr0, [sp, #152]
{OTHER}
10000604:\te707      \tb.n\t10000700
{CHAIN}
10000606:\tf89d 0098 \tldrb.w\tr0, [sp, #152]
{CHAIN}
1000060a:\t2800      \tcmp\tr0, #0
{CHAIN}
1000060c:\td005      \tbeq.n\t10000618
"""

#: The oracle a coarse barrier hid, in the shape a real build gave it: two secret
#: bytes loaded into CALLEE-saved registers, a libcall, then the early exit's
#: compare. AAPCS makes `bl` preserve `sl`/`fp`, and the call returns, so the
#: `cmp` is on the only path. Copied from `ct_eq` at 0x1006afa0..0x1006afb8 in a
#: firmware built with `copy_from_slice` inside the accumulate loop.
CALL_KEEPS_CALLEE_SAVED = f"""{CHAIN}
10000800:\tf816 ab01 \tldrb.w\tsl, [r6], #1
{CHAIN}
10000804:\tf814 bb01 \tldrb.w\tfp, [r4], #1
{CHAIN}
10000808:\tf04b fcfb \tbl\t100b69a8
{CHAIN}
1000080c:\t45d3      \tcmp\tfp, sl
{CHAIN}
1000080e:\td10b      \tbne.n\t10000820
"""

#: The same shape over CALLER-saved registers, which the call may have destroyed.
#: Without it `clobbers` could return False for everything and the case above
#: would still pass — a guard nothing exercises.
CALL_CLOBBERS_CALLER_SAVED = f"""{CHAIN}
10000900:\tf816 0b01 \tldrb.w\tr0, [r6], #1
{CHAIN}
10000904:\tf814 1b01 \tldrb.w\tr1, [r4], #1
{CHAIN}
10000908:\tf04b fcfb \tbl\t100b69a8
{CHAIN}
1000090c:\t4288      \tcmp\tr1, r0
{CHAIN}
1000090e:\td10b      \tbne.n\t10000920
"""

#: `cbz` is CONDITIONAL: the next instruction is on the path, so a walk that
#: stops there loses a load it should have reached.
CBZ_IS_NOT_A_STOP = f"""{CHAIN}
10000a00:\tf816 ab01 \tldrb.w\tsl, [r6], #1
{CHAIN}
10000a04:\tb11a      \tcbz\tr2, 10000a10
{CHAIN}
10000a06:\tf1ba 0f00 \tcmp.w\tsl, #0
{CHAIN}
10000a0a:\td10b      \tbne.n\t10000a20
"""

#: A clobber of the flag-setter's operand, SCHEDULED BETWEEN the compare and the
#: branch, over an operand that genuinely came from a buffer. Thumb is scheduled,
#: so this shape is ordinary; a trace that starts at the BRANCH answers with the
#: `mov` and goes blind to the load the compare actually read. The clobber is
#: `mov.w` and not `movs` on purpose — an `s` form would set the flags itself and
#: become the governing instruction, and the case would stop being about the walk.
CLOBBERED_OPERAND = f"""{CHAIN}
10000b00:\tf810 3003 \tldrb.w\tr3, [r0, r3]
{CHAIN}
10000b04:\t2b00      \tcmp\tr3, #0
{CHAIN}
10000b06:\tf04f 0305 \tmov.w\tr3, #5
{CHAIN}
10000b0a:\td10b      \tbne.n\t10000b20
"""

#: The same scheduling, the other way round: here the CLOBBER is what reads the
#: buffer and the compare's real operand does not. Copied instruction for
#: instruction from `OtpApplet::process` at 0x10036fee..0x10036ff8 on the shipped
#: image, where `cmp r0, #56` reads `orr.w r0, sl, #8` and the `and.w r0, r4, #34`
#: after it feeds the NEXT compare. Traced from the branch this invents a finding.
CLOBBER_IS_NOT_THE_OPERAND = f"""{CHAIN}
10000c00:\t5cc4      \tldrb\tr4, [r0, r3]
{CHAIN}
10000c02:\tf04a 0008 \torr.w\tr0, sl, #8
{CHAIN}
10000c06:\t2838      \tcmp\tr0, #56
{CHAIN}
10000c08:\tf004 0022 \tand.w\tr0, r4, #34
{CHAIN}
10000c0c:\td155      \tbne.n\t10000c60
"""

#: A spill through the FRAME register beside one through `sp`, which is the only
#: shape that tells the row's two reload counts apart: both are reloads, one is
#: what the summary calls "excused through a base other than `sp`". Copied from
#: the `strb.w r0, [r7, #-29]` / `ldrb.w r0, [r7, #-29]` pair the `black_box`
#: barrier compiles to in the copies that do not spill to the stack.
TWO_SPILLS = f"""{CHAIN}
10000d00:\tf818 2001 \tldrb.w\tr2, [r8, r1]
{CHAIN}
10000d04:\t5c6b      \tldrb\tr3, [r5, r1]
{CHAIN}
10000d06:\t4053      \teors\tr3, r2
{CHAIN}
10000d08:\tf88d 0098 \tstrb.w\tr0, [sp, #152]
{CHAIN}
10000d0c:\tf89d 0098 \tldrb.w\tr0, [sp, #152]
{CHAIN}
10000d10:\tf807 0c1d \tstrb.w\tr0, [r7, #-29]
{CHAIN}
10000d14:\tf817 0c1d \tldrb.w\tr0, [r7, #-29]
{CHAIN}
10000d18:\t2800      \tcmp\tr0, #0
{CHAIN}
10000d1a:\td005      \tbeq.n\t10000d30
"""

#: One instruction the site's chain does NOT name, so two recordings of the loop
#: sit in two attributed runs rather than one — which is what "a copy fewer"
#: moves, and the quantity a literal floor was taken as a percentage of.
GAP = f"""{OTHER}
100000f0:\te7ff      \tb.n\t10000100
"""

#: A SECOND registered site, so the row can be asked whether it decides per site
#: or on a total. Its excuse covers two of its three loads — two spill/reload
#: pairs and one genuine buffer read — while `CLEAN`'s covers one of three, so
#: summed they cancel at 3 against 3 and only the per-site question sees it.
OATH = f"inlined by {CODE}:41 (_ZN8rsk_oath4code7ct_eq_b17h0000000000000002E)"
TWO_SITES = f"""{CLEAN}{OATH}
10001000:\tf88d 0090 \tstrb.w\tr0, [sp, #144]
{OATH}
10001004:\tf89d 0090 \tldrb.w\tr0, [sp, #144]
{OATH}
10001008:\tf88d 1094 \tstrb.w\tr1, [sp, #148]
{OATH}
1000100c:\tf89d 1094 \tldrb.w\tr1, [sp, #148]
{OATH}
10001010:\t5c8a      \tldrb\tr2, [r1, r2]
{OATH}
10001012:\t2a00      \tcmp\tr2, #0
{OATH}
10001014:\td005      \tbeq.n\t10001020
"""

SITE = {"CT-CMP-001": {"symbol": "rsk_crypto::mac::ct_eq", "class": "comparator"}}
NO_FLOORS = {
    "run_floor": 0,
    "branch_floor": 0,
    "reasoned_floor": 0,
}


def observed(text):
    return ct_gate.observe(ROOT, SITE, text.splitlines())["CT-CMP-001"]


def shifted(text, delta):
    """The same recorded run at another address, so two copies can coexist."""
    return re.sub(
        r"^([0-9a-f]{8}):",
        lambda m: f"{int(m.group(1), 16) + delta:08x}:",
        text,
        flags=re.M,
    )


def summary_of(text, page=None):
    """The row's own summary line over a recorded disassembly."""
    _, summary = ct_gate.audit(ROOT, lines=text.splitlines(), page=page, **NO_FLOORS)
    return summary


def shipped_registry() -> str:
    return (ROOT / ct_gate.REGISTRY).read_text(encoding="utf-8")


def test_the_shipped_loop_is_clean():
    """The control. Without it every case below could pass over a dead parser."""
    violations, runs, branches, callers, reasoned = observed(CLEAN)
    assert (runs, branches, reasoned) == (1, 2, 2), (runs, branches, reasoned)
    assert violations == []
    assert callers == {"rsk_openpgp::pin::check_pin"}


def test_a_branch_on_the_loaded_bytes_is_caught():
    violations, _, _, _, _ = observed(LEAKY)
    assert len(violations) == 1, violations
    addr, mnemonic, source, load = violations[0]
    assert (addr, mnemonic) == (0x10000012, "bne")
    assert source.startswith("eors")
    assert "ldrb" in load


def test_a_taint_that_passes_through_arithmetic_is_still_a_taint():
    """The rule this shipped wrong. Depth-1 — the flag operand's own definition
    must BE a load — is defeated by one `sxtb`, and a review drove exactly that
    on the real image: a genuine early exit, reported as zero."""
    violations, _, _, _, _ = observed(TRANSITIVE)
    assert len(violations) == 1, violations
    assert violations[0][1] == "bne"
    assert "ldrb" in violations[0][3]


def test_the_depth_is_finite_and_stated():
    assert ct_gate.TAINT_DEPTH == 4
    assert "sxtb" in ct_gate.TRANSPARENT and "eors" in ct_gate.TRANSPARENT
    assert "bl" not in ct_gate.TRANSPARENT


def test_a_predicated_compare_is_read_as_a_flag_setter():
    """Predication read as predication, in both directions. A rule that refused
    any run containing an `IT` reported `mac.rs`'s documented public early return
    as a finding; a rule that skipped the predicated `cmpeq` would miss the taint
    the same instruction carries."""
    violations, runs, branches, _, reasoned = observed(PREDICATED)
    assert (runs, branches, reasoned) == (1, 1, 1)
    assert len(violations) == 1, violations
    assert violations[0][2].startswith("cmpeq")


def test_a_predicated_compare_of_a_spill_is_not_a_finding():
    violations, _, branches, _, reasoned = observed(PREDICATED_SPILL)
    assert (branches, reasoned) == (1, 1)
    assert violations == []


def test_a_reload_of_this_frames_own_store_is_not_a_buffer_read():
    """`black_box`'s spill/reload feeds the terminal `cmp r0, #0`. The first rule
    here whitelisted `sp` and missed the copies that spill through the frame
    register `r7` instead — the shipped comparator reported itself.

    How many, measured 2026-09-01 over the default release image rather than
    asserted: 14 of the 39 attributed runs excuse a reload through `r7`, and the
    `sp`-whitelist rule reports 9 of them, because a load is only reported once a
    branch traces to it. The docstring of `ct_gate` said eight of both for its
    whole life and a later reading said ten; neither was ever read off an ELF,
    and the two counts were never one number. The 14 is derived by the row now
    (`excused_loads`), so this case pins the RULE and the image pins the count.
    """
    tail = CLEAN[CLEAN.index("10000014") - len(CHAIN) - 1 :]
    violations, _, branches, _, _ = observed(tail)
    assert branches == 1
    assert violations == []


def test_an_excuse_that_covers_every_load_is_a_finding(monkeypatch):
    """The hole the excuse ratio closes, driven in both directions.

    `reload_of_a_store` is the only rule here that EXCUSES a load, and nothing
    else this row counts asks it — runs, branches and traced come out identical
    whatever it answers. So a version that says True too often takes the row's
    own mutant with it and leaves every other number in place: a check that
    cannot fail, at exit 0. Measured the same way over the shipped image, stubbed
    to True it reports 0 secret-dependent branches over an unchanged 39 / 25 / 22
    with all three floors satisfied.

    No floor is patched here and there is none to patch: the rule is that the
    excuse may not cover more of a site's loads than it leaves exposed, so the
    fixture arms it as it stands (2 exposed, 1 excused) and the stub inverts it
    (0 exposed, 3 excused).
    """
    word = "visible to the taint"

    before = observed(LEAKY)
    findings, _ = ct_gate.audit(ROOT, lines=LEAKY.splitlines(), **NO_FLOORS)
    assert len(before[0]) == 1, before[0]
    assert not any(word in f for f in findings), findings

    monkeypatch.setattr(ct_gate, "reload_of_a_store", lambda stream, index: True)
    after = observed(LEAKY)
    findings, _ = ct_gate.audit(ROOT, lines=LEAKY.splitlines(), **NO_FLOORS)
    assert after[0] == [], after[0]  # the mutant this row exists to catch, gone
    assert after[1:] == before[1:], (before, after)  # and nothing else moved
    assert any(word in f for f in findings), findings


def test_the_excuse_ratio_does_not_move_with_the_copy_count():
    """The false alarm a LITERAL count carried, and the reason this is a ratio.

    Measured on the default release image: 27 of the 39 attributed runs
    contribute exactly 2 exposed loads each and the other 12 contribute none
    (histogram `{0: 12, 2: 27}`), so `exposed` has a GAIN of 2 per inlined copy.
    The literal that shipped here was 43 — "the same ~20% under the measurement"
    as the run and branch floors — and 20% of a quantity with gain 2 is FIVE
    copies. Driven over the image by dropping the site's attribution from k of
    the copies that carry an operand pair: k=5 answers 44 exposed over 34 runs
    and passes, k=6 answers 42 over 33 — RED on the literal while `RUN_FLOOR`
    still has three runs of slack. The band k=6..9 is defect-free code motion
    reddening the row. The same walk under the ratio is green to k=22 with the
    copies dropped in the harshest order — carriers first — and first red at
    k=23, well past the k=10 where `RUN_FLOOR` asks for the walk to be
    re-measured. Dropped in the other order it is green at every k driven.

    Here the invariance itself is pinned, which is the property the image
    measurement rests on: the same loop inlined twice and inlined once answer
    the same verdict while both counts double.
    """
    symbol = SITE["CT-CMP-001"]["symbol"]
    doubled = CLEAN + GAP + shifted(CLEAN, 0x100)
    assert observed(CLEAN)[1] == 1
    assert observed(doubled)[1] == 2, observed(doubled)[1]
    one = ct_gate.excused_loads(list(ct_gate.instructions(CLEAN.splitlines())), symbol)
    two = ct_gate.excused_loads(
        list(ct_gate.instructions(doubled.splitlines())), symbol
    )
    assert one == (0, 2, 1), one
    assert two == (0, 4, 2), two
    for lines in (CLEAN, doubled):
        findings, _ = ct_gate.audit(ROOT, lines=lines.splitlines(), **NO_FLOORS)
        assert not any("visible to the taint" in f for f in findings), findings


def test_the_excuse_ratio_is_asked_per_site_and_not_of_the_total(monkeypatch):
    """The dilution a summed count carries, and the reason it is asked per site.

    `docs/ct-audit.md` speaks of five hand-rolled comparators consolidated onto
    one, so a second registered site is a thing this file has to survive, and a
    TOTAL is the shape that stops meaning anything the moment there are two.
    Measured on the image: registering
    `rsk_crypto::mlkem::mlkem768_encapsulate` beside the comparator takes the
    total from 54 exposed to 367, so the comparator's whole exposure could go to
    zero under a literal floor of 43 that never moved.

    Driven here through the row: the second site's excuse covers 2 of its 3
    loads and the first site's covers 1 of 3, so the row must name the second
    and only the second. Summed the two cancel — 3 excused against 3 exposed —
    and a rule asked of the totals answers green over a site it has blinded.
    """
    sites = dict(SITE)
    sites["CT-CMP-002"] = {"symbol": "rsk_oath::code::ct_eq_b", "class": "comparator"}
    _, shipped_callers = ct_gate.registry(ROOT, [])
    monkeypatch.setattr(
        ct_gate, "registry", lambda root, findings, text=None: (sites, shipped_callers)
    )
    findings, summary = ct_gate.audit(ROOT, lines=TWO_SITES.splitlines(), **NO_FLOORS)
    named = [f for f in findings if "visible to the taint" in f]
    assert len(named) == 1, named
    assert named[0].startswith("CT-CMP-002: the reload excuse covers 2 of"), named[0]
    # The totals a summed rule would have read: 3 exposed against 3 excused.
    assert "3 load(s) still exposed to the taint" in summary, summary


def test_a_literal_pool_load_is_not_a_buffer_read():
    violations, _, branches, _, reasoned = observed(LITERAL)
    assert (branches, reasoned) == (1, 1)
    assert violations == []


def test_a_definition_on_the_far_side_of_a_barrier_is_not_a_definition():
    """The false positive that reddened the row, in the shape the image had it.

    A backward walk over the linear address order is a question about control
    flow, and past an unconditional `b` it answers with a block that has no edge
    to the use. The verdict then follows the block layout: nothing about the
    comparator or its callers changed, an unrelated OTP commit moved
    `cmd_configure`'s inlined copy near two PUBLIC branches in `cmd_calculate`,
    and both were reported as reading its operand load.

    Driven: with `last_definition` back to stepping OVER a barrier, this case
    falls on `violations == []` reporting `(0x10000410, 'bne', 'cmp r0, #56',
    'ldrb r4, [r0, r3]')` — the image's own finding, in the direction that
    invents one rather than the inverse that hides one.
    """
    violations, _, branches, _, _ = observed(ACROSS_BLOCKS)
    assert branches == 1, branches  # only the loop's back edge is inside the run
    assert violations == []


def test_a_call_does_not_hide_a_load_in_a_callee_saved_register():
    """The narrowing an independent review caught, and the reason the stop is a
    REGISTER question. Bundling every transfer into one barrier took a genuine
    oracle out of the row: measured on a real build, the rule before reported it
    and the bundled rule reported 0."""
    violations, _, _, _, _ = observed(CALL_KEEPS_CALLEE_SAVED)
    assert len(violations) == 1, violations
    assert violations[0][1] == "bne"
    assert violations[0][3].startswith("ldrb"), violations[0][3]


def test_a_call_does_hide_a_load_in_a_caller_saved_register():
    """The other half, so `clobbers` is a rule and not a constant: AAPCS lets the
    callee destroy r0-r3/ip/lr, so a definition before the call is not what the
    compare read."""
    violations, _, _, _, _ = observed(CALL_CLOBBERS_CALLER_SAVED)
    assert violations == [], violations


def test_a_conditional_branch_is_not_a_stop():
    """`cbz` falls through, so the walk must cross it."""
    violations, _, _, _, _ = observed(CBZ_IS_NOT_A_STOP)
    assert len(violations) == 1, violations
    assert violations[0][3].startswith("ldrb"), violations[0][3]


def test_the_operand_is_traced_from_the_flag_setter_and_not_the_branch():
    """The direction that HIDES a finding, and the reason the walk moved.

    `cmp r3, #0` reads a byte the comparator loaded, and the scheduler puts a
    `mov.w r3, #5` between it and the `bne`. Walking back from the BRANCH the
    rule met the `mov` first, traced `#5` to nothing and reported clean — the
    compare's real operand never asked about at all. That is the shape a live
    early exit has, so the miss is silent.

    Driven: with `governing`'s position dropped and the walk back on the branch
    index, this case falls on `len(violations) == 1` seeing `[]` — the gate
    SHOULD HAVE REFUSED this image and did not. The inverse defect would fall the
    other way, on a finding invented over a clean image, and
    [`test_the_clobber_after_the_compare_is_not_the_operand`] below is the case
    that falls THAT way; neither passes a rule that always answers the same.
    """
    violations, runs, branches, _, reasoned = observed(CLOBBERED_OPERAND)
    assert (runs, branches, reasoned) == (1, 1, 1), (runs, branches, reasoned)
    assert len(violations) == 1, violations
    addr, mnemonic, source, load = violations[0]
    assert (addr, mnemonic) == (0x10000B0A, "bne")
    assert source.startswith("cmp r3"), source
    assert load.startswith("ldrb "), load


def test_the_clobber_after_the_compare_is_not_the_operand():
    """The control, and the other direction of the same walk: a clobber that
    reads a buffer does not make the branch secret when the compare did not.

    Green before this change and after it — the rule must not have bought its
    reach by calling everything a taint. Driven with the walk back on the branch
    index it falls on `violations == []` reporting `(0x10000c0c, 'bne', 'cmp r0,
    #56', 'ldrb r4, [r0, r3]')`, which is the image's own `0x10036ff8` read
    wrongly."""
    violations, runs, branches, _, reasoned = observed(CLOBBER_IS_NOT_THE_OPERAND)
    assert (runs, branches, reasoned) == (1, 1, 1), (runs, branches, reasoned)
    assert violations == [], violations


def test_a_store_on_the_far_side_of_a_barrier_does_not_excuse_the_load():
    """Same rule, and this is the direction that could hide a finding: a match
    here EXCUSES the load, so a store the flow cannot have executed would excuse
    a genuine buffer read.

    Driven: with the barrier stop removed from `reload_of_a_store`, this case
    falls on `0 == 1` — the load excused, the finding gone."""
    violations, _, branches, _, _ = observed(STORE_ACROSS_BLOCKS)
    assert branches == 1
    assert len(violations) == 1, violations
    assert violations[0][3].startswith("ldrb ")


def test_the_summary_separates_a_frame_spill_from_a_stack_spill():
    """The row's HEADLINE quantity, and until this case nothing held it.

    "fourteen reloads excused through a base other than `sp`" is the number the
    commit that derived it is named after, and it was held by prose alone: drop
    the `!= "sp"` discriminator from `excused_loads` and the row prints 28 —
    every reload, the two questions fused again — with all 31 cases at exit 0.

    Both spills are in the fixture because one is not enough: a rule that
    answered "any reload" and a rule that answered "a reload through the frame
    register" agree on a fixture that has only the second. Driven with the
    discriminator dropped, this case falls on the `1 reload(s)` assertion seeing
    `2` — a stack spill counted as a frame-register spill.
    """
    summary = summary_of(TWO_SPILLS)
    assert ", 2 load(s) still exposed to the taint" in summary, summary
    assert "and 1 reload(s) excused through a base other than `sp`" in summary, summary


def test_a_literal_pool_load_counts_as_neither_half_of_the_split():
    """The `pc` skip, which today's image cannot reach — so it is pinned here.

    Measured on the default release image: 82 loads sit inside the site's runs
    and NONE of them is `pc`-based, so the clause decides nothing there and an
    assumption nothing branches on is a comment with a type. `buffer_load`
    refuses a literal-pool load before the excuse is ever put, so counting it
    either way would credit the excuse for a load it never decided.

    Driven with the `pc` skip deleted from `excused_loads`, this case falls on
    the `0 load(s) still exposed` assertion seeing `1` — a constant counted as a
    buffer read the taint had left alone.
    """
    summary = summary_of(LITERAL)
    assert ", 0 load(s) still exposed to the taint" in summary, summary
    assert "and 0 reload(s) excused through a base other than `sp`" in summary, summary


def test_the_row_diffs_the_page_it_was_handed_and_not_the_one_on_disk():
    """The desync no other case can see: `scope_finding` reads the handed-in
    page while the region diff reads the tree, and nothing held the two together.

    Driven with `render`'s `text` argument ignored — the file read
    unconditionally — this case falls on `any("cannot be generated" ...)` seeing
    no such finding: a page with no region markers at all passed the row,
    because the row was diffing a different document from the one it judged.
    """
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    head = page.index(f"<!-- {ct_gate.REGION}:start -->")
    tail = page.index(f"<!-- {ct_gate.REGION}:end -->")
    regionless = page[:head] + page[tail:].split("\n", 1)[1]
    assert f"{ct_gate.REGION}:start" not in regionless
    findings, _ = ct_gate.audit(
        ROOT, lines=CLEAN.splitlines(), page=regionless, **NO_FLOORS
    )
    assert any("cannot be generated" in f for f in findings), findings


def test_the_width_suffix_is_stripped_before_the_flag_set_is_consulted():
    """The defect this gate shipped with for one run: `cmp.w` was not in the set,
    the walk-back skipped the public bound and landed on the secret `eors`, and
    the shipped comparator was reported as secret-dependent — the inverse of the
    truth, at exit 1."""
    assert ct_gate.flag_setter("cmp") == ("cmp", False)
    assert ct_gate.flag_setter("cmpeq") == ("cmp", True)
    assert ct_gate.flag_setter("nop") is None
    wide = "10000000:\tf1b1 0f20 \tcmp.w\tr1, #32"
    assert list(ct_gate.instructions([wide]))[0][1] == "cmp"


def test_a_site_that_resolves_to_nothing_is_a_finding():
    """The vacuity control: a stripped image, or a symbol that stopped being
    inlined, makes every other rule pass over zero instructions."""
    findings, _ = ct_gate.audit(
        ROOT, lines=["10000000:\t4770      \tbx\tlr"], **NO_FLOORS
    )
    assert any("is in no inline chain" in f for f in findings), findings


@pytest.mark.parametrize(
    "floors,word",
    [
        ({"run_floor": 10_000}, "attributed run"),
        ({"branch_floor": 10_000}, "conditional branch"),
        ({"reasoned_floor": 10_000}, "traced to a definition"),
    ],
)
def test_each_floor_reports_its_own_shortfall(floors, word):
    """Three floors and three messages: a branch the rule WALKED PAST is not one
    it decided, and before the taint became transitive most of the shipped
    image's in-site branches were excused before the question was put.

    Three and not four: the excuse rule is a RATIO and has no floor to raise, so
    it is driven by widening the excuse instead — see
    [`test_an_excuse_that_covers_every_load_is_a_finding`]. A fourth entry sat
    here over a literal that no longer exists."""
    kwargs = dict(NO_FLOORS)
    kwargs.update(floors)
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines(), **kwargs)
    assert any("under the measured" in f and word in f for f in findings), findings


def test_the_shipped_floors_are_parameters_and_not_globals():
    """A case cannot patch them down: the defaults bind at `def` time, so the
    values the row runs with are the ones in the module. Pinned, so a floor moves
    in a diff that says why — the reasoned one went 15 -> 20 when a review
    measured that 15 against 24 let nine branches go silently unasked, and STAYED
    at 20 when the measurement itself fell to 22: a floor walked down after every
    narrowing follows the defect it is there to catch.

    Three, not four. `EXPOSED_FLOOR = 43` stood here and is gone: a literal on a
    quantity with a gain of 2 per inlined copy reddens on defect-free code
    motion, and summed across sites it stops being about any of them."""
    assert not hasattr(ct_gate, "EXPOSED_FLOOR")
    assert (
        ct_gate.RUN_FLOOR,
        ct_gate.BRANCH_FLOOR,
        ct_gate.REASONED_FLOOR,
    ) == (30, 20, 20)


def test_an_unregistered_inliner_is_a_finding():
    """The caller set is held BOTH ways; this is the direction that catches a new
    surface reaching the comparator with nobody saying what it is."""
    # The length prefix is part of the name: `9check_pin` -> `10check_pinX`,
    # or the demangler reads nine characters and the rename vanishes.
    stranger = CLEAN.replace("3pin9check_pin17h", "3pin10check_pinX17h")
    findings, _ = ct_gate.audit(ROOT, lines=stranger.splitlines(), **NO_FLOORS)
    assert any("says which protocol surface" in f for f in findings), findings


def test_a_surface_that_stopped_routing_through_it_is_a_finding():
    """The direction that catches the defect `docs/ct-audit.md` records twice: a
    compare that BYPASSED the comparator. The registry entry survives; the ELF
    stops naming it. Keyed on the OUTERMOST frame this could not see a bypass
    added beside a surviving call in the same function — the review drove that on
    `cmd_update` and the row stayed green."""
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines(), **NO_FLOORS)
    stale = [f for f in findings if "inlines no site in the image" in f]
    assert len(stale) == 28, stale


#: The scope clause as it read before `a4b53c2` refuted it, and the clause that
#: replaced it. Handed to `audit` as text, never written: the page is tracked,
#: and an interrupt mid-case would leave it modified.
REFUTED_SCOPE = "hand-written `rsk-rsa` keygen primitives."
SHIPPED_SCOPE = "hand-written `rsk-rsa` modexp, sieve and primality primitives"


def refuted_page(word: str = "keygen") -> str:
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    assert SHIPPED_SCOPE in page, "the scope clause moved; re-read the page"
    return page.replace(
        SHIPPED_SCOPE, f"hand-written `rsk-rsa` {word} primitives.", 1
    )


#: Every walk-past of the WORD rule that shipped here, each one measured against
#: the shipped page with `scope_finding` answering None. The first two are the
#: ones that settle the design and neither is an attack: a synonym restores the
#: refuted scope in plain English, and a blank line after "CTAP2)" is an editor
#: breaking a ten-line paragraph in two. The rest are spellings the `re.I`-less
#: `\bkeygen\b` could not see, plus two structural moves — the clause into a
#: bullet, and a decoy paragraph carrying the anchor, which `next(...)` reached
#: first. `key generation` is listed twice on purpose: once as the plain
#: synonym, once with the whole tail carried away, which is the shape a synonym
#: takes when the editor also tightens the sentence.
SCOPE_BYPASSES = {
    "synonym": lambda page: refuted_page("key generation"),
    "re-wrapped paragraph": lambda page: refuted_page().replace(
        "CTAP2): ", "CTAP2).\n\nThe verifiers covered: ", 1
    ),
    "Keygen": lambda page: refuted_page("Keygen"),
    "KEYGEN": lambda page: refuted_page("KEYGEN"),
    "KeyGen": lambda page: refuted_page("KeyGen"),
    "keyGen": lambda page: refuted_page("keyGen"),
    "key-generation": lambda page: refuted_page("key-generation"),
    "keygens": lambda page: refuted_page("keygens"),
    "key_gen": lambda page: refuted_page("key_gen"),
    "zero-width space": lambda page: refuted_page("key\u200bgen"),
    "line break": lambda page: refuted_page("key\ngen"),
    "moved into a bullet": lambda page: page.replace(
        SHIPPED_SCOPE + " — the modexp on\nboth of its callers, the prime search"
        " and the `rsa_private_exp_crt` that PIV\nGENERAL AUTHENTICATE and"
        " OpenPGP PSO:CDS / INTERNAL AUTHENTICATE / DECIPHER\nreach over USB"
        " against a long-lived key.",
        "the primitives listed below.\n\n- the hand-written `rsk-rsa` keygen"
        " primitives.",
        1,
    ),
    "decoy anchor": lambda page: refuted_page().replace(
        "# Constant-time / timing side-channel audit",
        "<!-- The hand-written `rsk-rsa` modexp and `rsa_private_exp_crt` are"
        " described below. -->\n\n# Constant-time / timing side-channel audit",
        1,
    ),
    "modexp renamed": lambda page: page.replace(
        SHIPPED_SCOPE + " — the modexp on\nboth",
        "hand-written `rsk-rsa` exponentiation, sieve and primality primitives —"
        " the exponentiation on\nboth",
        1,
    ),
    "CRT caller dropped": lambda page: page.replace(
        " — the modexp on\nboth of its callers, the prime search and the"
        " `rsa_private_exp_crt` that PIV\nGENERAL AUTHENTICATE and OpenPGP"
        " PSO:CDS / INTERNAL AUTHENTICATE / DECIPHER\nreach over USB against a"
        " long-lived key.",
        " — the modexp as the prime search reaches it.",
        1,
    ),
    "scoped by omission": lambda page: page.replace(
        SHIPPED_SCOPE + " — the modexp on\nboth of its callers, the prime search"
        " and the `rsa_private_exp_crt` that PIV\nGENERAL AUTHENTICATE and"
        " OpenPGP PSO:CDS / INTERNAL AUTHENTICATE / DECIPHER\nreach over USB"
        " against a long-lived key.",
        "hand-written `rsk-rsa` primitives that run while a key is being made.",
        1,
    ),
}


def test_the_scope_paragraph_may_not_rescope_the_modexp_to_keygen():
    """Both directions of the only prose rule here.

    The shipped sentence passes and the refuted one does not, so the rule is not
    a constant. It cannot tell a refutation from a claim — the page's own
    residuals say "not keygen-only", and ten hits of the refuted pattern sit
    elsewhere on the shipped page — which is why it reads the anchored paragraph
    alone, and why the case asserts the shipped page is clean rather than only
    that the mutant reddens.
    """
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    assert ct_gate.scope_finding(page) is None
    problem = ct_gate.scope_finding(refuted_page())
    assert problem and "as keygen" in problem, problem


@pytest.mark.parametrize("name", sorted(SCOPE_BYPASSES))
def test_the_scope_rule_is_not_walked_past(name):
    """The thirteen ways the WORD rule was walked past, plus the one it could
    never have seen — all thirteen measured green against it at exit 0.

    The rule they refuted anchored on "Its scope is", five lines above the clause
    it is about, and refused `\\bkeygen\\b`. Anchoring on the CLAUSE is what
    answers the two structural ones: a re-wrap or a move into a bullet carries
    the anchor along with the words, so the rule follows instead of falling off.
    Requiring the paragraph to NAME `modexp` and `rsa_private_exp_crt` is what
    answers "scoped by omission", where the word never appears at all.

    Driven per clause — each falls on its own row of this table, in the
    direction that ACCEPTS a refuted scope: without `re.I` the four
    capitalisations pass, without the separator class the hyphen, underscore,
    zero-width space and line break pass, without the trailing-boundary removal
    the plural passes, without `SCOPE_REQUIRED` "scoped by omission" and the
    bullet pass, and without the more-than-one-anchor rule the decoy passes.
    """
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    mutated = SCOPE_BYPASSES[name](page)
    assert mutated != page, name
    assert ct_gate.scope_finding(mutated) is not None, name


def test_the_row_itself_refuses_the_refuted_scope_sentence():
    """Through `audit`, not through the helper: a guard whose wiring nothing
    drives can be deleted with the suite still green."""
    findings, _ = ct_gate.audit(
        ROOT, lines=CLEAN.splitlines(), page=refuted_page(), **NO_FLOORS
    )
    assert any("as keygen" in f for f in findings), findings


def test_the_row_itself_refuses_a_re_wrapped_scope_paragraph():
    """The bypass that is not an attack, driven through the row rather than the
    helper: an editor breaking a ten-line paragraph in two took the whole rule
    off, and the exact refuted string then passed at EXIT=0."""
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    findings, _ = ct_gate.audit(
        ROOT,
        lines=CLEAN.splitlines(),
        page=SCOPE_BYPASSES["re-wrapped paragraph"](page),
        **NO_FLOORS,
    )
    assert any("as keygen" in f for f in findings), findings


def test_a_scope_paragraph_that_vanished_is_a_finding():
    """The deletion arm the rule needs to survive its own next edit: keyed on a
    string the page can simply drop, it would otherwise be silenced for free."""
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    problem = ct_gate.scope_finding(
        page.replace(ct_gate.SCOPE_ANCHOR, "hand-rolled `rsk-rsa`", 1)
    )
    assert problem and "no paragraph says" in problem, problem


def test_a_second_paragraph_carrying_the_anchor_is_itself_a_finding():
    """The decoy, in its own case because it is the one thing the positive
    requirements cannot answer: `scope_finding` reads ONE paragraph, so any
    earlier one carrying the anchor shields the real clause whatever the real
    clause says. Making the ambiguity the finding is what closes it.

    Driven with the count check deleted, this case falls on `problem is not
    None` seeing None — the decoy accepted, and with it the refuted scope it was
    hiding."""
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    problem = ct_gate.scope_finding(SCOPE_BYPASSES["decoy anchor"](page))
    assert problem and "paragraphs say" in problem, problem


def test_the_page_region_is_diffed_against_the_generator():
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines(), **NO_FLOORS)
    assert any("is not what the generator writes" in f for f in findings), findings


def test_the_registry_refuses_a_key_it_does_not_read():
    findings: list[str] = []
    patched = shipped_registry().replace(
        'class = "comparator"', 'class = "comparator"\nnote = "x"', 1
    )
    ct_gate.registry(ROOT, findings, text=patched)
    assert any("is not a field this registry reads" in f for f in findings), findings
    assert (ROOT / ct_gate.REGISTRY).read_text(encoding="utf-8") == shipped_registry()


def test_the_image_arms_were_driven_by_hand():
    """Recorded, because a case cannot relink the firmware.

    History now, and no longer the only evidence that a defect reaches an exit
    code: the arms below this one inject an early exit into the real image's
    disassembly and drive the real entry point over it on every run. What is kept
    here is what they cannot re-derive — the arms whose mutant was a SOURCE edit,
    and the four refutations that shaped the rule.

    Driven through the row's own command (`python scripts/ct_gate.py`) after
    `cargo build --release -p firmware`:

    | arm | attributed runs | branches | traced | secret-dependent | row |
    |---|---|---|---|---|---|
    | shipped | 39 | 25 | 22 | 0 | EXIT=0 |
    | early exit in `ct_eq` (`if diff != 0`) | 59 | 27 | 24 | 28 | EXIT=1 |
    | early exit on ONE BIT (`if diff & 0x80 != 0`) | 58 | 27 | 24 | 28 | EXIT=1 |
    | `cmd_update` back to a slice `!=`, `cmd_configure` untouched | 38 | 24 | 21 | 0 | EXIT=1, `cmd_update` inlines no site |
    | early exit with a `copy_from_slice` before it | 3 | 3 | — | 1 | EXIT=1, `0x1006afb8` |

    The last two are the arms an independent review used to refute the first
    version of this gate: at depth-1 taint the bit test reported 0 and passed,
    and keyed on the outermost frame the bypass beside a surviving call reported
    0 and passed. Both now redden, and the fourth reddens with the right message
    rather than on a floor.

    The fifth arm is the one an independent review built, and it is why the stop
    is a REGISTER question. Its `copy_from_slice` puts `bl __aeabi_memset4`
    between the two secret loads and the early exit's `cmp fp, sl`; `fp`/`sl` are
    callee-saved, so the call preserves them and the fall-through is the only
    path. A stop at every transfer reported 0 over it while the rule before this
    one reported 1 — measured on a real build, and the four arms above all sit
    BEFORE any transfer, so not one of them could have caught that.

    Re-driven when the walks were confined to the path, because a rule that stops
    earlier is exactly the change that could blind the row to its own mutant: all
    four arms answer as before, and the shipped one is 0 over 24 branches traced
    to a definition (floor 20). The counts moved from the
    previous recording because the IMAGE moved — two OTP commits — not the rule;
    that is also what surfaced the defect, `ct_eq`'s inlined copy landing within
    64 instructions of two public branches in `cmd_calculate` across two `b.n`
    and a `bl`.

    Re-driven again when the trace moved from the branch to the flag-setter, and
    the four rows above are that re-drive's own numbers. Both moves are the
    stricter direction: the shipped arm traces 22 and not 24, because a `subs r5,
    #1` is no longer credited as the definition of its own operand, and BOTH
    early-exit arms report 28 secret-dependent branches and not 27. The extra one
    is real — `0x10036ebe`, `bne` on `cmp r4, r3` over `ldrb r4, [r1, r2]` — and
    the shipped rule missed it because the walk from the BRANCH met the `b.n` at
    `0x10036ebc` and died one instruction short of the compare whose flags that
    branch reads. No arm lost a finding.

    The fifth row is the exception and is NOT this revision's measurement: its
    source edit was never recorded, so what ran here is a reconstruction —
    `copy_from_slice` into a scratch array ahead of the early exit. It answers 1
    secret-dependent at EXIT=1 like the original, but over 1 run and 2 branches
    rather than 3 and 3, so the row keeps the original's counts and its traced
    cell stays blank rather than borrowing a different mutant's number.

    `crates/rsk-crypto/src/mac.rs` and `crates/rsk-otp/src/lib.rs` restored
    byte-identical (sha256 compared) and the control re-run green after each
    rebuild.

    Cost, measured rather than quoted from the objdump alone: `arm-none-eabi-
    objdump -d -l --inlines` is 0.9 s over a 1 370 429-line dump, and the ROW —
    `python scripts/ct_gate.py` — is about 15 s wall, nearly all of it the Python
    pass. The firmware build it reads was already a row.
    """
    assert ct_gate.REGION == "ct-sites"


#: An emitted function's header line, which is what the cut below is made at.
#: Not `FUNC_HEAD`: that one matches the INLINE frames objdump reprints inside a
#: function, and cutting at those would cut a run in half.
FUNCTION = re.compile(r"^[0-9a-f]{8} <")

#: `ct_eq` as the disassembly SPELLS it, hash suffix excluded. `ct_gate.demangle`
#: is what turns this into `SYMBOL`; deciding which functions survive the cut is
#: a grep over the text, before any parse has happened.
MANGLED = "_ZN10rsk_crypto3mac5ct_eq"

SYMBOL = SITE["CT-CMP-001"]["symbol"]

#: The half of a finding that says THE DEFECT. A row that goes red on a floor, on
#: a missing image or on a parse error has gone red for the inverse reason, and
#: an arm that reads only the exit code cannot tell the two apart — measured in
#: this repo as 2 of 24 co-refutation patches scoring a kill for the wrong half.
LEAK = "a secret-dependent branch inside a constant-time site"

#: Every OTHER way the row can go red. An arm below asserts none of these is what
#: it caught, so a defect that stopped being a defect and started being a parse
#: failure cannot pass for a kill.
NOT_THE_DEFECT = (
    "under the measured",
    "is in no inline chain",
    "the reload excuse covers",
    "no paragraph says",
    "cannot be generated",
    "build it first",
)


@pytest.fixture(scope="session")
def whole_image():
    """`ct_gate`'s own reader, over `ct_gate`'s own image, run ONCE per session.

    Which image: whichever `target/` holds, and inside `check.sh` that is the
    `--features no-touch` build, because its row sits between the default build
    and pytest. Nothing here reads a count off it, so either image drives these
    arms — the row is what pins the default one.

    A missing ELF is a FINDING and not a skip. `conftest.py` fails the session on
    any skip for the reason this section exists: a case that stops running is the
    one state `check.sh` cannot tell from a pass.
    """
    elf = ROOT / ct_gate.ELF
    assert elf.is_file(), (
        f"{ct_gate.ELF} is not there — `cargo build --release -p firmware`"
        " first. The arms below prove a machine-code defect reddens the row, and"
        " they have no image to put a defect into."
    )
    done = subprocess.run(
        [ct_gate.OBJDUMP, "-d", "-l", "--inlines", "--section=.text", str(elf)],
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.splitlines()


@pytest.fixture(scope="session")
def inlining_functions(whole_image):
    """The dump cut to the emitted functions the site is inlined into.

    Why a cut at all: the whole dump is over a million lines and the row's Python
    pass over it is seconds, which is a suite nobody runs. Why it is SOUND: every
    walk in `ct_gate` stops when `chain[-1]` changes, and `chain[-1]` is the
    enclosing emitted function, so a whole function removed is a neighbourhood no
    walk could have entered. A finding needs a load the site is attributed to, so
    it can only ever be raised inside a function this keeps.

    And it cannot go BLIND either way, which is the property that matters more
    than the argument: a cut that lost a run drops the row under `RUN_FLOOR` and
    the green arms fail, a cut that lost a finding makes the defect arm fail.
    Both directions are asserted below, so a slicer that rotted breaks a case
    rather than quietly measuring a different stream.
    """
    blocks, current, prologue = [], [], []
    for line in whole_image:
        if FUNCTION.match(line):
            blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
        else:
            prologue.append(line)
    blocks.append(current)
    kept = [b for b in blocks if b and any(MANGLED in line for line in b)]
    cut = prologue + [line for block in kept for line in block]
    # Whole blocks are kept, so an attributed line falling outside the cut is the
    # one way it could lose a run before any case has looked at it.
    assert sum(MANGLED in line for line in cut) == sum(
        MANGLED in line for line in whole_image
    ), "the cut dropped a line the site is attributed to"
    return cut


def row(work, dump, script=None):
    """`main()` in a SUBPROCESS, with the disassembler substituted and nothing else.

    A shim first on `PATH`, not a monkeypatch: `check.sh` reads a process's exit
    code and nothing else, and an in-process patch cannot tell a gate that exits
    1 from one that prints its finding and returns 0 — the family
    `test_gate_scripts.py` measured on fourteen of thirty rows. Only `objdump` is
    shimmed; `toolchain()`'s `readelf` still resolves to the real one and still
    reads the real image.
    """
    script = ROOT / "scripts/ct_gate.py" if script is None else script
    work.mkdir(parents=True, exist_ok=True)
    text = work / "objdump.txt"
    text.write_text("\n".join(dump) + "\n", encoding="utf-8")
    argv = work / "argv"
    tool = work / ct_gate.OBJDUMP
    tool.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$*" > "{argv}"\nexec cat "{text}"\n',
        encoding="utf-8",
    )
    tool.chmod(0o755)
    done = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        env=dict(os.environ, PATH=f"{work}{os.pathsep}{os.environ['PATH']}"),
    )
    # The shim answered the row's OWN command over the row's OWN image, so a
    # `disassembly()` that stopped reading the ELF reads as a failure here rather
    # than as a green row over a stream nothing produced.
    spelled = argv.read_text(encoding="utf-8")
    assert str(script.parents[1] / ct_gate.ELF) in spelled, spelled
    assert "--inlines" in spelled and "--section=.text" in spelled, spelled
    return done


def cmp_zero(register, halfwords):
    """`cmp <register>, #0` as ARM encodes it, at the width it replaces.

    T1 is two bytes and only reaches r0-r7; T2 is four. Real encodings because a
    defect the parser REJECTS is a syntactic corruption, and a row that goes red
    on one has not read a defect at all.
    """
    number = int(register[1:])
    if halfwords == 1:
        return f"{0x2800 | number << 8:04x}      "
    return f"f1b{number:x} 0f00 "


def early_exit(lines):
    """Point the accumulate loop's back edge at the XOR instead of at the counter.

    `if diff != 0 { return false; }`, at the instruction the compiler emits for
    it: the two byte loads and the XOR stay where they are, and the compare the
    loop's `bne` reads becomes a compare of the accumulated difference. One
    instruction per copy, at the same address and the same width, so this is a
    machine-code defect and not a stream whose shape the parser rejects.

    Returns the mutated lines and {address: the register now compared}.
    """
    stream = list(ct_gate.instructions(lines))
    planned = {}
    for run in ct_gate.runs(stream, SYMBOL):
        loaded, accumulator = set(), None
        for address, mnemonic, operands, _ in run:
            if ct_gate.LOAD.match(mnemonic):
                base = ct_gate.BASE.search(operands)
                if base and base.group(1) != "pc":
                    loaded.add(operands.split(",")[0].strip())
            elif mnemonic in ("eor", "eors"):
                written, read = (p.strip() for p in operands.split(",")[:2])
                if written in loaded and read in loaded:
                    accumulator = written
            elif accumulator and mnemonic == "cmp" and "#" in operands:
                planned[address] = accumulator
                break
    out, injected = [], {}
    for line in lines:
        code = ct_gate.INSN.match(line)
        register = planned.get(int(code.group(1), 16)) if code else None
        halfwords = len(line.split("\t")[1].split()) if code else 0
        # A high register has no narrow `cmp #0`, so that copy is left alone
        # rather than widened: the mutant may not move an address.
        if register and not (halfwords == 1 and int(register[1:]) > 7):
            address = int(code.group(1), 16)
            out.append(
                f"{code.group(1)}:\t{cmp_zero(register, halfwords)}\tcmp\t{register}, #0"
            )
            injected[address] = register
            continue
        out.append(line)
    return out, injected


@pytest.fixture(scope="session")
def defective_image(inlining_functions):
    """The image with the early exit in it, built ONCE for the four arms below."""
    mutated, injected = early_exit(inlining_functions)
    # Asserted here so an injection that stopped applying is this fixture's
    # failure, not a green row somewhere downstream reading as a clean image.
    assert injected, "no copy of the site took the early exit"
    assert mutated != inlining_functions
    assert sum(
        1 for line in mutated if re.search(r"\tcmp\tr\d+, #0$", line)
    ) >= len(injected), "the mutated stream does not carry what was injected"
    return mutated, injected


def test_a_machine_code_early_exit_in_the_shipped_image_reddens_the_row(
    defective_image, tmp_path
):
    """The gap this section closes.

    The four binary mutants above call `audit(lines=…)` over a hand-written
    fixture: they falsify the RULE. Nothing drove the ROW — `python
    scripts/ct_gate.py` — over a defective image, so the five arms recorded in
    [`test_the_image_arms_were_driven_by_hand`] were the only evidence that a
    defect reaches an exit code, and re-running them meant editing Rust and
    relinking by hand. This one injects the same defect into the real image's
    real disassembly and drives the real entry point.
    """
    mutated, injected = defective_image
    done = row(tmp_path, mutated)
    assert done.returncode == 1, (done.stdout, done.stderr)
    leaks = [line for line in done.stderr.splitlines() if LEAK in line]
    assert leaks, done.stderr
    # WHICH assertion fell, and in which direction: the row must say a branch
    # reads a byte the comparator LOADED. A floor, a vanished site or an
    # unreadable image is the inverse defect wearing the same exit code.
    assert all(word not in done.stderr for word in NOT_THE_DEFECT), done.stderr

    # And that it is THE INJECTION it caught: the finding names the BRANCH, which
    # sits a few bytes past the compare that was rewritten, so the tie is the
    # compare it quotes and the distance between the two addresses.
    assert any(
        f"branches on flags from `cmp {register}, #0`" in done.stderr
        for register in set(injected.values())
    ), done.stderr
    reported = {int(a, 16) for a in re.findall(r"CT-CMP-001: 0x([0-9a-f]+) `b", done.stderr)}
    assert any(
        any(0 < branch - address <= 8 for branch in reported) for address in injected
    ), (sorted(injected), sorted(reported))


def test_the_row_is_green_over_the_image_as_it_ships(inlining_functions, tmp_path):
    """The control for the arm above, and the one that keeps the cut honest.

    Without it the case above is satisfied by a row that can only fail, and by a
    cut that lost the runs rather than by a defect. `RUN_FLOOR` and its two
    siblings are read off `ct_gate` rather than written here: pinning the numbers
    is what made the recorded table go stale twice.
    """
    done = row(tmp_path, inlining_functions)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "0 secret-dependent" in done.stdout, done.stdout
    counts = [int(n) for n in re.findall(r"(\d+) (?:attributed run|conditional branch)", done.stdout)]
    traced = int(re.search(r"and (\d+) traced", done.stdout).group(1))
    assert counts[0] >= ct_gate.RUN_FLOOR, done.stdout
    assert counts[1] >= ct_gate.BRANCH_FLOOR, done.stdout
    assert traced >= ct_gate.REASONED_FLOOR, done.stdout


def test_a_renamed_branch_target_is_not_a_behaviour_change(
    inlining_functions, tmp_path
):
    """The control that says the arm measures behaviour and not spelling.

    Every `<symbol+offset>` objdump prints beside a branch target is renamed —
    the labels, not the attribution: an `inlined by …` line is a location line
    and not an instruction, so the chains the verdict is keyed on are untouched.
    """
    relabelled = [
        re.sub(r"<[^>]*>", "<a_name_this_rule_may_not_read>", line)
        if ct_gate.INSN.match(line)
        else line
        for line in inlining_functions
    ]
    assert sum(
        1 for was, now in zip(inlining_functions, relabelled) if was != now
    ), "no label was renamed, so this control is a second copy of the one above"
    # The claim this control rests on, asserted rather than commented. Measured
    # while driving it: the 16 `<symbol>:` function-header lines carry the only
    # other angle brackets, and `ct_gate` parses nothing out of those either.
    assert [step[3] for step in ct_gate.instructions(relabelled)] == [
        step[3] for step in ct_gate.instructions(inlining_functions)
    ], "the rename reached the inline chains the verdict is keyed on"

    done = row(tmp_path, relabelled)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "0 secret-dependent" in done.stdout, done.stdout


def test_a_nop_outside_every_attributed_run_is_not_a_behaviour_change(
    inlining_functions, tmp_path
):
    """The second control, and the one about LAYOUT rather than names.

    Appended after the last instruction the site is not attributed to, which is
    also after every run: `walk_back`, `last_definition` and `reload_of_a_store`
    all walk BACKWARDS, so an instruction added behind them cannot move a window
    they never reach. That it landed outside the runs is asserted, not assumed.
    """
    stream = list(ct_gate.instructions(inlining_functions))
    after = next(
        address for address, _, _, chain in reversed(stream) if SYMBOL not in chain
    )
    nopped = []
    for line in inlining_functions:
        nopped.append(line)
        code = ct_gate.INSN.match(line)
        if code and int(code.group(1), 16) == after:
            nopped.append(f"{after + 2:08x}:\tbf00      \tnop")
    assert len(nopped) == len(inlining_functions) + 1

    runs = ct_gate.runs(list(ct_gate.instructions(nopped)), SYMBOL)
    assert len(runs) == len(ct_gate.runs(stream, SYMBOL)), "the nop split a run"
    assert not any(
        address == after + 2 for run in runs for address, _, _, _ in run
    ), "the nop landed inside an attributed run"

    done = row(tmp_path, nopped)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "0 secret-dependent" in done.stdout, done.stdout


#: One clause of `ct_gate.py`, deleted in a SCRATCH COPY, and what the row then
#: says over the defect above: (what it is, the text, what replaces it, the
#: finding that still reddens the row — `None` when nothing does).
#:
#: `None` is the arm that says the clause is load-bearing: the row goes GREEN
#: over an image whose comparator branches on the bytes it loaded. The other two
#: are honest about what actually holds them — a floor and the page diff, not the
#: rule — which is the reading a verdict column would have hidden.
CLAUSES = (
    (
        "buffer_load follows the taint through arithmetic",
        "    if depth <= 0 or mnemonic not in TRANSPARENT:\n        return None\n",
        "    return None\n",
        None,
    ),
    (
        "secret_branches reads a flag-setting branch at all",
        "        elif COND_BRANCH.match(mnemonic):",
        "        elif False:",
        "the rule stopped putting the question",
    ),
    (
        "audit turns a violation into a finding",
        "        for addr, mnemonic, source, load in violations:",
        "        for addr, mnemonic, source, load in []:",
        "is not what the generator writes",
    ),
)


def scratch(work, source):
    """The smallest tree the real script resolves itself against.

    The ELF is SYMLINKED and not copied: `disassembly` asks whether it is a file
    and `toolchain` reads its DWARF, and the image is 16 MB. The registry and the
    page are copied so a clause deletion cannot reach the working tree.
    """
    root = work / "tree"
    for directory in ("scripts", "assurance", "docs", str(ct_gate.ELF.parent)):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts/ct_gate.py").write_text(source, encoding="utf-8")
    for name in ("elf_gate.py",):
        shutil.copy(ROOT / "scripts" / name, root / "scripts" / name)
    for path in (ct_gate.REGISTRY, ct_gate.PAGE):
        shutil.copy(ROOT / path, root / path)
    (root / ct_gate.ELF).symlink_to(ROOT / ct_gate.ELF)
    return root / "scripts/ct_gate.py"


@pytest.mark.parametrize("what, clause, without, backstop", CLAUSES)
def test_the_clause_that_catches_the_early_exit_is_named(
    what, clause, without, backstop, defective_image, tmp_path
):
    """A clause that survives its own deletion is decorative. Which of these do.

    Read as the FINDING and not as the exit code, deliberately: two of the three
    clauses below still redden the row after they are gone, and both do it on
    something that is not the leak. An arm reading `returncode` alone would have
    called all three load-bearing.
    """
    source = (ROOT / "scripts/ct_gate.py").read_text(encoding="utf-8")
    assert source.count(clause) == 1, f"{what}: the clause is not where this reads it"
    mutated, _ = defective_image

    done = row(tmp_path, mutated, script=scratch(tmp_path, source.replace(clause, without)))
    assert LEAK not in done.stderr, (what, done.stderr)
    if backstop is None:
        assert done.returncode == 0, (what, done.stdout, done.stderr)
    else:
        assert done.returncode == 1, (what, done.stdout, done.stderr)
        assert backstop in done.stderr, (what, done.stderr)
