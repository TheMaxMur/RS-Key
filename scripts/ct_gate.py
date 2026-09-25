#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Constant-time sites, read out of the shipped ELF instead of asserted in prose.

`docs/ct-audit.md` says the canonical comparator's inlined copies "lower to a
loop whose only branch is governed by the *public* length counter", and that
every PIN/MAC/verifier surface routes through it. Both sentences were true when
someone disassembled the image by hand once. Nothing re-read the image
afterwards, and the page's own "42 candidate sites were examined" names a table
that has never existed in any revision of the file — the only table there has
three rows, the three fixed findings.

This gate makes the two sentences machine-checked against the ELF `check.sh`
just built:

* **No branch anywhere depends on a byte a registered site loaded.** For every
  conditional branch in `.text`, the flag-setting instruction it reads is found,
  and each register that instruction reads is traced back to its last
  definition. A definition that is a LOAD FROM A BUFFER whose own inline chain
  names a registered site makes the branch secret-dependent, and one such branch
  fails the row. (This line read "a `ldr*` whose base is not `sp`" for three
  revisions after `buffer_load` stopped asking that: the base test it does make
  is `pc`, and the spill question is `reload_of_a_store`'s, by ADDRESS.)

  The taint hangs on the LOAD and not on the branch, and that is the whole
  difference between this rule and the one that shipped first here. Restricted to
  branches inside the site's own address runs, the rule MISSED the early-exit
  mutant it exists to catch: with the early exit compiled in, the secret `cmp r2,
  r1` is the last instruction the site's chain covers and the back edge that
  consumes its flags carries the enclosing applet's frame instead. Measured, that
  arm came back 0 violations, EXIT=0 — a check that could not fail, over the
  defect it was written for.

  The trace is TRANSITIVE, and that is the second thing this shipped wrong. A
  depth-1 rule — the flag operand's own definition must BE a load — is defeated
  by one arithmetic step, and an independent review drove it: `if diff & 0x80 !=
  0 { return false; }` inside the comparator lowers to `orrs` / `sxtb` / `cmp` /
  `bgt`, a real secret-dependent early exit, and the depth-1 rule reported zero.
  The mutant that WAS caught was caught only because LLVM folded it back into a
  compare of two loads — a property of the optimiser, not of the rule.

  The trace follows the PATH, and that is the fourth thing this shipped wrong —
  see `leaves_the_block` / `clobbers`. Walking the linear address order past an
  unconditional transfer answers with a definition no path to the branch can
  have executed, so the verdict became a function of block layout: two branches
  in `rsk-otp` whose operands are not bytes the comparator loaded were reported
  the day an unrelated OTP change moved the comparator's inlined copy to within
  64 instructions of them. The over-correction is recorded beside the rule,
  because bundling every transfer into one stop hid a real oracle.
* **The caller set is derived, not listed.** EVERY first-party frame the chains
  name — not just the outermost — is held against `assurance/ct_sites.toml` BOTH
  WAYS: a surface that stops routing through the comparator disappears from the
  ELF and reddens, and a new one that appears owes the registry a line saying
  which protocol operation it is.

  "Every frame" and not "the outermost" is the third thing this shipped wrong,
  and it was the headline claim. Keyed on the outermost frame, a bypass added
  BESIDE a surviving `ct_eq` call in the same enclosing function is invisible:
  the review reproduced the page's own Medium finding — `rsk-otp`'s `cmd_update`
  moved back to a slice `!=` over the 6-byte access code while `cmd_configure`
  kept the comparator — and the row stayed EXIT=0 with the page still listing
  "OTP slot configure/update access code" as a surface that routes through it.
  With every frame registered, `cmd_update` leaving the chains is a stale entry
  and the row goes red.
* **The page's scope paragraph may not re-scope the modexp to keygen.** One
  sentence of prose, held because everything else on that page is held by
  nothing — see `SCOPE_ANCHOR`, which carries the measurement and the rule's
  limits.

Three things it deliberately does NOT do. It does not print instruction counts
or addresses into the page: both move on any unrelated code change, and a
generated page whose diff is noise trains its reader to run `--write` without
looking. It is not a timing measurement — `docs/ct-audit.md`'s own "Coverage &
limits" says what a source/disassembly audit cannot prove, and this changes none
of it.

And there is no SINK rule: nothing here flags a LOAD whose index traces back to
a secret, because the taint ends at a BRANCH. That is scope, and it is written
down so the next reader does not rebuild a rule this file has already refuted in
both of its spellings. Spelled literally, as "the base register is not `sp`", it
is the test `buffer_load` stopped making — the first bullet records the sentence
outliving it by three revisions — and what it reports is the frame-register
spills described below, not a channel. Spelled with the same taint walk it would
be sound and EMPTY: inside the registered site every register-indexed load is
indexed by the public length counter, and the one load-shaped residual
`docs/ct-audit.md` names — the `rsk-rsa` modexp secret-indexed window lookup —
is out of reach three ways, whichever surface drives it. The arm that ships folds
the secret nibble into the BASE pointer rather than an index
(`crates/rsk-rsa/csrc/bignum_high_level.c`'s
`table_entry = (void *)temp + four_bits * modulus_length_bytes`, the `#else` arm
that `CONSTANT_MEMORY_ACCESS_PATTERN 0` in `crates/rsk-rsa/csrc/bignum_config.h`
selects); the load itself happens inside `bignum_mulacc`, so the taint would have
to cross a `bl` and the ABI into hand-written asm; and neither end is in `.text`
— the C carries `BIGNUM_RAMFUNC`, which is `section(".data.bignum_hl")`, the
asm's whole translation unit is `.section .data.bignum_asm`, and the disassembly
below is `--section=.text`. A rule whose extension is empty over everything the
audit page names is a green cell with nothing in it, which is the shape this file
exists to refuse.

The word `keygen` stood in that descriptor until the page it quotes refuted the
scope: the same `bignum_modexp_private_exponent_internal` runs on `dP`/`dQ` for
PIV GENERAL AUTHENTICATE and for OpenPGP PSO:CDS / INTERNAL AUTHENTICATE /
DECIPHER, all reachable over USB against a long-lived key. None of the three
reasons above depended on which surface drives the modexp, which is why the
descriptor could rot without the reasoning going wrong — and why a copy of
another page's finding is worth this paragraph rather than a shorter sentence.

What such a rule would still owe if anyone built it: the RP2350 puts a 16 KB
cache in front of XIP flash (`crates/rsk-bench/src/lib.rs:12`), so a secret
index into a `.rodata` table and the same index into SRAM are not the same
access — and which of the two a `ldr` performs is not decidable from its base
register. Any sink rule here is conservative by construction; that is a
constraint on its design, not a reason it cannot exist.

Why a RELOAD is not a buffer read, measured rather than assumed: the `black_box`
barrier the comparator ends with spills the accumulator and reads it straight
back (`strb.w r0, [r7, #-29]` / `ldrb.w r0, [r7, #-29]`), and the `cbz r0` on
that reload is the terminal reduction to a `bool` — inherent, since the function
returns one, and positionless. A whitelist of `sp` was the first version and it
missed the copies that spill through the frame register `r7` instead. The rule is
therefore not "which register" but "did this frame already write that address" —
a load with a matching earlier store is a reload, and a reload of a value is not
a read of a buffer.

HOW MANY such copies is derived and printed by the row rather than asserted here,
and that is a correction twice over. The sentence above said "eight of the
comparator's copies spill through `r7`, and the baseline reported all eight" from
the day it shipped, a later reading of the same image said ten, and neither
number was ever re-read off an ELF. Both are stale, and the sentence also fuses
two counts that are not one number: how many copies the excuse fires on, and how
many of those an `sp` whitelist would have REPORTED. A load is only reported when
a branch traces to it, so the second is the smaller. Measured 2026-09-01 over the
default `cargo build --release -p firmware` image (sha256 395dd99a…, this file's
own reader, `arm-none-eabi-objdump -d -l --inlines --section=.text`): of 82 loads
inside the site's 39 attributed runs, 28 are excused as a reload — 14 through
`sp` and 14 through `r7` — and the `sp`-whitelist rule reports 9 of the 14, all
`r7`. So "all eight" is not a shape this image has in either reading, and 8 = 10
was never a disagreement about one quantity.

The 14 is what the summary prints; the 9 is by hand — `reload_of_a_store`
replaced with `base == "sp"` over the same stream — and nothing re-measures it.
Neither is stable: the OTP code motion that moved the traced count 26 -> 24 -> 22
moves these the same way, which is the whole reason the row derives the one it
can instead of storing it. The `--features no-touch` image, which `check.sh`
leaves at this path after its later rows, is NOT the source of that drift: built
into its own `CARGO_TARGET_DIR` on the same tree it answers 39 / 14 / 9,
identically. Nor is the walk: the same counterfactual over the pre-`b00d228`
walk, from the branch rather than the flag-setter, also answers 9.

The limit that leaves, stated rather than discovered later: a path that COPIES
secret bytes into a stack slot and then compares them there reads its own store
and is not flagged. Nothing in the audited sites does that — the comparator
indexes both operands in place — but the rule cannot see it if one starts.

The second limit, from `leaves_the_block`: the walk is LINEAR and stops at an
unconditional transfer, so a load whose block JUMPS to the branch's rather than
falling into it is out of reach. Stepping over that transfer would reach it —
and would equally reach every unrelated block sitting between them, which is
what made two branches over non-comparator bytes look secret. That direction
buys an accident, not a reach. It is the ONLY class the walk stops at blind: a
call stops it for a caller-saved register and nothing else, and a `cbz` does not
stop it at all.

The trace starts at the FLAG-SETTER, and that is the fifth thing this shipped
wrong. Thumb is scheduled, so an instruction sitting between the compare and the
branch may redefine the compare's operand, and the walk began at the BRANCH: at
`0x10036ff8` the shipped image reads `orr.w r0, sl, #8` / `cmp r0, #56` / `and.w
r0, r4, #34` / `bne`, and the rule answered with the `and` — a value the compare
never saw. Which way that errs is a coin toss on what the clobber happens to be,
and `cmp r0, r1` / `mov r0, #5` / `beq` is the losing side: the rule goes blind
to whatever really fed the compare, which is the shape a real early exit has. A
`cbz` is exempt because it reads its register at the branch itself. Measured:
the shipped image keeps its 0 secret-dependent branches and traces 22 rather
than 24, and the early-exit mutant goes from 27 findings to 28 — the extra one a
`bne` whose compare sat on the far side of a `b.n`, which the walk from the
branch met first and stopped at.

The mutant this row exists to catch is an early exit inside the accumulate loop
(`if diff != 0 { return false; }`): the accumulator and the barrier vanish and
the loop becomes a `memcmp`, with the two secret bytes reaching a `cmp` that
governs a branch. Driven through the row's own command after a rebuild: the
shipped tree reports 0 secret-dependent branches over 39 attributed runs and 25
conditional branches, EXIT=0; with the early exit compiled in, 27 over 59 runs,
EXIT=1.
The mutant that does NOT work, and is recorded so nobody re-tries it: deleting
the `black_box` — the page itself says the barrier "does not change the code
generated today", so that arm stays green and is a check that cannot fail.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_gate  # noqa: E402  the producer parser, so the two cannot disagree

ROOT = pathlib.Path(__file__).resolve().parent.parent

REGISTRY = pathlib.Path("assurance/ct_sites.toml")
PAGE = pathlib.Path("docs/ct-audit.md")
ELF = pathlib.Path("target/thumbv8m.main-none-eabihf/release/firmware")
OBJDUMP = "arm-none-eabi-objdump"

#: The region this script owns inside an otherwise hand-written page. NOT an
#: `ARTIFACT`/`GENERATED_BY` pair: `claims_gate.generated_pages` reads that pair
#: to exempt a page WHOLE, and `docs/ct-audit.md` is prose that must stay under
#: the claims rule. A region is masked; a page is excused.
REGION = "ct-sites"
REGION_HEADER = "<!-- Generated by scripts/ct_gate.py --write; do not edit. -->"

#: The one sentence of `docs/ct-audit.md`'s PROSE that anything holds, and it is
#: here because the alternative was nothing. `claims_gate` fires on a sentence
#: naming a registered `SEC-*` id; this page names none, so its prose sits at
#: exit 0 whatever it says. Measured 2026-09-01 with the refuted wording in
#: place: `claims_gate`, `run_count_gate`, `docs.sh check` and this row all
#: EXIT=0, and `citation_gate`'s red named `crates/rsk-oath/src/lib.rs` drift in
#: `formal/` only — not one word about this page.
#:
#: What it refuses: the scope paragraph calling the `rsk-rsa` primitives
#: `keygen`. `rsa_private_exp_crt` drives the same
#: `bignum_modexp_private_exponent_internal` on `dP`/`dQ` for PIV GENERAL
#: AUTHENTICATE and OpenPGP PSO:CDS / INTERNAL AUTHENTICATE / DECIPHER, all over
#: USB against a long-lived key, so a keygen scope is the refuted one.
#:
#: Its limit, stated rather than discovered: it is a WORD rule and cannot tell a
#: refutation from a claim — `docs/ct-audit.md`'s residuals say "not keygen-only"
#: and would fail it, and the shipped page carries ten such hits outside the
#: scope. That is why it is confined to the paragraph that carries the anchor,
#: and why a missing anchor is itself a finding: a rule keyed on a string the
#: page can simply drop is a rule the next edit deletes for free.
#:
#: The anchor is the CLAUSE and not a sentence five lines above it, and that is a
#: correction. Anchored on "Its scope is" and refusing `\bkeygen\b`, the rule was
#: walked past thirteen ways — every one measured 2026-09-01 against the shipped
#: page with the refuted scope restored and `scope_finding` answering None:
#: `key generation`, `Keygen`, `KEYGEN`, `KeyGen`, `keyGen`, `key-generation`,
#: `keygens`, `key_gen`, a zero-width space, a `key`/`gen` line break, the clause
#: moved into a bullet list, a decoy paragraph carrying the anchor (`next(...)`
#: took the FIRST), and — the one that settles the design — a blank line inserted
#: after "CTAP2)", which is not an attack but an editor breaking a ten-line
#: paragraph in two. Anchored on the clause, a re-wrap or a move carries the
#: anchor along with the words it is about.
#:
#: The bare `rsk-rsa` spelling is NOT the anchor, measured: it sits in 5
#: paragraphs of the shipped page, so the ambiguity rule below would fire on a
#: clean tree.
SCOPE_ANCHOR = "hand-written `rsk-rsa`"

#: What the anchored paragraph must SAY, and the half no synonym can walk past:
#: a scope that drops the CRT caller IS the refuted one whatever words it uses,
#: and carrying the clause elsewhere carries these away with it.
SCOPE_REQUIRED = ("modexp", "rsa_private_exp_crt")

#: Case-insensitive and separator-tolerant, because the shipped rule's `re.I`-less
#: `\bkeygen\b` missed four capitalisations, the hyphen, the underscore, the
#: plural (its trailing `\b`), a zero-width space and a line break. No trailing
#: boundary on purpose; the leading one keeps `monkey generator` out. The
#: zero-width space is written as an escape, so a reader can see it is there.
SCOPE_REFUTED = re.compile(r"\bkey[\s\u200b_-]*gen", re.I)

#: Hand-written keys. Everything else about a site — where it is inlined, how
#: many copies, which branches it contains — is read from the image.
#:
#: What is deliberately NOT a key here is a `subject` naming which property a
#: site is evidence for. Correctness and side-channel resistance are separated by
#: the REGISTRY a claim lives in, not by a column: a correctness claim is a row
#: of `assurance/properties.toml`, derived from model configurations and Kani
#: harness names and gated by `check.sh`'s `run "evidence vector"`; a
#: side-channel claim is a row of `assurance/ct_sites.toml`, derived from the
#: shipped LTO ELF and gated by `run "constant-time sites in the image"`. Named
#: by ROW and not by line because `check.sh` moves under every kind of change.
#:
#: Neither allowlist carries a field for the other's claim, which is stricter
#: than the column this would have added: nothing checks that a `[[property]]`
#: statement is a correctness claim, so the column would separate by convention
#: while the two registries separate by what each gate can derive. `registry`
#: below holds this set in BOTH directions — an extra key and a missing one —
#: where `evidence_gate.WRITTEN_FIELDS` is held only against the extra.
#:
#: Driven rather than argued, because the column is the obvious thing to add:
#: `subject` on a property row is EXIT=1 there, and widening its `WRITTEN_FIELDS`
#: to admit it left `subject = "banana"` at EXIT=0 — read by nothing, printed by
#: nothing, and absent from the page that gate writes. A column that separates
#: nothing is a weakening wearing the separation's name.
HAND_FIELDS = {"id", "symbol", "class", "statement"}
CALLER_FIELDS = {"symbol", "surface"}
CLASSES = {"comparator"}
SITE_ID = re.compile(r"^CT-[A-Z]+-\d{3}$")

#: A first-party frame, by CRATE and not by path: the paths objdump prints are
#: this machine's absolute build paths, and a rule keyed on them would answer
#: differently on the runner.
FIRST_PARTY = re.compile(r"^(rsk_[a-z0-9_]+|firmware)::")

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s*(.*)$")
FUNC_HEAD = re.compile(r"^(\S+)\(\):$")
INLINED_BY = re.compile(r"^inlined by (\S+):(\d+) \((\S+)\)$")
SOURCE_LINE = re.compile(r"^(/\S+):(\d+)(?: \(discriminator \d+\))?$")

#: Legacy Rust mangling: `_ZN` then length-prefixed components then `E`, with a
#: final `17h<16 hex>` disambiguator this drops.
LEGACY = re.compile(r"^_ZN(.+)E$")
COMPONENT = re.compile(r"(\d+)")
HASH_COMPONENT = re.compile(r"^h[0-9a-f]{16}$")

#: Every mnemonic is read with its width suffix REMOVED, and that is not a
#: nicety: the sets below first shipped matching `cmp` exactly, and the loop in
#: `spend_and_verify_pin_hash` spells its public bound `cmp.w fp, #32`. The
#: walk-back skipped it, landed on the `eors` that accumulates two secret bytes,
#: and reported the shipped comparator as secret-dependent. One spelling, and the
#: rule answered the opposite of the truth.
WIDTH = re.compile(r"\.[nw]$")

#: Conditional branches. `b` alone is unconditional and `bl`/`blx`/`bx` are
#: calls; the condition codes are spelled out rather than matched loosely,
#: because `bic` and `bfi` start with `b` too.
CONDS = (
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl",
    "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
)
COND_BRANCH = re.compile(r"^b(" + "|".join(CONDS) + r")$")
CBZ = re.compile(r"^cbn?z$")

#: Everything that writes the flags. The `s`-suffixed forms are enumerated
#: rather than matched by a trailing `s`, because `movs` and `subs` share that
#: letter with `mrs`, `bics` and `ldrsb` — one of which is a load.
FLAG_ONLY = {"cmp", "cmn", "tst", "teq"}
FLAG_SETTING = FLAG_ONLY | {
    "adds", "adcs", "subs", "sbcs", "rsbs", "ands", "orrs", "orns", "eors",
    "bics", "movs", "mvns", "lsls", "lsrs", "asrs", "rors", "rrxs", "muls",
}
LOAD = re.compile(r"^ldr(b|h|sb|sh|d)?$")

#: Data-processing mnemonics that carry a VALUE from their sources into their
#: destination, so a taint passes through them. Enumerated rather than
#: complemented: a mnemonic nobody listed stops the trace, which is the
#: under-reporting direction and the one a floor can still catch.
TRANSPARENT = {
    "mov", "movs", "mvn", "mvns", "uxtb", "uxth", "sxtb", "sxth", "rev", "rev16",
    "revsh", "rbit", "clz", "and", "ands", "orr", "orrs", "orn", "orns", "eor",
    "eors", "bic", "bics", "add", "adds", "adc", "adcs", "sub", "subs", "sbc",
    "sbcs", "rsb", "rsbs", "lsl", "lsls", "lsr", "lsrs", "asr", "asrs", "ror",
    "rors", "mul", "muls", "mla", "mls", "ubfx", "sbfx", "bfi", "bfc",
}

#: How many data-processing steps a taint may pass through. Four, because the
#: measured defect is two (`orrs` then `sxtb`) and the cost of one more level is
#: a walk, not a solve.
TAINT_DEPTH = 4
REGISTER = re.compile(r"\b(r\d+|sl|fp|ip|sp|lr|pc)\b")

#: The address base a load reads from, if the operand list has one.
BASE = re.compile(r"\[(r\d+|sl|fp|ip|sp|pc)")

#: Predication. `IT` makes the next instructions conditional, and the shipped
#: comparator uses it: `crates/rsk-crypto/src/mac.rs:55`'s public length-equality early return lowers
#: to `cmp r0,#1 / it eq / cmpeq fp,r1 / beq`. A blanket refusal of any run
#: containing an `IT` was the first rule here and it reported that as a finding —
#: the DOCUMENTED public early return, called secret-dependent. The rule instead
#: reads a predicated flag-setter as a flag-setter and keeps walking past it,
#: because when its condition is false the PREVIOUS flags still govern the
#: branch; both candidates are then asked the same buffer-load question.
CONDITION = re.compile(r"^(.*?)(" + "|".join(CONDS) + r")$")

#: The address part of a load or store, matched verbatim so a reload is
#: recognised by ADDRESS rather than by which register happens to hold the frame.
ADDRESS = re.compile(r"(\[[^\]]*\])")

STORE = re.compile(r"^str(b|h|d)?$")

#: Floors, and they are PARAMETERS of `audit` rather than globals a case patches
#: down — `run_count_gate.SCAN_FLOOR` shipped the other way and its own docstring
#: says the shipped value was therefore never checked against the shipped tree.
#: Measured on this tree: 39 attributed runs, 25 conditional branches examined,
#: 22 traced to a definition.
#:
#: The reasoned floor sat at 15 against a measurement of 24, so nine branches
#: could go silently unasked — and a change that narrowed the walk is exactly
#: what it was there to catch. It went to 20, the same ~20% under the
#: measurement the other two carry (39/30, 25/20).
#:
#: It STAYS 20 against 22, and the two it now stands under is deliberate. The 24
#: was inflated: traced from the branch, a loop's `subs r5, #1` was answered as
#: the definition of its own operand, so two branches were counted reasoned on a
#: self-credit that decided nothing. Tracing from the flag-setter reports them
#: untraced, which is the truth — the slack under this floor was always 2, and
#: only the arithmetic said a fifth. Lowering it to keep the ~20% would walk the
#: floor down behind exactly the narrowing it exists to catch.
#:
#: The cost, stated here rather than discovered later: this count also moved
#: 26 -> 24 on unrelated code motion, so a motion that size reddens the row with
#: no defect behind it. Re-measure the walk when that happens; the floor is not
#: the first thing to reach for.
RUN_FLOOR = 30
BRANCH_FLOOR = 20
REASONED_FLOOR = 20

# There is a fourth rule and it is deliberately NOT a floor: `audit` asks, per
# site, whether the reload excuse covers more of that site's loads than it leaves
# exposed. It answers the hole none of the three above can — they are all
# computed WITHOUT asking `reload_of_a_store`, so an excuse widened until it
# covers every load leaves them untouched and the row green over a rule that
# decides nothing. Driven: stubbed to `True` over the shipped image the row
# reports 0 secret-dependent branches with 39 / 25 / 22 unchanged and EXIT=0, and
# the table's own early-exit fixture loses its finding as well.
#
# A LITERAL was the first version (43, "the same ~20% under the measurement" as
# these three) and the percentage was taken on the wrong kind of quantity:
# measured on the default release image, 27 of the 39 attributed runs contribute
# exactly 2 exposed each and the other 12 contribute none, so `exposed` has a
# GAIN of 2 and 20% of it is five copies of code motion. Losing six — no defect,
# one inlining decision — answers 42 exposed over 33 runs: red on the literal
# while `RUN_FLOOR` is still comfortably green. Summed across sites it fails the
# other way, and both are why the rule is a ratio inside one site's own loads.
#
# Measured over fourteen constructed widenings of the excuse, the ratio reddens
# on all three that blind the row — including `[rN, rM]`, which a denominator
# derived from the run count answers 39 against 39 and MISSES — and it is green
# out to 22 copies lost, first red at 23, so `RUN_FLOOR` asks for the walk to be
# re-measured (k=10) long before it says anything. What no count here can see,
# stated rather than discovered later: an excuse narrowed to exactly the loads a
# taint reaches moves 2 of 82, and nothing fires.


def demangle(symbol: str) -> str:
    """`_ZN10rsk_crypto3mac5ct_eq17h3eb6…E` -> `rsk_crypto::mac::ct_eq`.

    The v0 scheme (`_R…`) and plain C names are returned unchanged: nothing this
    gate registers is mangled that way, and a wrong guess would silently widen
    attribution rather than narrow it.
    """
    body = LEGACY.match(symbol)
    if not body:
        return symbol
    rest, parts = body.group(1), []
    while rest:
        size = COMPONENT.match(rest)
        if not size:
            break
        start = size.end()
        width = int(size.group(1))
        parts.append(rest[start : start + width])
        rest = rest[start + width :]
    if parts and HASH_COMPONENT.match(parts[-1]):
        parts.pop()
    return unescape("::".join(parts)) if parts else symbol


#: The escapes legacy mangling puts in a generic component. Only the ones this
#: tree actually produces, because an unescape nobody drove is a second parser.
ESCAPES = (("$LT$", "<"), ("$GT$", ">"), ("$C$", ","), ("$u20$", " "),
           ("$RF$", "&"), ("$u7b$", "{"), ("$u7d$", "}"), ("..", "::"))


def unescape(name: str) -> str:
    for spelling, char in ESCAPES:
        name = name.replace(spelling, char)
    return name


def registry(root: pathlib.Path, findings: list[str], text: str | None = None):
    """The hand-written half: sites and the surface each caller stands for.

    `text` is the registry, handed in so a case can mutate it without writing to
    the working tree — the first version of the table did write, and a review
    pointed out that an interrupt during `pytest (gate scripts)` would leave a
    tracked file modified.
    """
    doc = tomllib.loads(
        (root / REGISTRY).read_text(encoding="utf-8") if text is None else text
    )
    for key in sorted(set(doc) - {"site", "caller"}):
        findings.append(
            f"{REGISTRY}: top-level `{key}` — the file holds `[[site]]` and"
            " `[[caller]]` tables and nothing else"
        )
    sites, callers = {}, {}
    for entry in doc.get("site", []):
        name = str(entry.get("id", "")).strip()
        if not SITE_ID.match(name):
            findings.append(f"{REGISTRY}: `{name}` is not a `CT-<AREA>-<NNN>` id")
            continue
        for key in sorted(set(entry) - HAND_FIELDS):
            findings.append(f"{name}: `{key}` is not a field this registry reads")
        for key in sorted(HAND_FIELDS - set(entry)):
            findings.append(f"{name}: no `{key}`")
        if entry.get("class") not in CLASSES:
            findings.append(
                f"{name}: class {entry.get('class')!r} is outside"
                f" {sorted(CLASSES)} — a class the rule cannot decide is a label"
            )
        sites[name] = entry
    for entry in doc.get("caller", []):
        for key in sorted(set(entry) - CALLER_FIELDS):
            findings.append(f"{REGISTRY}: caller `{key}` is not a field it reads")
        symbol = str(entry.get("symbol", "")).strip()
        surface = str(entry.get("surface", "")).strip()
        if not symbol or not surface:
            findings.append(f"{REGISTRY}: a caller needs both `symbol` and `surface`")
            continue
        if symbol in callers:
            findings.append(f"{REGISTRY}: `{symbol}` is registered twice")
        callers[symbol] = surface
    return sites, callers


def disassembly(root: pathlib.Path) -> list[str]:
    elf = root / ELF
    if not elf.is_file():
        raise FileNotFoundError(
            f"{ELF} — build it first: cargo build --release -p firmware"
        )
    out = subprocess.run(
        [OBJDUMP, "-d", "-l", "--inlines", "--section=.text", str(elf)],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.splitlines()


def instructions(lines):
    """(addr, mnemonic, operands, chain) per instruction, innermost frame first.

    objdump reprints a location line only when it CHANGES, so an instruction with
    no location lines of its own inherits the previous one. Rebuilding the chain
    from scratch per instruction would attribute those to nothing — which is the
    silent-undercount direction, so it is done the other way.
    """
    chain, inner, outer, func = [], None, [], None
    fresh = False
    for line in lines:
        head = FUNC_HEAD.match(line)
        if head:
            func, inner, outer, fresh = demangle(head.group(1)), None, [], True
            continue
        under = INLINED_BY.match(line)
        if under:
            outer.append(demangle(under.group(3)))
            fresh = True
            continue
        source = SOURCE_LINE.match(line)
        if source:
            inner, fresh = func, True
            continue
        code = INSN.match(line)
        if not code:
            continue
        if fresh:
            chain = ([inner] if inner else []) + outer
            inner, outer, fresh = None, [], False
        yield int(code.group(1), 16), WIDTH.sub("", code.group(2)), code.group(3), chain


def runs(stream, symbol):
    """Maximal contiguous instruction runs the inline chain attributes to `symbol`."""
    out, current = [], []
    for step in stream:
        if symbol in step[3]:
            current.append(step)
        elif current:
            out.append(current)
            current = []
    if current:
        out.append(current)
    return out


#: Where the FLAG-SETTER search stops — `walk_back`'s rule, and only its. A call
#: may leave any flags, an unconditional transfer means the fall-through is not
#: how we got here, and a change of enclosing function means we left the frame.
#: The data-flow walks want a finer question and ask `leaves_the_block` /
#: `clobbers` instead: a call CLOBBERS caller-saved registers, which is a rule
#: about a register and not a place to stop.
BARRIER = re.compile(r"^(bl|blx|bx|b|pop|cbz|cbnz)$")

#: Where a DATA-FLOW walk stops, and it is a REGISTER question rather than only a
#: mnemonic one. `BARRIER` bundles four classes and only two of them end a
#: fall-through: `bl`/`blx` return, and `cbz`/`cbnz` are conditional, so for both
#: the next instruction IS on the path. Stopping at all four was measured to hide
#: a real oracle — an early exit whose two secret bytes reach `cmp fp, sl` across
#: a `bl __aeabi_memset4`, with `fp`/`sl` callee-saved so the call cannot have
#: touched them. A review built it, and the coarse rule reported 0 where the
#: rule before this one reported 1. Over the shipped image the two rules are put
#: 16698 branch-register questions and differ on 1250: `bl` 833, `cbz` 337,
#: `blx` 53, `cbnz` 27, and nothing else. `b`/`bx`/`pop {..,pc}` cannot differ —
#: both rules stop there — so the whole behaviour change is the unsound half.
#:
#: What the finer rule is FOR, since a stop that reaches nothing is not one: an
#: `OtpApplet` branch at `crates/rsk-otp/src/lib.rs:718` and the `CFG_HMAC_LT64`
#: test below it were reported as reading the comparator's operand load, on the
#: strength of a walk that crossed two `b.n` into `cmd_configure`'s inlined copy.
#: Neither operand is a byte the comparator loaded. Nothing about `ct_eq` or its
#: callers had changed: two OTP commits moved that copy to within 64 instructions
#: of them, and the same rule is green on the image built before those commits.
LEAVES_BLOCK = re.compile(r"^(b|bx)$")
CALL = re.compile(r"^(bl|blx)$")

#: AAPCS: a call may clobber these and must preserve r4-r11. Spelled with the
#: aliases objdump prints, because `ip` and `r12` are the same register.
CALLER_SAVED = {"r0", "r1", "r2", "r3", "r12", "ip", "lr"}


def leaves_the_block(mnemonic, operands):
    """Whether control cannot reach the next instruction by falling through."""
    if LEAVES_BLOCK.match(mnemonic):
        return True
    return mnemonic == "pop" and "pc" in REGISTER.findall(operands or "")


def clobbers(mnemonic, register):
    """Whether a call here may have destroyed `register` on the way to the use."""
    return bool(CALL.match(mnemonic)) and register in CALLER_SAVED



def walk_back(stream, index, want, limit=64):
    """(position, instruction) before `index`, nearest first, to a barrier or `limit`.

    The position is yielded because the flag-setter's caller has to trace its
    operands from WHERE IT SITS, not from the branch that reads its flags.
    """
    frame = stream[index][3][-1] if stream[index][3] else None
    for step in range(index - 1, max(-1, index - limit - 1), -1):
        addr, mnemonic, operands, chain = stream[step]
        if (chain[-1] if chain else None) != frame:
            return
        yield step, stream[step]
        if BARRIER.match(mnemonic) and step != index - 1:
            return
        if want is not None and mnemonic == want:
            return


def last_definition(stream, index, register):
    """(position, instruction) of the nearest write to `register` before `index`.

    Within the block: a definition on the far side of a barrier is not one this
    use could have read, and crediting it makes the verdict a function of how the
    linker laid the blocks out.
    """
    frame = stream[index][3][-1] if stream[index][3] else None
    for step in range(index - 1, max(-1, index - 65), -1):
        addr, mnemonic, operands, chain = stream[step]
        if (chain[-1] if chain else None) != frame:
            return None
        if mnemonic in FLAG_ONLY:
            continue
        if leaves_the_block(mnemonic, operands) or clobbers(mnemonic, register):
            return None
        written = REGISTER.search(operands.split(",")[0]) if operands else None
        if written and written.group(1) == register:
            return step, stream[step]
    return None


def buffer_load(stream, index, register, depth=TAINT_DEPTH, seen=None):
    """The buffer load `register` at `index` ultimately reads, if any.

    Transitive: a value that reaches a compare through `orrs` and `sxtb` came
    from the load all the same, and a rule that only accepts a load as the
    IMMEDIATE definition is defeated by one arithmetic step.
    """
    found = last_definition(stream, index, register)
    if found is None:
        return None
    where, (addr, mnemonic, operands, chain) = found
    if LOAD.match(mnemonic):
        base = BASE.search(operands)
        if base and base.group(1) == "pc":
            return None  # a literal pool holds constants, never a buffer
        if reload_of_a_store(stream, where):
            return None
        return addr, mnemonic, operands, chain
    if depth <= 0 or mnemonic not in TRANSPARENT:
        return None
    seen = set() if seen is None else seen
    if where in seen:
        return None
    seen.add(where)
    tail = operands.split(",", 1)[1] if "," in operands else ""
    for source in REGISTER.findall(tail):
        deeper = buffer_load(stream, where, source, depth - 1, seen)
        if deeper:
            return deeper
    return None


def flag_setter(mnemonic):
    """(base mnemonic, predicated) if `mnemonic` writes the flags, else None."""
    if mnemonic in FLAG_SETTING:
        return mnemonic, False
    suffix = CONDITION.match(mnemonic)
    if suffix and suffix.group(1) in FLAG_SETTING:
        return suffix.group(1), True
    return None


def reload_of_a_store(stream, index):
    """Whether the load at `index` reads back an address this frame already wrote.

    Same block as the store, for the same reason as `last_definition` — and here
    the direction matters more, because a match EXCUSES the load: a store the
    control flow cannot have executed would excuse a genuine buffer read.
    """
    load = stream[index]
    address = ADDRESS.search(load[2])
    if not address:
        return False
    frame = load[3][-1] if load[3] else None
    for step in range(index - 1, max(-1, index - 64), -1):
        addr, mnemonic, operands, chain = stream[step]
        if (chain[-1] if chain else None) != frame:
            return False
        if leaves_the_block(mnemonic, operands):
            return False
        if STORE.match(mnemonic) and ADDRESS.search(operands or "") == None:
            continue
        if STORE.match(mnemonic):
            written = ADDRESS.search(operands)
            if written and written.group(1) == address.group(1):
                return True
    return False


def excused_loads(stream, symbol):
    """(reloads excused through a base other than `sp`, exposed, excused).

    The first is the count the docstring used to assert and now prints. The other
    two are the two halves of ONE partition of the site's non-`pc` loads, which
    is the whole of what `audit` holds them for: an excuse that widens moves both
    at once, and no other count in this file moves at all.

    It is NOT a reachability claim, and the sentence that stood here said it was
    ("a load this counts as exposed is a load the taint can still reach").
    Refuted 2026-09-01 on the default release image with a spy inside
    `secret_branches`: `buffer_load` puts the excuse question about 21 in-site
    loads, all 21 come back excused, and of the 54 this counts exposed the taint
    reaches NONE. The two sets do not intersect on a clean tree, so "exposed"
    reads as "the excuse did not decide this load" and nothing more.
    """
    spilled = exposed = excused = 0
    for index, (_, mnemonic, operands, chain) in enumerate(stream):
        if symbol not in chain or not LOAD.match(mnemonic):
            continue
        base = BASE.search(operands)
        # A literal pool holds constants: `buffer_load` refuses it before the
        # excuse is ever put, so counting it either way would credit the excuse
        # for a load it never decided.
        if base and base.group(1) == "pc":
            continue
        if not reload_of_a_store(stream, index):
            exposed += 1
            continue
        excused += 1
        # `!= sp` and not "any reload", because the two are different questions:
        # 28 of this image's in-site loads are reloads, and 14 of those spill
        # through the frame register rather than the stack pointer.
        if base and base.group(1) != "sp":
            spilled += 1
    return spilled, exposed, excused


def scope_finding(text: str) -> str | None:
    """What `docs/ct-audit.md`'s scope paragraph must say and may not say, or None."""
    anchored = [block for block in text.split("\n\n") if SCOPE_ANCHOR in block]
    if not anchored:
        return (
            f"{PAGE}: no paragraph says `{SCOPE_ANCHOR}` — the page's scope is the"
            " only prose here anything holds, and dropping the clause drops the"
            " rule with it"
        )
    # Ambiguity is itself the finding: the rule reads ONE paragraph, so a second
    # one carrying the anchor — an HTML comment will do — shields the real clause
    # from it whichever of the two this picks.
    if len(anchored) > 1:
        return (
            f"{PAGE}: {len(anchored)} paragraphs say `{SCOPE_ANCHOR}` — this rule"
            " reads one of them, so the other shields the scope clause from it"
        )
    scope = anchored[0]
    # The POSITIVE half, and the half a synonym cannot walk past: a scope that
    # stops naming the CRT caller is the refuted one whatever words it uses, and
    # carrying the clause into a bullet carries these away with it.
    missing = [word for word in SCOPE_REQUIRED if word not in scope]
    if missing:
        return (
            f"{PAGE}: the scope paragraph no longer names"
            f" {', '.join(f'`{word}`' for word in missing)} — a scope that drops"
            " the modexp's USB-reachable caller is the keygen-only one a4b53c2"
            " refuted, whether or not it still spells the word"
        )
    if SCOPE_REFUTED.search(scope):
        return (
            f"{PAGE}: the scope paragraph scopes the `rsk-rsa` primitives as"
            " keygen. `rsa_private_exp_crt` drives the same modexp on dP/dQ for"
            " PIV GENERAL AUTHENTICATE and OpenPGP PSO:CDS / INTERNAL"
            " AUTHENTICATE / DECIPHER, over USB against a long-lived key"
        )
    return None


def governing(stream, index):
    """Every flag-setter that can govern the branch at `index`, WITH its position.

    More than one when predication is in play: a predicated `cmpeq` writes the
    flags only if its own condition held, so the branch may still be reading what
    the flag-setter before it left. Walking back to the first UNPREDICATED one
    and asking all of them is the conservative direction.
    """
    out = []
    for where, step in walk_back(stream, index, None):
        found = flag_setter(step[1])
        if not found:
            continue
        out.append((where, step))
        if not found[1]:
            break
    return out


def secret_branches(stream, symbols, asked=None):
    """Conditional branches whose flags trace to a byte a registered site loaded.

    `asked` collects the branches the rule actually REASONED about, as opposed to
    the ones it merely walked past: a review measured that 20 of the shipped
    image's 26 in-site branches are excused before the buffer question is put,
    so a floor on branches SEEN says less than it looks.
    """
    out = []
    asked = set() if asked is None else asked
    for index, (addr, mnemonic, operands, _) in enumerate(stream):
        # A `cbz` reads its register AT THE BRANCH; every other conditional
        # branch reads flags, and those were set where the flag-setter sits, so
        # its operands must be traced from THERE.
        if CBZ.match(mnemonic):
            candidates = [(mnemonic, operands.split(",")[0].strip(), index)]
        elif COND_BRANCH.match(mnemonic):
            candidates = [
                (f"{flags[1]} {flags[2]}", register, where)
                for where, flags in governing(stream, index)
                for register in REGISTER.findall(flags[2])
            ]
        else:
            continue
        reasoned = False
        for source, register, reads_at in candidates:
            found = REGISTER.search(register)
            name = found.group(1) if found else None
            if name and last_definition(stream, reads_at, name):
                reasoned = True
            defined = buffer_load(stream, reads_at, name) if name else None
            if not defined:
                continue
            site = next((s for s in symbols if s in defined[3]), None)
            if site is None:
                continue
            out.append((site, addr, mnemonic, source, f"{defined[1]} {defined[2]}"))
            break
        if reasoned:
            asked.add(addr)
    return out


def observe(root: pathlib.Path, sites, lines=None, loads=None):
    """{site id: (violations, run count, branch count, first-party callers)}.

    `lines` is the disassembly, so a case can hand in a recorded one instead of
    paying for a firmware build — the parser and the rule are what a case is
    about, and the live image is what the gate row is about.

    `loads` collects `excused_loads`'s three counts PER SITE, the same way
    `asked` collects the branches the rule reasoned about: the stream is built
    here, and building it a second time in `audit` would double a 15 s row. Per
    site and not summed, because summing is what let a second site stand in for
    the first — measured, registering `rsk_crypto::mlkem::mlkem768_encapsulate`
    beside the comparator takes the total from 54 exposed to 367, so the
    comparator's whole exposure could vanish under a total that never moved.
    """
    lines = disassembly(root) if lines is None else lines
    stream = list(instructions(lines))
    by_site = {entry["symbol"]: name for name, entry in sites.items()}
    asked: set[int] = set()
    tainted = secret_branches(stream, set(by_site), asked)
    out = {}
    for name, entry in sorted(sites.items()):
        found = runs(stream, entry["symbol"])
        branches, callers = 0, set()
        for run in found:
            branches += sum(
                1 for _, mnemonic, _, _ in run
                if CBZ.match(mnemonic) or COND_BRANCH.match(mnemonic)
            )
            # EVERY first-party frame, including the per-crate forwarders: a
            # roster of outermost frames alone cannot see a bypass added BESIDE
            # a surviving call in the same enclosing function, which is exactly
            # the finding docs/ct-audit.md records twice.
            callers.update(
                f for f in run[0][3] if f != entry["symbol"] and FIRST_PARTY.match(f)
            )
        violations = [v[1:] for v in tainted if by_site[v[0]] == name]
        reasoned = sum(
            1 for run in found for addr, _, _, _ in run if addr in asked
        )
        if loads is not None:
            loads[name] = excused_loads(stream, entry["symbol"])
        out[name] = (violations, len(found), branches, callers, reasoned)
    return out


def toolchain(root: pathlib.Path, elf: pathlib.Path) -> str:
    """What compiled THIS image, out of its own DWARF.

    Not `rustc -vV`: a review pointed out that reads the compiler on the path,
    which is the one that would build the image and not the one that did.
    """
    names = elf_gate.producers(
        subprocess.run(
            ["arm-none-eabi-readelf", "--debug-dump=info", "--dwarf-depth=1",
             str(root / elf)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    if not names:
        return "unknown"
    # The MAJORITY producer, because the image is not built by one compiler: a
    # prebuilt `cortex-m` asm blob carries a 2021 nightly's string, and picking
    # the first name alphabetically published that one as "built by". The SET is
    # `assurance/image.toml`'s `producers`, checked by `scripts/elf_gate.py` —
    # which is what this comment claimed while that file had no producer code at
    # all, so a third compiler was invisible to both. Shared parser, one string.
    return names.most_common(1)[0][0]


def body(root, sites, callers, seen) -> list[str]:
    """The region, and it prints NO count and NO address on purpose."""
    out = [
        f"<!-- {REGION}:start -->",
        REGION_HEADER,
        "",
        f"Read out of `{ELF}` with `{OBJDUMP} -d -l --inlines`, built by"
        f" {toolchain(root, ELF)}. A site's verdict is `constant-time` when no"
        " conditional"
        " branch inside any address run the inline chain attributes to it reads"
        " flags set from a buffer load; the callers are the first-party frames"
        " those chains name, so a surface that stops routing through the site"
        " leaves this table.",
        "",
        "| Site | Class | Verdict | Surfaces that inline it |",
        "|---|---|---|---|",
    ]
    for name, entry in sorted(sites.items()):
        violations, _, _, found, _ = seen[name]
        verdict = "SECRET-DEPENDENT" if violations else "constant-time"
        surfaces = ", ".join(
            f"{callers.get(symbol, symbol)}" for symbol in sorted(found)
        )
        out.append(
            f"| `{entry['symbol']}` | {entry['class']} | {verdict} |"
            f" {surfaces or '—'} |"
        )
    out += ["", f"<!-- {REGION}:end -->"]
    return out


def render(root: pathlib.Path, sites, callers, seen, text=None) -> str:
    # `text` is the page `audit` was HANDED, and reading the file instead would
    # desync the two halves of one verdict: `scope_finding` decides on the handed
    # copy while the region diff decides on the tree.
    text = (root / PAGE).read_text(encoding="utf-8") if text is None else text
    start, end = f"<!-- {REGION}:start -->", f"<!-- {REGION}:end -->"
    head = text.find(start)
    tail = text.find(end)
    if head == -1 or tail == -1 or tail < head:
        raise ValueError(f"{PAGE} needs exactly one {REGION!r} marker pair")
    return text[:head] + "\n".join(body(root, sites, callers, seen)) + text[tail + len(end) :]


def audit(
    root: pathlib.Path,
    run_floor=RUN_FLOOR,
    branch_floor=BRANCH_FLOOR,
    reasoned_floor=REASONED_FLOOR,
    lines=None,
    page=None,
):
    findings: list[str] = []
    sites, callers = registry(root, findings)
    if findings:
        return findings, ""
    loads: dict[str, tuple[int, int, int]] = {}
    try:
        seen = observe(root, sites, lines, loads)
    except (OSError, subprocess.CalledProcessError) as error:
        return [f"{ELF}: {error}"], ""

    total_runs = total_branches = 0
    total_reasoned = total_exposed = total_spilled = 0
    for name, (violations, found, branches, inlined, reasoned) in sorted(seen.items()):
        total_runs += found
        total_branches += branches
        total_reasoned += reasoned
        spilled, exposed, excused = loads.get(name, (0, 0, 0))
        total_exposed += exposed
        total_spilled += spilled
        # PER SITE and a ratio, not a total and not a literal — the reasoning,
        # and every number behind it, sits beside `REASONED_FLOOR`.
        if excused > exposed:
            findings.append(
                f"{name}: the reload excuse covers {excused} of the site's"
                f" {excused + exposed} load(s) and leaves {exposed} visible to"
                " the taint — an excuse that decides the majority of a site's"
                " loads is the one rule here nothing else measures"
            )
        symbol = sites[name]["symbol"]
        if not found:
            findings.append(
                f"{name}: `{symbol}` is in no inline chain of the image — either"
                " it is gone or the DWARF is, and both make this row vacuous"
            )
        for addr, mnemonic, source, load in violations:
            findings.append(
                f"{name}: {addr:#x} `{mnemonic}` branches on flags from"
                f" `{source}`, whose operand was loaded by `{load}` — a"
                " secret-dependent branch inside a constant-time site"
            )
        for symbol in sorted(inlined - set(callers)):
            findings.append(
                f"{name}: `{symbol}` inlines it and no `[[caller]]` says which"
                " protocol surface that is"
            )
    for symbol in sorted(set(callers) - {s for row in seen.values() for s in row[3]}):
        findings.append(
            f"{REGISTRY}: `{symbol}` is registered as a caller and inlines no"
            " site in the image — the surface stopped routing through it, or the"
            " entry is stale"
        )

    # Both floors answer the same question the other rules cannot: a parser that
    # silently stopped matching reports zero of everything and zero violations.
    if total_runs < run_floor:
        findings.append(
            f"{total_runs} attributed run(s), under the measured {run_floor} —"
            " the objdump format moved under the parser"
        )
    if total_branches < branch_floor:
        findings.append(
            f"{total_branches} conditional branch(es) examined, under the"
            f" measured {branch_floor} — a rule that reads no branch cannot fail"
        )
    # The floor that says something the one above cannot: a branch the rule
    # WALKED PAST is not a branch it decided. Measured, most of the shipped
    # image's in-site branches are reloads of the barrier's own spill, so a
    # change that made every one of them look like a reload would satisfy the
    # count above while reasoning about nothing.
    if total_reasoned < reasoned_floor:
        findings.append(
            f"{total_reasoned} branch(es) traced to a definition, under the"
            f" measured {reasoned_floor} — the rule stopped putting the question"
        )

    try:
        text = (root / PAGE).read_text(encoding="utf-8") if page is None else page
    except OSError as error:
        findings.append(f"{PAGE}: {error}")
    else:
        problem = scope_finding(text)
        if problem:
            findings.append(problem)
        try:
            want = render(root, sites, callers, seen, text)
        except ValueError as error:
            findings.append(f"{PAGE} cannot be generated: {error}")
        else:
            if text != want:
                findings.append(
                    f"{PAGE}'s `{REGION}` region is not what the generator writes"
                    " — run `python scripts/ct_gate.py --write` and commit the"
                    " result"
                )

    summary = (
        f"ct-gate: ok — {len(sites)} constant-time site(s) over {total_runs}"
        f" attributed run(s), {total_branches} conditional branch(es) examined"
        f" and {total_reasoned} traced to a definition, {total_exposed}"
        f" load(s) still exposed to the taint and {total_spilled}"
        " reload(s) excused through a base other than `sp`, 0 secret-dependent,"
        f" {len(callers)} surface(s) registered"
    )
    return findings, summary


def run(root: pathlib.Path, write=False) -> int:
    if write:
        findings: list[str] = []
        sites, callers = registry(root, findings)
        if findings:
            for finding in findings:
                print(f"  {finding}", file=sys.stderr)
            return 1
        seen = observe(root, sites)
        (root / PAGE).write_text(render(root, sites, callers, seen), encoding="utf-8")
        print(f"ct-gate: wrote the {REGION} region of {PAGE}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("ct-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: ct_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
