#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The gate's second layer: the TLA+ plumbing and the registries held against
# the prose. Run it once before opening a pull request, not on every commit; CI
# runs it as its own job on every pull request and weekly (docs/testing.md).
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/gate-lib.sh

# check.sh's `flake.lock in sync` proves the lock is not STALE and nothing
# proves what it pins is in the TCB at all: `flip-link`, `rust-lld` and
# `arm-none-eabi-as` appeared in no registry, no gate and no page, and
# `cargo-kani` is in no nix file whatsoever — its only pin is an `env:` written
# three times, of which `kani_gate.py` reads one. This holds every tool's
# recorded pin against the file that pins it and prints the TCB into
# docs/supply-chain.md.
run "toolchain TCB registry"   python scripts/toolchain_gate.py
# The same question one register out. docs/verified-compilation.md DECIDES about
# that TCB — whether a kernel of this firmware should move to a language with a
# verified compiler — and every reason it gives is a number about this tree. A
# decision record whose numbers nothing re-derives is a decision that was true
# the day it was typed, which is what the registry above exists to prevent.
run "11C decision measurements" python scripts/level11c_gate.py
# 235 of the 236 configurations say "do not edit by hand" in their first line,
# and nothing made that true: deleting a whole mutant family left every row
# green, because run-tlc.sh lists families with `ls` so the tiers shrank with
# them. This regenerates into a temp tree and diffs.
run "generated TLC configs"    python scripts/config_gen_gate.py
# The shape of check.sh's bcd and SPDX rows, one layer out: the TLA+ model's
# ~175 `file.rs:line` citations were checked once, by hand, and a model
# pointing at a line that has moved reads as authoritative while being wrong.
run "formal citations"         python scripts/citation_gate.py
run "assurance registry"       python scripts/assurance_gate.py
# The registry above says WHAT is claimed; this says of WHICH IMAGE. `nix build`
# makes nineteen, `largeblob-ext` swaps the CTAP surface with no flake package at
# all, and four no-touch builds remove the consent gate the authorization
# properties are about — so a claim proved on the default build was being
# asserted about eighteen others by silence.
run "build-configuration matrix" python scripts/matrix_gate.py
# And of WHICH THREAT. The threat model is the root of every evidence chain here
# and was cited by the file name alone on 33 rows, which names no threat. This
# derives the page's clauses, holds each P0-family row to one of them, and makes
# a row with none say which of the two things that is.
run "threat-model traceability" python scripts/threat_gate.py
# A model constant that stands for a fact about the world, not a defect switch.
# `PowerOnClearsScratch2` was TRUE in all seven Boot configurations and read by
# no action: deleting its `ASSUME` left every run bit-identical.
run "standing assumptions"     python scripts/assumption_gate.py
# And the assumptions no constant can carry, which the row above refuses by
# construction: a board question, a recorded PASS, emulator fidelity. Their
# candidates are DERIVED from five sources — the slice bundle's own ids said
# "registered: no" on eight of ten rows, and `assurance/crates.toml`'s `abstracts`
# is what anchors a store-backend row so deleting one is a diff — and so is how
# many are discharged: the row prints the live tally on a green run, because the
# copy typed here read "one of the eighteen" long after both numbers had moved.
run "platform assumptions"     python scripts/platform_gate.py
# `floors.txt` catches a run that got smaller; this catches one whose
# CONSTANTS are too small to express the defect its own mutants rebuild.
# Two of the twenty-five module mutants go GREEN one element down.
run "formal scopes"            python scripts/scope_gate.py
# The scope row is a `>=`, so `Cap = 3 -> 4` on the transport configuration
# clears it and no Rust file mentions Cap at all. This holds the four numbers
# the chunk-to-byte bridge is proved through against each other.
run "transport bridge"         python scripts/transport_bridge_gate.py
# And the abstractions no scope constant can express: the "Narrower than the
# firmware" roster, ten bullets on formal/README.md that NO script read — a
# whole one could be deleted at exit 0 on citation, claims, run-count, threat,
# evidence, scope, config-gen and comutants. The list is generated from
# assurance/abstractions.toml now, and each row's disposition is held to the
# artifact it rests on: a `closed` needs a mutant a tier runs and floors.txt
# requires RED, an `open-obligation` reddens when its question is settled.
run "narrow abstractions"      python scripts/narrow_gate.py
# And `floors.txt` itself, which only the weekly TLC matrix reads — so between
# two weeklies it could be weakened with every row here green. Measured: the two
# layers that did reach it name 2 of its 25 wildcard families, and flipping
# `SeamMut_*.cfg` from RED to GREEN passed all 98 rows. This one derives the
# verdict from each configuration's own CONSTANTS instead of trusting the column.
run "TLA verdict registry"     python scripts/verdict_gate.py
run "comutants lint"           python scripts/comutate.py --lint
run "seam trace map"           python scripts/trace_map.py
run "security trace refinement" python scripts/security_trace.py --check-data formal/TraceSecurityData.tla formal/traces/security-phase4.jsonl
# A `"Name" \notin viol` clause is only as strong as the set of actions that
# write the name, and this model named that set in a COMMENT that said eleven.
# It is 21, over 24 routes -- and three of them record TWICE, so a name-set
# equality stays green over a half-deleted guard. This derives both.
run "ghost completeness"       python scripts/ghost_gate.py
# And the other end of the same question: not what a ghost's writers are, but
# where a model deliberately stops being about the product. `RSKeyAppletSeams`
# hard-coded `\/ a = Oath` TWICE -- once to re-lock OATH on a re-SELECT, once to
# keep the conformance recorder quiet about it -- and deleting either changed the
# input of no gate. Nothing was a registry for that class: `git grep -i exempt
# scripts/` found only tier exclusions. This derives the narrowings out of the
# `.tla` (a narrowing operand or `IF` condition, a set literal that omits what
# its sibling has, a CASE that answers for part of its domain) and holds them to
# assurance/model_exceptions.toml both ways -- an exception with no row, and a
# row whose clause the model no longer has. How many there are and how many still
# owe a mutant is DERIVED and printed on every green run; the ledger records the
# debt with the file that would pay it, and holds that the file is not there yet.
run "model exceptions"         python scripts/model_exception_gate.py
# The first closed slice's raw evidence, held to stage 1A's ten-group contract.
# Ten headings with one line each satisfy "all ten groups are present", so this
# counts LEAVES and floors them per group — and refuses a cost written as a
# range, which is an estimate wearing a measurement's field.
run "slice evidence bundle"    python scripts/bundle_gate.py
# And the registry's one word, split into the six questions it was mixing. The
# slice above moved SEC-FIDO-001 from one Kani harness to four and its `status`
# would have read the same with either, because the word derives from a harness
# NAME. This derives six axes apart, rebuilds the word from two of them, and
# writes the public page so a release sentence cannot outrun the axes.
run "evidence vector"          python scripts/evidence_gate.py
# And the bundles' OTHER half: the numbers each obligation was measured at. The
# row above floors them at 2 per method row and 24 per bundle -- on COUNT and
# TYPE, never on value -- while the scope table a reader actually reads was
# fourteen rows typed by hand into docs/authorization-slice.md that nothing read.
# Six mutations proved it: a docs bound moved while the bundle stood still, the
# bundle moved while the docs stood still, a row renamed after a constant that
# does not exist, a row deleted -- exit 0 on all eight gates. This writes all 295
# from assurance/bundle/*.toml and refuses a second table anywhere.
run "bundle bounds table"      python scripts/bounds_gate.py
# And what the pages SAY a run was. Seven were stale the day this row landed --
# `safety` published as 190 rows against a tier of 195, the model's state space
# at 63% of the measured count in the paragraph the docs call the one to quote,
# and five more between them -- because every one was typed. The sentences are
# written from `formal/runs.toml`, which holds the runner's own matrix per tier
# and TLC's own summary of the same run beside it, so no number in either has
# one source. A count typed in any tracked text file under docs/, formal/ or
# .github/, or on any page at the root, is a finding: by DIRECTORY, because the
# suffix whitelist this said before let a count into a new formal/*.md, a .tla
# comment, a .github/*.json, SECURITY.md and eighteen more, all driven at
# exit 0. `formal/runs.toml` itself and CHANGELOG.md are the two carve-outs.
run "published run-counts"     python scripts/run_count_gate.py
# And what the pages SAY a property IS. Stage 0 item 3 and the last exit of stage 4
# are one predicate -- a public claim about a registered id is generated, and one
# written by hand fails on a docs row -- and this file carried no docs row at all,
# so four false sentences including "`SEC-FIDO-001` ... PROVEN on hardware" in
# README.md were exit 0 on all eight gates. The CI step `docs.sh check` is
# `mdbook build` plus a link check and never reads a claim. Not "generated or
# refused", which would refuse true prose no table replaces: a hand-written
# status is held to the status the registry HOLDS for the id beside it, so
# `PROVEN` -- no row's status anywhere -- is refused of every id.
run "published claims"         python scripts/claims_gate.py
# And what the pages SAY a RELEASE RUNS. Same shape, one layer out: it was prose
# transcribed from a workflow nothing held it to -- "rebuilds all fourteen
# flavors", "builds every artifact reproducibly, hashes it, and signs the
# manifest" -- and that transcription has already rotted once, when the signature
# asset was renamed `.cosign.bundle` -> `.sigstore.json` and every published
# verify command went on naming a file that no longer exists. Every command,
# flavor, action pin and asset name is read out of release.yml, release-build.yml
# and nix/firmware.nix here and printed into docs/supply-chain.md. Two things it
# refuses that no other row can see: a rebuild loop covering thirteen of the
# fourteen images the build loop makes, so the fourteenth is signed and attested
# with nothing having compared its bytes; and an entry claiming `source->binary`
# off the reproducibility gate -- determinism is not semantic preservation, and
# PLAT-TOOLCHAIN-001 is the row that owns that gap. It binds to no tag and no
# artifact: that half needs a release, and the region says so.
run "release manifest"        python scripts/release_gate.py
run "token refinement export" ./scripts/token_refinement.sh --check
run "token refinement completeness" python scripts/token_refinement_gate.py
# The tables behind the rows above: every file marked `assurance`. check.sh
# collects the same directory with `-m "not assurance"`, so none falls between.
run "pytest (assurance scripts)" python -m pytest scripts -q -m assurance \
  --basetemp="$GATE_PYTEST_TMP/assurance" "${GATE_PYTEST_KEEP[@]}"

echo
echo "ALL ASSURANCE CHECKS PASSED"
