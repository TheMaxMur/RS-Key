#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Mutation testing over the host crates — the weekly deep-checks `mutants` row.
#
#   nix develop -c ./scripts/mutants-all.sh
#   MUTANTS_SHARD=2/8 nix develop -c ./scripts/mutants-all.sh
#
# Coverage says a line ran. This says a test would notice if that line changed,
# which is a different question and the one this tree keeps getting wrong: the
# first full sweep (13 232 mutants, 2026-08-15) found `require_pin_inputs`
# replaceable by `Ok(())` with the gate green, and the trusted display's four
# applet loaders driven by no test at all.
#
# **Advisory.** It reports; it does not gate. 3247 of that first sweep's mutants
# survived and most are not defects — code behind an off `cfg`, a guard a deeper
# guard masks, a coordinate no test pins on purpose — so a gating row would be red
# every week, and a row that is always red is a row nobody reads. It becomes a
# gate when the survivors have been triaged and an accepted-survivor baseline
# exists to diff against. What this row DOES fail on is its own apparatus: a shard
# that tested nothing, or a run that produced no summary at all.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
OUT="${MUTANTS_OUT:-target/mutants}"

# Measured 13 232 on 2026-08-15 over these crates. A floor with margin, not a
# ratchet: its job is to catch a selection that collapsed — a `-p` roster that
# stopped matching, an exclude glob that ate the tree — not to police the count,
# which moves with every commit.
MUTANT_FLOOR=10000

if ! command -v cargo-mutants >/dev/null; then
  echo "FAIL: cargo-mutants is not on PATH — this is not the dev shell." >&2
  echo "      run it as: nix develop -c $0" >&2
  exit 1
fi

# The roster, derived rather than hand-written: a new crate joins by existing.
# `firmware` and `rsk-wipe` are absent for the reason `scripts/check.sh` excludes
# them from every host row — they are `no_std` and do not build here.
packages=()
for dir in crates/*/; do
  packages+=(-p "$(basename "$dir")")
done

# Two exclusions, each for a measured reason (see the sweep's triage):
#   --target        the workspace default is thumbv8m, where no test runs at all
#   -e **/*kani.rs  `#[cfg(kani)]` code `cargo test` never builds, so every
#                   mutation in it survives and means nothing
# `#[cfg(test)]` modules need no exclusion — cargo-mutants already skips them.
common=(
  "${packages[@]}"
  -C "--target=$HOST"
  -e '**/kani.rs'
  -e '**/*_kani.rs'
)

# `|| true` because `grep -c` exits 1 on zero matches, and with `set -e` that
# would end the script here — before the floor below could say why.
total="$(cargo-mutants mutants --list "${common[@]}" | grep -cE '^crates/' || true)"
echo "roster: ${total} mutants (floor ${MUTANT_FLOOR})"
if [ "$total" -lt "$MUTANT_FLOOR" ]; then
  echo "::error::--list yielded ${total} mutants, under the ${MUTANT_FLOOR} floor — the package roster or an exclude glob collapsed"
  exit 1
fi

MUTANTS_SHARD="${MUTANTS_SHARD:-1/1}"
shard_i="${MUTANTS_SHARD%%/*}"
shard_n="${MUTANTS_SHARD##*/}"
if ! [ "$shard_i" -ge 1 ] 2>/dev/null || ! [ "$shard_i" -le "$shard_n" ] 2>/dev/null; then
  echo "::error::MUTANTS_SHARD=$MUTANTS_SHARD is not i/k with 1 <= i <= k"
  exit 1
fi

# cargo-mutants creates its output directory but not the parent, and on a runner
# whose `target/` cache missed there is no parent to create it in: "create output
# parent directory target/mutants: No such file or directory", five shards of the
# first real run. The apparatus check below is what caught it — the row failed as
# "no summary line" rather than passing with nothing tested.
mkdir -p "$OUT"

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
# `|| true` deliberately: cargo-mutants exits non-zero when mutants survive, and
# on this row that is the expected outcome rather than a failure. The summary line
# below is what says the run happened, so a crash cannot pass as "none survived".
# cargo-mutants numbers shards from ZERO — `--shard 8/8` is "invalid value: shard
# k must be less than n". Passing this script's 1-based number straight through
# therefore ran indices 1..7 and never index 0: an eighth of the tree silently
# unmutated, while the last shard failed outright. Converted here so the shard
# number means the same thing in every row (`FUZZ_SHARD`, `MIRI_SHARD`, this one)
# and only the flag sees the tool's own convention.
cargo-mutants mutants "${common[@]}" \
  --shard "$((shard_i - 1))/$shard_n" -j "${MUTANTS_JOBS:-4}" --output "$OUT" 2>&1 | tee "$log" || true

summary="$(grep -E '^[0-9]+ mutants tested' "$log" | tail -1 || true)"
if [ -z "$summary" ]; then
  echo "::error::shard ${MUTANTS_SHARD} produced no summary line — the run did not finish"
  exit 1
fi
tested="${summary%% *}"
if [ "$tested" -eq 0 ]; then
  echo "::error::shard ${MUTANTS_SHARD} tested 0 of ${total} mutants"
  exit 1
fi

echo "mutants: shard ${MUTANTS_SHARD}, ${summary}"
{
  echo "### mutants shard ${MUTANTS_SHARD}"
  echo
  echo '```'
  echo "$summary"
  echo '```'
  echo
  echo "Advisory row — survivors are triaged by hand, not gated. See docs/testing.md."
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
