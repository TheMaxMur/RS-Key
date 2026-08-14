#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Fuzz every target for FUZZ_SECONDS each — the deep-checks `fuzz` row.
#
#   nix develop .#fuzz -c ./scripts/fuzz-all.sh
#   FUZZ_SECONDS=30 nix develop .#fuzz -c ./scripts/fuzz-all.sh
#
# A FILE, not an inline `nix develop .#fuzz -c bash -euo pipefail -c '…'`, which
# is what the workflow used to carry. That form loses the dev shell's PATH on a
# GitHub runner: `cargo` falls through to the image's rustup shim, which syncs
# *stable* and answers "no such command: fuzz". Measured in one run, same image,
# same minute — the sibling row `nix develop .#fuzz -c ./scripts/fuzz-coverage.sh`
# listed 53 targets while the inline one listed 0. Not reproducible in a local
# Linux VM, which is why the shape is the fix and the check below is the proof.
set -euo pipefail
cd "$(dirname "$0")/.."

# The row's own toolchain, asserted before anything depends on it. Without this a
# `cargo` that is not the dev shell's reads as "the roster shrank" — the failure
# that sent a maintainer looking for a deleted fuzz target.
if ! command -v cargo-fuzz >/dev/null; then
  echo "FAIL: cargo-fuzz is not on PATH — this is not the .#fuzz dev shell." >&2
  echo "      cargo:      $(command -v cargo || echo '(none)')" >&2
  echo "      rustc:      $(command -v rustc || echo '(none)')" >&2
  echo "      run it as:  nix develop .#fuzz -c $0" >&2
  exit 1
fi

FUZZ_SECONDS="${FUZZ_SECONDS:-120}"
# Same floor and same reason as `scripts/fuzz-coverage.sh` and the `fuzz targets
# alive` row in `scripts/check.sh`: `set -e` does not fire on an empty or failing
# $( ) in a `for` word list, so a broken `cargo fuzz list` fuzzed zero targets and
# the row reported green — measured, rc=0. It needs no margin, unlike the
# firmware-size ratchet: a target count has no build noise. A literal, not
# `${FUZZ_TARGET_FLOOR:-53}`, because a floor the environment can lower is not a
# floor. Lower all three copies in the commit that removes a target.
FUZZ_TARGET_FLOOR=53

mapfile -t targets < <(cargo fuzz list)
# The corpus lives in one LRU-evictable cache entry; on a restore miss every
# target starts from empty and the run still says DONE.
echo "roster: ${#targets[@]} targets (floor ${FUZZ_TARGET_FLOOR}), corpus: $(find fuzz/corpus -type f 2>/dev/null | wc -l) inputs restored"
if [ "${#targets[@]}" -lt "$FUZZ_TARGET_FLOOR" ]; then
  echo "::error::cargo fuzz list yielded ${#targets[@]} targets, under the ${FUZZ_TARGET_FLOOR} floor — the roster shrank or the list failed"
  exit 1
fi

# FUZZ_SHARD=i/k — this runner's slice of the roster, so the row's wall time is
# the slowest shard's rather than the sum of every target's. Sliced only AFTER the
# floor above has been checked against the whole list: a per-shard floor would be
# a second number to re-balance, and the guard it replaced is the one that catches
# `cargo fuzz list` failing outright.
FUZZ_SHARD="${FUZZ_SHARD:-1/1}"
shard_i="${FUZZ_SHARD%%/*}"
shard_n="${FUZZ_SHARD##*/}"
if ! [ "$shard_i" -ge 1 ] 2>/dev/null || ! [ "$shard_i" -le "$shard_n" ] 2>/dev/null; then
  echo "::error::FUZZ_SHARD=$FUZZ_SHARD is not i/k with 1 <= i <= k"
  exit 1
fi

# Round-robin over the list, which is balanced by construction. Hashing the name
# would keep a target on the same shard when the roster changes — the corpus is
# cached per shard, so a reshuffle costs the moved targets their accumulated
# inputs — but no cheap hash divides 54 names evenly into both 3 and 4 buckets:
# `cksum` low bits track the shared prefixes (7/12/10/25 measured), and the safe
# mixes traded one bad split for another (15/14/20/5). Balance is what this row is
# sharded for; the corpus is best-effort anyway, living in one LRU-evictable cache
# entry that has already been dropped once.
mine=()
for i in "${!targets[@]}"; do
  if [ $((i % shard_n)) -eq $((shard_i - 1)) ]; then
    mine+=("${targets[$i]}")
  fi
done
# A shard with nothing in it exits 0 having fuzzed nothing — the same green-on-zero
# this script exists to refuse, just one runner at a time.
if [ "${#mine[@]}" -eq 0 ]; then
  echo "::error::shard ${FUZZ_SHARD} selected no targets from ${#targets[@]}"
  exit 1
fi
echo "shard ${FUZZ_SHARD}: ${#mine[@]} of ${#targets[@]} targets"

failed=""
for t in "${mine[@]}"; do
  echo "::group::${t} (${FUZZ_SECONDS}s)"
  if ! cargo fuzz run "$t" -- -max_total_time="$FUZZ_SECONDS" -print_final_stats=1; then
    failed="$failed $t"
  fi
  echo "::endgroup::"
done

if [ -n "$failed" ]; then
  echo "::error::crashing targets:$failed"
  exit 1
fi
echo "fuzz: shard ${FUZZ_SHARD}, ${#mine[@]} of ${#targets[@]} targets, ${FUZZ_SECONDS}s each, no crashes"
