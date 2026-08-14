#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Every fuzz target's logic under Miri's UB checker — the deep-checks `miri` row.
#
#   nix develop .#fuzz -c ./scripts/miri-all.sh
#   MIRI_SHARD=2/4 nix develop .#fuzz -c ./scripts/miri-all.sh
#
# A file rather than an inline `run:`, for the reason `scripts/fuzz-all.sh` states
# at length: that form loses the dev shell's PATH on a GitHub runner and `cargo`
# falls through to the image's rustup shim.
set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST=fuzz/Cargo.toml

# The roster floor, same shape and same reason as `scripts/fuzz-all.sh`: a filter
# that matches nothing prints "0 passed" and exits 0. Measured on this tree's own
# harness — `cargo test -- --exact a b` with two names selects **zero** tests and
# returns 0, which is why the shard below is expressed as `--skip` (repeatable,
# and verified to subtract) and not as a list of names to run.
#
# 49 distinct tests over the workspace's three test targets — `tests/miri.rs` (43),
# `tests/apdu_frame.rs` and `tests/churn_compaction.rs` — measured 2026-08-15.
# A literal, not `${MIRI_TEST_FLOOR:-49}`: a floor the environment can lower is
# not a floor. Raise it in the commit that adds a test.
MIRI_TEST_FLOOR=49

if ! cargo miri --version >/dev/null 2>&1; then
  echo "FAIL: cargo-miri is not on PATH — this is not the .#fuzz dev shell." >&2
  echo "      cargo:     $(command -v cargo || echo '(none)')" >&2
  echo "      run it as: nix develop .#fuzz -c $0" >&2
  exit 1
fi

# Listed by Miri's own build, not by a native `cargo test --list`: a `cfg(miri)`
# test exists in one and not the other, and the roster has to be the one that runs.
#
# `sort -u` is load-bearing. The dev shell sets `-Zmiri-many-seeds=0..8`, so Miri
# re-executes each test binary once per seed and `--list` prints the whole roster
# eight times over — 392 lines for 49 tests, measured. Without the dedup the shards
# would be slices of a list with eight copies of everything.
mapfile -t tests < <(cargo miri test --manifest-path "$MANIFEST" -- --list 2>/dev/null | sed -n 's/: test$//p' | sort -u)

echo "roster: ${#tests[@]} tests (floor ${MIRI_TEST_FLOOR})"
if [ "${#tests[@]}" -lt "$MIRI_TEST_FLOOR" ]; then
  echo "::error::--list yielded ${#tests[@]} tests, under the ${MIRI_TEST_FLOOR} floor — the roster shrank or the list failed"
  exit 1
fi

MIRI_SHARD="${MIRI_SHARD:-1/1}"
shard_i="${MIRI_SHARD%%/*}"
shard_n="${MIRI_SHARD##*/}"
if ! [ "$shard_i" -ge 1 ] 2>/dev/null || ! [ "$shard_i" -le "$shard_n" ] 2>/dev/null; then
  echo "::error::MIRI_SHARD=$MIRI_SHARD is not i/k with 1 <= i <= k"
  exit 1
fi

# Round-robin, and expressed as everything-but-mine: one Miri process per shard
# instead of one per test, because Miri re-interprets std's startup on every
# process and that cost would dwarf the tests on a shard this size.
skip=()
mine=0
for i in "${!tests[@]}"; do
  if [ $((i % shard_n)) -eq $((shard_i - 1)) ]; then
    mine=$((mine + 1))
  else
    skip+=(--skip "${tests[$i]}")
  fi
done
if [ "$mine" -eq 0 ]; then
  echo "::error::shard ${MIRI_SHARD} selected no tests from ${#tests[@]}"
  exit 1
fi
echo "shard ${MIRI_SHARD}: ${mine} of ${#tests[@]} tests"

# What the shard will actually run, asked of the same lister that built the
# roster. `--list` honours `--skip` (25 -> 23 on a scratch crate, measured), so a
# skip name that stopped matching shows up HERE, before the run is spent, and a
# stale list can no longer quietly widen or narrow a shard.
#
# This replaces counting what the run reported, which cannot be done: the eight
# seed processes write to one stdout concurrently and shred each other's lines —
# `test result: test result: okokokok. 0 passed;` is verbatim from a run that
# passed. `scripts/kani.sh` refuses `--jobs` over the same hazard.
selected="$(cargo miri test --manifest-path "$MANIFEST" -- --list ${skip[@]+"${skip[@]}"} 2>/dev/null | sed -n 's/: test$//p' | sort -u | wc -l | tr -d ' ')"
if [ "${selected:-0}" -ne "$mine" ]; then
  echo "::error::shard ${MIRI_SHARD} selects ${selected:-0} tests, expected ${mine} — a --skip name no longer matches"
  exit 1
fi

cargo miri test --manifest-path "$MANIFEST" -- ${skip[@]+"${skip[@]}"}
echo "miri: shard ${MIRI_SHARD}, ${mine} of ${#tests[@]} tests, no UB"
