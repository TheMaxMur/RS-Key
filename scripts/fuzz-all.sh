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

failed=""
for t in "${targets[@]}"; do
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
echo "fuzz: ${#targets[@]} targets, ${FUZZ_SECONDS}s each, no crashes"
