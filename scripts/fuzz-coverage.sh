#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Per-target libFuzzer coverage — advisory reporter, NOT a gate (the sibling of
# scripts/metrics.sh). For each cargo-fuzz target it replays the accumulated
# corpus under `-Cinstrument-coverage`, then renders rust's own llvm-cov into a
# per-target HTML report plus one summary-table row. Nothing here gates a commit;
# the host-crate coverage floor lives in the deep-checks `coverage` job, not fuzz.
# Run inside the nightly fuzz shell:
#   nix develop .#fuzz -c ./scripts/fuzz-coverage.sh [target ...]
# No args ⇒ every target (`cargo fuzz list`); pass names to scope it. Output lands
# in fuzz/coverage/<target>/{coverage.profdata,html/} (all git-ignored).
set -euo pipefail
cd "$(dirname "$0")/.."

# llvm-cov MUST be the one from the same nightly toolchain as the instrumented
# build (rust's own llvm-tools): a version-mismatched nixpkgs llvm-cov cannot
# parse the embedded coverage map. Pin it to the active sysroot.
host="$(rustc -vV | sed -n 's/^host: //p')"
llvm_cov="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-cov"
if [ ! -x "$llvm_cov" ]; then
  echo "no rust llvm-cov at $llvm_cov — run inside 'nix develop .#fuzz'" >&2
  exit 1
fi

# A dedicated target-dir keeps the instrumented build at a deterministic path
# (<dir>/<host>/release/<target>) and off the fuzzing build tree; cargo-fuzz
# writes the merged profdata to fuzz/coverage/<target>/ regardless of this.
covbuild="fuzz/coverage/.build"
# Drop the libFuzzer shims, the vendored deps and the std/rustc sources from the
# report — we measure OUR parser/dispatch surface, not the glue around it.
ign='(fuzz/fuzz_targets/|/\.cargo/registry/|/rustc/|/library/|/rustlib/)'

# Same floor and same reason as the deep-checks fuzz loop: `set -e` does not fire
# on an empty or failing $( ) in a `for` word list, so a broken `cargo fuzz list`
# printed an empty table and exited 0. Lower both floors in the same commit.
# A literal, not `${FUZZ_TARGET_FLOOR:-53}`: a floor the environment can lower is
# not a ratchet, so `env FUZZ_TARGET_FLOOR=… ` in front of this script does nothing.
FUZZ_TARGET_FLOOR=53
targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
  mapfile -t targets < <(cargo fuzz list)
  if [ "${#targets[@]}" -lt "$FUZZ_TARGET_FLOOR" ]; then
    echo "FAIL: cargo fuzz list yielded ${#targets[@]} targets, under the ${FUZZ_TARGET_FLOOR} floor." >&2
    exit 1
  fi
fi
# The numbers below are only as good as the corpus behind them, and in CI that
# corpus is one evictable cache entry.
echo "${#targets[@]} target(s), corpus: $(find fuzz/corpus -type f 2>/dev/null | wc -l) inputs"

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
printf '### libFuzzer per-target coverage\n\n| target | regions | lines |\n|---|---|---|\n' >> "$summary"

for t in "${targets[@]}"; do
  echo "== coverage: $t =="
  # cargo-fuzz merges EVERY profraw it ever wrote here and never clears it, so a
  # local number could only go up: two unrelated corpora returned byte-identical
  # percentages. CI is unaffected — it caches .build, never raw/.
  rm -rf "fuzz/coverage/$t/raw"
  # Replay the accumulated corpus under instrumentation → merged profdata. A
  # target with an empty/absent corpus or a build hiccup must not abort the rest.
  if ! cargo fuzz coverage "$t" --target-dir "$covbuild"; then
    printf '| %s | (coverage failed) | |\n' "$t" >> "$summary"
    continue
  fi
  bin="$covbuild/$host/release/$t"
  prof="fuzz/coverage/$t/coverage.profdata"
  if [ ! -f "$bin" ] || [ ! -f "$prof" ]; then
    printf '| %s | (no data) | |\n' "$t" >> "$summary"
    continue
  fi
  "$llvm_cov" show "$bin" -instr-profile="$prof" -ignore-filename-regex="$ign" \
    -format=html -output-dir="fuzz/coverage/$t/html" >/dev/null
  # `llvm-cov report`'s TOTAL row: field 4 = region cover %, field 10 = line cover %.
  row="$("$llvm_cov" report "$bin" -instr-profile="$prof" -ignore-filename-regex="$ign" \
    | awk '/^TOTAL/ { print $4 " | " $10 }')"
  printf '| %s | %s |\n' "$t" "${row:-(no lines) | }" >> "$summary"
done

echo "per-target HTML in fuzz/coverage/<target>/html/index.html"
