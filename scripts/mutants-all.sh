#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Mutation testing over the host crates — the weekly deep-checks `mutants` row,
# and the same roster over the lines one diff touches.
#
#   nix develop -c ./scripts/mutants-all.sh
#   MUTANTS_SHARD=2/12 nix develop -c ./scripts/mutants-all.sh
#   nix develop -c ./scripts/mutants-all.sh --in-diff HEAD      # uncommitted work
#   nix develop -c ./scripts/mutants-all.sh --in-diff HEAD~1    # the last commit
#
# Coverage says a line ran. This says a test would notice if that line changed,
# which is a different question and the one this tree keeps getting wrong: the
# first full sweep (13 232 mutants, 2026-08-15) found `require_pin_inputs`
# replaceable by `Ok(())` with the gate green, and the trusted display's four
# applet loaders driven by no test at all.
#
# The sweep gates against scripts/mutants-accepted.txt, not against zero: 3247 of
# that first sweep's mutants survived and most are not defects — code behind an
# off `cfg`, a guard a deeper guard masks, a coordinate no test pins on purpose —
# so each is recorded there, under the class that says why. A shard fails on
# a survivor the file does not hold, on an entry a test now catches, and on an
# entry whose mutant no longer exists; the file's header says how to move one.
# It also fails on its own apparatus: a shard that tested nothing, or a run that
# produced no summary at all.
#
# `--in-diff <base>` (default `origin/main`) mutates only the lines the working
# tree changes against its merge base with <base>, untracked files under crates/
# included. No baseline and no floor: it exits 2 when a mutant on those lines
# survives, for the fix loop to read, and 0 when none does or none exists.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
OUT="${MUTANTS_OUT:-target/mutants}"
ACCEPTED=scripts/mutants-accepted.txt

# Measured 13 232 on 2026-08-15 over these crates. A floor with margin, not a
# ratchet: its job is to catch a selection that collapsed — a `-p` roster that
# stopped matching, an exclude glob that ate the tree — not to police the count,
# which moves with every commit.
MUTANT_FLOOR=10000

base=""
case "${1:-}" in
  "") ;;
  --in-diff) base="${2:-origin/main}" ;;
  *) echo "usage: $0 [--in-diff [<base>]]" >&2; exit 2 ;;
esac

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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# cargo-mutants creates its output directory but not the parent, and on a runner
# whose `target/` cache missed there is no parent to create it in: "create output
# parent directory target/mutants: No such file or directory", five shards of the
# first real run. The apparatus check below is what caught it — the row failed as
# "no summary line" rather than passing with nothing tested.
mkdir -p "$OUT"

# `|| true` on each run deliberately: cargo-mutants exits non-zero when mutants
# survive, which on this row is an outcome to read, not a failure. The summary
# line is what says the run happened, so a crash cannot pass as "none survived".
run_summary() {
  local summary
  summary="$(grep -E '^[0-9]+ mutants tested' "$tmp/log" | tail -1 || true)"
  if [ -z "$summary" ]; then
    echo "::error::$1 produced no summary line — the run did not finish" >&2
    exit 1
  fi
  if [ "${summary%% *}" -eq 0 ]; then
    echo "::error::$1 tested 0 mutants" >&2
    exit 1
  fi
  printf '%s' "$summary"
}

# A mutant's name without `:LINE:COL`, which moves with every edit above it.
names() { sed -E 's/^([^:]+):[0-9]+:[0-9]+: /\1: /; s/[[:space:]]+$//' "$@" | grep -v '^$' || true; }

if [ -n "$base" ]; then
  mb="$(git merge-base "$base" HEAD)"
  {
    git diff "$mb"
    # `git diff` does not show a file git has never seen, and a fix's new
    # module is exactly the code that most needs a test that notices it.
    git ls-files --others --exclude-standard -- 'crates/*.rs' | while read -r f; do
      git diff --no-index -- /dev/null "$f" || true
    done
  } > "$tmp/diff"
  # Not piped into the count: an empty diff or one with no Rust in it lists
  # nothing at rc 0, so a failing list is a failure, not "no mutants".
  cargo-mutants mutants --list --in-diff "$tmp/diff" "${common[@]}" > "$tmp/list"
  n="$(grep -cE '^crates/' "$tmp/list" || true)"
  echo "in-diff: ${n} mutants on the lines this tree changes against ${base} (${mb:0:12})"
  [ "$n" -gt 0 ] || exit 0
  cargo-mutants mutants --in-diff "$tmp/diff" "${common[@]}" \
    -j "${MUTANTS_JOBS:-4}" --output "$OUT" 2>&1 | tee "$tmp/log" || true
  summary="$(run_summary "the in-diff run")"
  echo "mutants: in-diff, ${summary}"
  names "$OUT/mutants.out/missed.txt" > "$tmp/missed"
  if [ -s "$tmp/missed" ]; then
    echo "$(grep -c . "$tmp/missed") mutant(s) on this diff's lines survived — each is a test to write or a reason to state:"
    sed 's/^/  /' "$tmp/missed"
    exit 2
  fi
  exit 0
fi

# `|| true` because `grep -c` exits 1 on zero matches, and with `set -e` that
# would end the script here — before the floor below could say why.
cargo-mutants mutants --list "${common[@]}" > "$tmp/list"
total="$(grep -cE '^crates/' "$tmp/list" || true)"
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

# cargo-mutants numbers shards from ZERO — `--shard 8/8` is "invalid value: shard
# k must be less than n". Passing this script's 1-based number straight through
# therefore ran indices 1..7 and never index 0: an eighth of the tree silently
# unmutated, while the last shard failed outright. Converted here so the shard
# number means the same thing in every row (`FUZZ_SHARD`, `MIRI_SHARD`, this one)
# and only the flag sees the tool's own convention.
cargo-mutants mutants "${common[@]}" \
  --shard "$((shard_i - 1))/$shard_n" -j "${MUTANTS_JOBS:-4}" --output "$OUT" 2>&1 | tee "$tmp/log" || true
summary="$(run_summary "shard ${MUTANTS_SHARD}")"
echo "mutants: shard ${MUTANTS_SHARD}, ${summary}"

# Per shard, since a shard sees only its slice; "no longer a mutant" is asked
# once, of the whole roster. Counted, not set-compared: one function can carry
# the same mutation twice, and one copy caught is not both.
res="$OUT/mutants.out"
rm -f "$OUT/new-survivors.txt"
names "$res/missed.txt" > "$tmp/missed"
names "$res/caught.txt" > "$tmp/caught"
names "$tmp/list" > "$tmp/roster"
awk '
  /^[[:space:]]*(#|$)/ { next }
  /^\[/ { if ($0 ~ /^\[[^]]+\] [^[:space:]]/) class = 1; else { print "class line with no reason " NR ": " $0 > "/dev/stderr"; bad = 1 }; next }
  !class { print "entry outside a [class] line " NR ": " $0 > "/dev/stderr"; bad = 1; next }
  { sub(/[[:space:]]+$/, ""); print }
  END { exit bad }
' "$ACCEPTED" > "$tmp/accepted" || { echo "::error::$ACCEPTED: every entry sits under a \`[class] reason\` line" >&2; exit 1; }
awk -v first="$([ "$shard_i" -eq 1 ] && echo 1 || echo 0)" -v file="$ACCEPTED" -v new_out="$OUT/new-survivors.txt" '
  FILENAME == ARGV[1] { a[$0]++; next }
  FILENAME == ARGV[2] { m[$0]++; next }
  FILENAME == ARGV[3] { c[$0]++; next }
  { r[$0]++ }
  END {
    for (x in m) if (m[x] > a[x]) {
      for (i = a[x]; i < m[x]; i++) { print "::error::survived, and not in " file ": " x; print x > new_out }
      fail = 1
    }
    for (x in a) {
      if (c[x] && a[x] > m[x]) { print "::error::in " file " and now caught — delete the entry: " x; fail = 1 }
      if (first && !r[x]) { print "::error::in " file " and no longer a mutant of the tree — delete the entry: " x; fail = 1 }
    }
    exit fail
  }
' "$tmp/accepted" "$tmp/missed" "$tmp/caught" "$tmp/roster" && verdict=ok || verdict=red

{
  echo "### mutants shard ${MUTANTS_SHARD}"
  echo
  echo '```'
  echo "$summary"
  echo '```'
  echo
  echo "Gated against \`$ACCEPTED\`: baseline ${verdict}. See docs/testing.md."
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
if [ "$verdict" != ok ]; then
  echo "FAIL: shard ${MUTANTS_SHARD} disagrees with $ACCEPTED; the new survivors, one per line, are in $OUT/new-survivors.txt" >&2
  exit 1
fi
echo "baseline: every survivor of shard ${MUTANTS_SHARD} is accepted, and no entry it can see is stale"
