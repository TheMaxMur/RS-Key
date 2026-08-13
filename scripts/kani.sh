#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The Kani roster, in tiers, with one owner.
#
# The proofs used to run in one place — the daily `deep-checks` row — because one
# harness in `rsk-rescue` costs half an hour or more and nothing that expensive
# belongs on a pull request. But that put every proof a day away from the change that broke
# it, and the split is cheap once the cost is measured rather than assumed: the
# whole fast tier discharges in ~212 s of solving (docs/testing.md carries the
# table), while four crates hold everything slow.
#
# So: `pr` on every pull request that touches the crates, `state` additionally
# when the change reaches the security-state surface those proofs are about, and
# `all` — the union, nothing dropped — daily.
#
# The tier membership lives here and nowhere else. It used to be a hand-written
# `-p` list repeated in the workflow, in the workflow's own header comment and in
# docs/testing.md, kept in step by `scripts/kani_gate.py` comparing the three
# strings; three copies were the most that guard could hold, and a fourth tier
# would have been a fourth copy. `--tiers` prints the table, and that is what the
# guard reads, so the rows the CI runs and the list the guard checks cannot
# disagree.
#
# Usage:
#   scripts/kani.sh <tier> [extra cargo-kani args…]
#   scripts/kani.sh --tiers      # `name: crate crate …` per tier, for the guard
set -euo pipefail
cd "$(dirname "$0")/.."

# --- the tiers ---------------------------------------------------------------
#
# FAST: every crate whose whole harness set discharges in under a minute a
# harness. Measured 2026-08-13 on kani 0.67.0 under load — 49 harnesses, 200 s of
# solving all told, the slowest three being `rsk-piv::set_protected…` at 45 s,
# `rsk-led::every_block_length…` at 44 s and `indices_in_range` at 29 s. The
# `rsk-device` six (the presence arbitration) cost 3 s together, and the four
# `rsk-fs::powercut` rules 0.5 s.
# `--harness-timeout 5m` below is the tripwire on that claim: a harness that
# grows past it fails the PR row rather than quietly making every pull request
# wait, and the answer is to move its crate to SLOW, not to raise the cap.
FAST="rsk-sdk rsk-fs rsk-crypto rsk-openpgp rsk-otp rsk-piv rsk-oath rsk-usb rsk-ui rsk-led rsk-slip39 rsk-bip39 rsk-device"

# SLOW: the arithmetic and the state sequences. `rsk-rescue` carries
# `serialize_parse_roundtrip` (27m42s measured 2026-08-13; ~80 min was recorded
# once), `rsk-rsa-asm` the functional division spec and the sieve, `rsk-mldsa` the
# rounding round-trips, `rsk-fido` the three sequence proofs (~12 min together,
# and one of them peaks at 9.3 GiB).
SLOW="rsk-rescue rsk-rsa-asm rsk-mldsa rsk-fido"

# STATEFUL: the crates whose proofs are about the security state a reset, a wipe
# or a torn write can leave behind -- a cross-cut of the two tiers above
# (rsk-fido is SLOW, rsk-fs is FAST), selected by subject, not by cost. A change
# that reaches them does not get to wait a day for the SLOW half: ci.yml runs
# this tier too when the diff touches rsk-fido, rsk-fs, rsk-store or rsk-wipe.
STATEFUL="rsk-fido rsk-fs"

# Harnesses each tier must prove. A tier that selects nothing is the failure this
# repo has now shipped three times — `cargo test <filter>` matching no test, the
# fuzz row over an empty target list, a `-p` roster missing two thirds of the
# crates — and every one of them exited 0. The floor catches the weaker version
# too: a rename or a deleted `#[cfg(kani)]` hook that takes harnesses away
# silently. These are not kept by hand: `scripts/kani_gate.py` counts the tree's
# `#[kani::proof]` per tier and fails the merge gate on any disagreement. So
# they are a consistency check against the tree, not a ratchet against history:
# deleting a harness and pasting the new number is self-consistent, and only
# the diff shows it.
FLOOR_pr=50
FLOOR_state=8
FLOOR_all=65

# Source-level `kani::cover!`s each tier must report on. Kani 0.67.0 has no
# `--fail-uncoverable`, so an unsatisfiable cover prints "N of M cover properties
# satisfied" and the harness still reports SUCCESSFUL — the row below is what
# turns this tree's "vacuity guards" from comments into checks. Reading nothing
# is caught on its own (the row fails when the per-check listing is absent); the
# floor is for the partial case, a cover that stopped being reported while the
# rest still are. Counted from source by the same guard as the floors above.
COVERS_pr=23
COVERS_state=9
COVERS_all=31

# `kani::cover!` properties CBMC may report unsatisfied while their source-level
# cover is still reached. One `cover!` becomes several properties wherever the
# enclosing MIR branches on something the condition re-tests, and the copies on
# the contradicting arms are dead by construction; the row below groups by source
# location so those do not fail it. This ceiling is what keeps that allowance
# from being unbounded — measured, the whole tree has exactly one
# (`rebuild_meta_any_blob`'s `!with_new` arm), and a second means a copy stopped
# being reachable for a reason nobody has looked at.
DEAD_COVER_COPIES_MAX=1

# The per-harness cap. Kani runs the rest and fails at the end, so it bounds one
# non-convergent proof rather than the tier — but the run then exits 1, `pipefail`
# ends this script at the `tee`, and none of the checks below is reached (measured).
TIMEOUT_pr=5m
TIMEOUT_state=30m
# 27m42s against this 30m, an 8% margin, and a slower box tips it — at which point
# the row fails on a correct harness and `FLOOR_all` is never read at all.
TIMEOUT_all=30m

# The one owner of tier → crates. `--tiers` and the run path both come through
# here, so a tier the guard is shown is a tier that would actually run.
crates_of() {
  case "$1" in
    pr) echo "$FAST" ;;
    state) echo "$STATEFUL" ;;
    all) echo "$FAST $SLOW" ;;
    *) return 1 ;;
  esac
}

TIERS="pr state all"

usage() {
  echo "usage: $0 {${TIERS// /|}} [cargo-kani args…]" >&2
  echo "       $0 --tiers" >&2
}

if [ "${1:-}" = "--tiers" ]; then
  for tier in $TIERS; do
    # `xargs` normalizes the spacing so the guard compares crate sets, not
    # whitespace.
    echo "$tier: $(crates_of "$tier" | xargs)"
  done
  exit 0
fi

tier="${1:-}"
shift || true
crates="$(crates_of "$tier")" || {
  usage
  exit 2
}

# The cover groups below are keyed by the harness whose `Checking harness` line
# came last, so running harnesses in parallel interleaves the listing and files a
# cover under the wrong one. Refused, not parsed around: an interleaved log gives
# a wrong verdict quietly, which is the failure this row exists to end.
for arg in "$@"; do
  case "$arg" in
  -j* | --jobs*)
    echo "FAIL: $0 will not run harnesses in parallel ('$arg')." >&2
    echo "      The kani::cover! verdicts are read per harness out of Kani's" >&2
    echo "      per-check listing, and parallel harnesses interleave it." >&2
    exit 2
    ;;
  esac
done

eval "floor=\${FLOOR_$tier} timeout=\${TIMEOUT_$tier} cover_floor=\${COVERS_$tier}"

packages=""
for c in $crates; do
  packages="$packages -p $c"
done

log=$(mktemp)
# `set -e` + `pipefail` end this script at the `tee` on any failing run, so an
# explicit `rm` below it never runs — and a tripped --harness-timeout is now a
# known way to get there.
trap 'rm -f "$log"' EXIT
echo "== kani ($tier): $(echo "$crates" | xargs | tr ' ' ',') =="
# `tee`, not a redirect: the harness output belongs on the console. `pipefail`
# (set above) keeps cargo-kani's own failure the pipeline's, so a real property
# violation ends the run here and never reaches the floor check below.
# shellcheck disable=SC2086 # $packages is our own list, word-splitting intended
cargo kani $packages -Z unstable-options --harness-timeout "$timeout" "$@" 2>&1 | tee "$log"

# Kani's own count, off its summary line: "Complete - N successfully verified
# harnesses, 0 failures, N total."
proved=$(sed -n 's/^Complete - .*, \([0-9][0-9]*\) total\.$/\1/p' "$log" | tail -1)

# One group per source-level `kani::cover!`, keyed by harness and source
# location. NOT the "N of M cover properties satisfied" summary line: one
# `cover!` becomes several CBMC properties wherever the enclosing MIR branches on
# something the condition re-tests, and the copies on the arms that contradict it
# are dead by construction. `rebuild_meta_any_blob` is the worked example — its
# `!with_new && …` cover is reported twice, once UNSATISFIABLE on the `with_new`
# arm and once SATISFIED, and the summary line says "2 of 3". A row that failed
# on the summary would go red on a cover that is genuinely reached.
cover_report=$(awk '
  /^Checking harness / { h = $3; sub(/\.\.\.$/, "", h); next }
  /^Check [0-9]+: / { c = ($0 ~ /\.cover\.[0-9]+[ \t\r]*$/); s = ""; next }
  c && /^[ \t]*- Status:/ { s = $NF; next }
  c && /^[ \t]*- Location:/ {
    k = h " " $3
    if (!(k in seen)) { seen[k] = 1; order[++n] = k }
    if (s == "SATISFIED") live[k] = 1; else copies++
    c = 0
  }
  END {
    for (i = 1; i <= n; i++) if (!(order[i] in live)) print "dead " order[i]
    print "seen " n
    print "copies " copies + 0
  }
' "$log")
cover_dead=$(printf '%s\n' "$cover_report" | sed -n 's/^dead //p')
cover_seen=$(printf '%s\n' "$cover_report" | sed -n 's/^seen //p')
cover_copies=$(printf '%s\n' "$cover_report" | sed -n 's/^copies //p')
if [ -z "$proved" ]; then
  echo "FAIL: kani tier '$tier' printed no summary line — it proved nothing." >&2
  exit 1
fi
if [ "$proved" -lt "$floor" ]; then
  echo "FAIL: kani tier '$tier' proved $proved harnesses, under the $floor floor." >&2
  echo "      A roster that selects nothing exits 0 and reads as a pass." >&2
  exit 1
fi
if [ -z "$cover_seen" ]; then
  echo "FAIL: kani tier '$tier' printed no per-check listing — the cover verdicts" >&2
  echo "      could not be read at all, which is not the same as none being dead." >&2
  exit 1
fi
if [ -n "$cover_dead" ]; then
  echo "FAIL: kani tier '$tier' left these kani::cover! unreached:" >&2
  printf '%s\n' "$cover_dead" | sed 's/^/        /' >&2
  echo "      Nothing satisfies them, so every assertion they guard holds over an" >&2
  echo "      empty region. Kani exits 0 on this by itself." >&2
  exit 1
fi
if [ "$cover_seen" -lt "$cover_floor" ]; then
  echo "FAIL: kani tier '$tier' reported $cover_seen kani::cover!, under the $cover_floor floor." >&2
  echo "      A cover that stopped being reported is one nobody is checking." >&2
  exit 1
fi
if [ "$cover_copies" -gt "$DEAD_COVER_COPIES_MAX" ]; then
  echo "FAIL: kani tier '$tier' left $cover_copies kani::cover! properties unsatisfied," >&2
  echo "      over the $DEAD_COVER_COPIES_MAX ceiling. Their source covers are still reached by some" >&2
  echo "      other copy, so grouping hides them — which is the point of the ceiling." >&2
  exit 1
fi
echo "kani ($tier): $proved harnesses proved (floor $floor), $cover_seen covers reached (floor $cover_floor)"
