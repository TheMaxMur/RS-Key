#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The Kani roster, in tiers, with one owner.
#
# The proofs used to run in one place — the daily `deep-checks` row — because one
# harness in `rsk-rescue` costs ~80 minutes and nothing that expensive belongs on
# a pull request. But that put every proof a day away from the change that broke
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

# SLOW: the arithmetic and the state sequences. `rsk-rescue` carries the ~80 min
# `serialize_parse_roundtrip`, `rsk-rsa-asm` the functional division spec and the
# sieve, `rsk-mldsa` the rounding round-trips, `rsk-fido` the three sequence
# proofs (~12 min together, and one of them peaks at 9.3 GiB).
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
# silently. Raise these in the commit that adds a harness; lower one only in the
# commit that removes one.
FLOOR_pr=49
FLOOR_state=8
FLOOR_all=64

# The per-harness cap. Not per row — Kani runs the rest and fails at the end — so
# it bounds one non-convergent proof, never the tier.
TIMEOUT_pr=5m
TIMEOUT_state=30m
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

eval "floor=\${FLOOR_$tier} timeout=\${TIMEOUT_$tier}"

packages=""
for c in $crates; do
  packages="$packages -p $c"
done

log=$(mktemp)
echo "== kani ($tier): $(echo "$crates" | xargs | tr ' ' ',') =="
# `tee`, not a redirect: the harness output belongs on the console. `pipefail`
# (set above) keeps cargo-kani's own failure the pipeline's, so a real property
# violation ends the run here and never reaches the floor check below.
# shellcheck disable=SC2086 # $packages is our own list, word-splitting intended
cargo kani $packages -Z unstable-options --harness-timeout "$timeout" "$@" 2>&1 | tee "$log"

# Kani's own count, off its summary line: "Complete - N successfully verified
# harnesses, 0 failures, N total."
proved=$(sed -n 's/^Complete - .*, \([0-9][0-9]*\) total\.$/\1/p' "$log" | tail -1)
rm -f "$log"
if [ -z "$proved" ]; then
  echo "FAIL: kani tier '$tier' printed no summary line — it proved nothing." >&2
  exit 1
fi
if [ "$proved" -lt "$floor" ]; then
  echo "FAIL: kani tier '$tier' proved $proved harnesses, under the $floor floor." >&2
  echo "      A roster that selects nothing exits 0 and reads as a pass." >&2
  exit 1
fi
echo "kani ($tier): $proved harnesses proved (floor $floor)"
