#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Cognitive-complexity ratchet. Runs in `check.sh` (so a hotspot is caught before
# it is pushed, not the next night) and in deep-checks, the sibling of the
# coverage floor: it fails when ANY
# non-test function in the crate libraries crosses the cognitive ceiling, so a
# new hotspot trips the moment it lands instead of at the next manual
# metrics.sh pass. It is a ratchet — when a refactor lowers the peak, lower the
# ceiling in the same commit to lock the win in; raise it, with a stated reason,
# only when a function legitimately must grow.
#
# Scope is `crates/*/src` — the host-testable libraries that are the project's
# home for logic and the target of every complexity refactor so far. `firmware/`
# is deliberately out: it is embedded-only glue plus the trusted-display UI
# subsystem (screen state machines that carry inherent, HW-gated complexity),
# whose reduction is a separate effort, not a per-day alarm.
#
# rust-code-analysis is pulled ad-hoc via `nix shell --inputs-from .` (as in
# scripts/metrics.sh and the pages workflow): its version is pinned to the
# flake's nixpkgs so the gate scores deterministically across CI runs, yet it
# never joins the pinned dev shell / SBOM trust base — it only reads source,
# never a shipping build.
set -euo pipefail
cd "$(dirname "$0")/.."

# The current crate peak is 35 (`rsk_fido::credmgmt::enumerate_creds`), which is
# the ceiling itself — there is no headroom left, so the next function to reach it
# trips this. Ratchet the ceiling down as the peak falls; do not raise it to buy
# room for a hotspot, which is what the alarm is for.
COGNITIVE_CEILING="${COGNITIVE_CEILING:-35}"

mapfile -t src < <(find crates -maxdepth 2 -type d -name src | sort)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rca_args=()
for c in "${src[@]}"; do rca_args+=(-p "$c"); done
nix shell --inputs-from . nixpkgs#rust-code-analysis -c rust-code-analysis-cli -m -O json -o "$tmp" "${rca_args[@]}"
python3 scripts/metrics_complexity.py "$tmp" --max-cognitive "$COGNITIVE_CEILING"
