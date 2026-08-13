#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Run TLC over one configuration, or over all of them (`./run-tlc.sh all`).
# Runs are SEQUENTIAL and capped at 2 workers on purpose: this machine also
# carries the conformance tracks, and a TLC run that starves them is worse than
# a slow one. Timings printed here were taken under that load -- they are an
# upper bound, not a benchmark.
#
# TLA+ is deliberately NOT in flake.nix (208 MB, and that is the maintainer's
# call). Only the 2.2 MB tla2tools.jar is needed; the JRE comes from the host:
#
#   nix build --no-link --print-out-paths \
#     "$(nix eval --raw nixpkgs#tlaplus.src.drvPath 2>/dev/null || true)"
#
# The jar below was realized with the exact command recorded in FORMAL-L2.md.
set -uo pipefail
cd "$(dirname "$0")"

JAR=${TLA2TOOLS_JAR:-/nix/store/kvrhq0951riz03ffwiskcyr0dymg6k5g-tla2tools.jar}
JAVA=${JAVA:-$(command -v java)}
WORKERS=${WORKERS:-2}
HEAP=${HEAP:-4g}

[ -r "$JAR" ] || { echo "tla2tools.jar not found at $JAR" >&2; exit 2; }
[ -n "$JAVA" ] || { echo "no java on PATH" >&2; exit 2; }

# Which module a configuration belongs to: the seam configs are the second
# module's, and TLC takes the module name rather than reading it from the cfg.
spec_for() { case "$1" in Seam*) echo RSKeyAppletSeams ;; *) echo RSKeySecurityState ;; esac; }

one() {
  local cfg=$1 log="out/${1%.cfg}.log" SPEC
  SPEC=$(spec_for "$cfg")
  mkdir -p out
  local t0 t1
  t0=$(date +%s)
  "$JAVA" -XX:+UseParallelGC -Xmx"$HEAP" -cp "$JAR" tlc2.TLC \
      -nowarning -workers "$WORKERS" -config "$cfg" "$SPEC" > "$log" 2>&1
  t1=$(date +%s)
  local states distinct depth verdict
  states=$(grep -oE '^[0-9]+ states generated' "$log" | tail -1 | cut -d' ' -f1)
  distinct=$(grep -oE '[0-9]+ distinct states found' "$log" | tail -1 | cut -d' ' -f1)
  depth=$(grep -oE 'depth of the complete state graph search is [0-9]+' "$log" \
            | tail -1 | grep -oE '[0-9]+$')
  if grep -q 'Model checking completed. No error has been found' "$log"; then
    # A GREEN run over a state space that never took a step is not a pass, it is
    # a spec nothing enabled -- which is how `Seams.cfg` first came back GREEN
    # over ONE distinct state, on a conjunct that TLA+ precedence had turned into
    # an extra guard (`fresh' = x /\ fresh` is `(fresh' = x) /\ fresh`). Every
    # invariant holds vacuously there. Two is the floor because it is not a
    # judgement call: below it the Next relation fired nothing at all.
    if [ "${distinct:-0}" -lt 2 ] || [ "${depth:-0}" -lt 2 ]; then
      verdict="VACUOUS: nothing was enabled"
    else
      verdict="GREEN"
    fi
  else
    verdict="RED: $(grep -oE 'Invariant [A-Za-z]+ is violated' "$log" | head -1 \
                     | sed 's/Invariant //; s/ is violated//')"
    [ "$verdict" = "RED: " ] && verdict="RED: $(grep -m1 -E '^Error' "$log")"
  fi
  printf '%-42s %-38s states=%-9s distinct=%-8s depth=%-3s %ss\n' \
    "$cfg" "$verdict" "${states:-?}" "${distinct:-?}" "${depth:-?}" "$((t1-t0))"
}

if [ "${1:-}" = "all" ]; then
  one Shipped.cfg              # the tree as it stands -- expected GREEN
  one Historical_E76.cfg       # each shipped fix taken back out, so the
  one Historical_E77.cfg       # counterexample it closed stays reproducible
  for f in Mut_*.cfg; do one "$f"; done   # mutant vs the whole invariant set
  for f in Solo_*.cfg; do one "$f"; done  # mutant vs its own target only
  one Liveness.cfg                        # the three temporal properties, and
  for f in LiveMut_*.cfg; do one "$f"; done # one mutant per property
  one Seams.cfg                           # the second module: the applet seams
  for f in SeamMut_*.cfg; do one "$f"; done
  for f in SeamSolo_*.cfg; do one "$f"; done
  # Liveness_Full.cfg is NOT here: 1475 s for the same verdict the reduced
  # constants give in 139 s. Run it by hand when the reduction is questioned.
else
  one "${1:?usage: run-tlc.sh <config.cfg> | all}"
fi
