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

# Two TLA+ traps that leave a spec well-formed and a run GREEN -- a precedence
# slip that turns an assignment into a guard, and an action pinned to a no-op by
# its own UNCHANGED. Both have bitten this model. Checking anything before the
# source is clean would be checking the wrong spec.
python3 tla-lint.py || exit 2

# Which module a configuration belongs to: the seam configs are the second
# module's, and TLC takes the module name rather than reading it from the cfg.
spec_for() { case "$1" in Seam*) echo RSKeyAppletSeams ;; *) echo RSKeySecurityState ;; esac; }

# floors.txt: what each configuration must produce. First match wins.
expect_for() {
  local cfg=$1 pat rest
  while read -r pat rest; do
    case "$pat" in '\*'|''|'#'*) continue ;; esac
    # shellcheck disable=SC2254 -- $pat is a glob on purpose
    case "$cfg" in $pat) echo "$rest"; return ;; esac
  done < floors.txt
  echo ""
}

FAILED=0

one() {
  local cfg=$1 log="out/${1%.cfg}.log" SPEC
  SPEC=$(spec_for "$cfg")
  mkdir -p out
  local want floor heap
  read -r want floor heap <<< "$(expect_for "$cfg")"
  local t0 t1 cov=()
  # THE VACUITY QUESTION, and it is the same one `kani::cover!` answers: an
  # action that never fires makes every clause guarding it free. COVERAGE=1
  # asks TLC for the per-action firing counts and refuses on a zero.
  [ "${COVERAGE:-0}" = 1 ] && cov=(-coverage 5)
  t0=$(date +%s)
  "$JAVA" -XX:+UseParallelGC -Xmx"${HEAP_OVERRIDE:-${heap:-$HEAP}}" -cp "$JAR" tlc2.TLC \
      -nowarning -workers "$WORKERS" "${cov[@]+"${cov[@]}"}" -config "$cfg" "$SPEC" \
      > "$log" 2>&1
  t1=$(date +%s)
  if [ "${COVERAGE:-0}" = 1 ]; then
    local dead
    dead=$(grep -oE '^<[A-Za-z_][A-Za-z0-9_]* line [0-9]+.*>: [0-9]+:0$' "$log" \
             | sed -E 's/^<([A-Za-z_][A-Za-z0-9_]*) .*/\1/' | sort -u | tr '\n' ' ')
    if [ -n "$dead" ]; then
      echo "run-tlc: DEAD ACTION in $cfg -- never fired: $dead" >&2
      FAILED=$((FAILED + 1))
    fi
  fi
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
    elif [ "${floor:--}" != "-" ] && [ -n "${floor:-}" ] \
         && [ "${distinct:-0}" -lt "$floor" ]; then
      # The VACUOUS rule above only sees the collapse all the way to nothing.
      # A run that merely got SMALL is the same failure with a survivor.
      verdict="FLOOR: $distinct < $floor"
    else
      verdict="GREEN"
    fi
  else
    verdict="RED: $(grep -oE 'Invariant [A-Za-z]+ is violated' "$log" | head -1 \
                     | sed 's/Invariant //; s/ is violated//')"
    [ "$verdict" = "RED: " ] && verdict="RED: $(grep -m1 -E '^Error' "$log")"
  fi
  # A mutant that stops firing is the one failure this apparatus exists to
  # avoid, and it does not look like a failure: BugSetPinKeepsPpuat explored
  # 40 459 667 states without a counterexample once a fix made its defect
  # unreachable, and only a human reading the matrix noticed.
  local mark="" got=${verdict%%:*}
  if [ -n "${want:-}" ] && [ "$want" != "$got" ]; then
    mark="  !! expected $want"
    FAILED=$((FAILED + 1))
  fi
  printf '%-42s %-38s states=%-9s distinct=%-8s depth=%-3s %ss%s\n' \
    "$cfg" "$verdict" "${states:-?}" "${distinct:-?}" "${depth:-?}" "$((t1-t0))" \
    "$mark"
}

if [ "${1:-}" = "all" ]; then
  one Shipped.cfg              # the tree as it stands -- expected GREEN
  one Historical_E76.cfg       # each shipped fix taken back out, so the
  one Historical_E77.cfg       # counterexample it closed stays reproducible
  for f in Mut_*.cfg; do one "$f"; done   # mutant vs the whole invariant set
  for f in Solo_*.cfg; do one "$f"; done  # mutant vs its own target only
  for f in SoloClause_*.cfg; do one "$f"; done  # and vs ONE clause of it
  one Fairness.cfg                        # the one fairness assumption that is
  for f in FairMut_*.cfg; do one "$f"; done # a disjunction, and E160 verbatim
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

if [ "$FAILED" -gt 0 ]; then
  echo "run-tlc: FAIL -- $FAILED row(s) did not produce what was required of them" >&2
  exit 1
fi
