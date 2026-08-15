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
# TLA+ comes from the dev shell now, which is what lets a workflow run this at
# all: the jar path and its JVM are `nix develop`'s to supply, not this file's.
# It used to name a /nix/store path realized by hand on one machine -- correct
# there, unreadable anywhere else, and so the whole matrix was a ratchet only
# its author could pull. The pinned jar is byte-identical to that one
# (sha256 936a2620...), so `floors.txt` still describes the TLC that measured it.
set -uo pipefail
cd "$(dirname "$0")"

JAR=${TLA2TOOLS_JAR:-}
JAVA=${JAVA:-$(command -v java)}
WORKERS=${WORKERS:-2}
HEAP=${HEAP:-4g}

# `--tiers` is a pure query -- scripts/assurance_gate.py reads it to hold every
# .cfg against the tier union -- so it must answer without a jar, a JVM or a
# lint pass. Everything else pays the toll.
if [ "${1:-}" != "--tiers" ]; then
  [ -n "$JAR" ] || { echo "TLA2TOOLS_JAR unset -- run inside \`nix develop\`" >&2; exit 2; }
  [ -r "$JAR" ] || { echo "tla2tools.jar not readable at $JAR" >&2; exit 2; }
  [ -n "$JAVA" ] || { echo "no java on PATH -- run inside \`nix develop\`" >&2; exit 2; }

  # Two TLA+ traps that leave a spec well-formed and a run GREEN -- a precedence
  # slip that turns an assignment into a guard, and an action pinned to a no-op
  # by its own UNCHANGED. Both have bitten this model. Checking anything before
  # the source is clean would be checking the wrong spec.
  python3 tla-lint.py || exit 2
fi

# Which module a configuration belongs to: the seam configs are the second
# module's, and TLC takes the module name rather than reading it from the cfg.
spec_for() { case "$1" in Seam*) echo RSKeyAppletSeams ;; Store*) echo RSKeyStore ;; Lat*) echo RSKeyRetryLattice ;; Admin*) echo RSKeyAdminSurface ;; Disp*) echo RSKeyTrustedDisplay ;; Boot*) echo RSKeyBootHardening ;; *) echo RSKeySecurityState ;; esac; }

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

# --- the tiers -------------------------------------------------------------
#
# Membership lives here and nowhere else, the way scripts/kani.sh owns its own.
# The split is drawn by HEAP, not by taste: everything in `safety` runs at the
# 4g default, while `Liveness.cfg` needs the 12g `floors.txt` gives it -- and a
# hosted runner is where kani's 11.1 GB harness already died twice. So `safety`
# is the weekly CI row and `liveness` is run by hand, or wherever 12g is real.
#
# `all` is still the union, so a local `./run-tlc.sh all` means what it always did.
#
# Each tier is a LIST function, and the run functions iterate it -- so `--tiers`
# prints exactly what a run would execute, the way scripts/kani.sh does it, and
# scripts/assurance_gate.py can hold every .cfg against the union without a
# second copy of the membership.

list_safety() {
  echo Shipped.cfg              # the tree as it stands -- expected GREEN
  echo Historical_E76.cfg       # each shipped fix taken back out, so the
  echo Historical_E77.cfg       # counterexample it closed stays reproducible
  ls Mut_*.cfg                  # mutant vs the whole invariant set
  ls Solo_*.cfg                 # mutant vs its own target only
  ls SoloClause_*.cfg           # and vs ONE clause of it
  echo Fairness.cfg             # the one fairness assumption that is
  ls FairMut_*.cfg              # a disjunction, and E160 verbatim
  echo Seams.cfg                # the second module: the applet seams
  ls SeamMut_*.cfg
  ls SeamSolo_*.cfg
  echo Store.cfg                # the third module: the flash layer
  ls StoreMut_*.cfg
  ls StoreSolo_*.cfg
  echo Lattice.cfg             # the fourth module: the retry/recovery lattice
  ls LatMut_*.cfg
  ls LatSolo_*.cfg
  echo Admin.cfg               # the fifth module: the administrative surface
  ls AdminMut_*.cfg
  ls AdminSolo_*.cfg
  echo Display.cfg             # the sixth module: the trusted-display ceremony
  ls DispMut_*.cfg
  ls DispSolo_*.cfg
  echo Boot.cfg                # the seventh module: the cross-boot hardening
  ls BootMut_*.cfg
  ls BootSolo_*.cfg
}

list_liveness() {
  echo Liveness.cfg             # the three temporal properties, and
  ls LiveMut_*.cfg              # one mutant per property
  # Liveness_Full.cfg is NOT here: 1475 s for the same verdict the reduced
  # constants give in 139 s. Run it by hand when the reduction is questioned.
}

run_tier() { local f; for f in $($1); do one "$f"; done; }

case "${1:-}" in
  --tiers)  echo "safety: $(list_safety | tr '\n' ' ')"
            echo "liveness: $(list_liveness | tr '\n' ' ')"
            exit 0 ;;
  safety)   run_tier list_safety ;;
  liveness) run_tier list_liveness ;;
  all)      run_tier list_safety; run_tier list_liveness ;;
  *)        one "${1:?usage: run-tlc.sh <config.cfg> | safety | liveness | all | --tiers}" ;;
esac

if [ "$FAILED" -gt 0 ]; then
  echo "run-tlc: FAIL -- $FAILED row(s) did not produce what was required of them" >&2
  exit 1
fi
