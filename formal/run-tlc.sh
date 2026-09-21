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
# Where the logs and TLC's scratch land, knobs because this runner's own mutation
# table drives the REAL script: pointing it into the real `out/` is what put a NUL
# run in a live `Shipped.log` and reported a 48.7 M-state GREEN as VACUOUS.
OUT=${TLC_OUT:-out}
STATES=${TLC_STATES:-states}

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

  # TLC names its metadir after the second, and a run refuted in its initial state
  # leaves it: the next start in that second refused to run at all, which cost a
  # whole safety tier its record once. So every row gets its own directory here.
  mkdir -p "$STATES"
  metaroot=$(mktemp -d "$STATES/run.XXXXXX")
  trap 'rm -rf "$metaroot"' EXIT
  [ -n "$metaroot" ] || { echo "run-tlc: no metadir under $STATES" >&2; exit 2; }
fi

# Which module a configuration belongs to: the seam configs are the second
# module's, and TLC takes the module name rather than reading it from the cfg.
spec_for() { case "$1" in TokenGate*) echo RSKeyTokenGate ;; TokenRefinement*) echo RSKeyTokenRefinement ;; TraceSecurity*) echo TraceSecurity ;; TraceSeamsBad*) echo TraceSeamsBad ;; TraceSeams*) echo TraceSeams ;; Seam*) echo RSKeyAppletSeams ;; Store*) echo RSKeyStore ;; Lat*) echo RSKeyRetryLattice ;; Polic*) echo RSKeyAppletPolicies ;; Admin*) echo RSKeyAdminSurface ;; Disp*) echo RSKeyTrustedDisplay ;; Historical_Boot*|Boot*) echo RSKeyBootHardening ;; Trans*) echo RSKeyTransport ;; *) echo RSKeySecurityState ;; esac; }

# The invariants a configuration checks, in order.
invariants_of() {
  awk '
    /^INVARIANTS?[[:space:]]*$/ { block = 1; next }
    /^INVARIANTS?[[:space:]]+[A-Za-z][A-Za-z0-9_]*[[:space:]]*$/ {
      print $2; block = 0; next
    }
    block && /^[[:space:]]+[A-Za-z][A-Za-z0-9_]*[[:space:]]*$/ { print $1; next }
    block { block = 0 }
  ' "$1"
}

# The invariant a MUTATION configuration says it targets, for the rows where
# floors.txt says nothing: `gen-configs.sh` writes that one first under
# INVARIANTS because TLC reports the first violated invariant and stops, and
# scripts/verdict_gate.py reads the same block to decide solo attribution. So
# this is the generated relation being read, not a second column written by hand.
derived_inv() { invariants_of "$1" | grep -v '^TypeOK$' | head -1; }

# The temporal properties a configuration declares. A run refuted by one of these
# prints `Action property <name> is violated` and no invariant at all, which is a
# RIGHT answer and not a missing one: `TokenRefinementDeadToken.cfg` checks one
# invariant, declares one property, and is RED on the PROPERTY by design -- the
# state stutter it models is legal and the outcome is not. Measured by this rule
# firing on it the first time it ran a whole tier.
properties_of() {
  awk '
    /^PROPERT(Y|IES)[[:space:]]*$/ { block = 1; next }
    /^PROPERT(Y|IES)[[:space:]]+[A-Za-z][A-Za-z0-9_]*[[:space:]]*$/ {
      print $2; block = 0; next
    }
    block && /^[[:space:]]+[A-Za-z][A-Za-z0-9_]*[[:space:]]*$/ { print $1; next }
    block { block = 0 }
  ' "$1"
}

# Whether a RED verdict names something this configuration declares as a property.
names_a_property() {
  local cfg=$1 verdict=$2 name
  while read -r name; do
    [ -n "$name" ] || continue
    case "$verdict" in *"$name"*) return 0 ;; esac
  done < <(properties_of "$cfg")
  return 1
}

# Which defect switches a configuration ARMS. One is what makes the derived
# name the right question. Zero is `TraceSeamsBad.cfg`, which lists invariants and
# is refused by a deadlock, so a derived name there would demand one no run can
# print. TWO is a mutant whose own defect the shipped tree makes unreachable
# alone, and there the first-listed name is the generator's INTENT rather than a
# prediction: measured on `Mut_BugSetPinKeepsPpuat.cfg`, the companion's
# counterexample is the shallower one (`NoAccessibleSecretWithoutGate` at depth
# 13 against `NoTokenAfterInvalidation` at 15), so TLC halts on the companion's.
# Those rows are held to a name one of their OWN switches targets, read off the
# solo twins below -- not merely to a name the configuration checks, which on the
# two `Mut_` rows was any of six and so was barely narrower than nothing.
#
# Registering the exception in `floors.txt` instead was tried and is REFUSED by
# `scripts/verdict_gate.py`: an exact row in front of its class glob is the very
# shape it rejects, because nothing in the tree can tell first-match from
# last-match. The header of `floors.txt` advertises that mechanism and its own
# gate forbids it -- the gate wins.
armed_switches() {
  sed -nE 's/^[[:space:]]*((Bug|Mutate)[A-Z][A-Za-z0-9_]*)[[:space:]]*(=|<-)[[:space:]]*TRUE([[:space:]].*)?$/\1/p' "$1"
}

# Counted off the same reader, so the branch a row takes below and the names that
# branch accepts cannot come to disagree about what is armed in it.
armed_count() { armed_switches "$1" | grep -c .; }

# The solo family that answers for a configuration's own, derived not listed:
# `SeamMut_X` asks `SeamSolo_X`, and a `SoloClause_` row asks the plain `Solo_`
# twins of the switches it arms. A family with no solo half answers nothing and
# the caller falls back, which is what keeps this from being a second roster.
twin_family() {
  local fam=${1%%_*}
  case "$fam" in
    *Mut)        echo "${fam%Mut}Solo" ;;
    *SoloClause) echo "${fam%Clause}" ;;
    *Solo)       echo "$fam" ;;
    *)           echo "" ;;
  esac
}

# What the armed switches THEMSELVES target: each one's solo twin checks its own
# invariant and `gen-configs.sh` writes that name first, so `derived_inv` over the
# twin is the switch's target. It is the twin `scripts/verdict_gate.py` already
# searches for to decide a multi-target RED is attributable at all -- asked here
# for the name rather than for its existence.
twin_targets() {
  local fam sw twin
  fam=$(twin_family "$1")
  [ -n "$fam" ] || return 0
  while read -r sw; do
    twin="${fam}_${sw}.cfg"
    [ -r "$twin" ] && derived_inv "$twin"
  done < <(armed_switches "$1")
  return 0
}

# The names a RED may carry where no single one can be predicted: what this
# configuration CHECKS, narrowed to what its own switches target. An empty
# intersection means the two cannot meet -- a `SoloClause_` row names one CLAUSE
# of an invariant, which no twin's block can name -- and there the wider set is
# the answer rather than a refusal nobody can satisfy.
allowed_names() {
  local mine wanted narrowed=""
  mine=$(invariants_of "$1" | grep -vx TypeOK)
  [ -n "$mine" ] || return 0
  wanted=$(twin_targets "$1")
  [ -n "$wanted" ] && narrowed=$(printf '%s\n' "$mine" | grep -xF "$wanted")
  printf '%s\n' "${narrowed:-$mine}"
}

# What a configuration with NO switch armed may be refused BY. It models no
# defect, so nothing in its INVARIANTS block describes it -- and `TypeOK` is in
# that block, which is exactly what a "names something it checks" rule accepts.
refused_by_shape() {
  case "$2" in *Deadlock*) return 0 ;; esac
  names_a_property "$1" "$2"
}

# And what a configuration that checks NO invariant may be refused BY. It declares
# a temporal property and nothing else, so an invariant name or a deadlock in its
# verdict is a kill for something it does not model. TLC does not always say WHICH
# property fell -- a plain temporal refutation names none and an inline action
# property is reported by source location -- so those two shapes are all there is
# to hold the row to.
refuted_by_a_property() {
  names_a_property "$1" "$2" && return 0
  case "$2" in
    "RED: Error: Temporal properties were violated."*) return 0 ;;
    # WIDE by construction: any line of any module satisfies it. It is tight in
    # EFFECT only because `TokenRefinementBadMap.cfg` declares exactly one
    # property, so the location it prints can be no other property's.
    "RED: Error: Action property line "*) return 0 ;;
  esac
  return 1
}

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
  local cfg=$1 log="$OUT/${1%.cfg}.log" SPEC
  SPEC=$(spec_for "$cfg")
  mkdir -p "$OUT"
  local want floor heap inv
  read -r want floor heap inv <<< "$(expect_for "$cfg")"
  # `-` is this file's spelling of "no value" and the heap column now has rows
  # after it, so it can be filled by a placeholder rather than left off the end.
  # Passed through it becomes `-Xmx-`, and every such row died reporting
  # "Could not create the Java Virtual Machine" -- a RED for no reason at all.
  if [ "${heap:-}" = "-" ]; then heap=""; fi
  # 168 of the 177 RED rows named no invariant, so the reason went uncompared on
  # 95% of them and a mutant reddening on `TypeOK` -- which every configuration
  # checks and none targets -- exited 0. The configuration itself names one.
  local armed_n checks
  armed_n=$(armed_count "$cfg")
  # Read once, because it answers two questions: the derived name below, and
  # whether the row has a name to derive AT ALL. A `LiveMut_*` checks a temporal
  # property and no invariant, so an empty answer here is a fact about the row.
  checks=$(derived_inv "$cfg")
  if [ -z "${inv:-}" ] || [ "$inv" = "-" ]; then
    inv=""
    [ "$armed_n" = 1 ] && inv=$checks
  fi
  local t0 t1 cov=()
  # THE VACUITY QUESTION, and it is the same one `kani::cover!` answers: an
  # action that never fires makes every clause guarding it free. COVERAGE=1
  # asks TLC for the per-action firing counts and refuses on a zero.
  [ "${COVERAGE:-0}" = 1 ] && cov=(-coverage 5)
  t0=$(date +%s)
  # `>` gives each writer its own offset, so a second one truncating under the
  # first leaves a HOLE where the first writes on -- 1550 NUL bytes at offset
  # 153, measured. O_APPEND has no offset to go stale: truncate here, append below.
  : > "$log"
  "$JAVA" -XX:+UseParallelGC -Xmx"${HEAP_OVERRIDE:-${heap:-$HEAP}}" -cp "$JAR" tlc2.TLC \
      -nowarning -metadir "$metaroot/${cfg%.cfg}" -workers "$WORKERS" \
      "${cov[@]+"${cov[@]}"}" -config "$cfg" "$SPEC" \
      >> "$log" 2>&1
  t1=$(date +%s)
  if [ "${COVERAGE:-0}" = 1 ]; then
    local dead
    dead=$(grep -a -oE '^<[A-Za-z_][A-Za-z0-9_]* line [0-9]+.*>: [0-9]+:0$' "$log" \
             | sed -E 's/^<([A-Za-z_][A-Za-z0-9_]*) .*/\1/' | sort -u | tr '\n' ' ')
    if [ -n "$dead" ]; then
      echo "run-tlc: DEAD ACTION in $cfg -- never fired: $dead" >&2
      FAILED=$((FAILED + 1))
    fi
  fi
  local states distinct depth verdict
  # `-a` on EVERY read of the log below: one NUL byte in it makes grep call the
  # whole file binary and match nothing, so all three fields come back empty and
  # a GREEN exhaustive run reads VACUOUS. The backstop; the fix is above.
  states=$(grep -a -oE '^[0-9]+ states generated' "$log" | tail -1 | cut -d' ' -f1)
  distinct=$(grep -a -oE '[0-9]+ distinct states found' "$log" | tail -1 | cut -d' ' -f1)
  depth=$(grep -a -oE 'depth of the complete state graph search is [0-9]+' "$log" \
            | tail -1 | grep -oE '[0-9]+$')
  if grep -a -q 'Model checking completed. No error has been found' "$log"; then
    # A GREEN run over a state space that never took a step is not a pass, it is
    # a spec nothing enabled -- which is how `Seams.cfg` first came back GREEN
    # over ONE distinct state, on a conjunct that TLA+ precedence had turned into
    # an extra guard (`fresh' = x /\ fresh` is `(fresh' = x) /\ fresh`). Every
    # invariant holds vacuously there. Two is the floor because it is not a
    # judgement call: below it the Next relation fired nothing at all.
    # An INDUCTION probe (`INIT IndInv` / `NEXT Next`) starts from every state
    # its invariant admits, so the depth floor above is inverted for it: depth 1
    # IS the claim. Every successor already being an initial state is exactly
    # `IndInv /\ Next => IndInv'`, and depth 2 means a step left the predicate --
    # which the INVARIANTS block need not notice, because a conjunct of `IndInv`
    # is not necessarily one of them.
    local vacuous=0
    if grep -qE '^INIT([[:space:]]|$)' "$cfg"; then
      [ "${depth:-0}" = 1 ] || vacuous="NOT INDUCTIVE: a step left IndInv (depth ${depth:-?})"
    elif [ "${distinct:-0}" -lt 2 ] || [ "${depth:-0}" -lt 2 ]; then
      vacuous=1
    fi
    if [ "$vacuous" = 1 ]; then
      verdict="VACUOUS: nothing was enabled"
    elif [ "$vacuous" != 0 ]; then
      verdict="$vacuous"
    elif [ "${floor:--}" != "-" ] && [ -n "${floor:-}" ] \
         && [ "${distinct:-0}" -lt "$floor" ]; then
      # The VACUOUS rule above only sees the collapse all the way to nothing.
      # A run that merely got SMALL is the same failure with a survivor.
      verdict="FLOOR: $distinct < $floor"
    else
      verdict="GREEN"
    fi
  else
    # `[A-Za-z]+` here for its whole life, and every R4* invariant has a DIGIT
    # in its name -- so the nine trace rows fell through to the generic branch
    # and their verdict column printed the raw error line. Coarsely they still
    # read RED, which is why nobody saw it until the name was compared.
    verdict="RED: $(grep -a -oE 'Invariant [A-Za-z][A-Za-z0-9_]* is violated' "$log" | head -1 \
                     | sed 's/Invariant //; s/ is violated//')"
    [ "$verdict" = "RED: " ] && verdict="RED: $(grep -a -m1 -E '^Error' "$log")"
  fi
  # A mutant that stops firing is the one failure this apparatus exists to
  # avoid, and it does not look like a failure: BugSetPinKeepsPpuat explored
  # 40 459 667 states without a counterexample once a fix made its defect
  # unreachable, and only a human reading the matrix noticed.
  local mark="" got=${verdict%%:*}
  if [ -n "${want:-}" ] && [ "$want" != "$got" ]; then
    mark="  !! expected $want"
    FAILED=$((FAILED + 1))
  # A RED for the WRONG invariant is the same failure wearing the right colour:
  # the mutant broke something, just not the thing it claims to model. Compared
  # only where the row names one, because the mutant families already name theirs
  # in their own INVARIANTS block.
  elif [ "$got" = RED ] && [ -n "${inv:-}" ] && [ "${inv:-}" != "-" ] \
       && [ "$verdict" != "RED: $inv" ] && ! names_a_property "$cfg" "$verdict"; then
    mark="  !! expected RED: $inv"
    FAILED=$((FAILED + 1))
  # A row that checks NO invariant is held to a PROPERTY refutation, having no
  # name to break. Nothing held these at all -- the three `LiveMut_*` and
  # `TokenRefinementBadMap.cfg`, which is the whole mutation half of the liveness
  # tier -- so each took a RED on `TypeOK`, on a name no module defines, and on a
  # deadlock. Measured on all four. Ahead of the two-armed rule because a row with
  # nothing to name is the narrower case, whatever it arms.
  # CI reaches ONE of the four: deep-checks.yml runs the `safety` tier and no
  # workflow anywhere runs `liveness`, so the three `LiveMut_*` are hand-run and
  # `TokenRefinementBadMap.cfg` is the only row this branch guards in CI.
  elif [ "$got" = RED ] && [ -z "${inv:-}" ] && [ "$armed_n" -ge 1 ] \
       && [ -z "$checks" ] && ! refuted_by_a_property "$cfg" "$verdict"; then
    mark="  !! expected RED on a property this configuration declares"
    FAILED=$((FAILED + 1))
  # A configuration arming two defects predicts no single name, but it does
  # predict a SET: what one of its OWN switches targets. `TypeOK`, an invariant
  # no armed switch is about, and a refusal naming none all fall outside it.
  elif [ "$got" = RED ] && [ "$armed_n" -gt 1 ] \
       && ! names_a_property "$cfg" "$verdict" \
       && ! allowed_names "$cfg" | grep -qxF "${verdict#RED: }"; then
    mark="  !! expected RED on an invariant one of its armed switches targets"
    FAILED=$((FAILED + 1))
  # And a RED with NOTHING armed is held to a SHAPE, having no defect to name.
  # Nothing looked at these rows at all, so `TraceSeamsBad.cfg` reddening on
  # `TypeOK` -- an invariant it checks -- was a pass.
  # `-z "$inv"` and not `armed_n = 0` alone: the branch above is a WRONG-NAME test
  # and skips ITSELF when the name matches, so a row floors.txt already governs --
  # `TokenGateDisagreement.cfg`, named `RequiredGateAgreesWithRelation` -- fell
  # through to here and was refused for producing exactly what was asked of it.
  elif [ "$got" = RED ] && [ "$armed_n" = 0 ] && [ -z "${inv:-}" ] \
       && ! refused_by_shape "$cfg" "$verdict"; then
    mark="  !! expected RED on a deadlock or a property this configuration declares"
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
# hosted runner is where kani's `heavy` harness already died twice (19.9 GiB
# measured 2026-08-26; 11.1 GB when this was written). So `safety`
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
  echo AlwaysUv.cfg             # AS-AUTH-2's other arm: the build that ships it
  echo PermWide.cfg             # WidePerms's other arm: all 16 permission subsets
  ls PermWideMut_*.cfg          # …and what says that arm can go red at all
  echo ForceChange.cfg          # ForceChangeModelled's other arm: EF_MINPINLEN[1]
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
  echo StoreInduction.cfg   # IndInv /\ Next => IndInv' -- the probe that found one
  ls StoreInductionMut_*.cfg
  echo Lattice.cfg             # the fourth module: the retry/recovery lattice
  ls LatMut_*.cfg
  ls LatSolo_*.cfg
  echo LatInduction.cfg    # IndInv /\ Next => IndInv' over the counters, and
  ls LatInductionMut_*.cfg # what says that probe can go red
  echo Policies.cfg            # the four applets' stateful operation policies
  ls PolicyMut_*.cfg
  ls PolicySolo_*.cfg
  echo Admin.cfg               # the fifth module: the administrative surface
  ls AdminMut_*.cfg
  ls AdminSolo_*.cfg
  echo Display.cfg             # the sixth module: the trusted-display ceremony
  ls DispMut_*.cfg
  ls DispSolo_*.cfg
  echo Boot.cfg                # the seventh module: the cross-boot hardening
  echo BootCarry.cfg           # …and its open hardware assumption's other arm
  ls BootMut_*.cfg
  ls BootSolo_*.cfg
  ls BootCarryMut_*.cfg    # …and every mutant of it on that arm too
  echo BootInduction.cfg   # IndInv /\ Next => IndInv', from ANY admitted state
  ls BootInductionMut_*.cfg  # and what says that probe can go red
  echo Historical_BootWriteThenRearm.cfg # the write/re-arm order the tree ships,
  echo Historical_BootRearmThenWrite.cfg # RED, against the order it does not
  echo Transport.cfg           # the eighth module: the CTAPHID reassembler
  ls TransMut_*.cfg
  ls TransSolo_*.cfg
  echo TraceSeams.cfg          # phase 4: a recorded session replayed -- GREEN
  echo TraceSeamsBad.cfg       # and one the model must refuse -- RED
  echo TraceSecurity.cfg       # raw C-state --beta--> B and alpha == gamma(B)
  echo TraceSecurityBadBeta.cfg # shifting one raw retry field is refused
  echo TraceSecurityBadAlpha.cfg # shifting alpha is refused by R4b
  echo TraceSecurityBadAlphaNoR4b.cfg # and no other observer catches that shift
  echo TraceSecurityBadOutcome.cfg # outcome_raw disagreement is refused
  echo TraceSecurityBadUvNotRqd.cfg # the gate rule ignoring `rk` is refused
  echo TraceSecurityBadResetWindow.cfg # and ignoring the reset window
  echo TraceSecurityBadAlwaysUvArm.cfg # and the alwaysUv arm of the same rule
  echo TraceSecurityBadPinSet.cfg # and the arm that only a PIN-less cell can refute
  echo TokenGate.cfg             # tier A's requirement half: the oracle, and
  echo TokenGateOracle.cfg       # the set on which it differs from the relation
  echo TokenGateDisagreement.cfg # …which is RED because the two are not one predicate
  echo TokenGateMut_BugUnauthorizedEdge.cfg # and one edge the requirement forbids
  echo TokenRefinement.cfg       # phase 5: native B -> A state refinement
  echo TokenRefinementBadMap.cfg # a wrong gamma must be refused
  echo TokenRefinementOutcome.cfg # labelled B outcomes refine A events
  echo TokenRefinementDeadToken.cfg # state stutter is GREEN; R1o is RED
}

list_liveness() {
  echo Liveness.cfg             # the three temporal properties, and
  ls LiveMut_*.cfg              # one mutant per property
  # Liveness_Full.cfg is NOT here: 1475 s for the same verdict the reduced
  # constants give in 139 s. Run it by hand when the reduction is questioned.
}

# One runner carried the whole safety tier until the model grew past the job it
# ran in, which then reported ONE configuration and was killed for time (the wall
# clocks are `runs.toml`'s to hold, and the CHANGELOG dates the ones that decided
# this). `TLC_SHARD=i/n` splits it the way `MIRI_SHARD` and `MUTANTS_SHARD` split
# theirs, with the one difference that is the whole point: round-robin puts the
# heaviest configuration and the next-heaviest in ONE shard -- they sit 7 apart
# in `list_safety`, and 0 == 6 mod 3. So membership is by RECORDED COST: heaviest
# first into the lightest shard, seconds read from `runs.toml`, which already
# holds the last observed run of this tier. No n can beat the heaviest single
# configuration, which is what bounds the job's cap rather than the tier's sum. A
# configuration `runs.toml` has never seen weighs 0 and lands in the lightest
# shard; it is never dropped, which is the property `scripts/test_run_tlc.py`
# holds over the union of the shards.
TLC_SHARD=${TLC_SHARD:-1/1}
shard_i=${TLC_SHARD%%/*}
shard_n=${TLC_SHARD##*/}
# Both expansions answer `3` for a bare `3`, so that spelling would silently run
# a THIRD of the tier under a row that asked for all of it. It has to round-trip.
[ "$TLC_SHARD" = "$shard_i/$shard_n" ] || shard_n=0
if ! [ "$shard_i" -ge 1 ] 2>/dev/null || ! [ "$shard_i" -le "$shard_n" ] 2>/dev/null; then
  echo "::error::TLC_SHARD=$TLC_SHARD is not i/k with 1 <= i <= k" >&2
  exit 2
fi

# The shard's configurations, in the TIER'S own order and not by weight: the log
# stays readable against `runs.toml`, and `--record` writes the rows in the order
# the lister names them.
shard_members() {
  "$1" | awk -v runs=runs.toml '
      BEGIN {
        while ((getline line < runs) > 0)
          if (match(line, / [0-9]+s$/)) {
            split(line, field, /[ \t]+/)
            seconds = substr(line, RSTART + 1, RLENGTH - 2) + 0
            if (field[1] ~ /\.cfg$/ && seconds > cost[field[1]]) cost[field[1]] = seconds
          }
      }
      { printf "%d\t%d\t%s\n", cost[$1] + 0, NR, $1 }' \
    | sort -k1,1nr -k3,3 \
    | awk -v want="$shard_i" -v n="$shard_n" '
        { bin = 1
          for (i = 2; i <= n; i++) if (load[i] < load[bin]) bin = i
          load[bin] += $1
          if (bin == want) print $2 "\t" $3 }' \
    | sort -k1,1n | cut -f2
}

run_tier() {
  local f mine total picked
  total=$("$1" | grep -c '\.cfg$')
  mine=$(shard_members "$1")
  picked=$(printf '%s\n' "$mine" | grep -c '\.cfg$')
  if [ "$picked" -eq 0 ]; then
    echo "::error::shard $TLC_SHARD selected no configuration of $total" >&2
    exit 2
  fi
  # Printed only when a shard is in play, so an unsharded run's output -- which
  # `--record` parses and the matrix quotes -- stays byte-identical.
  [ "$shard_n" -eq 1 ] || echo "run-tlc: shard $TLC_SHARD, $picked of $total configuration(s)"
  for f in $mine; do one "$f"; done
}

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
