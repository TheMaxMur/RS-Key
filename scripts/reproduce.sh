#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# One command for an independent reviewer: reproduce the SOFTWARE evidence this
# tree publishes, from a clean checkout, in tiers.
#
#   nix develop -c ./scripts/reproduce.sh quick   # minutes
#   nix develop -c ./scripts/reproduce.sh merge   # the per-commit gate
#   nix develop -c ./scripts/reproduce.sh model   # the TLA+ tiers, hours
#   nix develop -c ./scripts/reproduce.sh --list --refusals
#
# The one thing this must never be is a wrapper that claims more than it runs.
# Every phase prints the command it is about to run and its exit code, and every
# class of evidence this checkout CANNOT produce is printed by name -- at the
# start and again in the verdict -- rather than omitted. A reviewer who reads
# only the last screen still learns what was left unproven.
#
# The board half is deliberately not here: flashing, secure-boot signing, OTP
# fuse writes and any measurement taken off silicon are the maintainer's, and
# `docs/reproducing.md` is where they are written down.
# No `-e`: a failing phase must reach the verdict rather than abort the run, and
# the verdict is the whole point. Which makes the `cd` below load-bearing on its
# own -- without `-e` a failed one would leave every relative path pointing at
# whatever directory the reviewer happened to be in.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

#: The page that carries the maintainer-only, destructive hardware instructions.
#: Named in the refusal block and held to exist by `--self-test`, because a
#: refusal that points nowhere is the silent skip this file exists to refuse.
HIL_PAGE="docs/reproducing.md"

#: The host triple the host-target phases select, spelled and defaulted exactly
#: as `scripts/check.sh` does it -- the workspace defaults to the firmware's
#: thumbv8m, so a host row that forgets the flag builds the wrong tree.
#: Read by the `eval` of the coverage phase's command, which shellcheck cannot
#: see into -- hence the directive, whose own syntax takes no trailing comment.
# shellcheck disable=SC2034
HOST_TRIPLE="${HOST_TARGET:-aarch64-apple-darwin}"

# --- the phases ---------------------------------------------------------------
#
# `name|tier|cost|what it reproduces|command`. The command field is what runs
# AND what is printed, so the line a reviewer copies out of the log is the line
# that produced the verdict -- a display string beside a separate dispatcher is
# two copies of one fact, and this tree has been bitten by that shape often
# enough (see `scripts/gate_lines.py` for the same argument one layer down).
#
# Costs are wall-clock on an Apple M5 Pro with a warm `~/.cargo` and a warm nix
# store; they are the order of magnitude a reviewer needs to plan a session, not
# a benchmark. `formal/runs.toml` carries the model tiers' own measured matrix.
PHASES=(
  "pages|quick|~1 min|the four generated assurance pages, re-derived from the tree and diffed against what is committed|python scripts/evidence_gate.py && python scripts/matrix_gate.py && python scripts/platform_gate.py && python scripts/assurance_gate.py"
  "docs|quick|~1 min|the documentation site builds and every relative link in it resolves offline|./scripts/docs.sh check"
  "gate|merge|~25 min|the merge gate: fmt, clippy, rustdoc, host tests over every feature flavour, the firmware builds, the image gates, SCA, and every registry/citation/roster guard|./scripts/check.sh"
  "proofs|merge|~10 min|the two Kani tiers a pull request runs: bounded proofs over the applet crates, then over the security-state crates|./scripts/kani.sh pr && ./scripts/kani.sh state"
  "model-safety|model|~110 min|TLC over the safety tier: the eight modules, their mutants, the solo twins and the recorded floors|./formal/run-tlc.sh safety"
  "model-liveness|model|~35 min|TLC over the liveness tier: the temporal properties and one mutant per property|./formal/run-tlc.sh liveness"
  "comutants|deep|~60 min|co-refutation: every model defect injected into production Rust, each patch expected to redden a named test|python scripts/comutate.py run"
  "emu|deep|~15 min|the on-device suites, the vendored OpenPGP and ykman suites and the diff against a frozen YubiKey 5.8.0, against tools/emu instead of a board|./scripts/emu-suites.sh"
  "proofs-all|deep|~8 h|the weekly Kani roster: every harness in every proven crate, in the four tiers CI shards it into|./scripts/kani.sh light1 && ./scripts/kani.sh light2 && ./scripts/kani.sh light3 && ./scripts/kani.sh heavy"
  "coverage|deep|~20 min|host-crate line coverage against the floor the weekly job holds|cargo llvm-cov --summary-only --fail-under-lines 80 --target \$HOST_TRIPLE --workspace --exclude firmware --exclude rsk-wipe"
  "repro|deep|~30 min|the hermetic firmware build is bit-identical on a rebuild|nix build .#firmware -o result-repro && nix build .#firmware --rebuild"
  "miri|deep|~40 min|every fuzz target's logic under Miri's UB checker|nix develop .#fuzz -c ./scripts/miri-all.sh"
  "fuzz|deep|~2 h|a timed libFuzzer run over every fuzz target, from whatever corpus this checkout has|nix develop .#fuzz -c ./scripts/fuzz-all.sh"
  "mutants|deep|~10 h|the advisory cargo-mutants sweep: would any test notice if this line changed|./scripts/mutants-all.sh"
)

#: Tier -> the phases it runs, cheapest first. `all` is every phase this
#: checkout can produce, and is still not everything the project publishes --
#: see REFUSED.
TIERS=(
  "quick|pages docs"
  "merge|gate proofs"
  "model|model-safety model-liveness"
  "deep|comutants emu proofs-all coverage repro miri fuzz mutants"
  "all|pages docs gate proofs model-safety model-liveness comutants emu proofs-all coverage repro miri fuzz mutants"
)

# --- what this checkout cannot produce ----------------------------------------
#
# `name|reason`. Printed up front and again in the verdict. A class that moves
# out of this list has to gain a phase above; one that stays has to keep a
# reason a reviewer can act on. Naming them is the whole point: a reproduction
# script that omits its own gaps is worth less than the list it replaced.
REFUSED=(
  "on-device suites|the numbered tests/*.py drive real USB and real flash on an RP2350 board; tools/emu covers 48 of them and the emu phase runs those"
  "USB-stack suites|tests that need a host USB stack run tools/emu --usbip inside a Linux guest with vhci_hcd and KVM (scripts/usbip-suites.sh); a macOS or hosted-runner checkout has neither"
  "two-key interop|the RS-Key/YubiKey differential cells under tests/interop need both keys attached; the emu phase runs three of them (getInfo, ATR, DeviceInfo) against a frozen YubiKey 5.8.0, the rest are not run"
  "fuzz corpus coverage|scripts/fuzz-coverage.sh measures the corpus the weekly job has accumulated across runs, which is a CI cache artefact and not a property of this checkout"
  "CodeQL|the buildless CodeQL pass runs on GitHub's own infrastructure, is advisory, and has no local entry point"
  "release provenance|signing, attestation and the published-artifact half of the release manifest need a tag and the maintainer's signing identity; scripts/release_gate.py checks the recipe, not a release"
  "board measurement|latency, SRAM residue, side-channel and secure-boot measurements are taken off silicon"
  "flashing and fuses|writing an image, sealing it, or blowing an OTP fuse is irreversible and maintainer-only"
)

# --- the claim tables ---------------------------------------------------------
#
# Everything below is read by `--self-test` and by nothing else. It is the
# falsifiable half: a phase list drifting from the tree is the same defect this
# programme keeps finding one layer down, so the tree's own evidence runners,
# CI jobs and gate rows are each held to a claim here.
#
# `subject|phase|reason` -- `phase` is a declared phase, or `-` when nothing
# here reproduces it, and then `reason` says why. Both directions are checked:
# a claim naming something the tree no longer has is as red as an unclaimed
# subject.

#: Every shell runner under scripts/ and formal/.
CLAIM_RUNNERS=(
  "scripts/check.sh|gate|"
  "scripts/gate-lib.sh|gate|"
  "scripts/docs.sh|docs|"
  "scripts/kani.sh|proofs|"
  "formal/run-tlc.sh|model-safety|"
  "scripts/emu-suites.sh|emu|"
  "scripts/miri-all.sh|miri|"
  "scripts/fuzz-all.sh|fuzz|"
  "scripts/mutants-all.sh|mutants|"
  "scripts/ci-scope.sh|gate|"
  "scripts/ci-knobs.sh|gate|"
  "scripts/complexity_gate.sh|gate|"
  "scripts/token_refinement.sh|gate|"
  "formal/gen-configs.sh|gate|"
  "scripts/fuzz-coverage.sh|-|measures the weekly job's accumulated corpus cache, which no checkout carries"
  "scripts/usbip-suites.sh|-|needs a Linux host with vhci_hcd and KVM to boot the guest that owns the USB stack"
  "scripts/usbip-guest.sh|-|the in-guest half of the same suite, invoked by it and never directly"
  "scripts/pt.sh|-|applies a partition table to an ELF; a build step the gate's image rows invoke, not evidence of its own"
  "scripts/metrics.sh|-|advisory refactor reconnaissance, explicitly not a gate and nothing depends on its numbers"
  "scripts/pages/build-site.sh|-|renders the published docs site for GitHub Pages; the docs phase builds and link-checks the same book"
  "scripts/reproduce.sh|-|this file: the runner the phases above are run by, and the one shape that cannot be a phase of itself — its own drift check is --self-test"
)

#: Every job in the three workflows that produce evidence. `pages.yml`,
#: `release*.yml` and `rekor-monitor.yml` publish rather than check, and are not
#: read here at all -- which is stated so the omission is a decision and not an
#: oversight.
CLAIM_JOBS=(
  "ci:changes|-|path classification for the jobs below; scripts/ci-scope.sh --self-test is a gate row"
  "ci:docs|docs|"
  "ci:check|gate|"
  "ci:proofs|proofs|"
  "ci:flavors|-|builds the fourteen published image flavours; the gate phase builds four of them and scripts/matrix_gate.py holds the matrix"
  "ci:knob-builds|-|the same build matrix under the board and feature knobs, held by scripts/ci-knobs.sh --self-test in the gate phase"
  "ci:knobs|-|the same, sharded; the self-test row is what says the shards cover the matrix"
  "deep-checks:miri|miri|"
  "deep-checks:fuzz|fuzz|"
  "deep-checks:fuzz-coverage|-|needs the accumulated corpus cache; see REFUSED"
  "deep-checks:repro|repro|"
  "deep-checks:coverage|coverage|"
  "deep-checks:kani|proofs-all|"
  "deep-checks:mutants|mutants|"
  "deep-checks:comutants|comutants|"
  "deep-checks:formal|model-safety|"
  "emulator:changes|-|path classification, as above"
  "emulator:sockets|emu|"
  "emulator:usb|-|the USB-stack half, in a QEMU guest; see REFUSED"
)

#: How a `check.sh` row's command is recognised. The gate phase runs the file
#: whole, so every row it already has is reproduced by construction -- what this
#: table is for is the row that arrives needing something a clean checkout has
#: not got. A command shape nobody has classified is UNCLAIMED and red, so a row
#: invoking a board, a key or a network service has to be looked at by a human
#: before this script may go on claiming it reproduces the gate.
#:
#: `extended regex|phase|reason`, first match wins. One alternative per entry
#: and never an `|` inside a pattern: the record separator is `|`, so an
#: alternation would be cut in half and reach grep as `^(actionlint` --
#: `Unmatched (`, on stderr, while the row it was meant to claim reads as
#: unrecognised. Measured on the first run of this table.
CLAIM_ROWS=(
  "^cargo |gate|"
  "^env .*cargo |gate|"
  "^python3? scripts/|gate|"
  "^python3? -m pytest scripts\\b|gate|"
  "^python3? -m pytest tools/rsk\\b|gate|"
  "^python3? -m pytest tests/interop\\b|gate|"
  "^\\./scripts/[a-z_0-9-]+\\.sh|gate|"
  "^\\./formal/[a-z_0-9-]+\\.sh|gate|"
  "^actionlint |gate|"
  "^gitleaks |gate|"
  "^node --test |gate|"
  "^sh -c |gate|"
  "^[a-z_][a-z_0-9]*\$|gate|"
)

# --- running ------------------------------------------------------------------

#: One reproduction at a time. Two `check.sh` runs collide on their build tree
#: and two TLC runs on `formal/out/<cfg>.log`, so a second copy is refused rather
#: than started -- silently interleaved runs are how a recorded model tier stops
#: describing anything.
LOCK="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/reproduce.lock"

# `[r]…` so the pattern cannot match the `pgrep` that carries it, which is the
# oldest way to make this check report a run that is only itself.
OTHERS='[c]heck\.sh|[r]un-tlc\.sh|[c]argo-kani'

take_lock() {
  mkdir -p "$(dirname "$LOCK")"
  if ! mkdir "$LOCK" 2>/dev/null; then
    local held
    held=$(cat "$LOCK/pid" 2>/dev/null || echo "")
    if [ -n "$held" ] && kill -0 "$held" 2>/dev/null; then
      echo "refusing to start: reproduce.sh is already running as pid $held." >&2
      echo "  Two runs collide on the build tree and on formal/out/<cfg>.log." >&2
      exit 3
    fi
    echo "note: taking over a stale lock from pid ${held:-unknown}" >&2
    if ! { rm -rf "$LOCK" && mkdir "$LOCK"; }; then echo "cannot take $LOCK" >&2; exit 3; fi
  fi
  echo $$ > "$LOCK/pid"
  trap 'rm -rf "$LOCK"' EXIT
  local running
  running=$(pgrep -f "$OTHERS" 2>/dev/null | tr '\n' ' ')
  if [ -n "${running// /}" ]; then
    echo "refusing to start: a gate, model or proof run is already live (pids: $running)." >&2
    exit 3
  fi
}

#: Field `$2` of a `|`-separated record. Parameter expansion rather than `cut`,
#: because the self-test asks this thousands of times per run and a fork apiece
#: put the mutation table beside it at three and a half minutes. A record with
#: fewer fields than asked answers empty, so a short row reads as unclaimed
#: rather than as a copy of its own last field.
field() {
  local rec=$1 n=$2
  while [ "$n" -gt 1 ]; do
    case $rec in *"|"*) rec=${rec#*|} ;; *) return ;; esac
    n=$((n - 1))
  done
  printf '%s' "${rec%%|*}"
}
#: The trailing field, `|` and all. A command with a pipe in it read by `field`
#: would be silently truncated at the pipe and then PRINTED as the command that
#: ran, which is the one lie this file exists to make impossible.
rest() {
  local rec=$1 n=$2
  while [ "$n" -gt 1 ]; do
    case $rec in *"|"*) rec=${rec#*|} ;; *) return ;; esac
    n=$((n - 1))
  done
  printf '%s' "$rec"
}

phase_row() {
  local p
  for p in "${PHASES[@]}"; do
    [ "$(field "$p" 1)" = "$1" ] && { printf '%s' "$p"; return 0; }
  done
  return 1
}

tier_members() {
  local t
  for t in "${TIERS[@]}"; do
    [ "$(field "$t" 1)" = "$1" ] && { field "$t" 2; return 0; }
  done
  return 1
}

#: The reason this script refuses `$1`, when `$1` is one of the classes it names
#: as unreproducible. Matched on the leading word too, so `flashing`, `board` and
#: `CodeQL` all land on their own entry rather than on a usage message. Asked
#: LAST, after tiers and phases, so a leading word a phase already owns -- `fuzz`
#: -- stays the phase and is not shadowed by a refusal that merely starts with it.
refusal_for() {
  local r name
  for r in "${REFUSED[@]}"; do
    name=$(field "$r" 1)
    case "$1" in "$name"|"${name%% *}") rest "$r" 2; return 0 ;; esac
  done
  return 1
}

banner() { printf '%s\n' "======================================================================"; }

print_refusals() {
  local r
  echo
  banner
  echo " NOT reproducible from this checkout — ${#REFUSED[@]} classes, by name"
  banner
  for r in "${REFUSED[@]}"; do
    printf '  %-22s %s\n' "$(field "$r" 1)" "$(rest "$r" 2)"
  done
  echo
  echo "  The board half is maintainer-only and written down in $HIL_PAGE."
  echo "  Nothing in this script flashes, signs, or writes a fuse."
}

print_list() {
  local p
  banner
  echo " phases — ./scripts/reproduce.sh <tier|phase> …"
  banner
  printf '  %-15s %-7s %-8s %s\n' PHASE TIER COST REPRODUCES
  for p in "${PHASES[@]}"; do
    printf '  %-15s %-7s %-8s %s\n' \
      "$(field "$p" 1)" "$(field "$p" 2)" "$(field "$p" 3)" "$(field "$p" 4)"
    printf '  %-15s %-7s %-8s %s\n' "" "" "" "\$ $(rest "$p" 5)"
  done
  echo
  local t
  for t in "${TIERS[@]}"; do printf '  tier %-6s = %s\n' "$(field "$t" 1)" "$(field "$t" 2)"; done
}

#: The proof phases need a toolchain the dev shell deliberately does not pin:
#: Kani is rustup-based and is installed out of band by CI too. Missing, the
#: phase is REFUSED by name with the command that fixes it -- not skipped, and
#: not left to fail as `no such command` two minutes in.
missing_tool() {
  case "$1" in
    proofs|proofs-all)
      command -v cargo-kani >/dev/null || {
        echo "cargo-kani (cargo install --locked kani-verifier --version 0.67.0 && cargo kani setup)"
        return 0
      } ;;
    coverage)
      command -v cargo-llvm-cov >/dev/null || { echo "cargo-llvm-cov"; return 0; } ;;
    repro)
      command -v nix >/dev/null || { echo "nix"; return 0; } ;;
  esac
  return 1
}

RESULTS=()
run_phase() {
  local row name what cmd rc t0 t1 lack
  row=$(phase_row "$1") || { echo "no such phase: $1" >&2; exit 2; }
  name=$(field "$row" 1); what=$(field "$row" 4); cmd=$(rest "$row" 5)
  echo
  banner
  echo " phase: $name"
  echo " reproduces: $what"
  echo " command:    $cmd"
  banner
  if lack=$(missing_tool "$name"); then
    echo "REFUSED: this phase needs $lack"
    RESULTS+=("$name|refused|-|missing $lack")
    return
  fi
  t0=$(date +%s)
  # The command field is evaluated on purpose: it is one string so that what is
  # printed above and what runs below cannot come apart. No pipe, so the exit
  # code is the phase's own.
  eval "$cmd"
  rc=$?
  t1=$(date +%s)
  echo "-- $name: rc=$rc in $((t1 - t0))s"
  RESULTS+=("$name|$( [ "$rc" -eq 0 ] && echo ok || echo FAIL )|$rc|$((t1 - t0))s")
}

verdict() {
  local r bad=0 refused=0
  echo
  banner
  echo " verdict"
  banner
  for r in "${RESULTS[@]}"; do
    printf '  %-8s %-15s rc=%-4s %s\n' "$(field "$r" 2)" "$(field "$r" 1)" "$(field "$r" 3)" "$(field "$r" 4)"
    case "$(field "$r" 2)" in FAIL) bad=$((bad + 1)) ;; refused) refused=$((refused + 1)) ;; esac
  done
  print_refusals
  echo
  if [ "$bad" -eq 0 ] && [ "$refused" -eq 0 ]; then
    echo "VERDICT: ${#RESULTS[@]}/${#RESULTS[@]} phases reproduced. ${#REFUSED[@]} evidence classes are NOT software-reproducible and were not attempted."
    return 0
  fi
  echo "VERDICT: FAIL — $bad phase(s) failed, $refused refused for a missing tool, out of ${#RESULTS[@]}."
  echo "         ${#REFUSED[@]} evidence classes are NOT software-reproducible and were not attempted."
  return 1
}

# --- the self-test ------------------------------------------------------------

FAILS=0
bad() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }

#: `run`/`run_tests` rows, line continuations folded, as `check.sh` runs them.
check_rows() {
  sed -e ':a' -e '/\\$/{N;s/\\\n[[:space:]]*/ /;ba' -e '}' scripts/check.sh \
    | sed -nE 's/^[[:space:]]*(run|run_tests)[[:space:]]+"([^"]+)"[[:space:]]*(.*)$/\2\t\3/p'
}

claim_of() {
  # $1 subject, $2… the table; echoes `phase|reason`, empty when unclaimed.
  local subject=$1 entry; shift
  for entry in "$@"; do
    [ "$(field "$entry" 1)" = "$subject" ] && { printf '%s|%s' "$(field "$entry" 2)" "$(rest "$entry" 3)"; return; }
  done
}

declared_phase() {
  local p
  for p in "${PHASES[@]}"; do [ "$(field "$p" 1)" = "$1" ] && return 0; done
  return 1
}

#: A claim is well formed when it names a declared phase, or `-` with a reason.
check_claim() {
  local what=$1 subject=$2 claim=$3 phase reason
  phase=${claim%%|*}; reason=${claim#*|}
  case "$phase" in
    "") bad "$what: '$subject' is claimed by nothing here — give it a phase or a reason" ;;
    "-") [ -n "$reason" ] || bad "$what: '$subject' is excluded with no reason" ;;
    *) declared_phase "$phase" || bad "$what: '$subject' names phase '$phase', which is not declared" ;;
  esac
}

self_test() {
  local n cmd subject entry pat phase found t m

  # C1 — every check.sh row's command shape is recognised.
  n=$(check_rows | grep -c .)
  [ "$n" -ge 50 ] || bad "rows: read $n rows out of scripts/check.sh — the extractor is broken, and a table over nothing passes every case below"
  while IFS=$'\t' read -r subject cmd; do
    found=""
    for entry in "${CLAIM_ROWS[@]}"; do
      pat=$(field "$entry" 1)
      if printf '%s' "$cmd" | grep -qE "$pat"; then found=$(printf '%s|%s' "$(field "$entry" 2)" "$(rest "$entry" 3)"); break; fi
    done
    [ -n "$found" ] || bad "rows: check.sh row \"$subject\" runs '$cmd', a shape no claim here recognises — say which phase reproduces it, and whether a clean checkout can"
    [ -n "$found" ] && check_claim rows "$subject" "$found"
  done < <(check_rows)

  # C2 — every shell runner in the tree is claimed, and every claim is live.
  while read -r subject; do
    check_claim runners "$subject" "$(claim_of "$subject" "${CLAIM_RUNNERS[@]}")"
  done < <(find scripts formal -name '*.sh' | sort)
  for entry in "${CLAIM_RUNNERS[@]}"; do
    subject=$(field "$entry" 1)
    [ -f "$subject" ] || bad "runners: '$subject' is claimed here and is not in the tree"
  done

  # C3 — every evidence workflow's jobs are claimed, and every claim is live.
  while read -r subject; do
    check_claim jobs "$subject" "$(claim_of "$subject" "${CLAIM_JOBS[@]}")"
  done < <(workflow_jobs)
  found=$(workflow_jobs)
  for entry in "${CLAIM_JOBS[@]}"; do
    subject=$(field "$entry" 1)
    printf '%s\n' "$found" | grep -qxF "$subject" || bad "jobs: '$subject' is claimed here and is no job of that workflow"
  done

  # C4 — the tier table and the phase table agree, both ways.
  for t in "${TIERS[@]}"; do
    for m in $(field "$t" 2); do
      declared_phase "$m" || bad "phases: tier '$(field "$t" 1)' names '$m', which is not a declared phase"
    done
  done
  for entry in "${PHASES[@]}"; do
    phase=$(field "$entry" 1); found=""
    for t in "${TIERS[@]}"; do
      for m in $(field "$t" 2); do [ "$m" = "$phase" ] && found=1; done
    done
    [ -n "$found" ] || bad "phases: '$phase' is declared and is in no tier, so no tier runs it"
    [ -n "$(field "$entry" 4)" ] || bad "phases: '$phase' says nothing about what it reproduces"
    [ -n "$(rest "$entry" 5)" ] || bad "phases: '$phase' has no command"
  done

  # C5 — the refusals are non-empty, reasoned, and point somewhere that exists.
  [ "${#REFUSED[@]}" -ge 1 ] || bad "refusals: the list is empty, which claims this checkout can produce everything"
  for entry in "${REFUSED[@]}"; do
    [ -n "$(rest "$entry" 2)" ] || bad "refusals: '$(field "$entry" 1)' is refused with no reason"
  done
  [ -f "$HIL_PAGE" ] || bad "refusals: the maintainer-only page $HIL_PAGE does not exist, so the refusal points nowhere"
  print_refusals | grep -qF "$HIL_PAGE" || bad "refusals: the refusal block does not name $HIL_PAGE"

  if [ "$FAILS" -eq 0 ]; then
    echo "reproduce: self-test ok — $n gate rows, $(find scripts formal -name '*.sh' | grep -c .) runners, $(workflow_jobs | grep -c .) jobs, ${#PHASES[@]} phases, ${#REFUSED[@]} refusals"
  else
    echo "reproduce: $FAILS self-test failure(s)" >&2
    return 1
  fi
}

#: `workflow:job` for the three workflows that produce evidence. A job key is a
#: two-space-indented mapping key under `jobs:`, which is the whole of the shape
#: -- read with awk rather than a YAML parser so this stays a shell script.
workflow_jobs() {
  local w
  for w in ci deep-checks emulator; do
    awk -v w="$w" '
      /^jobs:/ { j = 1; next }
      j && /^[a-z]/ { j = 0 }
      j && /^  [a-z][a-z0-9_-]*:[[:space:]]*$/ { gsub(/[ :]/, ""); print w ":" $0 }
    ' ".github/workflows/$w.yml"
  done
}

# --- entry --------------------------------------------------------------------

usage() {
  echo "usage: $0 <tier|phase> …          # $(printf '%s ' "${TIERS[@]%%|*}")" >&2
  echo "       $0 --list | --refusals | --self-test" >&2
  exit 2
}

[ $# -ge 1 ] || usage

case "$1" in
  --list) print_list; exit 0 ;;
  --refusals) print_refusals; exit 0 ;;
  --self-test) self_test; exit $? ;;
esac

# Expand tiers to phases, keeping the order given and dropping repeats, so
# `all` and `merge` together do not run the gate twice.
WANTED=()
for arg in "$@"; do
  if members=$(tier_members "$arg"); then
    for m in $members; do WANTED+=("$m"); done
  elif phase_row "$arg" >/dev/null; then
    WANTED+=("$arg")
  elif refusal=$(refusal_for "$arg"); then
    # Asked for by the name this script itself prints for it. A usage shrug here
    # would read as "spell it differently"; the answer is that no spelling runs.
    echo "REFUSED: '$arg' is not reproducible from a checkout — $refusal" >&2
    echo "  The board half is maintainer-only and written down in $HIL_PAGE." >&2
    exit 3
  else
    echo "no such tier or phase: $arg" >&2
    usage
  fi
done

take_lock
echo "RS-Key — reproducing the software evidence of $(git rev-parse --short HEAD 2>/dev/null || echo 'this checkout')"
echo "phases: ${WANTED[*]}"
print_refusals

SEEN=""
for p in "${WANTED[@]}"; do
  case " $SEEN " in *" $p "*) continue ;; esac
  SEEN="$SEEN $p"
  run_phase "$p"
done
verdict
