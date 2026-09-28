#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Generate the TLC configurations: `Shipped.cfg` (every mutation switch off --
# the tree as it stands) plus one `Mut_<Bug>.cfg` per switch. Each mutant lists
# the invariant it is expected to break FIRST, because TLC reports the first
# violated invariant and stops.
set -euo pipefail
# Where to write. Defaults to this directory, so `./gen-configs.sh` still
# regenerates in place -- but scripts/config_gen_gate.py can regenerate into a
# temp tree and diff, which is the only way to check the 200 files against
# their generator without overwriting them first.
out_dir=${1:-$(dirname "$0")}
mkdir -p "$out_dir"
cd "$out_dir"

BUGS=(BugResetGatesFirst BugCredBeforeRp BugTokenSurvivesPinChange
      BugSetPinKeepsPpuat BugChangePinKeepsPpuat BugStopUsingKeepsPerms
      BugNoConsumeAfterUp BugUnscopedCancel BugTouchNotSpent
      BugSoftLockLostOnWarmReset BugWarmResetReopensWindow
      BugCmWalkIgnoresChannel BugDeleteRpBeforeCred BugBackupSealedNotAGate
      BugConsumeKeepsMcGa BugNoDropStaleCancelAtEntry BugWrongPinKeepsToken
      BugSeedDoesNotLead BugNoTouchRequired BugStateResetAfterWipe
      BugPanelCancelable BugUnscopedOtpCancel BugLocalPinKeepsToken
      BugSetPinOverExisting BugHostPreemptsLocalWait BugLocalPinIgnoresBudget
      BugPpuatIsAGate BugPinWriteBeforeRevoke
      BugUvNotRqdIgnoresRk BugTokenlessIgnoresAlwaysUv
      BugForceChangeIgnored)

# Mutants whose defect the shipped seed-lead makes unreachable: they rebuild a
# pre-0x08BF ordering bug, so their configuration must be the pre-0x08BF tree.
# That the list is not empty is the measured strength of that fix -- see README.
companion_bug() {
  case "$1" in
    BugBackupSealedNotAGate) echo BugSeedDoesNotLead ;;
    # eab4b5c moved EF_PAUTHTOKEN into the SECRETS phase, and phase 2 cannot
    # start until phase 1 is empty -- so `~pin.set /\ gate.ppuat` is now
    # unreachable, and setPIN can no longer meet a stranded grant to keep.
    # The mutant explores the whole space and comes back GREEN without this.
    BugSetPinKeepsPpuat)     echo BugPpuatIsAGate ;;
    *) echo "" ;;
  esac
}

# The invariant each mutant must break, so a silent mutant is visible as such.
target_inv() {
  case "$1" in
    BugResetGatesFirst)         echo ResetNeverWeakensSurvivingState ;;
    BugCredBeforeRp)            echo NoUnmanageableCredential ;;
    BugTokenSurvivesPinChange)  echo NoTokenAfterInvalidation ;;
    BugSetPinKeepsPpuat)        echo NoTokenAfterInvalidation ;;
    BugChangePinKeepsPpuat)     echo NoTokenAfterInvalidation ;;
    BugStopUsingKeepsPerms)     echo NoTokenAfterInvalidation ;;
    BugNoConsumeAfterUp)        echo NoAuthorizationBypass ;;
    BugUnscopedCancel)          echo NoCrossTransportTouchConsumption ;;
    BugTouchNotSpent)           echo NoCrossTransportTouchConsumption ;;
    BugSoftLockLostOnWarmReset) echo NoAuthorizationBypass ;;
    BugWarmResetReopensWindow)  echo NoAuthorizationBypass ;;
    BugCmWalkIgnoresChannel)    echo NoAuthorizationBypass ;;
    BugDeleteRpBeforeCred)      echo NoUnmanageableCredential ;;
    BugBackupSealedNotAGate)    echo ResetNeverWeakensSurvivingState ;;
    BugConsumeKeepsMcGa)        echo NoAuthorizationBypass ;;
    BugNoDropStaleCancelAtEntry) echo NoCrossTransportTouchConsumption ;;
    BugWrongPinKeepsToken)      echo NoTokenAfterInvalidation ;;
    BugSeedDoesNotLead)         echo NoUnmanageableCredential ;;
    BugNoTouchRequired)         echo NoAuthorizationBypass ;;
    BugStateResetAfterWipe)     echo ResetNeverWeakensSurvivingState ;;
    BugPanelCancelable)         echo NoCrossTransportTouchConsumption ;;
    BugUnscopedOtpCancel)       echo NoCrossTransportTouchConsumption ;;
    BugLocalPinKeepsToken)      echo NoTokenAfterInvalidation ;;
    BugSetPinOverExisting)      echo NoAuthorizationBypass ;;
    BugHostPreemptsLocalWait)   echo NoAuthorizationBypass ;;
    BugLocalPinIgnoresBudget)   echo NoAuthorizationBypass ;;
    BugPpuatIsAGate)            echo NoAccessibleSecretWithoutGate ;;
    BugPinWriteBeforeRevoke)    echo NoTokenAfterInvalidation ;;
    # The two halves of makecredential.rs's token-less carve-out. Both let an
    # operation the requirement forbids complete on the touch alone, which is
    # NoAuthorizationBypass and nothing narrower -- neither touches a grant that
    # was ever issued, so neither is NoTokenAfterInvalidation.
    BugUvNotRqdIgnoresRk)       echo NoAuthorizationBypass ;;
    BugTokenlessIgnoresAlwaysUv) echo NoAuthorizationBypass ;;
    BugForceChangeIgnored)      echo NoAuthorizationBypass ;;
  esac
}

# Liveness switches: always FALSE in a safety configuration, and one at a time
# in a LiveMut_*.cfg. They break no invariant by design.
LIVE_BUGS=(BugAssertWedgesOnTimeout BugWaitScopeNotCleared BugWalkNeverExpires)

live_target() {
  case "$1" in
    BugAssertWedgesOnTimeout) echo EveryOpQuiesces ;;
    BugWaitScopeNotCleared)   echo EveryWaitReleases ;;
    BugWalkNeverExpires)      echo EveryWalkCloses ;;
  esac
}
ALL_PROP=(EveryOpQuiesces EveryWaitReleases EveryWalkCloses)

# A switch on the SHAPE of a fairness assumption, not on a behaviour: it breaks
# an invariant rather than a property, so it belongs to neither list above and
# is emitted FALSE everywhere except its own configuration.
SHAPE_BUGS=(BugFairnessFoldsLocalCeremony)

ALL_INV=(NoAuthorizationBypass NoCrossTransportTouchConsumption
         NoTokenAfterInvalidation NoAccessibleSecretWithoutGate
         NoUnmanageableCredential ResetNeverWeakensSurvivingState)

# Structural facts the model's own arguments rest on, asserted on the baseline
# rather than argued in a comment. Deliberately NOT in ALL_INV: a mutant reports
# the FIRST invariant it violates, so adding one to the 27 mutant configs would
# move verdicts that are the record of which invariant names which defect. Each
# gets its own Solo config against the mutant that falsifies it.
EXTRA_INV=(RamNeverOutlivesFlashSeed NoLiveTokenWithoutPinRecord)

# The three conjuncts of ResetNeverWeakensSurvivingState, declared here because
# `emit`'s `clauses` knob names them and the SoloClause_* loop below reuses the
# same array -- one roster, so a fourth clause cannot land in one and not the
# other. NOT in ALL_INV: that would put them in every unarmed configuration and
# move the fallback list of every armed one.
CLAUSE_INV=(ResetKeepsThePinGate ResetKeepsTheAlwaysUvGate ResetKeepsTheBackupSeal)

extra_mutant() {
  # ctx.state.reset() moved back behind the flash work leaves the RAM seed
  # standing past the flash delete AND a live token past EF_PIN's deletion.
  case "$1" in
    RamNeverOutlivesFlashSeed)   echo BugStateResetAfterWipe ;;
    NoLiveTokenWithoutPinRecord) echo BugStateResetAfterWipe ;;
  esac
}

# `ship_auv` and not `auv`: `emit_security_trace` already has a local `auv` for
# the alwaysUv-ARM mutant, and a bare name here handed AS-AUTH-2's TRUE arm to
# TraceSecurityBadAlwaysUvArm.cfg -- caught by `assumption_gate.py`, which prints
# which configurations take each arm, and by nothing else.
emit() { # $1 = cfg, $2 = bug switch (""), $3 = sweep fix, $4 = ppuat fix
  local out=$1 on=${2:-} fix=${3:-TRUE} fix2=${4:-${3:-TRUE}}
  # Assigned here rather than inline: a `${rps:-{r1, r2}}` default cannot be
  # written in a double-quoted `echo` -- the first `}` closes the expansion, and
  # escaping it puts the backslash in the configuration.
  local rp_set=${rps:-} chan_set=${chans:-}
  [ -n "$rp_set" ] || rp_set="{r1, r2}"
  [ -n "$chan_set" ] || chan_set="{c1, c2}"
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    # MODEL VALUES, not strings, because `SYMMETRY` needs them -- and the
    # symmetry is what pays for the two constants below being the firmware's
    # own. Quotienting the interchangeable relying parties and channels takes
    # 61 215 504 distinct states to 25 829 584, which is what let MAX_PIN_RETRIES
    # = 8 and PIN_MISMATCH_LIMIT = 3 (consts.rs:371,375) be affordable at all.
    # They cost 108 618 956 now -- MORE than the reduced 3 : 2 explored before the
    # quotient, the token-less registration and the grant record having been folded
    # in since. The mechanism is the measurement; the margin was, and is not.
    echo "    RPs = $rp_set"
    echo "    Channels = $chan_set"
    # The retry pair is reduced ONLY on the assumption's other arm, and that is
    # the trade the arm makes: it buys the alwaysUv reachability question and
    # leaves the retry ladder to Shipped.cfg, which is the row that is about it.
    echo "    MaxRetries = ${retries:-8}"
    echo "    MismatchLimit = ${mism:-3}"
    echo "    MaxClock = 1"
    echo "    ResetWindow = 0"
    echo "    AlwaysUvShipped = ${ship_auv:-FALSE}"
    echo "    WidePerms = ${wide:-FALSE}"
    if [ "$on" = BugForceChangeIgnored ] || [ "${force_ch:-}" = TRUE ]
    then echo "    ForceChangeModelled = TRUE"
    else echo "    ForceChangeModelled = FALSE"; fi
    for b in "${BUGS[@]}"; do
      if [ "$b" = "$on" ] || { [ -n "$on" ] && [ "$b" = "$(companion_bug "$on")" ]; }
      then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    for b in "${LIVE_BUGS[@]}" "${SHAPE_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "    FixSweepDropsCredsBeforeRpEntries = $fix"
    echo "    FixPpuatRequiresPin = $fix2"
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "${SOLO:-0}" = 1 ]; then
      # Solo: ONLY the invariant this mutant must break, so a mutant caught by
      # a sibling invariant cannot be mistaken for one that names its own.
      echo "    ${SOLO_INV:-$(target_inv "$on")}"
    elif [ -n "$on" ]; then
      local t; t=$(target_inv "$on"); echo "    $t"
      for i in "${ALL_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${ALL_INV[@]}" "${EXTRA_INV[@]}"; do echo "    $i"; done
      # The clauses of ResetNeverWeakensSurvivingState, on the ONE configuration
      # that asks for them: every green exhaustive run of the parent checks all
      # three, but the gate that reads INVARIANTS lines saw them named only by
      # their own RED SoloClause_* rows and reported each asserted by nothing.
      # LAST in the block, for the reason emit_store appends CacheHonest last:
      # TLC reports the first violated invariant, so a name ahead of the others
      # would re-attribute verdicts already in formal/runs.toml.
      if [ "${clauses:-0}" = 1 ]; then
        for i in "${CLAUSE_INV[@]}"; do echo "    $i"; done
      fi
    fi
    echo "SYMMETRY Symm"
  } > "$out"
}

# THE TREE AS IT STANDS, and it is the green baseline the mutants are measured
# against. Two constants carry the history: `FixPpuatRequiresPin` shipped
# verbatim at 0x08C0, so it is ON; `FixSweepDropsCredsBeforeRpEntries` is a
# counterfactual the tree did NOT take -- 0x08BF made the seed lead the wipe
# instead, which is the default (`BugSeedDoesNotLead = FALSE`), so it is OFF.
#
# `clauses=1` HERE and on no other baseline, and the choice is a measurement.
# The three reset clauses are conjuncts of an invariant all four baselines check
# and pass, so naming them adds no logical content anywhere -- but on the arms
# that ship alwaysUv, ResetKeepsTheAlwaysUvGate cannot fail at all: EF_ALWAYS_UV
# exists only as an OVERRIDE of the compiled default, so ResetSweepGates' own
# `gate.alwaysUv # AlwaysUvShipped` guard can never take the gate from TRUE to
# FALSE, and ConfigOp -- the only other writer -- clears `snap` in the same step
# the clause's antecedent reads. Recording the clause as asserted there would be
# recording a row that cannot go red. This is the one green baseline on the
# FALSE arm, which is also the arm its own SoloClause mutant reddens on.
# Naming them makes the assertion VISIBLE, not stronger: `SeedReachable`'s
# `ram` disjunct is inert on the shipped tree -- RamNeverOutlivesFlashSeed is
# what says so -- and it stands in the antecedent of the first two clauses,
# so on this configuration they read on the flash record alone (README, the
# SeedReachable restatement).
clauses=1 emit Shipped.cfg "" FALSE TRUE
# AS-AUTH-2's OTHER ARM. `--features always-uv` is a build fact the shipped image
# does not carry, and an assumption no run can vary is an axiom -- so the whole
# invariant set runs once with alwaysUv as the compiled default. Reduced retry
# ladder, because the question is reachability under a stricter gate and not the
# 77-million-state ladder Shipped.cfg already walks.
ship_auv=TRUE retries=2 mism=1 emit AlwaysUv.cfg "" FALSE TRUE
# THE OTHER ARM OF `WidePerms`, and the reason it is its own configuration and
# not a widening of Shipped.cfg: measured on AlwaysUv.cfg's constants, 5 -> 16
# subsets costs x4.16 wall, which projects the safety tier past its CI ceiling.
# One relying party and one channel buys the same question for 493 s. alwaysUv
# is ON because that is where a token's permissions matter most -- with no PIN
# and no alwaysUv, OpGuard is trivially true and the domain never gets read.
# One relying party, but TWO channels: scopes.txt holds Channels >= 2 for any
# configuration CHECKING NoAuthorizationBypass, and this one checks it. Measured
# both ways -- the second channel costs 2.5 % more states and, under the symmetry
# quotient with no mutant armed, exactly zero more distinct ones, so the floor is
# satisfied. The counts are the results table's; the one-channel arm is not a
# recorded row and cost 493 s.
wide=TRUE ship_auv=TRUE retries=2 mism=1 rps='{r1}' chans='{c1, c2}' \
  emit PermWide.cfg "" FALSE TRUE
# AND WHAT SAYS THAT GREEN OBSERVED ANYTHING. Until these, no mutant ran at
# `WidePerms = TRUE` at all: the wide arm was a pass with no red beside it, which
# is a run that finished rather than a run that watched. The switches below are
# chosen for what each one argues and not to make up a family:
#
#   BugStopUsingKeepsPerms  is the UNIQUE switch that keeps only the permission
#                           SET across an invalidation (`!.live = FALSE` and the
#                           perms left standing), so the permission domain is the
#                           whole defence for it -- every other token-survival
#                           switch keeps `live` too and breaks the invariant
#                           whatever the domain is;
#   BugConsumeKeepsMcGa     arms on the model's ONE exact set equality over
#                           `tok.perms`, so it is what says the widening did not
#                           make the narrow witness unreachable.
#
# Between them they cover both of the only perms-valued invariant clauses.
# SOLO-style, and that is not a preference: the runner derives the expected
# reason only where exactly ONE switch is armed, and verdict_gate.check_reasons
# falls back to a TWIN SEARCH for a configuration that is not solo -- which would
# find the NARROW `Solo_*` twin of the same switch and attribute a run at this
# scope to a run at that one. floors.txt's BootCarryMut_* rows record the same
# reasoning for the same shape. No narrow twins at these constants either: both
# arms would be RED, floors.txt gives a RED row no floor, and nothing in the tree
# would compare them.
#
# THE HONEST LIMIT: no switch in the roster can be killed ONLY under the wide
# arm, so this family proves the wide arm's observers are FALSIFIABLE -- not that
# the widening is load-bearing. A `Perms` ALPHABET change is the only route to
# the stronger claim, and assurance/platform.toml's PLAT-MODEL-001 already
# records why that is a source obligation rather than a wider finite domain.
PERM_WIDE_BUGS=(BugStopUsingKeepsPerms BugConsumeKeepsMcGa)
for b in "${PERM_WIDE_BUGS[@]}"; do
  SOLO=1 wide=TRUE ship_auv=TRUE retries=2 mism=1 rps='{r1}' chans='{c1, c2}' \
    emit "PermWideMut_$b.cfg" "$b" FALSE TRUE
done
# EF_MINPINLEN[1] -- the gate PLAT-MODEL-010 measured missing. Its own pair for
# the same reason `WidePerms` has one: the flag is reachable from every PIN-set
# state, so carrying it in Shipped.cfg would be a second copy of the space that
# configuration's row in formal/README.md already pays for. The constants are
# PermWide.cfg's. alwaysUv is ON to keep the pair comparable with that arm and
# for no reason of this gate's own -- `AlwaysUvShipped` does not decide whether a
# PIN exists, and an earlier draft of this comment claimed it did. The mutant
# drops the guard and must go RED on NoAuthorizationBypass -- a token issued over
# a gate the firmware holds.
force_ch=TRUE ship_auv=TRUE retries=2 mism=1 rps='{r1}' chans='{c1, c2}' \
  emit ForceChange.cfg "" FALSE TRUE
# The two findings this model produced, kept as regression configurations rather
# than deleted: each is the tree with exactly the shipped fix taken back out.
#
# E76 IS THE ONE WHERE THAT SENTENCE PRODUCED NOTHING. The tree's own fix for it
# is `BugSeedDoesNotLead = FALSE`, so "the shipped fix taken back out" is the
# `Mut_` loop below verbatim -- and `emit Historical_E76.cfg BugSeedDoesNotLead
# FALSE TRUE` passed the same four arguments the loop passes, so the two files
# were BYTE-IDENTICAL from 301c53a, the commit that introduced them, until this
# line changed. One experiment under a pair of names, and every denominator
# derived by grepping `formal/*.cfg` counted that experiment twice.
#
# So the row is the COUNTERFACTUAL instead, which is the one experiment in this
# family nothing else runs: the pre-0x08BF tree with the repair the model
# proposed and the maintainer did not take. `FixSweepDropsCredsBeforeRpEntries`
# had never been passed TRUE by any call -- every configuration that assigned it
# assigned it FALSE -- so the conjunct it guards (RSKeySecurityState.tla:1412) could
# be deleted with every recorded verdict unchanged: a model constant nothing
# branches on. Armed HERE it is load-bearing, because this row is GREEN only if
# the repair closes E76, and deleting the conjunct makes this file's behaviour
# `Mut_BugSeedDoesNotLead.cfg`'s and the row goes RED. That is the discharge
# `assurance/platform.toml`'s PLAT-CRED-004 asks for, in the place it asks for.
#
# Shipped.cfg's constants and NOT a reduced ladder, which is the whole point:
# the sibling it must be read against, `Mut_BugSeedDoesNotLead.cfg`, runs at
# those constants, so a one-line difference between the two files is a one-line
# explanation of the difference in verdict. Reduce them and a GREEN could be the
# repair or could be a scope too small to express the defect, and nothing in the
# tree would separate the two -- there is no RED twin at reduced constants, and
# minting one would take a name the runner's own tier roster does not have.
emit Historical_E76.cfg BugSeedDoesNotLead TRUE TRUE
# E77 is closed at BOTH ends now: the consumer refuses the stranded record
# (32b9fa3) and eab4b5c stopped the wipe producing one. So reproducing its
# counterexample takes the producer back out too -- the record the consumer
# fix still exists for is one an OLDER build already wrote to flash.
emit Historical_E77.cfg BugPpuatIsAGate FALSE FALSE
# Mutants run on the tree's own settings, so nothing pre-existing can mask them.
for b in "${BUGS[@]}"; do emit "Mut_$b.cfg" "$b" FALSE TRUE; done
# One config per mutant listing ONLY its target invariant.
for b in "${BUGS[@]}"; do SOLO=1 emit "Solo_$b.cfg" "$b" FALSE TRUE; done
# NoAccessibleSecretWithoutGate is the one invariant no switch names as its
# target. BugResetGatesFirst breaks it as well as its own, and this proves that
# solo -- previously a hand-written file wearing this script's header.
SOLO=1 SOLO_INV=NoAccessibleSecretWithoutGate \
  emit Solo_NoAccessibleSecretWithoutGate.cfg BugResetGatesFirst FALSE TRUE
# One per structural fact, against the mutant that makes it false. Without these
# the two would be claims asserted only where nothing can break them.
for i in "${EXTRA_INV[@]}"; do
  SOLO=1 SOLO_INV="$i" emit "Solo_$i.cfg" "$(extra_mutant "$i")" FALSE TRUE
done
# ONE CONFIG PER CLAUSE. `Solo_*` names an invariant and never a clause, and all
# four reset-family mutants reported ResetNeverWeakensSurvivingState on its THIRD
# clause -- which fires at depth 8 where the other two need 16 and 18, so it
# always got there first and two thirds of the invariant had no owner on record.
# The grid behind these three lines is in formal/README.md. `CLAUSE_INV` is
# declared beside ALL_INV above, because `emit`'s `clauses` knob reads it too.
clause_mutant() {
  case "$1" in
    # The phase order is the ONLY owner of the first two clauses.
    ResetKeepsThePinGate)      echo BugResetGatesFirst ;;
    ResetKeepsTheAlwaysUvGate) echo BugResetGatesFirst ;;
    # The third has three; the marker's own is the one that names it.
    ResetKeepsTheBackupSeal)   echo BugBackupSealedNotAGate ;;
  esac
}
for i in "${CLAUSE_INV[@]}"; do
  SOLO=1 SOLO_INV="$i" emit "SoloClause_$i.cfg" "$(clause_mutant "$i")" FALSE TRUE
done

# Liveness. Its own constants, and they are SMALLER on purpose -- TLC's
# liveness check builds a behaviour graph on top of the state graph, so the cost
# is not comparable to an invariant run. The reduction is stated here rather
# than hidden: one relying party, one channel, MaxRetries 2 : MismatchLimit 1.
emit_live() { # $1 = cfg, $2 = liveness bug switch (""), $3 = "full" for the
              # safety matrix's own constants
  local out=$1 on=${2:-} size=${3:-small}
  local rps='{"r1"}' chans='{"c1"}' retries=2 mism=1
  if [ "$size" = full ]; then
    rps='{"r1", "r2"}'; chans='{"c1", "c2"}'; retries=3; mism=2
  fi
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION FairSpec"
    echo "CONSTANTS"
    echo "    RPs = $rps"
    echo "    Channels = $chans"
    echo "    MaxRetries = $retries"
    echo "    MismatchLimit = $mism"
    echo "    MaxClock = 1"
    echo "    ResetWindow = 0"
    echo "    AlwaysUvShipped = ${ship_auv:-FALSE}"
    echo "    WidePerms = FALSE"
    echo "    ForceChangeModelled = FALSE"
    for b in "${BUGS[@]}"; do echo "    $b = FALSE"; done
    for b in "${LIVE_BUGS[@]}" "${SHAPE_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "    FixSweepDropsCredsBeforeRpEntries = FALSE"
    echo "    FixPpuatRequiresPin = TRUE"
    echo "PROPERTIES"
    if [ -n "$on" ]; then
      echo "    $(live_target "$on")"
    else
      for pr in "${ALL_PROP[@]}"; do echo "    $pr"; done
    fi
  } > "$out"
}
# The fairness SHAPE check. `Spec`, not `FairSpec`: OpAdvancesIsOneActivity is a
# safety invariant about what can be ENABLED, and it costs eighteen ENABLED
# evaluations per state, so it runs at the liveness constants and alone.
emit_shape() { # $1 = cfg, $2 = switch ("")
  local out=$1 on=${2:-}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo "    RPs = {\"r1\"}"
    echo "    Channels = {\"c1\"}"
    echo "    MaxRetries = 2"
    echo "    MismatchLimit = 1"
    echo "    MaxClock = 1"
    echo "    ResetWindow = 0"
    echo "    AlwaysUvShipped = ${ship_auv:-FALSE}"
    echo "    WidePerms = FALSE"
    echo "    ForceChangeModelled = FALSE"
    for b in "${BUGS[@]}" "${LIVE_BUGS[@]}"; do echo "    $b = FALSE"; done
    for b in "${SHAPE_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "    FixSweepDropsCredsBeforeRpEntries = FALSE"
    echo "    FixPpuatRequiresPin = TRUE"
    echo "INVARIANTS"
    echo "    TypeOK"
    echo "    OpAdvancesIsOneActivity"
  } > "$out"
}
emit_shape Fairness.cfg ""
for b in "${SHAPE_BUGS[@]}"; do emit_shape "FairMut_$b.cfg" "$b"; done

emit_live Liveness.cfg ""
for b in "${LIVE_BUGS[@]}"; do emit_live "LiveMut_$b.cfg" "$b"; done
# The same three properties at the safety matrix's constants, so the price of
# the reduction above is a measurement rather than an assertion.
emit_live Liveness_Full.cfg "" full
echo "wrote Shipped.cfg, 2 historical configs, ${#BUGS[@]} mutant configs and ${#LIVE_BUGS[@]} liveness configs"

# ---------------------------------------------------------------------------
# RSKeyAppletSeams -- the CCID applets' security statuses. A second module, not
# more variables in the first: the two share no variable (`formal/README.md`
# carries the measurement), so a product would multiply 17 M states by this
# module's own and buy no new interleavings.
SEAM_BUGS=(BugSelectKeepsOtherApplet BugReselectResetsStatus
           BugOathReselectUnrecorded
           BugCardResetKeepsStatus BugAdminOpensKeyOps
           BugFailedChangeKeepsStatus BugPinFreshNotSpent BugPinFreshOutlivesPin
           BugSigPinNotSpent BugDecipherGhostSpentLikeSig
           BugUserStatusOpensAdmin BugRefusedValidateGrants
           BugPwStatusIgnoresAdmin BugPivChangeResetsStatus
           BugRefusedValidateDropsUnlock BugRemoveCodeUnvalidated
           BugFreshCardOpensOtpPin BugDeselectKeepsOathUnlock
           BugResetKeepsOathUnlock BugWipeWithoutItsReboot
           BugCodelessOathIsAStatus)

seam_target() {
  case "$1" in
    BugSelectKeepsOtherApplet)  echo NoStatusOutsideItsSelection ;;
    BugReselectResetsStatus)    echo ReselectPreservesAccessStatus ;;
    # The recorder's OATH exemption removed: the same invariant, reddened from
    # the other side -- by a re-lock the shipped applet performs on purpose.
    BugOathReselectUnrecorded)  echo ReselectPreservesAccessStatus ;;
    BugCardResetKeepsStatus)    echo NoStatusOutsideItsSelection ;;
    BugAdminOpensKeyOps)        echo NoKeyOpOnTheAdminStatus ;;
    BugFailedChangeKeepsStatus) echo NoStatusAfterARefusedAuth ;;
    BugPinFreshNotSpent)        echo NoKeyOpOnTheAdminStatus ;;
    BugPinFreshOutlivesPin)     echo NoKeyOpOnTheAdminStatus ;;
    BugSigPinNotSpent)          echo NoKeyOpOnTheAdminStatus ;;
    # The same invariant's STRUCTURAL clause `held["pw1"] = psig`, split the
    # other way: the ghost spends at the decipher reference, `held` does not.
    BugDecipherGhostSpentLikeSig) echo NoKeyOpOnTheAdminStatus ;;
    BugUserStatusOpensAdmin)    echo NoKeyOpOnTheAdminStatus ;;
    BugRefusedValidateGrants)   echo NoStatusAfterARefusedAuth ;;
    BugPwStatusIgnoresAdmin)    echo NoKeyOpOnTheAdminStatus ;;
    BugPivChangeResetsStatus)   echo ExemptRefusalPreservesStatus ;;
    BugRefusedValidateDropsUnlock) echo ExemptRefusalPreservesStatus ;;
    BugRemoveCodeUnvalidated)   echo AccessCodeRemovalNeedsTheCode ;;
    # The OATH default-open family. Every one of them is a status held outside
    # the selection that bought it, which is the seam invariant itself -- none
    # of the five needs a new one.
    BugFreshCardOpensOtpPin)    echo NoStatusOutsideItsSelection ;;
    BugDeselectKeepsOathUnlock) echo NoStatusOutsideItsSelection ;;
    BugResetKeepsOathUnlock)    echo NoStatusOutsideItsSelection ;;
    BugWipeWithoutItsReboot)    echo NoStatusOutsideItsSelection ;;
    BugCodelessOathIsAStatus)   echo NoStatusOutsideItsSelection ;;
  esac
}
SEAM_INV=(NoStatusOutsideItsSelection NoStatusAfterARefusedAuth
          NoKeyOpOnTheAdminStatus ReselectPreservesAccessStatus
          ExemptRefusalPreservesStatus AccessCodeRemovalNeedsTheCode)

emit_seam() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    for b in "${SEAM_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(seam_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(seam_target "$on"); echo "    $t"
      for i in "${SEAM_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${SEAM_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_seam Seams.cfg ""
for b in "${SEAM_BUGS[@]}"; do emit_seam "SeamMut_$b.cfg" "$b"; done
for b in "${SEAM_BUGS[@]}"; do emit_seam "SeamSolo_$b.cfg" "$b" 1; done
echo "wrote Seams.cfg and ${#SEAM_BUGS[@]} x 2 seam configs"

# ---------------------------------------------------------------------------
# RSKeyStore -- the flash layer (`rsk-fs`'s `Fs` over `Storage`). A third
# module for the same reason the seams are a second: the security model already
# has a PowerCut but abstracts the store to per-record flags, so it cannot ask
# whether a torn delete orphans metadata or the present-cache reads a committed
# key absent. Both are `Fs` contracts and both have shipped as defects.
STORE_BUGS=(BugDeleteValueBeforeMeta BugDeleteMetaOnlyUnderPresent
            BugDeleteHidesFaultedDrop
            BugCacheFaultAsAbsent BugTruncatedScanDecidesAll
            BugMetaAddDropsOnFault BugMetaDeleteDropsOnFault
            BugMetaWriteTearsBlob BugMetaDeleteTearsBlob)

store_target() {
  case "$1" in
    BugDeleteValueBeforeMeta)      echo NoOrphanedMetadata ;;
    BugDeleteMetaOnlyUnderPresent) echo NoOrphanedMetadata ;;
    BugDeleteHidesFaultedDrop)     echo NoSilentOrphan ;;
    BugCacheFaultAsAbsent)         echo NoFalseAbsent ;;
    BugTruncatedScanDecidesAll)    echo NoFalseAbsent ;;
    BugMetaAddDropsOnFault)        echo NoRecordLostToMetaWrite ;;
    BugMetaDeleteDropsOnFault)     echo NoFalseMetaAbsent ;;
    BugMetaWriteTearsBlob)         echo NoRecordLostToMetaWrite ;;
    BugMetaDeleteTearsBlob)        echo NoRecordLostToMetaWrite ;;
  esac
}
STORE_INV=(NoOrphanedMetadata NoSilentOrphan NoFalseAbsent NoRecordLostToMetaWrite
           NoFalseMetaAbsent)

emit_store() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo, $4 = 1 for induction, $5 = solo invariant
  local out=$1 on=${2:-} solo=${3:-0} induct=${4:-0} only=${5:-}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    # An induction probe starts from every state `IndInv` admits instead of from
    # `Init`, so depth 1 IS the claim `IndInv /\ Next => IndInv'`.
    if [ "$induct" = 1 ]; then echo "INIT IndInv"; echo "NEXT Next"
    else echo "SPECIFICATION Spec"; fi
    echo "CONSTANTS"
    echo "    Fids = {\"a\", \"b\"}"
    for b in "${STORE_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    ${only:-$(store_target "$on")}"
    elif [ -n "$on" ]; then
      local t; t=$(store_target "$on"); echo "    $t"
      for i in "${STORE_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${STORE_INV[@]}"; do echo "    $i"; done
    fi
    # The strengthening the probe named, checked here as well as assumed there --
    # and on the REACHABLE space too, which the module's own comment claimed and
    # this generator did not do: `Store.cfg` carried five invariants and not this
    # one, so `Init => IndInv` was asserted in prose and checked nowhere. Appended
    # LAST deliberately: TLC reports the first violated invariant, so a name added
    # ahead of the others would re-attribute every `StoreMut_` verdict in
    # `formal/runs.toml`.
    if [ "$induct" = 1 ] || [ -z "$on" ]; then echo "    CacheHonest"; fi
  } > "$out"
}
emit_store Store.cfg ""
for b in "${STORE_BUGS[@]}"; do emit_store "StoreMut_$b.cfg" "$b"; done
for b in "${STORE_BUGS[@]}"; do emit_store "StoreSolo_$b.cfg" "$b" 1; done
# The induction probe, and ONE mutant of it. `Init` satisfies `IndInv`, so a
# defect breaking the step from an admitted state also breaks it from a reachable
# one: the other five would be implied by their `StoreSolo_` rows and add no
# verdict. This one exists to prove the INIT/NEXT wiring can go red at all.
emit_store StoreInduction.cfg "" 0 1
emit_store StoreInductionMut_BugMetaAddDropsOnFault.cfg BugMetaAddDropsOnFault 1 1
# CacheHonest's own solo row, and the reason it is not in `store_target`: that
# table maps one switch to the ONE invariant it is the mutant OF, and
# `BugMetaDeleteDropsOnFault` is the mutant of `NoFalseMetaAbsent` — the losing
# WRITE. `CacheHonest` is the state that write leaves behind, so the same switch
# breaks both, at different moments. Without this row `SEC-STORE-005` is the only
# P0-launch property in the registry with NO model mutant at all: two
# configurations checked it and neither could go red from anything.
emit_store StoreSolo_CacheHonest.cfg BugMetaDeleteDropsOnFault 1 0 CacheHonest
echo "wrote Store.cfg, StoreInduction.cfg and ${#STORE_BUGS[@]} x 2 store configs"

# ---------------------------------------------------------------------------
# RSKeyRetryLattice -- the PIV/OpenPGP retry & recovery budget lattice. A fourth
# module for the same measured reason: it shares no variable with the others (it
# has counters, the seam has statuses), and it is the one part of the applet
# surface with no safe oracle -- exhausting a real PUK ladder blocks the card.
LATTICE_BUGS=(BugUseWhenBlocked BugWrongDoesNotSpend BugRecoveryWithoutSecret)

lattice_target() {
  case "$1" in
    BugUseWhenBlocked)        echo NoAuthWhenBlocked ;;
    BugWrongDoesNotSpend)     echo WrongAttemptIsCharged ;;
    BugRecoveryWithoutSecret) echo BudgetRisesOnlyWithItsSecret ;;
  esac
}
LATTICE_INV=(NoAuthWhenBlocked WrongAttemptIsCharged BudgetRisesOnlyWithItsSecret)

emit_lattice() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo, $4 = 1 for induction
  local out=$1 on=${2:-} solo=${3:-0} induct=${4:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    # An induction probe starts from every state `IndInv` admits instead of from
    # `Init`, so depth 1 IS the claim `IndInv /\ Next => IndInv'`.
    if [ "$induct" = 1 ]; then echo "INIT IndInv"; echo "NEXT Next"
    else echo "SPECIFICATION Spec"; fi
    echo "CONSTANTS"
    echo "    Max = 2"
    for b in "${LATTICE_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(lattice_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(lattice_target "$on"); echo "    $t"
      for i in "${LATTICE_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${LATTICE_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_lattice Lattice.cfg ""
for b in "${LATTICE_BUGS[@]}"; do emit_lattice "LatMut_$b.cfg" "$b"; done
for b in "${LATTICE_BUGS[@]}"; do emit_lattice "LatSolo_$b.cfg" "$b" 1; done
# The induction probe, and ONE mutant of it, the shape StoreInduction.cfg uses.
# `Init` satisfies `IndInv` (every counter at `Max`, `viol = {}`), so a defect
# that breaks the step from an admitted state breaks it from a reachable one too
# and the other two would only repeat their `LatSolo_` rows. This one is here to
# show the INIT/NEXT wiring can go red at all.
emit_lattice LatInduction.cfg "" 0 1
emit_lattice LatInductionMut_BugWrongDoesNotSpend.cfg BugWrongDoesNotSpend 1 1
echo "wrote Lattice.cfg, LatInduction.cfg and ${#LATTICE_BUGS[@]} x 2 lattice configs"

# ---------------------------------------------------------------------------
# RSKeyAppletPolicies -- the real stateful operation doors across PIV,
# OpenPGP, OATH and Yubico OTP. OATH/OTP access codes have no retry counters,
# so this complements the lattice without inventing protocol state.
POLICY_BUGS=(BugPivPolicyIgnored BugPivAlwaysDoesNotSpend
             BugPgpAttributeKeepsKey BugOathCodeIgnored BugOathTouchIgnored
             BugOtpCodeIgnored BugOtpCounterRepeats
             BugOtpPressTypesUnpersisted BugOtpBootKeepsPosition
             BugOtpSwapKeepsSession)

policy_target() {
  case "$1" in
    BugPivPolicyIgnored)          echo PivOperationNeedsSlotPolicy ;;
    BugPivAlwaysDoesNotSpend)     echo PivAlwaysSpendsFreshness ;;
    BugPgpAttributeKeepsKey)      echo AttributeChangeInvalidatesTheKey ;;
    BugOathCodeIgnored)           echo OathCredentialNeedsItsGates ;;
    BugOathTouchIgnored)          echo OathCredentialNeedsItsGates ;;
    BugOtpCodeIgnored)            echo OtpSlotMutationNeedsItsCode ;;
    BugOtpCounterRepeats)         echo OtpCounterNeverRepeats ;;
    BugOtpPressTypesUnpersisted)  echo OtpCounterNeverRepeats ;;
    BugOtpBootKeepsPosition)      echo OtpCounterNeverRepeats ;;
    BugOtpSwapKeepsSession)       echo OtpCounterNeverRepeats ;;
  esac
}
POLICY_INV=(PivOperationNeedsSlotPolicy PivAlwaysSpendsFreshness
            AttributeChangeInvalidatesTheKey OathCredentialNeedsItsGates
            OtpSlotMutationNeedsItsCode OtpCounterNeverRepeats)

emit_policy() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    # A boot's first press takes a step of the counter before it types, so three
    # leaves a record room to be pressed in a second boot; at two it never is.
    echo "    CounterMax = 3"
    # The session wraps at SessionMax, which is where the persisted half moves;
    # a second slot is what a swap needs to re-pair a record with the wrong
    # session. Both minima are measured and recorded in formal/scopes.txt.
    echo "    SessionMax = 1"
    echo "    Slots = {1, 2}"
    for b in "${POLICY_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(policy_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(policy_target "$on"); echo "    $t"
      for i in "${POLICY_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${POLICY_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_policy Policies.cfg ""
for b in "${POLICY_BUGS[@]}"; do emit_policy "PolicyMut_$b.cfg" "$b"; done
for b in "${POLICY_BUGS[@]}"; do emit_policy "PolicySolo_$b.cfg" "$b" 1; done
echo "wrote Policies.cfg and ${#POLICY_BUGS[@]} x 2 policy configs"

# ---------------------------------------------------------------------------
# RSKeyAdminSurface -- the enabled-applications mask, its always-on carve-out,
# and the rescue presence gate. A fifth module: it shares no variable with the
# rest (the mask is not a status, a counter, a flash record or the CTAP state),
# and its reversibility claim is a SEQUENCE property a single-call proof cannot
# see.
ADMIN_BUGS=(BugAdminGateable BugPrivilegedOpUngated BugLockWriteResetsCaps
            BugMaskIsCosmetic)

admin_target() {
  case "$1" in
    BugAdminGateable)        echo AdminSurfaceAlwaysReachable ;;
    BugPrivilegedOpUngated)  echo PrivilegedOpNeedsPresence ;;
    BugLockWriteResetsCaps)  echo DisableSetSurvivesLockWrite ;;
    BugMaskIsCosmetic)       echo DisabledAppletNeverDispatches ;;
  esac
}
ADMIN_INV=(AdminSurfaceAlwaysReachable PrivilegedOpNeedsPresence
           DisableSetSurvivesLockWrite DisabledAppletNeverDispatches)

emit_admin() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo "    Caps = {\"piv\", \"oath\", \"otp\"}"
    for b in "${ADMIN_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(admin_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(admin_target "$on"); echo "    $t"
      for i in "${ADMIN_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${ADMIN_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_admin Admin.cfg ""
for b in "${ADMIN_BUGS[@]}"; do emit_admin "AdminMut_$b.cfg" "$b"; done
for b in "${ADMIN_BUGS[@]}"; do emit_admin "AdminSolo_$b.cfg" "$b" 1; done
echo "wrote Admin.cfg and ${#ADMIN_BUGS[@]} x 2 admin configs"

# ---------------------------------------------------------------------------
# RSKeyTrustedDisplay -- the confirm ceremony: WhatIsConfirmedIsWhatIsShown,
# decomposed into the three rules TLC can hold. A sixth module: what the glass
# shows is no other module's variable, and two of the three mutants are defects
# that actually shipped on the display build.
DISP_BUGS=(BugPadSubstitutesForCard BugPreScreenTouchApproves BugAnyTapApproves)

disp_target() {
  case "$1" in
    BugPadSubstitutesForCard)  echo ConfirmNamesTheOperation ;;
    BugPreScreenTouchApproves) echo StaleTouchApprovesNothing ;;
    BugAnyTapApproves)         echo OnlyAllowConfirms ;;
  esac
}
DISP_INV=(ConfirmNamesTheOperation StaleTouchApprovesNothing OnlyAllowConfirms)

emit_disp() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    for b in "${DISP_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(disp_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(disp_target "$on"); echo "    $t"
      for i in "${DISP_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${DISP_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_disp Display.cfg ""
for b in "${DISP_BUGS[@]}"; do emit_disp "DispMut_$b.cfg" "$b"; done
for b in "${DISP_BUGS[@]}"; do emit_disp "DispSolo_$b.cfg" "$b" 1; done
echo "wrote Display.cfg and ${#DISP_BUGS[@]} x 2 display configs"

# ---------------------------------------------------------------------------
# RSKeyBootHardening -- the cross-boot at-rest lap and the scratch-word lock
# carry. A seventh module: firmware/ has no host tests by construction, so the
# model is the only instrument that exercises these interleavings at all.
BOOT_BUGS=(BugRekeyKeepsTheMarker BugMarkerBeforeScrub BugPartialLockCarry)

boot_target() {
  case "$1" in
    BugRekeyKeepsTheMarker) echo MarkerNeverLies ;;
    BugMarkerBeforeScrub)   echo MarkerNeverLies ;;
    BugPartialLockCarry)    echo TheWholeLockRides ;;
  esac
}
BOOT_INV=(MarkerNeverLies TheWholeLockRides)

emit_boot() { # cfg, switch (""), 1 for solo, scratch2 (TRUE), 1 for induction
  local out=$1 on=${2:-} solo=${3:-0} clears=${4:-TRUE} induct=${5:-0}
  # The write/re-arm ORDER arm, off unless the caller asks for it: `order` splits
  # the lazy re-key into two steps and `wfirst` picks which half lands first.
  # `only` names the one invariant such a row checks -- it arms no BOOT_BUGS
  # switch, so neither branch below has a target to derive for it.
  local order=${order:-FALSE} wfirst=${wfirst:-FALSE} only=${only:-}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    if [ "$induct" = 1 ]; then echo "INIT IndInv"; echo "NEXT Next"
    else echo "SPECIFICATION Spec"; fi
    echo "CONSTANTS"
    echo "    PowerOnClearsScratch2 = $clears"
    echo "    MaxWeak = 2"
    echo "    RekeyOrderModelled = $order"
    echo "    BugRecordWriteBeforeRearm = $wfirst"
    for b in "${BOOT_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$only" ]; then
      echo "    $only"
    elif [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(boot_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(boot_target "$on"); echo "    $t"
      for i in "${BOOT_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${BOOT_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_boot Boot.cfg ""
# The open hardware assumption's other arm: a power-on that does NOT clear the
# scratch word. Same invariants, so a difference here is the assumption's price.
emit_boot BootCarry.cfg "" 0 FALSE
for b in "${BOOT_BUGS[@]}"; do emit_boot "BootMut_$b.cfg" "$b"; done
for b in "${BOOT_BUGS[@]}"; do emit_boot "BootSolo_$b.cfg" "$b" 1; done
# Every mutant on the OTHER arm too. That they all still fall there was measured
# once when the arm landed and then thrown away, which is how "both arms behave"
# becomes a sentence nobody can re-check.
for b in "${BOOT_BUGS[@]}"; do emit_boot "BootCarryMut_$b.cfg" "$b" 1 FALSE; done
# The induction probe, and ONE mutant of it -- see the store half for why one.
emit_boot BootInduction.cfg "" 0 TRUE 1
emit_boot BootInductionMut_BugRekeyKeepsTheMarker.cfg BugRekeyKeepsTheMarker 1 TRUE 1
# THE WRITE/RE-ARM ORDER, both arms, and the only two rows in this module that
# split the pair. `Historical_` and not `BootMut_` because the RED one injects no
# defect -- it is the order the tree SHIPS, so it owes a hand-named row whose
# verdict the registry states, not a family whose glob would sweep it in with the
# mutants and hand it their expectations. MarkerNeverLies alone: neither arm
# touches the lock carry, so a RED naming TheWholeLockRides would be a kill for a
# defect neither row models.
order=TRUE wfirst=TRUE only=MarkerNeverLies emit_boot Historical_BootWriteThenRearm.cfg
order=TRUE wfirst=FALSE only=MarkerNeverLies emit_boot Historical_BootRearmThenWrite.cfg
echo "wrote Boot.cfg, BootCarry.cfg, BootInduction.cfg, the 2 order rows and ${#BOOT_BUGS[@]} x 3 boot configs + 1 probe mutant"

# ---------------------------------------------------------------------------
# RSKeyTransport -- the CTAPHID frame reassembler. An eighth module for the
# last uncovered crate (rsk-usb): the channel/seq/length checks are SEQUENCE
# properties over a multi-frame transaction, which a per-frame test and a
# sampling fuzzer exercise but do not assert.
TRANS_BUGS=(BugContIgnoresChannel BugContIgnoresSeq BugInitLenUnchecked)

trans_target() {
  case "$1" in
    BugContIgnoresChannel) echo NoCrossChannelSplice ;;
    BugContIgnoresSeq)     echo NoSequenceGap ;;
    BugInitLenUnchecked)   echo NoBufferOverrun ;;
  esac
}
TRANS_INV=(NoCrossChannelSplice NoSequenceGap NoBufferOverrun)

# SYMMETRY over Channels here: CONSIDERED, and REJECTED. The record sits beside
# the function that would carry the line rather than in a roadmap, because this
# is where the next reader will reach for it.
#
# It would erase the identity the properties are ABOUT. `owner` ranges over
# Channels and `Cont`'s first arm is `c # owner`; a permutation quotient
# identifies `owner = a` with `owner = b`, which is precisely the distinction
# NoCrossChannelSplice's ghost is written on. That is the same fact scopes.txt
# records as `Channels 2` for it: GREEN over one channel, RED from two.
#
# And there is nothing to buy. The quotient in `emit` above is priced at
# 61 215 504 distinct states -> 25 829 584; Transport.cfg's WHOLE graph is 13
# distinct states at depth 4, 127 generated, under a second (formal/runs.toml).
# RSKeyTransport defines no Symm and does not EXTEND TLC either, so it is a
# MODEL change plus a re-run of all seven transport rows, spent to halve 13.
emit_trans() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo "    Channels = {\"a\", \"b\"}"
    echo "    Cap = 3"
    for b in "${TRANS_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(trans_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(trans_target "$on"); echo "    $t"
      for i in "${TRANS_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${TRANS_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_trans Transport.cfg ""
for b in "${TRANS_BUGS[@]}"; do emit_trans "TransMut_$b.cfg" "$b"; done
for b in "${TRANS_BUGS[@]}"; do emit_trans "TransSolo_$b.cfg" "$b" 1; done
echo "wrote Transport.cfg and ${#TRANS_BUGS[@]} x 2 transport configs"

# ---------------------------------------------------------------------------
# Phase 4 -- trace validation. TraceSeams replays a RECORDED emulator session
# against the seam model (a divergence deadlocks at the exact step, so the row
# must be GREEN); TraceSeamsBad replays a hand-written session the model must
# REFUSE (floors.txt requires it RED -- the harness proven able to reject).
# Every seam Bug* is FALSE: a trace is validated against the SHIPPED model.
emit_traceval() { # $1 = cfg
  local out=$1
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION TraceSpec"
    echo "CONSTANTS"
    for b in "${SEAM_BUGS[@]}"; do echo "    $b = FALSE"; done
    echo "INVARIANTS"
    echo "    TypeOK"
    for i in "${SEAM_INV[@]}"; do echo "    $i"; done
  } > "$out"
}
emit_traceval TraceSeams.cfg
emit_traceval TraceSeamsBad.cfg
echo "wrote TraceSeams.cfg and TraceSeamsBad.cfg"

# RSKeySecurityState raw-snapshot replay. Unlike TraceSeams this consumes β over
# implementation fields and the canonical γ/α comparison. The two mutants are
# the phase-4 falsifiability tests; the no-R4b control proves the α shift has no
# other observer.
emit_security_trace() { # cfg, beta, alpha, outcome, R4b, uvNotRqd, resetWindow, auvArm, pinSet
  local out=$1 beta=$2 alpha=$3 outcome=$4 r4b=$5 uv=${6:-FALSE} win=${7:-FALSE}
  local auv=${8:-FALSE} pinset=${9:-FALSE}
  {
    echo "\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION TraceSpec"
    echo "CONSTANTS"
    echo '    RPs = {"rp1", "rp2"}'
    echo '    Channels = {"c1", "c2"}'
    echo "    MaxRetries = 8"
    echo "    MismatchLimit = 3"
    echo "    MaxClock = 1"
    echo "    ResetWindow = 0"
    echo "    AlwaysUvShipped = ${ship_auv:-FALSE}"
    echo "    WidePerms = FALSE"
    echo "    ForceChangeModelled = FALSE"
    for b in "${BUGS[@]}" "${LIVE_BUGS[@]}" "${SHAPE_BUGS[@]}"; do
      echo "    $b = FALSE"
    done
    echo "    FixSweepDropsCredsBeforeRpEntries = FALSE"
    echo "    FixPpuatRequiresPin = TRUE"
    echo "    MutateBeta = $beta"
    echo "    MutateAlpha = $alpha"
    echo "    MutateOutcome = $outcome"
    echo "    MutateUvNotRqd = $uv"
    echo "    MutateResetWindow = $win"
    echo "    MutateAlwaysUvArm = $auv"
    echo "    MutatePinSet = $pinset"
    echo "    CheckR4b = $r4b"
    echo "INVARIANTS"
    echo "    TypeOK"
    echo "    R4aRawRefinesB"
    echo "    R4bEventConsensus"
    echo "    R4cGateAnswers"
    if [ "$r4b" = TRUE ]; then echo "    R4bAlphaMatchesGamma"; fi
  } > "$out"
}
emit_security_trace TraceSecurity.cfg FALSE FALSE FALSE TRUE
emit_security_trace TraceSecurityBadBeta.cfg TRUE FALSE FALSE TRUE
emit_security_trace TraceSecurityBadAlpha.cfg FALSE TRUE FALSE TRUE
emit_security_trace TraceSecurityBadAlphaNoR4b.cfg FALSE TRUE FALSE FALSE
emit_security_trace TraceSecurityBadOutcome.cfg FALSE FALSE TRUE TRUE
# R4c's own two: each takes ONE half of the gate rule out, so a RED names which
# half was load-bearing rather than "a gate somewhere".
emit_security_trace TraceSecurityBadUvNotRqd.cfg FALSE FALSE FALSE TRUE TRUE FALSE
emit_security_trace TraceSecurityBadResetWindow.cfg FALSE FALSE FALSE TRUE FALSE TRUE
# R4c's third: the alwaysUv arm the rule did not have until the recording carried
# a session with it on. Without this arm `pin.set /\ rk` predicts SERVED where the
# device answers PUAT_REQUIRED.
emit_security_trace TraceSecurityBadAlwaysUvArm.cfg FALSE FALSE FALSE TRUE FALSE FALSE TRUE
# R4c's fourth, and the one the recording had no cell for until `09` was added:
# a rule that forgets `makeCredUvNotRqd` and refuses a token-less discoverable
# registration on a device with NO PIN. It can only go red at a gate boundary
# where `pin.set` is FALSE, which is exactly what that suite records -- while
# every boundary carried a PIN this conjunct was true rather than falsifiable.
emit_security_trace TraceSecurityBadPinSet.cfg FALSE FALSE FALSE TRUE FALSE FALSE FALSE TRUE
echo "wrote TraceSecurity baseline, state/outcome/gate divergences, and the R4b control"

# ---------------------------------------------------------------------------
# Phase 5 -- native state refinement B -> A and the separate outcome-labelled
# action property. Both use the liveness-sized constants: the purpose is an
# exhaustive semantic bridge, not another copy of the 60M-state shipped row.
emit_token_refinement() { # cfg, gamma mutant, outcome mutant, state|outcome
  local out=$1 bad_gamma=$2 dead_token=$3 kind=$4
  {
    echo "\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo '    RPs = {"r1"}'
    echo '    Channels = {"c1"}'
    echo "    MaxRetries = 1"
    echo "    MismatchLimit = 1"
    echo "    MaxClock = 0"
    echo "    ResetWindow = 0"
    echo "    AlwaysUvShipped = ${ship_auv:-FALSE}"
    echo "    WidePerms = FALSE"
    echo "    ForceChangeModelled = FALSE"
    for b in "${BUGS[@]}" "${LIVE_BUGS[@]}" "${SHAPE_BUGS[@]}"; do
      echo "    $b = FALSE"
    done
    echo "    FixSweepDropsCredsBeforeRpEntries = FALSE"
    echo "    FixPpuatRequiresPin = TRUE"
    echo "    MutateTokenGamma = $bad_gamma"
    echo "    BugDeadTokenAuthorized = $dead_token"
    if [ "$kind" = state ]; then
      echo "PROPERTIES"
      echo "    R1sTokenStateRefinement"
    else
      echo "INVARIANTS"
      echo "    R1oOutcomeCoverage"
      echo "PROPERTIES"
      echo "    R1oTokenOutcomes"
    fi
  } > "$out"
}
emit_token_refinement TokenRefinement.cfg FALSE FALSE state
emit_token_refinement TokenRefinementBadMap.cfg TRUE FALSE state
emit_token_refinement TokenRefinementOutcome.cfg FALSE FALSE outcome
emit_token_refinement TokenRefinementDeadToken.cfg FALSE TRUE outcome
echo "wrote phase-5 state/outcome refinement configs and mutants"

# ---------------------------------------------------------------------------
# Tier A's requirement half (RSKeyTokenGate). Three configurations, and the
# middle one is the reason the other two mean anything: `RequiredGate` is
# transcribed from CTAP rather than from `AllowedEventRel`, so the set on which
# the two disagree is a measurement and not a claim.
emit_token_gate() { # $1 = cfg, $2 = spec or "probe", $3 = bug switch (""), $4... = inv
  local out=$1 spec=$2 on=${3:-}
  shift 3
  {
    echo "\* Generated by formal/gen-configs.sh -- do not edit by hand."
    # The oracle row is a PROBE, the shape StoreInduction.cfg uses: every state
    # of the set is an initial state, so the distinct count IS its size.
    if [ "$spec" = probe ]; then echo "INIT DisagreeInit"; echo "NEXT DisagreeNext"
    else echo "SPECIFICATION $spec"; fi
    echo "CONSTANTS"
    if [ -n "$on" ]; then echo "    $on = TRUE"; else
      echo "    BugUnauthorizedEdge = FALSE"
    fi
    echo "INVARIANTS"
    local i; for i in "$@"; do echo "    $i"; done
  } > "$out"
}
emit_token_gate TokenGate.cfg Spec "" TypeOK NoAuthorizationBypassA
# The oracle's non-degeneracy, walked rather than asserted: every state on which
# the requirement and the relation differ, printed with the operations it
# differs on. An oracle taken from the relation leaves Init empty.
emit_token_gate TokenGateOracle.cfg probe "" TypeOK
# E4a: the two are NOT the same predicate, and this row is what says so. A GREEN
# here is the D5 refutation repeating itself, which is why floors.txt requires RED.
emit_token_gate TokenGateDisagreement.cfg Spec "" RequiredGateAgreesWithRelation
# One Authorized edge the requirement forbids, so the A-level invariant is known
# able to fail rather than assumed to be.
emit_token_gate TokenGateMut_BugUnauthorizedEdge.cfg Spec BugUnauthorizedEdge \
  NoAuthorizationBypassA
echo "wrote tier-A gate configs and the unauthorized-edge mutant"

# ---------------------------------------------------------------------------
# NO TWO NAMES MAY BE ONE CONFIGURATION, and this is what makes the duplicate
# above impossible to write again rather than merely absent today. Nothing here
# compared one emitted file with another for its whole life: `Historical_E76
# .cfg` and `Mut_BugSeedDoesNotLead.cfg` were byte-identical from 301c53a, so a
# pair of matrix rows ran a single experiment, each was paid for in wall time,
# and every denominator derived from the roster counted that file twice.
#
# ONE PASS AT THE END, not a test inside `emit`. FIFTEEN functions in this file
# write a configuration (`grep -c '^emit[a-z_]*() {'`); a per-emitter guard is
# fourteen copies plus the one the sixteenth emitter ships without -- which is
# this tree's measured shape for a new guard, 5 of 5. Sweeping `$out_dir` also
# reaches a configuration written BY HAND beside the generated ones, which no
# emitter can see.
#
# awk and not a hasher: the content IS the array key, so nothing here depends on
# `sha256sum`/`shasum`/`md5` existing under whichever shell runs this. The key
# folds a missing final newline into the same bucket as a present one; that is a
# WIDER net than byte equality and deliberately so -- `scripts/config_gen_gate
# .py` compares the tree byte-for-byte, and the two disagreeing would mean this
# passed something that row must then refuse.
# THE ONE PAIR WHERE TWO IDENTICAL FILES ARE TWO EXPERIMENTS, and it is written
# as a PAIR because the first edition wrote it as a NAME and shipped the sixth
# hole of the family it closes: a DUP_OK naming TraceSeamsBad.cfg alone exempted
# that file from being anybody's twin, so `cp Shipped.cfg TraceSeamsBad.cfg` passed both
# guards -- the exemption held while the file had become the twin of a DIFFERENT
# configuration and the pair it was granted for had quietly gone.
#
# Why the pair is legitimate: TLC takes the MODULE as an argument, and the
# runner's own `spec_for` routes `TraceSeamsBad.cfg` to TraceSeamsBad.tla and
# `TraceSeams.cfg` to TraceSeams.tla -- the divergence that pair of rows is
# about lives in the modules, which is the same sentence
# `scripts/verdict_gate.py`'s UNSWITCHED_RED already records for that file. This
# sweep cannot ASK that question (the routing lives in the runner, which is not
# beside this script in every tree it is generated into), so the pair is
# asserted here and `scripts/config_gen_gate.py` reads this line and checks the
# premise against `spec_for` itself. Both directions below: a pair that is no
# longer a pair is a stale carve-out, and reported as one.
#
# `<later>:<owner>`, with the names in the order the sweep prints them -- the
# owner is the alphabetically first of the two, because that is the one the
# `*.cfg` glob reaches first.
DUP_OK="TraceSeamsBad.cfg:TraceSeams.cfg"
pairs=$(awk '
  FNR == 1 { order[++n] = FILENAME }
  { body[FILENAME] = body[FILENAME] $0 "\n" }
  END {
    for (i = 1; i <= n; i++)
      if (body[order[i]] in seen) printf "%s:%s\n", order[i], seen[body[order[i]]]
      else seen[body[order[i]]] = order[i]
  }' *.cfg)
problems=""
for pair in $pairs; do
  case " $DUP_OK " in
    *" $pair "*) ;;
    *) problems="$problems  ${pair%%:*} is the same configuration as ${pair#*:}
" ;;
  esac
done
# Unquoted, so the newline separators collapse to spaces: `case " $pairs "` over
# the raw value cannot match a pair sitting at the start or end of a line, and
# the stale-carve-out arm would then fire on a pair that IS there.
pairs_line=$(echo $pairs)
for pair in $DUP_OK; do
  case " $pairs_line " in
    *" $pair "*) ;;
    *) problems="$problems  $pair: carved out as a legitimate identical pair, but
  they are not each other's twin now -- stale carve-out in gen-configs.sh
" ;;
  esac
done
if [ -n "$problems" ]; then
  echo "gen-configs: one configuration under a pair of names -- give it one" >&2
  echo "name, or make the second row a different experiment:" >&2
  printf '%s' "$problems" >&2
  exit 1
fi
echo "checked that no configuration is another's byte-for-byte twin"
