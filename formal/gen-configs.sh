#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Generate the TLC configurations: `Shipped.cfg` (every mutation switch off --
# the tree as it stands) plus one `Mut_<Bug>.cfg` per switch. Each mutant lists
# the invariant it is expected to break FIRST, because TLC reports the first
# violated invariant and stops.
set -euo pipefail
cd "$(dirname "$0")"

BUGS=(BugResetGatesFirst BugCredBeforeRp BugTokenSurvivesPinChange
      BugSetPinKeepsPpuat BugChangePinKeepsPpuat BugStopUsingKeepsPerms
      BugNoConsumeAfterUp BugUnscopedCancel BugTouchNotSpent
      BugSoftLockLostOnWarmReset BugWarmResetReopensWindow
      BugCmWalkIgnoresChannel BugDeleteRpBeforeCred BugBackupSealedNotAGate
      BugConsumeKeepsMcGa BugNoDropStaleCancelAtEntry BugWrongPinKeepsToken
      BugSeedDoesNotLead BugNoTouchRequired BugStateResetAfterWipe
      BugPanelCancelable BugUnscopedOtpCancel BugLocalPinKeepsToken
      BugSetPinOverExisting BugHostPreemptsLocalWait BugLocalPinIgnoresBudget
      BugPpuatIsAGate BugPinWriteBeforeRevoke)

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
extra_mutant() {
  # ctx.state.reset() moved back behind the flash work leaves the RAM seed
  # standing past the flash delete AND a live token past EF_PIN's deletion.
  case "$1" in
    RamNeverOutlivesFlashSeed)   echo BugStateResetAfterWipe ;;
    NoLiveTokenWithoutPinRecord) echo BugStateResetAfterWipe ;;
  esac
}

emit() { # $1 = cfg, $2 = bug switch (""), $3 = sweep fix, $4 = ppuat fix
  local out=$1 on=${2:-} fix=${3:-TRUE} fix2=${4:-${3:-TRUE}}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    # MODEL VALUES, not strings, because `SYMMETRY` needs them -- and the
    # symmetry is what pays for the two constants below being the firmware's
    # own. Quotienting the interchangeable relying parties and channels takes
    # 61 215 504 distinct states to 25 829 584, so MAX_PIN_RETRIES = 8 and
    # PIN_MISMATCH_LIMIT = 3 (consts.rs:319,323) cost 48 679 968 -- still
    # fewer than the reduced 3 : 2 explored before, with all thirty mutants
    # still RED. The README's "an argument, not a proof" is now a measurement.
    echo "    RPs = {r1, r2}"
    echo "    Channels = {c1, c2}"
    echo "    MaxRetries = 8"
    echo "    MismatchLimit = 3"
    echo "    MaxClock = 1"
    echo "    ResetWindow = 0"
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
    fi
    echo "SYMMETRY Symm"
  } > "$out"
}

# THE TREE AS IT STANDS, and it is the green baseline the mutants are measured
# against. Two constants carry the history: `FixPpuatRequiresPin` shipped
# verbatim at 0x08C0, so it is ON; `FixSweepDropsCredsBeforeRpEntries` is a
# counterfactual the tree did NOT take -- 0x08BF made the seed lead the wipe
# instead, which is the default (`BugSeedDoesNotLead = FALSE`), so it is OFF.
emit Shipped.cfg "" FALSE TRUE
# The two findings this model produced, kept as regression configurations rather
# than deleted: each is the tree with exactly the shipped fix taken back out.
emit Historical_E76.cfg BugSeedDoesNotLead FALSE TRUE
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
# The grid behind these three lines is in formal/README.md.
CLAUSE_INV=(ResetKeepsThePinGate ResetKeepsTheAlwaysUvGate ResetKeepsTheBackupSeal)
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
           BugCardResetKeepsStatus BugAdminOpensKeyOps
           BugFailedChangeKeepsStatus BugPinFreshNotSpent BugPinFreshOutlivesPin
           BugSigPinNotSpent
           BugUserStatusOpensAdmin BugRefusedValidateGrants
           BugPwStatusIgnoresAdmin BugPivChangeResetsStatus
           BugRefusedValidateDropsUnlock BugRemoveCodeUnvalidated)

seam_target() {
  case "$1" in
    BugSelectKeepsOtherApplet)  echo NoStatusOutsideItsSelection ;;
    BugReselectResetsStatus)    echo ReselectPreservesAccessStatus ;;
    BugCardResetKeepsStatus)    echo NoStatusOutsideItsSelection ;;
    BugAdminOpensKeyOps)        echo NoKeyOpOnTheAdminStatus ;;
    BugFailedChangeKeepsStatus) echo NoStatusAfterARefusedAuth ;;
    BugPinFreshNotSpent)        echo NoKeyOpOnTheAdminStatus ;;
    BugPinFreshOutlivesPin)     echo NoKeyOpOnTheAdminStatus ;;
    BugSigPinNotSpent)          echo NoKeyOpOnTheAdminStatus ;;
    BugUserStatusOpensAdmin)    echo NoKeyOpOnTheAdminStatus ;;
    BugRefusedValidateGrants)   echo NoStatusAfterARefusedAuth ;;
    BugPwStatusIgnoresAdmin)    echo NoKeyOpOnTheAdminStatus ;;
    BugPivChangeResetsStatus)   echo ExemptRefusalPreservesStatus ;;
    BugRefusedValidateDropsUnlock) echo ExemptRefusalPreservesStatus ;;
    BugRemoveCodeUnvalidated)   echo AccessCodeRemovalNeedsTheCode ;;
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
            BugCacheFaultAsAbsent BugTruncatedScanDecidesAll
            BugMetaAddDropsOnFault BugMetaDeleteDropsOnFault)

store_target() {
  case "$1" in
    BugDeleteValueBeforeMeta)      echo NoOrphanedMetadata ;;
    BugDeleteMetaOnlyUnderPresent) echo NoOrphanedMetadata ;;
    BugCacheFaultAsAbsent)         echo NoFalseAbsent ;;
    BugTruncatedScanDecidesAll)    echo NoFalseAbsent ;;
    BugMetaAddDropsOnFault)        echo NoRecordLostToMetaWrite ;;
    BugMetaDeleteDropsOnFault)     echo NoFalseMetaAbsent ;;
  esac
}
STORE_INV=(NoOrphanedMetadata NoFalseAbsent NoRecordLostToMetaWrite NoFalseMetaAbsent)

emit_store() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo "    Fids = {\"a\", \"b\"}"
    for b in "${STORE_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
      echo "    $(store_target "$on")"
    elif [ -n "$on" ]; then
      local t; t=$(store_target "$on"); echo "    $t"
      for i in "${STORE_INV[@]}"; do [ "$i" = "$t" ] || echo "    $i"; done
    else
      for i in "${STORE_INV[@]}"; do echo "    $i"; done
    fi
  } > "$out"
}
emit_store Store.cfg ""
for b in "${STORE_BUGS[@]}"; do emit_store "StoreMut_$b.cfg" "$b"; done
for b in "${STORE_BUGS[@]}"; do emit_store "StoreSolo_$b.cfg" "$b" 1; done
echo "wrote Store.cfg and ${#STORE_BUGS[@]} x 2 store configs"

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

emit_lattice() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo
  local out=$1 on=${2:-} solo=${3:-0}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
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
echo "wrote Lattice.cfg and ${#LATTICE_BUGS[@]} x 2 lattice configs"

# ---------------------------------------------------------------------------
# RSKeyAppletPolicies -- the real stateful operation doors across PIV,
# OpenPGP, OATH and Yubico OTP. OATH/OTP access codes have no retry counters,
# so this complements the lattice without inventing protocol state.
POLICY_BUGS=(BugPivPolicyIgnored BugPivAlwaysDoesNotSpend
             BugPgpAttributeKeepsKey BugOathCodeIgnored BugOathTouchIgnored
             BugOtpCodeIgnored BugOtpCounterRepeats)

policy_target() {
  case "$1" in
    BugPivPolicyIgnored)          echo PivOperationNeedsSlotPolicy ;;
    BugPivAlwaysDoesNotSpend)     echo PivAlwaysSpendsFreshness ;;
    BugPgpAttributeKeepsKey)      echo AttributeChangeInvalidatesTheKey ;;
    BugOathCodeIgnored)           echo OathCredentialNeedsItsGates ;;
    BugOathTouchIgnored)          echo OathCredentialNeedsItsGates ;;
    BugOtpCodeIgnored)            echo OtpSlotMutationNeedsItsCode ;;
    BugOtpCounterRepeats)         echo OtpCounterNeverRepeats ;;
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
    echo "    CounterMax = 2"
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

emit_boot() { # $1 = cfg, $2 = switch (""), $3 = 1 for solo, $4 = scratch2 (TRUE)
  local out=$1 on=${2:-} solo=${3:-0} clears=${4:-TRUE}
  {
    echo "\\* Generated by formal/gen-configs.sh -- do not edit by hand."
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo "    PowerOnClearsScratch2 = $clears"
    echo "    MaxWeak = 2"
    for b in "${BOOT_BUGS[@]}"; do
      if [ "$b" = "$on" ]; then echo "    $b = TRUE"; else echo "    $b = FALSE"; fi
    done
    echo "INVARIANTS"
    echo "    TypeOK"
    if [ -n "$on" ] && [ "$solo" = 1 ]; then
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
echo "wrote Boot.cfg, BootCarry.cfg and ${#BOOT_BUGS[@]} x 2 boot configs"

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
emit_security_trace() { # cfg, beta mutation, alpha mutation, outcome mutation, R4b
  local out=$1 beta=$2 alpha=$3 outcome=$4 r4b=$5
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
    for b in "${BUGS[@]}" "${LIVE_BUGS[@]}" "${SHAPE_BUGS[@]}"; do
      echo "    $b = FALSE"
    done
    echo "    FixSweepDropsCredsBeforeRpEntries = FALSE"
    echo "    FixPpuatRequiresPin = TRUE"
    echo "    MutateBeta = $beta"
    echo "    MutateAlpha = $alpha"
    echo "    MutateOutcome = $outcome"
    echo "    CheckR4b = $r4b"
    echo "INVARIANTS"
    echo "    TypeOK"
    echo "    R4aRawRefinesB"
    echo "    R4bEventConsensus"
    [ "$r4b" = TRUE ] && echo "    R4bAlphaMatchesGamma"
    echo "    TraceComplete"
  } > "$out"
}
emit_security_trace TraceSecurity.cfg FALSE FALSE FALSE TRUE
emit_security_trace TraceSecurityBadBeta.cfg TRUE FALSE FALSE TRUE
emit_security_trace TraceSecurityBadAlpha.cfg FALSE TRUE FALSE TRUE
emit_security_trace TraceSecurityBadAlphaNoR4b.cfg FALSE TRUE FALSE FALSE
emit_security_trace TraceSecurityBadOutcome.cfg FALSE FALSE TRUE TRUE
echo "wrote TraceSecurity baseline, state/outcome divergences, and the R4b control"

# ---------------------------------------------------------------------------
# Phase 5 -- native state refinement B -> A and the separate outcome-labelled
# action property. Both use the liveness-sized constants: the purpose is an
# exhaustive semantic bridge, not another copy of the 60M-state shipped row.
emit_token_refinement() { # $1 cfg, $2 gamma mutant, $3 outcome mutant, $4 state|outcome
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
