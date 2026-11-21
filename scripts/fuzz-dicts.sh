#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Which libFuzzer dictionary a target runs with — sourced by scripts/fuzz-all.sh
# (the deep-checks fuzz row) and scripts/check.sh (its `fuzz targets alive` row),
# so the PR gate parses every dictionary the nightly row loads. libFuzzer reads
# `-dict=` at startup and exits non-zero on a malformed file, which both rows
# already read as a failure.
#
# One place, because a target's dict is a property of the target and not of the
# runner: a second copy would let the local gate validate a file CI no longer uses.
# Every token is a copy of a named constant, so a new INS/tag/command byte gets a
# dictionary line — see the header of each fuzz/dicts/*.dict.

# Echo the `-dict=<path>` arguments for a target, or nothing when it has none.
# Paths are repo-relative: both callers `cd` to the repository root first.
dict_args_for() {
  local dict
  case "$1" in
    apdu|cross_applet|mgmt_apdu|oath_apdu|openpgp_apdu|otp_apdu|piv_apdu|rescue_apdu|fs_meta|tlv|phy_tlv)
      dict=apdu ;;
    fido_*|ctaphid|ctaphid_roundtrip)
      dict=ctap ;;
    ccid|ccid_secure_pin)
      dict=ccid ;;
    *)
      return 0 ;;
  esac
  echo "-dict=fuzz/dicts/${dict}.dict"
}
