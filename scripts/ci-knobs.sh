#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Build smokes for the compile-time env knobs (docs/build.md).
#
# Nothing else in the tree builds a `VIDPID=` or an `XOSC_DELAY_MULT=`, so
# without these a wrong value in the docs — the value a user gets by following
# them — reaches that user uncaught.
#
# One group per invocation so CI can run them as a matrix: they are independent
# builds, and in sequence they are the slowest job in the workflow. Grouped
# rather than one-per-preset because a hosted public repo gets 20 concurrent
# runners and the flavour matrix already wants 24 — past that, more rows buy
# queue time, not wall-clock.
set -euo pipefail
cd "$(dirname "$0")/.."

# NOT `GROUPS`: bash owns that name (the caller's gid list) and silently
# discards the assignment, so `echo "$GROUPS"` printed a group id.
KNOB_GROUPS="vidpid-1 vidpid-2 vidpid-3 identity misc"

build() { # <label> <env…> -- <cargo args…>
  local label="$1"
  shift
  echo "::group::$label"
  env "$@" cargo build --release -p firmware
  echo "::endgroup::"
}

vidpid() {
  for preset in "$@"; do
    build "VIDPID=$preset" "VIDPID=$preset"
  done
}

identity() {
  # The default build must bake THIS project's identity and the Yubico one must
  # be opt-in: the vendor-mimicking ids are local interop only and never ship as
  # a default. build.rs writes what it chose to `output`, which is where a swap
  # would show up.
  local o=target/thumbv8m.main-none-eabihf/release/build/firmware-*/output
  cargo clean -p firmware
  cargo build --release -p firmware >/dev/null
  # shellcheck disable=SC2086 # the glob is the point: one build dir, unknown hash
  grep -qx "cargo:rustc-env=PK_USB_VID=4617" $o
  # shellcheck disable=SC2086
  grep -qx "cargo:rustc-env=PK_USB_MANUFACTURER=RS-Key" $o
  # shellcheck disable=SC2086
  grep -qx "cargo:rustc-env=PK_USB_PRODUCT=RS-Key Security Key" $o
  env VIDPID=Yubikey5 cargo build --release -p firmware >/dev/null
  # shellcheck disable=SC2086
  grep -qx "cargo:rustc-env=PK_USB_VID=4176" $o
  # shellcheck disable=SC2086
  grep -qx "cargo:rustc-env=PK_USB_MANUFACTURER=Yubico" $o
  echo "default = RS-Key identity, Yubikey5 = Yubico identity: OK"

  build "raw USB_VID/USB_PID override" VIDPID=Dev USB_VID=0xFEFF USB_PID=0x0001
}

misc() {
  build "FW_VERSION + masquerade preset (the docs example)" \
    VIDPID=NitroFIDO2 FW_VERSION=1.4.0
  build "hardened XOSC startup delay" XOSC_DELAY_MULT=512
  build "FAKE_MKEK / FAKE_DEVK test build" \
    FAKE_MKEK=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    FAKE_DEVK=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
}

case "${1:-}" in
  # The presets docs/build.md lists, split three ways. Keep every preset in
  # exactly one group — a dropped one is a smoke nobody runs.
  vidpid-1) vidpid RSKey Yubikey5 YubikeyNeo YubiHSM NitroHSM ;;
  vidpid-2) vidpid NitroFIDO2 NitroStart NitroPro Nitro3 Gnuk ;;
  vidpid-3) vidpid GnuPG Pico Dev ;;
  identity) identity ;;
  misc) misc ;;
  --groups) echo "$KNOB_GROUPS" ;;
  # The matrix cannot call this script for its own row list, so the two are
  # written twice. A group here but not there is a smoke nobody runs, and nothing
  # else would say so — `check.sh` runs this.
  --self-test)
    wf=.github/workflows/ci.yml
    in_wf="$(sed -n 's/^ *group: \[\(.*\)\]$/\1/p' "$wf" | tr -d ' ' | tr ',' ' ')"
    for g in $KNOB_GROUPS; do
      case " $in_wf " in
        *" $g "*) ;;
        *) echo "ci-knobs: group '$g' is not in $wf's matrix" >&2; exit 1 ;;
      esac
    done
    for g in $in_wf; do
      case " $KNOB_GROUPS " in
        *" $g "*) ;;
        *) echo "ci-knobs: $wf names a group '$g' this script does not have" >&2; exit 1 ;;
      esac
    done
    echo "ci-knobs: groups match the workflow matrix"
    ;;
  *)
    echo "usage: $0 <${KNOB_GROUPS// /|}>" >&2
    exit 2
    ;;
esac
