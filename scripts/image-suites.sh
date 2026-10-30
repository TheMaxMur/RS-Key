#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Runs the partitioned no-touch ELF, not just the native applet backend.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST_TARGET="${HOST_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
EMU="tools/emu/target/$HOST_TARGET/release/rsk-emu"
WORK="${1:-target/image-assurance-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$(dirname "$WORK")"
mkdir "$WORK"
WORK="$(cd "$WORK" && pwd)"
echo "image suites: logs and reports in $WORK"

bash firmware/trustzone/build.sh --features no-touch
cp target/trustzone/combined.elf "$WORK/firmware-pt.elf"
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
  cargo build --locked --release --manifest-path tools/emu/Cargo.toml --target "$HOST_TARGET"

for scenario in basic stack operations cuts; do
  python tools/emu/image_assurance.py --emulator "$EMU" --image "$WORK/firmware-pt.elf" \
    --only "$scenario" --work "$WORK/$scenario" 2>&1 | tee "$WORK/$scenario.log"
done
python tools/emu/image_otp_seal.py --binary "$EMU" --image "$WORK/firmware-pt.elf" \
  --out "$WORK/otp-seal"
echo "IMAGE SUITES PASSED"
