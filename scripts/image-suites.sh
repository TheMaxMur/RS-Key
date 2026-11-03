#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Runs the partitioned no-touch ELF, not just the native applet backend.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST_TARGET="${HOST_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
EMU="tools/emu/target/$HOST_TARGET/release/rsk-emu"
TZ_OUT="${RSK_TZ_OUT:-${CARGO_TARGET_DIR:-target}/trustzone}"
HOSTILE_USBCTRL=0x50110000
HOSTILE_DMA=0x50000400
export RSK_TZ_PROBE_ACCESS=read
WORK="${1:-target/image-assurance-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$(dirname "$WORK")"
mkdir "$WORK"
WORK="$(cd "$WORK" && pwd)"
echo "image suites: logs and reports in $WORK"

RSK_TZ_PROBE_NAME= RSK_TZ_PROBE_ADDRESS= RSK_TZ_GATEWAY_PROBES=1 bash scripts/build.sh --features no-touch
cp "$TZ_OUT/combined.elf" "$WORK/gateway.elf"
build_hostile() {
  local name="$1" address="$2" access="$3"
  RSK_TZ_PROBE_NAME="$name" RSK_TZ_PROBE_ACCESS="$access" RSK_TZ_PROBE_ADDRESS="$address" \
    RSK_TZ_GATEWAY_PROBES=0 bash scripts/build.sh --features no-touch
  cp "$TZ_OUT/combined.elf" "$WORK/hostile-$name.elf"
  cp "$TZ_OUT/nonsecure/thumbv8m.main-none-eabihf/release/firmware-ns" "$WORK/hostile-$name-ns.elf"
}
build_hostile usbctrl-read "$HOSTILE_USBCTRL" read
build_hostile usbctrl-write "$HOSTILE_USBCTRL" write
build_hostile dma-write "$HOSTILE_DMA" write
build_hostile matrix-read 0 read
build_hostile matrix-write 0 write
RSK_TZ_PROBE_NAME= RSK_TZ_PROBE_ADDRESS= RSK_TZ_GATEWAY_PROBES=0 bash scripts/build.sh --features no-touch
cp "$TZ_OUT/combined.elf" "$WORK/firmware-pt.elf"
cp "$TZ_OUT/import.elf" "$WORK/import.elf"
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
  cargo build --locked --release --manifest-path tools/emu/Cargo.toml --target "$HOST_TARGET"

HOSTILE_PORT=19359
check_hostile() {
  local name="$1" address="$2" access="$3"
  python tests/97_trustzone_isolation.py --emulator "$EMU" --image "$WORK/hostile-$name.elf" \
    --ns-image "$WORK/hostile-$name-ns.elf" --address "$address" --access "$access" \
    --cfsr 0x8200 --require-fenced --base-port "$HOSTILE_PORT" 2>&1 | tee "$WORK/hostile-$name.log"
  HOSTILE_PORT=$((HOSTILE_PORT + 3))
}
check_hostile usbctrl-read "$HOSTILE_USBCTRL" read
check_hostile usbctrl-write "$HOSTILE_USBCTRL" write
check_hostile dma-write "$HOSTILE_DMA" write
for access in read write; do
  python tests/97_trustzone_isolation.py --emulator "$EMU" --image "$WORK/hostile-matrix-$access.elf" \
    --ns-image "$WORK/hostile-matrix-$access-ns.elf" --address 0 --access "$access" \
    --matrix --cfsr 0x8200 --require-fenced --base-port "$HOSTILE_PORT" \
    2>&1 | tee "$WORK/hostile-matrix-$access.log"
  HOSTILE_PORT=$((HOSTILE_PORT + 1024))
done
python tests/106_trustzone_rsa_events.py --emulator "$EMU" --work "$WORK/rsa-events" \
  2>&1 | tee "$WORK/rsa-events.log"
python tests/107_trustzone_fault_recovery.py --emulator "$EMU" --image "$WORK/firmware-pt.elf" \
  --hostile-image "$WORK/hostile-matrix-write.elf" --ns-image "$WORK/hostile-matrix-write-ns.elf" \
  --work "$WORK/fault-recovery" 2>&1 | tee "$WORK/fault-recovery.log"

for scenario in basic stack operations cuts; do
  python tools/emu/image_assurance.py --emulator "$EMU" --image "$WORK/firmware-pt.elf" \
    --import-image "$WORK/import.elf" --gateway-image "$WORK/gateway.elf" \
    --only "$scenario" --work "$WORK/$scenario" 2>&1 | tee "$WORK/$scenario.log"
done
python tools/emu/image_otp_seal.py --binary "$EMU" --image "$WORK/firmware-pt.elf" \
  --out "$WORK/otp-seal"
echo "IMAGE SUITES PASSED"
