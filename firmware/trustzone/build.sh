#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
out="$root/target/trustzone"
mkdir -p "$out"
export RSK_TRUSTZONE_PROTOTYPE=1
export RSK_TZ_IMPLIB="$out/secure-import.a"
env -u RSK_TZ_NS_IMAGE LED_KIND=none FLASH_SIZE=4M \
    CARGO_TARGET_DIR="$out/secure" cargo build --locked --release -p firmware --features no-touch
cp "$RSK_TZ_IMPLIB" "$out/ns-import.a"
RSK_TZ_IMPLIB="$out/ns-import.a" CARGO_TARGET_DIR="$out/nonsecure" \
    cargo build --locked --release --manifest-path firmware/trustzone/nonsecure/Cargo.toml
arm-none-eabi-objcopy -O binary \
    "$out/nonsecure/thumbv8m.main-none-eabihf/release/firmware" "$out/nonsecure.bin"
LED_KIND=none FLASH_SIZE=4M RSK_TZ_NS_IMAGE="$out/nonsecure.bin" \
    CARGO_TARGET_DIR="$out/secure" cargo build --locked --release -p firmware --features no-touch
cmp "$out/ns-import.a" "$RSK_TZ_IMPLIB"
cp "$out/secure/thumbv8m.main-none-eabihf/release/firmware" "$out/combined.elf"
picotool uf2 convert -t elf "$out/combined.elf" "$out/combined.uf2"
printf 'Prototype (no-touch): %s\n' "$out/combined.elf"
