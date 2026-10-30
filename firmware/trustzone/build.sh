#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
out="${RSK_TZ_OUT:-$root/target/trustzone}"
mkdir -p "$out"
export RSK_TRUSTZONE_PROTOTYPE=1
export RSK_TZ_IMPLIB="$out/secure-import.a"
export RSK_TZ_NS_MEMORY="$out/nonsecure-memory.x"
cargo_config=()
if [[ -n "${RSK_TZ_CARGO_CONFIG:-}" ]]; then cargo_config=(--config "$RSK_TZ_CARGO_CONFIG"); fi
secure_features="rsk-device/trustzone${FEATURES:+,$FEATURES}"
defaults=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --features|-F)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo 'TrustZone build: --features requires a feature list' >&2; exit 2
            fi
            secure_features+=,"$2"; shift 2 ;;
        --features=)
            echo 'TrustZone build: --features requires a feature list' >&2; exit 2 ;;
        --features=*) secure_features+=,"${1#*=}"; shift ;;
        --no-default-features) defaults=(--no-default-features); shift ;;
        *) echo "TrustZone build: unsupported argument: $1" >&2; exit 2 ;;
    esac
done
if [[ "${RSK_TZ_NO_TOUCH:-0}" == 1 ]]; then secure_features+=,no-touch; fi
if [[ "${RSK_TZ_DISPLAY:-0}" == 1 ]]; then secure_features+=,display; fi
env -u RSK_TZ_NS_IMAGE \
    CARGO_TARGET_DIR="$out/secure" cargo build "${cargo_config[@]}" --locked --release -p firmware "${defaults[@]}" --features "$secure_features"
cp "$RSK_TZ_IMPLIB" "$out/ns-import.a"
ns_features=""
# OTP transport policy is compiled in both worlds; all applet features stay S.
case ",${secure_features//[$' \t\r\n']/,}," in
    *,strict-config,*|*,firmware/strict-config,*) ns_features=strict-config ;;
esac
if [[ "${RSK_TZ_GATEWAY_PROBES:-0}" == 1 ]]; then
    ns_features+=${ns_features:+,}test-gateway-probes
fi
if [[ -n "${RSK_TZ_PROBE_ADDRESS:-}" ]]; then
    ns_features+=${ns_features:+,}test-hostile-access
fi
ns_args=()
if [[ -n "$ns_features" ]]; then ns_args=(--features "$ns_features"); fi
RSK_TZ_IMPLIB="$out/ns-import.a" CARGO_TARGET_DIR="$out/nonsecure" \
    cargo build "${cargo_config[@]}" --locked --release -p firmware-ns "${ns_args[@]}"
arm-none-eabi-objcopy -O binary \
    "$out/nonsecure/thumbv8m.main-none-eabihf/release/firmware-ns" "$out/nonsecure.bin"
RSK_TZ_NS_IMAGE="$out/nonsecure.bin" \
    CARGO_TARGET_DIR="$out/secure" cargo build "${cargo_config[@]}" --locked --release -p firmware "${defaults[@]}" --features "$secure_features"
cmp "$out/ns-import.a" "$RSK_TZ_IMPLIB"
cp "$out/secure/thumbv8m.main-none-eabihf/release/firmware" "$out/combined.elf"
bash scripts/pt.sh "$out/combined.elf" "$out/combined-pt.elf"
mv "$out/combined-pt.elf" "$out/combined.elf"
picotool uf2 convert -t elf "$out/combined.elf" "$out/combined.uf2"
printf 'TrustZone image (features=%s): %s\n' "$secure_features" "$out/combined.elf"
