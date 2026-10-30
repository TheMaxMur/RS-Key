#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
invocation=$PWD
out="${RSK_TZ_OUT:-${CARGO_TARGET_DIR:-$root/target}/trustzone}"
target=thumbv8m.main-none-eabihf
cargo_args=()
resolve_args=()
secure_features="${FEATURES:-}"
defaults=()

usage() {
    cat <<'EOF'
Usage: scripts/build.sh [--features LIST] [Cargo options]

Build the partitioned Secure + Non-secure release ELF and UF2 for RP2350.
All exported environment variables are inherited by Cargo. FEATURES composes
with repeated --features/-F; --no-default-features applies to both worlds.

Cargo options: --config KEY=VALUE|PATH, --jobs/-j N, --offline, --frozen,
--locked, --verbose/-v/-vv, --quiet/-q, --color WHEN, --message-format FMT,
--timings, --keep-going, --future-incompat-report, --release/-r.
Target, release profile and packages are fixed by the TrustZone link sequence.

Output: --target-dir DIR puts artifacts in DIR/trustzone. Otherwise use
RSK_TZ_OUT, then CARGO_TARGET_DIR/trustzone, then <repo>/target/trustzone.
Relative paths are resolved from the calling directory. S and NS use separate
Cargo directories under that output; combined.elf and combined.uf2 are final.

Examples (inside nix develop):
  BOARD=waveshare-one scripts/build.sh --features strong-pin,strict-config
  FEATURES=strong-pin scripts/build.sh -F advertise-pqc --offline --jobs 4
  scripts/build.sh --config 'build.jobs=4' --target-dir /tmp/rs-key-build
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "TrustZone build: $1 requires a value" >&2; exit 2
    fi
}

add_config() {
    local value=$1
    if [[ "$value" != *=* && "$value" != /* ]]; then value="$invocation/$value"; fi
    cargo_args+=(--config "$value")
    resolve_args+=(--config "$value")
}

if [[ -n "${RSK_TZ_CARGO_CONFIG:-}" ]]; then add_config "$RSK_TZ_CARGO_CONFIG"; fi
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --features|-F)
            require_value "$@"
            if [[ "$2" == -* ]]; then
                echo 'TrustZone build: --features requires a feature list' >&2; exit 2
            fi
            secure_features+=,"$2"; shift 2 ;;
        --features=)
            echo 'TrustZone build: --features requires a feature list' >&2; exit 2 ;;
        --features=*) secure_features+=,"${1#*=}"; shift ;;
        -F?*) secure_features+=,"${1#-F}"; shift ;;
        --no-default-features) defaults=(--no-default-features); shift ;;
        --target-dir)
            require_value "$@"; out="$2/trustzone"; shift 2 ;;
        --target-dir=)
            echo 'TrustZone build: --target-dir requires a directory' >&2; exit 2 ;;
        --target-dir=*) out="${1#*=}/trustzone"; shift ;;
        --config) require_value "$@"; add_config "$2"; shift 2 ;;
        --config=) echo 'TrustZone build: --config requires a value' >&2; exit 2 ;;
        --config=*) add_config "${1#*=}"; shift ;;
        --jobs|-j|--color|--message-format)
            require_value "$@"; cargo_args+=("$1" "$2"); shift 2 ;;
        --locked|--offline|--frozen)
            cargo_args+=("$1"); resolve_args+=("$1"); shift ;;
        --jobs=*|-j?*|--color=*|--message-format=*|\
        --verbose|-v|-vv|--quiet|-q|--timings|--keep-going|--future-incompat-report)
            cargo_args+=("$1"); shift ;;
        --release|-r) shift ;;
        *) echo "TrustZone build: unsupported argument: $1 (see --help)" >&2; exit 2 ;;
    esac
done
if [[ "$out" != /* ]]; then out="$invocation/$out"; fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$root"
export RSK_TZ_SECURE_MEMORY="$out/secure-memory.x"
export RSK_TZ_IMPLIB="$out/secure-import.a"
export RSK_TZ_NS_MEMORY="$out/nonsecure-memory.x"

if [[ "${RSK_TZ_NO_TOUCH:-0}" == 1 ]]; then secure_features+=,no-touch; fi
if [[ "${RSK_TZ_DISPLAY:-0}" == 1 ]]; then secure_features+=,display; fi
env -u RSK_TZ_NS_IMAGE \
    RSK_TZ_STAGE=import CARGO_TARGET_DIR="$out/secure" cargo build "${cargo_args[@]}" --locked --release --target "$target" --target-dir "$out/secure" -p firmware "${defaults[@]}" --features "$secure_features"
cp "$out/secure/$target/release/firmware" "$out/import.elf"
cp "$RSK_TZ_IMPLIB" "$out/ns-import.a"
ns_features=""
# Cargo resolves dependency aliases and conditional features; copying their
# spelling would miss a policy enabled through an optional dependency.
otp_features=$(CARGO_TARGET_DIR="$out/secure" cargo tree "${resolve_args[@]}" \
    --locked --target "$target" -p firmware "${defaults[@]}" --features "$secure_features" \
    --edges normal,build --invert rsk-otp --depth 0 --prefix none --format '{f}' --color never)
case ",$otp_features," in
    *,strict-config,*) ns_features=strict-config ;;
esac
if [[ "${RSK_TZ_GATEWAY_PROBES:-0}" == 1 ]]; then
    ns_features+=${ns_features:+,}test-gateway-probes
fi
if [[ -n "${RSK_TZ_PROBE_ADDRESS:-}" ]]; then
    ns_features+=${ns_features:+,}test-hostile-access
fi
ns_args=()
if [[ -n "$ns_features" ]]; then ns_args=(--features "$ns_features"); fi
env -u RSK_TZ_STAGE -u RSK_TZ_NS_IMAGE \
    RSK_TZ_IMPLIB="$out/ns-import.a" CARGO_TARGET_DIR="$out/nonsecure" \
    cargo build "${cargo_args[@]}" --locked --release --target "$target" --target-dir "$out/nonsecure" -p firmware-ns "${defaults[@]}" "${ns_args[@]}"
arm-none-eabi-objcopy -O binary \
    "$out/nonsecure/$target/release/firmware-ns" "$out/nonsecure.bin"
RSK_TZ_STAGE=final RSK_TZ_NS_IMAGE="$out/nonsecure.bin" \
    CARGO_TARGET_DIR="$out/secure" cargo build "${cargo_args[@]}" --locked --release --target "$target" --target-dir "$out/secure" -p firmware "${defaults[@]}" --features "$secure_features"
cmp "$out/ns-import.a" "$RSK_TZ_IMPLIB"
cp "$out/secure/$target/release/firmware" "$out/combined.elf"
bash scripts/pt.sh "$out/combined.elf" "$out/combined-pt.elf"
mv "$out/combined-pt.elf" "$out/combined.elf"
picotool uf2 convert -t elf "$out/combined.elf" "$out/combined.uf2"
printf 'TrustZone image (features=%s): %s\n' "$secure_features" "$out/combined.elf"
