#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Differential harness for asm/ctaphid.S. Builds the ARM side (a static
# Linux ELF, no libc, raw EABI syscalls — assembled with the firmware's
# arm-none-eabi toolchain) and the Rust oracle over rsk-usb's Reassembler,
# then requires byte-identical event streams over the spec vectors and
# seeded random frames.
#
# usage: difftest.sh [fuzz_frames_per_seed]   (default 700, 5 seeds)
# qemu:  qemu-arm must be in PATH, or set QEMU=/path/to/qemu-arm.
#        The devshell does not ship qemu (flakes are maintainer-only);
#        QEMU=$(ls -d /nix/store/*-qemu-*/bin/qemu-arm | head -1) works.

set -euo pipefail
cd "$(dirname "$0")"
OUT="${DIFFTEST_OUT:-$(git rev-parse --show-toplevel 2>/dev/null || echo ..)/target/asm}"
mkdir -p "$OUT"
FUZZ="${1:-700}"
HOST="${HOST_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
QEMU_BIN="${QEMU:-qemu-arm}"
command -v "$QEMU_BIN" >/dev/null || { echo "qemu-arm not found; set QEMU=" >&2; exit 2; }

CFLAGS="-mcpu=cortex-m33 -mthumb -mfloat-abi=soft -ffreestanding -fno-builtin -nostdlib"
arm-none-eabi-gcc $CFLAGS -c ctaphid.S -o "$OUT/ctaphid.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_tx.S -o "$OUT/ctaphid-tx.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_init.S -o "$OUT/ctaphid-init.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_ctrl.S -o "$OUT/ctaphid-ctrl.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_dispatch.S -o "$OUT/ctaphid-dispatch.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_wait.S -o "$OUT/ctaphid-wait.o"
arm-none-eabi-gcc $CFLAGS -c ccid.S -o "$OUT/ccid.o"
arm-none-eabi-gcc $CFLAGS -c difftest.S -o "$OUT/difftest-s.o"
arm-none-eabi-gcc $CFLAGS -Os -c difftest.c -o "$OUT/difftest-c.o"
arm-none-eabi-gcc -nostdlib -static -Wl,--build-id=none -e _start \
    -o "$OUT/difftest.elf" "$OUT/ctaphid.o" "$OUT/ctaphid-tx.o" "$OUT/ctaphid-init.o" "$OUT/ctaphid-ctrl.o" "$OUT/ctaphid-dispatch.o" "$OUT/ctaphid-wait.o" "$OUT/ccid.o" "$OUT/difftest-s.o" "$OUT/difftest-c.o"
arm-none-eabi-objdump -d "$OUT/difftest.elf" > "$OUT/difftest.disasm"
arm-none-eabi-size "$OUT/difftest.elf"

echo "== building oracle =="
cargo build --release --target "$HOST" --manifest-path oracle/Cargo.toml
ORACLE="oracle/target/$HOST/release/asm-oracle"

echo "== spec vectors =="
python3 gen_vectors.py > "$OUT/vectors.txt"
"$QEMU_BIN" "$OUT/difftest.elf" < "$OUT/vectors.txt" > "$OUT/spec-asm.txt"
"$ORACLE" < "$OUT/vectors.txt" > "$OUT/spec-rust.txt"
cmp "$OUT/spec-asm.txt" "$OUT/spec-rust.txt" \
    || { echo "DIFF FAILED on spec vectors:" >&2; diff "$OUT/spec-asm.txt" "$OUT/spec-rust.txt" | head -6 >&2; exit 1; }
echo "   $(wc -l < "$OUT/spec-asm.txt") events identical"

total=0
for seed in 1 2 3 4 5; do
    for mode in noise mixed tx ctrl dispatch wait ccid; do
        python3 gen_random.py "$seed" "$FUZZ" "$mode" > "$OUT/fuzz.txt"
        "$QEMU_BIN" "$OUT/difftest.elf" < "$OUT/fuzz.txt" > "$OUT/fuzz-asm.txt"
        "$ORACLE" < "$OUT/fuzz.txt" > "$OUT/fuzz-rust.txt"
        cmp "$OUT/fuzz-asm.txt" "$OUT/fuzz-rust.txt" \
            || { echo "DIFF FAILED on fuzz seed $seed ($mode):" >&2; diff "$OUT/fuzz-asm.txt" "$OUT/fuzz-rust.txt" | head -6 >&2; exit 1; }
    done
    total=$((total + 7 * FUZZ))
done
echo "== differential clean: spec vectors + $total random frames =="
