#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Model-level USB test: builds the EP0 driver (asm/usb.S) plus its SIE-model
# harness into a static ARM Linux ELF and runs it under qemu-arm. Green here
# means datasheet-model agreement only — hardware execution is untested.

set -euo pipefail
cd "$(dirname "$0")"
OUT="${USBTEST_OUT:-$(git rev-parse --show-toplevel 2>/dev/null || echo ..)/target/asm}"
mkdir -p "$OUT"
QEMU_BIN="${QEMU:-qemu-arm}"
command -v "$QEMU_BIN" >/dev/null || { echo "qemu-arm not found; set QEMU=" >&2; exit 2; }

CFLAGS="-mcpu=cortex-m33 -mthumb -mfloat-abi=soft -ffreestanding -fno-builtin -nostdlib"
arm-none-eabi-gcc $CFLAGS -c difftest.S -o "$OUT/difftest-s.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid.S -o "$OUT/ctaphid.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_tx.S -o "$OUT/ctaphid-tx.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_init.S -o "$OUT/ctaphid-init.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_ctrl.S -o "$OUT/ctaphid-ctrl.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_dispatch.S -o "$OUT/ctaphid-dispatch.o"
arm-none-eabi-gcc $CFLAGS -c ctaphid_wait.S -o "$OUT/ctaphid-wait.o"
arm-none-eabi-gcc $CFLAGS -c usb.S -o "$OUT/usb.o"
arm-none-eabi-gcc $CFLAGS -Os -c usbtest.c -o "$OUT/usbtest-c.o"
arm-none-eabi-gcc -nostdlib -static -Wl,--build-id=none -e _start \
    -o "$OUT/usbtest.elf" "$OUT/usb.o" "$OUT/ctaphid.o" "$OUT/ctaphid-tx.o" "$OUT/ctaphid-init.o" "$OUT/ctaphid-ctrl.o" "$OUT/ctaphid-dispatch.o" "$OUT/ctaphid-wait.o" "$OUT/difftest-s.o" "$OUT/usbtest-c.o"
arm-none-eabi-objdump -d "$OUT/usbtest.elf" > "$OUT/usbtest.disasm"
arm-none-eabi-size "$OUT/usbtest.elf"

# a poll on the wrong register would hang the driver; fail loudly instead
timeout 60 "$QEMU_BIN" "$OUT/usbtest.elf"
