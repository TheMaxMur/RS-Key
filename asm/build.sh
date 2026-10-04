#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# M2/M3 build: asm -> ELF -> bin/UF2, deterministic, then the store fence:
# the SAME scripts/pt.sh the shipping image runs, reading the SAME
# __kvmain_start/__kvcnt_end symbols link.ld now defines — no second copy
# of the layout to keep in step. Run inside nix develop (arm-none-eabi-gcc
# and picotool live there; no new dependencies).

set -euo pipefail
cd "$(dirname "$0")"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo ..)"
OUT="$ROOT/target/asm"
mkdir -p "$OUT"

# Audit trail: the pad/SIO register facts in boot.S cite these sites.
arm-none-eabi-objdump -d "$ROOT/target/thumbv8m.main-none-eabihf/release/firmware" \
    > "$OUT/ref.disasm" 2>/dev/null || true

arm-none-eabi-gcc -mcpu=cortex-m33 -mthumb -mfloat-abi=hard \
    -c boot.S -o "$OUT/boot.o"
arm-none-eabi-gcc -nostdlib -static -Wl,--build-id=none \
    -Wl,-T,link.ld -o "$OUT/boot.elf" "$OUT/boot.o"
arm-none-eabi-objcopy -O binary "$OUT/boot.elf" "$OUT/boot.bin"
arm-none-eabi-objdump -d "$OUT/boot.elf" > "$OUT/boot.disasm"
arm-none-eabi-size "$OUT/boot.elf"

# the fence: boot.elf is the bare pre-pt form (the M2 artifact); boot-pt.elf
# is the flashable one, the same relation cargo-build firmware has to the
# pt.sh'd release image
"$ROOT/scripts/pt.sh" "$OUT/boot.elf" "$OUT/boot-pt.elf"
picotool uf2 convert "$OUT/boot-pt.elf" -t elf "$OUT/boot-pt.uf2" \
    --family rp2350-arm-s >/dev/null

# the fence must bound the symbols it claims to: partition 1 spans
# __kvmain_start->__kvcnt_end and denies NSBOOT (the gate's
# partition_table_fences_the_store row, run here against the asm image)
want="$(arm-none-eabi-nm "$OUT/boot.elf" | awk '$3 == "__kvmain_start" { print $1 }')"
want="$want->$(arm-none-eabi-nm "$OUT/boot.elf" | awk '$3 == "__kvcnt_end" { print $1 }')"
for p in "0:NSBOOT(rw)" "1:NSBOOT(-)"; do
    line=$(picotool info -a "$OUT/boot-pt.elf" | grep -E "^ +partition ${p%%:*} ") || {
        echo "FAIL: no partition ${p%%:*} in the asm fence" >&2; exit 1; }
    grep -q -- "${p#*:}" <<<"$line" || {
        echo "FAIL: asm partition ${p%%:*} is not ${p#*:}: $line" >&2; exit 1; }
done
got=$(picotool info -a "$OUT/boot-pt.elf" | grep -E '^ +partition 1 ' | grep -oE '[0-9a-f]{8}->[0-9a-f]{8}')
[ "$got" = "$want" ] || {
    echo "FAIL: asm store partition is $got but __kvmain_start..__kvcnt_end is $want" >&2
    exit 1; }
echo "asm store partition $got, NSBOOT denied; firmware partition writable"

# differential: when the shipping firmware ELF is present, its fence must be
# the very same table — same script, same JSON, same bounds — so the parsed
# tables must agree line for line (picotool partition info needs a device;
# picotool info -a parses a file's table)
REF="$ROOT/target/thumbv8m.main-none-eabihf/release/firmware"
pt_lines() { picotool info -a "$1" 2>/dev/null | grep -E 'partition|un-partitioned'; }
if [ -f "$REF" ]; then
    "$ROOT/scripts/pt.sh" "$REF" "$OUT/ref-pt.elf" >&2
    if ! diff <(pt_lines "$OUT/boot-pt.elf") <(pt_lines "$OUT/ref-pt.elf") >/dev/null; then
        echo "FAIL: the asm fence differs from the shipping partition table" >&2
        diff <(pt_lines "$OUT/boot-pt.elf") <(pt_lines "$OUT/ref-pt.elf") >&2
        exit 1
    fi
    echo "fence differential: identical to the shipping partition table"
fi

sha256sum "$OUT/boot.bin" "$OUT/boot.elf" "$OUT/boot-pt.elf"
picotool info -a "$OUT/boot-pt.uf2" | head -20
