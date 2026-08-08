#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Embeds an RP2350 partition table into a firmware ELF, fencing the KV store off
# from the USB bootloader: with it in place `picotool save`/`load` over the store
# answer `permission failure`, so the BOOTSEL snapshot/restore that resets a
# wrong-PIN counter needs a reflash first (docs/threat-model.md → "Flash snapshot
# rollback"). It is a *complement* to secure boot, not a substitute — read that
# section before quoting this as protection.
#
#   scripts/pt.sh <in.elf> <out.elf>
#
# The bounds are read back out of the ELF, not restated here: `__kvmain_start`
# and `__kvcnt_end` are the same absolute symbols `flash_storage.rs` uses to find
# the store, so the fence can not drift from what it fences on any FLASH_SIZE /
# KVMAIN / BOARD. Restating them would be a second source of truth that still
# links, still boots, and silently locks the firmware out of its own data.

set -euo pipefail

in=${1:?usage: scripts/pt.sh <in.elf> <out.elf>}
out=${2:?usage: scripts/pt.sh <in.elf> <out.elf>}

# gcc-arm-embedded ships the one that always reads a thumbv8m ELF; the others are
# fallbacks for a host whose plain `nm` is cctools (Darwin) and can not.
nm_bin=
for c in arm-none-eabi-nm llvm-nm nm; do
  if command -v "$c" >/dev/null 2>&1; then nm_bin=$c; break; fi
done
[ -n "$nm_bin" ] || { echo "pt.sh: no nm on PATH (need arm-none-eabi-nm, llvm-nm or nm)" >&2; exit 1; }

syms=$("$nm_bin" "$in")
sym() {
  local v
  v=$(printf '%s\n' "$syms" | awk -v s="$1" '$3 == s { print $1; f=1 } END { exit !f }') || {
    echo "pt.sh: $in defines no $1 — not a firmware ELF?" >&2
    exit 1
  }
  printf '%d' "0x$v"
}

start=$(sym __kvmain_start)
end=$(sym __kvcnt_end)
size=$((end - start))

# A partition table that does not line up with the store is worse than none: the
# image boots, the gate stays green, and the firmware loses writes to its own
# flash at runtime. Refuse to emit one.
[ "$start" -gt 0 ] && [ "$size" -gt 0 ] || {
  echo "pt.sh: nonsensical store bounds ${start}..${end}" >&2; exit 1
}
[ $((start % 4096)) -eq 0 ] && [ $((size % 4096)) -eq 0 ] || {
  echo "pt.sh: store bounds ${start}..${end} are not 4K-aligned" >&2; exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# On the store, `bootloader: ""` denies the BOOTSEL *read* as well as the write.
# Upstream pico-keys-sdk leaves it `r`, which blocks the restore half of the
# rollback but still hands out a full dump of the sealed store; before the OTP
# burn the seal root derives from on-chip state alone (docs/threat-model.md), so
# that dump is not harmless. `secure: rw` keeps the running firmware in charge.
#
# Unpartitioned space, by contrast, MUST stay bootloader-writable. An image
# carries its own partition table as an `absolute`-family block, which lands
# there — deny it and the device refuses its own firmware updates with
# `permission failure`, recoverable only by a RAM-resident wipe. Measured on
# hardware, not theorised. It does not widen the store: that lives in partition 1
# and the bootrom applies the permissions of the partition containing the target
# address, which is why `save`/`load` over the store stay refused either way.
cat > "$tmp/pt.json" <<EOF
{
  "version": [1, 0],
  "unpartitioned": {
    "families": ["absolute"],
    "permissions": { "secure": "rw", "nonsecure": "", "bootloader": "rw" }
  },
  "partitions": [
    {
      "name": "RS-Key Firmware",
      "id": 0,
      "start": 0,
      "size": $start,
      "families": ["rp2350-arm-s"],
      "permissions": { "secure": "rw", "nonsecure": "rw", "bootloader": "rw" }
    },
    {
      "name": "RS-Key Store",
      "id": 1,
      "start": $start,
      "size": $size,
      "families": ["data"],
      "permissions": { "secure": "rw", "nonsecure": "", "bootloader": "" },
      "link": ["owner", 0],
      "ignored_during_arm_boot": true,
      "ignored_during_riscv_boot": true
    }
  ]
}
EOF

picotool partition create "$tmp/pt.json" "$out" "$in" -t elf >/dev/null
printf 'pt.sh: store fenced at 0x%08x..0x%08x (%d KiB), NSBOOT denied\n' \
  "$start" "$end" $((size / 1024)) >&2
