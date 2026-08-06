# rsk-wipe

A RAM-only flash-erase utility for the Waveshare RP2350-One — a Rust/embassy
port of upstream [pico-nuke](https://github.com/polhenarejos/pico-nuke)
(itself the pico-sdk `flash_nuke` example).

It wipes the whole device so `rs-key` flash-persistence behaviour can be
verified from a blank slate between firmware tests. On run it:

1. **white strobe ×8** — the SRAM image is alive (see *Reading the LED*),
2. erases the whole target flash — `FLASH_SIZE` bytes — via the
   bootrom sequence (`connect_internal_flash` → `flash_exit_xip` →
   `flash_range_erase` → `flash_flush_cache` → `flash_enter_cmd_xip`) — **solid
   blue** while erasing. The size comes from `BOARD`'s `[flash] size_mb` (the same
   board file the firmware reads) or from `FLASH_SIZE`, and **there is no default —
   a build that names neither does not link**. Getting it wrong is silent and
   total: the KV store sits at the *top* of flash, so an under-sized wipe erases
   the code, leaves every sealed secret, and still blinks green. Build it the way
   you built the firmware:
   `BOARD=waveshare-touch-lcd cargo build --release -p rsk-wipe`,
3. writes a `"NUKE"` eyecatcher into page 0 (so picotool can spot a wiped device),
4. **green ×3** — the sequence completed,
5. reboots to BOOTSEL (`reset_to_usb_boot`) so the `RP2350` drive reappears.

The bootrom flash sequence (rather than embassy's flash driver) is used because
it re-initialises the QSPI/XIP from scratch — necessary in a RAM boot, where the
normal second-stage XIP setup never ran.

## Reading the LED

The WS2812 pin and colour order come from `BOARD`'s `[led]` block (`LED_PIN` /
`LED_ORDER` override), so the wiper signals on the same LED the firmware uses. A
board with `kind = "none"` — the display build — drives nothing at all; its GPIO16
is the panel backlight, so read the outcome functionally there rather than by eye.

The startup **white strobe** is the key diagnostic — no flashed firmware blinks
white, so:

| You see | Meaning |
|---------|---------|
| white strobe → blue → **green ×3** | the erase sequence ran — confirm the wipe functionally (below) |
| white strobe → blue → *nothing* (hang) | a bootrom flash call faulted mid-erase |
| **no white strobe**, just red/green/blue cycling | the RAM image never launched — the board booted the old flashed firmware instead (a UF2/boot-handoff problem, not a flash problem) |

Green means the erase + eyecatcher sequence ran to completion — **not** that flash
was read back and checked. The ROM flash calls report no status, and reading flash
back immediately after a manual flash sequence in a RAM image is unreliable (XIP
returns stale/garbage data even via the no-cache alias). So confirm the wipe
functionally: flash `firmware.uf2` and run `tests/01_flash_persistence.py` —
`counter before = 0` means the KV partition really was erased.

## Why RAM-only

Erasing flash means erasing offset 0 too — the sectors a flash-resident image
would be executing from. Returning into just-erased flash would fault, so the
entire program runs from SRAM. `memory.x` places code, rodata and data all in
the RP2350's 512 KB of contiguous main SRAM (`0x2000_0000`); there is no flash
load region. The bootrom loads the SRAM image (via the BOOTSEL UF2) and runs it
from there, leaving flash free to be wiped.

## Build & run

Built as its own workspace target (own `memory.x`):

`BOARD` is required — it fixes both the erase length and the LED pin/colour order,
so a wiper built for the wrong board can erase too little *and* signal on a GPIO
that is the display backlight.

```sh
nix develop -c env BOARD=waveshare-one cargo build --release -p rsk-wipe
nix develop -c picotool uf2 convert \
  target/thumbv8m.main-none-eabihf/release/rsk-wipe -t elf rsk-wipe.uf2

# Enter BOOTSEL (hold BOOT, tap RESET) then flash it across:
cp rsk-wipe.uf2 /Volumes/RP2350/                    # or, more robust (verifies):
picotool load -v rsk-wipe.uf2 && picotool reboot
```

On a **secure-boot board** the plain UF2 is refused — seal the wipe image
exactly like firmware (it is a RAM image; it signs fine). Once the board has
`ROLLBACK_REQUIRED` fused, the seal must also carry the **current**
anti-rollback epoch — current, never higher: booting a higher-epoch image
advances the board's counter and orphans every image below it
([production.md](../docs/production.md#stage-3--anti-rollback-optional)):

```sh
picotool seal --sign --hash rsk-wipe.uf2 rsk-wipe-signed.uf2 \
    ~/.rs-key-secrets/secure_boot_key.pem ~/.rs-key-secrets/otp_secureboot.json \
    --major 1 --minor 0 --rollback 1
```

`picotool info -a rsk-wipe.uf2` should report family `rp2350-arm-s`, image type
**ARM Secure**, with the image-def at a `0x2000_xxxx` (SRAM) address — confirming
it is a RAM image. The board wipes flash, blinks, and re-enumerates as the
BOOTSEL drive; flash `rs-key` next to test it from a clean device.

> ⚠️ **This erases the entire device.** Anything in flash, including a flashed
> `rs-key` and its CONFIG/KV partition, is gone.

## Testing

There is no host-testable logic here: every step is an irreducible HAL
side-effect (flash erase/program, PIO LED, ROM reboot), so there are no unit
tests or fuzz targets — correctness is established by the on-device procedure
above.
