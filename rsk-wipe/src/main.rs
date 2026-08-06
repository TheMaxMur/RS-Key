// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! rsk-wipe — wipe the RP2350's flash for clean-slate testing; a Rust/embassy
//! port of upstream pico-nuke (the pico-sdk `flash_nuke` example). Erases all of
//! flash, leaves a `"NUKE"` eyecatcher in page 0, blinks the LED, reboots to BOOTSEL.
//!
//! Runs entirely from SRAM (see `memory.x`): erasing the sectors a flash-resident
//! image executes from would crash on return. Erase/program go through the bootrom
//! flash sequence (`connect_internal_flash` → `flash_exit_xip` → op →
//! `flash_flush_cache` → `flash_enter_cmd_xip`), which sets the QSPI/XIP up from
//! scratch — required in a RAM boot, where the second-stage XIP setup never ran.
//! The result is **not** read back: XIP reads right after a manual flash sequence
//! in a RAM image are unreliable (false negatives); the wipe is verified
//! functionally (a later firmware boot finds an empty KV store).
//!
//! LED (WS2812 on GPIO16): white strobe = RAM image is alive (distinct from any
//! flashed firmware's pattern); solid blue = erasing; green ×3 = sequence done.
#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::dma::InterruptHandler as DmaIrq;
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{Instance, InterruptHandler as PioIrq, Pio};
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program, Rgb, RgbColorOrder};
use embassy_rp::rom_data;
use embassy_time::Timer;
use smart_leds::RGB8;

use panic_halt as _;

// RP2350 bootrom image definition (`.start_block`); identical to the firmware's.
#[unsafe(link_section = ".start_block")]
#[used]
static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioIrq<PIO0>;
    DMA_IRQ_0 => DmaIrq<DMA_CH0>;
});

/// Target QSPI flash size, resolved from the `FLASH_SIZE` build knob (default
/// 4 MB) by [`build.rs`]. Erasing the whole chip — not a fixed 4 MB — is what
/// keeps a larger board (e.g. the 16 MiB display board) from retaining sealed
/// secrets above the assumed size.
const FLASH_SIZE: usize = parse_dec(env!("PK_FLASH_SIZE"));

/// Compile-time decimal parse for the build-emitted `PK_FLASH_SIZE`.
const fn parse_dec(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut n = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        assert!(
            b.is_ascii_digit(),
            "PK_FLASH_SIZE must be a decimal byte count"
        );
        n = n * 10 + (b - b'0') as usize;
        i += 1;
    }
    n
}
/// Board LED wiring, baked in by `build.rs` from the same `BOARD` / `LED_*` knobs
/// the firmware reads. `PK_LED_RGB` is 1 for an RGB-order strip, 0 for GRB.
const LED_PIN: u8 = parse_dec(env!("PK_LED_PIN")) as u8;
const LED_RGB: bool = parse_dec(env!("PK_LED_RGB")) != 0;
const LED_PRESENT: bool = !str_eq(env!("PK_LED_KIND"), "none");

/// Compile-time string equality (`==` on `&str` is not const).
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// One flash programming page.
const PAGE_SIZE: usize = 256;
/// 64 KiB block erase (pico-sdk `FLASH_BLOCK_SIZE` / `FLASH_BLOCK_ERASE_CMD`).
const BLOCK_SIZE: u32 = 1 << 16;
const BLOCK_ERASE_CMD: u8 = 0xD8;

const OFF: RGB8 = RGB8 { r: 0, g: 0, b: 0 };
const WHITE: RGB8 = RGB8 {
    r: 12,
    g: 12,
    b: 12,
};
const BLUE: RGB8 = RGB8 { r: 0, g: 0, b: 16 };
const GREEN: RGB8 = RGB8 { r: 0, g: 16, b: 0 };

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // LED first, so "the RAM image is running" can be signalled before flash. Pin
    // and colour order come from the same `BOARD`/`LED_*` knobs the firmware reads:
    // a hard-coded GPIO16 was dark on the boards that wire the LED elsewhere, and
    // on the display board it would drive the panel backlight (run-34 #31).
    let Pio {
        mut common, sm0, ..
    } = Pio::new(p.PIO0, Irqs);
    let program = PioWs2812Program::new(&mut common);
    macro_rules! ws2812_pin {
        ($pin:expr) => {
            PioWs2812::with_color_order(&mut common, sm0, p.DMA_CH0, Irqs, $pin, &program)
        };
    }
    // The wire order stays `Rgb` and `wire()` swaps the bytes instead, so one type
    // covers both boards — the same trick the firmware's `led::set_rg_swap` uses.
    let mut ws: Option<PioWs2812<'_, _, 0, 1, Rgb>> = if LED_PRESENT {
        Some(match LED_PIN {
            0 => ws2812_pin!(p.PIN_0),
            1 => ws2812_pin!(p.PIN_1),
            2 => ws2812_pin!(p.PIN_2),
            3 => ws2812_pin!(p.PIN_3),
            4 => ws2812_pin!(p.PIN_4),
            5 => ws2812_pin!(p.PIN_5),
            6 => ws2812_pin!(p.PIN_6),
            7 => ws2812_pin!(p.PIN_7),
            8 => ws2812_pin!(p.PIN_8),
            9 => ws2812_pin!(p.PIN_9),
            10 => ws2812_pin!(p.PIN_10),
            11 => ws2812_pin!(p.PIN_11),
            12 => ws2812_pin!(p.PIN_12),
            13 => ws2812_pin!(p.PIN_13),
            14 => ws2812_pin!(p.PIN_14),
            15 => ws2812_pin!(p.PIN_15),
            16 => ws2812_pin!(p.PIN_16),
            17 => ws2812_pin!(p.PIN_17),
            18 => ws2812_pin!(p.PIN_18),
            19 => ws2812_pin!(p.PIN_19),
            20 => ws2812_pin!(p.PIN_20),
            21 => ws2812_pin!(p.PIN_21),
            22 => ws2812_pin!(p.PIN_22),
            23 => ws2812_pin!(p.PIN_23),
            24 => ws2812_pin!(p.PIN_24),
            25 => ws2812_pin!(p.PIN_25),
            26 => ws2812_pin!(p.PIN_26),
            27 => ws2812_pin!(p.PIN_27),
            28 => ws2812_pin!(p.PIN_28),
            _ => ws2812_pin!(p.PIN_29),
        })
    } else {
        None
    };

    // "RAM image is running" — a fast white strobe, unlike any flashed firmware.
    blink(&mut ws, WHITE, 8, 50).await;

    // Solid blue for the (multi-second) full erase + eyecatcher write.
    solid(&mut ws, BLUE).await;
    flash_erase_all();
    let mut page = [0u8; PAGE_SIZE];
    page[..4].copy_from_slice(b"NUKE");
    flash_program(0, &page);

    // Sequence complete (the ROM flash calls report no status; the wipe is
    // verified functionally, not by a flaky in-RAM readback).
    blink(&mut ws, GREEN, 3, 150).await;

    rom_data::reset_to_usb_boot(0, 0);
    // reset_to_usb_boot does not return on success; park if a reboot ever fails.
    loop {
        cortex_m::asm::wfi();
    }
}

/// Erase all of flash via the bootrom, with interrupts off for the duration.
fn flash_erase_all() {
    critical_section::with(|_| unsafe {
        rom_data::connect_internal_flash();
        rom_data::flash_exit_xip();
        rom_data::flash_range_erase(0, FLASH_SIZE, BLOCK_SIZE, BLOCK_ERASE_CMD);
        rom_data::flash_flush_cache();
        rom_data::flash_enter_cmd_xip();
    });
}

/// Program one or more pages at `off` (offset + length must be page-multiples).
fn flash_program(off: u32, data: &[u8]) {
    critical_section::with(|_| unsafe {
        rom_data::connect_internal_flash();
        rom_data::flash_exit_xip();
        rom_data::flash_range_program(off, data.as_ptr(), data.len());
        rom_data::flash_flush_cache();
        rom_data::flash_enter_cmd_xip();
    });
}

/// The bytes to put on the wire for `c`. The PIO driver is pinned to `Rgb`, so a
/// GRB-order board gets its red and green swapped here instead of at the type
/// level — one binary shape for both, exactly as the firmware does it.
const fn wire(c: RGB8) -> RGB8 {
    if LED_RGB {
        c
    } else {
        RGB8 {
            r: c.g,
            g: c.r,
            b: c.b,
        }
    }
}

/// Hold `color`. A `LED_KIND=none` board has no addressable LED, and its GPIO16 is
/// the panel backlight, so there is nothing to drive and nothing to guess.
async fn solid<P: Instance, const S: usize, const N: usize, ORDER: RgbColorOrder>(
    ws: &mut Option<PioWs2812<'_, P, S, N, ORDER>>,
    color: RGB8,
) {
    if let Some(ws) = ws {
        ws.write(&[wire(color); N]).await;
    }
}

/// Blink `color` `times` times, `ms` on / `ms` off.
async fn blink<P: Instance, const S: usize, const N: usize, ORDER: RgbColorOrder>(
    ws: &mut Option<PioWs2812<'_, P, S, N, ORDER>>,
    color: RGB8,
    times: usize,
    ms: u64,
) {
    for _ in 0..times {
        solid(ws, color).await;
        Timer::after_millis(ms).await;
        solid(ws, OFF).await;
        Timer::after_millis(ms).await;
    }
}
