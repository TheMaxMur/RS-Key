// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! LED status engine: each status (boot/processing/touch/idle) has a fixed blink
//! timing plus a runtime-configurable color/brightness persisted in `EF_LED_CONF`.
//! The blink task runs on the high-priority interrupt executor, so the LED keeps
//! animating while the worker blocks in a touch wait or long synchronous crypto.
//!
//! The status engine is backend-agnostic — it keeps a colour/brightness per
//! status in atomics. The render half is chosen at build time by `LED_KIND`:
//! [`Blinker::tick`] computes the colour to show each tick, and one of the
//! `*_task`s drives the hardware — `ws2812` (addressable RGB), `gpio` (a plain
//! single-colour LED: hue collapsed to lit/unlit, brightness via software PWM),
//! `pimoroni` (3-pin PWM RGB), or `none` (no indicator).

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(not(led_kind = "none"))]
use embassy_time::{Duration, Instant, Timer};
#[cfg(not(led_kind = "none"))]
use smart_leds::RGB8;

// Every non-`none` build compiles all three hardware backends — the driver and
// pin are chosen at runtime from the phy record (see `main`). The embassy color
// order is fixed at `Rgb` (raw passthrough); the WS2812 wire byte order is instead
// a runtime software r/g swap (`LED_RG_SWAP`), so a board whose red/green come out
// swapped (standard WS2812B = GRB, e.g. the TenStar RP2350-USB; the Waveshare
// RP2350-One is unusually RGB) is corrected without reflashing. `LED_ORDER` only
// seeds the swap's boot default.
#[cfg(not(led_kind = "none"))]
use embassy_rp::peripherals::PIO0;
#[cfg(not(led_kind = "none"))]
use embassy_rp::pio_programs::ws2812::{PioWs2812, Rgb as Ws2812Order};

#[cfg(not(led_kind = "none"))]
use embassy_rp::gpio::Output;

#[cfg(not(led_kind = "none"))]
use embassy_rp::pwm::{Config as PwmConfig, Pwm};

/// Maximum number of addressable LEDs the PIO buffer and frame arrays are
/// sized to. Baked at compile time via the `MAX_LEDS` build flag (default 1);
/// the actual connected count is set at runtime via `rsk hw --led-num` and
/// must be ≤ this value.
#[cfg(not(led_kind = "none"))]
pub const MAX_LEDS: usize = max_leds();

/// Parse the `PK_MAX_LEDS` env string to `usize` in const context.
/// Panics at compile time if the value exceeds `u8::MAX` (the runtime count
/// is stored as a `u8`, so the ceiling must fit).
#[cfg(not(led_kind = "none"))]
const fn max_leds() -> usize {
    let s = env!("PK_MAX_LEDS");
    let b = s.as_bytes();
    let mut acc: usize = 0;
    let mut i = 0;
    while i < b.len() {
        acc = acc * 10 + (b[i] - b'0') as usize;
        i += 1;
    }
    assert!(acc <= 255, "MAX_LEDS must fit in u8");
    acc
}

/// Status indices and the per-status factory look — single-sourced in the codec,
/// which enforces the touch-indicator policy on every decode
/// ([`rsk_led::LedConfig::enforce_touch_invariants`]). Re-exported so the rest of
/// the firmware keeps naming them `led::STATUS_TOUCH` & co.
pub use rsk_led::{
    DEFAULT_BRIGHTNESS, DEFAULT_COLOR, DEFAULT_EFFECT, DEFAULT_SPEED, STATUS_BOOT, STATUS_IDLE,
    STATUS_PROCESSING, STATUS_TOUCH,
};

/// The palette and effect ids only the render half names (`LED_KIND=none` has none).
#[cfg(not(led_kind = "none"))]
pub use rsk_led::{
    COLOR_BLUE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW, EFFECT_BOUNCE, EFFECT_FLOW, EFFECT_SPARKLE,
    EFFECT_VAPOR,
};

const N_STATUS: usize = 4;

/// Fixed blink timing per status `(on_ms, off_ms)` — only color and brightness
/// are configurable. Indexed by the `STATUS_*` constants.
#[cfg(not(led_kind = "none"))]
const TIMING: [(u64, u64); N_STATUS] = [
    (500, 500),  // Idle
    (50, 50),    // Processing
    (1000, 100), // Touch
    (500, 500),  // Boot
];
/// `EF_LED_CONF` byte layout: `[steady, (effect, color, brightness, speed) × N_STATUS]`.
pub const CONF_LEN: usize = 1 + 4 * N_STATUS;

static LED_STATUS: AtomicU8 = AtomicU8::new(STATUS_BOOT);
/// When set, the blink task ignores the on/off phases and shows the current
/// status color solidly — the status still recolors the LED, it just stops
/// blinking. Off by default.
static LED_STEADY: AtomicBool = AtomicBool::new(false);
static STATUS_COLOR: [AtomicU8; N_STATUS] = [
    AtomicU8::new(DEFAULT_COLOR[STATUS_IDLE as usize]),
    AtomicU8::new(DEFAULT_COLOR[STATUS_PROCESSING as usize]),
    AtomicU8::new(DEFAULT_COLOR[STATUS_TOUCH as usize]),
    AtomicU8::new(DEFAULT_COLOR[STATUS_BOOT as usize]),
];
static STATUS_BRIGHTNESS: [AtomicU8; N_STATUS] = [
    AtomicU8::new(DEFAULT_BRIGHTNESS),
    AtomicU8::new(DEFAULT_BRIGHTNESS),
    AtomicU8::new(DEFAULT_BRIGHTNESS),
    AtomicU8::new(DEFAULT_BRIGHTNESS),
];
static STATUS_EFFECT: [AtomicU8; N_STATUS] = [
    AtomicU8::new(DEFAULT_EFFECT[STATUS_IDLE as usize]),
    AtomicU8::new(DEFAULT_EFFECT[STATUS_PROCESSING as usize]),
    AtomicU8::new(DEFAULT_EFFECT[STATUS_TOUCH as usize]),
    AtomicU8::new(DEFAULT_EFFECT[STATUS_BOOT as usize]),
];
static STATUS_SPEED: [AtomicU8; N_STATUS] = [
    AtomicU8::new(DEFAULT_SPEED[STATUS_IDLE as usize]),
    AtomicU8::new(DEFAULT_SPEED[STATUS_PROCESSING as usize]),
    AtomicU8::new(DEFAULT_SPEED[STATUS_TOUCH as usize]),
    AtomicU8::new(DEFAULT_SPEED[STATUS_BOOT as usize]),
];
/// WS2812 wire r/g swap, read live by the addressable render task. Seeds from the
/// `LED_ORDER` build flag (`grb` → swap red↔green, `rgb` → passthrough) and is
/// overridden at boot by the phy record's order tag via [`set_rg_swap`]. embassy's
/// color order stays `Rgb`, so this software swap is the single runtime knob.
#[cfg(not(led_kind = "none"))]
static LED_RG_SWAP: AtomicBool = AtomicBool::new(cfg!(led_order = "grb"));

/// The number of addressable LEDs actually connected; set from the phy record
/// at boot (`rsk hw --led-num`). Must be ≤ [`MAX_LEDS`]. Defaults to `MAX_LEDS`
/// when the phy record carries no count.
#[cfg(not(led_kind = "none"))]
static RUNTIME_LEDS: AtomicU8 = AtomicU8::new(MAX_LEDS as u8);

/// Return the runtime LED count — how many of the [`MAX_LEDS`] buffer slots
/// are actually connected and should be lit.
#[cfg(not(led_kind = "none"))]
pub fn runtime_leds() -> u8 {
    RUNTIME_LEDS.load(Ordering::Relaxed)
}

/// Set the runtime LED count from the phy record at boot. The phy record is
/// host/PicoForge-writable and survives every factory reset, so a value above
/// the compiled [`MAX_LEDS`] ceiling is **saturated**, never asserted — a panic
/// on this boot path would re-fire on every reboot (the bad value persists),
/// bricking the device into a loop recoverable only by reflashing. Lighting all
/// `MAX_LEDS` is the safe degradation for an over-large count.
#[cfg(not(led_kind = "none"))]
pub fn set_runtime_leds(n: u8) {
    RUNTIME_LEDS.store(rsk_led::clamp_leds(n, MAX_LEDS as u8), Ordering::Relaxed);
}

/// Set the active status (the worker on dispatch start/end, `presence` for a
/// touch wait). Out-of-range indices are clamped by the render loop.
pub fn set_status(idx: u8) {
    LED_STATUS.store(idx, Ordering::Relaxed);
}

/// The active status index — saved/restored around a touch wait by `presence`.
#[cfg_attr(feature = "no-touch", allow(dead_code))]
pub fn status() -> u8 {
    LED_STATUS.load(Ordering::Relaxed)
}

/// Read-modify-write the live config through the codec. Every writer goes through
/// here, so the touch indicator keeps its floor and stays distinguishable from the
/// other statuses whichever transport asked — a `SET LED` setter as much as a
/// decoded block ([`rsk_led::LedConfig::enforce_touch_invariants`]).
fn update_config(f: impl FnOnce(&mut rsk_led::LedConfig)) {
    let mut cfg = snapshot();
    f(&mut cfg);
    cfg.enforce_touch_invariants();
    LED_STEADY.store(cfg.steady, Ordering::Relaxed);
    for (i, s) in cfg.status.iter().enumerate() {
        STATUS_EFFECT[i].store(s.effect, Ordering::Relaxed);
        STATUS_COLOR[i].store(s.color, Ordering::Relaxed);
        STATUS_BRIGHTNESS[i].store(s.brightness, Ordering::Relaxed);
        STATUS_SPEED[i].store(s.speed, Ordering::Relaxed);
    }
}

/// The live atomics as a [`rsk_led::LedConfig`].
fn snapshot() -> rsk_led::LedConfig {
    let mut cfg = rsk_led::LedConfig {
        steady: LED_STEADY.load(Ordering::Relaxed),
        ..Default::default()
    };
    for (i, s) in cfg.status.iter_mut().enumerate() {
        s.effect = STATUS_EFFECT[i].load(Ordering::Relaxed);
        s.color = STATUS_COLOR[i].load(Ordering::Relaxed);
        s.brightness = STATUS_BRIGHTNESS[i].load(Ordering::Relaxed);
        s.speed = STATUS_SPEED[i].load(Ordering::Relaxed);
    }
    cfg
}

/// Override one status's color (0–7) and brightness (0–255, 0 = off); used by the
/// vendor SET LED command.
pub fn set_status_config(idx: u8, color: u8, brightness: u8) {
    let i = (idx as usize).min(N_STATUS - 1);
    update_config(|cfg| {
        cfg.status[i].color = color & 0x7;
        cfg.status[i].brightness = brightness;
    });
}

/// Override one status's effect.
pub fn set_status_effect(idx: u8, effect: u8) {
    let i = (idx as usize).min(N_STATUS - 1);
    update_config(|cfg| cfg.status[i].effect = effect);
}

/// Override one status's effect speed (0 = use the effect's built-in default).
/// Kept separate from [`set_status_effect`] so a SET LED that carries only an
/// effect byte leaves a previously-set custom speed untouched.
pub fn set_status_speed(idx: u8, speed: u8) {
    let i = (idx as usize).min(N_STATUS - 1);
    update_config(|cfg| cfg.status[i].speed = speed);
}

/// Toggle the global no-blink (solid) mode.
pub fn set_steady(on: bool) {
    LED_STEADY.store(on, Ordering::Relaxed);
}

/// Set the WS2812 wire r/g swap (the boot-applied phy order tag). `true` = the LED
/// is GRB-wired (standard WS2812B) and red/green are swapped before writing; the
/// addressable task reads this live.
#[cfg(not(led_kind = "none"))]
pub fn set_rg_swap(on: bool) {
    LED_RG_SWAP.store(on, Ordering::Relaxed);
}

/// Set every status's brightness at once — the phy record's boot-default channel
/// max (PicoForge's global brightness), applied before `EF_LED_CONF` can override.
#[cfg(not(led_kind = "none"))]
pub fn set_all_brightness(b: u8) {
    update_config(|cfg| {
        for s in cfg.status.iter_mut() {
            s.brightness = b;
        }
    });
}

/// The full config as the persisted/`GET LED` block `[steady, (effect, color, br, speed) × N]`.
pub fn config_block() -> [u8; CONF_LEN] {
    snapshot().encode()
}

/// Apply a config block (boot from flash / SET LED). The wire-format decode —
/// including the older 13/9/2-byte layouts an upgrade may still have in flash —
/// lives in [`rsk_led::LedConfig::apply_block`] (host-unit-tested). The live
/// atomics are the base, so a short block preserves whatever fields it doesn't
/// carry.
pub fn load_block(b: &[u8]) {
    update_config(|cfg| cfg.apply_block(b));
}

/// Map a status colour code (0–7) at channel max `b` to an RGB triple.
#[cfg(not(led_kind = "none"))]
fn color_rgb(color: u8, b: u8) -> RGB8 {
    let (r, g, bl) = match color {
        COLOR_RED => (b, 0, 0),
        COLOR_GREEN => (0, b, 0),
        COLOR_BLUE => (0, 0, b),
        COLOR_YELLOW => (b, b, 0),
        5 => (b, 0, b), // magenta
        6 => (0, b, b), // cyan
        7 => (b, b, b), // white
        _ => (0, 0, 0), // off
    };
    RGB8 { r, g, b: bl }
}

/// Tracks the blink phase and yields the colour to show each tick — shared by
/// every render backend. The status, colour and brightness are re-read every
/// tick so a mid-phase switch (touch wait, processing) recolors immediately. A
/// phase already underway keeps its length; in steady mode the timing still
/// advances (so toggling back to blinking resumes cleanly) but the colour stays
/// lit the whole phase.
#[cfg(not(led_kind = "none"))]
struct Blinker {
    on_phase: bool,
    phase_end: Instant,
}

#[cfg(not(led_kind = "none"))]
impl Blinker {
    fn new() -> Self {
        Self {
            on_phase: false,
            phase_end: Instant::now(),
        }
    }

    fn tick(&mut self) -> RGB8 {
        let s = (LED_STATUS.load(Ordering::Relaxed) as usize).min(N_STATUS - 1);
        let (on_ms, off_ms) = TIMING[s];
        let now = Instant::now();
        if now >= self.phase_end {
            self.on_phase = !self.on_phase;
            self.phase_end =
                now + Duration::from_millis(if self.on_phase { on_ms } else { off_ms });
        }
        if self.on_phase || LED_STEADY.load(Ordering::Relaxed) {
            color_rgb(
                STATUS_COLOR[s].load(Ordering::Relaxed),
                STATUS_BRIGHTNESS[s].load(Ordering::Relaxed),
            )
        } else {
            RGB8::default()
        }
    }
}

// Compile-time wire-format invariants (asserts fire during `cargo build`,
// no test harness needed).
const _: () = {
    let bytes_per_status = 4;
    let expected = 1 + bytes_per_status * N_STATUS;
    assert!(CONF_LEN == expected);
    assert!(CONF_LEN == 17);
    // The firmware atomics and the `rsk-led` codec must agree on the layout —
    // `config_block` / `load_block` marshal one into the other.
    assert!(CONF_LEN == rsk_led::CONF_LEN);
    assert!(N_STATUS == rsk_led::N_STATUS);
};

// ------------------------------------------------------------------
// Effect functions — each renders a full frame [[`RGB8`]; `MAX_LEDS`]
// from per-status atomics and the global tick counter.
// ------------------------------------------------------------------

/// Return the configured tick-interval for `status`, or `default_val` when
/// the stored speed is 0 (meaning "use the built-in default").
#[cfg(not(led_kind = "none"))]
fn speed_for(status: usize, default_val: u32) -> u32 {
    let s = STATUS_SPEED[status].load(Ordering::Relaxed);
    if s == 0 { default_val } else { s as u32 }
}

/// Vapour / breathing: all LEDs pulse together with a triangle-wave
/// brightness envelope (~2 s period).
#[cfg(not(led_kind = "none"))]
fn effect_vapor(status: usize, tick: u32) -> [RGB8; MAX_LEDS] {
    let color_idx = STATUS_COLOR[status].load(Ordering::Relaxed);
    let peak = STATUS_BRIGHTNESS[status].load(Ordering::Relaxed);
    if peak == 0 {
        return [RGB8::default(); MAX_LEDS];
    }

    // Speed = period in ticks (0 = default ~2 s = 400 ticks).
    let period = speed_for(status, 400);
    let half = period / 2;
    if half == 0 {
        return [RGB8::default(); MAX_LEDS];
    }
    let phase = tick % period;
    let breathe = if phase < half {
        phase * peak as u32 / half
    } else {
        (period - phase) * peak as u32 / half
    };

    // Clamp before the u8 cast: for an odd period the falling ramp divides by
    // `half` (floor) over `half+1` steps, so `breathe` can exceed `peak` at the
    // apex and wrap to a dark value instead of the brightest.
    let c = color_rgb(color_idx, breathe.min(peak as u32) as u8);
    let n = runtime_leds() as usize;
    let mut buf = [RGB8::default(); MAX_LEDS];
    for led in buf[..n].iter_mut() {
        *led = c;
    }
    buf
}

/// Smooth bounce: a wide hump of light glides back and forth along the
/// strip with half-step interpolation so there is no endpoint stutter.
/// Centre LED at full brightness, neighbours at half.
/// Falls back to a static colour when fewer than 2 runtime LEDs are
/// connected.
#[cfg(not(led_kind = "none"))]
fn effect_bounce(status: usize, tick: u32) -> [RGB8; MAX_LEDS] {
    let color_idx = STATUS_COLOR[status].load(Ordering::Relaxed);
    let peak = STATUS_BRIGHTNESS[status].load(Ordering::Relaxed);
    if peak == 0 {
        return [RGB8::default(); MAX_LEDS];
    }
    let base = color_rgb(color_idx, peak);

    let n = runtime_leds() as usize;
    if n <= 1 {
        let mut buf = [RGB8::default(); MAX_LEDS];
        if n == 1 {
            buf[0] = base;
        }
        return buf;
    }

    let speed = speed_for(status, 10); // ticks per half-step (0 = default 10 = 50 ms)
    let virtual_steps = 4 * (n - 1);
    let raw = (tick / speed) as usize % virtual_steps;

    let half_pos = if raw < 2 * (n - 1) {
        raw
    } else {
        virtual_steps - 1 - raw
    };

    let led_a = half_pos / 2;
    let frac = (half_pos & 1) != 0;

    let mut buf = [RGB8::default(); MAX_LEDS];
    if !frac {
        buf[led_a] = base;
        if led_a > 0 {
            buf[led_a - 1] = scale_rgb(base, 1, 2);
        }
        if led_a + 1 < n {
            buf[led_a + 1] = scale_rgb(base, 1, 2);
        }
    } else {
        buf[led_a] = scale_rgb(base, 1, 2);
        if led_a + 1 < n {
            buf[led_a + 1] = scale_rgb(base, 1, 2);
        }
    }
    buf
}

/// Flow: a comet of the configured status colour glides unidirectionally with a
/// trailing wake that dims along its length. Trail length adapts to the runtime
/// LED count. Honours the per-status colour (was a fixed yellow→red gradient).
#[cfg(not(led_kind = "none"))]
fn effect_flow(status: usize, tick: u32) -> [RGB8; MAX_LEDS] {
    let color_idx = STATUS_COLOR[status].load(Ordering::Relaxed);
    let peak = STATUS_BRIGHTNESS[status].load(Ordering::Relaxed) as u16;
    if peak == 0 {
        return [RGB8::default(); MAX_LEDS];
    }

    let n = runtime_leds() as usize;
    if n == 0 {
        return [RGB8::default(); MAX_LEDS];
    }

    let trail = (n - 1).min(4);
    let speed = speed_for(status, 4); // ticks per step (0 = default 4 = 20 ms)
    let front = ((tick / speed) as usize) % n;

    let mut buf = [RGB8::default(); MAX_LEDS];
    for (i, led) in buf[..n].iter_mut().enumerate() {
        let dist = (i + n - front) % n;
        let bright = match dist {
            0 => peak,
            1 if trail >= 1 => peak * 3 / 5,
            2 if trail >= 2 => peak * 2 / 5,
            3 if trail >= 3 => peak / 5,
            4 if trail >= 4 => peak / 8,
            _ => continue,
        };
        *led = color_rgb(color_idx, bright as u8);
    }
    buf
}

/// Sparkle: each LED independently twinkles in the configured status colour
/// (~25 % duty cycle, deterministic splitmix32 hash) at a pseudo-random brightness.
/// Honours the per-status colour (was random RGB). `speed` is the number of ticks a
/// pattern is held before the field re-rolls (`0` = built-in default 8 ≈ 40 ms);
/// seeding on `tick / speed` rather than `tick` both honors `--speed` and tames the
/// otherwise per-tick (~200 Hz) strobe.
#[cfg(not(led_kind = "none"))]
fn effect_sparkle(status: usize, tick: u32) -> [RGB8; MAX_LEDS] {
    let color_idx = STATUS_COLOR[status].load(Ordering::Relaxed);
    let peak = STATUS_BRIGHTNESS[status].load(Ordering::Relaxed);
    if peak == 0 {
        return [RGB8::default(); MAX_LEDS];
    }

    // speed_for never returns 0, so the division is always safe.
    let step = tick / speed_for(status, 8);
    let mut buf = [RGB8::default(); MAX_LEDS];
    let n = runtime_leds() as usize;
    for (i, led) in buf[..n].iter_mut().enumerate() {
        let h = splitmix32(step ^ (i as u32 * 0x9e3779b9));
        if (h & 0xFF) < 64 {
            // Configured hue, brightness scaled 96/255..=peak so each spark stays
            // visible — a twinkle in the chosen colour, not random RGB.
            let factor = 96 + (h >> 16) as u16 % 160; // 96..=255
            *led = color_rgb(color_idx, (peak as u16 * factor / 255) as u8);
        }
    }
    buf
}

/// Scale an `RGB8` by `num / den`.
#[cfg(not(led_kind = "none"))]
fn scale_rgb(c: RGB8, num: u8, den: u8) -> RGB8 {
    RGB8 {
        r: (c.r as u16 * num as u16 / den as u16) as u8,
        g: (c.g as u16 * num as u16 / den as u16) as u8,
        b: (c.b as u16 * num as u16 / den as u16) as u8,
    }
}

/// Minimal splitmix32 pseudo-random hash (deterministic, no std dependency).
#[cfg(not(led_kind = "none"))]
fn splitmix32(mut x: u32) -> u32 {
    x = x.wrapping_add(0x9e3779b9);
    x ^= x >> 16;
    x = x.wrapping_mul(0x85ebca6b);
    x ^= x >> 13;
    x = x.wrapping_mul(0xc2b2ae35);
    x ^= x >> 16;
    x
}

/// `ws2812` backend: addressable LED effect engine. Reads the active status
/// and its configured effect/color/brightness/speed from atomics each tick
/// and dispatches to the appropriate effect function. Only the first
/// [`runtime_leds()`] LEDs are lit; the remaining [`MAX_LEDS`] buffer
/// positions stay dark.
#[cfg(not(led_kind = "none"))]
#[embassy_executor::task]
pub async fn ws2812_task(mut ws2812: PioWs2812<'static, PIO0, 0, MAX_LEDS, Ws2812Order>) {
    let mut tick: u32 = 0;
    // LEGACY blink state (tracked here because it is the only effect that
    // needs mutable state across ticks).
    let mut on_phase = false;
    let mut phase_end = Instant::now();

    loop {
        tick = tick.wrapping_add(1);
        let s = (LED_STATUS.load(Ordering::Relaxed) as usize).min(N_STATUS - 1);

        // Steady mode shows the status colour solidly. The animated effects
        // otherwise ignore LED_STEADY (only the legacy on/off renderer reads it),
        // so honour it here for every effect — PicoForge's "Steady" writes it.
        let buf = if LED_STEADY.load(Ordering::Relaxed) {
            steady_frame(s)
        } else {
            dispatch(s, tick, &mut on_phase, &mut phase_end)
        };

        // Per-pixel r/g wire-order swap (GRB-corrected parts).
        let mut buf = buf;
        if LED_RG_SWAP.load(Ordering::Relaxed) {
            for c in &mut buf {
                core::mem::swap(&mut c.r, &mut c.g);
            }
        }
        ws2812.write(&buf).await;
        Timer::after_millis(5).await;
    }
}

/// Solid frame for steady mode: the status colour lit across the runtime LEDs,
/// no animation. Every effect defers to this when `LED_STEADY` is set.
#[cfg(not(led_kind = "none"))]
fn steady_frame(s: usize) -> [RGB8; MAX_LEDS] {
    let c = color_rgb(
        STATUS_COLOR[s].load(Ordering::Relaxed),
        STATUS_BRIGHTNESS[s].load(Ordering::Relaxed),
    );
    let n = runtime_leds() as usize;
    let mut buf = [RGB8::default(); MAX_LEDS];
    for led in buf[..n].iter_mut() {
        *led = c;
    }
    buf
}

/// Choose and run the effect for status `s`. Exposed as a separate function
/// (rather than inlined into the task) so it can be unit-tested.
#[cfg(not(led_kind = "none"))]
fn dispatch(s: usize, tick: u32, on_phase: &mut bool, phase_end: &mut Instant) -> [RGB8; MAX_LEDS] {
    let effect_id = STATUS_EFFECT[s].load(Ordering::Relaxed);
    match effect_id {
        EFFECT_VAPOR => effect_vapor(s, tick),
        EFFECT_BOUNCE => effect_bounce(s, tick),
        EFFECT_FLOW => effect_flow(s, tick),
        EFFECT_SPARKLE => effect_sparkle(s, tick),
        // Unknown effect or LEGACY — fall back to on/off blink.
        _ => legacy_broadcast(s, on_phase, phase_end),
    }
}

/// Classic on/off blink: all LEDs show the same colour during the on phase
/// and turn off during the off phase, controlled by `TIMING[s]`.
#[cfg(not(led_kind = "none"))]
fn legacy_broadcast(s: usize, on_phase: &mut bool, phase_end: &mut Instant) -> [RGB8; MAX_LEDS] {
    let (on_ms, off_ms) = TIMING[s];
    let now = Instant::now();
    if now >= *phase_end {
        *on_phase = !*on_phase;
        *phase_end = now + Duration::from_millis(if *on_phase { on_ms } else { off_ms });
    }
    let c = if *on_phase || LED_STEADY.load(Ordering::Relaxed) {
        color_rgb(
            STATUS_COLOR[s].load(Ordering::Relaxed),
            STATUS_BRIGHTNESS[s].load(Ordering::Relaxed),
        )
    } else {
        RGB8::default()
    };
    let n = runtime_leds() as usize;
    let mut buf = [c; MAX_LEDS];
    for led in buf[n..].iter_mut() {
        *led = RGB8::default();
    }
    buf
}

/// `gpio` backend: a plain single-colour LED (active-high). Hue collapses to
/// lit/unlit, but brightness is honoured via **software PWM** — a short on/off
/// duty cycle over a ~2 ms (500 Hz, flicker-free) period, duty = brightness/255.
/// So the configured brightness (and PicoForge's "Dimmable") actually dims a plain
/// LED, not just a WS2812 one.
#[cfg(not(led_kind = "none"))]
#[embassy_executor::task]
pub async fn gpio_task(mut led: Output<'static>) {
    const PERIOD_US: u64 = 2000;
    let mut blinker = Blinker::new();
    loop {
        let c = blinker.tick();
        // The lit LED's brightness is the brightest channel of the status colour.
        let duty = c.r.max(c.g).max(c.b) as u64;
        let on_us = PERIOD_US * duty / 255;
        if on_us > 0 {
            led.set_high();
            Timer::after_micros(on_us).await;
        }
        if on_us < PERIOD_US {
            led.set_low();
            Timer::after_micros(PERIOD_US - on_us).await;
        }
    }
}

/// `pimoroni` backend: a 3-pin PWM RGB LED (Pimoroni Tiny 2350 — R=GPIO18,
/// G=GPIO19, B=GPIO20; common-anode, so the channels are inverted). `rg` drives
/// R (channel A) + G (channel B) on one slice, `b` drives B (channel A) on
/// another; `top` = 255 so a colour byte maps straight onto a compare value.
#[cfg(not(led_kind = "none"))]
#[embassy_executor::task]
pub async fn pimoroni_task(mut rg: Pwm<'static>, mut b: Pwm<'static>) {
    let mut blinker = Blinker::new();
    loop {
        let c = blinker.tick();
        let mut cfg = pimoroni_cfg();
        cfg.compare_a = u16::from(c.r);
        cfg.compare_b = u16::from(c.g);
        rg.set_config(&cfg);
        let mut cfg_b = pimoroni_cfg();
        cfg_b.compare_a = u16::from(c.b);
        b.set_config(&cfg_b);
        Timer::after_millis(5).await;
    }
}

/// Base PWM config for the Pimoroni common-anode RGB: an 8-bit `top`, both
/// channels inverted (the LED lights when the pin is driven low / sinks current).
/// Shared by the task and `main`'s `Pwm` construction so the polarity matches.
#[cfg(not(led_kind = "none"))]
pub fn pimoroni_cfg() -> PwmConfig {
    // `PwmConfig` is `#[non_exhaustive]`, so build from Default and set fields.
    let mut cfg = PwmConfig::default();
    cfg.top = 255;
    cfg.invert_a = true;
    cfg.invert_b = true;
    cfg
}

/// USB device-event handler: flip the boot status to idle the moment the host
/// *configures* the device, so the LED shows "enumerated & ready" (green) rather
/// than staying on the red boot status until the first application command. On a
/// host with no PC/SC daemon (and nothing else probing the key) that first
/// command may never arrive even though the key is healthy and enumerated, which
/// looked like a hang. The worker still drives processing/idle per command.
pub struct StatusHandler;

impl embassy_usb::Handler for StatusHandler {
    fn configured(&mut self, configured: bool) {
        set_status(if configured { STATUS_IDLE } else { STATUS_BOOT });
    }
}
