// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_LED_CONF` wire-format codec — the persisted LED config block shared by the
//! firmware (`firmware/src/led.rs`) and the `rsk led` host tool.
//!
//! The current block is `[steady, (effect, color, brightness, speed) × N_STATUS]`
//! (17 bytes). [`LedConfig::apply_block`] also accepts the older 13-byte
//! (pre-speed), 9-byte (pre-effect), and 2/3-byte (idle-only legacy) layouts
//! written by earlier firmware, so a flash record survives a firmware upgrade
//! without losing a field — anything the shorter block omits keeps its current
//! value.
//!
//! The per-status factory look (`DEFAULT_*`) lives here too, because the codec
//! enforces the touch-indicator policy on every decode — see
//! [`LedConfig::enforce_touch_invariants`].
//!
//! This crate is deliberately pure (no `embassy` / HAL dependency) so the codec
//! is unit-testable on the host. The firmware's `led.rs` owns the live atomics,
//! the effect rendering, and the PIO task, and marshals them through
//! [`LedConfig`]; nothing here touches hardware.

#![cfg_attr(not(test), no_std)]

/// Number of device statuses (idle, processing, touch, boot), in that order.
pub const N_STATUS: usize = 4;

/// `EF_LED_CONF` length: `[steady, (effect, color, brightness, speed) × N_STATUS]`.
pub const CONF_LEN: usize = 1 + 4 * N_STATUS;

/// The flash FID that persists the config block — outside both reset scopes
/// (sticky). Single-sourced here so the firmware LED applet and the FIDO
/// `CONFIG_WRITE`/`CONFIG_READ` LED target agree on where it lives.
pub const EF_LED_CONF: u16 = 0x1123;

/// Status indices — the index into [`LedConfig::status`], the `EF_LED_CONF`
/// layout, and the firmware's per-status atomics.
pub const STATUS_IDLE: u8 = 0;
pub const STATUS_PROCESSING: u8 = 1;
pub const STATUS_TOUCH: u8 = 2;
pub const STATUS_BOOT: u8 = 3;

/// Palette codes for the `color` byte; 0 = off.
pub const COLOR_RED: u8 = 1;
pub const COLOR_GREEN: u8 = 2;
pub const COLOR_BLUE: u8 = 3;
pub const COLOR_YELLOW: u8 = 4;

/// Built-in effect identifiers, stored as the `effect` byte per status.
/// `EFFECT_LEGACY` reproduces the original on/off blink.
pub const EFFECT_LEGACY: u8 = 0;
pub const EFFECT_VAPOR: u8 = 1; // breathing (all LEDs pulse together)
pub const EFFECT_BOUNCE: u8 = 2; // smooth bounce with half-step interpolation
pub const EFFECT_FLOW: u8 = 3; // comet of the status colour with a dimming trail
pub const EFFECT_SPARKLE: u8 = 4; // per-LED twinkle in the status colour

/// Speed value meaning "use the effect's built-in default speed".
pub const SPEED_DEFAULT: u8 = 0;

/// `CTAPHID_WINK` burst length and half-period, in milliseconds. CTAP §11.2.9.2.1
/// asks for "a short burst of flashes"; 600/75 is four blinks in 0.6 s — fast
/// enough that nobody mistakes it for one of the four statuses, short enough that
/// it cannot mask a touch prompt arriving right behind it.
pub const WINK_MS: u32 = 600;
pub const WINK_HALF_MS: u32 = 75;

/// Whether the wink LED is lit with `ms_left` of the burst still to run
/// (`ms_left <= WINK_MS`; the caller's deadline guard enforces that). The caller
/// keeps only a deadline — the one form that survives the millisecond counter
/// wrapping — so the phase is taken from the elapsed half-periods, which is what
/// makes the burst *start* lit rather than with a pause.
pub const fn wink_lit(ms_left: u32) -> bool {
    let elapsed = WINK_MS.saturating_sub(ms_left);
    (elapsed / WINK_HALF_MS).is_multiple_of(2)
}

/// Whether the burst whose deadline is `end` is still running at `now_ms`; `0` is
/// the never-winked sentinel. A deadline is the one form that survives the
/// millisecond counter wrapping, so liveness is `end - now` read as an unsigned
/// distance: past the end it wraps to a huge value and reads as expired, which is
/// also what covers the 49-day rollover.
pub const fn wink_running(end: u32, now_ms: u32) -> bool {
    let left = end.wrapping_sub(now_ms);
    end != 0 && left != 0 && left <= WINK_MS
}

/// The deadline a `CTAPHID_WINK` arriving at `now_ms` leaves behind, given the
/// current one. §11.2.9.2.1 asks for *a* burst, so one already running is left
/// alone: an ungated host re-arming faster than [`WINK_HALF_MS`] would otherwise
/// never let it reach a dark half-period, holding the reserved touch colour solid
/// — forging the consent indicator [`LedConfig::enforce_touch_invariants`] exists
/// to keep unforgeable.
pub const fn wink_arm(end: u32, now_ms: u32) -> u32 {
    if wink_running(end, now_ms) {
        end
    } else {
        now_ms.wrapping_add(WINK_MS)
    }
}

/// Default effect per status (indexed by the `STATUS_*` constants).
pub const DEFAULT_EFFECT: [u8; N_STATUS] = [
    EFFECT_VAPOR,   // IDLE
    EFFECT_FLOW,    // PROCESSING
    EFFECT_BOUNCE,  // TOUCH
    EFFECT_SPARKLE, // BOOT
];
/// Default colour per status (indexed by the `STATUS_*` constants).
pub const DEFAULT_COLOR: [u8; N_STATUS] = [COLOR_GREEN, COLOR_GREEN, COLOR_YELLOW, COLOR_RED];
/// Default speed per status (all use the effect's built-in default).
pub const DEFAULT_SPEED: [u8; N_STATUS] = [SPEED_DEFAULT; N_STATUS];
/// Default channel max (a gentle 16/255).
pub const DEFAULT_BRIGHTNESS: u8 = 16;

/// The floor the awaiting-touch indicator is held to. Every other status may be
/// dimmed to nothing, but this one is the only signal a non-display build gives
/// that the key is waiting for consent.
pub const TOUCH_MIN_BRIGHTNESS: u8 = 8;

/// The floor for a non-default touch `speed`: the breathing effect derives its
/// half-period as `speed / 2`, so `speed = 1` renders an all-black frame every
/// tick while the brightness byte still reads compliant.
pub const TOUCH_MIN_SPEED: u8 = 2;

/// The factory look for one status (`STATUS_*`) — what a status is reset to when
/// [`LedConfig::enforce_touch_invariants`] catches it impersonating the touch
/// indicator. Out-of-range indices clamp, matching the firmware's render loop.
pub fn default_status(status: u8) -> StatusCfg {
    let i = (status as usize).min(N_STATUS - 1);
    StatusCfg {
        effect: DEFAULT_EFFECT[i],
        color: DEFAULT_COLOR[i],
        brightness: DEFAULT_BRIGHTNESS,
        speed: DEFAULT_SPEED[i],
    }
}

// The touch fallback only converges if the touch factory look already satisfies
// the floors and its colour is claimed by no other status's factory look —
// colour being the axis uniqueness keys on.
const _: () = {
    assert!(DEFAULT_BRIGHTNESS >= TOUCH_MIN_BRIGHTNESS);
    assert!(DEFAULT_COLOR[STATUS_TOUCH as usize] != 0);
    assert!(
        DEFAULT_SPEED[STATUS_TOUCH as usize] == SPEED_DEFAULT
            || DEFAULT_SPEED[STATUS_TOUCH as usize] >= TOUCH_MIN_SPEED
    );
    let mut i = 0;
    while i < N_STATUS {
        assert!(
            i == STATUS_TOUCH as usize || DEFAULT_COLOR[i] != DEFAULT_COLOR[STATUS_TOUCH as usize]
        );
        i += 1;
    }
};

/// One status's configurable look. `color` is a `0..=7` palette index (`0` = off).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatusCfg {
    pub effect: u8,
    pub color: u8,
    pub brightness: u8,
    pub speed: u8,
}

/// The whole `EF_LED_CONF` block as a plain struct: a global `steady` flag plus
/// one [`StatusCfg`] per device status.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LedConfig {
    pub steady: bool,
    pub status: [StatusCfg; N_STATUS],
}

impl LedConfig {
    /// Pack into the current 17-byte wire block. `color` is masked to its low 3
    /// bits so the encoding is canonical regardless of any stray high bits.
    pub fn encode(&self) -> [u8; CONF_LEN] {
        let mut b = [0u8; CONF_LEN];
        b[0] = self.steady as u8;
        for (i, s) in self.status.iter().enumerate() {
            b[1 + 4 * i] = s.effect;
            b[2 + 4 * i] = s.color & 0x7;
            b[3 + 4 * i] = s.brightness;
            b[4 + 4 * i] = s.speed;
        }
        b
    }

    /// Overlay a stored / `SET LED` block onto `self`. A field absent from a
    /// shorter (older-firmware) block keeps its current value, so an upgrade
    /// preserves the look. Four formats, longest first:
    ///
    /// | Length | Layout |
    /// |--------|--------|
    /// | 17+   | `[steady, (effect, color, brightness, speed) × N]` — current |
    /// | 13–16 | `[steady, (effect, color, brightness) × N]` — pre-speed |
    /// | 7–12  | `[steady, (color, brightness) × N]` — pre-effect |
    /// | 2–3   | `[brightness, idle_color[, steady]]` — idle-only legacy |
    ///
    /// A block shorter than 2 bytes carries no field at all.
    ///
    /// Every decode ends in [`Self::enforce_touch_invariants`], so no writer can
    /// slip a suppressed or idle-aliased touch indicator past the codec.
    pub fn apply_block(&mut self, b: &[u8]) {
        if b.len() >= CONF_LEN {
            // Current: [steady, (effect, color, brightness, speed) × N]
            self.steady = b[0] != 0;
            for (i, s) in self.status.iter_mut().enumerate() {
                s.effect = b[1 + 4 * i];
                s.color = b[2 + 4 * i] & 0x7;
                s.brightness = b[3 + 4 * i];
                s.speed = b[4 + 4 * i];
            }
        } else if b.len() >= 13 {
            // Pre-speed: [steady, (effect, color, brightness) × N]; speed kept.
            self.steady = b[0] != 0;
            for (i, s) in self.status.iter_mut().enumerate() {
                s.effect = b[1 + 3 * i];
                s.color = b[2 + 3 * i] & 0x7;
                s.brightness = b[3 + 3 * i];
            }
        } else if b.len() >= 7 {
            // Pre-effect: [steady, (color, brightness) × N]; effect + speed kept.
            self.steady = b[0] != 0;
            let n = (b.len() - 1) / 2;
            for (i, s) in self.status.iter_mut().enumerate().take(n.min(N_STATUS)) {
                s.color = b[1 + 2 * i] & 0x7;
                s.brightness = b[2 + 2 * i];
            }
        } else if b.len() >= 2 {
            // Idle-only legacy: [brightness, idle_color[, steady]].
            self.status[0].brightness = b[0];
            self.status[0].color = b[1] & 0x7;
            if b.len() >= 3 {
                self.steady = b[2] != 0;
            }
        }
        self.enforce_touch_invariants();
    }

    /// Hold the awaiting-touch indicator to its floor and keep its colour to
    /// itself. On a non-display build it is the only sign the key is waiting for
    /// consent, so no writer may black it out or dress another status in the
    /// touch colour and harvest an unrelated press. Living in the codec, it
    /// covers the vendor SET LED setter, the FIDO `CONFIG_WRITE` LED target and
    /// the boot reload alike. Idempotent: enforcing twice is enforcing once.
    ///
    /// Uniqueness keys on the **colour alone**. Brightness and speed are nudgeable
    /// by one unit while staying identical to the eye, and `effect` renders nothing
    /// in steady mode or on a one-LED board (`firmware/src/led.rs::steady_frame`).
    pub fn enforce_touch_invariants(&mut self) {
        const TOUCH: usize = STATUS_TOUCH as usize;

        let t = &mut self.status[TOUCH];
        if t.color == 0 {
            t.color = DEFAULT_COLOR[TOUCH];
        }
        t.brightness = t.brightness.max(TOUCH_MIN_BRIGHTNESS);
        if t.speed != SPEED_DEFAULT {
            t.speed = t.speed.max(TOUCH_MIN_SPEED);
        }

        // A status wearing the touch colour is reset to its factory look — unless
        // that factory look wears it too, which the reset cannot fix, so there the
        // touch look gives way instead (its factory colour is nobody else's).
        let mut color = self.status[TOUCH].color;
        if (0..N_STATUS)
            .any(|i| i != TOUCH && self.status[i].color == color && DEFAULT_COLOR[i] == color)
        {
            self.status[TOUCH] = default_status(STATUS_TOUCH);
            color = self.status[TOUCH].color;
        }

        for (i, s) in self.status.iter_mut().enumerate() {
            if i != TOUCH && s.color == color {
                *s = default_status(i as u8);
            }
        }
    }
}

/// Clamp a runtime LED count to the firmware's compile-time `MAX_LEDS` ceiling.
///
/// The count originates in the host/PicoForge-writable phy record, which persists
/// across factory resets, so an over-large value must **saturate**, never panic
/// the boot path (a panic there would re-fire every reboot — an unrecoverable
/// loop). Lighting all `max` LEDs is the safe degradation. See
/// `firmware/src/led.rs::set_runtime_leds`.
pub fn clamp_leds(n: u8, max: u8) -> u8 {
    n.min(max)
}

#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
