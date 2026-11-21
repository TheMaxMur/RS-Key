// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display colour palette — one place so every screen speaks the same
//! visual language. This is the high-fidelity redesign palette: a near-black blue-grey
//! background, a blue accent, calm danger / warning / success tiers, and a set of
//! pre-computed *solid* equivalents for the design's `rgba()` overlays (embedded-
//! graphics has no alpha blend, so each translucent border/tint is flattened to the
//! one opaque colour it resolves to over the background).
//!
//! Values are `Rgb565` (the panel's native format); the `#rrggbb` in each comment is
//! the 8-bit source the 5/6/5 channels are quantised from. Close dark tones may band
//! slightly on the panel — acceptable per the handoff.

use embedded_graphics::pixelcolor::Rgb565;

/// 8-bit `#rrggbb` → `Rgb565`, evaluated at compile time so every token stays a
/// `const` the renderer reads directly.
const fn rgb(r: u8, g: u8, b: u8) -> Rgb565 {
    Rgb565::new(r >> 3, g >> 2, b >> 3)
}

// --- Surfaces ---------------------------------------------------------------

/// Screen background. `#0A0D11`.
pub const BG: Rgb565 = rgb(0x0A, 0x0D, 0x11);
/// A lifted surface / card / list-row. `#13171D`.
pub const SURFACE: Rgb565 = rgb(0x13, 0x17, 0x1D);
/// A tappable key / control surface (PIN-pad keys, ± steppers). `#15191F`.
pub const KEY_BG: Rgb565 = rgb(0x15, 0x19, 0x1F);
/// The darker key (the backspace key on the pad). `#101317`.
pub const KEY_DARK: Rgb565 = rgb(0x10, 0x13, 0x17);
/// The service-icon chip behind an rp glyph. `#1C2127`.
pub const CHIP: Rgb565 = rgb(0x1C, 0x21, 0x27);

// --- Text tiers -------------------------------------------------------------

/// Primary text. `#EEF1F4`.
pub const TEXT: Rgb565 = rgb(0xEE, 0xF1, 0xF4);
/// Secondary text. `#C4CBD2`.
pub const TEXT_2: Rgb565 = rgb(0xC4, 0xCB, 0xD2);
/// Muted text. `#9AA3AD`.
pub const MUTED: Rgb565 = rgb(0x9A, 0xA3, 0xAD);
/// Grey text. `#8B949E`.
pub const GREY: Rgb565 = rgb(0x8B, 0x94, 0x9E);
/// Faint text / mono labels. `#7A8591`.
pub const FAINT: Rgb565 = rgb(0x7A, 0x85, 0x91);
/// Faintest text / captions. `#5F6B76`.
pub const CAPTION: Rgb565 = rgb(0x5F, 0x6B, 0x76);

// --- Accent (blue) ----------------------------------------------------------

/// Blue accent — headings, the active state, icons. `#4D9BFF`.
pub const ACCENT: Rgb565 = rgb(0x4D, 0x9B, 0xFF);
/// Blue button fill (the primary action). `#2F7DF0`.
pub const ACCENT_FILL: Rgb565 = rgb(0x2F, 0x7D, 0xF0);
/// Blue text on a dark tint. `#5AA2FF`.
pub const ACCENT_TEXT: Rgb565 = rgb(0x5A, 0xA2, 0xFF);

// --- Status colours ---------------------------------------------------------

/// Danger — text. `#FF7074`.
pub const DANGER: Rgb565 = rgb(0xFF, 0x70, 0x74);
/// Danger — fill (destructive button / hold). `#D2353A`.
pub const DANGER_FILL: Rgb565 = rgb(0xD2, 0x35, 0x3A);
/// Warning — amber. `#F0B429`.
pub const WARN: Rgb565 = rgb(0xF0, 0xB4, 0x29);
/// Success — green. `#3FB950`.
pub const SUCCESS: Rgb565 = rgb(0x3F, 0xB9, 0x50);
/// The "OK" status label (a softer green than [`SUCCESS`]). `#6EC07A`.
pub const OK: Rgb565 = rgb(0x6E, 0xC0, 0x7A);

// --- Solid equivalents of the design's rgba() overlays ----------------------

/// Card / button border (`rgba(255,255,255,.10)`). `#252C33`.
pub const BORDER_CARD: Rgb565 = rgb(0x25, 0x2C, 0x33);
/// Row divider (`rgba(255,255,255,.09)`). `#20262C`.
pub const DIVIDER: Rgb565 = rgb(0x20, 0x26, 0x2C);
/// Key border (`rgba(255,255,255,.08)`). `#1D232A`.
pub const BORDER_KEY: Rgb565 = rgb(0x1D, 0x23, 0x2A);
/// Blue tint background — outline buttons, the update card (`rgba(47,125,240,.08)`). `#11202F`.
pub const TINT_BLUE: Rgb565 = rgb(0x11, 0x20, 0x2F);
/// Blue badge — "OFFERED OVER USB" (`rgba(47,125,240,.16)`). `#1A2A40`.
pub const BADGE_BLUE: Rgb565 = rgb(0x1A, 0x2A, 0x40);
/// Input-field / dashed border (`rgba(77,155,255,.45)`). `#3A567C`.
pub const BORDER_FIELD: Rgb565 = rgb(0x3A, 0x56, 0x7C);
/// Firmware update card border (`rgba(77,155,255,.32)`). `#2A4366`.
pub const BORDER_UPDATE: Rgb565 = rgb(0x2A, 0x43, 0x66);
/// Danger outline-button background (`rgba(229,72,77,.07)`). `#1C1214`.
pub const DANGER_BG: Rgb565 = rgb(0x1C, 0x12, 0x14);
/// Danger outline-button border (`rgba(229,72,77,.50)`). `#7A3133`.
pub const DANGER_BORDER: Rgb565 = rgb(0x7A, 0x31, 0x33);
/// Warning plate background (`rgba(245,166,35,.09)`). `#1E1A12`.
pub const WARN_BG: Rgb565 = rgb(0x1E, 0x1A, 0x12);
/// Warning plate border (`rgba(245,166,35,.28)`). `#473717`.
pub const WARN_BORDER: Rgb565 = rgb(0x47, 0x37, 0x17);
/// Success circle background (`rgba(63,185,80,.12)`). `#16271A`.
pub const SUCCESS_BG: Rgb565 = rgb(0x16, 0x27, 0x1A);
/// Hold-progress overlay on a blue button (`rgba(255,255,255,.26)` over blue). `#6EA2F5`.
pub const HOLD_ON_BLUE: Rgb565 = rgb(0x6E, 0xA2, 0xF5);
/// Hold-progress overlay on a red button. `#DD6A6E`.
pub const HOLD_ON_RED: Rgb565 = rgb(0xDD, 0x6A, 0x6E);

// --- Back-compat aliases ----------------------------------------------------
// The renderer was written against the previous palette's token names; these keep it
// compiling while the screens are re-skinned onto the tokens above wave by wave.

/// Panel background. Alias of [`BG`].
pub const PANEL_BG: Rgb565 = BG;
/// List-row / card surface. Alias of [`SURFACE`].
pub const ROW_BG: Rgb565 = SURFACE;
/// Bottom-nav surface. Alias of [`KEY_DARK`].
pub const NAV_BG: Rgb565 = KEY_DARK;
/// Key edge. Alias of [`BORDER_KEY`].
pub const KEY_BORDER: Rgb565 = BORDER_KEY;
/// Affirmative / primary-action fill — now the blue primary button. Alias of [`ACCENT_FILL`].
pub const APPROVE: Rgb565 = ACCENT_FILL;
/// Decline / destructive accent. Alias of [`DANGER`].
pub const DENY: Rgb565 = DANGER;
/// Inactive bottom-nav glyph. Alias of [`CAPTION`].
pub const NAV_INACTIVE: Rgb565 = CAPTION;
/// Hairline separators. Alias of [`DIVIDER`].
pub const HAIRLINE: Rgb565 = DIVIDER;

#[cfg(test)]
#[path = "theme_tests.rs"]
mod tests;
