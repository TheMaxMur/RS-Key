// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Vector icons drawn as hand-authored 1-bit bitmaps — no bitmap *asset* files, no
//! icon font, but no longer one contour scaled to every size either. Each glyph is
//! drawn by hand at the **canonical render sizes** the UI actually paints it
//! (`CANON`: a 14px list-row marker, a 16/18/20px nav/header icon, a 36/44px
//! headline), so a detailed icon stays crisp at 14px instead of collapsing into a
//! blob the way a single 16×16 contour did once the `(gx*g1+8)/16` grid map rounded
//! its features off-axis. A request for an off-canonical size (12, 22, 28, 32, 38, …)
//! blits the nearest canonical bitmap nearest-neighbour scaled — those are the large
//! or simple glyphs where a scale reads clean.
//!
//! The bitmaps live in-source as `&[&str]` rows (`'#'` = ink) so they are readable
//! and hand-editable: the maintainer tweaks a pixel by editing a character. They are
//! host-testable like the rest of the UI model — one test asserts every bitmap is
//! square and paints inside its box, a second asserts each glyph is mirror-symmetric
//! about the axes `sym` claims for it, at every canonical size (this is what guards
//! against the "crooked" look: symmetry is now a property of the authored art, checked
//! exactly where it is authored).
//!
//! The set is deliberately small and abstract. Per-relying-party brand logos are
//! **not** drawable — the device only knows the rp *string* (and its hash), not the
//! brand — so a relying party gets the generic [`Glyph::Globe`] plus its rpId text.

use embedded_graphics::{
    Pixel, draw_target::DrawTarget, geometry::Point as EgPoint, pixelcolor::Rgb565,
};

use crate::Point;

/// A drawable icon. Abstract, not brand-specific (see the module note on logos).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Glyph {
    /// USB plug — the "connected / powered" status (replaces a battery icon: this is
    /// a bus-powered device, it has no battery).
    Usb,
    /// A bare check mark — the PIN pad's OK / commit key.
    Check,
    /// A backspace key (left-pointing tag with an ×) — the PIN pad's Del key.
    Backspace,
    /// A check inside a ring — the big idle "Ready" indicator.
    CheckCircle,
    /// A closed padlock — PIN set / locked.
    Lock,
    /// A key — passkeys / credentials, and the Passkeys nav tab.
    Key,
    /// A house — the Home nav tab.
    Home,
    /// A cog — settings / the Settings nav tab.
    Gear,
    /// A right chevron — "this row drills in".
    Chevron,
    /// A left chevron — the service-detail "back to the list" affordance.
    Back,
    /// A shield — the trusted-approval prompt.
    Shield,
    /// A globe — the generic relying-party marker.
    Globe,
    /// A warning triangle — caution text.
    Warn,
    /// A sun — the brightness setting.
    Sun,
    /// A clock — the touch-timeout setting.
    Clock,
    /// A crescent moon — the display-sleep setting.
    Moon,
    /// A counter-clockwise refresh ring — the post-factory-reset "erased / restarting"
    /// indicator (the design's grey rotate icon, distinct from the green success check).
    Rotate,
    /// A pencil — the service-detail "rename" affordance (sets a device-local nickname).
    Edit,
    /// An eye (lens outline + pupil) — the confirm-delete "reveal PIN" toggle.
    Eye,
    /// A lifebuoy (outer ring + inner hub + four diagonal spokes) — the seed-backup /
    /// recovery marker on the Backup screen.
    Lifebuoy,
    /// A microchip — a square die with a smaller core and two pins per side. The
    /// installed-firmware marker on the Firmware screen / its settings row.
    Cpu,
    /// A 2×2 grid of tiles — the unified "Apps" nav tab (the applet launcher:
    /// OpenPGP / PIV / OATH).
    Apps,
    /// A command prompt — a ">" caret and an underscore cursor: the marker for an SSH
    /// relying party (a shell host) on the Passkeys list, distinct from the web globe.
    Terminal,
    /// A person (head + shoulders) — the OpenPGP "card holder" identity row.
    User,
}

/// One hand-authored 1-bit bitmap of a glyph at a single size. `rows` is `size` strings
/// of `size` bytes each; a byte `b'#'` is ink, anything else (`'.'`) is clear.
struct Bitmap {
    size: u16,
    rows: &'static [&'static str],
}

/// Pick the authored bitmap whose size best matches `s`: exact if present, else the
/// nearest; on a tie the larger source wins (more detail to scale down from).
fn pick(tbl: &'static [Bitmap], s: u16) -> &'static Bitmap {
    let mut best = &tbl[0];
    let mut best_d = i32::MAX;
    for b in tbl {
        let d = (b.size as i32 - s as i32).abs();
        if d < best_d || (d == best_d && b.size > best.size) {
            best_d = d;
            best = b;
        }
    }
    best
}

/// Draw `g` into the square box at `at` (top-left) of side `s` pixels, stroked in `color`.
/// Blits the canonical bitmap for `s` (an exact size is a 1:1 copy); an off-canonical `s`
/// is nearest-neighbour scaled from the nearest canonical bitmap. One `draw_iter` so the
/// glyph paints atomically. Pure and generic.
pub fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    g: Glyph,
    at: Point,
    s: u16,
    color: Rgb565,
) -> Result<(), D::Error> {
    let bm = pick(table(g), s);
    let src = bm.size as i32;
    let dst = (s as i32).max(1);
    let ax = at.x as i32;
    let ay = at.y as i32;
    // Centre-sampled nearest-neighbour: target row `ty` reads source row `(2*ty+1)*src /
    // (2*dst)`. At src == dst this is the identity (`(2*ty+1)/2 == ty`), i.e. an exact blit;
    // for a scale it samples the pixel centre, which keeps a symmetric source symmetric.
    t.draw_iter((0..dst).flat_map(move |ty| {
        let sy = (((2 * ty + 1) * src) / (2 * dst)).min(src - 1) as usize;
        let row = bm.rows[sy].as_bytes();
        (0..dst).filter_map(move |tx| {
            let sx = (((2 * tx + 1) * src) / (2 * dst)).min(src - 1) as usize;
            (row[sx] == b'#').then(|| Pixel(EgPoint::new(ax + tx, ay + ty), color))
        })
    }))
}

/// The bitmap tables, kept in their own file so the art stays hand-editable
/// without burying the engine.
#[path = "glyph_data.rs"]
mod data;
use data::*;

/// The hand-authored 1-bit bitmaps for `g`, one per canonical render size.
fn table(g: Glyph) -> &'static [Bitmap] {
    use Glyph::*;
    match g {
        Usb => GLYPH_USB,
        Check => GLYPH_CHECK,
        Backspace => GLYPH_BACKSPACE,
        CheckCircle => GLYPH_CHECKCIRCLE,
        Lock => GLYPH_LOCK,
        Key => GLYPH_KEY,
        Home => GLYPH_HOME,
        Gear => GLYPH_GEAR,
        Chevron => GLYPH_CHEVRON,
        Back => GLYPH_BACK,
        Shield => GLYPH_SHIELD,
        Globe => GLYPH_GLOBE,
        Warn => GLYPH_WARN,
        Sun => GLYPH_SUN,
        Clock => GLYPH_CLOCK,
        Moon => GLYPH_MOON,
        Rotate => GLYPH_ROTATE,
        Edit => GLYPH_EDIT,
        Eye => GLYPH_EYE,
        Lifebuoy => GLYPH_LIFEBUOY,
        Cpu => GLYPH_CPU,
        Apps => GLYPH_APPS,
        Terminal => GLYPH_TERMINAL,
        User => GLYPH_USER,
    }
}

#[cfg(test)]
#[path = "glyph_tests.rs"]
mod tests;
