// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Icons drawn from hand-authored bitmaps with fixed-point coverage smoothing.
//! Each glyph has art at the canonical sizes that the UI uses. A request for a
//! different size selects the closest source and uses bilinear fixed-point
//! sampling. Fixed UI sizes use compile-time coverage streams; uncommon sizes
//! keep the same fixed-point sampler as a fallback.
//!
//! The source bitmaps live as `&[&str]` rows (`'#'` = ink) so they are readable
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
    draw_target::DrawTarget,
    geometry::{Point as EgPoint, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};

use crate::{Point, aa::blend_coverage};

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
const fn pick(tbl: &'static [Bitmap], s: u16) -> &'static Bitmap {
    let mut best = &tbl[0];
    let mut best_d = i32::MAX;
    let mut index = 0;
    while index < tbl.len() {
        let b = &tbl[index];
        let d = (b.size as i32 - s as i32).abs();
        if d < best_d || (d == best_d && b.size > best.size) {
            best_d = d;
            best = b;
        }
        index += 1;
    }
    best
}

const fn source_ink(bitmap: &Bitmap, x: i32, y: i32) -> u16 {
    if x < 0 || y < 0 || x >= bitmap.size as i32 || y >= bitmap.size as i32 {
        return 0;
    }
    if bitmap.rows[y as usize].as_bytes()[x as usize] == b'#' {
        1
    } else {
        0
    }
}

const fn source_coverage(bitmap: &Bitmap, x: i32, y: i32) -> u16 {
    let weight = source_ink(bitmap, x, y) * 12
        + source_ink(bitmap, x - 1, y)
        + source_ink(bitmap, x + 1, y)
        + source_ink(bitmap, x, y - 1)
        + source_ink(bitmap, x, y + 1);
    (weight * 15 + 8) / 16
}

const fn div_euclid_256(value: i32) -> i32 {
    if value >= 0 {
        value / 256
    } else {
        (value - 255) / 256
    }
}

const fn scaled_coverage(bitmap: &Bitmap, x: i32, y: i32, size: i32) -> u8 {
    let source = bitmap.size as i32;
    let fx = (2 * x + 1) * source * 128 / size - 128;
    let fy = (2 * y + 1) * source * 128 / size - 128;
    let x0 = div_euclid_256(fx);
    let y0 = div_euclid_256(fy);
    let dx = (fx - x0 * 256) as u32;
    let dy = (fy - y0 * 256) as u32;
    let top = source_coverage(bitmap, x0, y0) as u32 * (256 - dx)
        + source_coverage(bitmap, x0 + 1, y0) as u32 * dx;
    let bottom = source_coverage(bitmap, x0, y0 + 1) as u32 * (256 - dx)
        + source_coverage(bitmap, x0 + 1, y0 + 1) as u32 * dx;
    ((top * (256 - dy) + bottom * dy + 32_768) / 65_536) as u8
}

// These are all fixed sizes painted by the UI, including the four success-pop
// frames. One byte stores a coverage and a run of up to 16 pixels.
const FIXED_SIZES: [u16; 16] = [
    12, 13, 14, 16, 18, 20, 22, 24, 28, 29, 32, 34, 36, 38, 40, 44,
];
const FIXED_GLYPHS: [u32; FIXED_SIZES.len()] = [
    0x000100, 0x010002, 0xffffff, 0xffffff, 0xffffff, 0x000804, 0xffffff, 0x000006, 0xffffff,
    0x010002, 0x001011, 0x011012, 0xffffff, 0x000808, 0x000400, 0xffffff,
];
const GLYPH_COUNT: usize = 24;
const FIXED_MASK_COUNT: usize = GLYPH_COUNT * FIXED_SIZES.len();
const FIXED_MASK_BYTES: usize = 37_857;
const SOURCE_SIZE_OFFSETS: [usize; 7] = [0, 98, 226, 388, 588, 1236, 2204];
const SOURCE_BYTES_PER_GLYPH: usize = 2204;
const SOURCE_MASK_BYTES: usize = GLYPH_COUNT * SOURCE_BYTES_PER_GLYPH;

const fn source_masks() -> [u8; SOURCE_MASK_BYTES] {
    let mut masks = [0u8; SOURCE_MASK_BYTES];
    let mut glyph = 0;
    while glyph < GLYPH_COUNT {
        let mut bitmap_index = 0;
        while bitmap_index < GLYPH_TABLES[glyph].len() {
            let bitmap = &GLYPH_TABLES[glyph][bitmap_index];
            let mut pixel = 0;
            while pixel < bitmap.size as usize * bitmap.size as usize {
                let coverage = source_coverage(
                    bitmap,
                    (pixel % bitmap.size as usize) as i32,
                    (pixel / bitmap.size as usize) as i32,
                ) as u8;
                let byte =
                    glyph * SOURCE_BYTES_PER_GLYPH + SOURCE_SIZE_OFFSETS[bitmap_index] + pixel / 2;
                masks[byte] |= coverage << ((pixel & 1) * 4);
                pixel += 1;
            }
            bitmap_index += 1;
        }
        glyph += 1;
    }
    masks
}

// This table is used only to generate the smaller RLE table. A static would keep
// both tables in the firmware image.
#[allow(clippy::large_const_arrays)]
const SOURCE_MASKS: [u8; SOURCE_MASK_BYTES] = source_masks();

const fn pick_index(table: &[Bitmap], size: u16) -> usize {
    let mut best = 0;
    let mut best_distance = i32::MAX;
    let mut index = 0;
    while index < table.len() {
        let distance = (table[index].size as i32 - size as i32).abs();
        if distance < best_distance
            || (distance == best_distance && table[index].size > table[best].size)
        {
            best = index;
            best_distance = distance;
        }
        index += 1;
    }
    best
}

const fn masked_source_coverage(glyph: usize, bitmap: usize, x: i32, y: i32) -> u16 {
    let size = GLYPH_TABLES[glyph][bitmap].size as i32;
    if x < 0 || y < 0 || x >= size || y >= size {
        return 0;
    }
    let pixel = y as usize * size as usize + x as usize;
    let byte =
        SOURCE_MASKS[glyph * SOURCE_BYTES_PER_GLYPH + SOURCE_SIZE_OFFSETS[bitmap] + pixel / 2];
    ((byte >> ((pixel & 1) * 4)) & 0x0f) as u16
}

const fn scaled_masked_coverage(glyph: usize, bitmap: usize, x: i32, y: i32, size: i32) -> u8 {
    let source = GLYPH_TABLES[glyph][bitmap].size as i32;
    let fx = (2 * x + 1) * source * 128 / size - 128;
    let fy = (2 * y + 1) * source * 128 / size - 128;
    let x0 = div_euclid_256(fx);
    let y0 = div_euclid_256(fy);
    let dx = (fx - x0 * 256) as u32;
    let dy = (fy - y0 * 256) as u32;
    let top = masked_source_coverage(glyph, bitmap, x0, y0) as u32 * (256 - dx)
        + masked_source_coverage(glyph, bitmap, x0 + 1, y0) as u32 * dx;
    let bottom = masked_source_coverage(glyph, bitmap, x0, y0 + 1) as u32 * (256 - dx)
        + masked_source_coverage(glyph, bitmap, x0 + 1, y0 + 1) as u32 * dx;
    ((top * (256 - dy) + bottom * dy + 32_768) / 65_536) as u8
}

struct FixedMasks {
    bytes: [u8; FIXED_MASK_BYTES],
    offsets: [u32; FIXED_MASK_COUNT + 1],
}

const fn fixed_masks() -> FixedMasks {
    let mut masks = FixedMasks {
        bytes: [0; FIXED_MASK_BYTES],
        offsets: [0; FIXED_MASK_COUNT + 1],
    };
    let mut write = 0;
    let mut glyph = 0;
    while glyph < GLYPH_COUNT {
        let mut fixed_size = 0;
        while fixed_size < FIXED_SIZES.len() {
            let mask_index = glyph * FIXED_SIZES.len() + fixed_size;
            masks.offsets[mask_index] = write as u32;
            if FIXED_GLYPHS[fixed_size] & (1 << glyph) == 0 {
                fixed_size += 1;
                continue;
            }
            let size = FIXED_SIZES[fixed_size];
            let bitmap = pick_index(GLYPH_TABLES[glyph], size);
            let mut position = 0;
            let mut coverage = 0;
            let mut run = 0;
            while position < size as usize * size as usize {
                let next = scaled_masked_coverage(
                    glyph,
                    bitmap,
                    (position % size as usize) as i32,
                    (position / size as usize) as i32,
                    size as i32,
                );
                if run != 0 && (next != coverage || run == 16) {
                    assert!(write < FIXED_MASK_BYTES);
                    masks.bytes[write] = coverage << 4 | (run - 1);
                    write += 1;
                    run = 0;
                }
                coverage = next;
                run += 1;
                position += 1;
            }
            if run != 0 {
                assert!(write < FIXED_MASK_BYTES);
                masks.bytes[write] = coverage << 4 | (run - 1);
                write += 1;
            }
            fixed_size += 1;
        }
        glyph += 1;
    }
    masks.offsets[FIXED_MASK_COUNT] = write as u32;
    assert!(write == FIXED_MASK_BYTES);
    masks
}

static FIXED_MASKS: FixedMasks = fixed_masks();

struct FixedCoverage {
    offset: usize,
    end: usize,
    coverage: u8,
    left: u8,
}

impl Iterator for FixedCoverage {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            if self.offset == self.end {
                return None;
            }
            let token = FIXED_MASKS.bytes[self.offset];
            self.offset += 1;
            self.coverage = token >> 4;
            self.left = (token & 0x0f) + 1;
        }
        self.left -= 1;
        Some(self.coverage)
    }
}

fn glyph_index(glyph: Glyph) -> usize {
    glyph as usize
}

fn fixed_size_index(size: u16) -> Option<usize> {
    FIXED_SIZES.iter().position(|candidate| *candidate == size)
}

fn fixed_coverage(glyph: Glyph, size: u16) -> Option<FixedCoverage> {
    let glyph = glyph_index(glyph);
    let fixed_size = fixed_size_index(size)?;
    if FIXED_GLYPHS[fixed_size] & (1 << glyph) == 0 {
        return None;
    }
    let index = glyph * FIXED_SIZES.len() + fixed_size;
    Some(FixedCoverage {
        offset: FIXED_MASKS.offsets[index] as usize,
        end: FIXED_MASKS.offsets[index + 1] as usize,
        coverage: 0,
        left: 0,
    })
}

/// Draw `g` into a square and blend its coverage against `bg`.
pub fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    g: Glyph,
    at: Point,
    s: u16,
    color: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    let bm = pick(table(g), s);
    let mut colors = [Rgb565::new(0, 0, 0); 16];
    for (coverage, blended) in colors.iter_mut().enumerate() {
        *blended = blend_coverage(color, bg, coverage as u8);
    }
    let dst = (s as i32).max(1);
    let ax = at.x as i32;
    let ay = at.y as i32;
    let area = Rectangle::new(EgPoint::new(ax, ay), Size::new(u32::from(s), u32::from(s)));
    if let Some(coverage) = fixed_coverage(g, s) {
        t.fill_contiguous(
            &area,
            coverage.map(move |coverage| colors[usize::from(coverage)]),
        )
    } else {
        t.fill_contiguous(
            &area,
            (0..dst).flat_map(move |ty| {
                (0..dst).map(move |tx| {
                    let coverage = scaled_coverage(bm, tx, ty, dst);
                    colors[usize::from(coverage)]
                })
            }),
        )
    }
}

/// The bitmap tables, kept in their own file so the art stays hand-editable
/// without burying the engine.
#[path = "glyph_data.rs"]
mod data;
use data::*;

const GLYPH_TABLES: [&[Bitmap]; GLYPH_COUNT] = [
    GLYPH_USB,
    GLYPH_CHECK,
    GLYPH_BACKSPACE,
    GLYPH_CHECKCIRCLE,
    GLYPH_LOCK,
    GLYPH_KEY,
    GLYPH_HOME,
    GLYPH_GEAR,
    GLYPH_CHEVRON,
    GLYPH_BACK,
    GLYPH_SHIELD,
    GLYPH_GLOBE,
    GLYPH_WARN,
    GLYPH_SUN,
    GLYPH_CLOCK,
    GLYPH_MOON,
    GLYPH_ROTATE,
    GLYPH_EDIT,
    GLYPH_EYE,
    GLYPH_LIFEBUOY,
    GLYPH_CPU,
    GLYPH_APPS,
    GLYPH_TERMINAL,
    GLYPH_USER,
];

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
