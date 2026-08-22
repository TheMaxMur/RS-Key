// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Backup screens: status, format chooser, share picker, and the seed reveal flow.

use super::*;

/// The read-only **Backup** screen (Settings → Security → Backup). It paints the seed-
/// backup status the device genuinely tracks — *not* the static mockup's fictional "N of M
/// recovery shares": backup here is a one-time seed export over the USB host channel, then
/// sealed. A colour-coded status plate (review needed / backed up / no seed / restore-only)
/// sits over two fact rows (recovery seed present, export window sealed) and a muted hint
/// that the host app drives the backup — there is no on-device action. The title-bar back
/// chevron exits.
pub fn render_backup<D>(t: &mut D, v: &BackupView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Backup", theme::ACCENT, true)?;

    // The status plate + hint. State only what the device actually knows — the export
    // *window* state — never "a backup exists": the device cannot verify an export ever
    // happened (`sealed` is set by `BACKUP_FINALIZE`, which merely closes the window), so the
    // trusted headline must not vouch for a recovery copy it can't see. The fact rows below
    // restate the same window state.
    let (icon, l1, l2, fill, border, fg, h1, h2) = if !v.has_seed {
        (
            Glyph::Warn,
            "No recovery seed",
            "Nothing to back up yet.",
            theme::DANGER_BG,
            theme::DANGER_BORDER,
            theme::DANGER,
            "Set up the device first.",
            "",
        )
    } else if !v.exportable {
        (
            Glyph::Lock,
            "Restore-only",
            "Seed export disabled.",
            theme::TINT_BLUE,
            theme::BORDER_UPDATE,
            theme::ACCENT_TEXT,
            "Recovery is restore-only",
            "on this device.",
        )
    } else if v.sealed {
        (
            Glyph::Lock,
            "Export sealed",
            "Seed export is closed.",
            theme::TINT_BLUE,
            theme::BORDER_UPDATE,
            theme::ACCENT_TEXT,
            "Reset the device to",
            "export again.",
        )
    } else {
        (
            Glyph::Warn,
            "Review needed",
            "Seed export still open.",
            theme::WARN_BG,
            theme::WARN_BORDER,
            theme::WARN,
            "Back up the seed using",
            "the RS-Key app over USB.",
        )
    };
    let plate = Rect::new(14, CONTENT_TOP + 8, PANEL_W - 28, 54);
    crate::aa::rounded_rect(t, plate, 11, Some(fill), Some((border, 1)), BG)?;
    glyph::draw(
        t,
        icon,
        Point::new(plate.x + 12, plate.y + 18),
        18,
        fg,
        fill,
    )?;
    let tx = plate.x as i32 + 42;
    // Clip the two lines to the plate interior so a wider face never overruns the panel.
    let clip = Rect::new(
        tx as u16,
        plate.y,
        (plate.x + plate.w).saturating_sub(6 + tx as u16),
        plate.h,
    );
    text_left_clipped_on(
        t,
        l1,
        EgPoint::new(tx, plate.y as i32 + 20),
        Role::Strong,
        fg,
        fill,
        clip,
    )?;
    text_left_clipped_on(
        t,
        l2,
        EgPoint::new(tx, plate.y as i32 + 38),
        Role::Body,
        MUTED,
        fill,
        clip,
    )?;

    // The honest facts, as a small group below the plate.
    text_left(
        t,
        "RECOVERY SHARES",
        EgPoint::new(14, plate.y as i32 + plate.h as i32 + 14),
        Role::Mono,
        theme::CAPTION,
    )?;
    let row0 = Rect::new(16, 138, PANEL_W - 32, 34);
    let row1 = Rect::new(16, 176, PANEL_W - 32, 34);
    // One grouped card behind both fact rows, with a divider in the gap between them.
    group_panel(
        t,
        Rect::new(row0.x, row0.y, row0.w, row1.y + row1.h - row0.y),
    )?;
    group_divider(t, row0.x, row0.w, (row0.y + row0.h + row1.y) as i32 / 2)?;
    let seed = if v.has_seed {
        ("Present", theme::OK)
    } else {
        ("Missing", theme::DANGER)
    };
    row_body(t, row0, Glyph::Lifebuoy, "Seed", Some(seed), false, false)?;
    let window = if v.sealed {
        ("Sealed", theme::OK)
    } else if v.exportable {
        ("Open", theme::WARN)
    } else {
        ("Disabled", MUTED)
    };
    row_body(
        t,
        row1,
        Glyph::Lock,
        "Backup window",
        Some(window),
        false,
        false,
    )?;

    if v.can_reveal {
        // Window open + seed readable: the on-device actions. The phrase is shown ON the
        // device (it never crosses USB); sealing closes the window when the user is done.
        button(
            t,
            BACKUP_REVEAL_RECT,
            "Show recovery phrase",
            theme::ACCENT_FILL,
        )?;
        button(t, BACKUP_SEAL_RECT, "Seal backup", theme::KEY_BG)
    } else {
        // No on-device action available — a per-state hint points at the next step. A blank
        // `h2` draws nothing (the `!has_seed` state has a single line).
        text(t, h1, EgPoint::new(MIDX, 270), Role::Body, MUTED)?;
        text(t, h2, EgPoint::new(MIDX, 288), Role::Body, MUTED)
    }
}

/// The **recovery-format chooser** (after the device-PIN re-auth, before any secret is
/// shown): two cards — a single BIP-39 phrase, or SLIP-39 Shamir shares. Chrome-less like
/// the reveal gate; the firmware maps a tap with [`crate::hit_backup_format`] and the
/// top-left [`crate::PK_BACK_RECT`] chevron cancels. Each card is a title over a dim format
/// sublabel.
pub fn render_backup_format<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Choose format",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    choice_card(t, FMT_PHRASE_RECT, "Single phrase", "24 words (BIP-39)")?;
    choice_card(
        t,
        FMT_SHARES_RECT,
        "Shamir shares",
        "Split T-of-N (SLIP-39)",
    )
}

/// A two-line choice card: a bright title over a dim sublabel, on a bordered key surface —
/// the format-chooser's tappable options.
fn choice_card<D>(t: &mut D, r: Rect, title: &str, sub: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    key_surface(t, r, KEY_FILL, true)?;
    text_left_on(
        t,
        title,
        EgPoint::new(r.x as i32 + 14, r.y as i32 + 22),
        Role::Strong,
        FG,
        KEY_FILL,
    )?;
    text_left_on(
        t,
        sub,
        EgPoint::new(r.x as i32 + 14, r.y as i32 + 44),
        Role::Body,
        MUTED,
        KEY_FILL,
    )
}

/// The SLIP-39 **share picker**: two −/+ steppers (recovery threshold `T`, total shares `N`)
/// and a Continue button, summarising "Any T of N shares". Chrome-less like the chooser; the
/// firmware maps taps with [`crate::hit_share_picker`], steps the pair with
/// [`crate::step_share_params`], and the top-left [`crate::PK_BACK_RECT`] chevron returns to
/// the chooser.
pub fn render_share_picker<D>(t: &mut D, threshold: u8, total: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Shamir shares",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    stepper_row(
        t,
        "Needed to recover",
        PICK_T_MINUS_RECT,
        PICK_T_PLUS_RECT,
        threshold,
    )?;
    stepper_row(
        t,
        "Total shares",
        PICK_N_MINUS_RECT,
        PICK_N_PLUS_RECT,
        total,
    )?;
    // "Any T of N shares reconstruct the seed." — split across two lines.
    let mut b1 = [0u8; 5];
    let mut b2 = [0u8; 5];
    let mut line = [0u8; 24];
    let mut i = 0;
    for &c in b"Any " {
        line[i] = c;
        i += 1;
    }
    for &c in fmt_u16(threshold as u16, &mut b1).as_bytes() {
        line[i] = c;
        i += 1;
    }
    for &c in b" of " {
        line[i] = c;
        i += 1;
    }
    for &c in fmt_u16(total as u16, &mut b2).as_bytes() {
        line[i] = c;
        i += 1;
    }
    for &c in b" shares" {
        line[i] = c;
        i += 1;
    }
    text(
        t,
        str8(&line[..i]),
        EgPoint::new(MIDX, 228),
        Role::Body,
        theme::ACCENT_TEXT,
    )?;
    button(t, PICK_CONTINUE_RECT, "Continue", theme::ACCENT_FILL)
}

/// One picker stepper: a caption above a `[−]  value  [+]` row, the value centred between the
/// two key surfaces. Used for both the threshold and total rows.
fn stepper_row<D>(
    t: &mut D,
    caption: &str,
    minus: Rect,
    plus: Rect,
    value: u8,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    text_left(
        t,
        caption,
        EgPoint::new(16, minus.y as i32 - 14),
        Role::Body,
        MUTED,
    )?;
    key_surface(t, minus, KEY_FILL, true)?;
    text_on(t, "-", center(minus), Role::Strong, FG, KEY_FILL)?;
    key_surface(t, plus, KEY_FILL, true)?;
    text_on(t, "+", center(plus), Role::Strong, FG, KEY_FILL)?;
    let mut b = [0u8; 5];
    text(
        t,
        fmt_u16(value as u16, &mut b),
        EgPoint::new(MIDX, minus.y as i32 + minus.h as i32 / 2),
        Role::Ready,
        FG,
    )
}

/// The deliberate **reveal gate** before showing the recovery phrase: a warning that the
/// next screen prints the master secret, over a [hold button](render_hold_button) the
/// firmware drives with [`crate::DEL_HOLD_RECT`] / [`crate::PK_BACK_RECT`] (cancel). The
/// device PIN is checked *before* this screen; the hold is the second, deliberate gesture.
pub fn render_reveal_warning<D>(t: &mut D, kind: RevealKind) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (heading, line1) = match kind {
        RevealKind::Phrase => ("Reveal phrase", "Showing 24 secret words"),
        RevealKind::Shares => ("Reveal shares", "Showing secret shares"),
    };
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        heading,
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(PANEL_W / 2 - 16, 56),
        32,
        theme::WARN,
        BG,
    )?;
    text_left(t, line1, EgPoint::new(16, 118), Role::Body, theme::WARN)?;
    text_left(
        t,
        "that restore everything.",
        EgPoint::new(16, 136),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "Make sure no person or",
        EgPoint::new(16, 160),
        Role::Body,
        MUTED,
    )?;
    text_left(
        t,
        "camera can see the screen.",
        EgPoint::new(16, 178),
        Role::Body,
        MUTED,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to reveal", theme::DANGER_FILL)
}

/// The **seal confirmation**: closing the backup window is one-way (until a factory reset),
/// so it takes a deliberate hold. Same chrome-less layout / hold mechanics as the reveal
/// gate; the firmware drives [`crate::DEL_HOLD_RECT`] / [`crate::PK_BACK_RECT`].
pub fn render_seal_confirm<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Seal backup",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new(PANEL_W / 2 - 16, 56),
        32,
        theme::WARN,
        BG,
    )?;
    text_left(
        t,
        "Closes the backup window.",
        EgPoint::new(16, 118),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "You can't show or export the",
        EgPoint::new(16, 142),
        Role::Body,
        MUTED,
    )?;
    text_left(
        t,
        "phrase again until a reset.",
        EgPoint::new(16, 160),
        Role::Body,
        MUTED,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to seal", theme::DANGER_FILL)
}

/// The **recovery phrase** itself: the 24 BIP-39 words rendered on the trusted display so
/// the seed never crosses USB. Twelve words per page in two numbered columns; the
/// pager (`render_pager`) walks the pages, the title-bar back chevron exits. `words` is the
/// full ordered list (held transiently by the firmware, never stored), `page` the 0-based
/// page. The words are drawn bright with a dim index so a transcription error is unlikely.
pub fn render_seed_phrase<D>(
    t: &mut D,
    words: &[&str],
    page: u16,
    pages: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "Seed phrase", theme::ACCENT, true)?;
    word_grid(t, words, page)?;
    render_pager(t, page, pages)
}

/// Words per page of the word grid — the paging contract shared with the firmware's
/// backup pager (its page counts derive from this).
pub const SEED_WORDS_PER_PAGE: usize = 12;

/// Paint up to twelve numbered words of `words` for `page` (0-based, 12 per page) in two
/// columns of six — the shared body of the recovery-phrase and SLIP-39 share screens. The
/// 1-based word number (within `words`, so per-phrase or per-share) is dimmed to the left of
/// each bright word so a transcription error is unlikely.
fn word_grid<D>(t: &mut D, words: &[&str], page: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let per_page = SEED_WORDS_PER_PAGE;
    let start = page as usize * per_page;
    for c in 0..per_page {
        let gi = start + c;
        if gi >= words.len() {
            break;
        }
        let col = c / 6;
        let row = c % 6;
        let base_x = if col == 0 { 16 } else { 126 };
        let cy = 76 + row as i32 * 27;
        // "N." — the 1-based word number, right-aligned just left of the word and dimmed.
        let n = (gi + 1) as u8;
        let mut nb = [0u8; 4];
        let mut k = 0;
        if n >= 10 {
            nb[k] = b'0' + n / 10;
            k += 1;
        }
        nb[k] = b'0' + n % 10;
        k += 1;
        nb[k] = b'.';
        k += 1;
        let ns = core::str::from_utf8(&nb[..k]).unwrap_or(".");
        text_right(
            t,
            ns,
            EgPoint::new(base_x + 22, cy),
            Role::Mono,
            theme::CAPTION,
        )?;
        text_left(
            t,
            words[gi],
            EgPoint::new(base_x + 27, cy),
            Role::BodyStrong,
            FG,
        )?;
    }
    Ok(())
}

/// One page of a SLIP-39 **share**: `words` (the current share's full word list), under a
/// "Share i/N" title so the user knows which share to label. `page`/`pages` are the **global**
/// position across all shares (so the pager arrows dim correctly at the first/last page); the
/// share's own sub-page (which 12 words to show) is derived from `page` modulo the share's
/// page count. The words are secret (any threshold of shares reconstruct the seed) — the
/// firmware holds them transiently and zeroizes on exit.
pub fn render_slip39_share<D>(
    t: &mut D,
    words: &[&str],
    share_idx: u16,
    share_total: u16,
    page: u16,
    pages: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    let mut buf = [0u8; 18];
    title_bar(
        t,
        fmt_share_title(share_idx, share_total, &mut buf),
        theme::ACCENT,
        true,
    )?;
    let per_share = (words.len() as u16)
        .div_ceil(SEED_WORDS_PER_PAGE as u16)
        .max(1);
    word_grid(t, words, page % per_share)?;
    render_pager(t, page, pages)
}

/// Format `"Share P/N"` into `buf`, no alloc. Sized for the full u16 domain: `"Share " (6)
/// + 5 + "/" + 5 = 17` bytes.
fn fmt_share_title(p: u16, n: u16, buf: &mut [u8; 18]) -> &str {
    let mut i = 0;
    for &c in b"Share " {
        buf[i] = c;
        i += 1;
    }
    let mut a = [0u8; 5];
    for &c in fmt_u16(p, &mut a).as_bytes() {
        buf[i] = c;
        i += 1;
    }
    buf[i] = b'/';
    i += 1;
    let mut b = [0u8; 5];
    for &c in fmt_u16(n, &mut b).as_bytes() {
        buf[i] = c;
        i += 1;
    }
    str8(&buf[..i])
}
