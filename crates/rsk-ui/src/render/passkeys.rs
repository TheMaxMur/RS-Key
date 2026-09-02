// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Passkey screens: the RP list, service detail, rename, and the delete confirm.

use super::components;
use super::*;

/// The Passkeys tab: header, one row per relying party (generic globe + sanitized
/// rpId + account count + drill-in chevron), the list tail (pager when it spans more
/// than one page, else an "N items" footer), and the nav bar. `rows` is the current
/// page's slice; `page` is its 0-based index; `total` is the true RP count. A full-frame
/// paint, so it clears first. Standalone rather than a `Screen` variant — too large for
/// the `Copy` enum.
pub fn render_passkeys_list<D>(
    t: &mut D,
    rows: &[RpRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Passkeys", theme::ACCENT, false)?;
    passkeys_body(t, rows, page, total)?;
    render_nav(t, NavTab::Passkeys)
}

/// Replace a Passkeys page body while its typed screen identity, title, and active
/// navigation tab stay unchanged. The complete body is restored before composition.
pub fn render_passkeys_page<D>(
    t: &mut D,
    previous_rows: &[RpRow],
    previous_page: u16,
    previous_total: u16,
    rows: &[RpRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    if previous_rows == rows && previous_page == page && previous_total == total {
        return Ok(());
    }
    if !rows.is_empty() && previous_rows.len() == rows.len() {
        for (index, row) in rows.iter().enumerate() {
            if previous_rows[index] != *row {
                repaint_passkey_row(t, rows.len() as u16, index as u16, row)?;
            }
        }
        if previous_page != page || previous_total != total {
            clear_list_tail(t)?;
            list_tail(t, page, total, "item", "items")?;
        }
        return Ok(());
    }
    clear_region(t, PAGED_BODY_RECT)?;
    passkeys_body(t, rows, page, total)
}

fn passkeys_body<D>(t: &mut D, rows: &[RpRow], page: u16, total: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    if rows.is_empty() {
        glyph::draw(
            t,
            Glyph::Key,
            Point::new(MIDX as u16 - 18, 96),
            36,
            MUTED,
            BG,
        )?;
        text(
            t,
            "No passkeys yet",
            EgPoint::new(MIDX, 160),
            Role::Body,
            MUTED,
        )?;
    } else {
        components::list::group_card(t, PK_LIST_TOP, rows.len() as u16)?;
        for (i, r) in rows.iter().enumerate() {
            passkey_row(t, i as u16, r)?;
        }
        list_tail(t, page, total, "item", "items")?;
    }
    Ok(())
}

fn passkey_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    index: u16,
    row: &RpRow,
) -> Result<(), D::Error> {
    let mut buf = [0u8; 5];
    let trailing = if row.accounts > 1 {
        Some((fmt_u16(row.accounts as u16, &mut buf), MUTED))
    } else {
        None
    };
    let name = row.shown();
    // A source already clipped to LABEL_MAX must still show its marker here. This
    // owner-audit list must not present an attacker-padded rpId as complete.
    components::list::row(
        t,
        PK_LIST_TOP,
        index,
        service_glyph(name),
        name,
        trailing,
        true,
        true,
        row.nick.is_empty(),
        if row.nick.is_empty() {
            row.id.truncated
        } else {
            row.nick.truncated
        },
    )
}

fn repaint_passkey_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    count: u16,
    index: u16,
    row: &RpRow,
) -> Result<(), D::Error> {
    let bounds = crate::row_rect(PK_LIST_TOP, index);
    let mut clipped = t.clipped(&eg_rect(bounds));
    components::list::group_card(&mut clipped, PK_LIST_TOP, count)?;
    passkey_row(&mut clipped, index, row)
}

fn clear_list_tail<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    let y = crate::row_rect(PK_LIST_TOP, crate::PK_ROWS_MAX as u16).y;
    clear_region(t, Rect::new(0, y, PANEL_W, NAV_TOP - y))
}

/// The per-RP service detail: a back-chevron header + the (truncated) shown name (the
/// device-local nickname or the rpId), a pencil [edit affordance](TITLE_EDIT_RECT) at the
/// right of the title bar that opens the rename screen, one row per resident account (key
/// glyph + sanitized name + a "UV" tag when credProtect-gated), an "N accounts" footer,
/// and the nav bar. The firmware makes each row tappable to start the Confirm-Delete flow
/// ([`render_confirm_delete`]).
pub fn render_service<D>(
    t: &mut D,
    title: &Label,
    title_is_rp: bool,
    accounts: &[AccountRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    // The title is the attacker-chosen rpId unless the user set a device-local nickname; when
    // it is the rpId, head-ellipsize so the registrable-domain suffix stays visible (matches
    // the list row and the Confirm-Delete card).
    if title_is_rp {
        title_bar_domain(t, title, theme::ACCENT, true)?;
    } else {
        title_bar(t, title.as_str(), theme::ACCENT, true)?;
    }
    // Pencil icon: drawn right-aligned inside its hit rect, with a 4 px inset
    // from the right edge so the glyph doesn't touch the panel border.
    let er = TITLE_EDIT_RECT;
    glyph::draw(
        t,
        Glyph::Edit,
        Point::new(er.x + er.w - 18 - 4, er.y + er.h / 2 - 9),
        18,
        theme::ACCENT,
        BG,
    )?;
    service_body(t, accounts, page, total)?;
    render_nav(t, NavTab::Passkeys)
}

/// Replace only a service detail's paged account body. The caller must use this
/// only while the typed relying-party title and its edit/back chrome are unchanged.
pub fn render_service_page<D>(
    t: &mut D,
    previous_accounts: &[AccountRow],
    previous_page: u16,
    previous_total: u16,
    accounts: &[AccountRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    if previous_accounts == accounts && previous_page == page && previous_total == total {
        return Ok(());
    }
    if !accounts.is_empty() && previous_accounts.len() == accounts.len() {
        for (index, account) in accounts.iter().enumerate() {
            if previous_accounts[index] != *account {
                repaint_account_row(t, accounts.len() as u16, index as u16, account)?;
            }
        }
        if previous_page != page || previous_total != total {
            clear_list_tail(t)?;
            list_tail(t, page, total, "account", "accounts")?;
        }
        return Ok(());
    }
    clear_region(t, PAGED_BODY_RECT)?;
    service_body(t, accounts, page, total)
}

fn service_body<D>(
    t: &mut D,
    accounts: &[AccountRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    components::list::group_card(t, PK_LIST_TOP, accounts.len() as u16)?;
    for (i, a) in accounts.iter().enumerate() {
        account_row(t, i as u16, a)?;
    }
    list_tail(t, page, total, "account", "accounts")
}

fn account_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    index: u16,
    account: &AccountRow,
) -> Result<(), D::Error> {
    let trailing = if account.protected {
        Some(("UV", theme::ACCENT))
    } else {
        None
    };
    components::list::row(
        t,
        PK_LIST_TOP,
        index,
        Glyph::Key,
        account.name.as_str(),
        trailing,
        false,
        true,
        false,
        account.name.truncated,
    )
}

fn repaint_account_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    count: u16,
    index: u16,
    account: &AccountRow,
) -> Result<(), D::Error> {
    let bounds = crate::row_rect(PK_LIST_TOP, index);
    let mut clipped = t.clipped(&eg_rect(bounds));
    components::list::group_card(&mut clipped, PK_LIST_TOP, count)?;
    account_row(&mut clipped, index, account)
}

/// The rename screen: a T9 phone-style keypad for editing a device-local nickname.
/// Full-frame paint with clear — call once when entering the screen.
pub fn render_rename<D>(
    t: &mut D,
    value: &str,
    pending: Option<u8>,
    active_group: Option<usize>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    render_rename_chrome(t)?;
    render_rename_field(t, value, pending)?;
    render_rename_keys(t, active_group)
}

/// Status + title bar + caption (static chrome).
fn render_rename_chrome<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Rename", theme::ACCENT, true)?;
    text_left(
        t,
        "NICKNAME",
        EgPoint::new(14, RN_FIELD_RECT.y as i32 - 10),
        Role::Mono,
        theme::CAPTION,
    )
}

/// Repaint just the text field: committed `value` + optional `pending` char (underlined).
/// Clears the field area to BG first so shorter text erases longer prior text.
pub fn render_rename_field<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    value: &str,
    pending: Option<u8>,
) -> Result<(), D::Error> {
    // Clear the field area + a few px margin
    let clear = Rect::new(
        RN_FIELD_RECT.x.saturating_sub(4),
        RN_FIELD_RECT.y.saturating_sub(4),
        RN_FIELD_RECT.w + 8,
        RN_FIELD_RECT.h + 8,
    );
    Rectangle::new(
        EgPoint::new(clear.x as i32, clear.y as i32),
        Size::new(clear.w as u32, clear.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(t)?;

    let field = RN_FIELD_RECT;
    crate::aa::rounded_rect(
        t,
        field,
        8,
        Some(theme::SURFACE),
        Some((theme::BORDER_FIELD, 1)),
        BG,
    )?;
    let pad = 10i32;
    let inner = Rect::new(
        field.x + pad as u16,
        field.y,
        field.w - 2 * pad as u16,
        field.h,
    );
    let baseline = field.y as i32 + field.h as i32 / 2;
    text_left_clipped_on(
        t,
        value,
        EgPoint::new(inner.x as i32, baseline),
        Role::Body,
        FG,
        theme::SURFACE,
        inner,
    )?;
    let text_w = font::width(value, Role::Body).unwrap_or(0) as i32;
    let cursor_x = (inner.x as i32 + text_w).min(field.x as i32 + field.w as i32 - 12);

    if let Some(ch) = pending {
        let b = [ch];
        let ps = core::str::from_utf8(&b).unwrap_or("?");
        let pw = font::width(ps, Role::Body).unwrap_or(0) as i32;
        let px = cursor_x + 4;
        text_left_on(
            t,
            ps,
            EgPoint::new(px, baseline),
            Role::Body,
            theme::ACCENT,
            theme::SURFACE,
        )?;
        Line::new(
            EgPoint::new(px, baseline + 4),
            EgPoint::new(px + pw, baseline + 4),
        )
        .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 2))
        .draw(t)?;
    } else {
        Line::new(
            EgPoint::new(cursor_x, field.y as i32 + 7),
            EgPoint::new(cursor_x, field.y as i32 + field.h as i32 - 7),
        )
        .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 1))
        .draw(t)?;
    }
    Ok(())
}

/// Repaint just the T9 keypad (when `active_group` changes).
/// Paints every key — the keypad is 12 small rects, repainting all of them
/// is still much cheaper than a full-frame redraw.
pub fn render_rename_keys<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    active_group: Option<usize>,
) -> Result<(), D::Error> {
    for row in 0..4u16 {
        for col in 0..3u16 {
            let r = t9_key_rect(row, col);
            match (row, col) {
                (3, 0) => {
                    key_surface(t, r, theme::KEY_DARK, true)?;
                    glyph_centered(t, Glyph::Backspace, r, 20, MUTED, theme::KEY_DARK)?;
                }
                (3, 2) => {
                    crate::aa::rounded_rect(t, r, KEY_RADIUS, Some(ALLOW_FILL), None, BG)?;
                    text_on(t, "Save", center(r), Role::Strong, FG, ALLOW_FILL)?;
                }
                _ => {
                    let idx = if row < 3 { (row * 3 + col) as usize } else { 9 };
                    let is_active = active_group == Some(idx);
                    let fill = if is_active {
                        theme::ACCENT_FILL
                    } else {
                        KEY_FILL
                    };
                    key_surface(t, r, fill, !is_active)?;
                    let color = if is_active { FG } else { theme::TEXT };
                    let (digit, letters) = T9_KEY_LABELS[idx];
                    let cx = r.x as i32 + r.w as i32 / 2;
                    text_on(
                        t,
                        digit,
                        EgPoint::new(cx, r.y as i32 + 14),
                        Role::Strong,
                        color,
                        fill,
                    )?;
                    text_on(
                        t,
                        letters,
                        EgPoint::new(cx, r.y as i32 + 32),
                        Role::MonoSmall,
                        color,
                        fill,
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// The trusted Confirm-Delete screen for a resident passkey: the back (cancel)
/// chevron and a "Delete passkey" header in the decline colour, a card naming the
/// relying party and account about to be removed, a plain-language warning, and the
/// full-width **Hold to delete** button. The hold button starts empty; the firmware
/// grows it via [`render_hold_fill`] as the user holds. Standalone full-frame (like
/// [`render_service`]) — the labels are too large for the `Copy` `Screen` enum.
pub fn render_confirm_delete<D>(t: &mut D, rp: &Label, account: &Label) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::DENY)?;
    text_left(
        t,
        "Delete passkey",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::DENY,
    )?;
    // Card naming exactly what is about to be removed: relying party + account.
    let card = Rect::new(14, 54, PANEL_W - 28, 46);
    crate::aa::rounded_rect(t, card, 8, Some(theme::ROW_BG), None, BG)?;
    glyph::draw(
        t,
        Glyph::Globe,
        Point::new(card.x + 10, card.y + 13),
        20,
        theme::MUTED,
        theme::ROW_BG,
    )?;
    let tx = card.x as i32 + 40;
    // Clip + ellipsize the untrusted rp/account to the card, marking any truncation —
    // an anti-phishing screen must never show a silently-cut look-alike identity
    // (matches the getAssertion-approve and add-passkey ceremonies).
    let clip = Rect::new(tx as u16, card.y, (card.x + card.w) - tx as u16, card.h);
    // The rp is attacker-chosen: head-ellipsize (leading "…") so the registrable-domain
    // suffix stays on screen and a padded look-alike can't hide the real domain behind
    // the cut on the very screen meant to expose it (matches the getAssertion ceremony).
    text_right_ellipsized_on(
        t,
        rp.as_str(),
        EgPoint::new(tx, card.y as i32 + 16),
        Role::Body,
        theme::TEXT,
        theme::ROW_BG,
        clip,
        rp.truncated,
    )?;
    text_left_ellipsized_on(
        t,
        account.as_str(),
        EgPoint::new(tx, card.y as i32 + 32),
        Role::Body,
        theme::MUTED,
        theme::ROW_BG,
        clip,
        account.truncated,
    )?;
    // Plain-language warning — including the honest caveat that the site is not told.
    text_left(
        t,
        "This removes the passkey",
        EgPoint::new(16, 124),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "from RS-Key. The site may",
        EgPoint::new(16, 142),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "still expect it.",
        EgPoint::new(16, 160),
        Role::Body,
        theme::WARN,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to delete", theme::DANGER_FILL)
}
