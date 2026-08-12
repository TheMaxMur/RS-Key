// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The read-only audit-log screen.

use super::components;
use super::*;

/// The read-only on-device audit log (Settings → Security → Audit log): the most recent
/// journal events, newest first — a status dot coloured by [`AuditKind`], the event
/// label, and a compact "time ago" for current-power-cycle entries. The back chevron
/// returns to Security. Standalone full-frame like [`render_passkeys_list`] but without
/// the nav bar (a settings sub-screen, not a tab). `rows` is the current page's slice,
/// `page` its 0-based index, `total` the live journal depth — so the tail shows the pager
/// ("page / pages") when the log spans more than one page, else a true "N events" count.
/// `logging` is the journal's own enabled flag: journalling is opt-in, so an empty page
/// means something different when nothing was ever being recorded.
pub fn render_audit_log<D>(
    t: &mut D,
    rows: &[AuditRow],
    page: u16,
    total: u16,
    logging: bool,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Audit log", theme::ACCENT, true)?;
    if rows.is_empty() {
        // "No activity yet" is a claim about the world, and journalling is off by
        // default — so only make it when the device was actually watching. An owner
        // checking for evidence must not read "none was found" as "none exists".
        let (icon, color, headline) = if logging {
            (Glyph::Clock, MUTED, "No activity yet")
        } else {
            (Glyph::Warn, theme::WARN, "Logging is off")
        };
        glyph::draw(t, icon, Point::new(MIDX as u16 - 18, 96), 36, color)?;
        text(t, headline, EgPoint::new(MIDX, 160), Role::Body, color)?;
        if !logging {
            text(
                t,
                "Nothing is being recorded",
                EgPoint::new(MIDX, 184),
                Role::MonoSmall,
                theme::CAPTION,
            )?;
        }
    } else {
        components::list::group_card(t, PK_LIST_TOP, rows.len() as u16)?;
        for (i, r) in rows.iter().enumerate() {
            audit_body(t, crate::row_rect(PK_LIST_TOP, i as u16), r)?;
        }
        list_tail(t, page, total, "event", "events")?;
    }
    Ok(())
}

/// One audit row: a status dot (its colour the at-a-glance signal), the event label, and
/// a right-aligned "time ago". Mirrors `components::list::row`'s card + clip metrics,
/// but leads with a coloured dot instead of a muted glyph.
fn audit_body<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    r: &AuditRow,
) -> Result<(), D::Error> {
    let cy = rect.y as i32 + rect.h as i32 / 2;
    let dot: u32 = 8;
    Circle::new(EgPoint::new(rect.x as i32 + 10, cy - dot as i32 / 2), dot)
        .into_styled(PrimitiveStyle::with_fill(audit_dot(r.kind)))
        .draw(t)?;
    // Trailing time first (right), then the label clipped to end before it.
    let right_x = rect.x as i32 + rect.w as i32 - 8;
    let label_x = rect.x as i32 + 30;
    let label_right = if let Some(secs) = r.secs_ago {
        let mut buf = [0u8; 8];
        let s = fmt_ago(secs, &mut buf);
        text_right(t, s, EgPoint::new(right_x, cy), Role::Mono, theme::CAPTION)?;
        right_x - font::width(s, Role::Mono).unwrap_or(0) as i32 - ROW_TRAILING_GAP
    } else {
        right_x - ROW_TRAILING_GAP
    };
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_ellipsized(
        t,
        r.kind.label(),
        EgPoint::new(label_x, cy),
        Role::Body,
        FG,
        clip,
        false,
    )
}

/// The status-dot colour for an audit event class (green = sign-in, blue = add/backup,
/// red = lockout/reset, grey = everything else).
fn audit_dot(kind: AuditKind) -> Rgb565 {
    match kind {
        AuditKind::Login => theme::SUCCESS,
        AuditKind::Register | AuditKind::Backup => theme::ACCENT,
        AuditKind::Denied | AuditKind::Reset => theme::DANGER,
        _ => theme::GREY,
    }
}
