// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Painting a [`Screen`] onto an ST7789-class panel. Pure and generic over
//! `embedded_graphics::DrawTarget<Color = Rgb565>`, so the security-relevant
//! layout — above all that the word "Allow" is painted inside [`ALLOW_RECT`], the
//! exact region [`crate::hit_confirm`] approves — is decided here and unit-tested
//! on the host against a recording target, with the firmware's `display.rs` only
//! supplying the real panel. There is no retained framebuffer (240×320×2 would not
//! fit the heap): [`render`] paints the whole frame and the caller repaints on a
//! state change.

use embedded_graphics::{
    Drawable,
    draw_target::{DrawTarget, DrawTargetExt},
    geometry::{Angle, Point as EgPoint, Size},
    pixelcolor::Rgb565,
    primitives::{
        Arc, Circle, Line, Primitive, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle,
        RoundedRectangle, StrokeAlignment,
    },
};

use crate::{
    ADJ_MINUS_RECT, ADJ_PLUS_RECT, ALLOW_RECT, AccountRow, AuditKind, AuditRow, BACKUP_REVEAL_RECT,
    BACKUP_SEAL_RECT, BRIGHTNESS_LEVELS, BackupView, CONTENT_TOP, ConfirmPrompt, DEL_HOLD_RECT,
    DENY_RECT, FMT_PHRASE_RECT, FMT_SHARES_RECT, Glyph, HomeView, Label, NAV_H, NAV_TABS, NAV_TOP,
    NavTab, ONBOARD_SET_RECT, ONBOARD_SKIP_RECT, OPENPGP_ROWS, PAGER_NEXT_RECT, PAGER_PREV_RECT,
    PANEL_H, PANEL_W, PICK_CONTINUE_RECT, PICK_N_MINUS_RECT, PICK_N_PLUS_RECT, PICK_T_MINUS_RECT,
    PICK_T_PLUS_RECT, PIN_CANCEL_RECT, PIN_COLS, PIN_EYE_RECT, PIN_ROWS, PIV_KEYGEN_PICK_ROWS,
    PIV_KEYGEN_PICK_TOP, PIV_PIN_MENU_ROWS, PIV_ROWS, PIV_RSA_PICK_ROWS, PK_BACK_RECT, PK_LIST_TOP,
    PinCaption, PinKey, PinPad, Point, RN_FIELD_RECT, Rect, RevealKind, RpRow, STATUS_BAR_H,
    Screen, SettingsPage, SettingsView, StatusKind, SuccessKind, T9_KEY_LABELS, TITLE_BACK_RECT,
    TITLE_BAR_H, TITLE_EDIT_RECT, font, font::Role, glyph, hex_u16, hex_u64, nav_tab_rect,
    page_count, pin_grid_key, pin_key_rect, settings_row_rect, t9_key_rect, theme,
};
use crate::{
    AppsView, CardholderView, OathDetailView, OathRow, OpenpgpView, PgpKeyView, PivExtraRow,
    PivSlotView, PivView,
};

mod applets;
mod audit;
mod backup;
mod boot;
mod ceremony;
mod components;
mod home;
mod passkeys;
mod pin;
mod reset;
mod settings;

pub use applets::{
    render_apps, render_oath, render_oath_cred, render_openpgp, render_openpgp_cardholder,
    render_openpgp_key, render_piv, render_piv_extra, render_piv_keygen_confirm,
    render_piv_keygen_pick, render_piv_keygen_rsa_pick, render_piv_keygen_working,
    render_piv_pin_menu, render_piv_protect_confirm, render_piv_slot,
};
pub use audit::render_audit_log;
pub use backup::{
    SEED_WORDS_PER_PAGE, render_backup, render_backup_format, render_reveal_warning,
    render_seal_confirm, render_seed_phrase, render_share_picker, render_slip39_share,
};
pub use boot::render_locked_breathe;
pub use ceremony::render_add_passkey;
pub use home::{STATUS_ARC_START, render_status_arc};
pub use passkeys::{
    render_confirm_delete, render_passkeys_list, render_rename, render_rename_field,
    render_rename_keys, render_service,
};
pub use pin::{PIN_TITLE_BAND, pin_title_overflows, render_pin_dots, render_pin_title};
pub use reset::{
    render_confirm_factory_reset, render_erasing, render_pin_blocked, render_success,
    render_success_circle, render_wipe_failed,
};
pub use settings::{render_firmware, render_rebooting};

use boot::{locked, onboard, splash};
use ceremony::confirm;
use home::home;
use pin::pin;
use settings::settings;

// Local semantic aliases, all sourced from `theme` so the whole renderer speaks one
// palette (these equal their tokens — re-sourcing is hygiene, not a visual change).
const BG: Rgb565 = theme::PANEL_BG;
const FG: Rgb565 = theme::TEXT;
const MUTED: Rgb565 = theme::MUTED;
/// Affirmative fill — the PIN pad's OK key and the brightness level bar. Calm
/// sea-green, not vivid, so it reads as confirmation rather than alarm. The decline
/// pair (Deny / Cancel) is a low-emphasis outline in [`theme::DENY`] instead, so
/// there is no filled-red counterpart const here.
const ALLOW_FILL: Rgb565 = theme::APPROVE;
/// Corner radius for the floating buttons — the design's 11px, matching [`CARD_RADIUS`].
const BTN_RADIUS: u32 = 11;
/// Corner radius for the pad / stepper key surfaces — the design's 9px, tighter than the
/// 11px buttons (handoff: "Клавиатура PIN: … скругление 9").
const KEY_RADIUS: u32 = 9;
/// Fill for the numeric PIN keys and the settings −/+ steppers — a dark neutral card
/// ([`theme::KEY_BG`]) edged with [`theme::KEY_BORDER`]. The affirmative OK is a solid
/// Allow-green key and Del a backspace glyph, so the special keys still stand out.
const KEY_FILL: Rgb565 = theme::KEY_BG;

/// Center the screen horizontally on a half-pixel-free integer midline.
const MIDX: i32 = PANEL_W as i32 / 2;

/// Render `screen` as a full frame. Clears to the background first, so the caller
/// need not track dirty regions — it repaints when the model changes.
pub fn render<D>(target: &mut D, screen: &Screen) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    target.clear(BG)?;
    match screen {
        Screen::Splash => splash(target),
        Screen::Locked => locked(target),
        Screen::Onboard => onboard(target),
        Screen::Home(v) => home(target, v),
        Screen::Confirm(prompt) => confirm(target, prompt),
        Screen::Pin(pad) => pin(target, pad),
        Screen::Settings(view) => settings(target, view),
    }
}

/// A right-aligned `"<n> <unit>"` footer just above the nav bar (the list / detail
/// total), in the muted colour.
fn footer_count<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    n: u16,
    unit: &str,
) -> Result<(), D::Error> {
    let mut buf = [0u8; 16];
    let s = fmt_count(n, unit, &mut buf);
    text_right(
        t,
        s,
        EgPoint::new(PANEL_W as i32 - 12, NAV_TOP as i32 - 10),
        Role::Mono,
        MUTED,
    )
}

/// The bottom of a scrollable list: the [pager](render_pager) when it spans more than
/// one page, else the item-count footer. Keeps the three list screens consistent.
fn list_tail<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    page: u16,
    total: u16,
    one: &str,
    many: &str,
) -> Result<(), D::Error> {
    let pages = page_count(total);
    if pages > 1 {
        render_pager(t, page, pages)
    } else {
        footer_count(t, total, if total == 1 { one } else { many })
    }
}

/// Paint the pager band: a `‹` prev arrow (dimmed on the first page), a centred
/// "page / pages" indicator, and a `›` next arrow (dimmed on the last page). The arrows
/// land in [`PAGER_PREV_RECT`] / [`PAGER_NEXT_RECT`] — exactly where [`crate::hit_pager`]
/// maps a tap — so a painted arrow and its hit target can never disagree.
fn render_pager<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    page: u16,
    pages: u16,
) -> Result<(), D::Error> {
    let cy = PAGER_PREV_RECT.y as i32 + PAGER_PREV_RECT.h as i32 / 2;
    let prev_col = if page > 0 {
        theme::ACCENT
    } else {
        theme::CAPTION
    };
    let next_col = if page + 1 < pages {
        theme::ACCENT
    } else {
        theme::CAPTION
    };
    glyph::draw(
        t,
        Glyph::Back,
        Point::new(
            PAGER_PREV_RECT.x + PAGER_PREV_RECT.w / 2 - 8,
            (cy - 8) as u16,
        ),
        16,
        prev_col,
    )?;
    glyph::draw(
        t,
        Glyph::Chevron,
        Point::new(
            PAGER_NEXT_RECT.x + PAGER_NEXT_RECT.w / 2 - 8,
            (cy - 8) as u16,
        ),
        16,
        next_col,
    )?;
    let mut buf = [0u8; 13];
    text(
        t,
        fmt_pages(page + 1, pages, &mut buf),
        EgPoint::new(MIDX, cy),
        Role::Mono,
        MUTED,
    )
}

/// Format `"P / N"` (current / total pages) into `buf`, no alloc. Sized for the full u16
/// domain: 5 digits + " / " + 5 digits = 13 bytes (page counts never reach that, but the
/// buffer matches `fmt_u16`'s range so it can't index out of bounds).
fn fmt_pages(p: u16, n: u16, buf: &mut [u8; 13]) -> &str {
    let mut a = [0u8; 5];
    let ps = fmt_u16(p, &mut a);
    let mut b = [0u8; 5];
    let ns = fmt_u16(n, &mut b);
    let mut i = 0;
    for &c in ps.as_bytes() {
        buf[i] = c;
        i += 1;
    }
    for &c in b" / " {
        buf[i] = c;
        i += 1;
    }
    for &c in ns.as_bytes() {
        buf[i] = c;
        i += 1;
    }
    str8(&buf[..i])
}

/// An outlined (not filled) rounded button — the low-emphasis action (Deny).
fn outline_button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    color: Rgb565,
) -> Result<(), D::Error> {
    // The design's outline button is a 1px border over a faint tint of its own colour, not a
    // bare stroke: danger (Deny / Cancel) on [`theme::DANGER_BG`] edged [`theme::DANGER_BORDER`],
    // any other accent on the blue [`theme::TINT_BLUE`] edged [`theme::BORDER_FIELD`]. The label
    // keeps the full-strength `color`.
    let (bg, border) = if color == theme::DANGER {
        (theme::DANGER_BG, theme::DANGER_BORDER)
    } else {
        (theme::TINT_BLUE, theme::BORDER_FIELD)
    };
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(bg))
        .draw(t)?;
    // Inside-aligned stroke: the outline stays within `r`, so a button's paint never
    // bleeds past the exact rect the hit-test maps (the Allow/Deny contract).
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(border)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    text(t, label, center(r), Role::Strong, color)
}

/// Fill a rounded floating button and center its caption — the fill and the
/// caption share the one [`Rect`] the hit-test uses, so paint and hit-test can
/// never disagree. The rounded card never extends past `r`, so it stays within the
/// exact region [`crate::hit_confirm`] approves.
fn button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    fill: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    text(t, label, center(r), Role::Strong, FG)
}

/// Paint a rounded key surface at `r`: a `fill`, plus (when `bordered`) a subtle
/// [`theme::KEY_BORDER`] edge so a dark key still reads as pressable. The caller
/// centres the digit or glyph on top. Shared by the PIN pad and the settings ±.
fn key_surface<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    fill: Rgb565,
    bordered: bool,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(KEY_RADIUS, KEY_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    if bordered {
        RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(KEY_RADIUS, KEY_RADIUS))
            .into_styled(
                PrimitiveStyleBuilder::new()
                    .stroke_color(theme::KEY_BORDER)
                    .stroke_width(1)
                    .stroke_alignment(StrokeAlignment::Inside)
                    .build(),
            )
            .draw(t)?;
    }
    Ok(())
}

/// Draw glyph `g` of side `size` centred in `r`.
fn glyph_centered<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    g: Glyph,
    r: Rect,
    size: u16,
    color: Rgb565,
) -> Result<(), D::Error> {
    glyph::draw(
        t,
        g,
        Point::new(r.x + r.w / 2 - size / 2, r.y + r.h / 2 - size / 2),
        size,
        color,
    )
}

/// A back / cancel affordance with a **visible bounded tap target**: a rounded outline
/// drawn around the whole hit `rect` (so it is obvious how large the pressable area is)
/// with a centred chevron inside. Used for every small back/cancel chevron — the title
/// bar, the chrome-less modals, the PIN pad — so they all read as real buttons rather
/// than a lone glyph. The outline tints with the action `color` (accent for a plain
/// back, the decline colour for a cancel).
fn back_button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    color: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(9, 9))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(color)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    glyph_centered(t, Glyph::Back, rect, 18, color)
}

/// Draw `s` centered on `at` (horizontal center, vertical middle).
fn text<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    font::centered(t, s, at, role, color)
}

fn center(r: Rect) -> EgPoint {
    EgPoint::new(r.x as i32 + r.w as i32 / 2, r.y as i32 + r.h as i32 / 2)
}

fn eg_rect(r: Rect) -> Rectangle {
    Rectangle::new(
        EgPoint::new(r.x as i32, r.y as i32),
        Size::new(r.w as u32, r.h as u32),
    )
}

// --- Design-system widgets (the re-skin layout) ----------------------------

/// Left-aligned, vertically-centred text (list-row labels, header titles).
fn text_left<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    font::left(t, s, at, role, color)
}

/// Right-aligned, vertically-centred text (trailing row status / values).
fn text_right<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    font::right(t, s, at, role, color)
}

/// Left-aligned text hard-clipped to `clip`, so a label too long for its slot is cut at
/// the boundary rather than overrunning a trailing value — proportional faces make long,
/// variable rp names a real risk.
fn text_left_clipped<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    clip: Rect,
) -> Result<(), D::Error> {
    font::left(&mut t.clipped(&eg_rect(clip)), s, at, role, color)
}

/// Like [`text_left_clipped`], but when `s` is too wide for `clip` it is shortened to the
/// widest character prefix that fits with a trailing `"..."` — so an over-long label reads
/// as deliberately truncated ("Authenticat...") instead of cut mid-glyph ("Authentica"),
/// and on the anti-phishing screens a padded look-alike id is *visibly* truncated. Input is
/// ASCII-sanitised ([`crate::Label::clamp`]) and the static titles are ASCII, so a byte is a
/// char; the ellipsis is ASCII because the `_tr` faces carry no `U+2026`.
///
/// `force_mark` appends the marker even when `s` fits: a [`crate::Label`] already cut at
/// `LABEL_MAX` (its `truncated` flag) is a prefix of a longer original, so on a trust screen
/// it must still read as truncated even if the clamped prefix happens to fit the box.
fn text_left_ellipsized<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    clip: Rect,
    force_mark: bool,
) -> Result<(), D::Error> {
    if !force_mark && font::width(s, role).unwrap_or(0) <= clip.w as u32 {
        return font::left(&mut t.clipped(&eg_rect(clip)), s, at, role, color);
    }
    const ELL: &str = "...";
    let budget = (clip.w as u32).saturating_sub(font::width(ELL, role).unwrap_or(0));
    // Widest byte-prefix (byte == char on ASCII input) whose width still leaves room for
    // the ellipsis. Bounded to the 64-byte buffer below; only runs on the rare overflow.
    let mut end = 0;
    let mut i = 1;
    while i <= s.len() && i <= 64 {
        if s.is_char_boundary(i) {
            if font::width(&s[..i], role).unwrap_or(u32::MAX) <= budget {
                end = i;
            } else {
                break;
            }
        }
        i += 1;
    }
    let mut buf = [0u8; 67];
    buf[..end].copy_from_slice(&s.as_bytes()[..end]);
    buf[end..end + ELL.len()].copy_from_slice(ELL.as_bytes());
    let out = core::str::from_utf8(&buf[..end + ELL.len()]).unwrap_or(ELL);
    font::left(&mut t.clipped(&eg_rect(clip)), out, at, role, color)
}

/// Like [`text_left_ellipsized`] but keeps the **suffix** and prepends the marker:
/// `"...registrable.domain"`. Used for relying-party / domain labels, where the
/// security-relevant part is the rightmost registrable domain — head-truncation
/// would let a look-alike (`accounts.google.com.attacker.com`) hide the real domain
/// behind the ellipsis. `s` is ASCII (a [`crate::Label`]), so a byte is a char.
fn text_right_ellipsized<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    clip: Rect,
    force_mark: bool,
) -> Result<(), D::Error> {
    if !force_mark && font::width(s, role).unwrap_or(0) <= clip.w as u32 {
        return font::left(&mut t.clipped(&eg_rect(clip)), s, at, role, color);
    }
    const ELL: &str = "...";
    let budget = (clip.w as u32).saturating_sub(font::width(ELL, role).unwrap_or(0));
    // Widest byte-suffix whose width still leaves room for the leading ellipsis: walk
    // the start boundary backward from the end until `s[start..]` no longer fits.
    let mut start = s.len();
    let mut i = s.len();
    while i > 0 {
        i -= 1;
        if s.is_char_boundary(i) {
            if font::width(&s[i..], role).unwrap_or(u32::MAX) <= budget {
                start = i;
            } else {
                break;
            }
        }
    }
    let mut buf = [0u8; 67];
    buf[..ELL.len()].copy_from_slice(ELL.as_bytes());
    // Keep the rightmost bytes of the fitting suffix, bounded to the buffer.
    let suffix = &s.as_bytes()[start..];
    let n = suffix.len().min(buf.len() - ELL.len());
    let suffix = &suffix[suffix.len() - n..];
    buf[ELL.len()..ELL.len() + n].copy_from_slice(suffix);
    let out = core::str::from_utf8(&buf[..ELL.len() + n]).unwrap_or(ELL);
    font::left(&mut t.clipped(&eg_rect(clip)), out, at, role, color)
}

/// The persistent top **status bar** (the design's framing chrome): a mono "RS-Key"
/// wordmark at the left and the USB power indicator at the right. Faint, so it frames
/// the screen without competing with content. This is a bus-powered device, so the power
/// indicator is always the USB plug + "USB" label — never a battery.
pub fn status_bar<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    let cy = STATUS_BAR_H as i32 / 2 + 1;
    text_left(
        t,
        "RS-Key",
        EgPoint::new(13, cy),
        Role::MonoSmall,
        theme::FAINT,
    )?;
    // USB indicator: the "USB" label flush to the right edge, the plug glyph just left
    // of it (measured so they sit together regardless of the label's width).
    let label_right = PANEL_W as i32 - 13;
    text_right(
        t,
        "USB",
        EgPoint::new(label_right, cy),
        Role::MonoSmall,
        theme::FAINT,
    )?;
    let label_w = font::width("USB", Role::MonoSmall).unwrap_or(20) as i32;
    glyph::draw(
        t,
        Glyph::Usb,
        Point::new((label_right - label_w - 16).max(0) as u16, (cy - 7) as u16),
        14,
        theme::GREY,
    )
}

/// The **title bar** below the status bar: an optional back chevron (painted in
/// [`TITLE_BACK_RECT`], the region [`crate::hit_title_back`] maps a tap to) and the
/// screen `title`. The chevron tints with the title (both `color`), per the design. The
/// title is **clipped** to the strip left of the right-edge affordance zone
/// ([`TITLE_EDIT_RECT`]): a long, user-controllable title (e.g. a device-local nickname)
/// is cut at the boundary rather than overrunning off-panel or under the edit pencil.
pub fn title_bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    color: Rgb565,
    back: bool,
) -> Result<(), D::Error> {
    // Default: leave the right edge for the [`render_service`] edit pencil.
    title_bar_to(
        t,
        title,
        color,
        back,
        TITLE_EDIT_RECT.x.saturating_sub(4),
        false,
        false,
    )
}

/// A [`title_bar`] whose title is an **attacker-chosen domain** (a relying-party id): it
/// head-ellipsizes (`...registrable.domain`) so the security-relevant suffix stays on
/// screen, instead of the tail-cut a padded look-alike could hide the real domain behind.
/// Same right-edge as [`title_bar`] (reserves the [`render_service`] edit pencil).
pub fn title_bar_domain<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &Label,
    color: Rgb565,
    back: bool,
) -> Result<(), D::Error> {
    title_bar_to(
        t,
        title.as_str(),
        color,
        back,
        TITLE_EDIT_RECT.x.saturating_sub(4),
        true,
        // An rpId clipped to LABEL_MAX must carry its marker on the detail screen
        // too, not only on the ceremony card (audit run-33).
        title.truncated,
    )
}

/// A [`title_bar`] for screens that draw **no** right-edge affordance (the applet
/// overview / detail screens): the title clips to the full content margin instead of
/// reserving the edit-pencil zone, so a longer title isn't cut mid-word.
fn title_bar_wide<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    color: Rgb565,
    back: bool,
) -> Result<(), D::Error> {
    title_bar_to(t, title, color, back, PANEL_W - 13, false, false)
}

/// [`title_bar_wide`] for a title the *host* chose (an OATH credential name), so a
/// value already clipped to `LABEL_MAX` carries its marker here too — same reason
/// the passkey screens pass `Label::truncated`: this is where the owner audits what
/// is stored, and a padded look-alike must not read as whole.
fn title_bar_wide_label<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &Label,
    color: Rgb565,
    back: bool,
) -> Result<(), D::Error> {
    title_bar_to(
        t,
        title.as_str(),
        color,
        back,
        PANEL_W - 13,
        false,
        title.truncated,
    )
}

/// Shared title-bar paint: an optional back chevron, then the title clipped to end at
/// `right` (a single px past which nothing paints), so paint and the back hit-test agree.
/// `domain` keeps the suffix (head-ellipsis) for an attacker-chosen relying-party id; the
/// default keeps the head (tail-ellipsis) for a static / user-chosen title.
fn title_bar_to<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    color: Rgb565,
    back: bool,
    right: u16,
    domain: bool,
    marked: bool,
) -> Result<(), D::Error> {
    let cy = STATUS_BAR_H as i32 + TITLE_BAR_H as i32 / 2;
    let tx = if back {
        back_button(t, TITLE_BACK_RECT, color)?;
        TITLE_BACK_RECT.x as i32 + TITLE_BACK_RECT.w as i32 + 6
    } else {
        13
    };
    let clip = Rect::new(
        tx as u16,
        STATUS_BAR_H,
        right.saturating_sub(tx as u16),
        TITLE_BAR_H,
    );
    let at = EgPoint::new(tx, cy);
    if domain {
        text_right_ellipsized(t, title, at, Role::Heading, color, clip, marked)
    } else {
        text_left_ellipsized(t, title, at, Role::Heading, color, clip, marked)
    }
}

/// The top header strip: a title (accent or muted) at the left, an optional status
/// glyph at the right.
pub fn render_header<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    accent: bool,
    right: Option<Glyph>,
) -> Result<(), D::Error> {
    let color = if accent { theme::ACCENT } else { theme::MUTED };
    text_left(t, title, EgPoint::new(12, 15), Role::Heading, color)?;
    if let Some(g) = right {
        glyph::draw(t, g, Point::new(PANEL_W - 26, 6), 18, theme::MUTED)?;
    }
    Ok(())
}

/// The corner radius shared by every list-row / settings card — the design's 11px, so a
/// row reads as a rounded card rather than the old near-square 6px tile.
const CARD_RADIUS: u32 = 11;

/// A list-row / settings card: the surface `fill` plus the design's 1px hairline `border`,
/// at the shared [`CARD_RADIUS`]. The single place row chrome lives, so every list speaks
/// the same visual language and a tweak lands everywhere at once.
fn card<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    fill: Rgb565,
    border: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(CARD_RADIUS, CARD_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(CARD_RADIUS, CARD_RADIUS))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(border)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)
}

/// The content of one list row — a leading glyph (on a service `chip` when set), the label,
/// an optional trailing coloured status/value, and an optional drill-in chevron — *without*
/// the card behind it. [`group_card`] backs a whole grouped list, then each row's content
/// is drawn with this.
fn row_body<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    icon: Glyph,
    label: &str,
    trailing: Option<(&str, Rgb565)>,
    chevron: bool,
    chip: bool,
) -> Result<(), D::Error> {
    let cy = rect.y as i32 + rect.h as i32 / 2;
    let gx = if chip {
        RoundedRectangle::with_equal_corners(
            eg_rect(Rect::new(rect.x + 3, (cy - 11) as u16, 22, 22)),
            Size::new(6, 6),
        )
        .into_styled(PrimitiveStyle::with_fill(theme::CHIP))
        .draw(t)?;
        rect.x + 7
    } else {
        rect.x + 8
    };
    glyph::draw(t, icon, Point::new(gx, (cy - 7) as u16), 14, theme::GREY)?;
    let mut right_x = rect.x as i32 + rect.w as i32 - 8;
    if chevron {
        right_x -= 12;
        glyph::draw(
            t,
            Glyph::Chevron,
            Point::new(right_x as u16, (cy - 6) as u16),
            12,
            theme::MUTED,
        )?;
    }
    let label_x = rect.x as i32 + 28;
    let label_right = if let Some((txt, col)) = trailing {
        let tx = right_x - 4;
        let tclip = Rect::new(label_x as u16, rect.y, (tx - label_x).max(0) as u16, rect.h);
        font::right(
            &mut t.clipped(&eg_rect(tclip)),
            txt,
            EgPoint::new(tx, cy),
            Role::Body,
            col,
        )?;
        tx - font::width(txt, Role::Body).unwrap_or(0) as i32 - ROW_TRAILING_GAP
    } else {
        right_x - ROW_TRAILING_GAP
    };
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    let at = EgPoint::new(label_x, cy);
    text_left_ellipsized(t, label, at, Role::Body, theme::TEXT, clip, false)
}

/// Paint one grouped surface behind list rows `0..n` (each at `row_rect(y0, i)`), with a
/// hairline divider at every inter-row gap. The row content is then drawn on top with
/// [`row_body`], so the list reads as the design's single grouped card rather than a stack
/// of separate pills — while `row_rect` stays the tap target, so paint and
/// [`crate::hit_list`] still share geometry.
fn group_card<D: DrawTarget<Color = Rgb565>>(t: &mut D, y0: u16, n: u16) -> Result<(), D::Error> {
    if n == 0 {
        return Ok(());
    }
    let first = crate::row_rect(y0, 0);
    let last = crate::row_rect(y0, n - 1);
    group_panel(
        t,
        Rect::new(first.x, first.y, first.w, last.y + last.h - first.y),
    )?;
    for i in 1..n {
        // The divider sits at the midpoint of the gap between consecutive row rects.
        let dy = (crate::row_rect(y0, i - 1).y + crate::LIST_ROW_H + crate::row_rect(y0, i).y) / 2;
        group_divider(t, first.x, first.w, dy as i32)?;
    }
    Ok(())
}

/// The surface behind a grouped list (or any multi-row group with custom rects): one
/// rounded card, fill + hairline border, at the shared [`CARD_RADIUS`].
fn group_panel<D: DrawTarget<Color = Rgb565>>(t: &mut D, span: Rect) -> Result<(), D::Error> {
    card(t, span, theme::ROW_BG, theme::BORDER_CARD)
}

/// A hairline divider inside a grouped card, inset from the rounded edges.
fn group_divider<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    x: u16,
    w: u16,
    y: i32,
) -> Result<(), D::Error> {
    Line::new(
        EgPoint::new(x as i32 + 12, y),
        EgPoint::new((x + w) as i32 - 12, y),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::DIVIDER, 1))
    .draw(t)
}

/// A relying-party row's leading glyph: a terminal for an SSH host, else the generic globe.
fn service_glyph(label: &str) -> Glyph {
    let b = label.as_bytes();
    // Case-insensitive search for "ssh" (`| 0x20` lowercases an ASCII letter).
    let ssh = b
        .windows(3)
        .any(|w| w[0] | 0x20 == b's' && w[1] | 0x20 == b's' && w[2] | 0x20 == b'h');
    if ssh { Glyph::Terminal } else { Glyph::Globe }
}

/// The gap kept between a row's (clipped) label and its trailing value / chevron, so the
/// two never touch even when the label fills its slot.
const ROW_TRAILING_GAP: i32 = 8;

/// The bottom nav bar: a surface + hairline, the `active` tab in accent and the rest
/// dimmed. Glyphs sit in the exact [`nav_tab_rect`] cells [`crate::hit_nav`] maps.
pub fn render_nav<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    active: NavTab,
) -> Result<(), D::Error> {
    Rectangle::new(
        EgPoint::new(0, NAV_TOP as i32),
        Size::new(PANEL_W as u32, NAV_H as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(theme::NAV_BG))
    .draw(t)?;
    Line::new(
        EgPoint::new(0, NAV_TOP as i32),
        EgPoint::new(PANEL_W as i32 - 1, NAV_TOP as i32),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::HAIRLINE, 1))
    .draw(t)?;
    for (i, &tab) in NAV_TABS.iter().enumerate() {
        let r = nav_tab_rect(i as u16);
        let color = if tab == active {
            theme::ACCENT
        } else {
            theme::NAV_INACTIVE
        };
        let g = match tab {
            NavTab::Home => Glyph::Home,
            NavTab::Passkeys => Glyph::Key,
            NavTab::Apps => Glyph::Apps,
            NavTab::Settings => Glyph::Gear,
        };
        // Glyph high in the cell, its caption centred below — four tabs at 60px each
        // are tight, so the label disambiguates the (smaller, 16px) icon.
        let cx = r.x + r.w / 2;
        glyph::draw(t, g, Point::new(cx - 8, NAV_TOP + 4), 16, color)?;
        text(
            t,
            tab.label(),
            EgPoint::new(cx as i32, NAV_TOP as i32 + 28),
            Role::MonoSmall,
            color,
        )?;
    }
    Ok(())
}

/// The lighter progress wash a hold button grows as the finger holds — what the design's
/// `rgba(255,255,255,.26)` overlay resolves to over the solid base: [`theme::HOLD_ON_RED`]
/// over a red ([`theme::DANGER_FILL`]) base, else [`theme::HOLD_ON_BLUE`] over the blue
/// primary. Keyed off the base colour so each caller passes only its one fill.
fn hold_overlay(base: Rgb565) -> Rgb565 {
    if base == theme::DANGER_FILL {
        theme::HOLD_ON_RED
    } else {
        theme::HOLD_ON_BLUE
    }
}

/// Re-stamp the centred white label of a hold button on top of the fill, so the advancing
/// progress edge never eats it. Small caption so longer labels ("Hold to approve") fit.
fn hold_label<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
) -> Result<(), D::Error> {
    text(t, label, center(rect), Role::Body, FG)
}

/// The **static base** of a hold-to-confirm button: a solid `fill` card (the design's
/// primary blue / danger red) with the centred white label. Painted once when the screen
/// appears and again on a hold reset; [`render_hold_fill`] then grows the lighter
/// `hold_overlay` wash over it without re-clearing the card, so the build-up never
/// flickers.
pub fn render_hold_button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
    fill: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    hold_label(t, rect, label)
}

/// Grow the hold wash from `prev_num/den` to `num/den` of the button width, drawn over the
/// solid base with **no card clear**, so repainting each poll doesn't flicker. The wash —
/// the lighter `hold_overlay` of the base `fill` — is the button's *own* rounded-rect
/// shape painted through a clip of only the advancing strip `[prev_w, w]`: so its rounded
/// corners are exactly the base's (no square corner ever pokes past the card — the artifact
/// the earlier left-rounded approach left when narrow widths clamped the radius), the
/// advancing edge is the flat clip boundary, and only the thin new strip is painted (the
/// centred label is overdrawn ~2px at a time, not washed every frame). Pass `prev_num == 0`
/// to start a fresh fill.
pub fn render_hold_fill<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
    prev_num: u16,
    num: u16,
    den: u16,
    fill: Rgb565,
) -> Result<(), D::Error> {
    if den > 0 {
        let frac = |n: u16| (rect.w as u32 * n.min(den) as u32 / den as u32).min(rect.w as u32);
        let (w, pw) = (frac(num), frac(prev_num));
        if w > pw {
            let strip = Rectangle::new(
                EgPoint::new(rect.x as i32 + pw as i32, rect.y as i32),
                Size::new(w - pw, rect.h as u32),
            );
            let mut clipped = t.clipped(&strip);
            RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(BTN_RADIUS, BTN_RADIUS))
                .into_styled(PrimitiveStyle::with_fill(hold_overlay(fill)))
                .draw(&mut clipped)?;
        }
    }
    hold_label(t, rect, label)
}

/// `&str` view of an all-ASCII fixed buffer (the hex/decimal we built); falls back to
/// empty rather than panic if the invariant were ever broken.
fn str8(buf: &[u8]) -> &str {
    core::str::from_utf8(buf).unwrap_or("")
}

/// Decimal-format `v` into the tail of `buf`, returning the written slice (no alloc).
fn fmt_u16(mut v: u16, buf: &mut [u8; 5]) -> &str {
    let mut i = buf.len();
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    str8(&buf[i..])
}

/// Format `secs` as `"NN s"` into `buf` (≤5 digits + " s" ≤ 8).
fn fmt_secs(secs: u16, buf: &mut [u8; 8]) -> &str {
    let mut tmp = [0u8; 5];
    let num = fmt_u16(secs, &mut tmp);
    let n = num.len();
    buf[..n].copy_from_slice(num.as_bytes());
    buf[n] = b' ';
    buf[n + 1] = b's';
    str8(&buf[..n + 2])
}

/// Format `"<n> <unit>"` into `buf` with no alloc (e.g. `"2 accounts"`); returns
/// empty if it wouldn't fit, so the caller never panics on a tiny buffer.
fn fmt_count<'a>(n: u16, unit: &str, buf: &'a mut [u8]) -> &'a str {
    let mut tmp = [0u8; 5];
    let num = fmt_u16(n, &mut tmp);
    let end = num.len() + 1 + unit.len();
    if end > buf.len() {
        return "";
    }
    buf[..num.len()].copy_from_slice(num.as_bytes());
    buf[num.len()] = b' ';
    buf[num.len() + 1..end].copy_from_slice(unit.as_bytes());
    str8(&buf[..end])
}

/// Format a "time ago" as a compact mono token (`"now"`, `"5m"`, `"3h"`, `"2d"`, `"1w"`)
/// into `buf`. Boot-relative, so only meaningful within the current power cycle — the
/// firmware passes the elapsed seconds only for current-session entries. The numeric
/// part is always < 60, so it fits two digits.
fn fmt_ago(secs: u32, buf: &mut [u8; 8]) -> &str {
    let (n, unit) = if secs < 60 {
        return "now";
    } else if secs < 3_600 {
        (secs / 60, b'm')
    } else if secs < 86_400 {
        (secs / 3_600, b'h')
    } else if secs < 604_800 {
        (secs / 86_400, b'd')
    } else {
        (secs / 604_800, b'w')
    };
    let mut tmp = [0u8; 5];
    let num = fmt_u16(n as u16, &mut tmp);
    let len = num.len();
    buf[..len].copy_from_slice(num.as_bytes());
    buf[len] = unit;
    str8(&buf[..len + 1])
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
