// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Applet hub screens: the OpenPGP / PIV / OATH overviews, details, and keygen flows.

use super::components;
use super::*;

// --- Applet hub (OpenPGP / PIV / OATH) --------------------------------------

/// Colour a remaining-attempts count by how close it is to lockout.
fn retry_color(n: u8) -> Rgb565 {
    match n {
        0 => theme::DANGER,
        1 => theme::WARN,
        _ => theme::CAPTION,
    }
}

/// Format `"<label> <n>"` (e.g. "PIN 3") into `buf`. Takes a `u32` so the OpenPGP
/// signature counter (a 3-byte field up to 16,777,215) is never narrowed.
fn fmt_labeled<'a>(label: &str, n: u32, buf: &'a mut [u8]) -> &'a str {
    let mut tn = [0u8; 10];
    let mut i = tn.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        tn[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        tn[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let num = &tn[i..];
    let lab = label.as_bytes();
    let need = lab.len() + 1 + num.len();
    if need > buf.len() {
        return "";
    }
    buf[..lab.len()].copy_from_slice(lab);
    buf[lab.len()] = b' ';
    buf[lab.len() + 1..need].copy_from_slice(num);
    str8(&buf[..need])
}

/// Format `"<label> <a>/<b>"` (e.g. "PIN 3/3") into `buf`.
fn fmt_pair<'a>(label: &str, a: u8, b: u8, buf: &'a mut [u8]) -> &'a str {
    let (mut ta, mut tb) = ([0u8; 5], [0u8; 5]);
    let sa = fmt_u16(a as u16, &mut ta).as_bytes();
    let sb = fmt_u16(b as u16, &mut tb).as_bytes();
    let lab = label.as_bytes();
    let need = lab.len() + 1 + sa.len() + 1 + sb.len();
    if need > buf.len() {
        return "";
    }
    let mut n = 0;
    for part in [lab, b" ", sa, b"/", sb] {
        buf[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    str8(&buf[..n])
}

/// Hex-encode `bytes` into `buf` as upper-case pairs with a space every 2 bytes
/// ("A1B2 C3D4 …") — the on-screen form of an OpenPGP fingerprint.
fn fmt_hex_grouped<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut n = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && i % 2 == 0 && n < buf.len() {
            buf[n] = b' ';
            n += 1;
        }
        if n + 2 <= buf.len() {
            buf[n] = HEX[(b >> 4) as usize];
            buf[n + 1] = HEX[(b & 0xf) as usize];
            n += 2;
        }
    }
    str8(&buf[..n])
}

/// A read-only detail card: a bordered surface of `label → value` rows, each a muted
/// label at the left and its value (mono) at the right, divided by hairlines. Used by
/// the OpenPGP key-detail and PIV slot-detail screens.
fn detail_card<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    top: u16,
    rows: &[(&str, &str, Rgb565)],
) -> Result<(), D::Error> {
    const X: u16 = 13;
    const W: u16 = PANEL_W - 2 * X;
    const RH: i32 = 30;
    let h = rows.len() as u16 * RH as u16 + 8;
    card(
        t,
        Rect::new(X, top, W, h),
        theme::SURFACE,
        theme::BORDER_CARD,
    )?;
    for (i, (label, value, color)) in rows.iter().enumerate() {
        let row_top = top as i32 + 4 + i as i32 * RH;
        if i > 0 {
            Line::new(
                EgPoint::new(X as i32 + 10, row_top),
                EgPoint::new((X + W) as i32 - 10, row_top),
            )
            .into_styled(PrimitiveStyle::with_stroke(theme::DIVIDER, 1))
            .draw(t)?;
        }
        let cy = row_top + RH / 2;
        text_left_on(
            t,
            label,
            EgPoint::new(X as i32 + 12, cy),
            Role::Body,
            theme::MUTED,
            theme::SURFACE,
        )?;
        font::right(
            t,
            value,
            EgPoint::new((X + W) as i32 - 12, cy),
            Role::Mono,
            *color,
            theme::SURFACE,
        )?;
    }
    Ok(())
}

/// The empty-slot body of an applet detail screen: a centred muted glyph, a headline,
/// and a one-line hint on how to populate the slot. Keeps an unprovisioned slot
/// explorable (it still drills in) rather than an inert, unexplained row.
fn empty_slot<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    icon: Glyph,
    headline: &str,
    hint: &str,
) -> Result<(), D::Error> {
    glyph::draw(t, icon, Point::new(MIDX as u16 - 22, 120), 44, MUTED, BG)?;
    text(
        t,
        headline,
        EgPoint::new(MIDX, 192),
        Role::Strong,
        theme::TEXT_2,
    )?;
    text(
        t,
        hint,
        EgPoint::new(MIDX, 216),
        Role::MonoSmall,
        theme::CAPTION,
    )
}

/// Build a retired-slot title `"Retired #N"` (N = wire slot − 0x81, so 82 → #1) into
/// `buf`, returning the slice. `"Retired #" ` is 9 bytes + ≤2 digits ≤ 12.
fn retired_title(slot: u8, buf: &mut [u8; 12]) -> &str {
    const PRE: &[u8] = b"Retired #";
    buf[..PRE.len()].copy_from_slice(PRE);
    let mut nb = [0u8; 5];
    let ns = fmt_u16(slot.wrapping_sub(0x81) as u16, &mut nb).as_bytes();
    let end = PRE.len() + ns.len();
    buf[PRE.len()..end].copy_from_slice(ns);
    str8(&buf[..end])
}

/// The Apps tab: the unified applet launcher — one row per credential applet
/// (OpenPGP / PIV / OATH) with its live item count, plus the bottom nav.
pub fn render_apps<D>(t: &mut D, v: &AppsView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "Apps", theme::ACCENT, false)?;
    let (mut b0, mut b1, mut b2) = ([0u8; 16], [0u8; 16], [0u8; 16]);
    let rows: [(Glyph, &str, &str); 3] = [
        (
            Glyph::Key,
            "OpenPGP",
            fmt_count(
                v.openpgp_keys as u16,
                if v.openpgp_keys == 1 { "key" } else { "keys" },
                &mut b0,
            ),
        ),
        (
            Glyph::Cpu,
            "PIV",
            fmt_count(
                v.piv_slots as u16,
                if v.piv_slots == 1 { "slot" } else { "slots" },
                &mut b1,
            ),
        ),
        (
            Glyph::Clock,
            "OATH",
            fmt_count(
                v.oath_codes,
                if v.oath_codes == 1 { "code" } else { "codes" },
                &mut b2,
            ),
        ),
    ];
    components::list::group_card(t, PK_LIST_TOP, rows.len() as u16)?;
    for (i, (g, name, trailing)) in rows.into_iter().enumerate() {
        components::list::row(
            t,
            PK_LIST_TOP,
            i as u16,
            g,
            name,
            Some((trailing, MUTED)),
            true,
            true,
            false,
            false,
        )?;
    }
    render_nav(t, NavTab::Apps)
}

/// The OpenPGP overview: the three key slots (Signature / Encryption / Authentication)
/// with their algorithm, a footer with the signature counter and the PW1 / PW3
/// remaining attempts, and the nav bar. A present slot drills into its key detail.
pub fn render_openpgp<D>(t: &mut D, v: &OpenpgpView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "OpenPGP", theme::ACCENT, true)?;
    const NAMES: [&str; 3] = ["Signature", "Encryption", "Authentication"];
    const GLYPHS: [Glyph; 3] = [Glyph::Edit, Glyph::Lock, Glyph::Shield];
    // Three key slots + a card-holder row (its name as the trailing value).
    components::list::group_card(t, PK_LIST_TOP, OPENPGP_ROWS)?;
    for (i, slot) in v.slots.iter().enumerate() {
        let trailing = if slot.present {
            (slot.algo.as_str(), MUTED)
        } else {
            ("—", theme::CAPTION)
        };
        // Every slot drills into its own detail (an empty slot's screen explains its
        // role), so every row gets the chevron.
        components::list::row(
            t,
            PK_LIST_TOP,
            i as u16,
            GLYPHS[i],
            NAMES[i],
            Some(trailing),
            true,
            true,
            false,
            false,
        )?;
    }
    let ch_trailing = if v.cardholder_name.as_str().is_empty() {
        ("Not set", theme::CAPTION)
    } else {
        (v.cardholder_name.as_str(), MUTED)
    };
    components::list::row(
        t,
        PK_LIST_TOP,
        3,
        Glyph::User,
        "Card holder",
        Some(ch_trailing),
        true,
        true,
        false,
        false,
    )?;
    let cy = NAV_TOP as i32 - 10;
    let mut sbuf = [0u8; 16];
    text_left(
        t,
        fmt_labeled("sig", v.sig_count, &mut sbuf),
        EgPoint::new(13, cy),
        Role::Mono,
        theme::CAPTION,
    )?;
    let mut pbuf = [0u8; 16];
    text_right(
        t,
        fmt_pair("PIN", v.pw1, v.pw3, &mut pbuf),
        EgPoint::new(PANEL_W as i32 - 13, cy),
        Role::Mono,
        retry_color(v.pw1.min(v.pw3)),
    )?;
    render_nav(t, NavTab::Apps)
}

/// One OpenPGP key's detail (back-only, no nav). A present slot shows its algorithm,
/// touch policy, generation-time state, and the full SHA-1 fingerprint (two grouped
/// mono rows) — the public key itself is deliberately not shown (it is not
/// reconstructable without a PIN, and never leaves the card). An empty slot shows what
/// the slot is for and how to set it up, so every slot is explorable.
pub fn render_openpgp_key<D>(t: &mut D, v: &PgpKeyView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    let (title, purpose) = match v.slot {
        0 => ("Sign key", "Signs data and commits"),
        1 => ("Decrypt key", "Decrypts messages"),
        _ => ("Auth key", "SSH and authentication"),
    };
    title_bar_wide(t, title, theme::ACCENT, true)?;
    text_left(
        t,
        purpose,
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )?;
    if !v.present {
        return empty_slot(
            t,
            Glyph::Key,
            "No key in this slot",
            "Set it up with gpg over USB.",
        );
    }
    let card_top = CONTENT_TOP + 28;
    detail_card(
        t,
        card_top,
        &[
            ("Algorithm", v.algo.as_str(), theme::TEXT),
            (
                "Touch to use",
                if v.touch { "Required" } else { "Off" },
                if v.touch {
                    theme::ACCENT_TEXT
                } else {
                    theme::MUTED
                },
            ),
            (
                "Created",
                if v.created { "Recorded" } else { "Not set" },
                theme::MUTED,
            ),
        ],
    )?;
    let fp_top = card_top as i32 + 3 * 30 + 8 + 8;
    text_left(
        t,
        "FINGERPRINT",
        EgPoint::new(14, fp_top),
        Role::Mono,
        theme::CAPTION,
    )?;
    if v.has_fp {
        let mut r0 = [0u8; 32];
        let mut r1 = [0u8; 32];
        text_left(
            t,
            fmt_hex_grouped(&v.fingerprint[..10], &mut r0),
            EgPoint::new(14, fp_top + 24),
            Role::Mono,
            theme::TEXT_2,
        )?;
        text_left(
            t,
            fmt_hex_grouped(&v.fingerprint[10..], &mut r1),
            EgPoint::new(14, fp_top + 44),
            Role::Mono,
            theme::TEXT_2,
        )?;
    } else {
        text_left(
            t,
            "Not set",
            EgPoint::new(14, fp_top + 26),
            Role::Body,
            theme::MUTED,
        )?;
    }
    text_left(
        t,
        "Public key is not exportable",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
}

/// The PIV overview: the four primary slots (9A / 9C / 9D / 9E) with their algorithm
/// (or "cert" when only a certificate is stored), a footer with the PIN / PUK remaining
/// attempts, and the nav bar. A populated slot drills into its detail.
pub fn render_piv<D>(t: &mut D, v: &PivView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "PIV", theme::ACCENT, true)?;
    const NAMES: [&str; 4] = ["Authentication", "Signature", "Key Management", "Card Auth"];
    // Four primary slots + a "Retired & F9" row (its populated count as the trailing value).
    components::list::group_card(t, PK_LIST_TOP, PIV_ROWS)?;
    for (i, slot) in v.slots.iter().enumerate() {
        let trailing = if slot.present {
            (slot.algo.as_str(), MUTED)
        } else if slot.cert {
            ("cert", theme::CAPTION)
        } else {
            ("—", theme::CAPTION)
        };
        // Every slot drills into its own detail (an empty slot's screen explains its
        // role), so every row gets the chevron.
        components::list::row(
            t,
            PK_LIST_TOP,
            i as u16,
            Glyph::Cpu,
            NAMES[i],
            Some(trailing),
            true,
            true,
            false,
            false,
        )?;
    }
    let mut eb = [0u8; 5];
    components::list::row(
        t,
        PK_LIST_TOP,
        4,
        Glyph::Apps,
        "Retired & F9",
        Some((fmt_u16(v.extra as u16, &mut eb), MUTED)),
        true,
        true,
        false,
        false,
    )?;
    let cy = NAV_TOP as i32 - 10;
    let mut a = [0u8; 12];
    text_left(
        t,
        fmt_labeled("PIN", v.pin as u32, &mut a),
        EgPoint::new(13, cy),
        Role::Mono,
        retry_color(v.pin),
    )?;
    let mut b = [0u8; 12];
    text_right(
        t,
        fmt_labeled("PUK", v.puk as u32, &mut b),
        EgPoint::new(PANEL_W as i32 - 13, cy),
        Role::Mono,
        retry_color(v.puk),
    )?;
    render_nav(t, NavTab::Apps)
}

/// One PIV slot's detail (back-only, no nav). A populated slot shows its algorithm,
/// PIN / touch policy, key origin, and certificate presence. An empty slot shows what
/// the slot is for and how to set it up (and notes a stored cert if one exists without
/// a key), so every slot is explorable.
pub fn render_piv_slot<D>(t: &mut D, v: &PivSlotView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    let mut tb = [0u8; 12];
    let (title, purpose): (&str, &str) = match v.slot {
        0x9A => ("9A Auth", "Authentication / login"),
        0x9C => ("9C Sign", "Digital signatures"),
        0x9D => ("9D Key Mgmt", "Encryption / key mgmt"),
        0x9E => ("9E Card Auth", "Card auth, no PIN"),
        0xF9 => ("F9 Attestation", "Device attestation key"),
        s if (0x82..=0x95).contains(&s) => (retired_title(s, &mut tb), "Retired key-mgmt slot"),
        _ => ("PIV slot", ""),
    };
    title_bar_wide(t, title, theme::ACCENT, true)?;
    text_left(
        t,
        purpose,
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )?;
    if v.present {
        detail_card(
            t,
            CONTENT_TOP + 28,
            &[
                ("Algorithm", v.algo.as_str(), theme::TEXT),
                ("PIN policy", v.pin_policy.as_str(), theme::MUTED),
                ("Touch policy", v.touch_policy.as_str(), theme::MUTED),
                ("Origin", v.origin.as_str(), theme::MUTED),
                (
                    "Certificate",
                    if v.cert { "Stored" } else { "None" },
                    if v.cert {
                        theme::ACCENT_TEXT
                    } else {
                        theme::CAPTION
                    },
                ),
            ],
        )
    } else {
        let hint = if v.cert {
            "Certificate stored, no key."
        } else {
            "Set it up with ykman over USB."
        };
        empty_slot(t, Glyph::Cpu, "No key in this slot", hint)
    }
}

/// The OATH list: one row per stored credential (a clock, or a padlock when touch-gated,
/// plus the label and its TOTP / HOTP type), the nav bar, and a footer reminding that
/// codes themselves are read in the host app (the device has no clock for TOTP). Paged
/// when it spans more than one screen.
pub fn render_oath<D>(t: &mut D, rows: &[OathRow], page: u16, total: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "OATH", theme::ACCENT, true)?;
    oath_body(t, rows, page, total)?;
    render_nav(t, NavTab::Apps)
}

/// Replace an OATH page body while the typed applet title and Apps navigation stay fixed.
pub fn render_oath_page<D>(
    t: &mut D,
    rows: &[OathRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    clear_region(t, PAGED_BODY_RECT)?;
    oath_body(t, rows, page, total)
}

fn oath_body<D>(t: &mut D, rows: &[OathRow], page: u16, total: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    if total == 0 {
        glyph::draw(
            t,
            Glyph::Clock,
            Point::new(MIDX as u16 - 18, 96),
            36,
            MUTED,
            BG,
        )?;
        text(
            t,
            "No codes yet",
            EgPoint::new(MIDX, 160),
            Role::Body,
            MUTED,
        )?;
    } else {
        components::list::group_card(t, PK_LIST_TOP, rows.len() as u16)?;
        for (i, r) in rows.iter().enumerate() {
            let icon = if r.touch { Glyph::Lock } else { Glyph::Clock };
            let kind = if r.hotp { "HOTP" } else { "TOTP" };
            // Each row drills into the credential's detail (algorithm / digits / period).
            components::list::row(
                t,
                PK_LIST_TOP,
                i as u16,
                icon,
                r.name.as_str(),
                Some((kind, MUTED)),
                true,
                true,
                false,
                // Host-chosen, like an rpId: a name already clipped to LABEL_MAX
                // must show it here rather than pass for a complete one.
                r.name.truncated,
            )?;
        }
        if page_count(total) > 1 {
            render_pager(t, page, page_count(total))?;
        } else {
            text(
                t,
                "Codes shown in the RS-Key app",
                EgPoint::new(MIDX, NAV_TOP as i32 - 10),
                Role::MonoSmall,
                theme::CAPTION,
            )?;
        }
    }
    Ok(())
}

/// One OATH credential's detail (back-only, no nav): its type, HMAC algorithm, digit
/// count, TOTP step and touch gate. No code is shown — the device has no clock, so it
/// cannot compute a time-correct TOTP, and reading a HOTP would burn its counter; the
/// footer points at the host app where codes are read.
pub fn render_oath_cred<D>(t: &mut D, v: &OathDetailView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide_label(t, &v.name, theme::ACCENT, true)?;
    let purpose = if v.hotp {
        "Counter-based \u{00B7} HOTP"
    } else {
        "Time-based \u{00B7} TOTP"
    };
    text_left(
        t,
        purpose,
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )?;
    let mut digit_buf = [0u8; 5];
    let mut period_buf = [0u8; 8];
    let period = if v.hotp {
        "—"
    } else {
        fmt_secs(v.period, &mut period_buf)
    };
    detail_card(
        t,
        CONTENT_TOP + 28,
        &[
            ("Type", if v.hotp { "HOTP" } else { "TOTP" }, theme::TEXT),
            ("Algorithm", v.algo.as_str(), theme::TEXT),
            (
                "Digits",
                fmt_u16(v.digits as u16, &mut digit_buf),
                theme::TEXT,
            ),
            ("Period", period, theme::MUTED),
            (
                "Touch to use",
                if v.touch { "Required" } else { "Off" },
                if v.touch {
                    theme::ACCENT_TEXT
                } else {
                    theme::MUTED
                },
            ),
        ],
    )?;
    text_left(
        t,
        "Codes shown in the RS-Key app",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
}

/// The OpenPGP card-holder detail (back-only): the public cardholder data objects, read
/// without a PIN — name, login and language in a card, the (possibly long) URL on its own
/// ellipsized line below. An empty card shows what it is and how to set it.
pub fn render_openpgp_cardholder<D>(t: &mut D, v: &CardholderView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "Card holder", theme::ACCENT, true)?;
    text_left(
        t,
        "Public card identity",
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )?;
    if !v.any {
        return empty_slot(
            t,
            Glyph::User,
            "No cardholder data",
            "Set it with gpg over USB.",
        );
    }
    // Stacked caption + value blocks. Every value is clipped/ellipsized to the panel width,
    // so a long name / login / URL can never overrun the column or draw off-panel (the
    // cardholder fields are free-form and may be near the 48-byte label cap).
    // The array carries the `Label`, not its `&str`: `rsk_openpgp`'s reader returns
    // CH_FIELD_MAX = LABEL_MAX + 1 bytes for the sole purpose of letting `Label::clamp`
    // set `truncated`, and this screen threw the flag away — so a 48-byte clip of a
    // longer value painted with no ellipsis and read as the whole thing, which is
    // exactly what audit run-34 #39 widened the reader to prevent (audit run-36).
    let fields: [(&str, &Label); 4] = [
        ("NAME", &v.name),
        ("LOGIN", &v.login),
        ("URL", &v.url),
        ("LANGUAGE", &v.lang),
    ];
    let mut y = CONTENT_TOP as i32 + 38;
    for (cap, val) in fields {
        text_left(t, cap, EgPoint::new(14, y), Role::Mono, theme::CAPTION)?;
        let (shown, color, marked) = if val.is_empty() {
            ("Not set", theme::MUTED, false)
        } else {
            (val.as_str(), theme::TEXT_2, val.truncated)
        };
        text_left_ellipsized(
            t,
            shown,
            EgPoint::new(14, y + 20),
            Role::Body,
            color,
            Rect::new(14, (y + 8) as u16, PANEL_W - 28, 24),
            marked,
        )?;
        y += 46;
    }
    Ok(())
}

/// The "Retired & F9" screen (back-only, paged): the populated retired key-management
/// slots (82–95) and the F9 attestation slot, plus a trailing "Generate key" action row
/// when a retired slot is free. Each slot row drills into the shared slot-detail; the
/// action row starts the on-device generate flow. Empty rows are not listed.
pub fn render_piv_extra<D>(
    t: &mut D,
    rows: &[PivExtraRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "Retired & F9", theme::ACCENT, true)?;
    piv_extra_body(t, rows, page, total)
}

/// Replace a Retired/F9 page body while its typed title and back affordance stay fixed.
pub fn render_piv_extra_page<D>(
    t: &mut D,
    rows: &[PivExtraRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    clear_region(t, PUSHED_BODY_RECT)?;
    piv_extra_body(t, rows, page, total)
}

fn piv_extra_body<D>(t: &mut D, rows: &[PivExtraRow], page: u16, total: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    if rows.is_empty() {
        return empty_slot(
            t,
            Glyph::Cpu,
            "All slots full",
            "Manage retired keys with ykman.",
        );
    }
    components::list::group_card(t, PK_LIST_TOP, rows.len() as u16)?;
    let mut tb = [0u8; 12];
    for (i, r) in rows.iter().enumerate() {
        if r.generate {
            // No algorithm badge: the action now offers EC / Ed25519 / X25519 / RSA, picked on
            // the next screen — any single-algo label here (it used to read "EC") would mislead.
            components::list::row(
                t,
                PK_LIST_TOP,
                i as u16,
                Glyph::Key,
                "Generate key",
                None,
                true,
                true,
                false,
                false,
            )?;
            continue;
        }
        let (icon, label) = if r.slot == 0xF9 {
            (Glyph::Shield, "F9 Attestation")
        } else {
            (Glyph::Cpu, retired_title(r.slot, &mut tb))
        };
        let trailing = if r.present {
            (r.algo.as_str(), MUTED)
        } else if r.cert {
            ("cert", theme::CAPTION)
        } else {
            ("—", theme::CAPTION)
        };
        components::list::row(
            t,
            PK_LIST_TOP,
            i as u16,
            icon,
            label,
            Some(trailing),
            true,
            true,
            false,
            false,
        )?;
    }
    if page_count(total) > 1 {
        render_pager(t, page, page_count(total))?;
    }
    Ok(())
}

/// The on-device key-generate algorithm chooser (back-only): a one-line caption naming the
/// target retired slot over a five-row list (P-256 / P-384 / Ed25519 / X25519 / RSA). The curves
/// are instant; the **RSA** row drills into [`render_piv_keygen_rsa_pick`] (2048 / 3072 / 4096),
/// each of which runs a slow dual-core prime search behind a "generating" screen. RSA-1024 (weak)
/// is not offered.
pub fn render_piv_keygen_pick<D>(t: &mut D, slot: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "New key", theme::ACCENT, true)?;
    let mut tb = [0u8; 12];
    text_left(
        t,
        retired_title(slot, &mut tb),
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )?;
    components::list::group_card(t, PIV_KEYGEN_PICK_TOP, PIV_KEYGEN_PICK_ROWS)?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        0,
        Glyph::Cpu,
        "NIST P-256",
        Some(("fast", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        1,
        Glyph::Cpu,
        "NIST P-384",
        Some(("stronger", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        2,
        Glyph::Cpu,
        "Ed25519",
        Some(("EdDSA", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        3,
        Glyph::Cpu,
        "X25519",
        Some(("ECDH", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        4,
        Glyph::Cpu,
        "RSA",
        Some(("2048-4096", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    text_left_ellipsized(
        t,
        "Generated on-device, never leaves it",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
        Rect::new(14, PANEL_H - 30, PANEL_W - 28, 24),
        false,
    )
}

/// The RSA key-size sub-picker (reached from the **RSA** row of [`render_piv_keygen_pick`]) — a
/// three-row list of RSA 2048 / 3072 / 4096. Each runs the firmware's dual-core prime search,
/// slower with size: 2048 is a few seconds, 4096 can be a minute-plus of frozen panel.
pub fn render_piv_keygen_rsa_pick<D>(t: &mut D, slot: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "RSA size", theme::ACCENT, true)?;
    let mut tb = [0u8; 12];
    text_left(
        t,
        retired_title(slot, &mut tb),
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )?;
    components::list::group_card(t, PIV_KEYGEN_PICK_TOP, PIV_RSA_PICK_ROWS)?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        0,
        Glyph::Cpu,
        "RSA 2048",
        Some(("slow", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        1,
        Glyph::Cpu,
        "RSA 3072",
        Some(("slower", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        2,
        Glyph::Cpu,
        "RSA 4096",
        Some(("slowest", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    text_left(
        t,
        "Larger keys take much longer",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
}

/// The PIV PIN/PUK sub-menu (Settings → Security → "PIV PIN"): change the PIV PIN, change the
/// PUK, or unblock a blocked PIN with the PUK. A chrome modal like the keygen picker — the
/// title-bar chevron backs out to the Security list; rows hit-test via [`crate::hit_list`] at
/// [`PIV_KEYGEN_PICK_TOP`].
pub fn render_piv_pin_menu<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar_wide(t, "PIV PIN", theme::ACCENT, true)?;
    components::list::group_card(t, PIV_KEYGEN_PICK_TOP, PIV_PIN_MENU_ROWS)?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        0,
        Glyph::Lock,
        "Change PIN",
        None,
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        1,
        Glyph::Key,
        "Change PUK",
        None,
        true,
        true,
        false,
        false,
    )?;
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        2,
        Glyph::Lifebuoy,
        "Unblock PIN",
        Some(("with PUK", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )?;
    // No trailing caption: a right-aligned hint here is laid out first and the label is
    // clipped to what's left, and "Protect mgmt key" is wide enough that any meaningful
    // caption ("random, PIN-unlocked" was 159 px) ellipsised the label to nothing. The
    // random / PIN-unlocked consequence is stated in full on the confirm screen instead.
    components::list::row(
        t,
        PIV_KEYGEN_PICK_TOP,
        3,
        Glyph::Shield,
        "Protect mgmt key",
        None,
        true,
        true,
        false,
        false,
    )?;
    text_left(
        t,
        "PIN / PUK / management key",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
}

/// The hold-to-confirm for "Protect management key" (ykman `--protect`): a chrome-less modal
/// like the keygen / delete holds. It states the consequence honestly on the trusted screen —
/// a random key replaces the current one and the PIV PIN alone then grants admin — before the
/// deliberate hold commits it.
pub fn render_piv_protect_confirm<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text(
        t,
        "Protect mgmt key?",
        EgPoint::new(MIDX, 84),
        Role::Strong,
        FG,
    )?;
    text(
        t,
        "Sets a random management key,",
        EgPoint::new(MIDX, 116),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        "unlocked by your PIV PIN.",
        EgPoint::new(MIDX, 138),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        "The PIN alone then grants admin.",
        EgPoint::new(MIDX, 170),
        Role::MonoSmall,
        theme::WARN,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to protect", theme::ACCENT_FILL)
}

/// The generate confirm screen: a deliberate hold (driven by the firmware on
/// [`crate::DEL_HOLD_RECT`], the chrome-less [`crate::PK_BACK_RECT`] chevron cancels)
/// before an EC key is written into the named retired slot.
pub fn render_piv_keygen_confirm<D>(t: &mut D, slot: u8, algo: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    // A full-screen confirm modal like the delete / factory / seal holds: chrome-less (no
    // status bar), so the top-left PK_BACK_RECT cancel chevron stands alone — drawing the
    // status bar here put "RS-Key" behind that chevron (PK_BACK_RECT starts at y=6).
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text(t, "Generate key?", EgPoint::new(MIDX, 92), Role::Strong, FG)?;
    let mut tb = [0u8; 12];
    text(
        t,
        retired_title(slot, &mut tb),
        EgPoint::new(MIDX, 122),
        Role::Body,
        MUTED,
    )?;
    text(t, algo, EgPoint::new(MIDX, 146), Role::Body, theme::TEXT_2)?;
    // Says what the write is fenced to, not "erases nothing": the generate also writes
    // the slot's self-signed certificate, so the promise only holds because
    // `next_free_retired` skips a slot that already has one.
    text(
        t,
        "Adds a key to an empty slot.",
        EgPoint::new(MIDX, 172),
        Role::MonoSmall,
        theme::CAPTION,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to generate", theme::ACCENT_FILL)
}

/// The "generating" screen shown while an on-device RSA prime search runs. This paints the
/// full frame once (spinner ring + label); the search itself is a blocking dual-core busy-loop,
/// so the firmware can't repaint from a loop — instead it spins just the indicator arc
/// ([`render_status_arc`]) from the search's per-candidate hook, so the screen reads as actively
/// working rather than hung. USB / CCID keepalives stay interrupt-driven throughout.
pub fn render_piv_keygen_working<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    render_status_arc(t, StatusKind::Processing, STATUS_ARC_START)?;
    text(
        t,
        "Generating key...",
        EgPoint::new(MIDX, 158),
        Role::Heading,
        FG,
    )?;
    text(
        t,
        "This can take a while",
        EgPoint::new(MIDX, 186),
        Role::MonoSmall,
        theme::CAPTION,
    )
}
