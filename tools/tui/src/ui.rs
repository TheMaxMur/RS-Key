// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Rendering only — no state mutation, no device I/O. Takes `&App` and paints a
//! frame. The layout adapts to the terminal size: the sidebar narrows and the
//! event panel drops away on small screens.

use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};

use crate::app::{App, AppMode, Modal, Search};
use crate::device::COLORS;
use crate::model::*;
use crate::theme::{Theme, bold, dim};

/// A rounded, muted-border panel — the shared frame for every box.
fn frame(theme: Theme) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border_style())
}

/// A framed panel with an accented title (surrounding spaces added).
fn titled(theme: Theme, title: &str) -> Block<'static> {
    frame(theme).title(Span::styled(format!(" {title} "), theme.title_style()))
}

pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    let theme = app.theme;

    // Outer rows: header, body, [event log], status bar. The main panel is the
    // priority, so the event log stays modest and drops away on short screens.
    let show_log = area.height >= 16;
    let two_line_status = area.height >= 9;
    let status_h = if two_line_status { 2 } else { 1 };
    let log_h = if show_log {
        (area.height / 5).clamp(3, 6)
    } else {
        0
    };
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(log_h),
        Constraint::Length(status_h),
    ])
    .split(area);

    header(f, app, theme, rows[0]);
    body(f, app, theme, rows[1]);
    if show_log {
        event_log(f, app, theme, rows[2]);
    }
    status_bar(f, app, theme, rows[3], two_line_status);

    match &app.mode {
        AppMode::Modal(m) => modal(f, theme, m),
        AppMode::Search(s) => search_overlay(f, theme, s),
        AppMode::Normal => {}
    }
}

fn header(f: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let snap = &app.snapshot;
    let health = snap.overall_health();
    let mut spans = vec![
        Span::styled(" rs-key ", theme.chip_style()),
        Span::raw(" cockpit  "),
        Span::styled(theme.dot(health), theme.health_style(health)),
        Span::raw(" "),
        Span::styled(health.word(), theme.health_style(health)),
        Span::raw("  "),
        Span::raw(snap.summary()),
    ];
    if snap.demo {
        spans.push(Span::styled(
            "  [DEMO]",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        format!("   refreshed {}s ago", app.refreshed.elapsed().as_secs()),
        dim(),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)).block(frame(theme)), area);
}

fn body(f: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let sidebar_w = if area.width >= 72 { 24 } else { 16 };
    let cols = Layout::horizontal([Constraint::Length(sidebar_w), Constraint::Min(20)]).split(area);
    sidebar(f, app, theme, cols[0]);
    panel(f, app, theme, cols[1]);
}

fn sidebar(f: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let items: Vec<ListItem> = Section::ALL
        .iter()
        .map(|s| {
            let h = section_health(*s, &app.snapshot);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", theme.dot(h)), theme.health_style(h)),
                Span::raw(s.title()),
            ]))
        })
        .collect();
    let mut st = ListState::default();
    st.select(Section::ALL.iter().position(|s| *s == app.section));
    f.render_stateful_widget(
        List::new(items)
            .block(titled(theme, "sections"))
            .highlight_style(theme.selection())
            .highlight_symbol(theme.arrow()),
        area,
        &mut st,
    );
}

fn panel(f: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let block = titled(theme, app.section.title());
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.section == Section::Help {
        f.render_widget(
            Paragraph::new(help_lines()).wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }

    let menu = app.menu();
    let menu_h = (menu.len() as u16 + 2).min(inner.height.saturating_sub(3));
    let split = Layout::vertical([Constraint::Min(3), Constraint::Length(menu_h)]).split(inner);

    // No wrap: a wrapped continuation starts at column 0, exactly where a genuine
    // row starts, so a long device-supplied value could paint a row of its own —
    // and the extra lines pushed the rows below it off the pane, which has no
    // scrollbar and no keys bound to it (audit run-34 #10). One row, one line;
    // what does not fit is marked, in the line and in the count.
    let lines = clip_to_width(section_status_lines(app, theme), split[0].width);
    f.render_widget(
        Paragraph::new(overflow_marked(lines, split[0].height)),
        split[0],
    );

    let items: Vec<ListItem> = menu
        .iter()
        .map(|it| {
            let faded = matches!(
                it.kind,
                crate::app::MenuKind::Note { .. } | crate::app::MenuKind::Disabled(_)
            );
            let label_style = if faded { dim() } else { Style::default() };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", theme.dot(it.health)),
                    theme.health_style(it.health),
                ),
                Span::styled(it.label.clone(), label_style),
                Span::styled(format!("  · {}", it.hint), dim()),
            ]))
        })
        .collect();
    let mut st = ListState::default();
    if !menu.is_empty() {
        st.select(Some(app.menu_sel.min(menu.len() - 1)));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(titled(theme, "actions"))
            .highlight_style(theme.selection())
            .highlight_symbol(theme.arrow()),
        split[1],
        &mut st,
    );
}

// ---- per-section status content ----

/// Cut every line to the pane width, marking what was dropped. The values on
/// these rows are device-supplied (USB descriptor strings, getInfo fields, PC/SC
/// reader names); the terminal would clip them anyway, so the marker is what
/// tells the reader a value they are judging the device by is not all of it.
fn clip_to_width(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let w = width as usize;
    if w == 0 {
        return lines;
    }
    lines
        .into_iter()
        .map(|line| {
            if line.spans.iter().map(span_len).sum::<usize>() <= w {
                return line;
            }
            let (mut used, mut spans) = (0usize, Vec::new());
            for span in line.spans {
                let len = span_len(&span);
                if used + len < w {
                    used += len;
                    spans.push(span);
                    continue;
                }
                let head: String = span.content.chars().take(w - 1 - used).collect();
                spans.push(Span::styled(head, span.style));
                spans.push(Span::styled("…", dim()));
                break;
            }
            Line::from(spans)
        })
        .collect()
}

fn span_len(s: &Span<'_>) -> usize {
    s.content.chars().count()
}

/// Replace the last visible line with a count when the section does not fit.
/// Cut rows are unreachable — the pane has no scroll state and `input.rs` binds
/// ↑↓/jk to the action list — so silently dropping them reads as "that is all".
fn overflow_marked(mut lines: Vec<Line<'static>>, height: u16) -> Vec<Line<'static>> {
    let h = height as usize;
    if h == 0 || lines.len() <= h {
        return lines;
    }
    let hidden = lines.len() - (h - 1);
    lines.truncate(h - 1);
    lines.push(Line::from(Span::styled(
        format!(" … {hidden} more row(s) — enlarge the terminal"),
        dim(),
    )));
    lines
}

fn row(theme: Theme, h: Health, key: &str, value: impl Into<String>) -> Line<'static> {
    let vstyle = match h {
        Health::Warn => theme.warn(),
        Health::Error => theme.danger(),
        _ => Style::default(),
    };
    Line::from(vec![
        Span::styled(format!(" {} ", theme.dot(h)), theme.health_style(h)),
        Span::styled(format!("{key:<14}"), dim()),
        Span::styled(value.into(), vstyle),
    ])
}

fn head(text: &str) -> Line<'static> {
    Line::from(Span::styled(text.to_string(), bold()))
}

/// The firmware's 8-colour wheel index → a terminal colour. Named ANSI colours
/// (not the brand palette) so the swatch matches the LED's actual colour and
/// adapts to the user's terminal; `0` = off = a muted block.
fn led_color(idx: u8) -> Color {
    match idx {
        1 => Color::Red,
        2 => Color::Green,
        3 => Color::Blue,
        4 => Color::Yellow,
        5 => Color::Magenta,
        6 => Color::Cyan,
        7 => Color::White,
        _ => Color::DarkGray,
    }
}

/// One LED status row: a solid colour swatch (background fill, so it shows with
/// no glyph support) plus the colour name (the always-legible signal).
fn led_row(name: &str, idx: u8) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!(" {name:<13}")),
        Span::styled("   ", Style::default().bg(led_color(idx))),
        Span::raw(format!(
            "  {}",
            COLORS.get(idx as usize).copied().unwrap_or("?")
        )),
    ])
}

fn opt(s: &Option<String>) -> String {
    s.clone().unwrap_or_else(|| "—".into())
}

fn section_status_lines(app: &App, theme: Theme) -> Vec<Line<'static>> {
    let s = &app.snapshot;
    let mut out = Vec::new();
    match app.section {
        Section::Overview => {
            out.push(head("Identity"));
            let idh = if s.identity.serial.is_some() || s.identity.firmware.is_some() {
                Health::Ok
            } else {
                Health::Unknown
            };
            out.push(row(theme, idh, "serial", opt(&s.identity.serial)));
            out.push(row(theme, idh, "firmware", opt(&s.identity.firmware)));
            out.push(row(
                theme,
                idh,
                "bcdDevice",
                s.identity
                    .bcd_device
                    .map(|b| format!("{b:#06x}"))
                    .unwrap_or_else(|| "—".into()),
            ));
            out.push(row(theme, idh, "sdk", opt(&s.identity.sdk)));
            out.push(row(
                theme,
                Health::Unknown,
                "aaguid",
                s.identity
                    .aaguid
                    .as_ref()
                    .map(|a| a.chars().take(16).collect::<String>() + "…")
                    .unwrap_or_else(|| "—".into()),
            ));
            out.push(Line::from(""));
            out.push(head("Transports"));
            out.push(row(
                theme,
                s.transport.hid.health(),
                "FIDO HID",
                s.transport.hid.word(),
            ));
            out.push(row(
                theme,
                s.transport.pcsc.health(),
                "PC/SC",
                s.transport.pcsc.word(),
            ));
            out.push(row(
                theme,
                s.transport.ccid.health(),
                "CCID applet",
                s.transport.ccid.word(),
            ));
            if let Some(note) = &s.transport.note {
                out.push(row(theme, Health::Warn, "", note.clone()));
            }
            out.push(Line::from(""));
            out.push(head("Security"));
            security_lines(theme, s, &mut out);
        }
        Section::Fido => {
            out.push(head("CTAPHID"));
            out.push(row(
                theme,
                s.transport.hid.health(),
                "present",
                if s.fido.present { "yes" } else { "no" },
            ));
            out.push(row(
                theme,
                Health::Ok,
                "versions",
                s.fido.versions.join(", "),
            ));
            let (ph, pv) = match s.fido.client_pin {
                Some(true) => (Health::Ok, "set"),
                Some(false) => (Health::Warn, "not set (recommended)"),
                None => (Health::Unknown, "unknown"),
            };
            out.push(row(theme, ph, "clientPIN", pv));
            out.push(row(
                theme,
                Health::Unknown,
                "options",
                s.fido.options.join(", "),
            ));
            out.push(Line::from(""));
            out.push(head("Resident keys"));
            out.push(row(
                theme,
                Health::NotApplicable,
                "credentials",
                "run “Count resident passkeys” (PIN · credMgmt)",
            ));
        }
        Section::OpenPgp => {
            out.push(head("OpenPGP card"));
            let (h, v) = present_health(s.applets.openpgp);
            out.push(row(theme, h, "applet", v));
            if let Some(p) = &s.pgp {
                if let Some(sn) = &p.serial {
                    out.push(row(theme, Health::Ok, "serial", sn.clone()));
                }
                if let Some(r) = p.pin_retries {
                    let h = if r[0] == 0 || r[2] == 0 {
                        Health::Warn
                    } else {
                        Health::Ok
                    };
                    out.push(row(
                        theme,
                        h,
                        "PIN retries",
                        format!("PW1 {}  RC {}  PW3 {}", r[0], r[1], r[2]),
                    ));
                }
                out.push(row(
                    theme,
                    if p.keys_present > 0 {
                        Health::Ok
                    } else {
                        Health::Unknown
                    },
                    "keys",
                    format!("{} of 3 slots populated", p.keys_present),
                ));
            }
            out.push(row(
                theme,
                Health::NotApplicable,
                "full data",
                "gpg --card-status",
            ));
        }
        Section::Piv => {
            out.push(head("PIV applet"));
            let (h, v) = present_health(s.applets.piv);
            out.push(row(theme, h, "applet", v));
            if let Some(p) = s.piv_meta {
                let h = if p.pin_left == 0 {
                    Health::Error
                } else if p.pin_default {
                    Health::Warn
                } else {
                    Health::Ok
                };
                out.push(row(
                    theme,
                    h,
                    "PIN",
                    format!(
                        "{}/{} tries{}",
                        p.pin_left,
                        p.pin_total,
                        if p.pin_default {
                            " · still default"
                        } else {
                            ""
                        }
                    ),
                ));
            }
            out.push(row(
                theme,
                Health::NotApplicable,
                "full data",
                "ykman piv info",
            ));
        }
        Section::OathOtp => {
            out.push(head("OATH / Yubico-OTP"));
            let (ho, vo) = present_health(s.applets.oath);
            out.push(row(theme, ho, "OATH", vo));
            let (ht, vt) = present_health(s.applets.otp);
            out.push(row(theme, ht, "Yubico-OTP", vt));
            out.push(row(
                theme,
                Health::NotApplicable,
                "codes",
                "ykman oath accounts",
            ));
        }
        Section::Backup => {
            out.push(head("Seed backup"));
            match s.backup {
                Some(b) => {
                    out.push(row(
                        theme,
                        if b.has_seed { Health::Ok } else { Health::Warn },
                        "has seed",
                        if b.has_seed { "yes" } else { "no" },
                    ));
                    out.push(row(
                        theme,
                        if b.sealed { Health::Warn } else { Health::Ok },
                        "export window",
                        if b.sealed {
                            "sealed (reset to reopen)"
                        } else {
                            "open"
                        },
                    ));
                }
                None => out.push(row(theme, Health::Unknown, "state", "—")),
            }
            if let Some(l) = s.lock {
                out.push(row(
                    theme,
                    if l.locked && !l.unlocked {
                        Health::Warn
                    } else {
                        Health::Ok
                    },
                    "seed lock",
                    lock_text(l),
                ));
            }
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                "BIP-39 (24 words) here; SLIP-39 stays in the CLI. The phrase is shown",
                dim(),
            )));
            out.push(Line::from(Span::styled(
                "on screen, zeroized on close, and never written to the log.",
                dim(),
            )));
        }
        Section::Led => {
            out.push(head("LED"));
            match &s.led {
                Some(led) => {
                    out.push(row(
                        theme,
                        Health::Ok,
                        "mode",
                        if led.steady { "steady" } else { "blink" },
                    ));
                    out.push(led_row("idle", led.idle));
                    out.push(led_row("processing", led.processing));
                    out.push(led_row("touch", led.touch));
                    out.push(led_row("boot", led.boot));
                }
                None => out.push(row(
                    theme,
                    Health::NotApplicable,
                    "state",
                    "refresh with a device present, or run “Read LED state”",
                )),
            }
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                "Cycle steps the idle color through the 7-color wheel; it persists in flash.",
                dim(),
            )));
        }
        Section::Audit => {
            out.push(head("Audit journal"));
            out.push(row(
                theme,
                Health::NotApplicable,
                "journal",
                "read it from the menu (PIN if one is set)",
            ));
            out.push(row(
                theme,
                attest_health(s),
                "checkpoint key",
                match &s.attestation {
                    Some(a) if a.installed => "org key installed",
                    _ => "DEVK-derived (run Verify)",
                },
            ));
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                "Verify signs a fresh challenge with the device’s P-256 attestation key;",
                dim(),
            )));
            out.push(Line::from(Span::styled(
                "the signature is checked here. Full chain proof: `rsk audit verify`.",
                dim(),
            )));
        }
        Section::Reboot => {
            out.push(head("Reboot / Maintenance"));
            out.push(row(theme, Health::Ok, "device", s.summary()));
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                "Reboot → app is a warm restart. Reboot → BOOTSEL drops to firmware-update",
                dim(),
            )));
            out.push(Line::from(Span::styled(
                "mode (confirm required). Lock / attestation / fuse rituals stay CLI-only —",
                dim(),
            )));
            out.push(Line::from(Span::styled(
                "see the menu below for the exact commands.",
                dim(),
            )));
        }
        Section::Help => {}
    }
    if !s.errors.is_empty() {
        out.push(Line::from(""));
        out.push(head("Notes"));
        for e in &s.errors {
            out.push(row(theme, Health::Warn, "", e.clone()));
        }
    }
    out
}

fn security_lines(theme: Theme, s: &DeviceSnapshot, out: &mut Vec<Line<'static>>) {
    // The classification lives in the model as typed `FeatureStatus` rows; here
    // we only paint them.
    for fs in s.security_status() {
        out.push(row(theme, fs.health, &fs.key, fs.value));
    }
}

fn lock_text(l: LockState) -> String {
    l.describe().into()
}

fn attest_health(s: &DeviceSnapshot) -> Health {
    match &s.attestation {
        Some(a) if a.installed => Health::Ok,
        _ => Health::NotApplicable,
    }
}

/// Worst-of health for a section, shown as the sidebar dot.
fn section_health(section: Section, s: &DeviceSnapshot) -> Health {
    let connected = s.any_device();
    match section {
        Section::Overview => s.overall_health(),
        Section::Fido => match s.fido.client_pin {
            _ if !s.fido.present => Health::Unknown,
            Some(false) => Health::Warn,
            _ => Health::Ok,
        },
        Section::OpenPgp => present_health(s.applets.openpgp).0,
        Section::Piv => present_health(s.applets.piv).0,
        Section::OathOtp => present_health(s.applets.oath).0,
        Section::Backup => match s.backup {
            Some(b) if !b.has_seed => Health::Warn,
            Some(_) => Health::Ok,
            None => Health::Unknown,
        },
        Section::Led | Section::Audit | Section::Reboot => {
            if connected {
                Health::Ok
            } else {
                Health::Unknown
            }
        }
        Section::Help => Health::Ok,
    }
}

// ---- event log + status bar ----

fn event_log(f: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let block = titled(theme, "events");
    let inner = block.inner(area);
    f.render_widget(block, area);
    if app.log.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(" no events yet", dim()))),
            inner,
        );
        return;
    }
    let cap = inner.height as usize;
    let total = app.log.len();
    let lines: Vec<Line> = app
        .log
        .iter()
        .skip(total.saturating_sub(cap))
        .map(|e| Line::from(Span::styled(e.text.clone(), theme.log_style(e.level))))
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn status_bar(f: &mut Frame, app: &App, theme: Theme, area: Rect, two_line: bool) {
    let rows = if two_line {
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area)
    } else {
        Layout::vertical([Constraint::Length(1)]).split(area)
    };
    let result = if app.status.is_empty() {
        Line::from(Span::styled(" ready", dim()))
    } else {
        Line::from(Span::styled(
            format!(" {}", app.status),
            theme.log_style(app.status_level),
        ))
    };
    f.render_widget(Paragraph::new(result), rows[0]);
    if two_line {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(keybinds(app), dim()))),
            rows[1],
        );
    }
}

fn keybinds(app: &App) -> String {
    match &app.mode {
        AppMode::Normal => {
            " Tab/←→ section   ↑↓/jk move   ↵ run   r refresh   / search   ? help   q quit ".into()
        }
        AppMode::Search(_) => " type to filter   ↑↓ move   ↵ run   esc cancel ".into(),
        AppMode::Modal(Modal::Input { mask: true, .. }) => {
            " type PIN (hidden)   ↵ confirm   esc cancel ".into()
        }
        AppMode::Modal(Modal::Input { .. }) => " type   ↵ confirm   esc cancel ".into(),
        AppMode::Modal(Modal::Confirm { want, .. }) => {
            format!(" type {want} to confirm   ↵ confirm   esc cancel ")
        }
        AppMode::Modal(Modal::YesNo { .. }) => " y confirm   n/esc cancel ".into(),
        AppMode::Modal(Modal::Reveal { .. }) => {
            " write it down   any key clears the screen ".into()
        }
        AppMode::Modal(Modal::Message { .. }) => {
            " ↑↓/jk scroll   PgUp/PgDn page   ↵/esc/q close ".into()
        }
    }
}

// ---- overlays ----

fn centered(area: Rect, pct_x: u16, lines: u16) -> Rect {
    // u32 math: width * pct can exceed u16 on an ultrawide terminal.
    let w = ((area.width as u32 * pct_x as u32 / 100) as u16).clamp(20.min(area.width), area.width);
    let h = lines.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    }
}

fn modal(f: &mut Frame, theme: Theme, m: &Modal) {
    let area = f.area();
    match m {
        Modal::Input {
            title,
            prompt,
            buf,
            mask,
            ..
        } => {
            let shown = if *mask {
                "•".repeat(buf.chars().count())
            } else {
                buf.clone()
            };
            let r = centered(area, 72, 6);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(format!("  {prompt}"), dim())),
                    Line::from(""),
                    Line::from(format!("  {shown}_")),
                ])
                .block(titled(theme, title))
                .wrap(Wrap { trim: false }),
                r,
            );
        }
        Modal::Confirm {
            title,
            body,
            want,
            buf,
            ..
        } => {
            let r = centered(area, 76, 10);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(body.clone(), theme.warn())),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(format!("  type {want} : "), bold()),
                        Span::raw(format!("{buf}_")),
                    ]),
                ])
                .block(titled(theme, title).border_style(theme.warn()))
                .wrap(Wrap { trim: true }),
                r,
            );
        }
        Modal::YesNo { title, body, .. } => {
            let r = centered(area, 70, 8);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(body.clone()),
                    Line::from(""),
                    Line::from(Span::styled("  [y] yes    [n] no", bold())),
                ])
                .block(titled(theme, title))
                .wrap(Wrap { trim: true }),
                r,
            );
        }
        Modal::Reveal { title, body } => {
            // Grow to the body (SLIP-39 spans several shares) but never shrink
            // below the single-line BIP-39 layout; clamp to the screen.
            let lines = (body.lines().count() as u16 + 6)
                .max(11)
                .min(area.height.saturating_sub(2))
                .max(3);
            let r = centered(area, 88, lines);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(
                        "  WRITE THIS DOWN — the only backup of your FIDO seed.",
                        theme.warn(),
                    )),
                    Line::from(Span::styled(
                        "  Not logged. Cleared from the screen on the next key.",
                        dim(),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("  {}", body.as_str()),
                        theme.health_style(Health::Ok),
                    )),
                ])
                .block(titled(theme, title))
                .wrap(Wrap { trim: true }),
                r,
            );
        }
        Modal::Message {
            title,
            body,
            level,
            scroll,
        } => {
            let total = body.lines().count() as u16;
            // Never clamp(min, max) with max<min: a short terminal makes the
            // available height smaller than the preferred minimum.
            let lines: u16 = (total + 4).min(area.height.saturating_sub(2)).max(3);
            let r = centered(area, 84, lines);
            f.render_widget(Clear, r);
            let style = theme.log_style(*level);
            // Inner text height = box minus the top+bottom border; clamp the offset
            // so the last page sits at the bottom instead of scrolling into blank.
            let view = r.height.saturating_sub(2);
            let max_scroll = total.saturating_sub(view);
            let off = (*scroll).min(max_scroll);
            let title = if max_scroll > 0 {
                format!("{title}  [{}/{}]", off + 1, max_scroll + 1)
            } else {
                title.clone()
            };
            f.render_widget(
                Paragraph::new(
                    body.lines()
                        .map(|l| Line::from(Span::styled(format!(" {l}"), style)))
                        .collect::<Vec<_>>(),
                )
                .block(titled(theme, &title))
                .wrap(Wrap { trim: false })
                .scroll((off, 0)),
                r,
            );
        }
    }
}

fn search_overlay(f: &mut Frame, theme: Theme, s: &Search) {
    let area = f.area();
    let results = App::search_results(&s.query);
    let h = (results.len() as u16 + 4)
        .min(area.height.saturating_sub(2))
        .max(3);
    let r = centered(area, 70, h);
    f.render_widget(Clear, r);
    let block = titled(theme, "search actions");
    let inner = block.inner(r);
    f.render_widget(block, r);
    let rows = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(inner);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!(" > {}_", s.query)),
            Line::from(Span::styled(" ─────────────", dim())),
        ]),
        rows[0],
    );
    let items: Vec<ListItem> = results
        .iter()
        .map(|a| ListItem::new(format!("  {}", a.label())))
        .collect();
    let mut st = ListState::default();
    if !results.is_empty() {
        st.select(Some(s.sel.min(results.len() - 1)));
    }
    f.render_stateful_widget(
        List::new(items)
            .highlight_style(theme.selection())
            .highlight_symbol(theme.arrow()),
        rows[1],
        &mut st,
    );
}

// ---- help text ----

fn help_lines() -> Vec<Line<'static>> {
    let b = |s: &str| Line::from(Span::styled(s.to_string(), bold()));
    let p = |s: &str| Line::from(s.to_string());
    let d = |s: &str| Line::from(Span::styled(s.to_string(), dim()));
    vec![
        b("Key bindings"),
        p("  Tab / Shift-Tab, ← / →    switch section"),
        p("  ↑ ↓  or  j k              move selection in the action list"),
        p("  Enter                     run the selected action"),
        p("  r                         refresh device status"),
        p("  /                         search actions across all sections"),
        p("  ?                         this help"),
        p("  Esc                       cancel a modal / input"),
        p("  q  or  Ctrl-C             quit (terminal restored on exit)"),
        Line::from(""),
        b("Sections"),
        p("  Overview   identity, transports, headline security state"),
        p("  FIDO       CTAPHID presence, versions, clientPIN status"),
        p("  OpenPGP    card presence (full data via gpg)"),
        p("  PIV        applet presence (full data via ykman/opensc)"),
        p("  OATH/OTP   applet presence"),
        p("  Backup     export / restore / seal the FIDO seed (BIP-39)"),
        p("  LED        read / cycle the idle color"),
        p("  Audit      read the journal; verify the signed checkpoint"),
        p("  Reboot     warm restart / BOOTSEL; CLI-only maintenance pointers"),
        Line::from(""),
        b("Safety model"),
        d("  • Destructive / irreversible ops require a typed confirmation."),
        d("  • PINs are masked and never written to the log."),
        d("  • The seed is shown only after you confirm export, then zeroized;"),
        d("    it never reaches the event log or any file."),
        d("  • Production fuse / secure-boot / factory-reset rituals are left to"),
        d("    the `rsk` CLI — this dashboard never performs them."),
    ]
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
