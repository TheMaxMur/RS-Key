// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::device::MockProvider;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn buffer_text(app: &App, w: u16, h: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render(f, app)).unwrap();
    let buf = term.backend().buffer().clone();
    buf.content().iter().map(|c| c.symbol()).collect()
}

fn demo_app() -> App {
    App::new(
        Box::new(MockProvider::new()),
        Theme {
            ascii: true,
            depth: crate::theme::Depth::Basic,
        },
    )
}

#[test]
fn renders_demo_overview() {
    let app = demo_app();
    let text = buffer_text(&app, 100, 40);
    assert!(text.contains("rs-key"));
    assert!(text.contains("Overview"));
    assert!(text.contains("DEMO"));
    assert!(text.contains("firmware"));
}

#[test]
fn renders_new_metadata_sections_in_demo() {
    let mut app = demo_app();
    // LED preview: the idle colour name from the demo snapshot (idx 6 = cyan).
    app.set_section(Section::Led);
    let t = buffer_text(&app, 100, 40);
    assert!(
        t.contains("idle") && t.contains("cyan"),
        "LED preview missing"
    );
    // OpenPGP: parsed serial + retry counters.
    app.set_section(Section::OpenPgp);
    let t = buffer_text(&app, 100, 40);
    assert!(t.contains("2a1b3c4d"), "OpenPGP serial missing");
    assert!(t.contains("PIN retries"), "OpenPGP retries missing");
    // PIV: PIN tries from GET METADATA.
    app.set_section(Section::Piv);
    assert!(
        buffer_text(&app, 100, 40).contains("tries"),
        "PIV PIN missing"
    );
    // FIDO: the credMgmt count action is offered.
    app.set_section(Section::Fido);
    assert!(
        buffer_text(&app, 100, 40).contains("Count resident passkeys"),
        "credMgmt count action missing"
    );
}

#[test]
fn renders_at_tiny_size_without_panicking() {
    // Below the log / 2-line-status thresholds — must still paint.
    let app = demo_app();
    for (w, h) in [(40, 8), (24, 6), (10, 3), (80, 1)] {
        let _ = buffer_text(&app, w, h);
    }
}

#[test]
fn modal_and_search_paint_at_tiny_size() {
    // A Message modal / Search overlay on a terminal shorter than the modal's
    // preferred height must not panic (regression: clamp(min, max<min)).
    let mut app = demo_app();
    app.open_message("t".into(), "a\nb\nc\nd\ne\nf".into(), LogLevel::Warn);
    for (w, h) in [(40, 4), (20, 3), (60, 2)] {
        let _ = buffer_text(&app, w, h);
    }
    app.open_search();
    for (w, h) in [(40, 4), (20, 3)] {
        let _ = buffer_text(&app, w, h);
    }
}

#[test]
fn reveal_modal_shows_seed_but_log_does_not() {
    let mut app = demo_app();
    // Drive export: confirm EXPORT, enter a PIN, run.
    app.begin_action(Action::BackupExport);
    if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut app.mode {
        *buf = "EXPORT".into();
    }
    app.submit_modal();
    if let AppMode::Modal(Modal::Input { buf, .. }) = &mut app.mode {
        *buf = "1234".into();
    }
    let _ = app.submit_modal(); // returns Run(BackupExport)
    let input = std::mem::take(&mut app.staging);
    let result = app.provider.run(Action::BackupExport, &input);
    drop(input);
    if let ActionResult::Reveal { title, body } = result {
        let words = body.to_string();
        app.open_reveal(title, body);
        app.log(LogLevel::Good, "seed exported — on screen, not logged");
        // The reveal modal renders the mnemonic…
        let screen = buffer_text(&app, 100, 40);
        assert!(screen.contains(words.split(' ').next().unwrap()));
        // …but no log entry ever contains any of it.
        for w in words.split(' ') {
            for entry in app.log.iter() {
                assert!(!entry.text.contains(w), "log leaked seed word {w}");
            }
        }
    } else {
        panic!("expected a reveal");
    }
}

// --- a hostile device cannot author or hide a status row (audit run-34 #10) ---

/// The screen as the operator reads it: one string per painted line, so a row
/// forged out of a wrapped continuation is visible as its own line here.
fn buffer_lines(app: &App, w: u16, h: u16) -> Vec<String> {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render(f, app)).unwrap();
    let buf = term.backend().buffer().clone();
    buf.content()
        .chunks(w as usize)
        .map(|r| r.iter().map(|c| c.symbol()).collect())
        .collect()
}

/// The forgery from the finding, with a tail nothing genuine paints:
/// `fido.versions` is a device-supplied list, and with wrapping on its
/// continuation started at column 0 and read as a row of its own.
const FORGED: &str = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV\
                      clientPIN     set (attacker)";

#[test]
fn a_long_device_value_cannot_paint_a_row_of_its_own() {
    let mut app = demo_app();
    app.snapshot.fido.versions = vec![FORGED.into()];
    app.set_section(Section::Fido);
    let lines = buffer_lines(&app, 100, 40);
    let genuine = lines.iter().filter(|l| l.contains("clientPIN")).count();
    assert_eq!(
        genuine, 1,
        "clientPIN appears on {genuine} lines: {lines:#?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("(attacker)")),
        "the payload's tail reached the screen"
    );
    // The visible part is clipped to the pane, and the marker says it was cut.
    let carrier = lines
        .iter()
        .find(|l| l.contains("VVVV"))
        .expect("the versions row is gone");
    assert!(
        carrier.contains('…'),
        "clipped without a marker: {carrier:?}"
    );
}

#[test]
fn clip_to_width_marks_the_cut_and_keeps_the_prefix() {
    let line = Line::from(vec![Span::raw("key  "), Span::raw("0123456789")]);
    assert_eq!(
        clip_to_width(vec![line.clone()], 15)[0].to_string(),
        "key  0123456789"
    );
    assert_eq!(
        clip_to_width(vec![line.clone()], 10)[0].to_string(),
        "key  0123…"
    );
    // The cut can land on a span boundary, and a 1-column pane must not underflow.
    assert_eq!(clip_to_width(vec![line.clone()], 5)[0].to_string(), "key …");
    assert_eq!(clip_to_width(vec![line.clone()], 1)[0].to_string(), "…");
    assert_eq!(
        clip_to_width(vec![line], 0)[0].to_string(),
        "key  0123456789"
    );
}

#[test]
fn a_long_device_value_cannot_push_rows_off_the_pane() {
    let mut app = demo_app();
    app.set_section(Section::Overview);
    let clean = buffer_text(&app, 100, 40);
    // `transport.note` is built from PC/SC reader names — USB iProduct strings.
    app.snapshot.transport.note = Some("x".repeat(4000));
    let hostile = buffer_text(&app, 100, 40);
    // The rows *below* the note: these are the ones a wrapped value shoved off,
    // and every one of them is a security verdict the operator came here to read.
    for anchor in ["anti-rollback", "org attest", "flash"] {
        assert!(
            clean.contains(anchor),
            "{anchor} missing from the clean render"
        );
        assert!(
            hostile.contains(anchor),
            "{anchor} was pushed off the pane by a device-supplied value"
        );
    }
}

#[test]
fn rows_that_do_not_fit_are_counted_not_dropped() {
    let lines: Vec<Line<'static>> = (0..10).map(|i| Line::from(format!("row {i}"))).collect();
    // Fits: unchanged.
    assert_eq!(overflow_marked(lines.clone(), 10).len(), 10);
    // Does not fit: 4 rows shown, the 5th says how many are hidden.
    let cut = overflow_marked(lines.clone(), 5);
    assert_eq!(cut.len(), 5);
    assert!(cut[3].to_string().contains("row 3"));
    assert!(cut[4].to_string().contains("6 more row(s)"), "{:?}", cut[4]);
    // A zero-height pane must not panic or underflow.
    assert_eq!(overflow_marked(lines, 0).len(), 10);
}

/// Audit run-35: the clipping marker has to be placed in the unit ratatui renders
/// in. Measuring `chars()` under-counted every double-width grapheme by half, so a
/// device-supplied fullwidth string was cut at the pane edge with its "…" pushed
/// off-screen — the marker suppressed exactly when it matters.
#[test]
fn clip_to_width_measures_display_columns_not_chars() {
    // 30 fullwidth characters = 60 display columns, but only 30 `chars()`.
    let wide: String = "Ｘ".repeat(30);
    let line = Line::from(vec![Span::raw(wide)]);
    let out = clip_to_width(vec![line], 20);
    let w: usize = out[0].spans.iter().map(|s| s.width()).sum();
    assert!(
        w <= 20,
        "clipped line is {w} display columns wide, pane has 20"
    );
    let text: String = out[0].spans.iter().map(|s| s.content.as_ref()).collect();
    assert!(
        text.ends_with('…'),
        "the truncation marker must survive inside the pane, got {text:?}"
    );
}
