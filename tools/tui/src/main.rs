// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! rsk-tui — a self-contained ratatui cockpit for rs-key.
//!
//! Talks to the key directly (CTAPHID over hidapi + the CCID applets over PC/SC,
//! see `device.rs`) — no external processes. A live, sectioned dashboard plus
//! in-band actions, including a native seed backup (MSE channel + clientPIN
//! token + BIP-39, all in Rust). The SLIP-39 export and the picotool/BOOTSEL
//! fuse rituals stay in the `rsk` CLI.
//!
//!     rsk-tui            # interactive cockpit
//!     rsk-tui --demo     # same UI, simulated device (no hardware)
//!     rsk-tui --once     # print the gathered status once and exit
//!     rsk-tui --identify # blink the indicator so you can tell this key apart
//!     rsk-tui --json     # one-shot machine-readable status
//!     rsk-tui --selftest # native backup round-trip self-test (no-touch build)

mod actions;
mod app;
mod device;
mod input;
mod model;
mod theme;
mod ui;

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crossterm::cursor;
use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use app::{App, AppMode, Flow};
use device::{DeviceProvider, HardwareProvider, MockProvider};
use theme::Theme;

pub type Term = Terminal<CrosstermBackend<Stdout>>;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let has = |name: &str| args.iter().any(|a| a == name);

    if has("--help") || has("-h") {
        print_help();
        return Ok(());
    }

    if let Some(i) = args.iter().position(|a| a == "--selftest") {
        match device::export_selftest(args.get(i + 1).map(String::as_str)) {
            Ok(s) => println!("export selftest OK: {s}"),
            Err(e) => {
                eprintln!("export selftest FAILED: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // Non-interactive twin of the Overview action. `rsk identify` is the usual
    // route, but the Python CLI needs hidapi, and on hosts where that cannot open a
    // FIDO device this is the only first-party way to make a key point at itself.
    if has("--identify") {
        match device::identify() {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("identify failed: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    let demo = has("--demo") || has("--mock");
    let mut provider: Box<dyn DeviceProvider> = if demo {
        Box::new(MockProvider::new())
    } else {
        Box::new(HardwareProvider)
    };

    if has("--json") {
        println!("{}", provider.snapshot().to_json());
        return Ok(());
    }
    if has("--once") {
        print_once(&provider.snapshot());
        return Ok(());
    }

    // Interactive. Restore the terminal on EVERY exit path — q / Ctrl-C, an io
    // error out of the loop, or a panic (device I/O can panic) — otherwise the
    // shell is left in raw mode with no echo.
    let prev_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev_panic(info);
    }));
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
    let app = App::new(provider, Theme::detect());
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let res = run(&mut term, app);
    restore_terminal();
    res
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
}

fn run(term: &mut Term, mut app: App) -> io::Result<()> {
    loop {
        term.draw(|f| ui::render(f, &app))?;
        if app.should_quit {
            return Ok(());
        }
        if !event::poll(Duration::from_millis(400))? {
            // Idle: re-read status only in Normal mode (don't disturb a modal,
            // and don't hammer the CCID bus while the user is mid-task).
            if matches!(app.mode, AppMode::Normal)
                && app.refreshed.elapsed() >= Duration::from_secs(5)
            {
                app.refresh();
            }
            continue;
        }
        // Resize / paste / focus events just fall through to a redraw.
        if let Event::Key(k) = event::read()? {
            match input::handle_key(&mut app, k) {
                Flow::Run(action) => {
                    actions::run(&mut app, term, action)?;
                    app.refreshed = Instant::now();
                }
                Flow::Continue => {}
            }
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

fn print_help() {
    println!(
        "rsk-tui — rs-key device cockpit\n\n\
         USAGE:\n  \
         rsk-tui [FLAGS]\n\n\
         FLAGS:\n  \
         (none)        interactive cockpit\n  \
         --demo,--mock interactive cockpit against a simulated device (no hardware)\n  \
         --once        print the gathered status once and exit\n  \
         --json        one-shot machine-readable status (JSON) and exit\n  \
         --identify    blink this key's indicator and exit (CTAPHID wink)\n  \
         --selftest    native backup export/restore round-trip (no-touch build)\n  \
         -h, --help    this help\n\n\
         In the cockpit: Tab/arrows switch sections, j/k move, Enter runs,\n  \
         r refreshes, / searches, ? shows help, q quits."
    );
}

/// Human-readable one-shot status (the `--once` path).
/// Strip terminal control bytes from a device-controlled string before printing it raw.
/// The `--once` path bypasses ratatui (whose cell grid neutralizes escapes), so a hostile
/// device could otherwise embed ANSI/OSC sequences in getInfo/identity text to manipulate or
/// spoof the operator's terminal. Any C0/C1 control (incl. ESC) — and the Cf bidi/format
/// overrides that `char::is_control()` misses (Trojan-Source reordering) — becomes U+FFFD.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            let bidi = matches!(c,
                '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
            if c.is_control() || bidi {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

fn print_once(s: &model::DeviceSnapshot) {
    if s.demo {
        println!("[DEMO — simulated device]");
    }
    println!("device     : {}", sanitize(&s.summary()));
    println!(
        "transports : HID {}  PC/SC {}  CCID {}",
        s.transport.hid.word(),
        s.transport.pcsc.word(),
        s.transport.ccid.word()
    );
    if let Some(serial) = &s.identity.serial {
        println!("serial     : {}", sanitize(serial));
    }
    if let Some(fw) = &s.identity.firmware {
        let bcd = s
            .identity
            .bcd_device
            .map(|b| format!("  bcdDevice {b:#06x}"))
            .unwrap_or_default();
        let sdk = s
            .identity
            .sdk
            .as_ref()
            .map(|v| format!("  sdk {}", sanitize(v)))
            .unwrap_or_default();
        println!("firmware   : {}{bcd}{sdk}", sanitize(fw));
    }
    if s.fido.present {
        println!(
            "fido       : {}  clientPin={}",
            sanitize(&s.fido.versions.join(", ")),
            s.fido
                .client_pin
                .map(|b| b.to_string())
                .unwrap_or_else(|| "?".into())
        );
    } else {
        println!("fido       : not found");
    }
    if let Some(b) = s.backup {
        println!("backup     : {}", b.describe());
    }
    if let Some(l) = s.lock {
        println!("seed lock  : {}", l.describe());
    }
    match s.secure_boot {
        Some(sb) => println!(
            "secure boot: {}  (enabled={} locked={} bootkey={:#x})",
            sb.describe(),
            sb.enabled,
            sb.locked,
            sb.bootkey
        ),
        None => println!("secure boot: (CCID unavailable)"),
    }
    if let Some(r) = s.rollback {
        println!(
            "rollback   : {}  boot version {}/{}",
            r.describe(),
            r.version,
            r.capacity
        );
    }
    if let Some(a) = &s.attestation {
        println!("org attest : {}", a.describe());
    }
    let applet = |p: Option<bool>| model::present_health(p).1;
    println!(
        "applets    : OpenPGP {}  PIV {}  OATH {}  OTP {}",
        applet(s.applets.openpgp),
        applet(s.applets.piv),
        applet(s.applets.oath),
        applet(s.applets.otp),
    );
    if let Some(p) = &s.pgp {
        let serial = p
            .serial
            .as_ref()
            .map(|x| format!("  serial {}", sanitize(x)))
            .unwrap_or_default();
        let retries = p
            .pin_retries
            .map(|r| format!("  retries PW1 {} RC {} PW3 {}", r[0], r[1], r[2]))
            .unwrap_or_default();
        println!("openpgp    : {} keys{serial}{retries}", p.keys_present);
    }
    if let Some(p) = s.piv_meta {
        println!(
            "piv        : PIN {}/{} tries{}",
            p.pin_left,
            p.pin_total,
            if p.pin_default { " (default)" } else { "" }
        );
    }
    if let Some(l) = s.led {
        let name = |i: u8| device::COLORS.get(i as usize).copied().unwrap_or("?");
        println!(
            "led        : {}  idle {}  processing {}  touch {}  boot {}",
            if l.steady { "steady" } else { "blink" },
            name(l.idle),
            name(l.processing),
            name(l.touch),
            name(l.boot),
        );
    }
    for e in &s.errors {
        println!("note       : {e}");
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
