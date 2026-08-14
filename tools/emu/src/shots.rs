// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `--screenshots <dir>`: the trusted display's screens, as PNGs, for the docs.
//!
//! `docs/guides/display.md` used to carry photographs of a soldered panel — a
//! camera pointed at a 2.8" screen, with whatever the room's light was doing.
//! These come from `rsk_ui::render`, the same call the panel makes, into the same
//! `SimulatorDisplay` the `--display` window shows: the pixels are the device's,
//! at the device's 240×320, and they can be regenerated the day a screen changes
//! instead of requiring a board and a camera.
//!
//! Deliberately *not* driven through the `Ui` flow. A screen is chosen here by
//! naming it, so the guide can show a state that takes a provisioned key and six
//! taps to reach — and the flow's own correctness is what `tests/*.py` and the
//! `--display` window are for.
//!
//! The two screens that show a build number take the tree's own `bcdDevice`, so
//! a shipped PNG is only as fresh as the checkout that rendered it; the rest of
//! what they show is fixture.

use std::path::Path;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics_simulator::{OutputSettingsBuilder, SimulatorDisplay};

use rsk_ui::{
    AccountRow, AppsView, AuditKind, AuditRow, BackupView, ConfirmPrompt, HomeView, Label, OathRow,
    OpenpgpView, PgpSlotRow, PinCaption, PinPad, PivSlotRow, PivView, Screen, SettingsPage,
    SettingsView, StatusKind,
};

/// The panel's own size. The PNGs are 1:1 with it — a doc image that has been
/// scaled is a doc image nobody can compare against a screen.
const PANEL: Size = Size::new(240, 320);

/// Every screen `docs/guides/display.md` shows, and the file it is written to.
/// The states match the guide's prose: a fresh device with a PIN set and nothing
/// provisioned, which is what a reader has in front of them.
fn shoot(dir: &Path) -> std::io::Result<Vec<String>> {
    let settings = OutputSettingsBuilder::new().scale(1).build();
    let mut written = Vec::new();

    let mut save = |name: &str, draw: &dyn Fn(&mut SimulatorDisplay<Rgb565>)| {
        let mut panel = SimulatorDisplay::<Rgb565>::new(PANEL);
        draw(&mut panel);
        let path = dir.join(format!("{name}.png"));
        match panel.to_rgb_output_image(&settings).save_png(&path) {
            Ok(()) => written.push(path.display().to_string()),
            Err(e) => eprintln!("emu: cannot write {}: {e}", path.display()),
        }
    };

    save("display-home", &|p| {
        let _ = rsk_ui::render(
            p,
            &Screen::Home(HomeView {
                status: StatusKind::Idle,
                pin_set: true,
                passkeys: 0,
            }),
        );
    });

    save("display-locked", &|p| {
        let _ = rsk_ui::render(p, &Screen::Locked);
    });

    // The unlock pad as a reader first meets it: nothing entered yet, and the
    // muted attempt count the design shows up front rather than after a refusal.
    save("display-pin", &|p| {
        let _ = rsk_ui::render(
            p,
            &Screen::Pin(PinPad {
                entered: 0,
                title: "Enter PIN",
                expected: 4,
                caption: Some(PinCaption::TriesRemaining { left: 8 }),
            }),
        );
    });

    save("display-passkeys", &|p| {
        let _ = rsk_ui::render_passkeys_list(p, &[], 0, 0);
    });

    save("display-apps", &|p| {
        let _ = rsk_ui::render_apps(
            p,
            &AppsView {
                openpgp_keys: 0,
                piv_slots: 0,
                oath_codes: 0,
            },
        );
    });

    save("display-settings", &|p| {
        let _ = rsk_ui::render(
            p,
            &Screen::Settings(SettingsView {
                page: SettingsPage::Root,
                brightness: rsk_ui::BRIGHTNESS_LEVELS,
                timeout_secs: 15,
                sleep_secs: 30,
                version: crate::bcd::BCD_DEVICE,
                chipid: 0,
                device_pin_set: true,
                fido_pin_set: false,
                backup_sealed: false,
            }),
        );
    });

    // The ceremony the whole guide is about: a trusted title the device owns, and
    // the relying party verbatim underneath it.
    save("display-approve", &|p| {
        let _ = rsk_ui::render(
            p,
            &Screen::Confirm(ConfirmPrompt::new("Sign in?", b"github.com", b"maxmur")),
        );
    });

    // The same prompt against a padded look-alike. The guide claims the clip keeps
    // the *registrable* suffix rather than the head, so `attacker.example` cannot
    // hide behind the cut — this is that claim, rendered.
    save("display-approve-lookalike", &|p| {
        let _ = rsk_ui::render(
            p,
            &Screen::Confirm(ConfirmPrompt::new(
                "Sign in?",
                b"accounts.google.com.attacker.com",
                b"maxmur",
            )),
        );
    });

    save("display-register", &|p| {
        let _ = rsk_ui::render(
            p,
            &Screen::Confirm(ConfirmPrompt::new(
                "Save new passkey?",
                b"github.com",
                b"maxmur",
            )),
        );
    });

    // Secure boot off, because that is the state a reader has: the screen warns
    // rather than claiming a check it is not doing.
    save("display-firmware", &|p| {
        let _ = rsk_ui::render_firmware(p, crate::bcd::BCD_DEVICE, 0x0052_534B_454D_5501, false);
    });

    save("display-audit", &|p| {
        let rows = [
            AuditRow {
                kind: AuditKind::Login,
                secs_ago: Some(12),
            },
            AuditRow {
                kind: AuditKind::Register,
                secs_ago: Some(340),
            },
            AuditRow {
                kind: AuditKind::Denied,
                secs_ago: Some(3_600),
            },
            AuditRow {
                kind: AuditKind::Pin,
                secs_ago: Some(7_200),
            },
            AuditRow {
                kind: AuditKind::Boot,
                secs_ago: Some(86_400),
            },
        ];
        let _ = rsk_ui::render_audit_log(p, &rows, 0, rows.len() as u16, true);
    });

    // A provisioned device whose export window is still open — the state the
    // seed-backup guide sends a reader here to check.
    save("display-backup", &|p| {
        let _ = rsk_ui::render_backup(
            p,
            &BackupView {
                sealed: false,
                has_seed: true,
                exportable: true,
                can_reveal: true,
            },
        );
    });

    save("display-service", &|p| {
        let accounts = [
            AccountRow {
                name: Label::clamp(b"maxmur"),
                protected: false,
            },
            AccountRow {
                name: Label::clamp(b"maxmur-work"),
                protected: true,
            },
        ];
        let _ = rsk_ui::render_service(
            p,
            &Label::clamp_domain(b"github.com"),
            true,
            &accounts,
            0,
            accounts.len() as u16,
        );
    });

    save("display-openpgp", &|p| {
        let _ = rsk_ui::render_openpgp(
            p,
            &OpenpgpView {
                slots: [
                    PgpSlotRow {
                        present: true,
                        algo: Label::clamp(b"Ed25519"),
                        touch: true,
                    },
                    PgpSlotRow {
                        present: true,
                        algo: Label::clamp(b"X25519"),
                        touch: false,
                    },
                    PgpSlotRow {
                        present: false,
                        algo: Label::default(),
                        touch: false,
                    },
                ],
                cardholder_name: Label::clamp(b"Maxim Muravev"),
                sig_count: 7,
                pw1: 3,
                pw3: 3,
            },
        );
    });

    save("display-piv", &|p| {
        let slot = |n: u8, present: bool, algo: &[u8], cert: bool| PivSlotRow {
            slot: n,
            present,
            cert,
            algo: Label::clamp(algo),
        };
        let _ = rsk_ui::render_piv(
            p,
            &PivView {
                slots: [
                    slot(0x9A, true, b"P-256", true),
                    slot(0x9C, true, b"RSA-2048", true),
                    slot(0x9D, false, b"", false),
                    slot(0x9E, false, b"", false),
                ],
                extra: 2,
                pin: 3,
                puk: 3,
            },
        );
    });

    save("display-oath", &|p| {
        let rows = [
            OathRow {
                name: Label::clamp(b"GitHub:maxmur"),
                hotp: false,
                touch: true,
            },
            OathRow {
                name: Label::clamp(b"AWS:root"),
                hotp: false,
                touch: false,
            },
            OathRow {
                name: Label::clamp(b"Bank:counter"),
                hotp: true,
                touch: false,
            },
        ];
        let _ = rsk_ui::render_oath(p, &rows, 0, rows.len() as u16);
    });

    Ok(written)
}

/// Write the docs' display screenshots into `dir` and report what landed.
pub fn run(dir: &str) -> ! {
    let dir = Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("emu: cannot create {}: {e}", dir.display());
        std::process::exit(1);
    }
    match shoot(dir) {
        Ok(written) => {
            for path in &written {
                println!("{path}");
            }
            eprintln!(
                "emu: {} screenshots at {}×{}",
                written.len(),
                PANEL.width,
                PANEL.height
            );
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("emu: {e}");
            std::process::exit(1)
        }
    }
}
