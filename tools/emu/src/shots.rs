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

use std::path::Path;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics_simulator::{OutputSettingsBuilder, SimulatorDisplay};

use rsk_ui::{
    AppsView, HomeView, PinCaption, PinPad, Screen, SettingsPage, SettingsView, StatusKind,
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
                version: crate::usbip_stack::BCD_DEVICE,
                chipid: 0,
                device_pin_set: true,
                fido_pin_set: false,
                backup_sealed: false,
            }),
        );
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
