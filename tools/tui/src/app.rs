// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! App state, modes, navigation, and the modal/confirmation flow.
//!
//! Everything here is pure state manipulation — no terminal, no blocking device
//! I/O. [`App::begin_action`] and [`App::submit_modal`] drive the multi-step
//! flows (typed confirmation → PIN → run) and are unit-tested directly against a
//! [`MockProvider`](crate::device::MockProvider).

use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

use crate::device::DeviceProvider;
use crate::model::*;
use crate::theme::Theme;

/// What the event loop should do after handling input.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    /// Nothing more — just redraw.
    Continue,
    /// Run this action (with whatever inputs are staged) via `actions::run`.
    Run(Action),
}

/// A step in a multi-stage modal flow — the continuation once the current modal
/// is submitted.
#[derive(Clone, Copy, Debug)]
pub enum Step {
    ExportConfirmed,
    ExportSlip39Confirmed,
    RestorePhrase,
    RestoreConfirmed,
    FinalizeConfirmed,
    RebootApp,
    RebootBootsel,
    /// PIN collected (or skipped) — now run this action. The single continuation
    /// for every PIN-gated action; opened via `App::gate_pin`.
    PinThenRun(Action),
}

pub enum Modal {
    /// Free-text or masked input.
    Input {
        title: String,
        prompt: String,
        buf: String,
        mask: bool,
        then: Step,
    },
    /// Typed confirmation: the user must type `want` exactly (e.g. "SEAL").
    Confirm {
        title: String,
        body: String,
        want: &'static str,
        buf: String,
        then: Step,
    },
    /// Simple yes/no (Enter/y = yes).
    YesNo {
        title: String,
        body: String,
        then: Step,
    },
    /// A secret shown once, then zeroized. Never logged.
    Reveal {
        title: String,
        body: Zeroizing<String>,
    },
    /// Non-secret informational / result modal. `scroll` is the first visible line
    /// (0 = top); long output (the audit journal) scrolls with the arrow keys.
    Message {
        title: String,
        body: String,
        level: LogLevel,
        scroll: u16,
    },
}

/// The `/` action search palette.
pub struct Search {
    pub query: String,
    pub sel: usize,
}

pub enum AppMode {
    Normal,
    Modal(Modal),
    Search(Search),
}

/// One row of a section's menu.
pub struct MenuItem {
    pub label: String,
    pub hint: String,
    pub health: Health,
    pub kind: MenuKind,
}

pub enum MenuKind {
    /// A device operation the TUI can run.
    Run(Action),
    /// CLI-only / informational pointer. Selecting it explains; never faked.
    Note { title: String, body: String },
    /// Currently unavailable; selecting it explains why.
    Disabled(String),
}

pub struct App {
    pub provider: Box<dyn DeviceProvider>,
    pub theme: Theme,
    pub snapshot: DeviceSnapshot,
    pub refreshed: Instant,
    pub section: Section,
    pub menu_sel: usize,
    pub mode: AppMode,
    pub log: EventLog,
    pub status: String,
    pub status_level: LogLevel,
    /// Secrets collected across a modal flow; consumed by `actions::run`.
    pub staging: ActionInput,
    pub should_quit: bool,
}

impl App {
    pub fn new(mut provider: Box<dyn DeviceProvider>, theme: Theme) -> Self {
        let snapshot = provider.snapshot();
        let mut app = App {
            provider,
            theme,
            snapshot,
            refreshed: Instant::now(),
            section: Section::Overview,
            menu_sel: 0,
            mode: AppMode::Normal,
            log: EventLog::default(),
            status: String::new(),
            status_level: LogLevel::Info,
            staging: ActionInput::default(),
            should_quit: false,
        };
        if app.snapshot.demo {
            app.log(LogLevel::Info, "demo mode — no hardware, simulated device");
        } else if app.snapshot.any_device() {
            app.log(
                LogLevel::Good,
                format!("connected: {}", app.snapshot.summary()),
            );
        } else {
            app.log(LogLevel::Warn, "no device detected — plug in an RS-Key");
        }
        app
    }

    // ---- logging (the one place action text lands; redaction lives here) ----

    /// Push a log line + update the status bar. Any live PIN/phrase substring is
    /// redacted as a defensive backstop on top of never passing secrets here.
    pub fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        let text = text.into();
        let mut secrets: Vec<&str> = Vec::new();
        if let Some(p) = &self.staging.pin {
            secrets.push(p);
        }
        if let Some(p) = &self.staging.phrase {
            secrets.push(p);
        }
        match &self.mode {
            AppMode::Modal(Modal::Input { buf, .. })
            | AppMode::Modal(Modal::Confirm { buf, .. }) => secrets.push(buf),
            _ => {}
        }
        // `self.log` is a distinct field from staging/mode, so these borrows are
        // disjoint and the borrow checker accepts the simultaneous access.
        self.log.push(level, text.clone(), &secrets);
        self.status = text;
        self.status_level = level;
    }

    /// Set the status bar without adding a log entry (transient "working…").
    pub fn set_status(&mut self, level: LogLevel, text: impl Into<String>) {
        self.status = text.into();
        self.status_level = level;
    }

    // ---- snapshot ----

    pub fn refresh(&mut self) {
        self.snapshot = self.provider.snapshot();
        self.refreshed = Instant::now();
    }

    pub fn pin_set(&self) -> bool {
        self.snapshot.pin_set()
    }

    // ---- navigation ----

    pub fn next_section(&mut self) {
        let i = Section::ALL
            .iter()
            .position(|s| *s == self.section)
            .unwrap_or(0);
        self.set_section(Section::ALL[(i + 1) % Section::ALL.len()]);
    }

    pub fn prev_section(&mut self) {
        let n = Section::ALL.len();
        let i = Section::ALL
            .iter()
            .position(|s| *s == self.section)
            .unwrap_or(0);
        self.set_section(Section::ALL[(i + n - 1) % n]);
    }

    pub fn set_section(&mut self, s: Section) {
        self.section = s;
        self.menu_sel = 0;
    }

    pub fn move_menu(&mut self, delta: i32) {
        let n = self.menu().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.menu_sel as i32;
        self.menu_sel = (((cur + delta) % n + n) % n) as usize;
    }

    // ---- menus ----

    /// The menu for the current section, computed from the live snapshot.
    pub fn menu(&self) -> Vec<MenuItem> {
        menu_for(self.section, &self.snapshot)
    }

    /// Enter on the highlighted menu row.
    pub fn activate_menu(&mut self) -> Flow {
        let menu = self.menu();
        let Some(item) = menu.into_iter().nth(self.menu_sel) else {
            return Flow::Continue;
        };
        match item.kind {
            MenuKind::Run(action) => self.begin_action(action),
            MenuKind::Note { title, body } => {
                self.open_message(title, body, LogLevel::Info);
                Flow::Continue
            }
            MenuKind::Disabled(reason) => {
                self.open_message("unavailable".into(), reason, LogLevel::Warn);
                Flow::Continue
            }
        }
    }

    // ---- the action / confirmation flow ----

    /// Begin an action: either run it immediately or open the first modal of a
    /// confirmation flow.
    pub fn begin_action(&mut self, action: Action) -> Flow {
        match action {
            Action::Refresh | Action::Identify | Action::LedGet | Action::LedCycle => {
                Flow::Run(action)
            }
            Action::Verify => self.gate_pin(Action::Verify),
            Action::CredCount => self.gate_pin(Action::CredCount),
            Action::AuditRead => self.gate_pin(Action::AuditRead),
            Action::RebootApp => {
                self.mode = AppMode::Modal(Modal::YesNo {
                    title: "reboot to app".into(),
                    body: "Restart the firmware now? The device will briefly disconnect.".into(),
                    then: Step::RebootApp,
                });
                Flow::Continue
            }
            Action::RebootBootsel => {
                self.open_confirm(
                    "reboot to BOOTSEL".into(),
                    "Drops the device into firmware-update (mass-storage) mode — it leaves \
                     the USB bus until reflashed or re-plugged."
                        .into(),
                    "BOOTSEL",
                    Step::RebootBootsel,
                );
                Flow::Continue
            }
            Action::BackupExport => {
                self.open_confirm(
                    "export seed".into(),
                    "Reveals your FIDO seed as a 24-word phrase on this screen. Anyone who \
                     reads it can clone your identity. Make sure nobody is watching."
                        .into(),
                    "EXPORT",
                    Step::ExportConfirmed,
                );
                Flow::Continue
            }
            Action::BackupExportSlip39 => {
                self.open_confirm(
                    "export seed (SLIP-39)".into(),
                    "Reveals your FIDO seed as 3 SLIP-39 shares (any 2 reconstruct it) on this \
                     screen. Anyone who reads 2 shares can clone your identity. Make sure nobody \
                     is watching."
                        .into(),
                    "EXPORT",
                    Step::ExportSlip39Confirmed,
                );
                Flow::Continue
            }
            Action::BackupRestore => {
                self.mode = AppMode::Modal(Modal::Input {
                    title: "restore seed".into(),
                    prompt: "BIP-39 phrase (24 words)".into(),
                    buf: String::new(),
                    mask: false,
                    then: Step::RestorePhrase,
                });
                Flow::Continue
            }
            Action::BackupFinalize => {
                if self.snapshot.sealed() {
                    self.open_message(
                        "already sealed".into(),
                        "The export window is already sealed. A factory reset reopens it.".into(),
                        LogLevel::Info,
                    );
                } else {
                    self.open_confirm(
                        "seal backup window".into(),
                        "Permanently disables seed export until a factory reset. Make sure you \
                         have a backup first."
                            .into(),
                        "SEAL",
                        Step::FinalizeConfirmed,
                    );
                }
                Flow::Continue
            }
        }
    }

    /// Enter inside a modal.
    pub fn submit_modal(&mut self) -> Flow {
        let mode = std::mem::replace(&mut self.mode, AppMode::Normal);
        let AppMode::Modal(modal) = mode else {
            self.mode = mode;
            return Flow::Continue;
        };
        match modal {
            Modal::Reveal { mut body, .. } => {
                body.zeroize();
                self.log(LogLevel::Info, "seed cleared from the screen");
                Flow::Continue
            }
            Modal::Message { .. } => Flow::Continue,
            Modal::YesNo { then, .. } => self.advance(then),
            Modal::Confirm {
                want,
                mut buf,
                then,
                ..
            } => {
                let ok = buf.trim() == want;
                buf.zeroize();
                if ok {
                    self.advance(then)
                } else {
                    self.clear_staging();
                    self.log(
                        LogLevel::Warn,
                        format!("cancelled — type {want} to confirm"),
                    );
                    Flow::Continue
                }
            }
            Modal::Input { mut buf, then, .. } => {
                match then {
                    Step::RestorePhrase => self.staging.phrase = Some(Zeroizing::new(buf.clone())),
                    Step::PinThenRun(_) => self.staging.pin = Some(Zeroizing::new(buf.clone())),
                    // Input modals only ever collect a restore phrase or a PIN.
                    other => debug_assert!(false, "unexpected Input step: {other:?}"),
                }
                buf.zeroize();
                self.advance(then)
            }
        }
    }

    /// Advance a confirmation flow to its next modal or to the run.
    fn advance(&mut self, step: Step) -> Flow {
        match step {
            Step::ExportConfirmed => self.gate_pin(Action::BackupExport),
            Step::ExportSlip39Confirmed => self.gate_pin(Action::BackupExportSlip39),
            Step::RestorePhrase => {
                self.open_confirm(
                    "restore seed".into(),
                    "Overwrites this device's current seed with the phrase you entered. All \
                     credentials derived from the old seed stop working."
                        .into(),
                    "RESTORE",
                    Step::RestoreConfirmed,
                );
                Flow::Continue
            }
            Step::RestoreConfirmed => self.gate_pin(Action::BackupRestore),
            Step::FinalizeConfirmed => Flow::Run(Action::BackupFinalize),
            Step::RebootApp => Flow::Run(Action::RebootApp),
            Step::RebootBootsel => Flow::Run(Action::RebootBootsel),
            Step::PinThenRun(action) => Flow::Run(action),
        }
    }

    // ---- modal helpers ----

    /// The single PIN chokepoint: if the device has a clientPIN, open the masked
    /// PIN prompt and run `action` once it is entered; otherwise run `action`
    /// straight away. Every PIN-gated action routes through here, so "does this
    /// need a PIN?" lives in exactly one place (mirrors the CLI's `resolve_pin`).
    fn gate_pin(&mut self, action: Action) -> Flow {
        if self.pin_set() {
            self.open_pin(Step::PinThenRun(action));
            Flow::Continue
        } else {
            Flow::Run(action)
        }
    }

    fn open_pin(&mut self, then: Step) {
        self.mode = AppMode::Modal(Modal::Input {
            title: "authenticate".into(),
            prompt: "FIDO2 PIN".into(),
            buf: String::new(),
            mask: true,
            then,
        });
    }

    fn open_confirm(&mut self, title: String, body: String, want: &'static str, then: Step) {
        self.mode = AppMode::Modal(Modal::Confirm {
            title,
            body,
            want,
            buf: String::new(),
            then,
        });
    }

    pub fn open_message(&mut self, title: String, body: String, level: LogLevel) {
        self.mode = AppMode::Modal(Modal::Message {
            title,
            body,
            level,
            scroll: 0,
        });
    }

    /// Scroll the open Message modal by `delta` lines. Clamped to `[0, lines-1]`
    /// so it never runs far past the content; the renderer clamps the tail to the
    /// viewport. A no-op in any other mode.
    pub fn scroll_message(&mut self, delta: i32) {
        if let AppMode::Modal(Modal::Message { scroll, body, .. }) = &mut self.mode {
            let max = body.lines().count().saturating_sub(1) as i32;
            *scroll = (*scroll as i32 + delta).clamp(0, max.max(0)) as u16;
        }
    }

    pub fn open_reveal(&mut self, title: String, body: Zeroizing<String>) {
        self.mode = AppMode::Modal(Modal::Reveal { title, body });
    }

    /// Esc / Ctrl-C cleanup: zeroize any in-flight secret and return to Normal.
    pub fn cancel_modal(&mut self) {
        let mode = std::mem::replace(&mut self.mode, AppMode::Normal);
        if let AppMode::Modal(modal) = mode {
            match modal {
                Modal::Input { mut buf, .. } | Modal::Confirm { mut buf, .. } => buf.zeroize(),
                Modal::Reveal { mut body, .. } => body.zeroize(),
                _ => {}
            }
        }
        self.clear_staging();
    }

    pub fn clear_staging(&mut self) {
        // Zeroizing wipes on drop.
        self.staging = ActionInput::default();
    }

    // ---- search palette ----

    pub fn open_search(&mut self) {
        self.mode = AppMode::Search(Search {
            query: String::new(),
            sel: 0,
        });
    }

    /// Actions whose label matches the query (case-insensitive substring).
    pub fn search_results(query: &str) -> Vec<Action> {
        let q = query.trim().to_ascii_lowercase();
        Action::ALL
            .iter()
            .copied()
            .filter(|a| q.is_empty() || a.label().to_ascii_lowercase().contains(&q))
            .collect()
    }
}

/// Build the menu rows for a section from the snapshot.
fn menu_for(section: Section, snap: &DeviceSnapshot) -> Vec<MenuItem> {
    let run = |label: &str, hint: &str, action: Action| MenuItem {
        label: label.into(),
        hint: hint.into(),
        health: Health::Ok,
        kind: MenuKind::Run(action),
    };
    let note = |label: &str, hint: &str, title: &str, body: &str| MenuItem {
        label: label.into(),
        hint: hint.into(),
        health: Health::NotApplicable,
        kind: MenuKind::Note {
            title: title.into(),
            body: body.into(),
        },
    };
    match section {
        Section::Overview => vec![
            run("Refresh status", "re-read all channels", Action::Refresh),
            run(
                "Identify this key",
                "blink the indicator · no PIN",
                Action::Identify,
            ),
            run(
                "Verify device identity",
                "signed challenge · touch",
                Action::Verify,
            ),
        ],
        Section::Fido => vec![
            run("Refresh status", "re-read getInfo", Action::Refresh),
            run(
                "Count resident passkeys",
                "PIN · credMgmt",
                Action::CredCount,
            ),
            note(
                "Set / change PIN",
                "CLI",
                "FIDO PIN",
                "Auth-changing writes stay in the CLI:\n  rsk fido set-pin\n  rsk fido change-pin",
            ),
            note(
                "List resident passkeys",
                "CLI · PIN",
                "list passkeys",
                "Resident-credential enumeration needs the PIN + credMgmt:\n  rsk fido list-passkeys --pin …",
            ),
            note(
                "Factory reset FIDO",
                "CLI · destructive",
                "FIDO reset",
                "Destructive — erases the seed, every passkey, and the PIN:\n  rsk fido reset   (touch within 10 s of plug-in)",
            ),
        ],
        Section::OpenPgp => vec![
            note(
                "Card status",
                "external",
                "OpenPGP card",
                "Presence is shown above. Full card data (key fingerprints, PIN\nretries, cardholder): gpg --card-status",
            ),
            note(
                "Factory reset",
                "CLI · destructive",
                "OpenPGP reset",
                "Destructive — blocks the PINs, then TERMINATE + ACTIVATE:\n  rsk openpgp reset",
            ),
        ],
        Section::Piv => vec![
            note(
                "Card status",
                "external",
                "PIV applet",
                "Presence is shown above. Full data: ykman piv info, or OpenSC\n  pkcs11-tool --list-objects",
            ),
            note(
                "Factory reset",
                "CLI · destructive",
                "PIV reset",
                "Destructive — needs PIN + PUK blocked first:\n  ykman piv reset",
            ),
        ],
        Section::OathOtp => vec![
            note(
                "OATH codes",
                "external",
                "OATH (TOTP/HOTP)",
                "Presence is shown above. Manage credentials with:\n  ykman oath accounts …",
            ),
            note(
                "Yubico-OTP slots",
                "CLI · write",
                "OTP slots",
                "Slot programming is a write — use the CLI:\n  rsk otp …   (or ykman otp)",
            ),
        ],
        Section::Backup => {
            let mut v = vec![MenuItem {
                label: "Export seed (BIP-39)".into(),
                hint: "touch · reveals 24 words".into(),
                health: if snap.sealed() {
                    Health::Warn
                } else {
                    Health::Ok
                },
                kind: MenuKind::Run(Action::BackupExport),
            }];
            v.push(MenuItem {
                label: "Export seed (SLIP-39)".into(),
                hint: "touch · 2-of-3 shares".into(),
                health: if snap.sealed() {
                    Health::Warn
                } else {
                    Health::Ok
                },
                kind: MenuKind::Run(Action::BackupExportSlip39),
            });
            v.push(run(
                "Restore seed (BIP-39)",
                "touch · overwrites seed",
                Action::BackupRestore,
            ));
            if snap.sealed() {
                v.push(MenuItem {
                    label: "Finalize — seal export window".into(),
                    hint: "already sealed".into(),
                    health: Health::NotApplicable,
                    kind: MenuKind::Disabled(
                        "The export window is already sealed. A factory reset reopens it.".into(),
                    ),
                });
            } else {
                v.push(run(
                    "Finalize — seal export window",
                    "touch · irreversible",
                    Action::BackupFinalize,
                ));
            }
            v.push(note(
                "SLIP-39 restore (combine shares)",
                "CLI",
                "SLIP-39 restore",
                "Recombining SLIP-39 shares to restore stays in the CLI:\n  rsk backup restore --scheme slip39",
            ));
            v
        }
        Section::Led => vec![
            run("Read LED state", "GET LED", Action::LedGet),
            run("Cycle idle color", "SET LED", Action::LedCycle),
        ],
        Section::Audit => vec![
            run("Read journal", "AUDIT_READ · PIN if set", Action::AuditRead),
            run(
                "Verify identity (checkpoint)",
                "touch · ECDSA verify",
                Action::Verify,
            ),
            note(
                "Full chain verify",
                "CLI",
                "audit verify",
                "rsk audit verify cross-checks the exported window against the\nsigned head and can pin the key with --expect-key.",
            ),
        ],
        Section::Reboot => vec![
            run("Reboot → app", "warm restart", Action::RebootApp),
            run(
                "Reboot → BOOTSEL",
                "firmware-update mode · confirm",
                Action::RebootBootsel,
            ),
            note(
                "Seed soft-lock",
                "CLI · PIN · touch",
                "soft-lock",
                "Engage / unlock / disengage the seed soft-lock:\n  rsk lock engage | unlock | disengage",
            ),
            note(
                "Org attestation",
                "CLI · PIN · touch",
                "attestation",
                "Import / clear an org attestation key + chain:\n  rsk fido attest import | clear",
            ),
            note(
                "Secure boot / OTP fuses",
                "CLI · irreversible",
                "production fuses",
                "Irreversible production rituals stay CLI-only:\n  rsk secure-boot …   rsk otp …\nSee docs/production.md before running any of these.",
            ),
        ],
        Section::Help => Vec::new(),
    }
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
