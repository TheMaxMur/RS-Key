// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Action dispatch and result handling.
//!
//! This is the only place that bridges app state to a (possibly long, touch-
//! gated) device call: it paints a "working…" status and redraws *before*
//! blocking, takes the staged secrets, runs the provider, then folds the typed
//! [`ActionResult`] back into app state (log line, reveal modal, refresh).

use std::io;

use crate::app::App;
use crate::model::{Action, ActionResult, LogLevel};
use crate::{Term, ui};

/// Run an action with whatever inputs the modal flow staged.
pub fn run(app: &mut App, term: &mut Term, action: Action) -> io::Result<()> {
    if action == Action::Refresh {
        app.set_status(LogLevel::Info, "refreshing…");
        term.draw(|f| ui::render(f, app))?;
        app.refresh();
        app.log(LogLevel::Info, "status refreshed");
        return Ok(());
    }

    // Paint the transient status and redraw so the user sees "touch the device"
    // before we block on a (possibly 20 s) I/O call.
    app.set_status(LogLevel::Info, working_message(action));
    term.draw(|f| ui::render(f, app))?;

    let input = std::mem::take(&mut app.staging);
    let result = app.provider.run(action, &input);
    drop(input); // Zeroizing wipes the PIN / phrase here.

    apply(app, action, result);
    Ok(())
}

fn apply(app: &mut App, action: Action, result: ActionResult) {
    match result {
        ActionResult::Ok(msg) => {
            app.log(LogLevel::Good, msg);
            if mutates_state(action) {
                app.refresh();
            }
        }
        ActionResult::Failed(msg) => app.log(LogLevel::Error, msg),
        ActionResult::Report { title, body } => {
            app.log(LogLevel::Info, format!("{title} — shown in panel"));
            app.open_message(title, body, LogLevel::Info);
        }
        ActionResult::Reveal { title, body } => {
            app.open_reveal(title, body);
            // The secret is on screen, never in the log.
            app.log(LogLevel::Good, "seed exported — on screen, not logged");
        }
    }
}

/// State-changing ops worth re-reading the snapshot after (reboots excepted:
/// the device is mid-transition, so we let the user refresh manually).
fn mutates_state(action: Action) -> bool {
    matches!(
        action,
        Action::LedCycle | Action::BackupRestore | Action::BackupFinalize
    )
}

fn working_message(action: Action) -> &'static str {
    match action {
        Action::Refresh => "refreshing…",
        Action::Identify => "winking…",
        Action::CredCount => "counting passkeys — enter PIN…",
        Action::LedGet => "reading LED…",
        Action::LedCycle => "setting LED…",
        Action::BackupExport => "exporting — touch the device if it asks…",
        Action::BackupExportSlip39 => "exporting shares — touch the device if it asks…",
        Action::BackupRestore => "restoring — touch the device if it asks…",
        Action::BackupFinalize => "sealing — touch the device if it asks…",
        Action::AuditRead => "reading audit journal…",
        Action::Verify => "verifying — touch the device to sign the challenge…",
        Action::RebootApp => "rebooting to app…",
        Action::RebootBootsel => "rebooting to BOOTSEL…",
    }
}
