// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! User presence for the emulator: either instant (the default, matching a
//! no-touch test image) or a prompt on the terminal that waits for a line on
//! stdin.
//!
//! The prompt prints the [`Confirm`] context — the trusted title plus the
//! relying party's untrusted strings — because a terminal is the closest thing
//! the emulator has to the trusted display, and seeing what a real screen would
//! have shown is most of the value of running one.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use rsk_sdk::Confirm;

use crate::signals::Signals;

/// How long a prompted touch may go unanswered. The firmware's button wait is
/// the same order; a client gives up well before this.
const TOUCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll the cancel flag this often while waiting for a line.
const POLL: Duration = Duration::from_millis(50);

/// The emulator's own presence verdict, mapped to each crate's `Presence` below.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Confirmed,
    Timeout,
    Declined,
    Cancelled,
}

pub struct EmuPresence {
    prompt: bool,
    lines: Option<Receiver<String>>,
    signals: Arc<Signals>,
}

impl EmuPresence {
    /// `prompt = false` confirms instantly (the `AlwaysConfirm` behaviour host
    /// tests and a no-button build already have); `true` waits on `lines`.
    pub fn new(prompt: bool, lines: Option<Receiver<String>>, signals: Arc<Signals>) -> Self {
        Self {
            prompt,
            lines,
            signals,
        }
    }

    fn ask(&mut self, confirm: Confirm<'_>) -> Verdict {
        if !self.prompt {
            return Verdict::Confirmed;
        }
        let Some(lines) = &self.lines else {
            return Verdict::Confirmed;
        };
        eprintln!("\n┌─ {} ─────────────", confirm.title);
        if !confirm.primary.is_empty() {
            eprintln!("│ {}", printable(confirm.primary));
        }
        if !confirm.secondary.is_empty() {
            eprintln!("│ {}", printable(confirm.secondary));
        }
        eprintln!("└─ [Enter] approve · [d] deny");

        self.signals.set_up_pending(true);
        let deadline = std::time::Instant::now() + TOUCH_TIMEOUT;
        let verdict = loop {
            if self.signals.cancelled() {
                eprintln!("   … cancelled by the host");
                break Verdict::Cancelled;
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("   … timed out");
                break Verdict::Timeout;
            }
            match lines.recv_timeout(POLL) {
                Ok(l) if l.trim().eq_ignore_ascii_case("d") => break Verdict::Declined,
                Ok(_) => break Verdict::Confirmed,
                Err(RecvTimeoutError::Timeout) => continue,
                // stdin closed: nothing can ever answer, so stop pretending.
                Err(RecvTimeoutError::Disconnected) => break Verdict::Timeout,
            }
        };
        self.signals.set_up_pending(false);
        verdict
    }
}

/// Reduce an untrusted relying-party string to printable ASCII before it reaches
/// the terminal — the same rule the trusted display applies, for the same reason:
/// these bytes are attacker-chosen, and a terminal takes escape sequences.
fn printable(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .take(64)
        .collect()
}

impl rsk_fido::UserPresence for EmuPresence {
    fn request(&mut self, confirm: rsk_fido::Confirm<'_>) -> rsk_fido::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_fido::Presence::Confirmed,
            Verdict::Timeout => rsk_fido::Presence::Timeout,
            Verdict::Declined => rsk_fido::Presence::Declined,
            Verdict::Cancelled => rsk_fido::Presence::Cancelled,
        }
    }

    /// The terminal prompt does name the operation, so a `--touch` run is the
    /// confirm-showing kind of authenticator CTAP 2.1 §6.6 exempts from the
    /// reset window; an auto-confirming one is not.
    fn shows_confirm(&self) -> bool {
        self.prompt
    }
}

// The sibling applets' traits carry no `Cancelled` arm — a cancel is a timeout
// to them, which is how `firmware`'s button backend maps it too.
impl rsk_openpgp::UserPresence for EmuPresence {
    fn request(&mut self, confirm: rsk_openpgp::Confirm<'_>) -> rsk_openpgp::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_openpgp::Presence::Confirmed,
            Verdict::Declined => rsk_openpgp::Presence::Declined,
            Verdict::Timeout | Verdict::Cancelled => rsk_openpgp::Presence::Timeout,
        }
    }
}

impl rsk_oath::UserPresence for EmuPresence {
    fn request(&mut self, confirm: rsk_oath::Confirm<'_>) -> rsk_oath::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_oath::Presence::Confirmed,
            Verdict::Declined => rsk_oath::Presence::Declined,
            Verdict::Timeout | Verdict::Cancelled => rsk_oath::Presence::Timeout,
        }
    }
}

impl rsk_otp::UserPresence for EmuPresence {
    fn request(&mut self, confirm: rsk_otp::Confirm<'_>) -> rsk_otp::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_otp::Presence::Confirmed,
            Verdict::Declined => rsk_otp::Presence::Declined,
            Verdict::Timeout | Verdict::Cancelled => rsk_otp::Presence::Timeout,
        }
    }
}

impl rsk_mgmt::UserPresence for EmuPresence {
    fn request(&mut self, confirm: rsk_mgmt::Confirm<'_>) -> rsk_mgmt::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_mgmt::Presence::Confirmed,
            Verdict::Declined => rsk_mgmt::Presence::Declined,
            Verdict::Timeout | Verdict::Cancelled => rsk_mgmt::Presence::Timeout,
        }
    }
}

impl rsk_rescue::UserPresence for EmuPresence {
    fn request(&mut self, confirm: rsk_rescue::Confirm<'_>) -> rsk_rescue::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_rescue::Presence::Confirmed,
            Verdict::Declined => rsk_rescue::Presence::Declined,
            Verdict::Timeout | Verdict::Cancelled => rsk_rescue::Presence::Timeout,
        }
    }
}
