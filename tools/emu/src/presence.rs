// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! User presence for the emulator: instant, prompted on the terminal, or
//! deterministically confirmed after a delay.
//!
//! The prompt prints the [`Confirm`] context — the trusted title plus the
//! relying party's untrusted strings — because a terminal is the closest thing
//! the emulator has to the trusted display, and seeing what a real screen would
//! have shown is most of the value of running one.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use rsk_sdk::Confirm;

use crate::signals::Signals;

/// How long a prompted touch may go unanswered. The firmware's button wait is
/// the same order; a client gives up well before this.
const TOUCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll the cancel flag this often while waiting for a line.
const POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PresenceMode {
    Instant,
    Terminal,
    Delayed(Duration),
}

/// The emulator's own presence verdict, mapped to each crate's `Presence` below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Confirmed,
    Timeout,
    Declined,
    Cancelled,
}

pub struct EmuPresence {
    mode: PresenceMode,
    lines: Option<Receiver<String>>,
    signals: Arc<Signals>,
}

impl EmuPresence {
    pub fn new(mode: PresenceMode, lines: Option<Receiver<String>>, signals: Arc<Signals>) -> Self {
        Self {
            mode,
            lines,
            signals,
        }
    }

    fn ask(&mut self, confirm: Confirm<'_>) -> Verdict {
        if self.mode == PresenceMode::Instant {
            return Verdict::Confirmed;
        }
        eprintln!("\n┌─ {} ─────────────", confirm.title);
        if !confirm.primary.is_empty() {
            eprintln!("│ {}", printable(confirm.primary));
        }
        if !confirm.secondary.is_empty() {
            eprintln!("│ {}", printable(confirm.secondary));
        }
        match self.mode {
            PresenceMode::Terminal => eprintln!("└─ [Enter] approve · [d] deny"),
            PresenceMode::Delayed(delay) => {
                eprintln!("└─ auto-approve in {} ms", delay.as_millis())
            }
            PresenceMode::Instant => unreachable!(),
        }

        self.signals.set_up_pending(true);
        let verdict = match self.mode {
            PresenceMode::Terminal => self.wait_for_terminal(),
            PresenceMode::Delayed(delay) => self.wait_for_delay(delay),
            PresenceMode::Instant => unreachable!(),
        };
        self.signals.set_up_pending(false);
        verdict
    }

    fn wait_for_terminal(&self) -> Verdict {
        let lines = self
            .lines
            .as_ref()
            .expect("terminal presence requires a stdin receiver");
        let deadline = Instant::now() + TOUCH_TIMEOUT;
        loop {
            if self.signals.cancelled() {
                eprintln!("   … cancelled by the host");
                return Verdict::Cancelled;
            }
            if Instant::now() >= deadline {
                eprintln!("   … timed out");
                return Verdict::Timeout;
            }
            match lines.recv_timeout(POLL) {
                Ok(l) if l.trim().eq_ignore_ascii_case("d") => return Verdict::Declined,
                Ok(_) => return Verdict::Confirmed,
                Err(RecvTimeoutError::Timeout) => continue,
                // stdin closed: nothing can ever answer, so stop pretending.
                Err(RecvTimeoutError::Disconnected) => return Verdict::Timeout,
            }
        }
    }

    fn wait_for_delay(&self, delay: Duration) -> Verdict {
        let deadline = Instant::now() + delay;
        loop {
            if self.signals.cancelled() {
                eprintln!("   … cancelled by the host");
                return Verdict::Cancelled;
            }
            let now = Instant::now();
            if now >= deadline {
                return Verdict::Confirmed;
            }
            std::thread::sleep(POLL.min(deadline - now));
        }
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

impl rsk_sdk::UserPresence for EmuPresence {
    /// A smartcard touch policy. Those applets are reached over CCID, which
    /// carries no `CTAPHID_CANCEL` — a cancel is a non-confirmation, which is
    /// how `firmware`'s button backend maps it too.
    fn request(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_sdk::Presence::Confirmed,
            Verdict::Declined => rsk_sdk::Presence::Declined,
            Verdict::Timeout | Verdict::Cancelled => rsk_sdk::Presence::Timeout,
        }
    }

    /// A CTAP2 ceremony, which *can* be cancelled mid-wait — the in-flight
    /// command owes `CTAP2_ERR_KEEPALIVE_CANCEL`, so report it.
    fn request_ceremony(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        match self.ask(confirm) {
            Verdict::Confirmed => rsk_sdk::Presence::Confirmed,
            Verdict::Timeout => rsk_sdk::Presence::Timeout,
            Verdict::Declined => rsk_sdk::Presence::Declined,
            Verdict::Cancelled => rsk_sdk::Presence::Cancelled,
        }
    }

    /// The terminal prompt does name the operation and wait for a person, so a
    /// `--touch` run is the confirm-showing kind of authenticator CTAP 2.1 §6.6
    /// exempts from the reset window. An auto-confirming one is not, and
    /// [`PresenceMode::Delayed`] is auto-confirming — it prints the same lines,
    /// but a timer answers them, so nobody has seen anything. Claiming otherwise
    /// turns off the reset window (`rsk_fido::reset`) in the one mode built for
    /// unattended conformance runs: measured, a reset 13.3 s after power-on
    /// returned `0x00` instead of `NOT_ALLOWED`, and `tests/27_reset_window.py`
    /// failed. It also promotes the emulator to the trusted-display profile for
    /// `makeCredential` / `getAssertion` / `setPIN`, which is not what a
    /// screenless key under test is.
    fn shows_confirm(&self) -> bool {
        self.mode == PresenceMode::Terminal
    }
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;
