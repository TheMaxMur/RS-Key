// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The touch presence backend: trusted Approve/Deny prompts for host ceremonies.

use super::gates::PinScope;
use super::*;

/// The on-screen presence backend — the `display` build's
/// [`crate::presence::Presence`]. Holds the shared [`Ui`]; renders a trusted
/// Approve/Deny prompt and block-waits a tap.
pub struct TouchPresence {
    ui: &'static RefCell<Ui>,
}

/// Outcome of a confirm wait. Unlike the BOOTSEL button, the screen has a real
/// decline gesture (the Deny button) → [`Outcome::Declined`].
enum Outcome {
    Confirmed,
    Declined,
    Timeout,
    Cancelled,
}

/// Common entry for a touch ceremony: switch the LED to the touch indicator, drop any
/// stale cancel left from an earlier wait, and arm `UP_PENDING` so the CTAPHID
/// keepalive reports `UPNEEDED`. Returns the LED status [`ceremony_end`] restores.
fn ceremony_begin() -> u8 {
    let saved = led::status();
    led::set_status(led::STATUS_TOUCH);
    CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    UP_PENDING.store(true, Ordering::Release);
    saved
}

/// Common exit: clear the presence flags, briefly hold the ambient status screen back
/// (so a hand-off to a following modal — pad, approve hold — doesn't flash idle), note
/// activity so a long ceremony doesn't immediately sleep, and restore the LED.
fn ceremony_end(saved_led: u8) {
    UP_PENDING.store(false, Ordering::Release);
    CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    AMBIENT_QUIET_UNTIL_MS.store(
        (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
        Ordering::Relaxed,
    );
    note_activity();
    led::set_status(saved_led);
}

impl TouchPresence {
    pub fn new(ui: &'static RefCell<Ui>) -> Self {
        Self { ui }
    }

    /// The standard-key BOOTSEL typed-ticket gesture has no analogue on the touch
    /// board (the screen is the interface), so the click-counter never fires.
    pub fn poll_pressed(&mut self) -> bool {
        false
    }

    /// Render `confirm` and block-wait for an Allow/Deny tap, a `CTAPHID_CANCEL`,
    /// or the presence timeout, then hand the panel back to the status loop. Sets
    /// `UP_PENDING` so the CTAPHID keepalive reports `UPNEEDED`, and polls
    /// `CANCEL_REQUESTED` each iteration — the same cross-executor contract the
    /// BOOTSEL wait honours.
    fn confirm_wait(&mut self, confirm: Confirm<'_>) -> Outcome {
        let saved = ceremony_begin();

        let prompt = ConfirmPrompt::new(confirm.title, confirm.primary, confirm.secondary);
        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let outcome = {
            // Held across the whole wait. The wait is synchronous, so the status
            // loop can't run (let alone borrow) until we return the panel.
            let mut u = self.ui.borrow_mut();
            // A host ceremony can arrive while the panel slept — restore it so the
            // trusted prompt is actually visible, and count it as activity.
            u.wake();
            note_activity();
            let _ = rsk_ui::render(&mut u.panel, &Screen::Confirm(prompt));
            u.shown = None; // force the status loop to repaint once we release it
            // Debounce: the CST328 reports a level, not an edge, so a finger still
            // down from a previous ceremony would start filling this hold on the
            // first poll — one press approving two ceremonies. Every other modal
            // waits for release for the same reason; so does the button build.
            u.touch.wait_release_ceremony(start, timeout);
            // Deny is a single tap; Approve is a deliberate hold that fills the button
            // as it builds (an accidental brush can't approve). The base button was
            // painted by the `render(Screen::Confirm)` above; the fill then grows in
            // place (no per-poll card clear → no flicker). Lifting the finger — or
            // sliding off the button — repaints the base, clearing the fill.
            let mut hold_start: Option<Instant> = None;
            let mut last_num: u16 = 0;
            loop {
                // The power button sleeps (and auto-locks) from a host confirm prompt too;
                // aborting the ceremony (→ Cancelled) is the safe outcome, like a decline —
                // no signature is ever produced without the deliberate on-screen hold.
                if u.sleep_button_pressed() {
                    break Outcome::Cancelled;
                }
                match u.touch.read().and_then(rsk_ui::hit_confirm) {
                    Some(Button::Deny) => break Outcome::Declined,
                    Some(Button::Allow) => {
                        let held = hold_start.get_or_insert_with(Instant::now).elapsed();
                        let num = held.as_millis().min(HOLD_MS) as u16;
                        let _ = rsk_ui::render_hold_fill(
                            &mut u.panel,
                            ALLOW_RECT,
                            "Hold to approve",
                            last_num,
                            num,
                            HOLD_MS as u16,
                            rsk_ui::theme::APPROVE,
                        );
                        last_num = num;
                        if held >= Duration::from_millis(HOLD_MS) {
                            break Outcome::Confirmed;
                        }
                    }
                    // Finger lifted or slid off the buttons: reset a building hold.
                    None => {
                        if hold_start.take().is_some() {
                            let _ = rsk_ui::render_hold_button(
                                &mut u.panel,
                                ALLOW_RECT,
                                "Hold to approve",
                                rsk_ui::theme::APPROVE,
                            );
                            last_num = 0;
                        }
                    }
                }
                if CANCEL_REQUESTED.load(Ordering::Acquire) {
                    break Outcome::Cancelled;
                }
                if start.elapsed() >= timeout {
                    break Outcome::Timeout;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        };

        ceremony_end(saved);
        outcome
    }

    /// The WebAuthn registration ceremony: the design's "Save new passkey?" card, with
    /// Cancel / Save (a tap, not a hold — registration is the lower-stakes action; the
    /// deliberate hold is reserved for the sign-in approve). Save confirms.
    fn run_add_passkey(&mut self, confirm: Confirm<'_>) -> Outcome {
        let rp = Label::clamp_domain(confirm.primary);
        let account = Label::clamp(confirm.secondary);
        let saved = ceremony_begin();
        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let outcome = {
            let mut u = self.ui.borrow_mut();
            u.wake();
            note_activity();
            let _ = rsk_ui::render_add_passkey(&mut u.panel, &rp, &account);
            u.shown = None;
            // Save is a single tap and this loop polls before any delay, so without
            // a release wait a finger already down approves the card in the same
            // frame it is painted — too fast to read. See confirm_wait above.
            u.touch.wait_release_ceremony(start, timeout);
            loop {
                // Save is a single tap, so the deadline must be tested BEFORE the read:
                // an expired ceremony that still sees a finger on ALLOW_RECT would read
                // the leftover press as a fresh approval (`confirm_wait`'s hold can't).
                if start.elapsed() >= timeout {
                    break Outcome::Timeout;
                }
                // The power button sleeps (and auto-locks) from the registration card too,
                // abandoning it (→ Cancelled) like a lifted finger that times out.
                if u.sleep_button_pressed() {
                    break Outcome::Cancelled;
                }
                match u.touch.read().and_then(rsk_ui::hit_confirm) {
                    Some(Button::Allow) => break Outcome::Confirmed,
                    Some(Button::Deny) => break Outcome::Declined,
                    None => {}
                }
                if CANCEL_REQUESTED.load(Ordering::Acquire) {
                    break Outcome::Cancelled;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        };
        ceremony_end(saved);
        outcome
    }

    /// Collect a PIN on the on-screen pad for the host built-in-UV path (clientPIN 0x06).
    /// The pad loop lives on [`Ui`] (which owns the panel + touch); borrow the shared
    /// `Ui` and run it there, so the host path and a display-initiated gate
    /// ([`Ui::run_delete`]) share one implementation.
    fn collect_pin_impl(&mut self, min_len: usize, out: &mut [u8]) -> rsk_fido::PinEntry {
        // No up-front "N tries remaining" caption here, unlike the local unlock gate: the
        // worker already holds the shared `fs` RefCell borrowed across this CTAP call
        // (clientPIN 0x06 → get_uv_token), so re-reading the counter would double-borrow
        // and panic. The placeholder dots (sized from `min_len`) still show; the host
        // already exposes the retry count via getPINRetries / getUVRetries.
        let expected = min_len.min(u8::MAX as usize) as u8;
        // The host built-in-UV PIN is the FIDO clientPIN — name it, so the user knows it
        // isn't the device-unlock or PIV PIN (the reported confusion behind a reset).
        self.ui.borrow_mut().collect_pin(
            PinScope::Fido.pin_title(),
            None,
            min_len,
            expected,
            out,
            false,
        )
    }

    /// Collect a PIN on the on-screen pad for a host CCID secure-PIN-entry request
    /// (OpenPGP / PIV VERIFY over a pinpad reader). Like [`Self::collect_pin_impl`]
    /// but with a per-PIN `title` so the trusted screen names which PIN is asked for.
    /// The host is waiting on this exact PIN (its `PC_to_RDR_Secure` is in flight,
    /// the CCID transport streaming time-extensions), so it blocks to the presence
    /// timeout (`yield_to_host = false`), exactly like the FIDO built-in-UV path. The
    /// worker holds `fs` borrowed across this call, so this — like `collect_pin_impl`
    /// — must never read `fs` (it touches only the panel's `Ui` RefCell).
    pub fn collect_pin_titled(
        &mut self,
        title: &'static str,
        min_len: usize,
        out: &mut [u8],
    ) -> rsk_fido::PinEntry {
        let expected = min_len.min(u8::MAX as usize) as u8;
        self.ui
            .borrow_mut()
            .collect_pin(title, None, min_len, expected, out, false)
    }
}

impl rsk_fido::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_fido::Confirm<'_>) -> rsk_fido::Presence {
        // The design's incoming ceremony, picked by the request kind:
        //  - Register (makeCredential) → "Save new passkey?" card (Cancel/Save tap)
        //  - Generic (sign-in / selection / probe) → the trusted Approve/Hold prompt
        let outcome = match confirm.kind {
            rsk_fido::ConfirmKind::Register => self.run_add_passkey(confirm),
            rsk_fido::ConfirmKind::Generic => self.confirm_wait(confirm),
        };
        match outcome {
            Outcome::Confirmed => {
                // A granted WebAuthn approval gets the design's brief "Approved" pop.
                // Scoped to the FIDO ceremony path (one request per make/getAssertion),
                // NOT the shared `confirm_wait`: OpenPGP/PIV touch policies call request()
                // once per signature, so flashing this — and paying its ~0.4 s — on every
                // PGP/PIV op would be both wrong-worded and a latency regression. The
                // ceremony borrow is already released, so this re-borrow is safe.
                self.ui
                    .borrow_mut()
                    .show_success(SuccessKind::Approved, Some(150));
                rsk_fido::Presence::Confirmed
            }
            Outcome::Declined => rsk_fido::Presence::Declined,
            Outcome::Timeout => rsk_fido::Presence::Timeout,
            Outcome::Cancelled => rsk_fido::Presence::Cancelled,
        }
    }

    // Every ceremony paints the `Confirm` it is asking about, so a tap approves that
    // operation and no other — the CTAP 2.1 §6.6 exemption from the reset window.
    fn shows_confirm(&self) -> bool {
        true
    }

    // The trusted display has an on-screen PIN pad, so built-in UV is available and
    // getInfo advertises `options.uv` — the PIN is typed here, never on the host.
    fn uv_available(&self) -> bool {
        true
    }

    fn collect_pin(&mut self, min_len: usize, out: &mut [u8]) -> rsk_fido::PinEntry {
        self.collect_pin_impl(min_len, out)
    }
}

impl rsk_openpgp::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_openpgp::Confirm<'_>) -> rsk_openpgp::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_openpgp::Presence::Confirmed,
            Outcome::Declined => rsk_openpgp::Presence::Declined,
            // OpenPGP/PIV run over CCID, which carries no CTAPHID_CANCEL.
            Outcome::Timeout | Outcome::Cancelled => rsk_openpgp::Presence::Timeout,
        }
    }
}

impl rsk_otp::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_otp::Confirm<'_>) -> rsk_otp::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_otp::Presence::Confirmed,
            Outcome::Declined => rsk_otp::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_otp::Presence::Timeout,
        }
    }
}

impl rsk_oath::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_oath::Confirm<'_>) -> rsk_oath::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_oath::Presence::Confirmed,
            Outcome::Declined => rsk_oath::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_oath::Presence::Timeout,
        }
    }
}

impl rsk_rescue::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_rescue::Confirm<'_>) -> rsk_rescue::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_rescue::Presence::Confirmed,
            Outcome::Declined => rsk_rescue::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_rescue::Presence::Timeout,
        }
    }
}

impl rsk_mgmt::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_mgmt::Confirm<'_>) -> rsk_mgmt::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_mgmt::Presence::Confirmed,
            Outcome::Declined => rsk_mgmt::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_mgmt::Presence::Timeout,
        }
    }
}
