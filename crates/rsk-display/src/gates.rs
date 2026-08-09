// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The local PIN gates: unlock, first-run onboarding, and the shared PIN scopes.

use super::*;

/// Which PIN a trusted-display gate or set/change flow operates on. The **device PIN**
/// gates local control (unlock, on-device delete, factory reset) and is independent of the
/// **FIDO** clientPIN (WebAuthn / built-in UV). The on-screen pad and verify logic are
/// shared; only the backing record (`EF_DEVICE_PIN` vs `EF_PIN`) and floor differ.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PinScope {
    Device,
    Fido,
}

impl PinScope {
    /// The PIN-screen header for this scope — so every pad names *which* credential it
    /// is collecting (the user's reported confusion: the same bare "Enter PIN" served
    /// the device lock, the FIDO clientPIN, and the PIV PIN). The step (New / Confirm /
    /// current) rides in the caption line, so this stays a stable scope label.
    pub(super) fn pin_title(self) -> &'static str {
        match self {
            PinScope::Device => "Device PIN",
            PinScope::Fido => "FIDO PIN",
        }
    }
}

/// The PIN-screen header for a PIV reference (the application PIN or the PUK), the
/// PIV analog of [`PinScope::pin_title`]. Also the CCID secure-PIN path's title source
/// (`worker::secure_pin_meta`), so a host VERIFY and an on-panel change name the same thing.
pub fn piv_ref_title(which: rsk_piv::PinRef) -> &'static str {
    match which {
        rsk_piv::PinRef::Pin => "PIV PIN",
        rsk_piv::PinRef::Puk => "PIV PUK",
    }
}

impl<'a, P, T, H, S, R> Ui<'a, P, T, H, S, R>
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
    R: rsk_device::Rng,
{
    /// The on-screen unlock flow, reached by a tap on the Locked screen. Reuses the
    /// device-PIN gate (the `EF_DEVICE_PIN` retry ladder, same as the destructive-action
    /// gate): a correct PIN drops the lock, a wrong one re-prompts until the right PIN, a
    /// cancel / timeout, or the counter is spent — all of which leave it locked. Returns
    /// the panel to [`status_task`], which then paints Home (unlocked) or Locked again.
    pub(super) fn run_unlock(&mut self) {
        // Let the unlock tap's finger lift before the pad starts reading digits.
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        // `local_pin_gate` returns true with no device PIN set; that can only happen here if
        // EF_DEVICE_PIN vanished after the lock — only via a touch-confirmed host
        // authenticatorReset (clears it in place) or the device-PIN-gated on-device factory
        // reset (reboots). Both are authorized resets, so "no PIN ⇒ unlock" is the correct
        // post-reset behaviour (nothing to verify against), never a bypass.
        if self.local_pin_gate(PinScope::Device) {
            self.locked = false;
        }
        self.end_modal();
    }

    /// Handle a tap on the first-run onboarding screen ([`Screen::Onboard`]). **Set a PIN**
    /// opens the device-PIN set flow; if a PIN ends up set, onboarding is done (and the
    /// device is unlocked for this session — the user just proved presence). **Continue
    /// without PIN** records the choice in `EF_DISPLAY` so the prompt is never shown again
    /// (until a factory reset), then drops to Home. A tap that misses both buttons, or a
    /// queued host command / timeout reaching here, leaves onboarding pending — it re-shows
    /// on the next idle frame, so the offer is never silently lost. `p` is the opening tap.
    pub(super) fn run_onboarding(&mut self, p: rsk_ui::Point) {
        match rsk_ui::hit_onboard(p) {
            Some(rsk_ui::OnboardChoice::SetPin) => {
                // `run_set_pin` waits for the opening finger to lift, gates (a no-op with no
                // PIN set yet), then collects New + Confirm; it writes only on a match.
                self.run_set_pin(PinScope::Device);
                if rsk_fido::passkeys::device_pin_is_set(&mut self.fs.borrow_mut()) {
                    self.onboarding = false;
                    self.refresh_home_stats();
                }
            }
            Some(rsk_ui::OnboardChoice::Skip) => {
                self.pin_declined = true;
                self.save_display_config();
                self.onboarding = false;
                // Refresh the Home cache before the caller paints Home: a host ceremony can
                // have added/removed a resident passkey while the panel sat on Onboard (it
                // paints over Onboard without consulting `onboarding`), so the count could be
                // stale — the same reason the unlock path refreshes. (The SetPin branch above
                // already refreshes.)
                self.refresh_home_stats();
                // Let the choosing finger lift before the next idle read paints Home, so the
                // same touch isn't re-read as a nav tap.
                self.touch
                    .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
            }
            None => {}
        }
        self.end_modal();
    }

    /// Gate a destructive local action behind a PIN when one is set: collect it on the pad
    /// and verify it against the chosen `scope`'s record and retry counter (the device PIN
    /// for local control, or the FIDO clientPIN for the FIDO-PIN change flow). A wrong entry
    /// re-prompts with a "Wrong PIN, N left" caption until the right PIN, a decline /
    /// timeout, or the counter is spent. Returns whether the action may proceed (`true` =
    /// no PIN of that scope set, or the correct PIN was entered).
    pub(super) fn local_pin_gate(&mut self, scope: PinScope) -> bool {
        let title = scope.pin_title();
        let (retries, expected) = {
            let mut fs = self.fs.borrow_mut();
            let is_set = match scope {
                PinScope::Device => rsk_fido::passkeys::device_pin_is_set(&mut fs),
                PinScope::Fido => rsk_fido::passkeys::pin_is_set(&mut fs),
            };
            if !is_set {
                return true;
            }
            let retries = match scope {
                PinScope::Device => rsk_fido::passkeys::device_pin_retries_left(&mut fs),
                PinScope::Fido => rsk_fido::passkeys::pin_retries_left(&mut fs),
            };
            // The placeholder-dot count: the FIDO PIN shows its `minPINLength` policy; the
            // device PIN has no host policy, so it shows the compile-time MIN_PIN_LENGTH
            // floor (4 by default, 6 under `fips-profile`) — the floor `store_device_pin`
            // enforces. The OK floor stays 4 (below) — these can differ, hence the arg.
            let expected = match scope {
                PinScope::Device => rsk_fido::passkeys::MIN_PIN_LENGTH,
                PinScope::Fido => rsk_fido::passkeys::min_pin_length(&mut fs),
            };
            (retries, expected)
        };
        let mut pin = [0u8; 64];
        // Show the remaining attempts up front (the design's enterpin "N tries
        // remaining"); a wrong entry then swaps it for the danger "Wrong PIN, N left".
        let mut caption = retries.map(|left| PinCaption::TriesRemaining { left });
        let mut blocked = false;
        let proceed = loop {
            // CTAP's 4-digit floor; the verify checks the exact PIN regardless, so a higher
            // `minPINLength` policy is still satisfied by typing it in full. (A PIN set
            // before the policy was raised may be shorter than `expected`.)
            match self.collect_pin(title, caption, 4, expected, &mut pin, true) {
                rsk_fido::PinEntry::Entered(len) => {
                    let mkek = read_fused(self.keys.mkek_source);
                    let dev = self.keys.device(&mkek);
                    let verdict = match scope {
                        PinScope::Device => rsk_fido::passkeys::spend_and_verify_device_pin(
                            &dev,
                            &mut self.fs.borrow_mut(),
                            &pin[..len.min(pin.len())],
                        ),
                        PinScope::Fido => rsk_fido::passkeys::spend_and_verify_local_pin(
                            &dev,
                            &mut self.fs.borrow_mut(),
                            &pin[..len.min(pin.len())],
                        ),
                    };
                    match verdict {
                        rsk_fido::passkeys::LocalPin::Ok => break true,
                        // Re-prompt showing the remaining attempts until the budget runs out.
                        rsk_fido::passkeys::LocalPin::Wrong { retries_left } => {
                            caption = Some(PinCaption::WrongPin { retries_left });
                        }
                        // Budget spent — note it and break; the notice is shown below, once
                        // the immutable `dev` borrow has been released.
                        rsk_fido::passkeys::LocalPin::Blocked => {
                            blocked = true;
                            break false;
                        }
                    }
                }
                // Cancel / timeout / cancelled-by-host: abandon the action.
                _ => break false,
            }
        };
        pin.zeroize();
        if blocked {
            self.show_pin_blocked();
        }
        proceed
    }
}

#[cfg(test)]
#[path = "gates_tests.rs"]
mod tests;
