// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The seed-backup screens: status, on-device recovery reveal, and sealing.

use super::gates::PinScope;
use super::*;

/// How long a revealed PIN stays shown on the pad without a key press before it auto
/// re-masks, so a device left mid-entry with the PIN revealed doesn't keep the cleartext
/// digits lit for the whole presence timeout.
pub(super) const REVEAL_MASK_MS: u64 = 4_000;

impl<'a, P, T, H, S, R> Ui<'a, P, T, H, S, R>
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng,
{
    /// The read-only on-device backup status (Settings → Security → Backup): snapshot the
    /// seed-backup flags and show them until the back chevron, the power button (sleeps +
    /// locks), a queued host command, or the inactivity timeout. Synchronous like the other
    /// browse modals (the worker is parked); read-only — no tap mutates anything and it
    /// shows no secret, only whether a recovery seed is present and its export window sealed.
    /// Snapshot the seed-backup status into the view model. `can_reveal` decides whether the
    /// on-device recovery-phrase + seal actions are offered: only while the window is open and
    /// the seed is actually readable (present, exportable build, not soft-locked).
    fn load_backup(&self) -> BackupView {
        // Both reads under ONE borrow (multiple `borrow_mut()` in one statement would panic).
        let (st, device_pin_set) = {
            let mut fs = self.fs.borrow_mut();
            (
                rsk_fido::passkeys::backup_status(&mut fs),
                rsk_fido::passkeys::device_pin_is_set(&mut fs),
            )
        };
        BackupView {
            sealed: st.sealed,
            has_seed: st.has_seed,
            exportable: st.exportable,
            // The reveal exposes the master secret, so it requires a device PIN to be set (the
            // hold is the second factor, not the only one); the seal shares the gate. Without a
            // device PIN the device never locks, so a bare hold would let anyone with physical
            // access read the seed.
            can_reveal: st.has_seed && st.exportable && !st.sealed && !st.locked && device_pin_set,
        }
    }

    /// The Backup screen (Settings → Security → Backup): the seed-backup status, plus — while
    /// the window is open — the on-device **Show recovery phrase** and **Seal backup** actions.
    /// The phrase is shown on the trusted panel and never crosses USB. Reloads the status after
    /// each action so a seal flips the screen to sealed. Synchronous (worker parked); the back
    /// chevron, power button, a queued host command, or the inactivity timeout exit.
    pub(super) fn run_backup(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        'screen: loop {
            let view = self.load_backup();
            let _ = rsk_ui::render_backup(&mut self.panel, &view);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        return;
                    }
                    if view.can_reveal
                        && let Some(k) = rsk_ui::hit_backup(p)
                    {
                        match k {
                            rsk_ui::BackupKey::Reveal => self.run_reveal_recovery(),
                            rsk_ui::BackupKey::Seal => self.run_seal_backup(),
                        }
                        if self.asleep {
                            return; // a sub-modal slept + locked via the power button
                        }
                        continue 'screen; // reload status (a seal flips it) and repaint
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if self.hooks.host_request_pending_after(last) || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }
    }

    /// Reveal the recovery seed on the trusted display — read and rendered **on-device**, never
    /// over USB. Gated by the device PIN (re-auth before any secret is shown), then a format
    /// chooser: a single 24-word BIP-39 phrase, or `T`-of-`N` SLIP-39 Shamir shares. The PIN is
    /// entered once; the chooser re-shows after each format flow so the user can view both. The
    /// back chevron / power button / a queued host command / the inactivity timeout exit.
    fn run_reveal_recovery(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        // Re-authenticate with the device PIN before any recovery secret is shown (no PIN set
        // returns true at once; a wrong PIN / decline / timeout aborts with nothing revealed).
        if !self.local_pin_gate(PinScope::Device) {
            return;
        }
        'chooser: loop {
            let _ = rsk_ui::render_backup_format(&mut self.panel);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_pk_back(p) {
                        return;
                    }
                    if let Some(fmt) = rsk_ui::hit_backup_format(p) {
                        match fmt {
                            rsk_ui::BackupFormat::Phrase => self.reveal_phrase(),
                            rsk_ui::BackupFormat::Shares => self.reveal_shares(),
                        }
                        if self.asleep {
                            return; // a sub-modal slept + locked via the power button
                        }
                        continue 'chooser; // re-show the chooser after the format flow
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if self.hooks.host_request_pending_after(last) || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }
    }

    /// Show the 24-word BIP-39 recovery phrase (the chooser's "Single phrase" choice). A
    /// deliberate hold over the warning, then the paged words. The seed is zeroized the instant
    /// the indices are derived; the indices + word slots on exit, and the screen auto-clears on
    /// the inactivity timeout (walked-away guard). The device PIN was already checked.
    fn reveal_phrase(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let _ = rsk_ui::render_reveal_warning(&mut self.panel, rsk_ui::RevealKind::Phrase);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if !self.hold_to_confirm("Hold to reveal", rsk_ui::theme::DANGER_FILL) {
            return;
        }
        // Read + derive. The seed lives only long enough to compute the indices, then is wiped.
        let mkek = read_fused(self.keys.mkek_source);
        let dev = self.keys.device(&mkek);
        let mut seed_opt = {
            let mut fs = self.fs.borrow_mut();
            rsk_fido::passkeys::load_keydev(&dev, &mut fs)
        };
        let mut indices = match seed_opt {
            // `Option<[u8;32]>` is `Copy`, so this copies the seed out — derive, then wipe BOTH
            // the copy here and the original `seed_opt` below, or a seed remnant lingers.
            Some(mut seed) => {
                let idx = rsk_bip39::entropy_to_indices(&seed);
                seed.zeroize();
                idx
            }
            None => return, // no seed / soft-locked — nothing to show
        };
        seed_opt.zeroize();
        // The seed left the device's own keeping — the same event `BACKUP_EXPORT`
        // records over USB, and the higher-value half of the pair, since nothing on
        // the host can attest that it happened (audit run-34 #17).
        self.journal_local(rsk_fido::journal::EV_BACKUP_EXPORT);
        let mut words: [&str; rsk_bip39::WORD_COUNT] = [""; rsk_bip39::WORD_COUNT];
        for (w, &i) in words.iter_mut().zip(indices.iter()) {
            *w = rsk_bip39::word(i);
        }
        let pages: u16 = rsk_bip39::WORD_COUNT.div_ceil(rsk_ui::SEED_WORDS_PER_PAGE) as u16;
        let mut page: u16 = 0;
        let _ = rsk_ui::render_seed_phrase(&mut self.panel, &words, page, pages);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = match k {
                        rsk_ui::PagerKey::Prev => page.saturating_sub(1),
                        rsk_ui::PagerKey::Next => (page + 1).min(pages - 1),
                    };
                    let _ = rsk_ui::render_seed_phrase(&mut self.panel, &words, page, pages);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            // A queued host command or the idle timeout exits + wipes — the master secret must
            // never linger on a walked-away panel.
            if self.hooks.host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        // Wipe both secrets from RAM: the indices (the canonical secret) via `Zeroize`, and the
        // word slots (which also encode the order) via a black-boxed fill so it isn't elided.
        indices.zeroize();
        words.fill("");
        let _ = core::hint::black_box(&words);
        note_activity();
        self.end_modal();
    }

    /// Show the recovery seed as `T`-of-`N` SLIP-39 Shamir shares (the chooser's "Shamir
    /// shares" choice). A `T`/`N` picker (default 2-of-3), a deliberate hold over the warning,
    /// then the shares page-by-page **on-device** (never over USB). The shares are split from
    /// the device DRBG and are bit-for-bit recombinable by `rsk backup restore --scheme
    /// slip39`. The seed is wiped the instant the shares are derived; the share words on exit.
    fn reveal_shares(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let (mut threshold, mut total): (u8, u8) = (2, 3); // default 2-of-3
        'picker: loop {
            let _ = rsk_ui::render_share_picker(&mut self.panel, threshold, total);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_pk_back(p) {
                        return; // back to the format chooser
                    }
                    if let Some(k) = rsk_ui::hit_share_picker(p) {
                        if k == rsk_ui::ShareAdjust::Continue {
                            break 'picker;
                        }
                        let (t, n) = rsk_ui::step_share_params(threshold, total, k);
                        threshold = t;
                        total = n;
                        continue 'picker; // re-render the picker with the new values
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if self.hooks.host_request_pending_after(last) || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }

        // A deliberate hold over the warning before any secret is shown.
        self.touch.wait_release(Instant::now(), idle_limit);
        let _ = rsk_ui::render_reveal_warning(&mut self.panel, rsk_ui::RevealKind::Shares);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if !self.hold_to_confirm("Hold to reveal", rsk_ui::theme::DANGER_FILL) {
            return;
        }

        // Read the seed and split it on-device; the seed lives only long enough to generate the
        // shares, then is wiped (both the copied-out seed and the original `Option`).
        let mkek = read_fused(self.keys.mkek_source);
        let dev = self.keys.device(&mkek);
        let mut seed_opt = {
            let mut fs = self.fs.borrow_mut();
            rsk_fido::passkeys::load_keydev(&dev, &mut fs)
        };
        let mut shares = [[0u16; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES];
        let ok = match seed_opt {
            Some(mut seed) => {
                let r = {
                    let mut rng = self.rng.borrow_mut();
                    let mut fill = |b: &mut [u8]| rsk_sdk::Rng::fill(&mut *rng, b);
                    rsk_slip39::generate(&seed, threshold, total, &mut fill, &mut shares)
                };
                seed.zeroize();
                r.is_ok()
            }
            None => false, // no seed / soft-locked — nothing to show
        };
        seed_opt.zeroize();
        if ok {
            self.journal_local(rsk_fido::journal::EV_BACKUP_EXPORT);
            self.show_shares(&shares, total);
        }
        shares.zeroize();
        note_activity();
        self.end_modal();
    }

    /// Page through the generated SLIP-39 shares: "Share i/N" with that share's words, a global
    /// pager walking every share's pages in order (3 pages of ≤12 words per 33-word share). The
    /// back chevron / power button / a queued host command / the inactivity timeout exit; the
    /// word slots are wiped on exit (the caller zeroizes the share indices).
    fn show_shares(
        &mut self,
        shares: &[[u16; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES],
        total: u8,
    ) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let total = total as u16;
        let per_share: u16 =
            (rsk_slip39::WORDS_PER_SHARE as u16).div_ceil(rsk_ui::SEED_WORDS_PER_PAGE as u16); // 3 pages/share
        let pages = total * per_share;
        let mut words: [&str; rsk_slip39::WORDS_PER_SHARE] = [""; rsk_slip39::WORDS_PER_SHARE];
        let mut page: u16 = 0;
        let mut shown_share = u16::MAX;
        'paged: loop {
            let share = page / per_share;
            if share != shown_share {
                for (w, &i) in words.iter_mut().zip(shares[share as usize].iter()) {
                    *w = rsk_slip39::word(i);
                }
                shown_share = share;
            }
            let _ =
                rsk_ui::render_slip39_share(&mut self.panel, &words, share + 1, total, page, pages);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    break 'paged;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        break 'paged;
                    }
                    if let Some(k) = rsk_ui::hit_pager(p) {
                        page = match k {
                            rsk_ui::PagerKey::Prev => page.saturating_sub(1),
                            rsk_ui::PagerKey::Next => (page + 1).min(pages - 1),
                        };
                        continue 'paged; // repaint (rebuilds words when the share changes)
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if self.hooks.host_request_pending_after(last) || last.elapsed() >= idle_limit {
                    break 'paged;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }
        // The share words encode the (secret) share order — wipe the slots on exit. A
        // black-boxed fill so the compiler can't elide it; the indices are the caller's to wipe.
        words.fill("");
        let _ = core::hint::black_box(&words);
    }

    /// Seal the backup window on-device (Settings → Security → Backup → Seal backup): the
    /// device PIN, then a deliberate hold, then write the seal marker so the seed can no
    /// longer be shown or exported until a factory reset. The PIN gate is not about
    /// exposing a secret — it is about the change being *irreversible*, the same rule
    /// [`Ui::run_delete`] and [`Ui::run_factory_reset`] follow. Relying on "Settings is
    /// already locked" would be wrong twice over: the button only renders when a device
    /// PIN exists, and the host equivalent (`BACKUP_FINALIZE`) carries its own PIN gate.
    fn run_seal_backup(&mut self) {
        if !self.local_pin_gate(PinScope::Device) {
            self.end_modal();
            return;
        }
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let _ = rsk_ui::render_seal_confirm(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if self.hold_to_confirm("Hold to seal", rsk_ui::theme::DANGER_FILL) {
            let _ = rsk_fido::passkeys::mark_backup_sealed(&mut self.fs.borrow_mut());
            self.journal_local(rsk_fido::journal::EV_BACKUP_FINALIZE);
        }
        self.end_modal();
    }
}
