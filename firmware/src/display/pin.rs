// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The on-screen PIN pad and the PIN/hold-gated set, change, and confirm flows.

use super::backup::REVEAL_MASK_MS;
use super::gates::{PinScope, piv_ref_title};
use super::*;

/// PIV PIN/PUK length floor for the on-panel change/unblock pads — the PIV minimum (the
/// default PIN `123456` is six). The applet stores up to eight; `rsk_piv::pad_pin` pads the
/// rest to the 8-byte `0xFF` wire form so a host VERIFY (which always pads) matches.
const PIV_PIN_MIN: usize = 6;

impl Ui {
    /// The rename screen: edit a relying party's device-local nickname with a T9
    /// phone-style keypad. Each key 1-9 cycles through its letter group on repeated
    /// presses; pressing a different key (or waiting [`T9_COMMIT_MS`]) commits the
    /// pending character. Backspace deletes, Save persists via
    /// [`rsk_fido::passkeys::set_rp_nickname`]. Returns the committed nickname on
    /// success, `None` on cancel / sleep / timeout / failed store.
    pub(super) fn run_rename(&mut self, current: &Label, hash: &[u8; 32]) -> Option<Label> {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let groups = rsk_ui::T9_GROUPS;
        let mut buf = [0u8; rsk_fido::passkeys::RP_NICK_MAX_LEN];
        let mut len = 0usize;
        for &b in current.as_str().as_bytes() {
            if len < buf.len() {
                buf[len] = b;
                len += 1;
            }
        }

        // T9 state
        let mut pending: Option<u8> = None; // char being cycled (not yet committed)
        let mut active_group: Option<usize> = None; // which T9 group is active
        let mut cycle_at: usize = 0; // position within the active group
        let mut last_t9_press = Instant::now();
        /// Auto-commit the pending character after this long without a same-key press.
        const T9_COMMIT_MS: u64 = 800;

        let val = |buf: &[u8], len: usize| -> Label { Label::clamp(&buf[..len]) };

        // Initial full-frame paint.
        let _ = rsk_ui::render_rename(
            &mut self.panel,
            val(&buf, len).as_str(),
            pending,
            active_group,
        );
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        let mut last = Instant::now();
        let mut prev_active = active_group;
        loop {
            if self.sleep_button_pressed() {
                return None;
            }

            // Auto-commit pending char after T9 timeout
            if pending.is_some()
                && active_group.is_some()
                && last_t9_press.elapsed() >= Duration::from_millis(T9_COMMIT_MS)
            {
                if len < buf.len() {
                    buf[len] = pending.unwrap();
                    len += 1;
                }
                pending = None;
                active_group = None;
                let _ =
                    rsk_ui::render_rename_field(&mut self.panel, val(&buf, len).as_str(), pending);
                if prev_active != active_group {
                    let _ = rsk_ui::render_rename_keys(&mut self.panel, active_group);
                    prev_active = active_group;
                }
                self.shown = None;
            }

            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    return None;
                }
                if let Some(k) = rsk_ui::hit_rename(p) {
                    match k {
                        rsk_ui::RenameKey::Char(gi) => {
                            let group = groups[gi];
                            if active_group == Some(gi) {
                                cycle_at = (cycle_at + 1) % group.len();
                            } else {
                                if let Some(ch) = pending
                                    && len < buf.len()
                                {
                                    buf[len] = ch;
                                    len += 1;
                                }
                                active_group = Some(gi);
                                cycle_at = 0;
                            }
                            pending = Some(group[cycle_at]);
                            last_t9_press = Instant::now();
                        }
                        rsk_ui::RenameKey::Backspace => {
                            if pending.is_some() {
                                pending = None;
                                active_group = None;
                            } else {
                                len = len.saturating_sub(1);
                            }
                        }
                        rsk_ui::RenameKey::Save => {
                            if let Some(ch) = pending
                                && len < buf.len()
                            {
                                buf[len] = ch;
                                len += 1;
                            }
                            let committed = val(&buf, len);
                            let dev = self.keys.device();
                            let saved = rsk_fido::passkeys::set_rp_nickname(
                                &dev,
                                &mut self.fs.borrow_mut(),
                                hash,
                                committed.as_str(),
                            );
                            return saved.then_some(committed);
                        }
                    }
                    // Partial updates: field always, keys only if active group changed.
                    let _ = rsk_ui::render_rename_field(
                        &mut self.panel,
                        val(&buf, len).as_str(),
                        pending,
                    );
                    if prev_active != active_group {
                        let _ = rsk_ui::render_rename_keys(&mut self.panel, active_group);
                        prev_active = active_group;
                    }
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                return None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// The on-device Firmware flow (Settings → Firmware): show the installed build and the
    /// honest update story, then take a deliberate (blue) hold to reboot into the BOOTSEL
    /// bootloader so the RS-Key host app can flash a new signed image. The signature is only
    /// verified by the boot ROM when secure boot is fused, so the screen reads the *real* OTP
    /// state and states the check as fact only then. The back chevron, a slid-off finger, or
    /// the inactivity timeout abandon it without rebooting. On a completed hold it *queues* a
    /// secure reboot rather than calling the ROM directly: the worker owns the live RAM
    /// secrets (FIDO auth state, the DRBG), so only it can scrub them before dropping to
    /// BOOTSEL. Returns `true` once a reboot is queued so the caller exits the menu — the
    /// worker shares this thread-mode executor and only runs once this busy-waiting UI yields,
    /// so the ambient loop must park (on `reboot_pending`) and hand the executor over to it.
    pub(super) fn run_firmware(&mut self) -> bool {
        use rsk_rescue::Platform as _;
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        // A pure OTP read (no flash / no shared borrow) — true only on a fused, secure-boot
        // device, where the boot ROM actually verifies the image signature on next boot.
        let secure_boot = crate::rescue_platform::RescuePlatform
            .secure_boot_status()
            .enabled;
        let _ = rsk_ui::render_firmware(
            &mut self.panel,
            self.info.version,
            self.info.chipid,
            secure_boot,
        );
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if self.hold_to_confirm("Verify & install", rsk_ui::theme::ACCENT_FILL) {
            let _ = rsk_ui::render_rebooting(&mut self.panel);
            crate::vendor::request_reboot(true);
            return true;
        }
        self.end_modal();
        false
    }

    /// Enumerate the resident accounts under `hash` into `accts`, recording each one's
    /// `EF_CRED` slot fid into the parallel `fids` (the key [`run_delete`] takes to
    /// remove it). The label is the user name, else the display name, else a placeholder
    /// (a binary user id is not a legible label); credProtect ≥ 2 marks the row UV-gated.
    pub(super) fn load_accts(
        &self,
        hash: &[u8; 32],
        accts: &mut [AccountRow],
        fids: &mut [u16],
        page: u16,
    ) -> (usize, u16) {
        let dev = self.keys.device();
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut store = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let total = rsk_fido::passkeys::for_each_cred(&dev, &mut *store, hash, |a| {
            if idx >= offset && n < accts.len() {
                let name = if !a.user_name.is_empty() {
                    Label::clamp(a.user_name.as_bytes())
                } else if !a.user_display_name.is_empty() {
                    Label::clamp(a.user_display_name.as_bytes())
                } else {
                    Label::clamp(b"(no name)")
                };
                accts[n] = AccountRow {
                    name,
                    protected: a.cred_protect >= 2,
                };
                fids[n] = a.ef_cred_fid;
                n += 1;
            }
            idx += 1;
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// Collect a PIN on the on-screen pad (the trusted built-in-UV input). Renders the
    /// masked keypad, block-polls the CST328 accumulating ASCII digits into `out`, and
    /// honours the same UP_PENDING / CANCEL_REQUESTED / timeout contract as the confirm
    /// wait. Owns the panel via `&mut self` (single thread executor → the worker is
    /// parked), so both the host built-in-UV path ([`TouchPresence::collect_pin`]) and a
    /// display-initiated gate ([`local_pin_gate`]) share one pad. Each key debounces to
    /// release; OK commits only at/above `min_len`, Del backspaces, Cancel declines, and the
    /// eye toggle reveals/hides the typed digits (auto re-masking after a short idle). The
    /// entered digits are the caller's to zeroize after verifying.
    ///
    /// `yield_to_host`: on a *local* gate (delete / factory-reset / unlock) no host is
    /// waiting on this PIN, so a queued host command must not be starved while the user
    /// types — set it `true` to abandon entry ([`PinEntry::Cancelled`], no retry burned)
    /// the instant a command arrives, mirroring the browse modals. The host built-in-UV
    /// path sets it `false`: there the host *is* waiting on this exact PIN (its `REQ` is
    /// already consumed), so it blocks to the presence timeout as before.
    ///
    /// `expected` is the number of placeholder dots the entry row outlines before any are
    /// filled (the policy minimum length) — the design's fixed indicator. The caller
    /// supplies it rather than this fn re-reading `fs`, because the host built-in-UV path
    /// runs while the worker already holds `fs` borrowed (a re-read there would panic).
    pub(super) fn collect_pin(
        &mut self,
        title: &'static str,
        caption: Option<PinCaption>,
        min_len: usize,
        expected: u8,
        out: &mut [u8],
        yield_to_host: bool,
    ) -> rsk_fido::PinEntry {
        let saved = led::status();
        led::set_status(led::STATUS_TOUCH);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        UP_PENDING.store(true, Ordering::Release);

        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let mut entered = 0usize;
        // The entry starts masked; the eye toggle flips this. `last_input` tracks the last
        // key so a revealed PIN can auto re-mask after a short idle.
        let mut reveal = false;
        let mut last_input = Instant::now();

        // A built-in-UV PIN entry can arrive while the panel slept — restore it first.
        self.wake();
        note_activity();
        let _ = rsk_ui::render(
            &mut self.panel,
            &Screen::Pin(PinPad::with_caption(entered, title, caption).expecting(expected)),
        );
        self.shown = None; // force the status loop to repaint once we release it
        // The CST328 reports a level, not an edge, so a finger still down from whatever
        // preceded this pad reads as a keypress on the very first poll — and the Allow
        // button overlaps the bottom key row, so it types a stray `0` and burns a PIN
        // retry. Every other modal waits for release for the same reason; this one had
        // nothing in front of it until a consent card (clientPIN 0x06) and a U2F naming
        // card were put there (audit run-28).
        self.touch.wait_release_ceremony(start, timeout);
        // A title too wide for the band (e.g. "OpenPGP Sign PIN") scrolls as a marquee so
        // it can't slide under the back chevron; a short one stays centred and static.
        let scroll_title = rsk_ui::pin_title_overflows(title);
        let mut last_off = u32::MAX; // != any real offset, so the first frame always draws
        let outcome = loop {
            // The power button sleeps (and auto-locks) from the PIN pad too — abandoning the
            // entry with `Cancelled`, the same outcome a host CTAPHID_CANCEL yields, so a host
            // waiting on this PIN is released. Checked first, before any repaint.
            if self.sleep_button_pressed() {
                break rsk_fido::PinEntry::Cancelled;
            }
            if scroll_title {
                let ms = start.elapsed().as_millis();
                let off = (ms.saturating_sub(MARQUEE_PAUSE_MS) / MARQUEE_MS_PER_PX) as u32;
                // Redraw only when the scroll actually advances a pixel (the loop polls far
                // faster than the marquee moves), so the blit — and SPI traffic — is minimal.
                if off != last_off {
                    self.render_marquee_frame(title, off);
                    last_off = off;
                }
            }
            if let Some(p) = self.touch.read() {
                last_input = Instant::now();
                let mut repaint = true;
                let done = match rsk_ui::hit_pin(p) {
                    Some(PinKey::Digit(d)) => {
                        if entered < out.len() {
                            out[entered] = b'0' + d;
                            entered += 1;
                        }
                        None
                    }
                    Some(PinKey::Del) => {
                        entered = entered.saturating_sub(1);
                        None
                    }
                    Some(PinKey::Reveal) => {
                        reveal = !reveal;
                        None
                    }
                    Some(PinKey::Ok) if entered >= min_len => {
                        Some(rsk_fido::PinEntry::Entered(entered))
                    }
                    Some(PinKey::Cancel) => Some(rsk_fido::PinEntry::Declined),
                    _ => {
                        repaint = false;
                        None
                    }
                };
                if repaint && done.is_none() {
                    let shown = if reveal { Some(&out[..entered]) } else { None };
                    let _ = rsk_ui::render_pin_dots(&mut self.panel, entered, expected, shown);
                }
                self.touch.wait_release(start, timeout);
                if let Some(o) = done {
                    break o;
                }
            }
            // Auto re-mask a revealed PIN after a short idle (a walked-away device must not
            // keep the cleartext digits lit until the presence timeout).
            if reveal && last_input.elapsed() >= Duration::from_millis(REVEAL_MASK_MS) {
                reveal = false;
                let _ = rsk_ui::render_pin_dots(&mut self.panel, entered, expected, None);
            }
            if CANCEL_REQUESTED.load(Ordering::Acquire) {
                break rsk_fido::PinEntry::Cancelled;
            }
            // A local gate must not starve the parked worker: abandon the moment a host
            // command queues (no host awaits this PIN). The host built-in-UV path keeps
            // `yield_to_host=false` and blocks to the timeout (the host awaits it).
            if yield_to_host && crate::worker::host_request_pending() {
                break rsk_fido::PinEntry::Cancelled;
            }
            if start.elapsed() >= timeout {
                break rsk_fido::PinEntry::Timeout;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };

        UP_PENDING.store(false, Ordering::Release);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        AMBIENT_QUIET_UNTIL_MS.store(
            (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
            Ordering::Relaxed,
        );
        note_activity(); // a long ceremony shouldn't immediately fall asleep on return
        led::set_status(saved);
        outcome
    }

    /// After a local PIN gate exhausts the retry budget, show the "PIN blocked" notice
    /// rather than silently closing the pad. Held until a tap or ~5 s (or a queued host
    /// command), so the lockout — recoverable only by a host-side reset — is explained. Each
    /// scope has its own persistent counter (the device PIN's `EF_DEVICE_PIN`, the FIDO
    /// clientPIN's `EF_PIN`); a host `authenticatorReset` clears both.
    pub(super) fn show_pin_blocked(&mut self) {
        let _ = rsk_ui::render_pin_blocked(&mut self.panel);
        self.shown = None;
        // Let the final wrong-PIN tap lift, then hold the notice, dismissable by a fresh tap.
        let start = Instant::now();
        self.touch
            .wait_release(start, Duration::from_millis(MENU_INACTIVITY_MS));
        let show = Duration::from_millis(5000);
        let t0 = Instant::now();
        loop {
            // The power button dismisses the notice by sleeping (and auto-locking) too.
            if self.sleep_button_pressed() {
                break;
            }
            if self.touch.read().is_some() {
                self.touch.wait_release(t0, show);
                break;
            }
            if crate::worker::host_request_pending() || t0.elapsed() >= show {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        note_activity();
    }

    /// Paint one of the design's success "pop" screens (approve / delete / wipe) and
    /// dismiss it. The circle pops in over static chrome (the 0.6 → 1.06 → 1.0 scale),
    /// painted once and never repainted so it can't flicker. With `hold_ms = None` the
    /// screen carries a **Done** button and waits for a tap — or a queued host command /
    /// the inactivity timeout, so an unattended success screen never starves the worker.
    /// With `Some(ms)` it auto-dismisses after the pop plus `ms` (used where there is no
    /// one to tap Done: the approve pop, which the host ceremony is waiting behind, and
    /// the wipe pop, which is followed by a reboot).
    pub(super) fn show_success(&mut self, kind: SuccessKind, hold_ms: Option<u64>) {
        let wait_done = hold_ms.is_none();
        let _ = rsk_ui::render_success(&mut self.panel, kind, wait_done);
        for pct in [55u16, 85, 106, 100] {
            let _ = rsk_ui::render_success_circle(&mut self.panel, kind, pct);
            block_for(Duration::from_millis(70));
        }
        self.shown = None;
        note_activity();
        match hold_ms {
            // Auto-dismiss after `ms`, but poll the power button through the dwell so even a
            // brief self-dismissing pop is sleepable like every other screen (no touch: this
            // variant has no Done button). The wipe pop reboots right after, so a sleep there
            // is harmlessly moot.
            Some(ms) => {
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(ms) {
                    if self.sleep_button_pressed() {
                        break;
                    }
                    block_for(Duration::from_millis(TOUCH_POLL_MS));
                }
            }
            None => {
                let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
                self.touch.wait_release(Instant::now(), idle_limit);
                let mut last = Instant::now();
                loop {
                    // The power button sleeps (and auto-locks) instead of tapping Done.
                    if self.sleep_button_pressed() {
                        break;
                    }
                    if let Some(p) = self.touch.read() {
                        if rsk_ui::hit_success_done(p) {
                            break;
                        }
                        last = Instant::now();
                    }
                    if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                        break;
                    }
                    block_for(Duration::from_millis(TOUCH_POLL_MS));
                }
                note_activity();
            }
        }
    }

    /// The Confirm-Delete flow for one resident passkey (mockup screens 6 → 10): gate on
    /// the device PIN (if set), then paint the trusted confirm screen naming the rp +
    /// account and require a deliberate **hold** on the delete button before removing the
    /// credential. The header back chevron, a slid-off finger, or the inactivity timeout
    /// all abandon it without a write. Synchronous like the other modals (the worker is
    /// parked), so the `self.fs` borrows can't race.
    pub(super) fn run_delete(&mut self, rp: &Label, account: &Label, fid: u16) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        // Let the account-row tap's finger lift before the next touch is read.
        self.touch.wait_release(Instant::now(), idle_limit);
        // Gate on the device PIN first: when one is set the pad is shown straight away,
        // so the confirm screen below doesn't flash for a frame behind it. With no PIN,
        // `local_pin_gate` returns at once and the confirm screen is the first thing seen.
        if !self.local_pin_gate(PinScope::Device) {
            return; // no PIN, wrong PIN, or declined — nothing removed
        }
        // The destructive-action screen: name the rp + account, then require the hold.
        let _ = rsk_ui::render_confirm_delete(&mut self.panel, rp, account);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        if self.hold_to_confirm("Hold to delete", rsk_ui::theme::DANGER_FILL) {
            let removed = rsk_fido::passkeys::delete_cred(&mut self.fs.borrow_mut(), fid);
            if removed {
                self.show_success(SuccessKind::Deleted, None);
            }
        }
        self.end_modal();
    }

    /// The shared hold-to-confirm gesture on [`rsk_ui::DEL_HOLD_RECT`]: fill the
    /// button as the finger holds, returning `true` only once it is held the full
    /// [`HOLD_MS`] (so a brush can't commit). The header back chevron, a lifted or
    /// slid-off finger then the inactivity timeout, or a queued host command all
    /// return `false`. The caller paints the surrounding screen first; `label` is
    /// the button caption and `fill` its solid base colour (red [`rsk_ui::theme::DANGER_FILL`]
    /// for the destructive / reveal holds, blue [`rsk_ui::theme::ACCENT_FILL`] for the firmware
    /// update); the lighter progress wash is derived from it inside `render_hold_fill`.
    pub(super) fn hold_to_confirm(&mut self, label: &str, fill: Rgb565) -> bool {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut hold_start: Option<Instant> = None;
        let mut last_num: u16 = 0;
        let mut last = Instant::now();
        loop {
            // The power button sleeps (and auto-locks) mid-hold; nothing has committed yet,
            // so this abandons the confirm exactly like a lifted finger.
            if self.sleep_button_pressed() {
                return false;
            }
            let mut on_hold = false;
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_pk_back(p) {
                    return false; // cancel
                }
                if rsk_ui::hit_del_hold(p) {
                    on_hold = true;
                    let held = hold_start.get_or_insert_with(Instant::now).elapsed();
                    let num = held.as_millis().min(HOLD_MS) as u16;
                    let _ = rsk_ui::render_hold_fill(
                        &mut self.panel,
                        rsk_ui::DEL_HOLD_RECT,
                        label,
                        last_num,
                        num,
                        HOLD_MS as u16,
                        fill,
                    );
                    last_num = num;
                    if held >= Duration::from_millis(HOLD_MS) {
                        return true;
                    }
                }
            }
            // Finger lifted or slid off the button: reset a building hold.
            if !on_hold && hold_start.take().is_some() {
                let _ =
                    rsk_ui::render_hold_button(&mut self.panel, rsk_ui::DEL_HOLD_RECT, label, fill);
                last_num = 0;
            }
            // A queued host command aborts the (uncommitted) confirm so the worker can
            // run; nothing commits unless the hold actually completes.
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                return false; // timeout / yield
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// The on-device factory-reset flow (Settings → Factory reset): paint the danger
    /// confirm screen, gate on the device PIN (if set, exactly like delete), then
    /// require a deliberate hold before erasing every applet's data. The back
    /// chevron, a slid-off finger, or the inactivity timeout all abandon it without a
    /// write. On a completed hold it shows the wiping notice, erases all flash but the
    /// org attestation ([`rsk_fido::survives_factory_reset`]), and reboots — the next
    /// boot re-provisions a fresh seed, so the device returns blank. Diverges (resets)
    /// on confirm; returns only when cancelled.
    pub(super) fn run_factory_reset(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        // Let the Settings-row tap's finger lift before the next touch is read.
        self.touch.wait_release(Instant::now(), idle_limit);
        // PIN gate first (when set) so the pad doesn't flash the confirm screen behind it;
        // no PIN returns at once and the confirm screen below is shown directly.
        if !self.local_pin_gate(PinScope::Device) {
            return; // no PIN set is fine; a wrong PIN or decline aborts — nothing erased
        }
        // The destructive-action screen, then a deliberate hold to commit.
        let _ = rsk_ui::render_confirm_factory_reset(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        if self.hold_to_confirm("Hold to wipe", rsk_ui::theme::DANGER_FILL) {
            // The scrub blocks the panel for seconds, so paint the notice first, then
            // wipe everything but the attestation and reboot into a fresh device. The
            // reboot clears RAM and re-seeds at boot, so no rng/state is needed here.
            let _ = rsk_ui::render_erasing(&mut self.panel);
            let _ = self
                .fs
                .borrow_mut()
                .factory_wipe(rsk_fido::survives_factory_reset);
            // Confirm the wipe on the trusted screen before the reboot re-provisions a
            // fresh device (the grey rotate pop reads as "erased / restarting").
            self.show_success(SuccessKind::Wiped, Some(SUCCESS_POP_MS));
            cortex_m::peripheral::SCB::sys_reset();
        }
        self.end_modal();
    }

    /// The on-device Set / Change PIN flow for `target` (Settings → Security → Device/FIDO
    /// PIN). When that PIN is already set it is verified first via [`local_pin_gate`] (so a
    /// change still proves knowledge of the current PIN; a first-time set returns at once
    /// with no prompt), then the new PIN is entered twice and the two must match before it
    /// is written with a fresh retry budget. The **device** PIN goes to its own
    /// `EF_DEVICE_PIN` (independent local-control PIN, the compile-time `MIN_PIN_LENGTH`
    /// floor); the **FIDO** PIN goes to `EF_PIN` as the same verifier the host
    /// setPIN/changePIN path stores (so the host then sees a clientPIN unchanged,
    /// `minPINLength` floor). A wrong current PIN,
    /// a decline, a timeout, or a queued host command abandons it without a write; a
    /// mismatch clears both entries and re-prompts. Synchronous (the worker is parked).
    pub(super) fn run_set_pin(&mut self, target: PinScope) {
        // Let the Security-row tap's finger lift before the pad reads digits.
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        if !self.local_pin_gate(target) {
            return; // wrong current PIN, decline, timeout, or host yield — nothing changed
        }
        // The device PIN has no host policy → the compile-time MIN_PIN_LENGTH floor (4, or 6
        // under `fips-profile`) that `store_device_pin` enforces, so a set the user types is
        // actually stored; the FIDO PIN honours `minPINLength` so a panel-set clientPIN stays
        // host-usable.
        let min = match target {
            PinScope::Device => rsk_fido::passkeys::MIN_PIN_LENGTH as usize,
            PinScope::Fido => {
                rsk_fido::passkeys::min_pin_length(&mut self.fs.borrow_mut()) as usize
            }
        };
        // Size the pad buffers to the host-representable maximum so the pad can't accept a
        // digit beyond it (`collect_pin` caps at `out.len()`); a PIN chosen here is then
        // always one the store path can verify, and the store re-checks.
        let mut new = [0u8; rsk_fido::passkeys::MAX_PIN_LENGTH];
        let mut confirm = [0u8; rsk_fido::passkeys::MAX_PIN_LENGTH];
        // The header names the scope ("Device PIN" / "FIDO PIN"); the step rides in the
        // caption — a muted "Choose a PIN" on the first entry, "Re-enter to confirm" on the
        // second, or the danger-coloured "PINs don't match" after a mismatch.
        let title = target.pin_title();
        let mut new_caption = Some(PinCaption::ChoosePin);
        loop {
            new.zeroize();
            confirm.zeroize();
            let expected = min.min(u8::MAX as usize) as u8;
            let n1 = match self.collect_pin(title, new_caption, min, expected, &mut new, true) {
                rsk_fido::PinEntry::Entered(n) => n.min(new.len()),
                _ => break, // declined / timeout / host yield — nothing set
            };
            // Refuse a guessable PIN before the confirm step, matching the host set path.
            #[cfg(any(feature = "strong-pin", feature = "fips-profile"))]
            if rsk_fido::passkeys::pin_is_trivial(&new[..n1]) {
                new_caption = Some(PinCaption::TooWeak);
                continue;
            }
            let n2 = match self.collect_pin(
                title,
                Some(PinCaption::Reenter),
                min,
                expected,
                &mut confirm,
                true,
            ) {
                rsk_fido::PinEntry::Entered(n) => n.min(confirm.len()),
                _ => break, // confirm declined / timeout / host yield
            };
            if n1 == n2 && rsk_crypto::ct_eq(&new[..n1], &confirm[..n2]) {
                let dev = self.keys.device();
                // The pad already enforced the length floor; a flash error is the only
                // realistic failure and leaves no PIN set — abandon either way. Route to the
                // device PIN's own record or the FIDO clientPIN's by target.
                match target {
                    PinScope::Device => {
                        let _ = rsk_fido::passkeys::store_device_pin(
                            &dev,
                            &mut self.fs.borrow_mut(),
                            &new[..n1],
                        );
                        // Keep the cached lock-proxy fresh: a host ceremony sleeping right
                        // after this set reads `home_pin_set` (fs is borrowed there), so a
                        // stale `false` would skip the auto-lock. A store failure only makes
                        // this over-lock, which unlock-with-no-PIN harmlessly drops.
                        self.home_pin_set = true;
                    }
                    PinScope::Fido => {
                        let _ = rsk_fido::passkeys::store_local_pin(
                            &dev,
                            &mut self.fs.borrow_mut(),
                            &new[..n1],
                        );
                    }
                }
                break;
            }
            // Mismatch: re-prompt from "New PIN" with the reason; the loop clears both.
            new_caption = Some(PinCaption::Mismatch);
        }
        new.zeroize();
        confirm.zeroize();
        self.end_modal();
    }

    /// The PIV PIN/PUK sub-menu (Settings → Security → "PIV PIN"): change the PIV PIN, change
    /// the PUK, or unblock a blocked PIN with the PUK. A modal picker like the keygen chooser;
    /// the title-bar chevron backs out to the Security list. Each op is gated by knowledge of
    /// the current PIN/PUK — exactly the host APDU's authorisation, no device-PIN gate.
    pub(super) fn run_piv_pins(&mut self) {
        let idle = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle);
        // Materialise the PIV defaults if no host has ever selected the applet — a display
        // unit used only for FIDO never triggers the lazy first-SELECT scan, so EF_PIN / EF_PUK
        // / EF_RETRIES wouldn't exist for the gate to verify against (it would dead-end on the
        // missing retry counter). Idempotent: every step is has-data guarded.
        {
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            let _ = rsk_piv::files::scan_files(&dev, &mut fs, &mut *rng);
        }
        loop {
            let _ = rsk_ui::render_piv_pin_menu(&mut self.panel);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle);
            let mut last = Instant::now();
            let pick = loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        return;
                    }
                    if let Some(i) =
                        rsk_ui::hit_list(p, rsk_ui::PIV_KEYGEN_PICK_TOP, rsk_ui::PIV_PIN_MENU_ROWS)
                    {
                        break i;
                    }
                    self.touch.wait_release(last, idle);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            };
            match pick {
                0 => self.run_change_piv_ref(rsk_piv::PinRef::Pin),
                1 => self.run_change_piv_ref(rsk_piv::PinRef::Puk),
                2 => self.run_unblock_piv_pin(),
                _ => self.run_protect_mgm_key(),
            }
            // A sub-flow may have slept + locked via the power button; unwind instead of
            // re-showing this menu over the blanked panel (status_task owns it from here).
            if self.asleep {
                return;
            }
            // Each sub-flow ends in a success pop or a cancel; re-show this menu afterwards.
        }
    }

    /// Collect and verify the current PIV PIN or PUK on the pad, re-prompting with the
    /// remaining-attempts caption until it's right, the user backs out, or the counter is
    /// spent. Returns the secret padded to the 8-byte PIV wire form on success (for the
    /// following change/unblock), or `None` on cancel / timeout / blocked (the latter shows
    /// the lockout notice). The retry counter is the PIV applet's own (`EF_RETRIES`).
    fn gate_piv_ref(&mut self, which: rsk_piv::PinRef, buf: &mut [u8]) -> Option<[u8; 8]> {
        let title = piv_ref_title(which);
        let mut caption = rsk_piv::reference_retries_left(&mut self.fs.borrow_mut(), which)
            .map(|left| PinCaption::TriesRemaining { left });
        loop {
            let n =
                match self.collect_pin(title, caption, PIV_PIN_MIN, PIV_PIN_MIN as u8, buf, true) {
                    rsk_fido::PinEntry::Entered(n) => n.min(buf.len()),
                    _ => return None,
                };
            // `n <= buf.len() == 8`, so `pad_pin` only returns `None` defensively. The padded
            // copy is the cleartext current secret — zeroize it on every path (the PUK is the
            // recovery secret), matching `run_set_pin` / `collect_new_piv_pin` hygiene.
            let mut pad = rsk_piv::pad_pin(&buf[..n])?;
            let sw = {
                let dev = self.keys.device();
                rsk_piv::verify_reference(&dev, &mut self.fs.borrow_mut(), which, &pad)
            };
            if sw == rsk_sdk::Sw::OK {
                let out = pad;
                pad.zeroize();
                return Some(out);
            }
            if sw == rsk_sdk::Sw::PIN_BLOCKED {
                pad.zeroize();
                self.show_pin_blocked();
                return None;
            }
            let left =
                rsk_piv::reference_retries_left(&mut self.fs.borrow_mut(), which).unwrap_or(0);
            caption = Some(PinCaption::WrongPin { retries_left: left });
            pad.zeroize();
        }
    }

    /// Collect a new PIV PIN/PUK twice on the pad and return it padded to the wire form, or
    /// `None` on cancel / timeout / host-yield. The `title` names the scope ("PIV PIN" /
    /// "PIV PUK"); the New vs Confirm step rides in the caption (a muted "Choose a PIN" then
    /// "Re-enter to confirm"). A New ≠ Confirm mismatch re-prompts in place; both pad buffers
    /// are zeroized on every iteration and at exit.
    fn collect_new_piv_pin(&mut self, title: &'static str) -> Option<[u8; 8]> {
        let mut new = [0u8; 8];
        let mut confirm = [0u8; 8];
        let mut new_caption = Some(PinCaption::ChoosePin);
        let out = loop {
            new.zeroize();
            confirm.zeroize();
            let n1 = match self.collect_pin(
                title,
                new_caption,
                PIV_PIN_MIN,
                PIV_PIN_MIN as u8,
                &mut new,
                true,
            ) {
                rsk_fido::PinEntry::Entered(n) => n.min(new.len()),
                _ => break None,
            };
            let n2 = match self.collect_pin(
                title,
                Some(PinCaption::Reenter),
                PIV_PIN_MIN,
                PIV_PIN_MIN as u8,
                &mut confirm,
                true,
            ) {
                rsk_fido::PinEntry::Entered(n) => n.min(confirm.len()),
                _ => break None,
            };
            if n1 == n2 && rsk_crypto::ct_eq(&new[..n1], &confirm[..n2]) {
                break rsk_piv::pad_pin(&new[..n1]);
            }
            new_caption = Some(PinCaption::Mismatch);
        };
        new.zeroize();
        confirm.zeroize();
        out
    }

    /// Change the PIV application PIN or PUK from the panel: verify the current value, then
    /// collect the new one twice. Both are padded to the PIV wire form so a host VERIFY (which
    /// always pads to 8 with `0xFF`) accepts the result. Mirrors [`Self::run_set_pin`] but
    /// against the PIV applet's own PIN/PUK records, not the device/FIDO PIN.
    fn run_change_piv_ref(&mut self, which: rsk_piv::PinRef) {
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut cur = [0u8; 8];
        let gated = self.gate_piv_ref(which, &mut cur);
        cur.zeroize();
        let mut cur_pad = match gated {
            Some(p) => p,
            None => {
                self.end_modal();
                return;
            }
        };
        let applied = match self.collect_new_piv_pin(piv_ref_title(which)) {
            Some(mut new_pad) => {
                let sw = {
                    let dev = self.keys.device();
                    rsk_piv::change_reference(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        which,
                        &cur_pad,
                        &new_pad,
                    )
                };
                new_pad.zeroize();
                sw == rsk_sdk::Sw::OK
            }
            None => false,
        };
        cur_pad.zeroize();
        if applied {
            self.show_success(SuccessKind::Approved, Some(SUCCESS_POP_MS));
        } else {
            self.end_modal();
        }
    }

    /// Unblock a blocked PIV PIN with the PUK (Settings → Security → PIV PIN → Unblock PIN):
    /// verify the PUK, then set a new PIN — the on-device RESET RETRY COUNTER. The shared
    /// `unblock_pin_with_puk` resets the PIN's retry counter on success.
    fn run_unblock_piv_pin(&mut self) {
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut puk = [0u8; 8];
        let gated = self.gate_piv_ref(rsk_piv::PinRef::Puk, &mut puk);
        puk.zeroize();
        let mut puk_pad = match gated {
            Some(p) => p,
            None => {
                self.end_modal();
                return;
            }
        };
        let applied = match self.collect_new_piv_pin(piv_ref_title(rsk_piv::PinRef::Pin)) {
            Some(mut new_pad) => {
                let sw = {
                    let dev = self.keys.device();
                    rsk_piv::unblock_pin_with_puk(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        &puk_pad,
                        &new_pad,
                    )
                };
                new_pad.zeroize();
                sw == rsk_sdk::Sw::OK
            }
            None => false,
        };
        puk_pad.zeroize();
        if applied {
            self.show_success(SuccessKind::Approved, Some(SUCCESS_POP_MS));
        } else {
            self.end_modal();
        }
    }

    /// "Protect management key" (Settings → Security → PIV PIN → Protect mgmt key): generate a
    /// fresh random AES-256 management key, seal it, and mark it PIN-protected (ykman
    /// `--protect`) so a host can use it with just the PIV PIN. Gated by the device PIN (when
    /// set) and a deliberate hold — physical presence at the trusted panel is the authorisation
    /// (no management-key auth). It REPLACES the current management key, and afterwards the PIV
    /// PIN alone grants PIV admin (the confirm screen states this).
    fn run_protect_mgm_key(&mut self) {
        let idle = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle);
        // Materialise the PIV defaults first (a never-host-selected display unit) so the host
        // can later VERIFY the PIN to read the protected key. Idempotent.
        {
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            let _ = rsk_piv::files::scan_files(&dev, &mut fs, &mut *rng);
        }
        if !self.local_pin_gate(PinScope::Device) {
            return;
        }
        let _ = rsk_ui::render_piv_protect_confirm(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle);
        if !self.hold_to_confirm("Hold to protect", rsk_ui::theme::ACCENT_FILL) {
            return;
        }
        // The generate + seal holds the dev/rng/fs borrows across a synchronous, no-await span
        // (no key search — AES key gen is instant), so the worker can't preempt.
        let ok = {
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            rsk_piv::protect_mgm_key(&dev, &mut fs, &mut *rng) == rsk_sdk::Sw::OK
        };
        if ok {
            self.show_success(SuccessKind::Approved, Some(SUCCESS_POP_MS));
        } else {
            self.end_modal();
        }
    }
}
