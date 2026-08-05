// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The Passkeys/Apps browse tabs: per-applet lists, details, keygen, audit log.

use super::gates::PinScope;
use super::status::{KEYGEN_SPIN_MS, audit_kind, paged};
use super::*;

/// The cardholder reader must hand the panel one byte MORE than a `Label` keeps,
/// or `Label::clamp` can never set `truncated` and a cut value reads as complete
/// (audit run-34 #39). Only this crate sees both constants, so it holds the rule.
const _: () = assert!(rsk_openpgp::info::CH_FIELD_MAX == rsk_ui::LABEL_MAX + 1);

/// Outcome of the per-RP service-detail screen: return to the Passkeys list, or leave
/// the tab to another nav destination (`None` = the idle Home screen).
enum ServiceResult {
    Back,
    Leave(Option<NavTab>),
}

impl Ui {
    /// The Passkeys tab — list resident relying parties (read-only), with a drill-in to
    /// each RP's accounts. Enumerates from the shared flash store on entry (the worker is
    /// parked while this synchronous loop runs, so the borrow is safe). Returns the next
    /// nav destination so the [`status_task`] dispatcher can switch tabs directly:
    /// `Some(tab)` opens that tab, `None` returns to the idle Home screen.
    pub(super) fn run_passkeys(&mut self) -> Option<NavTab> {
        // Snapshot the RP list and render first (so the switch feels instant), then let
        // the opening finger lift. `hashes` parallels `rows` (the UI model carries no
        // rpIdHash) so a drilled-in RP can enumerate its own credentials.
        let mut rows = [RpRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut hashes = [[0u8; 32]; rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_rps(&mut rows, &mut hashes, page);
        self.render_list(&rows[..n], page, total);
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));

        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let next = loop {
            // The power button sleeps from the list too, not just on Home.
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_rps(&mut rows, &mut hashes, page);
                    n = r.0;
                    total = r.1;
                    self.render_list(&rows[..n], page, total);
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    let row = rows[i as usize];
                    match self.run_service(&row.id, &row.nick, &hashes[i as usize]) {
                        ServiceResult::Back => {
                            // A deleted last-account removes its RP, so the total can shrink —
                            // reload this page and clamp it if it scrolled off the end.
                            let r = self.load_rps(&mut rows, &mut hashes, page);
                            n = r.0;
                            total = r.1;
                            let clamped = page.min(rsk_ui::page_count(total).saturating_sub(1));
                            if clamped != page {
                                page = clamped;
                                let r = self.load_rps(&mut rows, &mut hashes, page);
                                n = r.0;
                                total = r.1;
                            }
                            self.render_list(&rows[..n], page, total);
                            self.touch.wait_release(Instant::now(), idle_limit);
                            last = Instant::now();
                            continue;
                        }
                        ServiceResult::Leave(target) => break target,
                    }
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        // Already on this tab — ignore (don't drop to Home).
                        NavTab::Passkeys => {}
                        NavTab::Home => break None,
                        NavTab::Apps => break Some(NavTab::Apps),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            // Yield to the parked worker the instant a host command arrives, so
            // browsing never starves it — the timeout is only the walked-away backstop.
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One RP's detail: show its name (the device-local nickname if set, else the rpId),
    /// list its resident accounts, let a tap on an account start the Confirm-Delete flow
    /// ([`run_delete`]), and the title-bar pencil open the rename flow ([`run_rename`]).
    /// The back chevron (or a tap on the active Passkeys tab) returns to the list; another
    /// nav tab leaves the Passkeys tab; the back chevron only ever returns
    /// [`ServiceResult::Back`]. After a delete the set is reloaded — when the last account
    /// goes, the screen drops back to the list (whose RP row is gone too).
    fn run_service(&mut self, rp_id: &Label, nick0: &Label, hash: &[u8; 32]) -> ServiceResult {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut accts = [AccountRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut fids = [0u16; rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        // The shown title tracks the nickname (Copy), so a rename updates it live.
        let mut nick = *nick0;
        let title = |nick: &Label| if nick.is_empty() { *rp_id } else { *nick };
        let (mut n, mut total) = self.load_accts(hash, &mut accts, &mut fids, page);
        let _ = rsk_ui::render_service(
            &mut self.panel,
            &title(&nick),
            nick.is_empty(),
            &accts[..n],
            page,
            total,
        );
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        let mut last = Instant::now();
        loop {
            // The power button sleeps from the detail view too, not just on Home.
            if self.sleep_button_pressed() {
                return ServiceResult::Leave(None);
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    return ServiceResult::Back;
                }
                if rsk_ui::hit_title_edit(p) {
                    // The pencil: rename this RP's device-local nickname, then repaint with
                    // the (possibly changed) title. The credential box is untouched. Gated
                    // by the device PIN like every other on-device write — the nickname is
                    // what the browse screens show in place of the rpId, so an
                    // unauthenticated relabel would be a lie told by the trusted display.
                    if !self.local_pin_gate(PinScope::Device) {
                        return ServiceResult::Back;
                    }
                    if let Some(new_nick) = self.run_rename(&nick, hash) {
                        nick = new_nick;
                    }
                    if self.asleep {
                        return ServiceResult::Leave(None); // slept via the power button
                    }
                    let _ = rsk_ui::render_service(
                        &mut self.panel,
                        &title(&nick),
                        nick.is_empty(),
                        &accts[..n],
                        page,
                        total,
                    );
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(tab) = rsk_ui::hit_nav(p) {
                    return match tab {
                        // The active tab drills back out to its own list.
                        NavTab::Passkeys => ServiceResult::Back,
                        NavTab::Home => ServiceResult::Leave(None),
                        NavTab::Apps => ServiceResult::Leave(Some(NavTab::Apps)),
                        NavTab::Settings => ServiceResult::Leave(Some(NavTab::Settings)),
                    };
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_accts(hash, &mut accts, &mut fids, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_service(
                        &mut self.panel,
                        &title(&nick),
                        nick.is_empty(),
                        &accts[..n],
                        page,
                        total,
                    );
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    // The destructive card names the real relying party, never the
                    // device-local nickname: a nickname is free text, so confirming a
                    // delete against it would let a relabel aim the owner's own
                    // PIN-gated ceremony at the wrong credential.
                    self.run_delete(rp_id, &accts[i as usize].name, fids[i as usize]);
                    if self.asleep {
                        return ServiceResult::Leave(None); // slept via the power button
                    }
                    let r = self.load_accts(hash, &mut accts, &mut fids, page);
                    n = r.0;
                    total = r.1;
                    if total == 0 {
                        return ServiceResult::Back; // last account gone — this RP vanished
                    }
                    // Clamp the page if the delete scrolled it off the end, then repaint.
                    let clamped = page.min(rsk_ui::page_count(total).saturating_sub(1));
                    if clamped != page {
                        page = clamped;
                        let r = self.load_accts(hash, &mut accts, &mut fids, page);
                        n = r.0;
                        total = r.1;
                    }
                    let _ = rsk_ui::render_service(
                        &mut self.panel,
                        &title(&nick),
                        nick.is_empty(),
                        &accts[..n],
                        page,
                        total,
                    );
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            // Same yield as the list: a pending host command takes priority over an
            // open read-only detail.
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                return ServiceResult::Leave(None);
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// Snapshot the per-applet item counts for the Apps chooser. One borrow covers all
    /// three reads (the device is taken first, so the OATH unseal-walk and the `fs` borrow
    /// don't overlap). Borrow-safe like [`Self::load_rps`] — the worker is parked here.
    fn load_apps(&self) -> rsk_ui::AppsView {
        let dev = self.keys.device();
        let mut fs = self.fs.borrow_mut();
        let openpgp_keys = rsk_openpgp::info::read_info(&mut fs).key_count();
        let piv_slots = rsk_piv::info::read_info(&mut fs).populated();
        let oath_codes =
            rsk_oath::for_each_cred(&dev, &mut fs, |_| {}).min(u16::MAX as usize) as u16;
        rsk_ui::AppsView {
            openpgp_keys,
            piv_slots,
            oath_codes,
        }
    }

    /// The Apps tab: a chooser for the credential applets. Reuses the tab modal shape — a
    /// drill-in per applet, the bottom nav for direct tab switches, the power button to
    /// sleep, and a break the moment a host command queues so a browse never starves the
    /// worker. Returns the next nav destination (`None` = back to idle Home).
    pub(super) fn run_apps(&mut self) -> Option<NavTab> {
        let view = self.load_apps();
        let _ = rsk_ui::render_apps(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if let Some(entry) = rsk_ui::hit_apps(p) {
                    let leave = match entry {
                        AppEntry::OpenPgp => self.run_openpgp(),
                        AppEntry::Piv => self.run_piv(),
                        AppEntry::Oath => self.run_oath(),
                    };
                    if self.asleep {
                        break None;
                    }
                    if leave.is_some() {
                        break leave;
                    }
                    // Back from an applet: re-snapshot (a host op may have run while parked)
                    // and repaint the chooser.
                    let view = self.load_apps();
                    let _ = rsk_ui::render_apps(&mut self.panel, &view);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => {}
                        NavTab::Home => break None,
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// Build the OpenPGP overview from the applet's plaintext metadata (no PIN / DEK).
    fn load_openpgp(&self) -> rsk_ui::OpenpgpView {
        let mut fs = self.fs.borrow_mut();
        let info = rsk_openpgp::info::read_info(&mut fs);
        let mut slots = [rsk_ui::PgpSlotRow::default(); 3];
        for (i, s) in info.slots.iter().enumerate() {
            slots[i] = rsk_ui::PgpSlotRow {
                present: s.present,
                algo: if s.present {
                    Label::clamp(s.algo.label().as_bytes())
                } else {
                    Label::default()
                },
                touch: s.touch,
            };
        }
        let cardholder_name = Label::clamp(rsk_openpgp::info::read_cardholder(&mut fs).name());
        rsk_ui::OpenpgpView {
            slots,
            cardholder_name,
            sig_count: info.sig_count,
            pw1: info.pw1_retries,
            pw3: info.pw3_retries,
        }
    }

    /// Build the OpenPGP card-holder detail (name / login / URL / language), all plaintext.
    fn load_openpgp_cardholder(&self) -> rsk_ui::CardholderView {
        let mut fs = self.fs.borrow_mut();
        let ch = rsk_openpgp::info::read_cardholder(&mut fs);
        rsk_ui::CardholderView {
            name: Label::clamp(ch.name()),
            login: Label::clamp(ch.login()),
            url: Label::clamp(ch.url()),
            lang: Label::clamp(ch.lang()),
            any: ch.any(),
        }
    }

    /// Build one OpenPGP key's detail (algorithm / touch / fingerprint).
    fn load_openpgp_key(&self, slot: usize) -> rsk_ui::PgpKeyView {
        let mut fs = self.fs.borrow_mut();
        let s = rsk_openpgp::info::read_info(&mut fs).slots[slot];
        rsk_ui::PgpKeyView {
            slot: slot as u8,
            present: s.present,
            algo: Label::clamp(s.algo.label().as_bytes()),
            touch: s.touch,
            created: s.created,
            fingerprint: s.fingerprint.unwrap_or([0u8; 20]),
            has_fp: s.fingerprint.is_some(),
        }
    }

    /// The OpenPGP overview (read-only): the three key slots + a drill-in to each present
    /// slot's detail. Same modal shape as [`Self::run_apps`]; `None` returns to the Apps
    /// chooser, `Some(tab)` leaves the hub to that tab.
    fn run_openpgp(&mut self) -> Option<NavTab> {
        let view = self.load_openpgp();
        let _ = rsk_ui::render_openpgp(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break None;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, rsk_ui::OPENPGP_ROWS) {
                    // Rows 0..2 are the key slots (each drills in — an empty slot's detail
                    // explains its role); row 3 opens the card-holder detail.
                    if (i as usize) < view.slots.len() {
                        self.run_openpgp_key(i as usize);
                    } else {
                        self.run_openpgp_cardholder();
                    }
                    if self.asleep {
                        break None;
                    }
                    let _ = rsk_ui::render_openpgp(&mut self.panel, &view);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => break None,
                        NavTab::Home => break Some(NavTab::Home),
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One OpenPGP key's detail screen (back-only, no nav). Read-only; back chevron / power
    /// button / a queued host command / inactivity all return to the overview.
    fn run_openpgp_key(&mut self, slot: usize) {
        let view = self.load_openpgp_key(slot);
        let _ = rsk_ui::render_openpgp_key(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
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
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// The OpenPGP card-holder detail screen (back-only, no nav). Read-only; back chevron /
    /// power button / a queued host command / inactivity all return to the overview.
    fn run_openpgp_cardholder(&mut self) {
        let view = self.load_openpgp_cardholder();
        let _ = rsk_ui::render_openpgp_cardholder(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
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
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// Build the PIV overview from the applet's slot metadata (no PIN / management key).
    fn load_piv(&self) -> rsk_ui::PivView {
        let mut fs = self.fs.borrow_mut();
        let info = rsk_piv::info::read_info(&mut fs);
        let mut slots = [rsk_ui::PivSlotRow::default(); 4];
        for (i, s) in info.slots.iter().enumerate() {
            slots[i] = rsk_ui::PivSlotRow {
                slot: s.slot,
                present: s.present,
                cert: s.cert,
                algo: if s.present {
                    Label::clamp(rsk_piv::info::algo_name(s.algo).as_bytes())
                } else {
                    Label::default()
                },
            };
        }
        let extra = rsk_piv::info::extra_count(&mut fs);
        rsk_ui::PivView {
            slots,
            extra,
            pin: info.pin_retries,
            puk: info.puk_retries,
        }
    }

    /// Build one PIV slot's detail (algorithm / policies / origin / cert) by wire slot —
    /// any slot, primary or retired / F9.
    fn load_piv_slot(&self, slot: u8) -> rsk_ui::PivSlotView {
        let mut fs = self.fs.borrow_mut();
        let s = rsk_piv::info::read_slot(&mut fs, slot);
        rsk_ui::PivSlotView {
            slot: s.slot,
            present: s.present,
            cert: s.cert,
            algo: Label::clamp(rsk_piv::info::algo_name(s.algo).as_bytes()),
            pin_policy: Label::clamp(rsk_piv::info::pin_policy_name(s.pin_policy).as_bytes()),
            touch_policy: Label::clamp(rsk_piv::info::touch_policy_name(s.touch_policy).as_bytes()),
            origin: Label::clamp(rsk_piv::info::origin_name(s.origin).as_bytes()),
        }
    }

    /// The PIV overview (read-only): the four primary slots + a drill-in to each populated
    /// slot's detail. Mirrors [`Self::run_openpgp`].
    fn run_piv(&mut self) -> Option<NavTab> {
        let view = self.load_piv();
        let _ = rsk_ui::render_piv(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break None;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, rsk_ui::PIV_ROWS) {
                    // Rows 0..3 are the primary slots (each drills in — an empty slot's
                    // detail explains its role); row 4 opens the retired / F9 screen.
                    if (i as usize) < view.slots.len() {
                        self.run_piv_slot(view.slots[i as usize].slot);
                    } else {
                        self.run_piv_extra();
                    }
                    if self.asleep {
                        break None;
                    }
                    let view = self.load_piv();
                    let _ = rsk_ui::render_piv(&mut self.panel, &view);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => break None,
                        NavTab::Home => break Some(NavTab::Home),
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One PIV slot's detail screen (back-only, no nav). Read-only. `slot` is the wire
    /// reference (primary `0x9A…`, retired `0x82…0x95`, or F9).
    fn run_piv_slot(&mut self, slot: u8) {
        let view = self.load_piv_slot(slot);
        let _ = rsk_ui::render_piv_slot(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
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
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// Build one page of the "Retired & F9" list: every populated retired slot + F9, then a
    /// trailing "Generate key" action row when a retired slot is free. Returns the kept count
    /// and the true total (slots + the optional action).
    fn load_piv_extra(&self, rows: &mut [rsk_ui::PivExtraRow], page: u16) -> (usize, u16) {
        let mut fs = self.fs.borrow_mut();
        let mut slots = [rsk_piv::info::PivSlot::default(); rsk_piv::info::MAX_EXTRA_SLOTS];
        let nslots = rsk_piv::info::read_extra(&mut fs, &mut slots);
        let can_gen = rsk_piv::info::next_free_retired(&mut fs).is_some();
        let total = nslots + can_gen as usize;
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut n = 0;
        let mut i = offset;
        while i < total && n < rows.len() {
            rows[n] = if i < nslots {
                let s = slots[i];
                rsk_ui::PivExtraRow {
                    slot: s.slot,
                    present: s.present,
                    cert: s.cert,
                    algo: if s.present {
                        Label::clamp(rsk_piv::info::algo_name(s.algo).as_bytes())
                    } else {
                        Label::default()
                    },
                    generate: false,
                }
            } else {
                rsk_ui::PivExtraRow {
                    generate: true,
                    ..Default::default()
                }
            };
            n += 1;
            i += 1;
        }
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// The "Retired & F9" screen (back-only): the populated retired slots + F9, paged, each
    /// drilling into the shared slot-detail, plus a "Generate key" action when a slot is free.
    /// Mirrors [`Self::run_oath`] — pager, sleep, host-yield; no nav (a sub-screen of PIV).
    fn run_piv_extra(&mut self) {
        let mut rows = [rsk_ui::PivExtraRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_piv_extra(&mut rows, page);
        let _ = rsk_ui::render_piv_extra(&mut self.panel, &rows[..n], page, total);
        self.shown = None;
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
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
                    page = paged(page, total, k);
                    let r = self.load_piv_extra(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_piv_extra(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    let row = rows[i as usize];
                    if row.generate {
                        self.run_piv_generate();
                    } else {
                        self.run_piv_slot(row.slot);
                    }
                    if self.asleep {
                        break;
                    }
                    let r = self.load_piv_extra(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_piv_extra(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// The on-device PIV key-generate flow (from the "Retired & F9" screen's Generate row):
    /// target the next free retired slot, gate on the device PIN (when set), pick an EC curve,
    /// require a deliberate hold, then generate + seal the key. EC only — RSA's prime search
    /// would block the panel. Physical presence here is the authorisation (no management key),
    /// and generation only ever *adds* a key to an empty slot. Returns when done or cancelled.
    fn run_piv_generate(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let slot = match rsk_piv::info::next_free_retired(&mut self.fs.borrow_mut()) {
            Some(s) => s,
            None => return,
        };
        // PIN gate first (when set) so the chooser doesn't flash behind the pad.
        if !self.local_pin_gate(PinScope::Device) {
            return;
        }
        // Algorithm chooser: the curves are instant; the RSA row drills into a size
        // sub-picker (2048/3072/4096), each run by the firmware's dual-core prime search.
        let algo = loop {
            let _ = rsk_ui::render_piv_keygen_pick(&mut self.panel, slot);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            // `None` selects the RSA row (open the size sub-picker); `Some` is a concrete algo.
            let main_pick = loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        return;
                    }
                    if let Some(i) = rsk_ui::hit_list(
                        p,
                        rsk_ui::PIV_KEYGEN_PICK_TOP,
                        rsk_ui::PIV_KEYGEN_PICK_ROWS,
                    ) {
                        break match i {
                            0 => Some(rsk_piv::files::ALGO_ECCP256),
                            1 => Some(rsk_piv::files::ALGO_ECCP384),
                            2 => Some(rsk_piv::files::ALGO_ED25519),
                            3 => Some(rsk_piv::files::ALGO_X25519),
                            _ => None,
                        };
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            };
            if let Some(a) = main_pick {
                break a;
            }
            // RSA size sub-picker; its back chevron returns to the main chooser.
            let _ = rsk_ui::render_piv_keygen_rsa_pick(&mut self.panel, slot);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            let sub_pick = loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        break None;
                    }
                    if let Some(i) =
                        rsk_ui::hit_list(p, rsk_ui::PIV_KEYGEN_PICK_TOP, rsk_ui::PIV_RSA_PICK_ROWS)
                    {
                        break Some(match i {
                            0 => rsk_piv::files::ALGO_RSA2048,
                            1 => rsk_piv::files::ALGO_RSA3072,
                            _ => rsk_piv::files::ALGO_RSA4096,
                        });
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            };
            if let Some(a) = sub_pick {
                break a;
            }
            // Otherwise the user backed out of the sub-picker — re-show the main chooser.
        };
        // A deliberate hold before the write.
        let _ = rsk_ui::render_piv_keygen_confirm(
            &mut self.panel,
            slot,
            rsk_piv::info::algo_name(algo),
        );
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if !self.hold_to_confirm("Hold to generate", rsk_ui::theme::ACCENT_FILL) {
            return;
        }
        // The keygen + seal holds the dev/rng/fs borrows across a synchronous, no-await
        // span, so the worker can't preempt and the borrows stay safe. The free slot is
        // re-checked under the borrow in case state moved while the chooser was open.
        let rsa_nbits = match algo {
            rsk_piv::files::ALGO_RSA2048 => Some(2048usize),
            rsk_piv::files::ALGO_RSA3072 => Some(3072),
            rsk_piv::files::ALGO_RSA4096 => Some(4096),
            _ => None,
        };
        let ok = if let Some(nbits) = rsa_nbits {
            // RSA's prime search is slow (seconds for 2048, up to minutes for 4096): paint a
            // "generating" screen, then run it dual-core. The search is a blocking busy-loop
            // (no await), so the panel can't repaint on its own — instead the search's per-
            // candidate hook spins the indicator arc (throttled to KEYGEN_SPIN_MS) so it reads
            // as actively working, not hung. USB + CCID keepalives stay interrupt-driven.
            let _ = rsk_ui::render_piv_keygen_working(&mut self.panel);
            self.shown = None;
            let key = {
                let mut rng = self.rng.borrow_mut();
                let panel = &mut self.panel;
                let mut spin = rsk_ui::STATUS_ARC_START;
                let mut last_paint = Instant::now();
                let mut tick = || {
                    if last_paint.elapsed() >= Duration::from_millis(KEYGEN_SPIN_MS) {
                        spin = spin.wrapping_add(SPIN_STEP_DEG);
                        let _ = rsk_ui::render_status_arc(panel, StatusKind::Processing, spin);
                        last_paint = Instant::now();
                    }
                };
                crate::core1::run_rsa_search_progress(nbits, &mut *rng, &mut tick)
            };
            match key {
                Some(key) => {
                    let dev = self.keys.device();
                    let mut rng = self.rng.borrow_mut();
                    let mut fs = self.fs.borrow_mut();
                    match rsk_piv::info::next_free_retired(&mut fs) {
                        Some(s) => {
                            rsk_piv::info::store_retired_rsa(&dev, &mut fs, &mut *rng, s, &key)
                                .is_ok()
                        }
                        None => false,
                    }
                }
                None => false,
            }
        } else {
            // EC / Ed25519 / X25519 are instant.
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            match rsk_piv::info::next_free_retired(&mut fs) {
                Some(s) => {
                    rsk_piv::info::generate_slot_key(&dev, &mut fs, &mut *rng, s, algo).is_ok()
                }
                None => false,
            }
        };
        if ok {
            self.show_success(SuccessKind::Generated, Some(SUCCESS_POP_MS));
        }
    }

    /// Enumerate stored OATH credentials into `rows` (one page), returning the kept count
    /// and the true total. Each credential is device-unsealed inside the enumerator (the
    /// display never holds the secret); borrow-safe like [`Self::load_rps`].
    fn load_oath(&self, rows: &mut [rsk_ui::OathRow], page: u16) -> (usize, u16) {
        let dev = self.keys.device();
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut fs = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let total = rsk_oath::for_each_cred(&dev, &mut fs, |c| {
            if idx >= offset && n < rows.len() {
                rows[n] = rsk_ui::OathRow {
                    name: Label::clamp(c.name),
                    hotp: c.hotp,
                    touch: c.touch,
                };
                n += 1;
            }
            idx += 1;
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// The OATH list (read-only): one row per stored credential, paged. No code is shown
    /// (the device has no clock for TOTP); the footer points at the host app. Mirrors
    /// [`Self::run_passkeys`] — pager, nav, sleep, host-yield.
    fn run_oath(&mut self) -> Option<NavTab> {
        let mut rows = [rsk_ui::OathRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_oath(&mut rows, page);
        let _ = rsk_ui::render_oath(&mut self.panel, &rows[..n], page, total);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break None;
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_oath(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_oath(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    // Drill into the credential's detail (paged index → global position).
                    self.run_oath_cred(page as usize * rsk_ui::PK_ROWS_MAX + i as usize);
                    if self.asleep {
                        break None;
                    }
                    let r = self.load_oath(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_oath(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => break None,
                        NavTab::Home => break Some(NavTab::Home),
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// Build one OATH credential's detail by its global list position. Re-enumerates (the
    /// display holds no secret), clamps the picked credential's metadata for display.
    fn load_oath_cred(&self, idx: usize) -> rsk_ui::OathDetailView {
        let dev = self.keys.device();
        let mut fs = self.fs.borrow_mut();
        let mut view = rsk_ui::OathDetailView::default();
        let mut i = 0usize;
        rsk_oath::for_each_cred(&dev, &mut fs, |c| {
            if i == idx {
                view = rsk_ui::OathDetailView {
                    name: Label::clamp(c.name),
                    hotp: c.hotp,
                    algo: Label::clamp(rsk_oath::algo_name(c.algo).as_bytes()),
                    digits: c.digits,
                    period: c.period,
                    touch: c.touch,
                };
            }
            i += 1;
        });
        view
    }

    /// One OATH credential's detail screen (back-only, no nav). Read-only; back chevron /
    /// power button / a queued host command / inactivity all return to the list.
    fn run_oath_cred(&mut self, idx: usize) {
        let view = self.load_oath_cred(idx);
        let _ = rsk_ui::render_oath_cred(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
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
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// Repaint the Passkeys list (a full-frame paint) and mark the panel for the ambient
    /// loop to refresh once the tab closes.
    fn render_list(&mut self, rows: &[RpRow], page: u16, total: u16) {
        let _ = rsk_ui::render_passkeys_list(&mut self.panel, rows, page, total);
        self.shown = None;
    }

    /// Enumerate resident RPs into `rows` (+ their rpIdHashes into `hashes`), returning
    /// the kept count and the true total. Reads + decrypts from the shared store; the
    /// seed is loaded and zeroized inside the enumerator (the display never holds it).
    fn load_rps(&self, rows: &mut [RpRow], hashes: &mut [[u8; 32]], page: u16) -> (usize, u16) {
        let dev = self.keys.device();
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut store = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let total = rsk_fido::passkeys::for_each_rp(&dev, &mut *store, |rp| {
            if idx >= offset && n < rows.len() {
                rows[n] = RpRow {
                    // Domain: keep the registrable-domain suffix, not the head, so a
                    // padded look-alike rpId can't impersonate a service on the list,
                    // service-detail title and Confirm-Delete card (matches the ceremony).
                    id: Label::clamp_domain(rp.rp_id.as_bytes()),
                    nick: rp
                        .nickname
                        .map(|s| Label::clamp(s.as_bytes()))
                        .unwrap_or_default(),
                    accounts: rp.count,
                };
                hashes[n] = rp.rp_id_hash;
                n += 1;
            }
            idx += 1;
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// Snapshot the most recent journal events for the audit log, newest first. Each
    /// `EV_*` code maps to its display [`rsk_ui::AuditKind`], and an entry from the
    /// **current** power cycle also carries how long ago it happened — the journal
    /// stamps [`crate::usb_attach::elapsed_ms`], which resets each boot, so a boot
    /// entry marks the session boundary and older rows show no time (no wall clock).
    /// Borrow-safe like [`Self::load_rps`] (the worker is parked while this modal runs).
    fn load_events(&self, rows: &mut [AuditRow], page: u16) -> (usize, u16) {
        let dev = self.keys.device();
        // Cap the live clock at the journal's own resolution: `build_entry` saturates the
        // stored `uptime_ms` to `u32::MAX`, so after ~49.7 days of continuous uptime both
        // sides saturate together and a just-logged event still reads "now" rather than a
        // delta measured from the saturation point.
        let now_ms = crate::usb_attach::elapsed_ms().min(u32::MAX as u64);
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut store = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let mut current_session = true;
        let total = rsk_fido::journal::for_each_event(&dev, &mut *store, |e| {
            if idx >= offset && n < rows.len() {
                let secs_ago = if current_session && (e.uptime_ms as u64) <= now_ms {
                    Some(((now_ms - e.uptime_ms as u64) / 1000) as u32)
                } else {
                    None
                };
                rows[n] = AuditRow {
                    kind: audit_kind(e.event),
                    secs_ago,
                };
                n += 1;
            }
            // Track the boot boundary for EVERY visited entry (including newer ones skipped
            // before the page window), so the current-session flag is correct by the time we
            // reach the page.
            if e.event == rsk_fido::journal::EV_BOOT {
                current_session = false; // everything older is a prior power cycle
            }
            idx += 1;
            n < rows.len() // stop once the page is full (older entries needn't be visited)
        });
        (n, total.min(u16::MAX as u32) as u16)
    }

    /// The read-only on-device audit log (Settings → Security → Audit log): snapshot the
    /// current page of journal events and show them until the back chevron, the power
    /// button (sleeps + locks), a queued host command, or the inactivity timeout. The
    /// pager arrows page through a longer log. Synchronous like the other browse modals
    /// (the worker is parked); read-only, so no tap mutates anything. After a power-button
    /// sleep the caller ([`Self::run_settings`]) sees `asleep` and unwinds without
    /// repainting over the blanked panel.
    pub(super) fn run_auditlog(&mut self) {
        let mut rows = [AuditRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_events(&mut rows, page);
        let _ = rsk_ui::render_audit_log(&mut self.panel, &rows[..n], page, total);
        self.shown = None;
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
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
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_events(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_audit_log(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending_after(last) || last.elapsed() >= idle_limit {
                return;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }
}
