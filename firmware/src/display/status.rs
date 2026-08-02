// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The ambient status loop and its status/audit display mappers.

use super::power::BREATHE_TICKS;
use super::*;

/// Repaint cadence for the on-device keygen spinner. The hook fires far more often than this
/// (once per prime candidate); time-gating to ~100ms keeps the panel repaint off the keygen's
/// hot path so the search isn't slowed by SPI traffic.
pub(super) const KEYGEN_SPIN_MS: u64 = 100;

/// Step the live presence/touch timeout to the next/previous menu choice and store
/// it (the seconds → ms atomic the waits read). [`Ui::persist_settings`] writes the
/// new value back to the phy record's `PresenceTimeout` tag on Settings exit, so it
/// survives a reboot (the same tag `rsk hw --touch-timeout` and boot both read).
/// Returns whether the value actually changed, so a no-op tap at a clamp boundary
/// doesn't mark the session dirty (and thus doesn't trigger a redundant flash write).
pub(super) fn adjust_timeout(delta: i8) -> bool {
    let cur = (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_timeout(cur, delta);
    PRESENCE_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
    next != cur
}

/// Step the display-sleep timeout from the menu (−/+). `0` seconds = Off (never blanks).
/// Returns whether the value actually changed (see [`adjust_timeout`]).
pub(super) fn adjust_sleep(delta: i8) -> bool {
    let cur = (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_sleep(cur, delta);
    SLEEP_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
    next != cur
}

/// Map the LED status engine's index ([`led::status`]) onto the on-screen status,
/// so the panel shows the same idle/working/touch state the LED would.
fn status_to_kind(s: u8) -> StatusKind {
    match s {
        led::STATUS_IDLE => StatusKind::Idle,
        led::STATUS_PROCESSING => StatusKind::Processing,
        led::STATUS_TOUCH => StatusKind::Touch,
        _ => StatusKind::Boot,
    }
}

/// Deadline for the on-device auto-lock. It follows the display-sleep setting so the two
/// stay intuitive, but "Off" (`0`) disables blanking only — a security control must not be
/// switchable off from a display page, so the lock falls back to the built-in default.
fn lock_after_ms(sleep_ms: u32) -> u32 {
    if sleep_ms == 0 {
        super::DEFAULT_SLEEP_MS
    } else {
        sleep_ms
    }
}

/// Apply a pager tap to the current page, clamped to `0..page_count(total)` — a Prev on
/// page 0 or a Next on the last page is a harmless no-op (the arrow is drawn dimmed).
pub(super) fn paged(page: u16, total: u16, k: rsk_ui::PagerKey) -> u16 {
    let last = rsk_ui::page_count(total).saturating_sub(1);
    match k {
        rsk_ui::PagerKey::Prev => page.saturating_sub(1),
        rsk_ui::PagerKey::Next => (page + 1).min(last),
    }
}

/// Map a journal event code to its on-device audit-log display class (the boundary
/// translation, the way an rpId is clamped into a `Label` — rsk-ui has no rsk-fido dep).
pub(super) fn audit_kind(ev: u8) -> rsk_ui::AuditKind {
    use rsk_fido::journal as j;
    use rsk_ui::AuditKind as K;
    match ev {
        j::EV_GET_ASSERT | j::EV_U2F_AUTH => K::Login,
        j::EV_MAKE_CRED | j::EV_U2F_REGISTER => K::Register,
        j::EV_PIN_SET | j::EV_PIN_CHANGE => K::Pin,
        j::EV_PIN_LOCKOUT => K::Denied,
        j::EV_BOOT => K::Boot,
        j::EV_RESET => K::Reset,
        j::EV_LOCK_ENGAGE | j::EV_LOCK_RELEASE => K::Lock,
        j::EV_CFG_MIN_PIN | j::EV_CFG_EA | j::EV_CFG_ALWAYS_UV | j::EV_AUDIT_CFG => K::Config,
        j::EV_BACKUP_EXPORT | j::EV_BACKUP_LOAD | j::EV_BACKUP_FINALIZE => K::Backup,
        _ => K::Other,
    }
}

/// Ambient status screen: after letting the splash linger, repaint the idle/working
/// status whenever [`led::status`] changes. The confirm prompt is painted by
/// [`TouchPresence`] (which holds the same [`Ui`]); a synchronous confirm occupies
/// this executor, so this loop never runs mid-confirm and the two never collide on
/// the panel (the `try_borrow_mut` is belt-and-suspenders).
#[embassy_executor::task]
pub async fn status_task(ui: &'static RefCell<Ui>) {
    Timer::after_millis(600).await; // let the boot splash linger
    note_local_activity(); // the fresh boot counts as activity, so the sleep clock starts now
    // Prime the Home status-card cache once before the first idle paint (boot has settled
    // the flash; the worker is parked here while this task runs, so the borrow is safe).
    ui.borrow_mut().refresh_home_stats();
    // Liveness animation state: the spinner arc angle (advanced while busy) and the
    // locked-hint breathe phase (advanced every few ticks), plus a tick counter to pace
    // the breathe. These pulse a small region on top of the already-painted frame, so
    // they never trigger a full repaint and can't flicker the idle hot path.
    let mut spin = rsk_ui::STATUS_ARC_START;
    let mut breathe: u8 = 0;
    let mut tick: u32 = 0;
    loop {
        // A Settings → Firmware update queued a reboot: stop driving the panel and just yield
        // so the worker (same thread-mode executor) gets scheduled to scrub the live secrets
        // and reset to BOOTSEL on its next tick. Parking here — before any repaint — keeps the
        // "Rebooting" notice on screen instead of flashing Home over it.
        if crate::vendor::reboot_pending() {
            Timer::after_millis(10).await;
            continue;
        }
        tick = tick.wrapping_add(1);
        // Wrap-safe deadline checks (millis truncated to u32 wrap every ~49 days).
        let now = Instant::now().as_millis() as u32;
        if let Ok(mut u) = ui.try_borrow_mut() {
            if u.asleep {
                // Blanked for retention: poll only the wake sources. A touch anywhere or
                // the wake button restores the panel — repainted right away so waking
                // shows Home, not the black sleep frame — and the gesture is consumed
                // (wait for release) so it isn't read as a tap / an instant re-sleep.
                if u.touch.read().is_some() || u.wake_pressed() {
                    u.wake();
                    note_local_activity();
                    // Wake to the Locked screen if the device locked on sleep, or the
                    // onboarding screen on a fresh PIN-less device; the wake gesture only
                    // wakes (it isn't read as the unlock/onboard tap — that comes after
                    // release). Otherwise wake straight to Home.
                    let screen = if u.locked {
                        Screen::Locked
                    } else if u.onboarding {
                        Screen::Onboard
                    } else {
                        // Woke from sleep: a host ceremony may have added/removed a passkey
                        // while the panel was dark, so refresh the card before painting.
                        u.refresh_home_stats();
                        Screen::Home(HomeView {
                            status: status_to_kind(led::status()),
                            pin_set: u.home_pin_set,
                            passkeys: u.home_passkeys,
                        })
                    };
                    let _ = rsk_ui::render(&mut u.panel, &screen);
                    u.shown = Some(screen);
                    u.touch
                        .wait_release(Instant::now(), Duration::from_millis(1000));
                    u.wait_wake_release();
                }
            } else {
                // Skip the ambient repaint while a modal hand-off is in flight, so the
                // status screen never flickers between the pad and the confirm prompt.
                let quiet_over =
                    now.wrapping_sub(AMBIENT_QUIET_UNTIL_MS.load(Ordering::Relaxed)) as i32 >= 0;
                if quiet_over {
                    let kind = status_to_kind(led::status());
                    // Working / awaiting-touch is activity — never sleep mid-operation.
                    if kind != StatusKind::Idle {
                        note_activity();
                    }
                    // When the on-device UI is locked, the Locked screen stands in for
                    // Home; a tap there starts the unlock PIN flow instead of nav. A fresh
                    // PIN-less device stands on the Onboard screen instead, until the user
                    // sets a PIN or continues without. Host ceremonies still paint their own
                    // prompts over either (they don't consult `locked` / `onboarding`).
                    let screen = if u.locked {
                        Screen::Locked
                    } else if u.onboarding {
                        Screen::Onboard
                    } else {
                        // Idle hot path: cached stats only — never a per-frame flash scan.
                        Screen::Home(HomeView {
                            status: kind,
                            pin_set: u.home_pin_set,
                            passkeys: u.home_passkeys,
                        })
                    };
                    if u.shown != Some(screen) {
                        let _ = rsk_ui::render(&mut u.panel, &screen);
                        u.shown = Some(screen);
                    }
                    // Liveness: pulse a small region over the (already-painted) frame — the
                    // spinner arc while busy, the breathe hint while locked. Both redraw in
                    // place (no clear), so they never flicker and the idle frame is untouched.
                    match screen {
                        Screen::Home(v) if v.status != StatusKind::Idle => {
                            spin = spin.wrapping_add(SPIN_STEP_DEG);
                            let _ = rsk_ui::render_status_arc(&mut u.panel, v.status, spin);
                        }
                        Screen::Locked if tick.is_multiple_of(BREATHE_TICKS) => {
                            breathe = breathe.wrapping_add(1);
                            let _ = rsk_ui::render_locked_breathe(&mut u.panel, breathe);
                        }
                        _ => {}
                    }
                    // Input and the auto-lock must not depend on the USB configuration
                    // state. `kind` is a *display* concern (which glyph to paint), and it
                    // sits at `Boot` until a host completes SET_CONFIGURATION — so gating
                    // touch on `Idle` left the panel animating but deaf on charger or
                    // battery power. Processing/Touch stay excluded because a dispatch or
                    // ceremony owns the executor then anyway.
                    if matches!(kind, StatusKind::Idle | StatusKind::Boot) {
                        if u.wake_pressed() {
                            // The wake button doubles as a manual "sleep now" while awake
                            // (also locks, like any sleep, when a PIN is set).
                            note_local_activity();
                            u.enter_sleep();
                            u.wait_wake_release();
                        } else if let Some(p) = u.touch.read() {
                            note_local_activity();
                            if u.locked {
                                // Locked: any tap opens the unlock pad. Repaint the result
                                // at once — Home if the correct PIN dropped the lock, else
                                // the Locked screen — so the pad's last frame never lingers
                                // through collect_pin's ambient-quiet window.
                                u.run_unlock();
                                note_local_activity();
                                // The power button can sleep from the unlock pad; the panel is
                                // then blanked, so leave the repaint to the wake path.
                                if !u.asleep {
                                    let screen = if u.locked {
                                        Screen::Locked
                                    } else {
                                        // Just unlocked: a host op during the lock may have
                                        // changed the count, so refresh before painting Home.
                                        u.refresh_home_stats();
                                        Screen::Home(HomeView {
                                            status: status_to_kind(led::status()),
                                            pin_set: u.home_pin_set,
                                            passkeys: u.home_passkeys,
                                        })
                                    };
                                    let _ = rsk_ui::render(&mut u.panel, &screen);
                                    u.shown = Some(screen);
                                }
                            } else if u.onboarding {
                                // Fresh PIN-less device: route the tap to the onboarding
                                // buttons (Set a PIN / Continue without). Repaint at once —
                                // Onboard again if it's still pending (a missed-button tap or
                                // an abandoned set), else Home now that the offer is resolved.
                                // `run_onboarding` refreshes the Home cache on whichever branch
                                // resolves the prompt, so the cached stats are current here.
                                u.run_onboarding(p);
                                note_local_activity();
                                // Setting a PIN here runs the pad, which the power button can
                                // sleep from; skip the repaint when it did (panel blanked).
                                if !u.asleep {
                                    let screen = if u.onboarding {
                                        Screen::Onboard
                                    } else {
                                        Screen::Home(HomeView {
                                            status: status_to_kind(led::status()),
                                            pin_set: u.home_pin_set,
                                            passkeys: u.home_passkeys,
                                        })
                                    };
                                    let _ = rsk_ui::render(&mut u.panel, &screen);
                                    u.shown = Some(screen);
                                }
                            } else {
                                // A tap on the bottom nav opens a tab. Each tab modal returns
                                // the next nav destination, so the user switches tab→tab
                                // directly (e.g. Passkeys → Settings) without a Home detour.
                                let mut target = rsk_ui::hit_nav(p);
                                let opened_tab = matches!(
                                    target,
                                    Some(NavTab::Settings | NavTab::Passkeys | NavTab::Apps)
                                );
                                while let Some(tab) = target {
                                    target = match tab {
                                        NavTab::Home => None,
                                        NavTab::Settings => u.run_settings(),
                                        NavTab::Passkeys => u.run_passkeys(),
                                        NavTab::Apps => u.run_apps(),
                                    };
                                }
                                note_local_activity(); // a browse session just ended — restart clock
                                // The power button can sleep from inside a tab modal; the panel
                                // is then blanked (and locked if a PIN is set), so leave the
                                // repaint to status_task's wake path and paint here only awake.
                                if !u.asleep {
                                    if u.locked {
                                        // The menu closed with the UI locked (a sub-flow slept
                                        // + locked without blanking is impossible, so this is
                                        // unreachable today, but keeps Locked from lingering).
                                        let screen = Screen::Locked;
                                        let _ = rsk_ui::render(&mut u.panel, &screen);
                                        u.shown = Some(screen);
                                    } else if opened_tab && !crate::worker::host_request_pending() {
                                        // Closing a tab back to idle repaints Home now (not next
                                        // poll) so it feels instant. Skip if a host command is
                                        // queued — the worker paints next (no stale flash). The
                                        // tab modal may have added/deleted a passkey or set the
                                        // PIN, so refresh the card facts first.
                                        u.refresh_home_stats();
                                        let screen = Screen::Home(HomeView {
                                            status: status_to_kind(led::status()),
                                            pin_set: u.home_pin_set,
                                            passkeys: u.home_passkeys,
                                        });
                                        let _ = rsk_ui::render(&mut u.panel, &screen);
                                        u.shown = Some(screen);
                                    }
                                }
                            }
                        } else {
                            // Idle this tick (no tap, no button): blank once past the
                            // (runtime) sleep timeout — `0` disables sleep. Re-read the
                            // clock: a tab/menu modal *above* can run for many seconds, so
                            // the top-of-loop `now` would be stale and underflow against the
                            // freshly-bumped activity stamp.
                            let now = Instant::now().as_millis() as u32;
                            let sleep_ms = SLEEP_TIMEOUT_MS.load(Ordering::Relaxed);
                            if sleep_ms != 0
                                && now.wrapping_sub(LAST_ACTIVITY_MS.load(Ordering::Relaxed))
                                    >= sleep_ms
                            {
                                u.enter_sleep();
                            } else if now.wrapping_sub(LAST_LOCAL_MS.load(Ordering::Relaxed))
                                >= lock_after_ms(sleep_ms)
                                && u.lock_now()
                            {
                                // The auto-lock runs on its own deadline, counted from the
                                // last *local* interaction, so neither a host ceremony loop
                                // nor "Display sleep: Off" can hold the panel unlocked. It
                                // only re-arms the lock — blanking stays the sleep setting's
                                // business — so repaint the Locked screen now.
                                let screen = Screen::Locked;
                                let _ = rsk_ui::render(&mut u.panel, &screen);
                                u.shown = Some(screen);
                            }
                        }
                    }
                }
            }
        }
        Timer::after_millis(100).await;
    }
}
