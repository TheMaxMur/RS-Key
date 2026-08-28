// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, PIN, Pad, backdate, backdate_local, center, nowhere};

fn home(status: StatusKind, pin_set: bool, passkeys: u16) -> Screen {
    Screen::Home(HomeView {
        status,
        pin_set,
        passkeys,
    })
}

#[test]
fn the_panel_shows_the_status_the_led_would() {
    assert_eq!(status_to_kind(rsk_led::STATUS_IDLE), StatusKind::Idle);
    assert_eq!(
        status_to_kind(rsk_led::STATUS_PROCESSING),
        StatusKind::Processing
    );
    assert_eq!(status_to_kind(rsk_led::STATUS_TOUCH), StatusKind::Touch);
    assert_eq!(status_to_kind(u8::MAX), StatusKind::Boot);
}

#[test]
fn a_status_glyph_is_not_a_different_surface() {
    // Audit run-34 #14: the host drives `led_status` around every dispatch, so
    // counting the glyph as a new screen let a plain CTAP loop disarm the panel on
    // every tick and swallow every tap. A tap on Home means the same thing
    // whatever the glyph says.
    let idle = home(StatusKind::Idle, true, 3);
    let busy = home(StatusKind::Processing, true, 3);
    assert!(same_surface(Some(idle), busy));
}

#[test]
fn a_changed_home_card_is_a_different_surface() {
    let base = home(StatusKind::Idle, true, 3);
    // The card's own facts do move what is under the finger — the PIN row and the
    // passkey count are rows, not a glyph.
    assert!(!same_surface(Some(base), home(StatusKind::Idle, false, 3)));
    assert!(!same_surface(Some(base), home(StatusKind::Idle, true, 4)));
    assert!(!same_surface(Some(base), Screen::Locked));
    assert!(
        !same_surface(None, base),
        "nothing painted is never the same"
    );
    assert!(same_surface(Some(Screen::Locked), Screen::Locked));
}

#[test]
fn display_sleep_off_does_not_switch_the_lock_off() {
    // The lock is a security control; "Off" is a display setting. Off falls back to
    // the built-in deadline rather than disabling the lock with the blanking.
    assert_eq!(lock_after_ms(0), DEFAULT_SLEEP_MS);
    assert_eq!(lock_after_ms(5_000), 5_000);
}

#[test]
fn a_pager_tap_clamps_to_the_real_pages() {
    let total = rsk_ui::PK_ROWS_MAX as u16 + 1; // two pages
    let last = rsk_ui::page_count(total) - 1;
    assert_eq!(paged(0, total, rsk_ui::PagerKey::Prev), 0);
    assert_eq!(paged(0, total, rsk_ui::PagerKey::Next), 1);
    assert_eq!(paged(last, total, rsk_ui::PagerKey::Next), last);
    assert_eq!(paged(last, total, rsk_ui::PagerKey::Prev), last - 1);
    assert_eq!(
        paged(0, 0, rsk_ui::PagerKey::Next),
        0,
        "an empty list has one page"
    );
}

#[test]
fn journal_events_map_onto_their_display_class() {
    use rsk_fido::journal as j;
    use rsk_ui::AuditKind as K;
    assert_eq!(audit_kind(j::EV_GET_ASSERT), K::Login);
    assert_eq!(audit_kind(j::EV_U2F_AUTH), K::Login);
    assert_eq!(audit_kind(j::EV_MAKE_CRED), K::Register);
    assert_eq!(audit_kind(j::EV_PIN_LOCKOUT), K::Denied);
    assert_eq!(audit_kind(j::EV_RESET), K::Reset);
    assert_eq!(audit_kind(j::EV_BACKUP_EXPORT), K::Backup);
    // An event a newer firmware wrote must still list, unclassified rather than lost.
    assert_eq!(audit_kind(u8::MAX), K::Other);
}

#[test]
fn a_step_that_cannot_move_is_not_a_change() {
    // A no-op tap at a clamp boundary must not mark the settings session dirty —
    // that is a flash write into the credential partition for nothing.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let mut steps = 0;
    while adjust_timeout(&mut ui.hooks, -1) {
        steps += 1;
        assert!(steps < 32, "the touch-timeout menu does not terminate");
    }
    let floor = ui.hooks.presence_ms;
    assert!(!adjust_timeout(&mut ui.hooks, -1));
    assert_eq!(ui.hooks.presence_ms, floor);
    assert!(
        adjust_timeout(&mut ui.hooks, 1),
        "+ still moves off the floor"
    );
}

#[test]
fn a_sleep_step_that_cannot_move_is_not_a_change() {
    let _env = Env::new();
    let mut steps = 0;
    while adjust_sleep(1) {
        steps += 1;
        assert!(steps < 32, "the display-sleep menu does not terminate");
    }
    let ceiling = SLEEP_TIMEOUT_MS.load(Ordering::Relaxed);
    assert!(!adjust_sleep(1));
    assert_eq!(SLEEP_TIMEOUT_MS.load(Ordering::Relaxed), ceiling);
    assert!(adjust_sleep(-1));
}

#[test]
fn an_unchanged_ambient_screen_is_not_repainted() {
    // The idle frame is the hot path: a repaint per 100 ms tick is SPI traffic the
    // panel does not need and a flicker the user would see.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.onboarding = false;
    let (mut spin, mut breathe) = (rsk_ui::STATUS_ARC_START, 0u8);
    ui.ambient_repaint(1, &mut spin, &mut breathe);
    assert_eq!(ui.shown, Some(home(StatusKind::Idle, false, 0)));
    let frames = ui.panel.frames;
    let damage = ui.panel.damage_presentations;
    ui.ambient_repaint(2, &mut spin, &mut breathe);
    assert_eq!(ui.panel.frames, frames);
    assert_eq!(ui.panel.damage_presentations, damage);
}

#[test]
fn a_status_glyph_change_repaints_without_disarming_the_panel() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.onboarding = false;
    let (mut spin, mut breathe) = (rsk_ui::STATUS_ARC_START, 0u8);
    ui.ambient_repaint(1, &mut spin, &mut breathe);
    ui.touch_armed = true;
    let writes = ui.panel.writes;
    let damage = ui.panel.damage_presentations;
    let rects = ui.panel.damage_rects.len();
    ui.hooks.led = rsk_led::STATUS_PROCESSING;
    ui.ambient_repaint(2, &mut spin, &mut breathe);
    assert!(ui.panel.writes > writes, "the glyph did change");
    assert_eq!(ui.panel.damage_presentations, damage + 1);
    assert_eq!(ui.panel.damage_rects.len(), rects + 1);
    assert_eq!(
        ui.panel.damage_rects[rects],
        rsk_ui::Rect::new(
            0,
            rsk_ui::STATUS_BAR_H,
            rsk_ui::PANEL_W,
            rsk_ui::NAV_TOP - rsk_ui::STATUS_BAR_H,
        )
    );
    assert!(ui.touch_armed, "…but the surface under the finger did not");
}

#[test]
fn one_changed_home_row_uses_one_retained_panel_window() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.paint(home(StatusKind::Idle, false, 7));
    let damage = ui.panel.damage_presentations;
    let rects = ui.panel.damage_rects.len();

    ui.paint(home(StatusKind::Idle, true, 7));

    assert_eq!(ui.panel.damage_presentations, damage + 1);
    assert_eq!(ui.panel.damage_rects.len(), rects + 1);
}

#[test]
fn a_new_surface_disarms_the_panel() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.onboarding = false;
    let (mut spin, mut breathe) = (rsk_ui::STATUS_ARC_START, 0u8);
    ui.ambient_repaint(1, &mut spin, &mut breathe);
    ui.touch_armed = true;
    ui.locked = true;
    ui.ambient_repaint(2, &mut spin, &mut breathe);
    assert_eq!(ui.shown, Some(Screen::Locked));
    assert!(!ui.touch_armed, "a screen that just appeared is untouched");
}

#[test]
fn a_busy_device_never_falls_asleep_mid_operation() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.onboarding = false;
    ui.hooks.led = rsk_led::STATUS_PROCESSING;
    backdate(DEFAULT_SLEEP_MS);
    let (mut spin, mut breathe) = (rsk_ui::STATUS_ARC_START, 0u8);
    ui.ambient_repaint(1, &mut spin, &mut breathe);
    ui.tick_deadlines();
    assert!(!ui.asleep, "working counts as activity");
}

#[test]
fn touch_is_read_before_a_host_has_configured_the_device() {
    // `kind` is a *display* concern (which glyph to paint) and sits at `Boot` until
    // a host completes SET_CONFIGURATION — so gating input on `Idle` left the panel
    // animating but deaf on charger or battery power.
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::nav_tab_rect(0))]));
    ui.onboarding = false;
    assert!(!ui.handle_local_input(StatusKind::Processing));
    assert!(!ui.handle_local_input(StatusKind::Touch));
    assert_eq!(
        ui.touch.reads, 0,
        "a busy device never even samples the pad"
    );
    assert!(
        (0..8).any(|_| ui.handle_local_input(StatusKind::Boot)),
        "a tap on an unconfigured device is still input"
    );
}

#[test]
fn a_tap_that_hits_nothing_is_still_a_local_interaction() {
    // The auto-lock measures from the last touch, not from the last touch that hit
    // something — a user reading the screen is present.
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[nowhere()]));
    ui.onboarding = false;
    ui.handle_local_input(StatusKind::Idle); // arms the pad
    backdate_local(DEFAULT_SLEEP_MS);
    let stale = LAST_LOCAL_MS.load(Ordering::Relaxed);
    assert!((0..8).any(|_| ui.handle_local_input(StatusKind::Idle)));
    assert_ne!(LAST_LOCAL_MS.load(Ordering::Relaxed), stale);
}

#[test]
fn the_panel_blanks_after_the_sleep_timeout() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    backdate(SLEEP_TIMEOUT_MS.load(Ordering::Relaxed));
    ui.tick_deadlines();
    assert!(ui.asleep);
}

#[test]
fn display_sleep_off_still_arms_the_lock() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::idle());
    ui.locked = false;
    SLEEP_TIMEOUT_MS.store(0, Ordering::Relaxed);
    backdate(DEFAULT_SLEEP_MS);
    ui.tick_deadlines();
    assert!(!ui.asleep, "Off means the panel never blanks");
    assert!(ui.locked);
    assert_eq!(ui.shown, Some(Screen::Locked));
}

#[test]
fn a_host_ceremony_loop_cannot_hold_the_lock_off() {
    // Audit run-34 #15: the auto-lock counts from the last *local* interaction, so
    // a loop of unauthenticated `authenticatorSelection` — each one activity —
    // cannot postpone it, which is what `power.rs` promises a host cannot do.
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::idle());
    ui.locked = false;
    backdate_local(DEFAULT_SLEEP_MS);
    note_activity(); // the host, again and again
    ui.tick_deadlines();
    assert!(!ui.asleep, "the host did keep the backlight awake");
    assert!(ui.locked, "…and did not keep the panel unlocked");
}

#[test]
fn a_touch_wakes_the_panel_without_tapping_what_it_woke_to() {
    let env = Env::new();
    let mut ui = env.ui(Pad::script(&[Some(nowhere()), None]));
    ui.enter_sleep();
    assert!(ui.asleep);
    ui.tick_asleep();
    assert!(!ui.asleep);
    assert_eq!(
        ui.shown,
        Some(Screen::Onboard),
        "waking shows the screen, not the black frame"
    );
    assert!(
        !ui.touch_armed,
        "the waking contact is consumed, not delivered"
    );
}

#[test]
fn a_sleeping_panel_ignores_everything_but_a_wake_source() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.enter_sleep();
    let frames = ui.panel.frames;
    ui.tick_asleep();
    assert!(ui.asleep);
    assert_eq!(ui.panel.frames, frames, "a blanked panel stays blank");
}
