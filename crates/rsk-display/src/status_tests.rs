// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::pin_entry;
use crate::tests::{
    Env, PIN, Pad, WORKER_RESET_WAIT_MS, WORKER_TICK_MS, backdate, backdate_local, center, nowhere,
    settings_row,
};

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
    env.local(&mut ui)
        .ambient_repaint(1, &mut spin, &mut breathe);
    assert_eq!(ui.shown, Some(home(StatusKind::Idle, false, 0)));
    let frames = ui.panel.frames;
    let damage = ui.panel.damage_presentations;
    env.local(&mut ui)
        .ambient_repaint(2, &mut spin, &mut breathe);
    assert_eq!(ui.panel.frames, frames);
    assert_eq!(ui.panel.damage_presentations, damage);
}

#[test]
fn a_status_glyph_change_repaints_without_disarming_the_panel() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.onboarding = false;
    let (mut spin, mut breathe) = (rsk_ui::STATUS_ARC_START, 0u8);
    env.local(&mut ui)
        .ambient_repaint(1, &mut spin, &mut breathe);
    ui.touch_armed = true;
    let writes = ui.panel.writes;
    let damage = ui.panel.damage_presentations;
    let rects = ui.panel.damage_rects.len();
    ui.hooks.led = rsk_led::STATUS_PROCESSING;
    env.local(&mut ui)
        .ambient_repaint(2, &mut spin, &mut breathe);
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
    env.local(&mut ui)
        .ambient_repaint(1, &mut spin, &mut breathe);
    ui.touch_armed = true;
    ui.locked = true;
    env.local(&mut ui)
        .ambient_repaint(2, &mut spin, &mut breathe);
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
    env.local(&mut ui)
        .ambient_repaint(1, &mut spin, &mut breathe);
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
    assert!(
        !env.local(&mut ui)
            .handle_local_input(StatusKind::Processing)
    );
    assert!(!env.local(&mut ui).handle_local_input(StatusKind::Touch));
    assert_eq!(
        ui.touch.reads, 0,
        "a busy device never even samples the pad"
    );
    assert!(
        (0..8).any(|_| env.local(&mut ui).handle_local_input(StatusKind::Boot)),
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
    env.local(&mut ui).handle_local_input(StatusKind::Idle); // arms the pad
    backdate_local(DEFAULT_SLEEP_MS);
    let stale = LAST_LOCAL_MS.load(Ordering::Relaxed);
    assert!((0..8).any(|_| env.local(&mut ui).handle_local_input(StatusKind::Idle)));
    assert_ne!(LAST_LOCAL_MS.load(Ordering::Relaxed), stale);
}

/// A flow the panel runs leaves its frames dead when it returns, and no host request
/// may follow to sweep them: the tick that ran it asks the board to, a quiet one not.
#[test]
fn a_returned_panel_flow_asks_for_the_dead_stack_sweep() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[nowhere()]));
    ui.onboarding = false;
    env.local(&mut ui).handle_local_input(StatusKind::Idle); // arms the pad
    assert_eq!(ui.hooks.sweeps, 0, "a tick with no gesture ran no flow");
    assert!((0..8).any(|_| env.local(&mut ui).handle_local_input(StatusKind::Idle)));
    assert_eq!(
        ui.hooks.sweeps, 1,
        "the tap's flow returned, and its frames were swept"
    );
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
    env.local(&mut ui).tick_asleep();
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
    env.local(&mut ui).tick_asleep();
    assert!(ui.asleep);
    assert_eq!(ui.panel.frames, frames, "a blanked panel stays blank");
}

/// The centre of the nav tab `want`, found through `rsk-ui`'s own hit test.
fn nav_tab(want: NavTab) -> rsk_ui::Point {
    (0..rsk_ui::NAV_TABS.len() as u16)
        .map(|i| center(rsk_ui::nav_tab_rect(i)))
        .find(|&p| rsk_ui::hit_nav(p) == Some(want))
        .expect("the nav bar has that tab")
}

/// Well past the reset flow's own few seconds, for a stand-in worker still waiting on it.
const RESET_FLOW_BOUND: Duration = Duration::from_secs(30);

/// From a completed factory reset to the reset itself the panel handles no input and the
/// host's session is over. The worker takes the queued reboot and waits before its scrub, on
/// the panel's executor: a slot that read clear once taken let the panel run in that wait.
#[test]
fn a_panel_reset_leaves_no_input_or_session_until_the_reset() {
    let env = Env::new();
    let security = settings_row(
        rsk_ui::SETTINGS_ROWS,
        rsk_ui::hit_settings_root,
        RootEntry::Security,
    );
    let reset = settings_row(
        rsk_ui::SECURITY_ROWS,
        rsk_ui::hit_security,
        SecurityEntry::FactoryReset,
    );
    let mut ui = env.ui(Pad::taps_then_hold(
        &[nav_tab(NavTab::Settings), security, reset],
        center(rsk_ui::DEL_HOLD_RECT),
    ));
    ui.onboarding = false;
    let ui = RefCell::new(ui);

    // `Worker::run`'s idle tick taking the request, then `Worker::reboot`: the latch, and the
    // wait before its scrub with a wake press inside it.
    let worker = async {
        let bound = Instant::now() + RESET_FLOW_BOUND;
        let mode = loop {
            let taken = ui.borrow().hooks.slot.take();
            if taken.is_some() || Instant::now() >= bound {
                break taken;
            }
            Timer::after_millis(WORKER_TICK_MS).await;
        };
        ui.borrow().hooks.slot.begin_reset();
        ui.borrow().hooks.wake_polls.set(1);
        Timer::after_millis(WORKER_RESET_WAIT_MS).await;
        let ui = ui.borrow();
        let hooks = &ui.hooks;
        (mode, ui.asleep, hooks.wake_polls.get(), hooks.pin_changed)
    };
    let embassy_futures::select::Either::Second(at_reset) = embassy_futures::block_on(
        embassy_futures::select::select(status_loop(&ui, env.cells()), worker),
    ) else {
        unreachable!("the status loop never returns");
    };
    assert_eq!(
        at_reset,
        (Some(1), false, 1, 1),
        "a completed reset must queue its reboot, handle no input until the reset, and end \
         the host's session"
    );
}

/// A finger still down when the flow a tap opened has closed is not a second tap: Settings
/// left through the nav bar hands the ambient loop the very contact that left it.
#[test]
fn a_finger_still_down_when_a_tab_closes_is_not_a_second_tap() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps_then_hold(
        &[nav_tab(NavTab::Settings)],
        nav_tab(NavTab::Home),
    ));
    ui.onboarding = false;
    // The lead-in samples arm the panel; the tap then runs Settings until Home is held.
    let opened = (0..3).any(|_| env.local(&mut ui).handle_local_input(StatusKind::Idle));
    let again = env.local(&mut ui).handle_local_input(StatusKind::Idle);
    assert_eq!(
        (opened, again),
        (true, false),
        "the contact that closed the tab must not be a tap on the screen it returned to"
    );
}

/// A contact resting on the panel — a finger, or something lying on it — is one tap. Read
/// as a fresh one every tick it kept the local-activity clock current, and the auto-lock
/// never armed for as long as it rested.
#[test]
fn a_contact_resting_on_the_panel_cannot_hold_the_lock_off() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::held(nowhere()));
    ui.locked = false;
    ui.touch_armed = true;
    let landed = env.local(&mut ui).handle_local_input(StatusKind::Idle);
    backdate_local(lock_after_ms(SLEEP_TIMEOUT_MS.load(Ordering::Relaxed)));
    let rested = env.local(&mut ui).handle_local_input(StatusKind::Idle);
    ui.tick_deadlines();
    assert_eq!(
        (landed, rested, ui.locked),
        (true, false, true),
        "a resting contact must not count as a tap again, or the auto-lock never arms"
    );
}

#[test]
fn an_unlock_tap_repaints_home_but_power_cancellation_keeps_the_panel_dark() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&pin_entry(PIN)));
    ui.hooks.presence_ms = 3000;
    env.local(&mut ui).tap_locked();
    assert!(!ui.locked && !ui.asleep);
    assert_eq!(ui.shown, Some(home(StatusKind::Idle, true, 0)));
    let mut ui = env.ui(Pad::idle());
    ui.hooks.press_wake(1);
    env.local(&mut ui).tap_locked();
    assert!(ui.locked && ui.asleep);
    assert_ne!(ui.shown, Some(home(StatusKind::Idle, true, 0)));
}

#[test]
fn onboarding_taps_repaint_only_after_a_resolved_choice() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    env.local(&mut ui).tap_onboarding(nowhere());
    assert_eq!(ui.shown, Some(Screen::Onboard));
    env.local(&mut ui)
        .tap_onboarding(center(rsk_ui::ONBOARD_SET_RECT));
    assert!(ui.onboarding);
    assert_eq!(ui.shown, Some(Screen::Onboard));
    env.local(&mut ui)
        .tap_onboarding(center(rsk_ui::ONBOARD_SKIP_RECT));
    assert!(!ui.onboarding);
    assert_eq!(ui.shown, Some(home(StatusKind::Idle, false, 0)));
    assert!(!ui.panel.oob);
}

#[test]
fn direct_tab_switches_return_to_a_refreshed_home() {
    let env = Env::new();
    let mut samples = vec![None, None];
    for tab in [NavTab::Passkeys, NavTab::Settings, NavTab::Home] {
        samples.extend([Some(nav_tab(tab)), None, None, None, None]);
    }
    let mut ui = env.ui(Pad::script(&samples));
    ui.onboarding = false;
    let before = ui.panel.writes;
    let started = Instant::now();
    env.local(&mut ui).tap_nav(nav_tab(NavTab::Apps));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(ui.shown, Some(home(StatusKind::Idle, false, 0)));
    assert!(ui.panel.writes > before);
    assert!(!ui.panel.oob);
}
