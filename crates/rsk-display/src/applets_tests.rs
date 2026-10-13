// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, Pad, center, nowhere};

#[test]
fn every_applet_browse_window_yields_to_a_queued_host_request_or_sleep() {
    let _env = Env::new();
    for sleep in [false, true] {
        macro_rules! window {
            ($run:expr) => {
                crate::tests::with_isolated_ui(|ui, cells| {
                    if sleep {
                        ui.hooks.press_wake(1);
                    } else {
                        ui.hooks.host_pending = true;
                    }
                    let before = cells.fs.borrow().write_gen();
                    let start = Instant::now();
                    let mut local = Local::new(ui, cells);
                    $run(&mut local);
                    assert!(start.elapsed() < Duration::from_secs(5));
                    assert_eq!(local.asleep, sleep);
                    assert_eq!(local.cells.fs.borrow().write_gen(), before);
                    assert!(!local.panel.oob);
                });
            };
        }
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_apps(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_openpgp(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_openpgp_key(0));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_openpgp_cardholder());
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_piv(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local
            .run_piv_slot(rsk_piv::files::SLOT_AUTHENTICATION));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_piv_extra());
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_oath(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_oath_cred(0));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_auditlog());
    }
}

#[test]
fn every_idle_browse_window_returns_at_the_real_inactivity_deadline() {
    let _env = Env::new();
    std::thread::scope(|scope| {
        macro_rules! window {
            ($run:expr) => {
                scope.spawn(|| {
                    crate::tests::with_isolated_ui(|ui, cells| {
                        let before = cells.fs.borrow().write_gen();
                        let start = Instant::now();
                        let mut local = Local::new(ui, cells);
                        $run(&mut local);
                        assert!(start.elapsed() >= Duration::from_millis(MENU_INACTIVITY_MS));
                        assert!(!local.asleep);
                        assert!(!local.hooks.host_request_pending());
                        assert_eq!(local.cells.fs.borrow().write_gen(), before);
                        assert!(!local.panel.oob);
                    })
                });
            };
        }
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_passkeys(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert!(matches!(
            local.run_service(&Label::clamp(b"example.com"), &Label::default(), &[0; 32]),
            ServiceResult::Leave(None)
        )));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_apps(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_openpgp(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_openpgp_key(0));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_openpgp_cardholder());
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_piv(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local
            .run_piv_slot(rsk_piv::files::SLOT_AUTHENTICATION));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_piv_extra());
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert!(matches!(
            local.pick_row(rsk_ui::PK_LIST_TOP, 1),
            Pick::Leave
        )));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| assert_eq!(local.run_oath(), None));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_oath_cred(0));
        window!(|local: &mut Local<'_, '_, _, _, _, _, _>| local.run_auditlog());
    });
}

fn view(nick: &[u8]) -> ServiceView {
    ServiceView {
        accts: [AccountRow::default(); rsk_ui::PK_ROWS_MAX],
        fids: [0u16; rsk_ui::PK_ROWS_MAX],
        page: 0,
        n: 0,
        total: 0,
        nick: Label::clamp(nick),
    }
}

#[test]
fn a_nickname_stands_in_for_the_relying_party_id() {
    let rp = Label::clamp(b"login.example.com");
    assert_eq!(service_title(&rp, &view(b"Work")).as_str(), "Work");
}

#[test]
fn without_a_nickname_the_real_relying_party_id_is_shown() {
    // The fallback is the *real* id, never a blank title — the screen's whole claim
    // is that it names who is asking.
    let rp = Label::clamp(b"login.example.com");
    assert_eq!(service_title(&rp, &view(b"")).as_str(), "login.example.com");
}

#[test]
fn a_list_poll_reports_the_row_that_was_tapped() {
    let env = Env::new();
    let rows = rsk_ui::PK_ROWS_MAX as u16;
    let target = rows - 1;
    let tap = center(rsk_ui::row_rect(rsk_ui::PK_LIST_TOP, target));
    let mut ui = env.ui(Pad::taps(&[tap]));
    assert!(
        matches!(env.local(&mut ui).pick_row(rsk_ui::PK_LIST_TOP, rows), Pick::Row(i) if i == target)
    );
}

#[test]
fn each_openpgp_overview_row_opens_its_own_detail_screen() {
    let env = Env::new();
    for row in 0..4 {
        let apps = rsk_ui::NAV_TABS
            .iter()
            .position(|tab| *tab == NavTab::Apps)
            .unwrap();
        let mut ui = env.ui(Pad::taps(&[
            center(rsk_ui::row_rect(rsk_ui::PK_LIST_TOP, row)),
            center(rsk_ui::TITLE_BACK_RECT),
            center(rsk_ui::nav_tab_rect(apps as u16)),
        ]));
        let mut reference = env.ui(Pad::idle());
        let mut local = env.local(&mut reference);
        if row < 3 {
            let view = local.load_openpgp_key(row as usize);
            rsk_ui::render_openpgp_key(&mut local.frame(), &view).unwrap();
        } else {
            let view = local.load_openpgp_cardholder();
            rsk_ui::render_openpgp_cardholder(&mut local.frame(), &view).unwrap();
        }
        let expected = reference.panel.raster_hash();
        assert_eq!(env.local(&mut ui).run_openpgp(), None);
        assert!(
            ui.panel.frame_hashes.contains(&expected),
            "overview row {row} must paint its own detail"
        );
    }
}

#[test]
fn each_piv_overview_row_opens_its_own_detail_screen() {
    let env = Env::new();
    let generation = env.fs.borrow().write_gen();
    for row in 0..rsk_ui::PIV_ROWS {
        let apps = rsk_ui::NAV_TABS
            .iter()
            .position(|tab| *tab == NavTab::Apps)
            .unwrap();
        let mut ui = env.ui(Pad::taps(&[
            center(rsk_ui::row_rect(rsk_ui::PK_LIST_TOP, row)),
            center(rsk_ui::TITLE_BACK_RECT),
            center(rsk_ui::nav_tab_rect(apps as u16)),
        ]));
        let mut reference = env.ui(Pad::idle());
        let mut local = env.local(&mut reference);
        let overview = local.load_piv();
        if usize::from(row) < overview.slots.len() {
            let view = local.load_piv_slot(overview.slots[usize::from(row)].slot);
            rsk_ui::render_piv_slot(&mut local.frame(), &view).unwrap();
        } else {
            let mut rows = [rsk_ui::PivExtraRow::default(); rsk_ui::PK_ROWS_MAX];
            let (n, total) = local.load_piv_extra(&mut rows, 0);
            rsk_ui::render_piv_extra(&mut local.frame(), &rows[..n], 0, total).unwrap();
        }
        let expected = reference.panel.raster_hash();
        assert_eq!(env.local(&mut ui).run_piv(), None);
        assert!(
            ui.panel.frame_hashes.contains(&expected),
            "PIV overview row {row} must paint its own detail"
        );
    }
    assert_eq!(env.fs.borrow().write_gen(), generation);
}

#[test]
fn a_list_poll_reports_the_back_chevron() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::TITLE_BACK_RECT)]));
    assert!(matches!(
        env.local(&mut ui)
            .pick_row(rsk_ui::PK_LIST_TOP, rsk_ui::PK_ROWS_MAX as u16),
        Pick::Back
    ));
}

#[test]
fn a_queued_host_command_closes_an_open_list() {
    // A browse modal parks the worker (one thread executor), so an open list must
    // yield the moment a host command arrives rather than make it wait out the
    // inactivity bound.
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[nowhere()]));
    ui.hooks.host_pending = true;
    assert!(matches!(
        env.local(&mut ui)
            .pick_row(rsk_ui::PK_LIST_TOP, rsk_ui::PK_ROWS_MAX as u16),
        Pick::Leave
    ));
}

#[test]
fn the_power_button_closes_an_open_list() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.hooks.press_wake(1);
    assert!(matches!(
        env.local(&mut ui)
            .pick_row(rsk_ui::PK_LIST_TOP, rsk_ui::PK_ROWS_MAX as u16),
        Pick::Leave
    ));
    assert!(ui.asleep, "and the panel is blanked on the way out");
}

#[test]
fn a_tap_past_the_last_loaded_row_selects_nothing() {
    // The row count is the *loaded* one, not the geometry's — a page with two rows
    // must not hand row 4 to a delete.
    let env = Env::new();
    let loaded = 2u16;
    let tap = center(rsk_ui::row_rect(rsk_ui::PK_LIST_TOP, loaded));
    let mut ui = env.ui(Pad::taps(&[tap]));
    ui.hooks.host_pending = true; // so the poll ends instead of idling out
    assert!(matches!(
        env.local(&mut ui).pick_row(rsk_ui::PK_LIST_TOP, loaded),
        Pick::Leave
    ));
}

#[test]
fn the_cardholder_reader_can_always_see_a_truncation() {
    // `Label::clamp` can only set `truncated` if it is handed one byte more than it
    // keeps; equal buffers would let a cut value read as complete (audit run-34 #39).
    // The crate holds the rule because only it sees both constants — assert it runs.
    const _: () = assert!(rsk_openpgp::info::CH_FIELD_MAX == rsk_ui::LABEL_MAX + 1);
    let long = [b'x'; rsk_ui::LABEL_MAX + 1];
    assert!(Label::clamp(&long).truncated);
}
