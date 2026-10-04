// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, Pad, center, nowhere};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

fn nav(tab: NavTab) -> rsk_ui::Point {
    let i = rsk_ui::NAV_TABS.iter().position(|t| *t == tab).unwrap();
    center(rsk_ui::nav_tab_rect(i as u16))
}

fn row(i: u16) -> rsk_ui::Point {
    center(rsk_ui::row_rect(rsk_ui::PK_LIST_TOP, i))
}

fn seed_metadata(env: &Env) {
    use rsk_openpgp::consts as pgp;
    use rsk_piv::files as piv;
    let mut fs = env.fs.borrow_mut();
    // Browsing may inspect record presence but must never open these opaque blobs.
    for (i, fid) in [pgp::EF_PK_SIG, pgp::EF_PK_DEC, pgp::EF_PK_AUT]
        .into_iter()
        .enumerate()
    {
        fs.put_key(fid, rsk_fs::Sealed::wrap(&[0xA5; 32])).unwrap();
        fs.put(pgp::EF_FP_SIG + i as u16, &[0x71; 20]).unwrap();
        fs.put(pgp::EF_TS_SIG + i as u16, &[0, 0, 0, 1]).unwrap();
        fs.put(pgp::EF_UIF_SIG + i as u16, &[1, 0]).unwrap();
    }
    fs.put(pgp::EF_CH_NAME, b"Test user").unwrap();
    fs.put(pgp::EF_LOGIN_DATA, b"test@example.com").unwrap();
    fs.put(pgp::EF_URI_URL, b"https://example.com").unwrap();
    fs.put(pgp::EF_LANG_PREF, b"en").unwrap();
    let fid = piv::key_fid(piv::SLOT_AUTHENTICATION);
    fs.put_key(fid, rsk_fs::Sealed::wrap(&[0xA5; 32])).unwrap();
    fs.meta_add(
        fid.get(),
        &[
            piv::ALGO_ECCP256,
            piv::PINPOLICY_ALWAYS,
            piv::TOUCHPOLICY_CACHED,
            piv::ORIGIN_GENERATED,
        ],
    )
    .unwrap();
}

fn seed_oath(env: &Env, count: usize) {
    let presence = RefCell::new(rsk_sdk::AlwaysConfirm);
    let mut app = rsk_oath::OathApplet::new(
        env.keys.serial_id,
        env.keys.serial_hash,
        None,
        &env.rng,
        &presence,
    );
    for i in 0..count {
        let name = std::format!("code{i:02}");
        let mut body = vec![0x71, name.len() as u8];
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&[0x73, 16, if i % 2 == 0 { 0x11 } else { 0x21 }, 6]);
        body.extend_from_slice(b"keykeykeykeyke");
        body.extend_from_slice(&[0x78, 2]);
        let mut apdu = vec![0, 1, 0, 0, body.len() as u8];
        apdu.extend_from_slice(&body);
        let mut out = [0; 256];
        assert_eq!(
            app.process(
                &Apdu::parse(&apdu).unwrap(),
                &mut env.fs.borrow_mut(),
                &mut ResBuf::new(&mut out),
            ),
            Sw::OK
        );
    }
}

#[test]
fn app_summaries_report_public_metadata_without_decrypting_keys() {
    let env = Env::new();
    seed_metadata(&env);
    seed_oath(&env, 7);
    let mut ui = env.ui(Pad::idle());
    let entropy = env.rng.borrow().served.len();
    let local = env.local(&mut ui);
    let apps = local.load_apps();
    assert_eq!(
        (apps.openpgp_keys, apps.piv_slots, apps.oath_codes),
        (3, 1, 7)
    );
    let pgp = local.load_openpgp();
    assert!(pgp.slots.iter().all(|slot| slot.present && slot.touch));
    assert_eq!(pgp.cardholder_name.as_str(), "Test user");
    let holder = local.load_openpgp_cardholder();
    assert!(holder.any);
    assert_eq!(holder.login.as_str(), "test@example.com");
    assert_eq!(holder.url.as_str(), "https://example.com");
    assert_eq!(holder.lang.as_str(), "en");
    for i in 0..3 {
        let key = local.load_openpgp_key(i);
        assert!(key.present && key.has_fp && key.created && key.touch);
        assert_eq!(key.fingerprint, [0x71; 20]);
    }
    let piv = local.load_piv();
    assert!(piv.slots[0].present);
    assert_eq!(piv.slots[0].algo.as_str(), "NIST P-256");
    let slot = local.load_piv_slot(rsk_piv::files::SLOT_AUTHENTICATION);
    assert_eq!(slot.pin_policy.as_str(), "Always");
    assert_eq!(slot.touch_policy.as_str(), "Cached");
    assert_eq!(slot.origin.as_str(), "Generated");
    let oath = local.load_oath_cred(0);
    assert_eq!(oath.name.as_str(), "code00");
    assert!(oath.hotp && oath.touch);
    assert_eq!(oath.digits, 6);
    assert_eq!(local.load_oath_cred(99).name.as_str(), "");
    assert_eq!(env.rng.borrow().served.len(), entropy);
}

#[test]
fn the_hub_keeps_its_active_tab_and_returns_the_selected_destination() {
    for target in [NavTab::Home, NavTab::Passkeys, NavTab::Settings] {
        let env = Env::new();
        let mut ui = env.ui(Pad::taps(&[nowhere(), nav(NavTab::Apps), nav(target)]));
        assert_eq!(
            env.local(&mut ui).run_apps(),
            if target == NavTab::Home {
                None
            } else {
                Some(target)
            }
        );
        assert!(!ui.asleep && !ui.panel.oob);
        assert!(ui.shown.is_none());
    }
}

#[test]
fn each_applet_drills_in_and_returns_to_the_hub() {
    for (i, entries) in [(0, 4), (1, 4), (2, 1)] {
        let env = Env::new();
        seed_metadata(&env);
        seed_oath(&env, 1);
        let mut taps = vec![row(i)];
        for detail in 0..entries {
            taps.extend([row(detail), nowhere(), center(rsk_ui::TITLE_BACK_RECT)]);
        }
        taps.extend([nav(NavTab::Apps), nav(NavTab::Home)]);
        let mut ui = env.ui(Pad::taps(&taps));
        assert_eq!(env.local(&mut ui).run_apps(), None);
        assert!(!ui.asleep && !ui.panel.oob);
        assert!(ui.panel.frames >= 2 * entries as usize + 3);
    }
}

#[test]
fn applet_navigation_can_leave_the_hub_directly() {
    for i in 0..3 {
        for target in [NavTab::Home, NavTab::Passkeys, NavTab::Settings] {
            let env = Env::new();
            let mut ui = env.ui(Pad::taps(&[row(i), nav(target)]));
            assert_eq!(env.local(&mut ui).run_apps(), Some(target));
        }
    }
}

#[test]
fn pending_host_requests_and_power_close_each_browse_screen() {
    for entry in [AppEntry::OpenPgp, AppEntry::Piv, AppEntry::Oath] {
        for power in [false, true] {
            let env = Env::new();
            let mut ui = env.ui(Pad::taps(&[nowhere()]));
            ui.hooks.host_pending = !power;
            if power {
                ui.hooks.press_wake(1);
            }
            let mut local = env.local(&mut ui);
            let leave = match entry {
                AppEntry::OpenPgp => local.run_openpgp(),
                AppEntry::Piv => local.run_piv(),
                AppEntry::Oath => local.run_oath(),
            };
            assert_eq!(leave, None);
            assert_eq!(ui.asleep, power);
        }
    }
}

#[test]
fn pending_host_requests_and_power_close_each_detail_screen() {
    for entry in [AppEntry::OpenPgp, AppEntry::Piv, AppEntry::Oath] {
        for power in [false, true] {
            let env = Env::new();
            let mut ui = env.ui(Pad::taps(&[nowhere()]));
            ui.hooks.host_pending = !power;
            if power {
                ui.hooks.press_wake(1);
            }
            let mut local = env.local(&mut ui);
            match entry {
                AppEntry::OpenPgp => local.run_openpgp_key(0),
                AppEntry::Piv => local.run_piv_slot(rsk_piv::files::SLOT_AUTHENTICATION),
                AppEntry::Oath => local.run_oath_cred(0),
            }
            assert_eq!(ui.asleep, power);
        }
    }
}

#[test]
fn oath_pages_keep_the_total_and_the_correct_credential_indices() {
    let env = Env::new();
    seed_oath(&env, 7);
    let mut ui = env.ui(Pad::taps(&[
        center(rsk_ui::PAGER_NEXT_RECT),
        row(1),
        center(rsk_ui::TITLE_BACK_RECT),
        center(rsk_ui::PAGER_PREV_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
    ]));
    {
        let local = env.local(&mut ui);
        let mut rows = [rsk_ui::OathRow::default(); rsk_ui::PK_ROWS_MAX];
        assert_eq!(local.load_oath(&mut rows, 1), (2, 7));
        assert_eq!(rows[0].name.as_str(), "code05");
        assert_eq!(rows[1].name.as_str(), "code06");
        assert_eq!(local.load_oath(&mut rows, 2), (0, 7));
    }
    assert_eq!(env.local(&mut ui).run_oath(), None);
    assert!(ui.panel.damage_presentations >= 2);
    assert!(!ui.panel.oob);
}

#[test]
fn the_retired_piv_list_pages_keys_and_offers_generation_after_them() {
    let env = Env::new();
    {
        let mut fs = env.fs.borrow_mut();
        for slot in 0x82..=0x87 {
            fs.put_key(
                rsk_piv::files::key_fid(slot),
                rsk_fs::Sealed::wrap(&[0xA5; 32]),
            )
            .unwrap();
            fs.meta_add(
                rsk_piv::files::key_fid(slot).get(),
                &[rsk_piv::files::ALGO_ED25519],
            )
            .unwrap();
        }
    }
    let mut ui = env.ui(Pad::taps(&[
        center(rsk_ui::PAGER_NEXT_RECT),
        row(0),
        center(rsk_ui::TITLE_BACK_RECT),
        center(rsk_ui::PAGER_PREV_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
    ]));
    {
        let local = env.local(&mut ui);
        let mut rows = [rsk_ui::PivExtraRow::default(); rsk_ui::PK_ROWS_MAX];
        assert_eq!(local.load_piv_extra(&mut rows, 1), (2, 7));
        assert_eq!(rows[0].slot, 0x87);
        assert!(rows[0].present);
        assert!(rows[1].generate);
    }
    env.local(&mut ui).run_piv_extra();
    assert!(ui.panel.damage_presentations >= 2);
    assert!(!ui.panel.oob);
}

#[test]
fn an_unread_fused_key_hides_oath_records_and_the_audit_log() {
    let mut env = Env::new();
    seed_oath(&env, 1);
    env.keys.mkek_source = Some(FusedKey::latched(|_| false));
    let mut ui = env.ui(Pad::idle());
    let local = env.local(&mut ui);
    let mut oath = [rsk_ui::OathRow::default(); rsk_ui::PK_ROWS_MAX];
    let mut events = [AuditRow::default(); rsk_ui::PK_ROWS_MAX];
    assert_eq!(local.load_apps().oath_codes, 0);
    assert_eq!(local.load_oath(&mut oath, 0), (0, 0));
    assert_eq!(local.load_oath_cred(0).name.as_str(), "");
    assert_eq!(local.load_events(&mut events, 0), (0, 0));
}
