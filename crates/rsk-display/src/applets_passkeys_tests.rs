// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, PIN, Pad, center, dev, nowhere};
use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_store};

const SEED: [u8; 32] = [0x5A; 32];

fn nav(tab: NavTab) -> rsk_ui::Point {
    center(rsk_ui::nav_tab_rect(
        rsk_ui::NAV_TABS.iter().position(|t| *t == tab).unwrap() as u16,
    ))
}

fn row(i: u16) -> rsk_ui::Point {
    center(rsk_ui::row_rect(rsk_ui::PK_LIST_TOP, i))
}

fn seed_accounts(env: &Env, rps: usize, accounts: usize) {
    let mut fs = env.fs.borrow_mut();
    rsk_fido::seed::encrypt_keydev_f1(&dev(), &mut fs, &SEED).unwrap();
    let mut rng = env.rng.borrow_mut();
    for rp in 0..rps {
        let rp_id = std::format!("service{rp}.example.com");
        let hash = rsk_crypto::sha256(rp_id.as_bytes());
        for account in 0..accounts {
            let id = [rp as u8, account as u8];
            let name = std::format!("user{account}");
            let input = CredInput {
                rp_id: &rp_id,
                user_id: &id,
                user_name: &name,
                user_display_name: &name,
                use_sign_count: false,
                rk: true,
                created_ms: 1,
                alg: rsk_fido::consts::ALG_ES256,
                curve: i64::from(rsk_fido::consts::CURVE_P256),
                ext: CredExt::default(),
            };
            let mut boxbuf = [0; 512];
            let n = credential_create(
                &SEED,
                &dev(),
                &input,
                &hash,
                &[account as u8; 12],
                &mut boxbuf,
            )
            .unwrap();
            credential_store(
                &SEED,
                &dev(),
                &mut fs,
                &mut *rng,
                &boxbuf[..n],
                &hash,
                &rp_id,
                &id,
                &[],
            )
            .unwrap();
        }
    }
}

fn service() -> Label {
    Label::clamp(b"service0.example.com")
}

fn hash() -> [u8; 32] {
    rsk_crypto::sha256(service().as_str().as_bytes())
}

fn delete_script(before: &[rsk_ui::Point], after: &[rsk_ui::Point]) -> Pad {
    let mut samples = vec![None; 4];
    for &point in before {
        samples.push(Some(point));
        samples.extend([None; 4]);
    }
    samples.extend(vec![
        Some(center(rsk_ui::DEL_HOLD_RECT));
        3 * (HOLD_MS / TOUCH_POLL_MS) as usize
    ]);
    samples.extend([None; 4]);
    for &point in after {
        samples.push(Some(point));
        samples.extend([None; 4]);
    }
    Pad::script(&samples)
}

#[test]
fn deleting_the_last_rp_on_the_last_page_clamps_the_passkeys_list() {
    let env = Env::new();
    seed_accounts(&env, 6, 1);
    let mut ui = env.ui(delete_script(
        &[center(rsk_ui::PAGER_NEXT_RECT), row(0), row(0)],
        &[center(rsk_ui::DEL_HOLD_RECT), nav(NavTab::Home)],
    ));
    assert_eq!(env.local(&mut ui).run_passkeys(), None);
    assert_eq!(
        rsk_fido::passkeys::for_each_rp(&dev(), &mut env.fs.borrow_mut(), |_| {}),
        5
    );
    assert!(!ui.panel.oob);
    assert!(ui.panel.frames >= 6);
}

#[test]
fn deleting_the_last_account_on_a_page_clamps_the_service_without_losing_other_accounts() {
    let env = Env::new();
    seed_accounts(&env, 1, 6);
    let mut ui = env.ui(delete_script(
        &[center(rsk_ui::PAGER_NEXT_RECT), row(0)],
        &[center(rsk_ui::DEL_HOLD_RECT), nav(NavTab::Apps)],
    ));
    assert!(matches!(
        env.local(&mut ui)
            .run_service(&service(), &Label::default(), &hash()),
        ServiceResult::Leave(Some(NavTab::Apps))
    ));
    let mut names = Vec::new();
    rsk_fido::passkeys::for_each_cred(&dev(), &mut env.fs.borrow_mut(), &hash(), |account| {
        names.push(account.user_name.to_owned())
    });
    assert_eq!(names, ["user0", "user1", "user2", "user3", "user4"]);
    assert!(!ui.panel.oob);
}

#[test]
fn refusing_the_device_pin_changes_neither_a_nickname_nor_an_account() {
    for rename in [false, true] {
        let env = Env::new();
        seed_accounts(&env, 1, 1);
        env.set_device_pin(PIN);
        let mut taps = vec![
            if rename {
                center(rsk_ui::TITLE_EDIT_RECT)
            } else {
                row(0)
            },
            center(rsk_ui::PIN_CANCEL_RECT),
        ];
        if !rename {
            taps.push(nav(NavTab::Passkeys));
        }
        let mut ui = env.ui(Pad::taps(&taps));
        assert!(matches!(
            env.local(&mut ui)
                .run_service(&service(), &Label::default(), &hash()),
            ServiceResult::Back
        ));
        assert_eq!(
            rsk_fido::passkeys::for_each_cred(&dev(), &mut env.fs.borrow_mut(), &hash(), |_| {}),
            1
        );
        rsk_fido::passkeys::for_each_rp(&dev(), &mut env.fs.borrow_mut(), |rp| {
            assert_eq!(rp.nickname, None)
        });
    }
}

#[test]
fn passkey_pages_drill_into_the_correct_rp_and_return_to_the_list() {
    let env = Env::new();
    seed_accounts(&env, 7, 1);
    let mut ui = env.ui(Pad::taps(&[
        center(rsk_ui::PAGER_PREV_RECT),
        center(rsk_ui::PAGER_NEXT_RECT),
        row(1),
        nowhere(),
        center(rsk_ui::TITLE_BACK_RECT),
        nav(NavTab::Passkeys),
        center(rsk_ui::PAGER_PREV_RECT),
        nav(NavTab::Home),
    ]));
    let mut rows = [RpRow::default(); rsk_ui::PK_ROWS_MAX];
    let mut hashes = [[0; 32]; rsk_ui::PK_ROWS_MAX];
    assert_eq!(
        env.local(&mut ui).load_rps(&mut rows, &mut hashes, 1),
        (2, 7)
    );
    assert_eq!(rows[1].id.as_str(), "service6.example.com");
    assert_eq!(
        hashes[1],
        rsk_crypto::sha256(rows[1].id.as_str().as_bytes())
    );
    assert_eq!(env.local(&mut ui).run_passkeys(), None);
    assert!(ui.panel.damage_presentations >= 2);
    assert!(!ui.panel.oob);
}

#[test]
fn account_pages_and_navigation_preserve_the_passkeys() {
    for target in rsk_ui::NAV_TABS {
        let env = Env::new();
        seed_accounts(&env, 1, 7);
        let mut ui = env.ui(Pad::taps(&[
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_PREV_RECT),
            nav(target),
        ]));
        let got = env
            .local(&mut ui)
            .run_service(&service(), &Label::default(), &hash());
        match target {
            NavTab::Passkeys => assert!(matches!(got, ServiceResult::Back)),
            NavTab::Home => assert!(matches!(got, ServiceResult::Leave(None))),
            NavTab::Apps | NavTab::Settings => {
                assert!(matches!(got, ServiceResult::Leave(Some(tab)) if tab == target))
            }
        }
        assert_eq!(
            rsk_fido::passkeys::for_each_cred(&dev(), &mut env.fs.borrow_mut(), &hash(), |_| {}),
            7
        );
        assert!(ui.panel.damage_presentations >= 2);
    }
}

#[test]
fn each_nav_destination_can_leave_the_passkeys_list_and_service() {
    for detail in [false, true] {
        for target in [NavTab::Home, NavTab::Apps, NavTab::Settings] {
            let env = Env::new();
            seed_accounts(&env, 1, 1);
            let mut taps = vec![nowhere()];
            if detail {
                taps.push(row(0));
            }
            taps.push(nav(target));
            let mut ui = env.ui(Pad::taps(&taps));
            assert_eq!(
                env.local(&mut ui).run_passkeys(),
                if target == NavTab::Home {
                    None
                } else {
                    Some(target)
                }
            );
        }
    }
}

#[test]
fn browsing_passkeys_yields_to_host_requests_and_the_power_button() {
    for detail in [false, true] {
        for power in [false, true] {
            let env = Env::new();
            let mut ui = env.ui(Pad::taps(&[nowhere()]));
            ui.hooks.host_pending = !power;
            if power {
                ui.hooks.press_wake(1);
            }
            let mut local = env.local(&mut ui);
            if detail {
                assert!(matches!(
                    local.run_service(&service(), &Label::default(), &hash()),
                    ServiceResult::Leave(None)
                ));
            } else {
                assert_eq!(local.run_passkeys(), None);
            }
            assert_eq!(ui.asleep, power);
        }
    }
}

#[test]
fn renaming_from_the_service_updates_only_the_nickname() {
    let env = Env::new();
    seed_accounts(&env, 1, 1);
    let mut ui = env.ui(Pad::taps(&[
        center(rsk_ui::TITLE_EDIT_RECT),
        center(rsk_ui::t9_key_rect(0, 1)),
        center(rsk_ui::t9_key_rect(0, 1)),
        center(rsk_ui::t9_key_rect(3, 2)),
        nav(NavTab::Passkeys),
    ]));
    assert!(matches!(
        env.local(&mut ui)
            .run_service(&service(), &Label::default(), &hash()),
        ServiceResult::Back
    ));
    let mut rows = [RpRow::default(); rsk_ui::PK_ROWS_MAX];
    let mut hashes = [[0; 32]; rsk_ui::PK_ROWS_MAX];
    assert_eq!(
        env.local(&mut ui).load_rps(&mut rows, &mut hashes, 0),
        (1, 1)
    );
    assert_eq!(rows[0].nick.as_str(), "a");
    assert_eq!(rows[0].id, service());
    assert_eq!(
        rsk_fido::passkeys::for_each_cred(&dev(), &mut env.fs.borrow_mut(), &hash(), |_| {}),
        1
    );
    assert!(!ui.panel.oob);
}

#[test]
fn declining_delete_keeps_the_account_on_the_service_page() {
    let env = Env::new();
    seed_accounts(&env, 1, 1);
    let mut ui = env.ui(Pad::taps(&[
        row(0),
        center(rsk_ui::TITLE_BACK_RECT),
        nav(NavTab::Passkeys),
    ]));
    assert!(matches!(
        env.local(&mut ui)
            .run_service(&service(), &Label::default(), &hash()),
        ServiceResult::Back
    ));
    assert_eq!(
        rsk_fido::passkeys::for_each_cred(&dev(), &mut env.fs.borrow_mut(), &hash(), |_| {}),
        1
    );
}
