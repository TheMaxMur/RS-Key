// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, PIN, Pad, center, pin_entry};
use rsk_piv::files::*;

fn pick(i: u16) -> rsk_ui::Point {
    center(rsk_ui::row_rect(rsk_ui::PIV_KEYGEN_PICK_TOP, i))
}

fn fill_retired(env: &Env) {
    let mut fs = env.fs.borrow_mut();
    for slot in 0x82..=0x95 {
        fs.put(cert_fid_for_slot(slot).unwrap(), &[0x30, 0])
            .unwrap();
    }
}

#[test]
fn the_algorithm_chooser_maps_every_row_and_rsa_size() {
    let cases = [
        (0, None, ALGO_ECCP256),
        (1, None, ALGO_ECCP384),
        (2, None, ALGO_ED25519),
        (3, None, ALGO_X25519),
        (4, Some(0), ALGO_RSA2048),
        (4, Some(1), ALGO_RSA3072),
        (4, Some(2), ALGO_RSA4096),
    ];
    for (main, sub, algo) in cases {
        let env = Env::new();
        let mut taps = vec![pick(main)];
        if let Some(sub) = sub {
            taps.push(pick(sub));
        }
        let mut ui = env.ui(Pad::taps(&taps));
        assert_eq!(env.local(&mut ui).piv_pick_algo(0x82), Some(algo));
        assert!(!ui.panel.oob);
    }
}

#[test]
fn backing_out_of_rsa_returns_to_the_main_chooser() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[
        pick(4),
        center(rsk_ui::TITLE_BACK_RECT),
        pick(2),
    ]));
    assert_eq!(env.local(&mut ui).piv_pick_algo(0x82), Some(ALGO_ED25519));
    assert_eq!(ui.panel.frames, 4);
}

#[test]
fn cancelling_generation_never_fills_a_slot() {
    for exit in 0..4 {
        let env = Env::new();
        let taps = match exit {
            0 => vec![center(rsk_ui::TITLE_BACK_RECT)],
            1 => vec![
                pick(4),
                center(rsk_ui::TITLE_BACK_RECT),
                center(rsk_ui::TITLE_BACK_RECT),
            ],
            _ => vec![],
        };
        let mut ui = env.ui(Pad::taps(&taps));
        ui.hooks.host_pending = exit == 2;
        if exit == 3 {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).run_piv_generate();
        assert_eq!(
            rsk_piv::info::next_free_retired(&mut env.fs.borrow_mut()),
            Some(0x82)
        );
        assert_eq!(ui.asleep, exit == 3);
    }
}

#[test]
fn a_full_retired_list_cannot_start_generation() {
    let env = Env::new();
    fill_retired(&env);
    let mut ui = env.ui(Pad::idle());
    let frames = ui.panel.frames;
    env.local(&mut ui).run_piv_generate();
    assert_eq!(ui.panel.frames, frames);
    let mut rows = [rsk_ui::PivExtraRow::default(); rsk_ui::PK_ROWS_MAX];
    assert_eq!(env.local(&mut ui).load_piv_extra(&mut rows, 3), (5, 20));
    assert!(rows.iter().all(|row| !row.generate));
}

#[test]
fn generation_requires_the_device_pin_and_a_completed_hold() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    env.local(&mut ui).run_piv_generate();
    assert!(!rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82).present);

    let mut taps = pin_entry(PIN);
    taps.extend([pick(2), center(rsk_ui::TITLE_BACK_RECT)]);
    let mut ui = env.ui(Pad::taps(&taps));
    ui.hooks.presence_ms = 3000;
    env.local(&mut ui).run_piv_generate();
    assert!(!rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82).present);

    let mut taps = pin_entry(PIN);
    taps.push(pick(2));
    let mut ui = env.ui(Pad::taps_then_hold(&taps, center(rsk_ui::DEL_HOLD_RECT)));
    ui.hooks.presence_ms = 3000;
    env.local(&mut ui).run_piv_generate();
    let slot = rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82);
    assert!(slot.present && !slot.cert);
    assert_eq!(slot.algo, ALGO_ED25519);
    assert_eq!(slot.origin, ORIGIN_GENERATED);
}

#[test]
fn curve_generation_fills_distinct_slots_and_preserves_existing_keys() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    for (i, algo) in [ALGO_ECCP256, ALGO_ECCP384, ALGO_ED25519, ALGO_X25519]
        .into_iter()
        .enumerate()
    {
        assert!(env.local(&mut ui).piv_store_generated(algo));
        let slot = rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82 + i as u8);
        assert!(slot.present);
        assert_eq!(slot.algo, algo);
    }
    assert!(!env.local(&mut ui).piv_store_generated(0xff));
    assert_eq!(
        rsk_piv::info::next_free_retired(&mut env.fs.borrow_mut()),
        Some(0x86)
    );
    fill_retired(&env);
    assert!(!env.local(&mut ui).piv_store_generated(ALGO_ED25519));
}

#[test]
fn an_unread_fused_key_refuses_curve_generation() {
    let mut env = Env::new();
    env.keys.mkek_source = Some(FusedKey::latched(|_| false));
    let mut ui = env.ui(Pad::idle());
    let entropy = env.rng.borrow().served.len();
    assert!(!env.local(&mut ui).piv_store_generated(ALGO_ED25519));
    assert_eq!(env.rng.borrow().served.len(), entropy);
    assert!(!rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82).present);
}

fn rsa_result(env: &Env) -> rsk_openpgp::keys::RsaKey {
    use rsk_openpgp::{consts, init, keypairgen, keys, pin};

    let dev = crate::tests::dev();
    let mut fs = env.fs.borrow_mut();
    let mut rng = env.rng.borrow_mut();
    init::scan_files(&dev, &mut fs, &mut *rng).unwrap();
    let mut session = pin::Session::new();
    assert_eq!(
        pin::verify(
            &dev,
            &mut fs,
            &mut session,
            &mut *rng,
            0,
            consts::PW3_MODE83,
            consts::PW3_DEFAULT,
        ),
        rsk_sdk::Sw::OK
    );
    let mut public = [0u8; 300];
    assert_eq!(
        keypairgen::keypair_gen(
            &dev,
            &mut fs,
            &session,
            &mut *rng,
            0x80,
            0,
            &[consts::CRT_SIG, 0],
            &mut public,
        )
        .1,
        rsk_sdk::Sw::OK
    );
    keys::load_rsa_key(&dev, &mut fs, &session, consts::EF_PK_SIG).unwrap()
}

#[test]
fn rsa_generation_requests_the_selected_width_and_reports_accelerator_failure() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    for algo in [ALGO_RSA2048, ALGO_RSA3072, ALGO_RSA4096] {
        assert!(!env.local(&mut ui).piv_store_generated(algo));
    }
    assert_eq!(ui.hooks.rsa_requests, [2048, 3072, 4096]);
    assert!(!rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82).present);
}

#[test]
fn a_real_rsa_result_is_stored_only_when_a_slot_and_the_fused_key_are_available() {
    for refuse in 0..3 {
        let mut env = Env::new();
        let key = rsa_result(&env);
        if refuse == 1 {
            fill_retired(&env);
        }
        if refuse == 2 {
            env.keys.mkek_source = Some(FusedKey::latched(|_| false));
        }
        let mut ui = env.ui(Pad::idle());
        ui.hooks.rsa_key = Some(Box::new(key));
        assert_eq!(
            env.local(&mut ui).piv_store_generated(ALGO_RSA2048),
            refuse == 0
        );
        assert!(ui.hooks.rsa_key.is_none());
        let slot = rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82);
        assert_eq!(slot.present, refuse == 0);
        if refuse == 0 {
            assert_eq!(slot.algo, ALGO_RSA2048);
            assert_eq!(slot.origin, ORIGIN_GENERATED);
        }
        assert!(!ui.panel.oob);
    }
}

#[test]
fn a_missed_chooser_row_and_failed_generation_do_not_fill_a_slot() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[
        crate::tests::nowhere(),
        center(rsk_ui::TITLE_BACK_RECT),
    ]));
    assert!(matches!(
        env.local(&mut ui).pick_row(rsk_ui::PIV_KEYGEN_PICK_TOP, 1),
        Pick::Back
    ));
    drop(ui);
    drop(env);
    let mut env = Env::new();
    env.keys.mkek_source = Some(FusedKey::latched(|_| false));
    let mut samples = vec![None; 6];
    samples.push(Some(pick(2)));
    samples.extend([None; 6]);
    samples.extend(core::iter::repeat_n(
        Some(center(rsk_ui::DEL_HOLD_RECT)),
        3 * (HOLD_MS / TOUCH_POLL_MS) as usize,
    ));
    let mut ui = env.ui(Pad::script(&samples));
    let generation = env.fs.borrow().write_gen();
    env.local(&mut ui).run_piv_generate();
    assert_eq!(env.fs.borrow().write_gen(), generation);
    assert!(!rsk_piv::info::read_slot(&mut env.fs.borrow_mut(), 0x82).present);
    assert!(!ui.asleep);
}
