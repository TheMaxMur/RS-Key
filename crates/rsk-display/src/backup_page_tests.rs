// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_phrase_pager_delivers_the_last_twelve_words_and_clamps_there() {
    let env = Env::new();
    provision(&env);
    rsk_fido::seed::encrypt_keydev_f1(&dev(), &mut env.fs.borrow_mut(), &[0; 32]).unwrap();
    let mut ui = env.ui(held_then_taps(
        &[],
        &[
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::TITLE_BACK_RECT),
        ],
    ));
    env.local(&mut ui).reveal_phrase();
    let mut words = ["abandon"; 24];
    words[23] = "art";
    let mut reference = env.ui(Pad::idle());
    rsk_ui::render_seed_phrase(&mut reference.frame(), &words, 1, 2).unwrap();
    assert!(
        ui.panel.pixels() == reference.panel.pixels(),
        "the last BIP39 page must contain words 13 through 24"
    );
    assert_eq!(exports(&env), 1);
    assert_eq!(
        rsk_fido::passkeys::load_keydev(&dev(), &mut env.fs.borrow_mut())
            .unwrap()
            .expose(),
        &[0; 32]
    );
}

#[test]
fn generated_share_pages_deliver_the_right_words_share_number_and_global_page() {
    let env = Env::new();
    let generation = env.fs.borrow().write_gen();
    let mut shares = Secret::new([[0; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES]);
    let mut byte = 0u8;
    let mut entropy = |output: &mut [u8]| {
        for value in output {
            *value = byte;
            byte = byte.wrapping_add(1);
        }
    };
    rsk_slip39::generate(&SEED, 2, 3, &mut entropy, shares.expose_mut()).unwrap();
    for (page, share, next_taps) in [(1, 0, 1), (8, 2, 9)] {
        let mut taps = vec![center(rsk_ui::PAGER_NEXT_RECT); next_taps];
        taps.push(center(rsk_ui::TITLE_BACK_RECT));
        let mut ui = env.ui(Pad::taps(&taps));
        env.local(&mut ui).show_shares(shares.expose(), 3);
        let words: [&str; rsk_slip39::WORDS_PER_SHARE] =
            core::array::from_fn(|index| rsk_slip39::word(shares.expose()[share][index]));
        let mut reference = env.ui(Pad::idle());
        rsk_ui::render_slip39_share(&mut reference.frame(), &words, share as u16 + 1, 3, page, 9)
            .unwrap();
        assert!(
            ui.panel.pixels() == reference.panel.pixels(),
            "SLIP39 page {page} must deliver share {} and its own words",
            share + 1
        );
        assert!(!ui.panel.oob);
    }
    assert_eq!(env.fs.borrow().write_gen(), generation);
}
