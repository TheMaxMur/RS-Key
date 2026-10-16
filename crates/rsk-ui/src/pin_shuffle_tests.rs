// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const FIRST_SWAP_ACCEPTED_BYTES: u8 = 250;

#[test]
fn every_digit_has_the_same_first_swap_frequency() {
    let mut counts = [0; PIN_DIGIT_CELLS];
    for first in 0..FIRST_SWAP_ACCEPTED_BYTES {
        let mut entropy = [u8::MAX; PIN_SHUFFLE_ENTROPY];
        entropy[0] = first;
        let layout = PinLayout::shuffled(&entropy);
        // Later swaps cannot move the final cell; exhausted redraws isolate this draw.
        let PinKey::Digit(digit) = pin_grid_key(1, 3, &layout) else {
            panic!("the last digit cell must display a digit");
        };
        *counts.get_mut(usize::from(digit)).unwrap() += 1;
    }
    assert_eq!(
        counts, [25; PIN_DIGIT_CELLS],
        "accepted entropy must give every final-cell digit equal weight"
    );
}

#[test]
fn every_rejected_first_byte_requires_a_fresh_draw() {
    for first in FIRST_SWAP_ACCEPTED_BYTES..=u8::MAX {
        let mut entropy = [u8::MAX; PIN_SHUFFLE_ENTROPY];
        entropy[0] = first;
        assert_eq!(
            PinLayout::shuffled(&entropy),
            PinLayout::identity(),
            "rejected first byte {first} must leave an exhausted layout unchanged"
        );
        entropy[1] = 0;
        assert_eq!(
            pin_grid_key(1, 3, &PinLayout::shuffled(&entropy)),
            PinKey::Digit(1),
            "rejected first byte {first} must consume a fresh accepted draw"
        );
    }
}
