// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn direct_key_captions_include_every_non_grid_key() {
    for (key, caption) in [
        (PinKey::Del, "Del"),
        (PinKey::Ok, "OK"),
        (PinKey::Cancel, "Cancel"),
        (PinKey::Reveal, ""),
        (PinKey::Digit(0), "0"),
        (PinKey::Digit(9), "9"),
        (PinKey::Digit(255), "5"),
    ] {
        assert_eq!(key_label(key), caption);
    }
}
