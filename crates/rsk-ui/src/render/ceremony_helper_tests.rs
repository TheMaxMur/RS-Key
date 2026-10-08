// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::render::tests::Rec;

#[test]
fn a_direct_one_line_ceremony_plate_has_a_distinct_caption_layout() {
    let mut one = Rec::new();
    let mut two = Rec::new();
    ceremony_plate(
        &mut one,
        Glyph::Key,
        "first",
        "",
        theme::SURFACE,
        theme::BORDER_CARD,
        FG,
    )
    .unwrap();
    ceremony_plate(
        &mut two,
        Glyph::Key,
        "first",
        "second",
        theme::SURFACE,
        theme::BORDER_CARD,
        FG,
    )
    .unwrap();
    assert_ne!(one.px, two.px);
    assert!(!one.oob && !two.oob);
    assert!(one.px.contains(&FG));
    assert!(two.px.contains(&FG));
}
