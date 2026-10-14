// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Frame controls for the Home status indicator (frozen mutation roster). The expected
//! ring is rebuilt from an independent centre, diameter and start angle, so a rewritten
//! ring colour or a shifted arc start fails the pixel equality.

use super::*;
use crate::render::tests::Rec;

#[test]
fn status_arc_start_is_the_top_of_the_ring() {
    assert_eq!(STATUS_ARC_START, -90);
}

#[test]
fn status_ring_frames_match_their_kind_colours() {
    for (kind, mark) in [
        (StatusKind::Touch, theme::WARN),
        (StatusKind::Boot, theme::MUTED),
        (StatusKind::Processing, theme::ACCENT),
    ] {
        let mut actual = Rec::new();
        render_status_arc(&mut actual, kind, STATUS_ARC_START).unwrap();

        let mut expected = Rec::new();
        crate::aa::ring_arc(
            &mut expected,
            EgPoint::new(120, 92),
            50,
            3,
            -90,
            270,
            theme::BORDER_CARD,
            mark,
            BG,
        )
        .unwrap();

        assert_eq!(actual.px, expected.px, "{kind:?}");
        assert!(!actual.oob && !expected.oob, "{kind:?}");
    }
}
