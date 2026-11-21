// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn partial_coverage_blends_every_nonzero_background_channel() {
    assert_eq!(
        blend_coverage(Rgb565::BLACK, Rgb565::WHITE, 7),
        Rgb565::new(17, 34, 17)
    );
}

#[test]
fn renderer_circle_sizes_retain_their_fixed_coverage_tables() {
    for diameter in [6, 8, 10, 12, 39, 58, 61, 64, 70, 72, 76] {
        let center = diameter as usize / 2;
        assert!(fixed_circle_coverage(diameter, center, center).is_some());
    }
    assert_eq!(fixed_circle_coverage(11, 5, 5), None);
}

#[test]
fn the_largest_admitted_round_mask_remains_available() {
    assert!(fixed_round_supported(Rect::new(0, 0, 16, 16), 16));
    assert!(!fixed_round_supported(Rect::new(0, 0, 16, 16), 17));
}

#[test]
fn fixed_round_central_stripes_are_full_without_indexing_a_neighbor_mask() {
    for diameter in [10, 16] {
        assert_eq!(
            fixed_rounded_coverage(Rect::new(0, 0, 40, 40), diameter, 1, 17),
            16
        );
    }
}

#[test]
fn a_round_mask_with_no_middle_height_dispatches_only_its_corner_strips() {
    let mut target = Transactions {
        draw: 0,
        contiguous: 0,
        solid: 0,
    };
    rounded_rect(
        &mut target,
        Rect::new(0, 0, 16, 16),
        16,
        Some(Rgb565::WHITE),
        None,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.draw, 0);
    assert_eq!(target.contiguous, 2);
    assert_eq!(target.solid, 0);
}

#[test]
fn an_uncached_circle_keeps_its_independent_right_and_bottom_full_pixels() {
    let mut target = Rec::new(20, Rgb565::BLACK);
    filled_circle(
        &mut target,
        EgPoint::new(3, 5),
        13,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.at(15, 11), Rgb565::WHITE);
    assert_eq!(target.at(9, 17), Rgb565::WHITE);
    assert!(!target.oob);
}

#[test]
fn a_cached_circle_keeps_full_pixels_at_a_nonzero_origin() {
    let mut target = Rec::new(20, Rgb565::BLACK);
    filled_circle(
        &mut target,
        EgPoint::new(3, 5),
        12,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.at(9, 5), Rgb565::WHITE);
    assert_eq!(target.at(3, 11), Rgb565::WHITE);
    assert!(!target.oob);
}

#[test]
fn a_zero_width_outline_leaves_the_existing_surface_untouched() {
    let mut target = Rec::new(20, Rgb565::BLUE);
    circle(
        &mut target,
        EgPoint::new(3, 5),
        12,
        0,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.pixels.iter().all(|color| *color == Rgb565::BLUE));
    assert!(!target.oob);
}

#[test]
fn a_zero_width_round_border_keeps_the_straight_strip_fill() {
    let mut target = Rec::new(20, Rgb565::BLACK);
    rounded_rect(
        &mut target,
        Rect::new(0, 0, 20, 20),
        8,
        Some(Rgb565::WHITE),
        Some((Rgb565::RED, 0)),
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.at(10, 1), Rgb565::WHITE);
    assert!(!target.oob);
}

#[test]
fn angle_approximation_preserves_octants_and_positive_rescaling() {
    let shallow = angle_deg(3, 1);
    let steep = angle_deg(1, 3);
    assert!((1..45).contains(&shallow));
    assert!((46..90).contains(&steep));
    assert_eq!(shallow, angle_deg(9, 3));
    assert_eq!(steep, angle_deg(3, 9));
    assert!((136..180).contains(&angle_deg(-3, 1)));
}

#[test]
fn an_arc_includes_its_start_axis_and_excludes_its_end_axis() {
    assert!(angle_in_arc(0, 7, 90, 90));
    assert!(!angle_in_arc(-7, 0, 90, 90));
}

#[test]
fn separately_empty_round_dimensions_dispatch_no_transfers() {
    let mut target = Transactions {
        draw: 0,
        contiguous: 0,
        solid: 0,
    };
    for rect in [Rect::new(2, 2, 0, 6), Rect::new(2, 2, 6, 0)] {
        rounded_rect(
            &mut target,
            rect,
            8,
            Some(Rgb565::WHITE),
            None,
            Rgb565::BLACK,
        )
        .unwrap();
    }
    assert_eq!((target.draw, target.contiguous, target.solid), (0, 0, 0));
}

#[test]
fn a_supported_bordered_round_keeps_its_solid_and_contiguous_transfers() {
    let mut target = Transactions {
        draw: 0,
        contiguous: 0,
        solid: 0,
    };
    rounded_rect(
        &mut target,
        Rect::new(2, 2, 20, 20),
        8,
        Some(Rgb565::WHITE),
        Some((Rgb565::RED, 1)),
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!((target.draw, target.contiguous, target.solid), (0, 2, 3));
}

#[test]
fn an_uncached_round_at_zero_y_emits_its_full_center_pixel() {
    let mut target = Rec::new(12, Rgb565::BLACK);
    rounded_rect(
        &mut target,
        Rect::new(2, 0, 8, 6),
        17,
        Some(Rgb565::WHITE),
        None,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.at(6, 3), Rgb565::WHITE);
    assert!(!target.oob);
}

#[test]
fn a_cached_arc_at_a_nonzero_origin_keeps_its_full_mark_pixel() {
    let mut target = Rec::new(64, Rgb565::BLUE);
    ring_arc(
        &mut target,
        EgPoint::new(32, 32),
        50,
        3,
        crate::render::STATUS_ARC_START,
        270,
        Rgb565::WHITE,
        Rgb565::RED,
        Rgb565::BLUE,
    )
    .unwrap();
    assert_eq!(target.at(55, 32), Rgb565::RED);
    assert!(!target.oob);
}

#[test]
fn a_zero_width_arc_leaves_the_existing_surface_untouched() {
    let mut target = Rec::new(20, Rgb565::BLUE);
    ring_arc(
        &mut target,
        EgPoint::new(10, 10),
        12,
        0,
        17,
        270,
        Rgb565::WHITE,
        Rgb565::RED,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.pixels.iter().all(|color| *color == Rgb565::BLUE));
    assert!(!target.oob);
}

#[test]
fn the_home_arc_retains_full_mark_and_empty_background_pixels() {
    let mut target = Rec::new(50, Rgb565::BLUE);
    ring_arc(
        &mut target,
        EgPoint::new(25, 25),
        50,
        3,
        crate::render::STATUS_ARC_START,
        270,
        Rgb565::WHITE,
        Rgb565::RED,
        Rgb565::BLUE,
    )
    .unwrap();
    assert_eq!(target.at(48, 25), Rgb565::RED);
    assert_eq!(target.at(0, 0), Rgb565::BLUE);
    assert!(!target.oob);
}
