// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn damage_at_the_right_panel_edge_keeps_the_last_tile_width() {
    let mut previous = Scene::default();
    previous.finalize(DAMAGE_KEY).unwrap();
    let mut tags = [0; DAMAGE_TILES];
    for row in 0..DAMAGE_ROWS {
        for column in 0..DAMAGE_COLS {
            tags[row * DAMAGE_COLS + column] = previous.tile_tag(column, row);
        }
    }
    let mut next = Scene::default();
    next.fill_solid(
        &Rectangle::new(Point::new(239, 10), Size::new(1, 1)),
        Rgb565::GREEN,
    )
    .unwrap();
    next.finalize(DAMAGE_KEY).unwrap();
    let mut updated = [0; DAMAGE_TILES];
    let mut damage = [Rect::new(0, 0, 0, 0); DAMAGE_TILES];
    assert_eq!(next.damage_rects(&tags, true, &mut updated, &mut damage), 1);
    assert_eq!(damage[0], Rect::new(224, 0, 16, 32));
}

#[test]
fn the_last_partial_band_preserves_bytes_beyond_the_requested_rectangle() {
    let mut scene = Scene::default();
    scene.clear(Rgb565::BLUE).unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut out = [0xA5; 4];
    scene.raster_band(Rect::new(10, 10, 1, 2), 11, 2, &mut out);
    assert_eq!(out, [0, 31, 0xA5, 0xA5]);
}

#[test]
fn a_vertically_disjoint_raster_in_the_same_band_index_is_skipped() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::new(0, 3), Size::new(1, 1)),
            [Rgb565::RED],
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut out = [0xA5; 2];
    scene.raster_band(Rect::new(0, 0, 1, 1), 0, 1, &mut out);
    assert_eq!(out, [0, 0]);
}

#[test]
fn a_solid_band_cursor_advances_from_an_off_band_prefix_to_each_visible_record() {
    let mut scene = Scene::default();
    for (x, y, color) in [
        (0, 0, Rgb565::RED),
        (0, 16, Rgb565::GREEN),
        (1, 16, Rgb565::BLUE),
    ] {
        scene
            .fill_solid(&Rectangle::new(Point::new(x, y), Size::new(1, 1)), color)
            .unwrap();
    }
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut out = [0xA5; 4];
    scene.raster_band(Rect::new(0, 16, 2, 1), 16, 1, &mut out);
    assert_eq!(out, [7, 224, 0, 31]);
}

#[test]
fn a_raster_record_returns_the_next_complete_record_offset() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::zero(), Size::new(3, 3)),
            core::iter::repeat_n(Rgb565::GREEN, 9),
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut out = [0; 12];
    assert_eq!(scene.raster_record(0, Rect::new(0, 1, 3, 2), &mut out), 17);
    for color in out.as_chunks::<2>().0.iter() {
        assert_eq!(*color, [7, 224]);
    }
}
