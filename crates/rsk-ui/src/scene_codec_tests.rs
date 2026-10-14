// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_raster_command_iterator_returns_one_complete_pixel_before_finishing() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::new(3, 4), Size::new(1, 1)),
            [Rgb565::GREEN],
        )
        .unwrap();
    let mut commands = scene.commands();
    let command = commands.next().unwrap();
    assert_eq!(command.rect, Rect::new(3, 4, 1, 1));
    assert_eq!(command.color, Rgb565::GREEN);
    assert_eq!(command.opcode, OP_RASTER);
    assert!(commands.next().is_none());
}

#[test]
fn a_partial_final_raster_row_does_not_paint_unsupplied_pixels() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::zero(), Size::new(3, 2)),
            core::iter::repeat_n(Rgb565::RED, 4),
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut out = [0; 6];
    scene.raster_band(Rect::new(0, 1, 3, 1), 1, 1, &mut out);
    assert_eq!(out, [248, 0, 0, 0, 0, 0]);
}

#[test]
fn two_visible_raster_rows_keep_their_columns_and_fill_the_whole_band() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::zero(), Size::new(3, 3)),
            core::iter::repeat_n(Rgb565::RED, 9),
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut out = [0; 12];
    scene.raster_band(Rect::new(0, 1, 3, 2), 1, 2, &mut out);
    for color in out.chunks_exact(2) {
        assert_eq!(color, [248, 0]);
    }
}

#[test]
fn each_damage_tile_matches_the_literal_panel_grid_and_right_edge_extent() {
    for (row, y) in [0, 32, 64, 96, 128, 160, 192, 224, 256, 288]
        .into_iter()
        .enumerate()
    {
        for (column, (x, width)) in [
            (0, 32),
            (32, 32),
            (64, 32),
            (96, 32),
            (128, 32),
            (160, 32),
            (192, 32),
            (224, 16),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(damage_tile(column, row), Rect::new(x, y, width, 32));
        }
    }
}

#[test]
fn command_tags_hash_the_complete_canonical_geometry_and_color_bytes() {
    let mut actual = SipHasher24::new_with_keys(DAMAGE_KEY[0], DAMAGE_KEY[1]);
    tag_command(
        &mut actual,
        OP_SOLID,
        Rect::new(35, 258, 2, 3),
        RawU16::new(0x1234).into(),
    );
    let mut expected = SipHasher24::new_with_keys(DAMAGE_KEY[0], DAMAGE_KEY[1]);
    expected.write(&[0, 35, 2, 1, 2, 3, 0x12, 0x34]);
    let actual: u128 = actual.finish128().into();
    let expected: u128 = expected.finish128().into();
    assert_eq!(actual, expected);
}
