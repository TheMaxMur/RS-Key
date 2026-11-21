// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_lower_row_change_updates_only_its_own_damage_tag_and_rectangle() {
    let mut previous = Scene::default();
    previous.finalize(DAMAGE_KEY).unwrap();
    let mut next = Scene::default();
    next.fill_solid(
        &Rectangle::new(Point::new(35, 35), Size::new(3, 3)),
        Rgb565::RED,
    )
    .unwrap();
    next.finalize(DAMAGE_KEY).unwrap();
    let mut changed = Vec::new();
    let mut old_tags = [0; DAMAGE_TILES];
    for row in 0..DAMAGE_ROWS {
        for column in 0..DAMAGE_COLS {
            old_tags[row * DAMAGE_COLS + column] = previous.tile_tag(column, row);
            if next.tile_tag(column, row) != previous.tile_tag(column, row) {
                changed.push((column, row));
            }
        }
    }
    assert_eq!(changed, [(1, 1)]);
    let mut tags = [0; DAMAGE_TILES];
    let mut rects = [Rect::new(0, 0, 0, 0); DAMAGE_TILES];
    assert_eq!(next.damage_rects(&old_tags, true, &mut tags, &mut rects), 1);
    assert_eq!(rects[0], Rect::new(32, 32, 32, 32));
}

#[test]
fn a_one_pixel_raster_has_a_nonzero_record_width_when_finalized() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::new(3, 4), Size::new(1, 1)),
            [Rgb565::GREEN],
        )
        .unwrap();
    assert_eq!(scene.finalize(DAMAGE_KEY), Ok(()));
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    assert_eq!(canvas.pixel(3, 4), Rgb565::GREEN);
    assert_eq!(
        canvas
            .pixels
            .iter()
            .filter(|&&c| c != Rgb565::BLACK)
            .count(),
        1
    );
}

#[test]
fn mixed_raster_and_solid_damage_paints_every_disjoint_record() {
    let mut sink = DamageSink::filled(Rgb565::BLACK);
    {
        let mut frame = DamageFrame::new(&mut sink);
        frame
            .fill_contiguous(
                &Rectangle::new(Point::new(1, 1), Size::new(1, 1)),
                [Rgb565::RED],
            )
            .unwrap();
        frame
            .fill_solid(
                &Rectangle::new(Point::new(50, 1), Size::new(1, 1)),
                Rgb565::GREEN,
            )
            .unwrap();
        frame
            .fill_solid(
                &Rectangle::new(Point::new(100, 1), Size::new(1, 1)),
                Rgb565::BLUE,
            )
            .unwrap();
    }
    assert_eq!(sink.presentations, 1);
    assert_eq!(sink.rects.len(), 3);
    assert_eq!(sink.canvas.pixel(1, 1), Rgb565::RED);
    assert_eq!(sink.canvas.pixel(50, 1), Rgb565::GREEN);
    assert_eq!(sink.canvas.pixel(100, 1), Rgb565::BLUE);
}
