// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use core::cell::Cell;

#[test]
fn a_clipped_right_column_cannot_shift_colors_into_the_next_row() {
    let colors = (0..480).map(|i| {
        if i == 239 {
            Rgb565::GREEN
        } else if i < 240 {
            Rgb565::RED
        } else {
            Rgb565::BLUE
        }
    });
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::new(1, 20), Size::new(240, 2)),
            colors,
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    for (i, &color) in canvas.pixels.iter().enumerate() {
        let (x, y) = (i % 240, i / 240);
        let expected = if x > 0 && y == 20 {
            Rgb565::RED
        } else if x > 0 && y == 21 {
            Rgb565::BLUE
        } else {
            Rgb565::BLACK
        };
        assert_eq!(color, expected, "({x},{y})");
    }
}

#[test]
fn a_clipped_bottom_row_never_becomes_an_off_panel_record() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::new(0, 1), Size::new(2, 320)),
            core::iter::repeat_n(Rgb565::BLUE, 640),
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    for (i, &color) in canvas.pixels.iter().enumerate() {
        let (x, y) = (i % 240, i / 240);
        assert_eq!(
            color,
            if x < 2 && y > 0 {
                Rgb565::BLUE
            } else {
                Rgb565::BLACK
            },
            "({x},{y})"
        );
    }
}

#[test]
fn a_fully_clipped_raster_does_not_poll_its_color_source() {
    let polls = Cell::new(0);
    let colors = [Rgb565::RED]
        .into_iter()
        .inspect(|_| polls.set(polls.get() + 1));
    let mut scene = Scene::default();
    assert_eq!(
        scene.fill_contiguous(
            &Rectangle::new(Point::new(240, 10), Size::new(1, 1)),
            colors
        ),
        Ok(())
    );
    assert_eq!(polls.get(), 0);
    assert_eq!(scene.command_count(), 0);
    assert_eq!(scene.stream_len, 0);
}

#[test]
fn raster_header_preflight_distinguishes_exact_room_from_insufficient_room() {
    for (solids, before, expected) in [
        (1820, 16380, Err(SceneError::Capacity)),
        (1819, 16371, Ok(())),
    ] {
        let mut scene = Scene::default();
        let area = Rectangle::new(Point::zero(), Size::new(1, 1));
        for _ in 0..solids {
            scene.fill_solid(&area, Rgb565::RED).unwrap();
        }
        assert_eq!(scene.stream_len, before);
        assert_eq!(scene.fill_contiguous(&area, core::iter::empty()), expected);
        assert_eq!(scene.stream_len, before);
        assert_eq!(scene.error(), expected.err());
    }
}

#[test]
fn a_checkpoint_band_starts_at_its_own_rows_for_an_inset_raster() {
    let mut scene = Scene::default();
    let colors = (0..96).map(|i| {
        if i < 32 {
            Rgb565::RED
        } else if i < 64 {
            Rgb565::GREEN
        } else {
            Rgb565::BLUE
        }
    });
    scene
        .fill_contiguous(&Rectangle::new(Point::new(2, 0), Size::new(4, 24)), colors)
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut band = [0; 64];
    scene.raster_band(Rect::new(2, 8, 4, 8), 8, 8, &mut band);
    for color in band.chunks_exact(2) {
        assert_eq!(color, Rgb565::GREEN.into_storage().to_be_bytes());
    }
}

#[test]
fn the_final_palette_relocation_can_exactly_fill_the_stream() {
    let mut scene = Scene::default();
    for _ in 0..3 {
        scene
            .fill_contiguous(
                &Rectangle::new(Point::zero(), Size::new(240, 2)),
                core::iter::repeat_n(Rgb565::RED, 263),
            )
            .unwrap();
    }
    let area = Rectangle::new(Point::new(1, 1), Size::new(1, 1));
    for _ in 0..1813 {
        scene.fill_solid(&area, Rgb565::BLUE).unwrap();
    }
    assert_eq!(scene.stream_len, 16368);
    assert_eq!(scene.fill_contiguous(&area, [Rgb565::GREEN]), Ok(()));
    assert_eq!(scene.stream_len, 16384);
    assert_eq!(scene.error(), None);
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    assert_eq!(canvas.pixels[241], Rgb565::GREEN);
}
